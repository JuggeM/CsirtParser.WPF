using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Helpers
{
    public static class QuickWinsHeader
    {
        private const string QuickWinsFileName = "QuickWins.txt";
        private const string HeaderMarker = "# Quick Wins - Global Summary";
        private const string TimelineMarker = "########## Timeline Coverage ##########";

        private static string QuickWinsPath(string outputDir) => Path.Combine(outputDir, QuickWinsFileName);

        public static void EnsureHeader(string outputDir, DateTime generatedOnUtc, DateTime? firstLogUtc, DateTime? lastLogUtc)
        {
            Directory.CreateDirectory(outputDir);
            var path = QuickWinsPath(outputDir);

            if (!File.Exists(path))
            {
                File.WriteAllText(path, BuildHeader(generatedOnUtc, firstLogUtc, lastLogUtc),
                    new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                return;
            }

            var existing = File.ReadAllText(path, new UTF8Encoding(false));
            bool hasHeader = existing.Contains(HeaderMarker);
            bool hasTimeline = existing.Contains(TimelineMarker);

            if (!hasHeader)
            {
                string fixedContent = BuildHeader(generatedOnUtc, firstLogUtc, lastLogUtc) + existing;
                File.WriteAllText(path, fixedContent, new UTF8Encoding(false));
                return;
            }

            if (!hasTimeline)
            {
                // Insert timeline right after header block
                int insertPos = FindHeaderEnd(existing);
                string fixedContent = existing.Insert(insertPos, BuildTimelineBlock(firstLogUtc, lastLogUtc));
                File.WriteAllText(path, fixedContent, new UTF8Encoding(false));
            }
        }

        /// <summary>
        /// Overwrites the two Timeline lines in-place (First/Last) if the timeline block exists.
        /// If it doesn't exist yet, it is inserted below the header.
        /// </summary>
        // Helpers/QuickWinsHeader.cs  — replace the whole UpsertTimeline method

        public static void UpsertTimeline(string outputDir, DateTime? firstLogUtc, DateTime? lastLogUtc)
        {
            var path = QuickWinsPath(outputDir);
            if (!File.Exists(path)) return;

            var text = File.ReadAllText(path, new UTF8Encoding(false));

            // Ensure header exists
            if (!text.Contains(HeaderMarker))
            {
                text = BuildHeader(DateTime.UtcNow, firstLogUtc, lastLogUtc) + text;
                File.WriteAllText(path, text, new UTF8Encoding(false));
                return;
            }

            // Find (or insert) the timeline marker
            int markerIndex = text.IndexOf(TimelineMarker, StringComparison.Ordinal);
            if (markerIndex < 0)
            {
                int insertPos = FindHeaderEnd(text);
                text = text.Insert(insertPos, BuildTimelineBlock(firstLogUtc, lastLogUtc));
                File.WriteAllText(path, text, new UTF8Encoding(false));
                return;
            }

            // Replace everything from the marker line to the end of that small block
            int lineStart = text.LastIndexOf('\n', markerIndex);
            lineStart = (lineStart < 0) ? 0 : lineStart + 1;

            // End of the block = first double-newline or next "##########" section after the two lines
            int searchFrom = markerIndex + TimelineMarker.Length;
            int nextSection = text.IndexOf("##########", searchFrom, StringComparison.Ordinal);
            int doubleNewline = text.IndexOf("\n\n", searchFrom, StringComparison.Ordinal);

            int blockEnd;
            if (doubleNewline >= 0 && (nextSection < 0 || doubleNewline < nextSection))
                blockEnd = doubleNewline + 2;  // keep the trailing blank line
            else if (nextSection >= 0)
                blockEnd = nextSection;
            else
                blockEnd = text.Length;

            string before = text.Substring(0, lineStart);
            string after = text.Substring(blockEnd);
            string timeline = BuildTimelineBlock(firstLogUtc, lastLogUtc);

            File.WriteAllText(path, before + timeline + after, new UTF8Encoding(false));
        }

        /// <summary>
        /// Inserts or updates the global summary section right after the timeline.
        /// Should be called after all parsing is complete.
        /// </summary>
        public static void UpsertGlobalSummary(
            string outputDir,
            DateTime? firstLogUtc,
            DateTime? lastLogUtc,
            Dictionary<string, int> processedFileCountsByLog,
            Dictionary<string, List<string>> suspiciousLogs)
        {
            var path = QuickWinsPath(outputDir);
            if (!File.Exists(path)) return;

            var text = File.ReadAllText(path, new UTF8Encoding(false));
            const string globalMarker = "########## GLOBAL SUMMARY ##########";

            // Build the summary block
            var sb = new StringBuilder();
            sb.AppendLine(globalMarker);
            sb.AppendLine($"Timeline: {FormatMaybe(firstLogUtc)} → {FormatMaybe(lastLogUtc)}");
            sb.AppendLine("Logs Processed:");

            foreach (var logKey in processedFileCountsByLog.Keys.OrderBy(k => k))
            {
                int fileCount = processedFileCountsByLog[logKey];
                int susCount = suspiciousLogs.TryGetValue(logKey, out var findings) ? findings.Count : 0;
                string status = susCount > 0 ? $"{susCount} suspicious" : "clean";
                sb.AppendLine($"  [{logKey}] {fileCount} file(s) - {status}");
            }
            sb.AppendLine("########## END GLOBAL SUMMARY ##########");
            sb.AppendLine();

            string summaryBlock = sb.ToString();

            // Check if global summary already exists
            int existingMarkerIdx = text.IndexOf(globalMarker, StringComparison.Ordinal);

            if (existingMarkerIdx >= 0)
            {
                // Remove old global summary
                int lineStart = text.LastIndexOf('\n', existingMarkerIdx);
                lineStart = (lineStart < 0) ? 0 : lineStart + 1;

                int endMarkerIdx = text.IndexOf("########## END GLOBAL SUMMARY ##########", existingMarkerIdx, StringComparison.Ordinal);
                if (endMarkerIdx < 0)
                    endMarkerIdx = text.IndexOf("##########", existingMarkerIdx + globalMarker.Length, StringComparison.Ordinal);

                int blockEnd = endMarkerIdx >= 0
                    ? text.IndexOf('\n', endMarkerIdx) + 1
                    : text.Length;

                // Also consume trailing blank line if present
                if (blockEnd < text.Length && text[blockEnd] == '\n')
                    blockEnd++;

                string before = text.Substring(0, lineStart);
                string after = text.Substring(blockEnd);
                text = before + summaryBlock + after;
            }
            else
            {
                // Insert after timeline block
                int timelineIdx = text.IndexOf(TimelineMarker, StringComparison.Ordinal);
                if (timelineIdx < 0)
                {
                    // No timeline, insert after header
                    int insertPos = FindHeaderEnd(text);
                    text = text.Insert(insertPos, summaryBlock);
                }
                else
                {
                    // Find end of timeline block (after "Last Log Entry:" line)
                    int afterTimeline = text.IndexOf("Last Log Entry:", timelineIdx, StringComparison.Ordinal);
                    if (afterTimeline >= 0)
                    {
                        afterTimeline = text.IndexOf('\n', afterTimeline) + 1;
                        // Skip blank line after timeline if present
                        if (afterTimeline < text.Length && text[afterTimeline] == '\n')
                            afterTimeline++;
                    }
                    else
                    {
                        afterTimeline = FindHeaderEnd(text);
                    }

                    text = text.Insert(afterTimeline, summaryBlock);
                }
            }

            File.WriteAllText(path, text, new UTF8Encoding(false));
        }
        /// <summary>
        /// Inserts the global summary section immediately after the Timeline Coverage block.
        /// Re-entrant: removes any existing global block before re-inserting.
        /// </summary>
        public static void InsertGlobalAfterTimeline(
            string outputDir, string title, IEnumerable<string> lines)
        {
            if (lines == null) return;
            var list = lines.Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
            if (list.Count == 0) return;

            var path = QuickWinsPath(outputDir);
            if (!File.Exists(path)) return;

            var text = File.ReadAllText(path, new UTF8Encoding(false));

            // Build the section block
            var sb = new System.Text.StringBuilder();
            sb.AppendLine();
            sb.AppendLine($"########## {title} ##########");
            foreach (var line in list)
                sb.AppendLine(line);
            sb.AppendLine();
            string block = sb.ToString();

            // Remove any existing version of this section to avoid duplication on re-run
            string marker = $"########## {title} ##########";
            int existingIdx = text.IndexOf(marker, StringComparison.Ordinal);
            if (existingIdx >= 0)
            {
                int lineStart = text.LastIndexOf('\n', existingIdx);
                lineStart = lineStart < 0 ? 0 : lineStart + 1;
                int nextSection = text.IndexOf("##########",
                    existingIdx + marker.Length, StringComparison.Ordinal);
                int blockEnd = nextSection >= 0 ? nextSection : text.Length;
                // Pull back to consume the preceding blank line
                while (blockEnd > lineStart + 1 &&
                       blockEnd < text.Length && text[blockEnd - 1] == '\n')
                    blockEnd--;
                blockEnd++;
                text = text.Substring(0, lineStart) + text.Substring(blockEnd);
            }

            // Find insertion point: end of Timeline Coverage block
            int insertPos;
            int timelineIdx = text.IndexOf(TimelineMarker, StringComparison.Ordinal);
            if (timelineIdx >= 0)
            {
                int lastEntry = text.IndexOf("Last Log Entry:", timelineIdx,
                    StringComparison.Ordinal);
                if (lastEntry >= 0)
                {
                    insertPos = text.IndexOf('\n', lastEntry);
                    insertPos = insertPos >= 0 ? insertPos + 1 : text.Length;
                    // Skip one blank line separator after timeline
                    if (insertPos < text.Length && text[insertPos] == '\n')
                        insertPos++;
                }
                else
                    insertPos = FindHeaderEnd(text);
            }
            else
                insertPos = FindHeaderEnd(text);

            text = text.Insert(insertPos, block);
            File.WriteAllText(path, text, new UTF8Encoding(false));
        }

        private static string BuildHeader(DateTime generatedOnUtc, DateTime? firstLogUtc, DateTime? lastLogUtc)
        {
            var sb = new StringBuilder();
            sb.AppendLine("##########################################");
            sb.AppendLine(HeaderMarker);
            sb.AppendLine($"# Generated on {generatedOnUtc:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine("##########################################");
            sb.Append(BuildTimelineBlock(firstLogUtc, lastLogUtc));
            return sb.ToString();
        }

        private static string BuildTimelineBlock(DateTime? firstLogUtc, DateTime? lastLogUtc)
        {
            var sb = new StringBuilder();
            sb.AppendLine(TimelineMarker);
            sb.AppendLine($"First Log Entry: {FormatMaybe(firstLogUtc)}");
            sb.AppendLine($"Last Log Entry:  {FormatMaybe(lastLogUtc)}");
            sb.AppendLine();
            return sb.ToString();
        }

        private static string FormatMaybe(DateTime? dtUtc)
            => dtUtc.HasValue ? $"{dtUtc.Value:yyyy-MM-dd HH:mm:ss} UTC" : "n/a";

        private static int FindHeaderEnd(string text)
        {
            // Position after the second hash line of the header block
            const string hash = "##########################################";
            int first = text.IndexOf(hash, StringComparison.Ordinal);
            if (first < 0) return 0;
            int second = text.IndexOf(hash, first + hash.Length, StringComparison.Ordinal);
            if (second < 0) return text.Length;
            int afterSecond = text.IndexOf('\n', second);
            return afterSecond >= 0 ? afterSecond + 1 : text.Length;
        }
    }
}
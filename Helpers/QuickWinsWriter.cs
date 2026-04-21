using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Parser.Models;   // canonical ParsedBodyFile & BodyFileEntry — do not redefine here

namespace Helpers
{
    public static class QuickWinsWriter
    {
        private const string QuickWinsFileName = "QuickWins.txt";

        private static string QuickWinsPath(string outputDir)
            => Path.Combine(outputDir, QuickWinsFileName);

        /// <summary>
        /// Create header once, and place 'Timeline Coverage' right after the header block.
        /// Calling this repeatedly will NOT overwrite existing content.
        /// </summary>
        public static void EnsureHeader(string outputDir, DateTime generatedOnUtc,
            DateTime? firstLogUtc, DateTime? lastLogUtc)
        {
            Directory.CreateDirectory(outputDir);
            string path = QuickWinsPath(outputDir);

            if (File.Exists(path))
                return;

            var sb = new StringBuilder();
            sb.AppendLine("##########################################");
            sb.AppendLine("# Quick Wins - Global Summary");
            sb.AppendLine($"# Generated on {generatedOnUtc:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine("##########################################");
            sb.AppendLine("########## Timeline Coverage ##########");
            sb.AppendLine($"First Log Entry: {FormatMaybe(firstLogUtc)}");
            sb.AppendLine($"Last Log Entry:  {FormatMaybe(lastLogUtc)}");
            sb.AppendLine();

            File.WriteAllText(path, sb.ToString(),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }

        /// <summary>
        /// Append a titled section safely (append-only).
        /// </summary>
        public static void AppendSection(string outputDir, string title,
            IEnumerable<string> lines)
        {
            if (lines == null) return;
            var list = lines.Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
            if (list.Count == 0) return;

            Directory.CreateDirectory(outputDir);

            var sb = new StringBuilder();
            sb.AppendLine();
            sb.AppendLine($"########## {title} ##########");
            foreach (var line in list)
                sb.AppendLine(line);
            sb.AppendLine();

            File.AppendAllText(QuickWinsPath(outputDir), sb.ToString(),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }

        /// <summary>
        /// Convenience wrapper for BodyFile findings. Adds a [BODYFILE] tag per line.
        /// </summary>
        public static void AppendBodyFileFindings(string outputDir,
            IEnumerable<string> findings)
        {
            if (findings == null) return;

            var tagged = findings
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.StartsWith("[BODYFILE]", StringComparison.OrdinalIgnoreCase)
                    ? s : "[BODYFILE] " + s);

            AppendSection(outputDir, "BodyFile Findings", tagged);
        }

        /// <summary>
        /// Writes BodyFile rows to CSV. Epoch timestamps are converted to UTC ISO 8601.
        /// </summary>
        public static void WriteProcessedBodyFileCsv(string outputDir, ParsedBodyFile parsed)
        {
            if (parsed?.Entries == null || parsed.Entries.Count == 0) return;

            Directory.CreateDirectory(outputDir);
            string csvPath = Path.Combine(outputDir, "ProcessedBodyFile.csv");

            bool writeHeader = !File.Exists(csvPath);
            using var fs = new FileStream(csvPath, FileMode.Append, FileAccess.Write,
                FileShare.Read);
            using var sw = new StreamWriter(fs,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

            if (writeHeader)
                sw.WriteLine(
                    "Path,Size,Mode,UID,GID,MD5," +
                    "AccessTimeUtc,ModTimeUtc,ChangeTimeUtc,BirthTimeUtc");

            static string Esc(string s) =>
                s == null ? "" : "\"" + s.Replace("\"", "\"\"") + "\"";

            foreach (var e in parsed.Entries)
            {
                sw.WriteLine(string.Join(",",
                    Esc(e.Path),
                    e.Size.ToString(CultureInfo.InvariantCulture),
                    Esc(e.Mode),
                    Esc(e.UID),
                    Esc(e.GID),
                    Esc(e.MD5),
                    Esc(ToIsoUtc(e.AccessEpoch)),
                    Esc(ToIsoUtc(e.ModifyEpoch)),
                    Esc(ToIsoUtc(e.ChangeEpoch)),
                    Esc(ToIsoUtc(e.BirthEpoch))));
            }
        }

        // ── Helpers ──────────────────────────────────────────────────────

        private static string ToIsoUtc(long? epoch)
        {
            if (epoch is null or <= 0) return "";
            try
            {
                return DateTimeOffset.FromUnixTimeSeconds(epoch.Value).UtcDateTime
                    .ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
            }
            catch { return ""; }
        }

        private static string FormatMaybe(DateTime? dtUtc)
            => dtUtc.HasValue ? $"{dtUtc.Value:yyyy-MM-dd HH:mm:ss} UTC" : "n/a";
    }
}
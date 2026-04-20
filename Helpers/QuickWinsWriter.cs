using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace Helpers
{
    public static class QuickWinsWriter
    {
        private const string QuickWinsFileName = "QuickWins.txt";

        private static string QuickWinsPath(string outputDir)
            => Path.Combine(outputDir, QuickWinsFileName);

        /// <summary>
        /// Create header once (no canary), and place 'Timeline Coverage' right after the header block.
        /// Calling this repeatedly will NOT overwrite existing content.
        /// </summary>
        public static void EnsureHeader(string outputDir, DateTime generatedOnUtc, DateTime? firstLogUtc, DateTime? lastLogUtc)
        {
            Directory.CreateDirectory(outputDir);
            string path = QuickWinsPath(outputDir);

            if (File.Exists(path))
                return; // header already present, do not rewrite / overwrite

            var sb = new StringBuilder();
            sb.AppendLine("##########################################");
            sb.AppendLine("# Quick Wins - Global Summary");
            sb.AppendLine($"# Generated on {generatedOnUtc:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine("##########################################");
            sb.AppendLine("########## Timeline Coverage ##########");
            sb.AppendLine($"First Log Entry: {FormatMaybe(firstLogUtc)}");
            sb.AppendLine($"Last Log Entry:  {FormatMaybe(lastLogUtc)}");
            sb.AppendLine();

            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }

        /// <summary>
        /// Append a titled section safely (append-only).
        /// </summary>
        public static void AppendSection(string outputDir, string title, IEnumerable<string> lines)
        {
            if (lines == null) return;
            var list = lines.Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
            if (list.Count == 0) return;

            string path = QuickWinsPath(outputDir);
            Directory.CreateDirectory(outputDir);

            var sb = new StringBuilder();
            sb.AppendLine();
            sb.AppendLine($"########## {title} ##########");
            foreach (var line in list)
                sb.AppendLine(line);
            sb.AppendLine();

            File.AppendAllText(path, sb.ToString(), new UTF8Encoding(false));
        }

        /// <summary>
        /// Convenience wrapper for BodyFile findings. Adds a [BODYFILE] tag per line.
        /// </summary>
        public static void AppendBodyFileFindings(string outputDir, IEnumerable<string> findings)
        {
            if (findings == null) return;

            var tagged = findings
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.StartsWith("[BODYFILE]", StringComparison.OrdinalIgnoreCase) ? s : "[BODYFILE] " + s);

            AppendSection(outputDir, "BodyFile Findings", tagged);
        }

        /// <summary>
        /// Writes BodyFile rows to CSV next to QuickWins.txt. This is strictly the bodyfile->CSV export,
        /// NOT findings. Epoch timestamps are converted to UTC ISO 8601.
        /// </summary>
        public static void WriteProcessedBodyFileCsv(string outputDir, ParsedBodyFile parsed)
        {
            if (parsed == null || parsed.Entries == null || parsed.Entries.Count == 0) return;

            Directory.CreateDirectory(outputDir);
            string csvPath = Path.Combine(outputDir, "ProcessedBodyFile.csv");

            // Header on first write
            bool writeHeader = !File.Exists(csvPath);
            using var fs = new FileStream(csvPath, FileMode.Append, FileAccess.Write, FileShare.Read);
            using var sw = new StreamWriter(fs, new UTF8Encoding(false));

            if (writeHeader)
            {
                sw.WriteLine("Path,Size,Mode,UID,GID,MD5,AccessTimeUtc,ModTimeUtc,ChangeTimeUtc,BirthTimeUtc");
            }

            foreach (var e in parsed.Entries)
            {
                // Assuming typical bodyfile fields; adjust to your model names
                string a = ToIsoUtc(e.AccessEpoch);
                string m = ToIsoUtc(e.ModifyEpoch);
                string c = ToIsoUtc(e.ChangeEpoch);
                string b = ToIsoUtc(e.BirthEpoch);

                // Escape commas/quotes
                string esc(string s) => s == null ? "" :
                    "\"" + s.Replace("\"", "\"\"") + "\"";

                sw.WriteLine(string.Join(",",
                    esc(e.Path),
                    e.Size.ToString(CultureInfo.InvariantCulture),
                    esc(e.Mode),
                    esc(e.UID),
                    esc(e.GID),
                    esc(e.MD5),
                    esc(a),
                    esc(m),
                    esc(c),
                    esc(b)
                ));
            }
        }

        private static string ToIsoUtc(long? unixEpochSeconds)
        {
            if (unixEpochSeconds == null || unixEpochSeconds <= 0) return "";
            try
            {
                var dt = DateTimeOffset.FromUnixTimeSeconds(unixEpochSeconds.Value).UtcDateTime;
                return dt.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
            }
            catch
            {
                return "";
            }
        }

        private static string FormatMaybe(DateTime? dtUtc)
            => dtUtc.HasValue ? $"{dtUtc.Value:yyyy-MM-dd HH:mm:ss} UTC" : "n/a";
    }

    // Minimal model placeholder – use your actual one.
    public class ParsedBodyFile
    {
        public List<BodyFileEntry> Entries { get; set; } = new();
        public List<string> Findings { get; set; } = new();
        public DateTime? FirstLogUtc { get; set; }
        public DateTime? LastLogUtc { get; set; }
    }

    public class BodyFileEntry
    {
        public string Path { get; set; }
        public long Size { get; set; }
        public string Mode { get; set; }
        public string UID { get; set; }
        public string GID { get; set; }
        public string MD5 { get; set; }
        public long? AccessEpoch { get; set; }
        public long? ModifyEpoch { get; set; }
        public long? ChangeEpoch { get; set; }
        public long? BirthEpoch { get; set; }
    }
}

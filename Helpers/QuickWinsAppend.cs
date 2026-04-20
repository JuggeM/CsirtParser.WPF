using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Parser.Models;   // <- single source of truth for ParsedBodyFile & BodyFileEntry

namespace Helpers
{
    public static class QuickWinsAppend
    {
        private const string QuickWinsFileName = "QuickWins.txt";
        private static string QuickWinsPath(string outputDir) => Path.Combine(outputDir, QuickWinsFileName);

        /// <summary>
        /// Appends a titled section to QuickWins.txt (append-only).
        /// Skips if lines are null/empty after trimming.
        /// </summary>
        public static void AppendSection(string outputDir, string title, IEnumerable<string> lines)
        {
            if (lines == null) return;
            var list = lines.Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
            if (list.Count == 0) return;

            Directory.CreateDirectory(outputDir);
            string path = QuickWinsPath(outputDir);

            var sb = new StringBuilder();
            sb.AppendLine();
            sb.AppendLine($"########## {title} ##########");
            foreach (var line in list)
                sb.AppendLine(line);
            sb.AppendLine();

            File.AppendAllText(path, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        }

        /// <summary>
        /// Appends BodyFile findings as a dedicated section; each line is prefixed with [BODYFILE].
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
        /// Writes Bodyfile rows to CSV next to QuickWins.txt (append-only). Epochs are rendered as ISO UTC.
        /// The CSV contains ONLY bodyfile rows; it never includes findings.
        /// </summary>
        public static void WriteProcessedBodyFileCsv(string outputDir, ParsedBodyFile parsed)
        {
            if (parsed == null || parsed.Entries == null || parsed.Entries.Count == 0) return;

            Directory.CreateDirectory(outputDir);
            string csvPath = Path.Combine(outputDir, "ProcessedBodyFile.csv");

            bool writeHeader = !File.Exists(csvPath);
            using var fs = new FileStream(csvPath, FileMode.Append, FileAccess.Write, FileShare.Read);
            using var sw = new StreamWriter(fs, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

            if (writeHeader)
            {
                sw.WriteLine("Path,Size,Mode,UID,GID,MD5,AccessTimeUtc,ModTimeUtc,ChangeTimeUtc,BirthTimeUtc");
            }

            foreach (BodyFileEntry e in parsed.Entries)
            {
                string a = ToIsoUtc(e.AccessEpoch);
                string m = ToIsoUtc(e.ModifyEpoch);
                string c = ToIsoUtc(e.ChangeEpoch);
                string b = ToIsoUtc(e.BirthEpoch);

                static string Esc(string s) => s == null ? "" : "\"" + s.Replace("\"", "\"\"") + "\"";

                sw.WriteLine(string.Join(",",
                    Esc(e.Path),
                    e.Size.ToString(CultureInfo.InvariantCulture),
                    Esc(e.Mode),
                    Esc(e.UID),
                    Esc(e.GID),
                    Esc(e.MD5),
                    Esc(a),
                    Esc(m),
                    Esc(c),
                    Esc(b)
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
    }
}

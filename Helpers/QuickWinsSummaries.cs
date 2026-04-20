using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Parser.Models;

namespace Helpers
{
    public static class QuickWinsSummaries
    {
        /// <summary>
        /// Appends a compact per-log summary with a footer:
        /// "##### [LOG] Summary ..."  ...  "########## End of LOG Summary ##########"
        /// </summary>
        public static void AppendPerLogSummaries(
            string outputDir,
            Dictionary<string, List<string>> suspiciousLogs,
            Dictionary<string, Dictionary<string, int>> patternCountsByLog,
            Dictionary<string, (DateTime firstSeen, DateTime lastSeen)> firstLastSeenByLog,
            Dictionary<string, int> processedFileCountsByLog)
        {
            foreach (var logKey in processedFileCountsByLog.Keys.OrderBy(k => k))
            {
                processedFileCountsByLog.TryGetValue(logKey, out var fileCount);

                // Skip log types where no files were found — keeps the RTF clean
                if (fileCount == 0) continue;

                firstLastSeenByLog.TryGetValue(logKey, out var fl);

                string firstStr = IsValidTimestamp(fl.firstSeen) ? $"{fl.firstSeen:yyyy-MM-dd HH:mm:ss} UTC" : "n/a";
                string lastStr = IsValidTimestamp(fl.lastSeen) ? $"{fl.lastSeen:yyyy-MM-dd HH:mm:ss} UTC" : "n/a";

                int findingsCount = suspiciousLogs.TryGetValue(logKey, out var findings) && findings != null ? findings.Count : 0;

                var lines = new List<string>();

                // Header line (compact)
                lines.Add($"##### [{logKey}] Summary  Files: {fileCount}  First: {firstStr}  Last: {lastStr}  Findings: {findingsCount} #####");

                // Top patterns (up to 10)
                if (patternCountsByLog.TryGetValue(logKey, out var patterns) && patterns?.Count > 0)
                {
                    foreach (var kv in patterns.OrderByDescending(p => p.Value).Take(10))
                        lines.Add($"  PATTERN: {kv.Key}  x{kv.Value}");
                }

                // Footer line
                lines.Add($"########## End of {logKey} Summary ##########");

                // Write directly — no AppendSection wrapper so we don't get a
                // redundant "########## [AUTH.LOG] Summary ##########" outer header.
                string path = System.IO.Path.Combine(outputDir, "QuickWins.txt");
                System.IO.Directory.CreateDirectory(outputDir);
                var sb = new StringBuilder();
                sb.AppendLine();
                foreach (var line in lines)
                    sb.AppendLine(line);
                sb.AppendLine();
                System.IO.File.AppendAllText(path, sb.ToString(),
                    new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            }
        }

        private static bool IsValidTimestamp(DateTime dt)
        {
            if (dt == DateTime.MinValue || dt == DateTime.MaxValue) return false;
            if (dt.Year < 2000) return false;
            if (dt > DateTime.UtcNow.AddYears(1)) return false;
            return true;
        }
    }
}
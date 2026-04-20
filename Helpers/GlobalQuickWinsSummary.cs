using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Helpers
{
    public static class GlobalQuickWinsSummary
    {
        // Parser importance order — determines display order in the global section.
        // Parsers not in this list are sorted alphabetically after the known ones.
        private static readonly string[] ImportanceOrder =
        {
            "JOURNAL",
            "AUTH.LOG", "AUTH", "SECURE",
            "AUDIT",
            "WEB",
            "DOCKER",
            "SYSLOG",
            "MESSAGES",
            "CRON",
        };

        public static List<string> Build(
            Dictionary<string, List<string>> suspiciousLogs,
            Dictionary<string, Dictionary<string, int>> patternCountsByLog,
            Dictionary<string, (DateTime firstSeen, DateTime lastSeen)> firstLastSeenByLog,
            Dictionary<string, Dictionary<string, int>> interestingIPsByLog,
            Dictionary<string, int> processedFileCountsByLog,
            Dictionary<string, Dictionary<string, (DateTime firstSeen, DateTime lastSeen)>> perFileFirstLastSeenByLog)
        {
            var lines = new List<string>();

            // Sort by importance order, unknowns go alphabetically at the end
            var orderedKeys = processedFileCountsByLog.Keys
                .OrderBy(k =>
                {
                    int idx = Array.FindIndex(ImportanceOrder,
                        x => x.Equals(k, StringComparison.OrdinalIgnoreCase));
                    return idx >= 0 ? idx : ImportanceOrder.Length;
                })
                .ToList();

            foreach (var logKey in orderedKeys)
            {
                processedFileCountsByLog.TryGetValue(logKey, out var fileCount);

                // Skip log types where no files were found
                if (fileCount == 0) continue;

                firstLastSeenByLog.TryGetValue(logKey, out var fl);

                suspiciousLogs.TryGetValue(logKey, out var allFindings);
                var allList = allFindings ?? new List<string>();

                // Global section shows HIGH/CRITICAL/BRUTEFORCE only
                var highFindings = allList
                    .Where(IsHighSeverity)
                    .ToList();

                // Total suspicious count includes MEDIUM for the counter
                int suspiciousCount = allList.Count(IsActuallySuspicious);

                var firstStr = IsValidTs(fl.firstSeen)
                    ? $"{fl.firstSeen:yyyy-MM-dd HH:mm:ss} UTC" : "n/a";
                var lastStr = IsValidTs(fl.lastSeen)
                    ? $"{fl.lastSeen:yyyy-MM-dd HH:mm:ss} UTC" : "n/a";

                lines.Add($"[{logKey}]  Files: {fileCount}  |  First: {firstStr}  |  Last: {lastStr}  |  Suspicious: {suspiciousCount}");

                // Top pattern counts (max 5) — always shown for context
                if (patternCountsByLog.TryGetValue(logKey, out var patterns) && patterns?.Count > 0)
                    foreach (var kv in patterns.OrderByDescending(p => p.Value).Take(5))
                        lines.Add($"  PATTERN: {kv.Key}  x{kv.Value}");

                // Top source IPs (max 3)
                if (interestingIPsByLog.TryGetValue(logKey, out var ips) && ips?.Count > 0)
                    foreach (var ip in ips.OrderByDescending(i => i.Value).Take(3))
                        lines.Add($"  IP: {ip.Key}  x{ip.Value}");

                // HIGH findings only — max 5 per log in global view
                if (highFindings.Count > 0)
                {
                    foreach (var f in highFindings.Take(5))
                        lines.Add($"  >> {f}");
                    if (highFindings.Count > 5)
                        lines.Add($"  >> … {highFindings.Count - 5} more HIGH findings — see full QuickWins");
                }

                lines.Add(string.Empty);
            }

            if (lines.Count == 0)
                lines.Add("No notable findings from parsed logs.");

            return lines;
        }

        // HIGH severity only — for global display
        private static bool IsHighSeverity(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return false;
            return line.Contains("[HIGH]", StringComparison.OrdinalIgnoreCase)
                || line.Contains("[CRITICAL]", StringComparison.OrdinalIgnoreCase)
                || line.Contains("[BRUTEFORCE]", StringComparison.OrdinalIgnoreCase)
                || line.Contains("[SUSPICIOUS]", StringComparison.OrdinalIgnoreCase);
        }

        // Broader filter — used for the Suspicious count shown in the header line
        private static bool IsActuallySuspicious(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return false;
            if (line.StartsWith("#####")) return false;
            if (line.TrimStart().StartsWith("===")) return false;
            if (line.Contains("0 suspicious", StringComparison.OrdinalIgnoreCase)) return false;
            if (line.Contains("0 containers", StringComparison.OrdinalIgnoreCase)) return false;
            if (line.Contains("0 jobs", StringComparison.OrdinalIgnoreCase)) return false;
            if (line.Contains("non-log lines", StringComparison.OrdinalIgnoreCase)) return false;

            return line.Contains("[HIGH]", StringComparison.OrdinalIgnoreCase)
                || line.Contains("[CRITICAL]", StringComparison.OrdinalIgnoreCase)
                || line.Contains("[MEDIUM]", StringComparison.OrdinalIgnoreCase)
                || line.Contains("[BRUTEFORCE]", StringComparison.OrdinalIgnoreCase)
                || line.Contains("[SUSPICIOUS]", StringComparison.OrdinalIgnoreCase)
                || line.Contains("Brute-force", StringComparison.OrdinalIgnoreCase)
                || line.Contains("[ERROR]", StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsValidTs(DateTime dt)
        {
            if (dt == DateTime.MinValue || dt == DateTime.MaxValue) return false;
            if (dt.Year < 2000 || dt.Year > DateTime.UtcNow.Year + 1) return false;
            return true;
        }
    }
}
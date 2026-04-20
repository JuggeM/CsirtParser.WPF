using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Helpers
{
    public static class QuickWinsTidy
    {
        // Keep other tidy hooks as no-ops unless you already use them elsewhere.
        public static void GroupSuspiciousFindingsUniform(string outputDir) { }
        public static void CollapseVerboseSessions(string outputDir, int minRepeatToCollapse = 5) { }
        public static void CollapseSyslogDuplicates(string outputDir, int minRepeatToCollapse = 2) { }
        public static void CollapseMessagesDuplicates(string outputDir, int minRepeatToCollapse = 2) { }

        /// <summary>
        /// Collapse duplicate CRON suspicious-job findings into a single grouped line:
        ///   [CRON] Group: Suspicious cron job → N occurrence(s) [First: … | Last: …] | Example: <command>
        /// Also removes raw CRON lines and noisy "PATTERN: Suspicious cron job" counters.
        /// </summary>
        public static void CollapseCronDuplicates(string outputDir, int minRepeatToCollapse = 2)
        {
            var quickWinsPath = Path.Combine(outputDir, "QuickWins.txt");
            if (!File.Exists(quickWinsPath)) return;

            var lines = File.ReadAllLines(quickWinsPath).ToList();
            if (lines.Count == 0) return;

            // Timestamp patterns
            var isoTs = new Regex(@"\b(?<iso>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\b",
                                  RegexOptions.Compiled);
            var sysTs = new Regex(@"\b(?<sys>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b",
                                  RegexOptions.Compiled);

            // Raw CRON suspicious finding lines to collapse
            // Example: "FINDING: [CRON] [SUSPICIOUS] Suspicious cron job at 2025-02-01 02:00:01: Feb  1 02:00:01 ...CMD=..."
            var cronFinding = new Regex(@"^\s*FINDING:\s*\[CRON\].*?\bSuspicious cron job\b.*$",
                                        RegexOptions.Compiled | RegexOptions.IgnoreCase);

            // Noisy per-pattern count lines to remove
            var cronPatternLine = new Regex(@"^\s*PATTERN:\s*Suspicious cron job\b.*$",
                                            RegexOptions.Compiled | RegexOptions.IgnoreCase);

            // --- Helpers ---

            // Try to extract a representative command snippet from the line.
            static string ExtractCronCommand(string line)
            {
                if (string.IsNullOrWhiteSpace(line)) return string.Empty;

                // (root) CMD (some command)
                var paren = Regex.Match(line, @"\)\s*CMD\s*\((?<cmd>.+?)\)\s*$", RegexOptions.IgnoreCase);
                if (paren.Success) return paren.Groups["cmd"].Value.Trim();

                // CMD=...
                var cmdEq = Regex.Match(line, @"\bCMD\s*=\s*(?<cmd>.+?)\s*$", RegexOptions.IgnoreCase);
                if (cmdEq.Success) return cmdEq.Groups["cmd"].Value.Trim();

                // CMD: ...
                var cmdColon = Regex.Match(line, @"\bCMD\s*[:]\s*(?<cmd>.+?)\s*$", RegexOptions.IgnoreCase);
                if (cmdColon.Success) return cmdColon.Groups["cmd"].Value.Trim();

                // Fallback: take tail after last ':' unless it's obviously just a timestamp
                var lastColon = line.LastIndexOf(':');
                if (lastColon >= 0 && lastColon + 1 < line.Length)
                {
                    var tail = line[(lastColon + 1)..].Trim();
                    if (!Regex.IsMatch(tail, @"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$"))
                        return tail;
                }

                return string.Empty;
            }

            // Normalize the line to form a dedup key (remove timestamps, compress whitespace)
            string Normalize(string s)
            {
                if (string.IsNullOrEmpty(s)) return string.Empty;
                s = isoTs.Replace(s, "");
                s = sysTs.Replace(s, "");
                s = Regex.Replace(s, @"\bat\b\s*:\s*", " ", RegexOptions.IgnoreCase); // " at : " remnants
                s = Regex.Replace(s, @"\s{2,}", " ");
                return s.Trim();
            }

            // Prefer ISO timestamp (with year) for First/Last
            DateTime? ExtractIsoTimestampUtc(string s)
            {
                var m = isoTs.Match(s);
                if (!m.Success) return null;

                return DateTime.TryParseExact(
                           m.Groups["iso"].Value,
                           "yyyy-MM-dd HH:mm:ss",
                           CultureInfo.InvariantCulture,
                           DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                           out var dt)
                       ? dt
                       : null;
            }

            // Aggregation: key → (Count, First, Last, SampleCmd)
            var groups = new Dictionary<string, (int Count, DateTime? First, DateTime? Last, string SampleCmd)>(StringComparer.Ordinal);
            var matchedLineIndexes = new HashSet<int>();

            for (int i = 0; i < lines.Count; i++)
            {
                var line = lines[i];

                // Drop noisy counters
                if (cronPatternLine.IsMatch(line))
                {
                    matchedLineIndexes.Add(i);
                    continue;
                }

                if (!cronFinding.IsMatch(line)) continue;

                matchedLineIndexes.Add(i);

                var key = Normalize(line);
                var ts = ExtractIsoTimestampUtc(line);
                var cmd = ExtractCronCommand(line);

                if (!groups.TryGetValue(key, out var agg))
                    agg = (0, null, null, string.Empty);

                var newCount = agg.Count + 1;
                var first = agg.First;
                var last = agg.Last;
                var sampleCmd = string.IsNullOrEmpty(agg.SampleCmd) ? cmd : agg.SampleCmd;

                if (ts.HasValue)
                {
                    if (!first.HasValue || ts.Value < first.Value) first = ts.Value;
                    if (!last.HasValue || ts.Value > last.Value) last = ts.Value;
                }

                groups[key] = (newCount, first, last, sampleCmd);
            }

            if (groups.Count == 0) return;

            // Build collapsed section
            var collapsed = new List<string> { "########## [CRON] Suspicious Findings (Collapsed) ##########" };

            foreach (var kv in groups
                     .Where(k => k.Value.Count >= Math.Max(1, minRepeatToCollapse))
                     .OrderByDescending(k => k.Value.Count)
                     .ThenBy(k => k.Key))
            {
                // Human-friendly title: keep "Suspicious cron job …"
                string title = kv.Key;
                var titleMatch = Regex.Match(title, @"\[CRON\].*?(Suspicious cron job)(.*)$", RegexOptions.IgnoreCase);
                if (titleMatch.Success)
                {
                    title = "Suspicious cron job" + titleMatch.Groups[2].Value;
                    title = title.Replace(" :", ":").Trim();
                }

                string firstStr = kv.Value.First.HasValue ? kv.Value.First.Value.ToString("yyyy-MM-dd HH:mm:ss") + " UTC" : "n/a";
                string lastStr = kv.Value.Last.HasValue ? kv.Value.Last.Value.ToString("yyyy-MM-dd HH:mm:ss") + " UTC" : "n/a";
                string sample = string.IsNullOrWhiteSpace(kv.Value.SampleCmd) ? "n/a" : kv.Value.SampleCmd;

                collapsed.Add(
                    $"[CRON] Group: {title} → {kv.Value.Count} occurrence(s) [First: {firstStr} | Last: {lastStr}] | Example: {sample}"
                );
            }

            if (collapsed.Count == 1) return; // only header, nothing to add

            // Rebuild file: remove raw cron lines and append collapsed section
            var rebuilt = new List<string>(lines.Count);
            for (int i = 0; i < lines.Count; i++)
            {
                if (matchedLineIndexes.Contains(i)) continue; // drop raw CRON spam
                rebuilt.Add(lines[i]);
            }

            if (rebuilt.Count > 0 && !string.IsNullOrWhiteSpace(rebuilt[^1]))
                rebuilt.Add(string.Empty);

            rebuilt.AddRange(collapsed);
            rebuilt.Add(string.Empty);

            File.WriteAllLines(quickWinsPath, rebuilt);
        }
    }
}

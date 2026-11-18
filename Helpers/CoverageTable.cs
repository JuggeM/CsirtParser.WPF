using System;
using System.Collections.Generic;
using System.Linq;

namespace Helpers
{
    /// <summary>
    /// One line per source: was it there, what time range it covers, and how
    /// many findings of each severity it produced. Tells the analyst what was
    /// checked and — just as important — what evidence was NOT available.
    /// Replaces the old [GLOBAL] Summary, which repeated the findings.
    /// </summary>
    public static class CoverageTable
    {
        public sealed record SourceInfo(string Key, int Files, DateTime First, DateTime Last, bool TimesAreFileMtimes = false);

        // Display order — most telling sources first
        private static readonly string[] Order =
        {
            "AUTH.LOG", "SECURE", "JOURNAL", "AUDIT", "SYSLOG", "MESSAGES", "CRONTAB",
            "LIVE_RESPONSE", "BODYFILE", "BASH", "ZSH", "AIAGENT", "PYHISTORY", "DBHISTORY",
            "VIMINFO", "LESSHST", "WGETHSTS", "WEB", "DOCKER",
        };

        public static List<string> Build(
            IEnumerable<SourceInfo> sources,
            IEnumerable<string> expectedButMissing,
            IEnumerable<(string Source, string Finding)> findings)
        {
            var bySource = findings
                .GroupBy(f => f.Source, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key,
                              g => g.Select(f => KeyFindingsBuilder.Parse(f.Source, f.Finding).Rank).ToList(),
                              StringComparer.OrdinalIgnoreCase);

            var rows = sources.ToList();
            foreach (var missing in expectedButMissing)
                if (!rows.Any(r => r.Key.Equals(missing, StringComparison.OrdinalIgnoreCase)))
                    rows.Add(new SourceInfo(missing, 0, DateTime.MaxValue, DateTime.MinValue));

            int OrderOf(string k)
            {
                int i = Array.FindIndex(Order, o => o.Equals(k, StringComparison.OrdinalIgnoreCase));
                return i >= 0 ? i : Order.Length;
            }

            var lines = new List<string>
            {
                $"  {"Source",-14} {"Files",5}  {"Time range (UTC)",-35}  {"Crit",4} {"High",4} {"Med",4}  Status",
                $"  {new string('-', 14)} {new string('-', 5)}  {new string('-', 35)}  {new string('-', 4)} {new string('-', 4)} {new string('-', 4)}  {new string('-', 12)}",
            };

            foreach (var r in rows.OrderBy(r => r.Files == 0 ? 1 : 0).ThenBy(r => OrderOf(r.Key)).ThenBy(r => r.Key))
            {
                bySource.TryGetValue(r.Key, out var ranks);
                ranks ??= new List<int>();
                int crit = ranks.Count(x => x == 0), high = ranks.Count(x => x == 1), med = ranks.Count(x => x is 2 or 3);

                string range;
                if (r.Files == 0) range = "";
                else if (r.TimesAreFileMtimes) range = "(no log times — file mtimes)";
                else if (Valid(r.First) && Valid(r.Last)) range = $"{r.First:yyyy-MM-dd HH:mm} → {r.Last:yyyy-MM-dd HH:mm}";
                else range = "(no timestamps)";

                string status = r.Files == 0 ? "not found"
                              : crit + high > 0 ? "REVIEW"
                              : med > 0 ? "minor"
                              : "clean";

                lines.Add(r.Files == 0
                    ? $"  {r.Key,-14} {"-",5}  {range,-35}  {"",4} {"",4} {"",4}  {status}"
                    : $"  {r.Key,-14} {r.Files,5}  {range,-35}  {crit,4} {high,4} {med,4}  {status}");
            }
            return lines;
        }

        /// <summary>One compact line of pattern counts per source.</summary>
        public static List<string> BuildPatternCounts(Dictionary<string, Dictionary<string, int>> patternsBySource)
        {
            var lines = new List<string>();
            foreach (var kv in patternsBySource.Where(k => k.Value != null && k.Value.Count > 0).OrderBy(k => k.Key))
            {
                var parts = kv.Value.OrderByDescending(p => p.Value).Select(p => $"{p.Key} x{p.Value}");
                lines.Add($"  [{kv.Key}] {string.Join(", ", parts)}");
            }
            if (lines.Count == 0) lines.Add("  (none)");
            return lines;
        }

        private static bool Valid(DateTime d) =>
            d != DateTime.MinValue && d != DateTime.MaxValue && d.Year >= 2000 && d.Year <= DateTime.UtcNow.Year + 1;
    }
}

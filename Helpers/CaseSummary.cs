using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Helpers
{
    /// <summary>
    /// Case-level view across all collections in Processed\:
    ///   • per host: critical/high/medium counts and the top findings,
    ///   • IOCs seen on more than one host (the strongest link between hosts).
    ///
    /// Reads each collection's Findings.tsv (written by <see cref="WriteFindingsFile"/>)
    /// rather than in-memory state, so collections skipped as "already
    /// processed" are still included.
    /// </summary>
    public static class CaseSummary
    {
        public const string FindingsFileName = "Findings.tsv";
        public const string SummaryFileName = "CaseSummary.txt";
        private const int TopPerHost = 5;
        private const int MaxIocs = 40;

        // ── Per-collection findings file ─────────────────────────────────
        public static void WriteFindingsFile(string outputDir, string hostname, string collection,
                                             IEnumerable<(string Source, string Finding)> findings)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"# host={Clean(hostname)}\tcollection={Clean(collection)}\tgenerated={DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z");
            sb.AppendLine("Source\tSeverity\tTimeUtc\tFinding");
            foreach (var (src, raw) in findings)
            {
                var f = KeyFindingsBuilder.Parse(src, raw);
                sb.Append(Clean(src)).Append('\t')
                  .Append(f.Severity).Append('\t')
                  .Append(f.TimeUtc.HasValue ? f.TimeUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") : "").Append('\t')
                  .AppendLine(Clean(raw));
            }
            File.WriteAllText(Path.Combine(outputDir, FindingsFileName), sb.ToString(), new UTF8Encoding(false));
        }

        private static string Clean(string s) => (s ?? string.Empty).Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');

        private sealed record HostData(string Host, string Collection, List<(string Source, string Finding)> Findings, bool HasFile);

        // ── Case summary ─────────────────────────────────────────────────
        public static string? Write(string processedRoot, string caseName, string analyst)
        {
            if (!Directory.Exists(processedRoot)) return null;

            var hosts = new List<HostData>();
            foreach (var dir in Directory.GetDirectories(processedRoot).OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
            {
                var collection = Path.GetFileName(dir);
                var file = Path.Combine(dir, FindingsFileName);
                if (!File.Exists(file))
                {
                    if (File.Exists(Path.Combine(dir, "QuickWins.txt")) || File.Exists(Path.Combine(dir, ".processed")))
                        hosts.Add(new HostData("?", collection, new(), false));
                    continue;
                }

                string host = collection;
                var list = new List<(string, string)>();
                foreach (var line in File.ReadLines(file))
                {
                    if (line.StartsWith("# host="))
                    {
                        host = line.Substring(7).Split('\t')[0];
                        continue;
                    }
                    if (line.StartsWith("Source\t") || string.IsNullOrWhiteSpace(line)) continue;
                    var parts = line.Split('\t');
                    if (parts.Length >= 4) list.Add((parts[0], parts[3]));
                }
                hosts.Add(new HostData(host, collection, list, true));
            }
            if (hosts.Count == 0) return null;

            var sb = new StringBuilder();
            sb.AppendLine("##########################################");
            sb.AppendLine("# Case Summary — all collections");
            sb.AppendLine($"# Generated on {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            if (!string.IsNullOrWhiteSpace(caseName)) sb.AppendLine($"# Case: {caseName}");
            if (!string.IsNullOrWhiteSpace(analyst)) sb.AppendLine($"# Analyst: {analyst}");
            sb.AppendLine("##########################################");
            sb.AppendLine();

            // Hosts table, most severe first
            sb.AppendLine("########## HOSTS ##########");
            sb.AppendLine($"  {"Host",-16} {"Crit",4} {"High",4} {"Med",4}  Collection");
            sb.AppendLine($"  {new string('-', 16)} {new string('-', 4)} {new string('-', 4)} {new string('-', 4)}  {new string('-', 30)}");
            var ranked = hosts.Select(h =>
            {
                var r = h.Findings.Select(f => KeyFindingsBuilder.Parse(f.Source, f.Finding).Rank).ToList();
                return (h, crit: r.Count(x => x == 0), high: r.Count(x => x == 1), med: r.Count(x => x is 2 or 3));
            }).OrderByDescending(x => x.crit).ThenByDescending(x => x.high).ThenBy(x => x.h.Host).ToList();
            foreach (var (h, crit, high, med) in ranked)
                sb.AppendLine(h.HasFile
                    ? $"  {h.Host,-16} {crit,4} {high,4} {med,4}  {h.Collection}"
                    : $"  {h.Host,-16} {"?",4} {"?",4} {"?",4}  {h.Collection}  (processed by an older version — delete its folder in Processed\\ to include it)");
            sb.AppendLine();

            // IOCs across hosts
            var iocHosts = new Dictionary<(string Kind, string Value), (HashSet<string> Hosts, HashSet<string> Sources)>();
            foreach (var h in hosts.Where(h => h.HasFile))
                foreach (var kv in KeyFindingsBuilder.ExtractIocs(h.Findings))
                {
                    if (!iocHosts.TryGetValue(kv.Key, out var e))
                        iocHosts[kv.Key] = e = (new HashSet<string>(StringComparer.OrdinalIgnoreCase), new HashSet<string>());
                    e.Hosts.Add(h.Host);
                    e.Sources.UnionWith(kv.Value);
                }

            sb.AppendLine("########## IOCs ACROSS HOSTS ##########");
            if (iocHosts.Count == 0)
                sb.AppendLine("  No IOCs extracted.");
            else
            {
                int shared = iocHosts.Count(k => k.Value.Hosts.Count > 1);
                sb.AppendLine($"  {shared} IOC(s) seen on more than one host — likely the same actor or campaign.");
                foreach (var kv in iocHosts
                             .OrderByDescending(k => k.Value.Hosts.Count)
                             .ThenBy(k => KeyFindingsBuilder.IocKindOrder(k.Key.Kind))
                             .ThenBy(k => k.Key.Value, StringComparer.Ordinal)
                             .Take(MaxIocs))
                {
                    var hostList = string.Join(", ", kv.Value.Hosts.OrderBy(x => x));
                    sb.AppendLine($"  {kv.Key.Kind,-8} {kv.Key.Value,-40} {kv.Value.Hosts.Count} host(s): {hostList}");
                }
                if (iocHosts.Count > MaxIocs) sb.AppendLine($"  … {iocHosts.Count - MaxIocs} more");
            }
            sb.AppendLine();

            // Top findings per host
            sb.AppendLine("########## TOP FINDINGS PER HOST ##########");
            foreach (var (h, crit, high, _) in ranked.Where(x => x.h.HasFile))
            {
                sb.AppendLine($"  ── {h.Host} ({h.Collection}) — {crit} critical, {high} high");
                var top = h.Findings
                    .Select(f => KeyFindingsBuilder.Parse(f.Source, f.Finding))
                    .Where(f => f.Rank <= 1)
                    .GroupBy(f => f.Text)
                    .Select(g => g.First())
                    .OrderBy(f => f.Rank).ThenBy(f => f.TimeUtc ?? DateTime.MaxValue)
                    .Take(TopPerHost)
                    .ToList();
                if (top.Count == 0) sb.AppendLine("     No critical or high findings.");
                foreach (var f in top)
                {
                    var when = f.TimeUtc.HasValue ? f.TimeUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") : "(no time)          ";
                    var text = f.Text.Length > 150 ? f.Text.Substring(0, 147) + "..." : f.Text;
                    sb.AppendLine($"     {f.Severity,-8} {when}  [{f.Source}] {text}");
                }
                sb.AppendLine($"     → full detail: {h.Collection}\\QuickWins.txt");
                sb.AppendLine();
            }

            var path = Path.Combine(processedRoot, SummaryFileName);
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
            return path;
        }
    }
}

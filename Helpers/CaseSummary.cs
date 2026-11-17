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
                                             IEnumerable<(string Source, string Finding)> findings,
                                             IEnumerable<string>? hostIps = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"# host={Clean(hostname)}\tcollection={Clean(collection)}\tgenerated={DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z" +
                          $"\tips={string.Join(",", hostIps ?? Enumerable.Empty<string>())}");
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

        // Collections processed by an older version have no host name; use the collection name
        public static string HostLabel(HostData h) => h.Host == "?" ? h.Collection : h.Host;

        private static string Fit(string s, int max) => s.Length > max ? s.Substring(0, max - 1) + "…" : s;

        private static string Clean(string s) => (s ?? string.Empty).Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');

        public sealed record HostData(string Host, string Collection, List<(string Source, string Finding)> Findings, bool HasFile,
                                      List<string> Ips);

        /// <summary>One host's own IP seen in another case host's findings.</summary>
        public sealed record LateralLink(string From, string To, string Ip, KeyFindingsBuilder.Finding? Evidence);

        /// <summary>Every processed collection under <paramref name="processedRoot"/>, read from its Findings.tsv.</summary>
        public static List<HostData> LoadHosts(string processedRoot)
        {
            if (!Directory.Exists(processedRoot)) return new List<HostData>();
            var hosts = new List<HostData>();
            foreach (var dir in Directory.GetDirectories(processedRoot).OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
            {
                var collection = Path.GetFileName(dir);
                var file = Path.Combine(dir, FindingsFileName);
                if (!File.Exists(file))
                {
                    if (File.Exists(Path.Combine(dir, "QuickWins.txt")) || File.Exists(Path.Combine(dir, ".processed")))
                        hosts.Add(new HostData("?", collection, new(), false, new()));
                    continue;
                }

                string host = collection;
                var ips = new List<string>();
                var list = new List<(string, string)>();
                foreach (var line in File.ReadLines(file))
                {
                    if (line.StartsWith("# host="))
                    {
                        var fields = line.Substring(2).Split('\t');
                        host = fields[0].Substring(5);
                        var ipField = fields.FirstOrDefault(f => f.StartsWith("ips="));
                        if (ipField != null)
                            ips.AddRange(ipField.Substring(4).Split(',', StringSplitOptions.RemoveEmptyEntries));
                        continue;
                    }
                    if (line.StartsWith("Source\t") || string.IsNullOrWhiteSpace(line)) continue;
                    var parts = line.Split('\t');
                    if (parts.Length >= 4) list.Add((parts[0], parts[3]));
                }
                hosts.Add(new HostData(host, collection, list, true, ips));
            }
            return hosts;
        }

        // ── Case summary ─────────────────────────────────────────────────
        public static string? Write(string processedRoot, string caseName, string analyst)
        {
            if (!Directory.Exists(processedRoot)) return null;
            var hosts = LoadHosts(processedRoot);
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
            sb.AppendLine($"  {"Host",-16} {"IP",-18} {"Crit",4} {"High",4} {"Med",4}  Collection");
            sb.AppendLine($"  {new string('-', 16)} {new string('-', 18)} {new string('-', 4)} {new string('-', 4)} {new string('-', 4)}  {new string('-', 30)}");
            var ranked = hosts.Select(h =>
            {
                var r = h.Findings.Select(f => KeyFindingsBuilder.Parse(f.Source, f.Finding).Rank).ToList();
                return (h, crit: r.Count(x => x == 0), high: r.Count(x => x == 1), med: r.Count(x => x is 2 or 3));
            }).OrderByDescending(x => x.crit).ThenByDescending(x => x.high).ThenBy(x => x.h.Host).ToList();
            foreach (var (h, crit, high, med) in ranked)
            {
                var ipText = h.Ips.Count == 0 ? "?" : h.Ips[0] + (h.Ips.Count > 1 ? $" +{h.Ips.Count - 1}" : "");
                sb.AppendLine(h.HasFile
                    ? $"  {h.Host,-16} {ipText,-18} {crit,4} {high,4} {med,4}  {h.Collection}"
                    : $"  {h.Host,-16} {"?",-18} {"?",4} {"?",4} {"?",4}  {h.Collection}  (processed by an older version — delete its folder in Processed\\ to include it)");
            }
            sb.AppendLine();

            // Analyst IOC list (iocs.txt) hits: IOC × host
            var hitRows = hosts
                .Select(h => (Host: HostLabel(h), Rows: IocSearch.ReadHitsFile(Path.Combine(processedRoot, h.Collection))))
                .ToList();
            bool searched = hosts.Any(h => File.Exists(Path.Combine(processedRoot, h.Collection, IocSearch.HitsFileName)));
            if (searched)
            {
                sb.AppendLine("########## CASE IOC HITS (analyst IOC list, iocs.txt) ##########");
                var byIoc = hitRows
                    .SelectMany(x => x.Rows.Select(r => (x.Host, r)))
                    .GroupBy(x => (x.r.Kind, x.r.Value))
                    .Select(g => (g.Key.Kind, g.Key.Value,
                                  First: g.Where(x => x.r.First.HasValue).Select(x => x.r.First).Min(),
                                  PerHost: g.GroupBy(x => x.Host, StringComparer.OrdinalIgnoreCase)
                                            .ToDictionary(h => h.Key, h => h.Sum(x => x.r.Count), StringComparer.OrdinalIgnoreCase),
                                  Comment: g.Select(x => x.r.Comment).FirstOrDefault(c => !string.IsNullOrWhiteSpace(c)) ?? ""))
                    .OrderByDescending(x => x.PerHost.Count)
                    .ThenBy(x => x.First ?? DateTime.MaxValue)
                    .ToList();
                if (byIoc.Count == 0)
                    sb.AppendLine("  No case IOC was seen on any host.");
                else
                {
                    var hostCols = hitRows.Where(x => x.Rows.Count > 0 || hosts.Any(h => h.HasFile && HostLabel(h) == x.Host))
                        .Select(x => x.Host).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    sb.AppendLine($"  {byIoc.Count} case IOC(s) seen. Cells = hit count per host, · = not seen. First seen = earliest hit on any host.");
                    sb.AppendLine($"  {"Kind",-7} {"IOC",-36} {"First seen (UTC)",-19} " + string.Join(" ", hostCols.Select(c => Fit(c, 8).PadLeft(8))));
                    foreach (var r in byIoc)
                    {
                        var cells = hostCols.Select(c => (r.PerHost.TryGetValue(c, out var n) ? n.ToString() : "·").PadLeft(8));
                        var first = r.First?.ToString("yyyy-MM-dd HH:mm:ss") ?? "(no time)";
                        var comment = string.IsNullOrWhiteSpace(r.Comment) ? "" : $"   # {r.Comment}";
                        sb.AppendLine($"  {r.Kind,-7} {Fit(r.Value, 36),-36} {first,-19} {string.Join(" ", cells)}{comment}");
                    }
                }
                sb.AppendLine();
            }

            var ipOwner = IpOwners(hosts);
            var iocHosts = IocsAcrossHosts(hosts);
            var lateral = FindLateral(hosts, ipOwner, iocHosts);
            sb.AppendLine("########## LATERAL MOVEMENT (case hosts seen in other hosts' findings) ##########");
            if (lateral.Count == 0)
                sb.AppendLine("  None found — no host's own IP appears in another host's findings.");
            foreach (var (from, to, ip, src) in lateral)
            {
                var text = src == null ? "" : (src.Text.Length > 110 ? src.Text.Substring(0, 107) + "..." : src.Text);
                sb.AppendLine($"  {from,-12} → {to,-12} ({ip})  [{src?.Source}] {text}");
            }
            sb.AppendLine();

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
                    var note = kv.Key.Kind == "IP" && ipOwner.TryGetValue(kv.Key.Value, out var owner)
                        ? $"   ← this is host {owner} (internal / lateral movement)" : "";
                    sb.AppendLine($"  {kv.Key.Kind,-8} {kv.Key.Value,-40} {kv.Value.Hosts.Count} host(s): {hostList}{note}");
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
        /// <summary>Which case host owns which address. An "IOC" IP that is another
        /// host in this case points at lateral movement, not an outside actor.</summary>
        public static Dictionary<string, string> IpOwners(IEnumerable<HostData> hosts)
        {
            var ipOwner = new Dictionary<string, string>();
            foreach (var h in hosts)
                foreach (var ip in h.Ips)
                    ipOwner.TryAdd(ip, h.Host);
            return ipOwner;
        }

        /// <summary>IOC (kind, value) → hosts it was seen on and the sources it came from.</summary>
        public static Dictionary<(string Kind, string Value), (HashSet<string> Hosts, HashSet<string> Sources)> IocsAcrossHosts(
            IEnumerable<HostData> hosts)
        {
            var iocHosts = new Dictionary<(string Kind, string Value), (HashSet<string> Hosts, HashSet<string> Sources)>();
            foreach (var h in hosts.Where(h => h.HasFile))
                foreach (var kv in KeyFindingsBuilder.ExtractIocs(h.Findings))
                {
                    if (!iocHosts.TryGetValue(kv.Key, out var e))
                        iocHosts[kv.Key] = e = (new HashSet<string>(StringComparer.OrdinalIgnoreCase), new HashSet<string>());
                    e.Hosts.Add(h.Host);
                    e.Sources.UnionWith(kv.Value);
                }
            return iocHosts;
        }

        /// <summary>Case hosts whose own IP shows up in another host's findings, with the most severe finding as evidence.</summary>
        public static List<LateralLink> FindLateral(List<HostData> hosts, Dictionary<string, string> ipOwner,
            Dictionary<(string Kind, string Value), (HashSet<string> Hosts, HashSet<string> Sources)> iocHosts)
        {
            return iocHosts
                .Where(k => k.Key.Kind == "IP" && ipOwner.ContainsKey(k.Key.Value))
                .SelectMany(k => k.Value.Hosts
                    .Where(seenOn => !seenOn.Equals(ipOwner[k.Key.Value], StringComparison.OrdinalIgnoreCase))
                    .Select(seenOn => (From: seenOn, To: ipOwner[k.Key.Value], Ip: k.Key.Value)))
                .OrderBy(x => x.From).ThenBy(x => x.To)
                .Select(x => new LateralLink(x.From, x.To, x.Ip,
                    hosts.First(h => h.Host == x.From).Findings
                        .Where(f => f.Finding.Contains(x.Ip))
                        .Select(f => KeyFindingsBuilder.Parse(f.Source, f.Finding))
                        .OrderBy(f => f.Rank).FirstOrDefault()))
                .ToList();
        }
    }
}

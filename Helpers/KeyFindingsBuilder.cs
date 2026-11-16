using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Builds the analyst-facing top of QuickWins.txt from every parser's
    /// findings for one collection:
    ///   • a host/context line,
    ///   • KEY FINDINGS — the most severe findings across all sources, by severity then time,
    ///   • IOCs — IPs, URLs, temp-path files and accounts, with the sources each appears in.
    /// Works on the finding strings the parsers already emit
    /// ("[SRC] [SEVERITY] [yyyy-MM-dd HH:mm:ss UTC] text"), so parsers need no changes.
    /// </summary>
    public static class KeyFindingsBuilder
    {
        public const int MaxKeyFindings = 25;
        public const int MaxIocs = 25;

        private static readonly Regex SeverityRx = new(
            @"\[(CRITICAL|HIGH|BRUTEFORCE|MEDIUM|LATERAL|SUSPICIOUS|LOW)\]", RegexOptions.Compiled);
        private static readonly Regex TimestampRx = new(
            @"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", RegexOptions.Compiled);
        private static readonly Regex IpRx = new(
            @"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])", RegexOptions.Compiled);
        private static readonly Regex UrlRx = new(
            @"\b(?:https?|ftp)://[^\s'""|;)<>]+", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex TempFileRx = new(
            @"(?<![\w/.])/(?:tmp|dev/shm|var/tmp)/[^\s'""|;&>)<,]+", RegexOptions.Compiled);
        private static readonly Regex AccountRx = new(
            @"Account created: (?<u>[A-Za-z0-9._-]+)|new user: name=(?<u>[A-Za-z0-9._-]+)|User (?<u>[A-Za-z0-9._-]+) added to privileged group",
            RegexOptions.Compiled);

        public sealed record Finding(string Source, string Severity, int Rank, DateTime? TimeUtc, string Text);

        public static int RankOf(string sev) => sev switch
        {
            "CRITICAL" => 0,
            "HIGH" or "BRUTEFORCE" => 1,
            "MEDIUM" or "LATERAL" => 2,
            "SUSPICIOUS" => 3,
            _ => 4,
        };

        public static Finding Parse(string source, string raw)
        {
            var sevM = SeverityRx.Match(raw);
            var sev = sevM.Success ? sevM.Groups[1].Value : "INFO";
            if (sev == "BRUTEFORCE") sev = "HIGH";
            if (sev == "LATERAL") sev = "MEDIUM";

            DateTime? ts = null;
            var tsM = TimestampRx.Match(raw);
            if (tsM.Success && DateTime.TryParseExact(tsM.Groups[1].Value, "yyyy-MM-dd HH:mm:ss",
                    CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t))
                ts = t;

            return new Finding(SourceOf(source, raw), sev, RankOf(sev), ts, CleanText(raw));
        }

        /// <summary>
        /// Strips the leading "[SRC] [SEV] [timestamp]" tags (now shown as
        /// columns) and collapses whitespace; keeps tags that carry meaning
        /// such as "[sysupdate]" or "[sudo]".
        /// </summary>
        public static string CleanText(string raw)
        {
            var s = raw.Trim();
            s = Regex.Replace(s, @"^[A-Za-z0-9_.\-]+:\s+(?=\[)", "");             // "auth.log: [HIGH] ..." prefix
            s = Regex.Replace(s, @"^\[[A-Z0-9_.]+\]\s*", "");                      // [SOURCE]
            s = Regex.Replace(s, @"^\[(CRITICAL|HIGH|BRUTEFORCE|MEDIUM|LATERAL|SUSPICIOUS|LOW)\]\s*", "");
            s = Regex.Replace(s, @"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[^\]]*|no-timestamp|unknown)\]\s*", "");
            s = Regex.Replace(s, @"\s{2,}", " ");
            return s;
        }

        private static string SourceOf(string source, string raw)
        {
            var m = Regex.Match(raw.TrimStart(), @"^\[([A-Z0-9_.]+)\]");
            var s = m.Success ? m.Groups[1].Value : source;
            return s == "LIVE" ? "LIVE_RESPONSE" : s;
        }

        // ── Key findings ─────────────────────────────────────────────────
        public static List<string> BuildKeyFindings(IEnumerable<(string Source, string Finding)> all)
        {
            var parsed = all.Select(f => Parse(f.Source, f.Finding))
                            .Where(f => f.Rank <= 1)
                            .ToList();

            // Same event reported by two parsers → keep one, list both sources
            var grouped = parsed
                .GroupBy(f => NormalizeForDedup(f.Text))
                .Select(g =>
                {
                    var best = g.OrderBy(x => x.Rank).ThenBy(x => x.TimeUtc ?? DateTime.MaxValue).First();
                    var sources = string.Join(", ", g.Select(x => x.Source).Distinct());
                    return (best, sources);
                })
                .OrderBy(x => x.best.Rank)
                .ThenBy(x => x.best.TimeUtc ?? DateTime.MaxValue)
                .ToList();

            var lines = new List<string>();
            if (grouped.Count == 0)
            {
                lines.Add("  No CRITICAL or HIGH findings.");
                return lines;
            }

            int crit = parsed.Count(f => f.Rank == 0), high = parsed.Count(f => f.Rank == 1);
            lines.Add($"  {crit} critical, {high} high across {parsed.Select(p => p.Source).Distinct().Count()} source(s)" +
                      (grouped.Count > MaxKeyFindings ? $" — top {MaxKeyFindings} shown, rest in the sections below" : ""));
            lines.Add("");
            foreach (var (f, sources) in grouped.Take(MaxKeyFindings))
            {
                var when = f.TimeUtc.HasValue ? f.TimeUtc.Value.ToString("yyyy-MM-dd HH:mm:ss") : "(no time)          ";
                var text = f.Text.Length > 170 ? f.Text.Substring(0, 167) + "..." : f.Text;
                lines.Add($"  {f.Severity,-8} {when}  [{sources}] {text}");
            }
            return lines;
        }

        private static string NormalizeForDedup(string text)
        {
            var t = text.ToLowerInvariant();
            t = Regex.Replace(t, @"\|\s*(cmd|exe):.*$", "");     // journal adds CMD/EXE tails
            t = Regex.Replace(t, @"\s+", " ").Trim();
            return t;
        }

        // ── IOCs ─────────────────────────────────────────────────────────
        /// <summary>IOC (kind, value) → sources it appears in, from finding lines.</summary>
        public static Dictionary<(string Kind, string Value), HashSet<string>> ExtractIocs(
            IEnumerable<(string Source, string Finding)> all)
        {
            var iocs = new Dictionary<(string Kind, string Value), HashSet<string>>();

            void Add(string kind, string value, string src)
            {
                if (string.IsNullOrWhiteSpace(value)) return;
                var key = (kind, value);
                if (!iocs.TryGetValue(key, out var set)) iocs[key] = set = new HashSet<string>();
                set.Add(src);
            }

            foreach (var (source, raw) in all)
            {
                var f = Parse(source, raw);
                if (f.Rank > 3) continue;   // only from findings, not info lines

                // Include text of a decoded payload too ("→ decoded: ...")
                foreach (Match m in IpRx.Matches(raw))
                    if (!LiveResponseTriage.IsPrivateOrLocal(m.Value)) Add("IP", m.Value, f.Source);
                foreach (Match m in UrlRx.Matches(raw))
                    Add("URL", m.Value.TrimEnd('.', ',', ')'), f.Source);
                foreach (Match m in TempFileRx.Matches(raw))
                {
                    var v = m.Value.TrimEnd('.', ',', ')', '\'');
                    if (v.EndsWith("/")) continue;
                    Add("File", v, f.Source);
                }
                foreach (Match m in AccountRx.Matches(raw))
                    Add("Account", m.Groups["u"].Value, f.Source);
            }
            return iocs;
        }

        public static int IocKindOrder(string kind) => kind switch { "IP" => 0, "URL" => 1, "File" => 2, _ => 3 };

        public static List<string> BuildIocs(IEnumerable<(string Source, string Finding)> all,
                                             IEnumerable<string>? ownAddresses = null)
        {
            var iocs = ExtractIocs(all);
            // The host's own addresses are not indicators
            var own = new HashSet<string>(ownAddresses ?? Enumerable.Empty<string>());
            foreach (var key in iocs.Keys.Where(k => k.Kind == "IP" && own.Contains(k.Value)).ToList())
                iocs.Remove(key);
            var lines = new List<string>();
            if (iocs.Count == 0)
            {
                lines.Add("  No IOCs extracted from findings.");
                return lines;
            }

            lines.Add("  Values pulled from findings; more sources = stronger link. Verify before blocking.");
            lines.Add("");
            foreach (var kv in iocs
                         .OrderByDescending(k => k.Value.Count)
                         .ThenBy(k => IocKindOrder(k.Key.Kind))
                         .ThenBy(k => k.Key.Value, StringComparer.Ordinal)
                         .Take(MaxIocs))
            {
                var srcs = string.Join(", ", kv.Value.OrderBy(s => s));
                lines.Add($"  {kv.Key.Kind,-8} {kv.Key.Value,-42} {kv.Value.Count} source(s): {srcs}");
            }
            if (iocs.Count > MaxIocs)
                lines.Add($"  … {iocs.Count - MaxIocs} more");
            return lines;
        }

        // ── Context line ─────────────────────────────────────────────────
        public static List<string> BuildContext(string hostname, string collection, TimeSpan? hostOffset,
                                                string caseName, string analyst,
                                                IReadOnlyList<HostIpResolver.HostIp>? ips = null)
        {
            string tz = hostOffset.HasValue
                ? $"host UTC{(hostOffset.Value < TimeSpan.Zero ? "-" : "+")}{hostOffset.Value:hh\\:mm}, all times shown in UTC"
                : "host timezone UNKNOWN — log times are uncorrected host-local time";
            var lines = new List<string>
            {
                $"  Host:       {hostname}",
                $"  Collection: {collection}",
                ips == null || ips.Count == 0
                    ? "  IP:         unknown (no ip addr / ifconfig output in live_response)"
                    : $"  IP:         {string.Join(", ", ips.Select(i => i.ToString()))}" +
                      (ips.All(i => i.Source.Contains("configured")) ? "  [configured, not live]" : ""),
                $"  Timezone:   {tz}",
            };
            if (!string.IsNullOrWhiteSpace(caseName)) lines.Add($"  Case:       {caseName}");
            if (!string.IsNullOrWhiteSpace(analyst)) lines.Add($"  Analyst:    {analyst}");
            return lines;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Searches already-processed output for the case IOC list (iocs.txt), so
    /// new IOCs can be checked in seconds without re-parsing:
    ///   • Processed\&lt;collection&gt;\Normalized_*.csv  (every parsed log line)
    ///   • Processed\&lt;collection&gt;\ProcessedBodyFile.csv  (paths, MD5)
    ///   • the collection's raw live_response\ (ps, netstat, hashes …), when
    ///     still present under Decompressed\.
    /// Per collection it writes IocHits.tsv and a "CASE IOC HITS" section at
    /// the top of QuickWins.txt. CaseSummary.Write turns the hit files into a
    /// host × IOC table.
    ///
    /// Matching is exact on token boundaries: 1.2.3.4 does not hit 11.2.3.45,
    /// a domain also hits its subdomains, a CIDR hits every address inside it,
    /// /tmp/x does not hit /var/tmp/x.
    /// </summary>
    public static class IocSearch
    {
        public const string HitsFileName = "IocHits.tsv";
        public const string SectionTitle = "CASE IOC HITS (analyst IOC list, iocs.txt)";
        private const int MaxSamples = 3;
        private const long MaxRawFileBytes = 50L * 1024 * 1024;

        // Sources whose rows only have a file write time unless the file itself has timestamps
        private static readonly HashSet<string> UntimedSources = new(StringComparer.OrdinalIgnoreCase)
        {
            "CRONTAB", "BASH", "ZSH", "SH", "PYHISTORY", "LESSHST", "VIMINFO", "WGETHSTS", "DBHISTORY", "MYSQL", "PSQL"
        };

        public sealed class Hit
        {
            public CaseIoc Ioc = null!;
            public int Count;
            public DateTime? First, Last;
            public SortedSet<string> Sources = new(StringComparer.Ordinal);
            public List<string> Samples = new();

            public void Add(string source, DateTime? ts, string sample)
            {
                Count++;
                Sources.Add(source);
                if (ts.HasValue)
                {
                    if (First == null || ts < First) First = ts;
                    if (Last == null || ts > Last) Last = ts;
                }
                var s = $"[{source}{(ts.HasValue ? " " + ts.Value.ToString("yyyy-MM-dd HH:mm:ss") : "")}] {Shorten(sample, 150)}";
                if (Samples.Count < MaxSamples && !Samples.Contains(s)) Samples.Add(s);
            }
        }

        public sealed record CaseResult(int IocCount, int CollectionsSearched, int CollectionsWithHits,
                                        int IocsHit, List<string> HitValues);

        // ── Matcher ──────────────────────────────────────────────────────
        public sealed class Matcher
        {
            private static readonly Regex Ipv4Rx = new(@"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d|\.\d)", RegexOptions.Compiled);
            private static readonly Regex Ipv6Rx = new(@"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])", RegexOptions.Compiled);
            private static readonly Regex HexRx = new(@"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])", RegexOptions.Compiled);
            private static readonly Regex HostRx = new(@"(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,62}(?![A-Za-z0-9-])", RegexOptions.Compiled);

            private readonly Dictionary<string, CaseIoc> _ips = new(StringComparer.OrdinalIgnoreCase);
            private readonly List<(IPAddress Net, int Prefix, CaseIoc Ioc)> _cidrs = new();
            private readonly Dictionary<string, CaseIoc> _hashes = new(StringComparer.OrdinalIgnoreCase);
            private readonly Dictionary<string, CaseIoc> _domains = new(StringComparer.OrdinalIgnoreCase);
            private readonly List<CaseIoc> _substrings = new();   // URL, Email
            private readonly List<CaseIoc> _files = new();
            private readonly Regex? _users;
            private readonly Dictionary<string, CaseIoc> _userMap = new(StringComparer.Ordinal);
            private readonly bool _anyV6;

            public Matcher(IEnumerable<CaseIoc> iocs)
            {
                foreach (var i in iocs)
                {
                    switch (i.Kind)
                    {
                        case "IP":
                            _ips[i.Value] = i;
                            if (i.Value.Contains(':')) _anyV6 = true;
                            break;
                        case "CIDR":
                            var parts = i.Value.Split('/');
                            if (IPAddress.TryParse(parts[0], out var net) && int.TryParse(parts[1], out var p))
                            {
                                _cidrs.Add((net, p, i));
                                if (net.AddressFamily == AddressFamily.InterNetworkV6) _anyV6 = true;
                            }
                            break;
                        case "MD5": case "SHA1": case "SHA256": _hashes[i.Value] = i; break;
                        case "Domain": _domains[i.Value] = i; break;
                        case "URL": case "Email": _substrings.Add(i); break;
                        case "File": _files.Add(i); break;
                        case "User": _userMap[i.Value] = i; break;
                    }
                }
                if (_userMap.Count > 0)
                    _users = new Regex(@"(?<![A-Za-z0-9_.\-])(?:" +
                        string.Join("|", _userMap.Keys.OrderByDescending(k => k.Length).Select(Regex.Escape)) +
                        @")(?![A-Za-z0-9_\-])", RegexOptions.Compiled);
            }

            public bool IsEmpty => _ips.Count + _cidrs.Count + _hashes.Count + _domains.Count +
                                   _substrings.Count + _files.Count + _userMap.Count == 0;

            /// <summary>Distinct IOCs found in one line.</summary>
            public List<CaseIoc> Match(string line)
            {
                var found = new List<CaseIoc>();
                if (string.IsNullOrEmpty(line)) return found;
                void Add(CaseIoc i) { if (!found.Contains(i)) found.Add(i); }

                if (_ips.Count > 0 || _cidrs.Count > 0)
                {
                    foreach (Match m in Ipv4Rx.Matches(line))
                        CheckIp(m.Value, Add);
                    if (_anyV6 && line.Contains("::", StringComparison.Ordinal) || _anyV6 && line.Count(c => c == ':') >= 3)
                        foreach (Match m in Ipv6Rx.Matches(line))
                            if (m.Value.Count(c => c == ':') >= 2) CheckIp(m.Value, Add);
                }
                if (_hashes.Count > 0)
                    foreach (Match m in HexRx.Matches(line))
                        if (_hashes.TryGetValue(m.Value, out var h)) Add(h);
                if (_domains.Count > 0)
                    foreach (Match m in HostRx.Matches(line))
                    {
                        // host and each parent: a.b.evil.com → b.evil.com → evil.com
                        var host = m.Value;
                        while (true)
                        {
                            if (_domains.TryGetValue(host, out var d)) { Add(d); break; }
                            int dot = host.IndexOf('.');
                            if (dot < 0 || host.IndexOf('.', dot + 1) < 0) break;
                            host = host[(dot + 1)..];
                        }
                    }
                foreach (var s in _substrings)
                    if (line.Contains(s.Value, StringComparison.OrdinalIgnoreCase)) Add(s);
                foreach (var f in _files)
                    if (ContainsPath(line, f.Value)) Add(f);
                if (_users != null)
                    foreach (Match m in _users.Matches(line))
                        if (_userMap.TryGetValue(m.Value, out var u)) Add(u);
                return found;
            }

            private void CheckIp(string candidate, Action<CaseIoc> add)
            {
                if (!IPAddress.TryParse(candidate, out var ip)) return;
                if (_ips.TryGetValue(ip.ToString(), out var hit)) add(hit);
                foreach (var (net, prefix, ioc) in _cidrs)
                    if (InNetwork(ip, net, prefix)) add(ioc);
            }

            private static bool InNetwork(IPAddress ip, IPAddress net, int prefix)
            {
                if (ip.AddressFamily != net.AddressFamily) return false;
                var a = ip.GetAddressBytes();
                var b = net.GetAddressBytes();
                int full = prefix / 8, rem = prefix % 8;
                for (int i = 0; i < full; i++) if (a[i] != b[i]) return false;
                if (rem == 0) return true;
                int mask = 0xFF << (8 - rem) & 0xFF;
                return (a[full] & mask) == (b[full] & mask);
            }

            private static bool IsPathChar(char c) => char.IsLetterOrDigit(c) || c is '_' or '-' or '.';

            private static bool ContainsPath(string line, string value)
            {
                bool absolute = value.StartsWith("/");
                int idx = 0;
                while ((idx = line.IndexOf(value, idx, StringComparison.Ordinal)) >= 0)
                {
                    char before = idx > 0 ? line[idx - 1] : ' ';
                    int endPos = idx + value.Length;
                    char after = endPos < line.Length ? line[endPos] : ' ';
                    bool okBefore = absolute ? !IsPathChar(before) : (before == '/' || !IsPathChar(before));
                    bool okAfter = !IsPathChar(after) && after != '/';
                    if (okBefore && okAfter) return true;
                    idx = endPos;
                }
                return false;
            }
        }

        // ── Case-wide search ─────────────────────────────────────────────
        /// <summary>
        /// Searches every processed collection for the IOCs in &lt;case&gt;\iocs.txt.
        /// With an empty list, old hit files and sections are removed.
        /// </summary>
        public static CaseResult SearchCase(string caseFolder, string processedRoot, Action<string>? log = null)
        {
            var iocs = CaseIocs.Load(caseFolder);
            var matcher = new Matcher(iocs);
            int searched = 0, withHits = 0;
            var hitValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (!Directory.Exists(processedRoot)) return new CaseResult(iocs.Count, 0, 0, 0, new());

            foreach (var dir in Directory.GetDirectories(processedRoot).OrderBy(d => d, StringComparer.OrdinalIgnoreCase))
            {
                if (!File.Exists(Path.Combine(dir, "QuickWins.txt")) && !File.Exists(Path.Combine(dir, CaseSummary.FindingsFileName)))
                    continue;
                var collection = Path.GetFileName(dir);

                if (matcher.IsEmpty)
                {
                    TryDelete(Path.Combine(dir, HitsFileName));
                    QuickWinsHeader.RemoveSection(dir, SectionTitle);
                    continue;
                }

                searched++;
                var rawRoot = new[]
                {
                    Path.Combine(caseFolder, "Decompressed", collection),
                    Path.Combine(caseFolder, collection)
                }.FirstOrDefault(Directory.Exists);

                List<Hit> hits;
                try
                {
                    hits = SearchCollection(dir, rawRoot, matcher);
                    WriteHitsFile(dir, collection, iocs, hits);
                    QuickWinsHeader.InsertGlobalAfterTimeline(dir, SectionTitle, BuildSection(iocs, hits));
                }
                catch (Exception ex)
                {
                    log?.Invoke($"[WARN] IOC search [{collection}] failed: {ex.Message}");
                    continue;
                }
                if (hits.Count > 0) withHits++;
                foreach (var h in hits) hitValues.Add(h.Ioc.Value);

                log?.Invoke(hits.Count == 0
                    ? $"IOC search [{collection}]: no hits."
                    : $"IOC search [{collection}]: {hits.Count} IOC(s) hit — {string.Join(", ", hits.Take(5).Select(h => h.Ioc.Value))}{(hits.Count > 5 ? ", …" : "")}");
            }
            return new CaseResult(iocs.Count, searched, withHits, hitValues.Count, hitValues.OrderBy(v => v).ToList());
        }

        public static List<Hit> SearchCollection(string processedDir, string? rawRoot, Matcher matcher)
        {
            var hits = new Dictionary<CaseIoc, Hit>();
            void Record(CaseIoc ioc, string source, DateTime? ts, string sample)
            {
                if (!hits.TryGetValue(ioc, out var h)) hits[ioc] = h = new Hit { Ioc = ioc };
                h.Add(source, ts, sample);
            }

            // Normalized_*.csv: Timestamp,Hostname,LogType,Daemon,User,IP,Message,Severity,Raw
            foreach (var csv in Directory.EnumerateFiles(processedDir, "Normalized_*.csv"))
            {
                var fallbackSource = Path.GetFileNameWithoutExtension(csv).Substring("Normalized_".Length);
                bool header = true;
                string? firstTs = null;
                bool oneTimestamp = true;
                var fileHits = new List<(CaseIoc Ioc, string Src, DateTime? Ts, string Msg)>();
                foreach (var line in SafeLines(csv))
                {
                    if (header) { header = false; continue; }
                    int comma = line.IndexOf(',');
                    var rawTs = comma > 0 ? line.Substring(0, comma) : "";
                    if (firstTs == null) firstTs = rawTs;
                    else if (oneTimestamp && rawTs != firstTs) oneTimestamp = false;

                    var m = matcher.Match(line);
                    if (m.Count == 0) continue;
                    var f = SplitCsv(line);
                    DateTime? ts = f.Count > 0 && DateTime.TryParse(f[0], CultureInfo.InvariantCulture,
                        DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t) ? t : null;
                    var src = f.Count > 2 && !string.IsNullOrWhiteSpace(f[2]) ? f[2] : fallbackSource;
                    var msg = f.Count > 6 && !string.IsNullOrWhiteSpace(f[6]) ? f[6] : line;
                    foreach (var ioc in m) fileHits.Add((ioc, src, ts, msg));
                }
                // History files and crontabs carry no event time: every row gets the
                // file's write time, which would make "last seen" look like today.
                bool untimed = fileHits.Count > 0 &&
                    (fileHits[0].Src.Equals("CRONTAB", StringComparison.OrdinalIgnoreCase)
                     || oneTimestamp && UntimedSources.Contains(fileHits[0].Src));
                foreach (var h in fileHits) Record(h.Ioc, h.Src, untimed ? null : h.Ts, h.Msg);
            }

            // Body file: Path,Size,Mode,UID,GID,MD5,AccessTimeUtc,ModTimeUtc,ChangeTimeUtc,BirthTimeUtc
            var body = Path.Combine(processedDir, "ProcessedBodyFile.csv");
            if (File.Exists(body))
            {
                bool header = true;
                foreach (var line in SafeLines(body))
                {
                    if (header) { header = false; continue; }
                    var m = matcher.Match(line);
                    if (m.Count == 0) continue;
                    var f = SplitCsv(line);
                    DateTime? ts = f.Count > 7 && DateTime.TryParse(f[7].Replace(" UTC", ""), CultureInfo.InvariantCulture,
                        DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t) ? t : null;
                    var sample = f.Count > 5 ? $"{f[0]} (mode {f[2]}, uid {f[3]}{(f[5].Length > 0 ? ", md5 " + f[5] : "")}, mtime)" : line;
                    foreach (var ioc in m) Record(ioc, "BODYFILE", ts, sample);
                }
            }

            // Raw live response output
            if (rawRoot != null)
            {
                IEnumerable<string> lrDirs;
                try { lrDirs = Directory.EnumerateDirectories(rawRoot, "live_response", SearchOption.AllDirectories).ToList(); }
                catch { lrDirs = Enumerable.Empty<string>(); }
                foreach (var lr in lrDirs)
                {
                    IEnumerable<string> files;
                    try { files = Directory.EnumerateFiles(lr, "*", SearchOption.AllDirectories).ToList(); }
                    catch { continue; }
                    foreach (var file in files)
                    {
                        try { if (new FileInfo(file).Length > MaxRawFileBytes) continue; } catch { continue; }
                        var rel = Path.GetRelativePath(lr, file).Replace('\\', '/');
                        foreach (var line in SafeLines(file))
                        {
                            var m = matcher.Match(line);
                            foreach (var ioc in m) Record(ioc, "LIVE_RESPONSE", null, $"{rel}: {line.Trim()}");
                        }
                    }
                }
            }

            return hits.Values
                .OrderBy(h => Array.IndexOf(CaseIocs.KindOrder, h.Ioc.Kind))
                .ThenByDescending(h => h.Count)
                .ToList();
        }

        // ── Output ───────────────────────────────────────────────────────
        public static List<string> BuildSection(IReadOnlyList<CaseIoc> iocs, IReadOnlyList<Hit> hits)
        {
            var lines = new List<string>();
            if (hits.Count == 0)
            {
                lines.Add($"  None of the {iocs.Count} case IOC(s) were seen in this collection ({CaseIocs.Summary(iocs)}).");
                return lines;
            }
            lines.Add($"  {hits.Count} of {iocs.Count} case IOC(s) seen on this host — treat as CRITICAL until explained. Detail: {HitsFileName}");
            foreach (var h in hits)
            {
                var range = h.First == null ? "no time"
                    : h.First == h.Last ? $"{h.First:yyyy-MM-dd HH:mm:ss} UTC"
                    : $"{h.First:yyyy-MM-dd HH:mm:ss} → {h.Last:yyyy-MM-dd HH:mm:ss} UTC";
                var comment = string.IsNullOrWhiteSpace(h.Ioc.Comment) ? "" : $"   # {h.Ioc.Comment}";
                lines.Add($"  [CRITICAL] {h.Ioc.Kind,-7} {h.Ioc.Value,-40} {h.Count,5} hit(s)  {range}  in {string.Join(", ", h.Sources)}{comment}");
                foreach (var s in h.Samples)
                    lines.Add($"        e.g. {s}");
            }
            var notSeen = iocs.Where(i => hits.All(h => !ReferenceEquals(h.Ioc, i))).ToList();
            if (notSeen.Count > 0)
                lines.Add($"  Not seen ({notSeen.Count}): {string.Join(", ", notSeen.Take(15).Select(i => i.Value))}{(notSeen.Count > 15 ? ", …" : "")}");
            return lines;
        }

        private static void WriteHitsFile(string dir, string collection, IReadOnlyList<CaseIoc> iocs, IReadOnlyList<Hit> hits)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"# collection={Clean(collection)}\tsearched={DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z\tiocs={iocs.Count}");
            sb.AppendLine("Kind\tValue\tCount\tFirstUtc\tLastUtc\tSources\tComment\tSamples");
            foreach (var h in hits)
                sb.Append(h.Ioc.Kind).Append('\t').Append(Clean(h.Ioc.Value)).Append('\t').Append(h.Count).Append('\t')
                  .Append(h.First?.ToString("yyyy-MM-dd HH:mm:ss") ?? "").Append('\t')
                  .Append(h.Last?.ToString("yyyy-MM-dd HH:mm:ss") ?? "").Append('\t')
                  .Append(string.Join(",", h.Sources)).Append('\t')
                  .Append(Clean(h.Ioc.Comment)).Append('\t')
                  .AppendLine(Clean(string.Join(" ; ", h.Samples)));
            File.WriteAllText(Path.Combine(dir, HitsFileName), sb.ToString(), new UTF8Encoding(false));
        }

        public sealed record HitRow(string Kind, string Value, int Count, DateTime? First, DateTime? Last, string Sources, string Comment);

        public static List<HitRow> ReadHitsFile(string dir)
        {
            var rows = new List<HitRow>();
            var p = Path.Combine(dir, HitsFileName);
            if (!File.Exists(p)) return rows;
            foreach (var line in SafeLines(p))
            {
                if (line.StartsWith("#") || line.StartsWith("Kind\t") || string.IsNullOrWhiteSpace(line)) continue;
                var f = line.Split('\t');
                if (f.Length < 7) continue;
                rows.Add(new HitRow(f[0], f[1], int.TryParse(f[2], out var c) ? c : 0,
                    DateTime.TryParse(f[3], CultureInfo.InvariantCulture, DateTimeStyles.None, out var a) ? a : null,
                    DateTime.TryParse(f[4], CultureInfo.InvariantCulture, DateTimeStyles.None, out var b) ? b : null,
                    f[5], f[6]));
            }
            return rows;
        }

        // ── Discovered IOCs (pivot loop) ─────────────────────────────────
        /// <summary>
        /// Writes &lt;output folder&gt;\iocs_discovered.txt, next to CaseSummary.txt, so
        /// each output folder of a case keeps its own list: IOCs the parsers pulled from
        /// findings across all hosts that are not yet in iocs.txt and are not
        /// a case host's own address. Same format as iocs.txt, so the analyst
        /// can copy lines over (or use "Load discovered" in the IOC panel).
        /// </summary>
        public static int WriteDiscovered(string caseFolder, string processedRoot)
        {
            if (string.IsNullOrWhiteSpace(caseFolder) || !Directory.Exists(processedRoot)) return 0;
            var caseList = CaseIocs.Load(caseFolder);
            var known = new HashSet<string>(caseList.Select(i => i.Value), StringComparer.OrdinalIgnoreCase);
            var covered = new Matcher(caseList);   // e.g. an IP inside a listed CIDR, a path ending in a listed file
            var ownIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var found = new Dictionary<(string Kind, string Value), (SortedSet<string> Hosts, SortedSet<string> Sources)>();

            foreach (var dir in Directory.GetDirectories(processedRoot))
            {
                var file = Path.Combine(dir, CaseSummary.FindingsFileName);
                if (!File.Exists(file)) continue;
                string host = Path.GetFileName(dir);
                var list = new List<(string, string)>();
                foreach (var line in SafeLines(file))
                {
                    if (line.StartsWith("# host="))
                    {
                        var fields = line.Substring(2).Split('\t');
                        host = fields[0].Substring(5);
                        var ipField = fields.FirstOrDefault(f => f.StartsWith("ips="));
                        if (ipField != null)
                            foreach (var ip in ipField.Substring(4).Split(',', StringSplitOptions.RemoveEmptyEntries))
                                ownIps.Add(ip);
                        continue;
                    }
                    if (line.StartsWith("Source\t")) continue;
                    var parts = line.Split('\t');
                    if (parts.Length >= 4) list.Add((parts[0], parts[3]));
                }
                foreach (var kv in KeyFindingsBuilder.ExtractIocs(list))
                {
                    if (!found.TryGetValue(kv.Key, out var e))
                        found[kv.Key] = e = (new SortedSet<string>(StringComparer.OrdinalIgnoreCase), new SortedSet<string>());
                    e.Hosts.Add(host);
                    e.Sources.UnionWith(kv.Value);
                }
            }

            var rows = found
                .Where(kv => !known.Contains(kv.Key.Value) && covered.Match(kv.Key.Value).Count == 0)
                .Where(kv => !(kv.Key.Kind == "IP" && ownIps.Contains(kv.Key.Value)))
                .OrderByDescending(kv => kv.Value.Hosts.Count)
                .ThenByDescending(kv => kv.Value.Sources.Count)
                .ThenBy(kv => KeyFindingsBuilder.IocKindOrder(kv.Key.Kind))
                .ThenBy(kv => kv.Key.Value, StringComparer.Ordinal)
                .ToList();

            var sb = new StringBuilder();
            sb.AppendLine("# IOCs found by the parsers in this output folder that are NOT yet in the case IOC list (<case>\\iocs.txt).");
            sb.AppendLine("# Review, then copy the lines you trust into iocs.txt (or use \"Load discovered\" in the IOC panel)");
            sb.AppendLine("# and search again — that finds every other place the indicator shows up.");
            sb.AppendLine($"# Generated {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine();
            foreach (var kv in rows)
            {
                var value = kv.Key.Kind switch
                {
                    "Account" => "user:" + kv.Key.Value,
                    "File" when !kv.Key.Value.StartsWith("/") => "file:" + kv.Key.Value,
                    _ => kv.Key.Value
                };
                sb.AppendLine($"{value,-45}  # discovered: {kv.Value.Hosts.Count} host(s) {string.Join(",", kv.Value.Hosts)}; sources {string.Join(",", kv.Value.Sources)}");
            }
            File.WriteAllText(Path.Combine(processedRoot, CaseIocs.DiscoveredFileName), sb.ToString(), new UTF8Encoding(false));
            return rows.Count;
        }

        // ── Helpers ──────────────────────────────────────────────────────
        private static IEnumerable<string> SafeLines(string path)
        {
            IEnumerator<string>? e = null;
            try { e = File.ReadLines(path).GetEnumerator(); }
            catch { yield break; }
            using (e)
            {
                while (true)
                {
                    string line;
                    try { if (!e.MoveNext()) yield break; line = e.Current; }
                    catch { yield break; }
                    yield return line;
                }
            }
        }

        internal static List<string> SplitCsv(string line)
        {
            var fields = new List<string>();
            var sb = new StringBuilder();
            bool quoted = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (quoted)
                {
                    if (c == '"' && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else if (c == '"') quoted = false;
                    else sb.Append(c);
                }
                else if (c == '"') quoted = true;
                else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
                else sb.Append(c);
            }
            fields.Add(sb.ToString());
            return fields;
        }

        private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
        private static string Clean(string s) => (s ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
        private static string Shorten(string s, int max)
        {
            s = (s ?? "").Replace('\t', ' ').Trim();
            return s.Length > max ? s.Substring(0, max - 3) + "..." : s;
        }
    }
}

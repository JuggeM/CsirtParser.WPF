using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Helpers
{
    // ── Likelihood (PHIA probability yardstick) ─────────────────────────
    /// <summary>Estimative probability language, lowest to highest.</summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum Likelihood
    {
        RemoteChance,
        HighlyUnlikely,
        Unlikely,
        RealisticPossibility,
        Likely,
        HighlyLikely,
        AlmostCertain,
    }

    public sealed record LikelihoodOption(Likelihood Value, string Label);

    public static class LikelihoodScale
    {
        public static string Label(Likelihood l) => l switch
        {
            Likelihood.AlmostCertain => "Almost certain",
            Likelihood.HighlyLikely => "Highly likely",
            Likelihood.Likely => "Likely",
            Likelihood.RealisticPossibility => "Realistic possibility",
            Likelihood.Unlikely => "Unlikely",
            Likelihood.HighlyUnlikely => "Highly unlikely",
            _ => "Remote chance",
        };

        public static string Range(Likelihood l) => l switch
        {
            Likelihood.AlmostCertain => "≥95%",
            Likelihood.HighlyLikely => "80–90%",
            Likelihood.Likely => "55–75%",
            Likelihood.RealisticPossibility => "40–50%",
            Likelihood.Unlikely => "25–35%",
            Likelihood.HighlyUnlikely => "10–20%",
            _ => "≤5%",
        };

        /// <summary>Highest first, for pick lists.</summary>
        public static IReadOnlyList<LikelihoodOption> Options { get; } =
            Enum.GetValues<Likelihood>().Reverse().Select(l => new LikelihoodOption(l, Label(l))).ToList();
    }

    // ── Report model ───────────────────────────────────────────────────
    /// <summary>
    /// One key finding in the case report: a de-duplicated finding on one host,
    /// with an automatic likelihood the analyst can override.
    /// </summary>
    public sealed class ReportFinding : INotifyPropertyChanged
    {
        public string Id { get; init; } = "";
        public string Host { get; init; } = "";
        public string Collection { get; init; } = "";
        public IReadOnlyList<string> HostIps { get; init; } = Array.Empty<string>();
        public string Severity { get; init; } = "";
        public int Rank { get; init; }
        public DateTime? TimeUtc { get; init; }
        public string Text { get; init; } = "";
        /// <summary>Parsers that reported this same event.</summary>
        public IReadOnlyList<string> Sources { get; init; } = Array.Empty<string>();
        /// <summary>Other parsers on the same host that saw an indicator from this finding.</summary>
        public IReadOnlyList<string> CorroboratedBy { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> SharedIndicators { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> CaseIocMatches { get; init; } = Array.Empty<string>();
        /// <summary>Case host whose own IP appears in this finding (lateral movement).</summary>
        public string? LateralTo { get; init; }
        public Likelihood AutoLikelihood { get; init; }
        public bool AutoInclude { get; set; }
        public string Basis { get; init; } = "";

        public string SourceText => string.Join(", ", Sources);
        public string TimeText => TimeUtc?.ToString("yyyy-MM-dd HH:mm:ss") ?? "";
        public string Title => CaseReport.SplitTitle(Text).Title;
        public string Detail => CaseReport.SplitTitle(Text).Detail;

        private bool _include;
        public bool Include { get => _include; set => Set(ref _include, value); }

        private Likelihood _likelihood;
        public Likelihood Likelihood
        {
            get => _likelihood;
            set { if (Set(ref _likelihood, value)) OnChanged(nameof(IsAnalystAssessed)); }
        }

        private string _note = "";
        public string Note { get => _note; set => Set(ref _note, value ?? ""); }

        public bool IsAnalystAssessed => Likelihood != AutoLikelihood;

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnChanged(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        private bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
        {
            if (EqualityComparer<T>.Default.Equals(field, value)) return false;
            field = value;
            OnChanged(name!);
            return true;
        }
    }

    public sealed record ReportHost(string Host, string Collection, IReadOnlyList<string> Ips, bool HasFile,
                                    int Critical, int High, int Medium, DateTime? First, DateTime? Last);

    public sealed record ReportIoc(string Kind, string Value, IReadOnlyList<string> Hosts, string Detail,
                                   DateTime? FirstSeen, string Comment);

    public sealed class CaseReportData
    {
        public string CaseName { get; init; } = "";
        public string Analyst { get; init; } = "";
        public DateTime GeneratedUtc { get; init; } = DateTime.UtcNow;
        public List<ReportHost> Hosts { get; init; } = new();
        public List<ReportFinding> Findings { get; init; } = new();
        public List<CaseSummary.LateralLink> Lateral { get; init; } = new();
        /// <summary>Hits from the analyst's case IOC list (iocs.txt).</summary>
        public List<ReportIoc> CaseIocHits { get; init; } = new();
        public bool CaseIocsSearched { get; init; }
        /// <summary>Indicators extracted from findings on more than one host.</summary>
        public List<ReportIoc> SharedIocs { get; init; } = new();
        public List<string> AutoGaps { get; init; } = new();
    }

    // ── Analyst input, saved next to the processed output ──────────────
    public sealed class CaseReportNotes
    {
        public string Title { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Status { get; set; } = "";
        public string Bluf { get; set; } = "";
        public string Gaps { get; set; } = "";
        public string NextSteps { get; set; } = "";
        public Dictionary<string, FindingOverride> Findings { get; set; } = new();
    }

    public sealed class FindingOverride
    {
        public bool? Include { get; set; }
        public Likelihood? Likelihood { get; set; }
        public string? Note { get; set; }
    }

    /// <summary>
    /// Builds the analyst-facing case report from every collection's
    /// Findings.tsv (and IocHits.tsv), assigns each key finding an
    /// estimative likelihood, and renders it as a self-contained HTML page.
    ///
    /// Automatic likelihood = detection severity + independent corroboration
    /// on the same host + case IOC list match:
    ///   score = (CRITICAL 3 | HIGH 2 | MEDIUM 1) + (another source corroborates ? 1 : 0) + (IOC list hit ? 1 : 0)
    ///   1 → realistic possibility, 2 → likely, 3 → highly likely, ≥4 → almost certain.
    /// </summary>
    public static class CaseReport
    {
        public const string NotesFileName = "CaseReport.json";
        public const string HtmlFileName = "CaseReport.html";
        private const int MaxSharedIocs = 30;
        /// <summary>Findings per host ticked by default; the rest stay in the list for the analyst to add.</summary>
        private const int DefaultPerHost = 4;

        public static readonly string[] SeverityLevels = { "Critical", "High", "Medium", "Low" };
        public static readonly string[] StatusLevels = { "Active", "Contained", "Eradicated", "Recovering", "Closed" };

        // ── Build ────────────────────────────────────────────────────────
        public static CaseReportData Build(string processedRoot, string caseName, string analyst)
        {
            var hosts = CaseSummary.LoadHosts(processedRoot);
            var ipOwner = CaseSummary.IpOwners(hosts);
            var iocHosts = CaseSummary.IocsAcrossHosts(hosts);
            var lateral = CaseSummary.FindLateral(hosts, ipOwner, iocHosts);

            // Case IOC list hits per host
            var hitsByHost = hosts.ToDictionary(
                h => h.Collection,
                h => IocSearch.ReadHitsFile(Path.Combine(processedRoot, h.Collection)),
                StringComparer.OrdinalIgnoreCase);
            bool searched = hosts.Any(h => File.Exists(Path.Combine(processedRoot, h.Collection, IocSearch.HitsFileName)));

            var findings = new List<ReportFinding>();
            var reportHosts = new List<ReportHost>();
            foreach (var h in hosts)
            {
                var parsed = h.Findings.Select(f => (Raw: f.Finding, P: KeyFindingsBuilder.Parse(f.Source, f.Finding))).ToList();
                var timed = parsed.Where(x => x.P.Rank <= 2 && x.P.TimeUtc.HasValue).Select(x => x.P.TimeUtc!.Value).ToList();
                reportHosts.Add(new ReportHost(CaseSummary.HostLabel(h), h.Collection, h.Ips, h.HasFile,
                    parsed.Count(x => x.P.Rank == 0), parsed.Count(x => x.P.Rank == 1), parsed.Count(x => x.P.Rank == 2),
                    timed.Count > 0 ? timed.Min() : null, timed.Count > 0 ? timed.Max() : null));
                if (!h.HasFile) continue;

                // Indicator → sources that mention it, on this host
                var hostIndex = KeyFindingsBuilder.ExtractIocs(h.Findings);
                foreach (var ip in h.Ips) hostIndex.Remove(("IP", ip));
                var hits = hitsByHost[h.Collection];

                foreach (var g in parsed.Where(x => x.P.Rank <= 2)
                                        .GroupBy(x => KeyFindingsBuilder.NormalizeForDedup(x.P.Text)))
                {
                    var best = g.OrderBy(x => x.P.Rank).ThenBy(x => x.P.TimeUtc ?? DateTime.MaxValue).First();
                    var sources = g.Select(x => x.P.Source).Distinct().OrderBy(s => s).ToList();
                    var raws = g.Select(x => x.Raw).ToList();

                    var own = KeyFindingsBuilder.ExtractIocs(g.Select(x => (x.P.Source, x.Raw)))
                        .Keys.Where(k => hostIndex.ContainsKey(k)).ToList();
                    var corroborating = own.SelectMany(k => hostIndex[k]).Distinct()
                        .Where(s => !sources.Contains(s)).OrderBy(s => s).ToList();
                    var shared = own.Where(k => hostIndex[k].Any(s => !sources.Contains(s)))
                        .Select(k => k.Value).Distinct().Take(3).ToList();
                    var iocMatches = hits
                        .Where(r => raws.Any(raw => raw.Contains(r.Value, StringComparison.OrdinalIgnoreCase)))
                        .Select(r => r.Value).Distinct().ToList();
                    var lateralTo = ipOwner
                        .Where(kv => !kv.Value.Equals(h.Host, StringComparison.OrdinalIgnoreCase)
                                     && raws.Any(raw => ContainsIp(raw, kv.Key)))
                        .Select(kv => kv.Value).FirstOrDefault();

                    int score = (3 - best.P.Rank) + (corroborating.Count > 0 ? 1 : 0) + (iocMatches.Count > 0 ? 1 : 0);
                    var auto = score switch
                    {
                        >= 4 => Likelihood.AlmostCertain,
                        3 => Likelihood.HighlyLikely,
                        2 => Likelihood.Likely,
                        _ => Likelihood.RealisticPossibility,
                    };

                    var basis = new List<string> { $"{best.P.Severity} detection in {string.Join(", ", sources)}" };
                    basis.Add(corroborating.Count > 0
                        ? $"corroborated by {string.Join(", ", corroborating)} on the same host (shared {string.Join(", ", shared)})"
                        : "no independent source on this host");
                    if (iocMatches.Count > 0) basis.Add($"matches case IOC list ({string.Join(", ", iocMatches.Take(3))})");
                    if (lateralTo != null) basis.Add($"references case host {lateralTo}");

                    findings.Add(new ReportFinding
                    {
                        Id = StableId(h.Collection, KeyFindingsBuilder.NormalizeForDedup(best.P.Text)),
                        Host = CaseSummary.HostLabel(h),
                        Collection = h.Collection,
                        HostIps = h.Ips,
                        Severity = best.P.Severity,
                        Rank = best.P.Rank,
                        TimeUtc = best.P.TimeUtc,
                        Text = best.P.Text,
                        Sources = sources,
                        CorroboratedBy = corroborating,
                        SharedIndicators = shared,
                        CaseIocMatches = iocMatches,
                        LateralTo = lateralTo,
                        AutoLikelihood = auto,
                        Basis = string.Join("; ", basis),
                        Likelihood = auto,
                    });
                }
            }

            // Default selection: the strongest few per host, plus anything linking case hosts
            var picked = findings
                .Where(f => f.Rank <= 1)
                .GroupBy(f => f.Collection)
                .SelectMany(g => g.OrderByDescending(f => f.AutoLikelihood).ThenBy(f => f.Rank)
                                  .ThenBy(f => f.TimeUtc ?? DateTime.MaxValue).Take(DefaultPerHost))
                .Concat(findings.Where(f => f.LateralTo != null && f.Rank <= 2))
                .Select(f => f.Id).ToHashSet();
            foreach (var f in findings) { f.AutoInclude = picked.Contains(f.Id); f.Include = f.AutoInclude; }
            findings = findings
                .OrderByDescending(f => f.AutoLikelihood)
                .ThenBy(f => f.Rank)
                .ThenBy(f => f.TimeUtc ?? DateTime.MaxValue)
                .ToList();

            // Case IOC list hits, IOC × host
            var caseIocs = hosts
                .SelectMany(h => hitsByHost[h.Collection].Select(r => (Host: CaseSummary.HostLabel(h), r)))
                .GroupBy(x => (x.r.Kind, x.r.Value))
                .Select(g => new ReportIoc(g.Key.Kind, g.Key.Value,
                    g.Select(x => x.Host).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x).ToList(),
                    $"{g.Sum(x => x.r.Count)} hit(s) in " + string.Join(", ", g.Select(x => x.r.Sources)
                        .SelectMany(s => s.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        .Distinct().OrderBy(s => s)),
                    g.Where(x => x.r.First.HasValue).Select(x => x.r.First).Min(),
                    g.Select(x => x.r.Comment).FirstOrDefault(c => !string.IsNullOrWhiteSpace(c)) ?? ""))
                .OrderByDescending(i => i.Hosts.Count).ThenBy(i => i.FirstSeen ?? DateTime.MaxValue)
                .ToList();

            var sharedIocs = iocHosts
                .Where(k => k.Value.Hosts.Count > 1)
                .OrderByDescending(k => k.Value.Hosts.Count)
                .ThenBy(k => KeyFindingsBuilder.IocKindOrder(k.Key.Kind))
                .ThenBy(k => k.Key.Value, StringComparer.Ordinal)
                .Take(MaxSharedIocs)
                .Select(k => new ReportIoc(k.Key.Kind, k.Key.Value, k.Value.Hosts.OrderBy(x => x).ToList(),
                    (k.Key.Kind == "IP" && ipOwner.TryGetValue(k.Key.Value, out var owner) ? $"Case host {owner}. " : "") +
                    "Seen in " + string.Join(", ", k.Value.Sources.OrderBy(s => s)), null, ""))
                .ToList();

            // Gaps the data itself shows
            var gaps = new List<string>();
            foreach (var h in reportHosts.Where(h => !h.HasFile))
                gaps.Add($"{h.Collection} was processed by an older version and is not in this report. Delete its folder in Processed\\ and run the parser again.");
            foreach (var h in reportHosts.Where(h => h.HasFile && h.Ips.Count == 0))
                gaps.Add($"IP address of {h.Host} is unknown (no ip/ifconfig output in live_response), so lateral movement to or from it can't be matched.");
            int untimed = findings.Count(f => f.Include && !f.TimeUtc.HasValue);
            if (untimed > 0)
                gaps.Add($"{untimed} key finding(s) have no timestamp (for example crontab entries) and are missing from the timeline. When were they created?");
            if (!searched)
                gaps.Add("No case IOC list has been searched. Add known indicators in the IOC panel to raise or lower confidence.");

            return new CaseReportData
            {
                CaseName = caseName,
                Analyst = analyst,
                GeneratedUtc = DateTime.UtcNow,
                Hosts = reportHosts
                    .OrderByDescending(h => h.Critical).ThenByDescending(h => h.High).ThenBy(h => h.Host).ToList(),
                Findings = findings,
                Lateral = lateral,
                CaseIocHits = caseIocs,
                CaseIocsSearched = searched,
                SharedIocs = sharedIocs,
                AutoGaps = gaps,
            };
        }

        private static bool ContainsIp(string text, string ip)
        {
            int i = 0;
            while ((i = text.IndexOf(ip, i, StringComparison.Ordinal)) >= 0)
            {
                bool before = i == 0 || !(char.IsDigit(text[i - 1]) || text[i - 1] == '.');
                int end = i + ip.Length;
                bool after = end >= text.Length || !(char.IsDigit(text[end]) || (text[end] == '.' && end + 1 < text.Length && char.IsDigit(text[end + 1])));
                if (before && after) return true;
                i = end;
            }
            return false;
        }

        private static string StableId(string collection, string text)
        {
            var bytes = SHA1.HashData(Encoding.UTF8.GetBytes(collection.ToLowerInvariant() + "|" + text));
            return Convert.ToHexString(bytes, 0, 6).ToLowerInvariant();
        }

        /// <summary>Splits "Webshell POST from x: 1 request(s) | e.g. ..." into a headline and the rest.</summary>
        public static (string Title, string Detail) SplitTitle(string text)
        {
            var cut = text.IndexOf(" | ", StringComparison.Ordinal);
            var title = cut > 0 ? text.Substring(0, cut) : text;
            var detail = cut > 0 ? text.Substring(cut + 3) : "";
            if (title.Length > 160)
            {
                detail = title.Substring(157) + (detail.Length > 0 ? " | " + detail : "");
                title = title.Substring(0, 157) + "…";
            }
            return (title, detail);
        }

        // ── Notes ────────────────────────────────────────────────────────
        public static CaseReportNotes LoadNotes(string processedRoot)
        {
            var p = Path.Combine(processedRoot, NotesFileName);
            try
            {
                if (File.Exists(p))
                    return JsonConvert.DeserializeObject<CaseReportNotes>(File.ReadAllText(p)) ?? new CaseReportNotes();
            }
            catch { /* unreadable notes: start fresh rather than fail the view */ }
            return new CaseReportNotes();
        }

        public static void SaveNotes(string processedRoot, CaseReportNotes notes)
        {
            Directory.CreateDirectory(processedRoot);
            File.WriteAllText(Path.Combine(processedRoot, NotesFileName),
                JsonConvert.SerializeObject(notes, Formatting.Indented), new UTF8Encoding(false));
        }

        public static void ApplyNotes(CaseReportData data, CaseReportNotes notes)
        {
            foreach (var f in data.Findings)
            {
                if (!notes.Findings.TryGetValue(f.Id, out var o)) continue;
                if (o.Include.HasValue) f.Include = o.Include.Value;
                if (o.Likelihood.HasValue) f.Likelihood = o.Likelihood.Value;
                if (!string.IsNullOrEmpty(o.Note)) f.Note = o.Note;
            }
        }

        /// <summary>Stores only what the analyst changed, so a re-run can still move the automatic values.</summary>
        public static void CaptureOverrides(CaseReportData data, CaseReportNotes notes)
        {
            foreach (var f in data.Findings)
            {
                var o = new FindingOverride
                {
                    Include = f.Include != f.AutoInclude ? f.Include : null,
                    Likelihood = f.Likelihood != f.AutoLikelihood ? f.Likelihood : null,
                    Note = string.IsNullOrWhiteSpace(f.Note) ? null : f.Note.Trim(),
                };
                if (o.Include == null && o.Likelihood == null && o.Note == null) notes.Findings.Remove(f.Id);
                else notes.Findings[f.Id] = o;
            }
        }

        public static string SuggestSeverity(CaseReportData data)
        {
            var inc = data.Findings.Where(f => f.Include).ToList();
            if (inc.Any(f => f.Rank == 0 && f.Likelihood >= Likelihood.HighlyLikely) || data.Lateral.Count > 0) return "Critical";
            if (inc.Any(f => f.Rank <= 1 && f.Likelihood >= Likelihood.Likely)) return "High";
            if (inc.Count > 0) return "Medium";
            return "Low";
        }

        public static string SuggestTitle(CaseReportData data)
        {
            var top = data.Findings.Where(f => f.Include).OrderByDescending(f => f.Likelihood).ThenBy(f => f.Rank).FirstOrDefault();
            if (top == null) return string.IsNullOrWhiteSpace(data.CaseName) ? "Case report" : data.CaseName;
            var affected = data.Findings.Where(f => f.Include).Select(f => f.Host).Distinct().Count();
            return $"{Headline(top.Text, 70)} on {top.Host}" +
                   (affected > 1 ? $" and {affected - 1} other host{(affected > 2 ? "s" : "")}" : "");
        }

        /// <summary>A first draft of the bottom line, in estimative language, for the analyst to edit.</summary>
        public static string DraftBluf(CaseReportData data)
        {
            var inc = data.Findings.Where(f => f.Include).ToList();
            if (inc.Count == 0)
                return "No key findings are included. Based on the collected evidence, malicious activity is unlikely, but coverage gaps below may hide it.";

            var sb = new StringBuilder();
            var byHost = inc.GroupBy(f => f.Host)
                .OrderByDescending(g => g.Max(f => f.Likelihood)).ThenBy(g => g.Min(f => f.TimeUtc ?? DateTime.MaxValue));
            int hostsWithFindings = byHost.Count();
            sb.Append($"Malicious activity was found on {hostsWithFindings} of {data.Hosts.Count} host(s). ");

            // Hosts whose strongest finding reads the same are reported together
            var lines = byHost
                .Select(g =>
                {
                    var top = g.OrderByDescending(f => f.Likelihood).ThenBy(f => f.Rank).ThenBy(f => f.TimeUtc ?? DateTime.MaxValue).First();
                    var first = g.Where(f => f.TimeUtc.HasValue).Select(f => (DateTime?)f.TimeUtc!.Value).Min();
                    return (Host: g.Key, Top: top, First: first);
                })
                .GroupBy(x => (x.Top.Likelihood, Head: Headline(x.Top.Text, 110)))
                .ToList();
            foreach (var g in lines.Take(4))
            {
                var hostsText = JoinAnd(g.Select(x => x.Host).ToList());
                var what = g.Count() == 1 ? Shorten(SplitTitle(g.First().Top.Text).Title, 140) : g.Key.Head;
                var first = g.Where(x => x.First.HasValue).Select(x => x.First!.Value).DefaultIfEmpty().Min();
                sb.Append($"{LikelihoodScale.Label(g.Key.Likelihood)}: {LowerFirst(what)} on {hostsText}");
                sb.Append(first != default ? $" (earliest activity {first:yyyy-MM-dd HH:mm} UTC). " : ". ");
            }
            if (lines.Count > 4) sb.Append($"{lines.Skip(4).Sum(g => g.Count())} more host(s) have findings. ");

            if (data.Lateral.Count > 0)
            {
                var links = data.Lateral.Select(l => $"{l.From} → {l.To}").Distinct().Take(4);
                sb.Append($"Lateral movement between case hosts is likely ({string.Join(", ", links)}). ");
            }
            if (data.CaseIocHits.Count > 0)
            {
                var multi = data.CaseIocHits.Count(i => i.Hosts.Count > 1);
                sb.Append($"{data.CaseIocHits.Count} indicator(s) from the case IOC list were seen" +
                          (multi > 0 ? $", {multi} of them on more than one host, which highly likely points to the same actor. " : ". "));
            }
            else if (data.SharedIocs.Count > 0)
            {
                sb.Append($"{data.SharedIocs.Count} indicator(s) appear on more than one host, so a single actor or campaign is likely. ");
            }
            sb.Append("Data exfiltration has not been assessed.");
            return sb.ToString().Trim();
        }

        private static string Shorten(string s, int max)
        {
            if (s.Length <= max) return s;
            var cut = s.LastIndexOf(' ', max - 1);
            return (cut > max / 2 ? s.Substring(0, cut) : s.Substring(0, max - 1)).TrimEnd(' ', ',', ';', ':') + "…";
        }

        /// <summary>The part before the first ": " ("Web login brute force succeeded") when that reads as a headline.</summary>
        private static string Headline(string text, int max)
        {
            var t = SplitTitle(text).Title;
            var colon = t.IndexOf(": ", StringComparison.Ordinal);
            if (colon >= 12 && colon <= max && !t.StartsWith("[")) return t.Substring(0, colon);
            return Shorten(t, max);
        }

        // "Webshell POST" → "webshell POST", but keep "SQL injection" / "[sudo]" as they are
        private static string LowerFirst(string s) =>
            s.Length > 1 && char.IsUpper(s[0]) && char.IsLower(s[1]) ? char.ToLowerInvariant(s[0]) + s.Substring(1) : s;

        private static string JoinAnd(IReadOnlyList<string> items) =>
            items.Count <= 1 ? string.Join("", items)
            : string.Join(", ", items.Take(items.Count - 1)) + " and " + items[^1];

        // ── HTML ─────────────────────────────────────────────────────────
        private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

        private static string Cls(Likelihood l) => l switch
        {
            Likelihood.AlmostCertain => "l-ac",
            Likelihood.HighlyLikely => "l-hl",
            Likelihood.Likely => "l-lk",
            _ => "l-lo",
        };

        private static string Pill(Likelihood l) => $"<span class=\"pill {Cls(l)}\">{E(LikelihoodScale.Label(l))}</span>";

        private static IEnumerable<string> Lines(string? s) =>
            (s ?? "").Replace("\r", "").Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0);

        public static string RenderHtml(CaseReportData data, CaseReportNotes notes)
        {
            var inc = data.Findings.Where(f => f.Include)
                .OrderByDescending(f => f.Likelihood).ThenBy(f => f.Rank).ThenBy(f => f.TimeUtc ?? DateTime.MaxValue)
                .ToList();
            var title = string.IsNullOrWhiteSpace(notes.Title) ? SuggestTitle(data) : notes.Title.Trim();
            var severity = string.IsNullOrWhiteSpace(notes.Severity) ? SuggestSeverity(data) : notes.Severity;
            var status = string.IsNullOrWhiteSpace(notes.Status) ? "Active" : notes.Status;
            var bluf = string.IsNullOrWhiteSpace(notes.Bluf) ? DraftBluf(data) : notes.Bluf.Trim();
            var affected = inc.Select(f => f.Host).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var times = inc.Where(f => f.TimeUtc.HasValue).Select(f => f.TimeUtc!.Value).ToList();
            DateTime? first = times.Count > 0 ? times.Min() : null, last = times.Count > 0 ? times.Max() : null;
            var ipsByHost = data.Hosts.ToDictionary(h => h.Host, h => h.Ips, StringComparer.OrdinalIgnoreCase);
            string HostCell(string host) =>
                $"<span class=\"mono\">{E(host)}</span>" +
                (ipsByHost.TryGetValue(host, out var ips) && ips.Count > 0 ? $" <span class=\"muted mono\">({E(string.Join(", ", ips))})</span>" : "");

            var sb = new StringBuilder();
            sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
            sb.Append($"<title>{E(string.IsNullOrWhiteSpace(data.CaseName) ? "Case report" : data.CaseName + " – case report")}</title>");
            sb.Append("<style>").Append(Css).Append("</style></head><body><main>");

            // Header
            sb.Append("<header><div>");
            var meta = new List<string>();
            if (!string.IsNullOrWhiteSpace(data.CaseName)) meta.Add(E(data.CaseName));
            if (!string.IsNullOrWhiteSpace(data.Analyst)) meta.Add("Analyst: " + E(data.Analyst));
            meta.Add($"Generated {data.GeneratedUtc:yyyy-MM-dd HH:mm} UTC");
            sb.Append($"<p class=\"meta\">{string.Join(" · ", meta)}</p>");
            sb.Append($"<h1>{E(title)}</h1></div><div class=\"tags\">");
            sb.Append($"<span class=\"pill {(severity is "Critical" ? "s-crit" : severity is "High" ? "s-high" : "s-other")}\">Severity: {E(severity.ToLowerInvariant())}</span>");
            sb.Append($"<span class=\"pill {(status is "Closed" ? "s-other" : "s-high")}\">Status: {E(status.ToLowerInvariant())}</span>");
            sb.Append("</div></header>");

            // Metrics
            sb.Append("<section class=\"metrics\">");
            Metric(sb, "Hosts with findings", $"{affected} <small>of {data.Hosts.Count}</small>");
            Metric(sb, "Key findings", inc.Count.ToString());
            Metric(sb, "Case IOCs seen", data.CaseIocsSearched ? data.CaseIocHits.Count.ToString() : "–");
            Metric(sb, "First activity (UTC)", first.HasValue ? $"{first:HH:mm} <small>{first:yyyy-MM-dd}</small>" : "–");
            Metric(sb, "Activity span", first.HasValue ? Span(last!.Value - first.Value) : "–");
            sb.Append("</section>");

            // BLUF
            sb.Append("<h2>Bottom line up front</h2>");
            sb.Append("<div class=\"bluf\">");
            foreach (var p in Lines(bluf)) sb.Append($"<p>{E(p)}</p>");
            sb.Append("</div>");
            sb.Append("<div class=\"scale\"><span>Probability scale:</span>");
            foreach (var l in Enum.GetValues<Likelihood>().Reverse())
                sb.Append($"<span class=\"pill {Cls(l)}\">{E(LikelihoodScale.Label(l))} {E(LikelihoodScale.Range(l))}</span>");
            sb.Append("</div>");

            // Key findings
            sb.Append($"<h2>Key findings <span class=\"count\">{inc.Count}</span></h2>");
            if (inc.Count == 0) sb.Append("<p class=\"muted\">No findings were selected for this report.</p>");
            int n = 0;
            foreach (var f in inc)
            {
                n++;
                var (head, detail) = SplitTitle(f.Text);
                sb.Append("<article class=\"finding\"><div class=\"fhead\">");
                sb.Append($"<span class=\"ftitle\">F{n} · {E(head)}</span>{Pill(f.Likelihood)}</div>");
                if (detail.Length > 0) sb.Append($"<p class=\"fdetail mono\">{E(detail)}</p>");
                sb.Append("<dl>");
                sb.Append($"<dt>Host</dt><dd>{HostCell(f.Host)}</dd>");
                sb.Append($"<dt>Time</dt><dd>{(f.TimeUtc.HasValue ? E(f.TimeText) + " UTC" : "<span class=\"muted\">no timestamp</span>")}</dd>");
                sb.Append($"<dt>Sources</dt><dd>{E(f.SourceText)} <span class=\"muted\">· {E(f.Collection)}\\QuickWins.txt</span></dd>");
                sb.Append($"<dt>Basis</dt><dd>{E(f.Basis)}</dd>");
                if (f.IsAnalystAssessed)
                    sb.Append($"<dt>Assessment</dt><dd>Set by analyst (automatic: {E(LikelihoodScale.Label(f.AutoLikelihood).ToLowerInvariant())})</dd>");
                if (!string.IsNullOrWhiteSpace(f.Note)) sb.Append($"<dt>Note</dt><dd>{E(f.Note)}</dd>");
                sb.Append("</dl></article>");
            }

            // Timeline
            var timeline = inc.Where(f => f.TimeUtc.HasValue).OrderBy(f => f.TimeUtc).ToList();
            if (timeline.Count > 0)
            {
                sb.Append("<h2>Timeline <span class=\"count\">UTC</span></h2><table class=\"tl\"><thead><tr><th>Time</th><th>Host</th><th>Event</th><th>Source</th><th>Likelihood</th></tr></thead><tbody>");
                string? lastDay = null;
                foreach (var f in timeline)
                {
                    var day = f.TimeUtc!.Value.ToString("yyyy-MM-dd");
                    if (day != lastDay) { sb.Append($"<tr class=\"day\"><td colspan=\"5\">{day}</td></tr>"); lastDay = day; }
                    sb.Append($"<tr><td class=\"mono nowrap\">{f.TimeUtc:HH:mm:ss}</td><td class=\"mono\">{E(f.Host)}</td><td>{E(SplitTitle(f.Text).Title)}");
                    if (f.LateralTo != null) sb.Append($" <span class=\"pill l-ac\">Lateral → {E(f.LateralTo)}</span>");
                    sb.Append($"</td><td class=\"muted\">{E(f.SourceText)}</td><td>{Pill(f.Likelihood)}</td></tr>");
                }
                sb.Append("</tbody></table>");
            }

            // Lateral movement
            if (data.Lateral.Count > 0)
            {
                sb.Append("<h2>Lateral movement between case hosts</h2><table><thead><tr><th>From</th><th>To</th><th>Evidence</th><th>Source</th></tr></thead><tbody>");
                foreach (var l in data.Lateral)
                    sb.Append($"<tr><td class=\"mono\">{E(l.From)}</td><td>{HostCell(l.To)}</td><td>{E(l.Evidence == null ? "" : SplitTitle(l.Evidence.Text).Title)}" +
                              $"{(l.Evidence?.TimeUtc is DateTime t ? $" <span class=\"muted\">{t:yyyy-MM-dd HH:mm:ss}</span>" : "")}</td><td class=\"muted\">{E(l.Evidence?.Source)}</td></tr>");
                sb.Append("</tbody></table>");
            }

            // Hosts
            sb.Append("<h2>Hosts</h2><table><thead><tr><th>Host</th><th>IP</th><th class=\"num\">Crit</th><th class=\"num\">High</th><th class=\"num\">Med</th><th>Activity (UTC)</th><th>Collection</th></tr></thead><tbody>");
            foreach (var h in data.Hosts)
            {
                var act = h.First.HasValue ? $"{h.First:yyyy-MM-dd HH:mm} → {h.Last:yyyy-MM-dd HH:mm}" : "–";
                sb.Append($"<tr><td class=\"mono\">{E(h.Host)}</td><td class=\"mono\">{E(h.Ips.Count == 0 ? "unknown" : string.Join(", ", h.Ips))}</td>" +
                          (h.HasFile
                              ? $"<td class=\"num{(h.Critical > 0 ? " crit" : "")}\">{h.Critical}</td><td class=\"num\">{h.High}</td><td class=\"num\">{h.Medium}</td>"
                              : "<td class=\"num\">?</td><td class=\"num\">?</td><td class=\"num\">?</td>") +
                          $"<td class=\"nowrap\">{act}</td><td class=\"muted\">{E(h.Collection)}</td></tr>");
            }
            sb.Append("</tbody></table>");

            // Indicators
            if (data.CaseIocHits.Count > 0 || data.SharedIocs.Count > 0)
            {
                sb.Append("<h2>Indicators</h2>");
                if (data.CaseIocHits.Count > 0)
                {
                    sb.Append("<h3>From the case IOC list</h3><table><thead><tr><th>Kind</th><th>Indicator</th><th>Hosts</th><th>First seen (UTC)</th><th>Detail</th></tr></thead><tbody>");
                    foreach (var i in data.CaseIocHits)
                        sb.Append($"<tr><td class=\"muted nowrap\">{E(i.Kind)}</td><td class=\"mono\">{E(i.Value)}</td><td class=\"mono\">{E(string.Join(", ", i.Hosts))}</td>" +
                                  $"<td class=\"nowrap\">{(i.FirstSeen.HasValue ? $"{i.FirstSeen:yyyy-MM-dd HH:mm:ss}" : "–")}</td><td>{E(i.Detail)}{(i.Comment.Length > 0 ? $" <span class=\"muted\"># {E(i.Comment)}</span>" : "")}</td></tr>");
                    sb.Append("</tbody></table>");
                }
                if (data.SharedIocs.Count > 0)
                {
                    sb.Append("<h3>Seen on more than one host</h3><table><thead><tr><th>Kind</th><th>Indicator</th><th>Hosts</th><th>Detail</th></tr></thead><tbody>");
                    foreach (var i in data.SharedIocs)
                        sb.Append($"<tr><td class=\"muted nowrap\">{E(i.Kind)}</td><td class=\"mono\">{E(i.Value)}</td><td class=\"mono\">{E(string.Join(", ", i.Hosts))}</td><td class=\"muted\">{E(i.Detail)}</td></tr>");
                    sb.Append("</tbody></table>");
                }
            }

            // Gaps
            var gaps = Lines(notes.Gaps).ToList();
            if (gaps.Count + data.AutoGaps.Count > 0)
            {
                sb.Append("<h2>Intelligence gaps</h2><ul class=\"gaps\">");
                foreach (var g in gaps) sb.Append($"<li>{E(g)}</li>");
                foreach (var g in data.AutoGaps) sb.Append($"<li>{E(g)} <span class=\"muted\">(detected)</span></li>");
                sb.Append("</ul>");
            }

            // Next steps
            var steps = Lines(notes.NextSteps).ToList();
            if (steps.Count > 0)
            {
                sb.Append("<h2>Next steps</h2><ul class=\"steps\">");
                foreach (var s in steps)
                {
                    bool done = s.StartsWith("[x]", StringComparison.OrdinalIgnoreCase);
                    var text = done || s.StartsWith("[ ]") ? s.Substring(3).Trim() : s;
                    sb.Append($"<li class=\"{(done ? "done" : "")}\"><span class=\"box\">{(done ? "✓" : "")}</span>{E(text)}</li>");
                }
                sb.Append("</ul>");
            }

            // Method
            sb.Append("<footer><p><b>How likelihood is assessed.</b> Terms follow the PHIA probability yardstick. " +
                      "The automatic value combines detection severity (critical, high, medium), independent corroboration " +
                      "(another parser on the same host saw an indicator from the finding) and matches against the case IOC list. " +
                      "Findings marked \"set by analyst\" were reviewed and changed manually. Each finding names the parser sources " +
                      "and collection it came from; full detail is in that collection's QuickWins.txt.</p>" +
                      "<p>Generated by CSIRT UAC Parser.</p></footer>");
            sb.Append("</main></body></html>");
            return sb.ToString();
        }

        private static void Metric(StringBuilder sb, string label, string valueHtml) =>
            sb.Append($"<div class=\"metric\"><p class=\"ml\">{E(label)}</p><p class=\"mv\">{valueHtml}</p></div>");

        private static string Span(TimeSpan t) =>
            t.TotalDays >= 2 ? $"{t.TotalDays:0} days" :
            t.TotalHours >= 1 ? $"{t.TotalHours:0.#} h" :
            $"{Math.Max(1, t.TotalMinutes):0} min";

        private const string Css = @"
:root{--text:#1a1a1a;--muted:#6b6b6b;--faint:#9a9a9a;--border:#e2e2e2;--surface:#f6f6f4;--bg:#fff;
--red-bg:#fcebeb;--red:#a32d2d;--amber-bg:#faeeda;--amber:#854f0b;--blue-bg:#e6f1fb;--blue:#185fa5;--gray-bg:#f1efe8;--gray:#5f5e5a;
--mono:Consolas,'Cascadia Mono',Menlo,monospace}
@media (prefers-color-scheme:dark){:root{--text:#ececec;--muted:#a8a8a8;--faint:#7a7a7a;--border:#3a3a3a;--surface:#262626;--bg:#1b1b1b;
--red-bg:#4a1b1b;--red:#f7c1c1;--amber-bg:#412402;--amber:#fac775;--blue-bg:#042c53;--blue:#b5d4f4;--gray-bg:#2c2c2a;--gray:#d3d1c7}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 'Segoe UI',system-ui,-apple-system,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 20px 48px}
h1{font-size:24px;font-weight:600;margin:4px 0 0;line-height:1.3}
h2{font-size:17px;font-weight:600;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--border)}
h3{font-size:14px;font-weight:600;margin:18px 0 8px;color:var(--muted)}
.count{font-weight:400;color:var(--faint);font-size:14px;margin-left:6px}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
.meta{margin:0;font-size:13px;color:var(--faint)}
.tags{display:flex;gap:6px;flex-wrap:wrap}
.pill{display:inline-block;font-size:12px;padding:2px 9px;border-radius:6px;white-space:nowrap;line-height:1.6}
.s-crit,.l-ac{background:var(--red-bg);color:var(--red)}
.s-high,.l-hl{background:var(--amber-bg);color:var(--amber)}
.l-lk{background:var(--blue-bg);color:var(--blue)}
.s-other,.l-lo{background:var(--gray-bg);color:var(--gray)}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:22px}
.metric{background:var(--surface);border-radius:8px;padding:12px 14px}
.metric p{margin:0}.ml{font-size:13px;color:var(--muted)}.mv{font-size:22px;font-weight:600}
.mv small{font-size:13px;font-weight:400;color:var(--faint)}
.bluf{border-left:3px solid var(--red);padding:2px 0 2px 16px;font-size:16px;line-height:1.7}
.bluf p{margin:0 0 8px}
.scale{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:12px;font-size:12px;color:var(--muted)}
.finding{border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin-bottom:12px;break-inside:avoid}
.fhead{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
.ftitle{font-weight:600;font-size:15px}
.fdetail{margin:8px 0 0;color:var(--muted);font-size:12.5px;word-break:break-word}
dl{display:grid;grid-template-columns:90px minmax(0,1fr);gap:4px 12px;margin:12px 0 0;padding-top:10px;border-top:1px solid var(--border);font-size:13.5px}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12.5px;padding:6px 8px;border-bottom:1px solid var(--border)}
td{padding:7px 8px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-word}
tr.day td{background:var(--surface);font-weight:600;font-size:12.5px;color:var(--muted);padding:4px 8px}
.num{text-align:right;font-variant-numeric:tabular-nums}.crit{color:var(--red);font-weight:600}
.mono{font-family:var(--mono);font-size:12.5px}
td.mono{overflow-wrap:anywhere;word-break:normal;min-width:110px}.muted{color:var(--muted)}.nowrap{white-space:nowrap}
ul.gaps,ul.steps{padding:0;margin:0;list-style:none}
ul.gaps li{padding:7px 0 7px 22px;border-bottom:1px solid var(--border);position:relative}
ul.gaps li:before{content:'?';position:absolute;left:2px;color:var(--amber);font-weight:600}
ul.steps li{padding:6px 0;display:flex;gap:10px;align-items:flex-start}
.box{flex:none;width:16px;height:16px;margin-top:4px;border:1.5px solid var(--faint);border-radius:4px;font-size:11px;line-height:13px;text-align:center}
li.done{color:var(--muted)}li.done .box{border-color:var(--blue);color:var(--blue)}
footer{margin-top:40px;padding-top:12px;border-top:1px solid var(--border);font-size:12.5px;color:var(--muted)}
footer b{color:var(--text);font-weight:600}
@media (max-width:640px){dl{grid-template-columns:1fr}.tl th:nth-child(4),.tl td:nth-child(4){display:none}}
@media print{body{font-size:12px}main{max-width:none;padding:0}h2{break-after:avoid}
.pill,.metric,tr.day td{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
@page{margin:16mm 14mm}";
    }
}

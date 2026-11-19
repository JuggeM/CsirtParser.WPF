using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Helpers;
using static Helpers.RtfKit;

namespace CsirtParser.WPF.Services;

/// <summary>
/// Converts a finished QuickWins.txt into QuickWins.rtf, laid out like the
/// case report (same fonts, colours, headings and tables via <see cref="RtfKit"/>).
/// QuickWins.txt stays the source of truth: this only reads it, splits it on
/// its "########## TITLE ##########" headers and draws the sections it knows
/// as tables. Lines it doesn't recognise are kept as plain paragraphs, so
/// nothing a parser writes is lost.
/// </summary>
public static class QuickWinsRtfConverter
{
    private static readonly Regex SectionRx = new(@"^#{10} (?<t>.+?) #{10}\s*$", RegexOptions.Compiled);
    private static readonly Regex GeneratedRx = new(@"^# Generated on (?<t>.+)$", RegexOptions.Compiled);
    private static readonly Regex KeyValueRx = new(@"^\s*(?<k>[A-Za-z][A-Za-z ]*?):\s+(?<v>.*)$", RegexOptions.Compiled);

    // "  CRITICAL 2026-11-02 09:13:40  [WEB, AUTH] text"
    private static readonly Regex KeyFindingRx = new(
        @"^\s+(?<sev>CRITICAL|HIGH|MEDIUM|SUSPICIOUS|LOW)\s+(?<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}|\(no time\))\s+\[(?<src>[^\]]+)\]\s(?<text>.*)$",
        RegexOptions.Compiled);

    // "  IP       203.0.113.45      8 source(s): AIAGENT, AUTH"
    private static readonly Regex IocRx = new(@"^\s+(?<kind>\S+)\s+(?<val>.+?)\s+(?<n>\d+) source\(s\): (?<src>.*)$", RegexOptions.Compiled);

    // Coverage rows (CoverageTable.BuildCoverage)
    private static readonly Regex CoverageRx = new(
        @"^\s+(?<src>\S+)\s+(?<files>\d+)\s{2}(?<range>.*?)\s+(?<c>\d+)\s+(?<h>\d+)\s+(?<m>\d+)\s+(?<st>\S.*?)\s*$", RegexOptions.Compiled);
    private static readonly Regex CoverageMissingRx = new(@"^\s+(?<src>\S+)\s+-\s+(?<st>\S.*?)\s*$", RegexOptions.Compiled);

    // "  [CRITICAL] USER    support     1 hit(s)  2026-… → 2026-…  in EVTX   # comment"
    private static readonly Regex CaseIocRx = new(
        @"^\s+\[CRITICAL\]\s+(?<kind>\S+)\s+(?<val>.+?)\s+(?<n>\d+) hit\(s\)\s+(?<range>.+?)\s+in (?<src>.+?)(?:\s+# (?<c>.*))?$",
        RegexOptions.Compiled);

    // Per-source finding: "  <file>: [SEV] [time UTC] text", "[BODYFILE] [HIGH] …", "[AUTH] [HIGH] …"
    private static readonly Regex FindingRx = new(
        @"^\s*(?:\[[A-Z0-9_.]+\]\s+)?(?:(?<file>[^\[\s].*?):\s)?\[(?<sev>CRITICAL|HIGH|BRUTEFORCE|SUSPICIOUS|MEDIUM|LOW|ERROR|INFO)\]\s*(?<rest>.*)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex LeadingTimeRx = new(
        @"^\[(?:(?<t>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: → \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})?) UTC|no-timestamp)\]\s*",
        RegexOptions.Compiled);

    // "  [AUTH.LOG] Failed login x4, Session opened x2"
    private static readonly Regex PatternRx = new(@"^\s+\[(?<src>[^\]]+)\]\s+(?<p>.*)$", RegexOptions.Compiled);

    private sealed class Section
    {
        public string Title = "";
        public List<string> Lines = new();
    }

    // ── Public entry point ───────────────────────────────────────────
    /// <summary>
    /// Reads QuickWins.txt from outputDir and writes QuickWins.rtf alongside it.
    /// Call this after ParserOrchestrator.RunAll() completes.
    /// </summary>
    public static void Convert(string outputDir)
    {
        var txtPath = Path.Combine(outputDir, "QuickWins.txt");
        var rtfPath = Path.Combine(outputDir, "QuickWins.rtf");

        if (!File.Exists(txtPath))
            throw new FileNotFoundException("QuickWins.txt not found.", txtPath);

        var lines = File.ReadAllLines(txtPath, Encoding.UTF8);
        File.WriteAllText(rtfPath, Render(lines), Encoding.ASCII);
    }

    /// <summary>Builds the RTF document from the lines of QuickWins.txt.</summary>
    public static string Render(IReadOnlyList<string> lines)
    {
        string? generated = null;
        var sections = new List<Section>();
        Section? cur = null;
        foreach (var line in lines)
        {
            var m = SectionRx.Match(line);
            if (m.Success) { sections.Add(cur = new Section { Title = m.Groups["t"].Value.Trim() }); continue; }
            if (line.Length > 0 && line.All(ch => ch == '#')) continue;
            if (cur == null)
            {
                var g = GeneratedRx.Match(line);
                if (g.Success) generated = g.Groups["t"].Value.Trim();
                continue;
            }
            cur.Lines.Add(line);
        }

        Section? Find(string prefix) => sections.FirstOrDefault(s => s.Title.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

        var host = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var l in Find("HOST")?.Lines ?? new())
        {
            var kv = KeyValueRx.Match(l);
            if (kv.Success) host[kv.Groups["k"].Value.Trim()] = kv.Groups["v"].Value.Trim();
        }
        var timeline = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var l in Find("Timeline Coverage")?.Lines ?? new())
        {
            var kv = KeyValueRx.Match(l);
            if (kv.Success) timeline[kv.Groups["k"].Value.Trim()] = kv.Groups["v"].Value.Replace(" UTC", "").Trim();
        }

        var sb = new StringBuilder();
        Begin(sb);
        WriteHeader(sb, host, timeline, generated, Find("COVERAGE"), Find("KEY FINDINGS"));

        Section? patterns = null;
        foreach (var s in sections)
        {
            var t = s.Title;
            if (t.StartsWith("HOST", StringComparison.OrdinalIgnoreCase) ||
                t.StartsWith("Timeline Coverage", StringComparison.OrdinalIgnoreCase)) continue;
            if (t.StartsWith("PATTERN COUNTS", StringComparison.OrdinalIgnoreCase)) { patterns = s; continue; }

            if (t.StartsWith("KEY FINDINGS", StringComparison.OrdinalIgnoreCase)) WriteKeyFindings(sb, s);
            else if (t.StartsWith("IOCs", StringComparison.Ordinal)) WriteIocs(sb, s);
            else if (t.StartsWith("COVERAGE", StringComparison.OrdinalIgnoreCase)) WriteCoverage(sb, s);
            else if (t.StartsWith("CASE IOC HITS", StringComparison.OrdinalIgnoreCase)) WriteCaseIocs(sb, s);
            else WriteGeneric(sb, s);
        }
        if (patterns != null) WritePatterns(sb, patterns);

        sb.Append($@"\pard\plain\f0\sb480\sa60\brdrt\brdrs\brdrw10\brsp100\brdrcf{Border}\fs17\cf{Muted}")
          .Append(E(" Full detail is in QuickWins.txt and the Normalized_*.csv files in this folder. Times are UTC."))
          .Append(@"\par").AppendLine();
        Para(sb, $@"\fs17\cf{Muted} Generated by CSIRT UAC Parser.");
        End(sb);
        return sb.ToString();
    }

    // ── Header ───────────────────────────────────────────────────────
    private static void WriteHeader(StringBuilder sb, Dictionary<string, string> host, Dictionary<string, string> timeline,
                                    string? generated, Section? coverage, Section? keyFindings)
    {
        host.TryGetValue("Host", out var hostName);
        host.TryGetValue("Collection", out var collection);

        var meta = new List<string> { "Quick wins" };
        if (host.TryGetValue("Case", out var caseName)) meta.Add($"Case {caseName}");
        if (!string.IsNullOrEmpty(collection)) meta.Add(collection);
        if (host.TryGetValue("Analyst", out var analyst)) meta.Add($"Analyst {analyst}");
        if (generated != null) meta.Add($"Generated {generated}");
        Para(sb, $@"\fs17\cf{Muted} " + E(string.Join(" · ", meta)), after: 60);
        Para(sb, @"\fs36\b " + E(string.IsNullOrEmpty(hostName) ? collection ?? "Quick wins" : hostName), after: 60);

        var facts = new List<string>();
        if (host.TryGetValue("IP", out var ip)) facts.Add($"IP {ip}");
        if (host.TryGetValue("Timezone", out var tz)) facts.Add($"Timezone {tz}");
        if (facts.Count > 0) Para(sb, $@"\fs18\cf{Muted} " + E(string.Join("   ·   ", facts)), after: 200);
        else Para(sb, "", after: 120);

        // Counts come from the coverage table; fall back to the key findings summary line
        int crit = 0, high = 0, med = 0, withFindings = 0, checkedSources = 0;
        bool haveCounts = false;
        foreach (var l in coverage?.Lines ?? new())
        {
            var m = CoverageRx.Match(l);
            if (!m.Success) continue;
            haveCounts = true;
            checkedSources++;
            int c = int.Parse(m.Groups["c"].Value), h = int.Parse(m.Groups["h"].Value), md = int.Parse(m.Groups["m"].Value);
            crit += c; high += h; med += md;
            if (c + h + md > 0) withFindings++;
        }
        if (!haveCounts)
        {
            var m = Regex.Match(string.Join("\n", keyFindings?.Lines ?? new()), @"(\d+) critical, (\d+) high");
            if (m.Success) { crit = int.Parse(m.Groups[1].Value); high = int.Parse(m.Groups[2].Value); }
        }

        timeline.TryGetValue("First Log Entry", out var first);
        timeline.TryGetValue("Last Log Entry", out var last);
        string span = first != null && last != null ? $@"{E(Trim(first))}\line {E("→ " + Trim(last))}" : E("–");

        string Metric(string label, string value, int colour = Text) =>
            $@"\fs17\cf{Muted} {E(label)}\line\fs26\b\cf{colour} {E(value)}";
        var cells = new[]
        {
            Metric("Critical", crit.ToString(), crit > 0 ? Red : Text),
            Metric("High", high.ToString(), high > 0 ? Amber : Text),
            Metric("Medium", haveCounts ? med.ToString() : "–"),
            Metric("Sources with findings", haveCounts ? $"{withFindings} of {checkedSources}" : "–"),
            $@"\fs17\cf{Muted} Log time span (UTC)\line\fs20\b\cf{Text} {span}",
        };
        Table(sb, new[] { 1500, 1500, 1500, 2200, PageWidth - 6700 }, new[] { cells }, header: false, shading: Surface, borders: false);

        // "2026-11-01 07:00:00" → "2026-11-01 07:00"
        static string Trim(string ts) => ts.Length >= 16 && ts[13] == ':' ? ts.Substring(0, 16) : ts;
    }

    // ── Known sections ───────────────────────────────────────────────
    private static void WriteKeyFindings(StringBuilder sb, Section s)
    {
        H2(sb, "Key findings (critical and high, all sources)");
        var rows = new List<string[]> { new[] { "Severity", "Time (UTC)", "Source", "Finding" } };
        foreach (var l in s.Lines)
        {
            var m = KeyFindingRx.Match(l);
            if (m.Success)
            {
                var time = m.Groups["time"].Value;
                rows.Add(new[]
                {
                    Sev(m.Groups["sev"].Value),
                    time.StartsWith("(") ? $@"\cf{Muted} no time" : $@"\f1\fs16 {E(time)}",
                    $@"\cf{Muted} {E(m.Groups["src"].Value)}",
                    E(m.Groups["text"].Value),
                });
            }
            else if (!string.IsNullOrWhiteSpace(l))
            {
                FlushTable(sb, ref rows, KeyWidths);
                Para(sb, $@"\fs18\cf{Muted} " + E(l.Trim()), after: 80);
            }
        }
        FlushTable(sb, ref rows, KeyWidths);
    }

    private static readonly int[] KeyWidths = { 1150, 1950, 1550, PageWidth - 4650 };

    private static void WriteIocs(StringBuilder sb, Section s)
    {
        H2(sb, "Indicators seen in findings");
        var rows = new List<string[]> { new[] { "Kind", "Indicator", "Sources" } };
        var widths = new[] { 900, 4400, PageWidth - 5300 };
        foreach (var l in s.Lines)
        {
            var m = IocRx.Match(l);
            if (m.Success)
            {
                int n = int.Parse(m.Groups["n"].Value);
                rows.Add(new[]
                {
                    $@"\cf{Muted} {E(m.Groups["kind"].Value)}",
                    $@"\f1\fs16 {E(m.Groups["val"].Value)}",
                    (n > 1 ? $@"{{\b {n}}} " : $"{n} ") + $@"{{\cf{Muted} {E(m.Groups["src"].Value)}}}",
                });
            }
            else if (!string.IsNullOrWhiteSpace(l))
            {
                FlushTable(sb, ref rows, widths);
                Para(sb, $@"\fs18\cf{Muted} " + E(l.Trim()), after: 80);
            }
        }
        FlushTable(sb, ref rows, widths);
    }

    private static void WriteCoverage(StringBuilder sb, Section s)
    {
        H2(sb, "Coverage (what was checked)");
        var body = s.Lines.Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
        bool IsHeader(string l) => l.TrimStart().StartsWith("Source ") || l.TrimStart().StartsWith("---");
        // A layout this converter doesn't know: keep its columns as monospace text rather than guess
        if (body.Any(l => !IsHeader(l) && !CoverageRx.IsMatch(l) && !CoverageMissingRx.IsMatch(l)))
        {
            foreach (var l in body)
                sb.Append($@"\pard\plain\f1\fs15\cf{Text}\sa0 ").Append(E(l).Replace("  ", @" \~")).Append(@"\par").AppendLine();
            Para(sb, "", after: 80);
            return;
        }
        var rows = new List<string[]> { new[] { "Source", "Files", "Time range (UTC)", "Crit", "High", "Med", "Status" } };
        foreach (var l in body)
        {
            if (IsHeader(l)) continue;
            var m = CoverageRx.Match(l);
            if (m.Success)
            {
                int c = int.Parse(m.Groups["c"].Value), h = int.Parse(m.Groups["h"].Value);
                var st = m.Groups["st"].Value;
                var range = m.Groups["range"].Value.Trim();
                rows.Add(new[]
                {
                    $@"\b {E(m.Groups["src"].Value)}",
                    m.Groups["files"].Value,
                    range.StartsWith("(") ? $@"\cf{Muted} {E(range)}" : E(range),
                    c > 0 ? $@"\b\cf{Red} {c}" : c.ToString(),
                    h > 0 ? $@"\b\cf{Amber} {h}" : h.ToString(),
                    m.Groups["m"].Value,
                    st == "REVIEW" ? $@"\b\cf{Red} review" : $@"\cf{Muted} {E(st)}",
                });
                continue;
            }
            var miss = CoverageMissingRx.Match(l);
            if (miss.Success)
                rows.Add(new[] { $@"\cf{Muted} {E(miss.Groups["src"].Value)}", $@"\cf{Muted} {E("–")}", "", "", "", "", $@"\cf{Muted} {E(miss.Groups["st"].Value)}" });
        }
        FlushTable(sb, ref rows, new[] { 1700, 700, 3438, 700, 700, 700, PageWidth - 7938 });
    }

    private static void WriteCaseIocs(StringBuilder sb, Section s)
    {
        H2(sb, "Case IOC hits (analyst IOC list)");
        var rows = new List<string[]> { new[] { "Kind", "Indicator", "Hits", "Seen (UTC)", "Sources" } };
        var widths = new[] { 900, 2900, 700, 2400, PageWidth - 6900 };
        foreach (var l in s.Lines)
        {
            if (string.IsNullOrWhiteSpace(l)) continue;
            var m = CaseIocRx.Match(l);
            if (m.Success)
            {
                var comment = m.Groups["c"].Success ? $@"\line{{\cf{Muted} # {E(m.Groups["c"].Value)}}}" : "";
                rows.Add(new[]
                {
                    $@"\b\cf{Red} {E(m.Groups["kind"].Value)}",
                    $@"\f1\fs16 {E(m.Groups["val"].Value)}\f0{comment}",
                    m.Groups["n"].Value,
                    $@"\f1\fs16 {E(m.Groups["range"].Value)}",
                    E(m.Groups["src"].Value),
                });
            }
            else if (l.TrimStart().StartsWith("e.g.") && rows.Count > 1)
            {
                var last = rows[^1];
                last[4] += $@"\line{{\f1\fs15\cf{Muted} {E(l.Trim())}}}";
            }
            else
            {
                FlushTable(sb, ref rows, widths);
                Para(sb, (l.Contains("treat as CRITICAL") ? $@"\fs18\b\cf{Red} " : $@"\fs18\cf{Muted} ") + E(l.Trim()), after: 80);
            }
        }
        FlushTable(sb, ref rows, widths);
    }

    private static void WritePatterns(StringBuilder sb, Section s)
    {
        H2(sb, "Appendix: pattern counts");
        var rows = new List<string[]> { new[] { "Source", "Patterns" } };
        foreach (var l in s.Lines)
        {
            var m = PatternRx.Match(l);
            if (m.Success) rows.Add(new[] { $@"\b {E(m.Groups["src"].Value)}", $@"\cf{Muted} {E(m.Groups["p"].Value)}" });
            else if (!string.IsNullOrWhiteSpace(l)) rows.Add(new[] { "", $@"\cf{Muted} {E(l.Trim())}" });
        }
        FlushTable(sb, ref rows, new[] { 1700, PageWidth - 1700 }, fontSize: 15);
    }

    // ── Per-source sections and anything else ────────────────────────
    /// <summary>
    /// Runs of finding lines become a Severity / Time / File / Finding table;
    /// every other line is kept as a paragraph in the order it was written.
    /// </summary>
    private static void WriteGeneric(StringBuilder sb, Section s)
    {
        // "[WEB] — 16 finding(s) across 8 file(s)" → "WEB — 16 finding(s) across 8 file(s)"
        var title = Regex.Replace(s.Title, @"^\[([^\]]+)\]", "$1");
        H2(sb, title);

        var run = new List<(string Sev, string? Time, string File, string Text)>();
        void Flush()
        {
            if (run.Count == 0) return;
            bool oneFile = run.Select(r => r.File).Distinct().Count() == 1;
            bool anyTime = run.Any(r => r.Time != null);
            if (oneFile && run[0].File.Length > 0)
                Para(sb, $@"\fs17\cf{Muted} {E("From ")}{{\f1 {E(run[0].File)}}}", after: 60);

            var head = new List<string> { "Severity" };
            var widths = new List<int> { 1150 };
            if (anyTime) { head.Add("Time (UTC)"); widths.Add(1950); }
            if (!oneFile) { head.Add("File"); widths.Add(1900); }
            head.Add("Finding");
            widths.Add(PageWidth - widths.Sum());

            var rows = new List<string[]> { head.ToArray() };
            foreach (var r in run)
            {
                var cells = new List<string> { Sev(r.Sev) };
                if (anyTime) cells.Add(r.Time == null ? $@"\cf{Muted} {E("–")}" : $@"\f1\fs16 {E(r.Time.Replace(" → ", "\n→ "))}");
                if (!oneFile) cells.Add($@"\f1\fs15\cf{Muted} {E(r.File)}");
                cells.Add(E(r.Text));
                rows.Add(cells.ToArray());
            }
            Table(sb, widths.ToArray(), rows.ToArray(), header: true);
            run.Clear();
        }

        foreach (var l in s.Lines)
        {
            if (string.IsNullOrWhiteSpace(l)) continue;
            var m = FindingRx.Match(l);
            if (m.Success)
            {
                var rest = m.Groups["rest"].Value;
                string? time = null;
                var t = LeadingTimeRx.Match(rest);
                if (t.Success)
                {
                    if (t.Groups["t"].Success) time = t.Groups["t"].Value;
                    rest = rest.Substring(t.Length);
                }
                run.Add((m.Groups["sev"].Value.ToUpperInvariant(), time, ShortPath(m.Groups["file"].Value), rest));
                continue;
            }
            Flush();
            var text = l.Trim();
            if (text.StartsWith("===") && text.EndsWith("==="))
                Para(sb, $@"\b\fs19 " + E(text.Trim('=', ' ')), before: 120, after: 60);
            else if (text.Contains("   "))
                // Space-aligned columns: keep them lined up in monospace
                sb.Append($@"\pard\plain\f1\fs15\cf{Text}\sa20 ").Append(E(l.TrimEnd()).Replace("  ", @" \~")).Append(@"\par").AppendLine();
            else
            {
                int indent = Math.Min(l.Length - l.TrimStart().Length, 8);
                Para(sb, $@"\li{Math.Max(0, indent - 2) * 120}\fs18 " + E(text), after: 40);
            }
        }
        Flush();
    }

    // ── Helpers ──────────────────────────────────────────────────────
    /// <summary>Writes the rows collected so far (if any) and starts over with the same header row.</summary>
    private static void FlushTable(StringBuilder sb, ref List<string[]> rows, int[] widths, int fontSize = 17)
    {
        if (rows.Count > 1) Table(sb, widths, rows.ToArray(), header: true, fontSize: fontSize);
        rows = new List<string[]> { rows[0] };
    }

    private static string Sev(string sev)
    {
        var s = sev.ToUpperInvariant();
        int colour = s switch
        {
            "CRITICAL" => Red,
            "HIGH" or "BRUTEFORCE" or "ERROR" => Amber,
            "MEDIUM" or "SUSPICIOUS" => Blue,
            _ => Gray,
        };
        var label = s is "CRITICAL" or "HIGH" or "MEDIUM" or "LOW" ? s.ToLowerInvariant() : s.ToLowerInvariant();
        return $@"\b\cf{colour} {E(label)}";
    }

    /// <summary>
    /// "C:\case\Decompressed\uac-db01\[root]\var\log\auth.log" → "/var/log/auth.log".
    /// Labels that aren't paths into the collected system are kept as written.
    /// </summary>
    internal static string ShortPath(string file)
    {
        if (string.IsNullOrEmpty(file)) return "";
        var p = file.Replace('\\', '/');
        int i = p.IndexOf("/[root]/", StringComparison.OrdinalIgnoreCase);
        if (i >= 0) return p.Substring(i + "/[root]".Length);
        int dec = p.IndexOf("/Decompressed/", StringComparison.OrdinalIgnoreCase);
        if (dec >= 0)
        {
            // Skip the collection folder; "root" is "[root]" with the brackets stripped by the extractor
            var after = p.Substring(dec + "/Decompressed/".Length);
            int slash = after.IndexOf('/');
            after = slash >= 0 ? after.Substring(slash + 1) : after;
            return after.StartsWith("root/", StringComparison.OrdinalIgnoreCase) ? after.Substring(4) : after;
        }
        return file;
    }
}

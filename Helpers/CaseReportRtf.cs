using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Helpers
{
    /// <summary>
    /// Case report as RTF (opens in Word, WordPad, LibreOffice). Same content
    /// and order as the HTML export, from <see cref="CaseReport.Compose"/>.
    /// A4, 2 cm margins; likelihood is shown as coloured bold text.
    /// </summary>
    public static class CaseReportRtf
    {
        // Colour table indexes (\cfN / \clcbpatN)
        private const int Text = 1, Muted = 2, Red = 3, RedBg = 4, Amber = 5, AmberBg = 6, Blue = 7, BlueBg = 8,
                          Gray = 9, GrayBg = 10, Border = 11, Surface = 12;

        private const string ColorTable =
            @"{\colortbl ;" +
            @"\red26\green26\blue26;" +      // 1 text
            @"\red107\green107\blue107;" +   // 2 muted
            @"\red163\green45\blue45;" +     // 3 red
            @"\red252\green235\blue235;" +   // 4 red bg
            @"\red133\green79\blue11;" +     // 5 amber
            @"\red250\green238\blue218;" +   // 6 amber bg
            @"\red24\green95\blue165;" +     // 7 blue
            @"\red230\green241\blue251;" +   // 8 blue bg
            @"\red95\green94\blue90;" +      // 9 gray
            @"\red241\green239\blue232;" +   // 10 gray bg
            @"\red226\green226\blue226;" +   // 11 border
            @"\red246\green246\blue244;}";   // 12 surface

        private const int PageWidth = 9638;   // A4 (11906) minus 2 × 1134 margins, in twips

        public static string Render(CaseReportData data, CaseReportNotes notes)
        {
            var c = CaseReport.Compose(data, notes);
            var sb = new StringBuilder();
            sb.Append(@"{\rtf1\ansi\ansicpg1252\deff0\uc1");
            sb.Append(@"{\fonttbl{\f0\fswiss\fcharset0 Segoe UI;}{\f1\fmodern\fcharset0 Consolas;}}");
            sb.Append(ColorTable);
            sb.Append(@"\paperw11906\paperh16838\margl1134\margr1134\margt1134\margb1134");
            sb.Append(@"\viewkind4\f0\fs20\cf1").AppendLine();

            // Header
            Para(sb, $@"\fs17\cf{Muted} " + E(string.Join(" · ", c.Meta)), after: 60);
            Para(sb, @"\fs36\b " + E(c.Title), after: 80);
            Para(sb,
                $@"{{\b\cf{(c.Severity is "Critical" ? Red : c.Severity is "High" ? Amber : Gray)} Severity: {E(c.Severity.ToLowerInvariant())}}}" +
                $@"\tab {{\b\cf{(c.Status is "Closed" ? Gray : Amber)} Status: {E(c.Status.ToLowerInvariant())}}}", after: 200);

            // Metrics, one shaded row
            var metrics = new (string Label, string Value)[]
            {
                ("Hosts with findings", $"{c.AffectedHosts} of {data.Hosts.Count}"),
                ("Key findings", c.Findings.Count.ToString()),
                ("Case IOCs seen", data.CaseIocsSearched ? data.CaseIocHits.Count.ToString() : "–"),
                ("First activity (UTC)", c.First.HasValue ? $"{c.First:yyyy-MM-dd HH:mm}" : "–"),
                ("Activity span", c.ActivitySpan),
            };
            Table(sb, Even(metrics.Length), new[]
            {
                metrics.Select(m => $@"\fs17\cf{Muted} {E(m.Label)}\line\fs26\b\cf{Text} {E(m.Value)}").ToArray()
            }, header: false, shading: Surface, borders: false);

            // BLUF
            H2(sb, "Bottom line up front");
            foreach (var p in c.Bluf)
                sb.Append($@"\pard\plain\f0\cf{Text}\li200\sa120\sl300\slmult1\brdrl\brdrs\brdrw30\brsp120\brdrcf{Red}\fs22 ").Append(E(p)).Append(@"\par").AppendLine();
            var scale = string.Join("   ", Enum.GetValues<Likelihood>().Reverse()
                .Select(l => $@"{{\b\cf{Fg(l)} {E(LikelihoodScale.Label(l))}}} {E(LikelihoodScale.Range(l))}"));
            Para(sb, $@"\fs16\cf{Muted} Probability scale:  " + scale, before: 60, after: 120);

            // Key findings
            H2(sb, $"Key findings ({c.Findings.Count})");
            if (c.Findings.Count == 0) Para(sb, $@"\cf{Muted} No findings were selected for this report.");
            int n = 0;
            foreach (var f in c.Findings)
            {
                n++;
                var (head, detail) = CaseReport.SplitTitle(f.Text);
                Para(sb, $@"\keepn\b\fs21 F{n} \u183? {E(head)}\b0   {{\b\cf{Fg(f.Likelihood)} {E(LikelihoodScale.Label(f.Likelihood))}}}", before: 200, after: 40);
                if (detail.Length > 0) Para(sb, $@"\keepn\f1\fs16\cf{Muted} {E(detail)}", after: 60);
                var ips = c.HostIps(f.Host);
                var rows = new List<string[]>
                {
                    new[] { "Host", $@"\f1 {E(f.Host)}\f0" + (ips.Length > 0 ? $@"{{\cf{Muted}  ({E(ips)})}}" : "") },
                    new[] { "Time", f.TimeUtc.HasValue ? E(f.TimeText) + " UTC" : $@"{{\cf{Muted} no timestamp}}" },
                    new[] { "Sources", $@"{E(f.SourceText)} {{\cf{Muted}  \u183? {E(f.Collection)}\\QuickWins.txt}}" },
                    new[] { "Basis", E(f.Basis) },
                };
                if (f.IsAnalystAssessed)
                    rows.Add(new[] { "Assessment", $"Set by analyst (automatic: {E(LikelihoodScale.Label(f.AutoLikelihood).ToLowerInvariant())})" });
                if (!string.IsNullOrWhiteSpace(f.Note)) rows.Add(new[] { "Note", E(f.Note) });
                Table(sb, new[] { 1300, PageWidth - 1300 },
                    rows.Select(r => new[] { $@"\cf{Muted} {r[0]}", r[1] }).ToArray(), header: false, fontSize: 18);
            }

            // Timeline
            if (c.Timeline.Count > 0)
            {
                H2(sb, "Timeline (UTC)");
                var rows = new List<string[]> { new[] { "Time", "Host", "Event", "Source", "Likelihood" } };
                string? lastDay = null;
                var dayRows = new HashSet<int>();
                foreach (var f in c.Timeline)
                {
                    var day = f.TimeUtc!.Value.ToString("yyyy-MM-dd");
                    if (day != lastDay) { dayRows.Add(rows.Count); rows.Add(new[] { $@"\b {day}", "", "", "", "" }); lastDay = day; }
                    rows.Add(new[]
                    {
                        $@"\f1 {f.TimeUtc:HH:mm:ss}",
                        $@"\f1 {E(f.Host)}",
                        E(CaseReport.SplitTitle(f.Text).Title) + (f.LateralTo != null ? $@" {{\b\cf{Red} Lateral {E("→")} {E(f.LateralTo)}}}" : ""),
                        $@"\cf{Muted} {E(f.SourceText)}",
                        $@"\b\cf{Fg(f.Likelihood)} {E(LikelihoodScale.Label(f.Likelihood))}",
                    });
                }
                Table(sb, new[] { 1000, 1100, 4838, 1200, 1500 }, rows.ToArray(), header: true, shadedRows: dayRows);
            }

            // Lateral movement
            if (data.Lateral.Count > 0)
            {
                H2(sb, "Lateral movement between case hosts");
                var rows = new List<string[]> { new[] { "From", "To", "Evidence", "Source" } };
                foreach (var l in data.Lateral)
                {
                    var ips = c.HostIps(l.To);
                    rows.Add(new[]
                    {
                        $@"\f1 {E(l.From)}",
                        $@"\f1 {E(l.To)}\f0" + (ips.Length > 0 ? $@"{{\cf{Muted}  ({E(ips)})}}" : ""),
                        E(l.Evidence == null ? "" : CaseReport.SplitTitle(l.Evidence.Text).Title) +
                            (l.Evidence?.TimeUtc is DateTime t ? $@" {{\cf{Muted} {t:yyyy-MM-dd HH:mm:ss}}}" : ""),
                        $@"\cf{Muted} {E(l.Evidence?.Source)}",
                    });
                }
                Table(sb, new[] { 1300, 2300, 4838, 1200 }, rows.ToArray(), header: true);
            }

            // Hosts
            H2(sb, "Hosts");
            var hostRows = new List<string[]> { new[] { "Host", "IP", "Crit", "High", "Med", "Activity (UTC)", "Collection" } };
            foreach (var h in data.Hosts)
                hostRows.Add(new[]
                {
                    $@"\f1 {E(h.Host)}",
                    $@"\f1 {E(h.Ips.Count == 0 ? "unknown" : string.Join(", ", h.Ips))}",
                    h.HasFile ? (h.Critical > 0 ? $@"\b\cf{Red} {h.Critical}" : h.Critical.ToString()) : "?",
                    h.HasFile ? h.High.ToString() : "?",
                    h.HasFile ? h.Medium.ToString() : "?",
                    h.First.HasValue ? $@"{h.First:yyyy-MM-dd HH:mm} {E("→")} {h.Last:yyyy-MM-dd HH:mm}" : "–",
                    $@"\cf{Muted} {E(h.Collection)}",
                });
            Table(sb, new[] { 1200, 1500, 600, 600, 600, 2400, 2738 }, hostRows.ToArray(), header: true);

            // Indicators
            if (data.CaseIocHits.Count > 0 || data.SharedIocs.Count > 0)
            {
                H2(sb, "Indicators");
                if (data.CaseIocHits.Count > 0)
                {
                    Para(sb, $@"\b\cf{Muted} From the case IOC list", before: 80, after: 60);
                    var rows = new List<string[]> { new[] { "Kind", "Indicator", "Hosts", "First seen (UTC)", "Detail" } };
                    foreach (var i in data.CaseIocHits)
                        rows.Add(new[]
                        {
                            $@"\cf{Muted} {E(i.Kind)}", $@"\f1 {E(i.Value)}", $@"\f1 {E(string.Join(", ", i.Hosts))}",
                            i.FirstSeen.HasValue ? $"{i.FirstSeen:yyyy-MM-dd HH:mm:ss}" : "–",
                            E(i.Detail) + (i.Comment.Length > 0 ? $@" {{\cf{Muted} # {E(i.Comment)}}}" : ""),
                        });
                    Table(sb, new[] { 900, 2400, 2000, 1600, 2738 }, rows.ToArray(), header: true);
                }
                if (data.SharedIocs.Count > 0)
                {
                    Para(sb, $@"\b\cf{Muted} Seen on more than one host", before: 160, after: 60);
                    var rows = new List<string[]> { new[] { "Kind", "Indicator", "Hosts", "Detail" } };
                    foreach (var i in data.SharedIocs)
                        rows.Add(new[] { $@"\cf{Muted} {E(i.Kind)}", $@"\f1 {E(i.Value)}", $@"\f1 {E(string.Join(", ", i.Hosts))}", $@"\cf{Muted} {E(i.Detail)}" });
                    Table(sb, new[] { 900, 2800, 2300, 3638 }, rows.ToArray(), header: true);
                }
            }

            // Gaps
            if (c.Gaps.Count > 0)
            {
                H2(sb, "Intelligence gaps");
                foreach (var (g, detected) in c.Gaps)
                    sb.Append($@"\pard\plain\f0\fs20\cf{Text}\li300\fi-300\sa80{{\b\cf{Amber} ?}}\tab ").Append(E(g))
                      .Append(detected ? $@" {{\cf{Muted} (detected)}}" : "").Append(@"\par").AppendLine();
            }

            // Next steps
            if (c.Steps.Count > 0)
            {
                H2(sb, "Next steps");
                foreach (var (text, done) in c.Steps)
                    sb.Append($@"\pard\plain\f0\fs20\cf{Text}\li360\fi-360\sa80{(done ? $@"{{\cf{Blue} {E("☑")}}}" : E("☐"))}\tab ")
                      .Append(done ? $@"{{\cf{Muted} {E(text)}}}" : E(text)).Append(@"\par").AppendLine();
            }

            // Method
            sb.Append($@"\pard\plain\f0\sb480\sa60\brdrt\brdrs\brdrw10\brsp100\brdrcf{Border}\fs17\cf{Muted}{{\b\cf{Text} How likelihood is assessed.}} ")
              .Append(E(CaseReport.MethodNote)).Append(@"\par").AppendLine();
            Para(sb, $@"\fs17\cf{Muted} Generated by CSIRT UAC Parser.");

            sb.Append('}');
            return sb.ToString();
        }

        private static int Fg(Likelihood l) => l switch
        {
            Likelihood.AlmostCertain => Red,
            Likelihood.HighlyLikely => Amber,
            Likelihood.Likely => Blue,
            _ => Gray,
        };

        private static int[] Even(int n) => Enumerable.Repeat(PageWidth / n, n).ToArray();

        private static void Para(StringBuilder sb, string rtf, int before = 0, int after = 0) =>
            sb.Append($@"\pard\plain\f0\fs20\cf{Text}\sb{before}\sa{after} ").Append(rtf).Append(@"\par").AppendLine();

        private static void H2(StringBuilder sb, string text) =>
            sb.Append($@"\pard\plain\keepn\f0\cf{Text}\sb400\sa140\brdrb\brdrs\brdrw10\brsp40\brdrcf{Border}\b\fs26 ")
              .Append(E(text)).Append(@"\par").AppendLine();

        /// <summary>Cells are RTF fragments (already escaped). Widths in twips.</summary>
        private static void Table(StringBuilder sb, int[] widths, string[][] rows, bool header, int shading = 0,
                                  bool borders = true, int fontSize = 17, ISet<int>? shadedRows = null)
        {
            for (int r = 0; r < rows.Length; r++)
            {
                bool isHeader = header && r == 0;
                int rowShade = isHeader || shadedRows?.Contains(r) == true ? Surface : shading;
                sb.Append(@"\trowd\trgaph100\trleft0\trpaddl100\trpaddr100\trpaddfl3\trpaddfr3");
                if (isHeader) sb.Append(@"\trhdr");
                if (!isHeader) sb.Append(@"\trkeep");
                if (shadedRows?.Contains(r) == true) sb.Append(@"\trkeepfollow");   // day header stays with its first event
                int x = 0;
                foreach (var w in widths)
                {
                    if (borders) sb.Append($@"\clbrdrb\brdrs\brdrw10\brdrcf{Border}");
                    if (rowShade > 0) sb.Append($@"\clcbpat{rowShade}");
                    // Shaded rows (timeline day headers) span the whole table
                    if (shadedRows?.Contains(r) == true) sb.Append(x == 0 ? @"\clmgf" : @"\clmrg");
                    sb.Append(@"\clvertalt");
                    x += w;
                    sb.Append($@"\cellx{x}");
                }
                sb.AppendLine();
                foreach (var cell in rows[r].Concat(Enumerable.Repeat("", Math.Max(0, widths.Length - rows[r].Length))))
                {
                    sb.Append($@"\pard\plain\intbl\f0\fs{fontSize}\cf{Text}\sb60\sa60 ");
                    sb.Append(isHeader ? $@"{{\b\cf{Muted} {cell}}}" : $"{{{cell}}}");
                    sb.Append(@"\cell");
                }
                sb.Append(@"\row").AppendLine();
            }
            sb.Append(@"\pard\plain\f0\fs20\sa80\par").AppendLine();
        }

        /// <summary>Escapes text for RTF; anything outside ASCII becomes \uN?.</summary>
        public static string E(string? s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(s.Length + 16);
            foreach (var ch in s)
            {
                switch (ch)
                {
                    case '\\': sb.Append(@"\\"); break;
                    case '{': sb.Append(@"\{"); break;
                    case '}': sb.Append(@"\}"); break;
                    case '\n': sb.Append(@"\line "); break;
                    case '\r': break;
                    case '\t': sb.Append(@"\tab "); break;
                    default:
                        if (ch < 0x80) sb.Append(ch);
                        else sb.Append(@"\u").Append((short)ch).Append('?');
                        break;
                }
            }
            return sb.ToString();
        }
    }
}

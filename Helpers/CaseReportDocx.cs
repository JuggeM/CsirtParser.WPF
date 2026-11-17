using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using W = DocumentFormat.OpenXml.Wordprocessing;

namespace Helpers
{
    /// <summary>
    /// Case report as a Word document (.docx). Same content and order as the
    /// HTML export, from <see cref="CaseReport.Compose"/>. Section titles use
    /// the built-in Heading 1/2 styles, so a table of contents and the Word
    /// navigation pane work; likelihood is a shaded label as in the HTML.
    /// </summary>
    public static class CaseReportDocx
    {
        private const string Text = "1A1A1A", Muted = "6B6B6B", Red = "A32D2D", RedBg = "FCEBEB",
                             Amber = "854F0B", AmberBg = "FAEEDA", Blue = "185FA5", BlueBg = "E6F1FB",
                             Gray = "5F5E5A", GrayBg = "F1EFE8", Border = "E2E2E2", Surface = "F6F6F4";
        private const string Mono = "Consolas", Sans = "Segoe UI";
        private const int PageWidth = 9638;   // A4 minus 2 × 2 cm margins, in twips

        /// <summary>One run of text and how it looks.</summary>
        private sealed record Seg(string Text, bool Bold = false, string? Color = null, bool Code = false,
                                  int? Size = null, string? Fill = null);

        private static Seg S(string t) => new(t);
        private static Seg B(string t, string? color = null) => new(t, Bold: true, Color: color);
        private static Seg M(string t, string? color = null) => new(t, Code: true, Color: color, Size: 17);
        private static Seg Dim(string t) => new(t, Color: Muted);

        public static void Write(string path, CaseReportData data, CaseReportNotes notes)
        {
            var c = CaseReport.Compose(data, notes);
            using var stream = new FileStream(path, FileMode.Create, FileAccess.ReadWrite);
            using var doc = WordprocessingDocument.Create(stream, WordprocessingDocumentType.Document);
            var main = doc.AddMainDocumentPart();
            AddStyles(main);
            doc.PackageProperties.Title = c.Title;
            doc.PackageProperties.Creator = string.IsNullOrWhiteSpace(data.Analyst) ? "CSIRT UAC Parser" : data.Analyst;

            var body = new W.Body();

            // Header
            body.Append(P(new[] { new Seg(string.Join(" · ", c.Meta), Color: Muted, Size: 17) }, after: 40));
            body.Append(P(new[] { S(c.Title) }, style: "Title"));
            body.Append(P(new[]
            {
                Pill("Severity: " + c.Severity.ToLowerInvariant(), c.Severity is "Critical" ? Red : c.Severity is "High" ? Amber : Gray,
                     c.Severity is "Critical" ? RedBg : c.Severity is "High" ? AmberBg : GrayBg),
                S("  "),
                Pill("Status: " + c.Status.ToLowerInvariant(), c.Status is "Closed" ? Gray : Amber, c.Status is "Closed" ? GrayBg : AmberBg),
            }, after: 200));

            // Metrics
            var metrics = new (string Label, string Value)[]
            {
                ("Hosts with findings", $"{c.AffectedHosts} of {data.Hosts.Count}"),
                ("Key findings", c.Findings.Count.ToString()),
                ("Case IOCs seen", data.CaseIocsSearched ? data.CaseIocHits.Count.ToString() : "–"),
                ("First activity (UTC)", c.First.HasValue ? $"{c.First:yyyy-MM-dd HH:mm}" : "–"),
                ("Activity span", c.ActivitySpan),
            };
            var mt = NewTable(Enumerable.Repeat(PageWidth / metrics.Length, metrics.Length).ToArray(), borders: false);
            var mrow = new W.TableRow();
            foreach (var (label, value) in metrics)
                mrow.Append(Cell(PageWidth / metrics.Length, Surface,
                    P(new[] { new Seg(label, Color: Muted, Size: 17) }, after: 20),
                    P(new[] { new Seg(value, Bold: true, Size: 26) }, after: 20)));
            mt.Append(mrow);
            body.Append(mt);

            // BLUF
            body.Append(H1("Bottom line up front"));
            foreach (var p in c.Bluf)
            {
                body.Append(P(new[] { new Seg(p, Size: 22) }, after: 120,
                    border: new W.ParagraphBorders(new W.LeftBorder { Val = W.BorderValues.Single, Size = 18, Space = 8, Color = Red }),
                    indent: new W.Indentation { Left = "200" }));
            }
            var scale = new List<Seg> { Dim("Probability scale:  ") };
            foreach (var l in Enum.GetValues<Likelihood>().Reverse())
            {
                scale.Add(Pill($"{LikelihoodScale.Label(l)} {LikelihoodScale.Range(l)}", Fg(l), Bg(l)) with { Size = 16 });
                scale.Add(S(" "));
            }
            body.Append(P(scale, before: 60, after: 120));

            // Key findings
            body.Append(H1($"Key findings ({c.Findings.Count})"));
            if (c.Findings.Count == 0) body.Append(P(new[] { Dim("No findings were selected for this report.") }));
            int n = 0;
            foreach (var f in c.Findings)
            {
                n++;
                var (head, detail) = CaseReport.SplitTitle(f.Text);
                body.Append(P(new[] { new Seg($"F{n} · {head}", Bold: true, Size: 21), S("   "), Pill(LikelihoodScale.Label(f.Likelihood), Fg(f.Likelihood), Bg(f.Likelihood)) },
                              before: 200, after: 40, keepNext: true));
                if (detail.Length > 0) body.Append(P(new[] { M(detail, Muted) with { Size = 16 } }, after: 60, keepNext: true));

                var ips = c.HostIps(f.Host);
                var rows = new List<Seg[]>
                {
                    new[] { Dim("Host"), M(f.Host), Dim(ips.Length > 0 ? $" ({ips})" : "") },
                    new[] { Dim("Time"), f.TimeUtc.HasValue ? S(f.TimeText + " UTC") : Dim("no timestamp") },
                    new[] { Dim("Sources"), S(f.SourceText), Dim($" · {f.Collection}\\QuickWins.txt") },
                    new[] { Dim("Basis"), S(f.Basis) },
                };
                if (f.IsAnalystAssessed)
                    rows.Add(new[] { Dim("Assessment"), S($"Set by analyst (automatic: {LikelihoodScale.Label(f.AutoLikelihood).ToLowerInvariant()})") });
                if (!string.IsNullOrWhiteSpace(f.Note)) rows.Add(new[] { Dim("Note"), S(f.Note) });
                var t = NewTable(new[] { 1300, PageWidth - 1300 });
                foreach (var r in rows)
                    t.Append(new W.TableRow(new W.TableRowProperties(new W.CantSplit()),
                        Cell(1300, null, P(new[] { r[0] } , size: 18)),
                        Cell(PageWidth - 1300, null, P(r.Skip(1), size: 18))));
                body.Append(t);
            }

            // Timeline
            if (c.Timeline.Count > 0)
            {
                body.Append(H1("Timeline (UTC)"));
                var widths = new[] { 1000, 1100, 4838, 1200, 1500 };
                var t = NewTable(widths);
                t.Append(HeaderRow(widths, "Time", "Host", "Event", "Source", "Likelihood"));
                string? lastDay = null;
                foreach (var f in c.Timeline)
                {
                    var day = f.TimeUtc!.Value.ToString("yyyy-MM-dd");
                    if (day != lastDay)
                    {
                        // keepNext keeps the day header on the same page as its first event
                        var dc = Cell(widths.Sum(), Surface, widths.Length, P(new[] { B(day, Muted) }, size: 17, keepNext: true));
                        t.Append(new W.TableRow(new W.TableRowProperties(new W.CantSplit()), dc));
                        lastDay = day;
                    }
                    var ev = new List<Seg> { S(CaseReport.SplitTitle(f.Text).Title) };
                    if (f.LateralTo != null) { ev.Add(S(" ")); ev.Add(Pill($"Lateral → {f.LateralTo}", Red, RedBg)); }
                    t.Append(Row(widths,
                        new[] { M($"{f.TimeUtc:HH:mm:ss}") }, new[] { M(f.Host) }, ev.ToArray(),
                        new[] { Dim(f.SourceText) }, new[] { Pill(LikelihoodScale.Label(f.Likelihood), Fg(f.Likelihood), Bg(f.Likelihood)) }));
                }
                body.Append(t);
            }

            // Lateral movement
            if (data.Lateral.Count > 0)
            {
                body.Append(H1("Lateral movement between case hosts"));
                var widths = new[] { 1300, 2300, 4838, 1200 };
                var t = NewTable(widths);
                t.Append(HeaderRow(widths, "From", "To", "Evidence", "Source"));
                foreach (var l in data.Lateral)
                {
                    var ips = c.HostIps(l.To);
                    t.Append(Row(widths,
                        new[] { M(l.From) },
                        new[] { M(l.To), Dim(ips.Length > 0 ? $" ({ips})" : "") },
                        new[] { S(l.Evidence == null ? "" : CaseReport.SplitTitle(l.Evidence.Text).Title),
                                Dim(l.Evidence?.TimeUtc is DateTime tm ? $" {tm:yyyy-MM-dd HH:mm:ss}" : "") },
                        new[] { Dim(l.Evidence?.Source ?? "") }));
                }
                body.Append(t);
            }

            // Hosts
            body.Append(H1("Hosts"));
            {
                var widths = new[] { 1200, 1500, 600, 600, 600, 2400, 2738 };
                var t = NewTable(widths);
                t.Append(HeaderRow(widths, "Host", "IP", "Crit", "High", "Med", "Activity (UTC)", "Collection"));
                foreach (var h in data.Hosts)
                    t.Append(Row(widths,
                        new[] { M(h.Host) },
                        new[] { M(h.Ips.Count == 0 ? "unknown" : string.Join(", ", h.Ips)) },
                        new[] { h.HasFile ? (h.Critical > 0 ? B(h.Critical.ToString(), Red) : S(h.Critical.ToString())) : S("?") },
                        new[] { S(h.HasFile ? h.High.ToString() : "?") },
                        new[] { S(h.HasFile ? h.Medium.ToString() : "?") },
                        new[] { S(h.First.HasValue ? $"{h.First:yyyy-MM-dd HH:mm} → {h.Last:yyyy-MM-dd HH:mm}" : "–") },
                        new[] { Dim(h.Collection) }));
                body.Append(t);
            }

            // Indicators
            if (data.CaseIocHits.Count > 0 || data.SharedIocs.Count > 0)
            {
                body.Append(H1("Indicators"));
                if (data.CaseIocHits.Count > 0)
                {
                    body.Append(P(new[] { S("From the case IOC list") }, style: "Heading2"));
                    var widths = new[] { 900, 2400, 2000, 1600, 2738 };
                    var t = NewTable(widths);
                    t.Append(HeaderRow(widths, "Kind", "Indicator", "Hosts", "First seen (UTC)", "Detail"));
                    foreach (var i in data.CaseIocHits)
                        t.Append(Row(widths,
                            new[] { Dim(i.Kind) }, new[] { M(i.Value) }, new[] { M(string.Join(", ", i.Hosts)) },
                            new[] { S(i.FirstSeen.HasValue ? $"{i.FirstSeen:yyyy-MM-dd HH:mm:ss}" : "–") },
                            new[] { S(i.Detail), Dim(i.Comment.Length > 0 ? $" # {i.Comment}" : "") }));
                    body.Append(t);
                }
                if (data.SharedIocs.Count > 0)
                {
                    body.Append(P(new[] { S("Seen on more than one host") }, style: "Heading2"));
                    var widths = new[] { 900, 2800, 2300, 3638 };
                    var t = NewTable(widths);
                    t.Append(HeaderRow(widths, "Kind", "Indicator", "Hosts", "Detail"));
                    foreach (var i in data.SharedIocs)
                        t.Append(Row(widths, new[] { Dim(i.Kind) }, new[] { M(i.Value) }, new[] { M(string.Join(", ", i.Hosts)) }, new[] { Dim(i.Detail) }));
                    body.Append(t);
                }
            }

            // Gaps
            if (c.Gaps.Count > 0)
            {
                body.Append(H1("Intelligence gaps"));
                foreach (var (g, detected) in c.Gaps)
                    body.Append(Hanging(new[] { B("?", Amber), S("\t" + g), Dim(detected ? " (detected)" : "") }, 300));
            }

            // Next steps
            if (c.Steps.Count > 0)
            {
                body.Append(H1("Next steps"));
                foreach (var (text, done) in c.Steps)
                    body.Append(Hanging(done
                        ? new[] { new Seg("☑", Color: Blue), new Seg("\t" + text, Color: Muted) }
                        : new[] { S("☐"), S("\t" + text) }, 360));
            }

            // Method
            body.Append(P(new[] { new Seg("How likelihood is assessed. ", Bold: true, Size: 17), new Seg(CaseReport.MethodNote, Color: Muted, Size: 17) },
                          before: 480, after: 60,
                          border: new W.ParagraphBorders(new W.TopBorder { Val = W.BorderValues.Single, Size = 4, Space = 6, Color = Border })));
            body.Append(P(new[] { new Seg("Generated by CSIRT UAC Parser.", Color: Muted, Size: 17) }));

            body.Append(new W.SectionProperties(
                new W.PageSize { Width = 11906U, Height = 16838U },
                new W.PageMargin { Top = 1134, Bottom = 1134, Left = 1134U, Right = 1134U, Header = 708U, Footer = 708U, Gutter = 0U }));

            main.Document = new W.Document(body);
            main.Document.Save();
        }

        // ── Building blocks ──────────────────────────────────────────────
        private static string Fg(Likelihood l) => l switch
        {
            Likelihood.AlmostCertain => Red,
            Likelihood.HighlyLikely => Amber,
            Likelihood.Likely => Blue,
            _ => Gray,
        };

        private static string Bg(Likelihood l) => l switch
        {
            Likelihood.AlmostCertain => RedBg,
            Likelihood.HighlyLikely => AmberBg,
            Likelihood.Likely => BlueBg,
            _ => GrayBg,
        };

        private static Seg Pill(string text, string fg, string bg) => new($" {text} ", Bold: true, Color: fg, Size: 17, Fill: bg);

        private static W.Run Run(Seg s, int? size = null)
        {
            var rp = new W.RunProperties();
            if (s.Code) rp.Append(new W.RunFonts { Ascii = Mono, HighAnsi = Mono, ComplexScript = Mono });
            if (s.Bold) rp.Append(new W.Bold());
            if (s.Color != null) rp.Append(new W.Color { Val = s.Color });
            var sz = s.Size ?? size;
            if (sz.HasValue) rp.Append(new W.FontSize { Val = sz.Value.ToString() });
            if (s.Fill != null) rp.Append(new W.Shading { Val = W.ShadingPatternValues.Clear, Color = "auto", Fill = s.Fill });

            var run = new W.Run(rp);
            var parts = s.Text.Split('\t');
            for (int i = 0; i < parts.Length; i++)
            {
                if (i > 0) run.Append(new W.TabChar());
                if (parts[i].Length > 0) run.Append(new W.Text(parts[i]) { Space = SpaceProcessingModeValues.Preserve });
            }
            return run;
        }

        // Children of w:pPr must follow the schema order: pStyle, keepNext, pBdr, tabs, spacing, ind
        private static W.Paragraph P(IEnumerable<Seg> segs, string? style = null, int? before = null, int? after = null,
                                     bool keepNext = false, int? size = null, W.ParagraphBorders? border = null,
                                     int? tab = null, W.Indentation? indent = null)
        {
            var pp = new W.ParagraphProperties();
            if (style != null) pp.Append(new W.ParagraphStyleId { Val = style });
            if (keepNext) pp.Append(new W.KeepNext());
            if (border != null) pp.Append(border);
            if (tab.HasValue) pp.Append(new W.Tabs(new W.TabStop { Val = W.TabStopValues.Left, Position = tab.Value }));
            if (before.HasValue || after.HasValue)
            {
                var sp = new W.SpacingBetweenLines();
                if (before.HasValue) sp.Before = before.Value.ToString();
                if (after.HasValue) sp.After = after.Value.ToString();
                pp.Append(sp);
            }
            if (indent != null) pp.Append(indent);
            var p = new W.Paragraph(pp);
            foreach (var s in segs) p.Append(Run(s, size));
            return p;
        }

        private static W.Paragraph H1(string text) => P(new[] { S(text) }, style: "Heading1");

        private static W.Paragraph Hanging(IEnumerable<Seg> segs, int indent) =>
            P(segs, after: 80, tab: indent, indent: new W.Indentation { Left = indent.ToString(), Hanging = indent.ToString() });

        private static W.Table NewTable(int[] widths, bool borders = true)
        {
            W.BorderType Line<T>() where T : W.BorderType, new() =>
                borders ? new T { Val = W.BorderValues.Single, Size = 4, Color = Border } : new T { Val = W.BorderValues.Nil };
            var t = new W.Table(new W.TableProperties(
                new W.TableWidth { Width = widths.Sum().ToString(), Type = W.TableWidthUnitValues.Dxa },
                new W.TableBorders(
                    new W.TopBorder { Val = W.BorderValues.Nil }, new W.LeftBorder { Val = W.BorderValues.Nil },
                    (W.BottomBorder)Line<W.BottomBorder>(), new W.RightBorder { Val = W.BorderValues.Nil },
                    (W.InsideHorizontalBorder)Line<W.InsideHorizontalBorder>(),
                    borders ? new W.InsideVerticalBorder { Val = W.BorderValues.Nil }
                            : new W.InsideVerticalBorder { Val = W.BorderValues.Single, Size = 24, Color = "FFFFFF" }),
                new W.TableLayout { Type = W.TableLayoutValues.Fixed },
                new W.TableCellMarginDefault(
                    new W.TopMargin { Width = "40", Type = W.TableWidthUnitValues.Dxa },
                    new W.TableCellLeftMargin { Width = 100, Type = W.TableWidthValues.Dxa },
                    new W.BottomMargin { Width = "40", Type = W.TableWidthUnitValues.Dxa },
                    new W.TableCellRightMargin { Width = 100, Type = W.TableWidthValues.Dxa })),
                new W.TableGrid(widths.Select(w => new W.GridColumn { Width = w.ToString() })));
            return t;
        }

        // w:tcPr order: tcW, gridSpan, shd, vAlign
        private static W.TableCell Cell(int width, string? fill, params W.Paragraph[] content) => Cell(width, fill, 1, content);

        private static W.TableCell Cell(int width, string? fill, int span, params W.Paragraph[] content)
        {
            var props = new W.TableCellProperties(new W.TableCellWidth { Width = width.ToString(), Type = W.TableWidthUnitValues.Dxa });
            if (span > 1) props.Append(new W.GridSpan { Val = span });
            if (fill != null) props.Append(new W.Shading { Val = W.ShadingPatternValues.Clear, Color = "auto", Fill = fill });
            props.Append(new W.TableCellVerticalAlignment { Val = W.TableVerticalAlignmentValues.Top });
            var cell = new W.TableCell(props);
            foreach (var p in content) cell.Append(p);
            return cell;
        }

        private static W.TableRow Row(int[] widths, params Seg[][] cells)
        {
            var row = new W.TableRow(new W.TableRowProperties(new W.CantSplit()));
            for (int i = 0; i < widths.Length; i++)
                row.Append(Cell(widths[i], null, P(i < cells.Length ? cells[i] : Array.Empty<Seg>(), before: 20, after: 20, size: 17)));
            return row;
        }

        private static W.TableRow HeaderRow(int[] widths, params string[] titles)
        {
            var row = new W.TableRow(new W.TableRowProperties(new W.TableHeader(), new W.CantSplit()));
            for (int i = 0; i < widths.Length; i++)
                row.Append(Cell(widths[i], Surface, P(new[] { B(titles[i], Muted) }, before: 20, after: 20, size: 17)));
            return row;
        }

        private static void AddStyles(MainDocumentPart main)
        {
            var part = main.AddNewPart<StyleDefinitionsPart>();
            W.Style ParaStyle(string id, string name, int size, int before, int after, bool border, int? outline)
            {
                var ppr = new W.StyleParagraphProperties(new W.KeepNext());
                if (border) ppr.Append(new W.ParagraphBorders(new W.BottomBorder { Val = W.BorderValues.Single, Size = 4, Space = 2, Color = Border }));
                ppr.Append(new W.SpacingBetweenLines { Before = before.ToString(), After = after.ToString() });
                if (outline.HasValue) ppr.Append(new W.OutlineLevel { Val = outline.Value });
                return new W.Style(
                    new W.StyleName { Val = name }, new W.BasedOn { Val = "Normal" }, new W.NextParagraphStyle { Val = "Normal" },
                    new W.PrimaryStyle(), ppr,
                    new W.StyleRunProperties(new W.Bold(), new W.Color { Val = Text }, new W.FontSize { Val = size.ToString() }))
                { Type = W.StyleValues.Paragraph, StyleId = id };
            }

            part.Styles = new W.Styles(
                new W.DocDefaults(
                    new W.RunPropertiesDefault(new W.RunPropertiesBaseStyle(
                        new W.RunFonts { Ascii = Sans, HighAnsi = Sans, ComplexScript = Sans, EastAsia = Sans },
                        new W.Color { Val = Text }, new W.FontSize { Val = "20" }, new W.Languages { Val = "en-GB" })),
                    new W.ParagraphPropertiesDefault(new W.ParagraphPropertiesBaseStyle(
                        new W.SpacingBetweenLines { After = "80", Line = "264", LineRule = W.LineSpacingRuleValues.Auto }))),
                new W.Style(new W.StyleName { Val = "Normal" }, new W.PrimaryStyle())
                    { Type = W.StyleValues.Paragraph, StyleId = "Normal", Default = true },
                ParaStyle("Title", "Title", 36, 0, 80, false, null),
                ParaStyle("Heading1", "heading 1", 26, 400, 140, true, 0),
                ParaStyle("Heading2", "heading 2", 20, 160, 60, false, 1));
            part.Styles.Save();
        }
    }
}

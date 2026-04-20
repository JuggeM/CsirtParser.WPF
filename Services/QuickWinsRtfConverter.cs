using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace CsirtParser.WPF.Services;

/// <summary>
/// Converts a finished QuickWins.txt into a formatted QuickWins.rtf.
/// Run this after all parsers have finished writing to QuickWins.txt.
/// Zero changes needed to any existing parser or writer code.
/// </summary>
public static class QuickWinsRtfConverter
{
    // ── RTF colour table indices (1-based) ───────────────────────────
    private const int ColBlack = 1;
    private const int ColRed = 2;   // high severity / errors
    private const int ColOrange = 3;   // suspicious / warnings
    private const int ColBlue = 4;   // IPs / timestamps
    private const int ColGreen = 5;   // success / accepted
    private const int ColGrey = 6;   // section separators
    private const int ColDarkRed = 7;   // critical headers
    private const int ColPurple = 8;   // body file findings
    private const int ColTeal = 9;   // info / file listings

    private static readonly string ColourTable =
        @"{\colortbl ;" +
        @"\red0\green0\blue0;" +   // 1 black
        @"\red180\green0\blue0;" +   // 2 red
        @"\red180\green90\blue0;" +   // 3 orange
        @"\red0\green70\blue160;" +   // 4 blue
        @"\red0\green120\blue60;" +   // 5 green
        @"\red120\green120\blue120;" +   // 6 grey
        @"\red140\green0\blue0;" +   // 7 dark red
        @"\red100\green0\blue160;" +   // 8 purple
        @"\red0\green100\blue100;" +   // 9 teal
        @"}";

    // ── IP address pattern ───────────────────────────────────────────
    private static readonly Regex IpPattern =
        new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);

    // ── Patterns that classify a line ────────────────────────────────
    private static readonly (Regex Pattern, LineStyle Style)[] LineRules = new[]
    {
        // Section headers
        (new Regex(@"^#{5,}", RegexOptions.Compiled),            LineStyle.SectionHeader),
        (new Regex(@"^#{3}", RegexOptions.Compiled),             LineStyle.SubHeader),

        // Timeline / meta
        (new Regex(@"^(First Log Entry|Last Log Entry|# Generated)", RegexOptions.Compiled), LineStyle.Meta),

        // High severity
        (new Regex(@"\[(HIGH|CRITICAL|BRUTEFORCE|SUSPICIOUS)\]", RegexOptions.IgnoreCase | RegexOptions.Compiled), LineStyle.High),
        (new Regex(@"\[AUTH\].*(?:SUSPICIOUS|failed root|root.*SSH|brute.force)", RegexOptions.IgnoreCase | RegexOptions.Compiled), LineStyle.High),
        (new Regex(@"Possible Brute-force Detected", RegexOptions.IgnoreCase | RegexOptions.Compiled), LineStyle.High),
        (new Regex(@"\[ERROR\]", RegexOptions.IgnoreCase | RegexOptions.Compiled), LineStyle.High),

        // Medium severity
        (new Regex(@"\[SUSPICIOUS\]|\[MEDIUM\]|MultipleFailures|failed attempt", RegexOptions.IgnoreCase | RegexOptions.Compiled), LineStyle.Medium),
        (new Regex(@"\[AUTH\].*Group:.*failed", RegexOptions.IgnoreCase | RegexOptions.Compiled), LineStyle.Medium),
        (new Regex(@"• \[MultipleFailures\]", RegexOptions.IgnoreCase | RegexOptions.Compiled), LineStyle.Medium),

        // Accepted / success
        (new Regex(@"Accepted (password|publickey)|session opened|successful login", RegexOptions.IgnoreCase | RegexOptions.Compiled), LineStyle.Success),

        // Body file
        (new Regex(@"^\[BODYFILE\]", RegexOptions.Compiled),     LineStyle.BodyFile),

        // File listings
        (new Regex(@"^\s+FILE:", RegexOptions.Compiled),         LineStyle.FileListing),

        // Pattern/finding summaries
        (new Regex(@"^\s+(PATTERN|FINDING|IP):", RegexOptions.Compiled), LineStyle.Finding),

        // Summary footers
        (new Regex(@"^#{5}.*Summary.*#{5}", RegexOptions.Compiled), LineStyle.SummaryFooter),
    };

    private enum LineStyle
    {
        Normal, SectionHeader, SubHeader, Meta,
        High, Medium, Success, BodyFile, FileListing, Finding, SummaryFooter
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
        var rtf = BuildRtf(lines);

        File.WriteAllText(rtfPath, rtf, Encoding.ASCII);
    }

    // ── RTF builder ──────────────────────────────────────────────────
    private static string BuildRtf(string[] lines)
    {
        var sb = new StringBuilder();

        // RTF header
        sb.Append(@"{\rtf1\ansi\deff0");
        sb.Append(@"{\fonttbl{\f0\fmodern\fcharset0 Courier New;}{\f1\fswiss\fcharset0 Segoe UI;}}");
        sb.Append(ColourTable);
        sb.Append(@"\margl720\margr720\margt720\margb720");
        sb.AppendLine();

        foreach (var rawLine in lines)
        {
            var style = ClassifyLine(rawLine);
            var escaped = EscapeRtf(rawLine);

            switch (style)
            {
                case LineStyle.SectionHeader:
                    // Large bold coloured header with a top border simulation
                    sb.Append($@"\pard\sb240\sa60\f1\fs26\b\cf{ColDarkRed} ");
                    sb.Append(escaped);
                    sb.AppendLine(@"\b0\f0\fs20\cf1\par");
                    break;

                case LineStyle.SubHeader:
                    sb.Append($@"\pard\sb120\sa40\f1\fs22\b\cf{ColBlue} ");
                    sb.Append(escaped);
                    sb.AppendLine(@"\b0\f0\fs20\cf1\par");
                    break;

                case LineStyle.Meta:
                    sb.Append($@"\pard\f1\fs18\cf{ColGrey} ");
                    sb.Append(escaped);
                    sb.AppendLine(@"\f0\fs20\cf1\par");
                    break;

                case LineStyle.High:
                    sb.Append($@"\pard\sb60\f0\fs20\b\cf{ColRed} ");
                    sb.Append(ColourIps(escaped, ColBlue, ColRed));
                    sb.AppendLine(@"\b0\cf1\par");
                    break;

                case LineStyle.Medium:
                    sb.Append($@"\pard\f0\fs20\cf{ColOrange} ");
                    sb.Append(ColourIps(escaped, ColBlue, ColOrange));
                    sb.AppendLine(@"\cf1\par");
                    break;

                case LineStyle.Success:
                    sb.Append($@"\pard\f0\fs20\cf{ColGreen} ");
                    sb.Append(ColourIps(escaped, ColBlue, ColGreen));
                    sb.AppendLine(@"\cf1\par");
                    break;

                case LineStyle.BodyFile:
                    sb.Append($@"\pard\f0\fs20\cf{ColPurple} ");
                    sb.Append(escaped);
                    sb.AppendLine(@"\cf1\par");
                    break;

                case LineStyle.FileListing:
                    sb.Append($@"\pard\li360\f0\fs18\cf{ColTeal} ");
                    sb.Append(escaped);
                    sb.AppendLine(@"\cf1\par");
                    break;

                case LineStyle.Finding:
                    sb.Append($@"\pard\li360\f0\fs19\cf{ColTeal} ");
                    sb.Append(ColourIps(escaped, ColBlue, ColTeal));
                    sb.AppendLine(@"\cf1\par");
                    break;

                case LineStyle.SummaryFooter:
                    sb.Append($@"\pard\sb80\f1\fs18\i\cf{ColGrey} ");
                    sb.Append(escaped);
                    sb.AppendLine(@"\i0\f0\fs20\cf1\par");
                    break;

                default:
                    if (string.IsNullOrWhiteSpace(rawLine))
                    {
                        sb.AppendLine(@"\pard\par");
                    }
                    else
                    {
                        sb.Append($@"\pard\f0\fs20\cf{ColBlack} ");
                        sb.Append(ColourIps(escaped, ColBlue, ColBlack));
                        sb.AppendLine(@"\cf1\par");
                    }
                    break;
            }
        }

        sb.Append('}');
        return sb.ToString();
    }

    // ── Line classifier ───────────────────────────────────────────────
    private static LineStyle ClassifyLine(string line)
    {
        foreach (var (pattern, style) in LineRules)
            if (pattern.IsMatch(line))
                return style;
        return LineStyle.Normal;
    }

    // ── IP colouring ──────────────────────────────────────────────────
    private static string ColourIps(string escapedLine, int ipColour, int restoreColour)
    {
        // We need to work on the raw (pre-escaped) content for the regex,
        // then re-escape the parts. Simpler: just apply colour tags around
        // the already-escaped IP match positions.
        return IpPattern.Replace(escapedLine, m =>
            $@"\cf{ipColour}\b {m.Value}\b0\cf{restoreColour}");
    }

    // ── RTF escape ───────────────────────────────────────────────────
    private static string EscapeRtf(string text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        var sb = new StringBuilder(text.Length + 16);
        foreach (var ch in text)
        {
            switch (ch)
            {
                case '\\': sb.Append(@"\\"); break;
                case '{': sb.Append(@"\{"); break;
                case '}': sb.Append(@"\}"); break;
                default:
                    if (ch > 127)
                        sb.Append($@"\u{(int)ch}?");
                    else
                        sb.Append(ch);
                    break;
            }
        }
        return sb.ToString();
    }
}
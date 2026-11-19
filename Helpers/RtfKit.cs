using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Helpers
{
    /// <summary>
    /// Shared RTF building blocks for the case report and QuickWins.rtf, so
    /// both documents look the same: A4, 2 cm margins, Segoe UI with Consolas
    /// for paths and times, a muted palette and ruled section headings.
    /// </summary>
    internal static class RtfKit
    {
        // Colour table indexes (\cfN / \clcbpatN)
        public const int Text = 1, Muted = 2, Red = 3, RedBg = 4, Amber = 5, AmberBg = 6, Blue = 7, BlueBg = 8,
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

        /// <summary>A4 (11906) minus 2 × 1134 margins, in twips.</summary>
        public const int PageWidth = 9638;

        /// <summary>Opens the document: fonts (\f0 Segoe UI, \f1 Consolas), colours, A4 page.</summary>
        public static void Begin(StringBuilder sb)
        {
            sb.Append(@"{\rtf1\ansi\ansicpg1252\deff0\uc1");
            sb.Append(@"{\fonttbl{\f0\fswiss\fcharset0 Segoe UI;}{\f1\fmodern\fcharset0 Consolas;}}");
            sb.Append(ColorTable);
            sb.Append(@"\paperw11906\paperh16838\margl1134\margr1134\margt1134\margb1134");
            sb.Append(@"\viewkind4\f0\fs20\cf1").AppendLine();
        }

        public static void End(StringBuilder sb) => sb.Append('}');

        public static int[] Even(int n) => Enumerable.Repeat(PageWidth / n, n).ToArray();

        /// <summary>A paragraph; <paramref name="rtf"/> is an already-escaped fragment.</summary>
        public static void Para(StringBuilder sb, string rtf, int before = 0, int after = 0) =>
            sb.Append($@"\pard\plain\f0\fs20\cf{Text}\sb{before}\sa{after} ").Append(rtf).Append(@"\par").AppendLine();

        public static void H2(StringBuilder sb, string text) =>
            sb.Append($@"\pard\plain\keepn\f0\cf{Text}\sb400\sa140\brdrb\brdrs\brdrw10\brsp40\brdrcf{Border}\b\fs26 ")
              .Append(E(text)).Append(@"\par").AppendLine();

        /// <summary>Cells are RTF fragments (already escaped). Widths in twips.</summary>
        public static void Table(StringBuilder sb, int[] widths, string[][] rows, bool header, int shading = 0,
                                 bool borders = true, int fontSize = 17, ISet<int>? shadedRows = null)
        {
            for (int r = 0; r < rows.Length; r++)
            {
                bool isHeader = header && r == 0;
                int rowShade = isHeader || shadedRows?.Contains(r) == true ? Surface : shading;
                sb.Append(@"\trowd\trgaph100\trleft0\trpaddl100\trpaddr100\trpaddfl3\trpaddfr3");
                if (isHeader) sb.Append(@"\trhdr");
                if (!isHeader) sb.Append(@"\trkeep");
                if (shadedRows?.Contains(r) == true) sb.Append(@"\trkeepfollow");   // a group header stays with its first row
                int x = 0;
                foreach (var w in widths)
                {
                    if (borders) sb.Append($@"\clbrdrb\brdrs\brdrw10\brdrcf{Border}");
                    if (rowShade > 0) sb.Append($@"\clcbpat{rowShade}");
                    // Shaded rows (group headers) span the whole table
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

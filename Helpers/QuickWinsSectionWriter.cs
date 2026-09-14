using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Single shared writer for every "########## [LOGKEY] ... ##########"
    /// section in QuickWins.txt. Replaces four near-duplicate inline writers
    /// that used to live in ParserOrchestrator (one each for the grouped
    /// logs, auth/secure, crontab, and web) plus Docker, whose findings
    /// previously never reached QuickWins.txt at all.
    ///
    /// What this fixes vs. the old per-caller code:
    ///   - One consistent section format instead of three slightly different
    ///     ones (some had "End of ..." footers, some didn't; Docker's
    ///     findings weren't written to the file body at all).
    ///   - Findings are sorted worst-first (Critical/High/Bruteforce before
    ///     Suspicious/Medium) instead of file-discovery order, so the most
    ///     important line in a section is always near the top.
    ///   - The redundant per-finding "[LOGKEY]" prefix (e.g. "[AUTH]" inside
    ///     an already-[AUTH.LOG]-headed section) is stripped — every finding
    ///     already carries its own severity tag, so the log-type tag added
    ///     nothing but repetition.
    ///   - Full Windows paths are shown as just the filename.
    ///
    /// RTF COMPATIBILITY: QuickWinsRtfConverter colourises QuickWins.txt
    /// afterwards by regex. It requires section headers to start with 5+
    /// '#' characters, and finding lines to contain a literal severity tag
    /// such as [CRITICAL]/[HIGH]/[SUSPICIOUS]/[BRUTEFORCE]/[MEDIUM]/[ERROR].
    /// Both are preserved here — every parser already emits an explicit
    /// severity tag on every finding, so only the redundant log-type tag is
    /// removed.
    /// </summary>
    public static class QuickWinsSectionWriter
    {
        private static readonly string[] SeverityOrder =
            { "CRITICAL", "HIGH", "BRUTEFORCE", "SUSPICIOUS", "MEDIUM", "ERROR" };

        // Matches a leading "[SOMETAG]" immediately followed by another
        // bracketed tag — the redundant log-type prefix every parser emits
        // ("[AUTH] [HIGH] ...", "[DOCKER] [CRITICAL] ..."). Only that first
        // tag is stripped; the severity tag right after it is kept.
        private static readonly Regex LeadingLogTag =
            new(@"^\[[A-Za-z0-9_.]+\](?=\s*\[)", RegexOptions.Compiled);

        /// <summary>
        /// Writes one section. Call once per log type per collection.
        /// perFileFindings pairs a short file/source label with that
        /// source's findings — pass a single group (e.g. "containers") for
        /// sources that aren't naturally file-based, like Docker.
        /// Safe to call with zero findings: writes a one-line notice using
        /// emptyMessage instead of an empty section body.
        /// </summary>
        public static void WriteSection(
            string quickWinsFile,
            string logKey,
            string emptyMessage,
            List<(string FileName, List<string> Findings)> perFileFindings)
        {
            using var w = new StreamWriter(quickWinsFile, append: true);
            w.WriteLine();

            int total = perFileFindings.Sum(f => f.Findings.Count);
            int fileCount = perFileFindings.Count(f => f.Findings.Count > 0);

            w.WriteLine(total > 0
                ? $"########## [{logKey}] — {total} finding(s) across {fileCount} file(s) ##########"
                : $"########## [{logKey}] ##########");

            if (total == 0)
            {
                w.WriteLine($"  {emptyMessage}");
                return;
            }

            var flattened = perFileFindings
                .Where(f => f.Findings.Count > 0)
                .SelectMany(f => f.Findings.Select(finding =>
                    (FileName: f.FileName, Text: CleanFinding(finding), Rank: SeverityRank(finding))))
                .OrderBy(x => x.Rank)
                .ThenBy(x => x.FileName, StringComparer.OrdinalIgnoreCase);

            foreach (var (fileName, text, _) in flattened)
                w.WriteLine($"  {ShortName(fileName)}: {text}");
        }

        /// <summary>
        /// Strips a redundant leading "[LOGKEY]" tag from a finding string,
        /// leaving the severity tag and everything after it untouched.
        /// </summary>
        private static string CleanFinding(string finding)
        {
            if (string.IsNullOrEmpty(finding)) return finding;
            return LeadingLogTag.Replace(finding, "").TrimStart();
        }

        private static int SeverityRank(string finding)
        {
            for (int i = 0; i < SeverityOrder.Length; i++)
                if (finding.Contains($"[{SeverityOrder[i]}]", StringComparison.OrdinalIgnoreCase))
                    return i;
            return SeverityOrder.Length; // no recognised tag — sort last, don't drop it
        }

        private static string ShortName(string fileNameOrPath)
        {
            if (string.IsNullOrEmpty(fileNameOrPath)) return fileNameOrPath;
            try { return Path.GetFileName(fileNameOrPath); }
            catch { return fileNameOrPath; }
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Helpers
{
    public abstract class LogFileParser
    {
        protected int? InferredYear = null;
        protected TimeSpan? TimeOffset = null;

        // ── Public entry points ──────────────────────────────────────────────

        /// <summary>
        /// Parse a single file and return findings WITHOUT writing to QuickWins.
        /// The orchestrator collects findings from every file in a rotation set and
        /// writes ONE combined section with per-file sub-headers, which is why this
        /// is the preferred entry point.
        ///
        /// Subclasses that already override this method (e.g. AuthSecureLogParser)
        /// continue to use their own implementation. Subclasses that don't override
        /// get the default delegation to ProcessLogAndReturnFindings.
        /// </summary>
        public virtual (List<string> Findings,
                         Dictionary<string, int> PatternCounts,
                         DateTime FirstSeen,
                         DateTime LastSeen)
            ParseFile(string filePath)
        {
            var ips = new Dictionary<string, int>();
            var (findings, patterns, first, last) =
                ProcessLogAndReturnFindings(filePath, outputDir: null, interestingIPs: ips, suppressFooter: true);
            return (findings, patterns, first, last);
        }

        /// <summary>
        /// Parse and immediately append findings to QuickWins.txt.
        /// Kept for back-compat with any callers that still use it directly.
        /// Prefer ParseFile() for new code.
        /// </summary>
        public (List<string> suspiciousFindings, Dictionary<string, int> patternCounts, DateTime firstSeen, DateTime lastSeen) ProcessLogAndWriteQuickWins(
            string logFilePath,
            string outputDir,
            Dictionary<string, int> interestingIPs = null)
        {
            var suspiciousFindings = new List<string>();
            var patternCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            DateTime firstSeen = DateTime.MaxValue;
            DateTime lastSeen = DateTime.MinValue;

            try
            {
                InferredYear = InferYearFromLogFile(logFilePath);
                TimeOffset = InferTimeOffset(logFilePath);

                ParseLog(logFilePath, suspiciousFindings, patternCounts, ref firstSeen, ref lastSeen, interestingIPs, outputDir);

                firstSeen = CorrectTimestamp(firstSeen);
                lastSeen = CorrectTimestamp(lastSeen);

                WriteToQuickWins(outputDir, suspiciousFindings, patternCounts);
            }
            catch (Exception ex)
            {
                suspiciousFindings.Add($"[ERROR] Exception while parsing {Path.GetFileName(logFilePath)}: {ex.Message}");
            }

            return (suspiciousFindings, patternCounts, firstSeen, lastSeen);
        }

        public (List<string> findings, Dictionary<string, int> patternCounts, DateTime firstSeen, DateTime lastSeen)
            ProcessLogAndReturnFindings(string logFilePath, string outputDir, Dictionary<string, int> interestingIPs = null, bool suppressFooter = false)
        {
            var findings = new List<string>();
            var patternCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            DateTime firstSeen = DateTime.MaxValue;
            DateTime lastSeen = DateTime.MinValue;

            InferredYear = InferYearFromLogFile(logFilePath);
            TimeOffset = InferTimeOffset(logFilePath);

            ParseLog(logFilePath, findings, patternCounts, ref firstSeen, ref lastSeen, interestingIPs, outputDir, suppressFooter);

            firstSeen = CorrectTimestamp(firstSeen);
            lastSeen = CorrectTimestamp(lastSeen);

            return (findings, patternCounts, firstSeen, lastSeen);
        }

        protected abstract void ParseLog(
            string logFilePath,
            List<string> suspiciousFindings,
            Dictionary<string, int> patternCounts,
            ref DateTime firstSeen,
            ref DateTime lastSeen,
            Dictionary<string, int> interestingIPs = null,
            string outputDir = null,
            bool suppressFooter = false);

        protected virtual void WriteToQuickWins(string outputDir, List<string> findings, Dictionary<string, int> patternCounts)
        {
            string quickWinsFile = Path.Combine(outputDir, "QuickWins.txt");
            string logTypeTag = GetType().Name.Replace("Parser", "").ToUpper();

            var suspicious = findings
                .Where(f => !string.IsNullOrWhiteSpace(f) && IsSuspiciousFinding(f))
                .ToList();

            // Informational lines — exclude pure structural noise (footer/header lines)
            var informational = findings
                .Where(f => !string.IsNullOrWhiteSpace(f)
                         && !IsSuspiciousFinding(f)
                         && !IsStructuralNoise(f))
                .ToList();

            // Nothing meaningful to write — skip entirely
            if (!suspicious.Any() && !informational.Any()
                && (patternCounts == null || !patternCounts.Any()))
                return;

            using StreamWriter writer = new(quickWinsFile, append: true);

            if (suspicious.Any())
            {
                writer.WriteLine($"########## [{logTypeTag}] Suspicious Findings ##########");
                foreach (var finding in suspicious)
                    writer.WriteLine(finding);
                writer.WriteLine();
            }

            if (informational.Any())
            {
                writer.WriteLine($"########## [{logTypeTag}] Summary ##########");
                foreach (var finding in informational)
                    writer.WriteLine(finding);
                writer.WriteLine();
            }

            if (patternCounts != null && patternCounts.Any())
            {
                writer.WriteLine($"########## [{logTypeTag}] Pattern Counts ##########");
                foreach (var kvp in patternCounts.OrderByDescending(kvp => kvp.Value))
                    writer.WriteLine($"{kvp.Key}: {kvp.Value}");
                writer.WriteLine();
            }
        }

        private static bool IsStructuralNoise(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return true;
            if (line.StartsWith("#####")) return true;
            if (line.StartsWith("##########")) return true;
            if (line.TrimStart().StartsWith("===") && line.TrimEnd().EndsWith("===")) return true;
            if (line.Contains("First logpost: N/A") && line.Contains("Last logpost: N/A")) return true;
            return false;
        }

        private static bool IsSuspiciousFinding(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return false;
            if (line.StartsWith("#####")) return false;
            if (line.TrimStart().StartsWith("===") && line.TrimEnd().EndsWith("===")) return false;
            if (line.Contains("0 suspicious", StringComparison.OrdinalIgnoreCase)) return false;
            if (line.Contains("0 jobs", StringComparison.OrdinalIgnoreCase)) return false;
            if (line.Contains("0 containers", StringComparison.OrdinalIgnoreCase)) return false;
            if (line.Contains("non-log lines skipped", StringComparison.OrdinalIgnoreCase)) return false;

            if (line.Contains("[SUSPICIOUS]", StringComparison.OrdinalIgnoreCase)) return true;
            if (line.Contains("[HIGH]", StringComparison.OrdinalIgnoreCase)) return true;
            if (line.Contains("[CRITICAL]", StringComparison.OrdinalIgnoreCase)) return true;
            if (line.Contains("[BRUTEFORCE]", StringComparison.OrdinalIgnoreCase)) return true;
            if (line.Contains("Possible Brute-force", StringComparison.OrdinalIgnoreCase)) return true;
            if (line.Contains("Brute-force Detected", StringComparison.OrdinalIgnoreCase)) return true;

            if (line.Contains("occurrence(s)", StringComparison.OrdinalIgnoreCase))
            {
                var m = System.Text.RegularExpressions.Regex.Match(line,
                    @"(\d+)\s+occurrence", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (m.Success && int.TryParse(m.Groups[1].Value, out var count) && count > 0)
                    return true;
                return false;
            }

            if (line.Contains("[ERROR]", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        protected void IncrementPatternCount(Dictionary<string, int> patternCounts, string pattern)
        {
            if (string.IsNullOrEmpty(pattern)) return;

            if (patternCounts.ContainsKey(pattern))
                patternCounts[pattern]++;
            else
                patternCounts[pattern] = 1;
        }

        protected virtual IEnumerable<string> ReadAllLines(string path)
        {
            return File.ReadLines(path);
        }

        protected DateTime CorrectTimestamp(DateTime raw)
        {
            if (raw == DateTime.MinValue || raw == DateTime.MaxValue) return raw;

            if (InferredYear.HasValue)
                raw = raw.AddYears(InferredYear.Value - raw.Year);

            if (TimeOffset.HasValue)
                raw = raw + TimeOffset.Value;

            return raw;
        }

        protected int? InferYearFromLogFile(string logFilePath)
        {
            try
            {
                DateTime lastWrite = File.GetLastWriteTime(logFilePath);
                return lastWrite.Year;
            }
            catch
            {
                return DateTime.Now.Year;
            }
        }

        protected TimeSpan? InferTimeOffset(string logFilePath)
        {
            return null;
        }
    }
}
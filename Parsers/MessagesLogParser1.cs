using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Helpers;
using Output;

namespace Parsers
{
    public class MessagesLogParser : LogFileParser, IAttachNormalizedWriter
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        // ── Classification ────────────────────────────────────────────
        //
        // Critical → RTF findings  (emerg / alert / crit + OOM / kernel panic)
        // Noise    → pattern counts only  (err / warning)
        // Info     → ignored
        //
        private static readonly string[] CriticalMessageKeywords =
        {
            "oom", "out of memory", "killed process",
            "kernel panic", "panic occurred",
            "segfault", "general protection fault",
            "call trace", "bug:", "oops:",
            "hardware error", "mce:", "machine check",
            "i/o error",
            "filesystem error", "ext4-fs error",
            "raid.*degraded", "md.*degraded",
        };

        // ── Field extractors ──────────────────────────────────────────
        private static string ExtractHostname(string line)
        {
            var m = Regex.Match(line,
                @"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?<host>\S+)\s+");
            return m.Success ? m.Groups["host"].Value : string.Empty;
        }

        private static string ExtractDaemon(string line)
        {
            var m = Regex.Match(line, @"\s(?<d>[A-Za-z0-9._\-]+)(?:\[\d+\])?:");
            return m.Success ? m.Groups["d"].Value : string.Empty;
        }

        private static string ExtractIPv4(string line)
        {
            var m = Regex.Match(line,
                @"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b");
            return m.Success ? m.Value : string.Empty;
        }

        private static string ExtractUser(string line)
        {
            var m = Regex.Match(line, @"\buser=(?<u>[A-Za-z0-9._\-]+)\b",
                RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups["u"].Value;
            m = Regex.Match(line, @"\bfor user (?<u>[A-Za-z0-9._\-]+)\b",
                RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups["u"].Value;
            m = Regex.Match(line, @"\bUID=(?<u>\d+)\b", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups["u"].Value : string.Empty;
        }

        private static string ExtractMessage(string line)
        {
            var m = Regex.Match(line, @"[A-Za-z0-9._\-]+(?:\[\d+\])?:\s*(?<msg>.*)$");
            if (m.Success) return m.Groups["msg"].Value.Trim();
            m = Regex.Match(line,
                @"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(?<rest>.*)$");
            return m.Success ? m.Groups["rest"].Value.Trim() : line;
        }

        private static string ExtractSeverityToken(string lineLower)
        {
            if (lineLower.Contains("level=emerg")) return "emerg";
            if (lineLower.Contains("level=alert")) return "alert";
            if (lineLower.Contains("level=crit")) return "crit";
            if (lineLower.Contains("level=error") ||
                lineLower.Contains("level=err")) return "err";
            if (lineLower.Contains("level=warning")) return "warning";
            var m = Regex.Match(lineLower,
                @":\s*(emerg|alert|crit|err|error|warning)\b");
            return m.Success ? m.Groups[1].Value : null;
        }

        // Returns "Critical", "Noise", or "Info"
        private static string ClassifyEntry(string line, string sevToken, string message)
        {
            if (sevToken is "emerg" or "alert" or "crit") return "Critical";

            string msgLo = (message ?? string.Empty).ToLowerInvariant();
            string lineLo = line.ToLowerInvariant();

            foreach (var kw in CriticalMessageKeywords)
                if (msgLo.Contains(kw) || Regex.IsMatch(lineLo, kw))
                    return "Critical";

            if (sevToken is "err" or "error" or "warning") return "Noise";

            return "Info";
        }

        private static string MapSeverityForCsv(string sevToken) =>
            sevToken switch
            {
                "emerg" => "High",
                "alert" => "High",
                "crit" => "High",
                "err" => "Medium",
                "error" => "Medium",
                "warning" => "Low",
                _ => "Info"
            };

        private void WriteNormalized(DateTime ts, string hostname, string daemon,
            string user, string ip, string message, string severity, string raw)
        {
            _normalizedWriter?.Write(NormalizedRecord.From(
                ts, hostname, "MESSAGES",
                daemon ?? string.Empty,
                user ?? string.Empty,
                ip ?? string.Empty,
                message ?? string.Empty,
                severity ?? string.Empty,
                raw ?? string.Empty));
        }

        // ── ParseLog ──────────────────────────────────────────────────
        protected override void ParseLog(
            string logFilePath,
            List<string> findings,
            Dictionary<string, int> patternCounts,
            ref DateTime firstSeen,
            ref DateTime lastSeen,
            Dictionary<string, int> interestingIPs = null,
            string outputDir = null,
            bool suppressFooter = false)
        {
            // Grouped critical events: normalized message key → (count, first, last, example)
            var criticalGroups = new Dictionary<string,
                (int Count, DateTime First, DateTime Last, string Example)>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var line in ReadAllLines(logFilePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (line.TrimStart().StartsWith("#")) continue;

                DateTime ts = TryParseTimestamp(line);
                if (ts == DateTime.MinValue) continue;

                if (ts < firstSeen) firstSeen = ts;
                if (ts > lastSeen) lastSeen = ts;

                string host = ExtractHostname(line);
                string daemon = ExtractDaemon(line);
                string ip = ExtractIPv4(line);
                string user = ExtractUser(line);
                string message = ExtractMessage(line);
                string sevToken = ExtractSeverityToken(line.ToLowerInvariant());
                string tier = ClassifyEntry(line, sevToken, message);

                if (tier != "Info")
                {
                    IncrementPatternCount(patternCounts,
                        sevToken switch
                        {
                            "emerg" => "Emergency",
                            "alert" => "Alert",
                            "crit" => "Critical",
                            "err" => "Error",
                            "error" => "Error",
                            "warning" => "Warning",
                            _ => "Critical event"
                        });

                    if (tier == "Critical")
                    {
                        // Normalize key: strip numbers so repeated OOM/panic messages group
                        string key = Regex.Replace(message, @"\d+", "#");
                        if (key.Length > 100) key = key.Substring(0, 100);

                        if (criticalGroups.TryGetValue(key, out var g))
                            criticalGroups[key] = (
                                g.Count + 1,
                                ts < g.First ? ts : g.First,
                                ts > g.Last ? ts : g.Last,
                                g.Example);
                        else
                            criticalGroups[key] = (1, ts, ts, message);
                    }
                }

                WriteNormalized(ts, host, daemon, user, ip, message,
                    MapSeverityForCsv(sevToken), line);
            }

            // Emit one finding per grouped critical event, highest count first
            foreach (var kv in criticalGroups.Values
                .OrderByDescending(g => g.Count)
                .ThenBy(g => g.First))
            {
                string range = kv.Count == 1
                    ? $"{kv.First:yyyy-MM-dd HH:mm:ss} UTC"
                    : $"{kv.First:yyyy-MM-dd HH:mm:ss} \u2192 {kv.Last:yyyy-MM-dd HH:mm:ss} UTC (x{kv.Count})";

                string display = kv.Example.Length > 160
                    ? kv.Example.Substring(0, 157) + "..."
                    : kv.Example;

                findings.Add($"[MESSAGES] [HIGH] [{range}] {display}");
            }
        }

        // ── Public parse-only entry point ─────────────────────────────
        // Called by the orchestrator to get results without writing to QuickWins,
        // so one combined section with per-file subheaders can be written instead.
        public (List<string> Findings,
                Dictionary<string, int> Patterns,
                DateTime First,
                DateTime Last)
            ParseFile(string filePath)
        {
            var findings = new List<string>();
            var patterns = new Dictionary<string, int>();
            DateTime first = DateTime.MaxValue;
            DateTime last = DateTime.MinValue;

            ParseLog(filePath, findings, patterns,
                     ref first, ref last,
                     interestingIPs: null, outputDir: null, suppressFooter: true);

            return (findings, patterns, first, last);
        }

        // ── Timestamp ─────────────────────────────────────────────────
        private static DateTime TryParseTimestamp(string line)
        {
            var m = Regex.Match(line,
                @"^(?<mon>\w{3})\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})");
            if (!m.Success) return DateTime.MinValue;

            string ts = $"{m.Groups["mon"].Value} {m.Groups["day"].Value} {m.Groups["time"].Value}";

            if (!DateTime.TryParseExact(ts, "MMM d HH:mm:ss",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt) &&
                !DateTime.TryParseExact(ts, "MMM dd HH:mm:ss",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out dt))
                return DateTime.MinValue;

            dt = dt.AddYears(DateTime.Now.Year - dt.Year);
            return dt;
        }
    }
}
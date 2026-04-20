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
    public class SyslogParser : LogFileParser
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        // ── Regexes ───────────────────────────────────────────────────
        private static readonly Regex RgxIso = new(
            @"^(?<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2}))\s+(?<host>\S+)\s+(?<daemon>[^\s:]+)(?:\[(?<pid>\d+)\])?:\s*(?<msg>.*)$",
            RegexOptions.Compiled);

        private static readonly Regex RgxClassic = new(
            @"^(?<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+(?<daemon>[^\s:]+)(?:\[(?<pid>\d+)\])?:\s*(?<msg>.*)$",
            RegexOptions.Compiled);

        private static readonly Regex RgxCronCmd = new(
            @"CRON(?:D)?\[\d+\]:\s*\((?<user>[^)]+)\)\s*CMD\s*\((?<cmd>.+)\)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // ── Classification ────────────────────────────────────────────
        //
        // Critical → RTF findings
        // Noise    → pattern counts only
        // Info     → ignored

        // Kernel / system Critical keywords
        private static readonly string[] CriticalSystemKeywords =
        {
            "panic", "kernel panic",
            "oops:", "bug:",
            "oom", "out of memory", "killed process",
            "segfault", "general protection fault",
            "call trace",
            "hardware error", "mce:",
            "i/o error",
            "ext4-fs error", "filesystem error",
            "raid.*degraded", "md.*degraded",
        };

        // Cron CMD keywords that are Critical (from CronLogParser)
        private static readonly string[] CriticalCronKeywords =
        {
            "bash -i", "sh -i", "zsh -i",
            "python -c", "python2 -c", "python3 -c",
            "perl -e", "ruby -e", "php -r",
            "nc ", "netcat", "ncat", "socat",
            "mkfifo", "mknod",
            "/tmp/", "/dev/shm/", "/var/tmp/",
            "base64 -d", "base64 --decode",
            "wget -O /tmp", "curl -o /tmp",
            "chattr +i",
            "0>&1", ">&2",
        };

        private static readonly string[] CronWhitelist =
        {
            "/usr/lib/sa/sa1", "/usr/lib/sa/sa2",
            "logrotate", "/usr/libexec/atrun",
            "/usr/bin/updatedb", "/usr/bin/yum-cron",
            "run-parts", "/etc/cron.",
            "/usr/bin/freshclam", "/usr/bin/mandb",
            "/usr/lib64/nagios/plugins/check",
            "/usr/bin/test", "/usr/bin/stat", "/usr/bin/true",
            "BECOME-SUCCESS", "ansible", "AnsiballZ",
        };

        // Noise: specific enough to be meaningful, not so broad they match everything
        private static readonly string[] NoiseSystemKeywords =
        {
            "authentication failure",
            "connection refused",
            "connection timed out",
            "permission denied",
            "operation not permitted",
            "disk quota exceeded",
            "no space left on device",
            "too many open files",
            "address already in use",
        };

        private static string ClassifyLine(string line, string daemon, string msg,
            out string cronUser, out string cronCmd)
        {
            cronUser = null;
            cronCmd = null;

            // ── Cron CMD detection ────────────────────────────────────
            var cronM = RgxCronCmd.Match(line);
            if (cronM.Success)
            {
                cronUser = cronM.Groups["user"].Value.Trim();
                cronCmd = cronM.Groups["cmd"].Value.Trim();

                // Capture into locals — out params cannot be used inside lambdas
                string localCmd = cronCmd;

                // Whitelisted → Info
                if (CronWhitelist.Any(w =>
                        localCmd.IndexOf(w, StringComparison.OrdinalIgnoreCase) >= 0))
                    return "Info";

                // Critical cron keywords
                if (CriticalCronKeywords.Any(kw =>
                        localCmd.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                    return "Critical";

                // Everything else → Info (routine cron noise)
                return "Info";
            }

            string lineLo = line.ToLowerInvariant();
            string msgLo = msg.ToLowerInvariant();

            // ── Pre-suppress: known-benign lines that contain Critical keywords ──
            // Checked BEFORE the Critical scan so they are never falsely escalated.
            //
            // rasdaemon registering its MCE tracepoint at boot — not a hardware error.
            // Actual MCEs look like: "Hardware Error: CPU 0: Machine Check Exception..."
            if ((daemon ?? "").Equals("rasdaemon", StringComparison.OrdinalIgnoreCase)
                && lineLo.Contains("event enabled"))
                return "Info";

            // ── System Critical ───────────────────────────────────────
            foreach (var kw in CriticalSystemKeywords)
                if (Regex.IsMatch(lineLo, kw)) return "Critical";

            // ── Noise ─────────────────────────────────────────────────
            // Skip session open/close — pure bookkeeping
            if (Regex.IsMatch(line, @"session\s+(opened|closed)", RegexOptions.IgnoreCase))
                return "Info";

            // Skip ansible/cron/systemd daemon noise
            string daemonLo = (daemon ?? "").ToLowerInvariant();
            if (daemonLo is "cron" or "crond" or "anacron" or "systemd" or "systemd-logind")
                return "Info";

            foreach (var kw in NoiseSystemKeywords)
                if (lineLo.Contains(kw)) return "Noise";

            return "Info";
        }

        // ── Field extractors ──────────────────────────────────────────
        private static (DateTime ts, string host, string daemon, string msg)
            ParseFields(string line, string logFilePath)
        {
            var iso = RgxIso.Match(line);
            if (iso.Success)
            {
                DateTime ts = DateTime.MinValue;
                if (DateTimeOffset.TryParse(iso.Groups["ts"].Value,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out var dto))
                    ts = dto.UtcDateTime;
                return (ts,
                    iso.Groups["host"].Value,
                    iso.Groups["daemon"].Value,
                    iso.Groups["msg"].Value.Trim());
            }

            var cls = RgxClassic.Match(line);
            if (cls.Success)
            {
                int year = DateTime.Now.Year;
                try { year = new FileInfo(logFilePath).LastWriteTime.Year; } catch { }
                string tsStr = $"{year} {cls.Groups["ts"].Value}";
                DateTime ts = DateTime.MinValue;
                if (DateTime.TryParseExact(tsStr, "yyyy MMM d HH:mm:ss",
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeLocal,
                        out var dt1))
                    ts = dt1.ToUniversalTime();
                else if (DateTime.TryParseExact(tsStr, "yyyy MMM dd HH:mm:ss",
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeLocal,
                        out var dt2))
                    ts = dt2.ToUniversalTime();
                return (ts,
                    cls.Groups["host"].Value,
                    cls.Groups["daemon"].Value,
                    cls.Groups["msg"].Value.Trim());
            }

            return (DateTime.MinValue, string.Empty, string.Empty, line);
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
            return m.Success ? m.Groups["u"].Value : string.Empty;
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
            // Group Critical events: normalized key → (count, first, last, example)
            var critGroups = new Dictionary<string,
                (int Count, DateTime First, DateTime Last, string Label, string Example)>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var line in ReadAllLines(logFilePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (line.TrimStart().StartsWith("#")) continue;

                var (ts, host, daemon, msg) = ParseFields(line, logFilePath);
                if (ts == DateTime.MinValue) continue;

                if (ts < firstSeen) firstSeen = ts;
                if (ts > lastSeen) lastSeen = ts;

                string ip = ExtractIPv4(line);
                string user = ExtractUser(line);

                string tier = ClassifyLine(line, daemon, msg,
                    out string cronUser, out string cronCmd);

                if (tier == "Info")
                {
                    WriteNormalized(ts, host, daemon, user, ip, msg, "Info", line);
                    continue;
                }

                // Pattern counting
                if (cronCmd != null)
                    IncrementPatternCount(patternCounts, "Suspicious cron job");
                else
                {
                    var kw = CriticalSystemKeywords
                        .FirstOrDefault(k => Regex.IsMatch(line.ToLowerInvariant(), k));
                    IncrementPatternCount(patternCounts, kw switch
                    {
                        var k when k?.Contains("oom") == true
                            || k?.Contains("memory") == true => "OOM / memory kill",
                        var k when k?.Contains("panic") == true => "Kernel panic",
                        var k when k?.Contains("segfault") == true => "Segfault",
                        var k when k?.Contains("raid") == true
                            || k?.Contains("md") == true => "RAID degraded",
                        var k when k?.Contains("i/o") == true => "I/O error",
                        _ => "System critical event"
                    });
                }

                if (tier == "Critical")
                {
                    string example = cronCmd != null
                        ? $"[CRON] user={cronUser} CMD: {cronCmd}"
                        : msg;

                    if (example.Length > 160) example = example.Substring(0, 157) + "...";

                    // Normalize key: strip numbers and session IDs
                    string key = cronCmd != null
                        ? $"CRON|{Regex.Replace(cronCmd, @"\d+", "#")}"
                        : $"SYS|{Regex.Replace(msg, @"\d+", "#")}";
                    if (key.Length > 120) key = key.Substring(0, 120);

                    string label = cronCmd != null ? "CRON" : daemon;

                    if (critGroups.TryGetValue(key, out var g))
                        critGroups[key] = (
                            g.Count + 1,
                            ts < g.First ? ts : g.First,
                            ts > g.Last ? ts : g.Last,
                            g.Label, g.Example);
                    else
                        critGroups[key] = (1, ts, ts, label, example);
                }

                // Only write Critical to normalized CSV — Noise is counted only.
                // Writing every "error"/"failed" match would produce millions of rows.
                if (tier == "Critical")
                    WriteNormalized(ts, host, daemon,
                        cronUser ?? user, ip, msg, "High", line);
            }

            // Emit findings
            foreach (var kv in critGroups
                .OrderByDescending(k => k.Key.StartsWith("CRON") ? 1 : 0)
                .ThenByDescending(k => k.Value.Count)
                .ThenBy(k => k.Value.First))
            {
                var g = kv.Value;
                string range = g.Count == 1
                    ? $"{g.First:yyyy-MM-dd HH:mm:ss} UTC"
                    : $"{g.First:yyyy-MM-dd HH:mm:ss} \u2192 {g.Last:yyyy-MM-dd HH:mm:ss} UTC (x{g.Count})";

                findings.Add($"[SYSLOG] [HIGH] [{g.Label}] [{range}] {g.Example}");
            }
        }

        // ── Public parse-only entry point ─────────────────────────────
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

        // ── Normalized CSV writer ─────────────────────────────────────
        private void WriteNormalized(DateTime ts, string host, string daemon,
            string user, string ip, string msg, string severity, string raw)
        {
            _normalizedWriter?.Write(NormalizedRecord.From(
                ts,
                host ?? string.Empty, "SYSLOG",
                daemon ?? string.Empty,
                user ?? string.Empty,
                ip ?? string.Empty,
                msg ?? string.Empty,
                severity ?? string.Empty,
                raw ?? string.Empty));
        }
    }
}
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
    public class AuditLogParser : LogFileParser
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        private static readonly Regex AuditLine = new(
            @"type=(?<type>\w+)\s+msg=audit\((?<epoch>\d+)\.\d+:\d+\):\s+(?<msg>.*)",
            RegexOptions.Compiled);

        // ── Classification ────────────────────────────────────────────
        //
        // Critical → RTF findings  (near-certain attack or serious anomaly)
        // Noise    → pattern counts only  (routine audit noise)
        // Info     → ignored

        // Event types that are Critical regardless of message content
        private static readonly HashSet<string> CriticalTypes = new(StringComparer.OrdinalIgnoreCase)
        {
            "ANOM_ABEND",         // process crash — possible exploitation attempt
            "ANOM_PROMISCUOUS",   // NIC in promiscuous mode — possible sniffer
            "KERN_MODULE",        // kernel module loaded/unloaded
            "MAC_POLICY_LOAD",    // SELinux/AppArmor policy changed
            "ANOM_EXEC",          // anomalous execution detected by audit daemon
            "ANOM_MK_EXEC",       // non-executable file made executable
            "ANOM_LINK",          // suspicious hardlink
        };

        // Event types that are Noise (counted but never in RTF)
        private static readonly HashSet<string> NoiseTypes = new(StringComparer.OrdinalIgnoreCase)
        {
            "PROCTITLE",    // just the process title, always accompanies EXECVE
            "PATH",         // filesystem path record — context only
            "CWD",          // current working directory — context only
            "BPRM_FCAPS",   // file capabilities — routine
            "MMAP",         // memory map — routine
            "SOCKADDR",     // socket address — routine
            "NETFILTER_PKT",// packet filter — very noisy
        };

        // Keywords in EXECVE/USER_CMD args that escalate to Critical
        private static readonly string[] CriticalExecKeywords =
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

        // Keywords that make a USER_CMD/EXECVE Noise rather than Critical
        private static readonly string[] AnsibleNoiseKeywords =
        {
            "BECOME-SUCCESS", "ansible", "AnsiballZ",
        };

        private static string ClassifyEvent(string type, string msg)
        {
            // Absolute noise — skip entirely
            if (NoiseTypes.Contains(type)) return "Info";

            // Absolute critical by type
            if (CriticalTypes.Contains(type)) return "Critical";

            string msgLo = msg.ToLowerInvariant();

            // Failed auth / denied access — Noise (counted)
            if (msg.Contains("res=failed", StringComparison.OrdinalIgnoreCase) ||
                msg.Contains("res=denied", StringComparison.OrdinalIgnoreCase) ||
                msg.Contains(" denied ", StringComparison.OrdinalIgnoreCase))
                return "Noise";

            // EXECVE / USER_CMD — only Critical if it contains attack keywords
            if (type is "EXECVE" or "USER_CMD" or "PROCTITLE")
            {
                // Ansible automation → noise
                if (AnsibleNoiseKeywords.Any(kw =>
                        msg.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                    return "Noise";

                if (CriticalExecKeywords.Any(kw =>
                        msg.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                    return "Critical";

                return "Noise"; // EXECVE without bad keywords — just count it
            }

            // USER_AUTH success after previous failures is handled separately
            // by grouping — classify as Noise here
            if (type is "USER_AUTH" or "USER_LOGIN" or "USER_START" or "USER_END")
                return "Noise";

            // SYSCALL — only Critical for specific dangerous calls
            if (type == "SYSCALL")
            {
                // execve of something from a temp path
                if (msgLo.Contains("syscall=59") || msgLo.Contains("syscall=execve"))
                    if (CriticalExecKeywords.Any(kw => msgLo.Contains(kw)))
                        return "Critical";
                return "Noise";
            }

            // Privilege escalation / ownership changes
            if (type is "CHOWN" or "CHMOD" or "SETUID" or "SETGID")
            {
                if (CriticalExecKeywords.Any(kw => msgLo.Contains(kw)))
                    return "Critical";
                return "Noise";
            }

            return "Noise";
        }

        private static string PatternLabel(string type, string msg) =>
            type switch
            {
                "EXECVE" => "Process execution",
                "USER_CMD" => "Sudo command",
                "USER_AUTH" => msg.Contains("res=failed", StringComparison.OrdinalIgnoreCase)
                                     ? "Auth failure" : "Auth success",
                "ANOM_ABEND" => "Process crash (ANOM_ABEND)",
                "ANOM_PROMISCUOUS" => "NIC promiscuous mode",
                "KERN_MODULE" => "Kernel module",
                "MAC_POLICY_LOAD" => "MAC policy change",
                _ => type
            };

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
            // Critical event grouping: normalized key → (count, first, last, example)
            var critGroups = new Dictionary<string,
                (int Count, DateTime First, DateTime Last, string Type, string Example)>(
                StringComparer.OrdinalIgnoreCase);

            // Track failed auth per account for success-after-failure detection
            var authFailures = new Dictionary<string, (int Count, DateTime Last)>(
                StringComparer.OrdinalIgnoreCase);

            // CSV output path — append so multiple files accumulate
            string? csvPath = string.IsNullOrEmpty(outputDir)
                ? null
                : Path.Combine(outputDir, "Audit_Parsed.csv");
            StreamWriter? csvWriter = null;

            try
            {
                if (csvPath != null)
                {
                    bool writeHeader = !File.Exists(csvPath);
                    csvWriter = new StreamWriter(csvPath, append: true);
                    if (writeHeader)
                        csvWriter.WriteLine(
                            "TimestampUtc,EventType,Tier,IsSuspicious,NormalizedMessage,RawMessage");
                }

                foreach (var line in ReadAllLines(logFilePath))
                {
                    var m = AuditLine.Match(line);
                    if (!m.Success) continue;

                    string type = m.Groups["type"].Value;
                    string msg = m.Groups["msg"].Value;
                    string tier = ClassifyEvent(type, msg);

                    DateTime ts = TryParseEpoch(m.Groups["epoch"].Value);
                    if (ts != DateTime.MinValue)
                    {
                        if (ts < firstSeen) firstSeen = ts;
                        if (ts > lastSeen) lastSeen = ts;
                    }

                    if (!IsInRange(ts)) continue;

                    if (tier == "Info")
                    {
                        // Write to CSV but don't count
                        WriteNormalizedRow(csvWriter, ts, type, "Info", false,
                            NormalizeMsg(msg), line);
                        continue;
                    }

                    IncrementPatternCount(patternCounts, PatternLabel(type, msg));

                    // ── Success-after-failure detection ────────────────
                    if (type is "USER_AUTH" or "USER_LOGIN")
                    {
                        var acctM = Regex.Match(msg, @"acct=""?(?<a>[^""\s]+)""?");
                        string acct = acctM.Success ? acctM.Groups["a"].Value : "unknown";

                        if (msg.Contains("res=failed", StringComparison.OrdinalIgnoreCase))
                        {
                            if (authFailures.TryGetValue(acct, out var af))
                                authFailures[acct] = (af.Count + 1, ts);
                            else
                                authFailures[acct] = (1, ts);
                        }
                        else if (msg.Contains("res=success", StringComparison.OrdinalIgnoreCase))
                        {
                            if (authFailures.TryGetValue(acct, out var af) && af.Count >= 5)
                            {
                                // Success after ≥5 failures on the same account
                                string key = $"AUTH_SUCCESS_AFTER_FAIL|{acct}";
                                if (!critGroups.ContainsKey(key))
                                    critGroups[key] = (1, ts, ts,
                                        "USER_AUTH",
                                        $"acct={acct} success after {af.Count} failures " +
                                        $"(last failure: {af.Last:yyyy-MM-dd HH:mm:ss} UTC)");
                            }
                        }
                    }

                    // ── Group Critical events ──────────────────────────
                    if (tier == "Critical")
                    {
                        // Normalize key: strip PIDs, UIDs, session IDs
                        string key = NormalizeMsg(msg);
                        if (key.Length > 100) key = key.Substring(0, 100);
                        key = $"{type}|{key}";

                        if (critGroups.TryGetValue(key, out var g))
                            critGroups[key] = (
                                g.Count + 1,
                                ts < g.First ? ts : g.First,
                                ts > g.Last ? ts : g.Last,
                                g.Type, g.Example);
                        else
                            critGroups[key] = (1, ts, ts, type,
                                msg.Length > 160 ? msg.Substring(0, 157) + "..." : msg);
                    }

                    bool isSusp = tier == "Critical";
                    WriteNormalizedRow(csvWriter, ts, type,
                        tier, isSusp, NormalizeMsg(msg), line);

                    _normalizedWriter?.Write(NormalizedRecord.From(
                        ts, string.Empty, "AUDIT",
                        type, string.Empty, string.Empty,
                        msg.Length > 200 ? msg.Substring(0, 200) : msg,
                        isSusp ? "High" : "Info",
                        line));
                }
            }
            finally
            {
                csvWriter?.Dispose();
            }

            // Emit findings — Critical groups sorted by severity then count
            // Auth-success-after-failure gets priority
            foreach (var kv in critGroups
                .OrderByDescending(k => k.Key.StartsWith("AUTH_SUCCESS_AFTER_FAIL") ? 2 : 1)
                .ThenByDescending(k => k.Value.Count)
                .ThenBy(k => k.Value.First))
            {
                var g = kv.Value;
                string range = g.Count == 1
                    ? $"{g.First:yyyy-MM-dd HH:mm:ss} UTC"
                    : $"{g.First:yyyy-MM-dd HH:mm:ss} \u2192 {g.Last:yyyy-MM-dd HH:mm:ss} UTC (x{g.Count})";

                string prefix = kv.Key.StartsWith("AUTH_SUCCESS_AFTER_FAIL")
                    ? "[AUDIT] [HIGH] [POSSIBLE BRUTE FORCE SUCCESS]"
                    : $"[AUDIT] [HIGH] [{g.Type}]";

                findings.Add($"{prefix} [{range}] {g.Example}");
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

        // ── CSV helpers ───────────────────────────────────────────────
        private static void WriteNormalizedRow(StreamWriter? w, DateTime ts,
            string type, string tier, bool suspicious, string normalized, string raw)
        {
            if (w == null) return;
            static string Q(string s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";
            w.WriteLine(string.Join(",",
                Q(ts == DateTime.MinValue ? "" : ts.ToString("yyyy-MM-dd HH:mm:ss")),
                Q(type),
                Q(tier),
                Q(suspicious ? "true" : "false"),
                Q(normalized),
                Q(raw.Length > 300 ? raw.Substring(0, 297) + "..." : raw)
            ));
        }

        // ── Timestamp ─────────────────────────────────────────────────
        private static DateTime TryParseEpoch(string epochStr)
        {
            if (!long.TryParse(epochStr, out long seconds)) return DateTime.MinValue;
            try
            {
                return DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime;
            }
            catch { return DateTime.MinValue; }
        }

        // ── Normalizer ────────────────────────────────────────────────
        private static string NormalizeMsg(string msg)
        {
            msg = Regex.Replace(msg, @"\bpid=\d+", "pid=X");
            msg = Regex.Replace(msg, @"\buid=\d+", "uid=X");
            msg = Regex.Replace(msg, @"\bgid=\d+", "gid=X");
            msg = Regex.Replace(msg, @"\bauid=\d+", "auid=X");
            msg = Regex.Replace(msg, @"\bses=\d+", "ses=X");
            msg = Regex.Replace(msg, @"0x[0-9a-fA-F]+", "0xHEX");
            msg = Regex.Replace(msg, @"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", "IP");
            msg = Regex.Replace(msg, @"\b\d{5,}\b", "N");  // long numbers only
            msg = Regex.Replace(msg, @"\s{2,}", " ").Trim();
            return msg;
        }
    }
}
// File: Parsers/AuthSecureLogParser.cs
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
    public class AuthSecureLogParser : LogFileParser
    {
        private SessionTracker _sessionTracker;
        public void AttachSessionTracker(SessionTracker tracker) => _sessionTracker = tracker;

        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        // ── Classification ────────────────────────────────────────────
        //
        // Three tiers — same philosophy as JournalFileParser:
        //   Critical → written to RTF findings (almost certainly malicious)
        //   Noise    → counted in pattern summary only
        //   Info     → ignored entirely
        //
        // Critical: shell spawns via sudo, brute-force detections
        private static readonly string[] CriticalSudoCommands =
        {
            "python -c", "python2 -c", "python3 -c",
            "perl -e", "ruby -e", "php -r",
            "nc ", "netcat", "ncat",
            "socat",
            "bash -i", "sh -i",
            "/tmp/", "/dev/shm/", "/var/tmp/",
            "base64 -d", "base64 --decode",
            "mkfifo", "mknod",
            "chmod +x", "chmod 777",
            "wget -O /tmp", "curl -o /tmp",
        };

        // A shell is only a "shell spawn" when it IS the command run via sudo
        // ("sudo /bin/bash"), not when it is an argument ("useradd -s /bin/bash").
        private static readonly HashSet<string> ShellBinaries = new(StringComparer.OrdinalIgnoreCase)
        {
            "/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh",
            "/bin/dash", "/bin/zsh", "/usr/bin/zsh", "bash", "sh", "su", "/bin/su", "/usr/bin/su",
        };

        // Failed attempts from one IP before a success that counts as a
        // successful brute force / password guess.
        private const int BruteForceSuccessThreshold = 3;

        private static bool IsCriticalSudoCommand(string command)
        {
            if (string.IsNullOrWhiteSpace(command)) return false;
            var first = command.TrimStart().Split(new[] { ' ', '\t' }, 2)[0];
            return ShellBinaries.Contains(first)
                || KeywordMatcher.ContainsAny(command, CriticalSudoCommands)
                || Indicators.IsPipeToShell(command)
                || Indicators.SensitiveFileWritten(command) != null;
        }

        // ── Field extractors ──────────────────────────────────────────
        private static string InferLogTypeFromPath(string logFilePath)
        {
            if (string.IsNullOrEmpty(logFilePath)) return "AUTH";
            var name = Path.GetFileName(logFilePath).ToLowerInvariant();
            return name.StartsWith("secure") ? "SECURE" : "AUTH";
        }

        private static string ExtractHostname(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return string.Empty;
            var iso = Regex.Match(line, @"^(?<ts>\d{4}-\d{2}-\d{2}T[^\s]+)\s+(?<host>\S+)\s+");
            if (iso.Success) return iso.Groups["host"].Value;
            var sys = Regex.Match(line, @"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?<host>\S+)\s+");
            return sys.Success ? sys.Groups["host"].Value : string.Empty;
        }

        private static string ExtractDaemonName(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return null;
            var m = Regex.Match(line, @"\s(?<daemon>[A-Za-z0-9_\-]+)(?:\[\d+\])?:\s");
            return m.Success ? m.Groups["daemon"].Value : null;
        }

        private static string ExtractIPv4(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return string.Empty;
            var m = Regex.Match(line,
                @"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b");
            return m.Success ? m.Value : string.Empty;
        }

        private static string ExtractUser(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return string.Empty;

            var m = Regex.Match(line,
                @"\b(?:Failed|Accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?(?<u>[A-Za-z0-9._\-]+)\b",
                RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups["u"].Value;

            m = Regex.Match(line,
                @"session\s+(?:opened|closed)\s+for\s+user\s+(?<u>[A-Za-z0-9._\-]+)",
                RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups["u"].Value;

            m = Regex.Match(line, @":\s+(?<u>[A-Za-z0-9._\-]+)\s+:\s+TTY=",
                RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups["u"].Value;

            m = Regex.Match(line, @"\bUSER=(?<u>[A-Za-z0-9._\-]+)\b",
                RegexOptions.IgnoreCase);
            if (m.Success) return m.Groups["u"].Value;

            m = Regex.Match(line, @"\buser=(?<u>[A-Za-z0-9._\-]+)\b",
                RegexOptions.IgnoreCase);
            return m.Success ? m.Groups["u"].Value : string.Empty;
        }

        private static string ExtractMessage(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return string.Empty;
            var m = Regex.Match(line, @"[A-Za-z0-9_\-]+(?:\[\d+\])?:\s*(?<msg>.*)$");
            if (m.Success) return m.Groups["msg"].Value.Trim();
            m = Regex.Match(line, @"^\d{4}-\d{2}-\d{2}T[^\s]+\s+\S+\s+(?<rest>.*)$");
            if (m.Success) return m.Groups["rest"].Value.Trim();
            m = Regex.Match(line,
                @"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(?<rest>.*)$");
            return m.Success ? m.Groups["rest"].Value.Trim() : line;
        }

        private void WriteNormalized(DateTime ts, string hostname, string logType,
            string daemon, string user, string ip, string message, string severity, string raw)
        {
            _normalizedWriter?.Write(NormalizedRecord.From(
                ts, hostname, logType,
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
            var sessionTracker = _sessionTracker ?? new SessionTracker();
            string logType = InferLogTypeFromPath(logFilePath);

            // Per-IP failed login tracking for brute-force detection
            var failedLines = new List<string>();
            var failedLoginGroups = new Dictionary<string,
                (int Count, DateTime First, DateTime Last)>();

            // Accepted login grouping — grouped by user+IP for the findings block
            var acceptedGroups = new Dictionary<string,
                (string User, string Ip, int Count, DateTime First, DateTime Last)>();

            // Critical sudo findings (shell spawns)
            var criticalSudoFindings = new List<string>();

            // Failed attempts per source IP (all users) — used to spot a
            // success that follows a run of failures from the same IP.
            var failuresByIp = new Dictionary<string, (int Count, DateTime First, HashSet<string> Users)>();
            var bruteSuccessFindings = new List<string>();
            var accountFindings = new List<string>();

            foreach (var line in ReadAllLines(logFilePath))
            {
                // ISO-8601 lines carry an explicit timezone offset — no year correction needed.
                // CorrectTimestamp in the base class can incorrectly bump years for past dates.
                bool lineIsIso = line.Length > 19 && line[4] == '-' && line[7] == '-' && line[10] == 'T';
                DateTime rawTs = TryParseTimestamp(line);
                DateTime ts = (lineIsIso || rawTs == DateTime.MinValue)
                                  ? rawTs
                                  : CorrectTimestamp(rawTs);
                if (ts != DateTime.MinValue)
                {
                    if (ts < firstSeen) firstSeen = ts;
                    if (ts > lastSeen) lastSeen = ts;
                }

                if (!IsInRange(ts)) continue;

                string hostname = ExtractHostname(line);
                string daemon = ExtractDaemonName(line) ?? "AUTH";
                string ip = ExtractIPv4(line);
                string user = ExtractUser(line);
                string message = ExtractMessage(line);

                // ── Session open ─────────────────────────────────────
                var openedM = Regex.Match(line,
                    @"session opened for user (\w+)", RegexOptions.IgnoreCase);
                if (openedM.Success)
                {
                    sessionTracker.AddSessionOpen(
                        openedM.Groups[1].Value,
                        string.IsNullOrEmpty(ip) ? null : ip, ts, daemon);
                    IncrementPatternCount(patternCounts, "Session opened");
                }

                // ── Session close ────────────────────────────────────
                var closedM = Regex.Match(line,
                    @"session closed for user (\w+)", RegexOptions.IgnoreCase);
                if (closedM.Success)
                {
                    sessionTracker.AddSessionClose(
                        closedM.Groups[1].Value,
                        string.IsNullOrEmpty(ip) ? null : ip, ts, daemon);
                    IncrementPatternCount(patternCounts, "Session closed");
                }

                // ── Failed password ───────────────────────────────────
                var failedM = Regex.Match(line,
                    @"Failed password for (invalid user )?(\w+) from (?<ip>\d{1,3}(\.\d{1,3}){3})",
                    RegexOptions.IgnoreCase);
                if (failedM.Success)
                {
                    string failUser = failedM.Groups[2].Value;
                    string failIp = failedM.Groups["ip"].Value;
                    string groupKey = $"{failIp}|{failUser}";

                    if (failedLoginGroups.TryGetValue(groupKey, out var fg))
                        failedLoginGroups[groupKey] = (
                            fg.Count + 1,
                            ts < fg.First ? ts : fg.First,
                            ts > fg.Last ? ts : fg.Last);
                    else
                        failedLoginGroups[groupKey] = (1, ts, ts);

                    failedLines.Add(line);
                    if (failuresByIp.TryGetValue(failIp, out var fip))
                    {
                        fip.Users.Add(failUser);
                        failuresByIp[failIp] = (fip.Count + 1, ts < fip.First ? ts : fip.First, fip.Users);
                    }
                    else
                        failuresByIp[failIp] = (1, ts, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { failUser });
                    IncrementPatternCount(patternCounts, "Failed login");
                    if (interestingIPs != null && !string.IsNullOrEmpty(failIp))
                        IncrementIPCount(interestingIPs, failIp);
                }

                // ── Accepted password ────────────────────────────────
                var acceptedM = Regex.Match(line,
                    @"Accepted password for (\w+) from (?<ip>\d{1,3}(\.\d{1,3}){3})",
                    RegexOptions.IgnoreCase);
                if (acceptedM.Success)
                {
                    string accUser = acceptedM.Groups[1].Value;
                    string accIp = acceptedM.Groups["ip"].Value;
                    string accKey = $"{accUser}|{accIp}";

                    sessionTracker.AddSessionOpen(accUser, accIp, ts, daemon);
                    IncrementPatternCount(patternCounts, "Successful login");
                    if (interestingIPs != null) IncrementIPCount(interestingIPs, accIp);

                    if (acceptedGroups.TryGetValue(accKey, out var ag))
                        acceptedGroups[accKey] = (ag.User, ag.Ip, ag.Count + 1,
                            ts < ag.First ? ts : ag.First,
                            ts > ag.Last ? ts : ag.Last);
                    else
                        acceptedGroups[accKey] = (accUser, accIp, 1, ts, ts);
                }

                // ── Success after failures from the same IP (any auth method) ──
                var anyAcceptM = Regex.Match(line,
                    @"Accepted (?<method>password|publickey|keyboard-interactive/pam|gssapi\S*) for (?<user>\S+) from (?<ip>\d{1,3}(\.\d{1,3}){3})",
                    RegexOptions.IgnoreCase);
                if (anyAcceptM.Success
                    && failuresByIp.TryGetValue(anyAcceptM.Groups["ip"].Value, out var priorFails)
                    && priorFails.Count >= BruteForceSuccessThreshold)
                {
                    string okUser = anyAcceptM.Groups["user"].Value;
                    string okIp = anyAcceptM.Groups["ip"].Value;
                    IncrementPatternCount(patternCounts, "Brute force succeeded");
                    bruteSuccessFindings.Add(
                        $"[AUTH] [CRITICAL] [{ts:yyyy-MM-dd HH:mm:ss} UTC] Brute force succeeded: " +
                        $"{okUser} logged in from {okIp} ({anyAcceptM.Groups["method"].Value}) after " +
                        $"{priorFails.Count} failed attempt(s) since {priorFails.First:yyyy-MM-dd HH:mm:ss} UTC " +
                        $"(users tried: {string.Join(", ", priorFails.Users.OrderBy(u => u))})");
                    // Count from zero again so a later burst is reported separately.
                    failuresByIp.Remove(okIp);
                }

                // ── Account / group creation (persistence) ───────────
                var newUserM = Regex.Match(line,
                    @"new user: name=(?<name>[^,\s]+),\s*UID=(?<uid>\d+)(?:.*?home=(?<home>[^,\s]+))?(?:.*?shell=(?<shell>[^,\s]+))?",
                    RegexOptions.IgnoreCase);
                if (newUserM.Success)
                {
                    IncrementPatternCount(patternCounts, "Account created");
                    accountFindings.Add(
                        $"[AUTH] [HIGH] [{ts:yyyy-MM-dd HH:mm:ss} UTC] Account created: {newUserM.Groups["name"].Value} " +
                        $"(UID {newUserM.Groups["uid"].Value}" +
                        (newUserM.Groups["shell"].Success ? $", shell {newUserM.Groups["shell"].Value}" : "") + ")");
                }
                var groupAddM = Regex.Match(line,
                    @"(?:add '(?<user>[^']+)' to (?:shadow )?group '(?<group>sudo|wheel|admin|root|docker)')",
                    RegexOptions.IgnoreCase);
                if (groupAddM.Success)
                {
                    IncrementPatternCount(patternCounts, "Privileged group membership");
                    accountFindings.Add(
                        $"[AUTH] [HIGH] [{ts:yyyy-MM-dd HH:mm:ss} UTC] User {groupAddM.Groups["user"].Value} " +
                        $"added to privileged group '{groupAddM.Groups["group"].Value}'");
                }

                // ── Sudo command ─────────────────────────────────────
                var sudoM = Regex.Match(line,
                    @":\s+(\w+)\s+:\s+TTY=.*?;\s+PWD=.*?;\s+USER=.*?;\s+COMMAND=(?<cmd>.+)$",
                    RegexOptions.IgnoreCase);
                if (sudoM.Success)
                {
                    string sudoUser = sudoM.Groups[1].Value;
                    string command = sudoM.Groups["cmd"].Value.Trim();

                    IncrementPatternCount(patternCounts, "Sudo command");

                    // Exclude ansible automation — it always uses sudo + /bin/sh
                    // but is legitimate orchestration, not an attacker shell spawn.
                    bool isAnsible = command.Contains("BECOME-SUCCESS", StringComparison.OrdinalIgnoreCase)
                        || command.Contains("ansible", StringComparison.OrdinalIgnoreCase)
                        || command.Contains("AnsiballZ", StringComparison.OrdinalIgnoreCase);

                    // Only flag if the command spawns a shell or does something critical
                    bool isCritical = !isAnsible && IsCriticalSudoCommand(command);

                    if (isCritical)
                    {
                        string tsStr = ts != DateTime.MinValue
                            ? ts.ToString("yyyy-MM-dd HH:mm:ss")
                            : "unknown";
                        criticalSudoFindings.Add(
                            $"[AUTH] [HIGH] [{tsStr} UTC] [sudo] {sudoUser} ran: {command}");
                    }
                }

                // ── Normalize every line to CSV ───────────────────────
                // Severity for normalized output only — not used for findings filtering
                string normSeverity = "Info";
                if (failedM.Success) normSeverity = "Medium";
                if (acceptedM.Success) normSeverity = "Info";
                if (anyAcceptM.Success && bruteSuccessFindings.Count > 0
                    && bruteSuccessFindings[^1].Contains($"{ts:yyyy-MM-dd HH:mm:ss} UTC")) normSeverity = "Critical";
                if (newUserM.Success || groupAddM.Success) normSeverity = "High";
                if (sudoM.Success)
                {
                    string cmd = sudoM.Groups["cmd"].Value;
                    normSeverity = IsCriticalSudoCommand(cmd) ? "High" : "Medium";
                }

                WriteNormalized(ts, hostname, logType, daemon,
                    user, ip, message, normSeverity, line);
            }

            // ── Emit Critical findings first ──────────────────────────
            findings.AddRange(bruteSuccessFindings);
            findings.AddRange(accountFindings);
            foreach (var f in criticalSudoFindings)
                findings.Add(f);

            // ── Emit accepted login groups (medium — analyst awareness) ─
            // Collapsed per user+IP — only if they've logged in at all
            foreach (var ag in acceptedGroups.Values
                .OrderByDescending(a => a.Count)
                .Take(20))
            {
                string range = ag.Count == 1
                    ? $"{ag.First:yyyy-MM-dd HH:mm:ss} UTC"
                    : $"{ag.First:yyyy-MM-dd HH:mm:ss} → {ag.Last:yyyy-MM-dd HH:mm:ss} UTC (x{ag.Count})";

                findings.Add(
                    $"[AUTH] [MEDIUM] [{range}] Accepted login: {ag.User} from {ag.Ip}");
            }

            // ── Emit top brute-force sources ──────────────────────────
            // BruteForceDetector does the heavy lifting; we just add its output
            var bruteFindings = BruteForceDetector.AnalyzeFailedLogins(failedLines);
            foreach (var bf in bruteFindings)
                findings.Add($"[AUTH] [BRUTEFORCE] {bf}");

            // ── Top failed login sources (max 10, high count only) ────
            // These go into findings so they appear in the global summary
            var topFailed = failedLoginGroups
                .OrderByDescending(kv => kv.Value.Count)
                .Take(10)
                .ToList();

            if (topFailed.Any())
            {
                foreach (var kv in topFailed)
                {
                    var parts = kv.Key.Split('|');
                    string fIp = parts.Length > 0 ? parts[0] : "?";
                    string fUser = parts.Length > 1 ? parts[1] : "?";
                    findings.Add(
                        $"[AUTH] [MEDIUM] Failed login: {fIp} user={fUser}" +
                        $" x{kv.Value.Count}" +
                        $" [{kv.Value.First:yyyy-MM-dd HH:mm:ss} → {kv.Value.Last:yyyy-MM-dd HH:mm:ss} UTC]");
                }
            }
        }

        // ── Helpers ───────────────────────────────────────────────────
        private static void IncrementIPCount(
            Dictionary<string, int> ips, string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress)) return;
            ips[ipAddress] = ips.TryGetValue(ipAddress, out var v) ? v + 1 : 1;
        }

        /// <summary>
        /// Supports ISO-8601 and traditional syslog "MMM dd HH:mm:ss" timestamps.
        /// </summary>
        private static DateTime TryParseTimestamp(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return DateTime.MinValue;

            // ISO-8601: 2025-12-17T08:43:59.462512+01:00
            var iso = Regex.Match(line,
                @"^(?<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\b");
            if (iso.Success &&
                DateTimeOffset.TryParse(iso.Groups["ts"].Value,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var dto))
                return dto.UtcDateTime;

            // Syslog: "MMM dd HH:mm:ss"
            var sys = Regex.Match(line,
                @"^(?<mon>\w{3})\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})\b");
            if (!sys.Success) return DateTime.MinValue;

            string ts2 = $"{sys.Groups["mon"].Value} {sys.Groups["day"].Value} {sys.Groups["time"].Value}";
            if (!DateTime.TryParseExact(ts2, "MMM d HH:mm:ss",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt) &&
                !DateTime.TryParseExact(ts2, "MMM dd HH:mm:ss",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out dt))
                return DateTime.MinValue;

            dt = dt.AddYears(DateTime.Now.Year - dt.Year);
            // Unspecified, not Local: this is the collected host's clock, not
            // the analyst workstation's. CorrectTimestamp() applies the real
            // per-collection year/offset correction downstream.
            return DateTime.SpecifyKind(dt, DateTimeKind.Unspecified);
        }
        // ── Public parse-only entry point (no QuickWins writing) ──────────
        // Called by the orchestrator so it can write ONE combined section
        // with per-file subheaders instead of repeating the header per file.
        public (List<string> Findings,
                Dictionary<string, int> Patterns,
                DateTime First,
                DateTime Last)
            ParseFile(string filePath)
        {
            // Routed through ProcessLogAndReturnFindings (not ParseLog directly)
            // so InferredYear/TimeOffset get set and CorrectTimestamp actually
            // runs on this live code path — previously this bypassed both.
            var (findings, patterns, first, last) =
                ProcessLogAndReturnFindings(filePath, outputDir: null,
                    interestingIPs: null, suppressFooter: true);

            return (findings, patterns, first, last);
        }
    }
}
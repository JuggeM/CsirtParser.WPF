using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Helpers;
using Output;

namespace Parsers
{
    /// <summary>
    /// Parses .bash_history files collected by UAC from user home directories.
    ///
    /// Handles:
    ///   - Plain history (one command per line)
    ///   - Timestamped history (HISTTIMEFORMAT set — #epoch lines before each command)
    ///
    /// Discovery covers:
    ///   [root]/root/.bash_history (or root_bash_history.txt UAC flat dump)
    ///   [root]/home/*/.bash_history
    ///   live_response/user_files/*/bash_history.txt  (UAC user_files collector)
    /// </summary>
    public class BashHistoryParser : LogFileParser, IAttachNormalizedWriter
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        // ════════════════════════════════════════════════════════════════
        // Classification tables
        // ════════════════════════════════════════════════════════════════

        // [HIGH] — near-certain attacker activity
        private static readonly string[] CriticalKeywords =
        {
            // Reverse shells
            "bash -i", "sh -i", "zsh -i",
            "/dev/tcp/", "/dev/udp/",
            "0>&1", ">&/dev/null",
            // Encoded one-liners
            "python -c", "python2 -c", "python3 -c",
            "perl -e", "ruby -e", "php -r",
            "node -e",
            // Listeners / forwarders
            "nc -l", "ncat -l", "socat",
            "mkfifo",
            // Credential access
            "cat /etc/shadow", "cat /etc/passwd",
            "unshadow", "john ", "hashcat",
            "mimikatz", "pypykatz",
            // Anti-forensics
            "history -c", "history -w /dev/null",
            "unset HISTFILE", "HISTFILE=/dev/null",
            "shred -u", "shred /var/log",
            "rm -rf /var/log", "rm -f /var/log",
            // SUID / privilege escalation
            "chmod +s", "chmod u+s",
            "chattr +i",
            "pkexec",
            // Kernel exploit indicators
            "insmod ", "modprobe ",
            // Dropper patterns
            "wget -O /tmp", "wget -o /tmp",
            "curl -o /tmp", "curl -O /tmp",
            "curl -s http", "curl -sS http",
            "/tmp/", "/dev/shm/", "/var/tmp/",
            // Explicit attacker tools
            "msfconsole", "msfvenom",
            "Empire", "Covenant",
            "chisel", "ligolo",
            "crackmapexec", "cme ",
            "impacket", "secretsdump",
        };

        // [SUSPICIOUS] — worth reviewing, not automatically malicious
        private static readonly string[] SuspiciousKeywords =
        {
            // Downloads (legitimate but commonly abused)
            "wget ", "curl ",
            "scp ", "rsync ",
            // Privilege changes
            "sudo su", "su -", "su root",
            "visudo",
            // User / group manipulation
            "useradd", "adduser", "usermod",
            "groupadd", "passwd ",
            // Persistence touches
            "crontab -e",
            "systemctl enable", "systemctl start",
            "~/.bashrc", "~/.bash_profile", "~/.profile",
            "/etc/rc.local",
            // Recon
            "nmap ", "masscan ", "zmap ",
            "netstat", "ss -", "lsof ",
            "ps aux", "ps -ef",
            "find / -perm", "find / -suid",
            // Package installs of hacking tools
            "apt install nmap", "apt-get install nmap",
            "pip install impacket",
            "pip3 install",
            // SSH key manipulation
            "ssh-keygen", "authorized_keys",
            // Encoding / obfuscation
            "base64 -d", "base64 --decode",
            "openssl enc",
            // Data staging
            "tar czf", "zip -r",
        };

        // Always suppress — routine admin commands that create noise
        private static readonly string[] Whitelist =
        {
            "ls ", "ls\t", "ls\n", "ls -",
            "cd ", "pwd", "echo ", "cat ",
            "grep ", "awk ", "sed ",
            "vim ", "vi ", "nano ", "less ", "more ",
            "man ", "history",
            "exit", "logout",
            "git ", "make ", "cmake ",
            "docker ps", "docker images", "docker logs",
            "kubectl get", "kubectl describe",
            "systemctl status", "systemctl list",
            "journalctl",
            "df ", "du ", "free ",
            "top", "htop",
            "ping ", "dig ", "nslookup ",
            "apt list", "apt show", "dpkg -l",
            "yum list", "rpm -q",
        };

        // Regex for HISTTIMEFORMAT timestamp lines: #1234567890
        private static readonly Regex HistTimestamp =
            new(@"^#(?<epoch>\d{10,})$", RegexOptions.Compiled);

        // Regex to extract SSH target IP/host from ssh commands
        private static readonly Regex SshTarget =
            new(@"ssh\s+(?:-\S+\s+)*(?<user>[A-Za-z0-9._\-]+@)?(?<host>[A-Za-z0-9.\-]+)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // ════════════════════════════════════════════════════════════════
        // Discovery
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Finds all bash_history files in a UAC collection root.
        /// Returns a list of (filePath, inferredUsername) tuples.
        /// </summary>
        public static List<(string FilePath, string Username)> DiscoverHistoryFiles(
            string collectionRoot)
        {
            var results = new List<(string FilePath, string Username)>();
            if (!Directory.Exists(collectionRoot)) return results;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // UAC stores the filesystem under [root]\ or root\
            var bases = new[]
            {
                collectionRoot,
                Path.Combine(collectionRoot, "[root]"),
                Path.Combine(collectionRoot, "root"),
            }.Where(Directory.Exists);

            foreach (var b in bases)
            {
                // root's history: /root/.bash_history
                foreach (var name in new[] { ".bash_history", "bash_history.txt" })
                {
                    var p = Path.Combine(b, "root", name);
                    if (File.Exists(p) && seen.Add(p))
                        results.Add((p, "root"));
                }

                // /home/*/.bash_history
                var homePath = Path.Combine(b, "home");
                if (Directory.Exists(homePath))
                {
                    foreach (var userDir in Directory.EnumerateDirectories(homePath))
                    {
                        var username = Path.GetFileName(userDir);
                        foreach (var name in new[] { ".bash_history", "bash_history.txt" })
                        {
                            var p = Path.Combine(userDir, name);
                            if (File.Exists(p) && seen.Add(p))
                                results.Add((p, username));
                        }
                    }
                }
            }

            // UAC user_files collector: live_response/user_files/<user>/bash_history.txt
            var lrPath = Directory.EnumerateDirectories(
                    collectionRoot, "live_response", SearchOption.AllDirectories)
                .FirstOrDefault();

            if (!string.IsNullOrEmpty(lrPath))
            {
                var userFilesPath = Path.Combine(lrPath, "user_files");
                if (Directory.Exists(userFilesPath))
                {
                    foreach (var userDir in Directory.EnumerateDirectories(userFilesPath))
                    {
                        var username = Path.GetFileName(userDir);
                        foreach (var name in new[] { "bash_history.txt", ".bash_history" })
                        {
                            var p = Path.Combine(userDir, name);
                            if (File.Exists(p) && seen.Add(p))
                                results.Add((p, username));
                        }
                    }
                }

                // Also try flat UAC dumps: live_response/*_bash_history.txt
                foreach (var f in Directory.EnumerateFiles(lrPath, "*bash_history*",
                             SearchOption.AllDirectories))
                {
                    if (!seen.Add(f)) continue;
                    // Infer username from filename: root_bash_history.txt → root
                    var username = Path.GetFileName(f)
                        .Replace("_bash_history.txt", "")
                        .Replace(".bash_history", "")
                        .Replace("bash_history", "unknown");
                    results.Add((f, username));
                }
            }

            return results.OrderBy(r => r.Username).ThenBy(r => r.FilePath).ToList();
        }

        // ════════════════════════════════════════════════════════════════
        // ParseLog (LogFileParser contract)
        // ════════════════════════════════════════════════════════════════

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
            // Infer username from path (best effort)
            string username = InferUsername(logFilePath);

            var lines = ReadAllLines(logFilePath).ToList();
            ParseLines(lines, username, logFilePath,
                findings, patternCounts, ref firstSeen, ref lastSeen);
        }

        // ════════════════════════════════════════════════════════════════
        // Core parsing logic
        // ════════════════════════════════════════════════════════════════

        private void ParseLines(
            IReadOnlyList<string> lines,
            string username,
            string filePath,
            List<string> findings,
            Dictionary<string, int> patternCounts,
            ref DateTime firstSeen,
            ref DateTime lastSeen)
        {
            DateTime? pendingTs = null;
            DateTime? prevTs = null;
            var antiForensics = new List<string>();

            for (int i = 0; i < lines.Count; i++)
            {
                var raw = lines[i];
                if (string.IsNullOrWhiteSpace(raw)) continue;

                // ── HISTTIMEFORMAT timestamp line ────────────────────────────
                var tsMatch = HistTimestamp.Match(raw);
                if (tsMatch.Success)
                {
                    if (long.TryParse(tsMatch.Groups["epoch"].Value, out var epoch))
                    {
                        try
                        {
                            pendingTs = DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime;
                            if (pendingTs < firstSeen || firstSeen == DateTime.MaxValue)
                                firstSeen = pendingTs.Value;
                            if (pendingTs > lastSeen)
                                lastSeen = pendingTs.Value;
                        }
                        catch { pendingTs = null; }
                    }
                    continue;
                }

                // ── Command line ─────────────────────────────────────────────
                string cmd = raw.Trim();
                DateTime cmdTs = pendingTs ?? DateTime.MinValue;

                // Timestamp gap detection — gaps > 12 h between commands are notable
                // (could indicate session break, or that history was tampered between)
                string gapNote = string.Empty;
                if (pendingTs.HasValue && prevTs.HasValue)
                {
                    var gap = pendingTs.Value - prevTs.Value;
                    if (gap.TotalHours > 12)
                        gapNote = $" [GAP {(int)gap.TotalHours}h since previous command]";
                }

                prevTs = pendingTs;
                pendingTs = null;

                // Only filter by date when a timestamp is actually known
                if (cmdTs != DateTime.MinValue && !IsInRange(cmdTs)) continue;

                string tier = ClassifyCommand(cmd);
                if (tier == "Info") continue;

                string tsStr = cmdTs != DateTime.MinValue
                    ? $"{cmdTs:yyyy-MM-dd HH:mm:ss} UTC"
                    : "no-timestamp";

                string display = cmd.Length > 200 ? cmd.Substring(0, 197) + "..." : cmd;
                string severity = tier == "Critical" ? "HIGH" : "SUSPICIOUS";
                string tag = tier == "Critical" ? "[HIGH]" : "[SUSPICIOUS]";

                // Track anti-forensics commands for special summary
                if (IsAntiForensics(cmd))
                    antiForensics.Add(cmd);

                IncrementPatternCount(patternCounts,
                    tier == "Critical" ? "Critical shell command" : "Suspicious shell command");

                findings.Add(
                    $"[BASH] {tag} [{tsStr}] user={username}: {display}{gapNote}");

                // Extract SSH lateral movement targets
                if (cmd.StartsWith("ssh ", StringComparison.OrdinalIgnoreCase))
                {
                    var sshM = SshTarget.Match(cmd);
                    if (sshM.Success)
                    {
                        string target = sshM.Groups["host"].Value;
                        string sshUser = sshM.Groups["user"].Value.TrimEnd('@');
                        findings.Add(
                            $"[BASH] [LATERAL] [{tsStr}] user={username} SSH→ {target}" +
                            (string.IsNullOrEmpty(sshUser) ? "" : $" as {sshUser}"));
                    }
                }

                _normalizedWriter?.Write(NormalizedRecord.From(
                    cmdTs != DateTime.MinValue ? cmdTs : DateTime.UtcNow,
                    string.Empty, "BASH",
                    "bash", username, string.Empty,
                    display, severity, cmd));
            }

            // Anti-forensics summary — always surface even if individual lines are medium
            if (antiForensics.Count > 0)
            {
                IncrementPatternCount(patternCounts, "Anti-forensics detected");
                findings.Add(
                    $"[BASH] [HIGH] user={username}: {antiForensics.Count} anti-forensics " +
                    $"command(s) detected (history clearing / HISTFILE manipulation)");
            }
        }

        // ════════════════════════════════════════════════════════════════
        // Classification helpers
        // ════════════════════════════════════════════════════════════════

        private static string ClassifyCommand(string cmd)
        {
            if (string.IsNullOrWhiteSpace(cmd)) return "Info";

            // Whitelist check first — avoids false positives on common commands
            // that happen to contain a suspicious substring (e.g. "cat /etc/hosts")
            if (IsWhitelisted(cmd)) return "Info";

            var lo = cmd.ToLowerInvariant();

            foreach (var kw in CriticalKeywords)
                if (lo.Contains(kw, StringComparison.OrdinalIgnoreCase)) return "Critical";

            foreach (var kw in SuspiciousKeywords)
                if (lo.Contains(kw, StringComparison.OrdinalIgnoreCase)) return "Suspicious";

            return "Info";
        }

        private static bool IsWhitelisted(string cmd)
        {
            // Only apply whitelist to commands that don't already hit Critical
            var lo = cmd.ToLowerInvariant();

            // cat is only safe when not reading shadow/passwd
            if (lo.StartsWith("cat "))
                return !lo.Contains("/etc/shadow") && !lo.Contains("/etc/passwd")
                    && !lo.Contains("/etc/sudoers");

            foreach (var w in Whitelist)
                if (lo.StartsWith(w, StringComparison.OrdinalIgnoreCase)
                    || lo.Equals(w.TrimEnd(), StringComparison.OrdinalIgnoreCase))
                    return true;

            return false;
        }

        private static bool IsAntiForensics(string cmd)
        {
            var lo = cmd.ToLowerInvariant();
            return lo.Contains("history -c")
                || lo.Contains("history -w /dev/null")
                || lo.Contains("unset histfile")
                || lo.Contains("histfile=/dev/null")
                || lo.Contains("shred") && lo.Contains("log")
                || lo.Contains("rm -rf /var/log")
                || lo.Contains("rm -f /var/log");
        }

        // ════════════════════════════════════════════════════════════════
        // Helpers
        // ════════════════════════════════════════════════════════════════

        private static string InferUsername(string filePath)
        {
            // .../home/alice/.bash_history → alice
            // .../root/.bash_history       → root
            // live_response/user_files/bob/bash_history.txt → bob
            var parts = filePath.Replace('\\', '/').Split('/');

            for (int i = parts.Length - 1; i >= 1; i--)
            {
                if (parts[i].Equals(".bash_history", StringComparison.OrdinalIgnoreCase)
                    || parts[i].Equals("bash_history.txt", StringComparison.OrdinalIgnoreCase))
                {
                    return parts[i - 1];
                }
            }

            // Flat dump pattern: root_bash_history.txt
            var fileName = Path.GetFileName(filePath);
            if (fileName.Contains("_bash_history"))
                return fileName.Replace("_bash_history.txt", "").Replace("_bash_history", "");

            return "unknown";
        }

        // ════════════════════════════════════════════════════════════════
        // Public parse-only entry point (no QuickWins write)
        // ════════════════════════════════════════════════════════════════

        /// <summary>
        /// Parses a single history file with a known username.
        /// Used by the orchestrator so it can write ONE combined QuickWins section.
        /// </summary>
        public (List<string> Findings,
                Dictionary<string, int> Patterns,
                DateTime First,
                DateTime Last)
            ParseFile(string filePath, string username)
        {
            var findings = new List<string>();
            var patterns = new Dictionary<string, int>();
            DateTime first = DateTime.MaxValue;
            DateTime last = DateTime.MinValue;

            var lines = File.Exists(filePath)
                ? File.ReadAllLines(filePath)
                : Array.Empty<string>();

            ParseLines(lines, username, filePath,
                findings, patterns, ref first, ref last);

            return (findings, patterns, first, last);
        }

        // LogFileParser.ParseFile(string) override — username inferred from path
        public override (List<string> Findings,
                          Dictionary<string, int> PatternCounts,
                          DateTime FirstSeen,
                          DateTime LastSeen)
            ParseFile(string filePath)
        {
            var (f, p, first, last) = ParseFile(filePath, InferUsername(filePath));
            return (f, p, first, last);
        }
    }
}
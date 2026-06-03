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
    /// Parses .zsh_history files from UAC collections.
    ///
    /// Handles two formats:
    ///   Extended (EXTENDED_HISTORY=on):  ": <epoch>:<duration>;<command>"
    ///   Plain:                           one command per line
    ///
    /// Discovery covers the same paths as BashHistoryParser but for zsh_history.
    /// </summary>
    public class ZshHistoryParser : LogFileParser, IAttachNormalizedWriter
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        private string _hostname = string.Empty;
        public void AttachHostname(string hostname) => _hostname = hostname ?? string.Empty;

        // ": <epoch>:<duration>;<command>"
        private static readonly Regex ExtendedLine =
            new(@"^:\s*(?<epoch>\d+):\d+;(?<cmd>.+)$", RegexOptions.Compiled);

        // Same suspicious keyword tables as BashHistoryParser
        private static readonly string[] CriticalKeywords =
        {
            "bash -i", "sh -i", "zsh -i",
            "/dev/tcp/", "/dev/udp/", "0>&1",
            "python -c", "python2 -c", "python3 -c",
            "perl -e", "ruby -e", "php -r", "node -e",
            "nc -l", "ncat -l", "socat", "mkfifo",
            "cat /etc/shadow", "cat /etc/passwd",
            "unshadow", "john ", "hashcat", "mimikatz", "pypykatz",
            "history -c", "unset HISTFILE", "HISTFILE=/dev/null",
            "shred -u", "shred /var/log", "rm -rf /var/log",
            "chmod +s", "chmod u+s", "chattr +i", "pkexec",
            "insmod ", "modprobe ",
            "wget -O /tmp", "curl -o /tmp", "curl -s http",
            "/tmp/", "/dev/shm/", "/var/tmp/",
            "msfconsole", "msfvenom", "chisel", "ligolo",
            "crackmapexec", "impacket", "secretsdump",
        };

        private static readonly string[] SuspiciousKeywords =
        {
            "wget ", "curl ", "scp ", "rsync ",
            "sudo su", "su -", "su root", "visudo",
            "useradd", "adduser", "usermod", "groupadd", "passwd ",
            "crontab -e", "systemctl enable", "systemctl start",
            "~/.zshrc", "~/.bashrc", "~/.bash_profile", "~/.profile",
            "nmap ", "masscan ", "zmap ",
            "netstat", "ss -", "lsof ", "ps aux", "ps -ef",
            "find / -perm", "find / -suid",
            "ssh-keygen", "authorized_keys",
            "base64 -d", "base64 --decode", "openssl enc",
            "tar czf", "zip -r",
        };

        // ── Discovery ─────────────────────────────────────────────────
        public static List<(string FilePath, string Username)> DiscoverFiles(string collectionRoot)
        {
            var results = new List<(string, string)>();
            if (!Directory.Exists(collectionRoot)) return results;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var bases = new[]
            {
                collectionRoot,
                Path.Combine(collectionRoot, "[root]"),
                Path.Combine(collectionRoot, "root"),
            }.Where(Directory.Exists);

            foreach (var b in bases)
            {
                foreach (var name in new[] { ".zsh_history", "zsh_history.txt" })
                {
                    var p = Path.Combine(b, "root", name);
                    if (File.Exists(p) && seen.Add(p)) results.Add((p, "root"));
                }

                var homePath = Path.Combine(b, "home");
                if (Directory.Exists(homePath))
                {
                    foreach (var userDir in Directory.EnumerateDirectories(homePath))
                    {
                        var user = Path.GetFileName(userDir);
                        foreach (var name in new[] { ".zsh_history", "zsh_history.txt" })
                        {
                            var p = Path.Combine(userDir, name);
                            if (File.Exists(p) && seen.Add(p)) results.Add((p, user));
                        }
                    }
                }
            }

            // live_response/user_files/<user>/zsh_history.txt
            var lrPath = Directory.EnumerateDirectories(
                collectionRoot, "live_response", SearchOption.AllDirectories).FirstOrDefault();

            if (!string.IsNullOrEmpty(lrPath))
            {
                var uf = Path.Combine(lrPath, "user_files");
                if (Directory.Exists(uf))
                {
                    foreach (var userDir in Directory.EnumerateDirectories(uf))
                    {
                        var user = Path.GetFileName(userDir);
                        foreach (var name in new[] { "zsh_history.txt", ".zsh_history" })
                        {
                            var p = Path.Combine(userDir, name);
                            if (File.Exists(p) && seen.Add(p)) results.Add((p, user));
                        }
                    }
                }
            }

            return results.OrderBy(r => r.Item2).ThenBy(r => r.Item1).ToList();
        }

        // ── ParseLog (LogFileParser contract) ─────────────────────────
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
            string username = InferUsername(logFilePath);
            ParseLines(ReadAllLines(logFilePath).ToList(), username,
                findings, patternCounts, ref firstSeen, ref lastSeen);
        }

        // ── Public entry point ────────────────────────────────────────
        public (List<string> Findings, Dictionary<string, int> Patterns, DateTime First, DateTime Last)
            ParseFile(string filePath, string username)
        {
            var findings = new List<string>();
            var patterns = new Dictionary<string, int>();
            DateTime first = DateTime.MaxValue, last = DateTime.MinValue;

            var lines = File.Exists(filePath)
                ? File.ReadAllLines(filePath)
                : Array.Empty<string>();

            ParseLines(lines, username, findings, patterns, ref first, ref last);
            return (findings, patterns, first, last);
        }

        public override (List<string>, Dictionary<string, int>, DateTime, DateTime) ParseFile(string filePath)
        {
            var (f, p, first, last) = ParseFile(filePath, InferUsername(filePath));
            return (f, p, first, last);
        }

        // ── Core parsing ──────────────────────────────────────────────
        private void ParseLines(
            IReadOnlyList<string> lines,
            string username,
            List<string> findings,
            Dictionary<string, int> patternCounts,
            ref DateTime firstSeen,
            ref DateTime lastSeen)
        {
            // Zsh can wrap long commands across lines with a trailing backslash
            var commands = new List<(string Cmd, DateTime Ts)>();
            string? pending = null;
            DateTime pendingTs = DateTime.MinValue;

            foreach (var raw in lines)
            {
                if (string.IsNullOrWhiteSpace(raw)) continue;

                var m = ExtendedLine.Match(raw);
                string cmdPart;
                DateTime ts = DateTime.MinValue;

                if (m.Success)
                {
                    if (long.TryParse(m.Groups["epoch"].Value, out var epoch))
                    {
                        try { ts = DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime; }
                        catch { ts = DateTime.MinValue; }
                    }
                    cmdPart = m.Groups["cmd"].Value;
                }
                else
                {
                    cmdPart = raw;
                }

                // Handle line continuation
                if (pending != null)
                {
                    pending += " " + cmdPart.TrimStart('\\').TrimStart();
                    if (!cmdPart.EndsWith("\\"))
                    {
                        commands.Add((pending.Trim(), pendingTs));
                        pending = null;
                    }
                    continue;
                }

                if (cmdPart.EndsWith("\\"))
                {
                    pending = cmdPart.TrimEnd('\\');
                    pendingTs = ts;
                    continue;
                }

                commands.Add((cmdPart.Trim(), ts));
            }

            if (pending != null) commands.Add((pending.Trim(), pendingTs));

            foreach (var (cmd, ts) in commands)
            {
                if (string.IsNullOrWhiteSpace(cmd)) continue;

                if (ts != DateTime.MinValue)
                {
                    if (ts < firstSeen) firstSeen = ts;
                    if (ts > lastSeen) lastSeen = ts;
                }

                string tier = Classify(cmd);
                if (tier == "Info") continue;

                string tsStr = ts != DateTime.MinValue ? $"{ts:yyyy-MM-dd HH:mm:ss} UTC" : "no-timestamp";
                string display = cmd.Length > 200 ? cmd[..197] + "..." : cmd;
                string severity = tier == "Critical" ? "HIGH" : "SUSPICIOUS";
                string tag = tier == "Critical" ? "[HIGH]" : "[SUSPICIOUS]";

                IncrementPatternCount(patternCounts,
                    tier == "Critical" ? "Critical shell command" : "Suspicious shell command");
                findings.Add($"[ZSH] {tag} [{tsStr}] user={username}: {display}");

                _normalizedWriter?.Write(NormalizedRecord.From(
                    ts != DateTime.MinValue ? ts : DateTime.UtcNow,
                    _hostname, "ZSH", "zsh_history",
                    username, string.Empty, display, severity, cmd));
            }
        }

        private static string Classify(string cmd)
        {
            if (string.IsNullOrWhiteSpace(cmd)) return "Info";
            var lo = cmd.ToLowerInvariant();
            foreach (var kw in CriticalKeywords)
                if (lo.Contains(kw, StringComparison.OrdinalIgnoreCase)) return "Critical";
            foreach (var kw in SuspiciousKeywords)
                if (lo.Contains(kw, StringComparison.OrdinalIgnoreCase)) return "Suspicious";
            return "Info";
        }

        private static string InferUsername(string filePath)
        {
            var parts = filePath.Replace('\\', '/').Split('/');
            for (int i = parts.Length - 1; i >= 1; i--)
            {
                if (parts[i].Equals(".zsh_history", StringComparison.OrdinalIgnoreCase)
                    || parts[i].Equals("zsh_history.txt", StringComparison.OrdinalIgnoreCase))
                    return parts[i - 1];
            }
            return "unknown";
        }
    }
}
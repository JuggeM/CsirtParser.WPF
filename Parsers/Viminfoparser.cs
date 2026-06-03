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
    /// Parses .viminfo / .vim/viminfo files from UAC collections.
    ///
    /// Forensically relevant sections:
    ///   ": <cmdline>"   — Vim command-line history  (:!cmd are shell escapes)
    ///   "/ <pattern>"   — Search string history
    ///   "> <filename>"  — File access history (mark registers)
    ///   "' <mark>"      — File marks with line numbers
    ///
    /// Shell escapes (:!cmd) are treated as Critical — they execute arbitrary
    /// commands from inside Vim and are a common attacker technique to avoid
    /// bash_history logging entirely.
    /// </summary>
    public class VimInfoParser : LogFileParser, IAttachNormalizedWriter
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        private string _hostname = string.Empty;
        public void AttachHostname(string hostname) => _hostname = hostname ?? string.Empty;

        // Sensitive files accessed via Vim
        private static readonly string[] SensitiveFiles =
        {
            "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/crontab",
            "id_rsa", "authorized_keys", ".ssh/", "known_hosts",
            "/etc/ssh/", ".bashrc", ".bash_profile", ".zshrc",
            "/etc/rc.local", "/etc/systemd/", "/etc/cron",
            ".aws/credentials", ".gnupg/", "wallet.dat",
        };

        // Suspicious search patterns inside Vim
        private static readonly string[] SuspiciousSearchTerms =
        {
            "password", "passwd", "secret", "credential", "token",
            "private key", "BEGIN RSA", "BEGIN EC", "BEGIN DSA",
            "id_rsa", "authorized", "shadow", "sudoers",
            "reverse shell", "exec", "system(", "popen",
        };

        // Shell escape commands inside Vim that are suspicious
        private static readonly string[] CriticalShellKeywords =
        {
            "bash -i", "/dev/tcp/", "nc -l", "socat", "mkfifo",
            "python -c", "perl -e", "ruby -e",
            "wget ", "curl ", "/tmp/", "/dev/shm/",
            "chmod +s", "useradd", "usermod",
            "cat /etc/shadow", "cat /etc/passwd",
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
                // root's viminfo
                foreach (var name in new[] { ".viminfo", "viminfo.txt" })
                {
                    var p = Path.Combine(b, "root", name);
                    if (File.Exists(p) && seen.Add(p)) results.Add((p, "root"));
                }
                // .vim/viminfo under root
                var vimDir = Path.Combine(b, "root", ".vim");
                if (Directory.Exists(vimDir))
                {
                    var p = Path.Combine(vimDir, "viminfo");
                    if (File.Exists(p) && seen.Add(p)) results.Add((p, "root"));
                }

                var homePath = Path.Combine(b, "home");
                if (Directory.Exists(homePath))
                {
                    foreach (var userDir in Directory.EnumerateDirectories(homePath))
                    {
                        var user = Path.GetFileName(userDir);
                        foreach (var name in new[] { ".viminfo", "viminfo.txt" })
                        {
                            var p = Path.Combine(userDir, name);
                            if (File.Exists(p) && seen.Add(p)) results.Add((p, user));
                        }
                        var vimD = Path.Combine(userDir, ".vim");
                        if (Directory.Exists(vimD))
                        {
                            var p = Path.Combine(vimD, "viminfo");
                            if (File.Exists(p) && seen.Add(p)) results.Add((p, user));
                        }
                    }
                }
            }

            // live_response/user_files/<user>/viminfo.txt
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
                        var p = Path.Combine(userDir, "viminfo.txt");
                        if (File.Exists(p) && seen.Add(p)) results.Add((p, user));
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
            var lines = File.Exists(filePath) ? File.ReadAllLines(filePath) : Array.Empty<string>();
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
            string section = string.Empty;

            for (int i = 0; i < lines.Count; i++)
            {
                var raw = lines[i];
                if (string.IsNullOrWhiteSpace(raw)) continue;

                // Section markers
                if (raw.StartsWith("# "))
                {
                    section = raw.ToUpperInvariant();
                    continue;
                }

                // ── Command-line history ──────────────────────────────
                if (raw.StartsWith(':'))
                {
                    var cmd = raw[1..].Trim();

                    // Shell escape: :!<command>
                    if (cmd.StartsWith('!'))
                    {
                        var shellCmd = cmd[1..].Trim();
                        bool isCritical = CriticalShellKeywords.Any(k =>
                            shellCmd.Contains(k, StringComparison.OrdinalIgnoreCase));
                        string severity = isCritical ? "HIGH" : "SUSPICIOUS";
                        string tag = isCritical ? "[HIGH]" : "[SUSPICIOUS]";

                        findings.Add(
                            $"[VIMINFO] {tag} [shell-escape] user={username}: {shellCmd}");
                        IncrementPatternCount(patternCounts,
                            isCritical ? "Vim shell escape (Critical)" : "Vim shell escape");

                        _normalizedWriter?.Write(NormalizedRecord.From(
                            DateTime.UtcNow, _hostname, "VIMINFO", "vim",
                            username, string.Empty, shellCmd, severity, raw));
                        continue;
                    }

                    // Interesting non-shell commands
                    if (cmd.StartsWith("r ") || cmd.Contains("read "))
                    {
                        findings.Add($"[VIMINFO] [SUSPICIOUS] [read-cmd] user={username}: {cmd}");
                        IncrementPatternCount(patternCounts, "Vim read command");
                        _normalizedWriter?.Write(NormalizedRecord.From(
                            DateTime.UtcNow, _hostname, "VIMINFO", "vim",
                            username, string.Empty, cmd, "SUSPICIOUS", raw));
                    }
                    continue;
                }

                // ── Search string history ─────────────────────────────
                if (raw.StartsWith('/') || raw.StartsWith('?'))
                {
                    var pattern = raw[1..].Trim();
                    if (string.IsNullOrEmpty(pattern)) continue;

                    bool isSuspicious = SuspiciousSearchTerms.Any(t =>
                        pattern.Contains(t, StringComparison.OrdinalIgnoreCase));

                    if (isSuspicious)
                    {
                        findings.Add(
                            $"[VIMINFO] [SUSPICIOUS] [search] user={username}: searched for \"{pattern}\"");
                        IncrementPatternCount(patternCounts, "Suspicious Vim search term");
                        _normalizedWriter?.Write(NormalizedRecord.From(
                            DateTime.UtcNow, _hostname, "VIMINFO", "vim",
                            username, string.Empty, $"Search: {pattern}", "SUSPICIOUS", raw));
                    }
                    continue;
                }

                // ── File access history (> <filename>) ───────────────
                if (raw.StartsWith('>'))
                {
                    var filePath2 = raw[1..].Trim();
                    bool isSensitive = SensitiveFiles.Any(s =>
                        filePath2.Contains(s, StringComparison.OrdinalIgnoreCase));

                    if (isSensitive)
                    {
                        findings.Add(
                            $"[VIMINFO] [SUSPICIOUS] [file-access] user={username}: opened \"{filePath2}\"");
                        IncrementPatternCount(patternCounts, "Sensitive file opened in Vim");
                        _normalizedWriter?.Write(NormalizedRecord.From(
                            DateTime.UtcNow, _hostname, "VIMINFO", "vim",
                            username, string.Empty, $"Opened: {filePath2}", "SUSPICIOUS", raw));
                    }
                    continue;
                }
            }
        }

        private static string InferUsername(string filePath)
        {
            var parts = filePath.Replace('\\', '/').Split('/');
            for (int i = parts.Length - 1; i >= 1; i--)
            {
                if (parts[i].Equals(".viminfo", StringComparison.OrdinalIgnoreCase)
                    || parts[i].Equals("viminfo.txt", StringComparison.OrdinalIgnoreCase)
                    || parts[i].Equals("viminfo", StringComparison.OrdinalIgnoreCase))
                    return parts[i - 1];
            }
            return "unknown";
        }
    }
}
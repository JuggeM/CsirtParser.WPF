using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Helpers;
using Output;

namespace Parsers
{
    /// <summary>
    /// Parses .lesshst files from UAC collections.
    ///
    /// .lesshst stores the search and shell history from the `less` pager.
    /// Attackers frequently clear .bash_history but forget this file.
    ///
    /// File format:
    ///   .less-history-file-format
    ///   ":search"
    ///   "term1"
    ///   "term2"
    ///   ":shell"
    ///   "command1"
    ///
    /// Forensic value:
    ///   - ":search" section reveals what the attacker searched for
    ///     inside files they were reading (credentials, keys, usernames)
    ///   - ":shell" section reveals commands run via the '!' escape
    ///     from inside less — these completely bypass bash_history
    ///   - No timestamps — but presence alone is significant
    /// </summary>
    public class LessHstParser : LogFileParser, IAttachNormalizedWriter
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        private string _hostname = string.Empty;
        public void AttachHostname(string hostname) => _hostname = hostname ?? string.Empty;

        private static readonly string[] SuspiciousSearchTerms =
        {
            "password", "passwd", "shadow", "secret", "credential", "token",
            "private", "id_rsa", "authorized", "BEGIN RSA", "BEGIN EC",
            "admin", "root", "sudo", "sudoers",
            "key", "cert", "pem", "pfx",
            ".aws", "access_key", "secret_key",
        };

        private static readonly string[] CriticalShellKeywords =
        {
            "bash -i", "/dev/tcp/", "nc -l", "socat", "mkfifo",
            "python -c", "perl -e", "ruby -e",
            "wget ", "curl ", "/tmp/", "/dev/shm/",
            "chmod +s", "useradd", "usermod",
            "cat /etc/shadow", "cat /etc/passwd",
            "history -c", "unset HISTFILE",
        };

        // ── Discovery ─────────────────────────────────────────────────
        public static List<(string FilePath, string Username)> DiscoverFiles(string collectionRoot)
        {
            var results = new List<(string, string)>();
            if (!Directory.Exists(collectionRoot)) return results;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var fileNames = new[] { ".lesshst", "lesshst.txt", "less_hst.txt" };

            var bases = new[]
            {
                collectionRoot,
                Path.Combine(collectionRoot, "[root]"),
                Path.Combine(collectionRoot, "root"),
            }.Where(Directory.Exists);

            foreach (var b in bases)
            {
                foreach (var name in fileNames)
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
                        foreach (var name in fileNames)
                        {
                            var p = Path.Combine(userDir, name);
                            if (File.Exists(p) && seen.Add(p)) results.Add((p, user));
                        }
                    }
                }
            }

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
                        foreach (var name in fileNames)
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
            ParseLines(ReadAllLines(logFilePath).ToList(), InferUsername(logFilePath),
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

            foreach (var raw in lines)
            {
                if (string.IsNullOrWhiteSpace(raw)) continue;

                // Strip surrounding quotes that less uses
                string value = raw.Trim().Trim('"');

                // Section header lines
                if (value.Equals(".less-history-file-format", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (value.StartsWith(':'))
                {
                    section = value.ToLowerInvariant(); // ":search" or ":shell"
                    continue;
                }

                if (string.IsNullOrEmpty(value)) continue;

                if (section == ":search")
                {
                    bool isSuspicious = SuspiciousSearchTerms.Any(t =>
                        value.Contains(t, StringComparison.OrdinalIgnoreCase));

                    if (isSuspicious)
                    {
                        findings.Add(
                            $"[LESSHST] [SUSPICIOUS] [search] user={username}: searched for \"{value}\"");
                        IncrementPatternCount(patternCounts, "Suspicious less search term");
                        _normalizedWriter?.Write(NormalizedRecord.From(
                            DateTime.UtcNow, _hostname, "LESSHST", "less",
                            username, string.Empty, $"Search: {value}", "SUSPICIOUS", raw));
                    }
                }
                else if (section == ":shell")
                {
                    bool isCritical = CriticalShellKeywords.Any(k =>
                        value.Contains(k, StringComparison.OrdinalIgnoreCase));
                    string severity = isCritical ? "HIGH" : "SUSPICIOUS";
                    string tag = isCritical ? "[HIGH]" : "[SUSPICIOUS]";

                    findings.Add(
                        $"[LESSHST] {tag} [shell-escape] user={username}: {value}");
                    IncrementPatternCount(patternCounts,
                        isCritical ? "Less shell escape (Critical)" : "Less shell escape");
                    _normalizedWriter?.Write(NormalizedRecord.From(
                        DateTime.UtcNow, _hostname, "LESSHST", "less",
                        username, string.Empty, value, severity, raw));
                }
            }
        }

        private static string InferUsername(string filePath)
        {
            var parts = filePath.Replace('\\', '/').Split('/');
            for (int i = parts.Length - 1; i >= 1; i--)
            {
                if (parts[i].Contains("lesshst", StringComparison.OrdinalIgnoreCase)
                    || parts[i].Contains("less_hst", StringComparison.OrdinalIgnoreCase))
                    return parts[i - 1];
            }
            return "unknown";
        }
    }
}
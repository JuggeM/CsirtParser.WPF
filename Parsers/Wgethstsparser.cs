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
    /// Parses .wget-hsts files from UAC collections.
    ///
    /// .wget-hsts is written by GNU Wget whenever it connects to an HTTPS host.
    /// It persists across reboots and is rarely cleared by attackers — making it
    /// a reliable record of download activity even after files are deleted.
    ///
    /// Format (tab-separated):
    ///   # HSTS 1.0 Known Hosts database for GNU Wget.
    ///   <hostname>  <port>  <incl_subdomains>  <created>  <max_age>  <seen>
    ///
    ///   created / seen = Unix epoch seconds
    ///
    /// Forensic value:
    ///   - C2 domains contacted via wget
    ///   - Dropper download sources
    ///   - Timestamps even after download files are deleted
    ///   - Unusual non-CDN/non-package-manager hosts
    /// </summary>
    public class WgetHstsParser : LogFileParser, IAttachNormalizedWriter
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        private string _hostname = string.Empty;
        public void AttachHostname(string hostname) => _hostname = hostname ?? string.Empty;

        // Trusted CDN/package domains — suppress to reduce noise
        private static readonly string[] TrustedDomains =
        {
            "ubuntu.com", "debian.org", "centos.org", "fedoraproject.org",
            "github.com", "githubusercontent.com", "pypi.org", "pythonhosted.org",
            "npmjs.com", "yarnpkg.com", "rubygems.org",
            "docker.com", "amazonaws.com", "cloudfront.net",
            "google.com", "googleapis.com", "gstatic.com",
            "microsoft.com", "azure.com", "windows.net",
            "mozilla.org", "mozilla.net",
            "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
            "archive.org",
        };

        // High-confidence suspicious: raw IPs, unusual TLDs, known free hosting
        private static readonly Regex SuspiciousHostPattern = new(
            @"(^(\d{1,3}\.){3}\d{1,3}$)|" +          // raw IPv4
            @"(\.xyz$)|(\.top$)|(\.tk$)|(\.ml$)|" +    // throwaway TLDs
            @"(\.onion$)|" +                            // Tor
            @"(ngrok\.io$)|(pagekite\.me$)|" +          // reverse tunnel
            @"(\.duckdns\.org$)|(\.no-ip\.com$)",       // DDNS
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // ── Discovery ─────────────────────────────────────────────────
        public static List<(string FilePath, string Username)> DiscoverFiles(string collectionRoot)
        {
            var results = new List<(string, string)>();
            if (!Directory.Exists(collectionRoot)) return results;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var fileNames = new[] { ".wget-hsts", "wget-hsts.txt", "wget_hsts.txt" };

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
            foreach (var raw in lines)
            {
                if (string.IsNullOrWhiteSpace(raw) || raw.TrimStart().StartsWith('#')) continue;

                // Tab-separated: hostname  port  incl_subdomains  created  max_age  seen
                var cols = raw.Split('\t');
                if (cols.Length < 4) continue;

                string host = cols[0].Trim();
                string portStr = cols[1].Trim();
                string created = cols.Length > 3 ? cols[3].Trim() : string.Empty;
                string seen = cols.Length > 5 ? cols[5].Trim() : string.Empty;

                // Parse timestamps
                DateTime ts = DateTime.UtcNow;
                if (long.TryParse(created, out var epoch) && epoch > 0)
                {
                    try
                    {
                        ts = DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime;
                        if (ts < firstSeen) firstSeen = ts;
                        if (ts > lastSeen) lastSeen = ts;
                    }
                    catch { /* ignore malformed */ }
                }

                if (string.IsNullOrEmpty(host)) continue;

                // Always write all entries to CSV for timeline reconstruction
                string severity = "Info";
                bool isTrusted = TrustedDomains.Any(d => host.EndsWith(d, StringComparison.OrdinalIgnoreCase));
                bool isSuspicious = !isTrusted && SuspiciousHostPattern.IsMatch(host);

                if (isSuspicious)
                {
                    severity = "HIGH";
                    findings.Add($"[WGETHSTS] [HIGH] user={username}: suspicious wget target: {host} (first seen: {ts:yyyy-MM-dd HH:mm:ss} UTC)");
                    IncrementPatternCount(patternCounts, "Suspicious wget host");
                }
                else if (!isTrusted)
                {
                    severity = "SUSPICIOUS";
                    findings.Add($"[WGETHSTS] [SUSPICIOUS] user={username}: untrusted wget target: {host} (first seen: {ts:yyyy-MM-dd HH:mm:ss} UTC)");
                    IncrementPatternCount(patternCounts, "Untrusted wget host");
                }

                // Write all entries (trusted ones as Info) for full download timeline
                _normalizedWriter?.Write(NormalizedRecord.From(
                    ts, _hostname, "WGETHSTS", "wget",
                    username, host,
                    $"HSTS entry: {host}:{portStr}",
                    severity, raw));
            }
        }

        private static string InferUsername(string filePath)
        {
            var parts = filePath.Replace('\\', '/').Split('/');
            for (int i = parts.Length - 1; i >= 1; i--)
            {
                if (parts[i].Contains("wget", StringComparison.OrdinalIgnoreCase)
                    || parts[i].Contains("hsts", StringComparison.OrdinalIgnoreCase))
                    return parts[i - 1];
            }
            return "unknown";
        }
    }
}
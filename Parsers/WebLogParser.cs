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
    public class WebLogParser : LogFileParser, IAttachNormalizedWriter
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        // Shared brute-force detector — injected by the orchestrator so it
        // accumulates across ALL web log files, not just one at a time.
        private WebBruteForceDetector _bruteForceDetector;
        public void AttachBruteForceDetector(WebBruteForceDetector d) => _bruteForceDetector = d;

        private static readonly Regex Combined = new(
            @"^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<dt>[^\]]+)\]\s+""(?<method>\S+)\s+(?<uri>\S+)(?:\s+(?<proto>[^""]+))?""\s+(?<status>\d{3})\s+(?<size>\d+|-)\s+""(?<ref>[^""]*)""\s+""(?<ua>[^""]*)""",
            RegexOptions.Compiled);

        // ── Classification ────────────────────────────────────────────
        //
        // Critical → RTF findings  (clear attack indicators in URI)
        // Noise    → pattern counts only  (scanners, 404s, common probes)
        // Info     → everything else
        //
        private static readonly string[] CriticalUriKeywords =
        {
            // SQL injection
            "union+select", "union%20select", "union select",
            "sleep(", "benchmark(", "' or '", "1=1",
            // RCE / LFI / path traversal
            "../../../", "../../", "%2e%2e", "%252e",
            "/etc/passwd", "/etc/shadow", "/proc/self",
            "cmd.php", "shell.php", "c99.php", "r57.php",
            "eval(", "base64_decode(",
            // XSS
            "<script>", "%3cscript", "javascript:",
            "onerror=", "onload=",
            // Web shells / admin probes
            "/phpmyadmin", "/adminer", "/.env", "/.git/config",
            "/wp-config.php", "/xmlrpc.php", "/.htpasswd",
            // Tools
            "sqlmap", "nikto", "masscan",
            // Null byte
            "%00",
        };

        private static readonly string[] NoiseUriKeywords =
        {
            "wp-login", "wp-admin", "/admin", "/login",
            "/.well-known", "/robots.txt", "/favicon.ico",
        };

        private static string ClassifyUri(string uriLower)
        {
            foreach (var kw in CriticalUriKeywords)
                if (uriLower.Contains(kw)) return "Critical";
            // High volume 4xx from a single IP is handled by brute-force detector
            return "Info";
        }

        // ── Discovery ─────────────────────────────────────────────────
        public static List<string> DiscoverWebLogFiles(string collectionRoot)
        {
            var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(collectionRoot) || !Directory.Exists(collectionRoot))
                return new List<string>();

            var candidateRoots = new[]
            {
                collectionRoot,
                Path.Combine(collectionRoot, "root"),
                Path.Combine(collectionRoot, "[root]")
            }.Distinct(StringComparer.OrdinalIgnoreCase);

            foreach (var baseRoot in candidateRoots)
            {
                if (!Directory.Exists(baseRoot)) continue;
                AddDir(results, Path.Combine(baseRoot, "var", "log", "nginx"));
                AddDir(results, Path.Combine(baseRoot, "var", "log", "apache2"));
                AddDir(results, Path.Combine(baseRoot, "var", "log", "httpd"));
                AddDir(results, Path.Combine(baseRoot, "var", "www"));
            }

            static void AddDir(HashSet<string> set, string dir)
            {
                if (!Directory.Exists(dir)) return;
                foreach (var f in Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories))
                {
                    var name = Path.GetFileName(f);
                    if (name.EndsWith(".log", StringComparison.OrdinalIgnoreCase) ||
                        name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                        name.EndsWith(".log.gz", StringComparison.OrdinalIgnoreCase) ||
                        name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                        set.Add(f);
                }
            }

            return results.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
        }

        // ── Helpers ───────────────────────────────────────────────────
        private static string InferDaemonFromPath(string path)
        {
            var p = (path ?? "").ToLowerInvariant();
            if (p.Contains("nginx")) return "nginx";
            if (p.Contains("apache") || p.Contains("httpd")) return "apache2";
            return "web";
        }

        private static DateTime TryParseApacheOrIsoToUtc(string line)
        {
            var iso = Regex.Match(line,
                @"^(?<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2}))");
            if (iso.Success && DateTimeOffset.TryParse(iso.Groups["iso"].Value, out var dtoIso))
                return dtoIso.UtcDateTime;

            var bracket = Regex.Match(line, @"\[(?<dt>[^\]]+)\]");
            if (bracket.Success && DateTimeOffset.TryParseExact(
                    bracket.Groups["dt"].Value,
                    "dd/MMM/yyyy:HH:mm:ss zzz",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AllowWhiteSpaces,
                    out var dtoApache))
                return dtoApache.UtcDateTime;

            return DateTime.MinValue;
        }

        private void WriteNormalized(DateTime tsUtc, string daemon, string ip,
            string msg, string severity, string rawLine)
        {
            _normalizedWriter?.Write(NormalizedRecord.From(
                tsUtc, string.Empty, "WEB",
                daemon ?? "web",
                string.Empty,
                ip ?? string.Empty,
                msg ?? string.Empty,
                severity ?? string.Empty,
                rawLine ?? string.Empty));
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
            string daemon = InferDaemonFromPath(logFilePath);
            var bfd = _bruteForceDetector ?? new WebBruteForceDetector();

            // Attack grouping: keyword → (count, first, last, sample IP, sample URI)
            var attackGroups = new Dictionary<string,
                (int Count, DateTime First, DateTime Last, string Ip, string Uri)>(
                StringComparer.OrdinalIgnoreCase);

            foreach (var line in ReadAllLines(logFilePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                DateTime tsUtc = TryParseApacheOrIsoToUtc(line);
                if (tsUtc != DateTime.MinValue)
                {
                    if (tsUtc < firstSeen) firstSeen = tsUtc;
                    if (tsUtc > lastSeen) lastSeen = tsUtc;
                }

                var m = Combined.Match(line);
                if (!m.Success)
                {
                    WriteNormalized(tsUtc, daemon, "", line, "Info", line);
                    continue;
                }

                string ip = m.Groups["ip"].Value;
                string method = m.Groups["method"].Value;
                string uri = m.Groups["uri"].Value;
                string status = m.Groups["status"].Value;
                string size = m.Groups["size"].Value;
                string uriLo = uri.ToLowerInvariant();

                string tier = ClassifyUri(uriLo);

                if (tier == "Critical")
                {
                    // Find which keyword matched for grouping
                    string kw = CriticalUriKeywords
                        .FirstOrDefault(k => uriLo.Contains(k)) ?? "attack";

                    IncrementPatternCount(patternCounts, kw);
                    if (interestingIPs != null) IncrementIPCount(interestingIPs, ip);

                    if (attackGroups.TryGetValue(kw, out var g))
                        attackGroups[kw] = (
                            g.Count + 1,
                            tsUtc < g.First ? tsUtc : g.First,
                            tsUtc > g.Last ? tsUtc : g.Last,
                            g.Ip, g.Uri);
                    else
                        attackGroups[kw] = (1, tsUtc, tsUtc, ip, uri);
                }

                bfd.Track(ip, uri, method, status, "", tsUtc);

                string msg = $"{method} {uri} -> {status} {size}B";
                WriteNormalized(tsUtc, daemon, ip, msg,
                    tier == "Critical" ? "High" : "Info", line);
            }

            // Emit grouped attack findings
            foreach (var kv in attackGroups.OrderByDescending(k => k.Value.Count))
            {
                string range = kv.Value.Count == 1
                    ? $"{kv.Value.First:yyyy-MM-dd HH:mm:ss} UTC"
                    : $"{kv.Value.First:yyyy-MM-dd HH:mm:ss} \u2192 {kv.Value.Last:yyyy-MM-dd HH:mm:ss} UTC (x{kv.Value.Count})";

                string uri = kv.Value.Uri.Length > 80
                    ? kv.Value.Uri.Substring(0, 77) + "..."
                    : kv.Value.Uri;

                findings.Add(
                    $"[WEB] [HIGH] [{range}] [{Truncate(kv.Key)}] {kv.Value.Ip}: {uri}");
            }

            // Brute-force findings are emitted by the orchestrator after all
            // files are parsed, so the shared detector has the full picture.

            static string Truncate(string k) =>
                k.Length > 30 ? k.Substring(0, 27) + "..." : k;
        }

        private static void IncrementIPCount(Dictionary<string, int> ips, string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return;
            ips[ip] = ips.TryGetValue(ip, out var v) ? v + 1 : 1;
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
    }
}
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
    public class WebLogParser : LogFileParser
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        // Shared brute-force detector — injected by the orchestrator so it
        // accumulates across ALL web log files, not just one at a time.
        private WebBruteForceDetector _bruteForceDetector;
        public void AttachBruteForceDetector(WebBruteForceDetector d) => _bruteForceDetector = d;

        // Access log line. Accepts:
        //   combined        ip - user [time] "req" status size "referer" "agent"
        //   common (CLF)    ip - user [time] "req" status size
        //   vhost_combined  vhost:port ip - user [time] "req" status size "referer" "agent"
        //                   (Debian's other_vhosts_access.log)
        private static readonly Regex Combined = new(
            @"^(?:(?<vhost>\S+:\d+)\s+(?=\S+\s+\S+\s+\S+\s+\[))?(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<dt>[^\]]+)\]\s+""(?<method>\S+)\s+(?<uri>\S+)(?:\s+(?<proto>[^""]+))?""\s+(?<status>\d{3})\s+(?<size>\d+|-)(?:\s+""(?<ref>[^""]*)""\s+""(?<ua>[^""]*)"")?",
            RegexOptions.Compiled);

        // ── error.log ─────────────────────────────────────────────────
        // Apache 2.4: [Mon Nov 30 10:08:44.120000 2026] [php:warn] [pid 2211] [client 1.2.3.4:5112] msg
        // Apache 2.2: [Mon Nov 30 10:08:44 2026] [error] [client 1.2.3.4] msg
        // nginx:      2026/11/30 10:02:00 [error] 1234#0: *5 msg, client: 1.2.3.4, server: …
        private static readonly Regex ApacheErrorTime = new(
            @"^\[\w{3}\s+(?<mon>\w{3})\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})(?:\.\d+)?\s+(?<year>\d{4})\]",
            RegexOptions.Compiled);
        private static readonly Regex NginxErrorTime = new(
            @"^(?<dt>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?<level>\w+)\]",
            RegexOptions.Compiled);
        private static readonly Regex ErrorClient = new(
            @"\[client\s+(?<ip>[0-9a-fA-F.:]+?)(?::\d+)?\]|\bclient:\s*(?<ip>[0-9a-fA-F.:]+)",
            RegexOptions.Compiled);
        private static readonly Regex ModSecMsg = new(@"\[msg\s+""(?<msg>[^""]+)""\]", RegexOptions.Compiled);
        private static readonly Regex ModSecUri = new(@"\[uri\s+""(?<uri>[^""]+)""\]", RegexOptions.Compiled);

        // (type, severity, pattern) — first match wins
        private static readonly (string Type, string Severity, Regex Rx)[] ErrorPatterns =
        {
            // stderr of commands run by PHP (webshell) lands in the error log, without a timestamp
            ("Shell command output", "HIGH", new Regex(
                @"^(?:sh|bash|dash|ash|zsh):\s+(?:\d+:\s+)?|^--\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}--\s+\S+|^curl:\s+\(\d+\)|^wget:\s|^(?:Resolving|Connecting to) \S+.*\.\.\.|^nc:\s|^python3?:\s|^perl:\s",
                RegexOptions.Compiled)),
            ("PHP command execution", "HIGH", new Regex(
                @"PHP\s+(?:Warning|Notice|Fatal error|Parse error|Deprecated).*?\b(?:system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec|assert|create_function)\s*\(\)|eval\(\)'d code|base64_decode\(\).*eval",
                RegexOptions.Compiled | RegexOptions.IgnoreCase)),
            ("Remote file include attempt", "MEDIUM", new Regex(
                @"\b(?:include|require)(?:_once)?\(\).*?(?:https?|ftp|data|php)://",
                RegexOptions.Compiled | RegexOptions.IgnoreCase)),
            ("LFI attempt (PHP include failed)", "MEDIUM", new Regex(
                @"\b(?:include|require)(?:_once)?\(\).*?(?:\.\./|/etc/|/proc/self/)",
                RegexOptions.Compiled | RegexOptions.IgnoreCase)),
            ("Worker crash (segfault)", "MEDIUM", new Regex(
                @"exit signal Segmentation fault|signal 11\b|exited on signal 11",
                RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        };

        // ── Classification ────────────────────────────────────────────
        //
        // Matching runs on the URL-DECODED request (twice, for double
        // encoding; '+' as space), because real logs carry %27, %2F, %3D…
        // Severity depends on the response: an attack the server answered
        // with 2xx/3xx is HIGH ("served"), a 4xx/5xx is MEDIUM ("attempt").
        // Webshell execution is CRITICAL. Findings are grouped per
        // (IP, attack type) with counts, status codes and sample requests.

        private static readonly (string Type, Regex Rx)[] AttackPatterns =
        {
            ("SQL injection", new Regex(
                @"union(?:\s|/\*.*?\*/)+(?:all(?:\s|/\*.*?\*/)+)?select\b|\b(?:and|or)\s+\d+\s*=\s*\d+|'\s*(?:or|and)\s+'?\d|'\s*(?:or|and)\s+'[^']*'\s*=\s*'|\bsleep\s*\(\s*\d|\bbenchmark\s*\(|information_schema|\bwaitfor\s+delay\b|\bextractvalue\s*\(|\bupdatexml\s*\(|concat\s*\([^)]*0x3a",
                RegexOptions.Compiled | RegexOptions.IgnoreCase)),
            ("Path traversal / LFI", new Regex(
                @"\.\.[/\\]|/etc/(?:passwd|shadow|hosts|group)\b|/proc/self/|php://(?:filter|input)|\bfile://|expect://|zip://",
                RegexOptions.Compiled | RegexOptions.IgnoreCase)),
            ("Command injection / RCE", new Regex(
                @"(?:[;|`]|&&)\s*(?:id|whoami|uname|cat|wget|curl|bash|sh|nc|python3?|perl)\b|\$\((?:id|whoami|curl|wget)|\b(?:eval|system|exec|passthru|shell_exec|base64_decode)\s*\(|\$\{jndi:",
                RegexOptions.Compiled | RegexOptions.IgnoreCase)),
            ("XSS", new Regex(
                @"<\s*script|javascript:|\bon(?:error|load|mouseover)\s*=|<\s*svg[^>]*on\w+\s*=",
                RegexOptions.Compiled | RegexOptions.IgnoreCase)),
        };

        // Requests for files that should never be served (secrets, VCS, admin tools)
        private static readonly Regex SensitiveProbe = new(
            @"/\.env\b|/\.git/|/\.svn/|/\.htpasswd|/\.htaccess|/\.aws/|/\.ssh/|wp-config\.php|/config\.php\.(?:bak|old|save)|\.(?:sql|bak|old|swp)(?:$|\?)|/phpmyadmin|/adminer|/server-status|/actuator\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // A script executed from a directory where users can upload files
        private static readonly Regex UploadDirScript = new(
            @"/(?:wp-content/uploads|uploads?|images?|img|files|media|tmp|temp|cache|assets/upload)/[^?#]*\.(?:php\d?|phtml|phar|jsp|jspx|aspx?|cgi|pl)(?:$|[?#])",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Well-known webshell names anywhere on the site
        private static readonly Regex KnownShellName = new(
            @"/(?:cmd|shell|c99|r57|wso|b374k|alfa|webshell|backdoor|up|uploader)\.(?:php\d?|phtml|jsp|aspx?)(?:$|[?#])",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Command parameter handed to a script
        private static readonly Regex CommandParam = new(
            @"[?&](?:cmd|exec|command|execute|shell|c|run|code)=(?<cmd>[^&#]+)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Attack tools identified by user agent
        private static readonly (string Tool, Regex Rx)[] ScannerAgents =
        {
            ("sqlmap", new Regex(@"sqlmap", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("Nikto", new Regex(@"nikto", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("Nuclei", new Regex(@"nuclei", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("WPScan", new Regex(@"wpscan", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("masscan", new Regex(@"masscan", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("zgrab", new Regex(@"zgrab", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("Nmap", new Regex(@"nmap scripting engine|\bnmap\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("gobuster", new Regex(@"gobuster", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("dirbuster", new Regex(@"dirbuster|dirb\b", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("ffuf", new Regex(@"\bffuf\b|fuzz faster", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("feroxbuster", new Regex(@"feroxbuster", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("Hydra", new Regex(@"hydra", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("Acunetix", new Regex(@"acunetix|acunetix-product", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("Burp", new Regex(@"burp", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("OpenVAS", new Regex(@"openvas", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
            ("WhatWeb", new Regex(@"whatweb", RegexOptions.IgnoreCase | RegexOptions.Compiled)),
        };

        /// <summary>URL-decodes twice (double encoding) and treats '+' as space.</summary>
        internal static string DecodeUri(string uri)
        {
            string s = uri ?? string.Empty;
            for (int i = 0; i < 2; i++)
            {
                string next;
                try { next = Uri.UnescapeDataString(s.Replace('+', ' ')); }
                catch { break; }
                if (next == s) break;
                s = next;
            }
            return s;
        }

        internal static string? ScannerTool(string userAgent)
        {
            foreach (var (tool, rx) in ScannerAgents)
                if (rx.IsMatch(userAgent ?? string.Empty)) return tool;
            return null;
        }

        /// <summary>
        /// Attack type for one request, or null. Webshell checks come first,
        /// so "img.php?cmd=wget …" is reported as a webshell command, not RCE.
        /// </summary>
        internal static string? ClassifyRequest(string rawUri, string decoded, string method, out string? command)
        {
            command = null;
            var path = decoded.Split('?')[0];
            bool shellPath = UploadDirScript.IsMatch(decoded) || KnownShellName.IsMatch(decoded);
            var cm = CommandParam.Match(decoded);
            if (shellPath && cm.Success)
            {
                command = cm.Groups["cmd"].Value.Trim();
                return "Webshell command";
            }
            if (shellPath) return method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                ? "Webshell POST" : "Script in upload dir";

            foreach (var (type, rx) in AttackPatterns)
                if (rx.IsMatch(decoded)) return type;

            if (rawUri.Contains("%00")) return "Null byte injection";
            if (SensitiveProbe.IsMatch(path)) return "Sensitive file probe";
            return null;
        }

        private static bool IsServed(int status) => status >= 200 && status < 400;

        private sealed class Group
        {
            public string Ip = "";
            public string Type = "";
            public int Count;
            public DateTime First = DateTime.MaxValue, Last = DateTime.MinValue;
            public SortedDictionary<int, int> Statuses = new();
            public List<string> Samples = new();
            public List<string> Commands = new();
            public string? Tool;
            public string? FixedSeverity;   // error.log groups: no HTTP status to judge by
            public int Served =>Statuses.Where(s => IsServed(s.Key)).Sum(s => s.Value);
        }

        private sealed class ScannerGroup
        {
            public string Ip = "", Tool = "";
            public int Count;
            public DateTime First = DateTime.MaxValue, Last = DateTime.MinValue;
            public SortedDictionary<int, int> Statuses = new();
            public List<string> Samples = new();
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
            string daemon = DaemonOverride ?? InferDaemonFromPath(logFilePath);
            if (IsErrorLog ?? IsErrorLogName(logFilePath))
            {
                ParseErrorLog(logFilePath, daemon, findings, patternCounts, ref firstSeen, ref lastSeen, interestingIPs);
                return;
            }
            var bfd = _bruteForceDetector ?? new WebBruteForceDetector();

            var groups = new Dictionary<(string Ip, string Type), Group>();
            var scanners = new Dictionary<string, ScannerGroup>(StringComparer.Ordinal);

            foreach (var line in ReadAllLines(logFilePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                DateTime tsUtc = TryParseApacheOrIsoToUtc(line);
                if (tsUtc != DateTime.MinValue)
                {
                    if (tsUtc < firstSeen) firstSeen = tsUtc;
                    if (tsUtc > lastSeen) lastSeen = tsUtc;
                }

                if (!IsInRange(tsUtc)) continue;

                var m = Combined.Match(line);
                if (!m.Success)
                {
                    WriteNormalized(tsUtc, daemon, "", line, "Info", line);
                    continue;
                }

                string ip = m.Groups["ip"].Value;
                string vhost = m.Groups["vhost"].Success ? m.Groups["vhost"].Value + " " : "";
                string method = m.Groups["method"].Value;
                string uri = m.Groups["uri"].Value;
                string statusStr = m.Groups["status"].Value;
                string size = m.Groups["size"].Value;
                string ua = m.Groups["ua"].Value;
                int status = int.TryParse(statusStr, out var st) ? st : 0;
                string decoded = DecodeUri(uri);

                string? tool = ScannerTool(ua);
                string? type = ClassifyRequest(uri, decoded, method, out var command);

                // Attack request → (IP, type) group
                if (type != null && !(type == "Sensitive file probe" && !IsServed(status) && tool != null))
                {
                    var key = (ip, type);
                    if (!groups.TryGetValue(key, out var g))
                        groups[key] = g = new Group { Ip = ip, Type = type };
                    g.Count++;
                    if (tsUtc < g.First) g.First = tsUtc;
                    if (tsUtc > g.Last) g.Last = tsUtc;
                    g.Statuses[status] = g.Statuses.TryGetValue(status, out var c) ? c + 1 : 1;
                    var sample = $"{vhost}{method} {Shorten(decoded, 110)} → {status}";
                    if (g.Samples.Count < 3 && !g.Samples.Contains(sample)) g.Samples.Add(sample);
                    if (command != null && g.Commands.Count < 5 && !g.Commands.Contains(command)) g.Commands.Add(command);
                    g.Tool ??= tool;
                    IncrementPatternCount(patternCounts, type);
                    if (interestingIPs != null) IncrementIPCount(interestingIPs, ip);
                }

                // Scanner traffic → one group per IP
                if (tool != null)
                {
                    if (!scanners.TryGetValue(ip, out var sg))
                        scanners[ip] = sg = new ScannerGroup { Ip = ip, Tool = tool };
                    sg.Count++;
                    if (tsUtc < sg.First) sg.First = tsUtc;
                    if (tsUtc > sg.Last) sg.Last = tsUtc;
                    sg.Statuses[status] = sg.Statuses.TryGetValue(status, out var c2) ? c2 + 1 : 1;
                    if (sg.Samples.Count < 4 && type != null) sg.Samples.Add(decoded.Split('?')[0]);
                    if (!sg.Tool.Contains(tool)) sg.Tool += "/" + tool;
                }

                bfd.Track(ip, uri, method, statusStr, ua, tsUtc);

                string sev = type == null ? "Info"
                           : type.StartsWith("Webshell") || type == "Script in upload dir" ? (IsServed(status) ? "Critical" : "Medium")
                           : IsServed(status) ? "High" : "Medium";
                string msg = $"{vhost}{method} {decoded} -> {status} {size}B" + (type != null ? $" [{type}]" : "");
                WriteNormalized(tsUtc, daemon, ip, msg, sev, line);
            }

            // ── Emit grouped attack findings ──────────────────────────
            foreach (var g in groups.Values
                         .OrderBy(g => Severity(g) switch { "CRITICAL" => 0, "HIGH" => 1, _ => 2 })
                         .ThenBy(g => g.First))
            {
                string sev = Severity(g);
                string outcome = g.Served == g.Count ? "served"
                               : g.Served == 0 ? "failed/blocked"
                               : $"{g.Served} of {g.Count} served";
                string range = g.Count == 1
                    ? $"{g.First:yyyy-MM-dd HH:mm:ss} UTC"
                    : $"{g.First:yyyy-MM-dd HH:mm:ss} \u2192 {g.Last:yyyy-MM-dd HH:mm:ss} UTC";
                string statuses = string.Join(", ", g.Statuses.Select(s => $"{s.Key} x{s.Value}"));
                string toolText = g.Tool != null ? $" via {g.Tool}" : "";
                string cmds = g.Commands.Count > 0 ? $" | commands: {string.Join(" ; ", g.Commands.Select(c => Shorten(c, 80)))}" : "";

                findings.Add(
                    $"[WEB] [{sev}] [{range}] {g.Type} from {g.Ip}{toolText}: {g.Count} request(s), {outcome} (status {statuses})" +
                    $"{cmds} | e.g. {string.Join(" ; ", g.Samples)}");
            }

            // ── Scanner summary per IP ────────────────────────────────
            foreach (var sg in scanners.Values.OrderByDescending(s => s.Count))
            {
                string range = sg.Count == 1
                    ? $"{sg.First:yyyy-MM-dd HH:mm:ss} UTC"
                    : $"{sg.First:yyyy-MM-dd HH:mm:ss} \u2192 {sg.Last:yyyy-MM-dd HH:mm:ss} UTC";
                string statuses = string.Join(", ", sg.Statuses.Select(s => $"{s.Key} x{s.Value}"));
                string samples = sg.Samples.Count > 0 ? $" | e.g. {string.Join(", ", sg.Samples.Distinct())}" : "";
                IncrementPatternCount(patternCounts, $"Scanner ({sg.Tool})");
                findings.Add(
                    $"[WEB] [MEDIUM] [{range}] Scanner {sg.Tool} from {sg.Ip}: {sg.Count} request(s) (status {statuses}){samples}");
            }

            // Brute-force findings are emitted by the orchestrator after all
            // files are parsed, so the shared detector has the full picture.

            static string Severity(Group g)
            {
                if (g.FixedSeverity != null) return g.FixedSeverity;
                bool shell = g.Type.StartsWith("Webshell") || g.Type == "Script in upload dir";
                if (shell) return g.Served > 0 ? "CRITICAL" : "MEDIUM";
                return g.Served > 0 ? "HIGH" : "MEDIUM";
            }
        }

        /// <summary>Daemon name to use when the parsed path is a temp copy (e.g. a decompressed .gz).</summary>
        public string? DaemonOverride { get; set; }

        /// <summary>Forces error-log parsing (temp copy of error.log.N.gz); null = decide by file name.</summary>
        public bool? IsErrorLog { get; set; }

        public static bool IsErrorLogName(string path) =>
            Path.GetFileName(path ?? "").Contains("error", StringComparison.OrdinalIgnoreCase);

        // ── error.log parsing ─────────────────────────────────────────
        private void ParseErrorLog(string logFilePath, string daemon, List<string> findings,
            Dictionary<string, int> patternCounts, ref DateTime firstSeen, ref DateTime lastSeen,
            Dictionary<string, int> interestingIPs)
        {
            var groups = new Dictionary<(string Ip, string Type), Group>();
            DateTime lastTs = DateTime.MinValue;
            string lastIp = "";

            foreach (var line in ReadAllLines(logFilePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                // Timestamp (host-local, no zone) → UTC. Lines without one
                // (stderr of child processes) inherit the previous line's time.
                DateTime ts = DateTime.MinValue;
                var a = ApacheErrorTime.Match(line);
                if (a.Success && DateTime.TryParseExact(
                        $"{a.Groups["day"].Value} {a.Groups["mon"].Value} {a.Groups["year"].Value} {a.Groups["time"].Value}",
                        "d MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var at))
                    ts = CorrectTimestamp(at);
                else
                {
                    var n = NginxErrorTime.Match(line);
                    if (n.Success && DateTime.TryParseExact(n.Groups["dt"].Value, "yyyy/MM/dd HH:mm:ss",
                            CultureInfo.InvariantCulture, DateTimeStyles.None, out var nt))
                        ts = CorrectTimestamp(nt);
                }

                bool timestamped = ts != DateTime.MinValue;
                if (timestamped)
                {
                    if (ts < firstSeen) firstSeen = ts;
                    if (ts > lastSeen) lastSeen = ts;
                    lastTs = ts;
                }
                else
                {
                    // wget's own progress line carries a (host-local) time: "--2026-11-02 10:16:05--  url"
                    var w = Regex.Match(line, @"^--(?<dt>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})--");
                    ts = w.Success && DateTime.TryParseExact(w.Groups["dt"].Value, "yyyy-MM-dd HH:mm:ss",
                             CultureInfo.InvariantCulture, DateTimeStyles.None, out var wt)
                        ? (lastTs = CorrectTimestamp(wt))
                        : lastTs;
                }

                if (!IsInRange(ts)) continue;

                var cm = ErrorClient.Match(line);
                string ip = cm.Success ? cm.Groups["ip"].Value : (timestamped ? "" : lastIp);
                if (timestamped) lastIp = ip;

                // Message = text after the last leading [..] block / nginx "*N "
                string msg = line;
                if (timestamped)
                {
                    msg = Regex.Replace(line, @"^(?:\[[^\]]*\]\s*)+", "");
                    msg = Regex.Replace(msg, @"^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[\w+\]\s+\d+#\d+:\s+(?:\*\d+\s+)?", "");
                }

                string? type = null, sev = null, sample = null;
                if (line.Contains("ModSecurity:", StringComparison.Ordinal))
                {
                    bool denied = line.Contains("Access denied", StringComparison.OrdinalIgnoreCase);
                    var ruleMsg = ModSecMsg.Match(line);
                    var ruleUri = ModSecUri.Match(line);
                    type = $"WAF {(denied ? "blocked" : "alert")}: " +
                           (ruleMsg.Success ? Shorten(ruleMsg.Groups["msg"].Value, 70) : "ModSecurity rule");
                    sev = "MEDIUM";
                    sample = ruleUri.Success ? DecodeUri(ruleUri.Groups["uri"].Value) : null;
                }
                else
                {
                    foreach (var (t, s, rx) in ErrorPatterns)
                    {
                        // Shell output patterns are anchored; match them on the bare
                        // stderr line or on the message after the [..] prefix.
                        if (rx.IsMatch(msg) || (!timestamped && rx.IsMatch(line.TrimStart())))
                        {
                            type = t; sev = s;
                            break;
                        }
                    }
                }

                string normSev = sev switch { "HIGH" => "High", "MEDIUM" => "Medium", _ => "Info" };
                WriteNormalized(ts, daemon, ip, msg.Trim(), normSev, line);
                if (type == null) continue;

                var key = (ip, type);
                if (!groups.TryGetValue(key, out var g))
                    groups[key] = g = new Group { Ip = ip, Type = type, FixedSeverity = sev };
                g.Count++;
                if (ts != DateTime.MinValue)
                {
                    if (ts < g.First) g.First = ts;
                    if (ts > g.Last) g.Last = ts;
                }
                var ex = Shorten((sample ?? msg).Trim(), 140);
                if (g.Samples.Count < 3 && !g.Samples.Contains(ex)) g.Samples.Add(ex);
                IncrementPatternCount(patternCounts, type.StartsWith("WAF") ? "WAF (ModSecurity)" : type);
                if (interestingIPs != null) IncrementIPCount(interestingIPs, ip);
            }

            foreach (var g in groups.Values
                         .OrderBy(g => g.FixedSeverity == "HIGH" ? 0 : 1)
                         .ThenBy(g => g.First))
            {
                string range = g.First == DateTime.MaxValue ? "no time"
                    : g.Count == 1 || g.First == g.Last ? $"{g.First:yyyy-MM-dd HH:mm:ss} UTC"
                    : $"{g.First:yyyy-MM-dd HH:mm:ss} → {g.Last:yyyy-MM-dd HH:mm:ss} UTC";
                string from = string.IsNullOrEmpty(g.Ip) ? "" : $" from {g.Ip}";
                findings.Add(
                    $"[WEB] [{g.FixedSeverity}] [{range}] {g.Type}{from}: {g.Count} error.log line(s) | e.g. {string.Join(" ; ", g.Samples)}");
            }
        }

        private static string Shorten(string s, int max) =>
            s.Length > max ? s.Substring(0, max - 3) + "..." : s;

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
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
    /// Parses .python_history files from UAC collections.
    ///
    /// Forensic value:
    ///   - Live exploit/payload development in the Python REPL
    ///   - subprocess / os.system calls that bypass bash_history
    ///   - Socket-based reverse shells built interactively
    ///   - Credential handling (base64 decode, file reads)
    ///   - Import of offensive libraries (impacket, scapy, pwntools)
    ///
    /// Note: Python history has no timestamps — all records written with
    /// collection time as a placeholder.
    /// </summary>
    public class PythonHistoryParser : LogFileParser, IAttachNormalizedWriter
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        private string _hostname = string.Empty;
        public void AttachHostname(string hostname) => _hostname = hostname ?? string.Empty;

        private static readonly string[] CriticalKeywords =
        {
            // OS command execution
            "os.system(", "os.popen(", "subprocess.call(",
            "subprocess.run(", "subprocess.Popen(",
            "commands.getoutput(", "commands.getstatusoutput(",
            // Socket reverse shells
            "socket.socket(", "/dev/tcp", "0>&1",
            // exec / eval abuse
            "exec(", "eval(", "compile(",
            "__import__(",
            // Credential access
            "open('/etc/shadow'", "open(\"/etc/shadow\"",
            "open('/etc/passwd'", "open(\"/etc/passwd\"",
            // Offensive imports
            "import impacket", "from impacket",
            "import scapy", "from scapy",
            "import pwntools", "from pwn import",
            "import paramiko",
            // Encoding / payloads
            "base64.b64decode(", "base64.decodebytes(",
            "marshal.loads(", "pickle.loads(",
            // Crypto miner / dropper patterns
            "xmrig", "cryptominer",
            "urllib.request.urlretrieve(",
            "requests.get(", "requests.post(",
        };

        private static readonly string[] SuspiciousKeywords =
        {
            // File operations on sensitive paths
            "open('/etc/", "open(\"/etc/",
            "open('/root/", "open(\"/root/",
            ".ssh/", "authorized_keys",
            // Network
            "socket.connect(", "socket.bind(",
            "http.client", "urllib.request",
            // Obfuscation
            "base64.b64encode(",
            "zlib.decompress(",
            "gzip.decompress(",
            // User/privilege operations
            "os.setuid(", "os.setgid(",
            "os.chmod(",  "os.chown(",
            "ctypes.CDLL(",
        };

        // ── Discovery ─────────────────────────────────────────────────
        public static List<(string FilePath, string Username)> DiscoverFiles(string collectionRoot)
        {
            var results = new List<(string, string)>();
            if (!Directory.Exists(collectionRoot)) return results;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var fileNames = new[]
            {
                ".python_history", "python_history.txt",
                ".python3_history", "python3_history.txt",
            };

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

                string cmd = raw.Trim();
                string display = cmd.Length > 200 ? cmd[..197] + "..." : cmd;

                bool isCritical = CriticalKeywords.Any(k => cmd.Contains(k, StringComparison.OrdinalIgnoreCase));
                bool isSuspicious = !isCritical && SuspiciousKeywords.Any(k => cmd.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (!isCritical && !isSuspicious) continue;

                string severity = isCritical ? "HIGH" : "SUSPICIOUS";
                string tag = isCritical ? "[HIGH]" : "[SUSPICIOUS]";

                findings.Add($"[PYTHON] {tag} user={username}: {display}");
                IncrementPatternCount(patternCounts,
                    isCritical ? "Critical Python command" : "Suspicious Python command");

                _normalizedWriter?.Write(NormalizedRecord.From(
                    DateTime.UtcNow, _hostname, "PYHISTORY", "python",
                    username, string.Empty, display, severity, cmd));
            }
        }

        private static string InferUsername(string filePath)
        {
            var parts = filePath.Replace('\\', '/').Split('/');
            for (int i = parts.Length - 1; i >= 1; i--)
            {
                if (parts[i].Contains("python_history", StringComparison.OrdinalIgnoreCase))
                    return parts[i - 1];
            }
            return "unknown";
        }
    }
}
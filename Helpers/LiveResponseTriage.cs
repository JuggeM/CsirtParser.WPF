using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Turns UAC live_response process and network listings into findings,
    /// so a running miner or an open reverse shell shows up in QuickWins
    /// instead of only in a raw dump.
    /// </summary>
    public static class LiveResponseTriage
    {
        private static readonly string[] TempPaths = { "/tmp/", "/dev/shm/", "/var/tmp/" };

        // Matched at a word start (see KeywordMatcher)
        private static readonly string[] SuspiciousCommandKeywords =
        {
            "bash -i", "sh -i", "nc ", "ncat ", "netcat", "socat", "/dev/tcp/", "/dev/udp/",
            "python -c", "python3 -c", "perl -e", "php -r", "mkfifo",
            "xmrig", "--pool", "stratum+tcp", "stratum+ssl", "--donate-level",
            "chisel", "ligolo", "frpc", "ngrok", "gsocket", "gs-netcat",
        };

        // Ports commonly used for reverse shells, C2 and mining pools
        private static readonly HashSet<int> SuspiciousPorts = new()
        {
            1337, 31337, 4444, 4445, 5555, 6666, 6667, 7777, 8888, 9001, 9050, 1080,
            3333, 5730, 7000, 14433, 14444, 45560,
        };

        private static readonly Regex AddrPort = new(
            @"(?<ip>(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]+:[0-9a-fA-F:]*)[:.](?<port>\d{1,5})$",
            RegexOptions.Compiled);

        public static List<string> Analyze(string liveResponseRoot)
        {
            var findings = new List<string>();
            if (string.IsNullOrEmpty(liveResponseRoot) || !Directory.Exists(liveResponseRoot)) return findings;

            var flaggedPids = new Dictionary<string, string>();   // pid -> command
            findings.AddRange(AnalyzeProcesses(liveResponseRoot, flaggedPids));
            findings.AddRange(AnalyzeNetwork(liveResponseRoot, flaggedPids));
            return findings;
        }

        // ── Processes ────────────────────────────────────────────────────
        private static IEnumerable<string> AnalyzeProcesses(string root, Dictionary<string, string> flaggedPids)
        {
            var results = new List<string>();
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var file in FindFiles(root, "ps*.txt"))
            {
                string[] lines;
                try { lines = File.ReadAllLines(file); } catch { continue; }
                if (lines.Length == 0) continue;

                // Locate the COMMAND/CMD column from the header
                int headerIdx = Array.FindIndex(lines, l => Regex.IsMatch(l, @"\bPID\b") && Regex.IsMatch(l, @"\b(COMMAND|CMD|ARGS)\b"));
                if (headerIdx < 0) continue;
                var header = lines[headerIdx];
                var cols = Regex.Split(header.Trim(), @"\s+");
                int pidCol = Array.FindIndex(cols, c => c == "PID");
                int userCol = Array.FindIndex(cols, c => c is "USER" or "UID");
                int cmdCol = Array.FindIndex(cols, c => c is "COMMAND" or "CMD" or "ARGS");
                if (pidCol < 0 || cmdCol < 0) continue;

                foreach (var line in lines.Skip(headerIdx + 1))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var parts = Regex.Split(line.Trim(), @"\s+", RegexOptions.None);
                    if (parts.Length <= cmdCol) continue;
                    var pid = parts[pidCol];
                    var user = userCol >= 0 ? parts[userCol] : "?";
                    var cmd = string.Join(" ", parts.Skip(cmdCol)).Trim();
                    // strip ps forest art
                    cmd = Regex.Replace(cmd, @"^[\\_| ]+", "");

                    string? reason = null;
                    var exe = cmd.Split(' ')[0];
                    if (TempPaths.Any(t => exe.StartsWith(t, StringComparison.Ordinal)))
                        reason = "runs from temp path";
                    else if (cmd.Contains("(deleted)", StringComparison.Ordinal))
                        reason = "binary deleted from disk";
                    else if (KeywordMatcher.ContainsAny(cmd, SuspiciousCommandKeywords))
                        reason = "suspicious command line";
                    else if (TempPaths.Any(t => cmd.Contains(" " + t, StringComparison.Ordinal)))
                        reason = "references temp path";
                    else if (Regex.IsMatch(exe, @"^\[?k?worker.*\]?$") && exe.Contains('/') && !exe.StartsWith("["))
                        reason = "masquerades as kernel thread";

                    if (reason == null) continue;
                    if (!seen.Add(cmd)) continue;

                    flaggedPids[pid] = cmd;
                    var disp = cmd.Length > 180 ? cmd.Substring(0, 177) + "..." : cmd;
                    results.Add($"[LIVE] [HIGH] Process {reason}: user={user} PID={pid} CMD: {disp}");
                }
            }
            return results;
        }

        // ── Network ──────────────────────────────────────────────────────
        private static IEnumerable<string> AnalyzeNetwork(string root, Dictionary<string, string> flaggedPids)
        {
            var results = new List<string>();
            var seen = new HashSet<string>(StringComparer.Ordinal);

            var files = FindFiles(root, "netstat*.txt").Concat(FindFiles(root, "ss*.txt"));
            foreach (var file in files)
            {
                string[] lines;
                try { lines = File.ReadAllLines(file); } catch { continue; }

                foreach (var line in lines)
                {
                    if (!line.Contains("ESTAB", StringComparison.OrdinalIgnoreCase)) continue;
                    var parts = Regex.Split(line.Trim(), @"\s+");

                    // Collect the address:port tokens; local first, remote second
                    var addrs = parts.Select(p => AddrPort.Match(p)).Where(m => m.Success).ToList();
                    if (addrs.Count < 2) continue;
                    var remoteIp = addrs[1].Groups["ip"].Value.Trim('[', ']');
                    var remotePort = int.TryParse(addrs[1].Groups["port"].Value, out var rp) ? rp : 0;
                    var localPort = addrs[0].Groups["port"].Value;

                    // netstat -p: "1502/.x.sh"; ss -p: users:(("sshd",pid=1400,fd=4))
                    string pid = "", prog = "";
                    var np = Regex.Match(line, @"\b(?<pid>\d+)/(?<prog>\S+)");
                    var sp = Regex.Match(line, @"\(\(""(?<prog>[^""]+)"",pid=(?<pid>\d+)");
                    if (sp.Success) { pid = sp.Groups["pid"].Value; prog = sp.Groups["prog"].Value; }
                    else if (np.Success) { pid = np.Groups["pid"].Value; prog = np.Groups["prog"].Value; }

                    if (IsPrivateOrLocal(remoteIp)) continue;

                    string sev, why;
                    if (!string.IsNullOrEmpty(pid) && flaggedPids.ContainsKey(pid))
                    { sev = "HIGH"; why = "from flagged process"; }
                    else if (SuspiciousPorts.Contains(remotePort))
                    { sev = "HIGH"; why = $"to suspicious port {remotePort}"; }
                    else if (prog.StartsWith(".", StringComparison.Ordinal))
                    { sev = "HIGH"; why = "from hidden program"; }
                    else
                    { sev = "MEDIUM"; why = "to external address"; }

                    var key = $"{remoteIp}:{remotePort}|{pid}";
                    if (!seen.Add(key)) continue;

                    var who = string.IsNullOrEmpty(prog) ? "" : $" by {prog}" + (string.IsNullOrEmpty(pid) ? "" : $" (PID {pid})");
                    results.Add($"[LIVE] [{sev}] Established connection {why}: local port {localPort} ↔ {remoteIp}:{remotePort}{who}");
                }
            }
            return results;
        }

        private static IEnumerable<string> FindFiles(string root, string pattern)
        {
            try { return Directory.EnumerateFiles(root, pattern, SearchOption.AllDirectories).ToList(); }
            catch { return Array.Empty<string>(); }
        }

        internal static bool IsPrivateOrLocal(string ip)
        {
            if (!IPAddress.TryParse(ip, out var addr)) return true;
            if (IPAddress.IsLoopback(addr)) return true;
            if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                return addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal || ip.StartsWith("fc", StringComparison.OrdinalIgnoreCase)
                    || ip.StartsWith("fd", StringComparison.OrdinalIgnoreCase) || ip == "::";
            var b = addr.GetAddressBytes();
            return b[0] == 10 || b[0] == 127 || b[0] == 0
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || b[0] >= 224;
        }
    }
}

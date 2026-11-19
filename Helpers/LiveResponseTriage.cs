using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Turns UAC live_response output (and the few related top-level UAC
    /// folders: chkrootkit/, system/, [root]/etc) into findings, so a running
    /// miner, an open reverse shell, a preload rootkit or a backdoor account
    /// shows up in QuickWins instead of only in a raw dump.
    ///
    /// File names are the ones UAC 3.x writes (ps_auxwww.txt, ss_-tanp.txt,
    /// last_-a_-F.txt, chkrootkit/etc_ld_so_preload.txt …).
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

        // ps -o lstart prints "Mon Nov  2 10:23:01 2026" (five tokens) in one column
        private static readonly Regex LstartRx = new(
            @"\b[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}\b", RegexOptions.Compiled);

        // last/lastb -a -F: "root  pts/0  Mon Nov  2 10:21:40 2026 - Mon Nov  2 10:40:03 2026  (00:18)  203.0.113.45"
        private static readonly Regex LastFullRx = new(
            @"^(?<user>\S+)\s+(?<tty>.+?)\s+(?<start>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})\s*(?<rest>.*)$",
            RegexOptions.Compiled);

        // X11/ICE sockets every desktop has in /tmp
        private static readonly Regex BenignHiddenTmp = new(
            @"^/tmp/\.(?:X11|ICE|font|XIM|Test)-unix(?:/|$)|^/tmp/\.X\d+-lock$", RegexOptions.Compiled);

        private static readonly HashSet<string> LastNonUsers = new(StringComparer.OrdinalIgnoreCase)
            { "reboot", "shutdown", "runlevel", "wtmp", "btmp", "utmp" };

        private static readonly HashSet<string> LastNonHosts = new(StringComparer.OrdinalIgnoreCase)
            { "in", "running", "crash", "down", "gone", "present", "logout", "0.0.0.0", ":0", ":0.0", "-" };

        public static List<string> Analyze(string liveResponseRoot, TimeSpan? hostUtcOffset = null)
            => AnalyzeDetailed(liveResponseRoot, hostUtcOffset).Select(f => f.Finding).ToList();

        /// <summary>Findings with a short pattern label for the pattern-count table.</summary>
        public static List<(string Pattern, string Finding)> AnalyzeDetailed(string liveResponseRoot, TimeSpan? hostUtcOffset = null)
        {
            var findings = new List<(string, string)>();
            if (string.IsNullOrEmpty(liveResponseRoot) || !Directory.Exists(liveResponseRoot)) return findings;

            var baseDir = Directory.GetParent(Path.TrimEndingDirectorySeparator(liveResponseRoot))?.FullName;
            var sysRoot = FindSystemRoot(baseDir);

            var flaggedPids = new Dictionary<string, string>();   // pid -> command
            var allPids = new Dictionary<string, string>();
            Run(findings, () => AnalyzeProcesses(liveResponseRoot, flaggedPids, allPids));
            Run(findings, () => AnalyzeDeletedBinaries(liveResponseRoot, flaggedPids, allPids));
            Run(findings, () => AnalyzeNetwork(liveResponseRoot, flaggedPids));
            Run(findings, () => AnalyzeLogins(liveResponseRoot, hostUtcOffset));
            Run(findings, () => AnalyzeKernelModules(liveResponseRoot));
            Run(findings, () => AnalyzePreload(baseDir, sysRoot));
            Run(findings, () => AnalyzeAccounts(sysRoot));
            Run(findings, () => AnalyzeHiddenPaths(baseDir));
            return findings;
        }

        private static void Run(List<(string, string)> into, Func<IEnumerable<(string, string)>> check)
        {
            try { into.AddRange(check()); } catch { /* one unreadable artifact must not stop the rest */ }
        }

        // ── Processes ────────────────────────────────────────────────────
        private static IEnumerable<(string, string)> AnalyzeProcesses(string root,
            Dictionary<string, string> flaggedPids, Dictionary<string, string> allPids)
        {
            var results = new List<(string, string)>();
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

                foreach (var raw in lines.Skip(headerIdx + 1))
                {
                    if (string.IsNullOrWhiteSpace(raw)) continue;
                    var line = LstartRx.Replace(raw, "LSTART");
                    var parts = Regex.Split(line.Trim(), @"\s+", RegexOptions.None);
                    if (parts.Length <= cmdCol) continue;
                    var pid = parts[pidCol];
                    var user = userCol >= 0 ? parts[userCol] : "?";
                    var cmd = string.Join(" ", parts.Skip(cmdCol)).Trim();
                    // strip ps forest art
                    cmd = Regex.Replace(cmd, @"^[\\_| ]+", "");
                    if (!allPids.ContainsKey(pid)) allPids[pid] = cmd;

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
                    if (!seen.Add(pid + "|" + cmd)) continue;

                    flaggedPids[pid] = cmd;
                    results.Add(("Suspicious process", $"[LIVE] [HIGH] Process {reason}: user={user} PID={pid} CMD: {Trunc(cmd, 180)}"));
                }
            }
            return results;
        }

        // UAC copies the binary of every process whose /proc/<pid>/exe is
        // "(deleted)" to live_response/process/proc/<pid>/recovered_exe, and
        // deleted files held open in /dev/shm or memfd to proc/<pid>/fd/<n>/recovered_file.
        private static IEnumerable<(string, string)> AnalyzeDeletedBinaries(string root,
            Dictionary<string, string> flaggedPids, Dictionary<string, string> allPids)
        {
            var results = new List<(string, string)>();
            var procDir = Path.Combine(root, "process", "proc");
            if (!Directory.Exists(procDir)) return results;

            foreach (var pidDir in Directory.EnumerateDirectories(procDir))
            {
                var pid = Path.GetFileName(pidDir);
                if (!pid.All(char.IsDigit)) continue;
                allPids.TryGetValue(pid, out var cmd);
                var what = string.IsNullOrEmpty(cmd) ? "" : $" CMD: {Trunc(cmd, 160)}";

                if (File.Exists(Path.Combine(pidDir, "recovered_exe")))
                {
                    flaggedPids[pid] = cmd ?? "(deleted binary)";
                    results.Add(("Process running from deleted binary",
                        $"[LIVE] [HIGH] Process running from a deleted binary: PID={pid}{what} — UAC recovered it to live_response/process/proc/{pid}/recovered_exe (hash it and check it)"));
                }

                var fdDir = Path.Combine(pidDir, "fd");
                if (Directory.Exists(fdDir))
                {
                    var fds = Directory.EnumerateFiles(fdDir, "recovered_file", SearchOption.AllDirectories)
                        .Select(f => Path.GetFileName(Path.GetDirectoryName(f)!)).ToList();
                    if (fds.Count > 0)
                    {
                        flaggedPids[pid] = cmd ?? "(deleted file open)";
                        results.Add(("Deleted file held open",
                            $"[LIVE] [HIGH] Deleted file in /dev/shm or memfd held open: PID={pid} fd {string.Join(",", fds)}{what} — recovered under live_response/process/proc/{pid}/fd/"));
                    }
                }
            }
            return results;
        }

        // ── Network ──────────────────────────────────────────────────────
        private static IEnumerable<(string, string)> AnalyzeNetwork(string root, Dictionary<string, string> flaggedPids)
        {
            var results = new List<(string, string)>();
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
                    results.Add(("Suspicious connection", $"[LIVE] [{sev}] Established connection {why}: local port {localPort} ↔ {remoteIp}:{remotePort}{who}"));
                }
            }
            return results;
        }

        // ── Login history (wtmp via last, btmp via lastb) ────────────────
        // wtmp/btmp outlive auth.log rotation and are often forgotten when an
        // attacker cleans logs, so they can show logins the logs no longer do.
        private sealed class LoginAgg
        {
            public int Count;
            public DateTime First = DateTime.MaxValue, Last = DateTime.MinValue;
            public readonly SortedSet<string> Users = new(StringComparer.Ordinal);
            public void Add(string user, DateTime? t)
            {
                Count++; Users.Add(user);
                if (t is { } v) { if (v < First) First = v; if (v > Last) Last = v; }
            }
        }

        private static IEnumerable<(string, string)> AnalyzeLogins(string root, TimeSpan? offset)
        {
            var results = new List<(string, string)>();
            var ok = ReadLoginRecords(root, "last", offset);
            var failed = ReadLoginRecords(root, "lastb", offset);
            if (ok.Count == 0 && failed.Count == 0) return results;

            string Range(LoginAgg a)
            {
                if (a.First == DateTime.MaxValue) return "";
                var zone = offset.HasValue ? "UTC" : "host time";
                return a.First == a.Last ? $", at {a.First:yyyy-MM-dd HH:mm:ss} {zone}"
                    : $", {a.First:yyyy-MM-dd HH:mm:ss} → {a.Last:yyyy-MM-dd HH:mm:ss} {zone}";
            }
            string Ts(LoginAgg a) => offset.HasValue && a.First != DateTime.MaxValue ? $"[{a.First:yyyy-MM-dd HH:mm:ss} UTC] " : "";

            // Successful logins
            var internalRoot = new List<string>();
            foreach (var (host, a) in ok.OrderBy(k => k.Value.First))
            {
                var isIp = IPAddress.TryParse(host, out _);
                var rootLogin = a.Users.Contains("root");
                failed.TryGetValue(host, out var f);
                var users = string.Join(",", a.Users);

                if (f != null && f.Count >= 3)
                    results.Add(("Login after failed attempts",
                        $"[LIVE] [HIGH] {Ts(a)}Successful login from {host} after {f.Count} failed attempt(s) (wtmp/btmp): users {users}, {a.Count} session(s){Range(a)}"));
                else if (isIp && !IsPrivateOrLocal(host))
                    results.Add((rootLogin ? "Root login from external IP" : "Login from external IP",
                        $"[LIVE] [{(rootLogin ? "HIGH" : "MEDIUM")}] {Ts(a)}Login(s) from external IP {host} in wtmp: users {users}, {a.Count} session(s){Range(a)}"));
                else if (rootLogin)
                    internalRoot.Add(host);
            }
            if (internalRoot.Count > 0)
                results.Add(("Direct root login", $"[LIVE] [LOW] Direct root login(s) in wtmp from internal host(s): {string.Join(", ", internalRoot.Take(15))}"));

            // Failed logins: one line per noisy source
            foreach (var (host, f) in failed.Where(k => k.Value.Count >= 10).OrderByDescending(k => k.Value.Count).Take(10))
            {
                var users = string.Join(",", f.Users.Take(8)) + (f.Users.Count > 8 ? $" (+{f.Users.Count - 8} more)" : "");
                results.Add(("Failed logins (btmp)",
                    $"[LIVE] [MEDIUM] {Ts(f)}{f.Count} failed login(s) in btmp from {host}: users {users}{Range(f)}"));
            }
            return results;
        }

        /// <summary>
        /// Reads every last/lastb output UAC wrote (current and rotated
        /// wtmp/btmp files) and groups the records by source host.
        /// Prefers "-a -F" output (full date, host last); falls back to "-i".
        /// </summary>
        private static Dictionary<string, LoginAgg> ReadLoginRecords(string root, string tool, TimeSpan? offset)
        {
            var byHost = new Dictionary<string, LoginAgg>(StringComparer.OrdinalIgnoreCase);
            var full = FindFiles(root, tool + "_-a_-F*.txt").ToList();
            var seenLines = new HashSet<string>(StringComparer.Ordinal);

            if (full.Count > 0)
            {
                foreach (var file in full)
                foreach (var line in SafeLines(file))
                {
                    var m = LastFullRx.Match(line.Trim());
                    if (!m.Success || !seenLines.Add(line.Trim())) continue;
                    var user = m.Groups["user"].Value;
                    if (LastNonUsers.Contains(user)) continue;
                    var rest = m.Groups["rest"].Value.Trim();
                    var host = rest.Length == 0 ? "" : Regex.Split(rest, @"\s+").Last();
                    if (host.Length == 0 || host.StartsWith("(") || LastNonHosts.Contains(host)) continue;
                    if (Regex.IsMatch(host, @"^\d{4}$")) continue;   // lastb without a host ends in the year

                    DateTime? t = null;
                    var startText = Regex.Replace(m.Groups["start"].Value, @"\s+", " ");
                    if (DateTime.TryParseExact(startText, "ddd MMM d HH:mm:ss yyyy", CultureInfo.InvariantCulture,
                            DateTimeStyles.AllowWhiteSpaces, out var local))
                        t = offset.HasValue ? local - offset.Value : local;

                    Agg(byHost, host).Add(user, t);
                }
                return byHost;
            }

            // "last -i": user tty ip  Mon Nov  2 10:21 - 10:40  (00:18)   (no year)
            var ipFile = FindFiles(root, tool + "_-i.txt").FirstOrDefault();
            if (ipFile == null) return byHost;
            foreach (var line in SafeLines(ipFile))
            {
                if (!seenLines.Add(line.Trim())) continue;
                var parts = Regex.Split(line.Trim(), @"\s+");
                if (parts.Length < 4 || LastNonUsers.Contains(parts[0])) continue;
                var host = parts[2];
                if (!IPAddress.TryParse(host, out _) || LastNonHosts.Contains(host)) continue;
                Agg(byHost, host).Add(parts[0], null);
            }
            return byHost;
        }

        private static LoginAgg Agg(Dictionary<string, LoginAgg> d, string host)
        {
            if (!d.TryGetValue(host, out var a)) d[host] = a = new LoginAgg();
            return a;
        }

        // ── Kernel modules ───────────────────────────────────────────────
        // Some LKM rootkits remove themselves from /proc/modules; an empty
        // list on a normal Linux host is worth a look.
        private static IEnumerable<(string, string)> AnalyzeKernelModules(string root)
        {
            var path = FindFiles(root, "lsmod.txt").FirstOrDefault();
            if (path == null) yield break;
            var count = SafeLines(path).Count(l => !string.IsNullOrWhiteSpace(l)
                && !l.TrimStart().StartsWith("Module", StringComparison.OrdinalIgnoreCase));
            if (count == 0)
                yield return ("Empty kernel module list",
                    "[LIVE] [SUSPICIOUS] lsmod.txt lists no kernel modules — rule out a module-hiding rootkit");
        }

        // ── /etc/ld.so.preload ───────────────────────────────────────────
        // Any entry forces that library into every dynamically linked
        // process: the classic userland rootkit (libprocesshider, Azazel…).
        // UAC reads the file twice: as a normal copy ([root]/etc) and raw from
        // the disk with debugfs/xfs_db (chkrootkit/etc_ld_so_preload.txt),
        // which a hooking rootkit can't hide.
        private static IEnumerable<(string, string)> AnalyzePreload(string? baseDir, string? sysRoot)
        {
            var results = new List<(string, string)>();
            var raw = baseDir == null ? null : Path.Combine(baseDir, "chkrootkit", "etc_ld_so_preload.txt");
            var copy = sysRoot == null ? null : Path.Combine(sysRoot, "etc", "ld.so.preload");

            var rawEntries = PreloadEntries(raw);
            var copyEntries = PreloadEntries(copy);
            var all = rawEntries.Concat(copyEntries).Distinct(StringComparer.Ordinal).ToList();
            if (all.Count == 0) return results;

            var hidden = rawEntries.Count > 0 && copyEntries.Count == 0
                ? " Only the raw disk read shows it — the normal file read came back empty or missing, so something is hiding it."
                : "";
            results.Add(("ld.so.preload rootkit",
                $"[LIVE] [CRITICAL] /etc/ld.so.preload is not empty — loaded into every process: {string.Join(", ", all.Take(10))}.{hidden}"));
            return results;
        }

        private static List<string> PreloadEntries(string? path)
        {
            if (path == null || !File.Exists(path)) return new List<string>();
            return SafeLines(path)
                .Select(l => l.Trim())
                .Where(l => l.Length > 0 && !l.StartsWith("#")
                            && !l.StartsWith("debugfs", StringComparison.OrdinalIgnoreCase)
                            && (l.StartsWith("/") || l.Contains(".so")))
                .ToList();
        }

        // ── Accounts ([root]/etc/passwd, sudoers) ────────────────────────
        // UAC excludes /etc/shadow, so passwd and sudoers are what's there.
        private static IEnumerable<(string, string)> AnalyzeAccounts(string? sysRoot)
        {
            var results = new List<(string, string)>();
            if (sysRoot == null) return results;
            var etc = Path.Combine(sysRoot, "etc");

            var passwd = Path.Combine(etc, "passwd");
            if (File.Exists(passwd))
            {
                foreach (var line in SafeLines(passwd))
                {
                    if (line.StartsWith("#")) continue;
                    var f = line.Split(':');
                    if (f.Length < 7) continue;
                    var (name, pw, uid, shell) = (f[0], f[1], f[2], f[6]);
                    if (uid == "0" && name != "root")
                        results.Add(("UID 0 account", $"[LIVE] [HIGH] Account '{name}' has UID 0 (root-equivalent) in /etc/passwd: {line.Trim()}"));
                    if (pw.Length == 0)
                        results.Add(("Passwordless account", $"[LIVE] [HIGH] Account '{name}' has an empty password field in /etc/passwd — login without a password (shell {shell})"));
                }
            }

            var sudoFiles = new List<string>();
            var sudoers = Path.Combine(etc, "sudoers");
            if (File.Exists(sudoers)) sudoFiles.Add(sudoers);
            var sudoD = Path.Combine(etc, "sudoers.d");
            if (Directory.Exists(sudoD)) sudoFiles.AddRange(Directory.EnumerateFiles(sudoD));
            foreach (var file in sudoFiles)
            {
                var rel = "/etc/" + Path.GetRelativePath(etc, file).Replace('\\', '/');
                foreach (var line in SafeLines(file))
                {
                    var t = line.Trim();
                    if (t.StartsWith("#") || t.StartsWith("Defaults")) continue;
                    if (Regex.IsMatch(t, @"NOPASSWD\s*:\s*ALL\b"))
                        results.Add(("Sudo NOPASSWD:ALL", $"[LIVE] [MEDIUM] Passwordless full sudo in {rel}: {t}"));
                }
            }
            return results;
        }

        // ── Hidden files outside home folders (UAC system/hidden_*.txt) ──
        private static IEnumerable<(string, string)> AnalyzeHiddenPaths(string? baseDir)
        {
            var results = new List<(string, string)>();
            if (baseDir == null) return results;
            foreach (var (file, label) in new[] { ("hidden_files.txt", "file"), ("hidden_directories.txt", "directory") })
            {
                var path = Path.Combine(baseDir, "system", file);
                if (!File.Exists(path)) continue;
                var staged = SafeLines(path)
                    .Select(l => l.Trim())
                    .Where(l => TempPaths.Any(t => l.StartsWith(t, StringComparison.Ordinal)) && !BenignHiddenTmp.IsMatch(l))
                    .Distinct(StringComparer.Ordinal)
                    .ToList();
                if (staged.Count == 0) continue;
                var sample = string.Join(", ", staged.Take(10)) + (staged.Count > 10 ? $" (+{staged.Count - 10} more)" : "");
                results.Add(("Hidden file in temp folder",
                    $"[LIVE] [SUSPICIOUS] {staged.Count} hidden {label}(s) in /tmp, /dev/shm or /var/tmp: {sample}"));
            }
            return results;
        }

        // ── Helpers ──────────────────────────────────────────────────────
        /// <summary>The collected file system: "[root]", or "root" when the archive extractor stripped the brackets.</summary>
        internal static string? FindSystemRoot(string? baseDir)
        {
            if (baseDir == null) return null;
            foreach (var name in new[] { "[root]", "root" })
            {
                var p = Path.Combine(baseDir, name);
                if (Directory.Exists(p)) return p;
            }
            return null;
        }

        private static IEnumerable<string> FindFiles(string root, string pattern)
        {
            try { return Directory.EnumerateFiles(root, pattern, SearchOption.AllDirectories).ToList(); }
            catch { return Array.Empty<string>(); }
        }

        private static IEnumerable<string> SafeLines(string path)
        {
            try { return File.ReadAllLines(path); }
            catch { return Array.Empty<string>(); }
        }

        private static string Trunc(string s, int max) => s.Length > max ? s.Substring(0, max - 3) + "..." : s;

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

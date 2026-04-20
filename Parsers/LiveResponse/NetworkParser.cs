using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Parser.Parsers.LiveResponse
{
    /// <summary>
    /// Parses network-related artifacts under live_response/network.
    /// Expected files (any subset): ss.txt, ss-anp.txt, netstat.txt, netstat-anp.txt,
    /// ip_a.txt, ip_addr.txt, ifconfig.txt, ip_route.txt, route.txt, ip_r.txt,
    /// resolv.conf (or variants), hosts (or variants), iptables.txt, iptables-save.txt,
    /// nft_list_ruleset.txt.
    ///
    /// Produces concise, DFIR-ready summaries (listening ports, external connections,
    /// DNS settings, routes, and basic firewall rules presence).
    /// </summary>
    public class NetworkParser
    {
        private readonly string root;

        public NetworkParser(string networkRoot)
        {
            root = networkRoot;
        }

        public List<string> Process()
        {
            var findings = new List<string>();

            if (!Directory.Exists(root))
            {
                findings.Add($"[Network] Missing folder: {root}");
                return findings;
            }

            try
            {
                // ---- sockets: LISTEN + ESTABLISHED
                var sockCandidates = new[]
                {
                    "ss-anp.txt","ss.txt",
                    "netstat-anp.txt","netstat.txt"
                };
                var sockPath = FirstExisting(sockCandidates);
                if (sockPath != null)
                    SummarizeSockets(sockPath, findings);
                else
                    findings.Add("[Network] No ss/netstat output found.");

                // ---- interfaces
                var ipAPath = FirstExisting(new[] { "ip_a.txt", "ip_addr.txt", "ifconfig.txt" });
                if (ipAPath != null)
                    SummarizeInterfaces(ipAPath, findings);

                // ---- routes
                var routePath = FirstExisting(new[] { "ip_route.txt", "ip_r.txt", "route.txt" });
                if (routePath != null)
                    SummarizeRoutes(routePath, findings);

                // ---- DNS
                var resolvPath = FirstExisting(new[] { "resolv.conf", "resolv_conf.txt", "etc_resolv.conf.txt" });
                if (resolvPath != null)
                    SummarizeResolvConf(resolvPath, findings);

                // ---- hosts
                var hostsPath = FirstExisting(new[] { "hosts", "hosts.txt", "etc_hosts.txt" });
                if (hostsPath != null)
                    SummarizeHosts(hostsPath, findings);

                // ---- firewall rules presence
                var iptPath = FirstExisting(new[] { "iptables-save.txt", "iptables.txt" });
                var nftPath = FirstExisting(new[] { "nft_list_ruleset.txt", "nft.txt" });
                SummarizeFirewall(iptPath, nftPath, findings);
            }
            catch (Exception ex)
            {
                findings.Add($"[Network] Error while processing: {ex.Message}");
            }

            if (findings.Count == 0)
                findings.Add("[Network] No recognizable files found.");

            return findings;
        }

        private string FirstExisting(IEnumerable<string> candidates)
        {
            foreach (var name in candidates)
            {
                var p = Path.Combine(root, name);
                if (File.Exists(p)) return p;
            }
            return null;
        }

        // -------------------- Parsers / Summaries --------------------

        private void SummarizeSockets(string path, List<string> findings)
        {
            var lines = SafeReadAllLines(path);
            if (lines.Count == 0)
            {
                findings.Add($"[Network] {Path.GetFileName(path)} is empty.");
                return;
            }

            // Heuristics for parsing ss/netstat outputs
            // Examples:
            //   tcp   LISTEN 0 128 0.0.0.0:22     0.0.0.0:*    users:(("sshd",pid=671,fd=3))
            //   tcp   ESTAB  0     0 10.0.0.5:22  203.0.113.9:52344 users:(("sshd",pid=1023,fd=12))
            //   udp   UNCONN 0   0  127.0.0.53%lo:53  0.0.0.0:*  ...
            //   (netstat) tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd
            //
            // We’ll capture protocol, state, local addr:port, peer addr:port and proc if present.

            var listen = new List<SocketRow>();
            var estab = new List<SocketRow>();

            var reUsers = new Regex(@"users:\(\(([^""]+?)"",?pid=(\d+)", RegexOptions.Compiled);
            var reProcTail = new Regex(@"\s(\d+)/(.*)$", RegexOptions.Compiled); // netstat tail: "1234/sshd"
            var reSplit = new Regex(@"\s+", RegexOptions.Compiled);

            foreach (var raw in lines)
            {
                var line = raw.Trim();
                if (string.IsNullOrEmpty(line)) continue;
                if (line.StartsWith("Netid") || line.StartsWith("Proto")) continue; // headers

                var parts = reSplit.Split(line).Where(p => p.Length > 0).ToList();
                if (parts.Count < 5) continue;

                // Try to detect layout based on token positions
                string proto = parts[0];
                string state = null;
                string local = null;
                string peer = null;
                string proc = null;

                if (line.Contains("LISTEN") || line.Contains("ESTAB") || line.Contains("ESTABLISHED"))
                {
                    // ss layout often: proto state ... local peer ...
                    // Try to find tokens that look like ip:port
                    // We'll scan left->right for first token containing ':' as local, next ':' as peer
                    var idxLocal = parts.FindIndex(p => p.Contains(":"));
                    if (idxLocal >= 0)
                    {
                        local = parts[idxLocal];
                        var idxPeer = parts.FindIndex(idxLocal + 1, p => p.Contains(":") || p == "*" || p.EndsWith(":*"));
                        if (idxPeer > idxLocal)
                            peer = parts[idxPeer];
                    }
                    // state: best-effort from list
                    var knownStates = new[] { "LISTEN", "ESTAB", "ESTABLISHED", "UNCONN", "CLOSE-WAIT", "TIME-WAIT" };
                    state = parts.FirstOrDefault(p => knownStates.Contains(p)) ?? "UNKNOWN";

                    // process name via users:(...) or trailing "pid/name"
                    var mUsers = reUsers.Match(line);
                    if (mUsers.Success)
                        proc = $"{mUsers.Groups[1].Value}/{mUsers.Groups[2].Value}";
                    else
                    {
                        var mTail = reProcTail.Match(line);
                        if (mTail.Success)
                            proc = $"{mTail.Groups[2].Value}/{mTail.Groups[1].Value}";
                    }
                }
                else
                {
                    // netstat LISTEN at the end
                    var idxListen = parts.FindIndex(p => p.Equals("LISTEN", StringComparison.OrdinalIgnoreCase));
                    if (idxListen >= 0)
                    {
                        state = "LISTEN";
                        // heuristic: local usually at index ~3 or token before "LISTEN" -3 .. -1
                        local = parts.ElementAtOrDefault(idxListen - 3) ?? parts.ElementAtOrDefault(3);
                        peer = parts.ElementAtOrDefault(idxListen - 2) ?? parts.ElementAtOrDefault(4);

                        var mTail = reProcTail.Match(line);
                        if (mTail.Success)
                            proc = $"{mTail.Groups[2].Value}/{mTail.Groups[1].Value}";
                    }
                }

                var row = new SocketRow
                {
                    Proto = proto,
                    State = state ?? "UNKNOWN",
                    Local = local ?? "",
                    Peer = peer ?? "",
                    Process = proc ?? ""
                };

                if (row.State.StartsWith("LISTEN", StringComparison.OrdinalIgnoreCase))
                    listen.Add(row);
                else if (row.State.StartsWith("ESTAB", StringComparison.OrdinalIgnoreCase) ||
                         row.State.Equals("ESTABLISHED", StringComparison.OrdinalIgnoreCase))
                    estab.Add(row);
            }

            // Summaries
            findings.Add($"[Network] Sockets from {Path.GetFileName(path)}:");
            if (listen.Count > 0)
            {
                findings.Add($"    Listening: {listen.Count} (top 10)");
                foreach (var r in listen
                    .OrderBy(r => r.LocalPortNumeric)
                    .ThenBy(r => r.Proto)
                    .Take(10))
                {
                    findings.Add($"      {r.Proto} {r.Local,-22} proc={ShortProc(r.Process)}");
                }

                // quick risk: unusual high ports commonly abused
                var suspiciousPorts = new HashSet<int> { 22, 23, 80, 443, 445, 3389, 8000, 8080, 8443, 3333, 5555, 6666, 7777, 14444, 18080 };
                var sus = listen.Where(r => r.LocalPortNumeric.HasValue && suspiciousPorts.Contains(r.LocalPortNumeric.Value)).ToList();
                if (sus.Count > 0)
                    findings.Add($"    ⚠️ Notable listening ports: {string.Join(", ", sus.Select(s => s.Local))}");
            }
            else
            {
                findings.Add("    No LISTEN sockets parsed.");
            }

            if (estab.Count > 0)
            {
                findings.Add($"    Established: {estab.Count} (top 10)");
                foreach (var r in estab.Take(10))
                {
                    findings.Add($"      {r.Proto} {r.Local,-22} -> {r.Peer,-22} proc={ShortProc(r.Process)}");
                }

                // flag public remote IPs (very rough heuristic)
                var publicConns = estab.Where(r => IsPublicRemote(r.Peer)).Take(10).ToList();
                if (publicConns.Count > 0)
                    findings.Add($"    ⚠️ External connections (sample): {string.Join("; ", publicConns.Select(c => $"{c.Peer} ({ShortProc(c.Process)})"))}");
            }
            else
            {
                findings.Add("    No ESTABLISHED sockets parsed.");
            }
        }

        private void SummarizeInterfaces(string path, List<string> findings)
        {
            var lines = SafeReadAllLines(path);
            if (lines.Count == 0) return;

            // Simple extraction for interface names and IPv4/IPv6 addresses from ip addr/ifconfig
            var reIf = new Regex(@"^\d+:\s*([A-Za-z0-9\-\._]+):|^([A-Za-z0-9\-\._]+): flags=", RegexOptions.Compiled);
            var reIPv4 = new Regex(@"\b(?<![:\d])((25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(?!$)|$)){4}\b", RegexOptions.Compiled);
            var reIPv6 = new Regex(@"\b[0-9a-fA-F:]{2,}:[0-9a-fA-F:]+\b", RegexOptions.Compiled);

            var currentIf = "unknown";
            var entries = new List<string>();

            foreach (var line in lines)
            {
                var mIf = reIf.Match(line);
                if (mIf.Success)
                {
                    currentIf = !string.IsNullOrEmpty(mIf.Groups[1].Value) ? mIf.Groups[1].Value : mIf.Groups[2].Value;
                }

                foreach (Match m in reIPv4.Matches(line))
                    entries.Add($"{currentIf} IPv4 {m.Value}");
                foreach (Match m in reIPv6.Matches(line))
                    entries.Add($"{currentIf} IPv6 {m.Value}");
            }

            if (entries.Count > 0)
            {
                findings.Add($"[Network] Interfaces from {Path.GetFileName(path)} (sample up to 10):");
                foreach (var r in entries.Distinct().Take(10))
                    findings.Add($"    {r}");
            }
        }

        private void SummarizeRoutes(string path, List<string> findings)
        {
            var lines = SafeReadAllLines(path);
            if (lines.Count == 0) return;

            // Look for default routes and gateways
            var defaults = lines.Where(l => l.Contains("default ") || l.StartsWith("default ") || l.Contains("0.0.0.0")).Take(5).ToList();
            if (defaults.Count > 0)
            {
                findings.Add($"[Network] Routes from {Path.GetFileName(path)} (default routes):");
                foreach (var d in defaults)
                    findings.Add($"    {d.Trim()}");
            }
        }

        private void SummarizeResolvConf(string path, List<string> findings)
        {
            var lines = SafeReadAllLines(path);
            var dns = lines
                .Where(l => l.TrimStart().StartsWith("nameserver", StringComparison.OrdinalIgnoreCase))
                .Select(l => l.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).LastOrDefault())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct()
                .ToList();

            var search = lines
                .Where(l => l.TrimStart().StartsWith("search", StringComparison.OrdinalIgnoreCase))
                .Select(l => l.Trim())
                .ToList();

            if (dns.Count > 0)
                findings.Add($"[Network] DNS servers: {string.Join(", ", dns)}");
            if (search.Count > 0)
                findings.Add($"[Network] DNS search: {string.Join(" | ", search)}");

            // quick warning: unusual resolvers (public or RFC1918 from suspicious ranges) – heuristic only
            var notable = new HashSet<string> { "8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9" };
            var hit = dns.Where(d => notable.Contains(d)).ToList();
            if (hit.Count > 0)
                findings.Add($"    ⚠️ Uses public DNS resolvers: {string.Join(", ", hit)}");
        }

        private void SummarizeHosts(string path, List<string> findings)
        {
            var lines = SafeReadAllLines(path);
            var overrides = lines
                .Where(l => !l.TrimStart().StartsWith("#") && Regex.IsMatch(l, @"\b\d{1,3}(\.\d{1,3}){3}\b"))
                .Take(10)
                .ToList();

            if (overrides.Count > 0)
            {
                findings.Add($"[Network] Hosts overrides (sample):");
                foreach (var o in overrides)
                    findings.Add($"    {o.Trim()}");
            }
        }

        private void SummarizeFirewall(string iptablesPath, string nftPath, List<string> findings)
        {
            if (iptablesPath == null && nftPath == null)
            {
                findings.Add("[Network] No firewall dump (iptables/nft) found.");
                return;
            }

            if (iptablesPath != null)
            {
                var l = SafeReadAllLines(iptablesPath);
                var chains = l.Count(x => x.TrimStart().StartsWith(":", StringComparison.Ordinal));
                var rules = l.Count(x => x.TrimStart().StartsWith("-A", StringComparison.Ordinal));
                findings.Add($"[Network] iptables-save present: {chains} chains, {rules} rules (approx).");
            }

            if (nftPath != null)
            {
                var l = SafeReadAllLines(nftPath);
                // very rough approximations
                var tables = l.Count(x => x.TrimStart().StartsWith("table", StringComparison.OrdinalIgnoreCase));
                var chains = l.Count(x => x.TrimStart().StartsWith("chain", StringComparison.OrdinalIgnoreCase));
                findings.Add($"[Network] nftables present: {tables} tables, {chains} chains (approx).");
            }
        }

        // -------------------- helpers --------------------

        private List<string> SafeReadAllLines(string path)
        {
            try
            {
                return File.ReadAllLines(path).ToList();
            }
            catch
            {
                return new List<string>();
            }
        }

        private bool IsPublicRemote(string peer)
        {
            if (string.IsNullOrWhiteSpace(peer)) return false;
            // peer often like "203.0.113.9:52344"
            var host = peer.Split('%')[0]; // drop scope id if present
            var colon = host.LastIndexOf(':');
            if (colon >= 0) host = host.Substring(0, colon);

            if (IPAddressTryParse(host, out var octets))
            {
                // RFC1918 + loopback + link-local checks
                var (a, b) = (octets[0], octets[1]);
                if (a == 10) return false;
                if (a == 172 && b >= 16 && b <= 31) return false;
                if (a == 192 && b == 168) return false;
                if (a == 127) return false;
                if (a == 169 && b == 254) return false;
                return true;
            }
            // If not IPv4-looking, treat as possibly public (IPv6 or hostname)
            return true;
        }

        private bool IPAddressTryParse(string s, out byte[] octets)
        {
            octets = null;
            var parts = s.Split('.');
            if (parts.Length != 4) return false;
            var tmp = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                if (!int.TryParse(parts[i], out var n) || n < 0 || n > 255) return false;
                tmp[i] = (byte)n;
            }
            octets = tmp;
            return true;
        }

        private string ShortProc(string proc)
        {
            if (string.IsNullOrWhiteSpace(proc)) return "-";
            // forms like "sshd/1023" or "sshd, pid=1023"
            var slash = proc.IndexOf('/');
            if (slash > 0) return proc.Substring(0, slash);
            var comma = proc.IndexOf(',');
            if (comma > 0) return proc.Substring(0, comma);
            return proc.Length > 20 ? proc.Substring(0, 20) + "…" : proc;
        }

        private class SocketRow
        {
            public string Proto { get; set; }
            public string State { get; set; }
            public string Local { get; set; }
            public string Peer { get; set; }
            public string Process { get; set; }

            public int? LocalPortNumeric
            {
                get
                {
                    if (string.IsNullOrEmpty(Local)) return null;
                    var idx = Local.LastIndexOf(':');
                    if (idx < 0 || idx == Local.Length - 1) return null;
                    if (int.TryParse(Local.Substring(idx + 1), out var p)) return p;
                    return null;
                }
            }
        }
    }
}

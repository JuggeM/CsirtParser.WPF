using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Resolves the collected host's own IP addresses from UAC artifacts, so the
    /// analyst sees which machine a QuickWins report is about and can link the
    /// host to IPs seen in other hosts' logs (lateral movement).
    ///
    /// Sources, first one that yields addresses wins:
    ///   1. live_response/**/ip_*addr*.txt, ip_a*.txt   (`ip addr show`)
    ///   2. live_response/**/ifconfig*.txt                 (`ifconfig -a`, old and new format)
    ///   3. live_response/**/hostname_-I.txt               (`hostname -I`)
    ///   4. [root]/etc: netplan, network/interfaces, sysconfig ifcfg-*  (configured, not live)
    /// Loopback and IPv6 link-local addresses are left out.
    /// </summary>
    public static class HostIpResolver
    {
        public sealed record HostIp(string Address, string Interface, string Source)
        {
            public override string ToString() =>
                string.IsNullOrEmpty(Interface) ? Address : $"{Address} ({Interface})";
        }

        private static readonly Regex IpIfaceHeader = new(@"^\d+:\s+(?<if>[^:@\s]+)[@:]", RegexOptions.Compiled);
        private static readonly Regex IpInet = new(@"^\s*inet6?\s+(?<ip>[0-9a-fA-F:.]+)(?:/\d+)?(?:.*\s(?<label>[A-Za-z0-9_.:\-]+)$)?", RegexOptions.Compiled);
        private static readonly Regex IfcfgHeader = new(@"^(?<if>[A-Za-z0-9_.:\-]+)(?::\s+flags=|\s+Link encap)", RegexOptions.Compiled);
        private static readonly Regex IfcfgInet = new(@"^\s*inet6?\s+(?:addr:\s*)?(?<ip>[0-9a-fA-F:.]+)", RegexOptions.Compiled);

        public static List<HostIp> Resolve(string rootPath)
        {
            var result = new List<HostIp>();
            if (string.IsNullOrWhiteSpace(rootPath) || !Directory.Exists(rootPath)) return result;

            var lr = SafeDirs(rootPath, "live_response").FirstOrDefault();
            if (lr != null)
            {
                foreach (var f in SafeFiles(lr, "ip_*addr*.txt").Concat(SafeFiles(lr, "ip_a*.txt")).Distinct())
                    AddRange(result, FromIpAddr(f));
                if (result.Count == 0)
                    foreach (var f in SafeFiles(lr, "ifconfig*.txt"))
                        AddRange(result, FromIfconfig(f));
                if (result.Count == 0)
                    foreach (var f in SafeFiles(lr, "hostname_-I*.txt"))
                        AddRange(result, FromHostnameI(f));
            }

            if (result.Count == 0)
                AddRange(result, FromConfigFiles(rootPath));

            return result;
        }

        // ── `ip addr show` ───────────────────────────────────────────────
        internal static IEnumerable<HostIp> FromIpAddr(string path)
        {
            string iface = "";
            foreach (var line in SafeRead(path))
            {
                var h = IpIfaceHeader.Match(line);
                if (h.Success) { iface = h.Groups["if"].Value; continue; }
                var m = IpInet.Match(line);
                if (!m.Success) continue;
                var label = m.Groups["label"].Success && !m.Groups["label"].Value.Contains("lft") ? m.Groups["label"].Value : iface;
                // "scope global dynamic eth0" → label is eth0; "scope link" lines end in "link"
                if (label is "global" or "link" or "host" or "dynamic" or "noprefixroute" or "secondary" or "mngtmpaddr" or "temporary") label = iface;
                yield return new HostIp(m.Groups["ip"].Value, label, "ip addr");
            }
        }

        // ── `ifconfig -a` (net-tools new and old format) ─────────────────
        internal static IEnumerable<HostIp> FromIfconfig(string path)
        {
            string iface = "";
            foreach (var line in SafeRead(path))
            {
                var h = IfcfgHeader.Match(line);
                if (h.Success) { iface = h.Groups["if"].Value; continue; }
                var m = IfcfgInet.Match(line);
                if (m.Success) yield return new HostIp(m.Groups["ip"].Value, iface, "ifconfig");
            }
        }

        // ── `hostname -I` ────────────────────────────────────────────────
        internal static IEnumerable<HostIp> FromHostnameI(string path)
        {
            foreach (var line in SafeRead(path))
                foreach (var tok in line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                    yield return new HostIp(tok, "", "hostname -I");
        }

        // ── Configured addresses in the collected filesystem ─────────────
        private static IEnumerable<HostIp> FromConfigFiles(string rootPath)
        {
            var etc = SafeDirs(rootPath, "etc").FirstOrDefault(d =>
                Path.GetFileName(Path.GetDirectoryName(d) ?? "").Contains("root", StringComparison.OrdinalIgnoreCase));
            if (etc == null) yield break;

            foreach (var f in SafeFiles(Path.Combine(etc, "netplan"), "*.yaml"))
                foreach (var line in SafeRead(f))
                    foreach (Match m in Regex.Matches(line, @"(?<ip>\d{1,3}(?:\.\d{1,3}){3})/\d+"))
                        yield return new HostIp(m.Groups["ip"].Value, "", "netplan (configured)");

            var ifaces = Path.Combine(etc, "network", "interfaces");
            string cur = "";
            foreach (var line in SafeRead(ifaces))
            {
                var i = Regex.Match(line, @"^\s*iface\s+(?<if>\S+)");
                if (i.Success) cur = i.Groups["if"].Value;
                var a = Regex.Match(line, @"^\s*address\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3})");
                if (a.Success) yield return new HostIp(a.Groups["ip"].Value, cur, "interfaces (configured)");
            }

            foreach (var f in SafeFiles(Path.Combine(etc, "sysconfig", "network-scripts"), "ifcfg-*"))
                foreach (var line in SafeRead(f))
                {
                    var a = Regex.Match(line, @"^\s*IPADDR\d*\s*=\s*""?(?<ip>\d{1,3}(?:\.\d{1,3}){3})");
                    if (a.Success) yield return new HostIp(a.Groups["ip"].Value, Path.GetFileName(f).Substring(6), "ifcfg (configured)");
                }
        }

        // ── Helpers ──────────────────────────────────────────────────────
        private static void AddRange(List<HostIp> list, IEnumerable<HostIp> items)
        {
            foreach (var ip in items)
            {
                if (!IPAddress.TryParse(ip.Address, out var addr)) continue;
                if (IPAddress.IsLoopback(addr) || addr.IsIPv6LinkLocal) continue;
                if (addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any)) continue;
                if (list.Any(x => x.Address == ip.Address)) continue;
                list.Add(ip);
            }
        }

        private static IEnumerable<string> SafeRead(string path)
        {
            try { return File.Exists(path) ? File.ReadAllLines(path) : Array.Empty<string>(); }
            catch { return Array.Empty<string>(); }
        }

        private static IEnumerable<string> SafeFiles(string dir, string pattern)
        {
            try { return Directory.Exists(dir) ? Directory.EnumerateFiles(dir, pattern, SearchOption.AllDirectories).ToList() : Enumerable.Empty<string>(); }
            catch { return Enumerable.Empty<string>(); }
        }

        private static IEnumerable<string> SafeDirs(string root, string name)
        {
            try { return Directory.EnumerateDirectories(root, name, SearchOption.AllDirectories).ToList(); }
            catch { return Enumerable.Empty<string>(); }
        }
    }
}

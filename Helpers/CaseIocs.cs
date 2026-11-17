using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>One analyst-supplied indicator.</summary>
    public sealed record CaseIoc(string Kind, string Value, string Comment)
    {
        /// <summary>Line as stored in iocs.txt; kinds that can't be inferred keep their prefix.</summary>
        public string ToLine()
        {
            var v = Kind switch { "User" => "user:" + Value, "File" when !Value.StartsWith("/") => "file:" + Value, _ => Value };
            return string.IsNullOrWhiteSpace(Comment) ? v : $"{v,-45}  # {Comment}";
        }
    }

    /// <summary>
    /// The case IOC list (&lt;case&gt;\iocs.txt): parsing of pasted or imported
    /// text, re-fanging, type detection, and load/save.
    ///
    /// Input is forgiving: one or more IOCs per line, separated by whitespace,
    /// comma or semicolon; text after " #" is a comment for every IOC on that
    /// line. Defanged forms (hxxp, [.], (dot), [:], [@]) are re-fanged. Kinds
    /// that can't be told from the value need a prefix: user:alice, file:x.sh.
    /// A line that yields no IOC at all is reported as rejected; unrecognised
    /// tokens on a line that did yield one (CSV columns, words) are ignored.
    /// </summary>
    public static class CaseIocs
    {
        public const string FileName = "iocs.txt";
        public const string DiscoveredFileName = "iocs_discovered.txt";

        public static readonly string[] KindOrder =
            { "IP", "CIDR", "Domain", "URL", "Email", "MD5", "SHA1", "SHA256", "File", "User" };

        private static readonly Regex Hex = new(@"^[0-9a-fA-F]+$", RegexOptions.Compiled);
        private static readonly Regex Ipv4 = new(@"^\d{1,3}(?:\.\d{1,3}){3}$", RegexOptions.Compiled);
        private static readonly Regex DomainRx = new(
            @"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$",
            RegexOptions.Compiled);
        private static readonly Regex EmailRx = new(
            @"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", RegexOptions.Compiled);
        private static readonly Regex UrlRx = new(@"^(?:https?|ftp)://[^\s/$.?#][^\s]*$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // "x.sh", "img.php": file names, not domains (use file:x.sh for those)
        private static readonly HashSet<string> FileExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            "sh", "php", "py", "txt", "log", "conf", "so", "exe", "dll", "js", "html", "htm", "jsp",
            "asp", "aspx", "gz", "tar", "tgz", "json", "xml", "yml", "yaml", "bak", "ps1", "bat",
            "elf", "bin", "tmp", "csv", "ini", "cfg", "phtml", "pyc", "jar", "war", "zip", "out"
        };

        // ── Re-fang ──────────────────────────────────────────────────────
        public static string Refang(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            s = Regex.Replace(s, @"^h(?:xx|XX|\*\*|tt)p(s?)(?=\[?:)", "http$1", RegexOptions.IgnoreCase);
            s = Regex.Replace(s, @"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}|\\\.",
                ".", RegexOptions.IgnoreCase);
            s = Regex.Replace(s, @"\[\s*:\s*\]|\[:\/\/\]", m => m.Value.Contains("//") ? "://" : ":");
            s = Regex.Replace(s, @"\[\s*(?:@|at)\s*\]|\(\s*(?:@|at)\s*\)", "@", RegexOptions.IgnoreCase);
            return s;
        }

        // ── Classify one token ───────────────────────────────────────────
        /// <summary>Returns the IOC for a token, or null when it isn't one.</summary>
        public static CaseIoc? Classify(string token, string comment = "")
        {
            var t = Refang((token ?? "").Trim().Trim('"', '\'', '<', '>', '(', ')', '[', ']', '`'));
            t = t.TrimEnd(',', ';', '.');
            if (t.Length < 3) return null;

            // Explicit prefix: user:, file:, ip:, domain:, url:, hash:, md5:, sha1:, sha256:
            var pm = Regex.Match(t, @"^(?<p>user|account|file|path|ip|domain|host|url|hash|md5|sha1|sha256|email)\s*:\s*(?<v>.+)$",
                RegexOptions.IgnoreCase);
            if (pm.Success && !t.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            {
                var p = pm.Groups["p"].Value.ToLowerInvariant();
                var v = pm.Groups["v"].Value.Trim();
                if (p is "user" or "account")
                    return Regex.IsMatch(v, @"^[A-Za-z0-9_.\-$@]{1,64}$") ? new CaseIoc("User", v, comment) : null;
                if (p is "file" or "path")
                    return v.Length >= 2 ? new CaseIoc("File", v, comment) : null;
                var inner = Classify(v, comment);
                return inner;
            }

            if (UrlRx.IsMatch(t)) return new CaseIoc("URL", t, comment);

            // ip:port → ip
            var ipPort = Regex.Match(t, @"^(?<ip>\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$");
            if (ipPort.Success) t = ipPort.Groups["ip"].Value;
            if (EmailRx.IsMatch(t)) return new CaseIoc("Email", t.ToLowerInvariant(), comment);

            // CIDR
            var slash = t.IndexOf('/');
            if (slash > 0 && int.TryParse(t[(slash + 1)..], out var prefix)
                && IPAddress.TryParse(t[..slash], out var net))
            {
                int max = net.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
                if (prefix >= 0 && prefix <= max && (net.AddressFamily != AddressFamily.InterNetwork || Ipv4.IsMatch(t[..slash])))
                    return prefix == max
                        ? new CaseIoc("IP", net.ToString(), comment)
                        : new CaseIoc("CIDR", $"{net}/{prefix}", comment);
            }

            // IP (v4 must be dotted quad — IPAddress.TryParse accepts "1" and "1.2")
            if (IPAddress.TryParse(t, out var ip))
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork && Ipv4.IsMatch(t))
                    return new CaseIoc("IP", ip.ToString(), comment);
                if (ip.AddressFamily == AddressFamily.InterNetworkV6 && t.Contains(':'))
                    return new CaseIoc("IP", ip.ToString(), comment);
            }

            // Hashes
            if (Hex.IsMatch(t))
                return t.Length switch
                {
                    32 => new CaseIoc("MD5", t.ToLowerInvariant(), comment),
                    40 => new CaseIoc("SHA1", t.ToLowerInvariant(), comment),
                    64 => new CaseIoc("SHA256", t.ToLowerInvariant(), comment),
                    _ => null
                };

            // Absolute Unix path
            if (t.StartsWith("/") && t.Length > 1 && !t.Contains(' '))
                return new CaseIoc("File", t, comment);

            // Domain (not a file name)
            var lower = t.ToLowerInvariant();
            if (DomainRx.IsMatch(lower))
            {
                var tld = lower[(lower.LastIndexOf('.') + 1)..];
                if (!FileExtensions.Contains(tld)) return new CaseIoc("Domain", lower, comment);
            }
            return null;
        }

        // ── Parse pasted / imported text ─────────────────────────────────
        public static (List<CaseIoc> Iocs, List<string> Rejected) Parse(string text)
        {
            var result = new List<CaseIoc>();
            var seen = new HashSet<(string, string)>();
            var rejected = new List<string>();

            foreach (var rawLine in (text ?? "").Split('\n'))
            {
                var line = rawLine.Trim().TrimEnd('\r');
                if (line.Length == 0 || line.StartsWith("#") || line.StartsWith("//")) continue;

                // Comment: '#' preceded by whitespace (keeps URL fragments intact)
                string comment = "";
                var hash = Regex.Match(line, @"\s#\s?(?<c>.*)$");
                if (hash.Success)
                {
                    comment = hash.Groups["c"].Value.Trim();
                    line = line[..hash.Index].Trim();
                }

                int before = result.Count;
                bool any = false;
                foreach (var tok in Regex.Split(line, @"[\s,;|]+").Where(x => x.Length > 0))
                {
                    var ioc = Classify(tok, comment);
                    if (ioc == null) continue;
                    any = true;
                    if (seen.Add((ioc.Kind, ioc.Value.ToLowerInvariant()))) result.Add(ioc);
                }
                if (!any) rejected.Add(line.Length > 80 ? line[..77] + "..." : line);
            }
            return (result, rejected);
        }

        public static string Summary(IReadOnlyCollection<CaseIoc> iocs)
        {
            if (iocs.Count == 0) return "no IOCs";
            var parts = iocs.GroupBy(i => i.Kind)
                .OrderBy(g => Array.IndexOf(KindOrder, g.Key))
                .Select(g => $"{g.Count()} {g.Key}");
            return $"{iocs.Count} IOC(s): {string.Join(", ", parts)}";
        }

        // ── File I/O ─────────────────────────────────────────────────────
        public static string PathFor(string caseFolder) => Path.Combine(caseFolder, FileName);

        public static List<CaseIoc> Load(string caseFolder)
        {
            var p = PathFor(caseFolder ?? "");
            if (string.IsNullOrWhiteSpace(caseFolder) || !File.Exists(p)) return new List<CaseIoc>();
            return Parse(File.ReadAllText(p)).Iocs;
        }

        /// <summary>Normalised text: header, then IOCs grouped by kind.</summary>
        public static string Format(IEnumerable<CaseIoc> iocs, string? caseName = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# Case IOCs — one per line, text after \" #\" is a comment.");
            sb.AppendLine("# Prefix user: or file: for user names and bare file names.");
            if (!string.IsNullOrWhiteSpace(caseName)) sb.AppendLine($"# Case: {caseName}");
            foreach (var g in iocs.GroupBy(i => i.Kind).OrderBy(g => Array.IndexOf(KindOrder, g.Key)))
            {
                sb.AppendLine();
                sb.AppendLine($"# {g.Key}");
                foreach (var i in g) sb.AppendLine(i.ToLine());
            }
            return sb.ToString();
        }

        public static void Save(string caseFolder, IEnumerable<CaseIoc> iocs, string? caseName = null) =>
            File.WriteAllText(PathFor(caseFolder), Format(iocs, caseName), new UTF8Encoding(false));
    }
}

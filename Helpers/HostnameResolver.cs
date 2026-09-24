using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Resolves the collected host's name from UAC artifacts, so normalized CSV
    /// rows get the real hostname instead of whatever the collection folder
    /// happens to be called.
    ///
    /// Priority order (first valid hit wins):
    ///   1. live_response/**/hostname.txt        (`hostname` output)
    ///   2. live_response/**/hostnamectl*.txt    ("Static hostname:" line)
    ///   3. live_response/**/uname_-a.txt        (nodename, 2nd field)
    ///   4. [root]/etc/hostname                  (collected config file)
    /// Returns null if nothing usable is found — callers fall back to the
    /// collection-name heuristic.
    /// </summary>
    public static class HostnameResolver
    {
        // RFC 1123 labels, dot-separated; '_' tolerated since it shows up in the wild.
        private static readonly Regex RxValidHost = new(
            @"^[A-Za-z0-9](?:[A-Za-z0-9_\-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9_\-]{0,62}))*$",
            RegexOptions.Compiled);

        public static string Resolve(string rootPath)
        {
            if (string.IsNullOrWhiteSpace(rootPath) || !Directory.Exists(rootPath))
                return null;

            var lrDir = SafeEnumDirs(rootPath, "live_response").FirstOrDefault();
            if (lrDir != null)
            {
                var h = FromHostnameTxt(FindFile(lrDir, "hostname.txt"))
                     ?? FromHostnamectl(FindFiles(lrDir, "hostnamectl*.txt"))
                     ?? FromUname(FindFile(lrDir, "uname_-a.txt"));
                if (h != null) return h;
            }

            // /etc/hostname inside the collected filesystem tree ([root]/etc/hostname)
            var etcHostname = SafeEnumFiles(rootPath, "hostname")
                .FirstOrDefault(f => string.Equals(
                    Path.GetFileName(Path.GetDirectoryName(f)), "etc",
                    StringComparison.OrdinalIgnoreCase));
            return FromHostnameTxt(etcHostname);
        }

        internal static string FromHostnameTxt(string path)
        {
            if (path == null) return null;
            try
            {
                var line = File.ReadLines(path)
                    .Select(l => l.Trim())
                    .FirstOrDefault(l => l.Length > 0 && !l.StartsWith("#"));
                return Validate(line);
            }
            catch { return null; }
        }

        internal static string FromHostnamectl(string[] paths)
        {
            foreach (var p in paths ?? Array.Empty<string>())
            {
                try
                {
                    var m = Regex.Match(File.ReadAllText(p),
                        @"^\s*Static hostname:\s*(\S+)", RegexOptions.Multiline);
                    var h = m.Success ? Validate(m.Groups[1].Value) : null;
                    if (h != null) return h;
                }
                catch { /* try next */ }
            }
            return null;
        }

        internal static string FromUname(string path)
        {
            if (path == null) return null;
            try
            {
                // "Linux web01 6.8.0-45-generic #45-Ubuntu SMP ... x86_64 GNU/Linux"
                var parts = File.ReadLines(path).FirstOrDefault()?
                    .Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
                return parts != null && parts.Length >= 2 ? Validate(parts[1]) : null;
            }
            catch { return null; }
        }

        // Rejects empty output, "(none)", "localhost" and error text captured by UAC.
        private static string Validate(string h)
        {
            if (string.IsNullOrWhiteSpace(h)) return null;
            h = h.Trim().TrimEnd('.');
            if (h.Length > 253) return null;
            if (h.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                || h.Equals("localhost.localdomain", StringComparison.OrdinalIgnoreCase)
                || h.Equals("(none)", StringComparison.OrdinalIgnoreCase))
                return null;
            return RxValidHost.IsMatch(h) ? h : null;
        }

        private static string FindFile(string dir, string name) => FindFiles(dir, name).FirstOrDefault();

        private static string[] FindFiles(string dir, string pattern)
            => SafeEnumFiles(dir, pattern).OrderBy(f => f, StringComparer.Ordinal).ToArray();

        private static System.Collections.Generic.IEnumerable<string> SafeEnumFiles(string dir, string pattern)
        {
            try { return Directory.EnumerateFiles(dir, pattern, SearchOption.AllDirectories).ToList(); }
            catch { return Enumerable.Empty<string>(); }
        }

        private static System.Collections.Generic.IEnumerable<string> SafeEnumDirs(string dir, string pattern)
        {
            try { return Directory.EnumerateDirectories(dir, pattern, SearchOption.AllDirectories).ToList(); }
            catch { return Enumerable.Empty<string>(); }
        }
    }
}

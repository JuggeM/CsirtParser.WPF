using System;
using System.Text;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Command-line indicators shared by the parsers (bash history, crontab,
    /// cron/syslog, journal, audit) so they flag the same things the same way.
    /// </summary>
    public static class Indicators
    {
        // "... | bash", "... |sh", "... | sudo bash", "... | /bin/sh" — but not "| sha256sum".
        private static readonly Regex PipeToShellRx = new(
            @"\|\s*(?:sudo\s+)?(?:/usr)?(?:/bin/)?(?:bash|sh|dash|zsh|ksh)\b(?!\.)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Redirect / tee into a file an attacker uses for privilege or persistence.
        private static readonly Regex SensitiveWriteRx = new(
            @"(?:>>?|\btee\s+(?:-a\s+)?)\s*['""]?(?<path>" +
            @"/etc/sudoers(?:\.d/\S*)?|/etc/passwd|/etc/shadow|/etc/group|" +
            @"/etc/crontab|/etc/cron\.d/\S+|/var/spool/cron/\S+|" +
            @"/etc/rc\.local|/etc/ld\.so\.preload|/etc/profile(?:\.d/\S*)?|/etc/bash\.bashrc|" +
            @"/etc/ssh/sshd_config|/etc/systemd/system/\S+|" +
            @"\S*authorized_keys|\S*/\.bashrc|\S*/\.bash_profile|\S*/\.profile|~/\.bashrc|~/\.profile)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex AntiForensicsRx = new(
            @"\bhistory\s+-c\b|\bhistory\s+-w\s+/dev/null|\bunset\s+HISTFILE\b|HISTFILE=/dev/null|" +
            @"HISTSIZE=0|\bshred\b.*\blog|\brm\s+-[rf]+\s+/var/log|>\s*/var/log/(?:wtmp|btmp|lastlog|auth\.log|secure)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex Base64TokenRx = new(
            @"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])",
            RegexOptions.Compiled);

        /// <summary>Downloads or text piped straight into a shell interpreter.</summary>
        public static bool IsPipeToShell(string text) =>
            !string.IsNullOrEmpty(text) && PipeToShellRx.IsMatch(text);

        /// <summary>Returns the sensitive file written to (via &gt;, &gt;&gt; or tee), or null.</summary>
        public static string? SensitiveFileWritten(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            var m = SensitiveWriteRx.Match(text);
            return m.Success ? m.Groups["path"].Value : null;
        }

        /// <summary>History clearing, HISTFILE tampering or log wiping.</summary>
        public static bool IsAntiForensics(string text) =>
            !string.IsNullOrEmpty(text) && AntiForensicsRx.IsMatch(text);

        /// <summary>
        /// Decodes the first base64 token in <paramref name="text"/> that decodes
        /// to readable text (e.g. an "echo ... | base64 -d | bash" payload).
        /// Returns null when there is nothing readable to show.
        /// </summary>
        public static string? TryDecodeBase64(string text)
        {
            if (string.IsNullOrEmpty(text)) return null;
            foreach (Match m in Base64TokenRx.Matches(text))
            {
                var token = m.Value;
                // Skip things that are clearly not base64 payloads (paths, hex hashes).
                if (Regex.IsMatch(token, "^[0-9a-fA-F]+$")) continue;
                var padded = token.PadRight(token.Length + (4 - token.Length % 4) % 4, '=');
                try
                {
                    var bytes = Convert.FromBase64String(padded);
                    if (bytes.Length < 8) continue;
                    int printable = 0;
                    foreach (var b in bytes)
                        if (b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127)) printable++;
                    if (printable < bytes.Length * 0.9) continue;
                    var decoded = Encoding.ASCII.GetString(bytes).Replace('\n', ' ').Replace('\r', ' ').Trim();
                    return decoded.Length > 200 ? decoded.Substring(0, 197) + "..." : decoded;
                }
                catch (FormatException) { }
            }
            return null;
        }

        /// <summary>" → decoded: …" suffix for a finding, or empty.</summary>
        public static string DecodedSuffix(string text)
        {
            var d = TryDecodeBase64(text);
            return d == null ? string.Empty : $"  → decoded: {d}";
        }
    }
}

using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Resolves the UTC offset of the collected host from UAC artifacts, so log
    /// timestamps recorded in local host time can be corrected to UTC.
    ///
    /// UAC does not normalize timestamps in raw log files (syslog, auth.log,
    /// messages, etc.) — they are written in whatever timezone the host's clock
    /// was set to at the time. Without this resolver, timeline correlation
    /// across hosts in different timezones (or a host under DST) silently
    /// drifts by the offset.
    ///
    /// Looks for, in priority order:
    ///   1. .../live_response/system/timedatectl_status.txt (systemd hosts)
    ///   2. .../live_response/system/date.txt (fallback — `date` command output)
    /// </summary>
    public static class HostTimezoneResolver
    {
        /// <summary>
        /// Attempts to resolve the fixed UTC offset for the collection at
        /// rootPath. Returns null if no timezone artifact could be found or
        /// parsed — callers should treat null as "leave timestamps
        /// uncorrected", never assume UTC.
        /// </summary>
        public static TimeSpan? Resolve(string rootPath)
        {
            if (string.IsNullOrWhiteSpace(rootPath) || !Directory.Exists(rootPath))
                return null;

            var timedatectlPath = FindFile(rootPath, "timedatectl_status.txt")
                ?? FindFile(rootPath, "timedatectl.txt");
            if (timedatectlPath != null)
            {
                var offset = ParseTimedatectl(timedatectlPath);
                if (offset.HasValue) return offset;
            }

            var datePath = FindFile(rootPath, "date.txt");
            if (datePath != null)
            {
                var offset = ParseDateCommand(datePath);
                if (offset.HasValue) return offset;
            }

            return null;
        }

        private static string FindFile(string rootPath, string fileName)
        {
            try
            {
                return Directory.EnumerateFiles(rootPath, fileName, SearchOption.AllDirectories)
                    .FirstOrDefault();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Parses `timedatectl status` / `timedatectl show` output. Looks for
        /// the UTC offset in the "Time zone: Europe/Stockholm (CEST, +0200)"
        /// line — the parenthetical carries the *active* (DST-aware) offset at
        /// collection time, which is what we want since UAC captures a
        /// point-in-time snapshot rather than a continuous log.
        /// </summary>
        internal static TimeSpan? ParseTimedatectl(string filePath)
        {
            try
            {
                var text = File.ReadAllText(filePath);

                var m = Regex.Match(text,
                    @"Time zone:.*\(\s*\w+\s*,\s*([+-]\d{2}):?(\d{2})\s*\)");
                if (m.Success)
                    return BuildOffset(m.Groups[1].Value, m.Groups[2].Value);

                // Fallback for stripped/minimal output that only prints the raw offset.
                var m2 = Regex.Match(text, @"([+-]\d{2}):?(\d{2})");
                if (m2.Success)
                    return BuildOffset(m2.Groups[1].Value, m2.Groups[2].Value);
            }
            catch
            {
                // Missing/unreadable artifact — fall through to null.
            }

            return null;
        }

        /// <summary>
        /// Parses `date` command output, e.g. "Tue Jun 3 09:23:56 CEST 2026" or
        /// the RFC-2822-style "Tue, 03 Jun 2026 09:23:56 +0200".
        /// </summary>
        internal static TimeSpan? ParseDateCommand(string filePath)
        {
            try
            {
                var text = File.ReadAllText(filePath).Trim();

                var m = Regex.Match(text, @"([+-]\d{2}):?(\d{2})\s*$");
                if (m.Success)
                    return BuildOffset(m.Groups[1].Value, m.Groups[2].Value);
            }
            catch
            {
                // Missing/unreadable artifact — fall through to null.
            }

            return null;
        }

        private static TimeSpan BuildOffset(string hours, string minutes)
        {
            int h = int.Parse(hours);
            int m = int.Parse(minutes);
            int sign = h < 0 ? -1 : 1;
            return new TimeSpan(h, sign * m, 0);
        }
    }
}

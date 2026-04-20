using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Common utilities shared across all parsers
    /// Eliminates ~1000 lines of duplicated code
    /// </summary>
    public static class SyslogHelpers
    {
        #region Timestamp Parsing (Universal)

        private static readonly Regex IsoTimestampRegex = new Regex(
            @"^(?<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2}))\b",
            RegexOptions.Compiled);

        private static readonly Regex SyslogTimestampRegex = new Regex(
            @"^(?<mon>\w{3})\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})",
            RegexOptions.Compiled);

        private static readonly Regex ApacheTimestampRegex = new Regex(
            @"\[(?<dt>[^\]]+)\]",
            RegexOptions.Compiled);

        /// <summary>
        /// Universal timestamp parser - handles ISO8601, syslog, Apache, and epoch formats
        /// </summary>
        public static DateTime ParseTimestamp(string line, string logFilePath = null)
        {
            if (string.IsNullOrWhiteSpace(line))
                return DateTime.MinValue;

            // 1. Try ISO-8601 / RFC3339 (preferred - has year and timezone)
            var iso = IsoTimestampRegex.Match(line);
            if (iso.Success)
            {
                if (DateTimeOffset.TryParse(
                    iso.Groups["ts"].Value,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var dto))
                {
                    return dto.UtcDateTime;
                }
            }

            // 2. Try Apache format [dd/MMM/yyyy:HH:mm:ss zzz]
            var apache = ApacheTimestampRegex.Match(line);
            if (apache.Success)
            {
                if (DateTimeOffset.TryParseExact(
                    apache.Groups["dt"].Value,
                    "dd/MMM/yyyy:HH:mm:ss zzz",
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AllowWhiteSpaces,
                    out var apacheDt))
                {
                    return apacheDt.UtcDateTime;
                }
            }

            // 3. Try syslog format (no year - infer from file)
            var syslog = SyslogTimestampRegex.Match(line);
            if (syslog.Success)
            {
                return ParseSyslogTimestamp(syslog, logFilePath);
            }

            // 4. Try epoch timestamp
            var epochMatch = Regex.Match(line, @"msg=audit\((\d+)\.");
            if (epochMatch.Success && long.TryParse(epochMatch.Groups[1].Value, out long epochSeconds))
            {
                try
                {
                    return DateTimeOffset.FromUnixTimeSeconds(epochSeconds).UtcDateTime;
                }
                catch { }
            }

            return DateTime.MinValue;
        }

        private static DateTime ParseSyslogTimestamp(Match match, string logFilePath)
        {
            string monthStr = match.Groups["mon"].Value;
            string dayStr = match.Groups["day"].Value;
            string timeStr = match.Groups["time"].Value;

            // Infer year from file last write time (more reliable than DateTime.Now)
            int year = DateTime.UtcNow.Year;
            if (!string.IsNullOrEmpty(logFilePath) && System.IO.File.Exists(logFilePath))
            {
                try
                {
                    year = System.IO.File.GetLastWriteTimeUtc(logFilePath).Year;
                }
                catch { }
            }

            var formats = new[] { "MMM d HH:mm:ss", "MMM dd HH:mm:ss" };
            foreach (var format in formats)
            {
                if (DateTime.TryParseExact(
                    $"{monthStr} {dayStr} {timeStr}",
                    format,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeLocal,
                    out DateTime dt))
                {
                    return new DateTime(year, dt.Month, dt.Day, dt.Hour, dt.Minute, dt.Second, DateTimeKind.Utc);
                }
            }

            return DateTime.MinValue;
        }

        #endregion

        #region Field Extraction (Common)

        private static readonly Regex HostnameRegex = new Regex(
            @"(?:^\d{4}-\d{2}-\d{2}T[^\s]+\s+|^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)(?<host>\S+)\s+",
            RegexOptions.Compiled);

        private static readonly Regex DaemonRegex = new Regex(
            @"\s(?<daemon>[A-Za-z0-9._\-]+)(?:\[\d+\])?:",
            RegexOptions.Compiled);

        private static readonly Regex IPv4Regex = new Regex(
            @"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
            RegexOptions.Compiled);

        private static readonly Regex IPv6Regex = new Regex(
            @"\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b",
            RegexOptions.Compiled);

        private static readonly Regex UserRegex = new Regex(
            @"\b(?:user|USER)=(?<user>[A-Za-z0-9._\-]+)\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>
        /// Extract hostname from log line (ISO or syslog format)
        /// </summary>
        public static string ExtractHostname(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return string.Empty;

            var match = HostnameRegex.Match(line);
            return match.Success ? match.Groups["host"].Value : string.Empty;
        }

        /// <summary>
        /// Extract daemon/service name from log line
        /// </summary>
        public static string ExtractDaemon(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return string.Empty;

            var match = DaemonRegex.Match(line);
            return match.Success ? match.Groups["daemon"].Value : string.Empty;
        }

        /// <summary>
        /// Extract IP address (IPv4 or IPv6) from log line
        /// </summary>
        public static string ExtractIP(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return string.Empty;

            // Try IPv4 first (more common)
            var ipv4 = IPv4Regex.Match(line);
            if (ipv4.Success)
                return ipv4.Value;

            // Fallback to IPv6
            var ipv6 = IPv6Regex.Match(line);
            return ipv6.Success ? ipv6.Value : string.Empty;
        }

        /// <summary>
        /// Extract username from various log formats
        /// </summary>
        public static string ExtractUser(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return string.Empty;

            // Pattern: user=<username> or USER=<username>
            var match = UserRegex.Match(line);
            if (match.Success)
                return match.Groups["user"].Value;

            // Pattern: "for user <username>"
            match = Regex.Match(line, @"\bfor user (?<user>[A-Za-z0-9._\-]+)\b", RegexOptions.IgnoreCase);
            if (match.Success)
                return match.Groups["user"].Value;

            // Pattern: "session opened/closed for user <username>"
            match = Regex.Match(line, @"session\s+(?:opened|closed)\s+for\s+user\s+(?<user>[A-Za-z0-9._\-]+)", RegexOptions.IgnoreCase);
            if (match.Success)
                return match.Groups["user"].Value;

            return string.Empty;
        }

        /// <summary>
        /// Extract message content (everything after daemon token)
        /// </summary>
        public static string ExtractMessage(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
                return string.Empty;

            // Remove daemon[pid]: prefix
            var match = Regex.Match(line, @"[A-Za-z0-9._\-]+(?:\[\d+\])?:\s*(?<msg>.*)$");
            if (match.Success)
                return match.Groups["msg"].Value.Trim();

            return line;
        }

        #endregion

        #region Pattern Matching & Severity

        /// <summary>
        /// Check if line matches any pattern in the list (case-insensitive)
        /// </summary>
        public static bool ContainsAny(string line, IEnumerable<string> patterns)
        {
            if (string.IsNullOrWhiteSpace(line) || patterns == null)
                return false;

            var lower = line.ToLowerInvariant();
            return patterns.Any(pattern => lower.Contains(pattern.ToLowerInvariant()));
        }

        /// <summary>
        /// Get first matching pattern (returns null if none match)
        /// </summary>
        public static string GetFirstMatch(string line, IEnumerable<string> patterns)
        {
            if (string.IsNullOrWhiteSpace(line) || patterns == null)
                return null;

            var lower = line.ToLowerInvariant();
            return patterns.FirstOrDefault(pattern => lower.Contains(pattern.ToLowerInvariant()));
        }

        /// <summary>
        /// Classify severity based on configurable rules
        /// </summary>
        public static string ClassifySeverity(string line, Dictionary<string, string> severityMapping)
        {
            if (string.IsNullOrWhiteSpace(line) || severityMapping == null)
                return "Info";

            var lower = line.ToLowerInvariant();
            
            foreach (var kvp in severityMapping.OrderByDescending(x => x.Value))
            {
                if (lower.Contains(kvp.Key.ToLowerInvariant()))
                    return kvp.Value;
            }

            return "Info";
        }

        #endregion

        #region Normalization

        /// <summary>
        /// Normalize log message for deduplication/grouping
        /// Removes timestamps, PIDs, IP addresses, and numbers
        /// </summary>
        public static string NormalizeForGrouping(string message)
        {
            if (string.IsNullOrWhiteSpace(message))
                return string.Empty;

            var normalized = message;

            // Remove timestamps
            normalized = Regex.Replace(normalized, @"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", "TIMESTAMP");
            normalized = Regex.Replace(normalized, @"\b\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", "TIMESTAMP");

            // Remove IP addresses
            normalized = Regex.Replace(normalized, @"\b(?:\d{1,3}\.){3}\d{1,3}\b", "IP");
            normalized = Regex.Replace(normalized, @"\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b", "IP");

            // Remove PIDs
            normalized = Regex.Replace(normalized, @"\[?\bpid[=:]?\d+\]?", "PID", RegexOptions.IgnoreCase);
            normalized = Regex.Replace(normalized, @"\[\d+\]", "PID");

            // Remove UIDs/GIDs
            normalized = Regex.Replace(normalized, @"\b(?:uid|gid|auid)=\d+", "ID", RegexOptions.IgnoreCase);

            // Remove hex addresses
            normalized = Regex.Replace(normalized, @"0x[0-9a-fA-F]+", "HEX");

            // Remove generic numbers (but keep words with numbers)
            normalized = Regex.Replace(normalized, @"\b\d+\b", "N");

            // Collapse whitespace
            normalized = Regex.Replace(normalized, @"\s+", " ").Trim();

            return normalized;
        }

        /// <summary>
        /// Sanitize filename for safe filesystem operations
        /// </summary>
        public static string SanitizeFilename(string filename)
        {
            if (string.IsNullOrWhiteSpace(filename))
                return "unnamed";

            var invalid = System.IO.Path.GetInvalidFileNameChars();
            var sanitized = string.Join("_", filename.Split(invalid, StringSplitOptions.RemoveEmptyEntries));
            
            return string.IsNullOrWhiteSpace(sanitized) ? "unnamed" : sanitized;
        }

        #endregion

        #region Grouping & Counting

        /// <summary>
        /// Increment pattern count in dictionary (thread-safe)
        /// </summary>
        public static void IncrementCount(Dictionary<string, int> counts, string key)
        {
            if (counts == null || string.IsNullOrWhiteSpace(key))
                return;

            lock (counts)
            {
                if (counts.ContainsKey(key))
                    counts[key]++;
                else
                    counts[key] = 1;
            }
        }

        /// <summary>
        /// Add or update grouped event with timestamp tracking
        /// </summary>
        public static void UpdateGroupedEvent(
            Dictionary<string, GroupedEvent> groups,
            string key,
            DateTime timestamp)
        {
            if (groups == null || string.IsNullOrWhiteSpace(key))
                return;

            if (!groups.ContainsKey(key))
                groups[key] = new GroupedEvent();

            groups[key].Count++;

            if (timestamp != DateTime.MinValue)
            {
                if (timestamp < groups[key].FirstSeen)
                    groups[key].FirstSeen = timestamp;
                if (timestamp > groups[key].LastSeen)
                    groups[key].LastSeen = timestamp;
            }
        }

        #endregion

        #region Validation

        /// <summary>
        /// Check if IP is likely a public address (basic heuristic)
        /// </summary>
        public static bool IsPublicIP(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
                return false;

            // Parse IPv4
            var parts = ip.Split('.');
            if (parts.Length == 4 && int.TryParse(parts[0], out int first) && int.TryParse(parts[1], out int second))
            {
                // RFC1918 private ranges
                if (first == 10) return false;
                if (first == 172 && second >= 16 && second <= 31) return false;
                if (first == 192 && second == 168) return false;
                if (first == 127) return false; // loopback
                if (first == 169 && second == 254) return false; // link-local
                return true;
            }

            // For IPv6, assume public (more complex logic needed for accurate check)
            return ip.Contains(":");
        }

        /// <summary>
        /// Check if path matches whitelist patterns
        /// </summary>
        public static bool IsWhitelisted(string path, IEnumerable<string> whitelistPatterns)
        {
            if (string.IsNullOrWhiteSpace(path) || whitelistPatterns == null)
                return false;

            var lower = path.ToLowerInvariant();
            return whitelistPatterns.Any(pattern => 
                lower.Contains(pattern.ToLowerInvariant()) ||
                lower.StartsWith(pattern.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));
        }

        #endregion

        #region Formatting

        /// <summary>
        /// Format timestamp for output (consistent across all parsers)
        /// </summary>
        public static string FormatTimestamp(DateTime dt)
        {
            if (dt == DateTime.MinValue || dt == DateTime.MaxValue)
                return "N/A";

            return dt.ToString("yyyy-MM-dd HH:mm:ss") + " UTC";
        }

        /// <summary>
        /// Format time range for output
        /// </summary>
        public static string FormatTimeRange(DateTime first, DateTime last)
        {
            return $"{FormatTimestamp(first)} → {FormatTimestamp(last)}";
        }

        /// <summary>
        /// Format duration in human-readable form
        /// </summary>
        public static string FormatDuration(TimeSpan duration)
        {
            if (duration.TotalSeconds < 1)
                return "< 1 second";

            var parts = new List<string>();

            if (duration.TotalDays >= 1)
                parts.Add($"{(int)duration.TotalDays}d");
            if (duration.Hours > 0)
                parts.Add($"{duration.Hours}h");
            if (duration.Minutes > 0)
                parts.Add($"{duration.Minutes}m");
            if (duration.Seconds > 0 && duration.TotalHours < 1)
                parts.Add($"{duration.Seconds}s");

            return string.Join(" ", parts);
        }

        #endregion

        #region File Operations

        /// <summary>
        /// Read file with automatic decompression (.gz support)
        /// </summary>
        public static IEnumerable<string> ReadLinesWithDecompression(string filePath)
        {
            if (!System.IO.File.Exists(filePath))
                yield break;

            if (filePath.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                using var fileStream = System.IO.File.OpenRead(filePath);
                using var gzipStream = new System.IO.Compression.GZipStream(fileStream, System.IO.Compression.CompressionMode.Decompress);
                using var reader = new System.IO.StreamReader(gzipStream);
                
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    yield return line;
                }
            }
            else
            {
                foreach (var line in System.IO.File.ReadLines(filePath))
                {
                    yield return line;
                }
            }
        }

        #endregion
    }
}

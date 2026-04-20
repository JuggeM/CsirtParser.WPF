using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Detects SSH/login brute-force attempts from a list of failed login lines.
    /// Preserves all patterns from both the original and new-project versions.
    /// The threshold parameter replaces the old ParserConfiguration.Instance dependency
    /// so the analyst's UI setting is honoured — defaults to 5 if not supplied.
    /// </summary>
    public static class BruteForceDetector
    {
        // All patterns from the original project, preserved verbatim
        private static readonly Dictionary<string, string> DefaultPatterns = new()
        {
            ["vsftpd"] = @"(?<timestamp>[A-Z][a-z]{2}\s+\d+\s[\d:]+).*rhost=(?<ip>[\d.:a-fA-F]+)",
            ["sshd"] = @"(?<timestamp>[A-Z][a-z]{2}\s+\d+\s[\d:]+).*Failed password.*from (?<ip>[\d.:a-fA-F]+)",
            ["smbd"] = @"(?<timestamp>[A-Z][a-z]{2}\s+\d+\s[\d:]+).*smbd.*(authentication failed|failed session setup).*from (?<ip>[\d.:a-fA-F]+)",
            ["telnetd"] = @"(?<timestamp>[A-Z][a-z]{2}\s+\d+\s[\d:]+).*telnetd.*(login incorrect|failed login).*from (?<ip>[\d.:a-fA-F]+)",
            ["imapd"] = @"(?<timestamp>[A-Z][a-z]{2}\s+\d+\s[\d:]+).*imap.*authentication failure.*rhost=(?<ip>[\d.:a-fA-F]+)",
            ["pop3d"] = @"(?<timestamp>[A-Z][a-z]{2}\s+\d+\s[\d:]+).*pop3.*authentication failure.*rhost=(?<ip>[\d.:a-fA-F]+)",
            ["openvpn"] = @"(?<timestamp>[A-Z][a-z]{2}\s+\d+\s[\d:]+).*AUTH_FAILED.*from (?<ip>[\d.:a-fA-F]+)",
            ["ftp"] = @"(?<timestamp>[A-Z][a-z]{2}\s+\d+\s[\d:]+).*530 Login incorrect.*from (?<ip>[\d.:a-fA-F]+)",
            ["dovecot"] = @"(?<timestamp>[A-Z][a-z]{2}\s+\d+\s[\d:]+).*dovecot.*authentication failure.*rip=(?<ip>[\d.:a-fA-F]+)",
        };

        /// <summary>
        /// Analyse failed login lines and return brute-force findings.
        /// Pass Config.BruteForceThreshold from the orchestrator to honour the analyst's UI setting.
        /// Defaults to 5 if not supplied (matches original hardcoded behaviour).
        /// </summary>
        public static List<string> AnalyzeFailedLogins(List<string> failedLines, int threshold = 5)
        {
            var bruteForceFindings = new List<string>();

            if (failedLines == null || failedLines.Count == 0)
                return bruteForceFindings;

            // Use threshold floor of 1 to avoid accidentally suppressing all findings
            if (threshold < 1) threshold = 5;

            var ipFailureCounts = new Dictionary<string, int>();
            var ipFirstTimestamps = new Dictionary<string, string>();

            foreach (var line in failedLines)
            {
                foreach (var pattern in DefaultPatterns.Values)
                {
                    Match match;
                    try { match = Regex.Match(line, pattern); }
                    catch { continue; }

                    if (!match.Success) continue;

                    string ip = match.Groups["ip"].Value;
                    string timestamp = match.Groups["timestamp"].Value;

                    if (!ipFailureCounts.ContainsKey(ip))
                    {
                        ipFailureCounts[ip] = 0;
                        ipFirstTimestamps[ip] = timestamp;
                    }

                    ipFailureCounts[ip]++;
                    break;  // stop at first matching pattern — avoid double-counting
                }
            }

            foreach (var kvp in ipFailureCounts)
            {
                if (kvp.Value >= threshold)
                {
                    bruteForceFindings.Add(
                        $"Possible Brute-force Detected from IP {kvp.Key} " +
                        $"- {kvp.Value} failures since {ipFirstTimestamps[kvp.Key]}");
                }
            }

            return bruteForceFindings;
        }
    }
}
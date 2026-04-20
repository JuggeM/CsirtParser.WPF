using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Parser.Parsers.LiveResponse
{
    /// <summary>
    /// Parses user-related artifacts collected from the live_response/users directory.
    /// Typical sources: /etc/passwd, /etc/shadow, sudoers, lastlog, etc.
    /// Produces summary findings for DFIR triage.
    /// </summary>
    public class UserAccountParser
    {
        private readonly string usersRoot;

        public UserAccountParser(string usersRootPath)
        {
            usersRoot = usersRootPath;
        }

        /// <summary>
        /// Processes known user-related text dumps and extracts basic insights.
        /// </summary>
        public List<string> Process()
        {
            var findings = new List<string>();

            if (!Directory.Exists(usersRoot))
            {
                findings.Add($"[Users] Missing folder: {usersRoot}");
                return findings;
            }

            // Parse /etc/passwd
            var passwdPath = Path.Combine(usersRoot, "passwd.txt");
            if (File.Exists(passwdPath))
            {
                var passwdLines = File.ReadAllLines(passwdPath);
                var users = passwdLines
                    .Where(l => !l.StartsWith("#") && l.Contains(":"))
                    .Select(l => l.Split(':')[0])
                    .ToList();

                findings.Add($"[Users] Parsed {users.Count} accounts from passwd.txt");
                if (users.Any())
                    findings.AddRange(users.Select(u => $"    User: {u}"));
            }

            // Parse /etc/shadow for password hashes / lock status
            var shadowPath = Path.Combine(usersRoot, "shadow.txt");
            if (File.Exists(shadowPath))
            {
                var shadowLines = File.ReadAllLines(shadowPath);
                var locked = shadowLines.Count(l => l.Contains("!*") || l.Contains("!!"));
                var total = shadowLines.Length;

                findings.Add($"[Users] Parsed {total} shadow entries ({locked} locked accounts)");
            }

            // Parse sudoers
            var sudoersPath = Path.Combine(usersRoot, "sudoers.txt");
            if (File.Exists(sudoersPath))
            {
                var sudoLines = File.ReadAllLines(sudoersPath);
                var sudoUsers = sudoLines
                    .Where(l => !l.TrimStart().StartsWith("#") && l.Contains("ALL"))
                    .Select(l => l.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "")
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Distinct()
                    .ToList();

                findings.Add($"[Users] {sudoUsers.Count} sudo-capable accounts detected");
                foreach (var su in sudoUsers)
                    findings.Add($"    Sudo User: {su}");
            }

            // Parse lastlog summary
            var lastlogPath = Path.Combine(usersRoot, "lastlog.txt");
            if (File.Exists(lastlogPath))
            {
                var lines = File.ReadLines(lastlogPath)
                    .Where(l => l.Contains("pts/") || l.Contains("tty") || l.Contains("ssh"))
                    .Take(10)
                    .ToList();

                if (lines.Any())
                {
                    findings.Add($"[Users] Showing up to 10 recent logins from lastlog.txt:");
                    foreach (var l in lines)
                        findings.Add($"    {l}");
                }
            }

            if (findings.Count == 0)
                findings.Add("[Users] No recognizable user-related files found.");

            return findings;
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Helpers;
using Output;

namespace Parsers
{
    /// <summary>
    /// Scans actual crontab definition files for suspicious persistent job definitions.
    /// This is different from CronLogParser/SyslogParser which parse runtime log entries.
    ///
    /// Files scanned:
    ///   /etc/crontab
    ///   /etc/cron.d/*
    ///   /var/spool/cron/crontabs/*   (per-user crontabs)
    ///   /var/spool/cron/*            (RHEL/CentOS variant)
    /// </summary>
    public class CrontabScanner : LogFileParser
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        // ── Classification ────────────────────────────────────────────
        private static readonly string[] CriticalJobKeywords =
        {
            // Shell spawns / one-liners
            "bash -i", "sh -i", "zsh -i",
            "python -c", "python2 -c", "python3 -c",
            "perl -e", "ruby -e", "php -r",
            // Network tools
            "nc ", "netcat", "ncat", "socat",
            "mkfifo", "mknod",
            // Temp path execution
            "/tmp/", "/dev/shm/", "/var/tmp/",
            // Decode / dropper patterns
            "base64 -d", "base64 --decode",
            "wget -O /tmp", "wget -o /tmp",
            "curl -o /tmp", "curl -O /tmp",
            // File hiding
            "chattr +i",
            // Redirect tricks
            "0>&1", ">&2",
            // Explicit attacker terms
            "backdoor", "rootkit", "payload", "reverse",
        };

        private static readonly string[] SuspiciousJobKeywords =
        {
            // Downloads — not necessarily malicious but worth noting
            "wget", "curl", "http://", "https://", "ftp://",
            // Remote access
            "ssh", "scp", "rsync",
            "openssl",
        };

        private static readonly string[] Whitelist =
        {
            "/usr/lib/sa/sa1", "/usr/lib/sa/sa2",
            "logrotate", "/usr/libexec/atrun",
            "/usr/bin/updatedb", "/usr/bin/yum-cron",
            "run-parts", "/etc/cron.",
            "/usr/bin/freshclam", "/usr/bin/mandb",
            "/usr/lib64/nagios/plugins",
            "/usr/bin/test", "/usr/bin/stat", "/usr/bin/true",
            "BECOME-SUCCESS", "ansible", "AnsiballZ",
            "apt-get", "dpkg", "rpm", "yum", "dnf",
            "/usr/bin/find", "/usr/bin/locate",
        };

        private static bool IsWhitelisted(string cmd) =>
            Whitelist.Any(w => cmd.IndexOf(w, StringComparison.OrdinalIgnoreCase) >= 0);

        private static string ClassifyJob(string cmd)
        {
            if (IsWhitelisted(cmd)) return "Info";

            foreach (var kw in CriticalJobKeywords)
                if (cmd.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    return "Critical";

            foreach (var kw in SuspiciousJobKeywords)
                if (cmd.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    return "Suspicious";

            return "Info";
        }

        // ── Crontab file discovery ────────────────────────────────────
        public static List<string> DiscoverCrontabFiles(string collectionRoot)
        {
            var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (!Directory.Exists(collectionRoot)) return new List<string>();

            // Try both with and without [root] prefix
            var bases = new[]
            {
                collectionRoot,
                Path.Combine(collectionRoot, "[root]"),
                Path.Combine(collectionRoot, "root"),
            };

            foreach (var b in bases.Where(Directory.Exists))
            {
                // /etc/crontab
                AddFile(results, Path.Combine(b, "etc", "crontab"));

                // /etc/cron.d/*
                AddDir(results, Path.Combine(b, "etc", "cron.d"));

                // /etc/cron.hourly, daily, weekly, monthly (scripts, not log files)
                foreach (var sub in new[] { "cron.hourly", "cron.daily", "cron.weekly", "cron.monthly" })
                    AddDir(results, Path.Combine(b, "etc", sub));

                // /var/spool/cron/crontabs/* (Debian/Ubuntu)
                AddDir(results, Path.Combine(b, "var", "spool", "cron", "crontabs"));

                // /var/spool/cron/* (RHEL/CentOS — per-user files directly)
                AddDir(results, Path.Combine(b, "var", "spool", "cron"));
            }

            return results.OrderBy(x => x).ToList();
        }

        private static void AddFile(HashSet<string> set, string path)
        {
            if (File.Exists(path)) set.Add(path);
        }

        private static void AddDir(HashSet<string> set, string dir)
        {
            if (!Directory.Exists(dir)) return;
            foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
            {
                // Skip binary files and known non-crontab extensions
                var name = Path.GetFileName(f);
                if (name.EndsWith(".rpm-orig", StringComparison.OrdinalIgnoreCase)) continue;
                if (name.EndsWith(".dpkg-old", StringComparison.OrdinalIgnoreCase)) continue;
                set.Add(f);
            }
        }

        // ── ParseLog ──────────────────────────────────────────────────
        // Note: timestamp is meaningless for crontab definitions (they have no
        // log timestamps). firstSeen/lastSeen are set to the file's last-write time.
        protected override void ParseLog(
            string logFilePath,
            List<string> findings,
            Dictionary<string, int> patternCounts,
            ref DateTime firstSeen,
            ref DateTime lastSeen,
            Dictionary<string, int> interestingIPs = null,
            string outputDir = null,
            bool suppressFooter = false)
        {
            // Use file modification time as the timestamp proxy
            DateTime fileTime = DateTime.MinValue;
            try
            {
                fileTime = new FileInfo(logFilePath).LastWriteTimeUtc;
                if (fileTime < firstSeen) firstSeen = fileTime;
                if (fileTime > lastSeen) lastSeen = fileTime;
            }
            catch { }

            // If the file's modification time is known and entirely outside the
            // analyst's filter window, skip the file — crontab entries have no
            // per-line timestamps so file mtime is the only proxy available.
            if (!IsInRange(fileTime)) return;

            string relativePath = logFilePath;

            foreach (var rawLine in ReadAllLines(logFilePath))
            {
                string line = rawLine.Trim();
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (line.StartsWith("#")) continue;  // comment
                if (line.StartsWith("MAILTO") ||
                    line.StartsWith("PATH") ||
                    line.StartsWith("SHELL") ||
                    line.StartsWith("HOME")) continue; // env vars

                // Parse crontab entry
                // Formats:
                //   minute hour dom month dow [user] command     (/etc/crontab, /etc/cron.d/)
                //   @reboot [user] command
                //   @daily  [user] command  etc.

                string schedule;
                string rest;

                var atM = Regex.Match(line,
                    @"^(?<sched>@\w+)\s+(?<rest>.+)$");
                var fieldsM = Regex.Match(line,
                    @"^(?<sched>\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(?<rest>.+)$");

                if (atM.Success)
                {
                    schedule = atM.Groups["sched"].Value;
                    rest = atM.Groups["rest"].Value;
                }
                else if (fieldsM.Success)
                {
                    schedule = fieldsM.Groups["sched"].Value;
                    rest = fieldsM.Groups["rest"].Value;
                }
                else
                {
                    continue; // not a valid crontab line
                }

                // Determine if /etc/crontab or cron.d style (has username field)
                // vs per-user crontab (no username field)
                string user = string.Empty;
                string command = rest;

                bool isSystemCrontab =
                    logFilePath.IndexOf("cron.d", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    logFilePath.EndsWith("crontab", StringComparison.OrdinalIgnoreCase);

                if (isSystemCrontab)
                {
                    // First token of rest is the username
                    var parts = rest.Split(new[] { ' ', '\t' }, 2,
                        StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 2)
                    {
                        user = parts[0];
                        command = parts[1];
                    }
                }
                else
                {
                    // Per-user crontab — infer user from filename
                    user = Path.GetFileName(logFilePath);
                }

                string tier = ClassifyJob(command);

                if (tier == "Info") continue;

                IncrementPatternCount(patternCounts,
                    tier == "Critical" ? "Critical crontab entry" : "Suspicious crontab entry");

                string display = command.Length > 160
                    ? command.Substring(0, 157) + "..."
                    : command;

                string severity = tier == "Critical" ? "HIGH" : "MEDIUM";

                findings.Add(
                    $"[CRONTAB] [{severity}] [{Path.GetFileName(logFilePath)}] " +
                    $"user={user} schedule={schedule} CMD: {display}");

                _normalizedWriter?.Write(NormalizedRecord.From(
                    fileTime,
                    string.Empty, "CRONTAB",
                    "cron", user, string.Empty,
                    command, tier == "Critical" ? "High" : "Medium",
                    rawLine));
            }
        }

        // ── Public parse-only entry point ─────────────────────────────
        public (List<string> Findings,
                Dictionary<string, int> Patterns,
                DateTime First,
                DateTime Last)
            ParseFile(string filePath)
        {
            var findings = new List<string>();
            var patterns = new Dictionary<string, int>();
            DateTime first = DateTime.MaxValue;
            DateTime last = DateTime.MinValue;

            ParseLog(filePath, findings, patterns,
                     ref first, ref last,
                     interestingIPs: null, outputDir: null, suppressFooter: true);

            return (findings, patterns, first, last);
        }
    }
}
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
    /// Parses database CLI history files from UAC collections:
    ///   .mysql_history   — MySQL client history
    ///   .psql_history    — PostgreSQL client history
    ///   .sqlite_history  — SQLite CLI history
    ///   .rediscli_history — Redis CLI history
    ///
    /// Forensic value:
    ///   - Credentials in queries (passwords in ALTER USER / CREATE USER)
    ///   - Sensitive table reads (SELECT from user/password tables)
    ///   - Data exfil (SELECT INTO OUTFILE, COPY TO)
    ///   - Privilege escalation (GRANT ALL, CREATE USER)
    ///   - UDF / stored procedure abuse
    /// </summary>
    public class DbHistoryParser : LogFileParser, IAttachNormalizedWriter
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        private string _hostname = string.Empty;
        public void AttachHostname(string hostname) => _hostname = hostname ?? string.Empty;

        // Critical — near-certain attacker activity
        private static readonly string[] CriticalPatterns =
        {
            // Credential manipulation
            @"alter\s+user.+identified\s+by",
            @"create\s+user.+identified\s+by",
            @"set\s+password",
            @"update\s+mysql\.user",
            // Privilege escalation
            @"grant\s+all",
            @"grant\s+super",
            @"flush\s+privileges",
            // File read/write (MySQL)
            @"load\s+data\s+(local\s+)?infile",
            @"into\s+outfile",
            @"into\s+dumpfile",
            // UDF / OS command execution
            @"create\s+function.+soname",
            @"sys_exec\s*\(",
            @"do\s+sys_exec",
            // PostgreSQL COPY to/from
            @"copy\s+.+\s+to\s+",
            @"copy\s+.+\s+from\s+program",
            // PostgreSQL CREATE EXTENSION with plpgsql
            @"create\s+extension\s+adminpack",
        };

        // Suspicious — worth reviewing
        private static readonly string[] SuspiciousPatterns =
        {
            // Sensitive table reads
            @"select.+from\s+mysql\.user",
            @"select.+from\s+information_schema",
            @"select.+password",
            @"select.+shadow",
            // Schema discovery
            @"show\s+databases",
            @"show\s+tables",
            @"\\\!",                  // MySQL shell escape: \! command
            @"\\!",
        };

        private static readonly Regex[] _criticalRegexes =
            CriticalPatterns.Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase)).ToArray();
        private static readonly Regex[] _suspiciousRegexes =
            SuspiciousPatterns.Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase)).ToArray();

        // ── Discovery ─────────────────────────────────────────────────
        public static List<(string FilePath, string Username)> DiscoverFiles(string collectionRoot)
        {
            var results = new List<(string, string)>();
            if (!Directory.Exists(collectionRoot)) return results;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var fileNames = new[]
            {
                ".mysql_history", "mysql_history.txt",
                ".psql_history",  "psql_history.txt",
                ".sqlite_history","sqlite_history.txt",
                ".rediscli_history",
            };

            var bases = new[]
            {
                collectionRoot,
                Path.Combine(collectionRoot, "[root]"),
                Path.Combine(collectionRoot, "root"),
            }.Where(Directory.Exists);

            foreach (var b in bases)
            {
                foreach (var name in fileNames)
                {
                    var p = Path.Combine(b, "root", name);
                    if (File.Exists(p) && seen.Add(p)) results.Add((p, "root"));
                }

                var homePath = Path.Combine(b, "home");
                if (Directory.Exists(homePath))
                {
                    foreach (var userDir in Directory.EnumerateDirectories(homePath))
                    {
                        var user = Path.GetFileName(userDir);
                        foreach (var name in fileNames)
                        {
                            var p = Path.Combine(userDir, name);
                            if (File.Exists(p) && seen.Add(p)) results.Add((p, user));
                        }
                    }
                }
            }

            // live_response/user_files
            var lrPath = Directory.EnumerateDirectories(
                collectionRoot, "live_response", SearchOption.AllDirectories).FirstOrDefault();
            if (!string.IsNullOrEmpty(lrPath))
            {
                var uf = Path.Combine(lrPath, "user_files");
                if (Directory.Exists(uf))
                {
                    foreach (var userDir in Directory.EnumerateDirectories(uf))
                    {
                        var user = Path.GetFileName(userDir);
                        foreach (var name in fileNames)
                        {
                            var p = Path.Combine(userDir, name);
                            if (File.Exists(p) && seen.Add(p)) results.Add((p, user));
                        }
                    }
                }
            }

            return results.OrderBy(r => r.Item2).ThenBy(r => r.Item1).ToList();
        }

        // ── ParseLog (LogFileParser contract) ─────────────────────────
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
            string username = InferUsername(logFilePath);
            string dbType = InferDbType(logFilePath);
            ParseLines(ReadAllLines(logFilePath).ToList(), username, dbType,
                findings, patternCounts, ref firstSeen, ref lastSeen);
        }

        // ── Public entry point ────────────────────────────────────────
        public (List<string> Findings, Dictionary<string, int> Patterns, DateTime First, DateTime Last)
            ParseFile(string filePath, string username)
        {
            var findings = new List<string>();
            var patterns = new Dictionary<string, int>();
            DateTime first = DateTime.MaxValue, last = DateTime.MinValue;
            var lines = File.Exists(filePath) ? File.ReadAllLines(filePath) : Array.Empty<string>();
            ParseLines(lines, username, InferDbType(filePath),
                findings, patterns, ref first, ref last);
            return (findings, patterns, first, last);
        }

        public override (List<string>, Dictionary<string, int>, DateTime, DateTime) ParseFile(string filePath)
        {
            var (f, p, first, last) = ParseFile(filePath, InferUsername(filePath));
            return (f, p, first, last);
        }

        // ── Core parsing ──────────────────────────────────────────────
        private void ParseLines(
            IReadOnlyList<string> lines,
            string username,
            string dbType,
            List<string> findings,
            Dictionary<string, int> patternCounts,
            ref DateTime firstSeen,
            ref DateTime lastSeen)
        {
            // Accumulate multi-line statements (ending with ;)
            var stmtBuffer = new System.Text.StringBuilder();

            void FlushStatement()
            {
                var stmt = stmtBuffer.ToString().Trim();
                stmtBuffer.Clear();
                if (string.IsNullOrWhiteSpace(stmt)) return;

                string display = stmt.Length > 300 ? stmt[..297] + "..." : stmt;

                bool isCritical = _criticalRegexes.Any(r => r.IsMatch(stmt));
                bool isSuspicious = !isCritical && _suspiciousRegexes.Any(r => r.IsMatch(stmt));

                if (!isCritical && !isSuspicious) return;

                string severity = isCritical ? "HIGH" : "SUSPICIOUS";
                string tag = isCritical ? "[HIGH]" : "[SUSPICIOUS]";

                findings.Add($"[{dbType.ToUpper()}] {tag} user={username}: {display}");
                IncrementPatternCount(patternCounts,
                    isCritical ? $"Critical {dbType} command" : $"Suspicious {dbType} command");

                _normalizedWriter?.Write(NormalizedRecord.From(
                    DateTime.UtcNow, _hostname, "DBHISTORY", dbType,
                    username, string.Empty, display, severity, stmt));
            }

            foreach (var raw in lines)
            {
                if (string.IsNullOrWhiteSpace(raw))
                {
                    FlushStatement();
                    continue;
                }

                // MySQL writes a marker line starting with \
                if (raw.TrimStart().StartsWith("/*") || raw.TrimStart().StartsWith("--"))
                    continue;

                stmtBuffer.AppendLine(raw);

                if (raw.TrimEnd().EndsWith(';'))
                    FlushStatement();
            }

            FlushStatement(); // flush any unterminated statement
        }

        private static string InferDbType(string filePath)
        {
            var fn = Path.GetFileName(filePath).ToLowerInvariant();
            if (fn.Contains("mysql")) return "mysql";
            if (fn.Contains("psql")) return "psql";
            if (fn.Contains("sqlite")) return "sqlite";
            if (fn.Contains("redis")) return "redis";
            return "db";
        }

        private static string InferUsername(string filePath)
        {
            var parts = filePath.Replace('\\', '/').Split('/');
            for (int i = parts.Length - 1; i >= 1; i--)
            {
                var fn = parts[i].ToLowerInvariant();
                if (fn.Contains("history")) return parts[i - 1];
            }
            return "unknown";
        }
    }
}
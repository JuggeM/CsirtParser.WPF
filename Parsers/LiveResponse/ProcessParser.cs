using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Parser.Parsers.LiveResponse
{
    /// <summary>
    /// Parses process-related artifacts from the live_response/processes directory.
    /// Looks for ps_aux.txt, pstree.txt, lsof.txt, and cmdline dumps.
    /// Produces DFIR summaries (process counts, suspicious binaries, parent anomalies).
    /// </summary>
    public class ProcessParser
    {
        private readonly string procRoot;

        public ProcessParser(string processesRoot)
        {
            procRoot = processesRoot;
        }

        /// <summary>
        /// Processes known process listing artifacts and extracts triage findings.
        /// </summary>
        public List<string> Process()
        {
            var findings = new List<string>();

            if (!Directory.Exists(procRoot))
            {
                findings.Add($"[Processes] Missing folder: {procRoot}");
                return findings;
            }

            try
            {
                // --- Parse ps aux output ---
                var psPath = Path.Combine(procRoot, "ps_aux.txt");
                if (File.Exists(psPath))
                    findings.AddRange(ParsePsAux(psPath));

                // --- Parse pstree for parent-child context ---
                var pstreePath = Path.Combine(procRoot, "pstree.txt");
                if (File.Exists(pstreePath))
                    findings.AddRange(ParsePstree(pstreePath));

                // --- Parse lsof for open networked or deleted files ---
                var lsofPath = Path.Combine(procRoot, "lsof.txt");
                if (File.Exists(lsofPath))
                    findings.AddRange(ParseLsof(lsofPath));
            }
            catch (Exception ex)
            {
                findings.Add($"[Processes] Error parsing process data: {ex.Message}");
            }

            if (findings.Count == 0)
                findings.Add("[Processes] No recognizable process-related files found.");

            return findings;
        }

        // -------------------------------------------------------------------
        // --- ps aux parser ---
        // -------------------------------------------------------------------
        private List<string> ParsePsAux(string path)
        {
            var results = new List<string>();
            var lines = SafeReadAllLines(path);

            if (lines.Count == 0)
            {
                results.Add($"[Processes] {Path.GetFileName(path)} is empty.");
                return results;
            }

            // detect header
            var header = lines.FirstOrDefault(l => l.Contains("PID") && l.Contains("COMMAND"));
            if (header != null)
                lines = lines.SkipWhile(l => l != header).Skip(1).ToList();

            var procEntries = new List<(string user, int pid, string cmdline)>();
            var regex = new Regex(@"^\s*(\S+)\s+(\d+)\s+.*?\s+(.+)$", RegexOptions.Compiled);

            foreach (var line in lines)
            {
                var m = regex.Match(line);
                if (m.Success && int.TryParse(m.Groups[2].Value, out var pid))
                    procEntries.Add((m.Groups[1].Value, pid, m.Groups[3].Value.Trim()));
            }

            results.Add($"[Processes] Parsed {procEntries.Count} entries from ps_aux.txt");

            // Suspicious process names / keywords
            string[] susKeywords = {
                "nc ", "netcat", "bash -i", "perl ", "python ", "php ", "curl ", "wget ",
                "nmap", "xmrig", "crypto", "miner", "reverse", "revsh", "socat",
                "pty.spawn", "shell", "sudo su", "dropbear", "kworker", "crontab"
            };

            var susProcs = procEntries
                .Where(p => susKeywords.Any(k => p.cmdline.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0))
                .Take(10)
                .ToList();

            if (susProcs.Count > 0)
            {
                results.Add($"[Processes] ⚠️ Suspicious processes detected ({susProcs.Count} shown):");
                foreach (var p in susProcs)
                    results.Add($"    {p.user,-10} PID={p.pid,-6} CMD={p.cmdline}");
            }

            // Count by user
            var byUser = procEntries.GroupBy(p => p.user)
                                    .Select(g => $"{g.Key}: {g.Count()} processes")
                                    .OrderByDescending(x => x)
                                    .Take(10);
            results.Add("[Processes] Top users by process count:");
            foreach (var entry in byUser)
                results.Add($"    {entry}");

            // Long-running system daemons (heuristic)
            var daemons = procEntries
                .Where(p => p.cmdline.Contains("systemd") || p.cmdline.Contains("sshd") || p.cmdline.Contains("cron"))
                .Take(10)
                .ToList();
            if (daemons.Count > 0)
            {
                results.Add("[Processes] Core daemons (sample):");
                foreach (var d in daemons)
                    results.Add($"    {d.user,-10} PID={d.pid,-6} CMD={d.cmdline}");
            }

            return results;
        }

        // -------------------------------------------------------------------
        // --- pstree parser ---
        // -------------------------------------------------------------------
        private List<string> ParsePstree(string path)
        {
            var results = new List<string>();
            var lines = SafeReadAllLines(path);
            if (lines.Count == 0)
                return results;

            results.Add($"[Processes] Parsed pstree.txt ({lines.Count} lines)");

            // Quick anomaly detection: shells spawned under unexpected parents
            var shellMatches = lines
                .Where(l => Regex.IsMatch(l, @"(bash|sh|zsh|dash|ksh|python|perl|php|ruby)", RegexOptions.IgnoreCase))
                .Take(10)
                .ToList();

            if (shellMatches.Count > 0)
            {
                results.Add($"[Processes] ⚠️ Interactive shells found in pstree (sample):");
                foreach (var l in shellMatches)
                    results.Add($"    {l.Trim()}");
            }

            return results;
        }

        // -------------------------------------------------------------------
        // --- lsof parser ---
        // -------------------------------------------------------------------
        private List<string> ParseLsof(string path)
        {
            var results = new List<string>();
            var lines = SafeReadAllLines(path);
            if (lines.Count == 0)
                return results;

            // Detect deleted binaries or network sockets
            var deleted = lines
                .Where(l => l.Contains("(deleted)"))
                .Take(10)
                .ToList();
            var sockets = lines
                .Where(l => l.Contains("TCP") || l.Contains("UDP"))
                .Take(10)
                .ToList();

            if (deleted.Count > 0)
            {
                results.Add($"[Processes] ⚠️ {deleted.Count} deleted binaries still mapped in memory (sample):");
                foreach (var d in deleted)
                    results.Add($"    {d.Trim()}");
            }

            if (sockets.Count > 0)
            {
                results.Add($"[Processes] Sample of processes with open network sockets:");
                foreach (var s in sockets)
                    results.Add($"    {s.Trim()}");
            }

            return results;
        }

        // -------------------------------------------------------------------
        // --- Helpers ---
        // -------------------------------------------------------------------
        private List<string> SafeReadAllLines(string path)
        {
            try
            {
                return File.ReadAllLines(path).ToList();
            }
            catch
            {
                return new List<string>();
            }
        }
    }
}

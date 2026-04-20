using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Parser.Parsers.LiveResponse
{
    /// <summary>
    /// Parses file system–related artifacts from the live_response/filesystem directory.
    /// Focuses on indicators such as SUID files, world-writable paths, recent file activity,
    /// and suspicious executables in /tmp, /var/tmp, /dev/shm, or user home directories.
    /// </summary>
    public class FileSystemParser
    {
        private readonly string fsRoot;

        public FileSystemParser(string fsRootPath)
        {
            fsRoot = fsRootPath;
        }

        /// <summary>
        /// Process known file system dumps (find, ls, stat) and summarize forensic findings.
        /// </summary>
        public List<string> Process()
        {
            var findings = new List<string>();

            if (!Directory.Exists(fsRoot))
            {
                findings.Add($"[Filesystem] Missing folder: {fsRoot}");
                return findings;
            }

            // --- Parse SUID files ---
            var suidPath = Path.Combine(fsRoot, "suid_files.txt");
            if (File.Exists(suidPath))
            {
                var lines = File.ReadAllLines(suidPath)
                    .Where(l => !string.IsNullOrWhiteSpace(l))
                    .ToList();

                findings.Add($"[Filesystem] {lines.Count} SUID files found:");
                foreach (var l in lines.Take(10))
                    findings.Add($"    {l}");

                if (lines.Count > 10)
                    findings.Add($"    ... (truncated, total {lines.Count})");
            }

            // --- Parse world-writable files ---
            var wwPath = Path.Combine(fsRoot, "world_writable.txt");
            if (File.Exists(wwPath))
            {
                var wwLines = File.ReadAllLines(wwPath)
                    .Where(l => !string.IsNullOrWhiteSpace(l))
                    .ToList();

                findings.Add($"[Filesystem] {wwLines.Count} world-writable files detected");
                foreach (var l in wwLines.Take(10))
                    findings.Add($"    {l}");

                if (wwLines.Count > 10)
                    findings.Add($"    ... (truncated, total {wwLines.Count})");
            }

            // --- Parse recently modified files ---
            var recentPath = Path.Combine(fsRoot, "recent_files.txt");
            if (File.Exists(recentPath))
            {
                var lines = File.ReadAllLines(recentPath);
                var recent = lines
                    .Where(l => !string.IsNullOrWhiteSpace(l))
                    .OrderByDescending(l => l)
                    .Take(10)
                    .ToList();

                findings.Add($"[Filesystem] Showing up to 10 most recent files:");
                foreach (var r in recent)
                    findings.Add($"    {r}");
            }

            // --- Look for suspicious temp or hidden executables ---
            try
            {
                var suspicious = new List<string>();
                var searchDirs = new[] { "/tmp", "/var/tmp", "/dev/shm", "/home" };

                foreach (var d in Directory.GetFiles(fsRoot, "*", SearchOption.AllDirectories))
                {
                    var lower = d.ToLowerInvariant();
                    if (searchDirs.Any(s => lower.Contains(s)) &&
                        (lower.EndsWith(".sh") || lower.EndsWith(".py") || lower.EndsWith(".elf") ||
                         lower.Contains("minerd") || lower.Contains("backdoor") || lower.Contains("revsh")))
                    {
                        suspicious.Add(d);
                    }
                }

                if (suspicious.Count > 0)
                {
                    findings.Add($"[Filesystem] {suspicious.Count} suspicious temp or executable files detected:");
                    foreach (var s in suspicious.Take(10))
                        findings.Add($"    {s}");
                    if (suspicious.Count > 10)
                        findings.Add("    ... (truncated)");
                }
            }
            catch (Exception ex)
            {
                findings.Add($"[Filesystem] Error scanning for suspicious files: {ex.Message}");
            }

            if (findings.Count == 0)
                findings.Add("[Filesystem] No recognizable file system artifacts found.");

            return findings;
        }
    }
}

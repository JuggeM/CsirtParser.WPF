using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Parser.Parsers.LiveResponse
{
    /// <summary>
    /// Parses artifacts collected from UAC's live_response/system directory —
    /// previously not covered at all by LiveResponseParser. Covers three of
    /// the highest-value rootkit/persistence indicators UAC collects:
    ///   - loaded kernel modules (sys_module.yaml / lsmod)
    ///   - login history, successful and failed (last / lastb)
    ///   - hidden files and directories outside user home directories
    /// </summary>
    public class SystemParser
    {
        private readonly string root;

        public SystemParser(string systemRootPath)
        {
            root = systemRootPath;
        }

        public List<string> Process()
        {
            var findings = new List<string>();

            if (!Directory.Exists(root))
            {
                findings.Add($"[System] Missing folder: {root}");
                return findings;
            }

            SummarizeKernelModules(findings);
            SummarizeLoginHistory(findings);
            SummarizeHiddenPaths(findings);
            CheckLdSoPreload(findings);

            if (findings.Count == 0)
                findings.Add("[System] No recognizable system artifact files found.");

            return findings;
        }

        // ── Kernel modules ──────────────────────────────────────────────
        // A near-empty or missing module list on a host that should have one
        // is itself a rootkit indicator (some LKM rootkits hide their own
        // entry from /proc/modules and /sys/module while staying loaded).
        private void SummarizeKernelModules(List<string> findings)
        {
            var path = FirstExisting(new[] { "sys_module.txt", "lsmod.txt", "modules.txt" });
            if (path == null) return;

            var lines = File.ReadAllLines(path)
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .ToList();

            // First line is usually a header ("Module  Size  Used by") for
            // lsmod-style output — don't count it as a module.
            int count = lines.Count(l => !l.TrimStart().StartsWith("Module", StringComparison.OrdinalIgnoreCase));

            findings.Add($"[System] {count} loaded kernel module(s) recorded ({Path.GetFileName(path)})");

            if (count == 0)
                findings.Add("    [SUSPICIOUS] Zero kernel modules reported — " +
                    "verify this isn't a module-hiding rootkit rather than a genuinely module-free host.");
        }

        // ── Login history ────────────────────────────────────────────────
        // last/lastb cover the full login history from wtmp/btmp — broader
        // than the live SessionTracker, which only sees what's in the log
        // rotation window that was actually collected.
        private void SummarizeLoginHistory(List<string> findings)
        {
            var lastPath = FirstExisting(new[] { "last.txt" });
            if (lastPath != null)
            {
                var lines = File.ReadLines(lastPath)
                    .Where(l => !string.IsNullOrWhiteSpace(l)
                             && !l.StartsWith("wtmp begins", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                findings.Add($"[System] {lines.Count} login record(s) in last.txt");

                var rootLogins = lines.Where(l =>
                    l.TrimStart().StartsWith("root ", StringComparison.OrdinalIgnoreCase)).ToList();
                if (rootLogins.Count > 0)
                {
                    findings.Add($"    [HIGH] {rootLogins.Count} direct root login(s) found in history:");
                    foreach (var l in rootLogins.Take(10))
                        findings.Add($"        {l}");
                }
            }

            var lastbPath = FirstExisting(new[] { "lastb.txt" });
            if (lastbPath != null)
            {
                var lines = File.ReadLines(lastbPath)
                    .Where(l => !string.IsNullOrWhiteSpace(l)
                             && !l.StartsWith("btmp begins", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                findings.Add($"[System] {lines.Count} failed login record(s) in lastb.txt");
                if (lines.Count > 0)
                    findings.Add("    [MEDIUM] Failed logins recorded — cross-check against auth.log/secure brute-force findings.");
            }
        }

        // ── Hidden files/directories ─────────────────────────────────────
        // UAC's hidden_files/hidden_directories artifacts already restrict
        // to paths outside user home directories, so any hit here is
        // already somewhat unusual — flag hits inside classic staging
        // directories (/tmp, /dev/shm, /var/tmp) as higher severity.
        private void SummarizeHiddenPaths(List<string> findings)
        {
            var stagingDirs = new[] { "/tmp/", "/dev/shm/", "/var/tmp/" };

            void Summarize(string fileName, string label)
            {
                var path = FirstExisting(new[] { fileName });
                if (path == null) return;

                var lines = File.ReadAllLines(path)
                    .Where(l => !string.IsNullOrWhiteSpace(l))
                    .ToList();

                if (lines.Count == 0) return;

                findings.Add($"[System] {lines.Count} hidden {label} found outside user home directories");

                var staged = lines.Where(l => stagingDirs.Any(d =>
                    l.Contains(d, StringComparison.OrdinalIgnoreCase))).ToList();

                foreach (var l in staged.Take(15))
                    findings.Add($"    [SUSPICIOUS] Hidden {label} in staging directory: {l.Trim()}");
            }

            Summarize("hidden_files.txt", "file(s)");
            Summarize("hidden_directories.txt", "directory(ies)");
        }

        // ── /etc/ld.so.preload ───────────────────────────────────────────
        // A classic LKM-free rootkit / userland hooking technique: any
        // non-empty ld.so.preload forces every dynamically linked binary to
        // load the listed shared object first. On a clean host this file is
        // normally absent or empty, so any content here is worth an analyst
        // looking at directly — this is not a "maybe", it's rare enough that
        // false positives are minimal.
        private void CheckLdSoPreload(List<string> findings)
        {
            var path = FirstExisting(new[] { "ld_so_preload.txt", "ld.so.preload.txt", "ld.so.preload" });
            if (path == null) return;

            var content = File.ReadAllLines(path)
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .ToList();

            if (content.Count == 0) return;

            findings.Add($"[System] [CRITICAL] /etc/ld.so.preload is non-empty ({content.Count} entrie(s)) — " +
                "forces these shared objects into every dynamically linked process:");
            foreach (var l in content)
                findings.Add($"    {l.Trim()}");
        }

        private string FirstExisting(IEnumerable<string> candidates)
        {
            foreach (var name in candidates)
            {
                var p = Path.Combine(root, name);
                if (File.Exists(p)) return p;
            }
            return null;
        }
    }
}

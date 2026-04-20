using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Parser.Parsers.LiveResponse
{
    /// <summary>
    /// Parses persistence-related artifacts under live_response/persistence
    /// (systemd services, cron jobs, rc.local, shell profiles).
    /// </summary>
    public class PersistenceParser
    {
        private readonly string root;
        public PersistenceParser(string persistenceRoot) => root = persistenceRoot;

        public List<string> Process()
        {
            var findings = new List<string>();
            if (!Directory.Exists(root))
            {
                findings.Add($"[Persistence] Missing folder: {root}");
                return findings;
            }

            // systemd services
            var systemdPath = Path.Combine(root, "systemd_services.txt");
            if (File.Exists(systemdPath))
            {
                var lines = File.ReadAllLines(systemdPath).Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
                findings.Add($"[Persistence] systemd services listed: {lines.Count}");
                foreach (var l in lines.Take(10)) findings.Add($"    {l}");
                if (lines.Count > 10) findings.Add($"    ... (truncated, total {lines.Count})");

                var suspect = lines.Where(l =>
                        l.Contains("WantedBy=") ||
                        l.Contains(".service") && (l.Contains("/tmp/") || l.Contains("/dev/shm/") || l.Contains("/var/tmp/")))
                    .Take(10).ToList();
                if (suspect.Any())
                {
                    findings.Add($"[Persistence] ⚠️ Suspicious systemd entries (sample):");
                    foreach (var s in suspect) findings.Add($"    {s}");
                }
            }

            // cron
            var cronPath = Path.Combine(root, "crontab.txt");
            if (File.Exists(cronPath))
            {
                var cron = File.ReadAllLines(cronPath).Where(l => !l.TrimStart().StartsWith("#")).ToList();
                findings.Add($"[Persistence] crontab entries: {cron.Count}");
                foreach (var c in cron.Take(10)) findings.Add($"    {c}");
                if (cron.Count > 10) findings.Add($"    ... (truncated, total {cron.Count})");

                var bad = cron.Where(l => l.Contains("wget ") || l.Contains("curl ") || l.Contains("bash -c") || l.Contains("python ")).Take(10);
                foreach (var b in bad) findings.Add($"    ⚠️ {b}");
            }

            // rc.local
            var rcPath = Path.Combine(root, "rc_local.txt");
            if (File.Exists(rcPath))
            {
                var lines = File.ReadAllLines(rcPath);
                var execs = lines.Where(l => l.Contains("bash ") || l.Contains("sh ") || l.Contains("python ") || l.Contains("nohup ")).Take(10);
                if (execs.Any())
                {
                    findings.Add("[Persistence] rc.local contains executable lines (sample):");
                    foreach (var e in execs) findings.Add($"    {e}");
                }
            }

            // shell profiles
            var bashrcPath = Path.Combine(root, "bashrc.txt");
            if (File.Exists(bashrcPath))
            {
                var lines = File.ReadAllLines(bashrcPath).Where(l => !l.TrimStart().StartsWith("#")).ToList();
                var exports = lines.Where(l => l.StartsWith("export ")).Take(10).ToList();
                if (exports.Any())
                {
                    findings.Add("[Persistence] .bashrc export lines (sample):");
                    foreach (var e in exports) findings.Add($"    {e}");
                }
            }

            if (findings.Count == 0) findings.Add("[Persistence] No recognizable persistence artifacts found.");
            return findings;
        }
    }
}

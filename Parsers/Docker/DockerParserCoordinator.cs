using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using Helpers;
using Output;
using Parsers;

namespace Parser.Docker
{
    /// <summary>
    /// Parses Docker artefacts collected by UAC:
    ///   containers/[id]/config.v2.json  — container metadata
    ///   containers/[id]/[id]-json.log   — container stdout/stderr
    ///   docker.log                      — Docker daemon log
    ///   events.json / docker_events.log — Docker event stream
    ///
    /// DockerMetadataParser, DockerContainerLogParser, DockerEventParser,
    /// DockerImageParser and DockerLogParser are all superseded by this class.
    /// </summary>
    public class DockerParserCoordinator : LogFileParser, IAttachNormalizedWriter
    {
        private readonly string _basePath;
        private NormalizedCsvWriter _normalizedWriter;

        public DockerParserCoordinator(string dockerPath)
        {
            _basePath = dockerPath;
        }

        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        // ── Classification ────────────────────────────────────────────
        //
        // Critical → RTF findings  (near-certain attacker behaviour or escape risk)
        // High     → RTF findings  (significant misconfiguration)
        // Medium   → RTF findings  (notable but context-dependent)
        // Info     → CSV only

        private static readonly string[] SuspiciousExecKeywords =
        {
            "bash -i", "sh -i", "zsh -i",
            "python -c", "python2 -c", "python3 -c",
            "perl -e", "ruby -e", "php -r",
            "nc -e", "nc -l", "netcat", "ncat", "socat",
            "mkfifo", "mknod",
            "/tmp/", "/dev/shm/",
            "base64 -d", "base64 --decode",
            "wget http", "curl http",
            "xmrig", "stratum+tcp",           // cryptominer
            "cmd.php", "shell.php",
            "backdoor", "reverse shell",
        };

        private static readonly string[] DangerousCapabilities =
        {
            "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
            "NET_ADMIN", "NET_RAW", "SYS_RAWIO",
            "DAC_OVERRIDE", "CAP_SYS_ADMIN",
        };

        private static readonly string[] DangerousMounts =
        {
            "/", "/proc", "/dev", "/sys", "/boot",
            "/etc", "/root", "/var/run/docker.sock",
            "docker.sock", "/host",
        };

        // ── Public entry point ────────────────────────────────────────
        public (List<string> findings,
                Dictionary<string, int> patternCounts,
                DateTime firstSeen,
                DateTime lastSeen)
            ProcessLogAndWriteQuickWins()
        {
            return ProcessLogAndReturnFindings(_basePath, _basePath, null, false);
        }

        // ── ParseLog ──────────────────────────────────────────────────
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
            var containers = new List<ContainerInfo>();
            var critFindings = new List<string>();
            var highFindings = new List<string>();
            var medFindings = new List<string>();

            // ── Container metadata ────────────────────────────────────
            string containersPath = Path.Combine(_basePath, "containers");
            if (Directory.Exists(containersPath))
            {
                foreach (var containerDir in Directory.GetDirectories(containersPath))
                {
                    var info = ParseContainerMetadata(containerDir);
                    if (info == null) continue;

                    containers.Add(info);

                    if (!string.IsNullOrEmpty(info.Created) &&
                        DateTime.TryParse(info.Created, out var created))
                    {
                        var utc = created.ToUniversalTime();
                        if (utc < firstSeen) firstSeen = utc;
                        if (utc > lastSeen) lastSeen = utc;
                    }

                    // Tier 1 — Critical: privileged + dangerous mount (container escape)
                    if (info.IsPrivileged && info.DangerousMounts.Count > 0)
                    {
                        critFindings.Add(
                            $"[DOCKER] [CRITICAL] Privileged container with host mount" +
                            $" — {info.Name} ({info.Image})" +
                            $" mounts=[{string.Join(", ", info.DangerousMounts)}]");
                        IncrementPatternCount(patternCounts, "Privileged + host mount (escape risk)");
                    }
                    // Tier 1 — Critical: docker socket mounted (full host takeover)
                    else if (info.DangerousMounts.Any(m =>
                                 m.Contains("docker.sock", StringComparison.OrdinalIgnoreCase)))
                    {
                        critFindings.Add(
                            $"[DOCKER] [CRITICAL] Docker socket mounted in container" +
                            $" — {info.Name} ({info.Image})");
                        IncrementPatternCount(patternCounts, "Docker socket mount");
                    }
                    else
                    {
                        // Tier 2 — High: individual dangerous flags
                        if (info.IsPrivileged)
                        {
                            highFindings.Add(
                                $"[DOCKER] [HIGH] Privileged container" +
                                $" — {info.Name} ({info.Image})");
                            IncrementPatternCount(patternCounts, "Privileged container");
                        }

                        if (info.HostNetwork)
                        {
                            highFindings.Add(
                                $"[DOCKER] [HIGH] Host network mode" +
                                $" — {info.Name} ({info.Image})");
                            IncrementPatternCount(patternCounts, "Host network mode");
                        }

                        if (info.DangerousCapabilities.Count > 0)
                        {
                            highFindings.Add(
                                $"[DOCKER] [HIGH] Dangerous capabilities" +
                                $" [{string.Join(", ", info.DangerousCapabilities)}]" +
                                $" — {info.Name} ({info.Image})");
                            IncrementPatternCount(patternCounts, "Dangerous capabilities");
                        }

                        if (info.DangerousMounts.Count > 0)
                        {
                            highFindings.Add(
                                $"[DOCKER] [HIGH] Dangerous host mount" +
                                $" [{string.Join(", ", info.DangerousMounts)}]" +
                                $" — {info.Name} ({info.Image})");
                            IncrementPatternCount(patternCounts, "Dangerous host mount");
                        }

                        if (info.HostPid)
                        {
                            highFindings.Add(
                                $"[DOCKER] [HIGH] Host PID namespace" +
                                $" — {info.Name} ({info.Image})");
                            IncrementPatternCount(patternCounts, "Host PID namespace");
                        }
                    }

                    // Tier 3 — Medium: suspicious command / running as root
                    if (info.SuspiciousCommands.Count > 0)
                    {
                        medFindings.Add(
                            $"[DOCKER] [MEDIUM] Suspicious command in container" +
                            $" [{string.Join(", ", info.SuspiciousCommands)}]" +
                            $" — {info.Name} ({info.Image})");
                        IncrementPatternCount(patternCounts, "Suspicious container command");
                    }

                    if (info.RunningAsRoot && !info.IsPrivileged)
                    {
                        medFindings.Add(
                            $"[DOCKER] [MEDIUM] Running as root (UID 0)" +
                            $" — {info.Name} ({info.Image})");
                        IncrementPatternCount(patternCounts, "Container running as root");
                    }

                    WriteNormalized(info);
                }
            }

            // ── Container stdout/stderr logs ──────────────────────────
            if (Directory.Exists(containersPath))
            {
                foreach (var containerDir in Directory.GetDirectories(containersPath))
                {
                    string id = Path.GetFileName(containerDir);
                    string logFile = Path.Combine(containerDir, $"{id}-json.log");
                    if (!File.Exists(logFile)) continue;

                    string containerName = containers
                        .FirstOrDefault(c => c.Id.StartsWith(id, StringComparison.OrdinalIgnoreCase))
                        ?.Name ?? id.Substring(0, Math.Min(12, id.Length));

                    try
                    {
                        foreach (var line in File.ReadLines(logFile))
                        {
                            string lineLo = line.ToLowerInvariant();
                            var kw = SuspiciousExecKeywords
                                .FirstOrDefault(k => lineLo.Contains(k.ToLowerInvariant()));
                            if (kw == null) continue;

                            string display = line.Length > 120
                                ? line.Substring(0, 117) + "..."
                                : line;

                            highFindings.Add(
                                $"[DOCKER] [HIGH] Suspicious output in container log" +
                                $" [{kw}] — {containerName}: {display}");
                            IncrementPatternCount(patternCounts, "Suspicious container log output");
                        }
                    }
                    catch { }
                }
            }

            // ── Docker daemon log ─────────────────────────────────────
            string dockerLog = Path.Combine(_basePath, "docker.log");
            if (File.Exists(dockerLog))
                ParseDaemonLog(dockerLog, highFindings, patternCounts);

            // ── Docker event log ──────────────────────────────────────
            foreach (var eventFile in new[]
            {
                Path.Combine(_basePath, "events.json"),
                Path.Combine(_basePath, "docker_events.log"),
                Path.Combine(_basePath, "docker_events.txt"),
            })
            {
                if (File.Exists(eventFile))
                {
                    ParseEventLog(eventFile, medFindings, patternCounts, ref firstSeen, ref lastSeen);
                    break;
                }
            }

            // ── Emit findings: Critical first, then High, then Medium ─
            findings.AddRange(critFindings);
            findings.AddRange(highFindings);
            findings.AddRange(medFindings);

            // ── Write DockerContainers.csv ────────────────────────────
            if (!string.IsNullOrEmpty(outputDir) && containers.Count > 0)
                WriteContainersCsv(outputDir, containers);
        }

        // ── Container metadata parser ─────────────────────────────────
        private ContainerInfo ParseContainerMetadata(string containerDir)
        {
            try
            {
                string configPath = Path.Combine(containerDir, "config.v2.json");
                if (!File.Exists(configPath)) return null;

                var json = JObject.Parse(File.ReadAllText(configPath));

                var info = new ContainerInfo
                {
                    Id = Path.GetFileName(containerDir),
                    Name = json.SelectToken("Name")?.ToString().TrimStart('/') ?? "unknown",
                    Image = json.SelectToken("Config.Image")?.ToString() ?? "unknown",
                    Created = json.SelectToken("Created")?.ToString() ?? string.Empty,
                    State = json.SelectToken("State.Status")?.ToString() ?? "unknown",
                };

                var cmd = json.SelectToken("Config.Cmd")?.ToString() ?? string.Empty;
                var entrypoint = json.SelectToken("Config.Entrypoint")?.ToString() ?? string.Empty;
                info.Command = $"{entrypoint} {cmd}".Trim();

                // Suspicious command in config
                foreach (var kw in SuspiciousExecKeywords)
                    if (info.Command.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        info.SuspiciousCommands.Add(kw);

                // Privileged
                string priv = json.SelectToken("HostConfig.Privileged")?.ToString() ?? "false";
                info.IsPrivileged = priv.Equals("true", StringComparison.OrdinalIgnoreCase);

                // Network mode
                string netMode = json.SelectToken("HostConfig.NetworkMode")?.ToString() ?? string.Empty;
                info.HostNetwork = netMode.Equals("host", StringComparison.OrdinalIgnoreCase);

                // PID / IPC namespace
                string pidMode = json.SelectToken("HostConfig.PidMode")?.ToString() ?? string.Empty;
                info.HostPid = pidMode.Equals("host", StringComparison.OrdinalIgnoreCase);

                // Capabilities
                var capAdd = json.SelectToken("HostConfig.CapAdd");
                if (capAdd != null)
                    foreach (var cap in DangerousCapabilities)
                        if (capAdd.ToString().Contains(cap, StringComparison.OrdinalIgnoreCase))
                            info.DangerousCapabilities.Add(cap);

                // Mounts / binds
                var binds = json.SelectToken("HostConfig.Binds");
                if (binds?.Type == JTokenType.Array)
                {
                    foreach (var bind in binds)
                    {
                        string b = bind.ToString();
                        foreach (var dm in DangerousMounts)
                        {
                            if (b.StartsWith(dm + ":", StringComparison.OrdinalIgnoreCase) ||
                                b.Contains(dm, StringComparison.OrdinalIgnoreCase))
                            {
                                info.DangerousMounts.Add(b);
                                break;
                            }
                        }
                    }
                }

                // Running as root
                string user = json.SelectToken("Config.User")?.ToString() ?? "0";
                info.RunningAsRoot = string.IsNullOrEmpty(user) || user == "0" || user == "root";

                return info;
            }
            catch { return null; }
        }

        // ── Docker daemon log ─────────────────────────────────────────
        private static void ParseDaemonLog(string path,
            List<string> findings, Dictionary<string, int> counts)
        {
            try
            {
                foreach (var line in File.ReadLines(path))
                {
                    if (line.Contains("--privileged", StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(
                            $"[DOCKER] [HIGH] Privileged container launch in daemon log: " +
                            $"{line.Substring(0, Math.Min(120, line.Length))}");
                        IncrementCount(counts, "Privileged launch (daemon log)");
                    }

                    if (Regex.IsMatch(line,
                            @"mount.*(host|/proc|/dev|docker\.sock)",
                            RegexOptions.IgnoreCase))
                    {
                        findings.Add(
                            $"[DOCKER] [HIGH] Suspicious mount in daemon log: " +
                            $"{line.Substring(0, Math.Min(120, line.Length))}");
                        IncrementCount(counts, "Suspicious mount (daemon log)");
                    }
                }
            }
            catch { }
        }

        // ── Docker event log ──────────────────────────────────────────
        private static void ParseEventLog(string path,
            List<string> findings, Dictionary<string, int> counts,
            ref DateTime firstSeen, ref DateTime lastSeen)
        {
            try
            {
                foreach (var line in File.ReadLines(path))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    // Try to extract timestamp from JSON event format
                    var tsM = Regex.Match(line, @"""time""\s*:\s*(\d+)");
                    if (tsM.Success && long.TryParse(tsM.Groups[1].Value, out long epoch))
                    {
                        var ts = DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime;
                        if (ts < firstSeen) firstSeen = ts;
                        if (ts > lastSeen) lastSeen = ts;
                    }

                    // Flag privilege escalation events
                    if (line.Contains("\"privileged\":true", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("--privileged", StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(
                            $"[DOCKER] [MEDIUM] Privileged container event: " +
                            $"{line.Substring(0, Math.Min(120, line.Length))}");
                        IncrementCount(counts, "Privileged event");
                    }
                }
            }
            catch { }
        }

        // ── Normalized CSV ────────────────────────────────────────────
        private void WriteNormalized(ContainerInfo c)
        {
            if (_normalizedWriter == null) return;

            string severity = "Info";
            if (c.IsPrivileged && c.DangerousMounts.Count > 0) severity = "Critical";
            else if (c.IsPrivileged || c.HostNetwork || c.DangerousCapabilities.Count > 0) severity = "High";
            else if (c.SuspiciousCommands.Count > 0 || c.RunningAsRoot) severity = "Medium";

            string msg = $"Container={c.Name} Image={c.Image} State={c.State}";
            if (c.IsPrivileged) msg += " [PRIVILEGED]";
            if (c.HostNetwork) msg += " [HOST_NETWORK]";
            if (c.HostPid) msg += " [HOST_PID]";
            if (c.DangerousMounts.Count > 0) msg += $" [MOUNTS:{string.Join(";", c.DangerousMounts)}]";

            DateTime ts = DateTime.MinValue;
            if (!string.IsNullOrEmpty(c.Created) && DateTime.TryParse(c.Created, out var created))
                ts = created.ToUniversalTime();

            _normalizedWriter.Write(NormalizedRecord.From(
                ts, string.Empty, "DOCKER", "docker",
                string.Empty, string.Empty, msg, severity,
                $"ID={c.Id} Name={c.Name} Image={c.Image}"));
        }

        // ── DockerContainers.csv ──────────────────────────────────────
        private static void WriteContainersCsv(string outputDir, List<ContainerInfo> containers)
        {
            try
            {
                string csvPath = Path.Combine(outputDir, "DockerContainers.csv");
                using var w = new StreamWriter(csvPath, append: false);
                w.WriteLine("ContainerID,Name,Image,State,Created,Privileged,HostNetwork," +
                            "HostPid,RunningAsRoot,DangerousCapabilities,DangerousMounts," +
                            "SuspiciousCommands,Command");

                static string E(string s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";

                foreach (var c in containers)
                {
                    w.WriteLine(string.Join(",",
                        E(c.Id.Substring(0, Math.Min(12, c.Id.Length))),
                        E(c.Name),
                        E(c.Image),
                        E(c.State),
                        E(c.Created),
                        c.IsPrivileged ? "TRUE" : "FALSE",
                        c.HostNetwork ? "TRUE" : "FALSE",
                        c.HostPid ? "TRUE" : "FALSE",
                        c.RunningAsRoot ? "TRUE" : "FALSE",
                        E(string.Join("; ", c.DangerousCapabilities)),
                        E(string.Join("; ", c.DangerousMounts)),
                        E(string.Join("; ", c.SuspiciousCommands)),
                        E(c.Command.Length > 200 ? c.Command.Substring(0, 197) + "..." : c.Command)
                    ));
                }
            }
            catch { }
        }

        // ── Helpers ───────────────────────────────────────────────────
        private static void IncrementCount(Dictionary<string, int> d, string key)
        {
            d[key] = d.TryGetValue(key, out var v) ? v + 1 : 1;
        }

        // ── Container model ───────────────────────────────────────────
        private sealed class ContainerInfo
        {
            public string Id { get; set; } = string.Empty;
            public string Name { get; set; } = string.Empty;
            public string Image { get; set; } = string.Empty;
            public string State { get; set; } = string.Empty;
            public string Created { get; set; } = string.Empty;
            public string Command { get; set; } = string.Empty;
            public bool IsPrivileged { get; set; }
            public bool HostNetwork { get; set; }
            public bool HostPid { get; set; }
            public bool HostIpc { get; set; }
            public bool RunningAsRoot { get; set; }
            public List<string> DangerousCapabilities { get; } = new();
            public List<string> DangerousMounts { get; } = new();
            public List<string> SuspiciousCommands { get; } = new();
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;

namespace Helpers
{
    public class SessionTracker
    {
        private readonly Dictionary<string, List<Session>> _allSessions = new();
        private readonly List<Session> _suspiciousSessions = new();
        private readonly Dictionary<string, int> _failedAttemptsByIP = new();

        /// <summary>
        /// Number of failed logins from a single IP before it is flagged as a
        /// brute-force source.  Defaults to 5; set from ParserConfig.BruteForceThreshold.
        /// </summary>
        private readonly int _bruteForceThreshold;

        /// <summary>
        /// Number of failed logins before a *successful* session from the same IP
        /// is also flagged.  Always 2× the brute-force threshold.
        /// </summary>
        private int SuccessAfterBruteThreshold => _bruteForceThreshold * 2;

        public SessionTracker(int bruteForceThreshold = 5)
        {
            _bruteForceThreshold = Math.Max(1, bruteForceThreshold);
        }

        private static readonly HashSet<string> ServiceAccounts = new(StringComparer.OrdinalIgnoreCase)
        {
            "www-data", "apache", "nginx", "httpd", "mysql", "postgres", "postgresql",
            "redis", "mongodb", "nobody", "daemon", "bin", "sys", "sync", "games",
            "man", "lp", "mail", "news", "uucp", "proxy", "backup", "list", "irc",
            "gnats", "_apt", "messagebus", "systemd-network", "systemd-resolve"
        };

        private static readonly HashSet<string> NoisyDaemons = new(StringComparer.OrdinalIgnoreCase)
        {
            "CRON", "ANACRON", "ATD", "SYSTEMD", "SYSTEMD-USER"
        };

        // ── Session lifecycle ─────────────────────────────────────────────

        public void AddSessionOpen(string user, string ip, DateTime startTime, string daemon)
        {
            string key = $"{user}|{ip ?? "NO_IP"}|{daemon ?? "UNKNOWN"}";

            if (!_allSessions.ContainsKey(key))
                _allSessions[key] = new List<Session>();

            var session = new Session
            {
                Username = user,
                SourceIP = ip ?? "N/A",
                Daemon = daemon ?? "unknown",
                StartTime = startTime,
                EndTime = null,
                DurationSeconds = 0,
                Type = CategorizeSession(user, ip, daemon, null),
                IsSuspicious = false,
                Notes = ""
            };

            _allSessions[key].Add(session);
        }

        public void AddSessionClose(string user, string ip, DateTime closeTime, string daemon)
        {
            string key = $"{user}|{ip ?? "NO_IP"}|{daemon ?? "UNKNOWN"}";

            if (_allSessions.TryGetValue(key, out var sessionList))
            {
                var openSession = sessionList.LastOrDefault(s => !s.EndTime.HasValue);
                if (openSession != null)
                {
                    openSession.EndTime = closeTime;
                    openSession.DurationSeconds = (int)(closeTime - openSession.StartTime).TotalSeconds;
                    openSession.Type = CategorizeSession(user, ip, daemon, openSession.DurationSeconds);
                    CheckSuspicious(openSession);
                }
            }
        }

        public void RecordFailedLogin(string user, string ip, DateTime timestamp, string daemon)
        {
            if (!string.IsNullOrEmpty(ip) && ip != "N/A")
            {
                _failedAttemptsByIP[ip] = _failedAttemptsByIP.TryGetValue(ip, out var prev) ? prev + 1 : 1;
            }

            var failedSession = new Session
            {
                Username = user,
                SourceIP = ip ?? "N/A",
                Daemon = daemon ?? "sshd",
                StartTime = timestamp,
                EndTime = timestamp,
                DurationSeconds = 0,
                Type = SessionType.SshFailed,
                IsSuspicious = false,
                Notes = "Failed authentication"
            };

            // Flag once the configurable threshold is reached.
            if (!string.IsNullOrEmpty(ip) && ip != "N/A"
                && _failedAttemptsByIP[ip] >= _bruteForceThreshold)
            {
                failedSession.IsSuspicious = true;
                failedSession.SuspicionReason = SuspicionReason.MultipleFailures;
                failedSession.Notes = $"Failed attempt #{_failedAttemptsByIP[ip]} from this IP";
            }

            string key = $"{user}|{ip ?? "NO_IP"}|{daemon ?? "UNKNOWN"}";
            if (!_allSessions.ContainsKey(key))
                _allSessions[key] = new List<Session>();

            _allSessions[key].Add(failedSession);

            if (failedSession.IsSuspicious)
                _suspiciousSessions.Add(failedSession);
        }

        // ── Session categorisation ────────────────────────────────────────

        private SessionType CategorizeSession(string user, string ip, string daemon, int? durationSeconds)
        {
            var daemonLower = (daemon ?? "").ToLowerInvariant();

            if (daemonLower.Contains("cron") || daemonLower.Contains("atd") || daemonLower.Contains("anacron"))
                return SessionType.CronJob;

            if (daemonLower.Contains("systemd"))
                return SessionType.SystemdSession;

            if (durationSeconds.HasValue && durationSeconds.Value <= 2 &&
                (string.IsNullOrEmpty(ip) || ip == "N/A" || ip.StartsWith("127.") || ip.StartsWith("::1")))
                return SessionType.SudoCommand;

            if (daemonLower.Contains("sshd") || daemonLower.Contains("ssh"))
                if (!string.IsNullOrEmpty(ip) && ip != "N/A" && !ip.StartsWith("127."))
                    return SessionType.SshInteractive;

            if (daemonLower.Contains("su") && durationSeconds.HasValue && durationSeconds.Value <= 5)
                return SessionType.SuCommand;

            if (ServiceAccounts.Contains(user))
                return SessionType.ServiceAuth;

            return SessionType.PamGeneric;
        }

        // ── Suspicious checks ─────────────────────────────────────────────

        private void CheckSuspicious(Session session)
        {
            if (session.IsSuspicious) return;

            var ip = session.SourceIP ?? "N/A";

            // Service account with interactive SSH
            if (ServiceAccounts.Contains(session.Username) && session.Type == SessionType.SshInteractive)
            {
                MarkSuspicious(session, SuspicionReason.ServiceAccountSSH, "Service account with SSH session");
                return;
            }

            // Direct root SSH from non-local IP
            if (session.Username.Equals("root", StringComparison.OrdinalIgnoreCase)
                && session.Type == SessionType.SshInteractive
                && ip != "N/A" && !ip.StartsWith("127.") && !ip.StartsWith("::1"))
            {
                MarkSuspicious(session, SuspicionReason.RootSSH, "Direct root SSH login");
                return;
            }

            // Very short interactive session from external IP (possible probe or failed command)
            if (session.DurationSeconds < 1 && session.Type == SessionType.SshInteractive
                && ip != "N/A" && !IsLocalIP(ip))
            {
                MarkSuspicious(session, SuspicionReason.VeryShortWithIP, "Very short SSH session from external IP");
                return;
            }

            // Unusual hour (02:00–04:59)
            if (session.Type == SessionType.SshInteractive
                && session.StartTime.Hour >= 2 && session.StartTime.Hour < 5)
            {
                MarkSuspicious(session, SuspicionReason.UnusualTime,
                    $"Interactive session at unusual time ({session.StartTime.Hour}:00)");
                return;
            }

            // Successful login from an IP that previously triggered brute-force detection
            if (ip != "N/A"
                && _failedAttemptsByIP.TryGetValue(ip, out var failCount)
                && failCount >= SuccessAfterBruteThreshold)
            {
                MarkSuspicious(session, SuspicionReason.MultipleFailures,
                    $"IP has {failCount} failed attempts before this success");
            }
        }

        private void MarkSuspicious(Session session, SuspicionReason reason, string notes)
        {
            session.IsSuspicious = true;
            session.SuspicionReason = reason;
            session.Notes = notes;
            _suspiciousSessions.Add(session);
        }

        private static bool IsLocalIP(string ip)
        {
            if (string.IsNullOrEmpty(ip) || ip == "N/A") return true;
            if (ip.StartsWith("127.") || ip.StartsWith("::1")) return true;
            if (ip.StartsWith("10.")) return true;
            if (ip.StartsWith("192.168.")) return true;
            if (ip.StartsWith("172.") && ip.Split('.').Length > 1
                && int.TryParse(ip.Split('.')[1], out var b) && b >= 16 && b <= 31) return true;
            return false;
        }

        // ── Public API ────────────────────────────────────────────────────

        /// <summary>Backward-compatible alias kept for existing callers.</summary>
        public List<string> GenerateSummary(string logType) => GenerateSuspiciousSummary(logType);

        public List<string> GenerateSuspiciousSummary(string logType)
        {
            var summary = new List<string>();

            if (_suspiciousSessions.Count == 0)
            {
                summary.Add($"[{logType}] No suspicious sessions detected.");
                return summary;
            }

            summary.Add($"[{logType}] === SUSPICIOUS SESSIONS ({_suspiciousSessions.Count} detected) ===");

            foreach (var session in _suspiciousSessions.OrderBy(s => s.StartTime))
            {
                string endStr = session.EndTime.HasValue
                    ? session.EndTime.Value.ToString("yyyy-MM-dd HH:mm:ss") : "ongoing";
                summary.Add(
                    $"[{logType}] [SUSPICIOUS] [{session.SuspicionReason}] " +
                    $"User: {session.Username} | IP: {session.SourceIP} | " +
                    $"Type: {session.Type} | Started: {session.StartTime:yyyy-MM-dd HH:mm:ss} | " +
                    $"Ended: {endStr} | Duration: {session.DurationSeconds}s | {session.Notes}");
            }

            return summary;
        }

        public List<Session> GetAllSessions()
            => _allSessions.Values.SelectMany(s => s).OrderBy(s => s.StartTime).ToList();

        public List<Session> GetSuspiciousSessions()
            => _suspiciousSessions.OrderBy(s => s.StartTime).ToList();

        public Dictionary<string, int> GetStatistics()
        {
            var all = GetAllSessions();
            return new Dictionary<string, int>
            {
                { "Total Sessions",      all.Count },
                { "Suspicious Sessions", _suspiciousSessions.Count },
                { "SSH Interactive",     all.Count(s => s.Type == SessionType.SshInteractive) },
                { "Failed Logins",       all.Count(s => s.Type == SessionType.SshFailed) },
                { "Sudo Commands",       all.Count(s => s.Type == SessionType.SudoCommand) },
                { "Cron Jobs",           all.Count(s => s.Type == SessionType.CronJob) },
                { "Unique IPs",          all.Select(s => s.SourceIP).Where(ip => ip != "N/A").Distinct().Count() }
            };
        }
    }
}
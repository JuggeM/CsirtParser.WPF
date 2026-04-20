using System;
using System.Collections.Generic;
using System.Linq;

namespace Helpers
{
    /// <summary>
    /// Tracks web request patterns to detect:
    ///   1. Brute-force attempts (many 401/403 on login endpoints from one IP)
    ///   2. Potentially successful brute-force (failures followed by a 200/302
    ///      on the same endpoint from the same IP)
    /// </summary>
    public class WebBruteForceDetector
    {
        private readonly int _threshold;

        // Per-IP tracking
        private readonly Dictionary<string, IpState> _states = new();

        private static readonly HashSet<string> SuspiciousEndpoints = new(
            StringComparer.OrdinalIgnoreCase)
        {
            // WordPress
            "/wp-login.php", "/xmlrpc.php", "/wp-admin",

            // Generic login / admin panels
            "/login", "/admin", "/user/login", "/auth/login", "/account/login",
            "/dashboard", "/signin", "/cpanel", "/webmail", "/admin/login", "/adminpanel",

            // Application-specific
            "/phpmyadmin", "/roundcube", "/adminer", "/manager/html",
            "/joomla/administrator", "/typo3", "/drupal", "/zabbix", "/nagios",
            "/openwebmail", "/webmin",

            // API and token endpoints
            "/api/auth", "/oauth/token", "/v1/login", "/auth/token", "/auth/session",

            // SSH / web console paths
            "/shell", "/console", "/ssh", "/remoteDesktop", "/term.cgi", "/webshell",

            // Known exploit targets
            "/.env", "/config.json", "/.git", "/actuator", "/debug"
        };

        /// <param name="threshold">
        /// Number of denied requests per IP before flagging as brute-force.
        /// Defaults to 10.
        /// </param>
        public WebBruteForceDetector(int threshold = 10)
        {
            _threshold = threshold < 1 ? 10 : threshold;
        }

        public void Track(string ip, string uri, string method,
                          string status, string agent, DateTime timestamp)
        {
            if (!int.TryParse(status, out int statusCode)) return;

            string uriLo = uri.ToLowerInvariant();
            bool hitsEndpoint = SuspiciousEndpoints.Any(e => uriLo.Contains(e));
            if (!hitsEndpoint) return;

            if (!_states.TryGetValue(ip, out var state))
            {
                state = new IpState();
                _states[ip] = state;
            }

            bool isDenied = statusCode == 401 || statusCode == 403;
            bool isSuccess = statusCode == 200 || statusCode == 302;

            if (isDenied)
            {
                state.FailureCount++;
                state.Uris.Add(uri);
                if (state.FirstFailure == default) state.FirstFailure = timestamp;
                state.LastFailure = timestamp;
            }
            else if (isSuccess && state.FailureCount >= _threshold)
            {
                // Success after enough failures on the same endpoint = suspicious
                state.SuccessAfterFailure = true;
                state.SuccessUri = uri;
                state.SuccessStatus = statusCode;
                state.SuccessTimestamp = timestamp;
            }
        }

        public List<string> GetFindings()
        {
            var findings = new List<string>();

            foreach (var (ip, state) in _states
                .Where(kv => kv.Value.FailureCount >= _threshold)
                .OrderByDescending(kv => kv.Value.FailureCount))
            {
                string uriList = string.Join(", ",
                    state.Uris.Distinct().Take(5));
                if (state.Uris.Distinct().Count() > 5)
                    uriList += $" … (+{state.Uris.Distinct().Count() - 5} more)";

                string timeRange = state.FirstFailure != default
                    ? $"{state.FirstFailure:yyyy-MM-dd HH:mm:ss} \u2192 {state.LastFailure:yyyy-MM-dd HH:mm:ss} UTC"
                    : "unknown time";

                if (state.SuccessAfterFailure)
                {
                    // Potentially successful brute-force — highlight prominently
                    findings.Add(
                        $"[WEBLOG] [BRUTEFORCE] [POSSIBLE SUCCESS] " +
                        $"IP {ip} — {state.FailureCount} failures [{timeRange}] " +
                        $"then {state.SuccessStatus} on {state.SuccessUri} " +
                        $"at {state.SuccessTimestamp:yyyy-MM-dd HH:mm:ss} UTC " +
                        $"| Endpoints hit: {uriList}");
                }
                else
                {
                    findings.Add(
                        $"[WEBLOG] [BRUTEFORCE] " +
                        $"IP {ip} — {state.FailureCount} denied requests [{timeRange}] " +
                        $"| Endpoints: {uriList}");
                }
            }

            // Sort: possible successes first, then by failure count
            findings.Sort((a, b) =>
            {
                bool aSucc = a.Contains("[POSSIBLE SUCCESS]");
                bool bSucc = b.Contains("[POSSIBLE SUCCESS]");
                if (aSucc != bSucc) return aSucc ? -1 : 1;
                return 0;
            });

            return findings;
        }

        private sealed class IpState
        {
            public int FailureCount { get; set; }
            public DateTime FirstFailure { get; set; }
            public DateTime LastFailure { get; set; }
            public HashSet<string> Uris { get; } = new(StringComparer.OrdinalIgnoreCase);
            public bool SuccessAfterFailure { get; set; }
            public string SuccessUri { get; set; }
            public int SuccessStatus { get; set; }
            public DateTime SuccessTimestamp { get; set; }
        }
    }
}
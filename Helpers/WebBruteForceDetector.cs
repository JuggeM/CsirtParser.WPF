using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Helpers
{
    /// <summary>
    /// Web login brute force, accumulated across all web log files of a collection.
    ///
    /// Counted as a failed attempt:
    ///   • a POST to a login endpoint that is NOT a redirect — most web apps
    ///     (WordPress included) answer a wrong password with 200 and the form again;
    ///   • any 401/403 on a login or admin endpoint (HTTP basic auth, WAF denials).
    /// Counted as a success:
    ///   • a 302/303 answer to a login POST (the app redirects after a good login),
    ///     or a 2xx on an endpoint that previously only returned 401/403.
    /// xmlrpc.php POSTs are counted as attempts (system.multicall brute force)
    /// but never as success, since they always return 200.
    /// </summary>
    public class WebBruteForceDetector
    {
        private readonly int _threshold;
        private readonly Dictionary<string, IpState> _states = new();

        // Form login endpoints: POST = one password attempt
        private static readonly Regex LoginPost = new(
            @"/(?:wp-login\.php|xmlrpc\.php|login(?:\.php)?|signin|sign-in|logon|auth(?:/login|/session|/token)?|" +
            @"user/login|account/login|admin/login|administrator/index\.php|session|oauth/token|api/(?:v\d+/)?(?:auth|login|token))(?:$|[/?#])",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Endpoints where 401/403 means a denied login (basic auth, admin panels)
        private static readonly Regex ProtectedEndpoint = new(
            @"/(?:wp-admin|admin|administrator|manager/html|phpmyadmin|adminer|webmin|cpanel|webmail|roundcube|zabbix|nagios|login|signin|api/)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <param name="threshold">Failed attempts from one IP before it is reported (default 10).</param>
        public WebBruteForceDetector(int threshold = 10)
        {
            _threshold = threshold < 1 ? 10 : threshold;
        }

        public void Track(string ip, string uri, string method,
                          string status, string agent, DateTime timestamp)
        {
            if (!int.TryParse(status, out int code)) return;
            var path = (uri ?? string.Empty).Split('?')[0];
            bool isPost = string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase);
            bool loginPost = isPost && LoginPost.IsMatch(path);
            bool isXmlRpc = path.EndsWith("xmlrpc.php", StringComparison.OrdinalIgnoreCase);
            bool protectedHit = ProtectedEndpoint.IsMatch(path);
            if (!loginPost && !protectedHit) return;

            if (!_states.TryGetValue(ip, out var s))
                _states[ip] = s = new IpState();

            bool failed =
                (loginPost && !(code is 301 or 302 or 303) && !(isXmlRpc && code >= 500))
                || ((code is 401 or 403) && protectedHit);

            if (failed)
            {
                s.Failures++;
                s.Endpoints.Add(path);
                if (s.FirstFailure == default || timestamp < s.FirstFailure) s.FirstFailure = timestamp;
                if (timestamp > s.LastFailure) s.LastFailure = timestamp;
                if (!string.IsNullOrWhiteSpace(agent)) s.Agents.Add(agent);
                return;
            }

            bool success = !isXmlRpc && s.Failures >= _threshold && s.SuccessAt == default && (
                (loginPost && code is 302 or 303) ||
                (code is >= 200 and < 300 && protectedHit && s.Endpoints.Contains(path)));
            if (success)
            {
                s.SuccessAt = timestamp;
                s.SuccessPath = path;
                s.SuccessStatus = code;
                s.FailuresBeforeSuccess = s.Failures;
            }
        }

        /// <summary>Finished QuickWins finding lines ("[WEB] [SEVERITY] [time] …").</summary>
        public List<string> GetFindings()
        {
            var findings = new List<(int Rank, string Line)>();

            foreach (var (ip, s) in _states.Where(kv => kv.Value.Failures >= _threshold))
            {
                var endpoints = string.Join(", ", s.Endpoints.Take(5)) +
                                (s.Endpoints.Count > 5 ? $" (+{s.Endpoints.Count - 5} more)" : "");
                var agent = s.Agents.Count == 0 ? "" : $" | user agent: {s.Agents.First()}" +
                            (s.Agents.Count > 1 ? $" (+{s.Agents.Count - 1} more)" : "");

                if (s.SuccessAt != default)
                {
                    findings.Add((0,
                        $"[WEB] [CRITICAL] [{s.SuccessAt:yyyy-MM-dd HH:mm:ss} UTC] Web login brute force succeeded: " +
                        $"{ip} got {s.SuccessStatus} on {s.SuccessPath} after {s.FailuresBeforeSuccess} failed attempt(s) " +
                        $"since {s.FirstFailure:yyyy-MM-dd HH:mm:ss} UTC | endpoints: {endpoints}{agent}"));
                }
                else
                {
                    findings.Add((1,
                        $"[WEB] [HIGH] [{s.FirstFailure:yyyy-MM-dd HH:mm:ss} → {s.LastFailure:yyyy-MM-dd HH:mm:ss} UTC] " +
                        $"Web login brute force: {ip} made {s.Failures} failed attempt(s), no success seen | endpoints: {endpoints}{agent}"));
                }
            }

            return findings.OrderBy(f => f.Rank).ThenBy(f => f.Line, StringComparer.Ordinal).Select(f => f.Line).ToList();
        }

        private sealed class IpState
        {
            public int Failures;
            public DateTime FirstFailure, LastFailure;
            public HashSet<string> Endpoints { get; } = new(StringComparer.OrdinalIgnoreCase);
            public HashSet<string> Agents { get; } = new(StringComparer.Ordinal);
            public DateTime SuccessAt;
            public string SuccessPath = "";
            public int SuccessStatus;
            public int FailuresBeforeSuccess;
        }
    }
}

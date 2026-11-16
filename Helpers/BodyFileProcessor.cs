using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Parser.Models;
using CsirtParser.WPF.Models;

namespace Helpers
{
    public static class BodyFileProcessor
    {
        // ── Fallback constants (used only when no config is passed) ──────────
        // These match the defaults on ParserConfig so behaviour is unchanged
        // if ProcessBodyFile is called without a config object.
        private const int DefaultMinScore = 6;
        private const bool DefaultRequireKeyword = true;
        private const int DefaultRecentDays = 30;
        private const long DefaultMinSize = 1024;
        private const int DefaultMaxPerFolder = 10;

        private static readonly string[] DefaultSuspiciousKeywords =
        {
            "reverse_shell","backdoor","mimikatz","c2","creds","payload","dump",
            "chattr","shadow","netcat","nc ","/nc","suid","exploit","ps1",
            "lateral","exfil","xmr","xmrig","crypto","miner","bash -i","socat",
            "pkexec","wget","curl","/bash -i"
        };

        private static readonly string[] DefaultWhitelistPrefixes =
        {
            "/usr/","/lib","/etc/","/proc/","/sys/","/boot/","/dev/","/bin/","/sbin/",
            "/var/log/","/var/cache/","/var/run/","/var/tmp/","/var/lib/",
            "/opt/CrowdStrike/","/tmp/CSIRT_Collection/"
        };

        // These are always applied regardless of config — web-framework cache files
        // that are never suspicious no matter how they score.
        private static readonly string[] FrameworkCacheSubstrings =
        {
            "/phpMyAdmin/tmp/twig/",
            "/twig/cache/",
            "/smarty/templates_c/",
            "/cache/smarty/",
            "/compiled/",
            "/symfony/cache/",
            "/laravel/cache/",
            "storage/framework/cache/",
            "storage/framework/views/",
            "/doctrine/cache/",
            "/phpfastcache/",
            "/__pycache__/",
            "/.git/objects/",
        };

        private static readonly string[] SuspiciousPathHints =
        {
            "/tmp","/dev/shm","/var/tmp","/run","/root","/home","/mnt","/media"
        };

        private static readonly string[] BenignExtensions =
        {
            ".log",".conf",".cfg",".cnf",".ini",".repo",".service",".socket",
            ".target",".wants",".txt",".json",".xml",".yaml",".yml",".md",
            ".html",".htm",".css",".js",
            ".rpmnew",".rpmsave",".bak",".old",".save",".tmp",".swp",".lock"
        };

        private static readonly string[] ExecutableExtensions =
        {
            ".elf",".bin",".run",".so"
        };

        // ── Public entry point ───────────────────────────────────────────────

        /// <param name="config">
        /// When non-null all analyst-configurable thresholds, keyword lists, and
        /// whitelist prefixes are taken from here.  When null the built-in defaults
        /// are used (same behaviour as before the refactor).
        /// </param>
        public static ParsedBodyFile ProcessBodyFile(
            string bodyFilePath,
            string outputDir,
            ParserConfig? config = null)
        {
            // Resolve effective settings — config wins over built-in defaults.
            int minScore = config?.BodyFileMinScore ?? DefaultMinScore;
            bool requireKw = config?.BodyFileRequireKeyword ?? DefaultRequireKeyword;
            int recentDays = config?.BodyFileRecencyDays ?? DefaultRecentDays;
            long minSize = config?.BodyFileMinSizeBytes ?? DefaultMinSize;
            int maxPerFolder = config?.BodyFileMaxFindingsFolder ?? DefaultMaxPerFolder;

            IReadOnlyList<string> suspiciousKeywords =
                config?.BodyFileSuspiciousKeywords?.Count > 0
                    ? config.BodyFileSuspiciousKeywords.ToList()
                    : DefaultSuspiciousKeywords;

            IReadOnlyList<string> whitelistPrefixes =
                config?.BodyFileWhitelistPrefixes?.Count > 0
                    ? config.BodyFileWhitelistPrefixes.ToList()
                    : DefaultWhitelistPrefixes;

            return ParseInternal(
                bodyFilePath,
                minScore, requireKw, recentDays, minSize, maxPerFolder,
                suspiciousKeywords, whitelistPrefixes);
        }

        // ── Internal parser ──────────────────────────────────────────────────
        // bodyfile v3: md5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime

        private static ParsedBodyFile ParseInternal(
            string bodyFilePath,
            int minScore,
            bool requireKeyword,
            int recentDaysWindow,
            long minSizeForSuspicion,
            int maxFindingsPerFolder,
            IReadOnlyList<string> suspiciousKeywords,
            IReadOnlyList<string> whitelistPrefixes)
        {
            var parsed = new ParsedBodyFile
            {
                Entries = new List<BodyFileEntry>(),
                Findings = new List<string>(),
                FirstLogUtc = DateTime.MinValue,
                LastLogUtc = DateTime.MinValue
            };

            if (string.IsNullOrWhiteSpace(bodyFilePath) || !File.Exists(bodyFilePath))
                return parsed;

            // Dedup & cap structures
            var bestByPath = new Dictionary<string, (int Score, string Reason, DateTime? MUtc, long Size)>(
                                   StringComparer.OrdinalIgnoreCase);
            var countByFolder = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var tempDrops = new List<string>();

            foreach (var line in File.ReadLines(bodyFilePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (line[0] == '#') continue;
                if (line.Count(c => c == '|') < 10) continue;

                var parts = line.Split('|');
                if (parts.Length < 11) continue;

                try
                {
                    var path = parts[1];
                    var size = long.TryParse(parts[6], out var sz) ? sz : 0L;
                    var atEpoch = TryParseLong(parts[7]);
                    var mtEpoch = TryParseLong(parts[8]);
                    var ctEpoch = TryParseLong(parts[9]);
                    var btEpoch = TryParseLong(parts[10]);

                    var mode = parts[3];
                    parsed.Entries.Add(new BodyFileEntry
                    {
                        Path = path,
                        Size = size,
                        Mode = mode,
                        UID = parts[4],
                        GID = parts[5],
                        MD5 = parts[0] == "0" ? string.Empty : parts[0],
                        AccessEpoch = atEpoch,
                        ModifyEpoch = mtEpoch,
                        ChangeEpoch = ctEpoch,
                        BirthEpoch = btEpoch
                    });

                    // Update timeline coverage
                    foreach (var epoch in new[] { atEpoch, mtEpoch, ctEpoch, btEpoch })
                    {
                        var utc = ToUtc(epoch);
                        if (!utc.HasValue) continue;
                        if (parsed.FirstLogUtc == DateTime.MinValue || utc.Value < parsed.FirstLogUtc)
                            parsed.FirstLogUtc = utc.Value;
                        if (utc.Value > parsed.LastLogUtc)
                            parsed.LastLogUtc = utc.Value;
                    }

                    // ── Executable / hidden file in a world-writable temp dir ────
                    // Always reported (before the whitelist, which covers /var/tmp/):
                    // droppers and miners live here, and it's rare for anything
                    // legitimate to be executable there.
                    if (IsTempDropCandidate(path, mode, out var why))
                    {
                        var tmUtc = ToUtc(mtEpoch);
                        tempDrops.Add(
                            $"[BODYFILE] [{(why == "Hidden file" ? "MEDIUM" : "HIGH")}] {(tmUtc.HasValue ? $"[{tmUtc:yyyy-MM-dd HH:mm:ss} UTC] " : "")}" +
                            $"{why} in temp dir: {path} (mode {mode}, uid {parts[4]}, size {size})");
                        continue;
                    }

                    // ── Noise suppression ────────────────────────────────────────
                    if (IsWhitelistedPath(path, whitelistPrefixes)) continue;
                    if (IsFrameworkCache(path)) continue;
                    if (HasBenignExtension(path)) continue;

                    // ── Scoring ──────────────────────────────────────────────────
                    var lower = (path ?? string.Empty).ToLowerInvariant();
                    int score = 0;
                    var reasons = new List<string>();

                    // Suspicious path hint (+2)
                    if (SuspiciousPathHints.Any(h => lower.Contains(h, StringComparison.Ordinal)))
                    { score += 2; reasons.Add("PathHint=2"); }

                    // Suspicious keyword (+3)
                    bool hadKeyword = false;
                    if (suspiciousKeywords.Any(k => lower.Contains(k, StringComparison.Ordinal)))
                    { score += 3; reasons.Add("Keyword=3"); hadKeyword = true; }

                    // Executable-ish extension (+2)
                    if (HasExecutableExtension(path))
                    { score += 2; reasons.Add("ExecExt=2"); }

                    // Size gate (+1)
                    if (size >= minSizeForSuspicion)
                    { score += 1; reasons.Add("Size=1"); }

                    // Recent mtime boost (+2)
                    var mUtc = ToUtc(mtEpoch);
                    if (mUtc.HasValue && mUtc.Value > DateTime.UtcNow.AddDays(-recentDaysWindow))
                    { score += 2; reasons.Add($"RecentMTime=2({mUtc:yyyy-MM-dd})"); }

                    // ── Gates ────────────────────────────────────────────────────
                    if (score < minScore) continue;
                    if (requireKeyword && !hadKeyword) continue;

                    // Per-folder cap
                    var folder = GetFolder(path);
                    var cnt = countByFolder.TryGetValue(folder, out var c) ? c : 0;
                    if (cnt >= maxFindingsPerFolder) continue;

                    // Dedup — keep highest-scoring record per path
                    if (bestByPath.TryGetValue(path, out var prev) && score <= prev.Score) continue;

                    bestByPath[path] = (score, string.Join(", ", reasons), mUtc, size);
                    countByFolder[folder] = cnt + 1;
                }
                catch
                {
                    // Skip malformed lines silently
                }
            }

            // Temp-dir executables first — they are the strongest bodyfile signal
            parsed.Findings.AddRange(tempDrops.Distinct().Take(50));

            // Emit findings (already deduped and capped), ordered by score descending
            foreach (var kv in bestByPath.OrderByDescending(k => k.Value.Score).ThenBy(k => k.Key))
            {
                var (score, reason, mUtc, size) = kv.Value;
                var when = mUtc.HasValue ? $" mtime={mUtc:yyyy-MM-dd HH:mm:ss} UTC" : "";
                parsed.Findings.Add(
                    $"[BODYFILE] {kv.Key} — Score {score} ({reason}) size={size}{when}");
            }

            return parsed;
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private static readonly string[] TempDirs = { "/tmp/", "/dev/shm/", "/var/tmp/" };

        /// <summary>
        /// Regular file under /tmp, /dev/shm or /var/tmp that is executable or
        /// hidden (dot-name). Mode is the bodyfile mode string, e.g.
        /// "-rwxr-xr-x" or TSK-style "r/rrwxr-xr-x".
        /// </summary>
        private static bool IsTempDropCandidate(string path, string mode, out string why)
        {
            why = string.Empty;
            if (string.IsNullOrEmpty(path)) return false;
            if (!TempDirs.Any(t => path.StartsWith(t, StringComparison.Ordinal))) return false;

            var perms = mode ?? string.Empty;
            if (perms.StartsWith("d", StringComparison.Ordinal)) return false;          // directory
            if (perms.Contains('/')) perms = perms.Substring(perms.LastIndexOf('/') + 1);
            if (perms.Length > 9) perms = perms.Substring(perms.Length - 9);
            if (perms.StartsWith("d", StringComparison.Ordinal)) return false;

            bool exec = perms.Length == 9 && (perms[2] is 'x' or 's' || perms[5] is 'x' or 's' || perms[8] is 'x' or 't');
            var name = path.Substring(path.LastIndexOf('/') + 1);
            bool hidden = name.StartsWith(".", StringComparison.Ordinal) && name.Length > 1;

            // Skip well-known benign temp files
            if (name.StartsWith(".X", StringComparison.Ordinal) || name.StartsWith(".ICE", StringComparison.Ordinal)
                || name is ".font-unix" or ".Test-unix") return false;

            if (exec && hidden) why = "Hidden executable";
            else if (exec) why = "Executable";
            else if (hidden) why = "Hidden file";
            return why.Length > 0;
        }

        private static bool IsWhitelistedPath(string path, IReadOnlyList<string> prefixes)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var lower = path.ToLowerInvariant();
            foreach (var p in prefixes)
                if (lower.StartsWith(p, StringComparison.Ordinal)) return true;
            return false;
        }

        private static bool IsFrameworkCache(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var lower = path.ToLowerInvariant();
            foreach (var s in FrameworkCacheSubstrings)
                if (lower.Contains(s, StringComparison.Ordinal)) return true;
            return false;
        }

        private static bool HasBenignExtension(string path)
        {
            var ext = GetExtLower(path);
            return !string.IsNullOrEmpty(ext)
                   && BenignExtensions.Contains(ext, StringComparer.Ordinal);
        }

        private static bool HasExecutableExtension(string path)
        {
            var ext = GetExtLower(path);
            return !string.IsNullOrEmpty(ext)
                   && ExecutableExtensions.Contains(ext, StringComparer.Ordinal);
        }

        private static string GetExtLower(string path)
        {
            try
            {
                var idx = path.LastIndexOf('.');
                return idx < 0 ? string.Empty : path.Substring(idx).ToLowerInvariant();
            }
            catch { return string.Empty; }
        }

        private static string GetFolder(string path)
        {
            if (string.IsNullOrEmpty(path)) return "/";
            var idx = path.LastIndexOf('/');
            return idx > 0 ? path.Substring(0, idx) : "/";
        }

        private static long? TryParseLong(string s)
            => long.TryParse(s, out var v) && v > 0 ? v : (long?)null;

        private static DateTime? ToUtc(long? epoch)
        {
            if (!epoch.HasValue || epoch.Value <= 0) return null;
            try { return DateTimeOffset.FromUnixTimeSeconds(epoch.Value).UtcDateTime; }
            catch { return null; }
        }
    }
}
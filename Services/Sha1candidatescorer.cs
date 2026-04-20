using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace CsirtParser.WPF.Services;

/// <summary>
/// Parses a UAC hash_executables.sha1 file, scores each entry,
/// deduplicates by hash, and returns candidates worth submitting
/// to a threat intel datalake.
/// 
/// File format:  SHA1HASH  /path/to/file  (sha1sum standard output)
/// </summary>
public class Sha1CandidateScorer
{
    // ── Whitelist — almost always clean system paths ─────────────────
    private static readonly string[] WhitelistPrefixes = new[]
    {
        "/usr/share/", "/usr/lib/", "/usr/bin/", "/usr/sbin/",
        "/usr/local/share/", "/usr/local/lib/",
        "/lib/", "/lib64/", "/lib32/",
        "/bin/", "/sbin/",
        "/boot/",
        "/etc/",
        "/proc/", "/sys/",
        "/var/lib/dpkg/", "/var/lib/apt/", "/var/cache/apt/",
        "/var/lib/rpm/",
        "/opt/CrowdStrike/", "/opt/splunk/", "/opt/nessus/",
        "/tmp/CSIRT_Collection/",
    };

    // ── High-interest staging / attacker paths (+3) ──────────────────
    private static readonly string[] HighInterestPaths = new[]
    {
        "/tmp/", "/dev/shm/", "/var/tmp/", "/run/",
        "/root/", "/home/",
        "/mnt/", "/media/",
        "/.local/", "/.config/", "/.cache/",
    };

    // ── Medium-interest paths (+1) ───────────────────────────────────
    private static readonly string[] MediumInterestPaths = new[]
    {
        "/opt/", "/srv/", "/var/www/",
        "/usr/local/bin/", "/usr/local/sbin/",
    };

    // ── Suspicious filename keywords (+3) ────────────────────────────
    private static readonly string[] SuspiciousKeywords = new[]
    {
        "backdoor", "shell", "reverse", "exploit", "payload", "c2",
        "netcat", "ncat", "nc.", "socat", "xmrig", "miner", "crypto",
        "mimikatz", "dump", "inject", "hook", "rootkit", "stager",
        "beacon", "agent", "rat.", "implant", "pwn", "crack",
        "bypass", "escalate", "priv", "keylog", "exfil", "lateral",
    };

    // ── Suspicious extensions (+2) ────────────────────────────────────
    private static readonly string[] SuspiciousExtensions = new[]
    {
        ".elf", ".so", ".bin", ".run", ".out", ".x86", ".x64",
        ".arm", ".mips", ".sh", ".py", ".pl", ".rb", ".ps1",
    };

    // ── Scoring threshold ─────────────────────────────────────────────
    public int ScoreThreshold { get; set; } = 3;

    // ── Result type ───────────────────────────────────────────────────
    public record ScoredEntry(
        string Hash,
        string Path,
        int Score,
        string Reasons);

    // ── Main method ───────────────────────────────────────────────────
    /// <summary>
    /// Parse the sha1 file, score every entry, deduplicate by hash,
    /// and return only entries at or above ScoreThreshold.
    /// </summary>
    public (List<ScoredEntry> Candidates, ScorerStats Stats) Score(string sha1FilePath)
    {
        var stats = new ScorerStats();

        if (!File.Exists(sha1FilePath))
            throw new FileNotFoundException("SHA1 file not found.", sha1FilePath);

        // hash → best-scored entry for that hash
        var byHash = new Dictionary<string, ScoredEntry>(StringComparer.OrdinalIgnoreCase);

        foreach (var line in File.ReadLines(sha1FilePath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            // Format: "SHA1HASH  /path/to/file"  (two spaces between)
            var spaceIdx = line.IndexOf(' ');
            if (spaceIdx < 0) continue;

            string hash = line[..spaceIdx].Trim();
            string path = line[spaceIdx..].Trim();

            if (hash.Length != 40) continue;   // not a valid SHA1
            if (string.IsNullOrEmpty(path)) continue;

            stats.TotalLines++;

            // Whitelist check — skip entirely
            if (IsWhitelisted(path))
            {
                stats.WhitelistedCount++;
                continue;
            }

            var (score, reasons) = ComputeScore(path);
            stats.Scored++;

            if (score < ScoreThreshold)
            {
                stats.BelowThreshold++;
                continue;
            }

            // Deduplicate — keep the highest-scoring path for each hash
            if (!byHash.TryGetValue(hash, out var existing) || score > existing.Score)
                byHash[hash] = new ScoredEntry(hash, path, score, reasons);
            else
                stats.DuplicateHashCount++;
        }

        stats.UniqueCandidates = byHash.Count;

        var candidates = byHash.Values
            .OrderByDescending(e => e.Score)
            .ThenBy(e => e.Path)
            .ToList();

        return (candidates, stats);
    }

    // ── Scoring logic ─────────────────────────────────────────────────
    private static (int Score, string Reasons) ComputeScore(string path)
    {
        int score = 0;
        var reasons = new List<string>();

        string pathLower = path.ToLowerInvariant();
        string fileName = Path.GetFileName(pathLower);
        string ext = Path.GetExtension(fileName);

        // High-interest path
        foreach (var p in HighInterestPaths)
        {
            if (pathLower.StartsWith(p, StringComparison.Ordinal))
            {
                score += 3;
                reasons.Add($"high-interest path ({p})");
                break;
            }
        }

        // Medium-interest path
        if (score == 0)
        {
            foreach (var p in MediumInterestPaths)
            {
                if (pathLower.StartsWith(p, StringComparison.Ordinal))
                {
                    score += 1;
                    reasons.Add($"medium-interest path ({p})");
                    break;
                }
            }
        }

        // Suspicious keyword in filename or path
        foreach (var kw in SuspiciousKeywords)
        {
            if (fileName.Contains(kw, StringComparison.Ordinal)
                || pathLower.Contains(kw, StringComparison.Ordinal))
            {
                score += 3;
                reasons.Add($"suspicious keyword ({kw})");
                break;
            }
        }

        // Suspicious extension
        if (!string.IsNullOrEmpty(ext))
        {
            foreach (var sx in SuspiciousExtensions)
            {
                if (ext.Equals(sx, StringComparison.OrdinalIgnoreCase))
                {
                    score += 2;
                    reasons.Add($"suspicious extension ({ext})");
                    break;
                }
            }
        }

        // No extension at all on an executable = slightly more interesting
        if (string.IsNullOrEmpty(ext))
        {
            score += 1;
            reasons.Add("no extension");
        }

        // Hidden file (starts with .)
        if (fileName.StartsWith('.'))
        {
            score += 2;
            reasons.Add("hidden file");
        }

        // Deeply nested under a world-writable hint
        if (pathLower.Contains("/tmp/") || pathLower.Contains("/dev/shm/"))
        {
            score += 1;
            reasons.Add("world-writable location");
        }

        return (score, string.Join(", ", reasons));
    }

    private static bool IsWhitelisted(string path)
    {
        foreach (var prefix in WhitelistPrefixes)
            if (path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}

// ── Stats summary returned alongside candidates ───────────────────────
public class ScorerStats
{
    public int TotalLines { get; set; }
    public int WhitelistedCount { get; set; }
    public int Scored { get; set; }
    public int BelowThreshold { get; set; }
    public int DuplicateHashCount { get; set; }
    public int UniqueCandidates { get; set; }

    public override string ToString() =>
        $"Total lines: {TotalLines:N0} | " +
        $"Whitelisted: {WhitelistedCount:N0} | " +
        $"Scored: {Scored:N0} | " +
        $"Below threshold: {BelowThreshold:N0} | " +
        $"Duplicate hashes removed: {DuplicateHashCount:N0} | " +
        $"Unique candidates: {UniqueCandidates:N0}";
}
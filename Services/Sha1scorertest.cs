using System;
using System.IO;
using CsirtParser.WPF.Services;

namespace CsirtParser.WPF.Services;

/// <summary>
/// Temporary test harness — run this once to see candidate counts
/// before wiring into the full pipeline.
/// Remove or comment out after initial validation.
/// 
/// Call from MainViewModel or a button handler:
///     Sha1ScorerTest.Run(@"L:\UAC_Test_Case\Decompressed\...\hash_executables.sha1");
/// </summary>
public static class Sha1ScorerTest
{
    public static string Run(string sha1FilePath, int threshold = 3)
    {
        var scorer = new Sha1CandidateScorer { ScoreThreshold = threshold };

        var (candidates, stats) = scorer.Score(sha1FilePath);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("=== SHA1 Candidate Scorer Results ===");
        sb.AppendLine(stats.ToString());
        sb.AppendLine();

        // Show score distribution
        sb.AppendLine("Score distribution:");
        var groups = new System.Collections.Generic.Dictionary<int, int>();
        foreach (var c in candidates)
        {
            if (!groups.ContainsKey(c.Score)) groups[c.Score] = 0;
            groups[c.Score]++;
        }
        foreach (var g in new System.Collections.Generic.SortedDictionary<int, int>(groups))
            sb.AppendLine($"  Score {g.Key}: {g.Value} entries");

        sb.AppendLine();
        sb.AppendLine($"Top 30 highest-scoring candidates:");
        sb.AppendLine(new string('-', 80));

        int shown = 0;
        foreach (var entry in candidates)
        {
            if (shown++ >= 30) break;
            sb.AppendLine($"[{entry.Score,2}] {entry.Hash[..8]}… {entry.Path}");
            sb.AppendLine($"      → {entry.Reasons}");
        }

        // Write full candidate list to a file next to the sha1 file
        var outputPath = Path.Combine(
            Path.GetDirectoryName(sha1FilePath)!,
            "sha1_candidates.txt");

        using var writer = new StreamWriter(outputPath);
        writer.WriteLine($"Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        writer.WriteLine($"Source:    {sha1FilePath}");
        writer.WriteLine($"Threshold: {threshold}");
        writer.WriteLine(stats.ToString());
        writer.WriteLine();
        foreach (var entry in candidates)
            writer.WriteLine($"{entry.Score,2}  {entry.Hash}  {entry.Path}  [{entry.Reasons}]");

        sb.AppendLine();
        sb.AppendLine($"Full list written to: {outputPath}");

        return sb.ToString();
    }
}
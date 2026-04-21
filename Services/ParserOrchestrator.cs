using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;

using Helpers;
using Output;
using Parser.Docker;
using Parser.Output;
using Parser.Parsers.LiveResponse;
using Parsers;
using CsirtParser.WPF.Models;

namespace CsirtParser.WPF.Services;

/// <summary>
/// Drives all parsers for every UAC collection found under Decompressed\.
/// Driven by ParserConfig — all parser toggles, thresholds and keyword lists
/// come from the analyst's UI settings.
/// </summary>
public class ParserOrchestrator
{
    private readonly ParserConfig _config;
    private readonly Action<string> _log;

    // Keyword snapshots — copied from ObservableCollection once per run so
    // parser threads iterate a plain list rather than a UI-bound collection.
    private IReadOnlyList<string> _rank1Keywords = Array.Empty<string>();
    private IReadOnlyList<string> _rank2Keywords = Array.Empty<string>();
    private IReadOnlyList<string> _whitelist = Array.Empty<string>();

    public ParserOrchestrator(ParserConfig config, Action<string> log)
    {
        _config = config;
        _log = log;
    }

    // ════════════════════════════════════════════════════════════════════
    // Public entry point
    // ════════════════════════════════════════════════════════════════════

    /// <param name="ct">Honour this to support analyst-initiated cancel.</param>
    /// <param name="progress">Reports 0.0 → 1.0 as each parser step completes.</param>
    public void RunAll(CancellationToken ct = default, IProgress<double>? progress = null)
    {
        // Snapshot keyword lists once — safe to read from any thread.
        _rank1Keywords = _config.Rank1Keywords.ToList();
        _rank2Keywords = _config.Rank2Keywords.ToList();
        _whitelist = _config.WhitelistPatterns.ToList();

        var decompressDir = Path.Combine(_config.CaseFolderPath, "Decompressed");
        Directory.CreateDirectory(_config.OutputPath);

        var collections = BuildCollectionMap(decompressDir);

        if (collections.Count == 0)
        {
            _log("[WARN] No UAC collections found under Decompressed\\.");
            return;
        }

        // Progress accounting: enabled parsers × collection count.
        int stepsPerCollection = CountEnabledParsers();
        int totalSteps = collections.Count * stepsPerCollection;
        int completedSteps = 0;

        void Step(string label)
        {
            completedSteps++;
            progress?.Report(Math.Min((double)completedSteps / totalSteps, 1.0));
            _log(label);
        }

        foreach (var (collectionName, rootPath) in collections)
        {
            ct.ThrowIfCancellationRequested();

            var outputDir = Path.Combine(_config.OutputPath, collectionName);
            Directory.CreateDirectory(outputDir);

            _log($"===== Collection: {collectionName} =====");

            if (_config.ParseAuth || _config.ParseCrontab || _config.ParseMessages
                || _config.ParseSyslog || _config.ParseWebLogs || _config.ParseDocker
                || _config.ParseAudit || _config.ParseLiveResponse || _config.ParseJournal)
            {
                ProcessLogs(collectionName, rootPath, outputDir, ct, Step);
            }

            ct.ThrowIfCancellationRequested();

            if (_config.ParseProcess || _config.ParseNetwork || _config.ParsePersistence
                || _config.ParseFileSystem)
            {
                var lrPath = Directory.EnumerateDirectories(
                    rootPath, "live_response", SearchOption.AllDirectories).FirstOrDefault();

                if (!string.IsNullOrEmpty(lrPath) && Directory.Exists(lrPath))
                {
                    try
                    {
                        var lrOutDir = Path.Combine(outputDir, "LiveResponse");
                        Directory.CreateDirectory(lrOutDir);
                        WriteLiveResponse(lrPath, lrOutDir);
                    }
                    catch (Exception ex) { _log($"[ERROR] LiveResponse: {ex.Message}"); }
                }
            }

            if (_config.ParseBodyFile &&
                (_config.ParseAuth || _config.ParseCrontab || _config.ParseMessages
                 || _config.ParseSyslog || _config.ParseWebLogs || _config.ParseAudit))
            {
                ProcessBodyFile(collectionName, rootPath, outputDir);
            }

            if (_config.ParseBashHistory)
                ProcessBashHistory(collectionName, rootPath, outputDir);

            _log($"===== Done: {collectionName} =====");

            if (_config.OutputQuickWins)
            {
                try
                {
                    QuickWinsRtfConverter.Convert(outputDir);
                    _log($"[{collectionName}] QuickWins.rtf written.");
                }
                catch (Exception ex)
                {
                    _log($"[WARN] RTF conversion failed: {ex.Message} — QuickWins.txt is still available.");
                }
            }
        }

        progress?.Report(1.0);
    }

    // ════════════════════════════════════════════════════════════════════
    // Progress accounting
    // ════════════════════════════════════════════════════════════════════

    private int CountEnabledParsers()
    {
        int n = 0;
        if (_config.ParseAuth) n++;
        if (_config.ParseAudit) n++;
        if (_config.ParseMessages) n++;
        if (_config.ParseSyslog) n++;
        if (_config.ParseCrontab) n++;
        if (_config.ParseWebLogs) n++;
        if (_config.ParseDocker) n++;
        if (_config.ParseLiveResponse) n++;
        if (_config.ParseJournal) n++;
        if (_config.ParseBodyFile) n++;
        if (_config.ParseBashHistory) n++;
        return Math.Max(n, 1);
    }

    // ════════════════════════════════════════════════════════════════════
    // Collection discovery
    // ════════════════════════════════════════════════════════════════════

    private static Dictionary<string, string> BuildCollectionMap(string decompressDir)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!Directory.Exists(decompressDir)) return map;

        foreach (var folder in Directory.GetDirectories(decompressDir)
                     .Where(f => Path.GetFileName(f).StartsWith("uac", StringComparison.OrdinalIgnoreCase)))
        {
            var name = Path.GetFileName(folder);
            var nested = Path.Combine(folder, name);
            map[name] = Directory.Exists(nested) ? nested : folder;
        }

        return map;
    }

    // ════════════════════════════════════════════════════════════════════
    // Log parsing coordinator
    // ════════════════════════════════════════════════════════════════════

    private void ProcessLogs(
        string collectionName,
        string rootPath,
        string outputDir,
        CancellationToken ct,
        Action<string> step)
    {
        _log($"[{collectionName}] Starting log parsing…");
        QuickWinsHeader.EnsureHeader(outputDir, DateTime.UtcNow, null, null);

        var acc = new ParseAccumulator();
        var sessionTracker = new SessionTracker();

        if (_config.ParseAuth)
        {
            ct.ThrowIfCancellationRequested();
            ParseAuthLogs(rootPath, outputDir, sessionTracker, acc);
            step($"[{collectionName}] AUTH done.");
        }

        if (_config.ParseAudit)
        {
            ct.ThrowIfCancellationRequested();
            ParseGrouped("audit.log", new AuditLogParser(), "AUDIT", rootPath, outputDir, acc);
            step($"[{collectionName}] AUDIT done.");
        }

        if (_config.ParseMessages)
        {
            ct.ThrowIfCancellationRequested();
            ParseGrouped("messages", new MessagesLogParser(), "MESSAGES", rootPath, outputDir, acc);
            step($"[{collectionName}] MESSAGES done.");
        }

        if (_config.ParseSyslog)
        {
            ct.ThrowIfCancellationRequested();
            ParseGrouped("syslog", new SyslogParser(), "SYSLOG", rootPath, outputDir, acc);
            step($"[{collectionName}] SYSLOG done.");
        }

        if (_config.ParseCrontab)
        {
            ct.ThrowIfCancellationRequested();
            ParseCrontabFiles(rootPath, outputDir, acc);
            step($"[{collectionName}] CRONTAB done.");
        }

        if (_config.ParseWebLogs)
        {
            ct.ThrowIfCancellationRequested();
            using var webCsv = new NormalizedCsvWriter(
                Path.Combine(outputDir, "Normalized_WEB.csv"), append: false);
            var webParser = new WebLogParser();
            var webBfd = new WebBruteForceDetector();
            TryAttachWriter(webParser, webCsv);
            webParser.AttachBruteForceDetector(webBfd);
            ParseWebLogs(webParser, webBfd, rootPath, outputDir, acc);
            step($"[{collectionName}] WEB done.");
        }

        if (_config.ParseDocker)
        {
            ct.ThrowIfCancellationRequested();
            var dockerPath = Directory.EnumerateDirectories(
                rootPath, "containers", SearchOption.AllDirectories).FirstOrDefault();

            if (!string.IsNullOrEmpty(dockerPath) && Directory.Exists(dockerPath))
            {
                _log($"[{collectionName}] Parsing Docker containers…");
                using var dockerCsv = new NormalizedCsvWriter(
                    Path.Combine(outputDir, "Normalized_DOCKER.csv"), append: false);
                var dockerParser = new DockerParserCoordinator(dockerPath);
                TryAttachWriter(dockerParser, dockerCsv);
                var (findings, patterns, first, last) = dockerParser.ProcessLogAndWriteQuickWins();
                acc.Store("DOCKER", findings, patterns, first, last,
                    ips: null, fileCount: 1,
                    perFile: new Dictionary<string, (DateTime, DateTime)> { { "docker", (first, last) } });
            }
            else
            {
                _log($"[{collectionName}] Docker: containers folder not found — skipping.");
            }
            step($"[{collectionName}] DOCKER done.");
        }

        if (_config.ParseLiveResponse)
        {
            ct.ThrowIfCancellationRequested();
            var lrPath = Directory.EnumerateDirectories(
                rootPath, "live_response", SearchOption.AllDirectories).FirstOrDefault();

            if (!string.IsNullOrEmpty(lrPath) && Directory.Exists(lrPath))
            {
                try
                {
                    var lrOutDir = Path.Combine(outputDir, "LiveResponse");
                    Directory.CreateDirectory(lrOutDir);
                    WriteLiveResponse(lrPath, lrOutDir);
                }
                catch (Exception ex) { _log($"[ERROR] LiveResponse: {ex.Message}"); }
            }
            else
            {
                _log($"[{collectionName}] LiveResponse: folder not found — skipping.");
            }
            step($"[{collectionName}] LIVE RESPONSE done.");
        }

        if (_config.ParseJournal)
        {
            ct.ThrowIfCancellationRequested();
            var journalFiles = Directory.EnumerateFiles(
                    rootPath, "user-*.journal", SearchOption.AllDirectories)
                .OrderBy(f => f).ToList();

            if (journalFiles.Count > 0)
            {
                _log($"[{collectionName}] Parsing {journalFiles.Count} journal file(s)…");
                using var csv = new NormalizedCsvWriter(
                    Path.Combine(outputDir, "Normalized_JOURNAL.csv"), append: false);
                var journalParser = new JournalFileParser();
                TryAttachWriter(journalParser, csv);
                journalParser.SetFilter(_config.FilterFrom, _config.FilterTo);
                ParseFileSet("JOURNAL", journalFiles, journalParser, outputDir, acc);
            }
            else
            {
                _log($"[{collectionName}] Journal: no user-*.journal files found — skipping.");
            }
            step($"[{collectionName}] JOURNAL done.");
        }

        // SHA1 candidate scoring — opportunistic (runs when file is present, no toggle needed).
        var sha1File = Directory.EnumerateFiles(
                rootPath, "hash_executables.sha1", SearchOption.AllDirectories)
            .FirstOrDefault();
        if (sha1File != null)
        {
            ct.ThrowIfCancellationRequested();
            ProcessSha1File(sha1File, outputDir, collectionName);
        }

        // ── Finalise QuickWins ───────────────────────────────────────────────
        DateTime? overallFirst = null, overallLast = null;
        foreach (var fl in acc.FirstLastSeen.Values)
        {
            if (fl.First != DateTime.MinValue && fl.First != DateTime.MaxValue)
                overallFirst = overallFirst == null ? fl.First
                    : fl.First < overallFirst ? fl.First : overallFirst;
            if (fl.Last != DateTime.MinValue && fl.Last != DateTime.MaxValue)
                overallLast = overallLast == null ? fl.Last
                    : fl.Last > overallLast ? fl.Last : overallLast;
        }

        QuickWinsHeader.UpsertTimeline(outputDir, overallFirst, overallLast);

        var globalLines = GlobalQuickWinsSummary.Build(
            acc.SuspiciousLogs, acc.PatternCounts, acc.FirstLastSeen,
            acc.IpLogs, acc.FileCounts, acc.PerFileTimestamps);

        QuickWinsHeader.InsertGlobalAfterTimeline(outputDir, "[GLOBAL] Summary", globalLines);
        QuickWinsSummaries.AppendPerLogSummaries(
            outputDir, acc.SuspiciousLogs, acc.PatternCounts, acc.FirstLastSeen, acc.FileCounts);

        if (_config.OutputCollapseDups)
        {
            QuickWinsTidy.GroupSuspiciousFindingsUniform(outputDir);
            QuickWinsTidy.CollapseVerboseSessions(outputDir, 5);
            QuickWinsTidy.CollapseSyslogDuplicates(outputDir, 2);
            QuickWinsTidy.CollapseMessagesDuplicates(outputDir, 2);
        }

        _log($"[{collectionName}] QuickWins written.");
    }

    // ════════════════════════════════════════════════════════════════════
    // SHA1 candidate scorer
    // ════════════════════════════════════════════════════════════════════

    private void ProcessSha1File(string sha1FilePath, string outputDir, string collectionName)
    {
        _log($"[{collectionName}] Scoring SHA1 hashes…");
        try
        {
            var scorer = new Sha1CandidateScorer
            {
                ScoreThreshold = _config.BodyFileMinScore   // reuse analyst-configured threshold
            };

            var (candidates, stats) = scorer.Score(sha1FilePath);
            _log($"[{collectionName}] SHA1: {stats}");

            // CSV — full list
            var csvPath = Path.Combine(outputDir, "SHA1_Candidates.csv");
            using (var csv = new StreamWriter(csvPath, append: false,
                       encoding: new System.Text.UTF8Encoding(false)))
            {
                csv.WriteLine("Score,Hash,Path,Reasons");
                static string E(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
                foreach (var c in candidates)
                    csv.WriteLine($"{c.Score},{c.Hash},{E(c.Path)},{E(c.Reasons)}");
            }

            if (candidates.Count == 0)
            {
                _log($"[{collectionName}] SHA1: no candidates above threshold.");
                return;
            }

            // QuickWins section — top 20
            var findings = new List<string>
            {
                $"Stats: {stats}",
                $"Full list → SHA1_Candidates.csv ({candidates.Count} entries)",
                ""
            };

            int shown = 0;
            foreach (var c in candidates)
            {
                if (shown++ >= 20) break;
                string sev = c.Score >= 7 ? "[HIGH]" : c.Score >= 4 ? "[SUSPICIOUS]" : "[INFO]";
                findings.Add($"{sev} Score={c.Score}  {c.Path}");
                findings.Add($"         Hash: {c.Hash}  Reasons: {c.Reasons}");
            }

            if (candidates.Count > 20)
                findings.Add($"… {candidates.Count - 20} more — see SHA1_Candidates.csv");

            QuickWinsWriter.AppendSection(outputDir, "[SHA1] Suspicious Executable Hashes", findings);
            _log($"[{collectionName}] SHA1 done — {candidates.Count} candidate(s).");
        }
        catch (Exception ex)
        {
            _log($"[WARN] SHA1 scoring failed: {ex.Message}");
        }
    }

    // ════════════════════════════════════════════════════════════════════
    // Generic grouped parser
    // ════════════════════════════════════════════════════════════════════

    private void ParseGrouped(
        string baseName, LogFileParser parser, string logKey,
        string rootPath, string outputDir, ParseAccumulator acc)
    {
        var logFiles = DiscoverLogRotation(rootPath, baseName);
        acc.InitFileSet(logKey, logFiles.Count);
        if (logFiles.Count == 0) return;

        using var csv = new NormalizedCsvWriter(
            Path.Combine(outputDir, $"Normalized_{logKey}.csv"), append: false);
        TryAttachWriter(parser, csv);
        parser.SetFilter(_config.FilterFrom, _config.FilterTo);
        ParseFileSet(logKey, logFiles, parser, outputDir, acc);
    }

    // ════════════════════════════════════════════════════════════════════
    // Auth / Secure handler
    // ════════════════════════════════════════════════════════════════════

    private void ParseAuthLogs(
        string rootPath, string outputDir,
        SessionTracker sessionTracker, ParseAccumulator acc)
    {
        foreach (var baseName in new[] { "auth.log", "secure" })
        {
            var logKey = baseName.ToUpperInvariant();
            var logFiles = DiscoverLogRotation(rootPath, baseName);
            acc.InitFileSet(logKey, logFiles.Count);
            if (logFiles.Count == 0) continue;

            using var csv = new NormalizedCsvWriter(
                Path.Combine(outputDir, $"Normalized_{logKey.Replace(".", "_")}.csv"), append: false);
            var parser = new AuthSecureLogParser();
            TryAttachTracker(parser, sessionTracker);
            TryAttachWriter(parser, csv);
            parser.SetFilter(_config.FilterFrom, _config.FilterTo);
            ParseFileSet(logKey, logFiles, parser, outputDir, acc);
        }

        var stats = sessionTracker.GetStatistics();
        var suspiciousLines = sessionTracker.GenerateSuspiciousSummary("AUTH");

        if (suspiciousLines?.Count > 0)
        {
            var qwFile = Path.Combine(outputDir, "QuickWins.txt");
            using var w = new StreamWriter(qwFile, append: true);
            w.WriteLine();
            w.WriteLine("########## [AUTH] Suspicious Sessions ##########");
            w.WriteLine($"  Sessions: {stats.GetValueOrDefault("Total Sessions")} total" +
                        $" | SSH interactive: {stats.GetValueOrDefault("SSH Interactive")}" +
                        $" | Unique IPs: {stats.GetValueOrDefault("Unique IPs")}" +
                        $" | Suspicious: {stats.GetValueOrDefault("Suspicious Sessions")}" +
                        $"  (full detail → Sessions_AUTH.csv)");
            w.WriteLine();
            foreach (var line in suspiciousLines)
                w.WriteLine($"  {line}");
            w.WriteLine();
            w.WriteLine("########## End of [AUTH] Suspicious Sessions ##########");
            w.WriteLine();
        }

        WriteSessionsCsv(outputDir, sessionTracker);
    }

    // ════════════════════════════════════════════════════════════════════
    // Crontab scanner
    // ════════════════════════════════════════════════════════════════════

    private void ParseCrontabFiles(string rootPath, string outputDir, ParseAccumulator acc)
    {
        const string logKey = "CRONTAB";
        var crontabFiles = CrontabScanner.DiscoverCrontabFiles(rootPath);
        acc.InitFileSet(logKey, crontabFiles.Count);

        if (crontabFiles.Count == 0)
        {
            _log("CRONTAB: no crontab definition files found.");
            return;
        }

        _log($"CRONTAB: scanning {crontabFiles.Count} crontab file(s)…");
        using var csv = new NormalizedCsvWriter(
            Path.Combine(outputDir, "Normalized_CRONTAB.csv"), append: false);
        var scanner = new CrontabScanner();
        TryAttachWriter(scanner, csv);
        scanner.SetFilter(_config.FilterFrom, _config.FilterTo);
        ParseFileSet(logKey, crontabFiles, scanner, outputDir, acc,
            sectionTitle: "[CRONTAB] Suspicious Job Definitions",
            emptyMessage: "  No suspicious crontab entries found.");
    }

    // ════════════════════════════════════════════════════════════════════
    // Core file-set loop
    // ════════════════════════════════════════════════════════════════════

    private void ParseFileSet(
        string logKey,
        IReadOnlyList<string> logFiles,
        LogFileParser parser,
        string outputDir,
        ParseAccumulator acc,
        string? sectionTitle = null,
        string? emptyMessage = null)
    {
        var allFindings = new List<string>();
        var perFileFindings = new List<(string FilePath, List<string> Findings)>();
        var combinedPatterns = new Dictionary<string, int>();
        var combinedIPs = new Dictionary<string, int>();
        DateTime combFirst = DateTime.MaxValue;
        DateTime combLast = DateTime.MinValue;

        foreach (var logFile in logFiles)
        {
            var (parsePath, tempPath) = DecompressIfNeeded(logFile);
            try
            {
                _log($"Parsing {Path.GetFileName(parsePath)}");
                var (findings, patterns, first, last) = parser.ParseFile(parsePath);

                acc.SetPerFile(logKey, Path.GetFileName(logFile), first, last);

                if (findings.Count > 0)
                    perFileFindings.Add((logFile, findings));
                allFindings.AddRange(findings);

                foreach (var kv in patterns)
                    combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                        ? ex + kv.Value : kv.Value;

                if (first != DateTime.MaxValue && first < combFirst) combFirst = first;
                if (last != DateTime.MinValue && last > combLast) combLast = last;
            }
            finally
            {
                if (tempPath != null && File.Exists(tempPath)) File.Delete(tempPath);
            }
        }

        WriteQuickWinsSection(outputDir, logKey, perFileFindings, sectionTitle, emptyMessage);
        acc.Store(logKey, allFindings, combinedPatterns, combFirst, combLast, combinedIPs);
    }

    // ════════════════════════════════════════════════════════════════════
    // Web log handler
    // ════════════════════════════════════════════════════════════════════

    private void ParseWebLogs(
        WebLogParser parser, WebBruteForceDetector bfd,
        string rootPath, string outputDir, ParseAccumulator acc)
    {
        const string logKey = "WEB";

        var webLogs = WebLogParser.DiscoverWebLogFiles(rootPath)
            .Where(p => Path.GetFileName(p).IndexOf("access", StringComparison.OrdinalIgnoreCase) >= 0)
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();

        acc.InitFileSet(logKey, webLogs.Count);
        if (webLogs.Count == 0) { _log("WEB: no access logs discovered."); return; }

        var allFindings = new List<string>();
        var perFileFindings = new List<(string FilePath, List<string> Findings)>();
        var combinedPatterns = new Dictionary<string, int>();
        var combinedIPs = new Dictionary<string, int>();
        DateTime first = DateTime.MaxValue, last = DateTime.MinValue;

        foreach (var logFile in webLogs)
        {
            var (parsePath, tempPath) = DecompressIfNeeded(logFile);
            try
            {
                _log($"Parsing WEB {Path.GetFileName(logFile)}");
                var (findings, patterns, fileFirst, fileLast) = parser.ParseFile(parsePath);

                acc.SetPerFile(logKey, Path.GetFileName(logFile), fileFirst, fileLast);

                if (findings.Count > 0) perFileFindings.Add((logFile, findings));
                allFindings.AddRange(findings);

                foreach (var kv in patterns)
                    combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                        ? ex + kv.Value : kv.Value;

                if (fileFirst != DateTime.MaxValue && fileFirst < first) first = fileFirst;
                if (fileLast != DateTime.MinValue && fileLast > last) last = fileLast;
            }
            finally
            {
                if (tempPath != null && File.Exists(tempPath)) File.Delete(tempPath);
            }
        }

        var bruteList = bfd.GetFindings()
            .Select(bf => $"[WEB] [BRUTEFORCE] {bf.Replace("[WEBLOG] [BRUTEFORCE] ", "")}")
            .ToList();
        allFindings.AddRange(bruteList);

        var qwFile = Path.Combine(outputDir, "QuickWins.txt");
        using var w = new StreamWriter(qwFile, append: true);
        w.WriteLine(); w.WriteLine("########## [WEB] Suspicious Findings ##########"); w.WriteLine();

        if (perFileFindings.Count == 0 && bruteList.Count == 0)
        {
            w.WriteLine("  No suspicious web requests detected."); w.WriteLine();
        }
        else
        {
            foreach (var (lf, fileFindings) in perFileFindings)
            {
                var dp = lf;
                var idx = lf.IndexOf(@"\[root]", StringComparison.OrdinalIgnoreCase);
                if (idx >= 0) dp = lf.Substring(idx);
                w.WriteLine($"  --- {dp} ---");
                foreach (var f in fileFindings) w.WriteLine($"  >> {f}");
                w.WriteLine();
            }
            if (bruteList.Count > 0)
            {
                w.WriteLine("  --- Brute-force detections (all files combined) ---");
                foreach (var bf in bruteList) w.WriteLine($"  >> {bf}");
                w.WriteLine();
            }
        }

        w.WriteLine("########## End of [WEB] Suspicious Findings ##########");
        acc.Store(logKey, allFindings, combinedPatterns, first, last, combinedIPs);
    }

    // ════════════════════════════════════════════════════════════════════
    // Body file
    // ════════════════════════════════════════════════════════════════════

    private void ProcessBodyFile(string collectionName, string rootPath, string outputDir)
    {
        var bodyfilePath = Directory.EnumerateFiles(
            rootPath, "bodyfile.txt", SearchOption.AllDirectories).FirstOrDefault();

        if (string.IsNullOrEmpty(bodyfilePath))
        {
            _log($"[{collectionName}] Body file not found — skipping.");
            return;
        }

        _log($"[{collectionName}] Processing body file…");
        var parsed = Helpers.BodyFileProcessor.ProcessBodyFile(bodyfilePath, outputDir, _config);
        QuickWinsHeader.EnsureHeader(outputDir, DateTime.UtcNow, parsed.FirstLogUtc, parsed.LastLogUtc);
        QuickWinsAppend.WriteProcessedBodyFileCsv(outputDir, parsed);
        QuickWinsAppend.AppendBodyFileFindings(outputDir, parsed.Findings);
        _log($"[{collectionName}] Body file done.");
    }

    // ════════════════════════════════════════════════════════════════════
    // Bash history
    // ════════════════════════════════════════════════════════════════════

    private void ProcessBashHistory(string collectionName, string rootPath, string outputDir)
    {
        var historyFiles = BashHistoryParser.DiscoverHistoryFiles(rootPath);

        if (historyFiles.Count == 0)
        {
            _log($"[{collectionName}] BashHistory: no .bash_history files found — skipping.");
            return;
        }

        _log($"[{collectionName}] Parsing {historyFiles.Count} bash_history file(s)…");

        using var csv = new NormalizedCsvWriter(
            Path.Combine(outputDir, "Normalized_BASH.csv"), append: false);

        var parser = new BashHistoryParser();
        TryAttachWriter(parser, csv);
        parser.SetFilter(_config.FilterFrom, _config.FilterTo);

        var allFindings = new List<string>();
        var perFileFindings = new List<(string FilePath, List<string> Findings)>();
        var combinedPatterns = new Dictionary<string, int>();
        DateTime combFirst = DateTime.MaxValue;
        DateTime combLast = DateTime.MinValue;

        foreach (var (filePath, username) in historyFiles)
        {
            _log($"Parsing bash_history: {username}");

            var (findings, patterns, first, last) = parser.ParseFile(filePath, username);

            if (findings.Count > 0)
                perFileFindings.Add((filePath, findings));

            allFindings.AddRange(findings);

            foreach (var kv in patterns)
                combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                    ? ex + kv.Value : kv.Value;

            if (first != DateTime.MaxValue && first < combFirst) combFirst = first;
            if (last != DateTime.MinValue && last > combLast) combLast = last;
        }

        WriteQuickWinsSection(outputDir, "BASH", perFileFindings,
            sectionTitle: "[BASH] Suspicious Shell History",
            emptyMessage: "  No suspicious commands found in bash history.");

        _log($"[{collectionName}] BashHistory done — {allFindings.Count} finding(s) across " +
             $"{historyFiles.Count} file(s).");
    }

    // ════════════════════════════════════════════════════════════════════
    // Live response artefacts
    // ════════════════════════════════════════════════════════════════════

    private void WriteLiveResponse(string liveResponseRoot, string outDir)
    {
        var lines = new List<string>
        {
            "##########################################",
            "# Live Response Report",
            $"# Source: {liveResponseRoot}",
            $"# Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z",
            "##########################################", ""
        };

        DateTime first = DateTime.MinValue, last = DateTime.MinValue;

        if (_config.ParseProcess)
            TryAppendBlock(lines, liveResponseRoot, ref first, ref last,
                "## Processes", new[] { "ps_aux.txt", "ps.txt", "processes.txt" }, 500);
        if (_config.ParseNetwork)
            TryAppendBlock(lines, liveResponseRoot, ref first, ref last,
                "## Network", new[] { "netstat.txt", "ss.txt", "lsof_nP.txt", "ip_addr.txt" }, 500);

        TryAppendAccounts(lines, liveResponseRoot);
        TryAppendBlock(lines, liveResponseRoot, ref first, ref last,
            "## Cron", new[] { "crontab.txt", "cron.txt", "cron_d.txt" }, 200);
        TryAppendBlock(lines, liveResponseRoot, ref first, ref last,
            "## Services", new[] { "systemctl_list-units.txt", "services.txt", "chkconfig.txt" }, 200);

        if (_config.ParsePersistence) TryAppendPersistence(lines, liveResponseRoot, ref first, ref last);
        if (_config.ParseDocker) TryAppendDockerHints(lines, liveResponseRoot, ref first, ref last);

        var writer = new LiveResponseWriter(outDir);
        writer.WriteHeader("Live Response – DFIR");
        writer.WriteSection("Live Response Report", lines);
        _log($"LiveResponse: wrote {lines.Count} lines.");
    }

    private void TryAppendBlock(List<string> lines, string root,
        ref DateTime first, ref DateTime last, string header, string[] names, int take)
    {
        var path = FindFirst(root, names);
        if (path == null) return;
        lines.Add(header);
        foreach (var ln in SafeRead(path).Take(take)) { lines.Add(ln); UpdateTimestamps(ln, ref first, ref last); }
        lines.Add("");
    }

    private static void TryAppendAccounts(List<string> lines, string root)
    {
        var passwd = FindFirst(root, new[] { "etc_passwd.txt", "passwd.txt" });
        var sudoers = FindFirst(root, new[] { "etc_sudoers.txt", "sudoers.txt" });
        var shadow = FindFirst(root, new[] { "etc_shadow.txt", "shadow.txt" });
        if (passwd == null && sudoers == null && shadow == null) return;
        lines.Add("## Accounts");
        if (passwd != null) { lines.Add("-- /etc/passwd --"); lines.AddRange(SafeRead(passwd).Take(200)); lines.Add(""); }
        if (sudoers != null) { lines.Add("-- /etc/sudoers --"); lines.AddRange(SafeRead(sudoers).Take(200)); lines.Add(""); }
        if (shadow != null) { lines.Add("-- /etc/shadow (redacted) --"); lines.AddRange(SafeRead(shadow).Select(RedactHash).Take(50)); lines.Add(""); }
    }

    private void TryAppendPersistence(List<string> lines, string root,
        ref DateTime first, ref DateTime last)
    {
        var rcLocal = FindFirst(root, new[] { "etc_rc.local.txt", "rc_local.txt" });
        var profile = FindFirst(root, new[] { "etc_profile.txt", "profile.txt" });
        var bashrc = FindFirst(root, new[] { "etc_bashrc.txt", "bashrc.txt" });
        if (rcLocal == null && profile == null && bashrc == null) return;
        lines.Add("## Persistence candidates");
        foreach (var f in new[] { rcLocal, profile, bashrc }.Where(x => x != null))
        {
            lines.Add("-- " + Path.GetFileName(f));
            foreach (var ln in SafeRead(f!).Take(150)) { lines.Add(ln); UpdateTimestamps(ln, ref first, ref last); }
            lines.Add("");
        }
    }

    private void TryAppendDockerHints(List<string> lines, string root,
        ref DateTime first, ref DateTime last)
    {
        var docker = FindFirst(root, new[] { "docker_ps.txt", "docker_info.txt", "containers", "docker" });
        if (docker == null) return;
        lines.Add("## Docker hints");
        if (Directory.Exists(docker))
        {
            lines.Add($"Directory: {docker}");
            lines.AddRange(Directory.EnumerateFiles(docker, "*", SearchOption.AllDirectories).Take(30).Select(Path.GetFileName)!);
        }
        else
        {
            foreach (var ln in SafeRead(docker).Take(200)) { lines.Add(ln); UpdateTimestamps(ln, ref first, ref last); }
        }
        lines.Add("");
    }

    // ════════════════════════════════════════════════════════════════════
    // Sessions CSV
    // ════════════════════════════════════════════════════════════════════

    private void WriteSessionsCsv(string outputDir, SessionTracker sessionTracker)
    {
        try
        {
            var allSessions = sessionTracker.GetAllSessions();
            var grouped = allSessions
                .Where(s => s.Type.ToString() != "CronJob"
                         && s.Type.ToString() != "SystemdSession"
                         && s.Type.ToString() != "PamGeneric")
                .GroupBy(s => new { s.Username, s.SourceIP, s.Daemon, Type = s.Type.ToString() })
                .Select(g => (
                    g.Key.Username, g.Key.SourceIP, g.Key.Daemon, g.Key.Type,
                    Count: g.Count(),
                    FirstSeen: g.Min(s => s.StartTime),
                    LastSeen: g.Max(s => s.StartTime),
                    AvgDur: (int)g.Average(s => s.DurationSeconds),
                    Suspicious: g.Any(s => s.IsSuspicious) ? "Yes" : "No",
                    Reason: g.Where(s => s.IsSuspicious).Select(s => s.SuspicionReason.ToString()).FirstOrDefault() ?? "",
                    Notes: g.Where(s => s.IsSuspicious).Select(s => s.Notes).FirstOrDefault() ?? ""))
                .OrderByDescending(g => g.Suspicious).ThenByDescending(g => g.Count);

            static string E(string s) => s == null ? "" : "\"" + s.Replace("\"", "\"\"") + "\"";

            using var csv = new StreamWriter(Path.Combine(outputDir, "Sessions_AUTH.csv"), append: false,
                encoding: new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            csv.WriteLine("User,IP,Daemon,Type,Count,FirstSeen,LastSeen,AvgDurationSec,Suspicious,Reason,Notes");
            foreach (var g in grouped)
                csv.WriteLine(string.Join(",",
                    E(g.Username), E(g.SourceIP), E(g.Daemon), E(g.Type), g.Count,
                    E(g.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss")),
                    E(g.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")),
                    g.AvgDur, E(g.Suspicious), E(g.Reason), E(g.Notes)));
        }
        catch (Exception ex) { _log($"[WARN] Could not write Sessions_AUTH.csv: {ex.Message}"); }
    }

    // ════════════════════════════════════════════════════════════════════
    // Shared helpers
    // ════════════════════════════════════════════════════════════════════

    private static IReadOnlyList<string> DiscoverLogRotation(string rootPath, string baseName) =>
        Directory.EnumerateFiles(rootPath, baseName + "*", SearchOption.AllDirectories)
            .Where(f =>
                f.EndsWith(baseName, StringComparison.OrdinalIgnoreCase) ||
                f.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ||
                f.EndsWith(".1", StringComparison.OrdinalIgnoreCase) ||
                Regex.IsMatch(f, $@"{Regex.Escape(baseName)}\.\d+(\.gz)?$", RegexOptions.IgnoreCase))
            .OrderBy(f => f).ToList();

    private static (string parsePath, string? tempPath) DecompressIfNeeded(string logFile)
    {
        if (!logFile.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)) return (logFile, null);
        var tmp = Path.Combine(Path.GetTempPath(),
            Path.GetFileNameWithoutExtension(logFile) + "_" + Guid.NewGuid().ToString("N"));
        using var inFs = File.OpenRead(logFile); using var outFs = File.Create(tmp);
        using var gz = new GZipStream(inFs, CompressionMode.Decompress); gz.CopyTo(outFs);
        return (tmp, tmp);
    }

    private static void WriteQuickWinsSection(
        string outputDir, string logKey,
        IReadOnlyList<(string FilePath, List<string> Findings)> perFileFindings,
        string? sectionTitle = null, string? emptyMessage = null)
    {
        if (perFileFindings.Count == 0 && emptyMessage == null) return;
        var title = sectionTitle ?? $"[{logKey}] Suspicious Findings";
        using var w = new StreamWriter(Path.Combine(outputDir, "QuickWins.txt"), append: true);
        w.WriteLine(); w.WriteLine($"########## {title} ##########"); w.WriteLine();
        if (perFileFindings.Count == 0)
        {
            w.WriteLine(emptyMessage);
        }
        else
        {
            foreach (var (fp, findings) in perFileFindings)
            {
                var dp = fp;
                var idx = fp.IndexOf(@"\[root]", StringComparison.OrdinalIgnoreCase);
                if (idx >= 0) dp = fp.Substring(idx);
                w.WriteLine($"  --- {dp} ---");
                foreach (var f in findings) w.WriteLine($"  >> {f}");
                w.WriteLine();
            }
        }
        w.WriteLine($"########## End of {title} ##########");
    }

    private static void TryAttachTracker(object target, SessionTracker tracker)
    {
        if (tracker != null && target is IAttachSessionTracker sp)
            sp.AttachSessionTracker(tracker);
    }

    private static void TryAttachWriter(object target, NormalizedCsvWriter writer)
    {
        if (writer != null && target is IAttachNormalizedWriter np)
            np.AttachNormalizedWriter(writer);
    }

    private static string? FindFirst(string root, string[] names)
    {
        foreach (var n in names)
        {
            var e = Directory.EnumerateFileSystemEntries(root, n, SearchOption.AllDirectories).FirstOrDefault();
            if (!string.IsNullOrEmpty(e)) return e;
        }
        return null;
    }

    private static IEnumerable<string> SafeRead(string path)
    {
        try { return File.ReadLines(path); } catch { return Array.Empty<string>(); }
    }

    private static string RedactHash(string line) =>
        Regex.Replace(line, @"^([^:]*:)[^:]*(:.*)$", "$1********$2");

    private static void UpdateTimestamps(string line, ref DateTime first, ref DateTime last)
    {
        var m = Regex.Match(line, @"\b(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})\b");
        if (!m.Success || !DateTime.TryParse(m.Value, out var dt)) return;
        if (first == DateTime.MinValue || dt < first) first = dt;
        if (dt > last) last = dt;
    }
}

// ════════════════════════════════════════════════════════════════════════
// ParseAccumulator
// ════════════════════════════════════════════════════════════════════════

internal sealed class ParseAccumulator
{
    public Dictionary<string, List<string>> SuspiciousLogs { get; } = new();
    public Dictionary<string, Dictionary<string, int>> PatternCounts { get; } = new();
    public Dictionary<string, (DateTime First, DateTime Last)> FirstLastSeen { get; } = new();
    public Dictionary<string, Dictionary<string, int>> IpLogs { get; } = new();
    public Dictionary<string, int> FileCounts { get; } = new();
    public Dictionary<string, Dictionary<string, (DateTime First, DateTime Last)>> PerFileTimestamps { get; } = new();

    public void InitFileSet(string logKey, int fileCount)
    {
        FileCounts[logKey] = fileCount;
        PerFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();
    }

    public void SetPerFile(string logKey, string fileName, DateTime first, DateTime last)
    {
        if (!PerFileTimestamps.TryGetValue(logKey, out var bucket))
            PerFileTimestamps[logKey] = bucket = new Dictionary<string, (DateTime, DateTime)>();
        bucket[fileName] = (first, last);
    }

    public void Store(
        string logKey, List<string> findings, Dictionary<string, int> patterns,
        DateTime first, DateTime last,
        Dictionary<string, int>? ips = null, int fileCount = -1,
        Dictionary<string, (DateTime, DateTime)>? perFile = null)
    {
        SuspiciousLogs[logKey] = findings;
        PatternCounts[logKey] = patterns;
        FirstLastSeen[logKey] = (first, last);
        IpLogs[logKey] = ips ?? new Dictionary<string, int>();
        if (fileCount >= 0) FileCounts[logKey] = fileCount;
        if (perFile != null) PerFileTimestamps[logKey] = perFile;
    }
}
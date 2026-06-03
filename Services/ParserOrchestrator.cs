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
/// Replaces Form1's parser orchestration entirely.
/// Driven by ParserConfig — all parser toggles, thresholds and
/// keyword lists come from the analyst's UI settings.
/// </summary>
public class ParserOrchestrator
{
    private readonly ParserConfig _config;
    private readonly Action<string> _log;   // posts a message to the UI log

    public ParserOrchestrator(ParserConfig config, Action<string> log)
    {
        _config = config;
        _log = log;
    }

    // ── Public entry point ───────────────────────────────────────────
    public void RunAll(CancellationToken ct = default, IProgress<double>? progress = null)
    {
        var decompressDir = Path.Combine(_config.CaseFolderPath, "Decompressed");
        var outputBase = _config.OutputPath;

        Directory.CreateDirectory(outputBase);

        // Find all collection root paths under Decompressed\
        var collections = BuildCollectionMap(decompressDir);

        if (collections.Count == 0)
        {
            _log("[WARN] No UAC collections found under Decompressed\\.");
            return;
        }

        var collectionList = collections.ToList();
        int total = collectionList.Count;

        for (int i = 0; i < total; i++)
        {
            ct.ThrowIfCancellationRequested();

            var (collectionName, rootPath) = collectionList[i];
            var outputDir = Path.Combine(outputBase, collectionName);
            Directory.CreateDirectory(outputDir);

            _log($"===== Collection: {collectionName} =====");

            if (_config.ParseAuth || _config.ParseCrontab || _config.ParseMessages
                || _config.ParseSyslog || _config.ParseWebLogs || _config.ParseDocker
                || _config.ParseAudit || _config.ParseLiveResponse || _config.ParseJournal)
            {
                ct.ThrowIfCancellationRequested();
                ProcessLogs(collectionName, rootPath, outputDir);
            }

            if (_config.ParseProcess || _config.ParseNetwork || _config.ParsePersistence
                || _config.ParseFileSystem)
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
                    catch (Exception ex)
                    {
                        _log($"[ERROR] LiveResponse: {ex.Message}");
                    }
                }
            }

            if (_config.ParseAuth || _config.ParseCrontab || _config.ParseMessages
                || _config.ParseSyslog || _config.ParseWebLogs || _config.ParseAudit)
            {
                if (_config.ParseBodyFile)
                {
                    ct.ThrowIfCancellationRequested();
                    ProcessBodyFile(collectionName, rootPath, outputDir);
                }
            }

            _log($"===== Done: {collectionName} =====");

            // Convert QuickWins.txt → QuickWins.rtf for formatted output
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

            // Report progress as fraction of collections completed
            progress?.Report((double)(i + 1) / total);
        }
    }

    // ── Collection discovery ─────────────────────────────────────────
    private static Dictionary<string, string> BuildCollectionMap(string decompressDir)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!Directory.Exists(decompressDir)) return map;

        foreach (var folder in Directory.GetDirectories(decompressDir)
                     .Where(f => Path.GetFileName(f).StartsWith("uac", StringComparison.OrdinalIgnoreCase)))
        {
            var collectionName = Path.GetFileName(folder);
            // UAC archives often contain a nested folder with the same name
            var nested = Path.Combine(folder, collectionName);
            var rootPath = Directory.Exists(nested) ? nested : folder;
            map[collectionName] = rootPath;
        }

        return map;
    }

    // ── Log parsing ──────────────────────────────────────────────────
    private void ProcessLogs(string collectionName, string rootPath, string outputDir)
    {
        _log($"[{collectionName}] Starting log parsing…");

        string hostname = ExtractHostnameFromCollection(collectionName);

        QuickWinsHeader.EnsureHeader(outputDir, DateTime.UtcNow, null, null);

        var suspiciousLogs = new Dictionary<string, List<string>>();
        var patternCounts = new Dictionary<string, Dictionary<string, int>>();
        var firstLastSeen = new Dictionary<string, (DateTime, DateTime)>();
        var ipLogs = new Dictionary<string, Dictionary<string, int>>();
        var fileCounts = new Dictionary<string, int>();
        var perFileTimestamps = new Dictionary<string, Dictionary<string, (DateTime, DateTime)>>();
        var sessionTracker = new SessionTracker();

        void Parse(string baseName, LogFileParser parser, string label)
        {
            var csvPath = Path.Combine(outputDir, $"Normalized_{label}.csv");
            using var csv = new NormalizedCsvWriter(csvPath, append: false);
            TryAttach(parser, sessionTracker);
            TryAttach(parser, csv);
            TryAttach(parser, hostname);
            ParseLogFiles(parser, rootPath, baseName, outputDir,
                suspiciousLogs, patternCounts, firstLastSeen,
                ipLogs, fileCounts, perFileTimestamps);
        }

        if (_config.ParseAuth)
            ParseAuthLogs(rootPath, outputDir, sessionTracker, suspiciousLogs, patternCounts,
                firstLastSeen, ipLogs, fileCounts, perFileTimestamps);

        if (_config.ParseAudit)
            ParseGrouped("audit.log", new AuditLogParser(), "AUDIT",
                rootPath, outputDir, suspiciousLogs, patternCounts,
                firstLastSeen, ipLogs, fileCounts, perFileTimestamps);

        if (_config.ParseMessages)
            ParseGrouped("messages", new MessagesLogParser(), "MESSAGES",
                rootPath, outputDir, suspiciousLogs, patternCounts,
                firstLastSeen, ipLogs, fileCounts, perFileTimestamps);

        if (_config.ParseSyslog)
            ParseGrouped("syslog", new SyslogParser(), "SYSLOG",
                rootPath, outputDir, suspiciousLogs, patternCounts,
                firstLastSeen, ipLogs, fileCounts, perFileTimestamps);

        // Cron runtime logs now handled by SyslogParser (Debian/Ubuntu) above.
        // CrontabScanner scans actual job definition files for persistence.
        if (_config.ParseCrontab)
            ParseCrontabFiles(rootPath, outputDir, suspiciousLogs, patternCounts,
                firstLastSeen, ipLogs, fileCounts, perFileTimestamps);

        if (_config.ParseWebLogs)
        {
            using var webCsv = new NormalizedCsvWriter(
                Path.Combine(outputDir, "Normalized_WEB.csv"), append: false);
            var webParser = new WebLogParser();
            var webBfd = new WebBruteForceDetector();  // shared across all web files
            TryAttach(webParser, webCsv);
            TryAttach(webParser, hostname);
            webParser.AttachBruteForceDetector(webBfd);
            ParseWebLogs(webParser, webBfd, rootPath, outputDir,
                suspiciousLogs, patternCounts, firstLastSeen,
                ipLogs, fileCounts, perFileTimestamps);
        }

        if (_config.ParseDocker)
        {
            var dockerPath = Directory.EnumerateDirectories(
                rootPath, "containers", SearchOption.AllDirectories).FirstOrDefault();

            if (!string.IsNullOrEmpty(dockerPath) && Directory.Exists(dockerPath))
            {
                _log($"[{collectionName}] Parsing Docker containers…");
                using var dockerCsv = new NormalizedCsvWriter(
                    Path.Combine(outputDir, "Normalized_DOCKER.csv"), append: false);
                var dockerParser = new DockerParserCoordinator(dockerPath);
                TryAttach(dockerParser, dockerCsv);
                TryAttach(dockerParser, hostname);

                var (findings, patterns, first, last) = dockerParser.ProcessLogAndWriteQuickWins();
                suspiciousLogs["DOCKER"] = findings;
                patternCounts["DOCKER"] = patterns;
                firstLastSeen["DOCKER"] = (first, last);
                ipLogs["DOCKER"] = new Dictionary<string, int>();
                fileCounts["DOCKER"] = 1;
                perFileTimestamps["DOCKER"] = new Dictionary<string, (DateTime, DateTime)>
                    { { "docker", (first, last) } };
            }
            else
            {
                _log($"[{collectionName}] Docker: containers folder not found — skipping.");
            }
        }

        // Live response log artefacts
        if (_config.ParseLiveResponse)
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
                catch (Exception ex)
                {
                    _log($"[ERROR] LiveResponse: {ex.Message}");
                }
            }
            else
            {
                _log($"[{collectionName}] LiveResponse: folder not found — skipping.");
            }
        }

        // systemd user journal files (user-1000.journal, user-1001.journal, …)
        if (_config.ParseJournal)
        {
            var journalFiles = Directory.EnumerateFiles(
                    rootPath, "user-*.journal", SearchOption.AllDirectories)
                .OrderBy(f => f)
                .ToList();

            if (journalFiles.Count > 0)
            {
                _log($"[{collectionName}] Parsing {journalFiles.Count} journal file(s)…");

                const string logKey = "JOURNAL";
                var allFindings = new List<string>();
                var perFileFindings = new List<(string FileName, List<string> Findings)>();
                var combinedPatterns = new Dictionary<string, int>();
                DateTime jFirst = DateTime.MaxValue, jLast = DateTime.MinValue;

                var csvPath = Path.Combine(outputDir, "Normalized_JOURNAL.csv");
                using var csv = new NormalizedCsvWriter(csvPath, append: false);
                var journalParser = new JournalFileParser();
                TryAttach(journalParser, csv);
                TryAttach(journalParser, hostname);

                perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

                foreach (var jFile in journalFiles)
                {
                    _log($"Parsing {Path.GetFileName(jFile)}");

                    // ParseFile returns findings WITHOUT writing to QuickWins,
                    // so we can write ONE combined section below.
                    var (findings, patterns, first, last) = journalParser.ParseFile(jFile);

                    perFileTimestamps[logKey][Path.GetFileName(jFile)] = (first, last);

                    if (findings.Count > 0)
                        perFileFindings.Add((jFile, findings));

                    allFindings.AddRange(findings);

                    foreach (var kv in patterns)
                        combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                            ? ex + kv.Value : kv.Value;

                    if (first != DateTime.MaxValue && first < jFirst) jFirst = first;
                    if (last != DateTime.MinValue && last > jLast) jLast = last;
                }

                // Write ONE combined section with per-file subheaders
                if (perFileFindings.Count > 0)
                {
                    var quickWinsFile = Path.Combine(outputDir, "QuickWins.txt");
                    using var w = new StreamWriter(quickWinsFile, append: true);
                    w.WriteLine();
                    w.WriteLine("########## [JOURNAL] Suspicious Findings ##########");
                    w.WriteLine();

                    foreach (var (fileName, fileFindings) in perFileFindings)
                    {
                        // Strip everything before \[root]\ for a cleaner path
                        var displayPath = fileName;
                        var rootIdx = fileName.IndexOf(@"\[root]\", StringComparison.OrdinalIgnoreCase);
                        if (rootIdx >= 0) displayPath = fileName.Substring(rootIdx);
                        w.WriteLine($"  --- {displayPath} ---");
                        foreach (var finding in fileFindings)
                            w.WriteLine($"  >> {finding}");
                        w.WriteLine();
                    }

                    w.WriteLine("########## End of [JOURNAL] Suspicious Findings ##########");
                }

                suspiciousLogs[logKey] = allFindings;
                patternCounts[logKey] = combinedPatterns;
                firstLastSeen[logKey] = (jFirst, jLast);
                ipLogs[logKey] = new Dictionary<string, int>();
                fileCounts[logKey] = journalFiles.Count;
            }
            else
            {
                _log($"[{collectionName}] Journal: no user-*.journal files found — skipping.");
            }
        }

        // CRON findings written by ParseGrouped above

        // ── Bash history ─────────────────────────────────────────────
        if (_config.ParseBashHistory)
        {
            var histFiles = Parsers.BashHistoryParser.DiscoverHistoryFiles(rootPath);

            if (histFiles.Count > 0)
            {
                _log($"[{collectionName}] Parsing {histFiles.Count} bash_history file(s)…");

                const string logKey = "BASH";
                var allFindings = new List<string>();
                var perFileFindings = new List<(string File, List<string> Findings)>();
                var combinedPatterns = new Dictionary<string, int>();
                DateTime bashFirst = DateTime.MaxValue, bashLast = DateTime.MinValue;

                using var bashCsv = new NormalizedCsvWriter(
                    Path.Combine(outputDir, "Normalized_BASH.csv"), append: false);

                var bashParser = new Parsers.BashHistoryParser();
                bashParser.AttachNormalizedWriter(bashCsv);
                bashParser.AttachHostname(hostname);

                perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

                foreach (var (filePath, username) in histFiles)
                {
                    _log($"Parsing bash_history: {username}");
                    var (findings, patterns, first, last) = bashParser.ParseFile(filePath, username);

                    perFileTimestamps[logKey][username] = (first, last);

                    if (findings.Count > 0)
                        perFileFindings.Add((filePath, findings));

                    allFindings.AddRange(findings);

                    foreach (var kv in patterns)
                        combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                            ? ex + kv.Value : kv.Value;

                    if (first != DateTime.MaxValue && first < bashFirst) bashFirst = first;
                    if (last != DateTime.MinValue && last > bashLast) bashLast = last;
                }

                // Write ONE combined QuickWins section with per-user subheaders
                if (perFileFindings.Count > 0)
                {
                    var quickWinsFile = Path.Combine(outputDir, "QuickWins.txt");
                    using var w = new StreamWriter(quickWinsFile, append: true);
                    w.WriteLine();
                    w.WriteLine("########## [BASH] Suspicious Findings ##########");
                    w.WriteLine();

                    foreach (var (file, fileFindings) in perFileFindings)
                    {
                        w.WriteLine($"  --- {Path.GetFileName(file)} ---");
                        foreach (var finding in fileFindings)
                            w.WriteLine($"  >> {finding}");
                        w.WriteLine();
                    }

                    w.WriteLine("########## End of [BASH] Suspicious Findings ##########");
                }

                suspiciousLogs[logKey] = allFindings;
                patternCounts[logKey] = combinedPatterns;
                firstLastSeen[logKey] = (bashFirst, bashLast);
                ipLogs[logKey] = new Dictionary<string, int>();
                fileCounts[logKey] = histFiles.Count;
            }
            else
            {
                _log($"[{collectionName}] Bash: no bash_history files found — skipping.");
            }
        }

        // ── Zsh history ──────────────────────────────────────────────
        if (_config.ParseZsh)
        {
            using var zshCsv = new NormalizedCsvWriter(Path.Combine(outputDir, "Normalized_ZSH.csv"), append: false);
            var zshParser = new Parsers.ZshHistoryParser();
            zshParser.AttachNormalizedWriter(zshCsv);
            zshParser.AttachHostname(hostname);
            RunUserHistoryBlock("ZSH", collectionName, outputDir, hostname,
                Parsers.ZshHistoryParser.DiscoverFiles(rootPath),
                (p, u) => zshParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // ── VimInfo ───────────────────────────────────────────────────
        if (_config.ParseVimInfo)
        {
            using var vimCsv = new NormalizedCsvWriter(Path.Combine(outputDir, "Normalized_VIMINFO.csv"), append: false);
            var vimParser = new Parsers.VimInfoParser();
            vimParser.AttachNormalizedWriter(vimCsv);
            vimParser.AttachHostname(hostname);
            RunUserHistoryBlock("VIMINFO", collectionName, outputDir, hostname,
                Parsers.VimInfoParser.DiscoverFiles(rootPath),
                (p, u) => vimParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // ── Database history ──────────────────────────────────────────
        if (_config.ParseDbHistory)
        {
            using var dbCsv = new NormalizedCsvWriter(Path.Combine(outputDir, "Normalized_DBHISTORY.csv"), append: false);
            var dbParser = new Parsers.DbHistoryParser();
            dbParser.AttachNormalizedWriter(dbCsv);
            dbParser.AttachHostname(hostname);
            RunUserHistoryBlock("DBHISTORY", collectionName, outputDir, hostname,
                Parsers.DbHistoryParser.DiscoverFiles(rootPath),
                (p, u) => dbParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // ── Python history ────────────────────────────────────────────
        if (_config.ParsePythonHistory)
        {
            using var pyCsv = new NormalizedCsvWriter(Path.Combine(outputDir, "Normalized_PYHISTORY.csv"), append: false);
            var pyParser = new Parsers.PythonHistoryParser();
            pyParser.AttachNormalizedWriter(pyCsv);
            pyParser.AttachHostname(hostname);
            RunUserHistoryBlock("PYHISTORY", collectionName, outputDir, hostname,
                Parsers.PythonHistoryParser.DiscoverFiles(rootPath),
                (p, u) => pyParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // ── Wget HSTS ─────────────────────────────────────────────────
        if (_config.ParseWgetHsts)
        {
            using var wgetCsv = new NormalizedCsvWriter(Path.Combine(outputDir, "Normalized_WGETHSTS.csv"), append: false);
            var wgetParser = new Parsers.WgetHstsParser();
            wgetParser.AttachNormalizedWriter(wgetCsv);
            wgetParser.AttachHostname(hostname);
            RunUserHistoryBlock("WGETHSTS", collectionName, outputDir, hostname,
                Parsers.WgetHstsParser.DiscoverFiles(rootPath),
                (p, u) => wgetParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // ── Less history ──────────────────────────────────────────────
        if (_config.ParseLessHst)
        {
            using var lessCsv = new NormalizedCsvWriter(Path.Combine(outputDir, "Normalized_LESSHST.csv"), append: false);
            var lessParser = new Parsers.LessHstParser();
            lessParser.AttachNormalizedWriter(lessCsv);
            lessParser.AttachHostname(hostname);
            RunUserHistoryBlock("LESSHST", collectionName, outputDir, hostname,
                Parsers.LessHstParser.DiscoverFiles(rootPath),
                (p, u) => lessParser.ParseFile(p, u),
                suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);
        }

        // Finalise QuickWins
        DateTime? overallFirst = null, overallLast = null;
        foreach (var fl in firstLastSeen.Values)
        {
            // Exclude both sentinels: firstSeen starts at MaxValue, lastSeen at MinValue
            if (fl.Item1 != DateTime.MinValue && fl.Item1 != DateTime.MaxValue)
                overallFirst = overallFirst == null ? fl.Item1
                    : fl.Item1 < overallFirst ? fl.Item1 : overallFirst;
            if (fl.Item2 != DateTime.MinValue && fl.Item2 != DateTime.MaxValue)
                overallLast = overallLast == null ? fl.Item2
                    : fl.Item2 > overallLast ? fl.Item2 : overallLast;
        }

        QuickWinsHeader.UpsertTimeline(outputDir, overallFirst, overallLast);

        var globalLines = GlobalQuickWinsSummary.Build(
            suspiciousLogs, patternCounts, firstLastSeen, ipLogs, fileCounts, perFileTimestamps);

        // Insert global section immediately after Timeline Coverage so analysts
        // see the most important findings before the per-parser detail sections.
        QuickWinsHeader.InsertGlobalAfterTimeline(outputDir, "[GLOBAL] Summary", globalLines);
        QuickWinsSummaries.AppendPerLogSummaries(
            outputDir, suspiciousLogs, patternCounts, firstLastSeen, fileCounts);

        if (_config.OutputCollapseDups)
        {
            QuickWinsTidy.GroupSuspiciousFindingsUniform(outputDir);
            QuickWinsTidy.CollapseVerboseSessions(outputDir, 5);
            // CollapseCronDuplicates removed — grouping done at parse time
            QuickWinsTidy.CollapseSyslogDuplicates(outputDir, 2);
            QuickWinsTidy.CollapseMessagesDuplicates(outputDir, 2);
        }

        _log($"[{collectionName}] QuickWins written.");
    }

    // ── Crontab definition file scanner ─────────────────────────────
    private void ParseCrontabFiles(
        string rootPath,
        string outputDir,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        const string logKey = "CRONTAB";

        var crontabFiles = CrontabScanner.DiscoverCrontabFiles(rootPath);
        fileCounts[logKey] = crontabFiles.Count;
        perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

        if (crontabFiles.Count == 0)
        {
            _log("CRONTAB: no crontab definition files found.");
            return;
        }

        _log($"CRONTAB: scanning {crontabFiles.Count} crontab file(s)…");

        var csvPath = Path.Combine(outputDir, "Normalized_CRONTAB.csv");
        using var csv = new NormalizedCsvWriter(csvPath, append: false);
        var scanner = new CrontabScanner();
        TryAttach(scanner, csv);

        var allFindings = new List<string>();
        var perFileFindings = new List<(string FilePath, List<string> Findings)>();
        var combinedPatterns = new Dictionary<string, int>();
        DateTime combFirst = DateTime.MaxValue;
        DateTime combLast = DateTime.MinValue;

        foreach (var file in crontabFiles)
        {
            var (findings, patterns, first, last) = scanner.ParseFile(file);

            perFileTimestamps[logKey][Path.GetFileName(file)] = (first, last);

            if (findings.Count > 0)
                perFileFindings.Add((file, findings));

            allFindings.AddRange(findings);

            foreach (var kv in patterns)
                combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                    ? ex + kv.Value : kv.Value;

            if (first != DateTime.MaxValue && first < combFirst) combFirst = first;
            if (last != DateTime.MinValue && last > combLast) combLast = last;
        }

        // Write section
        var quickWinsFile = Path.Combine(outputDir, "QuickWins.txt");
        using var w = new StreamWriter(quickWinsFile, append: true);
        w.WriteLine();
        w.WriteLine("########## [CRONTAB] Suspicious Job Definitions ##########");
        w.WriteLine();

        if (perFileFindings.Count == 0)
        {
            w.WriteLine("  No suspicious crontab entries found.");
        }
        else
        {
            foreach (var (filePath, fileFindings) in perFileFindings)
            {
                var displayPath = filePath;
                var rootIdx = filePath.IndexOf(@"\[root]",
                    StringComparison.OrdinalIgnoreCase);
                if (rootIdx >= 0) displayPath = filePath.Substring(rootIdx);

                w.WriteLine($"  --- {displayPath} ---");
                foreach (var finding in fileFindings)
                    w.WriteLine($"  >> {finding}");
                w.WriteLine();
            }
        }

        w.WriteLine("########## End of [CRONTAB] Suspicious Job Definitions ##########");

        suspiciousLogs[logKey] = allFindings;
        patternCounts[logKey] = combinedPatterns;
        firstLastSeen[logKey] = (combFirst, combLast);
        ipLogs[logKey] = new Dictionary<string, int>();
    }

    // ── Generic grouped log handler ──────────────────────────────────
    // Calls ParseFile() on each discovered log file and writes ONE combined
    // section header with per-file subheaders. Requires the parser to expose
    // a ParseFile(string) method returning (Findings, Patterns, First, Last).
    private void ParseGrouped(
        string baseName,
        LogFileParser parser,
        string logKey,
        string rootPath,
        string outputDir,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        var logFiles = Directory.EnumerateFiles(rootPath, baseName + "*",
                SearchOption.AllDirectories)
            .Where(f =>
                f.EndsWith(baseName, StringComparison.OrdinalIgnoreCase) ||
                f.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ||
                f.EndsWith(".1", StringComparison.OrdinalIgnoreCase) ||
                Regex.IsMatch(f, $@"{Regex.Escape(baseName)}\.\d+(\.gz)?$",
                    RegexOptions.IgnoreCase))
            .OrderBy(f => f)
            .ToList();

        fileCounts[logKey] = logFiles.Count;
        perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

        if (logFiles.Count == 0) return;

        // Attach CSV writer if supported
        var csvPath = Path.Combine(outputDir, $"Normalized_{logKey}.csv");
        using var csv = new NormalizedCsvWriter(csvPath, append: false);
        TryAttach(parser, csv);

        var allFindings = new List<string>();
        var perFileFindings = new List<(string LogFile, List<string> Findings)>();
        var combinedPatterns = new Dictionary<string, int>();
        var combinedIPs = new Dictionary<string, int>();
        DateTime combFirst = DateTime.MaxValue;
        DateTime combLast = DateTime.MinValue;

        // Use reflection to call ParseFile if available, otherwise fall back to
        // ProcessLogAndWriteQuickWins so existing parsers without ParseFile still work.
        var parseFileMethod = parser.GetType().GetMethod("ParseFile",
            new[] { typeof(string) });

        foreach (var logFile in logFiles)
        {
            string parsePath = logFile;
            string? tempPath = null;

            if (logFile.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                tempPath = Path.Combine(Path.GetTempPath(),
                    Path.GetFileNameWithoutExtension(logFile) + "_" + Guid.NewGuid().ToString("N"));
                using var inFs = File.OpenRead(logFile);
                using var outFs = File.Create(tempPath);
                using var gz = new GZipStream(inFs, CompressionMode.Decompress);
                gz.CopyTo(outFs);
                parsePath = tempPath;
            }

            _log($"Parsing {Path.GetFileName(parsePath)}");

            List<string> findings;
            Dictionary<string, int> patterns;
            DateTime first, last;

            if (parseFileMethod != null)
            {
                // Value tuple element names (Findings/Patterns/First/Last) are
                // compile-time only — at runtime via reflection use Item1..Item4.
                var result = parseFileMethod.Invoke(parser, new object[] { parsePath })!;
                var resultTuple = (System.Runtime.CompilerServices.ITuple)result;
                findings = (List<string>)resultTuple[0];
                patterns = (Dictionary<string, int>)resultTuple[1];
                first = (DateTime)resultTuple[2];
                last = (DateTime)resultTuple[3];
            }
            else
            {
                (findings, patterns, first, last) =
                    parser.ProcessLogAndWriteQuickWins(parsePath, outputDir, combinedIPs);
            }

            perFileTimestamps[logKey][Path.GetFileName(logFile)] = (first, last);

            if (findings.Count > 0)
                perFileFindings.Add((logFile, findings));

            allFindings.AddRange(findings);

            foreach (var kv in patterns)
                combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                    ? ex + kv.Value : kv.Value;

            if (first != DateTime.MaxValue && first < combFirst) combFirst = first;
            if (last != DateTime.MinValue && last > combLast) combLast = last;

            if (tempPath != null && File.Exists(tempPath))
                File.Delete(tempPath);
        }

        // Write ONE combined section with per-file subheaders
        if (perFileFindings.Count > 0)
        {
            var quickWinsFile = Path.Combine(outputDir, "QuickWins.txt");
            using var w = new StreamWriter(quickWinsFile, append: true);
            w.WriteLine();
            w.WriteLine($"########## [{logKey}] Suspicious Findings ##########");
            w.WriteLine();

            foreach (var (lf, fileFindings) in perFileFindings)
            {
                var displayPath = lf;
                var rootIdx = lf.IndexOf(@"\[root]", StringComparison.OrdinalIgnoreCase);
                if (rootIdx >= 0) displayPath = lf.Substring(rootIdx);

                w.WriteLine($"  --- {displayPath} ---");
                foreach (var finding in fileFindings)
                    w.WriteLine($"  >> {finding}");
                w.WriteLine();
            }

            w.WriteLine($"########## End of [{logKey}] Suspicious Findings ##########");
        }

        suspiciousLogs[logKey] = allFindings;
        patternCounts[logKey] = combinedPatterns;
        firstLastSeen[logKey] = (combFirst, combLast);
        ipLogs[logKey] = combinedIPs;
    }

    // ── Auth / Secure log handler (grouped — ONE section header) ────────
    private void ParseAuthLogs(
        string rootPath,
        string outputDir,
        SessionTracker sessionTracker,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        // auth.log + auth.log.1 + auth.log.2.gz  AND  secure + secure.1 etc.
        var baseNames = new[] { "auth.log", "secure" };

        foreach (var baseName in baseNames)
        {
            string logKey = baseName.ToUpperInvariant();

            var logFiles = Directory.EnumerateFiles(rootPath, baseName + "*",
                    SearchOption.AllDirectories)
                .Where(f =>
                    f.EndsWith(baseName, StringComparison.OrdinalIgnoreCase) ||
                    f.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ||
                    f.EndsWith(".1", StringComparison.OrdinalIgnoreCase) ||
                    Regex.IsMatch(f, $@"{Regex.Escape(baseName)}\.\d+(\.gz)?$",
                        RegexOptions.IgnoreCase))
                .OrderBy(f => f)
                .ToList();

            fileCounts[logKey] = logFiles.Count;
            perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

            if (logFiles.Count == 0) continue;

            var csvPath = Path.Combine(outputDir, $"Normalized_{logKey.Replace(".", "_")}.csv");
            using var csv = new NormalizedCsvWriter(csvPath, append: false);
            var parser = new AuthSecureLogParser();
            TryAttach(parser, sessionTracker);
            TryAttach(parser, csv);

            var allFindings = new List<string>();
            var perFileFindings = new List<(string FilePath, List<string> Findings)>();
            var combinedPatterns = new Dictionary<string, int>();
            var combinedIPs = new Dictionary<string, int>();
            DateTime combFirst = DateTime.MaxValue;
            DateTime combLast = DateTime.MinValue;

            foreach (var logFile in logFiles)
            {
                string parsePath = logFile;
                string? tempPath = null;

                if (logFile.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                {
                    tempPath = Path.Combine(Path.GetTempPath(),
                        Path.GetFileNameWithoutExtension(logFile) + "_" + Guid.NewGuid().ToString("N"));
                    using var inFs = File.OpenRead(logFile);
                    using var outFs = File.Create(tempPath);
                    using var gz = new GZipStream(inFs, CompressionMode.Decompress);
                    gz.CopyTo(outFs);
                    parsePath = tempPath;
                }

                _log($"Parsing {Path.GetFileName(parsePath)}");

                var (findings, patterns, first, last) = parser.ParseFile(parsePath);

                perFileTimestamps[logKey][Path.GetFileName(logFile)] = (first, last);

                if (findings.Count > 0)
                    perFileFindings.Add((logFile, findings)); // logFile = original path, not temp

                allFindings.AddRange(findings);

                foreach (var kv in patterns)
                    combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                        ? ex + kv.Value : kv.Value;

                if (first != DateTime.MaxValue && first < combFirst) combFirst = first;
                if (last != DateTime.MinValue && last > combLast) combLast = last;

                if (tempPath != null && File.Exists(tempPath))
                    File.Delete(tempPath);
            }

            // Write ONE combined section with per-file subheaders
            if (perFileFindings.Count > 0)
            {
                var quickWinsFile = Path.Combine(outputDir, "QuickWins.txt");
                using var w = new StreamWriter(quickWinsFile, append: true);
                w.WriteLine();
                w.WriteLine($"########## [{logKey}] Suspicious Findings ##########");
                w.WriteLine();

                foreach (var (filePath, fileFindings) in perFileFindings)
                {
                    // Strip everything before \[root]\ for a cleaner display path
                    var displayPath = filePath;
                    var rootIdx = filePath.IndexOf(@"\[root]", StringComparison.OrdinalIgnoreCase);
                    if (rootIdx >= 0) displayPath = filePath.Substring(rootIdx);

                    w.WriteLine($"  --- {displayPath} ---");
                    foreach (var finding in fileFindings)
                        w.WriteLine($"  >> {finding}");
                    w.WriteLine();
                }

                w.WriteLine($"########## End of [{logKey}] Suspicious Findings ##########");
            }

            suspiciousLogs[logKey] = allFindings;
            patternCounts[logKey] = combinedPatterns;
            firstLastSeen[logKey] = (combFirst, combLast);
            ipLogs[logKey] = combinedIPs;
        }

        // ── Session output ────────────────────────────────────────────────
        var stats = sessionTracker.GetStatistics();

        // 1. Suspicious sessions → RTF (actionable: root SSH, odd hours, service account SSH etc.)
        var suspiciousLines = sessionTracker.GenerateSuspiciousSummary("AUTH");
        if (suspiciousLines?.Count > 0)
        {
            var quickWinsFile = Path.Combine(outputDir, "QuickWins.txt");
            using var w = new StreamWriter(quickWinsFile, append: true);
            w.WriteLine();
            w.WriteLine("########## [AUTH] Suspicious Sessions ##########");
            // Stats one-liner so analyst knows the full scale
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

        // 2. Sessions CSV — grouped by User+IP+Type, CRON/systemd noise excluded
        var csvSessionPath = Path.Combine(outputDir, "Sessions_AUTH.csv");
        try
        {
            var allSessions = sessionTracker.GetAllSessions();

            var grouped = allSessions
                .Where(s => s.Type.ToString() != "CronJob"
                         && s.Type.ToString() != "SystemdSession"
                         && s.Type.ToString() != "PamGeneric")
                .GroupBy(s => new { s.Username, s.SourceIP, s.Daemon, Type = s.Type.ToString() })
                .Select(g => (
                    g.Key.Username,
                    g.Key.SourceIP,
                    g.Key.Daemon,
                    g.Key.Type,
                    Count: g.Count(),
                    FirstSeen: g.Min(s => s.StartTime),
                    LastSeen: g.Max(s => s.StartTime),
                    AvgDur: (int)g.Average(s => s.DurationSeconds),
                    Suspicious: g.Any(s => s.IsSuspicious) ? "Yes" : "No",
                    Reason: g.Where(s => s.IsSuspicious)
                                  .Select(s => s.SuspicionReason.ToString())
                                  .FirstOrDefault() ?? "",
                    Notes: g.Where(s => s.IsSuspicious)
                                  .Select(s => s.Notes)
                                  .FirstOrDefault() ?? ""))
                .OrderByDescending(g => g.Suspicious)
                .ThenByDescending(g => g.Count);

            static string E(string s) =>
                s == null ? "" : "\"" + s.Replace("\"", "\"\"") + "\"";

            using var csv = new System.IO.StreamWriter(csvSessionPath, append: false,
                encoding: new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

            csv.WriteLine("User,IP,Daemon,Type,Count,FirstSeen,LastSeen,AvgDurationSec,Suspicious,Reason,Notes");

            foreach (var g in grouped)
            {
                csv.WriteLine(string.Join(",",
                    E(g.Username),
                    E(g.SourceIP),
                    E(g.Daemon),
                    E(g.Type),
                    g.Count,
                    E(g.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss")),
                    E(g.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")),
                    g.AvgDur,
                    E(g.Suspicious),
                    E(g.Reason),
                    E(g.Notes)
                ));
            }
        }
        catch (Exception ex)
        {
            _log($"[WARN] Could not write Sessions_AUTH.csv: {ex.Message}");
        }
    }

    // ── Generic log file handler (mirrors Form1.ParseLogWithHandler) ──
    private void ParseLogFiles(
        LogFileParser parser,
        string searchRoot,
        string baseFileName,
        string outputDir,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        var logFiles = Directory.EnumerateFiles(searchRoot, baseFileName + "*",
                SearchOption.AllDirectories)
            .Where(f =>
                f.EndsWith(baseFileName, StringComparison.OrdinalIgnoreCase) ||
                f.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) ||
                f.EndsWith(".1", StringComparison.OrdinalIgnoreCase) ||
                Regex.IsMatch(f, $@"{Regex.Escape(baseFileName)}\.\d+(\.gz)?$",
                    RegexOptions.IgnoreCase))
            .OrderBy(f => f)
            .ToList();

        string logKey = baseFileName.ToUpperInvariant();
        fileCounts[logKey] = logFiles.Count;
        perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

        if (logFiles.Count == 0) return;

        var allFindings = new List<string>();
        var combinedPatterns = new Dictionary<string, int>();
        var combinedIPs = new Dictionary<string, int>();
        DateTime combinedFirst = DateTime.MaxValue;
        DateTime combinedLast = DateTime.MinValue;

        foreach (var logFile in logFiles)
        {
            string parsePath = logFile;
            string? tempPath = null;

            if (logFile.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                tempPath = Path.Combine(Path.GetTempPath(),
                    Path.GetFileNameWithoutExtension(logFile) + "_" + Guid.NewGuid().ToString("N"));

                using var inFs = File.OpenRead(logFile);
                using var outFs = File.Create(tempPath);
                using var gz = new GZipStream(inFs, CompressionMode.Decompress);
                gz.CopyTo(outFs);
                parsePath = tempPath;
            }

            _log($"Parsing {Path.GetFileName(parsePath)}");

            var (findings, patterns, first, last) =
                parser.ProcessLogAndWriteQuickWins(parsePath, outputDir, combinedIPs);

            perFileTimestamps[logKey][Path.GetFileName(logFile)] = (first, last);
            allFindings.AddRange(findings);

            foreach (var kvp in patterns)
                combinedPatterns[kvp.Key] = combinedPatterns.TryGetValue(kvp.Key, out var existing)
                    ? existing + kvp.Value : kvp.Value;

            if (first < combinedFirst) combinedFirst = first;
            if (last > combinedLast) combinedLast = last;

            if (tempPath != null && File.Exists(tempPath))
                File.Delete(tempPath);
        }

        suspiciousLogs[logKey] = allFindings;
        patternCounts[logKey] = combinedPatterns;
        firstLastSeen[logKey] = (combinedFirst, combinedLast);
        ipLogs[logKey] = new Dictionary<string, int>(combinedIPs);
    }

    // ── Web log handler (discovery-based) ────────────────────────────
    private void ParseWebLogs(
        WebLogParser parser,
        WebBruteForceDetector bfd,
        string rootPath,
        string outputDir,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        const string logKey = "WEB";

        var allCandidates = WebLogParser.DiscoverWebLogFiles(rootPath);
        var webLogs = allCandidates
            .Where(p => Path.GetFileName(p).IndexOf("access",
                StringComparison.OrdinalIgnoreCase) >= 0)
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToList();

        fileCounts[logKey] = webLogs.Count;
        perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

        if (webLogs.Count == 0)
        {
            _log("WEB: no access logs discovered.");
            return;
        }

        var allFindings = new List<string>();
        var perFileFindings = new List<(string LogFile, List<string> Findings)>();
        var combinedPatterns = new Dictionary<string, int>();
        var combinedIPs = new Dictionary<string, int>();
        DateTime first = DateTime.MaxValue, last = DateTime.MinValue;

        foreach (var logFile in webLogs)
        {
            string parsePath = logFile;
            string? tempPath = null;

            if (logFile.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
            {
                tempPath = Path.Combine(Path.GetTempPath(),
                    Path.GetFileNameWithoutExtension(logFile) + "_" +
                    Guid.NewGuid().ToString("N"));
                using var inFs = File.OpenRead(logFile);
                using var outFs = File.Create(tempPath);
                using var gz = new GZipStream(inFs, CompressionMode.Decompress);
                gz.CopyTo(outFs);
                parsePath = tempPath;
            }

            _log($"Parsing WEB {Path.GetFileName(logFile)}");

            var (findings, patterns, fileFirst, fileLast) = parser.ParseFile(parsePath);

            perFileTimestamps[logKey][Path.GetFileName(logFile)] = (fileFirst, fileLast);

            if (findings.Count > 0)
                perFileFindings.Add((logFile, findings));

            allFindings.AddRange(findings);

            foreach (var kvp in patterns)
                combinedPatterns[kvp.Key] = combinedPatterns.TryGetValue(kvp.Key, out var ex)
                    ? ex + kvp.Value : kvp.Value;

            if (fileFirst != DateTime.MaxValue && fileFirst < first) first = fileFirst;
            if (fileLast != DateTime.MinValue && fileLast > last) last = fileLast;

            if (tempPath != null && File.Exists(tempPath))
                File.Delete(tempPath);
        }

        // Brute-force findings from shared detector (covers all files combined)
        // Fix: build bruteList separately — tuple value types can't be mutated via First()
        var bruteFindings = bfd.GetFindings();
        var bruteList = new List<string>();
        foreach (var bf in bruteFindings)
        {
            string bfLine = $"[WEB] [BRUTEFORCE] {bf.Replace("[WEBLOG] [BRUTEFORCE] ", "")}";
            allFindings.Add(bfLine);
            bruteList.Add(bfLine);
        }

        // Write ONE combined section — always write if any files were parsed,
        // even if no attack findings, so the RTF always has a WEB section.
        var quickWinsFile = Path.Combine(outputDir, "QuickWins.txt");
        using var w = new StreamWriter(quickWinsFile, append: true);
        w.WriteLine();
        w.WriteLine("########## [WEB] Suspicious Findings ##########");
        w.WriteLine();

        if (perFileFindings.Count == 0 && bruteList.Count == 0)
        {
            w.WriteLine("  No suspicious web requests detected.");
            w.WriteLine();
        }
        else
        {
            foreach (var (lf, fileFindings) in perFileFindings)
            {
                var displayPath = lf;
                var rootIdx = lf.IndexOf(@"\[root]", StringComparison.OrdinalIgnoreCase);
                if (rootIdx >= 0) displayPath = lf.Substring(rootIdx);
                w.WriteLine($"  --- {displayPath} ---");

                foreach (var finding in fileFindings)
                    w.WriteLine($"  >> {finding}");
                w.WriteLine();
            }

            if (bruteList.Count > 0)
            {
                w.WriteLine("  --- Brute-force detections (all files combined) ---");
                foreach (var bf in bruteList)
                    w.WriteLine($"  >> {bf}");
                w.WriteLine();
            }
        }

        w.WriteLine("########## End of [WEB] Suspicious Findings ##########");

        suspiciousLogs[logKey] = allFindings;
        patternCounts[logKey] = combinedPatterns;
        firstLastSeen[logKey] = (first, last);
        ipLogs[logKey] = new Dictionary<string, int>(combinedIPs);
    }

    // ── Body file ────────────────────────────────────────────────────
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

        var parsed = Helpers.BodyFileProcessor.ProcessBodyFile(bodyfilePath, outputDir);

        QuickWinsHeader.EnsureHeader(outputDir, DateTime.UtcNow, parsed.FirstLogUtc, parsed.LastLogUtc);
        QuickWinsAppend.WriteProcessedBodyFileCsv(outputDir, parsed);
        QuickWinsAppend.AppendBodyFileFindings(outputDir, parsed.Findings);

        _log($"[{collectionName}] Body file done.");
    }

    // ── Live response artefacts ───────────────────────────────────────
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

        if (_config.ParsePersistence)
            TryAppendPersistence(lines, liveResponseRoot, ref first, ref last);

        if (_config.ParseDocker)
            TryAppendDockerHints(lines, liveResponseRoot, ref first, ref last);

        var writer = new LiveResponseWriter(outDir);
        writer.WriteHeader("Live Response – DFIR");
        writer.WriteSection("Live Response Report", lines);

        _log($"LiveResponse: wrote {lines.Count} lines.");
    }

    // ── Live response helpers (mirrors Form1) ─────────────────────────
    private void TryAppendBlock(List<string> lines, string root,
        ref DateTime first, ref DateTime last, string header, string[] names, int take)
    {
        var path = FindFirst(root, names);
        if (path == null) return;
        lines.Add(header);
        foreach (var ln in SafeRead(path).Take(take))
        {
            lines.Add(ln);
            UpdateTimestamps(ln, ref first, ref last);
        }
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
        if (shadow != null)
        {
            lines.Add("-- /etc/shadow (redacted) --");
            lines.AddRange(SafeRead(shadow).Select(RedactHash).Take(50)); lines.Add("");
        }
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
            foreach (var ln in SafeRead(f!).Take(150))
            {
                lines.Add(ln);
                UpdateTimestamps(ln, ref first, ref last);
            }
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
            lines.AddRange(Directory.EnumerateFiles(docker, "*", SearchOption.AllDirectories)
                .Take(30).Select(Path.GetFileName)!);
        }
        else
        {
            foreach (var ln in SafeRead(docker).Take(200))
            {
                lines.Add(ln);
                UpdateTimestamps(ln, ref first, ref last);
            }
        }
        lines.Add("");
    }

    // ── Static helpers ────────────────────────────────────────────────
    private static string? FindFirst(string root, string[] names)
    {
        foreach (var n in names)
        {
            var entry = Directory.EnumerateFileSystemEntries(root, n, SearchOption.AllDirectories)
                                 .FirstOrDefault();
            if (!string.IsNullOrEmpty(entry)) return entry;
        }
        return null;
    }

    private static IEnumerable<string> SafeRead(string path)
    {
        try { return File.ReadLines(path); }
        catch { return Array.Empty<string>(); }
    }

    private static string RedactHash(string line) =>
        Regex.Replace(line, @"^([^:]*:)[^:]*(:.*)$", "$1********$2");

    private static void UpdateTimestamps(string line, ref DateTime first, ref DateTime last)
    {
        var m = Regex.Match(line, @"\b(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})\b");
        if (!m.Success) return;
        if (!DateTime.TryParse(m.Value, out var dt)) return;
        if (first == DateTime.MinValue || dt < first) first = dt;
        if (dt > last) last = dt;
    }

    // ── Reflection helpers (mirrors Form1) ────────────────────────────
    private static void TryAttach(object target, SessionTracker tracker)
    {
        var m = target.GetType().GetMethod("AttachSessionTracker", new[] { typeof(SessionTracker) });
        m?.Invoke(target, new object[] { tracker });
    }

    // ── User history parser helper ────────────────────────────────────
    // Shared block used by all user-history parsers (Zsh, VimInfo, DB, Python,
    // WgetHsts, LessHst). Handles discovery, parsing, QuickWins writing, and
    // stats population so each parser only needs a one-liner call site.
    private void RunUserHistoryBlock(
        string logKey,
        string collectionName,
        string outputDir,
        string hostname,
        List<(string FilePath, string Username)> files,
        Func<string, string, (List<string> Findings, Dictionary<string, int> Patterns, DateTime First, DateTime Last)> parseFile,
        Dictionary<string, List<string>> suspiciousLogs,
        Dictionary<string, Dictionary<string, int>> patternCounts,
        Dictionary<string, (DateTime, DateTime)> firstLastSeen,
        Dictionary<string, Dictionary<string, int>> ipLogs,
        Dictionary<string, int> fileCounts,
        Dictionary<string, Dictionary<string, (DateTime, DateTime)>> perFileTimestamps)
    {
        if (files.Count == 0)
        {
            _log($"[{collectionName}] {logKey}: no files found — skipping.");
            return;
        }

        _log($"[{collectionName}] Parsing {files.Count} {logKey} file(s)…");

        var allFindings = new List<string>();
        var perFileFindings = new List<(string File, List<string> Findings)>();
        var combinedPatterns = new Dictionary<string, int>();
        DateTime blockFirst = DateTime.MaxValue, blockLast = DateTime.MinValue;

        perFileTimestamps[logKey] = new Dictionary<string, (DateTime, DateTime)>();

        foreach (var (filePath, username) in files)
        {
            _log($"Parsing {logKey}: {username}");
            var (findings, patterns, first, last) = parseFile(filePath, username);

            perFileTimestamps[logKey][username] = (first, last);

            if (findings.Count > 0)
                perFileFindings.Add((filePath, findings));

            allFindings.AddRange(findings);

            foreach (var kv in patterns)
                combinedPatterns[kv.Key] = combinedPatterns.TryGetValue(kv.Key, out var ex)
                    ? ex + kv.Value : kv.Value;

            if (first != DateTime.MaxValue && first < blockFirst) blockFirst = first;
            if (last != DateTime.MinValue && last > blockLast) blockLast = last;
        }

        if (perFileFindings.Count > 0)
        {
            var quickWinsFile = Path.Combine(outputDir, "QuickWins.txt");
            using var w = new StreamWriter(quickWinsFile, append: true);
            w.WriteLine();
            w.WriteLine($"########## [{logKey}] Suspicious Findings ##########");
            w.WriteLine();
            foreach (var (file, fileFindings) in perFileFindings)
            {
                w.WriteLine($"  --- {Path.GetFileName(file)} ---");
                foreach (var finding in fileFindings)
                    w.WriteLine($"  >> {finding}");
                w.WriteLine();
            }
            w.WriteLine($"########## End of [{logKey}] Suspicious Findings ##########");
        }

        suspiciousLogs[logKey] = allFindings;
        patternCounts[logKey] = combinedPatterns;
        firstLastSeen[logKey] = (blockFirst, blockLast);
        ipLogs[logKey] = new Dictionary<string, int>();
        fileCounts[logKey] = files.Count;
    }

    private static void TryAttach(object target, NormalizedCsvWriter writer)
    {
        var m = target.GetType().GetMethod("AttachNormalizedWriter", new[] { typeof(NormalizedCsvWriter) });
        m?.Invoke(target, new object[] { writer });
    }

    private static void TryAttach(object target, string hostname)
    {
        var m = target.GetType().GetMethod("AttachHostname", new[] { typeof(string) });
        m?.Invoke(target, new object[] { hostname });
    }

    /// <summary>
    /// Derives the machine hostname from a UAC collection folder name.
    /// UAC naming convention: uac-&lt;hostname&gt;-YYYYMMDDHHmmss
    /// Falls back to the raw collection name if the pattern doesn't match.
    /// </summary>
    private static string ExtractHostnameFromCollection(string collectionName)
    {
        if (string.IsNullOrWhiteSpace(collectionName)) return string.Empty;
        var m = Regex.Match(collectionName,
            @"^uac-(?<host>.+?)-\d{14}$", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups["host"].Value : collectionName;
    }
}
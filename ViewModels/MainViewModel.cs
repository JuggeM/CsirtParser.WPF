using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Input;
using CsirtParser.WPF.Models;

using Application = System.Windows.Application;

namespace CsirtParser.WPF.ViewModels;

public class MainViewModel : ViewModelBase
{
    // ── Config shared across all panels ──────────────────────────────
    public ParserConfig Config { get; } = new();

    // ── Navigation ───────────────────────────────────────────────────
    private string _activePanel = "CaseSetup";
    public string ActivePanel
    {
        get => _activePanel;
        set => SetField(ref _activePanel, value);
    }

    public ICommand NavigateCommand { get; }

    // ── Case report panel ────────────────────────────────────────────
    public CaseReportViewModel Report { get; }

    // ── Scan state ───────────────────────────────────────────────────
    private bool _isScanning;
    public bool IsScanning
    {
        get => _isScanning;
        private set => SetField(ref _isScanning, value);
    }

    private string _scanStatus = string.Empty;
    public string ScanStatus
    {
        get => _scanStatus;
        private set => SetField(ref _scanStatus, value);
    }

    // ── Collections detected in the case folder ───────────────────────
    public ObservableCollection<string> DetectedCollections { get; } = new();

    // ── Status log shown in the Output panel ─────────────────────────
    public ObservableCollection<LogEntry> LogEntries { get; } = new();

    // ── Run state ────────────────────────────────────────────────────
    private bool _isRunning;
    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            SetField(ref _isRunning, value);
            OnPropertyChanged(nameof(CanRun));
            OnPropertyChanged(nameof(CanCancel));
        }
    }

    public bool CanRun => !IsRunning;
    public bool CanCancel => IsRunning;

    public ICommand RunCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand BrowseCommand { get; }
    public ICommand BrowseOutputCommand { get; }

    private string _runStatusText = "Ready";
    public string RunStatusText
    {
        get => _runStatusText;
        private set => SetField(ref _runStatusText, value);
    }

    // ── Progress (0.0 – 1.0) — bind to a ProgressBar in OutputView ───
    // Example XAML:
    //   <ProgressBar Value="{Binding Progress}" Maximum="1" Height="6"
    //                Visibility="{Binding IsRunning, Converter={...BoolToVisibility}}"/>
    //   <TextBlock Text="{Binding ProgressText}"/>
    private double _progress;
    public double Progress
    {
        get => _progress;
        private set
        {
            SetField(ref _progress, value);
            OnPropertyChanged(nameof(ProgressText));
        }
    }

    public string ProgressText => IsRunning
        ? $"{(int)(_progress * 100)} %"
        : string.Empty;

    // ── Cancellation ─────────────────────────────────────────────────
    private CancellationTokenSource? _cts;

    // ── Case IOC list (<case>\iocs.txt) ──────────────────────────────
    private string _iocText = string.Empty;
    private bool _iocDirty;
    private string? _iocLoadedFor;

    /// <summary>Editable IOC list text; parsed live for the preview line.</summary>
    public string IocText
    {
        get => _iocText;
        set
        {
            if (SetField(ref _iocText, value))
            {
                _iocDirty = true;
                UpdateIocPreview();
            }
        }
    }

    private string _iocPreview = "No IOCs yet — paste a list above.";
    public string IocPreview { get => _iocPreview; private set => SetField(ref _iocPreview, value); }

    private string _iocRejected = string.Empty;
    public string IocRejected { get => _iocRejected; private set => SetField(ref _iocRejected, value); }

    private string _iocStatus = string.Empty;
    public string IocStatus { get => _iocStatus; private set => SetField(ref _iocStatus, value); }

    private string _discoveredLabel = "Load discovered";
    public string DiscoveredLabel { get => _discoveredLabel; private set => SetField(ref _discoveredLabel, value); }

    public ICommand SaveIocsCommand { get; }
    public ICommand ImportIocsCommand { get; }
    public ICommand LoadDiscoveredCommand { get; }
    public ICommand SearchIocsCommand { get; }

    public MainViewModel()
    {
        Report = new CaseReportViewModel(Config);
        NavigateCommand = new RelayCommand(p =>
        {
            if (ActivePanel == "Report") Report.SaveIfDirty();
            ActivePanel = p as string ?? ActivePanel;
            if (ActivePanel == "Iocs") EnsureIocsLoaded();
            if (ActivePanel == "Report") Report.EnsureLoaded();
        });
        SaveIocsCommand = new RelayCommand(_ => SaveIocs());
        ImportIocsCommand = new RelayCommand(_ => BrowseIocFile());
        LoadDiscoveredCommand = new RelayCommand(_ => LoadDiscovered());
        SearchIocsCommand = new RelayCommand(_ => _ = SearchIocsAsync(), _ => CanRun);
        RunCommand = new RelayCommand(_ => _ = RunParserAsync(), _ => CanRun);
        CancelCommand = new RelayCommand(_ => RequestCancel(), _ => CanCancel);
        BrowseCommand = new RelayCommand(BrowseForFolder);
        BrowseOutputCommand = new RelayCommand(BrowseForOutput);
    }

    private void RequestCancel()
    {
        _cts?.Cancel();
        Log("Cancellation requested — stopping after the current parser…", LogLevel.Warning);
        RunStatusText = "Cancelling…";
    }

    // ── Folder browsers ──────────────────────────────────────────────
    private void BrowseForOutput(object? _)
    {
        var dlg = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = "Select the output folder",
            UseDescriptionForTitle = true,
            // Start in the current output folder (normally <case>\Processed),
            // not the case root — picking the root used to dump output there.
            SelectedPath = Directory.Exists(Config.ResolveOutputPath())
                                     ? Config.ResolveOutputPath()
                                     : Directory.Exists(Config.CaseFolderPath)
                                         ? Config.CaseFolderPath
                                         : string.Empty
        };
        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
        {
            Config.OutputPath = dlg.SelectedPath;
            OnPropertyChanged(nameof(Config));
        }
    }

    private void BrowseForFolder(object? _)
    {
        var dlg = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = "Select the UAC case folder",
            UseDescriptionForTitle = true
        };

        if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
        {
            var previousCase = Config.CaseFolderPath;
            Config.CaseFolderPath = dlg.SelectedPath;

            // Follow the new case unless the analyst chose a custom output
            // folder. Compare against the PREVIOUS case's defaults — the old
            // check compared with the already-updated path and never matched,
            // so output stayed in the previous case's folder.
            if (string.IsNullOrWhiteSpace(Config.OutputPath)
                || !Path.IsPathRooted(Config.OutputPath)
                || (!string.IsNullOrWhiteSpace(previousCase)
                    && (PathEquals(Config.OutputPath, Path.Combine(previousCase, "Processed"))
                        || PathEquals(Config.OutputPath, previousCase))))
            {
                Config.OutputPath = Path.Combine(dlg.SelectedPath, "Processed");
            }

            OnPropertyChanged(nameof(Config));
            _iocLoadedFor = null;
            EnsureIocsLoaded(force: true);
            _ = ScanForCollections();
        }
    }

    // ── Case IOC list ────────────────────────────────────────────────
    private bool HasCase => !string.IsNullOrWhiteSpace(Config.CaseFolderPath) && Directory.Exists(Config.CaseFolderPath);

    /// <summary>Loads iocs.txt for the current case (once per case; never over unsaved edits unless forced).</summary>
    private void EnsureIocsLoaded(bool force = false)
    {
        if (!HasCase) { IocStatus = "Choose a case folder first (Case setup)."; return; }
        if (!force && PathEqualsSafe(_iocLoadedFor, Config.CaseFolderPath)) { RefreshDiscoveredLabel(); return; }
        if (!force && _iocDirty && _iocLoadedFor != null) return;

        var path = Helpers.CaseIocs.PathFor(Config.CaseFolderPath);
        _iocText = File.Exists(path) ? File.ReadAllText(path) : string.Empty;
        OnPropertyChanged(nameof(IocText));
        _iocDirty = false;
        _iocLoadedFor = Config.CaseFolderPath;
        UpdateIocPreview();
        IocStatus = File.Exists(path) ? $"Loaded {path}" : $"No IOC list yet for this case — it will be saved to {path}";
        RefreshDiscoveredLabel();
    }

    private static bool PathEqualsSafe(string? a, string? b) =>
        !string.IsNullOrWhiteSpace(a) && !string.IsNullOrWhiteSpace(b) && PathEquals(a, b);

    private void UpdateIocPreview()
    {
        var (iocs, rejected) = Helpers.CaseIocs.Parse(_iocText);
        IocPreview = iocs.Count == 0 ? "No IOCs recognised yet." : Helpers.CaseIocs.Summary(iocs);
        IocRejected = rejected.Count == 0 ? string.Empty
            : $"{rejected.Count} line(s) without an IOC (dropped on save): " +
              string.Join("  |  ", rejected.Take(5)) + (rejected.Count > 5 ? "  | …" : "") +
              "   — user names and bare file names need a prefix: user:alice  file:x.sh";
    }

    private void RefreshDiscoveredLabel()
    {
        int n = 0;
        if (HasCase)
        {
            var p = Path.Combine(Config.ResolveOutputPath(), Helpers.CaseIocs.DiscoveredFileName);
            if (File.Exists(p))
                n = Helpers.CaseIocs.Parse(File.ReadAllText(p)).Iocs.Count;
        }
        DiscoveredLabel = n > 0 ? $"Load discovered ({n})" : "Load discovered";
    }

    /// <summary>Saves the parsed, re-fanged, de-duplicated list. Returns false when there is no case.</summary>
    private bool SaveIocs()
    {
        if (!HasCase) { IocStatus = "Choose a case folder first (Case setup)."; return false; }
        var (iocs, rejected) = Helpers.CaseIocs.Parse(_iocText);
        try
        {
            Helpers.CaseIocs.Save(Config.CaseFolderPath, iocs, Config.CaseName);
        }
        catch (Exception ex)
        {
            IocStatus = $"Could not save: {ex.Message}";
            return false;
        }
        _iocText = Helpers.CaseIocs.Format(iocs, Config.CaseName);
        OnPropertyChanged(nameof(IocText));
        _iocDirty = false;
        _iocLoadedFor = Config.CaseFolderPath;
        UpdateIocPreview();
        IocStatus = $"Saved {iocs.Count} IOC(s) to {Helpers.CaseIocs.PathFor(Config.CaseFolderPath)}" +
                    (rejected.Count > 0 ? $" — {rejected.Count} line(s) without an IOC dropped." : ".");
        return true;
    }

    private void BrowseIocFile()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Import IOCs",
            Filter = "IOC lists (*.txt;*.csv;*.tsv;*.ioc)|*.txt;*.csv;*.tsv;*.ioc|All files (*.*)|*.*",
            Multiselect = true
        };
        if (dlg.ShowDialog() == true)
            foreach (var f in dlg.FileNames) ImportIocFile(f);
    }

    /// <summary>Appends the IOCs found in a file (txt, CSV/MISP export, …) to the list.</summary>
    public void ImportIocFile(string path)
    {
        try
        {
            var (iocs, rejected) = Helpers.CaseIocs.Parse(File.ReadAllText(path));
            if (iocs.Count == 0) { IocStatus = $"No IOCs found in {Path.GetFileName(path)}."; return; }
            AppendIocBlock($"imported from {Path.GetFileName(path)}", iocs.Select(i => i.ToLine()));
            IocStatus = $"Imported {iocs.Count} IOC(s) from {Path.GetFileName(path)}" +
                        (rejected.Count > 0 ? $" ({rejected.Count} line(s) without an IOC skipped)" : "") +
                        " — review, then Save.";
        }
        catch (Exception ex)
        {
            IocStatus = $"Import failed: {ex.Message}";
        }
    }

    private void LoadDiscovered()
    {
        if (!HasCase) { IocStatus = "Choose a case folder first (Case setup)."; return; }
        var p = Path.Combine(Config.ResolveOutputPath(), Helpers.CaseIocs.DiscoveredFileName);
        if (!File.Exists(p)) { IocStatus = "No discovered IOCs yet — run the parser first."; return; }

        var current = new HashSet<string>(Helpers.CaseIocs.Parse(_iocText).Iocs.Select(i => i.Value), StringComparer.OrdinalIgnoreCase);
        var lines = File.ReadAllLines(p)
            .Where(l => !string.IsNullOrWhiteSpace(l) && !l.TrimStart().StartsWith("#"))
            .Where(l => Helpers.CaseIocs.Parse(l).Iocs.Any(i => !current.Contains(i.Value)))
            .ToList();
        if (lines.Count == 0) { IocStatus = "All discovered IOCs are already in the list."; return; }
        AppendIocBlock("discovered by the parser — delete lines you don't trust, then Save", lines);
        IocStatus = $"Added {lines.Count} discovered IOC(s) at the bottom — review them, then Save and Search.";
    }

    private void AppendIocBlock(string title, IEnumerable<string> lines)
    {
        var sb = new System.Text.StringBuilder(_iocText.TrimEnd());
        if (sb.Length > 0) sb.AppendLine().AppendLine();
        sb.AppendLine($"# ── {title} ──");
        foreach (var l in lines) sb.AppendLine(l);
        IocText = sb.ToString();
    }

    private async Task SearchIocsAsync()
    {
        if (_iocDirty && !SaveIocs()) return;
        if (!HasCase) return;
        var outputBase = Config.ResolveOutputPath();
        if (!Directory.Exists(outputBase))
        {
            IocStatus = "Nothing processed yet — run the parser first; it searches the IOC list automatically.";
            return;
        }

        IsRunning = true;
        IocStatus = "Searching processed output…";
        try
        {
            Log("IOC search started (processed output only — no re-parse).", LogLevel.Info);
            var result = await Task.Run(() => Services.ParserOrchestrator.FinishCase(
                Config.CaseFolderPath, outputBase, Config.CaseName, Config.AnalystName,
                m => Log(m, m.StartsWith("[WARN]") ? LogLevel.Warning : LogLevel.Info)));
            IocStatus = result == null || result.IocCount == 0
                ? "The IOC list is empty — previous hit sections were removed."
                : result.IocsHit == 0
                    ? $"None of the {result.IocCount} IOC(s) were seen in {result.CollectionsSearched} collection(s)."
                    : $"{result.IocsHit} of {result.IocCount} IOC(s) seen on {result.CollectionsWithHits} of {result.CollectionsSearched} collection(s): " +
                      string.Join(", ", result.HitValues.Take(6)) + (result.HitValues.Count > 6 ? ", …" : "") +
                      "  → CASE IOC HITS at the top of QuickWins.txt and in CaseSummary.txt";
            Log("IOC search done.", LogLevel.Success);
        }
        catch (Exception ex)
        {
            IocStatus = $"IOC search failed: {ex.Message}";
        }
        finally
        {
            IsRunning = false;
            RefreshDiscoveredLabel();
        }
    }

    private static bool PathEquals(string a, string b) =>
        string.Equals(Path.GetFullPath(a).TrimEnd('\\', '/'),
                      Path.GetFullPath(b).TrimEnd('\\', '/'),
                      StringComparison.OrdinalIgnoreCase);

    // ── UI thread helper ─────────────────────────────────────────────
    private static void UI(Action a) =>
        System.Windows.Application.Current.Dispatcher.Invoke(a);

    // ── Collection scan ──────────────────────────────────────────────
    public async Task ScanForCollections()
    {
        if (!Directory.Exists(Config.CaseFolderPath)) return;

        UI(() =>
        {
            IsScanning = true;
            ScanStatus = "Scanning case folder…";
            DetectedCollections.Clear();
        });

        var uploadDir = Path.Combine(Config.CaseFolderPath, "Upload");
        var decompressDir = Path.Combine(Config.CaseFolderPath, "Decompressed");
        var extractErrors = new List<string>();

        // ── Step 1: extract archives in Upload\ ───────────────────────
        if (Directory.Exists(uploadDir))
        {
            var archives = Directory.GetFiles(uploadDir, "uac*.tar.gz", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(uploadDir, "uac*.tgz", SearchOption.TopDirectoryOnly))
                .Concat(Directory.GetFiles(uploadDir, "uac*.tar", SearchOption.TopDirectoryOnly))
                .ToList();

            for (int i = 0; i < archives.Count; i++)
            {
                var archive = archives[i];
                var archiveName = Path.GetFileName(archive);

                var folderName = archiveName;
                if (folderName.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase)) folderName = folderName[..^7];
                else if (folderName.EndsWith(".tgz", StringComparison.OrdinalIgnoreCase)) folderName = folderName[..^4];
                if (folderName.EndsWith(".tar", StringComparison.OrdinalIgnoreCase)) folderName = folderName[..^4];

                var expectedPath = Path.Combine(decompressDir, folderName);

                // A collection counts as extracted only if its final folder exists
                // AND has content. Extraction writes into a temporary sibling
                // folder that is renamed to the final name only on success, so an
                // interrupted or failed extraction never leaves a folder behind
                // that would be mistaken for a finished one.
                if (Directory.Exists(expectedPath)
                    && Directory.EnumerateFileSystemEntries(expectedPath).Any())
                {
                    UI(() => ScanStatus = $"Already extracted: {folderName}");
                    continue;
                }

                // "_" prefix keeps the temp folder out of collection discovery,
                // which only picks up folders starting with "uac".
                var partialPath = Path.Combine(decompressDir, "_partial_" + folderName);

                UI(() => ScanStatus = $"Extracting {i + 1} of {archives.Count}: {archiveName}…");

                try
                {
                    // Leftovers from an earlier failed/interrupted run.
                    if (Directory.Exists(partialPath)) Directory.Delete(partialPath, recursive: true);
                    if (Directory.Exists(expectedPath)) Directory.Delete(expectedPath, recursive: true); // empty
                    Directory.CreateDirectory(partialPath);
                    var partialPrefix = Path.GetFullPath(partialPath) + Path.DirectorySeparatorChar;

                    await Task.Run(() =>
                    {
                        using var fs = File.OpenRead(archive);

                        Stream tarStream = archiveName.EndsWith(".tar", StringComparison.OrdinalIgnoreCase)
                                        && !archiveName.EndsWith(".tar.gz", StringComparison.OrdinalIgnoreCase)
                            ? fs
                            : (Stream)new System.IO.Compression.GZipStream(
                                fs, System.IO.Compression.CompressionMode.Decompress);

                        using var tarRead = new System.Formats.Tar.TarReader(tarStream, leaveOpen: false);

                        long fileCount = 0;
                        System.Formats.Tar.TarEntry? entry;
                        while ((entry = tarRead.GetNextEntry(copyData: true)) != null)
                        {
                            if (entry.EntryType is System.Formats.Tar.TarEntryType.Directory
                                                 or System.Formats.Tar.TarEntryType.SymbolicLink
                                                 or System.Formats.Tar.TarEntryType.HardLink)
                                continue;
                            try
                            {
                                var relPath = entry.Name.TrimStart('/', '\\');
                                var destPath = Path.GetFullPath(Path.Combine(partialPath, relPath));
                                if (!destPath.StartsWith(partialPrefix, StringComparison.OrdinalIgnoreCase))
                                    continue;
                                Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
                                if (entry.DataStream != null)
                                {
                                    using var outFs = File.Create(destPath);
                                    entry.DataStream.CopyTo(outFs);
                                }
                                fileCount++;
                                if (fileCount % 100 == 0)
                                    UI(() => ScanStatus = $"Extracting {archiveName}… ({fileCount:N0} files)");
                            }
                            catch { /* skip unwritable entries */ }
                        }

                        if (tarStream is System.IO.Compression.GZipStream gz) gz.Dispose();
                    });

                    if (!Directory.EnumerateFileSystemEntries(partialPath).Any())
                        throw new InvalidDataException("archive produced no files");

                    // Commit: only a fully extracted collection gets its final name.
                    Directory.Move(partialPath, expectedPath);
                }
                catch (Exception ex)
                {
                    extractErrors.Add($"[ERROR] {archiveName}: {ex.Message}");
                    try { if (Directory.Exists(partialPath)) Directory.Delete(partialPath, recursive: true); }
                    catch { /* best effort */ }
                }
            }
        }

        // ── Step 2: scan all locations ────────────────────────────────
        UI(() => ScanStatus = "Finding collections…");

        var searchRoots = new[] { decompressDir, uploadDir, Config.CaseFolderPath };
        var found = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var dir in Directory.GetDirectories(root))
            {
                if (!seen.Add(dir)) continue;
                var name = Path.GetFileName(dir);
                var relative = Path.GetRelativePath(Config.CaseFolderPath, dir);
                if (name.StartsWith("uac", StringComparison.OrdinalIgnoreCase)
                    || Directory.Exists(Path.Combine(dir, "logs"))
                    || Directory.Exists(Path.Combine(dir, "live_response")))
                {
                    var outputBase = Config.ResolveOutputPath();
                    found.Add(Services.ParserOrchestrator.IsCollectionProcessed(outputBase, name)
                        ? relative + "/  (already processed — will be skipped)"
                        : relative + "/");
                }
            }
        }

        // ── Step 3: populate list ─────────────────────────────────────
        UI(() =>
        {
            DetectedCollections.Clear();
            foreach (var f in found) DetectedCollections.Add(f);
            foreach (var e in extractErrors) DetectedCollections.Add(e);
            if (DetectedCollections.Count == 0)
                DetectedCollections.Add("(no UAC collections detected)");

            ScanStatus = found.Count > 0
                ? $"Found {found.Count} collection(s)"
                : "No collections found";
            IsScanning = false;
        });
    }

    // ── Parser run ───────────────────────────────────────────────────
    private async Task RunParserAsync()
    {
        IsRunning = true;
        Progress = 0;
        RunStatusText = "Running…";
        ActivePanel = "Output";
        LogEntries.Clear();

        // Fresh token for this run — previous token (if any) was already cancelled/disposed.
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;

        // Progress<double> marshals Report() calls back to the UI thread automatically.
        var progressReporter = new Progress<double>(pct =>
        {
            Progress = pct;
        });

        try
        {
            Log($"Case: {Config.CaseName}", LogLevel.Info);
            Log($"Analyst: {Config.AnalystName}", LogLevel.Info);
            Log($"Folder: {Config.CaseFolderPath}", LogLevel.Info);

            // Unsaved edits in the IOC panel are used for this run
            if (_iocDirty && HasCase && SaveIocs())
                Log("IOC list saved (unsaved edits in the IOC panel).", LogLevel.Info);

            // Check 1 always runs first: extract anything in Upload\ that is
            // not yet (fully) in Decompressed\. Check 2 (already processed)
            // happens per collection inside the orchestrator.
            Log(@"Checking Upload\ for archives to extract…", LogLevel.Info);
            await ScanForCollections();

            Log("Starting parse run…", LogLevel.Info);

            await Task.Run(() => RunParsers(ct, progressReporter), ct);

            Log("Done.", LogLevel.Success);
            RunStatusText = "Complete";
        }
        catch (OperationCanceledException)
        {
            Log("Parse cancelled by analyst.", LogLevel.Warning);
            RunStatusText = "Cancelled";
        }
        catch (Exception ex)
        {
            Log($"Fatal error: {ex.Message}", LogLevel.Error);
            RunStatusText = "Failed";
        }
        finally
        {
            IsRunning = false;
            Progress = 0;   // reset bar after run finishes
            RefreshDiscoveredLabel();
        }
    }

    private void RunParsers(CancellationToken ct, IProgress<double> progress)
    {
        if (!Directory.Exists(Config.CaseFolderPath))
        {
            Log("Case folder not found — aborting.", LogLevel.Error);
            return;
        }

        Directory.CreateDirectory(Config.ResolveOutputPath());

        var orchestrator = new Services.ParserOrchestrator(Config,
            message => Log(message,
                message.StartsWith("[ERROR]") ? LogLevel.Error :
                message.StartsWith("[WARN]") ? LogLevel.Warning :
                                                LogLevel.Info));

        orchestrator.RunAll(ct, progress);
    }

    // ── Logging helper ───────────────────────────────────────────────
    public void Log(string message, LogLevel level = LogLevel.Info)
    {
        System.Windows.Application.Current.Dispatcher.Invoke(() =>
            LogEntries.Add(new LogEntry(DateTime.Now, message, level)));
    }
}

// ── Supporting types ─────────────────────────────────────────────────
public enum LogLevel { Info, Success, Warning, Error }

public record LogEntry(DateTime Timestamp, string Message, LogLevel Level)
{
    public string Display => $"[{Timestamp:HH:mm:ss}] {Message}";
}
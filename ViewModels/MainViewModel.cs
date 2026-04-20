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

    public MainViewModel()
    {
        NavigateCommand = new RelayCommand(p => ActivePanel = p as string ?? ActivePanel);
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
            SelectedPath = Directory.Exists(Config.CaseFolderPath)
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
            Config.CaseFolderPath = dlg.SelectedPath;

            if (string.IsNullOrWhiteSpace(Config.OutputPath)
                || Config.OutputPath == "Processed"
                || !Path.IsPathRooted(Config.OutputPath)
                || Config.OutputPath == Path.Combine(Config.CaseFolderPath, "Processed"))
            {
                Config.OutputPath = Path.Combine(dlg.SelectedPath, "Processed");
            }

            OnPropertyChanged(nameof(Config));
            _ = ScanForCollections();
        }
    }

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

                if (Directory.Exists(expectedPath))
                {
                    UI(() => ScanStatus = $"Already extracted: {folderName}");
                    continue;
                }

                UI(() => ScanStatus = $"Extracting {i + 1} of {archives.Count}: {archiveName}…");

                try
                {
                    Directory.CreateDirectory(expectedPath);

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
                                var destPath = Path.GetFullPath(Path.Combine(expectedPath, relPath));
                                if (!destPath.StartsWith(expectedPath, StringComparison.OrdinalIgnoreCase))
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
                }
                catch (Exception ex)
                {
                    extractErrors.Add($"[ERROR] {archiveName}: {ex.Message}");
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
                    found.Add(relative + "/");
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
        }
    }

    private void RunParsers(CancellationToken ct, IProgress<double> progress)
    {
        if (!Directory.Exists(Config.CaseFolderPath))
        {
            Log("Case folder not found — aborting.", LogLevel.Error);
            return;
        }

        Directory.CreateDirectory(Config.OutputPath);

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
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Input;
using CsirtParser.WPF.Models;
using Helpers;

namespace CsirtParser.WPF.ViewModels;

/// <summary>
/// The "Case report" panel: an editable, exportable case summary built from
/// the processed output. Analyst edits (title, bottom line, per-finding
/// likelihood, gaps, next steps) are kept in Processed\CaseReport.json so they
/// survive re-runs; the export is a self-contained CaseReport.html.
/// </summary>
public class CaseReportViewModel : ViewModelBase
{
    private readonly ParserConfig _config;
    private CaseReportData? _data;
    private CaseReportNotes _notes = new();
    private string? _loadedFor;
    private DateTime _loadedStamp;

    public CaseReportViewModel(ParserConfig config)
    {
        _config = config;
        RefreshCommand = new RelayCommand(_ => Refresh());
        DraftBlufCommand = new RelayCommand(_ => { if (_data != null) Bluf = CaseReport.DraftBluf(_data); }, _ => _data != null);
        ExportCommand = new RelayCommand(_ => Export(), _ => _data != null);
        OpenCommand = new RelayCommand(_ => OpenInBrowser(), _ => _data != null);
        SaveCommand = new RelayCommand(_ => Save(), _ => _data != null);
    }

    public ICommand RefreshCommand { get; }
    public ICommand DraftBlufCommand { get; }
    public ICommand ExportCommand { get; }
    public ICommand OpenCommand { get; }
    public ICommand SaveCommand { get; }

    public IReadOnlyList<string> SeverityLevels => CaseReport.SeverityLevels;
    public IReadOnlyList<string> StatusLevels => CaseReport.StatusLevels;
    public IReadOnlyList<LikelihoodOption> LikelihoodOptions => LikelihoodScale.Options;

    public ObservableCollection<ReportFinding> Findings { get; } = new();

    private string _title = "";
    public string Title { get => _title; set { if (SetField(ref _title, value)) MarkDirty(); } }

    private string _severity = "";
    public string Severity { get => _severity; set { if (SetField(ref _severity, value)) MarkDirty(); } }

    private string _status = "Active";
    public string Status { get => _status; set { if (SetField(ref _status, value)) MarkDirty(); } }

    private string _bluf = "";
    public string Bluf { get => _bluf; set { if (SetField(ref _bluf, value)) MarkDirty(); } }

    private string _gaps = "";
    public string Gaps { get => _gaps; set { if (SetField(ref _gaps, value)) MarkDirty(); } }

    private string _nextSteps = "";
    public string NextSteps { get => _nextSteps; set { if (SetField(ref _nextSteps, value)) MarkDirty(); } }

    private string _autoGaps = "";
    /// <summary>Gaps detected from the data; shown read-only and added to the export.</summary>
    public string AutoGaps { get => _autoGaps; private set => SetField(ref _autoGaps, value); }

    private string _statusText = "Run the parser, then open this panel to build the report.";
    public string StatusText { get => _statusText; private set => SetField(ref _statusText, value); }

    private string _summary = "";
    public string Summary { get => _summary; private set => SetField(ref _summary, value); }

    private bool _hasData;
    public bool HasData { get => _hasData; private set => SetField(ref _hasData, value); }

    private bool _dirty;
    private bool _loading;
    private void MarkDirty() { if (!_loading) _dirty = true; }

    private string ProcessedRoot => _config.ResolveOutputPath();

    /// <summary>Builds the report the first time, or again when the output folder or its case summary changed.</summary>
    public void EnsureLoaded()
    {
        var root = ProcessedRoot;
        if (_loadedFor == null || !string.Equals(_loadedFor, root, StringComparison.OrdinalIgnoreCase) || Stamp(root) > _loadedStamp)
            Refresh();
    }

    private static DateTime Stamp(string root)
    {
        var p = Path.Combine(root, CaseSummary.SummaryFileName);
        return File.Exists(p) ? File.GetLastWriteTimeUtc(p) : DateTime.MinValue;
    }

    public void Refresh()
    {
        var root = ProcessedRoot;
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            Clear("Nothing processed yet. Pick a case and run the parser first.");
            return;
        }

        // Keep unsaved edits when rebuilding the same case
        if (_data != null && string.Equals(_loadedFor, root, StringComparison.OrdinalIgnoreCase))
            CaptureNotes();
        else
            _notes = CaseReport.LoadNotes(root);

        CaseReportData data;
        try
        {
            data = CaseReport.Build(root, _config.CaseName, _config.AnalystName);
        }
        catch (Exception ex)
        {
            Clear($"Couldn't build the report: {ex.Message}");
            return;
        }
        if (data.Hosts.Count == 0)
        {
            Clear("No processed collections found in the output folder. Run the parser first.");
            return;
        }

        CaseReport.ApplyNotes(data, _notes);
        foreach (var f in Findings) f.PropertyChanged -= Finding_Changed;
        Findings.Clear();
        foreach (var f in data.Findings)
        {
            f.PropertyChanged += Finding_Changed;
            Findings.Add(f);
        }

        _loading = true;
        Title = _notes.Title.Length > 0 ? _notes.Title : CaseReport.SuggestTitle(data);
        Severity = _notes.Severity.Length > 0 ? _notes.Severity : CaseReport.SuggestSeverity(data);
        Status = _notes.Status.Length > 0 ? _notes.Status : "Active";
        Bluf = _notes.Bluf.Length > 0 ? _notes.Bluf : CaseReport.DraftBluf(data);
        Gaps = _notes.Gaps;
        NextSteps = _notes.NextSteps;
        AutoGaps = string.Join(Environment.NewLine, data.AutoGaps.Select(g => "• " + g));
        _loading = false;
        _dirty = false;

        _data = data;
        _loadedFor = root;
        _loadedStamp = Stamp(root);
        HasData = true;
        UpdateSummary();
        StatusText = $"Built from {data.Hosts.Count} collection(s) at {DateTime.Now:HH:mm}. Edits are saved with the case.";
    }

    private void Clear(string message)
    {
        foreach (var f in Findings) f.PropertyChanged -= Finding_Changed;
        Findings.Clear();
        _data = null;
        _loadedFor = null;
        HasData = false;
        Summary = "";
        StatusText = message;
    }

    private void Finding_Changed(object? sender, PropertyChangedEventArgs e)
    {
        _dirty = true;
        if (e.PropertyName == nameof(ReportFinding.Include)) UpdateSummary();
    }

    private void UpdateSummary()
    {
        if (_data == null) return;
        var inc = Findings.Where(f => f.Include).ToList();
        Summary = $"{inc.Count} of {Findings.Count} finding(s) in the report · " +
                  $"{inc.Select(f => f.Host).Distinct().Count()} of {_data.Hosts.Count} host(s) · " +
                  $"{_data.Lateral.Count} lateral movement link(s)";
    }

    private void CaptureNotes()
    {
        if (_data == null) return;
        _notes.Title = Title.Trim() == CaseReport.SuggestTitle(_data) ? "" : Title.Trim();
        _notes.Severity = Severity == CaseReport.SuggestSeverity(_data) ? "" : Severity;
        _notes.Status = Status;
        _notes.Bluf = Bluf.Trim() == CaseReport.DraftBluf(_data) ? "" : Bluf.Trim();
        _notes.Gaps = Gaps;
        _notes.NextSteps = NextSteps;
        CaseReport.CaptureOverrides(_data, _notes);
    }

    private bool Save()
    {
        if (_data == null || _loadedFor == null) return false;
        try
        {
            CaptureNotes();
            CaseReport.SaveNotes(_loadedFor, _notes);
            _dirty = false;
            StatusText = $"Saved to {Path.Combine(_loadedFor, CaseReport.NotesFileName)}";
            return true;
        }
        catch (Exception ex)
        {
            StatusText = $"Couldn't save report notes: {ex.Message}";
            return false;
        }
    }

    /// <summary>Saves unsaved edits; called when leaving the panel.</summary>
    public void SaveIfDirty() { if (_dirty) Save(); }

    private string? WriteHtml(string path)
    {
        if (_data == null) return null;
        Save();
        try
        {
            File.WriteAllText(path, CaseReport.RenderHtml(_data, _notes), new UTF8Encoding(false));
            return path;
        }
        catch (Exception ex)
        {
            StatusText = $"Export failed: {ex.Message}";
            return null;
        }
    }

    private void Export()
    {
        if (_loadedFor == null) return;
        var name = string.IsNullOrWhiteSpace(_config.CaseName)
            ? "CaseReport"
            : string.Concat(_config.CaseName.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c)) + "_CaseReport";
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Export case report",
            Filter = "HTML report (*.html)|*.html",
            FileName = $"{name}_{DateTime.Now:yyyyMMdd}.html",
            InitialDirectory = _loadedFor,
        };
        if (dlg.ShowDialog() != true) return;
        var p = WriteHtml(dlg.FileName);
        if (p != null) StatusText = $"Exported: {p}  (open it and print to PDF if you need a PDF)";
    }

    private void OpenInBrowser()
    {
        if (_loadedFor == null) return;
        var p = WriteHtml(Path.Combine(_loadedFor, CaseReport.HtmlFileName));
        if (p == null) return;
        try
        {
            Process.Start(new ProcessStartInfo(p) { UseShellExecute = true });
            StatusText = $"Opened {p}";
        }
        catch (Exception ex)
        {
            StatusText = $"Report written to {p}, but it couldn't be opened: {ex.Message}";
        }
    }
}

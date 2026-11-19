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
/// survive re-runs; exports are a self-contained HTML page, RTF or Word (.docx).
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
        ExportCommand = new RelayCommand(p => Export(p as string ?? "html"), _ => _data != null);
        OpenCommand = new RelayCommand(_ => OpenInBrowser(), _ => _data != null);
        SaveCommand = new RelayCommand(_ => Save(), _ => _data != null);
        SelectAllCommand = new RelayCommand(_ => SetIncluded(_ => true), _ => _data != null);
        SelectHighCommand = new RelayCommand(_ => SetIncluded(f => f.Rank <= 1), _ => _data != null);
        ResetSelectionCommand = new RelayCommand(_ => SetIncluded(f => f.AutoInclude), _ => _data != null);
    }

    public ICommand SelectAllCommand { get; }
    public ICommand SelectHighCommand { get; }
    public ICommand ResetSelectionCommand { get; }

    private string _selectAllText = "Select all";
    public string SelectAllText { get => _selectAllText; private set => SetField(ref _selectAllText, value); }

    private string _selectHighText = "Select all ≥ HIGH";
    public string SelectHighText { get => _selectHighText; private set => SetField(ref _selectHighText, value); }

    private string _resetSelectionText = "Reset to default";
    public string ResetSelectionText { get => _resetSelectionText; private set => SetField(ref _resetSelectionText, value); }

    /// <summary>Ticks exactly the findings that match; likelihoods and notes are left alone.</summary>
    private void SetIncluded(Func<ReportFinding, bool> include)
    {
        foreach (var f in Findings) f.Include = include(f);
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
        SelectAllText = $"Select all ({Findings.Count})";
        SelectHighText = $"Select all ≥ HIGH ({Findings.Count(f => f.Rank <= 1)})";
        ResetSelectionText = $"Reset to default ({Findings.Count(f => f.AutoInclude)})";
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

    /// <summary>Writes the report in the format the file extension names (.html, .rtf, .docx).</summary>
    private string? WriteReport(string path)
    {
        if (_data == null) return null;
        Save();
        try
        {
            switch (Path.GetExtension(path).ToLowerInvariant())
            {
                case ".rtf":
                    File.WriteAllText(path, CaseReportRtf.Render(_data, _notes), Encoding.ASCII);
                    break;
                case ".docx":
                    CaseReportDocx.Write(path, _data, _notes);
                    break;
                case ".xlsx":
                    // Case tracker rows: exactly the findings ticked for the report
                    CaseTracker.Write(path, CaseTracker.Rows(_data, Findings.Where(f => f.Include)));
                    break;
                default:
                    File.WriteAllText(path, CaseReport.RenderHtml(_data, _notes), new UTF8Encoding(false));
                    break;
            }
            return path;
        }
        catch (IOException ex)
        {
            StatusText = $"Export failed — is the file open in another program? {ex.Message}";
            return null;
        }
        catch (Exception ex)
        {
            StatusText = $"Export failed: {ex.Message}";
            return null;
        }
    }

    private void Export(string format)
    {
        if (_loadedFor == null) return;
        var (ext, filter) = format switch
        {
            "rtf" => (".rtf", "Rich Text (*.rtf)|*.rtf"),
            "docx" => (".docx", "Word document (*.docx)|*.docx"),
            "xlsx" => (".xlsx", "Excel workbook (*.xlsx)|*.xlsx"),
            _ => (".html", "HTML report (*.html)|*.html"),
        };
        var name = string.IsNullOrWhiteSpace(_config.CaseName)
            ? "CaseReport"
            : string.Concat(_config.CaseName.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c)) + (format == "xlsx" ? "_CaseTracker" : "_CaseReport");
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = format == "xlsx" ? "Export case tracker rows" : "Export case report",
            Filter = filter,
            DefaultExt = ext,
            FileName = $"{name}_{DateTime.Now:yyyyMMdd}{ext}",
            InitialDirectory = _loadedFor,
        };
        if (dlg.ShowDialog() != true) return;
        var p = WriteReport(dlg.FileName);
        if (p != null)
            StatusText = $"Exported: {p}" + (ext == ".html" ? "  (open it and print to PDF if you need a PDF)"
                       : ext == ".xlsx" ? $"  ({Findings.Count(f => f.Include)} ticked finding(s) as tracker rows)" : "");
    }

    private void OpenInBrowser()
    {
        if (_loadedFor == null) return;
        var p = WriteReport(Path.Combine(_loadedFor, CaseReport.HtmlFileName));
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

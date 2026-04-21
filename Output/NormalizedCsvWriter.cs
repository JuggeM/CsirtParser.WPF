// File: Utils/NormalizedCsvWriter.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace Output
{
    /// <summary>
    /// Row model for normalized Splunk-ready CSV export.
    /// Columns: Timestamp, Hostname, LogType, Daemon, User, IP, Message, Severity, Raw
    /// </summary>
    public sealed class NormalizedRecord
    {
        public DateTime Timestamp { get; set; }
        public string Hostname { get; set; }
        public string LogType { get; set; }
        public string Daemon { get; set; }
        public string User { get; set; }
        public string IP { get; set; }
        public string Message { get; set; }
        public string Severity { get; set; }
        public string Raw { get; set; }

        public static NormalizedRecord From(
            DateTime timestamp, string hostname, string logType,
            string daemon, string user, string ip,
            string message, string severity, string raw)
        {
            return new NormalizedRecord
            {
                Timestamp = timestamp,
                Hostname = hostname,
                LogType = logType,
                Daemon = daemon,
                User = user,
                IP = ip,
                Message = message,
                Severity = severity,
                Raw = raw
            };
        }
    }

    /// <summary>
    /// Thread-safe CSV writer for normalized logs consolidated across all parsers.
    /// Default behaviour: overwrite on first open to avoid duplicates between runs.
    /// </summary>
    public sealed class NormalizedCsvWriter : IDisposable
    {
        private readonly object _sync = new object();
        private readonly string _csvPath;
        private readonly bool _append;
        private StreamWriter _writer;
        private bool _headerWritten;
        private bool _disposed;

        private static readonly string[] Header =
        {
            "Timestamp","Hostname","LogType","Daemon","User","IP","Message","Severity","Raw"
        };

        public static NormalizedCsvWriter ForCollection(string processedRoot,
            string collectionName, bool append = false)
        {
            if (string.IsNullOrWhiteSpace(processedRoot))
                throw new ArgumentException("processedRoot cannot be null/empty");
            if (string.IsNullOrWhiteSpace(collectionName))
                throw new ArgumentException("collectionName cannot be null/empty");

            string outDir = Path.Combine(processedRoot, "Processed", collectionName);
            Directory.CreateDirectory(outDir);
            return new NormalizedCsvWriter(Path.Combine(outDir, "NormalizedLogs.csv"), append);
        }

        public NormalizedCsvWriter(string csvPath, bool append = false)
        {
            _csvPath = csvPath ?? throw new ArgumentNullException(nameof(csvPath));
            _append = append;
            Open();
        }

        public void Write(NormalizedRecord record)
        {
            if (record == null) return;
            lock (_sync)
            {
                EnsureHeader();
                _writer.WriteLine(Serialize(record));
                _writer.Flush();
            }
        }

        public void Write(IEnumerable<NormalizedRecord> records)
        {
            if (records == null) return;
            lock (_sync)
            {
                EnsureHeader();
                foreach (var r in records)
                {
                    if (r == null) continue;
                    _writer.WriteLine(Serialize(r));
                }
                _writer.Flush();
            }
        }

        private static string Serialize(NormalizedRecord r)
        {
            string ts = r.Timestamp.Kind == DateTimeKind.Unspecified
                ? DateTime.SpecifyKind(r.Timestamp, DateTimeKind.Utc)
                    .ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture)
                : r.Timestamp.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK", CultureInfo.InvariantCulture);

            return ToCsv(new[]
            {
                ts,
                r.Hostname ?? string.Empty,
                r.LogType  ?? string.Empty,
                r.Daemon   ?? string.Empty,
                r.User     ?? string.Empty,
                r.IP       ?? string.Empty,
                r.Message  ?? string.Empty,
                r.Severity ?? string.Empty,
                r.Raw      ?? string.Empty
            });
        }

        private static string ToCsv(IEnumerable<string> columns)
        {
            var sb = new StringBuilder();
            bool first = true;
            foreach (var col in columns)
            {
                if (!first) sb.Append(',');
                first = false;

                if (col == null) continue;

                bool mustQuote = col.Contains(',') || col.Contains('"')
                              || col.Contains('\n') || col.Contains('\r');
                if (mustQuote)
                {
                    sb.Append('"');
                    sb.Append(col.Replace("\"", "\"\""));
                    sb.Append('"');
                }
                else
                {
                    sb.Append(col);
                }
            }
            return sb.ToString();
        }

        private void Open()
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_csvPath)!);

            // When overwriting (default): always write header.
            // When appending to an existing non-empty file: header is already there.
            bool writeHeader = !_append || !File.Exists(_csvPath)
                               || new FileInfo(_csvPath).Length == 0;

            _writer = new StreamWriter(
                new FileStream(_csvPath,
                    _append ? FileMode.Append : FileMode.Create,
                    FileAccess.Write, FileShare.Read),
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

            _headerWritten = !writeHeader;
            EnsureHeader();
        }

        private void EnsureHeader()
        {
            if (_headerWritten) return;
            _writer.WriteLine(string.Join(",", Header));
            _headerWritten = true;
        }

        public void Dispose()
        {
            if (_disposed) return;
            lock (_sync)
            {
                _writer?.Flush();
                _writer?.Dispose();
                _writer = null;
                _disposed = true;
            }
        }
    }
}
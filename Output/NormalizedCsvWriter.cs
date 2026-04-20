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
        public DateTime Timestamp { get; set; }         // Prefer UTC if available
        public string Hostname { get; set; }
        public string LogType { get; set; }             // e.g., AUTH, SECURE, SYSLOG, MESSAGES, CRON, WEB
        public string Daemon { get; set; }              // e.g., sshd, sudo, smbd, kernel, httpd
        public string User { get; set; }                // may be null/empty
        public string IP { get; set; }                  // IPv4/IPv6 or empty
        public string Message { get; set; }             // normalized/parsed message
        public string Severity { get; set; }            // High/Medium/Low or INFO/WARN/ERROR
        public string Raw { get; set; }                 // original log line or serialized object

        public static NormalizedRecord From(
            DateTime timestamp,
            string hostname,
            string logType,
            string daemon,
            string user,
            string ip,
            string message,
            string severity,
            string raw)
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
    /// Default behavior: overwrite on first open to avoid duplicates between runs.
    /// </summary>
    public sealed class NormalizedCsvWriter : IDisposable
    {
        private readonly object _sync = new object();
        private readonly string _csvPath;
        private readonly bool _append;
        private StreamWriter _writer;
        private bool _headerWritten;
        private bool _disposed;

        private static readonly string[] Header = new[]
        {
            "Timestamp","Hostname","LogType","Daemon","User","IP","Message","Severity","Raw"
        };

        /// <summary>
        /// Creates (or opens) NormalizedLogs.csv inside Processed/[collectionName]/.
        /// </summary>
        public static NormalizedCsvWriter ForCollection(string processedRoot, string collectionName, bool append = false)
        {
            if (string.IsNullOrWhiteSpace(processedRoot))
                throw new ArgumentException("processedRoot cannot be null/empty");
            if (string.IsNullOrWhiteSpace(collectionName))
                throw new ArgumentException("collectionName cannot be null/empty");

            string outDir = Path.Combine(processedRoot, "Processed", collectionName);
            Directory.CreateDirectory(outDir);
            string path = Path.Combine(outDir, "NormalizedLogs.csv");
            return new NormalizedCsvWriter(path, append);
        }

        /// <summary>
        /// Create a writer for an explicit path (useful for testing).
        /// </summary>
        public NormalizedCsvWriter(string csvPath, bool append = false)
        {
            _csvPath = csvPath ?? throw new ArgumentNullException(nameof(csvPath));
            _append = append;
            Open();
        }

        /// <summary>
        /// Write one record.
        /// </summary>
        public void Write(NormalizedRecord record)
        {
            if (record == null) return;
            lock (_sync)
            {
                EnsureHeader();
                _writer.WriteLine(Serialize(record));
                // Flush lightly to reduce data loss on crashes but keep perf decent
                _writer.Flush();
            }
        }

        /// <summary>
        /// Write multiple records.
        /// </summary>
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

        /// <summary>
        /// Serialize to a Splunk-friendly CSV line (RFC4180 quoting).
        /// Timestamp uses ISO 8601 with offset (yyyy-MM-ddTHH:mm:ss.fffK).
        /// </summary>
        private static string Serialize(NormalizedRecord r)
        {
            // Use invariant culture to avoid locale issues
            string ts = r.Timestamp.Kind == DateTimeKind.Unspecified
                ? DateTime.SpecifyKind(r.Timestamp, DateTimeKind.Utc).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture)
                : r.Timestamp.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK", CultureInfo.InvariantCulture);

            var cols = new[]
            {
                ts,
                r.Hostname ?? string.Empty,
                r.LogType ?? string.Empty,
                r.Daemon ?? string.Empty,
                r.User ?? string.Empty,
                r.IP ?? string.Empty,
                r.Message ?? string.Empty,
                r.Severity ?? string.Empty,
                r.Raw ?? string.Empty
            };

            return ToCsv(cols);
        }

        private static string ToCsv(IEnumerable<string> columns)
        {
            var sb = new StringBuilder();
            bool first = true;
            foreach (var col in columns)
            {
                if (!first) sb.Append(',');
                first = false;

                if (col == null)
                {
                    sb.Append("");
                    continue;
                }

                bool mustQuote = col.Contains(",") || col.Contains("\"") || col.Contains("\n") || col.Contains("\r");
                if (mustQuote)
                {
                    sb.Append('"');
                    // Escape quotes as ""
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
            // Ensure directory exists
            Directory.CreateDirectory(Path.GetDirectoryName(_csvPath));

            bool fileExists = File.Exists(_csvPath);
            bool writeHeader = true;

            // Overwrite by default to avoid duplicate rows across runs
            FileMode mode = _append ? FileMode.Append : FileMode.Create;

            _writer = new StreamWriter(new FileStream(_csvPath, mode, FileAccess.Write, FileShare.Read),
                                       new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)); // UTF-8 no BOM

            if (_append && fileExists)
            {
                // If appending to an existing file, assume header already there (best effort).
                // If the existing file is empty, we will write header below.
                writeHeader = new FileInfo(_csvPath).Length == 0;
            }

            _headerWritten = !writeHeader;
            if (writeHeader == false && !_append)
            {
                // When overwriting (FileMode.Create), always write header
                _headerWritten = false;
            }

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

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace Helpers
{
    /// <summary>
    /// Writes session data to CSV for analysis
    /// Format: Timestamp,Username,IP,Daemon,Type,Duration,IsSuspicious,SuspicionReason,Notes
    /// </summary>
    public class SessionsCsvWriter
    {
        private readonly string _csvPath;

        public SessionsCsvWriter(string outputDir, string filename = "Sessions_Full.csv")
        {
            Directory.CreateDirectory(outputDir);
            _csvPath = Path.Combine(outputDir, filename);
        }

        public void WriteAll(List<Session> sessions)
        {
            using var writer = new StreamWriter(_csvPath, append: false, new UTF8Encoding(false));

            // Write header
            writer.WriteLine("Timestamp,Username,SourceIP,Daemon,SessionType,DurationSeconds,EndTime,IsSuspicious,SuspicionReason,Notes");

            // Write sessions
            foreach (var session in sessions)
            {
                writer.WriteLine(ToCsvLine(session));
            }
        }

        private static string ToCsvLine(Session session)
        {
            string timestamp = session.StartTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
            string endTime = session.EndTime.HasValue
                ? session.EndTime.Value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
                : "ongoing";

            var fields = new[]
            {
                timestamp,
                session.Username ?? "",
                session.SourceIP ?? "N/A",
                session.Daemon ?? "unknown",
                session.Type.ToString(),
                session.DurationSeconds.ToString(),
                endTime,
                session.IsSuspicious ? "true" : "false",
                session.SuspicionReason.ToString(),
                session.Notes ?? ""
            };

            return string.Join(",", fields.Select(EscapeCsv));
        }

        private static string EscapeCsv(string field)
        {
            if (string.IsNullOrEmpty(field))
                return "\"\"";

            bool needsQuotes = field.Contains(",") || field.Contains("\"") || field.Contains("\n") || field.Contains("\r");

            if (needsQuotes)
                return "\"" + field.Replace("\"", "\"\"") + "\"";

            return field;
        }
    }
}

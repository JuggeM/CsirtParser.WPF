using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Parser.Output
{
    /// <summary>
    /// Writes LiveResponse findings to a dedicated output file (NOT QuickWins)
    /// </summary>
    public class LiveResponseWriter
    {
        private readonly string _outputDir;
        private readonly string _outPath;

        public LiveResponseWriter(string outputDir)
        {
            _outputDir = outputDir;
            Directory.CreateDirectory(_outputDir);

            _outPath = Path.Combine(_outputDir, "LiveResponseFindings.txt");
        }

        public void WriteHeader(string headerTag)
        {
            WriteLine("############################################");
            WriteLine($"{headerTag} Live Response Findings");
            WriteLine("############################################");
            WriteLine(string.Empty);
        }

        public void WriteLine(string line)
        {
            File.AppendAllText(_outPath, line + Environment.NewLine);
        }

        public void WriteSection(string title, List<string> lines)
        {
            WriteLine("------------------------------------------------------------");
            WriteLine(title);
            WriteLine("------------------------------------------------------------");

            if (lines == null || lines.Count == 0)
            {
                WriteLine("(none)");
                WriteLine(string.Empty);
                return;
            }

            foreach (var l in lines)
                WriteLine(l);

            WriteLine(string.Empty);
        }

        public void WriteSummary(string title, List<string> allFindings)
        {
            WriteLine("############################################################");
            WriteLine(title);
            WriteLine("############################################################");

            if (allFindings == null || allFindings.Count == 0)
            {
                WriteLine("(none)");
                WriteLine(string.Empty);
                return;
            }

            WriteLine($"Total findings: {allFindings.Count}");
            WriteLine(string.Empty);

            // De-duplicate for readability
            foreach (var line in allFindings.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct())
                WriteLine(line);

            WriteLine(string.Empty);
        }
    }
}

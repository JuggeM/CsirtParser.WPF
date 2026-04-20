using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Parser.Output;

namespace Parser.Parsers.LiveResponse
{
    public class LiveResponseParser
    {
        private readonly string liveResponseRoot;
        private readonly string outputDirectory;
        private readonly LiveResponseWriter writer;

        public LiveResponseParser(string liveResponsePath, string outputDir)
        {
            liveResponseRoot = liveResponsePath;
            outputDirectory = outputDir;
            writer = new LiveResponseWriter(outputDir);
        }

        public void ProcessAll()
        {
            writer.WriteHeader("[LIVERESPONSE]");

            if (!Directory.Exists(liveResponseRoot))
            {
                writer.WriteLine($"No live_response directory found at: {liveResponseRoot}");
                return;
            }

            var allFindings = new List<string>();

            try
            {
                var netParser = new NetworkParser(Path.Combine(liveResponseRoot, "network"));
                var netFindings = netParser.Process();
                writer.WriteSection("Network Artifacts", netFindings);
                allFindings.AddRange(netFindings);

                var procParser = new ProcessParser(Path.Combine(liveResponseRoot, "processes"));
                var procFindings = procParser.Process();
                writer.WriteSection("Running Processes", procFindings);
                allFindings.AddRange(procFindings);

                var persParser = new PersistenceParser(Path.Combine(liveResponseRoot, "persistence"));
                var persFindings = persParser.Process();
                writer.WriteSection("Persistence Mechanisms", persFindings);
                allFindings.AddRange(persFindings);

                var fsParser = new FileSystemParser(Path.Combine(liveResponseRoot, "filesystem"));
                var fsFindings = fsParser.Process();
                writer.WriteSection("Filesystem Artifacts", fsFindings);
                allFindings.AddRange(fsFindings);

                var userParser = new UserAccountParser(Path.Combine(liveResponseRoot, "users"));
                var userFindings = userParser.Process();
                writer.WriteSection("User Accounts", userFindings);
                allFindings.AddRange(userFindings);
            }
            catch (Exception ex)
            {
                writer.WriteLine($"[ERROR] LiveResponseParser failed: {ex}");
            }

            if (allFindings.Any())
                writer.WriteSummary("LiveResponse Summary", allFindings);
            else
                writer.WriteLine("No live_response findings were produced.");
        }
    }
}

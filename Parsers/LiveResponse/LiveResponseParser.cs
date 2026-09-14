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
                var netParser = new NetworkParser(ResolveArtifactDir(liveResponseRoot, "network"));
                var netFindings = netParser.Process();
                writer.WriteSection("Network Artifacts", netFindings);
                allFindings.AddRange(netFindings);

                var procParser = new ProcessParser(ResolveArtifactDir(liveResponseRoot, "process", "processes"));
                var procFindings = procParser.Process();
                writer.WriteSection("Running Processes", procFindings);
                allFindings.AddRange(procFindings);

                var persParser = new PersistenceParser(ResolveArtifactDir(liveResponseRoot, "persistence"));
                var persFindings = persParser.Process();
                writer.WriteSection("Persistence Mechanisms", persFindings);
                allFindings.AddRange(persFindings);

                var fsParser = new FileSystemParser(ResolveArtifactDir(liveResponseRoot, "storage", "filesystem"));
                var fsFindings = fsParser.Process();
                writer.WriteSection("Filesystem Artifacts", fsFindings);
                allFindings.AddRange(fsFindings);

                var userParser = new UserAccountParser(ResolveArtifactDir(liveResponseRoot, "user_accounts", "users"));
                var userFindings = userParser.Process();
                writer.WriteSection("User Accounts", userFindings);
                allFindings.AddRange(userFindings);

                // New: kernel modules, login history (last/lastb), hidden
                // files/directories, ld.so.preload — none of this was parsed
                // before even though UAC collects it under live_response/system.
                var sysParser = new SystemParser(ResolveArtifactDir(liveResponseRoot, "system"));
                var sysFindings = sysParser.Process();
                writer.WriteSection("System Artifacts", sysFindings);
                allFindings.AddRange(sysFindings);
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

        // ── Folder-name resolution ──────────────────────────────────────
        // UAC has renamed/moved a few live_response subfolders across
        // versions (e.g. "filesystem" artifacts are actually collected
        // under "storage" or top-level "system" depending on version; user
        // account artifacts live under "user_accounts", not "users"). A
        // hardcoded single name means a silent zero-findings result if it
        // doesn't match — this tries each candidate in order and falls back
        // to the first name (for a sensible "Missing folder: X" message)
        // only if none of them exist.
        private static string ResolveArtifactDir(string liveResponseRoot, params string[] candidateNames)
        {
            foreach (var name in candidateNames)
            {
                var path = Path.Combine(liveResponseRoot, name);
                if (Directory.Exists(path)) return path;
            }
            return Path.Combine(liveResponseRoot, candidateNames[0]);
        }
    }
}

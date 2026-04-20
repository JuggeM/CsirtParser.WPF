using System;
using System.Collections.Generic;
using Helpers;
using Output;

namespace Parsers
{
    // ── Core parser contract ─────────────────────────────────────────────────
    public interface ILogParser
    {
        ParserResult Parse(string logFilePath, string outputDir);
        string ParserName { get; }
        string[] SupportedPatterns { get; }
    }

    // ── Lean attach interfaces ────────────────────────────────────────────────
    // These let the orchestrator use a clean 'is' check instead of reflection.
    // Any parser that already has AttachSessionTracker / AttachNormalizedWriter
    // only needs to declare the interface — no new code required.

    public interface IAttachSessionTracker
    {
        void AttachSessionTracker(SessionTracker tracker);
    }

    public interface IAttachNormalizedWriter
    {
        void AttachNormalizedWriter(NormalizedCsvWriter writer);
    }

    // ── Composite interfaces (kept for future use) ───────────────────────────
    public interface ISessionTrackingParser : ILogParser, IAttachSessionTracker
    {
        SessionTracker SessionTracker { get; }
    }

    public interface INormalizedOutputParser : ILogParser, IAttachNormalizedWriter
    {
        NormalizedCsvWriter NormalizedWriter { get; }
    }

    public interface IFullFeaturedParser : ISessionTrackingParser, INormalizedOutputParser { }

    // ── Structured parse result ──────────────────────────────────────────────
    public class ParserResult
    {
        public List<string> Findings { get; set; } = new List<string>();
        public Dictionary<string, int> PatternCounts { get; set; } = new Dictionary<string, int>();
        public DateTime FirstSeen { get; set; } = DateTime.MaxValue;
        public DateTime LastSeen { get; set; } = DateTime.MinValue;
        public Dictionary<string, int> InterestingIPs { get; set; } = new Dictionary<string, int>();
        public bool Success { get; set; } = true;
        public string ErrorMessage { get; set; }
        public TimeSpan ParseDuration { get; set; }
        public int LinesProcessed { get; set; }
        public int SuspiciousEventsFound { get; set; }

        public static ParserResult CreateError(string errorMessage) =>
            new ParserResult { Success = false, ErrorMessage = errorMessage };
    }
}
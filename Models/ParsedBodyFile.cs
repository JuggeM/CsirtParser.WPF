using System;
using System.Collections.Generic;

namespace Parser.Models
{
    public class ParsedBodyFile
    {
        public List<BodyFileEntry> Entries { get; set; } = new();
        public List<string> Findings { get; set; } = new();
        public DateTime? FirstLogUtc { get; set; }
        public DateTime? LastLogUtc { get; set; }

        // Legacy fields (optional; keep if you still use them)
        public List<string> SuspiciousByPath { get; set; } = new();
        public Dictionary<string, string> SuspiciousBreakdown { get; set; } = new();
    }

    public class BodyFileEntry
    {
        public string Path { get; set; } = string.Empty;
        public long Size { get; set; }
        public string Mode { get; set; } = string.Empty;
        public string UID { get; set; } = string.Empty;
        public string GID { get; set; } = string.Empty;
        public string MD5 { get; set; } = string.Empty;

        // Epochs (UTC)
        public long? AccessEpoch { get; set; }
        public long? ModifyEpoch { get; set; }
        public long? ChangeEpoch { get; set; }
        public long? BirthEpoch { get; set; }
    }
}

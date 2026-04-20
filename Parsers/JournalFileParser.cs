// JournalFileParser.cs
// Pure C# binary parser for systemd journal files (.journal)
// Handles both regular and compact formats (systemd 246+)
// Format reference: https://systemd.io/JOURNAL_FILE_FORMAT/
// NuGet required: K4os.Compression.LZ4, ZstdSharp.Port

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Helpers;
using Output;

namespace Parsers
{
    public class JournalEntry
    {
        public DateTime TimestampUtc { get; set; }
        public string Hostname { get; set; } = string.Empty;
        public string Identifier { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public string Comm { get; set; } = string.Empty;
        public string Exe { get; set; } = string.Empty;
        public string Cmdline { get; set; } = string.Empty;
        public string Unit { get; set; } = string.Empty;
        public string Transport { get; set; } = string.Empty;
        public int? Pid { get; set; }
        public int? Uid { get; set; }
        public int Priority { get; set; } = 6;
    }

    public class JournalFileParser : LogFileParser, IAttachNormalizedWriter
    {
        private NormalizedCsvWriter _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter w) => _normalizedWriter = w;

        // Object types
        private const byte ObjData = 1;
        private const byte ObjEntry = 3;
        private const byte ObjEntryArray = 6;

        // Object compression flags
        private const byte FlagXz = 1;
        private const byte FlagLz4 = 2;
        private const byte FlagZstd = 4;

        // Header incompatible flags
        private const uint IncompatCompact = 16;

        // Max sane payload (256 KB)
        private const ulong MaxPayload = 256 * 1024;

        // DataObject fixed header sizes:
        //   Regular: header(16) + hash(8) + next_hash(8) + next_field(8)
        //            + entry_offset(8) + entry_array_offset(8) + n_entries(8) = 64
        //   Compact: same 64 + tail_entry_array_offset(8) = 72
        private const ulong DataHeaderBytesRegular = 64UL;
        private const ulong DataHeaderBytesCompact = 72UL;

        // ── Classification ───────────────────────────────────────────
        //
        // Three tiers:
        //   Critical → written to RTF findings (almost certainly malicious)
        //   Noise    → counted in pattern summary only (notable but expected)
        //   Info     → ignored entirely
        //
        // Critical: unambiguous attacker TTPs
        private static readonly string[] CriticalCmdKeywords =
        {
            // One-liner code execution (interpreter -c / -e / -r)
            "python -c", "python2 -c", "python3 -c",
            "perl -e", "ruby -e", "php -r", "lua -e",
            // Interactive shell spawns (reverse/bind shell indicator)
            "bash -i", "sh -i", "zsh -i", "ksh -i", "dash -i",
            // Network relay / pivot
            "socat",
            // Named pipe shell tricks
            "mkfifo", "mknod",
            // Obfuscation / decode
            "base64 -d", "base64 --decode",
            // Stdout/stderr redirect into a shell (reverse shell)
            "0>&1", ">&2",
            // Explicit attacker terms
            "backdoor", "rootkit", "exploit", "payload",
            // Download piped directly to shell
            "wget -q -O- |", "wget -qO- |", "curl -s |", "curl -fsSL |",
            "wget -q -O /tmp", "wget -O /tmp", "wget -O /dev/shm",
            "curl -o /tmp", "curl -o /dev/shm",
            // chattr to hide files from deletion/detection
            "chattr +i", "chattr -i",
        };

        // Executable running FROM a suspicious temp path → always critical
        private static readonly string[] CriticalExePaths =
            { "/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/" };

        // Noise: notable but not actionable on their own — counted only
        private static readonly string[] NoiseCmdKeywords =
        {
            "wget", "curl",
            "nc ", "netcat", "ncat",
            "chmod +x", "chmod 777",
            "xxd", "dd if=",
            "2>&1",
        };

        // Returns "Critical", "Noise", or "Info"
        private static string ClassifyEntry(JournalEntry e)
        {
            string msg = (e.Message ?? string.Empty).ToLowerInvariant();
            string exe = (e.Exe ?? string.Empty).ToLowerInvariant();
            string cmd = (e.Cmdline ?? string.Empty);
            string cmdLo = cmd.ToLowerInvariant();
            string ident = (e.Identifier ?? string.Empty).ToLowerInvariant();

            // ── NOISE fast-path ───────────────────────────────────────
            // Ansible automation — counted, never in findings
            if (IsAnsibleAutomation(e)) return "Noise";

            // SSH events — counted
            if (ident is "sshd" or "ssh") return "Noise";

            // pam_unix session open/close (sudo session bookkeeping)
            if (msg.StartsWith("pam_unix(sudo:session)")) return "Noise";

            // ── CRITICAL checks ───────────────────────────────────────
            // Emergency / Alert priority
            if (e.Priority <= 1) return "Critical";

            // Executable running from temp path
            foreach (var p in CriticalExePaths)
                if (exe.Contains(p)) return "Critical";

            // Command contains an unambiguous attacker keyword
            foreach (var kw in CriticalCmdKeywords)
                if (cmd.Contains(kw, StringComparison.OrdinalIgnoreCase)
                    || msg.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    return "Critical";

            // Non-ansible sudo running something from a temp path in cmdline
            if (ident == "sudo")
            {
                foreach (var p in CriticalExePaths)
                    if (cmdLo.Contains(p)) return "Critical";
                // sudo COMMAND= line pointing to something in temp
                if (msg.Contains("command="))
                {
                    foreach (var p in CriticalExePaths)
                        if (msg.Contains(p)) return "Critical";
                }
                // Everything else sudo → Noise (session events, normal commands)
                return "Noise";
            }

            // ── NOISE fallback ────────────────────────────────────────
            // Noisy keywords without escalating context
            foreach (var kw in NoiseCmdKeywords)
                if (cmdLo.Contains(kw) || msg.Contains(kw)) return "Noise";

            // Priority 2-4 (Critical/Error/Warning) — notable but not RTF
            if (e.Priority <= 4) return "Noise";

            return "Info";
        }

        // Pattern label for summary counts
        private static string ClassifyPattern(JournalEntry e)
        {
            string ident = (e.Identifier ?? string.Empty).ToLowerInvariant();
            string msg = (e.Message ?? string.Empty).ToLowerInvariant();
            string cmd = (e.Cmdline ?? string.Empty).ToLowerInvariant();

            if (IsAnsibleAutomation(e)) return "Ansible automation";
            if (ident is "sshd" or "ssh" && msg.Contains("failed")) return "SSH login failed";
            if (ident is "sshd" or "ssh" && msg.Contains("accepted")) return "SSH login accepted";
            if (ident is "sshd" or "ssh") return "SSH event";
            if (ident == "sudo") return "Sudo command";
            if (cmd.Contains("wget") || cmd.Contains("curl")) return "Download tool";
            if (cmd.Contains("/tmp/") || cmd.Contains("/dev/shm/")) return "Temp path execution";
            if (ident is "bash" or "sh" or "zsh") return "Shell execution";
            return "Suspicious journal entry";
        }

        private static string FormatFinding(JournalEntry e, string severity)
        {
            var sb = new StringBuilder();
            sb.Append($"[JOURNAL] [{severity.ToUpperInvariant()}]");
            sb.Append($" [{e.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC]");
            if (!string.IsNullOrEmpty(e.Identifier)) sb.Append($" [{e.Identifier}]");
            if (e.Uid.HasValue) sb.Append($" UID={e.Uid}");
            if (e.Pid.HasValue) sb.Append($" PID={e.Pid}");
            if (!string.IsNullOrEmpty(e.Message)) sb.Append($" {e.Message}");
            if (!string.IsNullOrEmpty(e.Cmdline) && e.Cmdline != e.Message)
                sb.Append($" | CMD: {e.Cmdline}");
            if (!string.IsNullOrEmpty(e.Exe)) sb.Append($" | EXE: {e.Exe}");
            return sb.ToString();
        }

        private static string BuildRaw(JournalEntry e)
            => $"{e.TimestampUtc:yyyy-MM-dd HH:mm:ss} {e.Hostname} {e.Identifier}[{e.Pid}]: {e.Message}";

        // ── Grouping / deduplication ──────────────────────────────────
        private static readonly System.Text.RegularExpressions.Regex RxAnsibleKey =
            new(@"key=[a-zA-Z0-9_]+", System.Text.RegularExpressions.RegexOptions.Compiled);
        private static readonly System.Text.RegularExpressions.Regex RxBecomeToken =
            new(@"BECOME-SUCCESS-[a-zA-Z0-9_]+", System.Text.RegularExpressions.RegexOptions.Compiled);
        private static readonly System.Text.RegularExpressions.Regex RxAnsibleTmp =
            new(@"ansible[/-]tmp[^\s\]""']*", System.Text.RegularExpressions.RegexOptions.Compiled);
        private static readonly System.Text.RegularExpressions.Regex RxAnsiballZ =
            new(@"AnsiballZ_\w+\.py", System.Text.RegularExpressions.RegexOptions.Compiled);
        private static readonly System.Text.RegularExpressions.Regex RxLongNum =
            new(@"\d{5,}", System.Text.RegularExpressions.RegexOptions.Compiled);

        // True if this entry is ansible automation noise (should be heavily collapsed)
        private static bool IsAnsibleAutomation(JournalEntry e)
        {
            string cmd = e.Cmdline ?? string.Empty;
            string msg = e.Message ?? string.Empty;
            return cmd.Contains("ansible", StringComparison.OrdinalIgnoreCase)
                || cmd.Contains("BECOME-SUCCESS")
                || msg.Contains("ansible", StringComparison.OrdinalIgnoreCase);
        }

        private static string NormalizeForDisplay(string s)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            s = RxAnsibleKey.Replace(s, "key=***");
            s = RxBecomeToken.Replace(s, "BECOME-SUCCESS-***");
            s = RxAnsibleTmp.Replace(s, "ansible-tmp-***");
            s = RxAnsiballZ.Replace(s, "AnsiballZ_***.py");
            s = RxLongNum.Replace(s, "***");
            // Truncate very long strings
            if (s.Length > 160) s = s.Substring(0, 157) + "...";
            return s;
        }

        private static string NormalizeSignature(JournalEntry e, string severity)
        {
            // Ansible automation: collapse ALL sudo-via-ansible into one group per UID.
            // These are legitimate automation runs; we only want ONE line per user.
            if (IsAnsibleAutomation(e))
                return $"ANSIBLE|{e.Uid}";

            // Sudo: group by UID + normalized command (strip volatile tokens)
            if ((e.Identifier ?? "").Equals("sudo", StringComparison.OrdinalIgnoreCase))
            {
                string cmd = RxLongNum.Replace(e.Cmdline ?? string.Empty, "***");
                if (cmd.Length > 120) cmd = cmd.Substring(0, 120);
                return $"{severity}|sudo|{e.Uid}|{cmd}";
            }

            // SSH: group by identifier + normalized message (drop session IDs / ports)
            if ((e.Identifier ?? "").StartsWith("ssh", StringComparison.OrdinalIgnoreCase))
            {
                string msg = RxLongNum.Replace(e.Message ?? string.Empty, "***");
                return $"{severity}|{e.Identifier}|{msg}";
            }

            // General: severity + identifier + UID + normalized message (truncated)
            {
                string msg = RxLongNum.Replace(e.Message ?? string.Empty, "***");
                if (msg.Length > 120) msg = msg.Substring(0, 120);
                return $"{severity}|{e.Identifier}|{e.Uid}|{msg}";
            }
        }

        private static string FormatGroupedFinding(
            JournalEntry rep, string severity,
            DateTime first, DateTime last, int count)
        {
            var sb = new StringBuilder();
            sb.Append($"[JOURNAL] [{severity.ToUpperInvariant()}]");

            // Timestamp range
            if (count == 1)
                sb.Append($" [{first:yyyy-MM-dd HH:mm:ss} UTC]");
            else
                sb.Append($" [{first:yyyy-MM-dd HH:mm:ss} → {last:yyyy-MM-dd HH:mm:ss} UTC] (x{count})");

            // Ansible gets a compact summary line — no raw cmdline noise
            if (IsAnsibleAutomation(rep))
            {
                sb.Append($" [sudo/ansible] UID={rep.Uid}");
                sb.Append(" Ansible automation via sudo (session open/close + module execution)");
                sb.Append(" | EXE: /usr/bin/sudo");
                return sb.ToString();
            }

            if (!string.IsNullOrEmpty(rep.Identifier)) sb.Append($" [{rep.Identifier}]");
            if (rep.Uid.HasValue) sb.Append($" UID={rep.Uid}");
            if (!string.IsNullOrEmpty(rep.Message))
                sb.Append($" {NormalizeForDisplay(rep.Message)}");

            if (!string.IsNullOrEmpty(rep.Cmdline) && rep.Cmdline != rep.Message)
                sb.Append($" | CMD: {NormalizeForDisplay(rep.Cmdline)}");

            if (!string.IsNullOrEmpty(rep.Exe)) sb.Append($" | EXE: {rep.Exe}");
            return sb.ToString();
        }

        // ── LogFileParser override ────────────────────────────────────
        protected override void ParseLog(
            string logFilePath,
            List<string> findings,
            Dictionary<string, int> patternCounts,
            ref DateTime firstSeen,
            ref DateTime lastSeen,
            Dictionary<string, int> interestingIPs = null,
            string outputDir = null,
            bool suppressFooter = false)
        {
            List<JournalEntry> entries;
            try
            {
                entries = ReadJournal(logFilePath);
            }
            catch (Exception ex)
            {
                findings.Add($"[JOURNAL] [ERROR] Failed to parse {Path.GetFileName(logFilePath)}: {ex.Message}");
                return;
            }

            if (entries.Count == 0) return;

            // Grouped findings (Critical only) — key = normalized signature
            var groups = new Dictionary<string, (JournalEntry Rep, string Severity, DateTime First, DateTime Last, int Count)>();

            foreach (var e in entries)
            {
                if (e.TimestampUtc > DateTime.MinValue)
                {
                    if (e.TimestampUtc < firstSeen) firstSeen = e.TimestampUtc;
                    if (e.TimestampUtc > lastSeen) lastSeen = e.TimestampUtc;
                }

                string tier = ClassifyEntry(e);
                if (tier == "Info") continue;

                // Every non-Info entry feeds pattern summary counts
                IncrementPatternCount(patternCounts, ClassifyPattern(e));

                // Only Critical entries go into RTF findings
                if (tier == "Critical")
                {
                    string sig = NormalizeSignature(e, tier);
                    if (groups.TryGetValue(sig, out var g))
                    {
                        groups[sig] = (g.Rep, g.Severity,
                            e.TimestampUtc < g.First ? e.TimestampUtc : g.First,
                            e.TimestampUtc > g.Last ? e.TimestampUtc : g.Last,
                            g.Count + 1);
                    }
                    else
                    {
                        groups[sig] = (e, tier, e.TimestampUtc, e.TimestampUtc, 1);
                    }
                }

                _normalizedWriter?.Write(NormalizedRecord.From(
                    timestamp: e.TimestampUtc,
                    hostname: e.Hostname,
                    logType: "JOURNAL",
                    daemon: e.Identifier,
                    user: e.Uid?.ToString() ?? string.Empty,
                    ip: string.Empty,
                    message: e.Message,
                    severity: tier == "Critical" ? "High" : "Info",
                    raw: BuildRaw(e)
                ));
            }

            // Emit one finding per group, sorted by first-seen
            foreach (var kv in groups.Values.OrderBy(g => g.First))
                findings.Add(FormatGroupedFinding(kv.Rep, kv.Severity, kv.First, kv.Last, kv.Count));
        }

        // ── Public parse-only entry point (no QuickWins writing) ──────
        // Called by the orchestrator so it can write ONE combined section
        // with per-file subheaders instead of repeating the header per file.
        public (List<string> Findings,
                Dictionary<string, int> Patterns,
                DateTime First,
                DateTime Last)
            ParseFile(string filePath)
        {
            var findings = new List<string>();
            var patterns = new Dictionary<string, int>();
            DateTime first = DateTime.MaxValue;
            DateTime last = DateTime.MinValue;

            ParseLog(filePath, findings, patterns,
                     ref first, ref last,
                     interestingIPs: null, outputDir: null, suppressFooter: true);

            return (findings, patterns, first, last);
        }

        // ── Binary journal reader ─────────────────────────────────────
        public static List<JournalEntry> ReadJournal(string filePath)
        {
            var entries = new List<JournalEntry>();

            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                                          FileShare.ReadWrite);
            using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);

            if (fs.Length < 256) return entries;

            // ── Verify magic ──────────────────────────────────────────
            var sig = br.ReadBytes(8);
            var expected = new byte[] { 0x4C, 0x50, 0x4B, 0x53, 0x48, 0x48, 0x52, 0x48 };
            for (int i = 0; i < 8; i++)
                if (sig[i] != expected[i])
                    throw new InvalidDataException("Not a systemd journal file");

            // ── Header ────────────────────────────────────────────────
            // Offset 12: incompatible_flags (4)
            // Offset 176: entry_array_offset (8)
            br.BaseStream.Position = 12;
            uint incompatFlags = br.ReadUInt32();
            bool compact = (incompatFlags & IncompatCompact) != 0;

            br.BaseStream.Position = 176;
            ulong entryArrayOffset = br.ReadUInt64();
            if (entryArrayOffset == 0 || entryArrayOffset >= (ulong)fs.Length)
                return entries;

            // ── Walk entry array chain ────────────────────────────────
            // Regular:  items are le64_t — raw absolute file offsets.
            // Compact:  items are le32_t — store (offset >> 3), multiply ×8 to recover.
            var entryOffsets = new List<ulong>(8192);
            ulong arrayOff = entryArrayOffset;

            while (arrayOff != 0 && (long)arrayOff + 24 <= fs.Length)
            {
                br.BaseStream.Position = (long)arrayOff;

                byte objType = br.ReadByte();
                byte objFlags = br.ReadByte();
                br.ReadBytes(6);
                ulong objSize = br.ReadUInt64();

                if (objType != ObjEntryArray) break;
                if (objSize < 24 || arrayOff + objSize > (ulong)fs.Length) break;

                ulong nextArray = br.ReadUInt64();
                ulong payloadBytes = objSize - 24;

                if (compact)
                {
                    ulong n = payloadBytes / 4;
                    for (ulong i = 0; i < n; i++)
                    {
                        ulong off = br.ReadUInt32(); // plain le32_t byte offset
                        if (off != 0 && off < (ulong)fs.Length)
                            entryOffsets.Add(off);
                    }
                }
                else
                {
                    ulong n = payloadBytes / 8;
                    for (ulong i = 0; i < n; i++)
                    {
                        ulong off64 = br.ReadUInt64();
                        if (off64 != 0 && off64 < (ulong)fs.Length)
                            entryOffsets.Add(off64);
                    }
                }

                arrayOff = nextArray;
            }

            // ── Parse each entry ──────────────────────────────────────
            foreach (var entryOff in entryOffsets)
            {
                try
                {
                    var entry = ReadEntry(br, entryOff, fs.Length, compact);
                    if (entry != null) entries.Add(entry);
                }
                catch { /* skip corrupted entries */ }
            }

            return entries;
        }

        private static JournalEntry ReadEntry(BinaryReader br, ulong offset,
                                               long fileLen, bool compact)
        {
            if (offset + 64 > (ulong)fileLen) return null;
            br.BaseStream.Position = (long)offset;

            // Object header: type(1) + flags(1) + reserved(6) + size(8) = 16 bytes
            byte objType = br.ReadByte();
            byte objFlags = br.ReadByte();
            br.ReadBytes(6);
            ulong objSize = br.ReadUInt64();

            if (objType != ObjEntry) return null;
            if (objSize < 64 || offset + objSize > (ulong)fileLen) return null;

            // Entry fixed fields (48 bytes):
            //   seqnum(8) + realtime(8) + monotonic(8) + boot_id(16) + xor_hash(8)
            br.ReadUInt64();
            ulong realtime = br.ReadUInt64();
            br.ReadUInt64();
            br.ReadBytes(16);
            br.ReadUInt64();

            ulong itemsBytes = objSize - 64;
            var dataOffsets = new List<ulong>();

            if (compact)
            {
                // Compact: plain le32_t byte offsets
                ulong n = itemsBytes / 4;
                if (n > 512) n = 512;
                for (ulong i = 0; i < n; i++)
                {
                    ulong off = br.ReadUInt32();
                    if (off != 0 && off < (ulong)fileLen)
                        dataOffsets.Add(off);
                }
            }
            else
            {
                // Regular: each item is {le64_t offset, le64_t hash} = 16 bytes
                ulong n = itemsBytes / 16;
                if (n > 512) n = 512;
                for (ulong i = 0; i < n; i++)
                {
                    ulong off64 = br.ReadUInt64();
                    br.ReadUInt64(); // hash (skip)
                    if (off64 != 0 && off64 < (ulong)fileLen)
                        dataOffsets.Add(off64);
                }
            }

            var entry = new JournalEntry();
            if (realtime > 0)
            {
                try
                {
                    entry.TimestampUtc = DateTimeOffset
                        .FromUnixTimeMilliseconds((long)(realtime / 1000))
                        .UtcDateTime;
                }
                catch { entry.TimestampUtc = DateTime.MinValue; }
            }

            foreach (var dataOff in dataOffsets)
            {
                try { ReadDataObject(br, dataOff, fileLen, entry, compact); }
                catch { /* skip corrupted field */ }
            }
            return entry;
        }


        // DataObject layout is identical in regular and compact modes.
        // Only EntryObject and EntryArrayObject items differ between the two.
        private static void ReadDataObject(BinaryReader br, ulong offset,
                                            long fileLen, JournalEntry entry, bool compact)
        {
            ulong dataHeaderBytes = compact ? DataHeaderBytesCompact : DataHeaderBytesRegular;

            if (offset + dataHeaderBytes > (ulong)fileLen)
            {
                return;
            }
            br.BaseStream.Position = (long)offset;

            // Object header (16 bytes)
            byte objType = br.ReadByte();
            byte objFlags = br.ReadByte();
            br.ReadBytes(6);
            ulong objSize = br.ReadUInt64();

            if (objType != ObjData)
            {
                return;
            }
            if (objSize < dataHeaderBytes || offset + objSize > (ulong)fileLen)
            {
                return;
            }

            // Skip remaining fixed fields after 16-byte header.
            // Regular: hash(8)+next_hash(8)+next_field(8)+entry_offset(8)+entry_array_offset(8)+n_entries(8) = 48
            // Compact: same 48 + tail_entry_array_offset(8) = 56
            br.ReadBytes((int)(dataHeaderBytes - 16));

            ulong payloadSize = objSize - dataHeaderBytes;
            if (payloadSize == 0 || payloadSize > MaxPayload)
            {
                return;
            }

            byte[] payload;

            if ((objFlags & FlagLz4) != 0)
            {
                if (payloadSize < 8) return;
                ulong origSize = br.ReadUInt64();
                if (origSize == 0 || origSize > MaxPayload) return;
                int compLen = (int)(payloadSize - 8);
                if (compLen <= 0) return;
                byte[] comp = br.ReadBytes(compLen);
                payload = DecompressLz4(comp, (int)origSize);
                if (payload == null) { return; }
            }
            else if ((objFlags & FlagZstd) != 0)
            {
                byte[] comp = br.ReadBytes((int)payloadSize);
                payload = DecompressZstd(comp);
                if (payload == null) { return; }
            }
            else if ((objFlags & FlagXz) != 0)
            {
                return;
            }
            else
            {
                payload = br.ReadBytes((int)payloadSize);
            }

            // Payload: "FIELD=value" (UTF-8)
            int sep = Array.IndexOf(payload, (byte)'=');
            if (sep <= 0)
            {
                return;
            }

            string key = Encoding.UTF8.GetString(payload, 0, sep);
            string value = Encoding.UTF8.GetString(payload, sep + 1, payload.Length - sep - 1)
                               .TrimEnd('\0', '\n', '\r');

            switch (key)
            {
                case "MESSAGE": entry.Message = value; break;
                case "SYSLOG_IDENTIFIER": entry.Identifier = value; break;
                case "_COMM": entry.Comm = value; break;
                case "_EXE": entry.Exe = value; break;
                case "_CMDLINE": entry.Cmdline = value.Replace('\0', ' ').Trim(); break;
                case "_HOSTNAME": entry.Hostname = value; break;
                case "_TRANSPORT": entry.Transport = value; break;
                case "_SYSTEMD_UNIT":
                case "_SYSTEMD_USER_UNIT": entry.Unit = value; break;
                case "_PID":
                    if (int.TryParse(value, out var pid)) entry.Pid = pid; break;
                case "_UID":
                    if (int.TryParse(value, out var uid)) entry.Uid = uid; break;
                case "PRIORITY":
                    if (int.TryParse(value, out var pri)) entry.Priority = pri; break;
            }
        }

        // ── LZ4 decompression (K4os.Compression.LZ4) ─────────────────
        private static byte[] DecompressLz4(byte[] compressed, int origSize)
        {
            try
            {
                var output = new byte[origSize];
                int decoded = K4os.Compression.LZ4.LZ4Codec.Decode(
                    compressed, 0, compressed.Length,
                    output, 0, output.Length);
                return decoded > 0 ? output : null;
            }
            catch { return null; }
        }

        // ── ZSTD decompression (ZstdSharp.Port) ───────────────────────
        private static byte[] DecompressZstd(byte[] compressed)
        {
            try
            {
                using var input = new MemoryStream(compressed);
                using var output = new MemoryStream();
                using var ds = new ZstdSharp.DecompressionStream(input);
                ds.CopyTo(output);
                return output.ToArray();
            }
            catch { return null; }
        }
    }
}
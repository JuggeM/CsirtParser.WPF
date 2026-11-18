using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Helpers;
using Output;

namespace Parsers
{
    /// <summary>
    /// AI coding agents (UAC 3.4.0+ artifacts/files/applications/ai_tools).
    ///
    /// Per user home it finds the agents' folders (Claude Code, Codex, Gemini CLI,
    /// Copilot, Cursor, Goose, OpenCode, Qwen, Kiro, …) and reads:
    ///   • Transcripts (*.jsonl / *.json): every shell command the agent ran, files it
    ///     wrote, URLs it fetched and the prompts it was given. One generic JSON walker
    ///     recognises the tool-call shapes of the different agents (Claude tool_use,
    ///     Codex function_call/local_shell_call, Gemini functionCall/toolCalls, …).
    ///   • Configuration: hooks and status-line commands (run automatically), MCP
    ///     servers, approval bypass (bypassPermissions, yolo, approval_policy=never),
    ///     API base URL redirection.
    ///   • Instruction files (CLAUDE.md, AGENTS.md, GEMINI.md, …): planted commands or
    ///     prompt-injection phrases.
    ///   • Credential files: reported as present, never read.
    ///
    /// Agents legitimately use /tmp, python -c and curl, so the bash keyword hits are
    /// SUSPICIOUS here; only strong signals (reverse shell, pipe to shell, secrets
    /// access, anti-forensics, writes to persistence files) are HIGH.
    /// </summary>
    public class AiAgentParser : LogFileParser, IAttachNormalizedWriter
    {
        public const string LogKey = "AIAGENT";

        private NormalizedCsvWriter? _normalizedWriter;
        public void AttachNormalizedWriter(NormalizedCsvWriter writer) => _normalizedWriter = writer;

        private string _hostname = string.Empty;
        public void AttachHostname(string hostname) => _hostname = hostname ?? string.Empty;

        // ── Agents and where UAC collects them (relative to a home folder) ──
        private sealed record AgentDef(string Name, string Key, string[] Paths);

        private static readonly AgentDef[] Agents =
        {
            new("Claude Code", "claude-code", new[] { ".claude", ".config/claude", ".claude.json" }),
            new("Claude Desktop", "claude-desktop", new[] { "Library/Application Support/Claude", "Library/Logs/Claude" }),
            new("OpenAI Codex", "codex", new[] { ".codex" }),
            new("Gemini CLI", "gemini", new[] { ".gemini" }),
            new("GitHub Copilot", "copilot", new[]
            {
                ".copilot", ".config/github-copilot",
                ".config/Code/User/workspaceStorage", ".config/Code/User/globalStorage/github.copilot-chat",
                ".config/Code/User/globalStorage/emptyWindowChatSessions",
                ".config/Code/User/globalStorage/transferredChatSessions",
                "Library/Application Support/Code/User/workspaceStorage",
                "Library/Application Support/Code/User/globalStorage/github.copilot-chat",
                "Library/Application Support/Code/User/globalStorage/emptyWindowChatSessions",
                "Library/Application Support/Code/User/globalStorage/transferredChatSessions",
            }),
            new("Cursor", "cursor", new[]
            {
                ".cursor", ".config/Cursor/User", "Library/Application Support/Cursor/User",
            }),
            new("Amp", "amp", new[] { ".local/share/amp", ".config/amp" }),
            new("Codebuff", "codebuff", new[] { ".config/manicode", ".config/manicode-dev", ".config/manicode-staging" }),
            new("Factory Droid", "droid", new[] { ".factory" }),
            new("Goose", "goose", new[]
            {
                ".local/share/goose", ".local/share/Block/goose", ".config/goose", "Library/Application Support/goose",
            }),
            new("Hermes", "hermes", new[] { ".hermes" }),
            new("Kilo", "kilo", new[] { ".local/share/kilo", ".config/kilo" }),
            new("Kimi", "kimi", new[] { ".kimi" }),
            new("Kiro", "kiro", new[]
            {
                ".kiro", "Library/Application Support/kiro-cli", "Library/Application Support/Kiro/User",
            }),
            new("OpenClaw", "openclaw", new[] { ".openclaw", ".clawdbot", ".moltbot", ".moldbot" }),
            new("OpenCode", "opencode", new[] { ".local/share/opencode", ".config/opencode", ".local/state/opencode" }),
            new("pi-agent", "pi", new[] { ".pi" }),
            new("Qwen Code", "qwen", new[] { ".qwen" }),
        };

        // ── Tool names (lower case) ───────────────────────────────────
        private static readonly HashSet<string> ShellTools = new(StringComparer.OrdinalIgnoreCase)
        {
            "bash", "shell", "local_shell", "exec_command", "run_shell_command", "execute_command",
            "run_terminal_cmd", "run_in_terminal", "terminal", "run_command", "shell_command",
            "execute_bash", "bash_command", "runcommand", "run_bash", "developer__shell", "powershell",
        };

        private static readonly HashSet<string> WriteTools = new(StringComparer.OrdinalIgnoreCase)
        {
            "write", "edit", "multiedit", "notebookedit", "write_file", "replace", "edit_file",
            "create_file", "str_replace_editor", "str_replace_based_edit_tool", "apply_patch",
            "patch", "writefile", "editfile", "fs_write", "text_editor", "developer__text_editor",
            "insert_edit_into_file", "replace_string_in_file",
        };

        private static readonly HashSet<string> FetchTools = new(StringComparer.OrdinalIgnoreCase)
        {
            "webfetch", "web_fetch", "fetch", "read_url", "fetch_url", "browser_navigate", "url_fetch",
            "fetch_webpage", "open_url",
        };

        private static readonly string[] NameKeys = { "name", "tool", "toolName", "tool_name", "recipient", "functionName" };
        private static readonly string[] ArgKeys = { "input", "args", "arguments", "parameters", "params", "action" };
        private static readonly string[] CommandKeys = { "command", "cmd", "commandLine", "command_line", "script" };
        private static readonly string[] PathKeys = { "file_path", "path", "filePath", "target_file", "absolute_path", "notebook_path", "filename" };
        private static readonly string[] TimeKeys = { "timestamp", "ts", "createdAt", "created_at", "startTime", "time", "created", "start" };

        // ── Credential / config / instruction file names ──────────────
        private static readonly HashSet<string> CredentialFiles = new(StringComparer.OrdinalIgnoreCase)
        {
            ".credentials.json", "credentials.json", "auth.json", "oauth_creds.json", "google_accounts.json",
            "hosts.json", "apps.json", "secrets.json", "token.json", "api_key", ".env",
        };

        private static readonly HashSet<string> InstructionFiles = new(StringComparer.OrdinalIgnoreCase)
        {
            "CLAUDE.md", "AGENTS.md", "GEMINI.md", "QWEN.md", "KIMI.md", "AGENT.md", ".cursorrules", ".goosehints",
        };

        // ── Detection patterns ────────────────────────────────────────
        private static Regex Rx(string p) => new(p, RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly (Regex Rx, string Label)[] StrongCommand =
        {
            (Rx(@"/dev/(?:tcp|udp)/|\b(?:bash|sh|zsh)\s+-i\b|\bnc(?:at)?\b[^|;]*\s-[a-z]*e\s|\bsocat\b[^|;]*exec|\bmkfifo\b"), "reverse shell"),
            (Rx(@"\b(?:find|locate|grep|rg|fd)\b[^|;]*(?:wallet|keystore|mnemonic|seed[ _-]?phrase|metamask|electrum|exodus|id_rsa|\.pem\b|\.kdbx)"), "secrets hunt"),
            (Rx(@"/etc/shadow\b|\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)|\.aws/credentials|\.kube/config\b|\.docker/config\.json|\.git-credentials|\.netrc\b|\.pgpass\b"), "credential access"),
            (Rx(@"\b(?:msfvenom|msfconsole|mimikatz|pypykatz|secretsdump|crackmapexec|hashcat|unshadow|chisel|ligolo)\b"), "attacker tool"),
            (Rx(@"\b(?:curl|wget)\b[^|;]*(?:transfer\.sh|file\.io|0x0\.st|paste(?:bin)?\.|webhook\.site|ngrok|requestbin|pipedream|interact\.sh|oast\.)"), "upload/tunnel service"),
            (Rx(@"\bcurl\b[^|;]*(?:\s-F\s|\s-T\s|--upload-file|--data(?:-binary)?\s+@)[^|;]*https?://\d{1,3}(?:\.\d{1,3}){3}"), "file upload to raw IP"),
        };

        private static readonly Regex SensitivePathRx = new(
            @"authorized_keys|/etc/(?:sudoers|passwd|shadow|group|crontab|cron\.|rc\.local|ld\.so\.preload|profile|bash\.bashrc|pam\.d/|ssh/sshd_config|systemd/)|" +
            @"/var/spool/cron/|/\.config/systemd/user/|(?:^|/)\.(?:bashrc|bash_profile|profile|zshrc|zprofile)$|/\.ssh/",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex AgentConfigPathRx = new(
            @"(?:^|/)\.(?:claude|gemini|codex|cursor|qwen|kiro|kimi|factory|copilot)/(?:settings(?:\.local)?\.json|config\.toml|mcp\.json)$|" +
            @"(?:^|/)\.mcp\.json$|(?:^|/)\.claude\.json$|(?:^|/)(?:CLAUDE|AGENTS|GEMINI|QWEN)\.md$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Same files, mentioned anywhere inside a shell command
        private static readonly Regex AgentConfigInCmdRx = new(
            @"\.(?:claude|gemini|codex|cursor|qwen|kiro|kimi|factory|copilot)/(?:settings(?:\.local)?\.json|config\.toml|mcp\.json)|" +
            @"\.mcp\.json|\.claude\.json|\b(?:CLAUDE|AGENTS|GEMINI|QWEN)\.md\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex RawIpUrlRx = new(
            @"\b(?:https?|wss?)://(?<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex ShadyHostRx = new(
            @"\b(?:transfer\.sh|file\.io|0x0\.st|pastebin\.com|paste\.ee|webhook\.site|ngrok(?:-free)?\.(?:io|app)|trycloudflare\.com|requestbin|pipedream\.net|interact\.sh|oast\.\w+)\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex SecretTermRx = new(
            @"\b(?:wallets?|seed\s*phrases?|mnemonics?|private\s+keys?|keystores?|metamask|electrum|ledger\s+live|id_rsa|ssh\s+keys?|api\s*keys?|\.env\b|credentials?|passwords?|tokens?)\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex SearchVerbRx = new(
            @"\b(?:search|find|scan|locate|look\s+for|collect|gather|inventory|enumerate|list\s+all|recursively|harvest|exfiltrat\w*|upload|send)\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex BroadScopeRx = new(
            @"\b(?:recursively|entire\s+(?:file\s*system|disk|home)|whole\s+(?:file\s*system|disk)|all\s+files|every\s+file|\$HOME|/home|/root|filesystem)\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex InjectionPhraseRx = new(
            @"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|do\s+not\s+(?:tell|inform|mention\s+(?:this\s+)?to)\s+the\s+user|" +
            @"without\s+(?:asking|telling)\s+the\s+user|disregard\s+(?:the\s+)?(?:system|safety)|<\s*/?\s*system\s*>|you\s+are\s+now\s+in\s+developer\s+mode",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex PatchFileRx = new(
            @"^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s*(?<p>.+)$", RegexOptions.Compiled | RegexOptions.Multiline);

        private const long MaxJsonDocBytes = 64L * 1024 * 1024;
        private const int MaxSuspiciousPerAgent = 60;
        private const int MaxHighPerAgent = 300;

        // ════════════════════════════════════════════════════════════════
        // Discovery: one entry per home folder that holds at least one agent
        // ════════════════════════════════════════════════════════════════
        public static List<(string FilePath, string Username)> DiscoverFiles(string collectionRoot)
        {
            var results = new List<(string, string)>();
            if (!Directory.Exists(collectionRoot)) return results;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var bases = new[]
            {
                collectionRoot,
                Path.Combine(collectionRoot, "[root]"),
                Path.Combine(collectionRoot, "root"),
            }.Where(Directory.Exists);

            void Consider(string home, string user)
            {
                if (!Directory.Exists(home) || !seen.Add(Path.GetFullPath(home))) return;
                if (Agents.Any(a => a.Paths.Any(p => PathExists(Path.Combine(home, p)))))
                    results.Add((home, user));
            }

            foreach (var b in bases)
            {
                Consider(Path.Combine(b, "root"), "root");
                foreach (var parent in new[] { "home", "Users" })
                {
                    var dir = Path.Combine(b, parent);
                    if (!Directory.Exists(dir)) continue;
                    foreach (var userDir in Directory.EnumerateDirectories(dir))
                    {
                        var user = Path.GetFileName(userDir);
                        if (user.Equals("Shared", StringComparison.OrdinalIgnoreCase)) continue;
                        Consider(userDir, user);
                    }
                }
            }

            return results.OrderBy(r => r.Item2).ThenBy(r => r.Item1).ToList();
        }

        private static bool PathExists(string p) => File.Exists(p) || Directory.Exists(p);

        // ════════════════════════════════════════════════════════════════
        // LogFileParser contract
        // ════════════════════════════════════════════════════════════════
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
            var (f, p, first, last) = ParseFile(logFilePath, Path.GetFileName(logFilePath));
            findings.AddRange(f);
            foreach (var kv in p) patternCounts[kv.Key] = patternCounts.TryGetValue(kv.Key, out var v) ? v + kv.Value : kv.Value;
            if (first < firstSeen) firstSeen = first;
            if (last > lastSeen) lastSeen = last;
        }

        public override (List<string>, Dictionary<string, int>, DateTime, DateTime) ParseFile(string filePath)
        {
            var (f, p, first, last) = ParseFile(filePath, Path.GetFileName(filePath));
            return (f, p, first, last);
        }

        // ════════════════════════════════════════════════════════════════
        // Per home folder
        // ════════════════════════════════════════════════════════════════
        public (List<string> Findings, Dictionary<string, int> Patterns, DateTime First, DateTime Last)
            ParseFile(string homeDir, string username)
        {
            var findings = new List<string>();
            var patterns = new Dictionary<string, int>();
            DateTime first = DateTime.MaxValue, last = DateTime.MinValue;

            foreach (var agent in Agents)
            {
                var files = CollectFiles(homeDir, agent);
                if (files.Count == 0) continue;

                var st = new AgentState(agent, username);
                foreach (var file in files)
                {
                    try { ProcessFile(file, homeDir, st); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
                    {
                        st.Unreadable++;
                    }
                }

                EmitAgent(st, findings, patterns);
                if (st.First < first) first = st.First;
                if (st.Last > last) last = st.Last;
            }

            return (findings, patterns, first, last);
        }

        private static List<string> CollectFiles(string home, AgentDef agent)
        {
            var list = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var rel in agent.Paths)
            {
                var p = Path.Combine(home, rel.Replace('/', Path.DirectorySeparatorChar));
                if (File.Exists(p)) { if (seen.Add(p)) list.Add(p); continue; }
                if (!Directory.Exists(p)) continue;

                bool chatOnly = rel.EndsWith("workspaceStorage", StringComparison.Ordinal);
                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(p, "*", SearchOption.AllDirectories).ToList(); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }

                foreach (var f in files)
                {
                    var norm = f.Replace('\\', '/');
                    // workspaceStorage holds every VS Code extension's state; only the chat sessions are Copilot's.
                    if (chatOnly && !norm.Contains("/chatSessions/") && !norm.Contains("/chatEditingSessions/")) continue;
                    if (seen.Add(f)) list.Add(f);
                }
            }
            // .claude.json.backup duplicates .claude.json
            return list.Where(f => !f.EndsWith(".json.backup", StringComparison.OrdinalIgnoreCase)
                                   || !list.Contains(f[..^".backup".Length], StringComparer.OrdinalIgnoreCase))
                       .OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList();
        }

        // ── State collected per agent and user ───────────────────────
        private sealed class AgentState
        {
            public AgentDef Agent;
            public string User;
            public int Transcripts, Commands, Prompts, Writes, Fetches, McpServers, Hooks, Unreadable;
            public DateTime First = DateTime.MaxValue, Last = DateTime.MinValue;
            public readonly HashSet<string> Sessions = new(StringComparer.Ordinal);
            public readonly HashSet<string> SeenCallIds = new(StringComparer.Ordinal);
            public readonly HashSet<string> SeenPrompts = new(StringComparer.Ordinal);
            public readonly List<string> CredentialFiles = new();
            public readonly Dictionary<string, Agg> Findings = new(StringComparer.Ordinal);

            public AgentState(AgentDef agent, string user) { Agent = agent; User = user; }

            public void Seen(DateTime ts)
            {
                if (ts == DateTime.MinValue) return;
                if (ts < First) First = ts;
                if (ts > Last) Last = ts;
            }
        }

        private sealed class Agg
        {
            public string Severity = "SUSPICIOUS";
            public string Text = "";
            public int Count;
            public DateTime First = DateTime.MaxValue, Last = DateTime.MinValue;
        }

        /// <summary>
        /// Config/instruction findings pass the file's mtime: it goes in the text, not the
        /// timestamp, so a setting doesn't show up on the timeline as an event at collection time.
        /// </summary>
        private void AddFinding(AgentState st, string severity, string pattern, string text, DateTime ts, DateTime? fileMtime)
        {
            if (fileMtime is { } m && m.Year > 1980)
                text += $" (file modified {m:yyyy-MM-dd HH:mm} UTC)";
            AddFinding(st, severity, pattern, text, DateTime.MinValue);
        }

        private void AddFinding(AgentState st, string severity, string pattern, string text, DateTime ts)
        {
            string key = severity + "|" + Regex.Replace(text, @"\d+", "#");
            if (!st.Findings.TryGetValue(key, out var a))
                st.Findings[key] = a = new Agg { Severity = severity, Text = text };
            a.Count++;
            if (ts != DateTime.MinValue)
            {
                if (ts < a.First) a.First = ts;
                if (ts > a.Last) a.Last = ts;
            }
            st.Findings[key] = a;
            _patternTally[pattern] = _patternTally.TryGetValue(pattern, out var n) ? n + 1 : 1;
        }

        private readonly Dictionary<string, int> _patternTally = new(StringComparer.Ordinal);

        // ════════════════════════════════════════════════════════════════
        // File dispatch
        // ════════════════════════════════════════════════════════════════
        private void ProcessFile(string file, string homeDir, AgentState st)
        {
            string name = Path.GetFileName(file);
            string rel = Path.GetRelativePath(homeDir, file).Replace('\\', '/');
            string ext = Path.GetExtension(name).ToLowerInvariant();

            if (CredentialFiles.Contains(name))
            {
                st.CredentialFiles.Add("~/" + rel);
                return;     // never read token values
            }

            if (InstructionFiles.Contains(name)
                || (ext == ".md" && Regex.IsMatch(rel, @"/(?:steering|commands|agents|skills|rules)/", RegexOptions.IgnoreCase)))
            {
                CheckInstructionFile(file, rel, st);
                return;
            }

            if (ext == ".sh")
            {
                // Claude Code's shell-snapshots are dumps of the user's own shell functions, not hooks
                if (rel.Contains("/shell-snapshots/", StringComparison.OrdinalIgnoreCase)) return;
                CheckScriptFile(file, rel, st);
                return;
            }

            if (ext == ".toml")
            {
                CheckToml(file, rel, st);
                return;
            }

            if (ext == ".jsonl" || ext == ".ndjson")
            {
                ProcessJsonl(file, rel, st);
                return;
            }

            if (ext == ".json")
            {
                var fi = new FileInfo(file);
                if (fi.Length == 0 || fi.Length > MaxJsonDocBytes) return;
                using var doc = JsonDocument.Parse(File.ReadAllBytes(file), JsonOpts);
                if (IsConfigName(name))
                    CheckJsonConfig(doc.RootElement, rel, name, fi.LastWriteTimeUtc, st);
                else
                {
                    int before = st.Commands + st.Prompts + st.Writes + st.Fetches;
                    Walk(doc.RootElement, new Ctx(), st, rel, 0, historyFile: false);
                    if (st.Commands + st.Prompts + st.Writes + st.Fetches > before) st.Transcripts++;
                }
            }
            // sqlite (state.vscdb, *.db), logs and binaries are left for manual review
        }

        private static readonly JsonDocumentOptions JsonOpts = new()
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip,
            MaxDepth = 256,
        };

        private static bool IsConfigName(string name) =>
            name.StartsWith("settings", StringComparison.OrdinalIgnoreCase)
            || name.Equals(".claude.json", StringComparison.OrdinalIgnoreCase)
            || name.Equals(".claude.json.backup", StringComparison.OrdinalIgnoreCase)
            || name.Contains("mcp", StringComparison.OrdinalIgnoreCase)
            || name.Equals("config.json", StringComparison.OrdinalIgnoreCase)
            || name.Equals("package.json", StringComparison.OrdinalIgnoreCase);

        private void ProcessJsonl(string file, string rel, AgentState st)
        {
            bool history = Path.GetFileName(file).StartsWith("history", StringComparison.OrdinalIgnoreCase);
            bool any = false;
            string? fileSession = null;     // Codex: only the first session_meta line carries the id
            foreach (var line in ReadLinesShared(file))
            {
                if (line.Length < 2 || line[0] != '{') continue;
                JsonDocument doc;
                try { doc = JsonDocument.Parse(line, JsonOpts); }
                catch (JsonException) { continue; }
                using (doc)
                {
                    var root = doc.RootElement;
                    // Claude Code logs the raw API requests too; they repeat earlier tool calls.
                    var type = Str(root, "type");
                    if (type != null && type.StartsWith("api-request", StringComparison.OrdinalIgnoreCase)) continue;
                    if (type == "session_meta" && root.TryGetProperty("payload", out var pl) && Str(pl, "id") is { } sid)
                    {
                        fileSession = sid;
                        st.Sessions.Add(sid);
                    }

                    int before = st.Commands + st.Prompts + st.Writes + st.Fetches;
                    Walk(root, new Ctx { Session = fileSession }, st, rel, 0, history);
                    if (st.Commands + st.Prompts + st.Writes + st.Fetches > before) any = true;
                }
            }
            if (any) st.Transcripts++;
        }

        private static IEnumerable<string> ReadLinesShared(string file)
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, Encoding.UTF8);
            string? line;
            while ((line = sr.ReadLine()) != null) yield return line;
        }

        // ════════════════════════════════════════════════════════════════
        // Generic transcript walker
        // ════════════════════════════════════════════════════════════════
        private struct Ctx
        {
            public DateTime Ts;
            public string? Session;
            public string? Cwd;
            public string? Mode;
        }

        private void Walk(JsonElement el, Ctx ctx, AgentState st, string rel, int depth, bool historyFile)
        {
            if (depth > 64) return;

            if (el.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in el.EnumerateArray())
                    Walk(item, ctx, st, rel, depth + 1, historyFile);
                return;
            }
            if (el.ValueKind != JsonValueKind.Object) return;

            // Context from this object (inherited by children)
            var ts = TimeOf(el);
            if (ts != DateTime.MinValue) ctx.Ts = ts;
            var sess = Str(el, "sessionId") ?? Str(el, "session_id") ?? Str(el, "conversationId");
            if (sess != null) { ctx.Session = sess; st.Sessions.Add(sess); }
            ctx.Cwd = Str(el, "cwd") ?? Str(el, "workdir") ?? ctx.Cwd;
            var mode = Str(el, "permissionMode") ?? Str(el, "approvalMode") ?? Str(el, "approval_policy");
            if (mode != null)
            {
                ctx.Mode = mode;
                if (IsBypassMode(mode))
                    AddFinding(st, "HIGH", "Agent approval bypass",
                        $"session ran with approvals disabled ({mode}) — commands ran without the user confirming them", ctx.Ts);
            }

            if (historyFile)
            {
                var text = Str(el, "display") ?? Str(el, "text") ?? Str(el, "prompt") ?? Str(el, "input");
                if (text != null) { Prompt(text, ctx, st, rel); return; }
            }

            if (TryToolCall(el, ctx, st, rel)) return;
            if (TryPrompt(el, ctx, st, rel)) return;

            foreach (var prop in el.EnumerateObject())
                if (prop.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                    Walk(prop.Value, ctx, st, rel, depth + 1, historyFile);
        }

        private static bool IsBypassMode(string mode) =>
            mode.Equals("bypassPermissions", StringComparison.OrdinalIgnoreCase)
            || mode.Equals("yolo", StringComparison.OrdinalIgnoreCase)
            || mode.Equals("never", StringComparison.OrdinalIgnoreCase)
            || mode.Equals("danger-full-access", StringComparison.OrdinalIgnoreCase);

        // ── Tool calls ────────────────────────────────────────────────
        private bool TryToolCall(JsonElement el, Ctx ctx, AgentState st, string rel)
        {
            string? type = Str(el, "type");
            string? name = null;
            foreach (var k in NameKeys)
                if ((name = Str(el, k)) != null) break;

            // Codex: {"type":"local_shell_call","action":{"type":"exec","command":[...]}}
            if (type != null && type.Equals("local_shell_call", StringComparison.OrdinalIgnoreCase))
                name ??= "local_shell";

            if (name == null) return false;
            string bare = name.Contains("__") && !name.StartsWith("developer__", StringComparison.OrdinalIgnoreCase)
                ? name : name.Split('.').Last();
            bool shell = ShellTools.Contains(bare), write = WriteTools.Contains(bare), fetch = FetchTools.Contains(bare);
            if (!shell && !write && !fetch) return false;

            // A tool *definition* (name + description/schema, no arguments) is not a call.
            JsonElement? args = ArgsOf(el, out string? rawArgs);
            if (args == null && rawArgs == null) return false;

            string? id = Str(el, "id") ?? Str(el, "call_id") ?? Str(el, "callId") ?? Str(el, "tool_use_id");
            if (id != null && !st.SeenCallIds.Add(id)) return true;

            var ts = ctx.Ts;
            st.Seen(ts);

            if (shell)
            {
                string? cmd = args is { } a ? CommandOf(a) : null;
                cmd ??= rawArgs;
                if (string.IsNullOrWhiteSpace(cmd)) return true;
                ShellCommand(cmd.Trim(), ctx, st, rel, bare);
            }
            else if (write)
            {
                var paths = new List<string>();
                if (args is { } a)
                {
                    foreach (var k in PathKeys)
                        if (Str(a, k) is { } p) { paths.Add(p); break; }
                    foreach (var k in new[] { "patch", "input", "content" })
                        if (Str(a, k) is { } patch && patch.Contains("*** ", StringComparison.Ordinal))
                            paths.AddRange(PatchFileRx.Matches(patch).Select(m => m.Groups["p"].Value.Trim()));
                }
                if (rawArgs != null)
                    paths.AddRange(PatchFileRx.Matches(rawArgs).Select(m => m.Groups["p"].Value.Trim()));
                foreach (var p in paths.Distinct())
                    FileWrite(p, ctx, st, rel, bare);
            }
            else
            {
                string? url = args is { } a ? (Str(a, "url") ?? Str(a, "uri") ?? Str(a, "href")) : null;
                if (url != null) Fetch(url, ctx, st, rel, bare);
            }
            return true;
        }

        private static JsonElement? ArgsOf(JsonElement el, out string? raw)
        {
            raw = null;
            foreach (var k in ArgKeys)
            {
                if (!el.TryGetProperty(k, out var v)) continue;
                if (v.ValueKind == JsonValueKind.Object) return v;
                if (v.ValueKind == JsonValueKind.String)
                {
                    var s = v.GetString() ?? "";
                    var t = s.TrimStart();
                    if (t.StartsWith("{"))
                    {
                        try { using var d = JsonDocument.Parse(s, JsonOpts); return d.RootElement.Clone(); }
                        catch (JsonException) { }
                    }
                    raw = s;
                    return null;
                }
            }
            // OpenCode: {"type":"tool","tool":"bash","state":{"input":{"command":"..."}}}
            if (el.TryGetProperty("state", out var state) && state.ValueKind == JsonValueKind.Object
                && state.TryGetProperty("input", out var inp) && inp.ValueKind == JsonValueKind.Object)
                return inp;
            return null;
        }

        private static string? CommandOf(JsonElement args)
        {
            foreach (var k in CommandKeys)
            {
                if (!args.TryGetProperty(k, out var v)) continue;
                if (v.ValueKind == JsonValueKind.String) return v.GetString();
                if (v.ValueKind == JsonValueKind.Array)
                {
                    var parts = v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String)
                                 .Select(x => x.GetString() ?? "").ToList();
                    // ["bash","-lc","<script>"] → the script
                    if (parts.Count >= 3 && Regex.IsMatch(parts[0], @"(?:^|/)(?:ba|z|da)?sh$")
                        && Regex.IsMatch(parts[1], @"^-[a-z]*c$"))
                        return parts[2];
                    return string.Join(" ", parts);
                }
            }
            // Codex local_shell_call: action.command
            if (args.TryGetProperty("action", out var action) && action.ValueKind == JsonValueKind.Object)
                return CommandOf(action);
            return null;
        }

        // ── Prompts ───────────────────────────────────────────────────
        private bool TryPrompt(JsonElement el, Ctx ctx, AgentState st, string rel)
        {
            string? type = Str(el, "type"), role = Str(el, "role");
            bool isUser = string.Equals(type, "user", StringComparison.OrdinalIgnoreCase)
                          || string.Equals(role, "user", StringComparison.OrdinalIgnoreCase)
                          || string.Equals(type, "user_message", StringComparison.OrdinalIgnoreCase);
            if (!isUser) return false;
            // Claude Code context-compaction summaries and meta lines are not typed by anyone
            if (el.TryGetProperty("isCompactSummary", out var cs) && cs.ValueKind == JsonValueKind.True) return true;
            if (el.TryGetProperty("isMeta", out var meta) && meta.ValueKind == JsonValueKind.True) return true;

            // Claude Code: {"type":"user","message":{"role":"user","content":"..."}}
            JsonElement src = el;
            if (el.TryGetProperty("message", out var msg) && msg.ValueKind == JsonValueKind.Object) src = msg;

            string? text = null;
            if (el.TryGetProperty("message", out var m2) && m2.ValueKind == JsonValueKind.String) text = m2.GetString();
            if (text == null && src.TryGetProperty("content", out var content))
            {
                if (content.ValueKind == JsonValueKind.String) text = content.GetString();
                else if (content.ValueKind == JsonValueKind.Array)
                {
                    var parts = new List<string>();
                    foreach (var c in content.EnumerateArray())
                    {
                        if (c.ValueKind == JsonValueKind.String) { parts.Add(c.GetString() ?? ""); continue; }
                        if (c.ValueKind != JsonValueKind.Object) continue;
                        var ct = Str(c, "type");
                        // tool results are the agent's own I/O, not the user's words
                        if (ct != null && ct.Contains("result", StringComparison.OrdinalIgnoreCase)) return false;
                        if (Str(c, "text") is { } t) parts.Add(t);
                    }
                    if (parts.Count > 0) text = string.Join("\n", parts);
                }
            }
            if (text == null && src.TryGetProperty("parts", out var gparts) && gparts.ValueKind == JsonValueKind.Array)
                text = string.Join("\n", gparts.EnumerateArray()
                    .Where(p => p.ValueKind == JsonValueKind.Object)
                    .Select(p => Str(p, "text")).Where(t => t != null));
            if (string.IsNullOrWhiteSpace(text)) return false;

            Prompt(text!, ctx, st, rel);
            return true;
        }

        private void Prompt(string text, Ctx ctx, AgentState st, string rel)
        {
            var t = text.Trim();
            // Injected context blocks (Codex environment_context, AGENTS.md, command wrappers) are not typed prompts
            if (t.StartsWith("<", StringComparison.Ordinal) || t.StartsWith("# AGENTS.md", StringComparison.Ordinal)
                || t.StartsWith("This session is being continued from a previous conversation", StringComparison.Ordinal)) return;
            // Codex logs each prompt twice (response_item + event_msg) and again in history.jsonl
            string key = (ctx.Session ?? "") + "|" + (t.Length > 200 ? t[..200] : t);
            if (!st.SeenPrompts.Add(key)) return;

            st.Prompts++;
            st.Seen(ctx.Ts);
            string one = OneLine(t, 300);

            string sev = "Info";
            if (SecretTermRx.IsMatch(t) && SearchVerbRx.IsMatch(t))
            {
                sev = BroadScopeRx.IsMatch(t) ? "HIGH" : "SUSPICIOUS";
                AddFinding(st, sev, "Prompt asks for secrets",
                    $"prompt asks the agent to look for secrets/credentials: \"{one}\"", ctx.Ts);
            }
            else if (InjectionPhraseRx.IsMatch(t))
            {
                sev = "SUSPICIOUS";
                AddFinding(st, sev, "Prompt-injection phrase", $"prompt contains an injection phrase: \"{one}\"", ctx.Ts);
            }

            Write(ctx.Ts, st, "prompt", $"[prompt] {one}", sev, ctx, rel, t);
        }

        // ── Events ────────────────────────────────────────────────────
        private void ShellCommand(string cmd, Ctx ctx, AgentState st, string rel, string tool)
        {
            st.Commands++;
            var (sev, reason) = ClassifyCommand(cmd);
            string display = OneLine(cmd, 220);

            if (sev != "Info")
            {
                string tag = ctx.Mode != null && IsBypassMode(ctx.Mode) ? $" (mode {ctx.Mode})" : "";
                AddFinding(st, sev, sev == "HIGH" ? "Agent ran critical command" : "Agent ran suspicious command",
                    $"agent ran{tag}: {display}{reason}", ctx.Ts);
            }
            if (AgentConfigInCmdRx.IsMatch(cmd.Replace('\\', '/')) && Regex.IsMatch(cmd, @">>?|\btee\b|\bsed\s+-i|\bcp\b|\bmv\b"))
                AddFinding(st, "SUSPICIOUS", "Agent modified own config",
                    $"agent command changes agent settings/instructions (prompt-injection persistence?): {display}", ctx.Ts);

            Write(ctx.Ts, st, tool, $"[cmd] {display}", sev == "Info" ? "Info" : sev, ctx, rel, cmd);
        }

        private void FileWrite(string path, Ctx ctx, AgentState st, string rel, string tool)
        {
            st.Writes++;
            var norm = path.Replace('\\', '/');
            string sev = "Info";
            if (SensitivePathRx.IsMatch(norm))
            {
                sev = "HIGH";
                AddFinding(st, sev, "Agent wrote persistence file", $"agent wrote {path} ({tool})", ctx.Ts);
            }
            else if (AgentConfigPathRx.IsMatch(norm))
            {
                sev = "SUSPICIOUS";
                AddFinding(st, sev, "Agent modified own config",
                    $"agent changed agent settings/instructions {path} ({tool}) — prompt-injection persistence?", ctx.Ts);
            }
            Write(ctx.Ts, st, tool, $"[write] {path}", sev, ctx, rel, path);
        }

        private void Fetch(string url, Ctx ctx, AgentState st, string rel, string tool)
        {
            st.Fetches++;
            string sev = "Info";
            if (RawIpUrlRx.IsMatch(url) || ShadyHostRx.IsMatch(url))
            {
                sev = "SUSPICIOUS";
                AddFinding(st, sev, "Agent fetched odd URL", $"agent fetched {OneLine(url, 200)}", ctx.Ts);
            }
            Write(ctx.Ts, st, tool, $"[fetch] {OneLine(url, 300)}", sev, ctx, rel, url);
        }

        /// <summary>
        /// HIGH only for strong signals; the bash history keyword lists (which flag
        /// /tmp, python -c, curl …) give SUSPICIOUS, since agents use those all day.
        /// </summary>
        // "<<'EOF' … EOF" — group 1: what the heredoc feeds (first word before <<), 3: body
        private static readonly Regex HeredocRx = new(
            @"(?<feed>[^\s;&|()]+)[^\n<]*<<-?\s*(?<q>['""]?)(?<tag>\w+)\k<q>[^\n]*\n(?<body>.*?)\n[ \t]*\k<tag>[ \t]*(?=\n|$)",
            RegexOptions.Compiled | RegexOptions.Singleline);

        // Search/edit tools: their quoted arguments are patterns and text, not code that runs
        private static readonly Regex TextToolRx = new(
            // quote-aware: a | or ; inside the quoted pattern doesn't end the command
            @"\b(?:grep|egrep|fgrep|rg|ag|sed|awk|git\s+(?:commit|log|grep|tag))\b(?:'[^']*'|""(?:\\.|[^""\\])*""|[^|;&\n'""])*",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex QuotedRx = new(@"'[^']*'|""(?:\\.|[^""\\])*""", RegexOptions.Compiled);

        /// <summary>
        /// Agents write scripts and commit messages through heredocs and search for attack
        /// strings with grep; that text is data, not executed. Heredoc bodies fed to a shell
        /// are kept; other bodies are classified separately and capped at SUSPICIOUS.
        /// </summary>
        internal static (string Severity, string Reason) ClassifyCommand(string cmd)
        {
            if (string.IsNullOrWhiteSpace(cmd)) return ("Info", "");

            var dataBodies = new List<string>();
            string exec = HeredocRx.Replace(cmd, m =>
            {
                var feed = Path.GetFileName(m.Groups["feed"].Value);
                if (Regex.IsMatch(feed, @"^(?:ba|z|da|k)?sh$")) return m.Value;   // runs as shell
                dataBodies.Add(m.Groups["body"].Value);
                return m.Value[..(m.Groups["body"].Index - m.Index)].TrimEnd() + " <heredoc>";
            });
            exec = TextToolRx.Replace(exec, m => QuotedRx.Replace(m.Value, "''"));

            var main = ClassifyExecuted(exec);
            if (main.Severity == "HIGH" || dataBodies.Count == 0) return main;

            foreach (var body in dataBodies)
            {
                var b = ClassifyExecuted(body);
                if (b.Severity != "Info")
                    return ("SUSPICIOUS", $"{b.Reason.TrimEnd(']')} in heredoc data]".Replace("  [ in", "  [in"));
            }
            return main;
        }

        private static (string Severity, string Reason) ClassifyExecuted(string cmd)
        {
            if (string.IsNullOrWhiteSpace(cmd)) return ("Info", "");
            if (Indicators.IsAntiForensics(cmd)) return ("HIGH", "  [anti-forensics]");
            if (Indicators.SensitiveFileWritten(cmd) is { } w) return ("HIGH", $"  [writes {w}]");
            if (Indicators.IsPipeToShell(cmd) && Regex.IsMatch(cmd, @"\b(?:curl|wget|fetch)\b|base64", RegexOptions.IgnoreCase))
                return ("HIGH", "  [download/decode piped into shell]");
            foreach (var (rx, label) in StrongCommand)
                if (rx.IsMatch(cmd)) return ("HIGH", $"  [{label}]");

            var tier = BashHistoryParser.ClassifyCommand(cmd);
            return tier == "Info" ? ("Info", "") : ("SUSPICIOUS", BashHistoryParser.ReasonFor(cmd));
        }

        // ════════════════════════════════════════════════════════════════
        // Configuration
        // ════════════════════════════════════════════════════════════════
        private void CheckJsonConfig(JsonElement root, string rel, string name, DateTime mtime, AgentState st)
        {
            if (root.ValueKind != JsonValueKind.Object) return;
            string where = "~/" + rel;

            // Hooks: {"hooks":{"PreToolUse":[{"matcher":"…","hooks":[{"type":"command","command":"…"}]}]}}
            if (root.TryGetProperty("hooks", out var hooks) && hooks.ValueKind == JsonValueKind.Object)
            {
                foreach (var ev in hooks.EnumerateObject())
                    foreach (var cmd in StringsNamed(ev.Value, "command"))
                        Hook(cmd, ev.Name, where, mtime, st);
            }
            // Claude Code status line runs a command on every refresh
            if (root.TryGetProperty("statusLine", out var sl) && sl.ValueKind == JsonValueKind.Object && Str(sl, "command") is { } slc)
                Hook(slc, "statusLine", where, mtime, st);
            if (Str(root, "apiKeyHelper") is { } akh)
                Hook(akh, "apiKeyHelper", where, mtime, st);

            // Approval bypass
            if (root.TryGetProperty("permissions", out var perms) && perms.ValueKind == JsonValueKind.Object)
            {
                if (Str(perms, "defaultMode") is { } dm && IsBypassMode(dm))
                    Setting(st, "HIGH", $"{where}: permissions.defaultMode = {dm} — every tool runs without asking", mtime);
                if (perms.TryGetProperty("allow", out var allow) && allow.ValueKind == JsonValueKind.Array)
                {
                    foreach (var a in allow.EnumerateArray())
                    {
                        var s = a.ValueKind == JsonValueKind.String ? a.GetString() ?? "" : "";
                        if (Regex.IsMatch(s, @"^(?:Bash|Shell|run_shell_command)(?:\((?:\*|\*:\*|)\))?$", RegexOptions.IgnoreCase))
                            Setting(st, "MEDIUM", $"{where}: all shell commands pre-approved ({s})", mtime);
                    }
                }
            }
            foreach (var (k, v) in FlatProps(root, 4))
            {
                bool truthy = v.ValueKind == JsonValueKind.True;
                string? sv = v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                if ((k.Equals("yolo", StringComparison.OrdinalIgnoreCase) || k.Equals("autoAccept", StringComparison.OrdinalIgnoreCase)
                     || k.Equals("dangerouslySkipPermissions", StringComparison.OrdinalIgnoreCase)) && truthy)
                    Setting(st, "MEDIUM", $"{where}: {k} = true — tool calls approved automatically", mtime);
                if ((k.Equals("approvalMode", StringComparison.OrdinalIgnoreCase) || k.Equals("defaultApprovalMode", StringComparison.OrdinalIgnoreCase))
                    && sv != null && IsBypassMode(sv))
                    Setting(st, "HIGH", $"{where}: {k} = {sv} — tool calls approved automatically", mtime);
                if (k.Equals("skipDangerousModePermissionPrompt", StringComparison.OrdinalIgnoreCase) && truthy)
                    Setting(st, "MEDIUM", $"{where}: bypass-permissions mode was accepted for this account", mtime);
                if (k.EndsWith("_BASE_URL", StringComparison.OrdinalIgnoreCase) && sv != null)
                    Setting(st, RawIpUrlRx.IsMatch(sv) || ShadyHostRx.IsMatch(sv) ? "HIGH" : "MEDIUM",
                        $"{where}: {k} = {sv} — model API traffic (prompts, code, secrets) goes to this endpoint", mtime);
            }

            // MCP servers, anywhere in the document (.claude.json keeps them per project)
            foreach (var servers in ObjectsNamed(root, n => n.Equals("mcpServers", StringComparison.OrdinalIgnoreCase)
                                                           || n.Equals("mcp_servers", StringComparison.OrdinalIgnoreCase)
                                                           || (n.Equals("servers", StringComparison.OrdinalIgnoreCase)
                                                               && name.Contains("mcp", StringComparison.OrdinalIgnoreCase)), 6))
            {
                foreach (var srv in servers.EnumerateObject())
                {
                    if (srv.Value.ValueKind != JsonValueKind.Object) continue;
                    string cmd = Str(srv.Value, "command") ?? "";
                    if (srv.Value.TryGetProperty("args", out var args) && args.ValueKind == JsonValueKind.Array)
                        cmd = (cmd + " " + string.Join(" ", args.EnumerateArray()
                            .Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()))).Trim();
                    string url = Str(srv.Value, "url") ?? Str(srv.Value, "httpUrl") ?? Str(srv.Value, "serverUrl") ?? "";
                    Mcp(srv.Name, cmd, url, where, mtime, st);
                }
            }
        }

        private void CheckToml(string file, string rel, AgentState st)
        {
            string where = "~/" + rel;
            var mtime = File.GetLastWriteTimeUtc(file);
            string section = "";
            string? approval = null, sandbox = null;
            string? mcpName = null, mcpCmd = null, mcpArgs = null, mcpUrl = null;

            void FlushMcp()
            {
                if (mcpName != null) Mcp(mcpName, $"{mcpCmd} {mcpArgs}".Trim(), mcpUrl ?? "", where, mtime, st);
                mcpName = mcpCmd = mcpArgs = mcpUrl = null;
            }

            foreach (var raw in File.ReadAllLines(file))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                var sec = Regex.Match(line, @"^\[(?<s>[^\]]+)\]$");
                if (sec.Success)
                {
                    FlushMcp();
                    section = sec.Groups["s"].Value.Trim();
                    var mm = Regex.Match(section, @"^mcp_servers\.(?<n>.+)$");
                    if (mm.Success) mcpName = mm.Groups["n"].Value.Trim('"');
                    continue;
                }
                var kv = Regex.Match(line, @"^(?<k>[A-Za-z0-9_.\-""]+)\s*=\s*(?<v>.+)$");
                if (!kv.Success) continue;
                string k = kv.Groups["k"].Value.Trim('"'), v = kv.Groups["v"].Value.Trim();
                string unq = v.Trim('"', '\'');

                if (mcpName != null)
                {
                    if (k == "command") mcpCmd = unq;
                    else if (k == "args") mcpArgs = string.Join(" ", Regex.Matches(v, @"""([^""]*)""").Select(x => x.Groups[1].Value));
                    else if (k == "url") mcpUrl = unq;
                    continue;
                }
                if (k == "approval_policy") approval = unq;
                if (k == "sandbox_mode") sandbox = unq;
                if (k == "notify")
                    Hook(string.Join(" ", Regex.Matches(v, @"""([^""]*)""").Select(x => x.Groups[1].Value)), "notify", where, mtime, st);
                if (k.EndsWith("base_url", StringComparison.OrdinalIgnoreCase))
                    Setting(st, RawIpUrlRx.IsMatch(unq) || ShadyHostRx.IsMatch(unq) ? "HIGH" : "MEDIUM",
                        $"{where}: [{section}] {k} = {unq} — model API traffic goes to this endpoint", mtime);
            }
            FlushMcp();

            bool noApproval = approval != null && approval.Equals("never", StringComparison.OrdinalIgnoreCase);
            bool noSandbox = sandbox != null && sandbox.Equals("danger-full-access", StringComparison.OrdinalIgnoreCase);
            if (noApproval && noSandbox)
                Setting(st, "HIGH", $"{where}: approval_policy = never and sandbox_mode = danger-full-access — commands run unasked and unsandboxed", mtime);
            else if (noApproval)
                Setting(st, "MEDIUM", $"{where}: approval_policy = never — commands run without asking", mtime);
            else if (noSandbox)
                Setting(st, "MEDIUM", $"{where}: sandbox_mode = danger-full-access — no sandbox", mtime);
        }

        private void Hook(string cmd, string evt, string where, DateTime mtime, AgentState st)
        {
            if (string.IsNullOrWhiteSpace(cmd)) return;
            st.Hooks++;
            var (sev, reason) = ClassifyCommand(cmd);
            bool network = Regex.IsMatch(cmd, @"\b(?:curl|wget|nc|ncat|socat)\b|https?://|base64", RegexOptions.IgnoreCase);
            string s = sev == "HIGH" || network || RawIpUrlRx.IsMatch(cmd) ? "HIGH" : "SUSPICIOUS";
            AddFinding(st, s, "Agent hook",
                $"{where}: {evt} runs a command automatically: {OneLine(cmd, 220)}{reason}", DateTime.MinValue, mtime);
            WriteConfig(mtime, st, $"[hook:{evt}] {OneLine(cmd, 300)}", s == "HIGH" ? "HIGH" : "SUSPICIOUS", where, cmd);
        }

        private void Mcp(string name, string cmd, string url, string where, DateTime mtime, AgentState st)
        {
            st.McpServers++;
            string target = string.IsNullOrEmpty(url) ? cmd : (cmd.Length > 0 ? $"{cmd} {url}" : url);
            string sev = "LOW";
            string why = "";
            var (csev, creason) = ClassifyCommand(cmd);
            if (csev == "HIGH" || Regex.IsMatch(cmd, @"(?:^|\s|/)(?:tmp|dev/shm|var/tmp)/", RegexOptions.IgnoreCase))
            { sev = "HIGH"; why = creason.Length > 0 ? creason : "  [runs from a temp folder]"; }
            else if (RawIpUrlRx.IsMatch(url) || ShadyHostRx.IsMatch(url) || RawIpUrlRx.IsMatch(cmd))
            { sev = "SUSPICIOUS"; why = "  [raw IP / tunnel endpoint]"; }

            AddFinding(st, sev, "MCP server", $"{where}: MCP server '{name}': {OneLine(target, 220)}{why}", DateTime.MinValue, mtime);
            WriteConfig(mtime, st, $"[mcp:{name}] {OneLine(target, 300)}", sev == "LOW" ? "Info" : sev, where, target);
        }

        private void Setting(AgentState st, string sev, string text, DateTime mtime)
        {
            AddFinding(st, sev, "Agent approval bypass", text, DateTime.MinValue, mtime);
            WriteConfig(mtime, st, $"[setting] {text}", sev, string.Empty, text);
        }

        private void CheckInstructionFile(string file, string rel, AgentState st)
        {
            var mtime = File.GetLastWriteTimeUtc(file);
            int n = 0;
            foreach (var raw in File.ReadLines(file))
            {
                n++;
                var line = raw.Trim();
                if (line.Length == 0) continue;
                if (InjectionPhraseRx.IsMatch(line))
                    AddFinding(st, "HIGH", "Instruction file injection",
                        $"~/{rel}:{n} prompt-injection phrase in agent instructions: \"{OneLine(line, 200)}\"", DateTime.MinValue, mtime);
                var (sev, reason) = ClassifyCommand(line);
                if (sev == "HIGH")
                    AddFinding(st, "HIGH", "Instruction file command",
                        $"~/{rel}:{n} agent instructions contain a dangerous command: {OneLine(line, 200)}{reason}", DateTime.MinValue, mtime);
                else if (RawIpUrlRx.IsMatch(line) || ShadyHostRx.IsMatch(line))
                    AddFinding(st, "SUSPICIOUS", "Instruction file URL",
                        $"~/{rel}:{n} agent instructions point to {OneLine(line, 200)}", DateTime.MinValue, mtime);
            }
        }

        private void CheckScriptFile(string file, string rel, AgentState st)
        {
            var mtime = File.GetLastWriteTimeUtc(file);
            int n = 0;
            foreach (var raw in File.ReadLines(file))
            {
                n++;
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                var (sev, reason) = ClassifyCommand(line);
                if (sev == "HIGH")
                    AddFinding(st, "HIGH", "Agent script command",
                        $"~/{rel}:{n} hook/helper script: {OneLine(line, 200)}{reason}", DateTime.MinValue, mtime);
            }
        }

        // ════════════════════════════════════════════════════════════════
        // Output
        // ════════════════════════════════════════════════════════════════
        private void EmitAgent(AgentState st, List<string> findings, Dictionary<string, int> patterns)
        {
            string who = $"{st.Agent.Name} user={st.User}";

            if (st.CredentialFiles.Count > 0)
                AddFinding(st, "MEDIUM", "Agent credential file",
                    $"credential/token file(s) present: {string.Join(", ", st.CredentialFiles.Take(6))} — revoke them if the host is compromised",
                    DateTime.MinValue);

            string Range(Agg a) => a.First == DateTime.MaxValue ? "no-timestamp"
                : a.Count == 1 || a.First == a.Last ? $"{a.First:yyyy-MM-dd HH:mm:ss} UTC"
                : $"{a.First:yyyy-MM-dd HH:mm:ss} → {a.Last:yyyy-MM-dd HH:mm:ss} UTC";

            int rank(string s) => s switch { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "SUSPICIOUS" => 3, _ => 4 };
            int high = 0, susp = 0;
            foreach (var a in st.Findings.Values.OrderBy(x => rank(x.Severity)).ThenBy(x => x.First))
            {
                if (a.Severity is "HIGH" or "CRITICAL" && ++high > MaxHighPerAgent) continue;
                if (a.Severity is "SUSPICIOUS" && ++susp > MaxSuspiciousPerAgent) continue;
                string count = a.Count > 1 ? $" (x{a.Count})" : "";
                findings.Add($"[{LogKey}] [{a.Severity}] [{Range(a)}{count}] {who}: {a.Text}");
            }
            if (susp > MaxSuspiciousPerAgent)
                findings.Add($"[{LogKey}] [LOW] {who}: {susp - MaxSuspiciousPerAgent} more SUSPICIOUS item(s) — see Normalized_{LogKey}.csv");

            string span = st.First == DateTime.MaxValue ? "" : $" {st.First:yyyy-MM-dd HH:mm:ss} → {st.Last:yyyy-MM-dd HH:mm:ss} UTC,";
            findings.Add($"[{LogKey}] [LOW] {who}: installed/used —{span} {st.Transcripts} transcript file(s), " +
                         $"{st.Sessions.Count} session(s), {st.Commands} shell command(s), {st.Prompts} prompt(s), " +
                         $"{st.Writes} file write(s), {st.Fetches} fetch(es), {st.McpServers} MCP server(s), {st.Hooks} hook(s)" +
                         (st.Unreadable > 0 ? $", {st.Unreadable} unreadable file(s)" : ""));

            Count(patterns, $"{st.Agent.Name} present", 1);
            Count(patterns, "Agent shell command", st.Commands);
            Count(patterns, "Agent prompt", st.Prompts);
            Count(patterns, "Agent file write", st.Writes);
            foreach (var kv in _patternTally) Count(patterns, kv.Key, kv.Value);
            _patternTally.Clear();
        }

        private static void Count(Dictionary<string, int> p, string k, int n)
        {
            if (n <= 0) return;
            p[k] = p.TryGetValue(k, out var v) ? v + n : n;
        }

        private void Write(DateTime ts, AgentState st, string tool, string message, string severity, Ctx ctx, string rel, string raw)
        {
            if (_normalizedWriter == null) return;
            string context = $"agent={st.Agent.Key} tool={tool}" +
                             (ctx.Session != null ? $" session={ctx.Session}" : "") +
                             (ctx.Cwd != null ? $" cwd={ctx.Cwd}" : "") + $" file=~/{rel} | ";
            _normalizedWriter.Write(NormalizedRecord.From(
                ts, _hostname, LogKey, st.Agent.Key, st.User, string.Empty,
                message, severity, context + (raw.Length > 4000 ? raw[..4000] + "…" : raw)));
        }

        private void WriteConfig(DateTime mtime, AgentState st, string message, string severity, string where, string raw)
        {
            _normalizedWriter?.Write(NormalizedRecord.From(
                mtime, _hostname, LogKey, st.Agent.Key, st.User, string.Empty,
                message + " (file mtime)", severity, $"agent={st.Agent.Key} file={where} | {raw}"));
        }

        // ════════════════════════════════════════════════════════════════
        // JSON helpers
        // ════════════════════════════════════════════════════════════════
        private static string? Str(JsonElement el, string name) =>
            el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString() : null;

        private static DateTime TimeOf(JsonElement el)
        {
            if (el.ValueKind != JsonValueKind.Object) return DateTime.MinValue;
            foreach (var k in TimeKeys)
            {
                if (!el.TryGetProperty(k, out var v)) continue;
                var t = ParseTime(v);
                if (t != DateTime.MinValue) return t;
            }
            return DateTime.MinValue;
        }

        internal static DateTime ParseTime(JsonElement v)
        {
            DateTime t = DateTime.MinValue;
            if (v.ValueKind == JsonValueKind.String)
            {
                var s = v.GetString();
                if (DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto))
                    t = dto.UtcDateTime;
                else if (long.TryParse(s, out var n)) t = FromEpoch(n);
            }
            else if (v.ValueKind == JsonValueKind.Number)
            {
                if (v.TryGetInt64(out var n)) t = FromEpoch(n);
                else if (v.TryGetDouble(out var d)) t = FromEpoch((long)(d < 1e11 ? d * 1000 : d), ms: true);
            }
            return t.Year is >= 2015 and <= 2100 ? DateTime.SpecifyKind(t, DateTimeKind.Utc) : DateTime.MinValue;
        }

        private static DateTime FromEpoch(long n, bool ms = false)
        {
            try
            {
                if (ms || n > 100_000_000_000L) return DateTimeOffset.FromUnixTimeMilliseconds(n).UtcDateTime;
                if (n > 1_000_000_000L) return DateTimeOffset.FromUnixTimeSeconds(n).UtcDateTime;
            }
            catch (ArgumentOutOfRangeException) { }
            return DateTime.MinValue;
        }

        private static IEnumerable<string> StringsNamed(JsonElement el, string name, int depth = 0)
        {
            if (depth > 12) yield break;
            if (el.ValueKind == JsonValueKind.Object)
            {
                foreach (var p in el.EnumerateObject())
                {
                    if (p.NameEquals(name) && p.Value.ValueKind == JsonValueKind.String)
                        yield return p.Value.GetString() ?? "";
                    else
                        foreach (var s in StringsNamed(p.Value, name, depth + 1)) yield return s;
                }
            }
            else if (el.ValueKind == JsonValueKind.Array)
                foreach (var item in el.EnumerateArray())
                    foreach (var s in StringsNamed(item, name, depth + 1)) yield return s;
        }

        private static IEnumerable<JsonElement> ObjectsNamed(JsonElement el, Func<string, bool> match, int maxDepth, int depth = 0)
        {
            if (depth > maxDepth || el.ValueKind != JsonValueKind.Object) yield break;
            foreach (var p in el.EnumerateObject())
            {
                if (p.Value.ValueKind != JsonValueKind.Object) continue;
                if (match(p.Name)) yield return p.Value;
                else foreach (var o in ObjectsNamed(p.Value, match, maxDepth, depth + 1)) yield return o;
            }
        }

        private static IEnumerable<(string Key, JsonElement Value)> FlatProps(JsonElement el, int maxDepth, int depth = 0)
        {
            if (depth > maxDepth || el.ValueKind != JsonValueKind.Object) yield break;
            foreach (var p in el.EnumerateObject())
            {
                if (p.Value.ValueKind == JsonValueKind.Object)
                {
                    // MCP server env blocks are the server's own; skip them here
                    if (p.NameEquals("mcpServers") || p.NameEquals("projects")) continue;
                    foreach (var x in FlatProps(p.Value, maxDepth, depth + 1)) yield return x;
                }
                else yield return (p.Name, p.Value);
            }
        }

        private static string OneLine(string s, int max)
        {
            var one = Regex.Replace(s ?? "", @"\s+", " ").Trim();
            return one.Length > max ? one[..(max - 3)] + "..." : one;
        }
    }
}

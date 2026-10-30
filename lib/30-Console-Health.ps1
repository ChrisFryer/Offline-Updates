# =====================================================================
#  30-Console-Health.ps1  -  THE HEALTH CONSOLE (tab 2)
# ---------------------------------------------------------------------
#  Three pages inside the tab:
#    HEALTH CHECKS  - read-only checks per server from the Health, Status,
#                     Inventory and Gpo collectors:
#                     automatic services not running, scheduled tasks with a
#                     failing last result, failed logons and lockouts, dormant
#                     software, disk space, uptime and pending reboot, event
#                     log errors, time synchronisation, certificate expiry,
#                     memory and processor load, Group Policy (errors, refresh,
#                     trust); under the grid, behind a divider, the SUMMARY:
#                     processor, memory and disk dials and what needs attention.
#    GROUP POLICY   - the GPOs applied or filtered on the servers shown, and
#                     each server's last policy run (13-GroupPolicy.ps1).
#    SOE STANDARDS  - a standard is a JSON file in soe\ listing the agents,
#                     software, forbidden software, features, services and
#                     settings every server must have.  The sysadmin composes
#                     it from scanned servers (the picker), from the fleet, or
#                     by hand, and compares servers against it.
#  Three collectors run ON the servers (read-only): Health, Agents, Settings.
#  Settings is shared with the Security console.
# =====================================================================

# ---------------------------------------------------------------------
#  REVIEW RECORD  -  30-Console-Health.ps1  (new in version 2)
# ---------------------------------------------------------------------
#  HUMAN REVIEW  (fill in by hand and keep it in the file)
#  Reviewer   : _______cf_______________________   Date : __30-10-2026____________
#  Verdict    : [x] Approved   [ ] Approved with comments   [ ] Changes required
#  Comments   :
#    -
# =====================================================================

function Get-BenignData {
    # Import-ToolData parses once and re-reads only when the file changes, so this is cheap to call often.
    $d = Import-ToolData -Name 'benign-services.psd1'
    if ($d) { return $d }
    return @{ Services = @(); TaskOkCodes = @(0); DormantIgnore = @() }
}

function Test-BenignService {
    # Is this stopped automatic service on the benign list?  Entries may hold wildcards (GoogleUpdaterService*, CDPUserSvc_*).
    param([string]$Name, [object[]]$List)
    foreach ($b in @($List)) { if ($Name -like [string]$b) { return $true } }
    return $false
}

function Get-SoeAgentRules {
    $d = Import-ToolData -Name 'soe-agents.psd1'
    if ($d) { return $d }
    return @{ AsOf = 'n/a'; Agents = @() }
}

function Get-SoeConfigPoints {
    # data\soe-config-points.psd1: the registry values and config-file lines an SOE deployment customises.
    $d = Import-ToolData -Name 'soe-config-points.psd1'
    if ($d) { return $d }
    return @{ AsOf = 'n/a'; Points = @() }
}

# ---------------------------------------------------------------------
#  PROBE collector - RUNS ON THE SERVER.  Reads registry values and lines of
#  configuration files, nothing else; a hand-edited standard can only ask for
#  reads.  One probe per line "type|path|key":
#     registry|HKLM:\SOFTWARE\...|ValueName     (ValueName * = every value as name=data)
#     file|C:\path\file.conf|Key                 (first "Key = value" line outside # ; comments)
#     file|C:\path\file.xml|re:<regex>           (first capture group of the first match)
#  Returns "type|path|key|value" lines.  Not readable: NotConfigured / file missing /
#  key missing / ERROR: <why> - the compare turns those into verdicts, never into a pass.
# ---------------------------------------------------------------------
$script:RemoteProbeScript = {
    param([string[]]$Probes)
    $ErrorActionPreference = 'Continue'
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($probe in @($Probes)) {
        $p = [string]$probe -split '\|', 3
        if ($p.Count -lt 3) { continue }
        $type = $p[0]; $path = $p[1]; $key = $p[2]; $value = ''
        try {
            if ($type -eq 'registry') {
                if (-not (Test-Path -LiteralPath $path)) { $value = 'NotConfigured (key absent)' }
                else {
                    $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
                    if ($key -eq '*') {
                        $names = @($item.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { '{0}={1}' -f $_.Name, ([string]$_.Value -replace '[\r\n|]', ' ') })
                        if ($names.Count -gt 0) { $value = $names -join '; ' } else { $value = '(no values)' }
                    } elseif ($null -eq $item.PSObject.Properties[$key]) { $value = 'NotConfigured' }
                    else { $v = $item.$key; if ($v -is [array]) { $value = ($v -join '; ') } else { $value = [string]$v } }
                }
            } elseif ($type -eq 'file') {
                if (-not (Test-Path -LiteralPath $path)) { $value = 'file missing' }
                elseif ((Get-Item -LiteralPath $path).Length -gt 2MB) { $value = 'ERROR: file larger than 2 MB, not read' }
                else {
                    $text = [System.IO.File]::ReadAllText($path)
                    if ($key -like 're:*') {
                        $m = [regex]::Match($text, $key.Substring(3), 'IgnoreCase, Multiline', [TimeSpan]::FromSeconds(2))   # a runaway pattern stops after 2 s (reported as ERROR:)
                        if (-not $m.Success) { $value = 'key missing' }
                        elseif ($m.Groups.Count -gt 1) { $value = $m.Groups[1].Value.Trim() }
                        else { $value = $m.Value.Trim() }
                    } else {
                        $value = 'key missing'
                        foreach ($line in ($text -split "`r?`n")) {
                            if ($line -match '^\s*[#;]') { continue }
                            if ($line -match ('^\s*' + [regex]::Escape($key) + '\s*[=:]\s*(.*)$')) { $value = $Matches[1].Trim(); break }
                        }
                    }
                }
            } else { $value = "ERROR: unknown probe type '$type'" }
        } catch { $value = 'ERROR: ' + $_.Exception.Message }
        $out.Add(('{0}|{1}|{2}|{3}' -f $type, $path, $key, ($value -replace '[\r\n|]', ' ')))
    }
    [pscustomobject]@{ Computer = $env:COMPUTERNAME; Lines = $out.ToArray(); Count = $out.Count }
}

function Get-SoeProbeList {
    # Every point worth reading on a server: the catalogue plus the registry / file items of every standard.
    $list = @()
    foreach ($p in @((Get-SoeConfigPoints).Points)) { $list += ('{0}|{1}|{2}' -f $p.Type, $p.Path, $p.Key) }
    foreach ($name in (Get-SoeStandardNames)) {
        $std = Read-SoeStandard -Name $name
        if ($std) { foreach ($it in @($std.items)) { if ([string]$it.type -in 'registry', 'file' -and $it.path) { $list += ('{0}|{1}|{2}' -f $it.type, $it.path, $it.key) } } }
    }
    return @(Get-UniqueNames $list)
}

function Get-ServerProbes {
    param([Parameter(Mandatory = $true)][string[]]$ComputerName, [string[]]$Probes)
    if (-not $Probes -or @($Probes).Count -eq 0) { return @() }
    $summary = { param($r) ('{0} configuration points read' -f $r.Count) }
    return (Invoke-Collector -Name 'Probes' -ScriptBlock $script:RemoteProbeScript -ComputerName $ComputerName -ArgumentList @(, [string[]]$Probes) -Summary $summary)
}

function Get-ProbeValue {
    # What one probe returned for a server, or $null when the server has not been probed for it.
    param([string]$Server, [string]$Type, [string]$Path, [string]$Key)
    $r = Get-CollectorResult -Name 'Probes' -Server $Server
    if (-not $r -or -not $r.Reachable) { return $null }
    $prefix = '{0}|{1}|{2}|' -f $Type, $Path, $Key
    foreach ($line in @($r.Lines)) { if (([string]$line).StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return ([string]$line).Substring($prefix.Length) } }
    return $null
}

function Get-SoeStandardNameForServer {
    # The standard a server is held to: "; soe: <name>" on its own group-file line, else the group's "# soe:" line
    # (both via Get-ServerAttribute), else the default standard if that file exists.
    param([string]$Server)
    $own = Get-ServerAttribute -Name $Server -Key 'soe'
    if ($own) { return $own }
    $default = [string]$script:Config.DefaultSoeStandard
    if ($default -and (Test-Path -LiteralPath (Get-SoeStandardPath -Name $default))) { return $default }
    return ''
}

function Get-SoeComplianceRows {
    # The SOE comparison of every server that has a standard and has been checked - for the details page and the report.
    param([string[]]$Servers)
    $rows = @()
    $cache = @{}
    foreach ($s in $Servers) {
        $name = Get-SoeStandardNameForServer -Server $s
        if (-not $name) { continue }
        if (-not (Get-CollectorResult -Name 'Inventory' -Server $s)) { continue }
        if (-not $cache.ContainsKey($name)) { $cache[$name] = Read-SoeStandard -Name $name }
        if ($cache[$name]) { $rows += @(Compare-SoeStandard -Standard $cache[$name] -Server $s) }
    }
    return $rows
}

# ---------------------------------------------------------------------
#  HEALTH collector - RUNS ON THE SERVER.  Read-only.  Every part is wrapped
#  so one failing query (for example no right to read the Security log)
#  shows up in Errors instead of killing the whole result.
# ---------------------------------------------------------------------
$script:RemoteHealthScript = {
    param([int]$WindowHours, [int]$MaxEvents, [int]$TaskDays, [int]$CertDays, [int[]]$TaskOkCodes, [int]$EventHours = 0, [int]$CpuSeconds = 3)
    $ErrorActionPreference = 'Continue'
    $errors = @()
    $since = (Get-Date).AddHours(-$WindowHours)                         # failed logons and lockouts (LogonFailWindowHours)
    if ($EventHours -le 0) { $EventHours = $WindowHours }
    $sinceEvents = (Get-Date).AddHours(-$EventHours)                    # System + Application errors (EventWindowHours)

    # Automatic services that are not running (the benign list is applied on the operator PC)
    $stopped = @()
    try {
        $boot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        $justBooted = ((Get-Date) - $boot).TotalMinutes -lt 10
        # -ErrorAction Stop: a failed query must reach the catch and be recorded, not pass as "no stopped service" (R6-D05)
        foreach ($s in (Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' })) {
            if ($justBooted -and $s.DelayedAutoStart) { continue }
            # does the service's program still exist?  An uninstaller that does not remove its own service leaves one
            # that can never start (field case 2026-10-22).  Fields 6-7: 1 = the program is missing, and its path.
            $prog = [string]$s.PathName
            if ($prog -match '^\s*"([^"]+)"') { $prog = $Matches[1] } elseif ($prog -match '^\s*(.+?\.exe)(\s|$)') { $prog = $Matches[1] } else { $prog = ($prog.Trim() -split '\s+')[0] }
            $prog = [Environment]::ExpandEnvironmentVariables($prog) -replace '^\\\?\?\\', ''
            if ($prog -match '^\\SystemRoot\\') { $prog = $env:SystemRoot + $prog.Substring(11) }
            $gone = 0; if ($prog -and -not (Test-Path -LiteralPath $prog)) { $gone = 1 }
            $stopped += '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $s.Name, ($s.DisplayName -replace '\|', '/'), $s.StartMode, $s.State, $s.StartName, $gone, ($prog -replace '\|', '/')
        }
    } catch { $errors += 'services: ' + $_.Exception.Message }

    # Scheduled tasks whose last result is a failure, run within the window
    $tasks = @()
    try {
        $cut = (Get-Date).AddDays(-$TaskDays)
        # the "fine" codes as unsigned 32-bit numbers: 0x800710E0 written in the data file arrives as a negative Int32 and
        # never matched the server's positive code (R6-D17)
        $okCodes = @(@($TaskOkCodes) | ForEach-Object { $n = [int64]$_; if ($n -lt 0) { $n += 4294967296L }; $n })
        foreach ($t in (Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' })) {
            $i = $null
            try { $i = $t | Get-ScheduledTaskInfo } catch { continue }
            if (-not $i -or -not $i.LastRunTime -or $i.LastRunTime -lt $cut) { continue }
            $code = [int64]$i.LastTaskResult          # a uint32 such as 0x80041324 does not fit an Int32
            if ($code -lt 0) { $code += 4294967296L }
            if ($okCodes -contains $code) { continue }
            $tasks += '{0}|{1}|{2}|0x{3:X}|{4}' -f $t.TaskPath, $t.TaskName, $t.State, $code, $i.LastRunTime.ToString('yyyy-MM-dd HH:mm')
        }
    } catch { $errors += 'tasks: ' + $_.Exception.Message }

    # Failed logons (4625) grouped by account, source and logon type; lockouts (4740)
    $logons = @(); $logonTotal = 0; $lockouts = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction Stop)
        $logonTotal = $events.Count
        $groups = @{}
        foreach ($e in $events) {
            $x = [xml]$e.ToXml()
            $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            $key = '{0}\{1}|{2}|{3}' -f $d['TargetDomainName'], $d['TargetUserName'], $d['IpAddress'], $d['LogonType']
            if (-not $groups.ContainsKey($key)) { $groups[$key] = @{ Count = 0; Last = $e.TimeCreated } }
            $groups[$key].Count++
            if ($e.TimeCreated -gt $groups[$key].Last) { $groups[$key].Last = $e.TimeCreated }
        }
        foreach ($k in ($groups.Keys | Sort-Object { $groups[$_].Count } -Descending | Select-Object -First 40)) {
            $logons += '{0}|{1}|{2}' -f $groups[$k].Count, $k, $groups[$k].Last.ToString('yyyy-MM-dd HH:mm')
        }
    } catch {
        # the "no events" error is matched by its id, not its (localised) text
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $errors += 'failed logons: ' + $_.Exception.Message }
    }
    try {
        foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4740; StartTime = $since } -MaxEvents 200 -ErrorAction Stop)) {
            $x = [xml]$e.ToXml(); $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            $lockouts += '{0}|{1}|{2}' -f $d['TargetUserName'], $d['TargetDomainName'], $e.TimeCreated.ToString('yyyy-MM-dd HH:mm')
        }
    } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $errors += 'lockouts: ' + $_.Exception.Message } }

    # Disks
    $disks = @()
    try {
        # the figures are written the invariant way: the runspace runs in the OPERATOR's culture, and "12,5" read back as a
        # number would be 125 on a comma-decimal operator PC (the readers parse them invariantly too: ConvertTo-HealthNumber)
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        foreach ($d in (Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) {
            $pct = 0.0; if ($d.Size -gt 0) { $pct = [math]::Round(100 * $d.FreeSpace / $d.Size, 1) }
            $disks += '{0}|{1}|{2}|{3}' -f $d.DeviceID, ([math]::Round($d.Size / 1GB, 1)).ToString('0.0', $inv), ([math]::Round($d.FreeSpace / 1GB, 1)).ToString('0.0', $inv), ([double]$pct).ToString('0.0', $inv)
        }
    } catch { $errors += 'disks: ' + $_.Exception.Message }

    # Error and critical events in System + Application
    $errorCount = 0; $errorTop = @()
    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = @('System', 'Application'); Level = @(1, 2); StartTime = $sinceEvents } -MaxEvents $MaxEvents -ErrorAction Stop)
        $errorCount = $ev.Count
        $errorTop = @($ev | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { '{0}|{1}' -f $_.Count, $_.Name })
    } catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $errors += 'event errors: ' + $_.Exception.Message } }

    # Time synchronisation.  /verbose adds "Phase Offset".  w32tm is a child process: it prints in the locale of the
    # remoting USER (not the runspace's, which is the operator's), so a dated line is read with that user's culture
    # first; "Time since Last Good Sync Time: 3594.12s" (newer builds) is a plain number in every culture.
    $timeSource = ''; $timeOffset = ''; $lastSyncHours = ''
    try {
        $status = (& w32tm.exe /query /status /verbose 2>&1) | Out-String
        if ($status -match 'Source:\s*(.+)') { $timeSource = $Matches[1].Trim() }
        if ($status -match 'Phase Offset:\s*([-\d\.,]+)s') { $timeOffset = $Matches[1] -replace ',', '.' }   # a comma-decimal locale prints 0,012s
        if ($status -match 'Time since Last Good Sync Time:\s*([\d\.,]+)s') { $lastSyncHours = [math]::Round([double]::Parse(($Matches[1] -replace ',', '.'), [System.Globalization.CultureInfo]::InvariantCulture) / 3600, 1) }
        elseif ($status -match 'Last Successful Sync Time:\s*(.+)') {
            $txt = $Matches[1].Trim()
            # the cultures w32tm may have printed in, most likely first: the remoting user's locale, the default user's, the
            # Windows language, the runspace's.  The first that gives a date not in the future wins; none = not readable.
            $cultures = New-Object System.Collections.Generic.List[object]
            foreach ($loc in @((Get-ItemProperty -Path 'HKCU:\Control Panel\International' -Name LocaleName -ErrorAction SilentlyContinue).LocaleName, (Get-ItemProperty -Path 'Registry::HKEY_USERS\.DEFAULT\Control Panel\International' -Name LocaleName -ErrorAction SilentlyContinue).LocaleName)) {
                if ($loc) { try { $cultures.Add([System.Globalization.CultureInfo]::GetCultureInfo([string]$loc)) } catch { } }
            }
            $cultures.Add([System.Globalization.CultureInfo]::InstalledUICulture); $cultures.Add([System.Globalization.CultureInfo]::CurrentCulture)
            foreach ($cu in $cultures) {
                $dt = [datetime]::MinValue
                if (-not [datetime]::TryParse($txt, $cu, [System.Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$dt)) { continue }
                $age = ((Get-Date) - $dt).TotalHours
                if ($age -lt -0.1) { continue }   # a date read the wrong way round, or a clock that jumped
                $lastSyncHours = [math]::Round($age, 1); break
            }
            if ($lastSyncHours -eq '') { $errors += "w32tm: the last sync time '$txt' could not be read as a date in this server's locales" }
        }
        if (-not $timeSource) {
            # no "Source:" line: the Windows Time service not running (w32tm then prints only its error), a w32tm in another
            # language, or another error - a stopped service is said as such, not blamed on the language (R6-D18)
            $w32 = Get-Service -Name W32Time -ErrorAction SilentlyContinue
            if ($w32 -and [string]$w32.Status -ne 'Running') { $errors += ('w32tm: the Windows Time service is {0}' -f $w32.Status) }
            else {
                $wp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction SilentlyContinue
                if ($wp -and $wp.Type) { $timeSource = '(registry) Type={0} NtpServer={1}' -f $wp.Type, $wp.NtpServer }
                $errors += 'w32tm: no "Source:" line in its output - ' + (($status -split "`n")[0]).Trim()
            }
        }
    } catch { $errors += 'w32tm: ' + $_.Exception.Message }

    # Certificates in the machine store expiring soon
    $certs = @()
    try {
        $limit = (Get-Date).AddDays($CertDays)
        foreach ($c in (Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.NotAfter -lt $limit })) {
            # Floor, not [int]: -0.4 days rounded to 0 and a certificate expired this morning read as "expires today" (R6-D16)
            $certs += '{0}|{1}|{2}|{3}' -f ($c.Subject -replace '\|', '/'), $c.NotAfter.ToString('yyyy-MM-dd'), $c.Thumbprint, [int][math]::Floor(($c.NotAfter - (Get-Date)).TotalDays)
        }
    } catch { $errors += 'certificates: ' + $_.Exception.Message }

    # Memory, and the three processes holding the most of it ("name|MB")
    $memFreePct = ''; $memFreeMB = ''; $memTotalGB = ''; $memTop = @()
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $memFreeMB = [int]($os.FreePhysicalMemory / 1KB)
        $memTotalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
        if ($os.TotalVisibleMemorySize -gt 0) { $memFreePct = [math]::Round(100 * $os.FreePhysicalMemory / $os.TotalVisibleMemorySize, 1) }
        $memTop = @(Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 3 | ForEach-Object { '{0}|{1}' -f $_.ProcessName, [int]($_.WorkingSet64 / 1MB) })
    } catch { $errors += 'memory: ' + $_.Exception.Message }

    # Processor load: Win32_Processor.LoadPercentage (each processor's load over the last second) read once a second for
    # $CpuSeconds seconds and averaged - a short snapshot, not a trend.  Over the same seconds, the three processes that used
    # the most processor time ("name|percent of the whole machine"; a process the account may not inspect is skipped).
    $cpuPct = ''; $cpuCount = ''; $cpuTop = @()
    try {
        $cpuCount = [int](Get-CimInstance -ClassName Win32_ComputerSystem).NumberOfLogicalProcessors
        $before = @{}
        foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { try { if ($null -ne $p.TotalProcessorTime) { $before[$p.Id] = $p.TotalProcessorTime.TotalSeconds } } catch { } }
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $loads = @()
        for ($n = 0; $n -lt [math]::Max(1, $CpuSeconds); $n++) {
            if ($n -gt 0) { Start-Sleep -Seconds 1 }
            $loads += @(Get-CimInstance -ClassName Win32_Processor | ForEach-Object { $_.LoadPercentage } | Where-Object { $null -ne $_ })
        }
        if ($loads.Count -gt 0) { $cpuPct = [math]::Round(($loads | Measure-Object -Average).Average, 1) } else { $errors += 'processor: no load figure (Win32_Processor.LoadPercentage is empty)' }
        $secs = $watch.Elapsed.TotalSeconds
        if ($secs -gt 0.5 -and $cpuCount -gt 0) {
            $use = @()
            foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
                if (-not $before.ContainsKey($p.Id)) { continue }
                try { $delta = $p.TotalProcessorTime.TotalSeconds - $before[$p.Id] } catch { continue }
                if ($delta -gt 0) { $use += [pscustomobject]@{ Name = $p.ProcessName; Pct = 100 * $delta / ($secs * $cpuCount) } }
            }
            $cpuTop = @($use | Sort-Object Pct -Descending | Select-Object -First 3 | ForEach-Object { '{0}|{1}' -f $_.Name, $_.Pct.ToString('0.0', [System.Globalization.CultureInfo]::InvariantCulture) })
        }
    } catch { $errors += 'processor: ' + $_.Exception.Message }

    [pscustomobject]@{
        Computer = $env:COMPUTERNAME; WindowHours = $WindowHours; EventWindowHours = $EventHours; TaskDays = $TaskDays; CertDays = $CertDays   # the windows this read used: the verdict texts quote these, not the setting of the moment
        StoppedAuto = $stopped; FailingTasks = $tasks; LogonFailures = $logons; LogonFailureTotal = $logonTotal; Lockouts = $lockouts
        Disks = $disks; ErrorCount = $errorCount; ErrorTop = $errorTop; TimeSource = $timeSource; TimeOffsetSec = $timeOffset; LastSyncHours = $lastSyncHours
        Certs = $certs; MemoryFreePct = $memFreePct; MemoryFreeMB = $memFreeMB; MemoryTotalGB = $memTotalGB; MemoryTop = $memTop
        CpuPercent = $cpuPct; CpuCount = $cpuCount; CpuSeconds = [math]::Max(1, $CpuSeconds); CpuTop = $cpuTop; Errors = $errors
    }
}

# ---------------------------------------------------------------------
#  AGENTS collector - RUNS ON THE SERVER.  One line per rule from
#  soe-agents.psd1: "Name|Installed|Running|Version|Detail"
# ---------------------------------------------------------------------
$script:RemoteAgentsScript = {
    param([string[]]$Rules)
    $ErrorActionPreference = 'Continue'
    # Stop: services that could not be listed must fail the collector (its agents then read "no agent scan" = not checked),
    # never read as "installed but not running" for every service-detected agent (R6-D05)
    $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
    $products = @(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })
    $defender = $null
    try { $defender = Get-MpComputerStatus -ErrorAction Stop } catch { }
    $out = @()
    foreach ($rule in $Rules) {
        $f = $rule -split '\|'
        $name = $f[0]; $svcPatterns = @($f[1] -split ';' | Where-Object { $_ }); $exes = @($f[2] -split ';' | Where-Object { $_ }); $prodPatterns = @($f[3] -split ';' | Where-Object { $_ })
        $installed = $false; $running = $false; $version = ''; $detail = @()
        foreach ($pat in $svcPatterns) {
            foreach ($s in ($services | Where-Object { $_.Name -like $pat -or $_.DisplayName -like $pat })) {
                $installed = $true
                if ($s.State -eq 'Running') { $running = $true }
                $detail += '{0}={1}' -f $s.Name, $s.State
                if (-not $version -and $s.PathName) {
                    $path = ($s.PathName -replace '^"([^"]+)".*$', '$1' -replace '^(\S+\.exe).*$', '$1')
                    if (Test-Path -LiteralPath $path) { try { $version = (Get-Item -LiteralPath $path).VersionInfo.ProductVersion } catch { } }
                }
            }
        }
        $fromExe = $false
        foreach ($exe in $exes) {
            if (Test-Path -LiteralPath $exe) { $installed = $true; try { $v = (Get-Item -LiteralPath $exe).VersionInfo.ProductVersion; if ($v) { $version = $v; $fromExe = $true; $detail += "exe=$v" } } catch { } }
        }
        # the agent's version: its program file's own when there is one; otherwise the HIGHEST matching product - a pattern
        # such as "McAfee Endpoint Security*" matches four modules with four versions, and the last one listed won (R6-D07)
        $toV = { param([string]$t) $m = [regex]::Match($t, '\d+(\.\d+){0,3}'); if ($m.Success) { try { return [version]($m.Value + $(if ($m.Value -notmatch '\.') { '.0' } else { '' })) } catch { } }; return $null }
        foreach ($pat in $prodPatterns) {
            foreach ($p in ($products | Where-Object { $_.DisplayName -like $pat })) {
                $installed = $true
                if (-not $p.DisplayVersion) { continue }
                $detail += ('product="{0}" {1}' -f $p.DisplayName, $p.DisplayVersion)
                if ($fromExe) { continue }
                $cand = & $toV ([string]$p.DisplayVersion); $cur = & $toV ([string]$version)
                if (-not $version -or ($cand -and (-not $cur -or $cand -gt $cur))) { $version = [string]$p.DisplayVersion }
            }
        }
        if ($name -like 'Microsoft Defender*' -and $defender) {
            $installed = $true; $running = [bool]$defender.AMServiceEnabled
            $version = [string]$defender.AMProductVersion
            $detail += ('mode={0} realtime={1} sigAgeDays={2} engine={3}' -f $defender.AMRunningMode, $defender.RealTimeProtectionEnabled, $defender.AntivirusSignatureAge, $defender.AMEngineVersion)
        }
        $out += '{0}|{1}|{2}|{3}|{4}' -f $name, $installed, $running, $version, (($detail | Select-Object -Unique) -join '; ')
    }
    [pscustomobject]@{ Computer = $env:COMPUTERNAME; Agents = $out }
}

# ---------------------------------------------------------------------
#  SETTINGS collector - RUNS ON THE SERVER.  A flat "Key=Value" dictionary
#  of everything the SOE standards can pin and the Security checks read.
#  Each read is wrapped; a missing key reads "NotConfigured", a failed read
#  "ERROR: ...".  Keys are documented in the Code Tour (Settings keys).
# ---------------------------------------------------------------------
$script:RemoteSettingsScript = {
    $ErrorActionPreference = 'Continue'
    $lines = New-Object System.Collections.Generic.List[string]
    function Add-S([string]$k, $v) { if ($null -eq $v) { $v = 'NotConfigured' }; if ($v -is [array]) { $v = ($v -join ';') }; $lines.Add("$k=$v") }
    function Get-RV([string]$path, [string]$name) { try { $p = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop; return $p.$name } catch { return $null } }
    function Get-Feat([string]$name) { try { $f = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction Stop; return [string]$f.State } catch { return 'Unknown' } }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        Add-S 'OS.Caption' $os.Caption
        Add-S 'OS.BuildMajor' $cv.CurrentBuildNumber
        Add-S 'OS.UBR' $cv.UBR
        Add-S 'OS.Build' ('{0}.{1}' -f $cv.CurrentBuildNumber, $cv.UBR)
        Add-S 'OS.Architecture' $os.OSArchitecture
        Add-S 'OS.InstallDate' $os.InstallDate.ToString('yyyy-MM-dd')
        Add-S 'Domain' $cs.Domain
        Add-S 'DomainRole' $cs.DomainRole      # 4/5 = domain controller
        Add-S 'IsDomainController' ($cs.DomainRole -ge 4)
    } catch { Add-S 'OS.Caption' ('ERROR: ' + $_.Exception.Message) }
    try { Add-S 'TimeZone' (Get-TimeZone).Id } catch { Add-S 'TimeZone' (& tzutil.exe /g 2>$null) }
    # (Get-Culture would report the OPERATOR's culture: a remoting session inherits it.  The server's own default-user locale instead.)
    try { Add-S 'Locale' ([string](Get-ItemProperty -LiteralPath 'Registry::HKEY_USERS\.DEFAULT\Control Panel\International' -ErrorAction Stop).LocaleName); Add-S 'SystemLocale' (Get-WinSystemLocale).Name } catch { }
    try { $pp = (& powercfg.exe /getactivescheme 2>$null) | Out-String; if ($pp -match '\((.+)\)') { Add-S 'PowerPlan' $Matches[1] } } catch { }

    # Remote Desktop
    Add-S 'RDP.Enabled' ((Get-RV 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0)
    try { $ts = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'" -ErrorAction Stop; Add-S 'RDP.NLA' $ts.UserAuthenticationRequired; Add-S 'RDP.SecurityLayer' $ts.SecurityLayer; Add-S 'RDP.MinEncryptionLevel' $ts.MinEncryptionLevel } catch { Add-S 'RDP.NLA' (Get-RV 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') }

    # WinRM service and client
    try {
        $w = (& winrm.cmd get winrm/config 2>$null) | Out-String
        # winrm prints Config, then the Client block, then the Service block, then Winrs; split at the line that
        # reads just "Service" so the Basic / AllowUnencrypted values below are the SERVICE's, not the client's
        $svc = ($w -split '(?m)^\s*Service\s*$')[-1]
        if ($w -match 'TrustedHosts\s*=\s*(.*)') { Add-S 'WinRM.TrustedHosts' $Matches[1].Trim() }
        if ($svc -match 'AllowUnencrypted\s*=\s*(\w+)') { Add-S 'WinRM.AllowUnencrypted' $Matches[1] }
        if ($svc -match 'Basic\s*=\s*(\w+)') { Add-S 'WinRM.Basic' $Matches[1] }
        if ($w -match 'MaxEnvelopeSizekb\s*=\s*(\d+)') { Add-S 'WinRM.MaxEnvelopeSizekb' $Matches[1] }
    } catch { Add-S 'WinRM.Basic' ('ERROR: ' + $_.Exception.Message) }

    # SMB
    try { $smb = Get-SmbServerConfiguration -ErrorAction Stop; Add-S 'SMB.SMB1' $smb.EnableSMB1Protocol; Add-S 'SMB.ServerSigningRequired' $smb.RequireSecuritySignature; Add-S 'SMB.EncryptData' $smb.EncryptData } catch { Add-S 'SMB.SMB1' ('ERROR: ' + $_.Exception.Message) }
    Add-S 'SMB.ClientSigningRequired' (Get-RV 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature')
    Add-S 'Feature:FS-SMB1' (Get-Feat 'SMB1Protocol')

    # TLS / SCHANNEL  (Enabled=0 or DisabledByDefault=1 under Server\ = disabled)
    foreach ($proto in 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3', 'SSL 3.0') {
        foreach ($side in 'Server', 'Client') {
            $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\$side"
            $en = Get-RV $base 'Enabled'; $dbd = Get-RV $base 'DisabledByDefault'
            $state = 'NotConfigured'
            if ($null -ne $en -or $null -ne $dbd) { if ($en -eq 0 -or $dbd -eq 1) { $state = 'Disabled' } else { $state = 'Enabled' } }
            Add-S ("TLS.{0}.{1}" -f ($proto -replace ' ', ''), $side) $state
        }
    }
    # cryptography the ISM grades by classification (SECRET / TOP SECRET): the TLS cipher suites and curves in force,
    # the Diffie-Hellman minimum, and the smallest RSA key among the machine's own certificates
    # (Get-TlsCipherSuite / Get-TlsEccCurve hand the pipeline ONE List object, not one item per suite - a ForEach-Object
    #  would see a single item whose .Name is every name; assigning first and enumerating the variable unrolls it)
    try { $cs = Get-TlsCipherSuite -ErrorAction Stop; Add-S 'TLS.CipherSuites' (@(foreach ($s in @($cs)) { foreach ($n in @($s.Name)) { [string]$n } }) -join ';') } catch { Add-S 'TLS.CipherSuites' 'Unknown' }
    try { $ec = Get-TlsEccCurve -ErrorAction Stop; Add-S 'TLS.EccCurves' (@(foreach ($s in @($ec)) { foreach ($n in @($s)) { [string]$n } }) -join ';') } catch { Add-S 'TLS.EccCurves' 'Unknown' }
    Add-S 'TLS.DH.ServerMinKeyBitLength' (Get-RV 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman' 'ServerMinKeyBitLength')
    try {
        $rsa = @(Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop | ForEach-Object { try { if ($_.PublicKey.Oid.FriendlyName -eq 'RSA') { [int]$_.PublicKey.Key.KeySize } } catch { } } | Where-Object { $_ -gt 0 })
        Add-S 'Certs.RsaMinBits' $(if ($rsa.Count -gt 0) { ($rsa | Measure-Object -Minimum).Minimum } else { 'none' })
    } catch { Add-S 'Certs.RsaMinBits' 'Unknown' }
    # radios: a server with a Wi-Fi or Bluetooth radio is an RF device (SECRET and TOP SECRET areas: ISM-0225 / ISM-0829)
    # (the counts in parentheses: in a command's argument list "@(...).Count" is the array and a bareword, not the count)
    try { Add-S 'Wireless.Adapters' (@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.PhysicalMediaType -eq 'Native 802.11' -or $_.InterfaceDescription -match '(?i)wi-?fi|wireless|802\.11' }).Count) } catch { Add-S 'Wireless.Adapters' 'Unknown' }
    # (Win32_PnPEntity, not Get-PnpDevice: the cmdlet throws when no device of the class exists, which is the answer wanted)
    try { Add-S 'Bluetooth.Devices' (@(Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='Bluetooth'" -ErrorAction Stop | Where-Object { $_.Present }).Count) } catch { Add-S 'Bluetooth.Devices' 'Unknown' }
    try { $wl = Get-Service -Name WlanSvc -ErrorAction Stop; Add-S 'Wireless.WlanSvc' ('{0}/{1}' -f $wl.StartType, $wl.Status) } catch { Add-S 'Wireless.WlanSvc' 'absent' }
    Add-S 'Wireless.BlockNonDomain' (Get-RV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' 'fBlockNonDomain')
    Add-S 'LLMNR.EnableMulticast' (Get-RV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast')
    try { $nb = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { $_.TcpipNetbiosOptions }); Add-S 'NetBIOS.Options' ($nb -join ';') } catch { }

    # UAC, autorun, firewall
    Add-S 'UAC.EnableLUA' (Get-RV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA')
    Add-S 'UAC.ConsentPromptBehaviorAdmin' (Get-RV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin')
    Add-S 'UAC.FilterAdministratorToken' (Get-RV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'FilterAdministratorToken')
    Add-S 'Logon.InactivityTimeoutSecs' (Get-RV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs')
    Add-S 'Logon.DontDisplayLastUserName' (Get-RV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DontDisplayLastUserName')
    Add-S 'Logon.CachedLogonsCount' (Get-RV 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount')
    Add-S 'AutoRun.NoDriveTypeAutoRun' (Get-RV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun')
    Add-S 'AutoRun.NoAutorun' (Get-RV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoAutorun')
    # -PolicyStore ActiveStore: the firewall as it is in force, Group Policy included (the default store is the local one only)
    try { foreach ($p in (Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) { Add-S ("Firewall.{0}" -f $p.Name) ('Enabled={0};Inbound={1};Outbound={2}' -f $p.Enabled, $p.DefaultInboundAction, $p.DefaultOutboundAction) } } catch { Add-S 'Firewall.Domain' ('ERROR: ' + $_.Exception.Message) }
    Add-S 'RemovableStorage.DenyAll' (Get-RV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' 'Deny_All')
    Add-S 'RemovableStorage.DenyWrite' (Get-RV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' 'Deny_Write')

    # Accounts.  The Administrators group is found by its SID (its name is localised) and read through the LocalAccounts
    # module where it exists (Server 2016+), else net.exe by position (the words around the list are localised too).  A
    # read that fails or finds nobody is written as ERROR, so SEC-CRD-02 can never pass on an empty answer.
    try {
        $members = $null
        try { $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.Name }) } catch { $members = $null }
        if ($null -eq $members) {
            $grp = ((New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([System.Security.Principal.NTAccount]).Value) -replace '^.*\\', ''
            $raw = @(& net.exe localgroup "$grp" 2>&1 | ForEach-Object { [string]$_ })
            $dash = -1; for ($i = 0; $i -lt $raw.Count; $i++) { if ($raw[$i] -match '^-{10,}') { $dash = $i } }
            if ($dash -lt 0) { throw ("net.exe localgroup '{0}' printed no member list: {1}" -f $grp, ((@($raw | Where-Object { $_ }) | Select-Object -First 2) -join ' ')) }
            # after the dashes: one member per line; the closing sentence ends with a full stop, a member name does not
            $members = @($raw | Select-Object -Skip ($dash + 1) | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '\.$' })
        }
        if (@($members).Count -eq 0) { throw 'no member was read' }
        Add-S 'LocalAdmins' ((@($members) | Where-Object { $_ }) -join ';')
    } catch { Add-S 'LocalAdmins' ('ERROR: ' + $_.Exception.Message) }
    try {
        $users = @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True")
        $guest = $users | Where-Object { $_.SID -like '*-501' } | Select-Object -First 1
        $admin = $users | Where-Object { $_.SID -like '*-500' } | Select-Object -First 1
        if ($guest) { Add-S 'Guest.Enabled' (-not $guest.Disabled) }
        if ($admin) { Add-S 'Administrator.Name' $admin.Name; Add-S 'Administrator.Enabled' (-not $admin.Disabled) }
    } catch { }

    # LSA / credentials
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    foreach ($n in 'LmCompatibilityLevel', 'NoLMHash', 'RestrictAnonymous', 'RestrictAnonymousSAM', 'EveryoneIncludesAnonymous', 'RunAsPPL', 'LimitBlankPasswordUse', 'DisableDomainCreds') { Add-S "LSA.$n" (Get-RV $lsa $n) }
    Add-S 'LSA.NTLMMinClientSec' (Get-RV "$lsa\MSV1_0" 'NTLMMinClientSec')
    Add-S 'LSA.NTLMMinServerSec' (Get-RV "$lsa\MSV1_0" 'NTLMMinServerSec')
    Add-S 'LSA.RestrictSendingNTLMTraffic' (Get-RV "$lsa\MSV1_0" 'RestrictSendingNTLMTraffic')
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $running = @($dg.SecurityServicesRunning)
        Add-S 'DeviceGuard.SecurityServicesRunning' $running
        Add-S 'DeviceGuard.CredentialGuard' ($running -contains 1)
        Add-S 'DeviceGuard.HVCI' ($running -contains 2)
        Add-S 'DeviceGuard.VBS' $dg.VirtualizationBasedSecurityStatus
        Add-S 'DeviceGuard.CodeIntegrityEnforcement' $dg.CodeIntegrityPolicyEnforcementStatus
        Add-S 'DeviceGuard.UsermodeCodeIntegrity' $dg.UsermodeCodeIntegrityPolicyEnforcementStatus
    } catch { Add-S 'DeviceGuard.CredentialGuard' 'Unknown'; Add-S 'DeviceGuard.HVCI' 'Unknown' }
    try { Add-S 'SecureBoot' (Confirm-SecureBootUEFI -ErrorAction Stop) } catch {
        # "not supported on this platform" = BIOS / no UEFI -> Unsupported (a real finding); access denied = not readable
        if ($_.Exception.Message -match 'denied|privilege') { Add-S 'SecureBoot' ('ERROR: ' + $_.Exception.Message) } else { Add-S 'SecureBoot' 'Unsupported' }
    }

    # Defender, ASR, exploit protection
    # Defender: "not installed" only when its cmdlets are missing or its service is off (a third-party antivirus); any other
    # error is "ERROR: ..." for the checks to Warn on.  The ASR preferences are read on their own: a failure there no longer
    # wrote Installed=False after Installed=True (the last value wins) (R6-D20)
    $mp = $null
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        Add-S 'Defender.Installed' $true; Add-S 'Defender.Mode' $mp.AMRunningMode; Add-S 'Defender.RealTime' $mp.RealTimeProtectionEnabled
        Add-S 'Defender.SignatureAgeDays' $mp.AntivirusSignatureAge; Add-S 'Defender.Version' $mp.AMProductVersion; Add-S 'Defender.TamperProtection' $mp.IsTamperProtected
    } catch {
        if ($_.Exception -is [System.Management.Automation.CommandNotFoundException] -or $_.Exception.Message -match '(?i)0x800106ba|not running|has been disabled|not installed') { Add-S 'Defender.Installed' $false }
        else { Add-S 'Defender.Installed' ('ERROR: ' + $_.Exception.Message) }
    }
    if ($mp) {
        try {
            $pref = Get-MpPreference -ErrorAction Stop
            $ids = @($pref.AttackSurfaceReductionRules_Ids); $acts = @($pref.AttackSurfaceReductionRules_Actions)
            Add-S 'Defender.ASRRules' $ids.Count
            Add-S 'Defender.ASRBlock' @($acts | Where-Object { $_ -eq 1 }).Count
        } catch { Add-S 'Defender.ASRRules' ('ERROR: ' + $_.Exception.Message); Add-S 'Defender.ASRBlock' ('ERROR: ' + $_.Exception.Message) }
    }
    try {
        $pm = Get-ProcessMitigation -System -ErrorAction Stop
        # NOTSET = no system-wide policy, the OS default applies; reported as NotConfigured like every other unset value
        foreach ($pair in @(@('ExploitProtection.DEP', $pm.DEP.Enable), @('ExploitProtection.ASLR', $pm.ASLR.BottomUp), @('ExploitProtection.CFG', $pm.CFG.Enable))) {
            $mv = [string]$pair[1]; if ($mv -eq 'NOTSET') { $mv = 'NotConfigured' }
            Add-S $pair[0] $mv
        }
    } catch { Add-S 'ExploitProtection.DEP' 'Unknown' }

    # PowerShell and script engines
    $psp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    Add-S 'PS.ScriptBlockLogging' (Get-RV "$psp\ScriptBlockLogging" 'EnableScriptBlockLogging')
    Add-S 'PS.ModuleLogging' (Get-RV "$psp\ModuleLogging" 'EnableModuleLogging')
    Add-S 'PS.Transcription' (Get-RV "$psp\Transcription" 'EnableTranscripting')
    Add-S 'PS.ProtectedEventLogging' (Get-RV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' 'EnableProtectedEventLogging')
    Add-S 'PS.LanguageMode' $ExecutionContext.SessionState.LanguageMode
    Add-S 'Feature:PowerShell-V2' (Get-Feat 'MicrosoftWindowsPowerShellV2Root')
    Add-S 'Feature:NET-Framework-3.5' (Get-Feat 'NetFx3')
    Add-S 'Feature:Telnet-Client' (Get-Feat 'TelnetClient')
    Add-S 'Feature:IE11' (Get-Feat 'Internet-Explorer-Optional-amd64')
    Add-S 'IE11.DisabledByPolicy' (Get-RV 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' 'DisableInternetExplorerApp')
    Add-S 'Audit.ProcessCreationCmdLine' (Get-RV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled')
    try { Add-S 'WMI.ActivityLogEnabled' (Get-WinEvent -ListLog 'Microsoft-Windows-WMI-Activity/Operational' -ErrorAction Stop).IsEnabled } catch { Add-S 'WMI.ActivityLogEnabled' 'Unknown' }

    # Application control: AppLocker effective policy + WDAC policy files
    try {
        $svc = Get-Service -Name AppIDSvc -ErrorAction Stop; Add-S 'AppLocker.Service' $svc.Status
        $xml = [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop)
        $cols = @('Exe', 'Msi', 'Script', 'Dll', 'Appx')
        $total = 0
        foreach ($col in $cols) {
            $node = $xml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq $col }
            $mode = 'NotConfigured'; $count = 0
            if ($node) { $mode = $node.EnforcementMode; $count = @($node.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count }
            $total += $count
            Add-S "AppLocker.$col" ('{0};{1} rules' -f $mode, $count)
        }
        Add-S 'AppLocker.RuleCount' $total
        foreach ($lg in 'EXE and DLL', 'MSI and Script') { try { Add-S ("AppLocker.Log.{0}" -f ($lg -replace ' ', '')) (Get-WinEvent -ListLog "Microsoft-Windows-AppLocker/$lg" -ErrorAction Stop).IsEnabled } catch { } }
    } catch { Add-S 'AppLocker.Service' ('ERROR: ' + $_.Exception.Message) }
    try {
        $cip = @(Get-ChildItem -Path "$env:windir\System32\CodeIntegrity\CiPolicies\Active" -Filter '*.cip' -ErrorAction SilentlyContinue).Count
        if (Test-Path -LiteralPath "$env:windir\System32\CodeIntegrity\SIPolicy.p7b") { $cip++ }
        Add-S 'WDAC.PolicyFiles' $cip
    } catch { }

    # LAPS
    # Windows LAPS reads its policy from the first of: CSP (Intune), Group Policy, local configuration; legacy LAPS separately
    $lapsNew = $null
    foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config') {
        $v = Get-RV $root 'BackupDirectory'
        if ($null -ne $v) { $lapsNew = $v; Add-S 'LAPS.Windows.PolicyRoot' $root; break }
    }
    $lapsOld = Get-RV 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
    Add-S 'LAPS.Windows.BackupDirectory' $lapsNew
    Add-S 'LAPS.Legacy.Enabled' $lapsOld
    Add-S 'LAPS.Managed' (($null -ne $lapsNew -and $lapsNew -ne 0) -or ($lapsOld -eq 1))

    # Event logging
    Add-S 'EventForwarding.SubscriptionManager' (Get-RV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' '1')
    foreach ($lg in 'Security', 'System', 'Application') {
        try { $logCfg = Get-WinEvent -ListLog $lg -ErrorAction Stop; Add-S "EventLog.$lg.MaxMB" ([int]($logCfg.MaximumSizeInBytes / 1MB)); Add-S "EventLog.$lg.Mode" $logCfg.LogMode } catch { }
    }
    try {
        $src = ((& w32tm.exe /query /source 2>$null) | Out-String).Trim()
        if ($src -match 'error occurred|denied|not running') { $src = 'ERROR: ' + $src }   # w32tm prints its errors on stdout
        Add-S 'Time.Source' $src
    } catch { }
    Add-S 'Time.Type' (Get-RV 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' 'Type')

    [pscustomobject]@{ Computer = $env:COMPUTERNAME; Lines = $lines.ToArray(); Count = $lines.Count }
}

function Get-ServerHealth {
    param([Parameter(Mandatory = $true)][string[]]$ComputerName)
    $b = Get-BenignData
    $summary = { param($r) ('CPU {7}% busy, memory {8}% free, {0} auto services stopped (before benign list), {1} failing tasks, {2} failed logons, {3} errors in {4} h, time offset {5}s{6}' -f @($r.StoppedAuto).Count, @($r.FailingTasks).Count, $r.LogonFailureTotal, $r.ErrorCount, $r.WindowHours, $r.TimeOffsetSec, $(if (@($r.Errors).Count -gt 0) { ' (' + @($r.Errors).Count + ' collector errors)' } else { '' }), $r.CpuPercent, $r.MemoryFreePct) }
    return (Invoke-Collector -Name 'Health' -ScriptBlock $script:RemoteHealthScript -ComputerName $ComputerName -ArgumentList @($script:Config.LogonFailWindowHours, $script:Config.MaxEvents, $script:Config.TaskFailDays, $script:Config.CertExpiryDays, [int[]]@($b.TaskOkCodes), $script:Config.EventWindowHours, $script:Config.CpuSampleSeconds) -Summary $summary)
}

function Get-ServerAgents {
    param([Parameter(Mandatory = $true)][string[]]$ComputerName)
    $rules = @((Get-SoeAgentRules).Agents | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Name, $_.Services, $_.Exe, $_.Products })
    $summary = { param($r) $hits = @($r.Agents | Where-Object { ($_ -split '\|')[1] -eq 'True' } | ForEach-Object { ($_ -split '\|')[0] }); 'agents found: ' + ($hits -join ', ') }
    return (Invoke-Collector -Name 'Agents' -ScriptBlock $script:RemoteAgentsScript -ComputerName $ComputerName -ArgumentList @(, [string[]]$rules) -Summary $summary)
}

function Get-ServerSettings {
    param([Parameter(Mandatory = $true)][string[]]$ComputerName)
    $summary = { param($r) ('{0} settings read' -f $r.Count) }
    return (Invoke-Collector -Name 'Settings' -ScriptBlock $script:RemoteSettingsScript -ComputerName $ComputerName -Summary $summary)
}

function Get-AgentRows {
    # Parsed Agents result for one server: Name, Installed, Running, Version, Detail
    param([string]$Server)
    $a = Get-CollectorResult -Name 'Agents' -Server $Server
    if (-not $a -or -not $a.Reachable) { return @() }
    $rows = @()
    foreach ($line in @($a.Agents)) {
        $f = $line -split '\|'
        $rows += [pscustomobject]@{ Name = $f[0]; Installed = ($f[1] -eq 'True'); Running = ($f[2] -eq 'True'); Version = $f[3]; Detail = $f[4] }
    }
    return $rows
}

# ---------------------------------------------------------------------
#  HEALTH CHECKS
# ---------------------------------------------------------------------
function Get-HealthReadError {
    # The Health collector's own error for one of its queries ('services:', 'tasks:', 'disks:', 'event errors:',
    # 'certificates:' ...), or ''.  A check whose query failed must say so, never pass on an empty list.
    param($Health, [string]$Prefix)
    $e = @($Health.Errors | Where-Object { [string]$_ -like ($Prefix + '*') })
    if ($e.Count -gt 0) { return ([string]$e[0]) }
    return ''
}

New-Check -Id 'H-SVC-01' -Console 'Health' -Group 'Services' -Title 'Automatic services are running' -Severity 'High' -Needs 'Health' `
    -Why 'A stopped automatic service is usually a crashed or misconfigured component.' `
    -Test {
        param($c)
        $err = Get-HealthReadError -Health $c.Health -Prefix 'services:'
        if ($err) { return (Warn "the services could not be read: $err") }
        $benign = @((Get-BenignData).Services)
        $bad = @($c.Health.StoppedAuto | Where-Object { -not (Test-BenignService -Name (($_ -split '\|')[0]) -List $benign) })
        if ($bad.Count -eq 0) { return (Pass ('all automatic services running (' + @($c.Health.StoppedAuto).Count + ' benign stopped)')) }
        # a service whose program no longer exists was left behind by an uninstall: starting it cannot work - it needs removing
        $gone = @($bad | Where-Object { ($_ -split '\|')[5] -eq '1' })
        $down = @($bad | Where-Object { ($_ -split '\|')[5] -ne '1' })
        $items = @($down | ForEach-Object { $f = $_ -split '\|'; "$($f[0]) ($($f[1])) is $($f[3])" })
        $items += @($gone | ForEach-Object { $f = $_ -split '\|'; "$($f[0]) ($($f[1])) is $($f[3]) - its program no longer exists ($($f[6])): left behind by an uninstall; remove it with sc.exe delete $($f[0])" })
        if ($down.Count -eq 0) { return (Warn ("{0} service(s) left behind by an uninstall - the program is gone, the service is still registered" -f $gone.Count) -Items $items) }
        return (Fail ("{0} automatic service(s) not running{1}" -f $down.Count, $(if ($gone.Count) { (', and {0} left behind by an uninstall' -f $gone.Count) } else { '' })) -Items $items)
    } -Fix 'A stopped service: Start-Service <name>, and the System log says why it stopped. A service whose program no longer exists was left behind by an uninstall: remove it with sc.exe delete <name> (a change - use a change record; the Commands tab can run it). Add benign ones to data\benign-services.psd1.'

New-Check -Id 'H-TSK-01' -Console 'Health' -Group 'Scheduled tasks' -Title 'Scheduled tasks completed successfully' -Needs 'Health' `
    -Why 'A task with a failing last result is a backup, cleanup or agent job that silently stopped working.' `
    -Test {
        param($c)
        $err = Get-HealthReadError -Health $c.Health -Prefix 'tasks:'
        if ($err) { return (Warn "the scheduled tasks could not be read: $err") }
        $t = @($c.Health.FailingTasks)
        $days = [int]$c.Health.TaskDays; if (-not $days) { $days = [int]$script:Config.TaskFailDays }   # the window the server was asked with (a setting changed since applies at the next check)
        if ($t.Count -eq 0) { return (Pass "no failing task runs in the last $days days") }
        return (Warn ("{0} task(s) with a failing last result in the last {1} days" -f $t.Count, $days) -Items @($t | ForEach-Object { $f = $_ -split '\|'; "$($f[0])$($f[1]) result $($f[3]) at $($f[4])" }))
    } -Fix 'Open Task Scheduler on the server, check the History tab of the task; result codes: 0x1 = generic error, 0x2 = file not found, 0x41301 = still running.'

New-Check -Id 'H-LOG-01' -Console 'Health' -Group 'Logons' -Title 'Failed logons (event 4625) within limits' -Severity 'High' -Needs 'Health' `
    -Why 'Many failed logons from one source are a password spray, a locked service account or a broken scheduled task credential.' `
    -Test {
        param($c)
        $readError = @($c.Health.Errors | Where-Object { $_ -like 'failed logons:*' })
        if ($readError.Count -gt 0) { return (Warn ('the Security log could not be read: ' + $readError[0] + ' (the account needs Administrators or Event Log Readers on the server)')) }
        $total = [int]$c.Health.LogonFailureTotal
        $max = 0; $top = ''
        foreach ($l in @($c.Health.LogonFailures)) { $f = $l -split '\|'; if ([int]$f[0] -gt $max) { $max = [int]$f[0]; $top = "$($f[1]) from $($f[2]) (type $($f[3]))" } }
        if ($max -ge $script:Config.LogonFailFail) { return (Fail "$total failed logons in $($c.Health.WindowHours) h; worst source $max x $top") }
        if ($max -ge $script:Config.LogonFailWarn) { return (Warn "$total failed logons in $($c.Health.WindowHours) h; worst source $max x $top") }
        return (Pass "$total failed logons in $($c.Health.WindowHours) h")
    } -Fix 'Event Viewer > Security, filter 4625; the Logon Type and Source Network Address say whether it is a user, a service account or a remote host.'

New-Check -Id 'H-LOG-02' -Console 'Health' -Group 'Logons' -Title 'No account lockouts (event 4740)' -Needs 'Health' `
    -Why 'Lockouts are logged on domain controllers; on a member server they point at local accounts.' `
    -Test {
        param($c)
        $readError = @($c.Health.Errors | Where-Object { $_ -like 'lockouts:*' })
        if ($readError.Count -gt 0) { return (Warn ('the Security log could not be read: ' + $readError[0])) }
        $lk = @($c.Health.Lockouts)
        if ($lk.Count -eq 0) { return (Pass 'none') }
        # event 4740 keeps the CALLER computer (where the bad password came from) in TargetDomainName - not a domain (R6-D15)
        return (Warn ("{0} lockout(s) (event 4740) in {1} h" -f $lk.Count, $c.Health.WindowHours) -Items @($lk | ForEach-Object { $f = $_ -split '\|'; "$($f[0]) locked out at $($f[2]), caller computer $($f[1])" }))
    } -Fix 'Find the caller computer in the 4740 event and the 4625/4771 events before it.'

New-Check -Id 'H-SW-01' -Console 'Health' -Group 'Software' -Title 'No dormant software' -Severity 'Low' -Needs 'Inventory' `
    -Why 'Software installed long ago that no service, process or scheduled task uses is attack surface without a purpose (ISM-0380).' `
    -Test {
        param($c)
        $months = $script:Config.DormantMonths
        $ignore = @((Get-BenignData).DormantIgnore)
        $uses = @()
        $uses += @($c.Inventory.Services | ForEach-Object { ($_ -split '\|')[5] })
        $uses += @($c.Inventory.Processes)
        $uses += @($c.Inventory.Tasks | ForEach-Object { ($_ -split '\|')[5] })
        $usesText = ($uses -join "`n").ToLower()
        $dormant = @()
        foreach ($line in @($c.Inventory.Products)) {
            $f = $line -split '\|'
            if ($f.Count -lt 5 -or -not $f[3] -or -not $f[4]) { continue }
            if ($ignore | Where-Object { $f[0] -like $_ }) { continue }
            try { $age = ((Get-Date) - [datetime]$f[3]).TotalDays / 30.4 } catch { continue }
            if ($age -lt $months) { continue }
            $loc = $f[4].TrimEnd('\').ToLower()
            if ($loc.Length -lt 8) { continue }
            if ($usesText.Contains($loc)) { continue }
            $dormant += ('{0} {1} (installed {2})' -f $f[0], $f[1], $f[3])
        }
        if ($dormant.Count -eq 0) { return (Pass "nothing installed over $months months ago without a service, process or task using it") }
        return (Warn ("{0} product(s) installed over {1} months ago with no service, process or task using them - verify" -f $dormant.Count, $months) -Items $dormant)
    } -Fix 'Confirm with the application owner, then uninstall; or add the product to DormantIgnore in data\benign-services.psd1 if it is used in another way.'

New-Check -Id 'H-DSK-01' -Console 'Health' -Group 'Capacity' -Title 'Disk space' -Severity 'High' -Needs 'Health' `
    -Test {
        param($c)
        $err = Get-HealthReadError -Health $c.Health -Prefix 'disks:'
        if ($err) { return (Warn "the volumes could not be read: $err") }
        $n = @($c.Health.Disks).Count
        if ($n -eq 0) { return (Warn 'no fixed volume was read - a server always has one') }
        $worst = 'Pass'; $parts = @()
        foreach ($d in @($c.Health.Disks)) {
            $f = $d -split '\|'; $parts += "$($f[0]) $($f[2])/$($f[1]) GB free ($($f[3])%)"
            $freeGb = ConvertTo-HealthNumber $f[2]; $freePct = ConvertTo-HealthNumber $f[3]   # invariant: the collector writes 12.5, never 12,5
            if ($null -eq $freeGb -or $null -eq $freePct) { return (Warn "a volume's figures could not be read: '$d'") }
            if ($freeGb -lt $script:Config.DiskFailGB) { $worst = 'Fail' } elseif ($freePct -lt $script:Config.DiskWarnPercent -and $worst -ne 'Fail') { $worst = 'Warn' }
        }
        if ($worst -eq 'Fail') { return (Fail ("a volume has less than {0} GB free ({1} volume(s) checked)" -f $script:Config.DiskFailGB, $n) -Items $parts) }
        if ($worst -eq 'Warn') { return (Warn ("a volume is below {0}% free ({1} volume(s) checked)" -f $script:Config.DiskWarnPercent, $n) -Items $parts) }
        return (Pass ("{0} volume(s), all above the thresholds" -f $n) -Items $parts)
    } -Fix 'Clear logs and temp files, extend the volume, or move data; a cumulative update needs several GB free on C:.'

New-Check -Id 'H-UPT-01' -Console 'Health' -Group 'Capacity' -Title 'Uptime and pending reboot' -Needs 'Status' `
    -Test {
        param($c)
        $s = $c.Status
        if ($s.PendingReboot -or $s.SoftwareRebootPending) { return (Warn ("pending reboot ({0}), up {1} days" -f (Get-PendingRebootText -Status $s).Substring(5), $s.UptimeDays)) }
        if ($s.RebootAdvised) { return (Warn ("reboot advised (not required): software removed since the last boot ({0}) - the reboot finishes its clean-up; up {1} days" -f $s.RebootAdvisedReasons, $s.UptimeDays)) }
        if ([double]$s.UptimeDays -gt $script:Config.UptimeWarnDays) { return (Warn "up $($s.UptimeDays) days (over $($script:Config.UptimeWarnDays))") }
        return (Pass "up $($s.UptimeDays) days, no reboot pending")
    } -Fix 'Reboot in the next change window (the O/S Patching console reboot button checks that nothing is servicing first).'

New-Check -Id 'H-EVT-01' -Console 'Health' -Group 'Event logs' -Title 'Error and critical events within limits' -Needs 'Health' `
    -Test {
        param($c)
        $err = Get-HealthReadError -Health $c.Health -Prefix 'event errors:'
        if ($err) { return (Warn "the System and Application logs could not be read: $err") }
        $n = [int]$c.Health.ErrorCount
        $top = @($c.Health.ErrorTop | Select-Object -First 3 | ForEach-Object { $f = $_ -split '\|'; "$($f[1]) x$($f[0])" })
        $hours = $c.Health.EventWindowHours; if (-not $hours) { $hours = $c.Health.WindowHours }
        if ($n -gt $script:Config.EventErrorWarn) { return (Warn ("{0} errors/criticals in System+Application in {1} h (over {2}); top sources" -f $n, $hours, $script:Config.EventErrorWarn) -Items $top) }
        return (Pass ("{0} errors/criticals in {1} h" -f $n, $hours) -Items $top)
    } -Fix 'Event Viewer > Windows Logs > System / Application, filter Level Critical + Error, look at the top sources.'

New-Check -Id 'H-TIM-01' -Console 'Health' -Group 'Time' -Title 'Time synchronised' -Severity 'High' -Ism 'ISM-0988' -Needs 'Health' `
    -Why 'Kerberos fails beyond 5 minutes of skew, and event logs are useless for investigation without accurate time (ISM-0988).' `
    -Test {
        param($c)
        $src = [string]$c.Health.TimeSource; $off = [string]$c.Health.TimeOffsetSec; $age = [string]$c.Health.LastSyncHours
        $svcErr = @($c.Health.Errors | Where-Object { [string]$_ -like 'w32tm: the Windows Time service is *' })
        if ($svcErr.Count -gt 0) { return (Fail ([string]$svcErr[0]).Substring(7) + ' - the clock is not being synchronised') }
        if (-not $src) { return (Warn 'w32tm did not report a source (service stopped?)') }
        if ($src -match 'Local CMOS Clock|Free-running|Type=NoSync') { return (Fail "source is '$src' - not synchronised") }
        # no "Source:" line could be read (a w32tm in another language): the registry says how the service is set up, not whether it is in sync
        if ($src -like '(registry)*') { return (Warn "w32tm's output could not be read (a non-English Windows?); the service is set up as $src") }
        $text = "source $src"
        if ($off) {
            # invariant (R6-D02): the operator PC's culture read 0.0000387 as 387 on a de-DE PC, and a failed parse was taken as 0
            $o = ConvertTo-HealthNumber $off
            if ($null -eq $o) { return (Warn "$text - the offset '$off' could not be read") }
            if ([math]::Abs($o) -gt $script:Config.TimeOffsetFailSec) { return (Fail "offset $off s from $src") }
            $text += ", offset $off s"
        }
        if ($age -match '^[\d\.]+$') {
            if ([double]$age -gt 24) { return (Warn "$text, last successful sync $age h ago") }
            $text += ", last sync $age h ago"
        }
        return (Pass $text)
    } -Fix 'w32tm /resync ; domain members should use the domain hierarchy (w32tm /config /syncfromflags:domhier /update).'

New-Check -Id 'H-CRT-01' -Console 'Health' -Group 'Certificates' -Title 'Machine certificates not expiring' -Needs 'Health' `
    -Test {
        param($c)
        $err = Get-HealthReadError -Health $c.Health -Prefix 'certificates:'
        if ($err) { return (Warn "the machine certificate store could not be read: $err") }
        $cs = @($c.Health.Certs)
        $days = [int]$c.Health.CertDays; if (-not $days) { $days = [int]$script:Config.CertExpiryDays }   # the window the server was asked with
        if ($cs.Count -eq 0) { return (Pass "none expiring within $days days") }
        $expired = @($cs | Where-Object { [int](($_ -split '\|')[3]) -lt 0 })
        $list = @($cs | ForEach-Object { $f = $_ -split '\|'; "$($f[0]) expires $($f[1]) ($($f[3]) d)" })
        if ($expired.Count -gt 0) { return (Fail ("{0} machine certificate(s) within {1} days of expiry, {2} already expired" -f $cs.Count, $days, $expired.Count) -Items $list) }
        return (Warn ("{0} machine certificate(s) within {1} days of expiry" -f $cs.Count, $days) -Items $list)
    } -Fix 'Renew through the issuing CA (certlm.msc > Personal > Certificates > All Tasks > Renew) and rebind the service that uses it.'

New-Check -Id 'H-MEM-01' -Console 'Health' -Group 'Capacity' -Title 'Memory headroom' -Needs 'Health' `
    -Test {
        param($c)
        $pct = ConvertTo-HealthNumber $c.Health.MemoryFreePct   # invariant (R6-D02)
        if ($null -eq $pct) { return (Warn 'memory figures were not read - see H-COL-01 for the collector error') }
        $text = "$pct % free ($($c.Health.MemoryFreeMB) MB$(if ($c.Health.MemoryTotalGB) { ' of ' + $c.Health.MemoryTotalGB + ' GB' }))"
        $top = @($c.Health.MemoryTop | Where-Object { $_ } | ForEach-Object { $f = $_ -split '\|'; '{0} holds {1} MB' -f $f[0], $f[1] })
        if ($pct -lt $script:Config.MemoryFailPercent) { return (Fail ('{0}; below {1}% free' -f $text, $script:Config.MemoryFailPercent) -Items $top) }
        if ($pct -lt $script:Config.MemoryWarnPercent) { return (Warn ('{0}; below {1}% free' -f $text, $script:Config.MemoryWarnPercent) -Items $top) }
        return (Pass $text)
    } -Fix 'Find the process in Task Manager (the biggest are named above); a slow leak shows as free memory falling over days.'

New-Check -Id 'H-CPU-01' -Console 'Health' -Group 'Capacity' -Title 'Processor load' -Needs 'Health' `
    -Why 'A processor that stays busy slows every service on the server. The figure is a few seconds averaged at the check - a snapshot: check again before acting on one reading.' `
    -Test {
        param($c)
        $pct = ConvertTo-HealthNumber $c.Health.CpuPercent   # invariant (R6-D02)
        if ($null -eq $pct) { return (Warn 'processor load was not read - see H-COL-01 for the collector error') }
        $text = '{0}% busy over {1} s at the check ({2} logical processor(s))' -f $pct, $c.Health.CpuSeconds, $c.Health.CpuCount
        $top = @($c.Health.CpuTop | Where-Object { $_ } | ForEach-Object { $f = $_ -split '\|'; '{0} used {1}% of the machine' -f $f[0], $f[1] })
        if ($pct -ge $script:Config.CpuFailPercent) { return (Fail ('{0}; at or above {1}%' -f $text, $script:Config.CpuFailPercent) -Items $top) }
        if ($pct -ge $script:Config.CpuWarnPercent) { return (Warn ('{0}; at or above {1}%' -f $text, $script:Config.CpuWarnPercent) -Items $top) }
        return (Pass $text)
    } -Fix 'Check again to see whether it stays busy; then Task Manager or Resource Monitor on the server (the busiest processes are named above). A scan, a backup or Windows Update can keep a server busy for a while.'

# ---- Group Policy (collector 'Gpo', lib\13-GroupPolicy.ps1) ----
New-Check -Id 'H-GPO-01' -Console 'Health' -Group 'Group Policy' -Title 'Group Policy applies without errors' -Severity 'High' -Needs 'Gpo' `
    -Why 'A computer policy that fails to apply leaves the server on old or default settings - security settings included - and nobody notices.' `
    -Test {
        param($c)
        if ($null -eq $c.Gpo.Joined) { return (Warn ('domain membership could not be read: ' + (@($c.Gpo.Errors | Where-Object { $_ }) -join '; '))) }   # unknown is not "workgroup" (R6-D03)
        if (-not $c.Gpo.Joined) { return (NotApplicable 'not a domain member: only the local policy applies') }
        # the collector's own failures (the GPO list, the extension list or the logs unreadable) are not a clean bill
        $gerr = @($c.Gpo.Errors | Where-Object { $_ })
        if ($gerr.Count -gt 0) { return (Warn ('the Group Policy state could not be fully read ({0} query(ies) failed)' -f $gerr.Count) -Items $gerr) }
        $failed = @(Get-GpoExtensionRows -Server $c.Server | Where-Object { $_.Failed })
        $events = @(Get-GpoEventRows -Server $c.Server)
        $errs = @($events | Where-Object { $_.Level -in 'Critical', 'Error' })
        $warns = @($events | Where-Object { $_.Level -eq 'Warning' })
        # an error from before the last refresh whose every extension succeeded has been cleared by it (the boot-time "no
        # network" error after a patch-night reboot failed every rebooted server for 24 h): such errors warn (R6-D14)
        $refresh = [string]$c.Gpo.LastRefresh
        if ($failed.Count -eq 0 -and $refresh.Length -ge 16) {
            $cleared = @($errs | Where-Object { [string]$_.Time -lt $refresh.Substring(0, 16) })
            if ($cleared.Count -gt 0) { $errs = @($errs | Where-Object { [string]$_.Time -ge $refresh.Substring(0, 16) }); $warns = @($warns) + @($cleared) }
        }
        $applied = @(Get-GpoRows -Server $c.Server | Where-Object { $_.Applied -and $_.GPO -ne 'Local Group Policy' }).Count
        $items = @($failed | ForEach-Object { "extension '$($_.Extension)' last run $($_.LastRun): $($_.Result)" })
        $items += @(@($errs) + @($warns) | Select-Object -First 8 | ForEach-Object { "$($_.Level) $($_.Id) ($($_.Log) log, $($_.Time)): $($_.Message)" })
        $gh = [int]$c.Gpo.WindowHours; if (-not $gh) { $gh = [int]$script:Config.EventWindowHours }   # the window the server was asked with
        if ($failed.Count -gt 0 -or $errs.Count -gt 0) { return (Fail ('{0} extension(s) failed, {1} Group Policy error(s) in {2} h' -f $failed.Count, $errs.Count, $gh) -Items $items) }
        if ($warns.Count -gt 0) { return (Warn ('{0} GPO(s) applied; {1} Group Policy warning(s) in {2} h' -f $applied, $warns.Count, $gh) -Items $items) }
        # every domain member gets at least the Default Domain Policy: none applied = the list was not read, or no policy reaches it
        if ($applied -eq 0) { return (Warn 'no domain GPO applied on a domain member - the policy list could not be read, or the server is not getting policy at all') }
        return (Pass ('{0} GPO(s) applied, every policy extension succeeded, no Group Policy error in {1} h' -f $applied, $gh))
    } -Fix 'On the server: gpupdate /force, then gpresult /h report.html (as an administrator) and the Group Policy log (Event Viewer > Applications and Services Logs > Microsoft > Windows > GroupPolicy). Common causes: no domain controller reachable (DNS, site, firewall), SYSVOL not readable, a broken secure channel (H-GPO-03), a WMI filter that errors.'

New-Check -Id 'H-GPO-02' -Console 'Health' -Group 'Group Policy' -Title 'Group Policy refreshed recently' -Severity 'Medium' -Needs 'Gpo' `
    -Why 'Computer policy refreshes about every 90 minutes; a server that has not refreshed for a day is not getting policy changes.' `
    -Test {
        param($c)
        if ($null -eq $c.Gpo.Joined) { return (Warn 'domain membership could not be read') }
        if (-not $c.Gpo.Joined) { return (NotApplicable 'not a domain member') }
        $age = ConvertTo-HealthNumber $c.Gpo.RefreshAgeHours   # invariant (R6-D02)
        if ($null -eq $age) { return (Warn 'the time of the last policy refresh is not recorded on the server') }
        $limit = [double]$script:Config.GpoStaleHours
        $text = 'last refresh {0} ({1:n1} h ago)' -f $c.Gpo.LastRefresh, $age
        if ($age -gt 7 * $limit) { return (Fail ($text + ('; more than 7 x {0} h' -f $limit))) }
        if ($age -gt $limit) { return (Warn ($text + ('; more than {0} h' -f $limit))) }
        return (Pass $text)
    } -Fix 'gpupdate /force on the server, then look at H-GPO-01 and the Group Policy log for why the background refresh stopped (no domain controller reachable, the Group Policy Client service, a hung extension).'

New-Check -Id 'H-GPO-03' -Console 'Health' -Group 'Group Policy' -Title 'Trust with the domain (secure channel) intact' -Severity 'High' -Needs 'Gpo' `
    -Why 'A broken secure channel stops domain logons, Kerberos to the server and every Group Policy refresh.' `
    -Test {
        param($c)
        if ($null -eq $c.Gpo.Joined) { return (Warn 'domain membership could not be read') }
        if (-not $c.Gpo.Joined) { return (NotApplicable 'not a domain member') }
        $sc = [string]$c.Gpo.SecureChannel
        if ($sc -eq 'True') { return (Pass ('secure channel to {0} verified' -f $c.Gpo.Domain)) }
        if ($sc -eq 'False') { return (Fail ('the secure channel to {0} is broken' -f $c.Gpo.Domain)) }
        return (Warn ('the secure channel could not be tested: {0}' -f $sc))
    } -Fix 'Test-ComputerSecureChannel -Repair -Credential <domain admin> on the server (a change - use a change record), or rejoin the domain. Check first that the computer account was not reset or deleted, and that a domain controller is reachable.'

New-Check -Id 'H-SOE-01' -Console 'Health' -Group 'SOE standard' -Title 'Matches the SOE standard of its group' -Severity 'Medium' -Needs 'Inventory', 'Agents', 'Settings' `
    -Test {
        param($c)
        $name = Get-SoeStandardNameForServer -Server $c.Server
        if (-not $name) { return (NotApplicable ("no SOE standard applies - use 'Assign SOE standard...' (writes '; soe: <name>' on the server's line in the group file), add '# soe: <name>' to the group file, or create soe\{0}.json on the SOE standards page" -f $script:Config.DefaultSoeStandard)) }
        if (-not (Test-Path -LiteralPath (Get-SoeStandardPath -Name $name))) { return (Warn "the group names SOE standard '$name' but soe\$name.json does not exist") }
        $std = Read-SoeStandard -Name $name
        if (-not $std -or @($std.items).Count -eq 0) { return (NotAssessable "standard '$name' has no items yet") }
        $rows = @(Compare-SoeStandard -Standard $std -Server $c.Server)
        $bad = @($rows | Where-Object { $_.Light -eq 'Red' })
        $soft = @($rows | Where-Object { $_.Light -eq 'Amber' })
        $unread = @($rows | Where-Object { $_.Light -eq 'Grey' })   # not read is not "differs" (R6-D09)
        $list = @(@($bad) + @($soft) + @($unread) | Select-Object -First 6 | ForEach-Object { "$($_.Name) ($($_.Verdict))" })
        if (($bad.Count + $soft.Count + $unread.Count) -gt 6) { $list += ('... and {0} more (the SOE comparison below lists every item)' -f (($bad.Count + $soft.Count + $unread.Count) - 6)) }
        $text = "{0} of {1} items differ from standard '{2}'" -f ($bad.Count + $soft.Count), $rows.Count, $name
        if ($unread.Count -gt 0) { $text += (', {0} not read' -f $unread.Count) }
        if ($bad.Count -gt 0) { return (Fail $text -Items $list) }
        if ($soft.Count -gt 0 -or $unread.Count -gt 0) { return (Warn $text -Items $list) }
        return (Pass $text)
    } -Fix 'Double-click the server: the SOE compliance table names every item that differs, with the expected and the actual value. Fix the server, or change the rule on the SOE standards page.'

New-Check -Id 'H-COL-01' -Console 'Health' -Group 'Collector' -Title 'All health queries succeeded' -Severity 'Low' -Needs 'Health' `
    -Test {
        param($c)
        $e = @($c.Health.Errors)
        if ($e.Count -eq 0) { return (Pass 'every query answered') }
        return (Warn ("{0} health query(ies) failed" -f $e.Count) -Items $e)
    } -Fix 'Usually a right that is missing (Security log needs administrators or Event Log Readers) or a service that is not installed.'

# ---------------------------------------------------------------------
#  SOE STANDARDS  (soe\<name>.json)
# ---------------------------------------------------------------------
function Get-SoeStandardNames {
    if (-not (Test-Path -LiteralPath $script:Config.SoeFolder)) { return @() }
    return @(Get-ChildItem -LiteralPath $script:Config.SoeFolder -Filter '*.json' | ForEach-Object { $_.BaseName } | Sort-Object)
}

function Get-SoeStandardPath {
    # soe\<name>.json - the name doubles as the file name, so it is made file-safe here.
    param([string]$Name)
    $safe = (([string]$Name -replace '[\\/:*?"<>|]', '_').Trim()).TrimEnd('.')
    if (-not $safe) { throw 'an SOE standard needs a name' }
    if ($safe -match '^(CON|PRN|AUX|NUL|COM\d|LPT\d)$') { $safe += '_' }   # reserved device names on Windows
    return (Join-Path $script:Config.SoeFolder ($safe + '.json'))
}

function Test-SoeRegex {
    # A hand-written "re:" rule against a value, case-insensitive, with the same 2-second limit the probe collector has: a
    # runaway pattern must not hang the repaint.  A pattern that is not valid, or times out, does not match.
    param([string]$Value, [string]$Pattern)
    try { return [regex]::IsMatch($Value, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromSeconds(2)) } catch { return $false }
}

function Read-SoeStandard {
    # The file name wins over the "name" inside the JSON, so Save and Delete always act on the file that was read.
    # Kept per file version: H-SOE-01 asks for the group's standard once per server, and a fleet must not re-read and
    # re-parse the same JSON 500 times (Save-SoeStandard writes the file, so the next read sees a new stamp).
    param([string]$Name)
    $path = Get-SoeStandardPath -Name $Name
    if (-not $script:SoeStandardMemo) { $script:SoeStandardMemo = @{} }
    $stamp = ''; if (Test-Path -LiteralPath $path) { $fi = Get-Item -LiteralPath $path; $stamp = '{0}|{1}' -f $fi.LastWriteTimeUtc.Ticks, $fi.Length }
    $hit = $script:SoeStandardMemo[$path]
    if ($hit -and $hit.Stamp -eq $stamp) { return $hit.Standard }
    $std = Read-ToolJson -Path $path
    $script:SoeStandardMemo[$path] = @{ Stamp = $stamp; Standard = $std }
    if (-not $std) { return $null }
    if (-not $std.PSObject.Properties['items'] -or $null -eq $std.items) { $std | Add-Member -NotePropertyName items -NotePropertyValue @() -Force }
    $std.items = @($std.items)
    # a standard written by hand: Save-SoeStandard sets "updated" (a missing one made every add and edit throw after the
    # cached copy had changed, R6-D06), and "required"/"mustRun" written as text read as [bool]'false' = true
    if (-not $std.PSObject.Properties['updated']) { $std | Add-Member -NotePropertyName updated -NotePropertyValue '' -Force }
    foreach ($it in @($std.items)) {
        foreach ($flagName in 'required', 'mustRun') {
            if ($it -and $it.PSObject.Properties[$flagName] -and $it.$flagName -is [string]) { $it.$flagName = ([string]$it.$flagName -notmatch '^(?i)\s*(false|no|0|off)\s*$') }
        }
    }
    if (-not $std.PSObject.Properties['name'] -or [string]$std.name -ne $Name) {
        Write-PatchLog ("soe\{0}.json calls itself '{1}' - using the file name '{0}'" -f $Name, $std.name) 'WARN'
        $std | Add-Member -NotePropertyName name -NotePropertyValue $Name -Force
    }
    return $std
}

function New-SoeStandard {
    param([string]$Name, [string]$Description = '')
    if ([string]$Name -match '[;#]') { throw "an SOE standard name cannot contain ';' or '#' (they separate settings and comments on a group-file line)" }
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension((Get-SoeStandardPath -Name $Name))   # throws on an empty name
    $std = [pscustomobject]@{ name = $fileName; description = $Description; updated = (Get-Date -Format 'yyyy-MM-dd HH:mm'); appliesTo = @(); items = @() }
    Save-SoeStandard -Standard $std
    return $std
}

function Save-SoeStandard {
    param($Standard)
    $Standard | Add-Member -NotePropertyName updated -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd HH:mm') -Force   # also on a standard written without it
    $Standard.items = @($Standard.items)
    Save-ToolJson -Object $Standard -Path (Get-SoeStandardPath -Name $Standard.name)
    Clear-CheckRowCache    # H-SOE-01 compares against this standard
    Write-PatchLog ("SOE standard '{0}' saved with {1} item(s) by {2}" -f $Standard.name, @($Standard.items).Count, (Get-OperatorIdentity)) 'OK'
}

function New-SoeItem {
    # One line of a standard.  Only the fields that make sense for the type are used:
    #   agent / software: name, version rule   feature: name, state   service: name, startType, state
    #   setting: key, expected                  registry / file: path, key, expected   forbidden: name
    param([string]$Type, [string]$Name, [string]$Version = '', [bool]$Required = $true, [bool]$MustRun = $false, [string]$State = '', [string]$StartType = '', [string]$Key = '', [string]$Expected = '', [string]$Path = '', [string]$Source = 'by hand', [string]$Note = '')
    return [pscustomobject]@{ type = $Type; name = $Name; key = $Key; path = $Path; expected = $Expected; version = $Version; required = $Required; mustRun = $MustRun; state = $State; startType = $StartType; source = $Source; note = $Note }
}

function Get-SoeCandidates {
    # Everything a scanned server offers for pinning into a standard: agents, products, features, services, settings.
    param([string]$Server)
    $rows = @()
    foreach ($a in (Get-AgentRows -Server $Server)) { if ($a.Installed) { $rows += [pscustomobject]@{ Type = 'agent'; Name = $a.Name; Value = $a.Version; Extra = $(if ($a.Running) { 'running' } else { 'stopped' }) } } }
    $inv = Get-CollectorResult -Name 'Inventory' -Server $Server
    if ($inv -and $inv.Reachable) {
        foreach ($line in @($inv.Products)) { $f = $line -split '\|'; if ($f.Count -ge 2) { $rows += [pscustomobject]@{ Type = 'software'; Name = $f[0]; Value = $f[1]; Extra = $f[2] } } }
        foreach ($line in @($inv.Features)) { $f = $line -split '\|'; if ($f[0] -ne 'ERROR') { $rows += [pscustomobject]@{ Type = 'feature'; Name = $f[0]; Value = 'Installed'; Extra = $f[1] } } }
        foreach ($line in @($inv.Services)) { $f = $line -split '\|'; if ($f.Count -ge 4) { $rows += [pscustomobject]@{ Type = 'service'; Name = $f[0]; Value = ('{0};{1}' -f $f[2], $f[3]); Extra = $f[1] } } }
    }
    $set = Get-CollectorResult -Name 'Settings' -Server $Server
    if ($set -and $set.Reachable) {
        foreach ($line in @($set.Lines)) { if ($line -match '^([^=]+)=(.*)$') { $rows += [pscustomobject]@{ Type = 'setting'; Name = $Matches[1]; Value = $Matches[2]; Extra = '' } } }
    }
    # the configuration points of the catalogue, with what this server returned for them
    foreach ($p in @((Get-SoeConfigPoints).Points)) {
        $v = Get-ProbeValue -Server $Server -Type $p.Type -Path $p.Path -Key $p.Key
        if ($null -ne $v -and [string]$v -notmatch '^(NotConfigured|file missing|key missing|ERROR:|\(no values\))') { $rows += [pscustomobject]@{ Type = [string]$p.Type; Name = [string]$p.Name; Value = $v; Extra = ('{0} > {1}' -f $p.Path, $p.Key); Path = [string]$p.Path; Key = [string]$p.Key; Note = [string]$p.Note } }
    }
    return $rows
}

function ConvertTo-SoeItem {
    # A picked candidate row -> a standard item (sensible defaults the sysadmin can edit).
    param($Candidate, [string]$Server)
    switch ($Candidate.Type) {
        'agent'    { return (New-SoeItem -Type 'agent' -Name $Candidate.Name -Version $(if ($Candidate.Value) { '>= ' + $Candidate.Value } else { '' }) -Required $true -MustRun ($Candidate.Extra -eq 'running') -Source "exemplar $Server") }
        'software' { return (New-SoeItem -Type 'software' -Name $Candidate.Name -Version $(if ($Candidate.Value) { '>= ' + $Candidate.Value } else { '' }) -Required $true -Source "exemplar $Server") }
        'feature'  { return (New-SoeItem -Type 'feature' -Name $Candidate.Name -State 'Installed' -Source "exemplar $Server") }
        'service'  { $p = $Candidate.Value -split ';'; return (New-SoeItem -Type 'service' -Name $Candidate.Name -StartType $p[0] -State $p[1] -Source "exemplar $Server") }
        # a value read from the reference server is a literal: one holding * or ? (TrustedHosts *, ?:\pagefile.sys) would
        # otherwise be compared as a wildcard and let other values pass - it is pinned as an exact regex instead (R6-D10)
        'setting'  { return (New-SoeItem -Type 'setting' -Name $Candidate.Name -Key $Candidate.Name -Expected (ConvertTo-SoeLiteral $Candidate.Value) -Source "exemplar $Server") }
        'registry' { return (New-SoeItem -Type 'registry' -Name $Candidate.Name -Path $Candidate.Path -Key $Candidate.Key -Expected (ConvertTo-SoeLiteral $Candidate.Value) -Source "exemplar $Server" -Note ([string]$Candidate.Note)) }
        'file'     { return (New-SoeItem -Type 'file' -Name $Candidate.Name -Path $Candidate.Path -Key $Candidate.Key -Expected (ConvertTo-SoeLiteral $Candidate.Value) -Source "exemplar $Server" -Note ([string]$Candidate.Note)) }
    }
    return $null
}

function Get-FleetAgentItems {
    # The most common version of every agent across all scanned servers -> items.
    $seen = @{}
    foreach ($server in @($script:Results['Agents'].Keys)) {
        foreach ($a in (Get-AgentRows -Server $server)) {
            if (-not $a.Installed) { continue }
            if (-not $seen.ContainsKey($a.Name)) { $seen[$a.Name] = @{} }
            $v = [string]$a.Version
            if (-not $seen[$a.Name].ContainsKey($v)) { $seen[$a.Name][$v] = 0 }
            $seen[$a.Name][$v]++
        }
    }
    $items = @()
    foreach ($name in $seen.Keys) {
        $best = ($seen[$name].GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key
        $items += New-SoeItem -Type 'agent' -Name $name -Version $(if ($best) { '>= ' + $best } else { '' }) -Required $true -MustRun $true -Source 'fleet majority'
    }
    return $items
}

function ConvertTo-SoeLiteral {
    # An expected value that compares as exactly itself: plain text stays plain; text with a wildcard character (or that
    # starts with re:) becomes re:^<escaped>$, so Compare-SoeStandard never reads it as a pattern.
    param([string]$Value)
    if ($Value -match '[*?\[\]]' -or $Value -like 're:*') { return ('re:^' + [regex]::Escape($Value) + '$') }
    return $Value
}

function Compare-SoeStandard {
    # One row per item for one server.  Verdicts: Compliant / Missing / Below version / Above version /
    # Not running / Forbidden present / Feature differs / Service differs / Setting differs / Not checked
    param($Standard, [string]$Server)
    $rows = @()
    $agents = @(Get-AgentRows -Server $Server)
    $inv = Get-CollectorResult -Name 'Inventory' -Server $Server
    $set = Get-CollectorResult -Name 'Settings' -Server $Server
    $S = @{}
    if ($set -and $set.Reachable) { $S = ConvertTo-SettingsTable -LineSets @(, @($set.Lines)) }
    $products = @(); $features = @(); $services = @(); $truncated = $false
    if ($inv -and $inv.Reachable) {
        $truncated = ($inv.PSObject.Properties['ProductsTruncated'] -and [bool]$inv.ProductsTruncated)
        $products = @($inv.Products | ForEach-Object { $f = $_ -split '\|'; [pscustomobject]@{ Name = $f[0]; Version = $f[1] } })
        $features = @($inv.Features | ForEach-Object { ($_ -split '\|')[0] })
        $featureError = ''; if (@($inv.Features).Count -gt 0 -and [string]@($inv.Features)[0] -like 'ERROR|*') { $featureError = [string]@($inv.Features)[0] }
        $services = @($inv.Services | ForEach-Object { $f = $_ -split '\|'; [pscustomobject]@{ Name = $f[0]; StartType = $f[2]; State = $f[3] } })
    }
    foreach ($it in @($Standard.items)) {
        $verdict = 'Not checked'; $actual = ''; $expected = ''
        $required = $true; if ($it.PSObject.Properties['required'] -and $null -ne $it.required) { $required = [bool]$it.required }
        switch ([string]$it.type) {
            'agent' {
                $expected = 'installed' + $(if ($it.version) { ' ' + $it.version } else { '' }) + $(if ($it.mustRun) { ', running' } else { '' })
                if ($agents.Count -eq 0) { $verdict = 'Not checked'; $actual = 'no agent scan'; break }
                $a = $agents | Where-Object { $_.Name -ieq $it.name } | Select-Object -First 1
                if (-not $a -or -not $a.Installed) { $verdict = 'Missing'; $actual = 'not installed'; break }
                $actual = 'installed ' + $a.Version + $(if ($a.Running) { ', running' } else { ', stopped' })
                $v = Compare-VersionRule -Actual $a.Version -Rule $it.version
                if ($it.mustRun -and -not $a.Running) { $verdict = 'Not running' }
                elseif ($v -eq 'Below') { $verdict = 'Below version' } elseif ($v -eq 'Above') { $verdict = 'Above version' } elseif ($v -eq 'Unknown') { $verdict = 'Not checked'; $actual += ' (version not readable)' } else { $verdict = 'Compliant' }
            }
            'software' {
                $expected = $(if ($required) { 'installed' } else { 'optional' }) + $(if ($it.version) { ' ' + $it.version } else { '' })
                if (-not $inv -or -not $inv.Reachable) { $actual = 'no inventory'; break }
                $hits = @($products | Where-Object { $_.Name -like $it.name })
                if ($hits.Count -eq 0 -and $truncated) { $actual = ('not in the first {0} products of {1} (the inventory list is cut at MaxProducts)' -f @($products).Count, $inv.ProductsTotal); break }
                if ($hits.Count -eq 0) { if ($required) { $verdict = 'Missing'; $actual = 'not installed' } else { $verdict = 'Compliant'; $actual = 'not installed (optional)' }; break }
                $best = ($hits | Sort-Object { try { [version]($_.Version -replace '[^\d\.].*$', '') } catch { [version]'0.0' } } -Descending | Select-Object -First 1)
                $actual = "$($best.Name) $($best.Version)"
                $v = Compare-VersionRule -Actual $best.Version -Rule $it.version
                if ($v -eq 'Below') { $verdict = 'Below version' } elseif ($v -eq 'Above') { $verdict = 'Above version' } elseif ($v -eq 'Unknown') { $verdict = 'Not checked'; $actual += ' (version not comparable with the rule)' } else { $verdict = 'Compliant' }
            }
            'forbidden' {
                $expected = 'absent'
                if (-not $inv -or -not $inv.Reachable) { $actual = 'no inventory'; break }
                $hits = @($products | Where-Object { $_.Name -like $it.name })
                if ($hits.Count -gt 0) { $verdict = 'Forbidden present'; $actual = (($hits | ForEach-Object { "$($_.Name) $($_.Version)" }) -join '; ') }
                elseif ($truncated) { $actual = ('not in the first {0} products of {1} (the inventory list is cut at MaxProducts)' -f @($products).Count, $inv.ProductsTotal) }   # stays Not checked
                else { $verdict = 'Compliant'; $actual = 'absent' }
            }
            'feature' {
                $want = [string]$it.state; if (-not $want) { $want = 'Installed' }
                $expected = $want
                if (-not $inv -or -not $inv.Reachable) { $actual = 'no inventory'; break }
                if ($featureError) { $actual = 'feature list could not be read: ' + ($featureError -replace '^ERROR\|', ''); break }
                $have = 'Absent'; if ($features -contains $it.name) { $have = 'Installed' }
                $actual = $have
                if ($have -eq $want) { $verdict = 'Compliant' } else { $verdict = 'Feature differs' }
            }
            'service' {
                $expected = (@($it.startType, $it.state) | Where-Object { $_ }) -join ', '
                if (-not $inv -or -not $inv.Reachable) { $actual = 'no inventory'; break }
                $svc = $services | Where-Object { $_.Name -ieq $it.name } | Select-Object -First 1
                if (-not $svc) { $verdict = 'Missing'; $actual = 'no such service'; break }
                $actual = "$($svc.StartType), $($svc.State)"
                $ok = $true
                if ($it.startType -and $svc.StartType -ne $it.startType) { $ok = $false }
                if ($it.state -and $svc.State -ne $it.state) { $ok = $false }
                if ($ok) { $verdict = 'Compliant' } else { $verdict = 'Service differs' }
            }
            'setting' {
                $expected = [string]$it.expected
                if ($S.Count -eq 0) { $actual = 'no settings scan'; break }
                $settingKey = [string]$it.key
                if (-not $settingKey) { $actual = 'item has no key (edit the standard)'; break }
                if (-not $S.ContainsKey($settingKey)) { $actual = 'key not collected'; break }
                $actual = [string]$S[$settingKey]
                if ($actual -like 'ERROR:*' -or $actual -eq 'Unknown') { break }   # stays Not checked: the value could not be read
                if ($expected -like 're:*') { $ok = (Test-SoeRegex -Value $actual -Pattern $expected.Substring(3)) } elseif ($expected -match '[*?]') { $ok = ($actual -like $expected) } else { $ok = ($actual -ieq $expected) }
                if ($ok) { $verdict = 'Compliant' } else { $verdict = 'Setting differs' }
            }
            { $_ -in 'registry', 'file' } {
                # a configuration point read by the Probe collector; expected: plain value, wildcard (*), or re:<regex>
                $expected = [string]$it.expected
                $v = Get-ProbeValue -Server $Server -Type $it.type -Path $it.path -Key $it.key
                if ($null -eq $v) { $actual = 'not read yet - run Check health'; break }
                $actual = $v
                if ($v -like 'ERROR:*') { break }
                $absent = ($v -in 'file missing', 'key missing' -or $v -like 'NotConfigured*')
                # a rule that WANTS the value absent (expected absent / NotConfigured / key missing / file missing) is met by its absence (R6-D11)
                if ($absent -and $expected -match '^(?i)\s*(absent|NotConfigured|key missing|file missing)\s*$') { $verdict = 'Compliant'; break }
                if ($absent) { if ($required) { $verdict = 'Missing' } else { $verdict = 'Compliant' }; break }
                $ok = $false
                if ($expected -like 're:*') { $ok = (Test-SoeRegex -Value $v -Pattern $expected.Substring(3)) } elseif ($expected -match '[*?]') { $ok = ($v -like $expected) } else { $ok = ($v -ieq $expected) }
                if ($ok) { $verdict = 'Compliant' } else { $verdict = 'Setting differs' }
            }
            default { $actual = "unknown item type '$($it.type)'" }
        }
        $light = 'Grey'
        switch ($verdict) {
            'Compliant' { $light = 'Green' }
            # above an upper bound ("< 9", "<= 10.2") that is required is a miss like any other: Red (R6-D08); above a
            # pinned "= x" stays Amber (newer than the standard knows)
            'Above version' { if ($required -and [string]$it.version -match '^\s*<') { $light = 'Red' } else { $light = 'Amber' } }
            'Not checked' { $light = 'Grey' }
            default { if ($required) { $light = 'Red' } else { $light = 'Amber' } }
        }
        $name = [string]$it.name; if (-not $name) { $name = [string]$it.key }
        $rows += [pscustomobject]@{ Server = $Server; Standard = $Standard.name; Type = $it.type; Name = $name; Expected = $expected; Actual = $actual; Verdict = $verdict; Light = $light; Note = [string]$it.note }
    }
    return $rows
}

# ---------------------------------------------------------------------
#  Health grid rows + report
# ---------------------------------------------------------------------
function Get-HealthSummaryRows {
    param([string[]]$Servers)
    $rows = @()
    foreach ($name in $Servers) {
        $h = Get-CollectorResult -Name 'Health' -Server $name
        $g = Get-ServerGroup -Name $name
        if (-not $h) { $rows += [pscustomobject]@{ Server = $name; Group = $(if ($g) { $g.Name } else { '' }); Light = 'Grey'; Checked = ''; Red = ''; Amber = ''; Green = ''; Services = ''; Tasks = ''; 'Failed logons' = ''; Lockouts = ''; Dormant = ''; SOE = ''; GPO = ''; CPU = ''; 'RAM used' = ''; 'Disk free (min)' = ''; 'Up (d)' = ''; 'Errors' = ''; 'Clock' = ''; Worst = 'not checked' }; continue }
        if (-not $h.Reachable) { $rows += [pscustomobject]@{ Server = $name; Group = $(if ($g) { $g.Name } else { '' }); Light = 'Grey'; Checked = $h.Checked.ToString('HH:mm:ss'); Red = ''; Amber = ''; Green = ''; Services = ''; Tasks = ''; 'Failed logons' = ''; Lockouts = ''; Dormant = ''; SOE = ''; GPO = ''; CPU = ''; 'RAM used' = ''; 'Disk free (min)' = ''; 'Up (d)' = ''; 'Errors' = ''; 'Clock' = ''; Worst = 'unreachable: ' + $h.Error }; continue }
        $checks = @(Get-CheckRows -Console 'Health' -Server $name)
        $c = Get-LightCounts -Rows $checks
        $worst = @($checks | Where-Object { $_.Light -eq 'Red' } | Select-Object -First 2 | ForEach-Object { $_.Title })
        if ($worst.Count -eq 0) { $worst = @($checks | Where-Object { $_.Light -eq 'Amber' } | Select-Object -First 2 | ForEach-Object { $_.Title }) }
        $s = $script:ServerStatus[$name]
        $benign = @((Get-BenignData).Services)
        $svcBad = @($h.StoppedAuto | Where-Object { -not (Test-BenignService -Name (($_ -split '\|')[0]) -List $benign) }).Count
        # the fullest disk: "28.4% free (C:)"
        $diskMin = ''
        if (@($h.Disks).Count -gt 0) {
            $fullest = @($h.Disks | ForEach-Object { $f = $_ -split '\|'; [pscustomobject]@{ Drive = $f[0]; Pct = (ConvertTo-HealthNumber $f[3]) } } | Where-Object { $null -ne $_.Pct } | Sort-Object Pct | Select-Object -First 1)[0]
            $diskMin = '{0}% free ({1})' -f $fullest.Pct, $fullest.Drive
        }
        # the clock against its time source: "in sync" within a second, otherwise the offset
        $clock = 'unknown'
        $offset = ConvertTo-HealthNumber $h.TimeOffsetSec   # invariant (R6-D02)
        if ($null -ne $offset -and [string]$h.TimeOffsetSec) { if ([math]::Abs($offset) -lt 1) { $clock = 'in sync' } else { $clock = 'off {0:n1} s' -f $offset } }
        $dormant = ($checks | Where-Object { $_.Id -eq 'H-SW-01' } | Select-Object -First 1)
        $dCount = ''; if ($dormant -and $dormant.Verdict -eq 'Warn') { $dCount = [string]@($dormant.Items).Count } elseif ($dormant -and $dormant.Verdict -eq 'Pass') { $dCount = '0' }   # one item per product (a ';' in a name must not count twice)
        # the SOE column: "ok", "N differ", "none" (no standard assigned to the group), "empty" (standard without items)
        $soe = ''
        $soeRow = ($checks | Where-Object { $_.Id -eq 'H-SOE-01' } | Select-Object -First 1)
        if ($soeRow) {
            switch ($soeRow.Verdict) {
                'Pass' { $soe = 'ok' }
                'NotApplicable' { $soe = 'none' }
                'NotAssessable' { $soe = 'empty' }
                'Error' { $soe = '?' }
                default {
                    if ($soeRow.Evidence -match '^(\d+) of (\d+)') { $soe = $Matches[1] + ' differ' } else { $soe = $soeRow.Verdict }
                    if ($soeRow.Evidence -match ', (\d+) not read') { $soe += ', ' + $Matches[1] + ' not read' }
                }
            }
        }
        $rows += [pscustomobject]@{
            Server = $name; Group = $(if ($g) { $g.Name } else { '' }); Light = (Get-WorstLight -Rows $checks); Checked = $h.Checked.ToString('HH:mm:ss')
            Red = $c.Red; Amber = $c.Amber; Green = $c.Green
            # a count whose query failed is "not read", never 0 (a Security log the account cannot read gave 0 failed logons, R6-D04)
            Services = $(if (Get-HealthReadError -Health $h -Prefix 'services:') { 'not read' } else { $svcBad }); Tasks = $(if (Get-HealthReadError -Health $h -Prefix 'tasks:') { 'not read' } else { @($h.FailingTasks).Count })
            'Failed logons' = $(if (Get-HealthReadError -Health $h -Prefix 'failed logons:') { 'not read' } else { $h.LogonFailureTotal }); Lockouts = $(if (Get-HealthReadError -Health $h -Prefix 'lockouts:') { 'not read' } else { @($h.Lockouts).Count }); Dormant = $dCount; SOE = $soe; GPO = (Get-GpoSummaryText -Server $name)
            CPU = (Format-HealthPercent $h.CpuPercent); 'RAM used' = (Format-HealthPercent $h.MemoryFreePct -Invert); 'Disk free (min)' = $diskMin; 'Up (d)' = $(if ($s) { $s.UptimeDays } else { '' }); 'Errors' = $h.ErrorCount; 'Clock' = $clock
            Worst = ($worst -join '; ')
        }
    }
    return $rows
}

function Get-HealthDetailsHtml {
    # The double-click page for one server: every check with its evidence and fix, then what the collector read.
    param([string]$Server)
    $h = Get-CollectorResult -Name 'Health' -Server $Server
    if (-not $h) { return (New-DetailsHtml -Title "Health: $Server" -Console 'Health' -Subtitle 'not checked yet - press "Check health (ticked, or all)"') }
    if (-not $h.Reachable) { return (New-DetailsHtml -Title "Health: $Server" -Console 'Health' -Subtitle ('unreachable: ' + $h.Error)) }
    $checks = @(Get-CheckRows -Console 'Health' -Server $Server | ForEach-Object {
        [pscustomobject]@{ Light = $_.Light; Id = $_.Id; Check = $_.Title; Evidence = $_.Evidence; Summary = $_.Summary; Items = $_.Items; 'How to fix' = $(if ($_.Light -in 'Red', 'Amber') { $_.Fix } else { '' }) } })
    $c = Get-LightCounts -Rows $checks
    $benign = @((Get-BenignData).Services)
    $services = @(ConvertFrom-PipeLines -Lines $h.StoppedAuto -Columns @('Name', 'Display', 'Start mode', 'State', 'Account', 'Gone', 'Program') | ForEach-Object {
        $_ | Add-Member -NotePropertyName 'Benign list' -NotePropertyValue $(if (Test-BenignService -Name $_.Name -List $benign) { 'yes - not counted' } else { '' }) -PassThru |
            Add-Member -NotePropertyName 'Program exists' -NotePropertyValue $(if ($_.Gone -eq '1') { 'NO - left behind by an uninstall' } elseif ($_.Gone -eq '0') { 'yes' } else { '' }) -PassThru })
    $agents = @(Get-AgentRows -Server $Server | ForEach-Object { [pscustomobject]@{ Agent = $_.Name; Installed = $_.Installed; Running = $_.Running; Version = $_.Version; Detail = $_.Detail } })
    $facts = @(
        @('Collected', $h.Checked.ToString('yyyy-MM-dd HH:mm:ss')),
        @('Checks', ('{0} red, {1} amber, {2} green' -f $c.Red, $c.Amber, $c.Green)),
        @('Logon window', "$($h.WindowHours) h"), @('Event window', "$($h.EventWindowHours) h"),
        @('Time source', [string]$h.TimeSource), @('Clock offset', "$($h.TimeOffsetSec) s (last sync $($h.LastSyncHours) h ago)"),
        @('Memory free', "$($h.MemoryFreePct) % ($($h.MemoryFreeMB) MB of $($h.MemoryTotalGB) GB)"), @('Processor', "$($h.CpuPercent) % busy over $($h.CpuSeconds) s, $($h.CpuCount) logical processor(s)"))
    $sections = @(
        @{ Heading = 'Checks'; Rows = $checks; Columns = @('Light', 'Id', 'Check', 'Evidence', 'How to fix') },
        @{ Heading = 'Automatic services not running'; Rows = $services; Columns = @('Name', 'Display', 'Start mode', 'State', 'Account', 'Program exists', 'Program', 'Benign list'); Note = 'Services on the benign list (data\benign-services.psd1) are shown here but not counted by H-SVC-01. "Program exists: NO" = the service was left behind by an uninstall: it can never start - remove it (sc.exe delete <name>, under a change record).' },
        @{ Heading = 'Scheduled tasks with a failing last result'; Rows = (ConvertFrom-PipeLines -Lines $h.FailingTasks -Columns @('Path', 'Task', 'State', 'Result', 'Last run')); Columns = @('Path', 'Task', 'State', 'Result', 'Last run'); Note = 'Result codes: 0x1 generic error, 0x2 file not found, 0x41301 still running, 0x41303 never run. The task''s History tab in Task Scheduler has the detail; codes that mean "fine" are listed in data\benign-services.psd1.' },
        @{ Heading = 'Failed logons (event 4625)'; Rows = (ConvertFrom-PipeLines -Lines $h.LogonFailures -Columns @('Count', 'Account', 'Source', 'Logon type', 'Last')); Columns = @('Count', 'Account', 'Source', 'Logon type', 'Last') },
        @{ Heading = 'Account lockouts (event 4740)'; Rows = (ConvertFrom-PipeLines -Lines $h.Lockouts -Columns @('Account', 'Caller computer', 'When')); Columns = @('Account', 'Caller computer', 'When') },
        @{ Heading = 'Disks'; Rows = (ConvertFrom-PipeLines -Lines $h.Disks -Columns @('Drive', 'Size GB', 'Free GB', 'Free %')); Columns = @('Drive', 'Size GB', 'Free GB', 'Free %') },
        @{ Heading = 'Top error sources (System + Application)'; Rows = (ConvertFrom-PipeLines -Lines $h.ErrorTop -Columns @('Count', 'Source')); Columns = @('Count', 'Source') },
        @{ Heading = 'Machine certificates expiring'; Rows = (ConvertFrom-PipeLines -Lines $h.Certs -Columns @('Subject', 'Expires', 'Thumbprint', 'Days left')); Columns = @('Subject', 'Expires', 'Days left', 'Thumbprint') },
        @{ Heading = 'Agents'; Rows = $agents; Columns = @('Agent', 'Installed', 'Running', 'Version', 'Detail'); Note = 'From "Agents + settings scan"; the agents looked for are listed in data\soe-agents.psd1.' },
        @{ Heading = 'Collector errors'; Lines = @($h.Errors); Note = 'Queries the Health collector could not run on this server (H-COL-01).' })
    # the SOE comparison right after the checks: every rule of the group's standard against this server
    $soeName = Get-SoeStandardNameForServer -Server $Server
    $soeRows = @()
    if ($soeName -and (Test-Path -LiteralPath (Get-SoeStandardPath -Name $soeName))) {
        $soeStd = Read-SoeStandard -Name $soeName
        if ($soeStd) { $soeRows = @(Compare-SoeStandard -Standard $soeStd -Server $Server | ForEach-Object { [pscustomobject]@{ Light = $_.Light; Type = $_.Type; Item = $_.Name; Expected = $_.Expected; Actual = $_.Actual; Verdict = $_.Verdict; Note = $_.Note } }) }
    }
    $soeSection = @{ Heading = $(if ($soeName) { "SOE standard '$soeName'" } else { 'SOE standard' }); Rows = $soeRows; Columns = @('Light', 'Type', 'Item', 'Expected', 'Actual', 'Verdict', 'Note'); Note = $(if ($soeName) { 'every rule of the standard against this server (check H-SOE-01); Red = a required rule differs, Amber = an optional one' } else { "no standard applies to this server's group: add '# soe: <name>' to the group file, or create soe\default.json" }) }
    $sections = @($sections[0]) + @($soeSection) + @($sections | Select-Object -Skip 1)
    $sections += @(Get-GpoDetailsSections -Server $Server)
    $sections += Get-ChangeLogSection -Server $Server
    return (New-DetailsHtml -Title "Health: $Server" -Subtitle 'every check with its evidence and fix, the SOE comparison, then what the collector read' -Console 'Health' -Facts $facts -Sections $sections)
}

function Export-HealthReport {
    $servers = @(Get-GridAllKeys -Grid $script:Gui['HealthGrid'])
    $summary = @(Get-HealthSummaryRows -Servers $servers)
    $checkRows = @()
    foreach ($s in $servers) { $h = Get-CollectorResult -Name 'Health' -Server $s; if ($h -and $h.Reachable) { $checkRows += @(Get-CheckRows -Console 'Health' -Server $s) } }
    $soeRows = @(Get-SoeComplianceRows -Servers $servers)   # every shown server that has a standard and has been checked
    $notes = @("Window: $($script:Config.LogonFailWindowHours) h for logons and lockouts, $($script:Config.EventWindowHours) h for event-log errors; thresholds as set on the Settings tab (Health).")
    if ($soeRows.Count -gt 0) { $notes += 'SOE comparison included: standard(s) ' + ((@($soeRows | ForEach-Object { $_.Standard } | Select-Object -Unique) | ForEach-Object { "'$_'" }) -join ', ') }
    $gpoRows = @(foreach ($s in $servers) { foreach ($r in @(Get-GpoRows -Server $s)) { [pscustomobject]@{ Server = $s; Order = $r.Order; GPO = $r.GPO; Status = $r.Status; 'Linked at' = $r.LinkedAt; Version = $r.Version } } })
    # what needs attention first (the list under the divider), with every server named
    $attention = @(Get-HealthAttentionRows -Servers $servers | ForEach-Object { [pscustomobject]@{ Level = $_.Level; Item = $_.Item; Servers = $_.Servers; Which = (@($_.Members) -join ', '); Example = $_.Example; Light = $(switch ($_.Level) { 'Critical' { 'Red' } 'Unreachable' { 'Red' } 'Warning' { 'Amber' } default { 'Grey' } }) } })
    $cap = Get-HealthCapacityFigures -Servers $servers
    foreach ($m in @(@('Processor busy', 'Cpu'), @('Memory used', 'Memory'), @('Disk used (fullest volume)', 'Disk'))) {
        $fg = $cap.($m[1])
        if ($null -ne $fg.Max) { $notes += ('{0}: {1}% to {2}%, average {3}%, highest on {4}; {5} warning, {6} critical' -f $m[0], [int][math]::Round($fg.Min), [int][math]::Round($fg.Max), [int][math]::Round($fg.Avg), $fg.Worst, $fg.Warning, $fg.Critical) }
    }
    return (Export-ConsoleReport -Console 'Health' -Title 'Health report' -Summary $summary -SummaryColumns @('Server', 'Group', 'Light', 'Red', 'Amber', 'Green', 'Services', 'Tasks', 'Failed logons', 'Lockouts', 'Dormant', 'SOE', 'GPO', 'CPU', 'RAM used', 'Disk free (min)', 'Up (d)', 'Errors', 'Clock', 'Worst') -Notes $notes -Sections @(
        @{ Name = 'Needs attention'; Rows = $attention; Columns = @('Level', 'Item', 'Servers', 'Which', 'Example') },
        @{ Name = 'Checks'; Rows = $checkRows; Columns = @('Server', 'Id', 'Group', 'Title', 'Verdict', 'Light', 'Evidence', 'Fix') },
        @{ Name = 'SOE compliance'; Rows = $soeRows; Columns = @('Server', 'Standard', 'Type', 'Name', 'Expected', 'Actual', 'Verdict', 'Light', 'Note') },
        @{ Name = 'Group Policy'; Rows = $gpoRows; Columns = @('Server', 'Order', 'GPO', 'Status', 'Linked at', 'Version') }))
}

# ---------------------------------------------------------------------
#  THE SUMMARY under the server grid (behind a divider): three dials -
#  processor % busy, memory % in use, disk % used of each server's
#  fullest volume - and NEEDS ATTENTION, every check red or amber on a
#  server shown.  It reads the last "Check health"; nothing talks to a
#  server.  Each server's band on a dial is its own check's verdict
#  (H-CPU-01, H-MEM-01, H-DSK-01), so the dials and the grid agree.
# ---------------------------------------------------------------------
# A server's dot and the counts: green = within the thresholds (all clear, as in the grid), amber = warning,
# red = critical, grey = no reading.  The dial's zones are pale versions of the same.
$script:HealthBandColours = [ordered]@{ OK = '#2E8B57'; Warning = '#D4A017'; Critical = '#C0392B'; NotRead = '#A9A9A9' }
$script:HealthBandLabels = [ordered]@{ OK = 'Within'; Warning = 'Warning'; Critical = 'Critical'; NotRead = 'No reading' }
$script:HealthZoneColours = @{ OK = '#D5ECDC'; Warning = '#F7E5A8'; Critical = '#F4C7C7' }
# The attention list colours one cell, the word in it (column 1) says the same
$script:HealthLevelCells = @{ Critical = 'LightCoral'; Unreachable = 'LightCoral'; Warning = 'Khaki'; 'Not checked' = 'Gainsboro' }

function ConvertTo-HealthNumber {
    # A collector figure as a number, or $null when there is none.  Numbers arrive as numbers; text (the fields of a
    # disk line, written invariantly by the collector) is read the invariant way - the one way every reader uses.
    param($Value)
    if ($Value -is [double] -or $Value -is [int] -or $Value -is [long] -or $Value -is [single] -or $Value -is [decimal]) { return [double]$Value }
    $v = 0.0
    if ([double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v)) { return $v }
    return $null
}

function Format-HealthPercent {
    # "12%" for a grid cell; -Invert turns "% free" into "% used".  Empty when nothing was read.
    param($Value, [switch]$Invert)
    $v = ConvertTo-HealthNumber $Value
    if ($null -eq $v) { return '' }
    if ($Invert) { $v = 100 - $v }
    return ('{0}%' -f [int][math]::Round($v))
}

function Get-ShortServerName {
    # "srv01" for "srv01.corp.local" (an IP address stays whole) - lists of many servers stay readable
    param([string]$Name)
    if ($Name -match '^\d+\.\d+\.\d+\.\d+$') { return $Name }
    return ($Name -split '\.')[0]
}

function Get-HealthThresholds {
    # Where each dial turns amber and red, in the dial's own unit (% busy, % used).  Fail is $null for the disk: its
    # critical limit is a size (DiskFailGB free), not a percentage.  Text = the limits as the Settings tab words them.
    $cfg = $script:Config
    return @{
        Cpu    = @{ Warn = [double]$cfg.CpuWarnPercent; Fail = [double]$cfg.CpuFailPercent; Text = ('warning at {0}% busy, critical at {1}%' -f $cfg.CpuWarnPercent, $cfg.CpuFailPercent) }
        Memory = @{ Warn = 100.0 - $cfg.MemoryWarnPercent; Fail = 100.0 - $cfg.MemoryFailPercent; Text = ('warning below {0}% free, critical below {1}%' -f $cfg.MemoryWarnPercent, $cfg.MemoryFailPercent) }
        Disk   = @{ Warn = 100.0 - $cfg.DiskWarnPercent; Fail = $null; Text = ('warning below {0}% free, critical below {1} GB' -f $cfg.DiskWarnPercent, $cfg.DiskFailGB) }
    }
}

function Get-HealthCapacity {
    # One server's three readings and the band its check gave each: OK (pass), Warning (warn), Critical (fail) or NotRead
    # (no reading: not checked, unreachable, or the figure was not read).
    param([string]$Server)
    $out = [pscustomobject]@{ Server = $Server; Checked = $false; Cpu = $null; Memory = $null; Disk = $null; DiskDrive = ''; CpuBand = 'NotRead'; MemoryBand = 'NotRead'; DiskBand = 'NotRead' }
    $h = Get-CollectorResult -Name 'Health' -Server $Server
    if (-not $h -or -not $h.Reachable) { return $out }
    $out.Checked = $true
    $out.Cpu = ConvertTo-HealthNumber $h.CpuPercent
    $free = ConvertTo-HealthNumber $h.MemoryFreePct
    if ($null -ne $free) { $out.Memory = 100 - $free }
    foreach ($line in @($h.Disks)) {
        $f = ([string]$line) -split '\|'
        if ($f.Count -lt 4) { continue }
        $pct = ConvertTo-HealthNumber $f[3]
        if ($null -ne $pct -and ($null -eq $out.Disk -or (100 - $pct) -gt $out.Disk)) { $out.Disk = 100 - $pct; $out.DiskDrive = $f[0] }
    }
    $verdicts = @{}
    foreach ($r in @(Get-CheckRows -Console 'Health' -Server $Server)) { if ($r.Id -in 'H-CPU-01', 'H-MEM-01', 'H-DSK-01') { $verdicts[$r.Id] = [string]$r.Verdict } }
    foreach ($pair in @(@('Cpu', 'H-CPU-01'), @('Memory', 'H-MEM-01'), @('Disk', 'H-DSK-01'))) {
        if ($null -eq $out.($pair[0])) { continue }
        $out.($pair[0] + 'Band') = switch ($verdicts[$pair[1]]) { 'Pass' { 'OK' } 'Warn' { 'Warning' } 'Fail' { 'Critical' } default { 'NotRead' } }
    }
    return $out
}

function Get-HealthCapacityFigures {
    # The three readings across servers.  Per dial: the servers by band, every reading (Values: Server, Value, Band,
    # Drive), the lowest, highest and average, and the server with the highest.
    param([string[]]$Servers)
    $caps = @(foreach ($s in @($Servers)) { Get-HealthCapacity -Server $s })
    $figs = @{}
    foreach ($m in 'Cpu', 'Memory', 'Disk') {
        $fig = [pscustomobject]@{ OK = 0; Warning = 0; Critical = 0; NotRead = 0; Values = @(); Min = $null; Max = $null; Avg = $null; Worst = ''; WorstDrive = '' }
        $vals = New-Object System.Collections.Generic.List[object]
        foreach ($cap in $caps) {
            $band = $cap.($m + 'Band')
            $fig.$band++
            if ($null -ne $cap.$m) { $vals.Add([pscustomobject]@{ Server = $cap.Server; Value = [double]$cap.$m; Band = $band; Drive = $(if ($m -eq 'Disk') { $cap.DiskDrive } else { '' }) }) }
        }
        if ($vals.Count -gt 0) {
            $stats = $vals | Measure-Object -Property Value -Minimum -Maximum -Average
            $fig.Min = $stats.Minimum; $fig.Max = $stats.Maximum; $fig.Avg = $stats.Average
            $top = @($vals | Sort-Object Value -Descending)[0]
            $fig.Worst = $top.Server; $fig.WorstDrive = $top.Drive
        }
        $fig.Values = $vals.ToArray()
        $figs[$m] = $fig
    }
    return [pscustomobject]@{ Cpu = $figs['Cpu']; Memory = $figs['Memory']; Disk = $figs['Disk']; Servers = $caps.Count; Checked = @($caps | Where-Object { $_.Checked }).Count }
}

function New-HealthGauge {
    # One dial as a bitmap: 270 degrees from 0 to 100%, its zones pale green / amber / red from the thresholds (the value
    # at each tick), the range of the readings as a dark band inside, a dot per server in its band's colour (critical
    # drawn last, on top; smaller dots for a big fleet), the highest reading in the middle with its server, then the
    # range and the servers by band.
    param([string]$Title, [string]$Subtitle, $Figure, $Limits, [int]$Size = 220)
    $sc = $Size / 250.0
    $w = $Size; $h = [int](272 * $sc)
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    try {
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
        $g.Clear([System.Drawing.Color]::White)
        $centre = New-Object System.Drawing.StringFormat; $centre.Alignment = 'Center'; $centre.LineAlignment = 'Center'; $centre.Trimming = 'EllipsisCharacter'; $centre.FormatFlags = 'NoWrap'
        $left = New-Object System.Drawing.StringFormat; $left.LineAlignment = 'Center'; $left.Trimming = 'EllipsisCharacter'; $left.FormatFlags = 'NoWrap'
        $titleFont = New-Object System.Drawing.Font('Segoe UI', [single]([math]::Max(7, 10.5 * $sc)), [System.Drawing.FontStyle]::Bold)
        $small = New-Object System.Drawing.Font('Segoe UI', [single]([math]::Max(7, 8.6 * $sc)))
        $big = New-Object System.Drawing.Font('Segoe UI', [single]([math]::Max(10, 21 * $sc)), [System.Drawing.FontStyle]::Bold)
        $dark = [System.Drawing.Brushes]::Black; $grey = [System.Drawing.Brushes]::DimGray
        $g.DrawString($Title, $titleFont, $dark, (New-Object System.Drawing.RectangleF(0, [single](2 * $sc), $w, [single](22 * $sc))), $centre)
        $g.DrawString($Subtitle, $small, $grey, (New-Object System.Drawing.RectangleF(0, [single](22 * $sc), $w, [single](16 * $sc))), $centre)

        # the dial: zones on the ring, angle = 135 + 270 x value / 100 (0% bottom left, 100% bottom right)
        $dia = 170 * $sc; $thick = 18 * $sc
        $cx = $w / 2.0; $cy = 44 * $sc + $dia / 2
        $r = $dia / 2 - $thick / 2
        $ring = New-Object System.Drawing.RectangleF([single]($cx - $r), [single]($cy - $r), [single](2 * $r), [single](2 * $r))
        $warn = [double]$Limits.Warn
        $zones = @(, @(0.0, $warn, 'OK'))
        if ($null -ne $Limits.Fail) { $zones += , @($warn, [double]$Limits.Fail, 'Warning'); $zones += , @([double]$Limits.Fail, 100.0, 'Critical') } else { $zones += , @($warn, 100.0, 'Warning') }
        foreach ($z in $zones) {
            if ($z[1] -le $z[0]) { continue }
            $pen = New-Object System.Drawing.Pen([System.Drawing.ColorTranslator]::FromHtml($script:HealthZoneColours[$z[2]]), [single]$thick)
            $g.DrawArc($pen, $ring, [single](135 + 270 * $z[0] / 100), [single](270 * ($z[1] - $z[0]) / 100))
            $pen.Dispose()
        }
        # the thresholds: a tick across the ring and the value outside it
        $tickPen = New-Object System.Drawing.Pen([System.Drawing.Color]::Gray, [single](1.5 * $sc))
        foreach ($t in @($Limits.Warn, $Limits.Fail)) {
            if ($null -eq $t) { continue }
            $a = (135 + 270 * [double]$t / 100) * [math]::PI / 180
            $g.DrawLine($tickPen, [single]($cx + ($r - $thick / 2 - 2) * [math]::Cos($a)), [single]($cy + ($r - $thick / 2 - 2) * [math]::Sin($a)), [single]($cx + ($r + $thick / 2 + 2) * [math]::Cos($a)), [single]($cy + ($r + $thick / 2 + 2) * [math]::Sin($a)))
            $lx = $cx + ($r + $thick / 2 + 12 * $sc) * [math]::Cos($a); $ly = $cy + ($r + $thick / 2 + 12 * $sc) * [math]::Sin($a)
            $g.DrawString(('{0}%' -f [int]$t), $small, $grey, (New-Object System.Drawing.RectangleF([single]($lx - 18 * $sc), [single]($ly - 8 * $sc), [single](36 * $sc), [single](16 * $sc))), $centre)
        }
        $tickPen.Dispose()
        $vals = @($Figure.Values)
        if ($vals.Count -gt 0) {
            # the range of the readings, inside the ring
            $ri = $r - $thick / 2 - 6 * $sc
            $inner = New-Object System.Drawing.RectangleF([single]($cx - $ri), [single]($cy - $ri), [single](2 * $ri), [single](2 * $ri))
            $rangePen = New-Object System.Drawing.Pen([System.Drawing.Color]::DimGray, [single](5 * $sc))
            $from = 135 + 270 * [math]::Max(0, [math]::Min(100, $Figure.Min)) / 100
            $sweep = [math]::Max(1.5, 270 * ([math]::Min(100, $Figure.Max) - [math]::Max(0, $Figure.Min)) / 100)
            $g.DrawArc($rangePen, $inner, [single]$from, [single]$sweep)
            $rangePen.Dispose()
            # a dot per server on the ring - smaller as the fleet grows, so hundreds stay a readable band
            $dot = $(if ($vals.Count -le 40) { 9 } elseif ($vals.Count -le 150) { 7 } else { 5 }) * $sc
            $edge = New-Object System.Drawing.Pen([System.Drawing.Color]::White, [single]([math]::Max(0.75, $dot / 6)))
            foreach ($band in 'NotRead', 'OK', 'Warning', 'Critical') {
                $brush = New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml($script:HealthBandColours[$band]))
                foreach ($v in @($vals | Where-Object { $_.Band -eq $band })) {
                    $a = (135 + 270 * [math]::Max(0, [math]::Min(100, $v.Value)) / 100) * [math]::PI / 180
                    $dx = $cx + $r * [math]::Cos($a) - $dot / 2; $dy = $cy + $r * [math]::Sin($a) - $dot / 2
                    $g.FillEllipse($brush, [single]$dx, [single]$dy, [single]$dot, [single]$dot)
                    $g.DrawEllipse($edge, [single]$dx, [single]$dy, [single]$dot, [single]$dot)
                }
                $brush.Dispose()
            }
            $edge.Dispose()
            # the highest reading and its server in the middle
            $who = Get-ShortServerName $Figure.Worst; if ($Figure.WorstDrive) { $who += ' ' + $Figure.WorstDrive }
            $g.DrawString(('{0}%' -f [int][math]::Round($Figure.Max)), $big, $dark, (New-Object System.Drawing.RectangleF([single]($cx - 60 * $sc), [single]($cy - 24 * $sc), [single](120 * $sc), [single](34 * $sc))), $centre)
            $g.DrawString('highest', $small, $grey, (New-Object System.Drawing.RectangleF([single]($cx - 60 * $sc), [single]($cy + 9 * $sc), [single](120 * $sc), [single](14 * $sc))), $centre)
            $g.DrawString($who, $small, $dark, (New-Object System.Drawing.RectangleF([single]($cx - 56 * $sc), [single]($cy + 23 * $sc), [single](112 * $sc), [single](15 * $sc))), $centre)
            $range = 'range {0}% to {1}%, average {2}%' -f [int][math]::Round($Figure.Min), [int][math]::Round($Figure.Max), [int][math]::Round($Figure.Avg)
        } else {
            $g.DrawString('n/a', $big, $grey, (New-Object System.Drawing.RectangleF([single]($cx - 60 * $sc), [single]($cy - 20 * $sc), [single](120 * $sc), [single](34 * $sc))), $centre)
            $range = 'no reading yet'
        }
        # under the dial: the range, then the servers by band, two by two
        $y = $cy + $r + $thick / 2 + 2 * $sc
        $g.DrawString($range, $small, $dark, (New-Object System.Drawing.RectangleF(0, [single]$y, $w, [single](16 * $sc))), $centre)
        $y += 19 * $sc
        $i = 0
        foreach ($band in @($script:HealthBandColours.Keys)) {
            $x = 16 * $sc + ($i % 2) * ($w / 2.0 - 2 * $sc); $ly = $y + [math]::Floor($i / 2) * 17 * $sc
            $brush = New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml($script:HealthBandColours[$band]))
            $g.FillEllipse($brush, [single]$x, [single]($ly + 3.5 * $sc), [single](9 * $sc), [single](9 * $sc)); $brush.Dispose()
            $g.DrawString(('{0}: {1}' -f $script:HealthBandLabels[$band], [int]$Figure.$band), $small, $dark, (New-Object System.Drawing.RectangleF([single]($x + 13 * $sc), [single]$ly, [single]($w / 2.0 - 24 * $sc), [single](16 * $sc))), $left)
            $i++
        }
    } finally {
        foreach ($o in @($titleFont, $small, $big, $centre, $left)) { if ($o) { $o.Dispose() } }   # three dials a repaint: GDI+ objects must not pile up
        $g.Dispose()
    }
    return $bmp
}

function New-HealthAttentionRow {
    # One line of the attention list.  Members (critical servers first) / Id / Order ride along for the details page and
    # the sort.  Where lists every server by its short name: the column cuts it with "..." and the tooltip has them all,
    # so a line about 3 servers and one about 300 read the same way.
    param([string]$Id, [string]$Level, [string]$Item, [string[]]$Members, [int]$Of, [string]$Example, [int]$Order)
    $short = @($Members | ForEach-Object { Get-ShortServerName $_ })
    $where = (@($short | Select-Object -First 40) -join ', ')
    if ($short.Count -gt 40) { $where += ', ...' }
    return [pscustomobject]@{
        Level = $Level; Item = $Item; Servers = ('{0} of {1}' -f @($Members).Count, $Of); Where = $where; Example = $Example
        Id = $Id; Members = @($Members); Count = @($Members).Count; Order = $Order
        Cells = @{ Level = $script:HealthLevelCells[$Level] }; Tip = ('{0}: {1}' -f $Item, (@($short) -join ', '))
    }
}

function Get-HealthAttentionRows {
    # What needs the sysadmin's attention on these servers: one row per check that is red or amber on at least one of
    # them (critical when any server has it red; its critical servers listed first), and the servers that could not be
    # read - a server nobody can check is a blind spot.  Checks that could not run at all (a collector missing or
    # refused) are one row, not one row each.  Order: critical, unreachable, warning, not checked; within each, the most
    # servers first.
    param([string[]]$Servers)
    $byId = [ordered]@{}; $unreach = @(); $never = @(); $noRun = @(); $checked = 0
    foreach ($s in @($Servers)) {
        $h = Get-CollectorResult -Name 'Health' -Server $s
        if (-not $h) { $never += $s; continue }
        if (-not $h.Reachable) { $unreach += [pscustomobject]@{ Server = $s; Error = [string]$h.Error }; continue }
        $checked++
        foreach ($r in @(Get-CheckRows -Console 'Health' -Server $s)) {
            if ($r.Light -notin 'Red', 'Amber') { continue }
            if ($r.Verdict -eq 'Error') { $noRun += $r; continue }
            if (-not $byId.Contains($r.Id)) { $byId[$r.Id] = New-Object System.Collections.Generic.List[object] }
            $byId[$r.Id].Add($r)
        }
    }
    $rows = @()
    foreach ($id in @($byId.Keys)) {
        $hits = $byId[$id].ToArray()
        $red = @($hits | Where-Object { $_.Light -eq 'Red' })
        $first = $(if ($red.Count -gt 0) { $red[0] } else { $hits[0] })
        $level = $(if ($red.Count -gt 0) { 'Critical' } else { 'Warning' })
        $members = @($red | ForEach-Object { $_.Server }) + @($hits | Where-Object { $_.Light -ne 'Red' } | ForEach-Object { $_.Server })
        $rows += New-HealthAttentionRow -Id $id -Level $level -Item $first.Title -Members $members -Of $checked -Example ((Get-ShortServerName $first.Server) + ': ' + $first.Summary) -Order $(if ($level -eq 'Critical') { 0 } else { 2 })
    }
    if ($noRun.Count -gt 0) {
        $who = @(Get-UniqueNames @($noRun | ForEach-Object { $_.Server }))
        $rows += New-HealthAttentionRow -Id 'couldnotrun' -Level 'Warning' -Item 'Checks that could not run' -Members $who -Of $checked -Example ('{0}: {1} check(s) - {2}' -f (Get-ShortServerName $noRun[0].Server), @($noRun | Where-Object { $_.Server -eq $noRun[0].Server }).Count, $noRun[0].Evidence) -Order 2
    }
    if ($unreach.Count -gt 0) { $rows += New-HealthAttentionRow -Id 'unreachable' -Level 'Unreachable' -Item 'Could not be reached (WinRM 5985)' -Members @($unreach | ForEach-Object { $_.Server }) -Of @($Servers).Count -Example ((Get-ShortServerName $unreach[0].Server) + ': ' + $unreach[0].Error) -Order 1 }
    if ($never.Count -gt 0) { $rows += New-HealthAttentionRow -Id 'notchecked' -Level 'Not checked' -Item 'Not checked yet' -Members $never -Of @($Servers).Count -Example 'press "Check health (ticked, or all)"' -Order 3 }
    return @($rows | Sort-Object -Property @{ Expression = 'Order'; Ascending = $true }, @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Item'; Ascending = $true })
}

function Get-HealthAttentionHtml {
    # The double-click page of one finding: every server it is on with what was found, why it matters and how to fix it.
    param([string]$Id, [string[]]$Servers)
    if ($Id -in 'unreachable', 'notchecked') {
        $rows = @(foreach ($s in $Servers) { $h = Get-CollectorResult -Name 'Health' -Server $s; [pscustomobject]@{ Server = $s; State = $(if (-not $h) { 'not checked yet' } else { 'unreachable: ' + [string]$h.Error }) } })
        $what = $(if ($Id -eq 'unreachable') { 'Could not be reached (WinRM 5985)' } else { 'Not checked yet' })
        $lines = @('A server without a reading is a blind spot: nothing on this page or in the dials covers it.', 'Unreachable: check that the server is up, that WinRM answers on port 5985 (the O/S Patching console''s status check shows the error in full), and that the account may connect.', 'Not checked yet: tick the servers and press "Check health (ticked, or all)".')
        return (New-DetailsHtml -Title ('Needs attention: ' + $what) -Console 'Health' -Facts @(@('Servers', [string]@($Servers).Count)) -Sections @(@{ Heading = 'Servers'; Rows = $rows; Columns = @('Server', 'State') }, @{ Heading = 'What to do'; Lines = $lines }))
    }
    if ($Id -eq 'couldnotrun') {
        $rows = @(foreach ($s in $Servers) { foreach ($r in @(Get-CheckRows -Console 'Health' -Server $s | Where-Object { $_.Verdict -eq 'Error' })) { [pscustomobject]@{ Server = $s; Check = ('{0} {1}' -f $r.Id, $r.Title); Reason = $r.Evidence } } })
        $lines = @('These checks have no verdict on these servers, so they are neither clear nor failing.', '"collector not available": that collector did not run or was refused on the server - press "Check health (ticked, or all)", which runs every collector, and look at the log for the error (often access denied).', 'Anything else is a check that broke on the data it was given - the Reason says what; report it with the server''s details page.')
        return (New-DetailsHtml -Title 'Needs attention: checks that could not run' -Console 'Health' -Facts @(@('Servers', [string]@($Servers).Count)) -Sections @(@{ Heading = 'Checks without a verdict'; Rows = $rows; Columns = @('Server', 'Check', 'Reason') }, @{ Heading = 'What to do'; Lines = $lines }))
    }
    $chk = @(Get-Checks -Console 'Health' | Where-Object { $_.Id -eq $Id })[0]
    $rows = @(foreach ($s in $Servers) {
        $r = @(Get-CheckRows -Console 'Health' -Server $s | Where-Object { $_.Id -eq $Id })[0]
        if (-not $r -or $r.Light -notin 'Red', 'Amber') { continue }
        [pscustomobject]@{ Light = $r.Light; Level = $(if ($r.Light -eq 'Red') { 'Critical' } else { 'Warning' }); Server = $s; Found = $r.Summary; Details = (@($r.Items) -join '; '); Sort = $(if ($r.Light -eq 'Red') { 0 } else { 1 }) }
    })
    $rows = @($rows | Sort-Object Sort, Server)
    $sections = @(@{ Heading = 'Where'; Rows = $rows; Columns = @('Level', 'Server', 'Found', 'Details') })
    $advice = @()
    if ($chk.Why) { $advice += 'Why it matters: ' + $chk.Why }
    if ($chk.Fix) { $advice += 'How to fix: ' + $chk.Fix }
    if ($advice.Count -gt 0) { $sections += @{ Heading = 'What to do'; Lines = $advice } }
    $facts = @(@('Check', $Id), @('Servers', ('{0} ({1} critical)' -f $rows.Count, @($rows | Where-Object { $_.Light -eq 'Red' }).Count)))
    return (New-DetailsHtml -Title ('Needs attention: ' + $chk.Title) -Subtitle 'every server shown with this finding, critical first; double-click a server in the grid for all of its checks' -Console 'Health' -Facts $facts -Sections $sections)
}

function Update-HealthDashboard {
    # Repaints the three dials and the attention list for the servers shown in the grid.
    param([string[]]$Servers)
    if (-not $script:Gui['HealthDashCpu']) { return }
    $fig = Get-HealthCapacityFigures -Servers $Servers
    $lim = Get-HealthThresholds
    foreach ($d in @(@('HealthDashCpu', 'Processor', 'busy', 'Cpu', 'Processor busy on each server shown, a few seconds averaged at the last check (H-CPU-01) - a snapshot: check again before acting'), @('HealthDashMem', 'Memory', 'in use', 'Memory', 'Physical memory in use on each server shown (H-MEM-01)'), @('HealthDashDisk', 'Disk', 'used, fullest volume', 'Disk', 'Space used on the fullest volume of each server shown (H-DSK-01); a volume under the GB limit is critical whatever its percentage'))) {
        $box = $script:Gui[$d[0]]; $old = $box.Image
        $box.Image = New-HealthGauge -Title $d[1] -Subtitle $d[2] -Figure $fig.($d[3]) -Limits $lim[$d[3]]
        if ($old) { $old.Dispose() }
        # what the dial does not spell out: the thresholds in words, and that every dot is a server in its check's colour
        $script:Gui['Tips'].SetToolTip($box, ('{0}. Thresholds: {1} (Settings tab). A dot per server in its check''s colour; the dark band is the lowest to the highest reading.' -f $d[4], $lim[$d[3]].Text))
    }
    $rows = @(Get-HealthAttentionRows -Servers $Servers)
    Set-GridRows -Grid $script:Gui['HealthAttention'] -Rows $rows -NoKeepChecks -ToolTipProperty 'Tip' -CellColourProperty 'Cells'
    $crit = @($rows | Where-Object { $_.Level -in 'Critical', 'Unreachable' }).Count; $warn = @($rows | Where-Object { $_.Level -eq 'Warning' }).Count
    $script:Gui['HealthAttentionHead'].Text = $(if ($rows.Count -eq 0) { 'all clear' } else { '{0} critical, {1} warning' -f $crit, $warn })
    $script:Gui['HealthDashInfo'].Text = ('{0} of {1} server(s) read' -f $fig.Checked, $fig.Servers)
}

function New-HealthDashboard {
    # The summary under the Health server grid (Panel2 of the Health checks page's divider): the dials on the left, the
    # attention list on the right, each under a heading strip like the grid's.
    param($Panel)
    $left = New-Object System.Windows.Forms.Panel; $left.Dock = 'Left'; $left.Width = 684
    $sh = New-GridHeader -Heading 'SUMMARY' -Detail '' -Tip 'Processor, memory and disk across the servers shown, from the last "Check health". Hover a dial for its thresholds.'
    $dials = New-Object System.Windows.Forms.FlowLayoutPanel; $dials.Dock = 'Fill'; $dials.WrapContents = $false; $dials.AutoScroll = $true; $dials.BackColor = 'White'
    foreach ($key in 'HealthDashCpu', 'HealthDashMem', 'HealthDashDisk') {
        $pic = New-Object System.Windows.Forms.PictureBox; $pic.Size = New-Object System.Drawing.Size(220, 240); $pic.SizeMode = 'Normal'
        $dials.Controls.Add($pic); $script:Gui[$key] = $pic
    }
    $left.Controls.AddRange(@($dials, $sh.Panel)); $dials.BringToFront()
    $right = New-Object System.Windows.Forms.Panel; $right.Dock = 'Fill'
    $att = New-ConsoleGrid -NoCheckBoxes -Columns @(@{ Name = 'Level'; Width = 80 }, @{ Name = 'Item'; Width = 230 }, @{ Name = 'Servers'; Width = 75 }, @{ Name = 'Where'; Width = 210 }, @{ Name = 'Example'; Width = 380; Fill = $true })
    $att.Add_DoubleClick({   # $this = the list; the row carries the finding's id and its servers
        if ($script:Gui['Busy']) { Write-PatchLog 'Busy - details are available again when the current action finishes' 'WARN'; return }
        if ($this.SelectedItems.Count -gt 0) { $row = $this.SelectedItems[0].Tag; if ($row) { Show-DetailsWindow -Title ('Needs attention: ' + $row.Item) -Html (Get-HealthAttentionHtml -Id $row.Id -Servers @($row.Members)) } }
    })
    $ah = New-GridHeader -Heading 'NEEDS ATTENTION' -Detail '' -Tip 'Every check that is red (critical) or amber (warning) on a server shown, and the servers that could not be read - critical first, then the most servers. Hover a line for every server; double-click it for each server''s finding and the fix.'
    $right.Controls.AddRange(@($att, $ah.Panel)); $att.BringToFront()
    $Panel.Controls.AddRange(@($right, $left)); $right.BringToFront()
    $script:Gui['HealthDashPics'] = $dials; $script:Gui['HealthAttention'] = $att; $script:Gui['HealthAttentionHead'] = $ah.Info; $script:Gui['HealthDashInfo'] = $sh.Info
}

# ---------------------------------------------------------------------
#  The tab
# ---------------------------------------------------------------------
function Update-HealthGrid {
    $grid = $script:Gui['HealthGrid']
    if (-not $grid) { return }
    $servers = @(Get-GroupRows -Combo $script:Gui['HealthGroupCombo'] | ForEach-Object { $_.Server })
    $names = @(Get-UniqueNames $servers)
    $rows = @(Get-HealthSummaryRows -Servers $names)
    Set-GridRows -Grid $grid -Rows $rows -RowColour { param($r) Get-LightColour $r.Light } -ToolTipProperty 'Worst'
    $script:Gui['HealthCount'].Text = ('{0} server(s), {1} red, {2} amber' -f $rows.Count, @($rows | Where-Object { $_.Light -eq 'Red' }).Count, @($rows | Where-Object { $_.Light -eq 'Amber' }).Count)
    Update-HealthDashboard -Servers $names
}

function Update-HealthGpoPage {
    # The Group Policy page: the GPOs across the servers shown, then one row per server.
    $grid = $script:Gui['GpoGrid']
    if (-not $grid) { return }
    $servers = @(Get-UniqueNames (Get-GroupRows -Combo $script:Gui['HealthGroupCombo'] | ForEach-Object { $_.Server }))
    $fleet = @(Get-GpoFleetRows -Servers $servers)
    Set-GridRows -Grid $grid -Rows $fleet -NoKeepChecks -ToolTipProperty 'Not applied on' -RowColour { param($r) if ([int]$r.Applied -eq 0) { 'WhiteSmoke' } else { '' } }
    $collected = @($servers | Where-Object { Get-CollectorResult -Name 'Gpo' -Server $_ }).Count
    $script:Gui['GpoHead'].Text = $(if ($collected -eq 0) { 'nothing collected yet - press "Check health" on the Health checks page' } else { '{0} GPO(s) on {1} of {2} server(s) read' -f $fleet.Count, $collected, $servers.Count })
    $rows = @(Get-GpoServerRows -Servers $servers)
    Set-GridRows -Grid $script:Gui['GpoServerGrid'] -Rows $rows -NoKeepChecks -RowColour { param($r) Get-LightColour $r.Light } -ToolTipProperty 'Note'
    $script:Gui['GpoServerHead'].Text = ('{0} server(s): {1} red, {2} amber' -f $rows.Count, @($rows | Where-Object { $_.Light -eq 'Red' }).Count, @($rows | Where-Object { $_.Light -eq 'Amber' }).Count)
}

function Update-SoeItemsGrid {
    $grid = $script:Gui['SoeItemsGrid']
    if (-not $grid) { return }
    $std = $script:Gui['SoeStandard']
    $rows = @()
    if ($std) {
        foreach ($it in @($std.items)) {
            $rule = ''
            $where = ''
            switch ([string]$it.type) {
                'agent' { $rule = $it.version; if ($it.mustRun) { $rule += ' (must run)' } }
                'software' { $rule = $it.version }
                'feature' { $rule = $it.state }
                'service' { $rule = (@($it.startType, $it.state) | Where-Object { $_ }) -join ', ' }
                'setting' { $rule = '= ' + $it.expected; $where = [string]$it.key }
                'registry' { $rule = '= ' + $it.expected; $where = '{0} > {1}' -f $it.path, $it.key }
                'file' { $rule = '= ' + $it.expected; $where = '{0} > {1}' -f $it.path, $it.key }
                'forbidden' { $rule = 'must be absent' }
            }
            $name = [string]$it.name; if (-not $name) { $name = [string]$it.key }
            $rows += [pscustomobject]@{ Type = $it.type; Name = $name; Rule = $rule; Where = $where; Required = $it.required; Source = $it.source; Note = $it.note; Item = $it }
        }
    }
    Set-GridRows -Grid $grid -Rows $rows -NoKeepChecks
    $label = 'No standard selected'
    if ($std) {
        $users = @(); $userGroups = @()
        foreach ($g in @($script:Groups)) { foreach ($s in @($g.Servers)) { if ((Get-SoeStandardNameForServer -Server $s) -ieq $std.name) { $users += $s; if ($userGroups -notcontains $g.Name) { $userGroups += $g.Name } } } }
        $usedBy = 'no servers yet'
        if ($users.Count -gt 0) { $usedBy = ('{0} server(s) in {1}' -f $users.Count, ($userGroups -join ', ')) }
        $label = ('{0}  |  {1} item(s)  |  saved {2}  |  {3}' -f $std.name, @($std.items).Count, $std.updated, $usedBy)
        if ($std.description) { $label += '  |  ' + $std.description }
    }
    $script:Gui['SoeLabel'].Text = $label
}

function Update-SoeConfigPointsGrid {
    # The catalogue of configuration points with the value the reference server returned for each.
    $grid = $script:Gui['SoeConfigGrid']
    if (-not $grid) { return }
    $combo = $script:Gui['SoeRefCombo']
    $keep = Get-ComboChoice -Combo $combo
    $probed = @()
    if ($script:Results.ContainsKey('Probes')) { $probed = @(Get-UniqueNames @($script:Results['Probes'].Keys | Where-Object { $script:Results['Probes'][$_].Reachable })) }
    # refilling the combo raises its SelectedIndexChanged, whose handler calls this function: the flag stops the loop
    $script:SoeRefFilling = $true
    try {
        $combo.Items.Clear()
        foreach ($s in $probed) { [void]$combo.Items.Add($s) }
        if ($keep -and $combo.Items.Contains($keep)) { $combo.SelectedItem = $keep } elseif ($combo.Items.Count -gt 0) { $combo.SelectedIndex = 0 }
    } finally { $script:SoeRefFilling = $false }
    $ref = Get-ComboChoice -Combo $combo
    $rows = @()
    foreach ($p in @((Get-SoeConfigPoints).Points)) {
        $value = ''
        if ($ref) { $v = Get-ProbeValue -Server $ref -Type $p.Type -Path $p.Path -Key $p.Key; if ($null -ne $v) { $value = $v } else { $value = '(not read - run Check health)' } }
        $rows += [pscustomobject]@{ Point = [string]$p.Name; Type = [string]$p.Type; Where = [string]$p.Path; Key = [string]$p.Key; Value = $value; Note = [string]$p.Note }
    }
    Set-GridRows -Grid $grid -Rows $rows -RowColour { param($r) if ($r.Value -like 'NotConfigured*' -or $r.Value -in 'file missing', 'key missing' -or $r.Value -like '(not read*') { 'WhiteSmoke' } elseif ($r.Value -like 'ERROR:*') { 'MistyRose' } else { 'White' } } -ToolTipProperty 'Note'
}

function Select-SoeStandard {
    param([string]$Name)
    $script:Gui['SoeStandard'] = $null
    if ($Name) { $script:Gui['SoeStandard'] = Read-SoeStandard -Name $Name }
    Update-SoeItemsGrid
}

function Update-SoeStandardCombo {
    $combo = $script:Gui['SoeCombo']
    if (-not $combo) { return }
    $keep = [string]$combo.SelectedItem
    $combo.Items.Clear()
    foreach ($n in (Get-SoeStandardNames)) { [void]$combo.Items.Add($n) }
    if ($keep -and $combo.Items.Contains($keep)) { $combo.SelectedItem = $keep } elseif ($combo.Items.Count -gt 0) { $combo.SelectedIndex = 0 } else { Select-SoeStandard -Name '' }
}

function Show-SoePicker {
    # "Add from server": tick candidates from one scanned server.  Returns the picked candidate rows.
    param([string[]]$Servers)
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Add items from a scanned server'; $dlg.Size = New-Object System.Drawing.Size(1000, 680); $dlg.StartPosition = 'CenterParent'; $dlg.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $top = New-Object System.Windows.Forms.Panel; $top.Dock = 'Top'; $top.Height = 70
    $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = 'Server:'; $lbl.Location = New-Object System.Drawing.Point(10, 12); $lbl.AutoSize = $true
    $combo = New-Object System.Windows.Forms.ComboBox; $combo.Location = New-Object System.Drawing.Point(60, 8); $combo.Width = 260; Set-ComboTypeAhead -Combo $combo
    foreach ($s in $Servers) { [void]$combo.Items.Add($s) }
    $typeLbl = New-Object System.Windows.Forms.Label; $typeLbl.Text = 'Show:'; $typeLbl.Location = New-Object System.Drawing.Point(340, 12); $typeLbl.AutoSize = $true
    $typeCombo = New-Object System.Windows.Forms.ComboBox; $typeCombo.Location = New-Object System.Drawing.Point(385, 8); $typeCombo.Width = 120; $typeCombo.DropDownStyle = 'DropDownList'
    foreach ($t in 'all', 'agent', 'software', 'feature', 'service', 'setting') { [void]$typeCombo.Items.Add($t) }
    $typeCombo.SelectedIndex = 0
    $filter = New-Object System.Windows.Forms.TextBox; $filter.Location = New-Object System.Drawing.Point(520, 8); $filter.Width = 220
    $filterLbl = New-Object System.Windows.Forms.Label; $filterLbl.Text = 'filter'; $filterLbl.Location = New-Object System.Drawing.Point(745, 12); $filterLbl.AutoSize = $true
    $all = New-Object System.Windows.Forms.CheckBox; $all.Text = 'Tick everything shown (whole server as exemplar)'; $all.Location = New-Object System.Drawing.Point(10, 40); $all.AutoSize = $true
    $top.Controls.AddRange(@($lbl, $combo, $typeLbl, $typeCombo, $filter, $filterLbl, $all))
    $grid = New-ConsoleGrid -Columns @(@{ Name = 'Type'; Width = 80 }, @{ Name = 'Name'; Width = 420 }, @{ Name = 'Value'; Width = 240; Fill = $true }, @{ Name = 'Extra'; Width = 200 })
    $bar = New-DialogButtonBar -Dialog $dlg -Buttons @(@{ Text = 'Add ticked items'; Result = 'OK'; Width = 140 }, @{ Text = 'Cancel'; Result = 'Cancel' }) -Hint '0 ticked'
    $ok = $bar.Buttons[0]; $cancel = $bar.Buttons[1]; $count = $bar.Panel.Controls[0]
    $dlg.Controls.Add($grid); $dlg.Controls.Add($top); $grid.BringToFront()
    $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
    $refreshCount = { $n = @($grid.Items | Where-Object { $_.Checked }).Count; $count.Text = ('{0} of {1} ticked - they become rules of the standard and are saved at once' -f $n, $grid.Items.Count) }
    $reload = {
        $rows = @()
        $ref = Get-ComboChoice -Combo $combo; if ($ref) { $rows = @(Get-SoeCandidates -Server $ref) }
        if ($typeCombo.SelectedItem -and $typeCombo.SelectedItem -ne 'all') { $rows = @($rows | Where-Object { $_.Type -eq $typeCombo.SelectedItem }) }
        if ($filter.Text) { $q = $filter.Text; $rows = @($rows | Where-Object { ([string]$_.Name).IndexOf($q, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or ([string]$_.Value).IndexOf($q, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 }) }   # plain text, not a wildcard
        Set-GridRows -Grid $grid -Rows $rows -NoKeepChecks
        if ($all.Checked) { Set-GridChecks -Grid $grid -Checked $true }
        & $refreshCount
    }
    $combo.Add_SelectedIndexChanged($reload); $combo.Add_TextChanged($reload); $typeCombo.Add_SelectedIndexChanged($reload); $filter.Add_TextChanged($reload)
    $all.Add_CheckedChanged({ Set-GridChecks -Grid $grid -Checked $all.Checked; & $refreshCount })
    $grid.Add_ItemChecked({ & $refreshCount })
    if ($combo.Items.Count -gt 0) { $combo.SelectedIndex = 0 }
    $picked = @()
    if ($dlg.ShowDialog($script:Gui['Form']) -eq 'OK') {
        foreach ($i in $grid.Items) { if ($i.Checked) { $picked += [pscustomobject]@{ Server = (Get-ComboChoice -Combo $combo); Candidate = $i.Tag } } }
    }
    $dlg.Dispose()
    return $picked
}

function Show-SoeItemEditor {
    # "Add by hand" / "Edit": a small form for one item.  Returns the item or $null.
    param($Item)
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'SOE item'; $dlg.Size = New-Object System.Drawing.Size(600, 420); $dlg.StartPosition = 'CenterParent'; $dlg.Font = New-Object System.Drawing.Font('Segoe UI', 9); $dlg.FormBorderStyle = 'FixedDialog'
    $y = 14
    $fields = @{}
    foreach ($spec in @(@('type', 'Type: agent, software, forbidden, feature, service, setting, registry, file'), @('name', 'Name (wildcards ok for software)'), @('path', 'Path (registry key or config file; registry / file only)'), @('key', 'Key (setting key; registry value name; file setting or re:<regex>)'), @('expected', 'Expected value (setting / registry / file; * or re:<regex> ok)'), @('version', 'Version rule, e.g. >= 10.7 (agents, software)'), @('startType', 'Start type (services: Auto / Manual / Disabled)'), @('state', 'State (features: Installed/Absent; services: Running/Stopped)'), @('note', 'Note'))) {
        $l = New-Object System.Windows.Forms.Label; $l.Text = $spec[1]; $l.Location = New-Object System.Drawing.Point(12, $y); $l.AutoSize = $true
        $t = New-Object System.Windows.Forms.TextBox; $t.Location = New-Object System.Drawing.Point(330, ($y - 3)); $t.Width = 200
        if ($Item -and $Item.PSObject.Properties[$spec[0]]) { $t.Text = [string]$Item.($spec[0]) }
        $dlg.Controls.Add($l); $dlg.Controls.Add($t); $fields[$spec[0]] = $t
        $y += 30
    }
    $req = New-Object System.Windows.Forms.CheckBox; $req.Text = 'Required (a miss is Red; otherwise Amber)'; $req.Location = New-Object System.Drawing.Point(12, $y); $req.AutoSize = $true; $req.Checked = $true
    if ($Item -and $Item.PSObject.Properties['required'] -and $null -ne $Item.required) { $req.Checked = [bool]$Item.required }
    $run = New-Object System.Windows.Forms.CheckBox; $run.Text = 'Must be running (agents)'; $run.Location = New-Object System.Drawing.Point(330, $y); $run.AutoSize = $true
    if ($Item -and $Item.PSObject.Properties['mustRun']) { $run.Checked = [bool]$Item.mustRun }
    $dlg.Controls.Add($req); $dlg.Controls.Add($run)
    $ok = New-Object System.Windows.Forms.Button; $ok.Text = 'OK'; $ok.Location = New-Object System.Drawing.Point(330, ($y + 36)); $ok.Size = New-Object System.Drawing.Size(95, 30); $ok.DialogResult = 'OK'
    $cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(435, ($y + 36)); $cancel.Size = New-Object System.Drawing.Size(95, 30); $cancel.DialogResult = 'Cancel'
    $dlg.Controls.Add($ok); $dlg.Controls.Add($cancel); $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
    $result = $null
    if ($dlg.ShowDialog($script:Gui['Form']) -eq 'OK') {
        $type = $fields['type'].Text.Trim().ToLower()
        if ($type -notin 'agent', 'software', 'forbidden', 'feature', 'service', 'setting', 'registry', 'file') { $null = Show-PatcherMessage -Text "Type must be one of agent, software, forbidden, feature, service, setting, registry, file (got '$type')" -Icon 'Warning' }
        elseif ($type -in 'registry', 'file' -and -not $fields['path'].Text.Trim()) { $null = Show-PatcherMessage -Text "A $type item needs a Path (the registry key or the configuration file)." -Icon 'Warning' }
        else {
            $src = 'by hand'; if ($Item -and $Item.PSObject.Properties['source'] -and $Item.source) { $src = $Item.source }
            $result = New-SoeItem -Type $type -Name $fields['name'].Text.Trim() -Path $fields['path'].Text.Trim() -Key $fields['key'].Text.Trim() -Expected $fields['expected'].Text -Version $fields['version'].Text.Trim() -StartType $fields['startType'].Text.Trim() -State $fields['state'].Text.Trim() -Required $req.Checked -MustRun $run.Checked -Source $src -Note $fields['note'].Text
            if ($type -eq 'setting' -and -not $result.key) { $result.key = $result.name }
            if (-not $result.name) { $result.name = $result.key }
        }
    }
    $dlg.Dispose()
    return $result
}

function New-HealthConsole {
    param($Tabs)
    $tab = Register-ConsoleTab -Tabs $Tabs -Console 'Health' -Text 'Health'

    $pages = New-Object System.Windows.Forms.TabControl
    $pages.Dock = 'Fill'
    $tab.Controls.Add($pages)
    $pageChecks = New-Object System.Windows.Forms.TabPage; $pageChecks.Text = 'Health checks'
    $pageSoe = New-Object System.Windows.Forms.TabPage; $pageSoe.Text = 'SOE standards'
    $pageGpo = New-Object System.Windows.Forms.TabPage; $pageGpo.Text = 'Group Policy'
    $pages.TabPages.AddRange(@($pageChecks, $pageSoe, $pageGpo))

    # ---- Health checks page ----
    $grid = New-ConsoleGrid -Columns @(@{ Name = 'Server'; Width = 170 }, @{ Name = 'Group'; Width = 100 }, @{ Name = 'Light'; Width = 55 }, @{ Name = 'Checked'; Width = 70 }, @{ Name = 'Red'; Width = 40 }, @{ Name = 'Amber'; Width = 50 }, @{ Name = 'Green'; Width = 50 }, @{ Name = 'Services'; Width = 60 }, @{ Name = 'Tasks'; Width = 50 }, @{ Name = 'Failed logons'; Width = 85 }, @{ Name = 'Lockouts'; Width = 65 }, @{ Name = 'Dormant'; Width = 60 }, @{ Name = 'SOE'; Width = 70 }, @{ Name = 'GPO'; Width = 120 }, @{ Name = 'CPU'; Width = 50 }, @{ Name = 'RAM used'; Width = 70 }, @{ Name = 'Disk free (min)'; Width = 110 }, @{ Name = 'Up (d)'; Width = 50 }, @{ Name = 'Errors'; Width = 55 }, @{ Name = 'Clock'; Width = 75 }, @{ Name = 'Worst'; Width = 420; Fill = $true })
    $grid.Add_DoubleClick({   # $this = the grid; a local such as $grid is gone by the time the event fires
        if ($script:Gui['Busy']) { Write-PatchLog 'Busy - details are available again when the current action finishes' 'WARN'; return }
        if ($this.SelectedItems.Count -gt 0) { $n = $this.SelectedItems[0].Text; Show-DetailsWindow -Title "Health: $n" -Html (Get-HealthDetailsHtml -Server $n) }
    })
    $count = New-Object System.Windows.Forms.Label; $count.Dock = 'Top'; $count.Height = 20; $count.ForeColor = 'DimGray'; $count.Padding = New-Object System.Windows.Forms.Padding(4, 3, 0, 0)
    # the grid above a divider, the summary below it (New-HealthDashboard): the summary keeps its height when the
    # window grows, the grid takes the rest
    $hSplit = New-Object System.Windows.Forms.SplitContainer; $hSplit.Dock = 'Fill'; $hSplit.Orientation = 'Horizontal'; $hSplit.FixedPanel = 'Panel2'
    $hSplit.Panel1.Controls.Add($grid); $hSplit.Panel1.Controls.Add($count); $grid.BringToFront()   # the row count sits above the grid
    New-HealthDashboard -Panel $hSplit.Panel2
    $script:Gui['HealthSplit'] = $hSplit
    $pageChecks.Controls.Add($hSplit)   # added before the toolbar, so the toolbar docks above it
    $pageChecks.Add_Resize({
        # the divider's first place: the dials in full; afterwards wherever the operator drags it
        $s = $script:Gui['HealthSplit']
        # a short page (a 1366 x 768 screen) still gets a usable share - the dials scroll - never the 46-px strip a SplitContainer starts with
        if (-not $script:Gui['HealthDashPlaced'] -and $s.Height -gt 200) { try { $want = $s.Height - 276; if ($want -lt 160) { $want = [int]($s.Height * 0.5) }; $s.SplitterDistance = $want; $script:Gui['HealthDashPlaced'] = $true } catch { } }
    })
    $script:Gui['HealthCount'] = $count
    $script:Gui['HealthGrid'] = $grid

    $toolbar = New-ConsoleToolbar -Tab $pageChecks
    $combo = New-GroupPicker -Toolbar $toolbar -OnChange { Update-HealthGrid; Update-HealthGpoPage }
    $script:Gui['HealthGroupCombo'] = $combo
    # ONE button collects everything the Health checks, the SOE standard check and the Security console need.
    $toolbar.Controls.Add((New-GuiButton -Text 'Check health (ticked, or all)' -X 235 -Y 8 -W 190 -Colour 'LightGreen' -ReadOnly -Tip 'Status, inventory, health, agents, settings, configuration-point and Group Policy collectors on the ticked servers (all shown if none ticked). Reads only - except that the status check removes the toolkit''s own finished OS patch tasks (\WinRMToolkit\OSPatch-*), as every status check does. Includes the SOE standard check (H-SOE-01).' -OnClick {
        Invoke-GuiAction -Name 'Health check' -ReadOnly -Action {
            $servers = @(Get-GridChecked -Grid $script:Gui['HealthGrid'])
            if ($servers.Count -eq 0) { $servers = @(Get-GridAllKeys -Grid $script:Gui['HealthGrid']) }
            if ($servers.Count -eq 0) { Show-GuiNotice 'No servers in the list.'; return }
            Get-ServerStatus -ComputerName $servers | Out-Null
            Get-ServerInventory -ComputerName $servers | Out-Null
            Get-ServerHealth -ComputerName $servers | Out-Null
            Get-ServerAgents -ComputerName $servers | Out-Null
            Get-ServerSettings -ComputerName $servers | Out-Null
            Get-ServerProbes -ComputerName $servers -Probes (Get-SoeProbeList) | Out-Null
            Get-ServerGpo -ComputerName $servers | Out-Null
        }
    }))
    $toolbar.Controls.Add((New-GuiButton -Text 'Tick all' -X 430 -Y 8 -W 70 -ReadOnly -OnClick { Set-GridChecks -Grid $script:Gui['HealthGrid'] -Checked $true }))
    $toolbar.Controls.Add((New-GuiButton -Text 'Untick' -X 505 -Y 8 -W 70 -ReadOnly -OnClick { Set-GridChecks -Grid $script:Gui['HealthGrid'] -Checked $false }))
    $toolbar.Controls.Add((New-GuiButton -Text 'Report (HTML + CSV)' -X 580 -Y 8 -W 150 -ReadOnly -Tip 'Health checks and the SOE comparison of the servers shown' -OnClick {
        Invoke-GuiAction -Name 'Health report' -ReadOnly -Action { Show-ReportDone -Report (Export-HealthReport) }
    }))
    $toolbar.Controls.Add((New-GuiButton -Text 'Open reports folder' -X 735 -Y 8 -W 140 -ReadOnly -OnClick { Invoke-GuiAction -Name 'Open reports folder' -ReadOnly -Action { Open-ReportFolder } }))
    $toolbar.Controls.Add((New-GuiButton -Text 'Assign SOE standard...' -X 885 -Y 8 -W 150 -Tip 'Which SOE standard each server is compared with (ticked servers come pre-selected). Written onto the server''s line in the group file as "; soe: <name>", so it persists with the list.' -OnClick {
        Invoke-GuiAction -Name 'Assign SOE standard' -Action {
            if (-not (Test-GuiDialogAllowed 'The assignment dialog')) { return }
            if (Show-SoeAssignmentDialog -Servers @(Get-GridChecked -Grid $script:Gui['HealthGrid'])) { Get-PatchGroups | Out-Null; Clear-CheckRowCache; Invoke-ConsoleRefresh; Update-SoeItemsGrid }
        }
    }))
    # what the row colours and the SOE column mean: on hover over the row count, not as a paragraph under the page
    $script:Gui['Tips'].SetToolTip($count, 'Row colour = worst check: red = a failure (services, logons, disk, memory, processor, time ...) or a required SOE item that differs, amber = a warning, green = all clear, grey = not checked. SOE column: the standard on the server''s group-file line ("Assign SOE standard..." writes "; soe: <name>" after the name), else the group''s "# soe:" line, else soe\default.json; none = no standard applies. Double-click a server for every check, the SOE comparison, evidence and fixes.')
    $hSplit.BringToFront()

    # ---- SOE standards page ----
    $soeSplit = New-Object System.Windows.Forms.SplitContainer; $soeSplit.Dock = 'Fill'; $soeSplit.Orientation = 'Horizontal'
    $pageSoe.Controls.Add($soeSplit)
    $itemsGrid = New-ConsoleGrid -Columns @(@{ Name = 'Type'; Width = 80 }, @{ Name = 'Name'; Width = 300 }, @{ Name = 'Rule'; Width = 220 }, @{ Name = 'Where'; Width = 300 }, @{ Name = 'Required'; Width = 65 }, @{ Name = 'Source'; Width = 180 }, @{ Name = 'Note'; Width = 300; Fill = $true })
    $itemsGrid.Add_DoubleClick({
        Invoke-GuiAction -Name 'Edit SOE item' -ReadOnly -Action {
            $row = Get-GridSelectedRow -Grid $script:Gui['SoeItemsGrid']
            if (-not $row -or -not $script:Gui['SoeStandard']) { return }
            if (-not (Test-GuiDialogAllowed 'The item editor')) { return }
            $edited = Show-SoeItemEditor -Item $row.Item
            if ($edited) { $std = $script:Gui['SoeStandard']; $std.items = @($std.items | ForEach-Object { if ([object]::ReferenceEquals($_, $row.Item)) { $edited } else { $_ } }); Save-SoeStandard -Standard $std; Update-SoeItemsGrid }
        }
    })
    $soeSplit.Panel1.Controls.Add($itemsGrid)
    $script:Gui['SoeItemsGrid'] = $itemsGrid
    # ---- lower pane: the configuration points an SOE deployment customises (data\soe-config-points.psd1) ----
    $cfgPanel = New-Object System.Windows.Forms.Panel; $cfgPanel.Dock = 'Fill'
    # the title is 21 px tall: the row under it starts at 27 so it never covers the combo's or the button's top edge
    $cfgBar = New-Object System.Windows.Forms.Panel; $cfgBar.Dock = 'Top'; $cfgBar.Height = 56
    $cfgTitle = New-Object System.Windows.Forms.Label; $cfgTitle.Text = 'Configuration points to pin'; $cfgTitle.Location = New-Object System.Drawing.Point(8, 3); $cfgTitle.AutoSize = $true; $cfgTitle.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $script:Gui['Tips'].SetToolTip($cfgTitle, 'Which update server, time source, monitoring or security server every server must point at. The list is data\soe-config-points.psd1 (add your own points); the values come from the reference server''s last "Check health".')
    $refLbl = New-Object System.Windows.Forms.Label; $refLbl.Text = 'Reference server:'; $refLbl.Location = New-Object System.Drawing.Point(8, 33); $refLbl.AutoSize = $true
    $refCombo = New-Object System.Windows.Forms.ComboBox; $refCombo.Location = New-Object System.Drawing.Point(110, 29); $refCombo.Width = 240; $refCombo.DropDownStyle = 'DropDownList'
    $refCombo.Add_SelectedIndexChanged({ if (-not $script:SoeRefFilling) { Update-SoeConfigPointsGrid } })
    Set-ComboTypeAhead -Combo $refCombo   # hundreds of scanned servers: type part of the name
    $refCombo.Add_TextChanged({ if (-not $script:SoeRefFilling -and (Get-ComboChoice -Combo $this)) { Update-SoeConfigPointsGrid } })
    $cfgBar.Controls.AddRange(@($cfgTitle, $refLbl, $refCombo))
    $cfgBar.Controls.Add((New-GuiButton -Text 'Add ticked points to the standard' -X 360 -Y 27 -W 230 -H 26 -Colour 'LightGreen' -ReadOnly -Tip 'Each ticked point becomes a rule with the value the reference server has (or a value you type when the reference has none). Saved at once.' -OnClick {
        Invoke-GuiAction -Name 'Add configuration points' -ReadOnly -Action {
            $std = $script:Gui['SoeStandard']; if (-not $std) { Show-GuiNotice 'Create or select a standard first (New).'; return }
            $picked = @($script:Gui['SoeConfigGrid'].Items | Where-Object { $_.Checked } | ForEach-Object { $_.Tag })
            if ($picked.Count -eq 0) { Show-GuiNotice 'Tick the configuration points to add first.'; return }
            $ref = Get-ComboChoice -Combo $script:Gui['SoeRefCombo']
            $added = 0
            foreach ($row in $picked) {
                $value = [string]$row.Value
                $source = "reference $ref"
                if (-not $ref -or -not $value -or $value -like 'NotConfigured*' -or $value -in 'file missing', 'key missing' -or $value -like 'ERROR:*' -or $value -like '(not read*') {
                    if (-not (Test-GuiDialogAllowed 'The value prompt')) { return }
                    $value = Show-InputBox -Title ('Expected value - ' + $row.Point) -Prompt 'Value every server must have (plain text, * wildcard, or re:<regex>):' -Default ''
                    if (-not $value) { continue }
                    $source = 'by hand'
                }
                $std.items = @($std.items) + (New-SoeItem -Type $row.Type -Name $row.Point -Path $row.Where -Key $row.Key -Expected $value -Required $true -Source $source -Note ([string]$row.Note))
                $added++
            }
            if ($added -gt 0) { Save-SoeStandard -Standard $std; Write-PatchLog "$added configuration point(s) added to standard '$($std.name)' and saved" 'OK'; Update-SoeItemsGrid }
        }
    }))
    $cfgGrid = New-ConsoleGrid -Columns @(@{ Name = 'Point'; Width = 240 }, @{ Name = 'Type'; Width = 60 }, @{ Name = 'Where'; Width = 330 }, @{ Name = 'Key'; Width = 150 }, @{ Name = 'Value'; Width = 260; Fill = $true }, @{ Name = 'Note'; Width = 320 })
    $cfgPanel.Controls.Add($cfgGrid); $cfgPanel.Controls.Add($cfgBar); $cfgGrid.BringToFront()
    $soeSplit.Panel2.Controls.Add($cfgPanel)
    $script:Gui['SoeConfigGrid'] = $cfgGrid; $script:Gui['SoeRefCombo'] = $refCombo
    $soeBar = New-ConsoleToolbar -Tab $pageSoe -Height 76
    $sl = New-Object System.Windows.Forms.Label; $sl.Text = 'Standard:'; $sl.Location = New-Object System.Drawing.Point(8, 13); $sl.AutoSize = $true
    $soeCombo = New-Object System.Windows.Forms.ComboBox; $soeCombo.Location = New-Object System.Drawing.Point(70, 9); $soeCombo.Width = 220; $soeCombo.DropDownStyle = 'DropDownList'
    $soeCombo.Add_SelectedIndexChanged({ Select-SoeStandard -Name ([string]$this.SelectedItem) })
    $soeBar.Controls.Add($sl); $soeBar.Controls.Add($soeCombo)
    $script:Gui['SoeCombo'] = $soeCombo
    # Every SOE button runs through Invoke-GuiAction -ReadOnly (errors land in the log, the consoles repaint) and
    # asks Test-GuiDialogAllowed before opening a dialog, so nothing here can stall an install running alongside.
    $soeBar.Controls.Add((New-GuiButton -Text 'New' -X 300 -Y 4 -W 60 -H 32 -ReadOnly -OnClick {
        Invoke-GuiAction -Name 'New SOE standard' -ReadOnly -Action {
            if (-not (Test-GuiDialogAllowed 'The new-standard dialog')) { return }
            $name = Show-InputBox -Title 'New SOE standard' -Prompt 'Name of the standard (becomes soe\<name>.json):'
            if ($name -and (Test-Path -LiteralPath (Get-SoeStandardPath -Name $name))) { Show-GuiNotice "A standard called '$name' already exists - pick it in the list, or choose another name."; return }
            if ($name) { $std = New-SoeStandard -Name $name; Update-SoeStandardCombo; $script:Gui['SoeCombo'].SelectedItem = $std.name; Write-PatchLog "SOE standard '$($std.name)' created (soe\$($std.name).json) - now add items with 'Add from server...', 'Add fleet agents' or 'Add by hand...'" 'OK' }
        }
    }))
    $soeBar.Controls.Add((New-GuiButton -Text 'Delete' -X 365 -Y 4 -W 70 -H 32 -ReadOnly -OnClick {
        Invoke-GuiAction -Name 'Delete SOE standard' -ReadOnly -Action {
            $std = $script:Gui['SoeStandard']; if (-not $std) { return }
            if (-not (Test-GuiDialogAllowed 'The delete confirmation')) { return }
            if ((Show-PatcherMessage -Text "Delete the standard '$($std.name)' (the JSON file)?" -Buttons 'YesNo' -Icon 'Warning' -Default 'Button2') -eq 'Yes') { Remove-Item -LiteralPath (Get-SoeStandardPath -Name $std.name) -Force; Write-PatchLog "SOE standard '$($std.name)' deleted by $(Get-OperatorIdentity)" 'WARN'; Clear-CheckRowCache; Update-SoeStandardCombo }
        }
    }))
    # Every change to a standard is written to its JSON file at once (no separate Save step to forget).
    $soeBar.Controls.Add((New-GuiButton -Text 'Add from server...' -X 440 -Y 4 -W 130 -H 32 -Colour 'LightGreen' -ReadOnly -Tip 'Pick agents, software, features, services and settings from a scanned server (tick everything = whole server as exemplar). Saved at once.' -OnClick {
        Invoke-GuiAction -Name 'Add SOE items from a server' -ReadOnly -Action {
            $std = $script:Gui['SoeStandard']; if (-not $std) { Show-GuiNotice 'Create or select a standard first (New).'; return }
            $scanned = @(Get-UniqueNames (@($script:Results['Inventory'].Keys) + @($script:Results['Agents'].Keys) + @($script:Results['Settings'].Keys)))
            if ($scanned.Count -eq 0) { Show-GuiNotice 'Check at least one server first (Health checks page: Check health).'; return }
            if (-not (Test-GuiDialogAllowed 'The candidate picker')) { return }
            $picked = @(Show-SoePicker -Servers $scanned)
            $added = 0
            foreach ($p in $picked) { $it = ConvertTo-SoeItem -Candidate $p.Candidate -Server $p.Server; if ($it) { $std.items = @($std.items) + $it; $added++ } }
            if ($added -gt 0) { Save-SoeStandard -Standard $std; Write-PatchLog "$added item(s) added to standard '$($std.name)' and saved" 'OK' } else { Write-PatchLog 'nothing ticked - the standard is unchanged' 'INFO' }
            Update-SoeItemsGrid
        }
    }))
    $soeBar.Controls.Add((New-GuiButton -Text 'Add fleet agents' -X 575 -Y 4 -W 120 -H 32 -ReadOnly -Tip 'The most common version of every agent across the scanned servers. Saved at once.' -OnClick {
        Invoke-GuiAction -Name 'Add fleet agents' -ReadOnly -Action {
            $std = $script:Gui['SoeStandard']; if (-not $std) { Show-GuiNotice 'Create or select a standard first (New).'; return }
            $items = @(Get-FleetAgentItems)
            if ($items.Count -eq 0) { Show-GuiNotice 'No agents found yet - run "Check health" on the Health checks page first.'; return }
            $std.items = @($std.items) + $items; Save-SoeStandard -Standard $std
            Write-PatchLog "$($items.Count) agent item(s) added from the fleet majority and saved" 'OK'; Update-SoeItemsGrid
        }
    }))
    $soeBar.Controls.Add((New-GuiButton -Text 'Add by hand...' -X 700 -Y 4 -W 110 -H 32 -ReadOnly -Tip 'One item from a form: type, name, rule. Saved at once.' -OnClick {
        Invoke-GuiAction -Name 'Add SOE item' -ReadOnly -Action {
            $std = $script:Gui['SoeStandard']; if (-not $std) { Show-GuiNotice 'Create or select a standard first (New).'; return }
            if (-not (Test-GuiDialogAllowed 'The item editor')) { return }
            $it = Show-SoeItemEditor; if ($it) { $std.items = @($std.items) + $it; Save-SoeStandard -Standard $std; Update-SoeItemsGrid }
        }
    }))
    $soeBar.Controls.Add((New-GuiButton -Text 'Remove ticked items' -X 815 -Y 4 -W 140 -H 32 -ReadOnly -Tip 'Removes the ticked rules from the standard (asks first). Saved at once.' -OnClick {
        Invoke-GuiAction -Name 'Remove SOE items' -ReadOnly -Action {
            $std = $script:Gui['SoeStandard']; if (-not $std) { return }
            $drop = @($script:Gui['SoeItemsGrid'].Items | Where-Object { $_.Checked } | ForEach-Object { $_.Tag.Item })
            if ($drop.Count -eq 0) { Show-GuiNotice 'Tick the items to remove first.'; return }
            if (-not (Test-GuiDialogAllowed 'The remove confirmation')) { return }
            if ((Show-PatcherMessage -Text "Remove $($drop.Count) item(s) from '$($std.name)'?" -Buttons 'YesNo' -Icon 'Warning' -Default 'Button2') -ne 'Yes') { return }
            $std.items = @($std.items | Where-Object { $it = $_; -not ($drop | Where-Object { [object]::ReferenceEquals($_, $it) }) })
            Save-SoeStandard -Standard $std
            Update-SoeItemsGrid
        }
    }))
    $soeBar.Controls.Add((New-GuiButton -Text 'Assign to servers...' -X 960 -Y 4 -W 130 -H 32 -Tip 'Which servers are compared with this standard. Written onto each server''s line in its group file as "; soe: <name>", so it persists with the list.' -OnClick {
        Invoke-GuiAction -Name 'Assign SOE standard' -Action {
            if (-not (Test-GuiDialogAllowed 'The assignment dialog')) { return }
            if (Show-SoeAssignmentDialog -Standard ([string]$script:Gui['SoeCombo'].SelectedItem)) { Get-PatchGroups | Out-Null; Clear-CheckRowCache; Invoke-ConsoleRefresh; Update-SoeItemsGrid }
        }
    }))
    $soeLabel = New-Object System.Windows.Forms.Label; $soeLabel.Location = New-Object System.Drawing.Point(8, 48); $soeLabel.AutoSize = $true; $soeLabel.ForeColor = 'DimGray'
    $script:Gui['Tips'].SetToolTip($soeLabel, ('Every change is saved to soe\<name>.json at once. A server is compared with the standard on its group-file line ("; soe: <name>", set by Assign to servers...), else its group''s "# soe:" line, else soe\{0}.json.' -f $script:Config.DefaultSoeStandard))
    $soeBar.Controls.Add($soeLabel); $script:Gui['SoeLabel'] = $soeLabel
    $soeSplit.BringToFront()
    $script:Gui['SoeSplit'] = $soeSplit
    $pageSoe.Add_Resize({ try { $s = $script:Gui['SoeSplit']; $s.SplitterDistance = [int]($s.Height * 0.45) } catch { } })

    # ---- Group Policy page: what applies on the servers shown (top), and how each server's last policy run went (bottom) ----
    $gpoSplit = New-Object System.Windows.Forms.SplitContainer; $gpoSplit.Dock = 'Fill'; $gpoSplit.Orientation = 'Horizontal'
    $gpoGrid = New-ConsoleGrid -NoCheckBoxes -Columns @(@{ Name = 'GPO'; Width = 300 }, @{ Name = 'Linked at'; Width = 250 }, @{ Name = 'Applied'; Width = 60 }, @{ Name = 'Not applied'; Width = 80 }, @{ Name = 'Applied on'; Width = 320; Fill = $true }, @{ Name = 'Not applied on'; Width = 320 })
    $gpoGrid.Add_DoubleClick({
        if ($script:Gui['Busy']) { Write-PatchLog 'Busy - details are available again when the current action finishes' 'WARN'; return }
        if ($this.SelectedItems.Count -gt 0) { $n = $this.SelectedItems[0].Text; Show-DetailsWindow -Title "GPO: $n" -Html (Get-GpoFleetDetailsHtml -Gpo $n -Servers @(Get-UniqueNames (Get-GroupRows -Combo $script:Gui['HealthGroupCombo'] | ForEach-Object { $_.Server }))) }
    })
    $gpoHead = New-GridHeader -Heading 'GPOS ON THE SERVERS SHOWN' -Detail 'nothing collected yet - press "Check health" on the Health checks page' -Tip 'The computer part of each server''s last policy run, read by "Check health" (read-only). "Not applied" is often deliberate: security filtering, a WMI filter, or a GPO meant for users. Which GPO sets which security value is on the Security console''s GPO recommendations page. Double-click a GPO for every server''s status.'
    $gpoSplit.Panel1.Controls.Add($gpoGrid); $gpoSplit.Panel1.Controls.Add($gpoHead.Panel); $gpoGrid.BringToFront()
    $gpoSrvGrid = New-ConsoleGrid -NoCheckBoxes -Columns @(@{ Name = 'Server'; Width = 170 }, @{ Name = 'Light'; Width = 55 }, @{ Name = 'Domain'; Width = 160 }, @{ Name = 'Site'; Width = 110 }, @{ Name = 'Last refresh'; Width = 200 }, @{ Name = 'GPOs'; Width = 130 }, @{ Name = 'Failing extensions'; Width = 180 }, @{ Name = 'Errors'; Width = 140 }, @{ Name = 'Secure channel'; Width = 100 }, @{ Name = 'Note'; Width = 250; Fill = $true })
    $gpoSrvGrid.Add_DoubleClick({
        if ($script:Gui['Busy']) { Write-PatchLog 'Busy - details are available again when the current action finishes' 'WARN'; return }
        if ($this.SelectedItems.Count -gt 0) { $n = $this.SelectedItems[0].Text; Show-DetailsWindow -Title "Health: $n" -Html (Get-HealthDetailsHtml -Server $n) }
    })
    $srvHead = New-GridHeader -Heading 'GROUP POLICY PER SERVER' -Detail '' -Tip 'Lights from checks H-GPO-01 (errors), H-GPO-02 (last refresh) and H-GPO-03 (secure channel). Red: an extension failed, a Group Policy error, or a broken secure channel. Amber: warnings, or no refresh for longer than the Settings tab allows. Double-click a server for its whole Health page.'
    $gpoSplit.Panel2.Controls.Add($gpoSrvGrid); $gpoSplit.Panel2.Controls.Add($srvHead.Panel); $gpoSrvGrid.BringToFront()
    $pageGpo.Controls.Add($gpoSplit)
    $script:Gui['GpoGrid'] = $gpoGrid; $script:Gui['GpoServerGrid'] = $gpoSrvGrid; $script:Gui['GpoHead'] = $gpoHead.Info; $script:Gui['GpoServerHead'] = $srvHead.Info; $script:Gui['GpoSplit'] = $gpoSplit
    $pageGpo.Add_Resize({ try { $s = $script:Gui['GpoSplit']; $s.SplitterDistance = [int]($s.Height * 0.5) } catch { } })

    $null = New-ConsoleBanner -Tab $tab -Console 'Health' -Title 'HEALTH CONSOLE' -Subtitle 'services, tasks, failed logons, dormant software, Group Policy, SOE standards - read-only'
    $pages.BringToFront()
    Update-SoeStandardCombo
    Register-ConsoleRefresher -Console 'Health' -Refresh { Update-HealthGrid; Update-SoeConfigPointsGrid; Update-HealthGpoPage }
}

function Get-SoeStandardSourceForServer {
    # Where a server's standard comes from: 'server line', 'group # soe:', 'soe\<default>.json' or '' (none).
    param([string]$Server)
    $g = Get-ServerGroup -Name $Server
    if ($g) {
        $own = ''; if ($g.PSObject.Properties['Attributes'] -and $g.Attributes) { $a = $g.Attributes[$Server.ToLower()]; if ($a -and $a['soe']) { $own = [string]$a['soe'] } }
        if ($own) { return 'server line' }
        if ($g.Soe) { return 'group # soe:' }
    }
    $default = [string]$script:Config.DefaultSoeStandard
    if ($default -and (Test-Path -LiteralPath (Get-SoeStandardPath -Name $default))) { return ('soe\{0}.json' -f $default) }
    return ''
}

function Show-SoeAssignmentDialog {
    # "Assign SOE standard...": which standard each SERVER is compared with.  Save writes "; soe: <name>" onto each
    # changed server's line in its group file (Set-ServerAttribute), so it persists with the list.  -Servers selects
    # those rows first; -Standard preselects the drop-down.  Big fleets: a filter box narrows the list, and the
    # choices made so far live in $pending, so filtering never loses them.  Returns $true when a file was written.
    param([string[]]$Servers = @(), [string]$Standard = '')
    $names = @(Get-SoeStandardNames)
    if ($names.Count -eq 0) { Show-GuiNotice 'No SOE standard exists yet - create one on the SOE standards page first (New, then Add from server...).'; return $false }
    if (@($script:Groups).Count -eq 0) { Show-GuiNotice 'No group files are loaded.'; return $false }
    $none = '(none - group or default standard, if any)'
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Assign SOE standards to servers'; $dlg.Size = New-Object System.Drawing.Size(1000, 600); $dlg.StartPosition = 'CenterParent'; $dlg.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $grid = New-ConsoleGrid -NoCheckBoxes -Columns @(@{ Name = 'Server'; Width = 230 }, @{ Name = 'Group'; Width = 120 }, @{ Name = 'On the server line'; Width = 220 }, @{ Name = 'In effect'; Width = 200 }, @{ Name = 'From'; Width = 160; Fill = $true })
    $grid.MultiSelect = $true
    $rows = @()
    foreach ($g in $script:Groups) {
        foreach ($s in @($g.Servers)) {
            $own = ''; if ($g.PSObject.Properties['Attributes'] -and $g.Attributes) { $a = $g.Attributes[$s.ToLower()]; if ($a -and $a['soe']) { $own = [string]$a['soe'] } }
            $rows += [pscustomobject]@{ Server = $s; Group = $g.Name; 'On the server line' = $(if ($own) { $own } else { $none }); 'In effect' = (Get-SoeStandardNameForServer -Server $s); From = (Get-SoeStandardSourceForServer -Server $s); Was = $own; GroupSoe = [string]$g.Soe }
        }
    }
    $pending = @{}     # server -> the standard chosen in this dialog ('' = none); only these are written on Save
    $top = New-Object System.Windows.Forms.Panel; $top.Dock = 'Top'; $top.Height = 32
    $fl = New-Object System.Windows.Forms.Label; $fl.Text = 'Filter (server or group):'; $fl.Location = New-Object System.Drawing.Point(10, 9); $fl.AutoSize = $true
    $filter = New-Object System.Windows.Forms.TextBox; $filter.Location = New-Object System.Drawing.Point(160, 5); $filter.Width = 260
    $shown = New-Object System.Windows.Forms.Label; $shown.Location = New-Object System.Drawing.Point(440, 9); $shown.AutoSize = $true; $shown.ForeColor = 'DimGray'
    $top.Controls.AddRange(@($fl, $filter, $shown))
    $fill = {
        $q = $filter.Text
        $view = @($rows | Where-Object { -not $q -or ([string]$_.Server).IndexOf($q, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or ([string]$_.Group).IndexOf($q, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 } | ForEach-Object {
            $r = $_; $line = $r.'On the server line'; $effect = $r.'In effect'; $from = $r.From
            if ($pending.ContainsKey($r.Server)) {
                $p = $pending[$r.Server]
                if ($p) { $line = $p; $effect = $p; $from = 'server line (unsaved)' }
                else {
                    # the same fallback Get-SoeStandardNameForServer uses: the group's standard, else the default one if its file exists (R6-D22)
                    $line = $none
                    $default = [string]$script:Config.DefaultSoeStandard
                    if ($r.GroupSoe) { $effect = $r.GroupSoe; $from = 'group # soe: (unsaved)' }
                    elseif ($default -and (Test-Path -LiteralPath (Get-SoeStandardPath -Name $default))) { $effect = $default; $from = 'default standard (unsaved)' }
                    else { $effect = ''; $from = '(unsaved)' }
                }
            }
            [pscustomobject]@{ Server = $r.Server; Group = $r.Group; 'On the server line' = $line; 'In effect' = $effect; From = $from } })
        Set-GridRows -Grid $grid -Rows $view -NoKeepChecks
        $shown.Text = ('{0} of {1} server(s) shown, {2} changed' -f $view.Count, $rows.Count, $pending.Count)
    }
    $filter.Add_TextChanged($fill)
    & $fill
    foreach ($i in $grid.Items) { if ($Servers -contains $i.Text) { $i.Selected = $true } }
    $bottom = New-Object System.Windows.Forms.Panel; $bottom.Dock = 'Bottom'; $bottom.Height = 120
    $l = New-Object System.Windows.Forms.Label; $l.Text = 'Standard for the selected server(s):'; $l.Location = New-Object System.Drawing.Point(10, 14); $l.AutoSize = $true
    $combo = New-Object System.Windows.Forms.ComboBox; $combo.Location = New-Object System.Drawing.Point(230, 10); $combo.Width = 320; $combo.DropDownStyle = 'DropDownList'
    [void]$combo.Items.Add($none); foreach ($n in $names) { [void]$combo.Items.Add($n) }
    if ($Standard -and $combo.Items.Contains($Standard)) { $combo.SelectedItem = $Standard } else { $combo.SelectedIndex = 0 }
    $apply = New-Object System.Windows.Forms.Button; $apply.Text = 'Apply to selected'; $apply.Location = New-Object System.Drawing.Point(560, 8); $apply.Size = New-Object System.Drawing.Size(130, 28)
    $hint = New-Object System.Windows.Forms.Label; $hint.Location = New-Object System.Drawing.Point(10, 46); $hint.Size = New-Object System.Drawing.Size(960, 66); $hint.ForeColor = 'DimGray'
    $hint.Text = ('Select one or more servers (Shift or Ctrl for several; the filter box narrows the list), pick a standard, press "Apply to selected", then Save. Save writes "; soe: <name>" after the server name on its line in the group file, e.g. "srv-web01.corp.local; soe: Web tier", so the assignment persists with the list and can be edited in Notepad. A server without its own entry uses the group file''s "# soe:" line, else soe\{0}.json. The comparison runs inside "Check health" (check H-SOE-01, the SOE column).' -f $script:Config.DefaultSoeStandard)
    $bottom.Controls.AddRange(@($l, $combo, $apply, $hint))
    $bar = New-DialogButtonBar -Dialog $dlg -Buttons @(@{ Text = 'Save'; Result = 'OK'; Width = 100 }, @{ Text = 'Cancel'; Result = 'Cancel' }) -Hint 'nothing changed yet'
    $ok = $bar.Buttons[0]; $cancel = $bar.Buttons[1]; $status = $bar.Panel.Controls[0]
    $dlg.Controls.Add($grid); $dlg.Controls.Add($top); $dlg.Controls.Add($bottom); $grid.BringToFront()
    $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
    $apply.Add_Click({
        if ($grid.SelectedItems.Count -eq 0) { $status.Text = 'select a server in the list first'; return }
        $pick = [string]$combo.SelectedItem; if ($pick -eq $none) { $pick = '' }
        $sel = @($grid.SelectedItems | ForEach-Object { $_.Text })
        foreach ($s in $sel) { $was = ($rows | Where-Object { $_.Server -eq $s } | Select-Object -First 1).Was; if ($pick -eq [string]$was) { $pending.Remove($s) } else { $pending[$s] = $pick } }
        & $fill
        foreach ($i in $grid.Items) { if ($sel -contains $i.Text) { $i.Selected = $true } }
        $status.Text = ('{0} server(s) changed - Save writes the group file(s)' -f $pending.Count)
    })
    $saved = 0
    if ($dlg.ShowDialog($script:Gui['Form']) -eq 'OK') {
        foreach ($s in @($pending.Keys)) {
            try { Set-ServerAttribute -Server $s -Key 'soe' -Value ([string]$pending[$s]); $saved++ }
            catch { Write-PatchLog "$s - the soe entry was not written: $(Get-ShortError $_)" 'ERROR' }
        }
    }
    $dlg.Dispose()
    return ($saved -gt 0)
}

function Show-InputBox {
    # A one-line prompt (WinForms has no InputBox of its own).
    param([string]$Title, [string]$Prompt, [string]$Default = '')
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title; $dlg.Size = New-Object System.Drawing.Size(480, 160); $dlg.StartPosition = 'CenterParent'; $dlg.FormBorderStyle = 'FixedDialog'; $dlg.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $l = New-Object System.Windows.Forms.Label; $l.Text = $Prompt; $l.Location = New-Object System.Drawing.Point(12, 12); $l.Size = New-Object System.Drawing.Size(440, 20)
    $t = New-Object System.Windows.Forms.TextBox; $t.Location = New-Object System.Drawing.Point(12, 40); $t.Width = 440; $t.Text = $Default
    $ok = New-Object System.Windows.Forms.Button; $ok.Text = 'OK'; $ok.Location = New-Object System.Drawing.Point(262, 76); $ok.Size = New-Object System.Drawing.Size(90, 28); $ok.DialogResult = 'OK'
    $cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; $cancel.Location = New-Object System.Drawing.Point(362, 76); $cancel.Size = New-Object System.Drawing.Size(90, 28); $cancel.DialogResult = 'Cancel'
    $dlg.Controls.AddRange(@($l, $t, $ok, $cancel)); $dlg.AcceptButton = $ok; $dlg.CancelButton = $cancel
    $dlg.ActiveControl = $t   # the cursor is in the box: type the name, press Enter
    $answer = ''
    if ($dlg.ShowDialog($script:Gui['Form']) -eq 'OK') { $answer = $t.Text.Trim() }
    $dlg.Dispose()
    return $answer
}

# =====================================================================
#  05-WinRM.ps1  -  TALKING TO THE SERVERS OVER WinRM (TCP 5985)
# ---------------------------------------------------------------------
#  Three kinds of call are used, from "no auth" to "full auth":
#    Test-WSMan      -> anonymous "identify" request. Proves the port and
#                       the WinRM service are alive. No credentials needed
#                       (this is why winrm get/enumerate worked without auth).
#    Invoke-Command  -> runs a script block ON the server. Uses your current
#                       Kerberos login, or $script:Credential if you set one.
#    New-PSSession   -> a persistent connection used for copying files
#                       (Copy-FileToSession) and the install job.
#
#  Credentials are ONLY asked for in the foreground, with Get-Credential,
#  when a server says "Access is denied" or when you click "Set credentials".
#  Use FQDNs in the group files so Kerberos can find the service; never set
#  TrustedHosts=* to "fix" an authentication error.
# =====================================================================

# ---------------------------------------------------------------------
#  REVIEW RECORD  -  05-WinRM.ps1
# ---------------------------------------------------------------------
#  Independent review 2026-10-14 (see CODE-REVIEW.md).  Fixed here:
#  R-05 status now reports servicing-in-progress and the extra reboot
#  keys (RebootInProgress, PostRebootReporting, UpdateExeVolatile,
#  computer rename); R-06 names de-duplicated case-insensitively; R-08
#  job wait loops treated any non-Running state as finished; R-17
#  -LiteralPath for file-derived paths; R-21 copy gave up after five
#  halvings with a misleading error; R-22 remote SHA256 computed even
#  when sizes differed; R-23 a corrupt staged file was left behind after
#  a failed verification; R-24 credential prompt could open behind the
#  GUI (form is re-activated afterwards).
#  ---------------------------------------------------------------------
#  HUMAN REVIEW  (fill in by hand and keep it in the file)
#  Reviewer   : ____CF__________________________   Date : ___14-10-2026___________
#  Verdict    : [X] Approved   [ ] Approved with comments   [ ] Changes required
#  Checked    : [x] read every function   [x] ran a status check   [x] ran a copy
#               [x] compared with CODE-REVIEW.md
#  Comments   :
#    - Note that New-PSSesssion or Invoke-Commmand may be blocked on a production
#  network, check GPOs and session configuration permissions if you get "Access is
#  denied" or "The WS-Management service cannot process the request" errors.
#    - Worked successfully in test environment.
# =====================================================================

# ---------------------------------------------------------------------
#  This script block is sent to each server and RUNS THERE.
#  It must be self contained: no functions or variables from this tool
#  exist on the remote side, only what is passed via -ArgumentList.
# ---------------------------------------------------------------------
$script:RemoteStatusScript = {
    param([bool]$TreatPfroAsReboot)
    $ErrorActionPreference = 'Stop'

    # Operating system, build and last boot
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $ubr = $cv.UBR
    if (-not $ubr) { $ubr = 0 }

    # Free space on C: (patches need room to stage and install)
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"

    # Installed updates, read TWO ways:
    #  1. Get-HotFix (Win32_QuickFixEngineering): only the CBS packages still present.  Each new
    #     cumulative update supersedes the previous one, which then drops off this list, so a
    #     well patched server shows only a handful of entries here.  This is the primary source.
    #  2. Windows Update Agent history (the same list as Settings > Update history): every
    #     install the server has ever done, including superseded, failed and Defender updates.
    #     Read offline from the local WUA database via COM - nothing goes to the internet.
    # Nested objects get flattened to text by remoting, so both lists are sent as ready-made lines.
    $hotfixes = @(Get-HotFix)
    $withDate = @($hotfixes | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn)
    # "Newest hotfixes" = EVERY Get-HotFix entry from the most recent install date.  The cumulative
    # update and the .NET cumulative update normally land on the same day, so one KB alone would be
    # misleading.  The Build number (UBR) is the real patch level; this column is only a hint.
    $lastText = 'none'
    if ($withDate.Count -gt 0) {
        $newestDate = $withDate[-1].InstalledOn.Date
        $sameDay = @($withDate | Where-Object { $_.InstalledOn.Date -eq $newestDate } | ForEach-Object { $_.HotFixID } | Sort-Object -Unique)
        $more = ''
        if ($sameDay.Count -gt 3) { $more = ' +{0}' -f ($sameDay.Count - 3) }
        $lastText = '{0}{1} ({2:yyyy-MM-dd})' -f (@($sameDay | Select-Object -First 3) -join ' + '), $more, $newestDate
    }
    $hotfixLines = @($hotfixes | Sort-Object InstalledOn -Descending | ForEach-Object {
        $d = 'unknown date'
        if ($_.InstalledOn) { $d = $_.InstalledOn.ToString('yyyy-MM-dd') }
        '{0,-10}  {1,-12}  {2,-24}  {3}' -f $_.HotFixID, $d, $_.Description, $_.InstalledBy
    })

    $historyLines = @()
    $historyInstalled = @()
    $historyCount = 0
    $historyError = ''
    try {
        $wuSession  = New-Object -ComObject 'Microsoft.Update.Session'
        $wuSearcher = $wuSession.CreateUpdateSearcher()
        $historyCount = [int]$wuSearcher.GetTotalHistoryCount()
        if ($historyCount -gt 0) {
            $take = [math]::Min($historyCount, 80)
            $seen = @{}
            foreach ($entry in $wuSearcher.QueryHistory(0, $take)) {
                if (-not $entry.Title) { continue }
                $kb = ''
                if ($entry.Title -match '(?i)(KB\d{6,7})') { $kb = $Matches[1].ToUpper() }
                $result = 'Code ' + $entry.ResultCode
                switch ([int]$entry.ResultCode) {
                    1 { $result = 'In progress' }
                    2 { $result = 'Succeeded' }
                    3 { $result = 'Succeeded w/errors' }
                    4 { $result = 'Failed' }
                    5 { $result = 'Aborted' }
                }
                $op = 'Install'
                if ([int]$entry.Operation -eq 2) { $op = 'Uninstall' }
                $when = ''
                if ($entry.Date) { $when = ([datetime]$entry.Date).ToLocalTime().ToString('yyyy-MM-dd HH:mm') }
                $historyLines += '{0,-16}  {1,-9}  {2,-18}  {3,-10}  {4}' -f $when, $op, $result, $kb, $entry.Title
                # newest entry per KB decides whether it counts as installed
                if ($kb -and -not $seen.ContainsKey($kb)) {
                    $seen[$kb] = $true
                    if ($op -eq 'Install' -and $result -like 'Succeeded*') { $historyInstalled += $kb }
                }
            }
        }
    } catch {
        $historyError = $_.Exception.Message
    }

    # Pending reboot - the HARD flags, every one of them counted:
    $reasons = @()
    $cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
    foreach ($k in 'RebootPending', 'PackagesPending', 'RebootInProgress') { if (Test-Path -LiteralPath "$cbs\$k") { $reasons += "CBS:$k" } }
    foreach ($k in 'RebootRequired', 'PostRebootReporting') { if (Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\$k") { $reasons += "WU:$k" } }
    $vol = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Updates' -Name UpdateExeVolatile -ErrorAction SilentlyContinue).UpdateExeVolatile
    if ($vol -and $vol -ne 0) { $reasons += 'UpdateExeVolatile' }
    $activeName = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name ComputerName -ErrorAction SilentlyContinue).ComputerName
    $wantedName = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name ComputerName -ErrorAction SilentlyContinue).ComputerName
    if ($activeName -and $wantedName -and $activeName -ne $wantedName) { $reasons += 'ComputerRename' }
    # PendingFileRenameOperations (PFRO): a list of files Windows must rename/delete at the next boot
    # because they were locked.  Installers and anti-virus products add to it all the time and it is
    # often left behind, so on its own it is a WEAK sign.  Shown, but not counted, unless the operator
    # sets TreatPendingFileRenameAsReboot = $true in 01-Config.ps1.
    $pfro = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    $pfroPresent = [bool]$pfro
    $pfroEntries = @()
    if ($pfroPresent) {
        $pfroEntries = @($pfro | Where-Object { $_ } | ForEach-Object { $_ -replace '^\\\?\?\\', '' } | Select-Object -First 15)
    }
    if ($pfroPresent -and $TreatPfroAsReboot) { $reasons += 'PendingFileRenameOperations' }

    # Is somebody servicing this box RIGHT NOW?  (another admin, Windows Update, a previous run)
    # dism.exe / wusa.exe present = yes.  TiWorker.exe alone is NOT enough: it idles for minutes after routine
    # maintenance, so it only counts while it is actually burning CPU (sampled over 2 s), and the Windows
    # Update agent is asked directly whether it is installing.  Same block in RemoteInstallScript/RemoteRebootScript.
    $busy = @(Get-Process -Name dism, wusa -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName } | Sort-Object -Unique)
    $ti = @(Get-Process -Name TiWorker -ErrorAction SilentlyContinue)
    if ($ti.Count -gt 0) {
        $cpu1 = 0.0; foreach ($p in $ti) { try { if ($p.CPU) { $cpu1 += $p.CPU } } catch { } }
        Start-Sleep -Seconds 2
        $cpu2 = 0.0; foreach ($p in @(Get-Process -Name TiWorker -ErrorAction SilentlyContinue)) { try { if ($p.CPU) { $cpu2 += $p.CPU } } catch { } }
        if (($cpu2 - $cpu1) -ge 0.25) { $busy += ('TiWorker busy ({0:N1} s CPU in 2 s)' -f ($cpu2 - $cpu1)) }
    }
    try { if ((New-Object -ComObject 'Microsoft.Update.Session').CreateUpdateInstaller().IsBusy) { $busy += 'Windows Update agent installing' } } catch { }

    [pscustomobject]@{
        Computer      = $env:COMPUTERNAME
        Caption       = $os.Caption
        Build         = '{0}.{1}' -f $cv.CurrentBuildNumber, $ubr
        LastBoot      = $os.LastBootUpTime
        UptimeDays    = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
        FreeGB        = [math]::Round($disk.FreeSpace / 1GB, 1)
        PendingReboot = ($reasons.Count -gt 0)
        RebootReasons = ($reasons -join ', ')
        PfroPresent   = $pfroPresent
        PfroEntries   = $pfroEntries
        PfroCount     = @($pfro | Where-Object { $_ }).Count
        ServicingActive  = ($busy.Count -gt 0)
        ServicingReasons = ($busy -join ', ')
        HotFixIDs     = @($hotfixes | ForEach-Object { $_.HotFixID })
        HotFixLines   = $hotfixLines
        HistoryInstalledKBs = $historyInstalled
        HistoryLines  = $historyLines
        HistoryCount  = $historyCount
        HistoryError  = $historyError
        LastHotFix    = $lastText
        PSVersion     = $PSVersionTable.PSVersion.ToString()
    }
}

function New-PatcherSessionOption {
    # OpenTimeout = how long to wait for a server that does not answer before giving up.
    return (New-PSSessionOption -OpenTimeout ($script:Config.OpenTimeoutSec * 1000))
}

function Get-ConnectionArgs {
    # A "splat" hashtable so every WinRM call is built the same way: @conn
    $splat = @{
        Port          = $script:Config.WinRMPort
        SessionOption = (New-PatcherSessionOption)
    }
    if ($script:Credential) { $splat['Credential'] = $script:Credential }
    return $splat
}

function Get-PatcherCredential {
    # Foreground credential prompt (Windows dialog), running as the logged-on user.
    # The dialog belongs to the console window, which can sit BEHIND the GUI - the status bar says so,
    # and the GUI is brought back to the front afterwards.
    param([string]$Reason = 'alternate credentials for WinRM')
    Write-PatchLog "Prompting for credentials in the foreground: $Reason  (look for the Windows credential dialog - it may be behind this window)" 'WHY'
    Set-GuiStatus 'Credential prompt open - it may be behind this window'
    $cred = Get-Credential -Message "Offline Patcher - $Reason" -UserName "$env:USERDOMAIN\"
    $form = $script:Gui['Form']
    if ($form -and -not $form.IsDisposed) { try { $form.Activate() } catch { } }
    if ($cred -and $cred.UserName -and $cred.UserName -ne "$env:USERDOMAIN\") {
        $script:Credential = $cred
        Write-PatchLog "Credentials stored in memory for $($cred.UserName) (never written to disk) by $env:USERDOMAIN\$env:USERNAME" 'OK'
        return $true
    }
    Write-PatchLog 'Credential prompt cancelled - still using the current Windows login' 'WARN'
    return $false
}

function Clear-PatcherCredential {
    $script:Credential = $null
    Write-PatchLog 'Stored credentials cleared - back to the current Windows login' 'INFO'
}

function Test-ServerWinRM {
    # The "no authentication" check. Good first step when a server shows as unreachable.
    param([Parameter(Mandatory = $true)][string]$ComputerName)
    Write-PatchLog "Test-WSMan -ComputerName $ComputerName -Port $($script:Config.WinRMPort)" 'CMD'
    try {
        $r = Test-WSMan -ComputerName $ComputerName -Port $script:Config.WinRMPort -ErrorAction Stop
        Write-PatchLog "$ComputerName answers on WinRM (stack $($r.ProductVersion))" 'OK'
        return $true
    } catch {
        Write-PatchLog "$ComputerName did NOT answer on $($script:Config.WinRMPort): $(Get-ShortError $_)" 'ERROR'
        return $false
    }
}

function Get-ShortError {
    # The exception message in full, but on ONE line (PowerShell's own multi-line
    # "+ CategoryInfo" noise is left out) so the log stays easy to read and grep.
    param($ErrorRecord)
    $msg = ''
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $msg = $ErrorRecord.Exception.Message }
    elseif ($ErrorRecord -is [System.Exception]) { $msg = $ErrorRecord.Message }
    else { $msg = [string]$ErrorRecord }
    $lines = @($msg -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    return ($lines -join ' | ')
}

function Get-ErrorLocation {
    # "file.ps1: line 123" for a caught error.  In all-in-one (Invoke-Expression) mode there is no
    # file, so it reads "<No file>: line N" where N counts from the top of the all-in-one text.
    param($ErrorRecord)
    if ($ErrorRecord.ScriptStackTrace) { return (($ErrorRecord.ScriptStackTrace -split "`r?`n")[0] -replace '^at ', '') }
    return ''
}

function New-UnreachableStatus {
    # Same shape as the remote object so the GUI never trips over a missing property.
    param([string]$ComputerName, [string]$Reason)
    return [pscustomobject]@{
        Computer = $ComputerName; Caption = ''; Build = ''; LastBoot = $null; UptimeDays = $null
        FreeGB = $null; PendingReboot = $false; RebootReasons = ''; PfroPresent = $false; PfroEntries = @(); PfroCount = 0
        ServicingActive = $false; ServicingReasons = ''
        HotFixIDs = @(); HotFixLines = @(); HistoryInstalledKBs = @(); HistoryLines = @(); HistoryCount = 0; HistoryError = ''
        LastHotFix = ''; PSVersion = ''
        Reachable = $false; Error = $Reason; Checked = (Get-Date)
    }
}

function Wait-PatcherJob {
    # Waits for a job while keeping the GUI alive (DoEvents) and the status bar ticking.
    # "Finished" means Completed / Failed / Stopped / Disconnected - NotStarted, Blocked and
    # Suspending (robust-connection retries after a network blip) are still "in progress".
    param($Job, [string]$Activity = 'Working', [int]$TimeoutSec = 3600)
    $finished = @('Completed', 'Failed', 'Stopped', 'Disconnected')
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($finished -notcontains $Job.State -and $watch.Elapsed.TotalSeconds -lt $TimeoutSec) {
        Set-GuiStatus ('{0} ... {1}s' -f $Activity, [int]$watch.Elapsed.TotalSeconds)
        Start-Sleep -Milliseconds 300
    }
    if ($finished -notcontains $Job.State) {
        Write-PatchLog "$Activity timed out after $TimeoutSec s - stopping the job" 'ERROR'
        Stop-Job -Job $Job
    }
}

function Set-GuiStatus {
    # Updates the status bar text if the GUI exists; harmless from the console.
    param([string]$Text)
    $label = $script:Gui['StatusLabel']
    if ($label) {
        $label.Text = $Text
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Set-GuiProgress {
    # Patch-o-meter: -Percent 0..100 shows a real bar, -Marquee goes back to "busy, unknown length".
    param([int]$Percent = -1, [switch]$Marquee)
    $bar = $script:Gui['Progress']
    if (-not $bar) { return }
    if ($Marquee) { $bar.Style = 'Marquee'; return }
    $bar.Style = 'Continuous'
    if ($Percent -lt 0) { $Percent = 0 }
    if ($Percent -gt 100) { $Percent = 100 }
    $bar.Value = $Percent
    [System.Windows.Forms.Application]::DoEvents()
}

function Get-ServerStatus {
    # Checks many servers at once (one child job per server) and stores the
    # result in $script:ServerStatus[name].  Returns the array of status objects.
    param(
        [Parameter(Mandatory = $true)][string[]]$ComputerName,
        [switch]$NoRetry       # internal: stops the "prompt for credentials and retry" loop
    )
    $names = @(Get-UniqueNames $ComputerName)
    if ($names.Count -eq 0) { return @() }

    $conn = Get-ConnectionArgs
    $who  = 'current login'
    if ($script:Credential) { $who = $script:Credential.UserName }
    Write-PatchLog ("Invoke-Command -ComputerName {0} -Port {1} -AsJob  (status script, as {2})" -f ($names -join ','), $conn.Port, $who) 'CMD'

    $call = @{
        ComputerName  = $names
        ScriptBlock   = $script:RemoteStatusScript
        ArgumentList  = $script:Config.TreatPendingFileRenameAsReboot
        ThrottleLimit = $script:Config.MaxParallel
        AsJob         = $true
        ErrorAction   = 'SilentlyContinue'
    }
    $job = Invoke-Command @call @conn
    Wait-PatcherJob -Job $job -Activity ("Checking {0} server(s)" -f $names.Count) -TimeoutSec 600

    $results = @()
    $denied  = @()
    foreach ($child in $job.ChildJobs) {
        $name = $child.Location
        $jobErrors = @()
        $out = Receive-Job -Job $child -ErrorAction SilentlyContinue -ErrorVariable jobErrors
        $status = $null
        if ($out) {
            $status = $out | Select-Object -First 1
            $status | Add-Member -NotePropertyName Reachable -NotePropertyValue $true  -Force
            $status | Add-Member -NotePropertyName Error     -NotePropertyValue ''     -Force
            $status | Add-Member -NotePropertyName Checked   -NotePropertyValue (Get-Date) -Force
            $flag = 'no reboot pending'
            if ($status.PendingReboot) { $flag = "PENDING REBOOT ($($status.RebootReasons))" }
            if ($status.ServicingActive) { $flag += ", SERVICING ACTIVE ($($status.ServicingReasons))" }
            Write-PatchLog ("{0}: build {1}, {2} GB free, up {3} d, {4}, newest hotfixes {5}" -f $name, $status.Build, $status.FreeGB, $status.UptimeDays, $flag, $status.LastHotFix) 'OK'
        } else {
            $reason = 'no data returned'
            if ($jobErrors.Count -gt 0) { $reason = Get-ShortError $jobErrors[0] }
            elseif ($child.JobStateInfo.Reason) { $reason = Get-ShortError $child.JobStateInfo.Reason }
            $status = New-UnreachableStatus -ComputerName $name -Reason $reason
            if ($reason -match 'Access is denied') { $denied += $name }
            Write-PatchLog "$name FAILED: $reason" 'ERROR'
        }
        $script:ServerStatus[$name] = $status
        $results += $status
    }
    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

    # Access denied with the current login?  Ask once (foreground) and retry just those servers.
    if ($denied.Count -gt 0 -and -not $NoRetry -and -not $script:Credential) {
        Write-PatchLog ("{0} server(s) refused the current login - offering a credential prompt" -f $denied.Count) 'WHY'
        if (Get-PatcherCredential -Reason "access denied on $($denied -join ', ')") {
            $retried = Get-ServerStatus -ComputerName $denied -NoRetry
            foreach ($r in $retried) { $results = @($results | Where-Object { $_.Computer -ne $r.Computer }) + $r }
        }
    }
    Set-GuiStatus 'Status check finished'
    return $results
}

# =====================================================================
#  COPYING A FILE OVER WinRM - IN SLICES
# ---------------------------------------------------------------------
#  Every WinRM request has to fit inside the server's "MaxEnvelopeSizekb"
#  (default 500 KB).  Copy-Item -ToSession in PowerShell 5.1 sends bigger
#  requests than that and fails with "...exceeded the configured
#  MaxEnvelopeSize quota".  So we do it ourselves: read the file in slices,
#  Base64 each slice (that makes it 37% bigger), send it as an argument to a
#  tiny script block that appends it on the server.  The slice size is worked
#  out from the server's own MaxEnvelopeSizekb (500 -> 224 KB slices), the
#  copy can resume, and the result is verified with a SHA256 hash on both sides.
# =====================================================================

# RUNS ON THE TARGET SERVER: what is there already, and how big may a request be?
$script:RemoteFileInfoScript = {
    param([string]$Path, [bool]$WithHash)
    $r = [pscustomobject]@{ Exists = $false; Length = -1; Hash = ''; EnvelopeKB = 500 }
    if (Test-Path -LiteralPath $Path) {
        $r.Exists = $true
        $r.Length = (Get-Item -LiteralPath $Path).Length
        if ($WithHash) { $r.Hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
    }
    # How big may one request be?  Try the WSMan provider, then winrm.cmd, else assume the default 500.
    $kb = 0
    try { $kb = [int](Get-Item -Path 'WSMan:\localhost\MaxEnvelopeSizekb' -ErrorAction Stop).Value } catch { }
    if ($kb -le 0) {
        try {
            $line = @(& winrm.cmd get winrm/config 2>$null | Where-Object { $_ -match 'MaxEnvelopeSizekb\s*=\s*(\d+)' })
            if ($line.Count -gt 0 -and $line[0] -match 'MaxEnvelopeSizekb\s*=\s*(\d+)') { $kb = [int]$Matches[1] }
        } catch { }
    }
    if ($kb -le 0) { $kb = 500 }
    $r.EnvelopeKB = $kb
    return $r
}

# RUNS ON THE TARGET SERVER: appends one slice (Create on the first slice) and returns the new length.
$script:RemoteWriteSliceScript = {
    param([string]$Path, [string]$Base64, [bool]$FirstSlice)
    $bytes = [System.Convert]::FromBase64String($Base64)
    $mode = [System.IO.FileMode]::Append
    if ($FirstSlice) {
        $mode = [System.IO.FileMode]::Create
        $folder = Split-Path -Path $Path -Parent
        if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    }
    $fs = New-Object System.IO.FileStream($Path, $mode, [System.IO.FileAccess]::Write)
    try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Close() }
    return (Get-Item -LiteralPath $Path).Length
}

# RUNS ON THE TARGET SERVER: throws away a staged file that failed verification.
$script:RemoteDeleteScript = {
    param([string]$Path)
    Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}

function Invoke-RemoteBlock {
    # Runs a script block inside the session - or locally when there is no session,
    # which lets the copy logic be tested on one machine (see the Code Tour).
    param($Session, [scriptblock]$ScriptBlock, [object[]]$ArgumentList)
    if ($Session) { return (Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop) }
    return (& $ScriptBlock @ArgumentList)
}

function Copy-FileToSession {
    param(
        [Parameter(Mandatory = $true)][string]$Path,          # local file
        [Parameter(Mandatory = $true)][string]$Destination,   # full path on the server
        $Session,                                              # PSSession; $null = local self-test
        [int]$SliceKB = 0,                                     # 0 = derive from the server's MaxEnvelopeSizekb
        [string]$LocalHash = ''                                # SHA256 if already known (saves hashing a big file again)
    )
    $local = Get-Item -LiteralPath $Path
    $label = 'local'
    if ($Session) { $label = $Session.ComputerName }
    $totalMB = [math]::Round($local.Length / 1MB, 1)
    if (-not $LocalHash) { $LocalHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }

    # 1. Is it already there?  Only hash the remote file when the sizes match (hashing a partial file is wasted work).
    $info = Invoke-RemoteBlock -Session $Session -ScriptBlock $script:RemoteFileInfoScript -ArgumentList $Destination, $false
    $offset = 0
    if ($info.Exists -and $info.Length -eq $local.Length) {
        Set-GuiStatus "$label - $($local.Name) already staged, checking its hash..."
        $info = Invoke-RemoteBlock -Session $Session -ScriptBlock $script:RemoteFileInfoScript -ArgumentList $Destination, $true
        if ($LocalHash -eq $info.Hash) {
            Write-PatchLog "$label - $($local.Name) is already there and the SHA256 matches - no copy needed" 'OK'
            return $true
        }
        Write-PatchLog "$label - a file of the same size is there but its hash differs - copying again from the start" 'WARN'
    } elseif ($info.Exists -and $info.Length -gt 0 -and $info.Length -lt $local.Length) {
        $offset = $info.Length
        Write-PatchLog ("{0} - a partial copy ({1} MB) is there - resuming from that point (the final hash check catches a bad one)" -f $label, [math]::Round($offset / 1MB, 1)) 'INFO'
    }

    # 2. Slice size: 65% of the envelope, shrunk by the Base64 overhead, rounded to 16 KB.
    if ($SliceKB -le 0) {
        $SliceKB = [int]([math]::Floor($info.EnvelopeKB * 0.65 / 1.37 / 16) * 16)
        if ($SliceKB -lt 32) { $SliceKB = 32 }
        if ($SliceKB -gt 4096) { $SliceKB = 4096 }
    }
    $trips = [math]::Ceiling(($local.Length - $offset) / ($SliceKB * 1024))
    Write-PatchLog ("{0} - MaxEnvelopeSizekb on the server is {1}, so {2} MB goes over in {3} KB slices = {4} round trips" -f $label, $info.EnvelopeKB, $totalMB, $SliceKB, $trips) 'WHY'
    if ($info.EnvelopeKB -le 1024 -and -not $script:EnvelopeTipShown) {
        Write-PatchLog '   tip: on the servers  winrm set winrm/config @{MaxEnvelopeSizekb="8192"}  makes copies many times faster (shown once per run)' 'WHY'
        $script:EnvelopeTipShown = $true
    }

    # 3. Send the slices.  If the server still says the request is too big, halve the slice and carry on.
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $lastTick = -10
    $completed = $false
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $fs.Position = $offset
            $sent = $offset
            $first = ($offset -eq 0)
            $buffer = New-Object byte[] ($SliceKB * 1024)
            while (($read = $fs.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $b64 = [System.Convert]::ToBase64String($buffer, 0, $read)
                $remoteLength = Invoke-RemoteBlock -Session $Session -ScriptBlock $script:RemoteWriteSliceScript -ArgumentList $Destination, $b64, $first
                $first = $false
                $sent += $read
                if ([long]$remoteLength -ne $sent) { throw "The server reports $remoteLength bytes but $sent were sent - aborting the copy" }
                if ($watch.Elapsed.TotalSeconds - $lastTick -ge 2) {
                    $lastTick = $watch.Elapsed.TotalSeconds
                    $rate = 0
                    if ($watch.Elapsed.TotalSeconds -gt 0) { $rate = [math]::Round(($sent - $offset) / 1MB / $watch.Elapsed.TotalSeconds, 1) }
                    Set-GuiStatus ("Copying {0} to {1}: {2} / {3} MB  ({4} MB/s)" -f $local.Name, $label, [math]::Round($sent / 1MB), $totalMB, $rate)
                    Set-GuiProgress -Percent ([int](100 * $sent / $local.Length))
                }
            }
            $completed = $true
            break
        } catch {
            $msg = Get-ShortError $_
            if ($msg -match 'MaxEnvelopeSize' -and $SliceKB -gt 32) {
                $SliceKB = [int]($SliceKB / 2)
                $again = Invoke-RemoteBlock -Session $Session -ScriptBlock $script:RemoteFileInfoScript -ArgumentList $Destination, $false
                $offset = 0
                if ($again.Exists -and $again.Length -gt 0) { $offset = $again.Length }
                Write-PatchLog ("{0} - the server rejected a slice as too big; retrying with {1} KB slices from {2} MB (attempt {3})" -f $label, $SliceKB, [math]::Round($offset / 1MB, 1), ($attempt + 1)) 'WARN'
            } else {
                throw
            }
        } finally {
            $fs.Close()
        }
    }
    Set-GuiProgress -Marquee
    if (-not $completed) { throw "$label - the server kept rejecting slices as too big (last size $SliceKB KB). Check MaxEnvelopeSizekb on the server: winrm get winrm/config" }

    # 4. Verify: size and SHA256 must match on both sides.  A bad copy is deleted so the next run starts clean.
    Set-GuiStatus "$label - verifying the copy (SHA256)..."
    $final = Invoke-RemoteBlock -Session $Session -ScriptBlock $script:RemoteFileInfoScript -ArgumentList $Destination, $true
    if ($final.Length -ne $local.Length -or $final.Hash -ne $LocalHash) {
        Invoke-RemoteBlock -Session $Session -ScriptBlock $script:RemoteDeleteScript -ArgumentList $Destination | Out-Null
        throw "Copy verification FAILED on $label - size $($final.Length) vs $($local.Length), hash match = $($final.Hash -eq $LocalHash). The staged file was deleted; run the install again."
    }
    $secs = [math]::Round($watch.Elapsed.TotalSeconds)
    $rate = 0
    if ($secs -gt 0) { $rate = [math]::Round(($local.Length - $offset) / 1MB / $secs, 1) }
    Write-PatchLog ("{0} - copy finished: {1} MB in {2} s ({3} MB/s), SHA256 verified" -f $label, $totalMB, $secs, $rate) 'OK'
    return $true
}

# =====================================================================
#  06-Install.ps1  -  INSTALLING A PATCH OVER WinRM
# ---------------------------------------------------------------------
#  The flow (see Install-PatchOnServers at the bottom):
#    1. Fresh status check of the chosen servers (never trust old data)
#    2. Build a plan: which KB goes to which server, and why not
#    3. Show the plan                          -> OK / Cancel
#    4. SAFETY POP-UP 1: VMware snapshot taken? -> No = abort
#    5. SAFETY POP-UP 2: Trellix in maintenance mode? -> No = abort
#    6. Status check AGAIN (the pop-ups may have been open for a while),
#       then per server: PSSession, locked-down C:\PatchStaging, slice copy
#    7. Start the install script block on every server at once (-AsJob)
#    8. Wait (GUI stays alive, progress every 45 s), collect the results
#    9. Fresh status check again so the grid shows the new truth
#
#  WHY DISM AND NOT WUSA?  wusa.exe refuses to run inside a remote
#  (WinRM) session - it fails with "access denied"/exit code 5.  DISM is
#  happy to run remotely, so we unpack the .msu with expand.exe and feed
#  the .cab inside it to  dism /Online /Add-Package.
#
#  RULE FOR EVERY POP-UP IN THIS FILE: a MessageBox RETURNS a value.  If
#  that value is not captured it leaks into the function's output and a
#  "return $false" silently becomes "@('OK', $false)" = true.  So every
#  pop-up whose answer we do not need is written as  $null = Show-...
# =====================================================================

# ---------------------------------------------------------------------
#  REVIEW RECORD  -  06-Install.ps1
# ---------------------------------------------------------------------
#  Independent review 2026-10-14 (two reviewers, see CODE-REVIEW.md).
#  Findings fixed in this file: R-01 safety pop-up "No" did not abort
#  (MessageBox result leaked into the return value); R-02 "nothing to do"
#  reported as a failed install; R-03 Reboot button had no pending-reboot
#  or servicing guard; R-04 timeout killed DISM mid-install; R-05 stale
#  status at install time + no servicing guard on the server; R-06 same
#  server twice (case / FQDN); R-07 staging folder writable by Users and
#  no hash re-check before expand; R-10 per-package results; R-13 KB in
#  failure rows; R-14 sessions leaked on error; R-15 reboot reported as
#  failed; R-16 pop-ups taller than the screen; R-19 remote path built
#  with local Join-Path; R-20 two files with one KB shared a folder.
#  ---------------------------------------------------------------------
#  HUMAN REVIEW  (fill in by hand and keep it in the file)
#  Reviewer   : ____CF__________________________   Date : ___14-10-2026___________
#  Verdict    : [X] Approved   [ ] Approved with comments   [ ] Changes required
#  Checked    : [x] read every function   [x] ran it against a test server
#               [x] compared with CODE-REVIEW.md   [x] safety pop-ups answered No
#  Comments   :
#    -
#    -
# =====================================================================

# ---------------------------------------------------------------------
#  RUNS ON THE TARGET SERVER before anything is copied: makes sure the
#  staging folder is a real folder owned by admins, with an ACL that
#  ordinary users cannot write to (C:\ lets Users create folders).
# ---------------------------------------------------------------------
$script:RemoteStagingScript = {
    param([string]$Staging)
    if (Test-Path -LiteralPath $Staging) {
        $item = Get-Item -LiteralPath $Staging -Force
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw "$Staging is a junction or symbolic link - refusing to use it" }
        if (-not $item.PSIsContainer) { throw "$Staging exists but is a file" }
        $owner = (Get-Acl -LiteralPath $Staging).Owner
        if ($owner -notmatch 'Administrators|SYSTEM|TrustedInstaller') { throw "$Staging is owned by '$owner', not by Administrators - refusing to use it" }
    } else {
        New-Item -ItemType Directory -Path $Staging -Force | Out-Null
    }
    # SYSTEM and Administrators only; inheritance from C:\ removed.
    $null = & icacls.exe "$Staging" /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls could not lock down $Staging (exit $LASTEXITCODE)" }
    return "$Staging ready (owner $((Get-Acl -LiteralPath $Staging).Owner), ACL = SYSTEM + Administrators)"
}

# ---------------------------------------------------------------------
#  RUNS ON THE TARGET SERVER.  Installs each staged file in turn and
#  returns one result object per file.  Self contained on purpose.
#  Guards, in order: nothing else servicing the box, no pending reboot,
#  the staged file still has the hash we copied, the file is Microsoft
#  signed.  Only then expand + DISM.
# ---------------------------------------------------------------------
$script:RemoteInstallScript = {
    param([string[]]$RemoteFiles, [string[]]$ExpectedHashes, [bool]$Cleanup, [bool]$RequireSignature, [string]$Operator)
    $results = @()

    for ($i = 0; $i -lt $RemoteFiles.Count; $i++) {
        $file = $RemoteFiles[$i]
        $expectedHash = ''
        if ($ExpectedHashes.Count -gt $i) { $expectedHash = $ExpectedHashes[$i] }
        $kb = 'KB?'
        if ($file -match '(?i)(KB\d{6,7})') { $kb = $Matches[1].ToUpper() }
        # Work folder/log names: KB + 6 chars from the file name, so two files with one KB never collide.
        $nameHash = [System.BitConverter]::ToString([System.Security.Cryptography.MD5]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes((Split-Path -Path $file -Leaf).ToLower()))).Replace('-', '').Substring(0, 6)
        $tag = "$kb-$nameHash"
        $r = [ordered]@{
            Computer = $env:COMPUTERNAME; KB = $kb; File = (Split-Path -Path $file -Leaf)
            Success = $false; RebootRequired = $false; ExitCode = $null; Message = ''; Detail = @(); Packages = @()
        }
        $extract = $null
        $logPath = $null
        $stage = Split-Path -Path $file -Parent
        try {
            # --- Guard 1: is something else servicing this box right now?  dism/wusa = yes; TiWorker only
            #     when it is actually burning CPU (it idles for minutes after routine maintenance); and the
            #     Windows Update agent is asked directly.  Same block as in RemoteStatusScript.
            $busy = @(Get-Process -Name dism, wusa -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName } | Sort-Object -Unique)
            $ti = @(Get-Process -Name TiWorker -ErrorAction SilentlyContinue)
            if ($ti.Count -gt 0) {
                $cpu1 = 0.0; foreach ($p in $ti) { try { if ($p.CPU) { $cpu1 += $p.CPU } } catch { } }
                Start-Sleep -Seconds 2
                $cpu2 = 0.0; foreach ($p in @(Get-Process -Name TiWorker -ErrorAction SilentlyContinue)) { try { if ($p.CPU) { $cpu2 += $p.CPU } } catch { } }
                if (($cpu2 - $cpu1) -ge 0.25) { $busy += ('TiWorker busy ({0:N1} s CPU in 2 s)' -f ($cpu2 - $cpu1)) }
            }
            try { if ((New-Object -ComObject 'Microsoft.Update.Session').CreateUpdateInstaller().IsBusy) { $busy += 'Windows Update agent installing' } } catch { }
            if ($busy.Count -gt 0) { throw "servicing already running on the server ($($busy -join ', ')) - try again in a few minutes" }
            # --- Guard 2: pending reboot (same hard keys as the status check)
            $cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
            $pending = @()
            foreach ($k in 'RebootPending', 'PackagesPending', 'RebootInProgress') { if (Test-Path -LiteralPath "$cbs\$k") { $pending += "CBS:$k" } }
            foreach ($k in 'RebootRequired', 'PostRebootReporting') { if (Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\$k") { $pending += "WU:$k" } }
            if ($pending.Count -gt 0) { throw "pending reboot on the server ($($pending -join ', ')) - reboot first" }
            # --- Guard 3: the staged file is intact (closes the gap between the copy and the install)
            if (-not (Test-Path -LiteralPath $file)) { throw "Staged file not found: $file" }
            if ($expectedHash) {
                $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
                if ($actual -ne $expectedHash) { throw "staged file hash changed since the copy ($actual vs $expectedHash) - refusing to install" }
            }
            # --- Guard 4: Microsoft signature
            if ($RequireSignature) {
                $sig = Get-AuthenticodeSignature -LiteralPath $file
                $subject = ''
                if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }
                if ($sig.Status -ne 'Valid' -or $subject -notmatch 'O=Microsoft Corporation') { throw "signature check failed: status $($sig.Status), signer '$subject'" }
                $r.Detail += "Authenticode: $($sig.Status), $subject"
            }

            $logPath = "$stage\dism-$tag.log"
            $packages = @()
            if ($file.ToLower().EndsWith('.msu')) {
                # Step A: unpack the .msu (a container holding one or more .cab files)
                $extract = "$stage\extract-$tag"
                if (Test-Path -LiteralPath $extract) { Remove-Item -LiteralPath $extract -Recurse -Force }
                New-Item -ItemType Directory -Path $extract -Force | Out-Null
                $r.Detail += "expand.exe -F:* `"$file`" `"$extract`""
                $null = & expand.exe -F:* "$file" "$extract" 2>&1
                if ($LASTEXITCODE -ne 0) { throw "expand.exe failed with exit code $LASTEXITCODE" }
                # WSUSSCAN.cab is only metadata; a separate SSU (servicing stack) cab must go first.
                $cabs = @(Get-ChildItem -LiteralPath $extract -Filter '*.cab' | Where-Object { $_.Name -notmatch '^WSUSSCAN' })
                $packages = @($cabs | Sort-Object @{ Expression = { if ($_.Name -match 'SSU') { 0 } else { 1 } } }, Name | ForEach-Object { $_.FullName })
                if ($packages.Count -eq 0) { throw 'No .cab file found inside the .msu' }
            } else {
                $packages = @($file)
            }

            # Step B: DISM installs each package in turn.  /NoRestart = we decide when to reboot.
            foreach ($pkg in $packages) {
                $pkgName = Split-Path -Path $pkg -Leaf
                $r.Detail += "dism.exe /Online /Add-Package /PackagePath:`"$pkg`" /NoRestart /Quiet /LogPath:`"$logPath`""
                $null = & dism.exe /Online /Add-Package /PackagePath:"$pkg" /NoRestart /Quiet /LogPath:"$logPath" 2>&1
                $code = $LASTEXITCODE
                $hex = '0x{0:X8}' -f ($code -band 0xFFFFFFFF)
                $r.ExitCode = $code
                $r.Packages += "$pkgName -> exit $code ($hex)"
                switch ($hex) {
                    '0x00000000' { }
                    '0x00000BC2' { $r.RebootRequired = $true }
                    '0x800F081E' { throw "$pkgName - DISM 0x800F081E NOT APPLICABLE to this server: wrong Windows build or a missing prerequisite" }
                    '0x800F0922' { throw "$pkgName - DISM 0x800F0922 install failed. Usual causes: pending reboot, missing servicing stack update, System Reserved partition full. See $logPath" }
                    '0x80070002' { throw "$pkgName - DISM 0x80070002 file not found (was the copy complete?)" }
                    default      { throw "$pkgName - DISM returned $code ($hex). See $logPath on the server" }
                }
            }
            $r.Success = $true
            $r.Message = 'Installed'
            if ($r.RebootRequired) { $r.Message = 'Installed - reboot required (3010)' }
            if ($packages.Count -gt 1) { $r.Message += " ($($packages.Count) packages: " + (($packages | ForEach-Object { Split-Path -Path $_ -Leaf }) -join ', ') + ')' }
        } catch {
            $r.Success = $false
            $r.Message = $_.Exception.Message
            if ($r.Packages.Count -gt 0) { $r.Message = "PARTIAL - earlier packages went in: " + ($r.Packages -join '; ') + " - then: " + $r.Message }
            # Pull the interesting lines out of the DISM log so the operator does not have to go looking.
            if ($logPath -and (Test-Path -LiteralPath $logPath)) {
                $r.Detail += @(Get-Content -LiteralPath $logPath -Tail 60 | Where-Object { $_ -match 'Error|Failed|0x8' } | Select-Object -Last 8)
            }
        }

        # Step C: leave a result file on the server (survives a lost connection) and an event log entry.
        $resultPath = "$stage\result-$tag.txt"
        try {
            @("Computer=$env:COMPUTERNAME", "KB=$kb", "File=$($r.File)", "Operator=$Operator", "When=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
              "Success=$($r.Success)", "RebootRequired=$($r.RebootRequired)", "ExitCode=$($r.ExitCode)", "Message=$($r.Message)") + @($r.Packages | ForEach-Object { "Package=$_" }) | Set-Content -LiteralPath $resultPath
        } catch { }
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists('OfflinePatcher')) { New-EventLog -LogName Application -Source 'OfflinePatcher' -ErrorAction Stop }
            $type = 'Information'
            if (-not $r.Success) { $type = 'Error' }
            Write-EventLog -LogName Application -Source 'OfflinePatcher' -EventId 900 -EntryType $type -Message ("Offline Patcher: {0} on {1} by {2} -> {3} (exit {4})" -f $kb, $env:COMPUTERNAME, $Operator, $r.Message, $r.ExitCode) -ErrorAction Stop
        } catch { $r.Detail += "event log entry not written: $($_.Exception.Message)" }

        # Step D: tidy up (only after success - on failure everything stays for investigation)
        if ($Cleanup -and $r.Success) {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
            if ($extract) { Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue }
        }
        $results += [pscustomobject]$r
    }
    return $results
}

# ---------------------------------------------------------------------
#  RUNS ON THE TARGET SERVER while DISM is busy: a progress snapshot.
#  The DISM log goes quiet after "CBS session options=0x100!" for the whole
#  install; the real progress is written to C:\Windows\Logs\CBS\CBS.log as
#  "Progress: UI message updated ... Stage: 1 out of 1. Percent progress: 37."
# ---------------------------------------------------------------------
$script:RemoteProgressScript = {
    param([string]$Staging)
    $dism = @(Get-Process -Name dism -ErrorAction SilentlyContinue)
    $ti   = @(Get-Process -Name TiWorker -ErrorAction SilentlyContinue)
    $tiCpu = 0
    if ($ti.Count -gt 0) { $tiCpu = [int]($ti | Measure-Object -Property CPU -Sum).Sum }

    $pct = ''; $stage = ''; $pctTime = ''
    $cbs = Join-Path $env:windir 'Logs\CBS\CBS.log'
    if (Test-Path -LiteralPath $cbs) {
        $line = Get-Content -LiteralPath $cbs -Tail 3000 -ErrorAction SilentlyContinue | Where-Object { $_ -match 'Percent progress: \d+' } | Select-Object -Last 1
        if ($line -match '^(\S+ \S+?),.*Stage: (\d+ out of \d+)\. Percent progress: (\d+)') { $pctTime = $Matches[1]; $stage = $Matches[2]; $pct = $Matches[3] }
    }

    $lastDism = ''
    $log = Get-ChildItem -LiteralPath $Staging -Filter 'dism-*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
    if ($log) {
        $l = [string](Get-Content -LiteralPath $log.FullName -Tail 1 -ErrorAction SilentlyContinue)
        if ($l -match '^(\S+ \S+?),.*TID=\d+ (.*?) - \w+::') { $lastDism = '{0} {1}' -f $Matches[1], $Matches[2] } else { $lastDism = $l }
        if ($lastDism.Length -gt 140) { $lastDism = $lastDism.Substring(0, 140) + '...' }
    }

    [pscustomobject]@{
        Computer = $env:COMPUTERNAME; DismRunning = ($dism.Count -gt 0); TiWorkerCpuSec = $tiCpu
        Percent = $pct; Stage = $stage; PercentTime = $pctTime; LastDism = $lastDism
    }
}

function Get-InstallProgress {
    # One progress snapshot per server (RemoteProgressScript), all servers asked at once.
    param([string[]]$ComputerName)
    try {
        $conn = Get-ConnectionArgs
        $job = Invoke-Command -ComputerName $ComputerName @conn -ScriptBlock $script:RemoteProgressScript -ArgumentList $script:Config.RemoteStaging -AsJob -ErrorAction Stop
        Wait-PatcherJob -Job $job -Activity 'Reading install progress' -TimeoutSec 60
        $rows = @(Receive-Job -Job $job -ErrorAction SilentlyContinue)
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        return $rows
    } catch {
        Write-PatchLog "Progress check failed (the install itself is unaffected): $(Get-ShortError $_)" 'WARN'
        return @()
    }
}

function Write-InstallProgress {
    # What DISM/CBS is up to right now.  With a GROUP of servers this is ONE summary line per poll;
    # a line per server only every ProgressDetailEveryMin (or always when 3 servers or fewer).
    param([string[]]$ComputerName, [int]$ElapsedSec, [switch]$Detail)
    $rows = @(Get-InstallProgress -ComputerName $ComputerName)
    Write-ProgressSummary -Rows $rows -ElapsedSec $ElapsedSec -Detail:$Detail
}

function Write-ProgressSummary {
    # The formatting half, separated so it can be tested without servers.
    param([object[]]$Rows, [int]$ElapsedSec, [switch]$Detail)
    if (-not $Rows -or $Rows.Count -eq 0) { return }
    $min = [int]($ElapsedSec / 60)
    $known = @($Rows | Where-Object { $null -ne $_.Percent -and $_.Percent -ne '' } | ForEach-Object { [int]$_.Percent })
    $alive = @($Rows | Where-Object { $_.DismRunning }).Count
    if ($Rows.Count -gt 1) {
        $summary = '{0} min elapsed - {1} servers installing, dism.exe alive on {2}: ' -f $min, $Rows.Count, $alive
        if ($known.Count -gt 0) {
            $stats = $known | Measure-Object -Minimum -Maximum -Average
            $summary += ('CBS progress {0}%..{1}% (avg {2}%) on {3} of them' -f $stats.Minimum, $stats.Maximum, [int]$stats.Average, $known.Count)
        } else { $summary += 'no CBS progress line yet' }
        Write-PatchLog $summary 'INFO'
    }
    if ($Detail -or $Rows.Count -le 3) {
        foreach ($r in $Rows) {
            $pctText = 'no CBS progress line yet'
            if ($null -ne $r.Percent -and $r.Percent -ne '') { $pctText = "CBS stage $($r.Stage) at $($r.Percent)% (as of $($r.PercentTime))" }
            $dismText = 'dism.exe running'
            if (-not $r.DismRunning) { $dismText = 'dism.exe not running (between packages or finishing)' }
            $name = $r.PSComputerName
            if (-not $name) { $name = $r.Computer }
            Write-PatchLog ("  {0}: {1} min - {2}, {3}, TiWorker CPU {4} s, last DISM line: {5}" -f $name, $min, $pctText, $dismText, $r.TiWorkerCpuSec, $r.LastDism) 'INFO'
        }
    }
    if ($known.Count -gt 0) { Set-GuiProgress -Percent ([int](($known | Measure-Object -Average).Average)) }
}

function Show-PatcherMessage {
    # One place for every pop-up, so they all look the same and sit on top of the GUI.
    # RETURNS the button pressed ('OK', 'Cancel', 'Yes', 'No').  Capture it, or write  $null = Show-PatcherMessage ...
    param(
        [string]$Text,
        [string]$Title = 'Offline Patcher',
        [string]$Buttons = 'OK',          # OK, OKCancel, YesNo
        [string]$Icon = 'Information',    # Information, Warning, Error, Question
        [string]$Default = 'Button1'      # Button1 / Button2 - which button Enter selects
    )
    Add-Type -AssemblyName System.Windows.Forms
    $lineCount = @($Text -split "`r?`n").Count
    if ($lineCount -gt 22) { return (Show-PatcherLongMessage -Text $Text -Title $Title -Buttons $Buttons -Default $Default) }
    $owner = $script:Gui['Form']
    if ($owner -and -not $owner.IsDisposed) {
        return [string][System.Windows.Forms.MessageBox]::Show($owner, $Text, $Title, $Buttons, $Icon, $Default)
    }
    return [string][System.Windows.Forms.MessageBox]::Show($Text, $Title, $Buttons, $Icon, $Default)
}

function Show-PatcherLongMessage {
    # A MessageBox taller than the screen loses its buttons; long texts get a scrollable window instead.
    param([string]$Text, [string]$Title, [string]$Buttons = 'OK', [string]$Default = 'Button1')
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = $Title; $dlg.Size = New-Object System.Drawing.Size(900, 600); $dlg.StartPosition = 'CenterParent'
    $dlg.Font = New-Object System.Drawing.Font('Segoe UI', 9); $dlg.MinimizeBox = $false; $dlg.MaximizeBox = $false
    $box = New-Object System.Windows.Forms.TextBox
    $box.Multiline = $true; $box.ReadOnly = $true; $box.ScrollBars = 'Both'; $box.WordWrap = $false; $box.Dock = 'Fill'
    $box.Font = New-Object System.Drawing.Font('Consolas', 9); $box.BackColor = 'White'; $box.Text = $Text
    $bottom = New-Object System.Windows.Forms.Panel; $bottom.Dock = 'Bottom'; $bottom.Height = 44
    $labels = @('OK')
    if ($Buttons -eq 'OKCancel') { $labels = @('OK', 'Cancel') }
    if ($Buttons -eq 'YesNo') { $labels = @('Yes', 'No') }
    $x = 880 - (110 * $labels.Count)
    $buttonObjects = @()
    foreach ($label in $labels) {
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $label; $b.Size = New-Object System.Drawing.Size(100, 30); $b.Location = New-Object System.Drawing.Point($x, 7); $b.Anchor = 'Top,Right'
        $b.Tag = $label
        $b.Add_Click({ $dlg.Tag = $this.Tag; $dlg.Close() })
        $bottom.Controls.Add($b); $buttonObjects += $b; $x += 110
    }
    $dlg.Controls.Add($box); $dlg.Controls.Add($bottom); $box.BringToFront(); $box.Select(0, 0)
    # Default button: Button2 = the second (No / Cancel) so Enter can never approve by accident.
    $dlg.AcceptButton = $buttonObjects[0]
    if ($Default -eq 'Button2' -and $buttonObjects.Count -gt 1) { $dlg.AcceptButton = $buttonObjects[1] }
    $dlg.CancelButton = $buttonObjects[-1]
    $dlg.Tag = $labels[-1]   # closing with X = the "safe" answer (No / Cancel / OK)
    $owner = $script:Gui['Form']
    if ($owner -and -not $owner.IsDisposed) { [void]$dlg.ShowDialog($owner) } else { [void]$dlg.ShowDialog() }
    $answer = [string]$dlg.Tag
    $dlg.Dispose()
    return $answer
}

function Confirm-SafetyChecks {
    # THE TWO MANDATORY POP-UPS.  Both must be answered Yes or nothing is installed.
    # The default button is "No" so a stray Enter key can never approve patching.
    # Returns a single [bool]; every other pop-up result is discarded with $null = ...
    param([string[]]$Servers)
    $list = ($Servers -join "`n")
    $who = Get-OperatorIdentity

    Write-PatchLog 'Safety check 1 of 2: asking operator to confirm VMware snapshot' 'WHY'
    $q1 = Show-PatcherMessage -Title 'SAFETY CHECK 1 of 2 - VMware snapshot' -Buttons 'YesNo' -Icon 'Warning' -Default 'Button2' -Text @"
Has a VMware SNAPSHOT been taken of every server below?

$list

Answer No and nothing will be installed.
"@
    if ($q1 -ne 'Yes') {
        Write-PatchLog "ABORTED - $who did not confirm the VMware snapshot (answer: $q1)" 'ERROR'
        $null = Show-PatcherMessage -Text 'Patching aborted. Take the snapshots first, then come back.' -Title 'Aborted' -Icon 'Error'
        return [bool]$false
    }
    Write-PatchLog "Confirmed by ${who}: VMware snapshot taken for $($Servers -join ', ')" 'OK'

    Write-PatchLog 'Safety check 2 of 2: asking operator to confirm Trellix maintenance mode' 'WHY'
    $q2 = Show-PatcherMessage -Title 'SAFETY CHECK 2 of 2 - Trellix' -Buttons 'YesNo' -Icon 'Warning' -Default 'Button2' -Text @"
Has TRELLIX been placed into MAINTENANCE MODE for every server below?

$list

Answer No and nothing will be installed.
"@
    if ($q2 -ne 'Yes') {
        Write-PatchLog "ABORTED - $who did not confirm Trellix maintenance mode (answer: $q2)" 'ERROR'
        $null = Show-PatcherMessage -Text 'Patching aborted. Put Trellix into maintenance mode first, then come back.' -Title 'Aborted' -Icon 'Error'
        return [bool]$false
    }
    Write-PatchLog "Confirmed by ${who}: Trellix in maintenance mode for $($Servers -join ', ')" 'OK'
    return [bool]$true
}

function New-PatchPlan {
    # One row per (server, patch) with Go = $true/$false and the reason.  The decision itself
    # lives in Get-PatchVerdict (04-Patches.ps1) so the grid and the plan can never disagree.
    param([string[]]$ComputerName, [object[]]$Patches)
    $plan = @()
    foreach ($c in $ComputerName) {
        $s = $script:ServerStatus[$c]
        foreach ($p in $Patches) {
            $v = Get-PatchVerdict -Status $s -Patch $p
            $plan += [pscustomobject]@{ Computer = $c; KB = $p.KB; Name = $p.Name; File = $p.FullName; Hash = $p.Hash; Go = $v.Go; Reason = $v.Reason }
        }
    }
    return $plan
}

function Install-PatchOnServers {
    param(
        [Parameter(Mandatory = $true)][string[]]$ComputerName,
        [Parameter(Mandatory = $true)][object[]]$Patches      # objects from Get-PatchFiles
    )
    $targets = @(Get-UniqueNames $ComputerName)
    $who = Get-OperatorIdentity
    Write-PatchLog ("=== INSTALL REQUESTED by {0}: {1} on {2} ===" -f $who, (($Patches | ForEach-Object { $_.KB }) -join ', '), ($targets -join ', ')) 'INFO'

    # 1. Fresh status, 2. plan
    Write-PatchLog 'Pre-flight: refreshing status so we never patch a server that is pending a reboot or busy' 'WHY'
    Get-ServerStatus -ComputerName $targets | Out-Null
    $targets = @(Remove-DuplicateServers $targets)
    $plan = New-PatchPlan -ComputerName $targets -Patches $Patches
    foreach ($item in $plan) {
        $lvl = 'WARN'; if ($item.Go) { $lvl = 'INFO' }
        Write-PatchLog ("Plan: {0}  {1}  -> {2}" -f $item.Computer, $item.KB, $item.Reason) $lvl
    }
    $todo = @($plan | Where-Object { $_.Go })
    if ($todo.Count -eq 0) {
        $null = Show-PatcherMessage -Text "Nothing to install - every server/patch pair is either done, blocked or unreachable. See the log for the reason per server." -Title 'Nothing to do' -Icon 'Information'
        return @()
    }

    # 3. Show the plan
    $planText = ($plan | ForEach-Object { '{0,-36} {1,-10} {2}' -f $_.Computer, $_.KB, $_.Reason }) -join "`n"
    $ok = Show-PatcherMessage -Title 'The plan' -Buttons 'OKCancel' -Icon 'Question' -Text @"
This is what will happen ("ready" rows are installed, the rest are skipped):

$planText

Continue to the safety checks?
"@
    if ($ok -ne 'OK') { Write-PatchLog "$who cancelled at the plan screen" 'WARN'; return @() }

    # 4 + 5. The two mandatory safety pop-ups.  Strict comparison: anything but a real $true aborts.
    $goServers = @(Get-UniqueNames ($todo | ForEach-Object { $_.Computer }))
    $confirmed = Confirm-SafetyChecks -Servers $goServers
    if ($confirmed -isnot [bool] -or $confirmed -ne $true) { Write-PatchLog 'Safety checks not confirmed - nothing was touched' 'WARN'; return @() }

    # 6a. The pop-ups may have been open for a long time: check the servers AGAIN and drop any that changed.
    Write-PatchLog 'Re-checking the servers now that the safety checks are done (status may be minutes old)' 'WHY'
    Get-ServerStatus -ComputerName $goServers | Out-Null
    $recheck = New-PatchPlan -ComputerName $goServers -Patches $Patches
    $stillGo = @()
    foreach ($item in $todo) {
        $now = $recheck | Where-Object { $_.Computer -eq $item.Computer -and $_.KB -eq $item.KB } | Select-Object -First 1
        if ($now -and $now.Go) { $stillGo += $item } else { Write-PatchLog ("Dropped {0} {1} - no longer ready: {2}" -f $item.Computer, $item.KB, $now.Reason) 'WARN' }
    }
    $todo = $stillGo
    $goServers = @(Get-UniqueNames ($todo | ForEach-Object { $_.Computer }))
    if ($todo.Count -eq 0) {
        $null = Show-PatcherMessage -Text 'Every server changed state while the pop-ups were open (pending reboot, busy or unreachable). Nothing was installed - check the log and try again.' -Title 'Nothing to do' -Icon 'Warning'
        return @()
    }

    # 6b + 7. Per server: session, locked staging folder, copy - and the install is started the moment
    #         that server's copy is verified, so server 1 is already installing while server 2 copies.
    #         Copies go one server at a time (the log stays readable); installs run in parallel.
    #         Everything sits in try/finally so sessions never leak.
    $sessions = @()
    $filesByComputer = @{}
    $results = @()
    $jobs = @()
    $keepOpen = @()     # sessions whose install is still running on the server (timeout) - never torn down
    $script:EnvelopeTipShown = $false
    try {
        $n = 0
        foreach ($c in $goServers) {
            $n++
            $sess = $null
            try {
                $conn = Get-ConnectionArgs
                Write-PatchLog ("[{0}/{1}] New-PSSession -ComputerName {2} -Port {3}" -f $n, $goServers.Count, $c, $conn.Port) 'CMD'
                $sess = New-PSSession -ComputerName $c @conn -ErrorAction Stop
                $ready = Invoke-Command -Session $sess -ScriptBlock $script:RemoteStagingScript -ArgumentList $script:Config.RemoteStaging -ErrorAction Stop
                Write-PatchLog "$c - $ready" 'INFO'

                $remoteFiles = @()
                $remoteHashes = @()
                foreach ($item in @($todo | Where-Object { $_.Computer -eq $c })) {
                    # Built as a string on purpose: Join-Path would check the drive letter on THIS machine.
                    $dest = $script:Config.RemoteStaging.TrimEnd('\') + '\' + $item.Name
                    $sizeMB = [math]::Round((Get-Item -LiteralPath $item.File).Length / 1MB, 1)
                    Write-PatchLog ("Copy-FileToSession -Path '{0}' -Destination '{1}' -Session [{2}]   ({3} MB, sent in WinRM-sized slices - this takes a while)" -f $item.File, $dest, $c, $sizeMB) 'CMD'
                    Copy-FileToSession -Path $item.File -Destination $dest -Session $sess -LocalHash $item.Hash | Out-Null
                    $remoteFiles += $dest
                    $remoteHashes += $item.Hash
                }
                $filesByComputer[$c] = $remoteFiles
                $sessions += $sess
                Write-PatchLog ("Invoke-Command -Session [{0}] -AsJob  (install script: {1})" -f $c, ($remoteFiles -join ', ')) 'CMD'
                $jobs += Invoke-Command -Session $sess -ScriptBlock $script:RemoteInstallScript -ArgumentList $remoteFiles, $remoteHashes, $script:Config.CleanupStaging, $script:Config.RequireValidSignature, $who -AsJob
                Write-PatchLog "$c - install started on the server; it keeps running while the next server is copied" 'OK'
            } catch {
                $msg = Get-ShortError $_
                Write-PatchLog "$c - staging failed: $msg" 'ERROR'
                Write-PatchLog "   failed at: $(Get-ErrorLocation $_)" 'WHY'
                if ($sess) { Remove-PSSession -Session $sess -ErrorAction SilentlyContinue }
                foreach ($item in @($todo | Where-Object { $_.Computer -eq $c })) {
                    $results += New-InstallResult -Computer $c -KB $item.KB -File $item.Name -Message "staging failed: $msg"
                }
            }
        }

        # 8. Wait for every install, keeping the GUI alive and reporting progress, then collect.
        if ($jobs.Count -gt 0) {
            Write-PatchLog ("All copies done; DISM is running on {0} server(s). Its log goes quiet after 'CBS session options'; real progress comes from CBS.log: a summary line every {1} s, one line per server every {2} min. A cumulative update usually takes 10-30 min - leave this window open (status checks still work meanwhile)." -f $jobs.Count, $script:Config.ProgressEverySec, $script:Config.ProgressDetailEveryMin) 'WHY'
        }
        $finished = @('Completed', 'Failed', 'Stopped', 'Disconnected')
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $lastProgress = 0
        $lastDetail = 0
        while (@($jobs | Where-Object { $finished -notcontains $_.State }).Count -gt 0 -and $watch.Elapsed.TotalMinutes -lt $script:Config.InstallTimeoutMin) {
            $running = @($jobs | Where-Object { $finished -notcontains $_.State } | ForEach-Object { $_.Location })
            Set-GuiStatus ('Installing on {0} server(s) [{1}] ... {2} min {3} s (DISM is slow, grab a coffee)' -f $running.Count, ($running -join ', '), [int][math]::Floor($watch.Elapsed.TotalMinutes), $watch.Elapsed.Seconds)
            if ($watch.Elapsed.TotalSeconds - $lastProgress -ge $script:Config.ProgressEverySec) {
                $lastProgress = $watch.Elapsed.TotalSeconds
                $detail = $false
                if ($watch.Elapsed.TotalSeconds - $lastDetail -ge ($script:Config.ProgressDetailEveryMin * 60)) { $detail = $true; $lastDetail = $watch.Elapsed.TotalSeconds }
                Write-InstallProgress -ComputerName $running -ElapsedSec ([int]$watch.Elapsed.TotalSeconds) -Detail:$detail
            }
            Start-Sleep -Milliseconds 500
        }
        foreach ($j in $jobs) {
            $c = $j.Location
            if ($finished -notcontains $j.State -or $j.State -eq 'Disconnected') {
                # Still running after the timeout (or the connection dropped).  Do NOT stop the job and do
                # NOT close the session: that would kill DISM half way.  Disconnect so the server carries on.
                $sess = $sessions | Where-Object { $_.ComputerName -eq $c } | Select-Object -First 1
                $keepOpen += $sess
                try { Disconnect-PSSession -Session $sess -ErrorAction Stop | Out-Null } catch { }
                $msg = "UNKNOWN - still running on the server after $($script:Config.InstallTimeoutMin) min (state $($j.State)). The install continues there. Result file: $($script:Config.RemoteStaging)\result-*.txt on $c. Reconnect: Get-PSSession -ComputerName $c | Connect-PSSession"
                Write-PatchLog "$c - $msg" 'ERROR'
                foreach ($f in $filesByComputer[$c]) { $results += New-InstallResult -Computer $c -KB (Get-KBFromName $f) -File (Split-Path -Path $f -Leaf) -Message $msg }
                continue
            }
            $jobErrors = @()
            $out = @(Receive-Job -Job $j -ErrorAction SilentlyContinue -ErrorVariable jobErrors)
            if ($out.Count -eq 0) {
                $reason = 'no result returned'
                if ($jobErrors.Count -gt 0) { $reason = Get-ShortError $jobErrors[0] }
                Write-PatchLog "$c - install job failed: $reason" 'ERROR'
                foreach ($f in $filesByComputer[$c]) { $results += New-InstallResult -Computer $c -KB (Get-KBFromName $f) -File (Split-Path -Path $f -Leaf) -Message $reason }
            }
            foreach ($r in $out) {
                $lvl = 'ERROR'; if ($r.Success) { $lvl = 'OK' }
                Write-PatchLog ("RESULT {0}  {1}  exit {2}  -> {3}   (by {4})" -f $r.Computer, $r.KB, $r.ExitCode, $r.Message, $who) $lvl
                foreach ($d in $r.Detail) { Write-PatchLog "    $d" 'CMD' }
                $results += $r
            }
            Remove-Job -Job $j -Force -ErrorAction SilentlyContinue
        }
    } finally {
        foreach ($sess in $sessions) {
            if ($keepOpen -contains $sess) { continue }
            Remove-PSSession -Session $sess -ErrorAction SilentlyContinue
        }
    }

    # 9. Fresh status again so the grid tells the truth
    Get-ServerStatus -ComputerName $goServers | Out-Null
    $good = @($results | Where-Object { $_.Success }).Count
    $bad  = @($results | Where-Object { -not $_.Success }).Count
    $reb  = @($results | Where-Object { $_.RebootRequired }).Count
    Write-PatchLog ("=== INSTALL FINISHED (by {3}): {0} ok, {1} failed/unknown, {2} need a reboot ===" -f $good, $bad, $reb, $who) 'INFO'
    return $results
}

function New-InstallResult {
    # A failure result shaped exactly like the ones the remote script returns.
    param([string]$Computer, [string]$KB, [string]$File, [string]$Message)
    return [pscustomobject]@{ Computer = $Computer; KB = $KB; File = $File; Success = $false; RebootRequired = $false; ExitCode = $null; Message = $Message; Detail = @(); Packages = @() }
}

function Get-KBFromName {
    param([string]$Name)
    if ($Name -match '(?i)(KB\d{6,7})') { return $Matches[1].ToUpper() }
    return 'KB?'
}

function Remove-DuplicateServers {
    # Two names that resolve to the SAME computer (short name + FQDN, or different case) would get two
    # concurrent installs.  After a status check we know each server's real name, so keep the first alias.
    param([string[]]$Names)
    $seen = @{}
    $keep = @()
    foreach ($n in $Names) {
        $s = $script:ServerStatus[$n]
        $real = $n
        if ($s -and $s.Reachable -and $s.Computer) { $real = $s.Computer.ToUpper() }
        if ($seen.ContainsKey($real)) {
            Write-PatchLog "$n is the same computer as $($seen[$real]) ($real) - skipping the duplicate" 'WARN'
            continue
        }
        $seen[$real] = $n
        $keep += $n
    }
    return $keep
}

# RUNS ON THE TARGET SERVER: refuses to reboot while servicing is active, then schedules the
# restart 10 s out with shutdown.exe so this call returns before the connection is cut.
$script:RemoteRebootScript = {
    param([string]$Operator)
    # Same "really servicing?" test as the status and install scripts: dism/wusa present, TiWorker actually
    # busy (CPU over 2 s), or the Windows Update agent installing.  An idle TiWorker does not block a reboot.
    $busy = @(Get-Process -Name dism, wusa -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName } | Sort-Object -Unique)
    $ti = @(Get-Process -Name TiWorker -ErrorAction SilentlyContinue)
    if ($ti.Count -gt 0) {
        $cpu1 = 0.0; foreach ($p in $ti) { try { if ($p.CPU) { $cpu1 += $p.CPU } } catch { } }
        Start-Sleep -Seconds 2
        $cpu2 = 0.0; foreach ($p in @(Get-Process -Name TiWorker -ErrorAction SilentlyContinue)) { try { if ($p.CPU) { $cpu2 += $p.CPU } } catch { } }
        if (($cpu2 - $cpu1) -ge 0.25) { $busy += ('TiWorker busy ({0:N1} s CPU in 2 s)' -f ($cpu2 - $cpu1)) }
    }
    try { if ((New-Object -ComObject 'Microsoft.Update.Session').CreateUpdateInstaller().IsBusy) { $busy += 'Windows Update agent installing' } } catch { }
    if ($busy.Count -gt 0) { throw "servicing still running ($($busy -join ', ')) - NOT rebooting; try again in a few minutes" }
    $null = & shutdown.exe /r /t 10 /d p:2:17 /c "Offline Patcher reboot requested by $Operator" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "shutdown.exe returned $LASTEXITCODE" }
    return "reboot scheduled in 10 s on $env:COMPUTERNAME"
}

function Restart-PatchedServers {
    # Reboots over WinRM.  Separate button, separate confirmations, never automatic.
    # Default set = servers whose FRESH status says "pending reboot".  Anything else needs a second,
    # explicit Yes.  On the server, a reboot is refused while dism/TiWorker are still running.
    param([Parameter(Mandatory = $true)][string[]]$ComputerName)
    $targets = @(Get-UniqueNames $ComputerName)
    $who = Get-OperatorIdentity
    Write-PatchLog "Reboot requested by $who for $($targets -join ', ') - checking status first" 'WHY'
    Get-ServerStatus -ComputerName $targets | Out-Null
    $targets = @(Remove-DuplicateServers $targets)
    $pending = @(); $notPending = @(); $unreachable = @()
    foreach ($c in $targets) {
        $s = $script:ServerStatus[$c]
        if (-not $s -or -not $s.Reachable) { $unreachable += $c }
        elseif ($s.PendingReboot) { $pending += $c }
        else { $notPending += $c }
    }
    foreach ($c in $unreachable) { Write-PatchLog "$c - unreachable, not rebooting" 'WARN' }

    $toReboot = @()
    if ($pending.Count -gt 0) {
        $a = Show-PatcherMessage -Title 'Reboot?' -Buttons 'YesNo' -Icon 'Warning' -Default 'Button2' -Text ("These servers are PENDING A REBOOT. Reboot them now?`n`n{0}" -f ($pending -join "`n"))
        if ($a -eq 'Yes') { $toReboot += $pending } else { Write-PatchLog "$who answered $a - pending servers not rebooted" 'WARN' }
    }
    if ($notPending.Count -gt 0) {
        $a = Show-PatcherMessage -Title 'Reboot servers that are NOT pending a reboot?' -Buttons 'YesNo' -Icon 'Warning' -Default 'Button2' -Text ("These servers do NOT need a reboot according to their status. Reboot them anyway?`n`n{0}`n`n(Logged-on users will be disconnected.)" -f ($notPending -join "`n"))
        if ($a -eq 'Yes') { $toReboot += $notPending } else { Write-PatchLog "$who answered $a - servers not pending a reboot are left alone" 'INFO' }
    }
    if ($toReboot.Count -eq 0) { Write-PatchLog 'No reboot sent' 'INFO'; return }

    foreach ($c in $toReboot) {
        try {
            $conn = Get-ConnectionArgs
            Write-PatchLog "Invoke-Command -ComputerName $c -Port $($conn.Port) (RemoteRebootScript: refuse if dism/TiWorker busy, then shutdown.exe /r /t 10)" 'CMD'
            $msg = Invoke-Command -ComputerName $c @conn -ScriptBlock $script:RemoteRebootScript -ArgumentList $who -ErrorAction Stop
            Write-PatchLog "REBOOT $c - $msg (by $who)" 'OK'
            $script:ServerStatus.Remove($c)   # old status is now meaningless
        } catch {
            $err = Get-ShortError $_
            if ($err -match 'shut down|restart|connection|closed|aborted') { Write-PatchLog "REBOOT $c - the connection dropped while the reboot was being sent; it is probably rebooting: $err" 'WARN'; $script:ServerStatus.Remove($c) }
            else { Write-PatchLog "REBOOT $c - refused or failed: $err" 'ERROR' }
        }
    }
}

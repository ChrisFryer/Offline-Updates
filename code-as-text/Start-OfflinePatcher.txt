# =====================================================================
#  Start-OfflinePatcher.ps1  -  THE ENTRY POINT  (PowerShell 5.1, WinForms)
# ---------------------------------------------------------------------
#  HOW TO RUN
#    A) Normal:   right-click this file -> "Run with PowerShell", or
#                 powershell.exe -ExecutionPolicy Bypass -File .\Start-OfflinePatcher.ps1
#    B) If .ps1 files are blocked by ExecutionPolicy, open PowerShell IN THIS FOLDER and run:
#                 Invoke-Expression (Get-Content -Raw .\Offline-Patcher-AllInOne.txt)
#       (or copy/paste the contents of that .txt into the console)
#       This does NOT help against AppLocker / WDAC: they put PowerShell into ConstrainedLanguage
#       mode, in which WinForms cannot be used at all.  The check below says so plainly.
#    C) Functions only, no window (fault finding):  $NoGui = $true  before A or B
#
#  WHAT IT DOES
#    1. Refuses to run in ConstrainedLanguage mode (nothing would work)
#    2. Works out the root folder (where the lists, \patches and \logs live) and checks it
#    3. Loads the building blocks from \lib - an EXPLICIT list, so a stray .ps1 cannot sneak in
#    4. Opens the GUI.  The console window stays open as a colour log.
#  Run it as the user who is an administrator on the target servers; it never
#  elevates itself and every credential prompt appears in the foreground.
#
#  TRUST BOUNDARY: everything in this folder runs as YOU on EVERY server.  Keep the
#  folder writable only by the operators (not on an open share).
# =====================================================================
#Requires -Version 5.1

# ---------------------------------------------------------------------
#  REVIEW RECORD  -  Start-OfflinePatcher.ps1
# ---------------------------------------------------------------------
#  Independent review 2026-10-14 (see CODE-REVIEW.md).  Fixed here:
#  R-25 a second Invoke-Expression run kept the old root folder ($AllInOne
#  is removed after loading; the all-in-one header sets the root);
#  R-27 lib\*.ps1 was a wildcard dot-source (now an explicit list, extra
#  files are reported and ignored); R-29 no ConstrainedLanguage check;
#  R-30 credentials outlived the GUI in paste mode; R-33 in paste mode
#  the root folder silently became whatever the console's current folder
#  was (now checked for the tool's own files).
#  ---------------------------------------------------------------------
#  HUMAN REVIEW  (fill in by hand and keep it in the file)
#  Reviewer   : ______________________________   Date : ______________
#  Verdict    : [ ] Approved   [ ] Approved with comments   [ ] Changes required
#  Comments   :
#    -
# =====================================================================

# 1. Language mode.  AppLocker/WDAC "blocked scripts" = ConstrainedLanguage: no Add-Type, no WinForms, no .NET.
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw "PowerShell is in $($ExecutionContext.SessionState.LanguageMode) mode (AppLocker / WDAC policy). This tool needs FullLanguage - the .txt fallback only helps against ExecutionPolicy, not against application control."
}

# 2. Root folder.  $PSScriptRoot is empty when the code is pasted into a console or loaded with
#    Invoke-Expression; the all-in-one header sets $script:RootFolder to the current folder first,
#    and we check that the folder really is the tool's folder (not C:\Windows\System32).
if ($PSScriptRoot) { $script:RootFolder = $PSScriptRoot } elseif (-not $script:RootFolder) { $script:RootFolder = (Get-Location).Path }
$markers = @('Start-OfflinePatcher.ps1', 'Offline-Patcher-AllInOne.txt', 'lib')
$found = @($markers | Where-Object { Test-Path -LiteralPath (Join-Path $script:RootFolder $_) })
if ($found.Count -eq 0) {
    throw "The root folder '$script:RootFolder' does not contain the tool (no Start-OfflinePatcher.ps1, Offline-Patcher-AllInOne.txt or lib\ folder). cd to the tool folder first, then run again."
}

# 3. Load the building blocks - an explicit list in load order.  The all-in-one text sets
#    $script:AllInOne = $true at its top because the functions are already defined above this point.
$script:LibFiles = @('01-Config.ps1', '02-Logging.ps1', '03-Groups.ps1', '04-Patches.ps1', '05-WinRM.ps1', '06-Install.ps1', '07-Gui.ps1', '08-CodeTour.ps1')
if (-not $script:AllInOne) {
    $libFolder = Join-Path $script:RootFolder 'lib'
    if (-not (Test-Path -LiteralPath $libFolder)) {
        throw "Cannot find the 'lib' folder. Root folder = '$script:RootFolder'. cd to the tool folder and try again."
    }
    foreach ($name in $script:LibFiles) {
        $path = Join-Path $libFolder $name
        if (-not (Test-Path -LiteralPath $path)) { throw "Missing building block: $path" }
        Write-Host "Loading $name" -ForegroundColor DarkGray
        . $path
    }
    $extra = @(Get-ChildItem -LiteralPath $libFolder -Filter '*.ps1' | Where-Object { $script:LibFiles -notcontains $_.Name })
    foreach ($e in $extra) { Write-Host "NOT loaded (not part of the tool): lib\$($e.Name) - remove it or add it to the list in Start-OfflinePatcher.ps1" -ForegroundColor Yellow }
} else {
    # Forget the flag so a later ". .\Start-OfflinePatcher.ps1" in the same console loads lib\ normally.
    Remove-Variable -Name AllInOne -Scope Script -ErrorAction SilentlyContinue
}

# 4. Hello (console + log file), then the window.
Write-Host $script:Banner -ForegroundColor Cyan
Write-PatchLog ("=== SESSION START by {0} on {1} (PID {2}, PowerShell {3}) root {4} ===" -f (Get-OperatorIdentity), $env:COMPUTERNAME, $PID, $PSVersionTable.PSVersion, $script:RootFolder) 'INFO'
if ($NoGui) {
    Write-Host 'NoGui mode: functions are loaded. Try  Get-PatchGroups ; Get-PatchFiles ; Get-ServerStatus -ComputerName SRV01' -ForegroundColor Yellow
} else {
    try {
        Show-PatcherGui
    } finally {
        if ($script:Credential) { Clear-PatcherCredential }
    }
}

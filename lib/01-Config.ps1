# =====================================================================
#  01-Config.ps1  -  SETTINGS AND SHARED STATE
# ---------------------------------------------------------------------
#  Everything an operator might want to tweak lives in $script:Config.
#  Everything the tool remembers while it runs (credentials, last known
#  server status, loaded lists) lives in the other $script: variables
#  below.  From the console you can inspect any of them at any time,
#  for example:   $Config        $ServerStatus        $Patches
#
#  NOTE: "$script:" simply means "a variable shared by all the files of
#  this tool".  When the code is pasted into a console it is the same
#  as a normal global variable.
# =====================================================================

# ---------------------------------------------------------------------
#  REVIEW RECORD  -  01-Config.ps1
# ---------------------------------------------------------------------
#  Independent review 2026-10-14 (see CODE-REVIEW.md).  Changed here:
#  new settings RequireValidSignature and AllowUnknownTargetBuild (R-09,
#  R-11); $script:Operator for the audit trail (R-18).  R-25 (a second
#  Invoke-Expression run in the same console kept the OLD root folder) is
#  fixed by the all-in-one header always setting $script:RootFolder.
#  ---------------------------------------------------------------------
#  HUMAN REVIEW  (fill in by hand and keep it in the file)
#  Reviewer   : __CF____________________________   Date : ___14-10-2026___________
#  Verdict    : [x] Approved   [ ] Approved with comments   [ ] Changes required
#  Comments   :
#    -
# =====================================================================

# The launcher (or the all-in-one header) sets $script:RootFolder before loading this file.
# If somebody loads this file on its own, fall back to the current folder.
if (-not $script:RootFolder) { $script:RootFolder = (Get-Location).Path }

$script:Config = @{
    # ---- Folders (relative to the root folder = where Start-OfflinePatcher.ps1 lives) ----
    PatchFolder    = Join-Path $script:RootFolder 'patches'   # drop .msu / .cab files here
    PatchInfoFolder = Join-Path $script:RootFolder 'patches\_info'   # cache: which build each file targets
    LogFolder      = Join-Path $script:RootFolder 'logs'      # one log file per day is written here

    # ---- WinRM ----
    WinRMPort      = 5985        # HTTP WinRM. 5986 would be HTTPS.
    OpenTimeoutSec = 20          # give up on a silent server after this many seconds
    MaxParallel    = 16          # how many servers are checked at the same time

    # ---- Remote staging (on the target server) ----
    RemoteStaging  = 'C:\PatchStaging'   # patch files are copied here before install
    CleanupStaging = $true               # delete the copied file after a successful install
    ProgressEverySec = 45                # while DISM runs, read CBS.log progress this often (one summary line)
    ProgressDetailEveryMin = 5           # ... and one line PER SERVER this often (always, when 3 servers or fewer)
    InstallTimeoutMin = 120              # stop waiting for an install after this long (DISM is NOT killed)

    # ---- Safety thresholds ----
    MinFreeGB      = 5           # refuse to install when C: has less free space than this
    WarnFreeGB     = 10          # show a warning colour below this
    TreatPendingFileRenameAsReboot = $false  # PendingFileRenameOperations is noisy; off by default
    RequireValidSignature  = $true    # a patch must be Authenticode-signed by Microsoft (checked here AND on the server)
    AllowUnknownTargetBuild = $false  # a file whose target build cannot be read is blocked (cannot tell 2019 from 2022)

    # ---- Fun ----
    OperatorName   = 'sys-admin'   # shown in the window title, the banner, the welcome line and a quip
                                   # ("<name>'s Patch Palace") - put the operator's first name here
}

# ---- Shared runtime state (filled in while the tool runs) ----
$script:Operator     = "$env:USERDOMAIN\$env:USERNAME"   # who is running the tool - goes into every audit line
$script:Credential   = $null   # PSCredential entered by the operator (kept in memory only, cleared when the GUI closes)
$script:ServerStatus = @{}     # hashtable: server name -> last status object from Get-ServerStatus
$script:Groups       = @()     # output of Get-PatchGroups
$script:Patches      = @()     # output of Get-PatchFiles
$script:Gui          = @{}     # hashtable of WinForms controls, filled by Show-PatcherGui

$script:Banner = @'
   ____        _       _       ____       _
  |  _ \ __ _ | |_ ___| |__   |  _ \ __ _| | __ _  ___ ___
  | |_) / _` || __/ __| '_ \  | |_) / _` | |/ _` |/ __/ _ \
  |  __/ (_| || || (__| | | | |  __/ (_| | | (_| | (_|  __/
  |_|   \__,_| \__\___|_| |_| |_|   \__,_|_|\__,_|\___\___|
        Offline Server 2022 patching over WinRM (5985)
'@

# The Patch Palace - offline Server 2022 patching over WinRM

The window title, banner and one of the quips carry the operator's name from `OperatorName` in
`lib\01-Config.ps1` (default `sys-admin`), so the tool can be personalised for whoever does the patching.

A small, readable PowerShell 5.1 tool with a Windows Forms GUI that:

1. Reads server lists (`PatchGroup-A.txt`, `PatchGroup-B.txt`, ... any `*.txt` in this folder).
2. Reads the update files you dropped into `patches\` (`.msu` or `.cab`, KB number taken from the file name).
3. Asks every server over **WinRM on TCP 5985** for its build, free disk, installed hotfixes and pending-reboot state.
4. Shows, per server and per KB: **Installed / Installed (history) / READY / Blocked: reboot, servicing, disk,
   signature, OS unknown or wrong OS / ?** (unreachable).
5. Installs the ticked KBs on the ticked servers (individually or a whole group) **only after**
   the plan is accepted **and** two safety pop-ups are answered *Yes*:
   * "Has a VMware snapshot been taken?"
   * "Has Trellix been placed in maintenance mode?"
   Either *No* aborts with nothing touched.
6. Explains itself: the **Code Tour** tab shows, for every step, what it does, why, how it fails, and the live source code.

Nothing is downloaded. The tool never goes online. Credentials are only ever requested in the foreground with the standard Windows prompt, in the logged-on user's context, and are kept in memory only.

## Folder layout

| Path | Purpose |
|---|---|
| `Start-OfflinePatcher.ps1` | The launcher. Sets the root folder, loads `lib\*.ps1`, opens the GUI. |
| `lib\01-Config.ps1` | Settings (`$Config`) and shared state. Change port, timeouts, thresholds here. |
| `lib\02-Logging.ps1` | `Write-PatchLog`: writes to `logs\`, the console and the GUI, colour coded. |
| `lib\03-Groups.ps1` | Parses the group `.txt` files. |
| `lib\04-Patches.ps1` | Scans `patches\` and extracts KB numbers from file names. |
| `lib\05-WinRM.ps1` | Status check over WinRM, credential prompt, `Test-WSMan` no-auth test. |
| `lib\06-Install.ps1` | The plan, the two safety pop-ups, file staging, DISM install, reboot. |
| `lib\07-Gui.ps1` | The window. Every button is a short call into the files above. |
| `lib\08-CodeTour.ps1` | The training text shown in the Code Tour tab. |
| `Build-TextCopies.ps1` | Regenerates the `.txt` copies below. Run it after editing any `.ps1`. |
| `Build-Diagrams.ps1` | Draws the six pictures in `images\` that the Code Tour shows (GDI+, offline). |
| `images\*.png` | The pictures: big picture, ports, operator folder, status check, install flow, endpoint layout. |
| `CODE-REVIEW.md` | The independent review: every finding, what was done, and the human sign-off checklist. |
| `code-as-text\*.txt` | One text copy per source file (same content, `.txt` extension). |
| `Offline-Patcher-AllInOne.txt` | All files concatenated in load order, for pasting into a console. |
| `PatchGroup-A/B/C.txt` | Sample server lists. One name per line, `#` for comments. |
| `patches\` | Put the `.msu` / `.cab` files here. See `patches\README.txt`. |
| `logs\` | `Patcher-YYYYMMDD.log`, created on first run. |

## Running it

**Normal way** (needs `.ps1` execution to be allowed):

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Start-OfflinePatcher.ps1
```

or right-click `Start-OfflinePatcher.ps1` and choose *Run with PowerShell*.

**When `.ps1` files are blocked**, open a PowerShell window, `cd` into this folder, and load the text copy:

```powershell
Invoke-Expression (Get-Content -Raw .\Offline-Patcher-AllInOne.txt)
```

You can also open `Offline-Patcher-AllInOne.txt` in Notepad, select all, and paste it into the console.
The code works out the root folder from the current directory in that case, so `cd` first; it refuses to run
from a folder that does not contain the tool. This fallback only helps against ExecutionPolicy. If AppLocker or
WDAC puts PowerShell into ConstrainedLanguage mode, the tool stops with a clear message, because WinForms
cannot run in that mode at all.

**Trust boundary.** Everything in this folder runs as you on every server. Keep the folder writable only by
the operators, never on an open share. The launcher loads an explicit list of `lib\` files and reports any
extra `.ps1` it finds there instead of running it.

**Functions only, no window** (fault finding, or to run one step by hand):

```powershell
$NoGui = $true
Invoke-Expression (Get-Content -Raw .\Offline-Patcher-AllInOne.txt)   # or . .\Start-OfflinePatcher.ps1
Get-PatchGroups
Get-PatchFiles
Get-ServerStatus -ComputerName SRV-APP01
$ServerStatus['SRV-APP01'] | Format-List
Show-PatcherGui       # open the window whenever you like
```

Run the tool as the account that is a local administrator on the target servers. It never elevates itself.
The PowerShell console stays open behind the GUI and shows the same log in colour.

## Finding this month's patch

Do this on a machine that has internet, then copy the file into `patches\`.

1. **Get the KB number.** Search "Windows Server 2022 update history" or open the history hub at
   <https://support.microsoft.com/help/5005454>. The left-hand list is newest first, for example
   "September 8, 2026 - KB5122882 (OS Build 20348.5622)". The top entry without the word *Preview* is the
   current cumulative update. The OS Build number is what the grid's Build column shows, so you can tell
   at a glance which servers are already current. For numbers only, per Server version, use
   <https://learn.microsoft.com/windows/release-health/windows-server-release-info>.
2. **Download from the Microsoft Update Catalog.** Each history article has a *Microsoft Update Catalog* link
   under *How to get this update*, or open <https://www.catalog.update.microsoft.com> and search for the KB,
   e.g. `KB5122882`. Server 2022 is listed as *Cumulative Update for Microsoft server operating system
   version 21H2 for x64-based Systems*; Server 2025 is *version 24H2*. Click Download, keep the file name.
3. **Sanity checks.** The name starts with `windows10.0-kb` for 2022 (`windows11.0-kb` is 2025). The
   servicing stack update is bundled inside the 2022 cumulative update, so one file is enough. .NET Framework
   updates are separate KBs. Press **Reload lists + patches** and check the new KB column appears.

The same text is behind the **Where do I get patches?** button in the GUI and in the Code Tour tab.

## Day-to-day use

1. Edit `PatchGroup-A.txt` (and B, C) with one server per line. Add more `.txt` files for more groups.
2. Copy the month's `.msu` files into `patches\`. Keep the Microsoft Update Catalog file name.
3. Start the tool. Pick a group in the drop-down, press **Check ALL shown**.
4. Read the grid. Pink rows are pending a reboot and will be skipped. Grey rows did not answer (hover for the reason, or press **Test WinRM port (no auth)**).
5. Tick the servers (or **Tick all shown** for the whole group) and tick the KB(s) on the right.
6. Press **PATCH IT!** You get: the plan, the snapshot question, the Trellix question, then a second status
   check (anything that changed while the pop-ups were open is dropped). The file is copied to one server at a
   time, and each server's install starts the moment its copy is verified, so the installs overlap and run in
   parallel. The status bar counts the minutes. In the log, a group run shows one summary line every 45 seconds
   ("7 servers installing, CBS progress 23%..81%") and one line per server every 5 minutes; with three servers
   or fewer you get the per-server line every time. While the run is going you can still check the status of
   other servers, run the WinRM test, switch group and open the log. Patching, reboot, reload and the credential
   buttons stay locked until it finishes.
7. When it finishes, rows that need a reboot turn pink. Press **Reboot ticked servers** when the change window
   allows. It checks status first, offers only the servers that are pending a reboot, asks separately about any
   others, and a server refuses to reboot while DISM is still running. Check status again afterwards.

## How the install works (and why DISM)

`wusa.exe` refuses to run inside a WinRM session, so the tool does what Microsoft recommends for remote installs:

```
RemoteStagingScript   C:\PatchStaging\ must be a real folder owned by admins; ACL locked to SYSTEM + Administrators
Copy-FileToSession    file.msu -> C:\PatchStaging\   (224 KB slices with the default MaxEnvelopeSizekb, SHA256 verified)
RemoteInstallScript   guards: nothing else servicing the box, no pending reboot, SHA256 re-checked, Microsoft signature
expand.exe -F:* file.msu C:\PatchStaging\extract-KBnnnnnnn-xxxxxx\
dism.exe /Online /Add-Package /PackagePath:<the .cab> /NoRestart /Quiet /LogPath:C:\PatchStaging\dism-KBnnnnnnn-xxxxxx.log
result-KBnnnnnnn-xxxxxx.txt written on the server + Application event 900 (source OfflinePatcher)
```

The copy is done in slices because every WinRM request has to fit inside the server's `MaxEnvelopeSizekb`
(500 KB by default). The tool does not use `Copy-Item -ToSession`, because in PowerShell 5.1 it sends requests
bigger than that limit and fails. With the default setting a 560 MB update takes a few minutes on a LAN. If you
want it faster, raise the limit on the servers and the tool will use bigger slices automatically:

```
winrm set winrm/config @{MaxEnvelopeSizekb="8192"}
```

| DISM exit | Meaning | Tool treats as |
|---|---|---|
| 0 | installed | success |
| 3010 | installed, reboot required | success, row goes pink |
| 0x800F081E | not applicable: wrong Windows line (a `windows11.0` file on Server 2022) or missing prerequisite | failure |
| 0x800F0922 | failed (pending reboot, missing SSU, full System Reserved partition) | failure, DISM log lines copied into our log |
| other | see `C:\PatchStaging\dism-KB*.log` and `C:\Windows\Logs\CBS\CBS.log` on the server | failure |

While DISM runs, its own log goes quiet after the line `CBS session options=0x100!` for the entire install, which
is normally 10 to 30 minutes. The tool therefore reads `C:\Windows\Logs\CBS\CBS.log` on each server every 45
seconds and logs the CBS percentage, whether `dism.exe` and `TiWorker` are still busy, and the last DISM log line,
so "still going" always comes with evidence. After 120 minutes (`InstallTimeoutMin`) the tool stops waiting but
does **not** stop DISM: the session is disconnected, the result is logged as UNKNOWN with the commands to reconnect,
and the server keeps its own `result-*.txt`.

After a success the staged file is deleted. After a failure it is left in place for investigation.
If DISM fails with memory errors inside the WinRM session, raise the shell quota on the target:

```
winrm set winrm/config/winrs @{MaxMemoryPerShellMB="4096"}
```

## Fault finding in one minute

* Every action logs the exact command it ran as a `[CMD]` line. Paste it into a console to reproduce by hand.
* `[WHY]` lines explain the reasoning before each step.
* Double-click any server row for a scrollable details window: status fields, the verdict for every patch in
  `patches\`, the `Get-HotFix` list, and the full Windows Update history with dates, results and titles.
  `Get-HotFix` is short on purpose: it only lists packages still on disk, and each cumulative update replaces
  the previous one. The history list is the same one Settings shows, read offline from the Windows Update Agent.
* The **Code Tour** tab has a troubleshooting checklist as its last topic.
* Pending-reboot detection uses the CBS `RebootPending` / `PackagesPending` keys and the Windows Update `RebootRequired` key.
  `PendingFileRenameOperations` (files to rename or delete at next boot) is shown as "no (PFRO only, ignored)" but not
  counted, because installers and anti-virus products leave it behind constantly. Set `TreatPendingFileRenameAsReboot`
  to `$true` in `lib\01-Config.ps1` to count it. The details window lists the actual file paths so you can judge.
* The **Build** column is the real patch level. The number after the dot changes with every cumulative update and only
  moves after the reboot. "Newest hotfixes" lists every `Get-HotFix` entry from the latest install date, because the
  cumulative update and the .NET cumulative update land on the same day under different KB numbers.

## Requirements

* Windows PowerShell 5.1 on the machine running the tool (it uses `Copy-Item -ToSession`, which needs 5.0+).
* WinRM reachable on TCP 5985 on the targets, with the operator's account in the local Administrators group.
* Built for Windows Server 2022, but mixed groups are fine. The tool reads the target build from inside every
  patch file with `expand.exe` (offline, cached in `patches\_info\`) and compares it with each server's build:
  14393 = 2016, 17763 = 2019, 20348 = 2022, 26100 = 2025. A file for another build shows **Blocked: wrong OS**, a
  file whose build cannot be read shows **Blocked: OS unknown**, and the plan skips both, so you can keep the 2019
  and 2022 cumulative updates in `patches\` together. DISM refuses a wrong package anyway (0x800F081E). The
  operator's job is to download the right files; the tool catches the common mistakes before a copy is wasted.
* Every patch file must be Authenticode-signed by Microsoft (`Get-AuthenticodeSignature`, checked on the operator
  PC and again on the server right before DISM). An unsigned or tampered file shows **Blocked: signature**.
* Use FQDNs in the group files. An IP address forces NTLM and would need `TrustedHosts`; never set that to `*`.
* No internet access needed anywhere.

## Code review

`CODE-REVIEW.md` records the independent review (34 findings plus two field-test changes, what was done about each,
and the self-tests to repeat). Every `.ps1` starts with a **REVIEW RECORD** block that names the findings touching that file and leaves
space for the human reviewer's name, date, verdict and comments. Fill those in by hand and keep them in the files.

## Editing the code

Keep it simple on purpose: no modules, no classes, no runspaces. If you change a `.ps1` file, run
`Build-TextCopies.ps1` so the `.txt` copies and the all-in-one file match. The builder also normalises
every file to CRLF line endings and UTF-8 with BOM so Notepad, ISE and the console agree.
Write `} else {` and `} catch {` on one line: the all-in-one text has to survive being pasted into a console.

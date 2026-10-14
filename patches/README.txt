Put Windows Server 2022 update files (.msu or .cab) in this folder.
The tool never goes online: you download on a machine with internet and copy the file here.

HOW TO FIND AND DOWNLOAD THIS MONTH'S PATCH

1. Find the latest KB number - the update history page is easiest
   Search "Windows Server 2022 update history" or open
   https://support.microsoft.com/help/5005454   (the Server 2022 history hub)
   The left-hand list is newest first, e.g.
      "September 8, 2026 - KB5122882 (OS Build 20348.5622)"
   The top entry WITHOUT the word "Preview" is the current cumulative update (LCU).
   Note the OS Build number: compare it with the Build column in the grid to see
   which servers are already current.
   Numbers only, per Server version:
   https://learn.microsoft.com/windows/release-health/windows-server-release-info

2. Download it from the Microsoft Update Catalog
   Each history article has a "Microsoft Update Catalog" link under
   "How to get this update", or open https://www.catalog.update.microsoft.com
   and search for the KB number, e.g.   KB5122882
   Server 2022 is listed as:
      "Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems"
   Server 2025 is listed as:
      "... Microsoft server operating system version 24H2 ..."
   Click Download, save the .msu, KEEP THE FILE NAME, copy it into this folder.

3. Sanity checks before you start
   * File name starts with windows10.0-kb... for Server 2022  (windows11.0-kb... = Server 2025).
     The tool reads the KB number from the name, e.g.
        windows10.0-kb5122882-x64_8a1b2c3d.msu   ->   KB5122882
     A file without a KB in its name is ignored (the log tells you).
   * The servicing stack update (SSU) is bundled inside the Server 2022 LCU - one file is enough.
   * .NET Framework updates are separate KBs; add them the same way if they are required.
   * Cumulative updates are 600-900 MB (2025 ones are bigger). Each server needs room on C:
     (the tool refuses below MinFreeGB, see lib\01-Config.ps1).
   * Only keep patches here that you intend to deploy: every file becomes a column in the
     grid and a tick-box in the install list. Move old months out.
   * Mixed operating systems are fine. The tool reads the target build from inside each file
     (offline, with expand.exe) and shows "Blocked: wrong OS" for a file that does not match a
     server, e.g. a Server 2022 update on a Server 2019 box. Put the 2019 and 2022 cumulative
     updates here together and each server only gets READY in its own column.
     The small _info folder is the cache of those reads; it is safe to delete.
   * Press "Reload lists + patches" in the tool and check the new KB column appears.

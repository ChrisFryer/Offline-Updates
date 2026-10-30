Put Microsoft update files in this folder. The tool installs Windows and .NET Framework updates (.msu / .cab)
itself; for the other products it reports the installed level so you can see what is missing.

The "Where do I get patches?" button in the tool has the full, current text; this file is the short version.

WHERE TO FIND MICROSOFT PATCHES  (on a machine that has internet, then copy the files over)

A. WINDOWS SERVER CUMULATIVE UPDATE (LCU) - the monthly patch
   1. KB number: search "Windows Server 2022 update history" or open https://support.microsoft.com/help/5005454
      (Server 2019: help/4464619, Server 2016: help/4000825, Server 2025: help/5045836). The list is newest first,
      e.g. "September 8, 2026 - KB5122882 (OS Build 20348.5622)". Take the top entry WITHOUT the word "Preview".
      The OS Build number is what the Build column in the grid shows, so you can see who is already current.
      Numbers only, per version: https://learn.microsoft.com/windows/release-health/windows-server-release-info
   2. Download: the history article links to the Microsoft Update Catalog under "How to get this update", or open
      https://www.catalog.update.microsoft.com and search the KB. Server 2022 is listed as "Cumulative Update for
      Microsoft server operating system version 21H2 for x64-based Systems"; Server 2025 is "version 24H2";
      Server 2019 and 2016 are listed by name. Click Download, save the .msu, KEEP THE FILE NAME, e.g.
         windows10.0-kb5122882-x64_8a1b2c3d.msu   ->   KB5122882
   3. The servicing stack update (SSU) is bundled inside the LCU for 2019/2022/2025 - one file is enough.

B. .NET FRAMEWORK CUMULATIVE UPDATE - separate KB, same day as the LCU
   Catalog search: ".NET Framework" "Windows Server 2022" (or the KB from the history page; the LCU article lists
   it under ".NET Framework updates"). File names look like windows10.0-kb5126050-x64-ndp481_....msu. One file
   per .NET line (4.8 / 4.8.1); the tool installs these the same way as the LCU.

C. .NET RUNTIME (.NET 6 / 8 / 9, formerly .NET Core) - not a KB
   https://dotnet.microsoft.com/download/dotnet - pick the version line the grid reports, download the Windows
   x64 "Runtime" (or "Hosting Bundle" for IIS) installer (.exe). Install by hand: <file>.exe /install /quiet /norestart

D. SQL SERVER CUMULATIVE UPDATE (CU) and SECURITY UPDATE (GDR)
   https://learn.microsoft.com/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server
   lists the latest CU and GDR per version (2016/2017/2019/2022) with build numbers. Compare with the build the
   grid reports (also SELECT @@VERSION on the instance). Download the CU .exe from the KB article; install by
   hand: SQLServer20xx-KBnnnnnnn-x64.exe /quiet /action=Patch /IAcceptSQLServerLicenseTerms /AllInstances

E. EXCHANGE SERVER SECURITY UPDATE (SU) and CUMULATIVE UPDATE (CU)
   https://learn.microsoft.com/exchange/new-features/build-numbers-and-release-dates gives the build per CU/SU.
   SUs come from the Microsoft Download Center (search "Exchange Server 2019 security update <month>"); CUs are
   ISO images. Install by hand on the Exchange server, SU: <file>.exe /passive (run elevated); CU: setup from the ISO.

F. OTHER MICROSOFT COMPONENTS
   Defender platform/engine updates: catalog search "KB4052623" (platform) - normally delivered with definitions.
   Visual C++ runtimes, SQL ODBC/OLE DB drivers, Edge: vendor pages; the grid reports installed versions.

G. DRIVERS AND FIRMWARE: from the hardware or hypervisor vendor (VMware Tools from the vSphere release).

SANITY CHECKS BEFORE YOU START
   * File name starts with windows10.0-kb... for Server 2016/2019/2022 (windows11.0-kb... = Server 2025); the
     tool reads the real target build from inside the file and blocks a mismatch, so mixed groups are fine.
   * Every file must be Authenticode-signed by Microsoft; an unsigned or altered file shows as "Blocked: signature".
   * Cumulative updates are 600-900 MB (Server 2025 ones are bigger). Each server needs room on C:
     (the tool refuses below MinFreeGB, see lib\01-Config.ps1).
   * Only keep patches here that you intend to deploy: every file becomes a column in the grid and a tick-box in
     the install list. Move old months out.
   * Press "Reload lists + patches" and check the new KB column appears. The small _info folder is the cache of
     each file's target build, signature and hash; it is safe to delete.
   * Put each file in its type's sub-folder (Windows, DotNet, SQL, Exchange, Other - the tool creates them); a file
     left in this folder counts as a Windows update.

@{
    # =================================================================
    #  command-cheatsheet.psd1  -  the Commands tab's cheat sheet
    # -----------------------------------------------------------------
    #  One command per line, never a long chain: run it, read the answer,
    #  and use what it shows in the next command (a service's program path
    #  goes into Test-Path, a process Id into Stop-Process ...).
    #  <name>, <path>, <id> ... are placeholders: picking a command puts it
    #  in the command box with the first placeholder selected - type over it.
    #  Whether a command may change a server is worked out by the tool
    #  (Get-CommandRisk), not written here: those show in dark red and ask
    #  for a change record and a confirmation before they run.
    #  Add your own: a Section with a Name and Commands (Command + What).
    #  Inside '...', a quote is written twice: 'Status -eq ''Stopped'''.
    # =================================================================
    AsOf = '2026-10-22'

    Sections = @(
        @{ Name = 'Services'; Commands = @(
            @{ Command = 'Get-Service -Name <name>'; What = 'One service: its state and how it starts.' }
            @{ Command = 'Get-Service | Where-Object Status -eq ''Stopped'''; What = 'Every stopped service.' }
            @{ Command = 'Get-CimInstance Win32_Service -Filter "Name=''<name>''" | Select-Object Name, State, StartMode, PathName'; What = 'The program a service runs (PathName) - take that path into Test-Path.' }
            @{ Command = 'Test-Path ''<path>'''; What = 'Does a file or folder exist?  False for a service''s program = the service was left behind by an uninstall.' }
            @{ Command = 'Get-ItemProperty ''HKLM:\SYSTEM\CurrentControlSet\Services\<name>'''; What = 'A service''s registry entry.  DeleteFlag = 1: Windows removes the service at the next reboot.' }
            @{ Command = 'sc.exe qc <name>'; What = 'The service''s configuration, the classic way.  Type sc.exe in full: in PowerShell, sc alone is Set-Content.' }
            @{ Command = 'Get-Service -Name <name> -DependentServices'; What = 'The services that stop when this one stops.' }
            @{ Command = 'Restart-Service -Name <name>'; What = 'Restart one service.' }
            @{ Command = 'sc.exe delete <name>'; What = 'Remove a service whose program is gone (left behind by an uninstall).  Gone at once, or at the next reboot if it is still open.' }
        ) }
        @{ Name = 'Processes'; Commands = @(
            @{ Command = 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 10'; What = 'The 10 processes that used the most processor time.' }
            @{ Command = 'Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10'; What = 'The 10 processes using the most memory.' }
            @{ Command = 'Get-Process -Name <name> | Select-Object Id, Path, StartTime'; What = 'Where a process runs from, and since when.' }
            @{ Command = 'Get-CimInstance Win32_Process -Filter ''ProcessId=<id>'' | Select-Object Name, CommandLine'; What = 'The full command line of one process (the Id from Get-Process).' }
            @{ Command = 'Stop-Process -Id <id>'; What = 'End one process.' }
        ) }
        @{ Name = 'Disks and files'; Commands = @(
            @{ Command = 'Get-PSDrive -PSProvider FileSystem'; What = 'Used and free space per drive.' }
            @{ Command = 'Get-ChildItem ''<folder>'' | Sort-Object LastWriteTime -Descending | Select-Object -First 20'; What = 'The 20 newest files in a folder.' }
            @{ Command = 'Get-ChildItem ''<folder>'' -Recurse -File | Measure-Object Length -Sum'; What = 'How many files a folder holds, and their size in bytes (Sum).' }
            @{ Command = 'Get-Content ''<file>'' -Tail 50'; What = 'The last 50 lines of a text or log file.' }
            @{ Command = 'Select-String -Path ''<file>'' -Pattern ''<text>'''; What = 'The lines of a file that contain a word.' }
            @{ Command = 'Get-ChildItem ''C:\PatchStaging'' -Recurse'; What = 'What this toolkit has staged on the server.' }
        ) }
        @{ Name = 'Event logs'; Commands = @(
            @{ Command = 'Get-WinEvent -LogName System -MaxEvents 20'; What = 'The 20 newest System events.' }
            @{ Command = 'Get-WinEvent -FilterHashtable @{ LogName = ''System''; Level = 2 } -MaxEvents 20'; What = 'The 20 newest errors in the System log.' }
            @{ Command = 'Get-WinEvent -FilterHashtable @{ LogName = ''System''; Id = 7000, 7009, 7031, 7034 } -MaxEvents 20'; What = 'Services that failed to start or stopped unexpectedly.' }
            @{ Command = 'Get-WinEvent -FilterHashtable @{ LogName = ''System''; Id = 1074, 6008 } -MaxEvents 10'; What = 'Who restarted the server and why (1074), and unexpected shutdowns (6008).' }
            @{ Command = 'Get-WinEvent -FilterHashtable @{ LogName = ''Application''; ProviderName = ''MsiInstaller'' } -MaxEvents 20'; What = 'Installs and removals by Windows Installer (1033 install, 1034 removal, 1038 restart needed).' }
            @{ Command = 'Get-WinEvent -FilterHashtable @{ LogName = ''Application''; ProviderName = ''OfflinePatcher'' } -MaxEvents 20'; What = 'This toolkit''s own records on the server: 900 patch, 910 software, 920 reboot, 930 command.' }
            @{ Command = 'Get-Content ''C:\PatchStaging\change-log.txt'' -Tail 20'; What = 'The change record this toolkit keeps on the server.' }
        ) }
        @{ Name = 'Software and updates'; Commands = @(
            @{ Command = 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10'; What = 'The 10 newest updates.' }
            @{ Command = 'Get-ItemProperty ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'' | Where-Object DisplayName -like ''*<name>*'' | Select-Object DisplayName, DisplayVersion, InstallLocation'; What = 'A 64-bit program as Programs and Features knows it.' }
            @{ Command = 'Get-ItemProperty ''HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'' | Where-Object DisplayName -like ''*<name>*'' | Select-Object DisplayName, DisplayVersion, InstallLocation'; What = 'The same for a 32-bit program.' }
            @{ Command = 'Get-ItemProperty ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'' | Where-Object DisplayName -like ''*<name>*'' | Select-Object DisplayName, QuietUninstallString'; What = 'How a program removes itself silently (what UNINSTALL would run).' }
            @{ Command = 'Get-ScheduledTask -TaskPath ''\WinRMToolkit\'''; What = 'This toolkit''s one-shot tasks - normally none.' }
            @{ Command = 'Get-ScheduledTask -TaskName ''<name>'' | Get-ScheduledTaskInfo'; What = 'When a scheduled task last ran, and its result.' }
        ) }
        @{ Name = 'Reboot and uptime'; Commands = @(
            @{ Command = '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime'; What = 'When the server last started.' }
            @{ Command = 'Test-Path ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'''; What = 'True = Windows servicing waits for a reboot.' }
            @{ Command = 'Test-Path ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'''; What = 'True = Windows Update waits for a reboot.' }
            @{ Command = 'Get-ItemProperty ''HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'' -Name PendingFileRenameOperations'; What = 'Files Windows renames or deletes at the next start.' }
        ) }
        @{ Name = 'Network'; Commands = @(
            @{ Command = 'Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress'; What = 'The server''s IPv4 addresses.' }
            @{ Command = 'Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalPort, OwningProcess'; What = 'The ports the server listens on, and the process Id behind each (into Get-Process -Id).' }
            @{ Command = 'Test-NetConnection <host> -Port <port>'; What = 'Can this server reach another one on a port?' }
            @{ Command = 'Resolve-DnsName <name>'; What = 'What a name resolves to, from this server.' }
            @{ Command = 'Get-DnsClientServerAddress -AddressFamily IPv4'; What = 'The DNS servers it asks.' }
            @{ Command = 'ipconfig /all'; What = 'Every adapter, the classic way.' }
        ) }
        @{ Name = 'Accounts and sessions'; Commands = @(
            @{ Command = 'Get-LocalGroupMember -Group Administrators'; What = 'Who is a local administrator.' }
            @{ Command = 'quser'; What = 'Who is logged on ("No User exists" when nobody is).' }
            @{ Command = 'whoami'; What = 'The account these commands run as on the server.' }
        ) }
        @{ Name = 'System'; Commands = @(
            @{ Command = 'Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory'; What = 'Hardware (or VMware) and memory in bytes.' }
            @{ Command = 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, FreePhysicalMemory'; What = 'Windows edition, version and free memory in KB.' }
            @{ Command = 'Get-WindowsFeature | Where-Object Installed'; What = 'The roles and features installed.' }
            @{ Command = 'w32tm /query /status'; What = 'Where the server gets its time, and when it last synchronised.' }
            @{ Command = 'Get-TimeZone'; What = 'The server''s time zone.' }
            @{ Command = '$PSVersionTable'; What = 'The PowerShell version on the server.' }
        ) }
    )
}

# =====================================================================
#  Build-Diagrams.ps1  -  DRAWS THE PICTURES USED BY THE "CODE TOUR" TAB
# ---------------------------------------------------------------------
#  Output: images\*.png  (six diagrams, listed at the bottom of this file)
#  Needs : nothing but Windows PowerShell 5.1 and System.Drawing (GDI+),
#          both part of Windows - no internet, no modules, no fonts to install.
#  Why a script and not a drawing tool?  So the pictures can be regenerated
#  offline after a text change, and so the "source" of every picture is
#  readable PowerShell that a trainee can follow line by line.
#
#  Run:  powershell.exe -ExecutionPolicy Bypass -File .\Build-Diagrams.ps1
#  Every diagram is built from four helpers:
#     New-Canvas   -> a bitmap with the title bar
#     Add-Box      -> a rounded box with a title and lines of text
#     Add-Arrow    -> a line with an arrow head and an optional label
#     Add-Tree     -> monospaced "folder tree" lines with grey notes
#  and Save-Canvas writes the PNG.
# =====================================================================
#Requires -Version 5.1

# ---------------------------------------------------------------------
#  REVIEW RECORD  -  Build-Diagrams.ps1
# ---------------------------------------------------------------------
#  Independent review 2026-10-14 (see CODE-REVIEW.md).  Changed here:
#  R-31 the pictures said 240 KB slices / ~2400 round trips; the formula
#  gives 224 KB / ~2560.  Step texts updated for the reboot and timeout
#  behaviour.  Build tool only - never runs on a server.
#  ---------------------------------------------------------------------
#  HUMAN REVIEW  (fill in by hand and keep it in the file)
#  Reviewer   : ______________________________   Date : ______________
#  Verdict    : [ ] Approved   [ ] Approved with comments   [ ] Changes required
#  Comments   :
#    -
# =====================================================================
Add-Type -AssemblyName System.Drawing

$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }
$outDir = Join-Path $root 'images'
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

# ---------------------------------------------------------------- helpers
$script:FontCache = @{}
function Get-DFont {
    param([string]$Family = 'Segoe UI', [single]$Size = 12, [switch]$Bold, [switch]$Italic)
    $style = [System.Drawing.FontStyle]::Regular
    if ($Bold)   { $style = $style -bor [System.Drawing.FontStyle]::Bold }
    if ($Italic) { $style = $style -bor [System.Drawing.FontStyle]::Italic }
    $key = "$Family|$Size|$style"
    if (-not $script:FontCache.ContainsKey($key)) { $script:FontCache[$key] = New-Object System.Drawing.Font -ArgumentList $Family, $Size, $style }
    return $script:FontCache[$key]
}
function Get-Colour { param([string]$Name) return [System.Drawing.Color]::FromName($Name) }
function Get-Brush  { param([string]$Name) return (New-Object System.Drawing.SolidBrush -ArgumentList (Get-Colour $Name)) }

function New-RoundedPath {
    param([single]$X, [single]$Y, [single]$W, [single]$H, [single]$R = 10)
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $R * 2
    $p.AddArc($X, $Y, $d, $d, 180, 90)
    $p.AddArc($X + $W - $d, $Y, $d, $d, 270, 90)
    $p.AddArc($X + $W - $d, $Y + $H - $d, $d, $d, 0, 90)
    $p.AddArc($X, $Y + $H - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

function New-Canvas {
    param([int]$W, [int]$H, [string]$Title, [string]$Subtitle = '')
    $bmp = New-Object System.Drawing.Bitmap -ArgumentList $W, $H
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear((Get-Colour 'White'))
    $g.FillRectangle((Get-Brush 'MidnightBlue'), 0, 0, $W, 64)
    $g.DrawString($Title, (Get-DFont 'Segoe UI' 22 -Bold), (Get-Brush 'Gold'), 16, 8)
    if ($Subtitle) { $g.DrawString($Subtitle, (Get-DFont 'Segoe UI' 11 -Italic), (Get-Brush 'White'), 18, 42) }
    $foot = "The Patch Palace  -  drawn by Build-Diagrams.ps1 on $(Get-Date -Format 'yyyy-MM-dd')  -  edit the script, run it again, the picture updates"
    $g.DrawString($foot, (Get-DFont 'Segoe UI' 9 -Italic), (Get-Brush 'Gray'), 16, $H - 22)
    return @{ Bitmap = $bmp; G = $g; W = $W; H = $H }
}

function Save-Canvas {
    param($C, [string]$Name)
    $path = Join-Path $outDir $Name
    $C.G.Dispose()
    $C.Bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $C.Bitmap.Dispose()
    Write-Host ("wrote {0}  ({1} KB)" -f $path, [math]::Round((Get-Item $path).Length / 1KB))
}

function Add-Box {
    param($C, [int]$X, [int]$Y, [int]$W, [int]$H, [string]$Title = '', [string[]]$Lines = @(),
          [string]$Fill = 'AliceBlue', [string]$Border = 'SteelBlue', [single]$TextSize = 11,
          [switch]$Mono, [string]$TextColour = 'Black', [single]$BorderWidth = 2)
    $g = $C.G
    $path = New-RoundedPath $X $Y $W $H 10
    $g.FillPath((Get-Brush $Fill), $path)
    $pen = New-Object System.Drawing.Pen -ArgumentList (Get-Colour $Border), $BorderWidth
    $g.DrawPath($pen, $path)
    $ty = $Y + 8
    if ($Title) {
        $tf = Get-DFont 'Segoe UI' ($TextSize + 2) -Bold
        $g.DrawString($Title, $tf, (Get-Brush $Border), ($X + 12), $ty)
        $ty += $tf.GetHeight($g) + 4
    }
    $family = 'Segoe UI'
    if ($Mono) { $family = 'Consolas' }
    $font = Get-DFont $family $TextSize
    $lineH = $font.GetHeight($g) + 1
    foreach ($line in $Lines) {
        $g.DrawString($line, $font, (Get-Brush $TextColour), ($X + 12), $ty)
        $ty += $lineH
    }
}

function Add-Label {
    param($C, [int]$X, [int]$Y, [string]$Text, [string]$Colour = 'DimGray', [single]$Size = 10.5, [switch]$Bold, [string]$Back = 'White', [switch]$Left)
    $font = Get-DFont 'Segoe UI' $Size -Bold:$Bold
    $sz = $C.G.MeasureString($Text, $font)
    $bx = $X - ($sz.Width / 2)
    if ($Left) { $bx = $X }
    $C.G.FillRectangle((Get-Brush $Back), $bx - 3, $Y - 2, $sz.Width + 6, $sz.Height + 3)
    $C.G.DrawString($Text, $font, (Get-Brush $Colour), $bx, $Y)
}

function Add-Arrow {
    param($C, [int]$X1, [int]$Y1, [int]$X2, [int]$Y2, [string]$Label = '', [string]$Colour = 'DimGray',
          [single]$Width = 2.5, [switch]$Dashed, [switch]$NoHead, [int]$LabelDy = -34, [switch]$BothEnds)
    $pen = New-Object System.Drawing.Pen -ArgumentList (Get-Colour $Colour), $Width
    if ($Dashed) { $pen.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash }
    if (-not $NoHead) { $pen.CustomEndCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap -ArgumentList 5, 6, $true }
    if ($BothEnds) { $pen.CustomStartCap = New-Object System.Drawing.Drawing2D.AdjustableArrowCap -ArgumentList 5, 6, $true }
    $C.G.DrawLine($pen, $X1, $Y1, $X2, $Y2)
    if ($Label) { Add-Label $C ([int](($X1 + $X2) / 2)) ([int](($Y1 + $Y2) / 2) + $LabelDy) $Label -Colour $Colour }
}

function Add-Text {
    param($C, [int]$X, [int]$Y, [string]$Text, [single]$Size = 12, [switch]$Bold, [switch]$Italic, [string]$Colour = 'Black', [switch]$Mono)
    $family = 'Segoe UI'
    if ($Mono) { $family = 'Consolas' }
    $C.G.DrawString($Text, (Get-DFont $family $Size -Bold:$Bold -Italic:$Italic), (Get-Brush $Colour), $X, $Y)
}

function Add-Lane {
    # A swim-lane background with a heading.
    param($C, [int]$X, [int]$Y, [int]$W, [int]$H, [string]$Title, [string]$Fill = 'WhiteSmoke', [string]$Colour = 'Gray')
    $C.G.FillRectangle((Get-Brush $Fill), $X, $Y, $W, $H)
    $pen = New-Object System.Drawing.Pen -ArgumentList (Get-Colour $Colour), 1
    $C.G.DrawRectangle($pen, $X, $Y, $W, $H)
    $C.G.FillRectangle((Get-Brush $Colour), $X, $Y, $W, 30)
    $C.G.DrawString($Title, (Get-DFont 'Segoe UI' 12 -Bold), (Get-Brush 'White'), ($X + 10), ($Y + 6))
}

function Add-Tree {
    # Lines of @('tree text', 'note') - the tree in Consolas, the note in grey to the right.
    param($C, [int]$X, [int]$Y, [object[]]$Rows, [int]$NoteX, [single]$Size = 11.5)
    $mono = Get-DFont 'Consolas' $Size
    $note = Get-DFont 'Segoe UI' ($Size - 1) -Italic
    $lineH = $mono.GetHeight($C.G) + 2
    $y = $Y
    foreach ($row in $Rows) {
        $text = [string]$row[0]
        $colour = 'Black'
        if ($text.StartsWith('##')) { $text = $text.Substring(2); $colour = 'MidnightBlue'; $C.G.DrawString($text, (Get-DFont 'Segoe UI' ($Size + 1) -Bold), (Get-Brush $colour), $X, $y) }
        else { $C.G.DrawString($text, $mono, (Get-Brush $colour), $X, $y) }
        if ($row.Count -gt 1 -and $row[1]) { $C.G.DrawString([string]$row[1], $note, (Get-Brush 'DimGray'), $NoteX, $y) }
        $y += $lineH
    }
    return [int]$y
}

# ================================================================ DIAGRAM 1
function New-BigPictureDiagram {
    $c = New-Canvas 1500 900 '1. The big picture' 'Who talks to whom, over which port, and what never happens'

    Add-Box $c 30 110 310 260 -Title 'INTERNET PC  (has web access)' -Fill 'Honeydew' -Border 'SeaGreen' -Lines @(
        '1. support.microsoft.com/help/5005454',
        '   -> this month''s KB number + OS build',
        '2. catalog.update.microsoft.com',
        '   -> search the KB, download the .msu',
        '3. carry the file over (USB / file share)',
        '',
        'The patching tool itself NEVER goes online.')
    Add-Arrow $c 340 240 400 240 -Dashed -Colour 'SeaGreen'
    Add-Label $c 370 196 "manual`ncopy" -Colour 'SeaGreen' -Size 9.5

    Add-Box $c 400 100 380 430 -Title 'OPERATOR PC  (where the sys-admin runs the tool)' -Fill 'AliceBlue' -Border 'SteelBlue' -Mono -TextSize 10.5 -Lines @(
        'Windows PowerShell 5.1  (console = colour log)',
        'Start-OfflinePatcher.ps1 + lib\01..08-*.ps1',
        'patches\*.msu          <- files from step 3',
        'PatchGroup-A/B/C.txt   <- one server per line',
        'logs\Patcher-YYYYMMDD.log',
        '',
        'Runs as YOUR domain account',
        '  (local admin on the target servers)',
        'Credentials: foreground prompt only,',
        '  kept in memory, never written to disk',
        '',
        'Nothing is installed on any server:',
        '  no agent, no service, no scheduled task')

    Add-Box $c 1060 100 410 430 -Title 'TARGET SERVERS  (from the group files)' -Fill 'WhiteSmoke' -Border 'Gray'
    Add-Box $c 1080 150 370 100 -Title 'SRV-A01   Server 2022   build 20348.xxxx' -Fill 'White' -Border 'SteelBlue' -TextSize 10 -Lines @(
        'WinRM listener  TCP 5985 (HTTP)',
        'wsmprovhost.exe runs our script blocks as you')
    Add-Box $c 1080 265 370 100 -Title 'SRV-B01   Server 2022   build 20348.xxxx' -Fill 'White' -Border 'SteelBlue' -TextSize 10 -Lines @(
        'WinRM listener  TCP 5985 (HTTP)',
        'C:\PatchStaging\ is created on first install')
    Add-Box $c 1080 380 370 130 -Title 'SRV-C01   Server 2019   build 17763.xxxx' -Fill 'White' -Border 'DarkOrange' -TextSize 10 -Lines @(
        'WinRM listener  TCP 5985 (HTTP)',
        'A Server 2022 file shows "Blocked: wrong OS"',
        'here - the build is read from inside the MSU')

    Add-Arrow $c 780 300 1060 300 -Colour 'DarkOrange' -Width 5
    Add-Label $c 920 236 'TCP 5985  -  WinRM over HTTP' -Colour 'DarkOrange' -Size 12 -Bold
    Add-Label $c 920 258 'WS-Management (SOAP) carrying' -Colour 'DimGray'
    Add-Label $c 920 274 'PowerShell Remoting (PSRP)' -Colour 'DimGray'
    Add-Label $c 920 312 'Kerberos authentication' -Colour 'DimGray'
    Add-Label $c 920 328 'payload encrypted at message level' -Colour 'DimGray'
    Add-Label $c 920 344 'even though the transport is plain HTTP' -Colour 'DimGray'

    Add-Box $c 400 610 380 130 -Title 'DOMAIN CONTROLLER  (already in place)' -Fill 'Lavender' -Border 'SlateBlue' -Mono -TextSize 10.5 -Lines @(
        'DNS       53   resolve names - use FQDNs',
        'Kerberos  88   ticket for HTTP/<server fqdn>',
        'Needed by WinRM auth; nothing new to open.')
    Add-Arrow $c 590 530 590 610 -Label 'DNS 53 / Kerberos 88' -Dashed -Colour 'SlateBlue' -LabelDy -8

    Add-Box $c 1060 570 410 170 -Title 'NOT used by the tool' -Fill 'MistyRose' -Border 'IndianRed' -TextSize 10.5 -Lines @(
        'SMB 445 admin shares  (\\server\C$)',
        'RPC / DCOM / WMI  135 + dynamic ports',
        'Windows Update, WSUS, the internet',
        'wusa.exe  (refuses to run inside WinRM)',
        'Any inbound port on the operator PC')

    Add-Box $c 30 770 1440 70 -Fill 'LemonChiffon' -Border 'Goldenrod' -TextSize 11 -Lines @(
        'Everything that happens on a server happens INSIDE the WinRM session, as your account: the status check, the file copy,',
        'expand.exe, dism.exe, the progress polls and the reboot.  One port, one protocol, one identity - that is all there is to audit.')
    Save-Canvas $c '1-big-picture.png'
}

# ================================================================ DIAGRAM 2
function New-PortsDiagram {
    $c = New-Canvas 1500 900 '2. Ports and protocols' 'What must be open, what already is, and what the tool deliberately never uses'
    $g = $c.G
    $cols = @(
        @{ X = 30;   W = 170; T = 'Port' },
        @{ X = 200;  W = 330; T = 'Protocol' },
        @{ X = 530;  W = 250; T = 'Direction' },
        @{ X = 780;  W = 520; T = 'Used for' },
        @{ X = 1300; W = 170; T = 'Status' })
    $rows = @(
        @('TCP 5985',          "WinRM over HTTP`nWS-Management SOAP carrying PSRP",  'operator PC -> server',   "EVERYTHING: status checks, the file copy in slices,`nexpand + DISM, progress polls, the reboot", 'REQUIRED', 'SeaGreen'),
        @('TCP 5986',          'WinRM over HTTPS',                                   'operator PC -> server',   "Not used.  Set WinRMPort = 5986 in 01-Config.ps1`nif your servers have HTTPS listeners", 'optional', 'SteelBlue'),
        @('TCP/UDP 88',        'Kerberos',                                           'operator PC -> domain controller', "Ticket for HTTP/<server FQDN>.  Use FQDNs in the`ngroup files so Kerberos can find the service", 'existing', 'SteelBlue'),
        @('TCP/UDP 53',        'DNS',                                                'operator PC -> DNS server', 'Resolve the server names', 'existing', 'SteelBlue'),
        @('TCP 445',           'SMB / admin shares',                                 '-',                       'NOT used - the tool never touches \\server\C$', 'not used', 'IndianRed'),
        @('TCP 135 + dynamic', 'RPC / DCOM / WMI',                                   '-',                       "NOT used - the CIM/WMI queries run INSIDE the`nWinRM session on the server itself", 'not used', 'IndianRed'),
        @('TCP 80 / 443',      'HTTP / HTTPS to the internet',                       '-',                       'NOT used - downloads happen on a different machine', 'not used', 'IndianRed'))

    $y = 90
    foreach ($col in $cols) {
        $g.FillRectangle((Get-Brush 'MidnightBlue'), $col.X, $y, $col.W, 34)
        $g.DrawString($col.T, (Get-DFont 'Segoe UI' 12 -Bold), (Get-Brush 'White'), ($col.X + 10), ($y + 7))
    }
    $y += 34
    $i = 0
    foreach ($r in $rows) {
        $h = 52
        $fill = 'White'
        if ($i % 2 -eq 1) { $fill = 'WhiteSmoke' }
        $g.FillRectangle((Get-Brush $fill), 30, $y, 1440, $h)
        $g.DrawLine((New-Object System.Drawing.Pen -ArgumentList (Get-Colour 'LightGray'), 1), 30, ($y + $h), 1470, ($y + $h))
        $g.DrawString($r[0], (Get-DFont 'Consolas' 12 -Bold), (Get-Brush 'Black'), 40, ($y + 15))
        $g.DrawString($r[1], (Get-DFont 'Segoe UI' 10.5), (Get-Brush 'Black'), 210, ($y + 8))
        $g.DrawString($r[2], (Get-DFont 'Segoe UI' 10.5), (Get-Brush 'Black'), 540, ($y + 15))
        $g.DrawString($r[3], (Get-DFont 'Segoe UI' 10.5), (Get-Brush 'Black'), 790, ($y + 8))
        $g.DrawString($r[4], (Get-DFont 'Segoe UI' 11 -Bold), (Get-Brush $r[5]), 1310, ($y + 15))
        $y += $h
        $i++
    }

    # the layers inside 5985
    $ly = 520
    Add-Text $c 30 $ly 'Inside TCP 5985, from the outside in:' -Size 13 -Bold -Colour 'MidnightBlue'
    $ly += 32
    $layers = @(
        @('HTTP', @('plain transport on TCP 5985', '(5986 would be HTTPS)')),
        @('SOAP / WS-Management', @('the WinRM envelope around every request;', 'MaxEnvelopeSizekb (500 KB default) caps its size')),
        @('PSRP', @('PowerShell Remoting Protocol: commands,', 'arguments and results, all serialized to XML')),
        @('wsmprovhost.exe', @('the process on the server that runs OUR', 'script blocks, as your account')))
    $lx = 30
    foreach ($layer in $layers) {
        Add-Box $c $lx $ly 345 70 -Title $layer[0] -Fill 'AliceBlue' -Border 'SteelBlue' -TextSize 9.5 -Lines $layer[1]
        if ($lx -gt 30) { Add-Arrow $c ($lx - 20) ($ly + 35) $lx ($ly + 35) -Colour 'SteelBlue' -Width 2 }
        $lx += 365
    }

    Add-Box $c 30 630 1440 180 -Title 'WinRM settings on the SERVER that matter to this tool' -Fill 'LemonChiffon' -Border 'Goldenrod' -Mono -TextSize 10.5 -Lines @(
        'winrm get winrm/config          MaxEnvelopeSizekb    500 KB default -> 224 KB copy slices.   8192 -> 3.8 MB slices, copies many times faster',
        'winrm get winrm/config/winrs    MaxMemoryPerShellMB  1024 default   -> raise to 4096 if DISM dies with an out-of-memory style error',
        'winrm quickconfig               creates the 5985 listener and the firewall rule on a server that has none',
        'Test-WSMan <server>             the anonymous "is anyone there?" request = the "Test WinRM port (no auth)" button',
        'Enable-PSRemoting -Force        the PowerShell way to do quickconfig + register the PowerShell session endpoint',
        'Set-Item WSMan:\localhost\MaxEnvelopeSizekb 8192      the PowerShell way to change the envelope size')
    Save-Canvas $c '2-ports-and-protocols.png'
}

# ================================================================ DIAGRAM 3
function New-OperatorFolderDiagram {
    $c = New-Canvas 1300 800 '3. The folder on the operator PC' 'Every file has one job; the root folder is wherever Start-OfflinePatcher.ps1 lives'
    Add-Box $c 30 90 1240 675 -Fill 'White' -Border 'SteelBlue'
    $rows = @(
        @('Offline-Updates\',                          'the ROOT folder - all paths are relative to it'),
        @('|-- Start-OfflinePatcher.ps1',              'the launcher: works out the root, loads lib\, opens the GUI'),
        @('|-- lib\',                                   'the building blocks, loaded in number order'),
        @('|   |-- 01-Config.ps1',                      '$Config: port, timeouts, thresholds, staging folder + shared state'),
        @('|   |-- 02-Logging.ps1',                     'Write-PatchLog -> log file + console + GUI box, colour coded'),
        @('|   |-- 03-Groups.ps1',                      'reads the PatchGroup-*.txt lists'),
        @('|   |-- 04-Patches.ps1',                     'scans patches\, reads each file''s target build with expand.exe'),
        @('|   |-- 05-WinRM.ps1',                       'status check, credential prompt, Test-WSMan, the slice copy'),
        @('|   |-- 06-Install.ps1',                     'plan, the two safety pop-ups, DISM install, progress, reboot'),
        @('|   |-- 07-Gui.ps1',                         'the window (WinForms); every button is a short call into 03-06'),
        @('|   ''-- 08-CodeTour.ps1',                   'the Code Tour text and picture entries'),
        @('|-- patches\',                               'YOU put the .msu / .cab files here (keep the catalog file name)'),
        @('|   |-- windows10.0-kb5122882-x64_....msu',  'one column in the grid + one tick-box per file'),
        @('|   |-- README.txt',                         'how to find and download the right file'),
        @('|   ''-- _info\<file>.txt',                  'cache: the build each file targets (safe to delete)'),
        @('|-- images\*.png',                           'these pictures, drawn by Build-Diagrams.ps1'),
        @('|-- logs\Patcher-YYYYMMDD.log',              'one file per day; every command the tool ran is in here'),
        @('|-- PatchGroup-A.txt  (-B, -C, ...)',        'one server per line, # for comments; file name = group name'),
        @('|-- code-as-text\*.txt',                     '.txt twin of every .ps1, for places that block scripts'),
        @('|-- Offline-Patcher-AllInOne.txt',           'all files in load order: Invoke-Expression (Get-Content -Raw ...)'),
        @('|-- Build-TextCopies.ps1',                   'regenerates the .txt copies - run after ANY edit'),
        @('|-- Build-Diagrams.ps1',                     'regenerates the pictures'),
        @('|-- CODE-REVIEW.md',                         'the review findings and the human sign-off checklist'),
        @('''-- README.md',                             'the manual'))
    $end = Add-Tree $c 50 105 $rows 560 12
    Add-Box $c 50 ($end + 20) 1200 110 -Title 'Shared state while the tool runs (inspect from the console at any time)' -Fill 'LemonChiffon' -Border 'Goldenrod' -Mono -TextSize 10.5 -Lines @(
        '$Config          the settings hashtable            $ServerStatus    name -> last status object (build, hotfixes, reboot flags...)',
        '$Groups          output of Get-PatchGroups         $Patches         output of Get-PatchFiles (KB, size, target build)',
        '$Credential      PSCredential or $null             $Gui             the WinForms controls, by name')
    Save-Canvas $c '3-operator-folder.png'
}

# ================================================================ DIAGRAM 4
function New-StatusFlowDiagram {
    $c = New-Canvas 1500 900 '4. A status check, step by step' 'What "Check status" does, where each piece of information comes from, and what happens when a server says no'
    Add-Lane $c 30 80 540 790 'OPERATOR PC  (the GUI, your account)' -Fill 'AliceBlue' -Colour 'SteelBlue'
    Add-Lane $c 590 80 220 790 'THE WIRE' -Fill 'White' -Colour 'DarkOrange'
    Add-Lane $c 830 80 640 790 'TARGET SERVER  (wsmprovhost.exe, still your account)' -Fill 'Honeydew' -Colour 'SeaGreen'

    Add-Box $c 50 130 500 120 -Title '1. Check status  (or the PATCH IT pre-flight)' -Fill 'White' -Border 'SteelBlue' -Mono -TextSize 10.5 -Lines @(
        'Get-ServerStatus -ComputerName A,B,C',
        'Invoke-Command ... -Port 5985 -AsJob -ThrottleLimit 16',
        'one child job per server, all running at once')
    Add-Arrow $c 550 190 850 190 -Colour 'DarkOrange' -Width 4
    Add-Label $c 700 150 'TCP 5985' -Colour 'DarkOrange' -Bold -Size 11
    Add-Label $c 700 206 'Kerberos ticket, or the' -Colour 'DimGray' -Size 9.5
    Add-Label $c 700 221 'stored credential if set' -Colour 'DimGray' -Size 9.5

    Add-Box $c 850 130 600 300 -Title '2. RemoteStatusScript runs ON the server' -Fill 'White' -Border 'SeaGreen' -Mono -TextSize 10.5 -Lines @(
        'Win32_OperatingSystem          caption, last boot time',
        'HKLM\...\Windows NT\CurrentVersion   CurrentBuildNumber.UBR = 20348.5622',
        'Win32_LogicalDisk C:           free GB',
        'Get-HotFix                     installed KBs (packages still on disk)',
        'Microsoft.Update.Session       Windows Update history (every attempt)',
        'CBS\RebootPending, CBS\PackagesPending,',
        '   WU\RebootRequired           the HARD reboot flags (counted)',
        'PendingFileRenameOperations    the WEAK flag (shown, not counted)',
        '',
        'Nothing is written to the server.  Read-only.  2-5 seconds.')
    Add-Arrow $c 850 470 550 470 -Colour 'DarkOrange' -Width 4
    Add-Label $c 700 430 'one result object per server' -Colour 'DarkOrange' -Bold -Size 10.5
    Add-Label $c 700 484 'remoting flattens nested objects,' -Colour 'DimGray' -Size 9.5
    Add-Label $c 700 499 'so the lists travel as text lines' -Colour 'DimGray' -Size 9.5

    Add-Box $c 50 420 500 150 -Title '3. Back on the operator PC' -Fill 'White' -Border 'SteelBlue' -Mono -TextSize 10.5 -Lines @(
        '$ServerStatus[name] = result  (+ Reachable, Error, Checked)',
        'grid repaint: row colour + one cell per KB column',
        '   Installed / Installed (history) / READY /',
        '   Blocked: reboot / disk / wrong OS',
        '[OK] log line: build, free GB, uptime, reboot flags')

    Add-Box $c 50 620 500 110 -Title 'Branch: "Access is denied"' -Fill 'MistyRose' -Border 'IndianRed' -TextSize 10.5 -Lines @(
        'Get-Credential pop-up in the FOREGROUND, in your context.',
        'Kept in memory only.  Those servers are retried once.',
        'Cancel = keep using the current Windows login.')
    Add-Box $c 50 745 500 110 -Title 'Branch: no answer at all' -Fill 'LightGray' -Border 'DimGray' -TextSize 10.5 -Lines @(
        'Grey row, reason in the tooltip and in the log (full text).',
        '"Test WinRM port (no auth)" = Test-WSMan: is 5985 even open?',
        'Fix on the server: winrm quickconfig ; Get-Service WinRM')
    Add-Box $c 850 620 600 235 -Title 'Why two update lists?' -Fill 'LemonChiffon' -Border 'Goldenrod' -TextSize 10.5 -Lines @(
        'Get-HotFix only shows CBS packages still on disk.  Each cumulative update',
        'supersedes the previous one, which then disappears - so the list is short.',
        'The Windows Update history keeps every attempt ever (Defender updates too).',
        'A KB counts as installed if either list says so.',
        '',
        'The BUILD (20348.5622) is the real patch level.  The number after the dot',
        'moves with every cumulative update - but only after the reboot.')
    Save-Canvas $c '4-status-check.png'
}

# ================================================================ DIAGRAM 5
function New-InstallFlowDiagram {
    $c = New-Canvas 1500 1000 '5. An install, step by step' 'From PATCH IT! to the reboot button - what runs where, and what every exit code means'
    Add-Lane $c 30 80 700 890 'OPERATOR PC' -Fill 'AliceBlue' -Colour 'SteelBlue'
    Add-Lane $c 770 80 700 890 'TARGET SERVER  (inside the WinRM session, as your account)' -Fill 'Honeydew' -Colour 'SeaGreen'
    Add-Label $c 750 90 'TCP' -Colour 'DarkOrange' -Bold -Size 10
    Add-Label $c 750 106 '5985' -Colour 'DarkOrange' -Bold -Size 10

    $steps = @(
        @('1. PATCH IT!  ->  fresh status  ->  New-PatchPlan', @('per server x KB:  unreachable / pending reboot / low disk /', 'already installed / wrong OS  ->  skipped.   Otherwise READY'), '', @(), 'none'),
        @('2. Three confirmations - the ONLY place a human says go', @('Plan (OK/Cancel)  ->  SAFETY 1: VMware snapshot taken?  ->', 'SAFETY 2: Trellix in maintenance mode?      No = abort, nothing touched'), '', @(), 'none'),
        @('3. Status AGAIN, then New-PSSession -ComputerName X -Port 5985', @('the pop-ups may have been open for minutes: anything no longer READY is dropped', 'one persistent session per server, used for steps 4 and 5'), 'RemoteStagingScript', @('C:\PatchStaging\ created or checked: a real folder, owned by admins,', 'ACL locked to SYSTEM + Administrators (C:\ lets Users create folders)'), 'right'),
        @('4. Copy-FileToSession - the file goes over in slices', @('read 224 KB -> Base64 -> one Invoke-Command per slice (~2560 for an LCU)', 'resumes a partial copy; halves the slice if the server says "too big"'), 'RemoteWriteSliceScript', @('appends each slice to C:\PatchStaging\<file>.msu', 'then both sides hash the file: SHA256 must match or the copy is deleted'), 'right'),
        @('5. Invoke-Command -Session -AsJob  RemoteInstallScript', @('started on EVERY target at the same time; the GUI stays alive', 'status bar counts the minutes; the window refuses to close while busy'), 'guards, then expand.exe, then dism.exe', @('refuse if dism/TiWorker busy or a reboot is pending; re-hash + Authenticode check', 'expand -F:* -> extract\ ; dism /Online /Add-Package <SSU cab> then <LCU cab> /NoRestart'), 'right'),
        @('6. Every 45 s: Write-InstallProgress', @('one log line per server + the Patch-o-meter percentage', '"still going" always comes with evidence'), 'RemoteProgressScript', @('CBS.log "Percent progress: NN"  (the DISM log goes quiet for the whole install)', 'is dism.exe alive?  TiWorker CPU seconds?  last DISM log line'), 'left'),
        @('7. One result object per KB, logged with the exact commands', @('exit 0 = installed   3010 = installed, REBOOT needed   0x800F081E = not applicable', '0x800F0922 = failed.  Timeout = UNKNOWN: the session is disconnected, DISM is NOT killed'), 'result file + event log, then cleanup', @('C:\PatchStaging\result-KB*.txt and Application event 900 (OfflinePatcher) on the server', 'success: .msu + extract\ deleted, dism log kept;  failure: everything kept'), 'left'),
        @('8. Fresh status  ->  pink rows  ->  "Reboot ticked servers"', @('fresh status first; only servers PENDING a reboot by default, others need a 2nd Yes', 'never automatic: Yes/No pop-ups, default No'), 'RemoteRebootScript', @('refuses while dism/TiWorker run, then shutdown.exe /r /t 10 (returns before the link drops)', 'after the reboot the Build column shows the new UBR'), 'right'))

    $y = 125
    foreach ($s in $steps) {
        $arrow = $s[4]
        Add-Box $c 50 $y 660 92 -Title $s[0] -Fill 'White' -Border 'SteelBlue' -TextSize 10 -Lines $s[1]
        if ($s[2]) {
            Add-Box $c 790 $y 660 92 -Title $s[2] -Fill 'White' -Border 'SeaGreen' -TextSize 10 -Lines $s[3]
            if ($arrow -eq 'right') { Add-Arrow $c 712 ($y + 46) 788 ($y + 46) -Colour 'DarkOrange' -Width 3 }
            if ($arrow -eq 'left')  { Add-Arrow $c 788 ($y + 46) 712 ($y + 46) -Colour 'DarkOrange' -Width 3 }
        }
        $y += 104
    }
    Save-Canvas $c '5-install-flow.png'
}

# ================================================================ DIAGRAM 6
function New-EndpointLayoutDiagram {
    $c = New-Canvas 1500 780 '6. What lands on the target server' 'Folders, logs, registry keys and processes you will find on an endpoint during and after a patch'
    Add-Box $c 30 90 1440 650 -Fill 'White' -Border 'SeaGreen'
    $rows = @(
        @('##C:\PatchStaging\                       (RemoteStaging in 01-Config.ps1)', ''),
        @('|-- windows10.0-kb5122882-x64_....msu',   'copied in slices, SHA256 verified; deleted after a successful install'),
        @('|-- extract-KB5122882-a1b2c3\',            'expand.exe output (KB + 6 chars of the file name); deleted after success, kept after failure'),
        @('|   |-- SSU-20348.5614-x64.cab',           'servicing stack update - installed FIRST'),
        @('|   |-- Windows10.0-KB5122882-x64.cab',    'the cumulative update itself - installed second'),
        @('|   |-- WSUSSCAN.cab',                     'WSUS metadata - skipped'),
        @('|   |-- Windows10.0-KB5122882-x64_uup.xml','package list with versions - where the target build (20348) is read from'),
        @('|   ''-- ...-pkgProperties.txt',          'Installer Version="10.0.20348.x", KB number, package type'),
        @('|-- dism-KB5122882-a1b2c3.log',            'DISM log, always kept.  Goes quiet after "CBS session options=0x100!" for the whole install'),
        @('''-- result-KB5122882-a1b2c3.txt',         'the outcome, written by the server itself - survives a lost connection or a timeout'),
        @('', ''),
        @('##C:\Windows\Logs\CBS\CBS.log', ''),
        @('    "Progress: UI message updated ... Percent progress: 37."', 'the REAL install progress - read every 45 s by the tool'),
        @('    "Error" / "Failed" lines', 'the first place to look when DISM returns 0x800F0922'),
        @('', ''),
        @('##Registry', ''),
        @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentBuildNumber + UBR  =  the Build column (20348.5622)'),
        @('HKLM\...\Component Based Servicing\RebootPending', 'HARD reboot flag - set by DISM after the LCU'),
        @('HKLM\...\Component Based Servicing\PackagesPending', 'HARD reboot flag - packages staged, waiting for the boot'),
        @('HKLM\...\WindowsUpdate\Auto Update\RebootRequired', 'HARD reboot flag - set by Windows Update'),
        @('HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations', 'WEAK flag - "no (PFRO only, ignored)"; the details window lists the paths'),
        @('', ''),
        @('##Processes while an install runs', ''),
        @('wsmprovhost.exe  ->  expand.exe  ->  dism.exe  ->  TiWorker.exe', 'your session -> unpack -> DISM front end -> CBS worker that does the real work (CPU climbs)'),
        @('', ''),
        @('##WinRM on the server', ''),
        @('listener TCP 5985  (winrm quickconfig)', 'the only door the tool uses'),
        @('winrm get winrm/config        MaxEnvelopeSizekb', '500 default = 224 KB copy slices;  8192 = 3.8 MB slices'),
        @('Application event log, source OfflinePatcher, ID 900', 'one event per KB: who, what, result - the audit trail on the server side'),
        @('winrm get winrm/config/winrs  MaxMemoryPerShellMB', '1024 default; raise to 4096 if DISM dies of memory inside the session'))
    [void](Add-Tree $c 50 100 $rows 760 11.5)
    Save-Canvas $c '6-endpoint-layout.png'
}

# ---------------------------------------------------------------- build all
New-BigPictureDiagram
New-PortsDiagram
New-OperatorFolderDiagram
New-StatusFlowDiagram
New-InstallFlowDiagram
New-EndpointLayoutDiagram
Write-Host 'Done. The Code Tour entries in lib\08-CodeTour.ps1 point at these file names.' -ForegroundColor Green

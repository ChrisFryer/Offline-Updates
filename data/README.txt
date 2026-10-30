data\  -  the catalogues the consoles read
=================================================================

Every file here is a PowerShell data file (.psd1): values only, never code.
Edit them in Notepad; the tool re-reads a file when it changes (the one
exception is security-settings.psd1: its entries become checks when the tool
starts, so restart after editing it).  Keep them ASCII (no typographic quotes -
PowerShell treats them as string delimiters).

The toolkit never goes online.  Each file carries an "AsOf" date; refresh them
by hand from the vendor pages named inside, then update AsOf.

File                   What it holds                                  Used by
---------------------  ---------------------------------------------  ----------------
known-apps.psd1        third-party products: Match pattern, Latest    O/S Patching console
                       version, release cadence, end-of-life date,    (Software grid:
                       note.  "Current / Behind / Stale / End of       Current, Behind,
                       life" verdicts come from here.                  Stale, Ageing, EOL)

product-patches.psd1   Windows: the latest cumulative update per      O/S Patching console
                       build (KB, UBR, release date) and the end of   and Security
                       support date; .NET Framework releases; SQL     SEC-OS-07/08,
                       Server and Exchange build tables.  Fill in     SEC-PAT-01
                       Server 2019 / 2025 and the SQL / Exchange
                       tables from the vendor history pages.
                       WindowsHistory (optional): earlier months'
                       KB + UBR, so a server already past an older
                       file shows "Installed (build)", not READY.

benign-services.psd1   automatic services that are allowed to be      Health console
                       stopped (trigger-started, on-demand), the      H-SVC-01,
                       scheduled-task result codes that mean "fine",  H-TSK-01,
                       and products ignored by the dormant-software   H-SW-01
                       check.  Service entries may use wildcards
                       (GoogleUpdaterService*, CDPUserSvc_*).

soe-agents.psd1        the agents every server should run: name,      Health (agents),
                       service names, exe, product match.  Add your   SOE standards,
                       own (SIEM forwarder, EDR, backup agent).        Security SEC-AV,
                                                                      SEC-LOG-01

security-settings.psd1 the EXPECTED value of every setting the        Security console
                       Security console checks one-for-one: audit     (89 data-driven
                       policy subcategories, account policy, security checks)
                       options, user rights, hardening registry keys.
                       Fields: Id, Group, Title, Key, Op, Expected,
                       Ism, ML, Severity, Fix, [Applies],
                       [NotConfiguredOk], [ExpectedAt] (the value at
                       a classification: @{ S = '17'; TS = '20' }).
                       ML = the lowest Essential Eight level among the
                       ISM controls cited.  Tune with the console's
                       tailoring rather than by weakening this file.

ism-catalogue.psd1     GENERATED - do not edit.  Every ISM control:   Security console
                       Id, Section, Topic, Rev, Updated, ML           (ISM wording in
                       (Essential Eight maturity level or 0), the     details and
                       classification columns NC / OS / P / S / TS,   reports; which
                       and the control text, generated from the ISM   controls apply at
                       annex spreadsheet; its header names the        your classification)
                       release.
                       Source: Australian Signals Directorate, Information Security Manual,
                       (c) Commonwealth of Australia, licensed under Creative Commons
                       Attribution 4.0 (https://www.cyber.gov.au/ism).

soe-config-points.psd1 the configuration points an SOE deployment              Health console
                       customises per server: WSUS server, KMS host, NTP      (SOE standards
                       source, DNS suffixes, event-forwarding collector,      page, "Check
                       SNMP contact, page file, Defender exclusions, the      health" reads
                       Zabbix / Splunk / NXLog / Trellix agent server         every point)
                       addresses.  Fields: Name, Type (registry | file),
                       Path, Key (value name; * = all; file setting; or
                       re:<regex>), Note.  Read-only probes - a point can
                       only make the tool READ a value.  Add your own.

software-packages.psd1 what the Software console may deploy, update or    Software console
                       remove, and exactly how: Id, Folder (under         (installer vetting,
                       software\; the Id when left out), Name, Match      verdicts, the command
                       (Uninstall DisplayName), FilePattern, VersionFrom  line on the server,
                       / VersionRegex, Installer (msi | exe), Arguments   what UNINSTALL may
                       (msi) or InstallArguments / UpdateArguments (exe;  remove)
                       {log} = the installer log, {file} = the staged
                       file; an exe must suppress the reboot), Modes
                       (Install / Update / Uninstall), Requires (hardware,
                       e.g. VMware*), Signers (the O= of the Authenticode
                       signer starts with one of these), AllowUnsigned,
                       Note.  ProtectedProducts: what UNINSTALL never
                       removes.  Ships with VMware Tools, a commented MSI
                       template and the packages registered so far.

command-cheatsheet.psd1 the Commands console's cheat sheet: Sections,    Commands console
                       each with a Name and Commands (Command + What).   (the cheat sheet
                       ONE command per entry - its answer feeds the      on the right)
                       next one, no chains.  <name>, <path> ... are
                       placeholders, selected when the command is put
                       in the box.  Whether a command may change a
                       server is worked out by the tool, not written
                       here.  Add your own.

gpo-guidance.psd1      how to close each Security gap with Group      Security console
                       Policy.  Gpos: the GPOs recommended, one per   (GPO recommendations
                       area.  Settings: per check Id (Check) - the    page, GPO plan,
                       GPO, the path in the Group Policy Management   report)
                       Editor, the value, Default (what Windows does
                       when nothing sets it, shown as "not set - ..."),
                       Rsop (how to recognise the setting
                       in a server's Resultant Set of Policy: R: an
                       administrative template, V: a security option,
                       S: account policy, U: a user right, D: advanced
                       audit), Impact (what could break), Expect
                       (None / Low / Review when no impact check
                       answers) and Probes (the impact checks run on
                       the server - their names are in
                       lib\45-Security-Gpo.ps1, $ImpactProbes).

Keys the checks read (Settings and SecurityPolicy collectors)
-------------------------------------------------------------
  Audit:<subcategory>    auditpol /get /category:* /r      e.g. Audit:Logon = Success and Failure
  Sec:<name>             secedit [System Access]           e.g. Sec:LockoutBadCount = 5
  Right:<privilege>      secedit [Privilege Rights]        e.g. Right:SeDebugPrivilege = *S-1-5-32-544
  Reg:<leaf>             secedit [Registry Values]
  LegacyAudit:<category> secedit [Event Audit]            the nine legacy categories
  everything else        the Settings collector (registry values, cmdlets, features)
                         - the full key list is in the Code Tour under "Settings keys".

Operators in security-settings.psd1
-----------------------------------
  eq  ne  ge  le        compare (numbers compared as numbers)
  between               Expected '1-900'
  in                    Expected 'a;b;c'
  contains              substring
  subset                every entry of the actual list is in Expected ('a;b')
  match                 regular expression
  report                show the value, never fail

A missing value gives a Warn ("not collected" or "OS default applies"), never a Fail,
unless NotConfiguredOk = $true says the default is acceptable.

Size note: PowerShell's own data-file loader gives up at roughly 2,000 values in one
file.  The toolkit reads bigger files (the ISM catalogue) through its own reader
(Import-DataFileSafely in lib\10-Checks.ps1), which applies the same values-only rule.

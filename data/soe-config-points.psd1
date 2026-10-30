@{
    # =================================================================
    #  soe-config-points.psd1  -  COMMON CONFIGURATION POINTS AN SOE DEPLOYMENT
    #  CUSTOMISES PER SERVER (which monitoring server, which update server,
    #  which time source ...).  The Health console's "Check health" reads every
    #  point here on every server (registry values and lines of configuration
    #  files - nothing is ever executed), the SOE standards page lists them with
    #  the value a reference server has, and a ticked point becomes a rule of the
    #  standard: "this server must point at THAT server".
    #
    #  Type = 'registry'  Path = the key, Key = the value name (* = every value, as name=data)
    #  Type = 'file'      Path = the file, Key = the setting name on a "Key = value" line
    #                     (lines starting with # or ; are comments), or re:<regex> whose
    #                     first capture group is the value - for XML and other formats.
    #  Paths and names marked "verify" are typical locations: check them once on a
    #  reference server (the page shows what each point returned) and correct them here.
    #  Add your own points below - any registry value or config-file line works.
    # =================================================================
    AsOf = '2026-10-19'
    Points = @(
        # ---- Windows platform ----
        @{ Name = 'Windows Update: WSUS server';        Type = 'registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate';            Key = 'WUServer';                    Note = 'the WSUS URL the server reports to (GPO: Specify intranet Microsoft update service location)' }
        @{ Name = 'Windows Update: use WSUS';           Type = 'registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU';         Key = 'UseWUServer';                 Note = '1 = updates come from WSUS, not the internet' }
        @{ Name = 'Activation: KMS host';               Type = 'registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'; Key = 'KeyManagementServiceName'; Note = 'the KMS host set with slmgr /skms (empty = DNS discovery or MAK / AD-based activation)' }
        @{ Name = 'Time: NTP source';                   Type = 'registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters';          Key = 'NtpServer';                   Note = 'only meaningful when Type = NTP; domain members use NT5DS (the domain hierarchy)' }
        @{ Name = 'Time: sync type';                    Type = 'registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters';          Key = 'Type';                        Note = 'NT5DS = domain hierarchy, NTP = the NtpServer list' }
        @{ Name = 'DNS: suffix search list';            Type = 'registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters';            Key = 'SearchList';                  Note = 'comma-separated suffixes appended to short names' }
        @{ Name = 'DNS: primary suffix';                Type = 'registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters';            Key = 'Domain';                      Note = 'the computer''s primary DNS suffix' }
        @{ Name = 'Event forwarding: collector';        Type = 'registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'; Key = '1';   Note = 'Server=http://<collector>:5985/wsman/SubscriptionManager/WEC,Refresh=60 (GPO: Configure target Subscription Manager)' }
        @{ Name = 'Page file';                          Type = 'registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; Key = 'PagingFiles';            Note = 'e.g. ?:\pagefile.sys (system managed) or C:\pagefile.sys 4096 8192' }
        @{ Name = 'SNMP: system contact';               Type = 'registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\RFC1156Agent';  Key = 'sysContact';                  Note = 'SNMP service > Agent tab' }
        @{ Name = 'SNMP: system location';              Type = 'registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\RFC1156Agent';  Key = 'sysLocation';                 Note = 'SNMP service > Agent tab' }
        @{ Name = 'SNMP: permitted managers';           Type = 'registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers'; Key = '*';                    Note = 'every value = one host allowed to query the agent' }
        @{ Name = 'Defender: exclusion paths';          Type = 'registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths';   Key = '*';                           Note = 'policy-set exclusions (value names are the paths); application exclusions belong in the SOE' }
        @{ Name = 'SCCM client: site code';             Type = 'registry'; Path = 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client';                           Key = 'AssignedSiteCode';            Note = 'Configuration Manager client assignment (verify)' }
        # ---- monitoring and logging agents ----
        @{ Name = 'Zabbix agent: Server';               Type = 'file';     Path = 'C:\Program Files\Zabbix Agent\zabbix_agentd.conf';                    Key = 'Server';                      Note = 'passive checks: the Zabbix server or proxy allowed to poll this agent' }
        @{ Name = 'Zabbix agent: ServerActive';         Type = 'file';     Path = 'C:\Program Files\Zabbix Agent\zabbix_agentd.conf';                    Key = 'ServerActive';                Note = 'active checks: where the agent sends its data' }
        @{ Name = 'Zabbix agent: Hostname';             Type = 'file';     Path = 'C:\Program Files\Zabbix Agent\zabbix_agentd.conf';                    Key = 'Hostname';                    Note = 'must match the host name in Zabbix' }
        @{ Name = 'Zabbix agent 2: Server';             Type = 'file';     Path = 'C:\Program Files\Zabbix Agent 2\zabbix_agent2.conf';                  Key = 'Server';                      Note = 'agent 2 keeps the same keys in its own file' }
        @{ Name = 'Zabbix agent 2: ServerActive';       Type = 'file';     Path = 'C:\Program Files\Zabbix Agent 2\zabbix_agent2.conf';                  Key = 'ServerActive';                Note = '' }
        @{ Name = 'Splunk forwarder: indexers';         Type = 'file';     Path = 'C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf'; Key = 'server';                 Note = 'the indexer list the forwarder sends to (first "server =" line)' }
        @{ Name = 'Splunk forwarder: deployment server'; Type = 'file';    Path = 'C:\Program Files\SplunkUniversalForwarder\etc\system\local\deploymentclient.conf'; Key = 'targetUri'; Note = 'where the forwarder fetches its apps from' }
        @{ Name = 'NXLog: output host';                 Type = 'file';     Path = 'C:\Program Files\nxlog\conf\nxlog.conf';                              Key = 're:^\s*Host\s+(\S+)';        Note = 'the syslog / SIEM destination in the <Output> block (verify the block name)' }
        # ---- security agents ----
        @{ Name = 'Trellix (McAfee) agent: ePO server'; Type = 'file';     Path = 'C:\ProgramData\McAfee\Agent\SiteList.xml';                            Key = 're:ServerName="([^"]+)"';     Note = 'the ePO / Trellix management server from the agent site list (verify the attribute name on a reference server)' }
        @{ Name = 'Trellix (McAfee) agent: ePO port';   Type = 'file';     Path = 'C:\ProgramData\McAfee\Agent\SiteList.xml';                            Key = 're:ServerPort="([^"]+)"';     Note = 'verify on a reference server' }
        @{ Name = 'Windows LAPS: backup directory';     Type = 'registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS';                              Key = 'BackupDirectory';             Note = '2 = Active Directory, 1 = Azure AD (GPO: LAPS > Configure password backup directory)' }
        @{ Name = 'Azure Arc / Monitor agent proxy';    Type = 'registry'; Path = 'HKLM:\SOFTWARE\Microsoft\AzureMonitorAgent';                          Key = 'ProxyAddress';                Note = 'example - verify; delete the point if not used' }
    )
}

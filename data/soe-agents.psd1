@{
    # =================================================================
    #  soe-agents.psd1  -  how to recognise each SOE agent on a server.
    #  The Agents collector tries, in order: services (wildcards allowed,
    #  ; separated), an executable (file version), a product name in the
    #  Uninstall registry (DisplayVersion).  "Installed" = any of them hit;
    #  "Running" = at least one listed service is running.
    #  VERIFY the service and product names against one of your own
    #  servers - vendors rename things.  Add your own agents below.
    # =================================================================
    AsOf = '2026-10-16'
    Agents = @(
        @{ Name = 'Microsoft Defender Antivirus'; Services = 'WinDefend';                    Exe = 'C:\Program Files\Windows Defender\MsMpEng.exe'; Products = '';                                                  Note = 'version from Get-MpComputerStatus when available' }
        @{ Name = 'Trellix Endpoint Security';    Services = 'mfemms;mfevtp;mfefire';        Exe = 'C:\Program Files\McAfee\Endpoint Security\Endpoint Security Platform\mfeesp.exe'; Products = 'Trellix Endpoint Security*;McAfee Endpoint Security*'; Note = 'ENS platform' }
        @{ Name = 'Trellix Agent';                Services = 'macmnsvc;masvc';               Exe = 'C:\Program Files\McAfee\Agent\masvc.exe';       Products = 'Trellix Agent*;McAfee Agent*';                       Note = 'ePO agent' }
        @{ Name = 'Airlock Digital Client';       Services = 'Airlock*';                     Exe = '';                                              Products = 'Airlock*';                                          Note = 'application control client - verify the service name' }
        @{ Name = 'CrowdStrike Falcon';           Services = 'CSFalconService';              Exe = '';                                              Products = 'CrowdStrike*';                                      Note = '' }
        @{ Name = 'Rapid7 Insight Agent';         Services = 'ir_agent';                     Exe = '';                                              Products = 'Rapid7 Insight Agent*';                             Note = '' }
        @{ Name = 'Qualys Cloud Agent';           Services = 'QualysAgent';                  Exe = '';                                              Products = 'Qualys Cloud Agent*';                               Note = '' }
        @{ Name = 'Splunk Universal Forwarder';   Services = 'SplunkForwarder';              Exe = '';                                              Products = 'UniversalForwarder*';                               Note = 'log forwarding (ISM-0582 evidence)' }
        @{ Name = 'Microsoft Monitoring Agent';   Services = 'HealthService';                Exe = '';                                              Products = 'Microsoft Monitoring Agent*';                       Note = 'SCOM / Azure Monitor' }
        @{ Name = 'Zabbix Agent';                 Services = 'Zabbix Agent*';                Exe = '';                                              Products = 'Zabbix Agent*';                                     Note = '' }
        @{ Name = 'Tenable Nessus Agent';         Services = 'Tenable Nessus Agent';         Exe = '';                                              Products = 'Nessus Agent*';                                     Note = 'vulnerability scanning (ISM-1808 evidence)' }
        @{ Name = 'VMware Tools';                 Services = 'VMTools';                      Exe = '';                                              Products = 'VMware Tools*';                                     Note = '' }
        @{ Name = 'SNMP Service';                 Services = 'SNMP';                         Exe = '';                                              Products = '';                                                  Note = 'Windows feature' }
    )
}

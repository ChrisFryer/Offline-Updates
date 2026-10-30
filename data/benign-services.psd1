@{
    # =================================================================
    #  benign-services.psd1  -  Windows services whose start type is
    #  Automatic but which are normally STOPPED on a healthy server
    #  (trigger-start, delayed-start that exit when idle, updaters).
    #  The "Automatic services not running" check ignores these.
    #  Add your own (one name per line, the short service name).
    # =================================================================
    Services = @(
        'RemoteRegistry'      # trigger start
        'sppsvc'              # Software Protection - trigger start
        'wuauserv'            # Windows Update - trigger start, stops when idle
        'BITS'                # stops when no transfers
        'MapsBroker'          # Downloaded Maps Manager - stops when idle
        'CDPSvc'              # Connected Devices Platform
        'dmwappushservice'
        'KtmRm'
        'sacsvr'              # Special Administration Console
        'WSearch'             # Windows Search - delayed, may stop
        'TrustedInstaller'
        'WbioSrvc'
        'tiledatamodelsvc'
        'gupdate'             # Google Update
        'gupdatem'
        'edgeupdate'          # Edge Update
        'edgeupdatem'
        'GoogleChromeElevationService'
        'MicrosoftEdgeElevationService'
        'clr_optimization_v4.0.30319_32'   # .NET optimisation - runs then stops
        'clr_optimization_v4.0.30319_64'
        'ShellHWDetection'
        'SharedAccess'
        'TapiSrv'
        'WerSvc'
        # wildcards are allowed: services with a version or a per-user suffix in their name
        'GoogleUpdaterService*'          # Google updater, e.g. GoogleUpdaterService157.0.8089.0
        'GoogleUpdaterInternalService*'
        'CDPUserSvc_*'                   # per-user service instances (the _xxxxx suffix changes per logon)
        'OneSyncSvc_*'
    )

    # Scheduled-task last-result codes that mean "fine", not "failed":
    #   0 = success, 0x41301 running, 0x41303 never run, 0x41325 queued.  0x41306 (terminated by a user) is NOT fine:
    #   somebody stopped the job - it shows as a failing task until it runs through
    TaskOkCodes = @(0, 267009, 267011, 267045)

    # Products never reported as dormant (infrastructure that has no process of its own, drivers, runtimes)
    DormantIgnore = @(
        'Microsoft Visual C++*'
        'Microsoft .NET*'
        'Microsoft ODBC*'
        'Microsoft OLE DB*'
        'Microsoft Edge*'
        'Microsoft Update Health Tools*'
        'VMware Tools*'
        'Windows Admin Center*'
        '*Driver*'
        '*Runtime*'
        '*Redistributable*'
    )
}

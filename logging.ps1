# Combined CCDC Windows Hardening & Logging Script
param(
    [string]$wazuhIP
)

# --- Initial Path Setup ---
[string]$currentFullPath = $MyInvocation.MyCommand.Path
# Using Split-Path for better reliability across different PS versions
[string]$scriptDir = Split-Path -Parent $currentFullPath
[string]$rootDir = Split-Path -Parent $scriptDir
$psLogFolder = Join-Path -Path $rootDir -ChildPath "powershellLogs"

# --- Helper Function ---
function printSuccessOrError{
    param(
        [string]$name,
        $result,
        $desiredResult,
        [bool]$multiple
    )
    if($multiple){
        if($desiredResult -in $result){
            Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] " -ForegroundColor White -NoNewline; Write-Host $name
        }
        else{
            Write-Host "[" -NoNewline; Write-Host "ERROR" -ForegroundColor Red -NoNewline; Write-Host "] " -ForegroundColor White -NoNewline; Write-Host $name -NoNewline; Write-Host " Failed: "
            Write-Host $result
        }
    }
    else{
        if($desiredResult -eq $result){
            Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] " -ForegroundColor White -NoNewline; Write-Host $name
        }
        else{
            Write-Host "[" -NoNewline; Write-Host "ERROR" -ForegroundColor Red -NoNewline; Write-Host "] " -ForegroundColor White -NoNewline; Write-Host $name -NoNewline; Write-Host " Failed: "
            Write-Host $result
        }
    }
}

# --- Step 1: Pre-Flight (Directory Creation) ---
if (!(Test-Path -Path $psLogFolder)) {
    New-Item -ItemType Directory -Path $psLogFolder -Force | Out-Null
    Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] Created Log Directory: $psLogFolder" -ForegroundColor White
}

# --- Step 2: Essential Services ---
if (!((Get-Service -Name "EventLog").Status -eq "Running")) {
    Start-Service -Name EventLog
    if(((Get-Service -Name "EventLog").Status -eq "Running")){
        Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] Windows Event Log Service Started" -ForegroundColor White
    }
    else{
        Write-Host "[" -NoNewline; Write-Host "ERROR" -ForegroundColor Red -NoNewline; Write-Host "] Windows Event Log Service Failed to start" -ForegroundColor White
    }
}

# --- Step 3: Event Log Configuration ---
# Setting max log sizes (Application, System, Security, PowerShell)
WevtUtil sl Application /ms:256000
WevtUtil sl System /ms:256000
WevtUtil sl Security /ms:2048000
WevtUtil sl "Windows PowerShell" /ms:512000
WevtUtil sl "Microsoft-Windows-PowerShell/Operational" /ms:512000
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true
Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] Event Log Sizes and Retention Set" -ForegroundColor White

# Threshold for security event log
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" /v WarningLevel /t REG_DWORD /d 90 /f | Out-Null

# --- Step 4: Audit & PowerShell Logging ---
# Enable audit policy subcategories
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f | Out-Null

# Detailed PowerShell Logging (Module, ScriptBlock, and Transcription)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d $psLogFolder /f | Out-Null

# Process Creation Audit (Command line arguments)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] PowerShell & CommandLine Registry Keys Set" -ForegroundColor White

# --- Step 5: External Tool Integration (Auditpol & Sysmon) ---
# Restore Audit Policy
[string]$auditpolPath = Join-Path -Path $scriptDir -ChildPath "conf\auditpol.csv"
if (Test-Path $auditpolPath) {
    $result = auditpol /restore /file:$auditpolPath
    printSuccessOrError -Name "System Audit Policy Restored" -result $result -desiredResult "The command was successfully executed." -multiple $true
}

# Install/Configure Sysmon
[string]$sysmonPath = Join-Path -Path $rootDir -ChildPath "tools\sys\sm\sysmon64_pp.exe"
[string]$xmlPath = Join-Path -Path $scriptDir -ChildPath "conf\sysmon.xml"

if (Test-Path $sysmonPath) {
    $result = & $sysmonPath -accepteula -i $xmlPath
    WevtUtil sl "Microsoft-Windows-Sysmon/Operational" /ms:1048576000
    if($result -match "already registered"){
        Write-Host "[" -NoNewline; Write-Host "INFO" -ForegroundColor Yellow -NoNewline; Write-Host "] Sysmon already running" -ForegroundColor White
    } else {
        Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] Sysmon Installed/Updated" -ForegroundColor White
    }
}

# --- Step 6: Service-Specific Logging (DNS, IIS, ADCS, ADFS) ---
# DNS Server (Tahoe .14)
if (Get-Service -Name "DNS" -ErrorAction SilentlyContinue) {
    Set-DnsServerDiagnostics -EventLogLevel 2 -UseSystemEventLog $true | Out-Null
    dnscmd /config /logfilemaxsize 0xC800000 | Out-Null
    Set-DnsServerDiagnostics -EnableLoggingForPluginDllEvent $true -EnableLoggingForServerStartStopEvent $true -EnableLoggingForLocalLookupEvent $true -EnableLoggingForRecursiveLookupEvent $true -EnableLoggingForRemoteServerEvent $true -EnableLoggingForZoneDataWriteEvent $true -EnableLoggingForZoneLoadingEvent $true | Out-Null
    Restart-Service DNS
    Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] DNS Logging configured and service restarted" -ForegroundColor White
}

# IIS Logging (Victoria .22)
if (Get-Service -Name W3SVC -ErrorAction SilentlyContinue) {
    try {
        C:\Windows\System32\inetsrv\appcmd.exe set config /section:httpLogging /dontLog:False
        Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] IIS Logging Enabled" -ForegroundColor White
    } catch { }
}

# ADCS Logging
if (Get-Service -Name CertSvc -ErrorAction SilentlyContinue) {
    auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
    certutil -setreg policy\EditFlags +EDITF_AUDITCERTTEMPLATELOAD
    Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] Certificate Services Logging Enabled" -ForegroundColor White
}

# --- Step 7: Wazuh Manager Configuration ---
[string]$wazuhConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (Test-Path $wazuhConfigPath) {
    if ($wazuhIP) {
        $configContent = Get-Content $wazuhConfigPath
        $newConfig = $configContent -replace '<address>.*</address>', "<address>$wazuhIP</address>"
        $newConfig | Set-Content $wazuhConfigPath
        Restart-Service -Name "Wazuh" -ErrorAction SilentlyContinue
        Write-Host "[" -NoNewline; Write-Host "SUCCESS" -ForegroundColor Green -NoNewline; Write-Host "] Wazuh Manager set to $wazuhIP" -ForegroundColor White
    }
}

# --- Final Status Report ---
Write-Host "`n--- Final Service Status Check ---" -ForegroundColor Cyan
$checkServices = @("EventLog", "dnssrv", "W3SVC", "Wazuh", "Sysmon64")
foreach ($svc in $checkServices) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s) {
        $color = if ($s.Status -eq "Running") { "Green" } else { "Red" }
        Write-Host "$svc is " -NoNewline; Write-Host $s.Status -ForegroundColor $color
    }
}

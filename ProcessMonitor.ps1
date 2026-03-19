# ---------------------------------------------------------------------------
# Script: ProcessMonitor.ps1
# Description: Monitors for new processes and terminates those not whitelisted.
# ---------------------------------------------------------------------------

# Configuration
$DryRun = $true # Set to $false to actually terminate processes
$IntervalSeconds = 1
$startTime = Get-Date

# Take a snapshot of currently running processes as "good processes"
$goodProcesses = Get-Process | Select-Object -Property Id, Name

# Create a log file
$logFileName = "ProcessMonitor_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$logFile = Join-Path -Path $env:TEMP -ChildPath $logFileName
"[$(Get-Date)] Process monitoring started. Snapshot taken." | Out-File -FilePath $logFile -Append

# Initialize counters
$terminatedCount = 0
$iteration = 0

# Create a hashtable for O(1) lookups
$goodProcessesHash = @{}
foreach ($proc in $goodProcesses) {
    $goodProcessesHash[$proc.Id] = $proc.Name
}

# Function to log and display messages
function Write-ProcessLog {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Color = "White"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
    "[$timestamp] $Message" | Out-File -FilePath $logFile -Append
}

# Function to check if a process is a critical system process
function Test-SystemProcess {
    param (
        [System.Diagnostics.Process]$Process
    )
    
    $criticalProcesses = @(
        "System", "svchost", "wininit", "winlogon", 
        "csrss", "smss", "lsass", "services", "explorer",
        "WmiPrvSE", "RuntimeBroker", "SearchHost"
    )
    
    return $criticalProcesses -contains $Process.Name
}

# Header UI
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "        PROCESS MONITOR ACTIVE          " -ForegroundColor Cyan
if ($DryRun) { Write-Host "        [MODE: SIMULATION ONLY]         " -ForegroundColor Yellow }
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Whitelisted: $($goodProcesses.Count) processes" -ForegroundColor Green
Write-Host "Log File:    $logFile" -ForegroundColor Green
Write-Host "Monitoring every $IntervalSeconds second(s). Press Ctrl+C to stop." -ForegroundColor Yellow
Write-Host "----------------------------------------" -ForegroundColor Cyan

try {
    while ($true) {
        $currentProcesses = Get-Process
        
        foreach ($process in $currentProcesses) {
            # Check if PID is in our whitelist
            if (-not $goodProcessesHash.ContainsKey($process.Id)) {
                
                # Safety check: System processes
                if (Test-SystemProcess -Process $process) {
                    Write-ProcessLog "SAFE: New system process allowed: $($process.Name) (PID: $($process.Id))" -Color "Gray"
                    $goodProcessesHash[$process.Id] = $process.Name
                    continue
                }
                
                $actionPrefix = if ($DryRun) { "[DRY RUN] Would terminate:" } else { "TERMINATING:" }
                Write-ProcessLog "$actionPrefix $($process.Name) (PID: $($process.Id))" -Color "Red"
                
                try {
                    # Capture details (Use ErrorAction SilentlyContinue as some props require Admin)
                    $pPath = try { $process.MainModule.FileName } catch { "Access Denied" }
                    $pStarted = try { $process.StartTime } catch { "Unknown" }
                    
                    if (-not $DryRun) {
                        Stop-Process -Id $process.Id -Force -ErrorAction Stop
                        $terminatedCount++
                        Write-ProcessLog "SUCCESS: Killed $($process.Name). Path: $pPath" -Color "Green"
                    } else {
                        Write-ProcessLog "INFO: Details - Path: $pPath, Started: $pStarted" -Color "Yellow"
                    }
                }
                catch {
                    Write-ProcessLog "ERROR: Could not stop $($process.Name): $($_.Exception.Message)" -Color "DarkRed"
                    # Add to whitelist temporarily to prevent log spamming if termination fails
                    $goodProcessesHash[$process.Id] = $process.Name
                }
            }
        }
        
        # Periodic Summary
        if ($iteration -gt 0 -and $iteration % 60 -eq 0) {
            Write-ProcessLog "HEARTBEAT: Monitor active. Total actions: $terminatedCount" -Color "Cyan"
        }
        
        $iteration++
        Start-Sleep -Seconds $IntervalSeconds
    }
}
catch [System.Management.Automation.BreakException], [System.Threading.ThreadAbortException] {
    # Handle manual stops gracefully
}
catch {
    Write-ProcessLog "CRITICAL EXCEPTION: $_" -Color "Red"
}
finally {
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalMinutes
    
    Write-ProcessLog "Monitoring stopped. Total terminated: $terminatedCount" -Color "Magenta"
    
    Write-Host "`n----------------------------------------" -ForegroundColor Cyan
    Write-Host "Summary Report:" -ForegroundColor Cyan
    Write-Host "Duration:    $([math]::Round($duration, 2)) minutes"
    Write-Host "Terminated:  $terminatedCount" -ForegroundColor $(if ($terminatedCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Log saved:   $logFile"
    Write-Host "----------------------------------------" -ForegroundColor Cyan
}

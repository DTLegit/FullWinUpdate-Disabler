# function Invoke-WPFUpdatesdisable {

    <#
    .SYNOPSIS
        Pauses Windows Update (feature, quality, overall) for 1042 weeks (~20 years) using ISO 8601 UTC date/time format.
    .DESCRIPTION
        This script performs the following actions:
          1. Checks if the relevant folder, child script file, registry key settings, and scheduled task already exist.
             Specifically, it examines the PauseUpdatesExpiryTime value under
             HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings to see if the pause is still in effect.
             If so, the script exits without reapplying settings.
          2. Otherwise, it creates a minimal child script that sets registry values under:
                HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings
             The values set are:
                - PauseFeatureUpdatesStartTime / PauseFeatureUpdatesEndTime
                - PauseQualityUpdatesStartTime / PauseQualityUpdatesEndTime
                - PauseUpdatesStartTime / PauseUpdatesExpiryTime
                - FlightSettingsMaxPauseDays (DWord set to hexadecimal 00001c84)
             The pause duration is 1042 weeks (~20 years) from the current UTC time.
          3. The child script is saved in the folder "C:\ProgramData\PauseWindowsUpdate".
          4. A scheduled task ("PauseWindowsUpdate") is registered to run the child script both at startup and weekly (every Monday at 03:00 AM) with these settings:
                - “Start When Available” is enabled.
                - The task is allowed to run even on battery.
                - If the task fails, it restarts every 1 minute, up to 5 times.
                - The task runs under the SYSTEM account.
          5. Finally, the child script is executed immediately.
    .NOTES
        Run as Administrator. Adapted for Windows 11 (24H2).
    #>

    # ----- Check for Administrator Rights -----
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Host "Not running as Administrator. Relaunching with elevated privileges..." -ForegroundColor Yellow
        $scriptPath = $MyInvocation.MyCommand.Path
        if ($scriptPath) {
            Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
        } else {
            Write-Host "Script path not available. Please run this script from a file." -ForegroundColor Red
        }
        return
    }

    # ----- Define Folder and File Paths -----
    $global:ScheduledFolder = "C:\ProgramData\PauseWindowsUpdate"
    if (-not (Test-Path $global:ScheduledFolder)) {
        New-Item -Path $global:ScheduledFolder -ItemType Directory -Force | Out-Null
    }
    $ScheduledScriptPath = Join-Path -Path $global:ScheduledFolder -ChildPath "PauseWindowsUpdate.ps1"

    # ----- Check for Existing Configuration -----
    # Instead of using a simple marker property, check if the PauseUpdatesExpiryTime is set and is still in the future.
    $regKeyPath   = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    $regKeyExists = Test-Path $regKeyPath
    $pauseActive  = $false
    if ($regKeyExists) {
        $currentPauseExpiry = (Get-ItemProperty -Path $regKeyPath -Name "PauseUpdatesExpiryTime" -ErrorAction SilentlyContinue).PauseUpdatesExpiryTime
        if ($currentPauseExpiry) {
            try {
                $parsedExpiry = [datetime]::ParseExact($currentPauseExpiry, "yyyy-MM-ddTHH:mm:ssZ", $null)
                if ($parsedExpiry -gt (Get-Date).ToUniversalTime()) {
                    $pauseActive = $true
                }
            }
            catch { }
        }
    }
    $folderExists = Test-Path $global:ScheduledFolder
    $fileExists   = Test-Path $ScheduledScriptPath
    $taskExists   = $null -ne (Get-ScheduledTask -TaskName "PauseWindowsUpdate" -ErrorAction SilentlyContinue)

    if ($folderExists -and $fileExists -and $regKeyExists -and $pauseActive -and $taskExists) {
        Write-Host "Pause settings are already active and all components exist. Exiting without changes." -ForegroundColor Yellow
        return
    }

    # ----- Create the Minimal Child Script -----
    $PauseScriptContent = @'
# Minimal Pause Script for Windows Update using ISO 8601 UTC Format
# This script sets registry values under:
#   HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings
# The values are:
#   - PauseFeatureUpdatesStartTime / PauseFeatureUpdatesEndTime
#   - PauseQualityUpdatesStartTime / PauseQualityUpdatesEndTime
#   - PauseUpdatesStartTime / PauseUpdatesExpiryTime
#   - FlightSettingsMaxPauseDays (DWord set to 0x00001c84)
# The pause duration is set for 1042 weeks (~20 years) from the current UTC time.
# Before applying changes, this script checks if the current pause expiry is still in the future.
# If so, it exits; otherwise, it re-applies the settings.

$UXKey = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"

# Check if a valid pause expiry exists.
$currentPauseExpiry = (Get-ItemProperty -Path $UXKey -Name "PauseUpdatesExpiryTime" -ErrorAction SilentlyContinue).PauseUpdatesExpiryTime
if ($currentPauseExpiry) {
    try {
        $parsedExpiry = [datetime]::ParseExact($currentPauseExpiry, "yyyy-MM-ddTHH:mm:ssZ", $null)
        if ($parsedExpiry -gt (Get-Date).ToUniversalTime()) {
            Write-Host "Pause settings are active until $currentPauseExpiry. Exiting child script."
            exit
        }
    } catch { }
}

Write-Host "Applying Windows Update pause for 1042 weeks (~20 years) using ISO 8601 UTC format..."

# Calculate pause times.
$nowUTC = (Get-Date).ToUniversalTime()
# 1042 weeks * 7 days per week = 7294 days.
$endUTC = $nowUTC.AddDays(1042 * 7)
$format = "yyyy-MM-ddTHH:mm:ssZ"

$pauseStart = $nowUTC.ToString($format)
$pauseEnd   = $endUTC.ToString($format)

Write-Host "Calculated Pause Start (UTC): $pauseStart"
Write-Host "Calculated Pause End   (UTC): $pauseEnd"

# Ensure the registry key exists.
if (!(Test-Path $UXKey)) {
    Write-Host "Registry key not found. Creating $UXKey..."
    New-Item -Path $UXKey -Force | Out-Null
}

$currentSettings = Get-ItemProperty -Path $UXKey -ErrorAction SilentlyContinue

if ($null -ne $currentSettings.PauseFeatureUpdatesStartTime) {
    Write-Host "Existing pause settings found. Reapplying updated settings..."
} else {
    Write-Host "No existing pause settings found. Applying new settings..."
}

# Set or update FlightSettingsMaxPauseDays.
if ($null -eq $currentSettings.FlightSettingsMaxPauseDays) {
    Write-Host "Creating FlightSettingsMaxPauseDays with value 0x00001c84..."
    New-ItemProperty -Path $UXKey -Name "FlightSettingsMaxPauseDays" -PropertyType DWord -Value 0x1c84 -Force | Out-Null
} else {
    Write-Host "Updating FlightSettingsMaxPauseDays to value 0x00001c84..."
    Set-ItemProperty -Path $UXKey -Name "FlightSettingsMaxPauseDays" -Value 0x1c84 -Force
}

# Apply the pause settings.
Set-ItemProperty -Path $UXKey -Name "PauseFeatureUpdatesStartTime" -Value $pauseStart -Type String -Force
Set-ItemProperty -Path $UXKey -Name "PauseFeatureUpdatesEndTime"   -Value $pauseEnd   -Type String -Force
Set-ItemProperty -Path $UXKey -Name "PauseQualityUpdatesStartTime" -Value $pauseStart -Type String -Force
Set-ItemProperty -Path $UXKey -Name "PauseQualityUpdatesEndTime"   -Value $pauseEnd   -Type String -Force
Set-ItemProperty -Path $UXKey -Name "PauseUpdatesStartTime"  -Value $pauseStart -Type String -Force
Set-ItemProperty -Path $UXKey -Name "PauseUpdatesExpiryTime" -Value $pauseEnd   -Type String -Force

Write-Host "Windows Update is now paused (feature, quality, overall) until $pauseEnd"
'@

    # ----- Write the Child Script to Disk -----
    $PauseScriptContent | Set-Content -Path $ScheduledScriptPath -Encoding UTF8 -Force
    Write-Host "Minimal pause script saved to $ScheduledScriptPath" -ForegroundColor Green

    # ----- Register Scheduled Task -----
    $TaskName = "PauseWindowsUpdate"
    $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Unrestricted -WindowStyle Hidden -File `"$ScheduledScriptPath`""
    $TriggerStartup = New-ScheduledTaskTrigger -AtStartup
    $TriggerWeekly  = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "03:00AM"
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    $TaskSettings = New-ScheduledTaskSettingsSet -Compatibility Win8
    $TaskSettings.StartWhenAvailable = $true
    $TaskSettings.DisallowStartIfOnBatteries = $false
    $TaskSettings.RestartInterval = [System.Xml.XmlConvert]::ToString((New-TimeSpan -Minutes 1))
    $TaskSettings.RestartCount = 5

    try {
        Register-ScheduledTask -TaskName $TaskName `
                               -Action $TaskAction `
                               -Trigger @($TriggerStartup, $TriggerWeekly) `
                               -Principal $Principal `
                               -Settings $TaskSettings `
                               -Description "Refreshes Windows Update pause settings (1042 weeks pause and FlightSettingsMaxPauseDays) weekly and at startup." `
                               -Force
        Write-Host "Scheduled task '$TaskName' registered." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to create scheduled task '$TaskName': $_" -ForegroundColor Red
    }

    # ----- Initialize the Pause Immediately -----
    Write-Host "Initializing Windows Update pause now..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Unrestricted -WindowStyle Hidden -File `"$ScheduledScriptPath`"" -Wait

    Write-Host "Windows Update is now paused for 1042 weeks (~20 years) using ISO 8601 UTC format. Task set to refresh weekly and at startup." -ForegroundColor Green
# }

# ================================================================
# WindowsUpdateSettings_Master.ps1
# ================================================================
# This Windows Update script configures the Windows Operating System to only receive security-related updates (quality updates)
# for the currently running feature update version of Windows until that current releases reaches end-of-life. 
# Once the currently running major feature release of Windows is EOL, it will automatically download the latest feature update
# and upgrade to the latest supported major feature version of Windows. 
# 
# Additionally, this script will also create and configure a task that re-runs a saved script, in which re-applies the settings if necessary
# and utilizes a timestamp.txt file to ensure that settings reapplication takes place once every 364 days if the set values have either changed, has been removed,
# or if the registry values it sets needs updating to reflect the current and latest running version of Windows on the system. 
# 
# This mechanism ensures that these settings stay in place and cannot be automatically removed by Microsoft or the Windows OS itself through an update 
# and that these settings stay persistent through upgrades. This also ensures that only the user has the ability to remove these settings and revert Windows Update back to its default configuration
# if they elect to do so. 
# 
# This script configures the following registry settings to the reference values: 
# Under Registry Settings Path: Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate 
# 
# 1) DeferQualityUpdates = 1 (Decimal Value/DWord)
# 2) TargetReleaseVersion = 1 (Decimal Value/DWord)
# 3) ProductVersion = The Major Windows Version that has been detected (Either Windows 10 or Windows 11 at the time that this script is written.) - String Value
# 4) TargetReleaseVersionInfo = The Subsequent Feature Update Version that is detected (2XHX at the time that this script is written. e.g. 24H2) - String Value
# 5) DeferQualityUpdatesPeriodInDays = 4 (Decimal Value / DWord) - NOTE: This means that system deployment for quality updates are being delayed for four days after official release. 
# -  The reasoning for this is to ensure that there are no issues and bugs that may occur from Microsoft's end, allowing for update retraction if needed before the quality update is applied to running systems. 
# -  This also makes sure that the update is deployed on the weekend rather than on Patch Tuesday (second Tuesday of each month) when Microsoft releases the updates, which is when the PC is less likely to be actively being used
#    in both business and residential home environments. 
# 6) ExcludeWUDriversInQualityUpdate = 1 (Decimal Value / DWord) - Disables Driver Updates through Windows Update. The philosophy here is to increase system stability and prevent breakage by letting drivers install and update 
#    via their own updaters and configurations in order to reduce risk of possible overrides or corruption imposed by Windows Update. 
# 7) Under Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
#    - AUPowerManagement = 0 (Decimal Value / DWord) 
# 
# DESCRIPTION: The settings below here sets the user active hours to be between 8AM and 2AM, to where the PC only restarts automatically early in the morning to finish installing a deployed security updates.
# This ensures that the PC auto-restarts only when the user is least likely to be using the PC. However, the user can revert back to enabling the auto-adjust setting or pick their own custom active times if they so wish. 
#
# Under Registry Settings Path: Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings
# 1) AllowMUUpdateService = 0 (Decimal Value / DWord)
# 2) SmartActiveHoursState = 0 (Decimal Value / DWord) 
# 3) UserChoiceActiveHoursStart = 8 (Decimal Value / DWord)
# 4) ActiveHoursStart = 8 (Decimal Value / DWord) 
# 5) UserChoiceActiveHoursEnd = 2 (Decimal Value / DWord)
# 6) ActiveHoursEnd = 2 (Decimal Value / DWord) 
# 
# This master script performs the following:
# 1. Ensures it is running as Administrator. If not, it relaunches itself.
# 2. Creates a folder structure in C:\ProgramData for storing:
#       - A child script (RunWindowsUpdateSettings.ps1) that contains
#         the core logic for checking and applying Windows Update settings.
#       - A timestamp text file.
#       - A Logs subfolder to store log files (keeping only the last 3).
#    The folder used is: "C:\ProgramData\Windows Updates Settings"
# 3. Saves the child script into that directory.
# 4. Registers a scheduled task that runs the saved child script at startup
#    and weekly (every Sunday at 03:00 AM) using the SYSTEM account.
#    The task is configured to run with a hidden window, using a temporary
#    Unrestricted execution policy.
#    Additionally, if the task fails, it will attempt to restart every 1 minute,
#    up to 5 times.
# 5. Immediately launches the child script (with Unrestricted policy and admin rights)
#    so that the Windows Update settings are checked and applied if necessary.
#
# Future modifications can be made by adjusting the child script.
# 
# Credit and shoutout goes to technology content creators Chris Titus Tech and Britec for their expertise on the Windows Operating System and Windows Update related settings and recommendations. 
# They both played a huge part with both their video tutorial content and website articles showcasing which registry settings to tweak and the values to set them at in order to make this work. 
# Once again, thanks to the both of them for sharing their knowledge, wisdom, and expertise in regards to this topic and large role in the inspiration of this script. 
# 
# DISCLAIMER: 
# The settings and methods that this script employs have only been tested on and guaranteed to work on later versions of the Pro and Enterprise editions of Windows (although this will likely work on the Education edition as well). 
# Microsoft limits and places restrictions on select registry settings and revokes access to the Group Policy Editor (gpedit.msc) on all Home editions of Windows. Therefore, it is not guaranteed that these settings will work
# and that Windows / Windows Update will respect the settings that this script sets on Windows Home, until a successful workaround to these restrictions/limitations has been discovered to remedy this issue. So, it is advised that you upgrade to 
# at least Windows Pro before you attempt to run this script to employ these policies. 
#
# LICENSING AND TERMS OF USE:
# This script may be used, consumed, modified, included in other software, distributed, etc. under the terms and conditions set forth by the latest version of the Mozilla Public License (MPL). 
# Although system breakage is certainly not likely, the author assumes no liability or responsibility for any outcomes associated with the use of this script. You accept that you use this at your own risk and that any impacts to your 
# PC are under your sole responsibility and discretion. The creation of a system restore point and backup of sensitive data is advised before running this script if you are worried or concerned about potential breakage that would result from 
# the settings and system modifications done by this script. Again, this is not likely, but this is a precaution in case if you at all concerned or worried. 
# 
# If any issues or problems arise or there are are any suggestions that you would like to make in improving this script, please feel free to either submit an issue or a PR request to the script's GitHub page if you feel so inclined.
# I hope you enjoy the use of this tool as much as I have with creating this :). 
# ================================================================

# ----- Function: Test for Administrator Privileges -----
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# If not running as Administrator, relaunch the script with elevated rights.
if (-not (Test-Admin)) {
    Write-Host "Master script is not running as Administrator. Relaunching as Administrator..."
    try {
        Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" `
            -Verb RunAs
    }
    catch {
        Write-Host "Failed to relaunch as Administrator. Please re-run this script manually as an Administrator." -ForegroundColor Red
    }
    exit
}

# ----- Define Folder and File Paths -----
$MainFolder    = "C:\ProgramData\Windows Updates Settings"
$LogFolder     = Join-Path $MainFolder "Logs"
$TimestampFile = Join-Path $MainFolder "LastRunTimestamp.txt"
$ChildScript   = Join-Path $MainFolder "RunWindowsUpdateSettings.ps1"

# Create the main folder if it does not exist.
if (-not (Test-Path $MainFolder)) {
    New-Item -Path $MainFolder -ItemType Directory -Force | Out-Null
}
# Create the Logs folder if it does not exist.
if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

# ----- Create the Child Script -----
# The child script contains the core function to check and apply Windows Update settings.
$childScriptContent = @'
# ================================================================
# RunWindowsUpdateSettings.ps1
# ================================================================
# This script checks and applies Windows Update security settings if needed.
#
# It performs the following:
# 1. Checks if this is the first run or if at least 364 days have elapsed
#    since the last update (using a timestamp file).
# 2. Detects the OS version (Windows 10 vs. Windows 11) and the major feature release.
# 3. Validates registry settings for Windows Update, Device Metadata,
#    Driver Searching, and WindowsUpdate\AU.
# 4. If discrepancies are found or it is the first run, applies the proper registry settings,
#    forces a gpupdate, and updates the timestamp.
# 5. Logs all actions to a log file in the Logs folder (keeping only the last 3 logs).
# ================================================================

param()

# ----- Start Logging -----
$LogFolder = Join-Path "C:\ProgramData\Windows Updates Settings" "Logs"
$TimeStampNow = (Get-Date).ToString("yyyyMMddHHmmss")
$LogFile = Join-Path $LogFolder ("WindowsUpdateSettings-$TimeStampNow.log")
try {
    Start-Transcript -Path $LogFile -Append | Out-Null
}
catch {
    Write-Host "WARNING: Failed to start transcript: $_"
}

$TimestampFile = Join-Path "C:\ProgramData\Windows Updates Settings" "LastRunTimestamp.txt"

# ----- Determine if Initial Run or 364+ Days Have Passed -----
$InitialRun = $false
if (-not (Test-Path $TimestampFile)) {
    Write-Host "Timestamp file not found. Assuming initial run."
    $InitialRun = $true
} else {
    $LastRunStr = Get-Content $TimestampFile -ErrorAction SilentlyContinue
    try {
        $LastRun = Get-Date $LastRunStr -ErrorAction Stop
    }
    catch {
        Write-Host "DEBUG: Failed to parse timestamp '$LastRunStr'. Treating as initial run."
        $InitialRun = $true
    }
}

if (-not $InitialRun) {
    $CurrentDate = Get-Date
    $TimeSpan = New-TimeSpan -Start $LastRun -End $CurrentDate
    Write-Host ("DEBUG: Elapsed time since last run: {0} days, {1} hours, {2} minutes, {3} seconds." `
        -f $TimeSpan.Days, $TimeSpan.Hours, $TimeSpan.Minutes, $TimeSpan.Seconds)
}

if ($InitialRun -or ($TimeSpan.TotalDays -ge 364)) {
    Write-Host "Proceeding to verify and apply Windows Update security settings..."
    
    # ----- OS and Feature Release Detection -----
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -eq 10 -and $osVersion.Build -ge 22000) {
        $ProductVersion = "Windows 11"
    }
    elseif ($osVersion.Major -eq 10) {
        $ProductVersion = "Windows 10"
    }
    else {
        $ProductVersion = "Unknown"
    }
    Write-Host "DEBUG: Detected OS: $ProductVersion (Build $($osVersion.Build))"
    
    # Determine Feature Release via layered detection.
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $primaryFeatureRelease = $null
    $secondaryFeatureRelease = $null
    $tertiaryFeatureRelease = $null
    try { $regValues = Get-ItemProperty -Path $regPath -ErrorAction Stop } catch { }
    if ($regValues -and $regValues.DisplayVersion) {
        if ($regValues.DisplayVersion -match "^\d{2}H\d$") {
            $primaryFeatureRelease = $regValues.DisplayVersion
            Write-Host "DEBUG: Primary Feature Release: $primaryFeatureRelease"
        } else {
            Write-Host "DEBUG: DisplayVersion format mismatch."
        }
    } else {
        Write-Host "DEBUG: DisplayVersion not found."
    }
    try { $osInfo = Get-ComputerInfo -ErrorAction Stop } catch { }
    if ($osInfo -and $osInfo.OSDisplayVersion) {
        if ($osInfo.OSDisplayVersion -match "^\d{2}H\d$") {
            $secondaryFeatureRelease = $matches[0]
            Write-Host "DEBUG: Secondary Feature Release: $secondaryFeatureRelease"
        } else {
            Write-Host "DEBUG: OSDisplayVersion format mismatch."
        }
    } else {
        Write-Host "DEBUG: OSDisplayVersion not found."
    }
    if (-not $primaryFeatureRelease -and $regValues -and $regValues.ReleaseId) {
        if ($regValues.ReleaseId -match "^\d{2}H\d$") {
            $tertiaryFeatureRelease = $regValues.ReleaseId
            Write-Host "DEBUG: Tertiary Feature Release: $tertiaryFeatureRelease"
        } else {
            Write-Host "DEBUG: ReleaseId format mismatch."
        }
    }
    $finalFeatureRelease = $primaryFeatureRelease
    if (-not $finalFeatureRelease) { $finalFeatureRelease = $secondaryFeatureRelease }
    if (-not $finalFeatureRelease) { $finalFeatureRelease = $tertiaryFeatureRelease }
    if ($finalFeatureRelease) {
        $TargetReleaseVersionInfo = $finalFeatureRelease
        Write-Host "DEBUG: Final Feature Release: $TargetReleaseVersionInfo"
    } else {
        $TargetReleaseVersionInfo = "24H2"
        Write-Host "DEBUG: No valid feature release detected; defaulting to $TargetReleaseVersionInfo"
    }
    
    # ----- Registry Settings Verification & Application -----
    $ReapplyNeeded = $false
    
    # --- Check WindowsUpdate Policy Key ---
    $WURegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $WUSettings = Get-ItemProperty -Path $WURegPath -ErrorAction SilentlyContinue
    if (-not $WUSettings) {
        Write-Host "DEBUG: WindowsUpdate key not found; it will be created."
        $ReapplyNeeded = $true
    }
    elseif (($WUSettings.ProductVersion -ne $ProductVersion) -or
            ($WUSettings.TargetReleaseVersionInfo -ne $TargetReleaseVersionInfo) -or
            ($WUSettings.TargetReleaseVersion -ne 1) -or
            ($WUSettings.DeferQualityUpdates -ne 1) -or
            ($WUSettings.DeferQualityUpdatesPeriodInDays -ne 4) -or
            ($WUSettings.ExcludeWUDriversInQualityUpdate -ne 1)) {
        Write-Host "DEBUG: WindowsUpdate registry discrepancy detected."
        $ReapplyNeeded = $true
    }

    # --- Check WindowsUpdate UX\Settings Key ---
    $UXRegPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
    $UXSettings = Get-ItemProperty -Path $UXRegPath -ErrorAction SilentlyContinue
    if (-not $UXSettings) {
        Write-Host "DEBUG: WindowsUpdate UX\Settings key not found; it will be created."
        $ReapplyNeeded = $true
    }
    else {
        if (($UXSettings.ActiveHoursEnd -ne 2) -or
            ($UXSettings.ActiveHoursStart -ne 8) -or
            ($UXSettings.AllowMUUpdateService -ne 0) -or
            ($UXSettings.SmartActiveHoursState -ne 0) -or
            ($UXSettings.UserChoiceActiveHoursStart -ne 8) -or
            ($UXSettings.UserChoiceActiveHoursEnd -ne 2)) {
            Write-Host "DEBUG: WindowsUpdate UX\Settings registry discrepancy detected."
            $ReapplyNeeded = $true
        }
    }
    
    # ----- Apply Registry Settings if Needed -----
    if ($InitialRun -or $ReapplyNeeded) {
        Write-Host "Applying registry settings..."
        
        # --- Apply settings for WindowsUpdate key ---
        $RegistrySettings = @{
            "ProductVersion"                  = $ProductVersion
            "TargetReleaseVersion"            = 1
            "TargetReleaseVersionInfo"        = $TargetReleaseVersionInfo
            "DeferQualityUpdates"             = 1
            "DeferQualityUpdatesPeriodInDays" = 4
            "ExcludeWUDriversInQualityUpdate" = 1
        }
        if (-not (Test-Path $WURegPath)) { New-Item -Path $WURegPath -Force | Out-Null }
        foreach ($Name in $RegistrySettings.Keys) {
            $Value = $RegistrySettings[$Name]
            $Type = if ($Value -is [int]) { "DWord" } else { "String" }
            try {
                $existingValue = Get-ItemProperty -Path $WURegPath -Name $Name -ErrorAction SilentlyContinue
                if ($null -eq $existingValue) {
                    New-ItemProperty -Path $WURegPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
                } else {
                    Set-ItemProperty -Path $WURegPath -Name $Name -Value $Value -Force
                }
                Write-Host "Set $Name to $Value ($Type)"
            } catch {
                Write-Host "Failed to set ${Name}: $_" -ForegroundColor Red
            }
        }
        
        # --- Create and Configure WindowsUpdate\AU Key ---
        $AUKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (-not (Test-Path $AUKey)) {
            New-Item -Path $AUKey -Force | Out-Null
            Write-Host "DEBUG: Created AU subkey under WindowsUpdate."
        }

        Set-ItemProperty -Path $AUKey -Name "AUPowerManagement" -Type DWord -Value 0
        Write-Host "Applied WindowsUpdate AU settings."
        
        # --- Configure WindowsUpdate UX\Settings Key ---
        $UXRegistrySettings = @{
            "ActiveHoursEnd"            = 2
            "ActiveHoursStart"          = 8
            "AllowMUUpdateService"      = 0
            "SmartActiveHoursState"     = 0
            "UserChoiceActiveHoursStart"= 8
            "UserChoiceActiveHoursEnd"  = 2
        }
        if (-not (Test-Path $UXRegPath)) { New-Item -Path $UXRegPath -Force | Out-Null }
        foreach ($Name in $UXRegistrySettings.Keys) {
            $Value = $UXRegistrySettings[$Name]
            $Type  = "DWord"  # All are DWORD values
            try {
                $existingValue = Get-ItemProperty -Path $UXRegPath -Name $Name -ErrorAction SilentlyContinue
                if ($null -eq $existingValue) {
                    New-ItemProperty -Path $UXRegPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
                } else {
                    Set-ItemProperty -Path $UXRegPath -Name $Name -Value $Value -Force
                }
                Write-Host "Set $Name to $Value ($Type)"
            } catch {
                Write-Host "Failed to set ${Name}: $_" -ForegroundColor Red
            }
        }

        gpupdate /force
        Write-Host "Registry settings applied."
        (Get-Date).ToString("o") | Out-File -FilePath $TimestampFile -Encoding UTF8
        Write-Host "Timestamp updated."
    }
    else {
        Write-Host "Registry settings are up-to-date. No changes applied."
    }
} else {
    Write-Host "No update required at this time."
}

# ----- Clean Up Old Logs (Keep Only Last 3) -----
try {
    $logs = Get-ChildItem -Path $LogFolder -Filter "WindowsUpdateSettings-*.log" | Sort-Object CreationTime -Descending
    $oldLogs = $logs | Select-Object -Skip 3
    foreach ($log in $oldLogs) { Remove-Item $log.FullName -Force }
}
catch { Write-Host "WARNING: Failed to clean old logs: $_" }

try { Stop-Transcript | Out-Null } catch { }
'@

# Save the child script to disk.
Set-Content -Path $ChildScript -Value $childScriptContent -Force -Encoding UTF8

# ----- Register Scheduled Task -----
# This scheduled task will run the child script with a temporary Unrestricted execution policy.
$TaskName = "WindowsUpdateSettingsTask"
$TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Unrestricted -WindowStyle Hidden -File `"$ChildScript`""
$TriggerStartup = New-ScheduledTaskTrigger -AtStartup
$TriggerWeekly  = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "03:00AM"
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$TaskSettings = New-ScheduledTaskSettingsSet -Compatibility Win8
$TaskSettings.StartWhenAvailable = $true
$TaskSettings.DisallowStartIfOnBatteries = $false
# Set task to restart every 1 minute up to 5 times if it fails.
$TaskSettings.RestartInterval = [System.Xml.XmlConvert]::ToString((New-TimeSpan -Minutes 1))
$TaskSettings.RestartCount = 5

Register-ScheduledTask -TaskName $TaskName `
                       -Action $TaskAction `
                       -Trigger @($TriggerStartup, $TriggerWeekly) `
                       -Principal $Principal `
                       -Settings $TaskSettings `
                       -Description "Runs the child script to check and apply Windows Update security settings if needed." `
                       -Force

Write-Host "Scheduled task '$TaskName' registered."

# ----- Run the Child Script Immediately for Initial Setup -----
Write-Host "Running initial application of Windows Update security settings..."
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Unrestricted -File `"$ChildScript`"" -Verb RunAs -Wait
Write-Host "Initial Windows Update security settings applied!" -ForegroundColor Green
Write-Host "The Windows Update Security Settings folder with the scheduled task-associated script, timestamp text file, and recent run logs have been saved to: " -ForegroundColor Green
Write-Host "C:\ProgramData\Windows Updates Settings" 
Write-Host "You can access these files at any time."

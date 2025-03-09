<#
================================================================================================================
Script Name: FullWinUpdateDisabler.ps1
Author: DTLegit (Based on and expanded further upon from the work of original author @tsgrgo)
Based on: windows-update-disabler by @tsgrgo (Original Work: https://github.com/tsgrgo/windows-update-disabler)
Thank you to @tsgrgo for your incredible work with the original batch file code that this script uses! 
Without your authorship, this would not have been possible.
Version: 1.0
================================================================================================================
DESCRIPTION:
  This PowerShell script is designed to manage Windows Update functionality on a Windows
  system by providing a modular, multi-phase solution. The script performs the following:
  
  1. Pre-Execution Checks (User Context):
     - Verifies administrator privileges and attempts elevation if necessary.
     - Checks for an active Internet connection.
     - Creates a system restore point for safety.
     - Performs an idempotency check to avoid redundant modifications.
     - Displays full-screen disclaimers and warnings (including legal disclaimers),
       requiring explicit user confirmation to proceed.
     - Checks and prompts for disabling Windows Defender if it is active.
     - Captures and stores the original user's Desktop and Documents paths.
     - Defines centralized configuration settings (e.g., the PsExec download URL).

  2. Temporary Execution Phase (SYSTEM Context):
     - Downloads PsExec.exe using robust multi-method logic.
     - Reconstructs and executes a temporary batch file that disables Windows Update,
       running under SYSTEM privileges.
     - Cleans up all temporary files and directories afterward.

  3. Permanent Phase (User Context):
     - Generates a dedicated PsExec download script (DownloadPsExec.ps1) with the robust 
       download logic.
     - Reconstructs two permanent batch files:
         a) "disable updates.bat" – to completely disable Windows Update.
         b) "use update services.bat" – to partially re-enable Windows Update for dependent
            applications.
     - Both batch files include calls to the dedicated PsExec download script, ensuring 
       that PsExec is downloaded (if needed) to their local directory and then removed after
       execution.
     - Saves the permanent batch files in a dedicated folder (e.g., "WUControlScripts") 
       on the user's Desktop, and creates desktop shortcuts for easy access.
  
  4. Final Cleanup:
     - Automatically deletes all temporary files and directories created during execution.

================================================================================================================
WARNING & DISCLAIMER:
  This script makes extensive modifications to system services, registry settings, and
  scheduled tasks to disable Windows Update. Although it has been thoroughly tested, the user uses
  this at their own risk. Creating a system restore point is highly recommended before running this
  script. The author(s) accept no liability for any damage caused by the use of this script.
  
  By running this script, you acknowledge that you fully understand the risks and agree to
  all disclaimers. If any issues arise, you are encouraged to report them or submit a pull
  request to the script's GitHub repository.

=================================================================================================================
NOTES:
  - The script is organized into multiple modules to ensure maintainability and clarity.
  - Only the actions that require SYSTEM privileges are executed under elevated context.
  - The PsExec download URL is defined in a single location and is reused across all modules.
=================================================================================================================
#>
# Define $global:OriginalDesktop and $global:PermanentFolder.
# $global:OriginalDesktop - The original user's Desktop path.
# $global:PermanentFolder - Path and name to the folder of saved files. 
$desktopPath = [Environment]::GetFolderPath("Desktop")
if ([string]::IsNullOrEmpty($desktopPath)) {
    Write-Host "No user Desktop found. Using C:\Temp as a fallback."
    $desktopPath = "C:\Temp"
}
$global:OriginalDesktop = $desktopPath
$global:PermanentFolder = Join-Path $global:OriginalDesktop "WUControlScripts"

#-----------------------------
# Start Transcript for Logging
#-----------------------------
# This will capture all console output.
$transcriptPath = Join-Path $global:PermanentFolder "FullWinUpdateDisabler_Transcript.log"
Start-Transcript -Path $transcriptPath -Append

#===============================================================================
# Script Configuration and Path Capture - Define $global:OriginalDocuments and $global:PsExecUrl 
#===============================================================================
# This module captures and sets the following global variables:
#   $global:OriginalDocuments   - The original user's Documents folder path.
#   $global:PsExecUrl           - The centralized URL from which PsExec.exe will be downloaded.
# These values are used by later modules to ensure that permanent files and shortcuts 
# are saved in the correct user-accessible locations and that the PsExec URL is defined only once.
    $global:OriginalDocuments = [Environment]::GetFolderPath("MyDocuments")
    $global:PsExecUrl         = "https://github.com/DTLegit/FullWinUpdate-Disabler/raw/refs/heads/main/PsExec.exe" # <--- CHANGE ME! Point this variable to the URL of where the PsExec.exe would be hosted. THIS IS NEEDED FOR THIS SCRIPT TO FULLY FUNCTION!!! 

    Write-Host "Configuration and path capture complete:" -ForegroundColor Cyan
    Write-Host "  Original Desktop:   $global:OriginalDesktop" -ForegroundColor White
    Write-Host "  Original Documents: $global:OriginalDocuments" -ForegroundColor White
    Write-Host "  PsExec Download URL: $global:PsExecUrl" -ForegroundColor White
    Write-Host "  Folder Name of Saved Management Batch Files and Script Log: $global:PermanentFolder" -ForegroundColor White

#===============================================================================
# Module 1: Administrator Privilege Check
#===============================================================================
# This function verifies that the current session has administrator rights.
# If not, it attempts to relaunch the script in an elevated PowerShell session.
# If the elevation fails, it displays an error message and exits.
function Ensure-Administrator {
    # Retrieve the current Windows identity.
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    
    # Create a WindowsPrincipal object from the current identity.
    $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
    
    # Check if the current user belongs to the Administrators group.
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script requires administrator privileges. Attempting to relaunch as Administrator..."
        try {
            # Relaunch the script with elevated privileges.
            Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" admin" -Verb RunAs
        }
        catch {
            Write-Host "Failed to relaunch the script with administrator privileges. Exiting..."
        }
        # Exit the current instance.
        exit
    }
    else {
        Write-Host "Administrator privileges confirmed."
    }
} # End Ensure-Administrator

#===============================================================================
# Module 2: Internet Connection Check
#===============================================================================
# This function tests for an active internet connection by pinging a reliable external host.
# An active Internet connection is required to download the necessary PsExec.exe file for the script to function fully.
# If no connection is detected, the script outputs an error message and exits.
function Test-InternetConnection {
    Write-Host "Checking for active Internet connection (required to download PsExec.exe)..."
    Write-Host "The PSExec.exe file is needed in order for this script to perform certain necessary operations as the SYSTEM user,"
    Write-Host "in order to fully disable Windows Update. The SYSTEM user has the needed permissions necessary for this to fully work."
    
    # Use a reliable endpoint (Google Public DNS: 8.8.8.8).
    $target = "8.8.8.8"
    
    try {
        # Test-NetConnection is available in Windows PowerShell 4.0+.
        $result = Test-NetConnection -ComputerName $target -InformationLevel Quiet
        
        if ($result -eq $true) {
            Write-Host "Internet connection is active."
            return $true
        }
        else {
            Write-Host "No active Internet connection detected. An active Internet connection is required to download PsExec.exe. Exiting..."
            return $false
        }
    }
    catch {
        # Fallback to ping if Test-NetConnection fails.
        Write-Host "Test-NetConnection failed. Trying ping as a fallback..."
        $ping = Test-Connection -ComputerName $target -Count 2 -Quiet
        if ($ping -eq $true) {
            Write-Host "Internet connection is active (detected via ping)."
            return $true
        }
        else {
            Write-Host "No active Internet connection detected (ping test failed). An active connection is required to download PsExec.exe. Exiting..."
            return $false
        }
    }
} # End Test-InternetConnection


#===============================================================================
# Module 3: System Restore Point Creation
#===============================================================================
# This function creates a system restore point so that the user can revert the system 
# to a previous state if anything goes wrong. It uses code and logic from Chris Titus Tech's Restore Point Creation Tweak, found within WinUtil. 
# (Thank you Chris!!!)  
# The function asks and advises the user on creating a restore point, and prompts for confirmation before proceeding in the creation of one.
function Create-SystemRestorePoint {
	
	# Ask the user if they want to create a restore point now.
    $userResponse = Read-Host "Do you want to create a system restore point now? It is advised that you create one before proceeding with this script. (Y/N) (Recommended: Y)"
    if ($userResponse -notin @("Y", "y")) {
        Write-Host "Skipping system restore point creation as per user choice."
        return
    }
	
    Write-Host "Enabling System Restore for drive $env:SystemDrive..."
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive"
    }
    catch {
        Write-Host "An error occurred while enabling System Restore: $_"
    }

    # Check if the SystemRestorePointCreationFrequency value exists
    try {
        $exists = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Error checking SystemRestorePointCreationFrequency: $_"
    }
    if ($null -eq $exists) {
        Write-Host "Changing system to allow multiple restore points per day..."
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0 -Type DWord -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Host "Failed to set SystemRestorePointCreationFrequency: $_"
        }
    }

    # Import the required module for Get-ComputerRestorePoint.
    try {
        Import-Module Microsoft.PowerShell.Management -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to load the Microsoft.PowerShell.Management module: $_"
        return
    }

    # Get all restore points created today.
    try {
        $existingRestorePoints = Get-ComputerRestorePoint | Where-Object { $_.CreationTime.Date -eq (Get-Date).Date }
    }
    catch {
        Write-Host "Failed to retrieve restore points: $_"
        return
    }

    # If no restore point has been created today, create one.
    if ($existingRestorePoints.Count -eq 0) {
        $description = "System Restore Point created by FullWinUpdate-Disabler Script."
        try {
            Checkpoint-Computer -Description $description -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            Write-Host -ForegroundColor Green "System Restore Point Created Successfully."
        }
        catch {
            Write-Host -ForegroundColor Red "Failed to create a system restore point: $_"
        }
    }
    else {
        Write-Host "A restore point has already been created today. Skipping creation."
    }
}

#===============================================================================
# Module 4: Previous Script Run Check
#===============================================================================
# This function performs a general check to determine if the modifications that this
# script intends to make have already been applied to the system.
#
# It checks the following:
#   1. Registry key: Checks if "NoAutoUpdate" in the Windows Update policies is set to 1.
#   2. Service status: Checks if the "wuauserv" service (Windows Update) is disabled.
#   3. Scheduled tasks: Performs a basic check to see if some Windows Update-related
#      scheduled tasks appear to be disabled.
#
# If any of these checks indicate that modifications are already in place,
# the function warns the user and prompts them whether to continue or exit.
function Check-PreviousRun {
    Write-Host "Performing idempotency check to determine if modifications are already applied..."
    $alreadyModified = $false

    # Check registry for "NoAutoUpdate" setting.
    try {
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
        $noAutoUpdate = (Get-ItemProperty -Path $regPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate
        if ($noAutoUpdate -eq 1) {
            Write-Host "Registry check: 'NoAutoUpdate' is set to 1."
            $alreadyModified = $true
        }
    }
    catch {
        Write-Host "Registry key not found or inaccessible; assuming modifications not applied."
    }

    # Check service status for Windows Update (wuauserv).
    try {
        $service = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
        if ($service -and $service.StartType -eq "Disabled") {
            Write-Host "Service check: 'wuauserv' is disabled."
            $alreadyModified = $true
        }
    }
    catch {
        Write-Host "Service 'wuauserv' not found; skipping service check."
    }

    # Check scheduled tasks as a soft indicator.
    try {
        # Check for any tasks under the InstallService path that are disabled.
        $tasks = Get-ScheduledTask -TaskPath "\Microsoft\Windows\InstallService\" -ErrorAction SilentlyContinue
        if ($tasks) {
            $disabledCount = ($tasks | Where-Object { $_.State -eq "Disabled" }).Count
            if ($disabledCount -gt 0) {
                Write-Host "Scheduled Tasks check: Some tasks under \Microsoft\Windows\InstallService are disabled."
                $alreadyModified = $true
            }
        }
    }
    catch {
        Write-Host "Scheduled tasks check failed; assuming modifications not applied."
    }

    if ($alreadyModified) {
        Write-Host "It appears that the system modifications have already been applied."
        $response = Read-Host "Do you want to continue anyway? (Y/N)"
        if ($response -notin @("Y","y")) {
            Write-Host "Exiting script as modifications appear to be in place."
            exit
        }
    }
    else {
        Write-Host "Idempotency check passed: No modifications detected."
    }
} # End Check-PreviousRun

#===============================================================================
# Module 5: Disclaimer and Warning
#===============================================================================
# This function displays two fullscreen prompts:
#   1. A detailed overview of the script's functionality and the important risks.
#      This includes warnings about system instability, potential data loss, and 
#      irreversible system modifications.
#   2. A legal disclaimer that states:
#      - The author is not responsible for any damage, misuse, or modifications.
#      - The user assumes full responsibility for using or altering the script.
#      - The script is licensed under the Mozilla Public License (MPL).
#
# The user must explicitly confirm by entering "Y" to proceed. Otherwise, the script exits.
function Show-Disclaimer {
    # Define the temporary file path for the combined notices.
    $tempNoticePath = Join-Path $env:TEMP "TempNotices.ps1"
    
    # Build the combined notice content using a single-quoted here-string.
    $noticeContent = @'
Clear-Host
# Overview Section
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "              Windows Update Control Script Overview      " -ForegroundColor Cyan
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will perform the following actions:" -ForegroundColor White
Write-Host "  * Disable Windows Update by stopping and disabling update services." -ForegroundColor White
Write-Host "  * Rename critical system DLLs to prevent Windows Update from functioning." -ForegroundColor White
Write-Host "  * Modify registry settings to block automatic updates." -ForegroundColor White
Write-Host "  * Delete the Windows Update download cache (SoftwareDistribution folder)." -ForegroundColor White
Write-Host "  * Disable scheduled tasks related to Windows Update." -ForegroundColor White
Write-Host ""
Write-Host "IMPORTANT RISKS:" -ForegroundColor Red
Write-Host "  - The script modifies protected system settings and files. Incorrect use" -ForegroundColor Red
Write-Host "    may render your system unstable or unbootable." -ForegroundColor Red
Write-Host "  - Changes made by this script may be irreversible without a system restore." -ForegroundColor Red
Write-Host "  - The script is intended solely for disabling/enabling Windows Update; any" -ForegroundColor Red
Write-Host "    modifications beyond its intended purpose are made at your own risk." -ForegroundColor Red
Write-Host "  - This script will make Windows Update UI within the main settings page inaccessible." -ForegroundColor Red
Write-Host "  - Since Windows Update will be fully disabled, your PC will no longer be receiving any Windows updates," -ForegroundColor Red
Write-Host "    until the modifications are reversed and Windows Update services are re-enabled again." -ForegroundColor Red
Write-Host "  - Without updates, your PC will become vulnerable to security exploits in the long-term." -ForegroundColor Red
Write-Host ""
Write-Host "If you consented into doing so, a system restore point has been created prior to making any modifications." -ForegroundColor White
Write-Host "Please also ensure that you have backed up any critical data before proceeding." -ForegroundColor White
Write-Host ""
Write-Host "Press any key to continue to the legal disclaimer..." -ForegroundColor Green

$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Clear-Host

# Legal Disclaimer Section
Write-Host "------------------------------------------------------------" -ForegroundColor Yellow
Write-Host "  DISCLAIMER  " -ForegroundColor Yellow
Write-Host "------------------------------------------------------------" -ForegroundColor Yellow
Write-Host ""
Write-Host "WARNING:" -ForegroundColor Red
Write-Host "  This script takes a more agressive approach in disabling Windows Update, making some modifications to the Windows OS, including" -ForegroundColor White
Write-Host "  renaming a couple of core files (a couple of Windows Update related DLLs), and changes to system services, registry settings, and scheduled tasks." -ForegroundColor White
Write-Host ""
Write-Host "  Use this script at your own risk. The author(s) are not responsible" -ForegroundColor White
Write-Host "  for any damage, data loss, or system instability that may result from" -ForegroundColor White
Write-Host "  using or modifying this script." -ForegroundColor White
Write-Host ""
Write-Host "  By running this script, you acknowledge that you fully understand the risks" -ForegroundColor White
Write-Host "  involved and agree to hold the author(s) harmless for any consequences." -ForegroundColor White
Write-Host "  Furthermore, any modifications or misuse of this script is solely your" -ForegroundColor White
Write-Host "  responsibility."
Write-Host ""
Write-Host "  YOU HAVE BEEN WARNED!!!" -ForegroundColor White
Write-Host ""
Write-Host "LICENSE NOTICE:" -ForegroundColor Magenta
Write-Host "  This script is licensed under the Mozilla Public License (MPL)." -ForegroundColor White
Write-Host "  You may use, modify, and distribute this script under the terms of the MPL." -ForegroundColor White
Write-Host ""
Write-Host "If you encounter any issues, please report them or submit a pull request on" -ForegroundColor White
Write-Host "the script's GitHub repository."
Write-Host ""
$response = Read-Host "Do you agree to continue? (Y/N)"
if ($response -notin @("Y","y")) {
    Write-Host "User did not agree. Exiting script..."
    exit 1
}
Pause
exit 0
'@
    
    # Write the notice content to the temporary file.
    $noticeContent | Out-File -FilePath $tempNoticePath -Encoding UTF8
    
    # Launch a new PowerShell window to run the temporary notice script.
    try {
        $proc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$tempNoticePath`"" -Wait -PassThru
        # If the external session exits with a nonzero exit code, then exit the main script.
        if ($proc.ExitCode -ne 0) {
            exit 1
        }
    }
    catch {
        Write-Host "Failed to open the separate notice session: $_" -ForegroundColor Red
        exit 1
    }
    
    # Remove the temporary file after the session closes.
    Remove-Item -Path $tempNoticePath -Force -ErrorAction SilentlyContinue
}

#===============================================================================
# Module 6: Windows Defender Check and Disable
#===============================================================================
# This module verifies that the following Windows Defender protections are disabled:
#   - DisableBehaviorMonitoring
#   - DisableIOAVProtection
#   - DisableScriptScanning
#
# Although it checks only these three properties via Get-MpPreference, the user is
# instructed to ensure that all five toggles in the Windows Defender Virus and Threat
# Protection settings page are turned off. The module provides reassurance that the script
# is not malicious and only disables Windows Update and related components.
#
# The user is prompted with a Y/N confirmation. If the user confirms by entering "Y",
# the module attempts to open the Defender settings page and then asks for manual confirmation.
# If the required Defender settings are not disabled, the script exits.
function Defender-CheckNDisable {
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop
    }
    catch {
        Write-Host "Unable to retrieve Windows Defender preferences. Exiting..." -ForegroundColor Red
        exit
    }
    
    # Helper function: If a property is null or empty, assume the toggle is disabled.
    function IsDisabled($prop) {
        if ([string]::IsNullOrEmpty($prop)) {
            return $true
        }
        else {
            return ($prop -eq $true)
        }
    }
    
    $disabledBehavior = IsDisabled($mpPref.DisableBehaviorMonitoring)
    $disabledIOAV     = IsDisabled($mpPref.DisableIOAVProtection)
    $disabledScript   = IsDisabled($mpPref.DisableScriptScanning)
    
    $allDisabled = ($disabledBehavior -and $disabledIOAV -and $disabledScript)
    
    if (-not $allDisabled) {
        Write-Host "Please ensure that all five toggles in the Windows Defender Virus and Threat Protection settings page are turned off." -ForegroundColor Yellow
        Write-Host "This is necessary for the script to modify system files effectively." -ForegroundColor Yellow
        Write-Host "Don't worry, this script is not malicious and will only disable Windows Update and related components." -ForegroundColor Yellow
        Write-Host "You can re-enable these settings once the script is complete." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Would you like to continue? (Y/N)" -ForegroundColor Green
        $response = Read-Host
        if ($response -notin @("Y", "y")) {
            Write-Host "User did not confirm. Exiting..." -ForegroundColor Red
            exit
        }
        else {
            try {
                # Attempt to open Defender settings (Virus & Threat Protection page)
                Start-Process "windowsdefender://threatsettings"
            }
            catch {
                Write-Host "Unable to automatically open Defender settings. Please open Defender manually." -ForegroundColor Red
            }
            Write-Host ""
            Write-Host "Once you have disabled all five toggles, please confirm by entering Y (Yes) to continue." -ForegroundColor Green
            $manualConfirm = Read-Host "Are all Defender settings now disabled? (Y/N)"
            if ($manualConfirm -notin @("Y", "y")) {
                Write-Host "Required Defender settings are still not disabled. Exiting..." -ForegroundColor Red
                exit
            }
            else {
                Write-Host "All required Defender protections are now disabled (per user confirmation)." -ForegroundColor Green
            }
        }
    }
    else {
        Write-Host "All required Defender protections are disabled." -ForegroundColor Green
    }
} # End Defender-CheckNDisable

#===============================================================================
# Module 7: Dedicated PsExec Download Script Generation
#===============================================================================
# This function generates a dedicated PowerShell script named "DownloadPsExec.ps1"
# in the specified destination folder. This script encapsulates robust logic to
# download PsExec.exe using three different methods (with 3 attempts each, 9 total)
# from a centralized URL (defined in the main script). It accepts an "action" parameter:
#
#   - If Action is "download" (default), the script checks whether PsExec.exe already
#     exists in the current directory; if not, it attempts to download it.
#
#   - If Action is "cleanup", the script deletes PsExec.exe from the current directory.
#
# This approach centralizes the PsExec download logic so that both permanent batch files
# can simply call this dedicated script to ensure PsExec.exe is available and later
# clean it up. The URL is defined only once in the main script and is interpolated here.
#
# Usage (from the permanent batch files):
#   To download PsExec.exe:
#       powershell -NoProfile -ExecutionPolicy Bypass -File "DownloadPsExec.ps1" download
#
#   To clean up (delete) PsExec.exe after use:
#       powershell -NoProfile -ExecutionPolicy Bypass -File "DownloadPsExec.ps1" cleanup
#===============================================================================

function Generate-PsExecDownloadScript {
    param(
        [string]$DestinationFolder
    )
    
    # Ensure the destination folder exists.
    if (-not (Test-Path $DestinationFolder)) {
        try {
            New-Item -ItemType Directory -Path $DestinationFolder -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Host "Error creating destination folder: $($DestinationFolder). Exiting..." -ForegroundColor Red
            exit 1
        }
    }
    
    # Define the path for the dedicated script.
    $scriptPath = Join-Path $DestinationFolder "DownloadPsExec.ps1"
    
    # Create the script content.
    $scriptContent = @"
<#
.SYNOPSIS
    Dedicated PsExec Download and Cleanup Script.
.DESCRIPTION
    This script downloads PsExec.exe from the centralized URL using a robust
    multi-method approach (3 methods with 3 attempts each) if the 'download' action
    is specified. If the 'cleanup' action is specified, it deletes the downloaded
    PsExec.exe from the current directory.
.PARAMETER Action
    Specify 'download' to download PsExec.exe (default) or 'cleanup' to delete it.
.NOTES
    The centralized PsExec download URL is passed via the global environment variable
    'PsExecUrl' defined in the main script.
#>

param(
    [string]$Action = "download"
)

$Destination = "PsExec.exe"
$Url = "https://github.com/DTLegit/FullWinUpdate-Disabler/raw/refs/heads/main/PsExec.exe"

function Download-PsExec {
    param(
        [string]$Url,
        [string]$Destination
    )
    
    $Methods = 1,2,3
    foreach ($Method in $Methods) {
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            Write-Host "Downloading PsExec.exe: Method $Method, Attempt $attempt..."
            try {
                switch ($Method) {
                    1 { Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop }
                    2 { Start-BitsTransfer -Source $Url -Destination $Destination -ErrorAction Stop }
                    3 { 
                        $webClient = New-Object System.Net.WebClient
                        $webClient.DownloadFile($Url, $Destination)
                    }
                }
                if (Test-Path $Destination) {
                    Write-Host "PsExec.exe downloaded successfully using Method $Method on Attempt $attempt."
                    return $true
                }
            }
            catch {
                Write-Host "Method $Method, Attempt $attempt failed: $_"
            }
        }
    }
    return $false
}

if ($Action -eq "download") {
    if (Test-Path $Destination) {
        Write-Host "PsExec.exe already exists in the current directory."
        exit 0
    }
    else {
        $downloadSuccessful = Download-PsExec -Url $Url -Destination $Destination
        if (-not $downloadSuccessful) {
            Write-Host "Failed to download PsExec.exe after all attempts. Exiting with error code 1."
            exit 1
        }
        else {
            exit 0
        }
    }
}
elseif ($Action -eq "cleanup") {
    if (Test-Path $Destination) {
        Remove-Item -Path $Destination -Force -ErrorAction SilentlyContinue
        Write-Host "PsExec.exe has been deleted from the current directory."
    }
    exit 0
}
else {
    Write-Host "Invalid action specified. Use 'download' or 'cleanup'."
    exit 1
}

"@

    # Write the content to the destination file.
    $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
    Write-Host "Dedicated PsExec download script generated at:" -ForegroundColor Cyan
    Write-Host $scriptPath -ForegroundColor White

# Example usage:
# To generate the script in the permanent folder (e.g., "WUControlScripts" on the Desktop),
# call the function like:
# Generate-PsExecDownloadScript -DestinationFolder (Join-Path $global:OriginalDesktop "WUControlScripts")

} # End Generate-PsExecDownloadScript

#===============================================================================
# Module 8: Temporary Execution Phase (SYSTEM Context for Disabler Batch File)
#===============================================================================
# This module performs the following steps:
#   1. Creates a temporary directory for storing PsExec.exe and the temporary disabler batch file.
#   2. Downloads PsExec.exe into the temporary directory using a robust multi-method approach 
#      (3 methods, 3 attempts each, for a total of 9 attempts).
#   3. Reconstructs the original update disabler batch file (minimally modified) and saves it as
#      "TempDisableUpdates.bat" in the temporary directory.
#   4. Executes the temporary batch file under SYSTEM privileges via PsExec (using "cmd /k" with a pause)
#      so that the CMD window remains open for inspection.
#   5. Cleans up (deletes) the temporary directory and all its contents after execution.
#
# Note: This module only handles the SYSTEM-level execution of the disabler batch file.
function Run-TemporaryDisablerPhase {
    Write-Host "Starting Temporary Execution Phase..." -ForegroundColor Cyan

    # Step 1: Create a temporary directory.
    $tempDir = Join-Path $env:TEMP ("DisableWU_" + [guid]::NewGuid().ToString())
    try {
        New-Item -ItemType Directory -Path $tempDir -ErrorAction Stop | Out-Null
        Write-Host "Temporary directory created at: $tempDir" -ForegroundColor White
    }
    catch {
        Write-Host "Failed to create temporary directory. Exiting..." -ForegroundColor Red
        exit 1
    }

    # Step 2: Download PsExec.exe into the temporary directory.
    $psexecPath = Join-Path $tempDir "PsExec.exe"
    
    function Download-PsExecToFolder {
        param(
            [string]$Url,
            [string]$Destination
        )
        $methods = 1, 2, 3
        foreach ($method in $methods) {
            for ($attempt = 1; $attempt -le 3; $attempt++) {
                Write-Host "Downloading PsExec.exe: Method $method, Attempt $attempt..."
                try {
                    switch ($method) {
                        1 { Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop }
                        2 { Start-BitsTransfer -Source $Url -Destination $Destination -ErrorAction Stop }
                        3 { 
                            $wc = New-Object System.Net.WebClient
                            $wc.DownloadFile($Url, $Destination)
                        }
                    }
                    if (Test-Path $Destination) {
                        Write-Host "PsExec.exe downloaded successfully (Method $method, Attempt $attempt)." -ForegroundColor Green
                        return $true
                    }
                }
                catch {
                    Write-Host "Method $method, Attempt $attempt failed: $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
        return $false
    }

    if (-not (Download-PsExecToFolder -Url $global:PsExecUrl -Destination $psexecPath)) {
        Write-Host "Failed to download PsExec.exe after all attempts. Exiting..." -ForegroundColor Red
        exit 1
    }

    # Step 3: Reconstruct the temporary disabler batch file.
    $tempBatchFile = Join-Path $tempDir "TempDisableUpdates.bat"
    $batchContent = @"
:: Author: tsgrgo
:: Completely disable Windows Update
:: PsExec is required to get system privileges - it should be in this directory

if not "%1"=="admin" (powershell start -verb runas '%0' admin & exit /b)
if not "%2"=="system" (powershell . '%~dp0\PsExec.exe' /accepteula -i -s -d '%0' admin system & exit /b)

:: Disable update related services
for %%i in (wuauserv, UsoSvc, uhssvc, WaaSMedicSvc) do (
    net stop %%i
    sc config %%i start= disabled
    sc failure %%i reset= 0 actions= ""
)

:: Brute force rename services
for %%i in (WaaSMedicSvc, wuaueng) do (
    takeown /f C:\Windows\System32\%%i.dll && icacls C:\Windows\System32\%%i.dll /grant *S-1-1-0:F
    rename C:\Windows\System32\%%i.dll %%i_BAK.dll
    icacls C:\Windows\System32\%%i_BAK.dll /setowner "NT SERVICE\TrustedInstaller" && icacls C:\Windows\System32\%%i_BAK.dll /remove *S-1-1-0
)

:: Update registry
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v FailureActions /t REG_BINARY /d 000000000000000000000000030000001400000000000000c0d4010000000000e09304000000000000000000 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f

:: Delete downloaded update files
erase /f /s /q c:\windows\softwaredistribution\*.* && rmdir /s /q c:\windows\softwaredistribution

:: Disable all update related scheduled tasks
powershell -command "Get-ScheduledTask -TaskPath '\Microsoft\Windows\InstallService\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateOrchestrator\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateAssistant\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WaaSMedic\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\WindowsUpdate\*' | Disable-ScheduledTask"

echo Finished
pause
"@
    $batchContent | Out-File -FilePath $tempBatchFile -Encoding ASCII
    Write-Host "Temporary disabler batch file created at: $tempBatchFile" -ForegroundColor White

    # Step 4: Execute the temporary batch file under SYSTEM using PsExec.
    $psexecArgs = "/accepteula -i -s cmd /k `"$tempBatchFile`""
    Write-Host "Launching temporary disabler batch file with PsExec..." -ForegroundColor Cyan
    try {
        Start-Process -FilePath $psexecPath -ArgumentList $psexecArgs -NoNewWindow -Wait
    }
    catch {
        Write-Host "Error launching temporary batch file via PsExec: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    # Step 5: Clean up the temporary directory.
    try {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Temporary directory cleaned up." -ForegroundColor Green
    }
    catch {
        Write-Host "Error cleaning up temporary directory: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} # End Run-TemporaryDisablerPhase

#===============================================================================
# Module 9: Permanent Batch Files Creation and Shortcut Setup
#===============================================================================
# This module performs the following actions:
#   1. Determines and creates a dedicated folder (named "WUControlScripts") 
#      on the original user's Desktop.
#   2. Reconstructs two permanent batch files:
#         a) "disable updates.bat" – which disables Windows Update and related components.
#         b) "use update services.bat" – which re-enables Windows Update partially so that 
#            applications relying on Windows Update can function.
#      Both batch files include:
#         - A check for PsExec.exe in the current directory.
#         - If not found, a call to a dedicated PsExec download script ("DownloadPsExec.ps1")
#           with the "download" action.
#         - Their main logic (identical to the original batch file content).
#         - A cleanup call to "DownloadPsExec.ps1" with the "cleanup" action to delete PsExec.exe.
#         - The PsExec download URL is referenced via a global variable defined in Module 7.
#   3. Saves these batch files to the dedicated folder.
#   4. Creates desktop shortcuts to the batch files using the original user's Desktop path.
#===============================================================================
function PermBatchCreation {

    # Define the permanent folder path using the global OriginalDesktop variable (from Module 7).
    $permanentFolder = Join-Path $global:OriginalDesktop "WUControlScripts"

    # Create the permanent folder if it doesn't exist.
    if (-not (Test-Path $permanentFolder)) {
        try {
            New-Item -ItemType Directory -Path $permanentFolder -ErrorAction Stop | Out-Null
            Write-Host "Permanent folder created at: $permanentFolder" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to create permanent folder at $permanentFolder. Exiting..." -ForegroundColor Red
            exit 1
        }
    }
    else {
         Write-Host "Permanent folder exists at: $permanentFolder" -ForegroundColor Green
    }

    # Define paths for the two permanent batch files.
    $disableBatchPath = Join-Path $permanentFolder "disable updates.bat"
    $reEnableBatchPath = Join-Path $permanentFolder "use update services.bat"

    # Define the content for "disable updates.bat".
    $disableBatchContent = @"
@echo off
REM -----------------------------------------------------------------------------
REM Permanent Update Disabler Batch File: disable updates.bat
REM This file disables Windows Update and related components.
REM It checks for PsExec.exe in the current directory.
REM If PsExec.exe is not found, it calls the dedicated download script to download it.
REM After performing its tasks, it calls the download script to clean up (delete PsExec.exe).
REM -----------------------------------------------------------------------------

cd /d "%~dp0"

if not exist "%~dp0\DownloadPsExec.ps1" (
    echo DownloadPsExec.ps1 was not found in %~dp0.
    pause
    exit /b 1
)

REM Check for PsExec.exe in the current directory.
if not exist "%~dp0\PsExec.exe" (
    echo PsExec.exe not found. Attempting to download...
    powershell -NoProfile -ExecutionPolicy Bypass -File "DownloadPsExec.ps1" download
    if errorlevel 1 (
        echo Failed to download PsExec.exe. Exiting...
        exit /b 1
    )
)

REM Ensure administrator and SYSTEM privileges.
if not "%1"=="admin" (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList 'admin'" & exit /b
)
if not "%2"=="system" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "& { & '%~dp0\PsExec.exe' /accepteula -i -s -d '%~f0' admin system }" & exit /b
)

REM Disable update related services.
for %%i in (wuauserv, UsoSvc, uhssvc, WaaSMedicSvc) do (
    net stop %%i
    sc config %%i start= disabled
    sc failure %%i reset= 0 actions= ""
)

REM Brute force rename services.
for %%i in (WaaSMedicSvc, wuaueng) do (
    takeown /f C:\Windows\System32\%%i.dll && icacls C:\Windows\System32\%%i.dll /grant *S-1-1-0:F
    rename C:\Windows\System32\%%i.dll %%i_BAK.dll
    icacls C:\Windows\System32\%%i_BAK.dll /setowner "NT SERVICE\TrustedInstaller" && icacls C:\Windows\System32\%%i_BAK.dll /remove *S-1-1-0
)

REM Update registry settings.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v FailureActions /t REG_BINARY /d 000000000000000000000000030000001400000000000000c0d4010000000000e09304000000000000000000 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f

REM Delete downloaded update files.
erase /f /s /q c:\windows\softwaredistribution\*.* && rmdir /s /q c:\windows\softwaredistribution

REM Disable all update related scheduled tasks.
powershell -command "Get-ScheduledTask -TaskPath '\Microsoft\Windows\InstallService\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateOrchestrator\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateAssistant\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WaaSMedic\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\WindowsUpdate\*' | Disable-ScheduledTask"

echo Finished
pause

REM Clean up: Delete PsExec.exe using the dedicated download script (cleanup action).
cd /d "%~dp0"
taskkill /IM PsExec.exe /F >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0\DownloadPsExec.ps1" cleanup
"@

    # Write the "disable updates.bat" content.
    $disableBatchContent | Out-File -FilePath $disableBatchPath -Encoding ASCII
    Write-Host "Permanent batch file 'disable updates.bat' created at: $disableBatchPath" -ForegroundColor Green

    # Define the content for "use update services.bat".
    $reEnableBatchContent = @"
@echo off
REM -----------------------------------------------------------------------------
REM Permanent Update Re-Enabler Batch File: use update services.bat
REM This file re-enables Windows Update service for applications that rely on it.
REM It checks for PsExec.exe in the current directory.
REM If PsExec.exe is not found, it calls the dedicated download script to download it.
REM After performing its tasks, it calls the download script to clean up (delete PsExec.exe).
REM -----------------------------------------------------------------------------

cd /d "%~dp0"

if not exist "%~dp0\DownloadPsExec.ps1" (
    echo DownloadPsExec.ps1 was not found in %~dp0.
    pause
    exit /b 1
)

REM Check for PsExec.exe in the current directory.
if not exist "%~dp0\PsExec.exe" (
    echo PsExec.exe not found. Attempting to download...
    powershell -NoProfile -ExecutionPolicy Bypass -File "DownloadPsExec.ps1" download
    if errorlevel 1 (
        echo Failed to download PsExec.exe. Exiting...
        exit /b 1
    )
)

REM Ensure administrator and SYSTEM privileges.
if not "%1"=="admin" (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList 'admin'" & exit /b
)
if not "%2"=="system" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "& { & '%~dp0\PsExec.exe' /accepteula -i -s -d '%~f0' admin system }" & exit /b
)

REM Restore renamed services.
for %%i in (wuaueng) do (
    takeown /f C:\Windows\System32\%%i_BAK.dll && icacls C:\Windows\System32\%%i_BAK.dll /grant *S-1-1-0:F
    rename C:\Windows\System32\%%i_BAK.dll %%i.dll
    icacls C:\Windows\System32\%%i.dll /setowner "NT SERVICE\TrustedInstaller" && icacls C:\Windows\System32\%%i.dll /remove *S-1-1-0
)

REM Change service configuration to re-enable Windows Update.
sc config wuauserv start= auto

echo.
echo Enabled Windows Update Service
echo You can now use software that relies on the Windows Update Service.
echo When finished, you can run the disabler again.
echo More info in README
echo.
pause

REM Clean up: Delete PsExec.exe using the dedicated download script (cleanup action).
cd /d "%~dp0"
taskkill /IM PsExec.exe /F >nul 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0\DownloadPsExec.ps1" cleanup
"@

    # Write the "use update services.bat" content.
    $reEnableBatchContent | Out-File -FilePath $reEnableBatchPath -Encoding ASCII
    Write-Host "Permanent batch file 'use update services.bat' created at: $reEnableBatchPath" -ForegroundColor Green

    #-------------------------------------------------------------------------------
    # Create Desktop Shortcuts for the Permanent Batch Files
    #-------------------------------------------------------------------------------
    function Create-Shortcut {
        param(
            [string]$TargetPath,
            [string]$ShortcutName
        )
        try {
            $WshShell = New-Object -ComObject WScript.Shell
        }
        catch {
            Write-Host "Unable to create shortcut object. Exiting..." -ForegroundColor Red
            exit 1
        }
    
        $desktopPath = $global:OriginalDesktop
        $shortcutPath = Join-Path $desktopPath "$ShortcutName.lnk"
        $shortcut = $WshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $TargetPath
        $shortcut.IconLocation = "$TargetPath,0"
        $shortcut.Save()
        Write-Host "Shortcut '$ShortcutName' created at: $shortcutPath" -ForegroundColor Green
    }

    # Create shortcuts for both batch files on the user's Desktop.
    Create-Shortcut -TargetPath $disableBatchPath -ShortcutName "Disable Windows Update"
    Create-Shortcut -TargetPath $reEnableBatchPath -ShortcutName "Use Update Services"

    Write-Host "Permanent batch files and desktop shortcuts have been successfully created in $permanentFolder." -ForegroundColor Cyan

  } # End PermBatchCreation

#===============================================================================
# Module 10: Final Cleanup
#===============================================================================
# This function searches for temporary directories created by the script (named "DisableWU_*")
# in the system's TEMP folder and removes them, ensuring that no temporary files remain.
function Final-Cleanup {
    Write-Host "Performing final cleanup of temporary files..." -ForegroundColor Cyan
    $tempPattern = Join-Path $env:TEMP "DisableWU_*"
    try {
        Get-ChildItem -Path $tempPattern -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Removed temporary directory: $($_.FullName)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Final cleanup encountered an error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} # End Final-Cleanup

#===============================================================================
# Module 11: Centralized Logging
#===============================================================================
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    
    if (-not $global:PermanentFolder) {
        $global:PermanentFolder = Join-Path $global:OriginalDesktop "WUControlScripts"
    }
    
    $logFile = Join-Path $global:PermanentFolder "WUControlScript.log"
    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Host "Error writing to log file: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} # End Write-Log

# ==================================
# Core Script Module Execution Logic
# ==================================

Write-Log "Script execution started."
Write-Host "Starting the Full Windows Update Disabler..." -ForegroundColor Cyan 
try {
    Ensure-Administrator
    if (-not (Test-InternetConnection)) { exit }
    Create-SystemRestorePoint
    Check-PreviousRun
	Write-Host "Displaying script overview and disclaimer notice..."
    Show-Disclaimer
	Write-Host "User confirmation successful. Proceeding with Defender Check..."
    Defender-CheckNDisable
    Generate-PsExecDownloadScript -DestinationFolder $global:PermanentFolder
    Write-Host "A download script for the PSExec.exe file for future uses of the saved batch files has been successfully saved!" -ForegroundColor Green
    Run-TemporaryDisablerPhase
    PermBatchCreation
    Final-Cleanup
    Write-Log "Script execution completed." "INFO"
}

catch {
    Write-Log "An error occurred: $_" "ERROR"
    exit 1
}
finally {
    Stop-Transcript
}

Write-Host "Script execution completed. Press any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# End of FullWinUpdate-Disabler

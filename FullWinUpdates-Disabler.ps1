<#
.SYNOPSIS
  Fully disables Windows Update using SYSTEM privileges with robust PsExec download logic.
  Also creates two permanent batch files for later re‑enabling and re‑disabling Windows Update,
  complete with embedded logic to download and temporarily use PsExec.exe, plus desktop shortcuts.

.DESCRIPTION
  This script:
    1. Checks for administrator rights and relaunches as admin if needed.
    2. Checks for SYSTEM privileges. If not running as SYSTEM, it downloads PsExec.exe using a robust
       three‑method (three tries each) download routine into a temporary folder and relaunches via PsExec.
    3. Creates a temporary child PowerShell script (with disable logic) in the temporary folder,
       launches it with SYSTEM privileges, waits for completion, then cleans up the temporary folder.
    4. Creates two permanent batch files in a permanent directory (under the user’s Documents\WUControlScripts):
         - ReEnableWU.bat (to re‑enable Windows Update)
         - ReDisableWU.bat (to re‑disable Windows Update)
       Each batch file contains embedded PowerShell code that downloads PsExec.exe (using the robust
       download routine with the URL defined once in `$psexecUrl`) if it isn’t found in its folder,
       and deletes PsExec.exe afterward.
    5. Creates desktop shortcuts to both permanent batch files.
.NOTES
  Use with extreme caution. Disabling Windows Update can make your system vulnerable.
  Tested on Windows 11 Pro.
#>

#----------------------------
# Configurable parameters
#----------------------------
$psexecUrl = "https://download.sysinternals.com/files/PsExec.exe"
$permanentDir = Join-Path $env:USERPROFILE "Documents\WUControlScripts"

#----------------------------
# Function: Download-PsExec
# Attempts to download PsExec.exe using 3 methods (each with 3 tries).
# Returns $true if download succeeds; otherwise $false.
#----------------------------
function Download-PsExec {
    param(
        [string]$Url,
        [string]$Destination
    )
    $methods = 1,2,3
    foreach ($method in $methods) {
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                Write-Host "Downloading PsExec.exe: method $method, attempt $attempt..."
                switch ($method) {
                    1 { Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop }
                    2 { Start-BitsTransfer -Source $Url -Destination $Destination -ErrorAction Stop }
                    3 { $wc = New-Object System.Net.WebClient; $wc.DownloadFile($Url, $Destination) }
                }
                if (Test-Path $Destination) {
                    Write-Host "PsExec.exe downloaded successfully via method $method on try $attempt."
                    return $true
                }
            }
            catch {
                Write-Warning "Method $method, attempt $attempt failed: $($_.Exception.Message)"
                Start-Sleep -Seconds 2
            }
        }
    }
    return $false
}

#----------------------------
# Privilege check & relaunch as needed
#----------------------------
function Ensure-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Not running as Administrator. Relaunching as admin..."
        Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`" admin" -Verb RunAs
        exit
    }
}
Ensure-Administrator

# Ensure our custom argument "admin" is present.
if ($args.Count -lt 1 -or $args[0] -ne "admin") {
    Write-Host "Relaunching with admin flag..."
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`" admin" -Verb RunAs
    exit
}

# Check for SYSTEM argument; if not, download PsExec.exe and relaunch via PsExec.
if ($args.Count -lt 2 -or $args[1] -ne "system") {
    $tempDir = Join-Path $env:TEMP ("DisableWU_" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    $psexecPath = Join-Path $tempDir "PsExec.exe"
    Write-Host "Downloading PsExec.exe into temporary folder: $tempDir"
    if (-not (Download-PsExec -Url $psexecUrl -Destination $psexecPath)) {
        Write-Error "Failed to download PsExec.exe after multiple attempts. Exiting."
        exit
    }
    Write-Host "Relaunching as SYSTEM via PsExec..."
    & "$psexecPath" /accepteula -i -s -d powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`" admin system"
    exit
}

#----------------------------
# Now running as SYSTEM
#----------------------------
Write-Host "Running as SYSTEM. Proceeding with Windows Update disable operations..."

# Ensure we have a temporary directory (if not already set)
if (-not $tempDir) {
    $tempDir = Join-Path $env:TEMP ("DisableWU_" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir | Out-Null
}

#----------------------------
# Create Child Disable Script (temporary)
#----------------------------
$childScriptPath = Join-Path $tempDir "DisableWU_Child.ps1"
$childScriptContent = @'
# Child Disable Script (runs as SYSTEM)
# Disable update related services
foreach ($svc in @("wuauserv", "UsoSvc", "uhssvc", "WaaSMedicSvc")) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    sc.exe config $svc start= disabled
    sc.exe failure $svc reset= 0 actions= ""
}

# Brute force rename services (rename DLLs)
foreach ($dll in @("WaaSMedicSvc", "wuaueng")) {
    $file = "C:\Windows\System32\$dll.dll"
    $bak = "C:\Windows\System32\${dll}_BAK.dll"
    takeown /f $file | Out-Null
    icacls $file /grant *S-1-1-0:F | Out-Null
    Rename-Item -Path $file -NewName "${dll}_BAK.dll" -Force
    icacls $bak /setowner "NT SERVICE\TrustedInstaller" | Out-Null
    icacls $bak /remove *S-1-1-0 | Out-Null
}

# Update registry settings
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v Start /t REG_DWORD /d 4 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v FailureActions /t REG_BINARY /d "000000000000000000000000030000001400000000000000c0d4010000000000e09304000000000000000000" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f

# Delete downloaded update files
Remove-Item -Path "C:\Windows\SoftwareDistribution\*.*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\SoftwareDistribution" -Force -Recurse -ErrorAction SilentlyContinue

# Disable update-related scheduled tasks
powershell -command "Get-ScheduledTask -TaskPath '\Microsoft\Windows\InstallService\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateOrchestrator\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateAssistant\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WaaSMedic\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\WindowsUpdate\*' | Disable-ScheduledTask"

Write-Host "Finished"
Pause
'@
$childScriptContent | Out-File -FilePath $childScriptPath -Encoding UTF8

# Launch the child disable script as a separate process
Write-Host "Launching child disable script..."
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File `"$childScriptPath`" admin system" -Wait -Verb RunAs

#----------------------------
# Cleanup temporary directory
#----------------------------
Write-Host "Child script completed. Cleaning up temporary files..."
Remove-Item -Path $tempDir -Recurse -Force

#----------------------------
# Create Permanent Batch Files for Re-Enable and Re-Disable Functions
# (These are saved in a permanent directory for later use.)
#----------------------------
if (-not (Test-Path $permanentDir)) {
    New-Item -Path $permanentDir -ItemType Directory | Out-Null
}

# Build the download snippet with the URL interpolated from $psexecUrl.
$downloadSnippet = @"
:: Check if PsExec.exe exists; if not, download it.
if not exist "%~dp0\PsExec.exe" (
    echo PsExec.exe not found. Downloading...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "& {
        \$url = '$psexecUrl';
        \$dest = '%~dp0\PsExec.exe';
        \$success = \$false;
        foreach (\$method in 1,2,3) {
            for (\$i=1; \$i -le 3; \$i++) {
                try {
                    if (\$method -eq 1) { Invoke-WebRequest -Uri \$url -OutFile \$dest -UseBasicParsing -ErrorAction Stop }
                    elseif (\$method -eq 2) { Start-BitsTransfer -Source \$url -Destination \$dest -ErrorAction Stop }
                    else { \$wc = New-Object System.Net.WebClient; \$wc.DownloadFile(\$url, \$dest) }
                    if (Test-Path \$dest) { \$success = \$true; break }
                } catch { Start-Sleep -Seconds 2 }
            }
            if (\$success) { break }
        }
        if (-not \$success) { exit 1 } else { exit 0 }
    }"
    if errorlevel 1 (
        echo Failed to download PsExec.exe.
        exit /b 1
    )
)
"@

# Append deletion of PsExec.exe after main logic.
$deletePsExec = @"
:: Delete the temporary PsExec.exe file after execution.
if exist "%~dp0\PsExec.exe" (
    del /f /q "%~dp0\PsExec.exe"
)
"@

# Content for the Re-Enable batch file
$reEnableBatContent = @"
:: Author: tsgrgo
:: This batch file re-enables Windows Update.
$downloadSnippet
@echo off
if not "%1"=="admin" (powershell start -verb runas "%~f0" admin & exit /b)
if not "%2"=="system" (powershell . "%~dp0\PsExec.exe" /accepteula -i -s -d "%~f0" admin system & exit /b)

:: Restore renamed services
for %%i in (wuaueng) do (
    takeown /f C:\Windows\System32\%%i_BAK.dll && icacls C:\Windows\System32\%%i_BAK.dll /grant *S-1-1-0:F
    rename C:\Windows\System32\%%i_BAK.dll %%i.dll
    icacls C:\Windows\System32\%%i.dll /setowner "NT SERVICE\TrustedInstaller" && icacls C:\Windows\System32\%%i.dll /remove *S-1-1-0
)

:: Change service config
sc config wuauserv start= auto

echo.
echo Enabled Windows Update Service
echo You can now use software that relies on the Windows Update Service.
echo When finished, you can run the disabler again.
echo More info in README
echo.
pause

$deletePsExec
"@

# Content for the Re-Disable batch file
$reDisableBatContent = @"
:: Author: tsgrgo
:: This batch file completely disables Windows Update.
$downloadSnippet
@echo off
if not "%1"=="admin" (powershell start -verb runas "%~f0" admin & exit /b)
if not "%2"=="system" (powershell . "%~dp0\PsExec.exe" /accepteula -i -s -d "%~f0" admin system & exit /b)

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
erase /f /s /q C:\Windows\SoftwareDistribution\*.* && rmdir /s /q C:\Windows\SoftwareDistribution

:: Disable all update related scheduled tasks
powershell -command "Get-ScheduledTask -TaskPath '\Microsoft\Windows\InstallService\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateOrchestrator\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\UpdateAssistant\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WaaSMedic\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\*' | Disable-ScheduledTask; Get-ScheduledTask -TaskPath '\Microsoft\WindowsUpdate\*' | Disable-ScheduledTask"

echo Finished
pause

$deletePsExec
"@

# Write the batch files to the permanent directory.
$reEnableBatPath = Join-Path $permanentDir "ReEnableWU.bat"
$reDisableBatPath = Join-Path $permanentDir "ReDisableWU.bat"
$reEnableBatContent | Out-File -FilePath $reEnableBatPath -Encoding ASCII
$reDisableBatContent | Out-File -FilePath $reDisableBatPath -Encoding ASCII

#----------------------------
# Create Desktop Shortcuts for the Permanent Batch Files
#----------------------------
function Create-Shortcut {
    param (
        [string]$TargetPath,
        [string]$ShortcutName
    )
    $WshShell = New-Object -ComObject WScript.Shell
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktopPath "$ShortcutName.lnk"
    $shortcut = $WshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $TargetPath
    $shortcut.IconLocation = "$TargetPath,0"
    $shortcut.Save()
}

Create-Shortcut -TargetPath $reEnableBatPath -ShortcutName "ReEnable Windows Update"
Create-Shortcut -TargetPath $reDisableBatPath -ShortcutName "ReDisable Windows Update"

Write-Host "Permanent batch files and desktop shortcuts have been created in $permanentDir."
Write-Host "Operation completed successfully."

@echo off
:: This script secures and hardens Windows 10 for a CyberPatriot competition.
:: It allows you to choose whether to proceed with each step or skip to the next one.

echo Securing Windows 10...

:: Step 1: Ensure the script is run with elevated privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This script must be run as an Administrator. Please right-click and select "Run as administrator."
    exit /b
)

:: Step 2: Disable SMBv1 (older and insecure file-sharing protocol)
echo.
echo Step 2: Disable SMBv1 (older and insecure file-sharing protocol)
set /p choice="Do you want to disable SMBv1? (Y/N): "
if /i "%choice%"=="Y" (
    powershell -Command "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
    powershell -Command "Set-SmbClientConfiguration -EnableSMB1Protocol $false -Force"
    echo SMBv1 has been disabled.
) else (
    echo Skipping SMBv1 disable.
)

:: Step 3: Enable Windows Defender Antivirus (and update definitions)
echo.
echo Step 3: Enable Windows Defender Antivirus and update definitions
set /p choice="Do you want to enable Windows Defender and update definitions? (Y/N): "
if /i "%choice%"=="Y" (
    powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"
    powershell -Command "Update-MpSignature"
    echo Windows Defender has been enabled and signatures updated.
) else (
    echo Skipping Windows Defender enable.
)

:: Step 4: Disable Windows Script Host (WSH)
echo.
echo Step 4: Disable Windows Script Host (WSH) to prevent scripting-based exploits
set /p choice="Do you want to disable Windows Script Host? (Y/N): "
if /i "%choice%"=="Y" (
    reg add "HKCU\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d "0" /f
    echo Windows Script Host has been disabled.
) else (
    echo Skipping Windows Script Host disable.
)

:: Step 5: Disable Windows Defender SmartScreen
echo.
echo Step 5: Disable Windows Defender SmartScreen
set /p choice="Do you want to disable SmartScreen? (Y/N): "
if /i "%choice%"=="Y" (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
    echo SmartScreen has been disabled.
) else (
    echo Skipping SmartScreen disable.
)

:: Step 6: Enable User Account Control (UAC)
echo.
echo Step 6: Enable User Account Control (UAC)
set /p choice="Do you want to enable User Account Control (UAC)? (Y/N): "
if /i "%choice%"=="Y" (
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "1" /f
    echo User Account Control has been enabled.
) else (
    echo Skipping UAC enable.
)

:: Step 7: Disable Remote Desktop
echo.
echo Step 7: Disable Remote Desktop
set /p choice="Do you want to disable Remote Desktop? (Y/N): "
if /i "%choice%"=="Y" (
    reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
    echo Remote Desktop has been disabled.
) else (
    echo Skipping Remote Desktop disable.
)

:: Step 8: Enable Windows Firewall
echo.
echo Step 8: Enable Windows Firewall
set /p choice="Do you want to enable Windows Firewall? (Y/N): "
if /i "%choice%"=="Y" (
    netsh advfirewall set allprofiles state on
    echo Windows Firewall has been enabled.
) else (
    echo Skipping Firewall enable.
)

:: Step 9: Enable Windows Updates Service
echo.
echo Step 9: Enable Windows Updates Service
set /p choice="Do you want to enable Windows Updates? (Y/N): "
if /i "%choice%"=="Y" (
    sc config wuauserv start= auto
    net start wuauserv
    echo Windows Updates service has been enabled.
) else (
    echo Skipping Windows Updates enable.
)

:: Step 10: Disable Unnecessary Services (e.g., Remote Registry)
echo.
echo Step 10: Disable Unnecessary Services
set /p choice="Do you want to disable unnecessary services like Remote Registry? (Y/N): "
if /i "%choice%"=="Y" (
    sc config RemoteRegistry start= disabled
    sc stop RemoteRegistry
    echo Unnecessary services have been disabled.
) else (
    echo Skipping unnecessary services disable.
)

:: Step 11: Enable Audit for Logon/Logoff
echo.
echo Step 11: Enable Audit for Logon/Logoff events
set /p choice="Do you want to enable audit for logon/logoff events? (Y/N): "
if /i "%choice%"=="Y" (
    auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
    echo Audit for logon/logoff events has been enabled.
) else (
    echo Skipping audit enable.
)

:: Step 12: Disable Unnecessary Scheduled Tasks (e.g., Error Reporting)
echo.
echo Step 12: Disable Unnecessary Scheduled Tasks (e.g., Error Reporting)
set /p choice="Do you want to disable unnecessary scheduled tasks (e.g., Windows Error Reporting)? (Y/N): "
if /i "%choice%"=="Y" (
    schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\Error Reporting Service" /Disable
    echo Unnecessary scheduled tasks have been disabled.
) else (
    echo Skipping scheduled tasks disable.
)

:: Step 13: Set Auto-lock after Inactivity (15 minutes)
echo.
echo Step 13: Set Auto-lock after Inactivity (15 minutes)
set /p choice="Do you want to set auto-lock after 15 minutes of inactivity? (Y/N): "
if /i "%choice%"=="Y" (
    reg add "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d "900" /f
    reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d "1" /f
    echo Auto-lock after inactivity has been set to 15 minutes.
) else (
    echo Skipping auto-lock setup.
)

:: Step 14: Disable File and Printer Sharing
echo.
echo Step 14: Disable File and Printer Sharing
set /p choice="Do you want to disable File and Printer Sharing? (Y/N): "
if /i "%choice%"=="Y" (
    netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=no
    echo File and Printer Sharing has been disabled.
) else (
    echo Skipping file and printer sharing disable.
)

:: Step 15: Set Complex Password Policy
echo.
echo Step 15: Set Complex Password Policy
set /p choice="Do you want to set complex password policy? (Y/N): "
if /i "%choice%"=="Y" (
    net accounts /minpwlen:12
    net accounts /maxpwage:30
    net accounts /uniquepw:5
    echo Password policy has been updated.
) else (
    echo Skipping password policy setup.
)

:: Step 16: Clear Recent Files History
echo.
echo Step 16: Clear Recent Files History
set /p choice="Do you want to clear recent files history? (Y/N): "
if /i "%choice%"=="Y" (
    del /f /q "%APPDATA%\Microsoft\Windows\Recent\*"
    echo Recent files history has been cleared.
) else (
    echo Skipping recent files history clear.
)

:: Step 17: Enable Audit for Privileged Account Changes
echo.
echo Step 17: Enable Audit for Privileged Account Changes
set /p choice="Do you want to enable audit for privileged account changes? (Y/N): "
if /i "%choice%"=="Y" (
    auditpol /set /subcategory:"Account Logon/Logoff" /success:enable /failure:enable
    echo Audit for privileged account changes has been enabled.
) else (
    echo Skipping privileged account changes audit.
)

:: Step 18: Disable Cortana and Search Indexing (Optional)
echo.
echo Step 18: Disable Cortana and Search Indexing
set /p choice="Do you want to disable Cortana and search indexing? (Y/N): "
if /i "%choice%"=="Y" (
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "

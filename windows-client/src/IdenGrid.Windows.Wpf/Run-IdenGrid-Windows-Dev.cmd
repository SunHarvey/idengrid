@echo off
chcp 65001 >nul
set "EXE=%USERPROFILE%\IdenGrid-Dev\artifacts\IdenGrid.Windows.Dev\IdenGrid.Windows.exe"
set "IDENGRID_AGENT_PATH=%USERPROFILE%\IdenGrid-Dev\artifacts\IdenGrid.Windows.Dev\Components\idengrid-agent.exe"
set "IDENGRID_CHROMIUM_PATH=%USERPROFILE%\IdenGrid-Dev\artifacts\IdenGrid.Windows.Dev\Components\Browser\chrome.exe"
if not exist "%EXE%" (
  echo IdenGrid Windows development build is missing.
  pause
  exit /b 1
)
start "" "%EXE%"
timeout /t 10 /nobreak >nul
tasklist /fi "imagename eq IdenGrid.Windows.exe" | find /i "IdenGrid.Windows.exe" >nul
if errorlevel 1 (
  echo IdenGrid exited or crashed during startup.
  pause
  exit /b 1
)

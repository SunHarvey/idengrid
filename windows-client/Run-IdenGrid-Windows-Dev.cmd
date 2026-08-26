@echo off
chcp 65001 >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Administrator\IdenGrid-Dev\Start-IdenGrid-Windows-Dev.ps1"
if errorlevel 1 (
  echo.
  echo Press any key to close this window.
  pause >nul
)

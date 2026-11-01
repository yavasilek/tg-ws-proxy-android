@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\build-native.ps1"
exit /b %errorlevel%

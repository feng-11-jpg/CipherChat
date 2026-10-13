@echo off
rem CipherChat client launcher: builds if needed, starts a local server when port 5050
rem is free, then opens the client window. Change the port in scripts\launch-client.ps1.
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\launch-client.ps1"

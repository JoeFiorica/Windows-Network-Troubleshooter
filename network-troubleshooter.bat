@echo off
setlocal
rem Process-scoped policy only. No system policy or configuration is changed.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0network-troubleshooter.ps1" %*
exit /b %errorlevel%

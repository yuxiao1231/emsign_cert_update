@echo off
setlocal
cd /d "%~dp0"
title eMudhra / emSign Certificate Vulnerability One-Click Fix

:: Launch PowerShell Remediation Engine with UAC auto-elevation
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Start-Process powershell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"\"%~dp0scripts\fix_windows.ps1\"\"' -Verb RunAs } else { & \"%~dp0scripts\fix_windows.ps1\" } }"

if %errorlevel% neq 0 (
    echo.
    echo [!] Administrator privilege was denied or process was cancelled.
    pause
)
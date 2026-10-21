@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
title eMudhra / emSign Intermediate CA Vulnerability One-Click Fix

echo ===============================================================================
echo   eMudhra / emSign Intermediate CA (1-Byte Entropy Flaw) One-Click Fix
echo   Targeting Mozilla Bug 2083449 | Windows CryptoAPI & Python Cert Remediation
echo ===============================================================================
echo.

:: 1. Check for Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privileges required to update system certificate store.
    echo [*] Requesting UAC elevation...
    powershell -Command "Start-Process cmd.exe -ArgumentList " /c "\%~f0\ -Verb RunAs"
    exit /b
)

:: 2. Execute PowerShell Remediation Engine
echo [*] Executing system certificate audit and remediation engine...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\fix_windows.ps1"
set PS_RESULT=%errorlevel%

:: 3. Check for Python Environment & Update certifi
echo.
echo --- Checking Python Environment ---
where python >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Python detected on system. Updating certifi bundle to >=2026.10.19...
    python -m pip install --upgrade "certifi>=2026.10.19"
    if %errorlevel% equ 0 (
        echo [OK] Python certifi package updated successfully!
    ) else (
        echo [!] pip upgrade encountered a warning or offline environment.
    )
) else (
    echo [*] Python is not installed. Windows system-wide certificate store is secured.
)

echo.
if %PS_RESULT% equ 0 (
    echo ===============================================================================
    echo   [SUCCESS] 恭喜！本地系统与证书库已成功修复并阻断 eMudhra 弱私钥证书！
    echo   All 16 compromised intermediate CAs are now permanently blocked in Windows.
    echo ===============================================================================
) else (
    echo ===============================================================================
    echo   [WARNING] 修复过程遇到异常，请检查管理员权限或网络连接后重试。
    echo ===============================================================================
)

echo.
echo 按任意键退出窗口...
pause >nul

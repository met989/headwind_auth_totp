@echo off
setlocal enabledelayedexpansion
title Headwind MDM 2FA TOTP - GitHub Publisher

echo ======================================================================
echo    Headwind MDM 2FA TOTP Plugin - GitHub Publisher
echo ======================================================================
echo.

REM 1. Check for git
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Git is not installed or not in your PATH.
    pause
    exit /b 1
)

REM 2. Initialize git if needed
if not exist ".git" (
    echo [INFO] Initializing new Git repository...
    git init -b main
    if %errorlevel% neq 0 (
        git init
        git branch -M main
    )
)

REM 3. Check remote origin
git remote get-url origin >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [SETUP] No GitHub remote repository configured yet.
    set /p REPO_URL="Enter your GitHub repository URL (e.g. https://github.com/met989/headwind_auth_totp.git): "
    if "!REPO_URL!"=="" (
        echo [ERROR] Repository URL cannot be empty.
        pause
        exit /b 1
    )
    git remote add origin !REPO_URL!
    echo [OK] Added remote origin: !REPO_URL!
)

REM 4. Staging files
echo.
echo [INFO] Staging files...
git add .

echo [INFO] Committing changes...
git commit -m "Release v1.0: Headwind MDM 2FA TOTP Authentication Plugin"

echo.
echo [INFO] Pushing to GitHub (main branch)...
git push -u origin main

if %errorlevel% equ 0 (
    echo.
    echo ======================================================================
    echo    [SUCCESS] Repository successfully pushed to GitHub!
    echo ======================================================================
) else (
    echo.
    echo [WARN] Push failed. If the remote repository has an initial commit, try:
    echo        git push -u origin main --force
)

echo.
pause

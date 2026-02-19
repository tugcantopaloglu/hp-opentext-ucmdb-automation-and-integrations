@echo off
REM =============================================================================
REM Download Packages Script (Windows)
REM Run this on a machine WITH internet access
REM Downloads all required packages for offline installation
REM =============================================================================

echo ==============================================
echo AD Network Sync - Package Downloader
echo ==============================================
echo.

set SCRIPT_DIR=%~dp0
set PKG_DIR=%SCRIPT_DIR%offline_packages

echo Creating package directory: %PKG_DIR%
if not exist "%PKG_DIR%" mkdir "%PKG_DIR%"

echo.
echo Downloading packages...
echo.

pip download --dest "%PKG_DIR%" ldap3 requests urllib3

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Download failed!
    pause
    exit /b 1
)

echo.
echo ==============================================
echo Download complete!
echo ==============================================
echo.
echo Downloaded packages:
dir "%PKG_DIR%"
echo.
echo Next steps:
echo 1. Copy these files to your offline machine:
echo    - offline_packages\ folder
echo    - install_pkg_windows.bat
echo    - ad_export.py
echo    - ad_network_sync.py
echo    - config.template.json
echo.
echo 2. On the offline machine, run:
echo    install_pkg_windows.bat
echo.
pause

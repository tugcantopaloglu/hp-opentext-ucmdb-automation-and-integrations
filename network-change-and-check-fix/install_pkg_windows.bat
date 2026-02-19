@echo off
REM =============================================================================
REM Install Packages Script (Windows - Offline)
REM Run this on the machine WITHOUT internet access
REM Installs packages from the offline_packages directory
REM =============================================================================

echo ==============================================
echo AD Network Sync - Offline Installer
echo ==============================================
echo.

set SCRIPT_DIR=%~dp0
set PKG_DIR=%SCRIPT_DIR%offline_packages

REM Check if package directory exists
if not exist "%PKG_DIR%" (
    echo ERROR: Package directory not found: %PKG_DIR%
    echo.
    echo Make sure you have copied the offline_packages folder
    echo from the machine where you ran download_pkg_windows.bat
    pause
    exit /b 1
)

echo Found package directory: %PKG_DIR%
echo.
echo Installing packages...
echo.

pip install --no-index --find-links="%PKG_DIR%" ldap3 requests urllib3

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Installation failed!
    echo.
    echo If you see "externally-managed-environment" error, try:
    echo   pip install --no-index --find-links="%PKG_DIR%" --break-system-packages ldap3 requests urllib3
    echo.
    echo Or create a virtual environment first:
    echo   python -m venv venv
    echo   venv\Scripts\activate
    echo   pip install --no-index --find-links="%PKG_DIR%" ldap3 requests urllib3
    pause
    exit /b 1
)

echo.
echo ==============================================
echo Installation complete!
echo ==============================================
echo.
echo Verifying installation...
python -c "import ldap3; import requests; import urllib3; print('ldap3:', ldap3.__version__); print('requests:', requests.__version__); print('urllib3:', urllib3.__version__); print(); print('All packages installed successfully!')"

echo.
echo You can now run:
echo   python ad_export.py --help
echo   python ad_network_sync.py --help
echo.
pause

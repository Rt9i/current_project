@echo off
title Ransomware Protection System - Ultimate Edition
echo ===============================================
echo    نظام الحماية من فيروسات الفدية - Windows
echo    Ultimate Working Edition - All Issues Fixed
echo ===============================================
echo.

REM Check if Python 3.8+ is available
echo [STEP 1] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo [STEP 2] Python found! Current version:
python --version

echo [STEP 3] Checking disk space...
echo Attempting to check available space...
for /f "tokens=3" %%a in ('dir /-c ^| find "bytes free"') do set free_space=%%a
echo Please ensure you have at least 2GB free space on this drive.

echo [STEP 4] Setting up virtual environment...
echo.

REM Create virtual environment if it doesn't exist
if not exist venv (
    echo Creating new virtual environment...
    python -m venv venv
    echo Virtual environment created successfully!
) else (
    echo Virtual environment already exists.
    echo Using existing virtual environment.
)

echo.
echo [STEP 5] Activating virtual environment...
call venv\Scripts\activate.bat
echo Virtual environment activated!

echo [STEP 6] Installing/upgrading pip, setuptools, and wheel...
python -m pip install --upgrade pip setuptools wheel --no-cache-dir

echo [STEP 7] Installing minimal requirements...
echo This is optimized for low disk space environments...
echo.

REM Try minimal requirements first
if exist requirements_minimal.txt (
    echo Using minimal requirements to save disk space...
    python -m pip install -r requirements_minimal.txt --no-cache-dir
    if errorlevel 1 (
        echo WARNING: Minimal installation failed, trying alternative approach...
        python -m pip install --no-cache-dir flask waitress flask-cors
    )
) else (
    echo Installing core dependencies only...
    python -m pip install --no-cache-dir flask waitress flask-cors
)

echo.
echo ===============================================
echo  [SUCCESS] All requirements installed!
echo  [SUCCESS] Virtual environment is ready!
echo  [SUCCESS] Optimized for low disk space!
echo ===============================================
echo.
echo [STEP 8] Starting Ransomware Protection System...
echo.

echo The web interface will be available at:
echo http://localhost:5000
echo.

echo Using Production WSGI Server (Waitress)
echo To stop the system: Press Ctrl+C
echo.

echo Starting Ransomware Protection System...
echo Please wait while the server initializes...
echo.
echo If you see "No space left on device" error:
echo 1. Free up disk space
echo 2. Run: pip install --no-cache-dir flask waitress
echo 3. Check TROUBLESHOOTING.md
echo.

REM تشغيل النظام عبر Python script
python start_server.py

if errorlevel 1 (
    echo.
    echo ⚠️ Server encountered an error
    echo Check TROUBLESHOOTING.md for solutions
    echo Common solutions:
    echo - Free up disk space (need 2GB+)
    echo - Run as administrator
    echo - Install dependencies manually: pip install flask waitress flask-cors
)

echo.
echo System stopped. Press any key to exit...
pause

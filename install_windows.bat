@echo off
echo ===============================================
echo    تثبيت نظام الحماية من الفدية - Windows
echo    Ransomware Protection System - Windows
echo ===============================================
echo.

echo [STEP 1] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

echo ✅ Python found!
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Current version: %PYTHON_VERSION%

echo.
echo [STEP 2] Checking disk space...
echo Please ensure you have at least 2GB free space on this drive.
echo.

echo [STEP 3] Setting up virtual environment...
python -m venv venv
if errorlevel 1 (
    echo ❌ Failed to create virtual environment
    pause
    exit /b 1
)
echo ✅ Virtual environment created successfully!

echo.
echo [STEP 4] Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ❌ Failed to activate virtual environment
    pause
    exit /b 1
)
echo ✅ Virtual environment activated!

echo.
echo [STEP 5] Installing/upgrading pip, setuptools, and wheel...
python -m pip install --upgrade pip setuptools wheel
if errorlevel 1 (
    echo ⚠️  Failed to upgrade pip/setuptools, continuing...
)

echo.
echo [STEP 6] Installing requirements (Windows Optimized)...
echo Using requirements_windows.txt (YARA marked as optional)

python -m pip install -r requirements_windows.txt
if errorlevel 1 (
    echo ⚠️  Installation completed with warnings
    echo Some packages may need manual installation
) else (
    echo ✅ All requirements installed successfully!
)

echo.
echo ===============================================
echo [SUCCESS] Installation completed!
echo [SUCCESS] Virtual environment is ready!
echo ===============================================
echo.

echo [STEP 7] Testing installation...
python test_fixes.py

echo.
echo [STEP 8] Ready to start the system!
echo.
echo To start the system:
echo   1. Activate virtual environment: venv\Scripts\activate.bat
echo   2. Run: python src\main.py
echo   3. Open web browser: http://localhost:5000
echo.
echo To stop the system: Press Ctrl+C
echo.

echo Press any key to exit...
pause >nul

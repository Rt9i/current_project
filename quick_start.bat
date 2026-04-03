@echo off
title Ransomware Protection System - Quick Start

echo 🚀 Ransomware Protection System - Quick Start
echo ================================================

:: تفعيل البيئة الافتراضية
if exist venv\Scripts\activate.bat (
    echo 📦 Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo ❌ Virtual environment not found!
    echo Run install_complete.bat first
    pause
    exit /b 1
)

:: تشغيل النظام
echo.
echo 🔧 Starting Ransomware Protection System...
echo 🌐 URL: http://localhost:5000
echo.
echo Press Ctrl+C to stop
echo.

python start_server.py

echo.
echo System stopped.
pause
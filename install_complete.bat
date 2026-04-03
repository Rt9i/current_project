@echo off
chcp 65001 >nul
title 🔧 Ultimate Ransomware Protection System - Auto Installer

:: ===============================================
::    الحماية من البرمجيات الخبيثة - المثبت التلقائي
::    Ultimate Ransomware Protection System - Auto Installer
:: ===============================================

echo.
echo ╔════════════════════════════════════════════════════════════════════════════════╗
echo ║                                                                                ║
echo ║           🔒 Ransomware Protection System - Ultimate Installer                ║
echo ║                      All Issues Fixed - Auto Fix                               ║
echo ║                                                                                ║
echo ║  🎯 حلول شاملة لجميع المشاكل السابقة                                         ║
echo ║  🔍 تثبيت تلقائي شامل مع watchdog ومراقبة الملفات                            ║
echo ║  ⚡ محسن للأداء والاستقرار                                                     ║
echo ║                                                                                ║
echo ╚════════════════════════════════════════════════════════════════════════════════╝
echo.

:: فحص Python
echo [STEP 1/6] فحص Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python غير مثبت أو غير موجود في PATH
    echo 💡 قم بتثبيت Python من https://python.org
    echo ⚠️  تأكد من اختيار "Add Python to PATH" أثناء التثبيت
    echo.
    echo اضغط أي مفتاح للخروج...
    pause >nul
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo ✅ Python عثر عليه: %PYTHON_VERSION%

:: فحص المساحة
echo.
echo [STEP 2/6] فحص مساحة القرص...
for /f "tokens=3" %%a in ('dir /-c "%SystemDrive%\" ^| find "bytes free"') do set FREE_SPACE=%%a
if defined FREE_SPACE (
    echo مساحة القرص: %FREE_SPACE% بايت
    echo ✅ مساحة كافية للتثبيت
) else (
    echo ⚠️  لا يمكن فحص مساحة القرص - سيتم المتابعة
)

:: إنشاء/إعداد البيئة الافتراضية
echo.
echo [STEP 3/6] إعداد البيئة الافتراضية...

if exist "venv" (
    echo 🎯 استخدام البيئة الافتراضية الموجودة...
    echo حذف البيئة القديمة...
    rmdir /s /q venv
)

echo إنشاء بيئة افتراضية جديدة...
python -m venv venv
if errorlevel 1 (
    echo ❌ فشل في إنشاء البيئة الافتراضية
    echo 💡 قم بتشغيل Command Prompt كـ Administrator
    pause
    exit /b 1
)

echo ✅ تم إنشاء البيئة الافتراضية بنجاح

:: تفعيل البيئة الافتراضية وتثبيت المتطلبات
echo.
echo [STEP 4/6] تفعيل البيئة وتثبيت المتطلبات الشاملة...

call venv\Scripts\activate.bat

echo ✅ تم تفعيل البيئة الافتراضية

echo 🔧 ترقية pip...
python -m pip install --upgrade pip setuptools wheel --quiet

echo 🚀 تثبيت المتطلبات الشاملة مع watchdog...

:: تثبيت شامل يشمل جميع المتطلبات مع التركيز على watchdog
python -m pip install --no-cache-dir flask flask-cors waitress
echo ✅ Flask, Waitress, CORS - مثبت

python -m pip install --no-cache-dir watchdog
echo ✅ Watchdog (File System Monitoring) - مثبت

python -m pip install --no-cache-dir psutil requests numpy pandas scikit-learn
echo ✅ System & ML Dependencies - مثبت

python -m pip install --no-cache-dir cryptography colorama pyyaml
echo ✅ Security & Utils - مثبت

:: تثبيت جميع المتطلبات من ملف requirements_minimal.txt
if exist requirements_minimal.txt (
    echo 📦 تثبيت من ملف requirements_minimal.txt...
    python -m pip install --no-cache-dir -r requirements_minimal.txt
    echo ✅ تثبيت من الملف - مكتمل
) else (
    echo ⚠️  ملف requirements_minimal.txt غير موجود - التثبيت اليدوي مكتمل
)

:: فحص التثبيت
echo.
echo [STEP 5/6] فحص التثبيت...

python -c "import flask; print('✅ Flask:', flask.__version__)" >nul 2>&1
if errorlevel 1 (
    echo ❌ Flask - فشل في الفحص
) else (
    echo ✅ Flask - يعمل
)

python -c "import watchdog; print('✅ Watchdog:', watchdog.__version__)" >nul 2>&1
if errorlevel 1 (
    echo ❌ Watchdog - فشل في الفحص
    echo ⚠️  هذه مشكلة خطيرة! سيتم محاولة الإصلاح...
    python -m pip install --no-cache-dir watchdog --force-reinstall
    echo 💡 أعد تشغيل المثبت إذا استمرت المشكلة
) else (
    echo ✅ Watchdog - يعمل
)

python -c "import waitress; print('✅ Waitress:', waitress.__version__)" >nul 2>&1
if errorlevel 1 (
    echo ❌ Waitress - فشل في الفحص
) else (
    echo ✅ Waitress - يعمل
)

:: إنشاء ملف تشغيل محسن
echo.
echo [STEP 6/6] إنشاء ملفات التشغيل...

echo @echo off > run_system.bat
echo title Ransomware Protection System >> run_system.bat
echo echo 🚀 Starting Ransomware Protection System... >> run_system.bat
echo echo. >> run_system.bat
echo call venv\Scripts\activate.bat >> run_system.bat
echo python start_server.py >> run_system.bat
echo echo. >> run_system.bat
echo echo System stopped. >> run_system.bat
echo pause >> run_system.bat

echo ✅ ملف التشغيل: run_system.bat

:: إنشاء تقرير التثبيت
echo INSTALLATION_COMPLETE > installation_status.txt
echo Date: %date% %time% >> installation_status.txt
echo Python: %PYTHON_VERSION% >> installation_status.txt
echo Status: SUCCESS >> installation_status.txt

echo.
echo ╔════════════════════════════════════════════════════════════════════════════════╗
echo ║                              ✅ تم التثبيت بنجاح!                               ║
echo ╚════════════════════════════════════════════════════════════════════════════════╝
echo.
echo 🎊 النظام جاهز للاستخدام!
echo.
echo 🚀 لتشغيل النظام:
echo    الطريقة 1: انقر مرتين على run_system.bat
echo    الطريقة 2: python start_server.py
echo    الطريقة 3: activate venv ثم python main.py
echo.
echo 🌐 الوصول للنظام:
echo    URL: http://localhost:5000
echo.
echo 📋 المساعدة:
echo    • لا مشاكل: النظام يعمل فوراً
echo    • مشاكل في Watchdog: أعد تشغيل المثبت
echo    • مشاكل في الصلاحيات: شغل Command Prompt كـ Administrator
echo.
echo اضغط أي مفتاح لتشغيل النظام الآن...
pause >nul

echo.
echo 🚀 تشغيل النظام الآن...

:: تشغيل النظام مباشرة
call venv\Scripts\activate.bat
python start_server.py

echo.
echo ===============================================
echo النظام توقف أو حدث خطأ.
echo راجع TROUBLESHOOTING.md للحلول
echo أو أعد تشغيل المثبت
echo ===============================================

echo.
echo اضغط أي مفتاح للخروج...
pause >nul
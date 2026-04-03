#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Start Server Script - Ultimate Working Edition
إعداد وتشغيل سيرفر Waitress الإنتاجي مع حلول شاملة للأخطاء
"""

import sys
import os
import time
import traceback
import importlib.util
import subprocess
from pathlib import Path

def check_python_version():
    """التحقق من إصدار Python"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ مطلوب. إصدارك:", sys.version)
        return False
    print(f"✅ Python version: {sys.version}")
    return True

def check_disk_space():
    """التحقق من مساحة القرص"""
    try:
        import shutil
        total, used, free = shutil.disk_usage(".")
        free_gb = free // (1024**3)
        
        print(f"💾 مساحة القرص المتاحة: {free_gb} GB")
        if free_gb < 2:
            print("⚠️ تحذير: مساحة القرص منخفضة (< 2GB)")
            return False
        return True
    except:
        return True

def setup_environment():
    """إعداد البيئة وإضافة مسار src"""
    # إضافة مسار src إلى Python path
    src_path = Path(__file__).parent / "src"
    sys.path.insert(0, str(src_path))
    
    # إضافة مسار المشروع الحالي
    project_path = Path(__file__).parent
    sys.path.insert(0, str(project_path))
    
    print("✅ Environment setup completed")

def check_dependencies():
    """التحقق من dependencies المطلوبة"""
    # المكتبات المطلوبة - مع ترتيب أولوية للحلول
    core_modules = ['flask', 'waitress', 'flask_cors', 'watchdog']
    missing_core_modules = []
    missing_critical_modules = []
    
    print("🔍 Checking dependencies...")
    print("   🎯 Critical modules (File System Monitoring):")
    
    # فحص watchdog أولاً كأولوية عالية
    for module in ['watchdog']:  # أولوية عالية
        try:
            spec = importlib.util.find_spec(module)
            if spec is None:
                missing_critical_modules.append(module)
                print(f"  ❌ {module} - NOT FOUND")
            else:
                print(f"  ✅ {module} - OK")
        except ImportError:
            missing_critical_modules.append(module)
            print(f"  ❌ {module} - IMPORT ERROR")
    
    print("   🎯 Core web modules:")
    
    # فحص باقي المكتبات
    for module in core_modules[1:]:  # باقي المكتبات
        try:
            if module == 'flask_cors':
                spec = importlib.util.find_spec('flask_cors')
            else:
                spec = importlib.util.find_spec(module)
            if spec is None:
                missing_core_modules.append(module)
                print(f"  ❌ {module} - NOT FOUND")
            else:
                print(f"  ✅ {module} - OK")
        except ImportError:
            missing_core_modules.append(module)
            print(f"  ❌ {module} - IMPORT ERROR")
    
    # معالجة الأخطاء
    all_missing = missing_core_modules + missing_critical_modules
    
    if all_missing:
        print(f"\n❌ Missing modules: {all_missing}")
        print("💡 Auto-installing missing dependencies...")
        
        # محاولة التثبيت التلقائي
        try:
            import subprocess
            
            # تثبيت مكتبة watchodك أولاً (أولوية عالية)
            if 'watchdog' in all_missing:
                print("   🎯 Installing watchdog (File System Monitoring)...")
                subprocess.run([
                    sys.executable, '-m', 'pip', 'install', 
                    '--no-cache-dir', 'watchdog>=2.0.0'
                ], check=True, capture_output=True)
                print("   ✅ watchdog installed successfully!")
            
            # تثبيت باقي المكتبات
            remaining_modules = [m for m in all_missing if m != 'watchdog']
            if remaining_modules:
                packages_to_install = {
                    'flask': 'flask>=2.0.0',
                    'waitress': 'waitress>=2.0.0', 
                    'flask_cors': 'flask-cors>=4.0.0',
                    'psutil': 'psutil>=5.8.0',
                    'requests': 'requests>=2.25.0',
                    'numpy': 'numpy>=1.20.0',
                    'pandas': 'pandas>=1.3.0',
                    'scikit-learn': 'scikit-learn>=1.0.0'
                }
                
                install_packages = [packages_to_install[m] for m in remaining_modules if m in packages_to_install]
                
                if install_packages:
                    print("   🎯 Installing remaining dependencies...")
                    subprocess.run([
                        sys.executable, '-m', 'pip', 'install', 
                        '--no-cache-dir'
                    ] + install_packages, check=True, capture_output=True)
                    print("   ✅ Dependencies installed successfully!")
            
            print("✅ All dependencies installed successfully!")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            print("💡 Manual installation required:")
            print("   1. Run: pip install -r requirements_minimal.txt")
            print("   2. If disk space issue: pip install --no-cache-dir flask flask-cors waitress watchdog")
            print("   3. If permission issue, run as administrator")
            return False
        except Exception as e:
            print(f"❌ Installation error: {e}")
            print("💡 Manual installation required:")
            print("   Run: pip install -r requirements_minimal.txt")
            return False
    
    return True

def start_ransomware_protection_system():
    """بدء نظام الحماية من الفدية"""
    try:
        print("\n🚀 Starting Ransomware Protection System...")
        
        # التحقق من Python version
        if not check_python_version():
            return False
        
        # التحقق من مساحة القرص
        if not check_disk_space():
            print("💡 Still continuing, but be aware...")
        
        # إعداد البيئة
        setup_environment()
        
        # التحقق من dependencies
        if not check_dependencies():
            print("\n⚠️ Dependencies missing. Attempting installation...")
            try:
                import subprocess
                
                # تثبيت شامل يتضمن watchdog
                print("🎯 Installing full dependency set...")
                subprocess.run([
                    sys.executable, '-m', 'pip', 'install', 
                    '--no-cache-dir',
                    'flask>=2.0.0',
                    'waitress>=2.0.0',
                    'flask-cors>=4.0.0', 
                    'watchdog>=2.0.0',
                    'psutil>=5.8.0',
                    'requests>=2.25.0',
                    'numpy>=1.20.0',
                    'pandas>=1.3.0',
                    'scikit-learn>=1.0.0'
                ], check=True, capture_output=True)
                print("✅ All dependencies installed successfully!")
                
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install dependencies automatically: {e}")
                print("💡 Please install manually:")
                print("   pip install -r requirements_minimal.txt")
                print("   OR:")
                print("   pip install flask waitress flask-cors watchdog")
                return False
        
        # استيراد التطبيق
        print("\n📦 Loading application components...")
        from main import get_app
        from waitress import serve
        
        # إنشاء مثيل التطبيق
        print("🔧 Initializing Flask application...")
        app = get_app()
        
        # معلومات البداية
        print("\n" + "=" * 50)
        print("    RANSOMWARE PROTECTION SYSTEM")
        print("    Enhanced Production Server - Ultimate Edition")
        print("=" * 50)
        print(f"📡 Server: Waitress Production WSGI")
        print(f"🧵 Threads: 8 concurrent threads")
        print(f"🌐 URL: http://localhost:5000")
        print(f"⚡ Performance: Production-ready")
        print(f"🔒 Security: Enhanced")
        print(f"💻 Platform: {sys.platform}")
        print("=" * 50)
        print()
        
        print("🎯 Starting server...")
        print("💡 Access the web interface at: http://localhost:5000")
        print("⏹️  To stop: Press Ctrl+C")
        print("🐛 For debugging: Check browser console (F12)")
        print()
        
        # تشغيل السيرفر
        serve(
            app, 
            host='0.0.0.0', 
            port=5000, 
            threads=8,
            expose_tracebacks=False,  # لا تُظهر خطأ في الإنتاج
            log_socket_errors=False   # تقليل ضوضاء السجلات
        )
        
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user (Ctrl+C)")
        return True
        
    except ImportError as e:
        print(f"\n❌ Import Error: {e}")
        print("💡 Make sure all requirements are installed")
        print("   Run: python -m pip install -r requirements_minimal.txt")
        print("   OR: pip install flask waitress flask-cors watchdog")
        return False
        
    except Exception as e:
        print(f"\n❌ Server Error: {e}")
        print("📋 Full traceback:")
        traceback.print_exc()
        print("\n💡 Troubleshooting:")
        print("   1. Check disk space")
        print("   2. Install dependencies: pip install -r requirements_minimal.txt")
        print("   3. OR: pip install flask waitress flask-cors watchdog")
        print("   4. Run as administrator")
        print("   5. Check TROUBLESHOOTING.md")
        return False

if __name__ == "__main__":
    try:
        success = start_ransomware_protection_system()
        if not success:
            input("\nPress Enter to exit...")
    except Exception as e:
        print(f"❌ Fatal Error: {e}")
        traceback.print_exc()
        input("Press Enter to exit...")

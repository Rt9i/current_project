#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
الملف النهائي لتشغيل نظام الحماية من الثعير الإلكتروني
Final Runtime File for Ransomware Protection System

هذا الملف هو الملف الأساسي الوحيد المطلوب لتشغيل النظام
This is the main and only file required to run the system
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_and_install_requirements():
    """التحقق من المتطلبات وتثبيتها"""
    print("🔍 التحقق من المتطلبات...")
    
    # قائمة المكتبات المطلوبة
    required_packages = [
        'flask', 'flask_cors', 'waitress', 'watchdog',
        'sklearn', 'numpy', 'psutil', 'requests'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"⚠️ مكتبات مفقودة: {missing_packages}")
        print("🔧 تثبيت المكتبات المطلوبة...")
        
        # استخدام pip install مع الحد الأدنى من الخيارات
        try:
            for package in missing_packages:
                print(f"   تثبيت {package}...")
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", 
                    "--no-cache-dir", "--disable-pip-version-check", package
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            print("✅ تم تثبيت جميع المكتبات بنجاح")
        except subprocess.CalledProcessError as e:
            print(f"❌ خطأ في تثبيت المكتبات: {e}")
            print("💡 جرب تشغيل: pip install -r requirements_comprehensive.txt")
            return False
    
    return True

def start_system():
    """بدء النظام"""
    print("🚀 بدء نظام الحماية من الثعير الإلكتروني")
    print("=" * 60)
    
    # التحقق من وجود ملف main.py
    current_dir = Path(__file__).parent
    main_script = current_dir / "src" / "main.py"
    
    if not main_script.exists():
        print("❌ ملف main.py غير موجود في مجلد src")
        return False
    
    # التحقق من المتطلبات
    if not check_and_install_requirements():
        return False
    
    print("🌐 بدء خادم النظام...")
    print("📍 الواجهة متاحة على: http://localhost:5000")
    print("⏹️ للإيقاف: اضغط Ctrl+C")
    print("=" * 60)
    
    try:
        # بدء النظام
        python_cmd = "python" if platform.system() == "Windows" else "python3"
        os.system(f'cd "{current_dir / "src"}" && {python_cmd} main.py')
        
    except KeyboardInterrupt:
        print("\n⏹️ تم إيقاف النظام بواسطة المستخدم")
    except Exception as e:
        print(f"❌ خطأ في بدء النظام: {e}")
        return False
    
    return True

def main():
    """الدالة الرئيسية"""
    print("🛡️ نظام الحماية من الثعير الإلكتروني")
    print("   Ransomware Protection System")
    print("=" * 60)
    
    # التحقق من Python
    if sys.version_info < (3, 8):
        print("❌ يتطلب Python 3.8 أو أحدث")
        return
    
    print(f"✅ Python version: {sys.version}")
    
    # بدء النظام
    success = start_system()
    
    if success:
        print("\n✅ تم تشغيل النظام بنجاح")
    else:
        print("\n❌ فشل في تشغيل النظام")
        print("\n💡 للمساعدة:")
        print("   1. تحقق من وجود جميع الملفات")
        print("   2. تثبيت المتطلبات يدوياً")
        print("   3. راجع ملف TROUBLESHOOTING.md")

if __name__ == "__main__":
    main()

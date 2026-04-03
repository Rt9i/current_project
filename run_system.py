#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
سكريبت التشغيل النهائي المبسط
Final Simple Startup Script
"""

import subprocess
import sys
import os
from pathlib import Path

def print_banner():
    """طباعة عنوان النظام"""
    print("=" * 60)
    print("🛡️  نظام الحماية من البرمجيات الخبيثة - النسخة المحسنة")
    print("   Ransomware Protection System - Enhanced Edition")
    print("=" * 60)
    print()

def check_venv():
    """فحص البيئة الافتراضية"""
    venv_path = Path(__file__).parent / "venv" / "bin" / "python"
    if not venv_path.exists():
        print("❌ البيئة الافتراضية غير موجودة!")
        print("💡 قم بتشغيل: source venv/bin/activate")
        return False
    return True

def start_system():
    """تشغيل النظام"""
    try:
        print("🚀 بدء تشغيل النظام...")
        
        # مسار Python من venv
        venv_python = Path(__file__).parent / "venv" / "bin" / "python"
        
        # مسار main.py
        main_script = Path(__file__).parent / "src" / "main.py"
        
        if not main_script.exists():
            print(f"❌ ملف main.py غير موجود: {main_script}")
            return False
        
        print(f"🐍 Python: {venv_python}")
        print(f"📁 Script: {main_script}")
        print(f"🌐 URL: http://localhost:5000")
        print()
        print("⏳ بدء التشغيل...")
        print("-" * 40)
        
        # تشغيل النظام
        result = subprocess.run([
            str(venv_python), str(main_script)
        ], cwd=str(main_script.parent))
        
        return result.returncode == 0
        
    except KeyboardInterrupt:
        print("\n\n⏹️  تم إيقاف النظام بواسطة المستخدم")
        return True
    except Exception as e:
        print(f"\n❌ خطأ في التشغيل: {e}")
        return False

def test_system():
    """اختبار سريع للنظام"""
    try:
        import requests
        response = requests.get("http://localhost:5000/api/health", timeout=3)
        if response.status_code == 200:
            print("✅ النظام يعمل بنجاح!")
            data = response.json()
            print(f"   الحالة: {'نشط' if not data.get('paused') else 'متوقف'}")
            print(f"   المراقبة: {'مفعلة' if data.get('running') else 'معطلة'}")
            return True
    except:
        pass
    return False

def main():
    """الدالة الرئيسية"""
    print_banner()
    
    # فحص البيئة الافتراضية
    if not check_venv():
        return False
    
    # بدء النظام
    success = start_system()
    
    if success:
        print("\n" + "=" * 60)
        print("🎉 تم إيقاف النظام بنجاح")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("⚠️  تم إيقاف النظام مع أخطاء")
        print("=" * 60)
    
    return success

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""سكريبت تفعيل البيئة الافتراضية المحسن"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def find_venv():
    """البحث عن مجلد البيئة الافتراضية"""
    
    project_root = Path(__file__).parent
    possible_venvs = [
        project_root / "venv",
        project_root / ".venv", 
        project_root / "src" / "venv",
        project_root / "src" / ".venv"
    ]
    
    for venv_path in possible_venvs:
        if venv_path.exists():
            return venv_path
    
    return None

def get_activation_script(venv_path):
    """الحصول على سكريبت التفعيل المناسب للنظام"""
    
    system = platform.system()
    
    if system == "Windows":
        return venv_path / "Scripts" / "activate.bat"
    else:
        return venv_path / "bin" / "activate"

def activate_venv():
    """تفعيل البيئة الافتراضية"""
    
    print("🔍 البحث عن البيئة الافتراضية...")
    
    venv_path = find_venv()
    
    if not venv_path:
        print("❌ لم يتم العثور على البيئة الافتراضية")
        print("💡 قم بتشغيل: python -m venv venv")
        return False
    
    print(f"✅ تم العثور على البيئة الافتراضية: {venv_path}")
    
    activation_script = get_activation_script(venv_path)
    
    if not activation_script.exists():
        print(f"❌ سكريبت التفعيل غير موجود: {activation_script}")
        return False
    
    # تفعيل البيئة الافتراضية
    system = platform.system()
    
    if system == "Windows":
        # Windows
        activate_command = f'"{activation_script}"'
        python_path = venv_path / "Scripts" / "python.exe"
        pip_path = venv_path / "Scripts" / "pip.exe"
    else:
        # Linux/macOS
        activate_command = f'source "{activation_script}"'
        python_path = venv_path / "bin" / "python"
        pip_path = venv_path / "bin" / "pip"
    
    print(f"🔄 تفعيل البيئة الافتراضية...")
    
    try:
        # تحديث متغيرات البيئة
        if system == "Windows":
            # إضافة مسارات Python إلى PATH
            current_path = os.environ.get("PATH", "")
            scripts_dir = str(venv_path / "Scripts")
            new_path = f"{scripts_dir};{current_path}"
            os.environ["PATH"] = new_path
            
            # إضافة VIRTUAL_ENV
            os.environ["VIRTUAL_ENV"] = str(venv_path)
            
        else:
            # Linux/macOS
            current_path = os.environ.get("PATH", "")
            bin_dir = str(venv_path / "bin")
            new_path = f"{bin_dir}:{current_path}"
            os.environ["PATH"] = new_path
            
            # إضافة VIRTUAL_ENV
            os.environ["VIRTUAL_ENV"] = str(venv_path)
        
        print("✅ تم تفعيل البيئة الافتراضية بنجاح!")
        print(f"🐍 Python: {python_path}")
        print(f"📦 Pip: {pip_path}")
        
        return True
        
    except Exception as e:
        print(f"❌ خطأ في تفعيل البيئة الافتراضية: {e}")
        return False

def check_dependencies():
    """فحص المكتبات المطلوبة"""
    
    required_packages = [
        "flask",
        "flask-cors", 
        "waitress",
        "google-api-python-client",
        "google-auth",
        "google-auth-oauthlib",
        "cryptography",
        "psutil",
        "hashlib3",
        "pymd5",
        "xxhash",
        "yara-python"
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
            print(f"✅ {package} - متوفر")
        except ImportError:
            print(f"❌ {package} - مفقود")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n📦 تثبيت المكتبات المفقودة: {missing_packages}")
        return False
    
    return True

def install_missing_packages():
    """تثبيت المكتبات المفقودة"""
    
    packages = [
        "flask",
        "flask-cors",
        "waitress", 
        "google-api-python-client",
        "google-auth",
        "google-auth-oauthlib",
        "google-auth-httplib2",
        "cryptography",
        "psutil",
        "hashlib3",
        "pymd5",
        "xxhash",
        "yara-python"
    ]
    
    print("📦 تثبيت المكتبات المطلوبة...")
    
    try:
        # استخدام pip مع pip بدلاً من uv
        import subprocess
        
        for package in packages:
            print(f"📦 تثبيت {package}...")
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", package
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ تم تثبيت {package} بنجاح")
            else:
                print(f"❌ فشل في تثبيت {package}: {result.stderr}")
        
        return True
        
    except Exception as e:
        print(f"❌ خطأ في تثبيت المكتبات: {e}")
        return False

if __name__ == "__main__":
    print("🔧 إصلاح تفعيل البيئة الافتراضية")
    print("=" * 50)
    
    # تفعيل البيئة الافتراضية
    if not activate_venv():
        sys.exit(1)
    
    # فحص المكتبات
    if not check_dependencies():
        print("💡 تثبيت المكتبات المفقودة...")
        install_missing_packages()
        
        # إعادة فحص
        if check_dependencies():
            print("✅ تم تثبيت جميع المكتبات بنجاح!")
        else:
            print("❌ لم يتم تثبيت جميع المكتبات")
    
    print("\n🎉 تم إعداد البيئة الافتراضية بنجاح!")

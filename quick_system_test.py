#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار سريع للنظام بعد الإصلاحات
"""

import sys
import os
import importlib.util

def test_imports():
    """اختبار استيراد المكتبات الأساسية"""
    print("🔍 اختبار الاستيراد...")
    
    # اختبار المكتبات الأساسية
    basic_modules = [
        'flask', 'flask_cors', 'waitress', 'watchdog', 
        'psutil', 'requests', 'numpy', 'pandas', 
        'sklearn', 'yaml', 'cryptography', 'colorama'
    ]
    
    failed_imports = []
    
    for module in basic_modules:
        try:
            __import__(module)
            print(f"  ✅ {module}")
        except ImportError as e:
            print(f"  ❌ {module}: {e}")
            failed_imports.append(module)
    
    # اختبار YARA
    try:
        import yara
        print(f"  ✅ yara - {yara.__version__}")
    except ImportError as e:
        print(f"  ❌ yara: {e}")
        failed_imports.append("yara-python")
    
    return failed_imports

def test_files():
    """اختبار وجود الملفات الأساسية"""
    print("\n📁 اختبار الملفات...")
    
    required_files = [
        "src/main.py",
        "src/database_handler.py", 
        "src/yara_scanner.py",
        "data/database/app.db",
        "data/YARA_RULES"
    ]
    
    missing_files = []
    
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"  ✅ {file_path}")
        else:
            print(f"  ❌ {file_path}")
            missing_files.append(file_path)
    
    return missing_files

def test_yara_files():
    """اختبار ملفات YARA"""
    print("\n🛡️ اختبار ملفات YARA...")
    
    yara_dir = "data/YARA_RULES"
    if os.path.exists(yara_dir):
        yara_files = [f for f in os.listdir(yara_dir) if f.endswith(('.yar', '.yara'))]
        print(f"  ✅ {len(yara_files)} ملف YARA موجود")
        return []
    else:
        print(f"  ❌ مجلد YARA_RULES غير موجود")
        return [yara_dir]

def test_config():
    """اختبار ملف التكوين"""
    print("\n⚙️ اختبار التكوين...")
    
    config_file = "src/config.json"
    if not os.path.exists(config_file):
        print(f"  ❌ ملف التكوين غير موجود: {config_file}")
        return [config_file]
    
    try:
        import json
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        monitoring = config.get('monitoring', {})
        protected_folders = monitoring.get('protected_folders', [])
        
        # التحقق من عدم وجود مجلدات محمية محظورة
        forbidden_paths = ['C:\\Documents and Settings']
        for forbidden in forbidden_paths:
            if forbidden in protected_folders:
                print(f"  ❌ مسار محظور في التكوين: {forbidden}")
                return [config_file]
        
        print(f"  ✅ التكوين صحيح")
        print(f"  📋 المجلدات المحمية: {len(protected_folders)} مجلد")
        return []
        
    except Exception as e:
        print(f"  ❌ خطأ في قراءة التكوين: {e}")
        return [config_file]

def main():
    print("=" * 50)
    print("  🔧 اختبار النظام بعد الإصلاحات")
    print("=" * 50)
    
    # تغيير المجلد إلى مجلد المشروع
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    failed_imports = test_imports()
    missing_files = test_files()
    missing_yara = test_yara_files()
    config_errors = test_config()
    
    print("\n" + "=" * 50)
    print("  📊 النتائج النهائية")
    print("=" * 50)
    
    all_good = True
    
    if failed_imports:
        print(f"❌ مكتبات مفقودة: {len(failed_imports)}")
        for module in failed_imports:
            print(f"   - {module}")
        all_good = False
    else:
        print("✅ جميع المكتبات متوفرة")
    
    if missing_files:
        print(f"❌ ملفات مفقودة: {len(missing_files)}")
        for file_path in missing_files:
            print(f"   - {file_path}")
        all_good = False
    else:
        print("✅ جميع الملفات الأساسية موجودة")
    
    if missing_yara:
        print(f"❌ مشاكل في YARA: {len(missing_yara)}")
        all_good = False
    else:
        print("✅ ملفات YARA متوفرة")
    
    if config_errors:
        print(f"❌ مشاكل في التكوين: {len(config_errors)}")
        all_good = False
    else:
        print("✅ التكوين صحيح")
    
    print("\n" + "=" * 50)
    if all_good:
        print("🎉 جميع الاختبارات نجحت! النظام جاهز للتشغيل")
        return True
    else:
        print("⚠️ بعض الاختبارات فشلت. يرجى مراجعة الأخطاء أعلاه.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""سكريبت بدء النظام المحسن"""

import os
import sys
import subprocess
import platform
from pathlib import Path
import time

def main():
    print("🚀 بدء نظام الحماية من الثعير الإلكتروني")
    print("=" * 50)
    
    # البحث عن دليل src
    current_dir = Path(__file__).parent
    src_dir = current_dir / "src"
    
    if not src_dir.exists():
        print("❌ مجلد src غير موجود")
        return False
    
    # تفعيل البيئة الافتراضية أولاً
    venv_script = current_dir / "activate_venv_fixed.py"
    
    if venv_script.exists():
        print("🔧 تفعيل البيئة الافتراضية...")
        try:
            result = subprocess.run([sys.executable, str(venv_script)], 
                                  capture_output=True, text=True, cwd=current_dir)
            if result.returncode != 0:
                print(f"❌ خطأ في تفعيل البيئة الافتراضية: {{result.stderr}}")
            else:
                print("✅ تم تفعيل البيئة الافتراضية")
        except Exception as e:
            print(f"⚠️ تحذير: {{e}}")
    
    # بدء النظام
    main_script = src_dir / "main.py"
    
    if not main_script.exists():
        print("❌ ملف main.py غير موجود")
        return False
    
    print("🌐 بدء خادم النظام...")
    
    try:
        # بدء النظام
        if platform.system() == "Windows":
            os.system(f'cd "{src_dir}" && python main.py')
        else:
            os.system(f'cd "{src_dir}" && python3 main.py')
    except KeyboardInterrupt:
        print("\n⏹️ تم إيقاف النظام")
    except Exception as e:
        print(f"❌ خطأ في بدء النظام: {{e}}")
        return False
    
    return True

if __name__ == "__main__":
    main()

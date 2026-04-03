#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
بدء خادم النظام مع البيئة الافتراضية
Start System with Virtual Environment
"""

import subprocess
import sys
import os
from pathlib import Path

def main():
    """تشغيل النظام مع venv"""
    print("=" * 60)
    print("🛡️  بدء نظام الحماية من البرمجيات الخبيثة")
    print("   Ransomware Protection System - With Virtual Environment")
    print("=" * 60)
    
    try:
        # مسار venv
        venv_python = Path(__file__).parent / "venv" / "bin" / "python"
        
        if not venv_python.exists():
            print("❌ Virtual environment not found!")
            return False
            
        print(f"🐍 Using Python from: {venv_python}")
        
        # مسار main.py
        main_script = Path(__file__).parent / "src" / "main.py"
        
        if not main_script.exists():
            print(f"❌ Main script not found: {main_script}")
            return False
            
        print(f"🚀 Starting main system...")
        
        # تشغيل النظام
        result = subprocess.run([
            str(venv_python), str(main_script)
        ], cwd=str(main_script.parent))
        
        return result.returncode == 0
        
    except KeyboardInterrupt:
        print("\n⏹️  تم إيقاف النظام بواسطة المستخدم")
        return True
    except Exception as e:
        print(f"❌ خطأ في بدء التشغيل: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    main()
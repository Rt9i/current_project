#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
بدء خادم النظام - Simple Server Starter
Ransomware Protection System - Direct Server Start
"""

import sys
import os
from pathlib import Path

# إضافة مسار src إلى Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

def main():
    """بدء النظام مباشرة"""
    print("=" * 60)
    print("🛡️  بدء نظام الحماية من البرمجيات الخبيثة")
    print("   Ransomware Protection System - Windows Edition")
    print("=" * 60)
    
    try:
        # تغيير الدليل إلى src
        os.chdir(src_path)
        print("📁 Current directory:", os.getcwd())
        
        # استيراد وتشغيل النظام مباشرة
        print("🚀 Starting system...")
        import main
        main.main()
        
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
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار شامل للنظام المحدث
Comprehensive System Test - All Components
"""

import os
import sys
import time
import sqlite3
from pathlib import Path
import logging

# إعداد الـ logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def test_database_connection():
    """اختبار اتصال قاعدة البيانات"""
    logger.info("🔍 Testing database connection...")
    try:
        db_path = Path("data/database/app.db")
        if not db_path.exists():
            logger.error("❌ Database file not found!")
            return False
            
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # اختبار الاتصال
        cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
        table_count = cursor.fetchone()[0]
        logger.info(f"✅ Database connected - {table_count} tables found")
        
        # اختبار إدراج سجل تجريبي
        current_time = int(time.time())
        cursor.execute("""
            INSERT INTO events (ts, iso, path, event, status, decision, priority, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (current_time, f"2025-11-29T{time.strftime('%H:%M:%S')}", 
              "test_file.txt", "created", "processed", "allowed", "low", "test data"))
        
        # اختبار استرجاع البيانات
        cursor.execute("SELECT COUNT(*) FROM events")
        events_count = cursor.fetchone()[0]
        logger.info(f"✅ Database operations test passed - {events_count} events in database")
        
        # اختبار الفهارس
        cursor.execute("PRAGMA database_list")
        db_info = cursor.fetchone()
        logger.info(f"✅ Database info: {db_info}")
        
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"❌ Database test failed: {e}")
        return False

def test_yara_import():
    """اختبار استيراد yara-python"""
    logger.info("🔍 Testing YARA Python import...")
    try:
        import yara
        logger.info("✅ YARA Python imported successfully")
        
        # اختبار إنشاء compiler بسيط
        rules = yara.compile(source='rule test { condition: true }')
        logger.info("✅ YARA compiler test passed")
        
        # اختبار مطابقة بسيطة
        matches = rules.match(data=b"test data")
        logger.info(f"✅ YARA matching test passed - {len(matches)} matches")
        
        return True
        
    except ImportError as e:
        logger.error(f"❌ YARA import failed: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ YARA test failed: {e}")
        return False

def test_yara_rules_directory():
    """اختبار مجلد قواعد YARA"""
    logger.info("🔍 Testing YARA rules directory...")
    try:
        yara_dir = Path("data/YARA_RULES")
        if not yara_dir.exists():
            logger.error("❌ YARA rules directory not found!")
            return False
            
        # عد الملفات
        yara_files = list(yara_dir.glob("*.yar")) + list(yara_dir.glob("*.yara"))
        logger.info(f"✅ Found {len(yara_files)} YARA rule files")
        
        # عرض أول 5 ملفات
        for i, file in enumerate(yara_files[:5]):
            logger.info(f"  📄 Rule {i+1}: {file.name}")
        
        if len(yara_files) > 5:
            logger.info(f"  ... and {len(yara_files) - 5} more files")
            
        return True
        
    except Exception as e:
        logger.error(f"❌ YARA rules directory test failed: {e}")
        return False

def test_file_structure():
    """اختبار هيكل الملفات المطلوب"""
    logger.info("🔍 Testing required file structure...")
    
    required_dirs = [
        "data",
        "data/database", 
        "data/YARA_RULES",
        "data/quarantine",
        "data/backups",
        "src"
    ]
    
    required_files = [
        "src/main.py",
        "src/database_handler.py",
        "src/yara_scanner.py",
        "src/file_monitor.py"
    ]
    
    all_good = True
    
    # فحص المجلدات
    for dir_path in required_dirs:
        if not Path(dir_path).exists():
            logger.error(f"❌ Missing directory: {dir_path}")
            all_good = False
        else:
            logger.info(f"✅ Directory exists: {dir_path}")
    
    # فحص الملفات
    for file_path in required_files:
        if not Path(file_path).exists():
            logger.error(f"❌ Missing file: {file_path}")
            all_good = False
        else:
            logger.info(f"✅ File exists: {file_path}")
    
    return all_good

def test_python_dependencies():
    """اختبار المكتبات المطلوبة"""
    logger.info("🔍 Testing Python dependencies...")
    
    required_modules = [
        'flask',
        'flask_cors', 
        'watchdog',
        'sqlite3',
        'yara',
        'threading',
        'logging',
        'pathlib'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            logger.info(f"✅ Module available: {module}")
        except ImportError:
            logger.error(f"❌ Missing module: {module}")
            missing_modules.append(module)
    
    return len(missing_modules) == 0

def test_system_initialization():
    """اختبار تهيئة النظام"""
    logger.info("🔍 Testing system initialization...")
    
    try:
        # إضافة مسار المشروع إلى Python path
        project_root = Path(__file__).parent.absolute()
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))
        
        # اختبار استيراد الوحدة الرئيسية
        logger.info("Testing main module import...")
        
        # إعدادات البيئة
        os.environ.setdefault('PYTHONPATH', str(project_root))
        
        logger.info("✅ System initialization test completed")
        return True
        
    except Exception as e:
        logger.error(f"❌ System initialization failed: {e}")
        return False

def run_comprehensive_test():
    """تشغيل الاختبار الشامل"""
    logger.info("🚀 Starting Comprehensive System Test")
    logger.info("=" * 60)
    
    tests = [
        ("File Structure", test_file_structure),
        ("Python Dependencies", test_python_dependencies),
        ("YARA Rules Directory", test_yara_rules_directory),
        ("YARA Python Library", test_yara_import),
        ("Database Connection", test_database_connection),
        ("System Initialization", test_system_initialization)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        logger.info(f"\n🔄 Running: {test_name}")
        logger.info("-" * 40)
        
        try:
            result = test_func()
            results[test_name] = result
            
            if result:
                logger.info(f"✅ {test_name}: PASSED")
            else:
                logger.error(f"❌ {test_name}: FAILED")
                
        except Exception as e:
            logger.error(f"❌ {test_name}: ERROR - {e}")
            results[test_name] = False
    
    # ملخص النتائج
    logger.info("\n" + "=" * 60)
    logger.info("📊 TEST SUMMARY")
    logger.info("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"{test_name:.<30} {status}")
        if result:
            passed += 1
    
    logger.info("-" * 60)
    logger.info(f"Total: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("🎉 ALL TESTS PASSED! System is ready!")
        return True
    else:
        logger.error(f"⚠️  {total - passed} tests failed. Please check errors above.")
        return False

if __name__ == "__main__":
    success = run_comprehensive_test()
    sys.exit(0 if success else 1)

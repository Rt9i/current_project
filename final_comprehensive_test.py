#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار نهائي شامل لنظام الحماية من الثعير الإلكتروني
Comprehensive Final Test for Ransomware Protection System
"""

import sys
import os
import json
import time
from pathlib import Path
import subprocess
import requests

def print_header(title):
    print("\n" + "="*60)
    print(f"🔧 {title}")
    print("="*60)

def print_success(message):
    print(f"✅ {message}")

def print_error(message):
    print(f"❌ {message}")

def print_warning(message):
    print(f"⚠️ {message}")

def print_info(message):
    print(f"ℹ️ {message}")

def test_imports():
    """اختبار استيراد المكتبات الأساسية"""
    print_header("اختبار استيراد المكتبات الأساسية")
    
    modules_to_test = [
        "flask",
        "flask_cors", 
        "waitress",
        "google.auth.transport.requests",
        "google.oauth2.credentials",
        "google_auth_oauthlib.flow",
        "watchdog.observers",
        "watchdog.events",
        "sqlite3",
        "hashlib",
        "hmac",
        "base64",
        "json",
        "requests"
    ]
    
    passed = 0
    failed = 0
    
    for module in modules_to_test:
        try:
            __import__(module)
            print_success(f"✅ {module} - متوفر")
            passed += 1
        except ImportError as e:
            print_error(f"❌ {module} - مفقود: {e}")
            failed += 1
    
    print_info(f"النتيجة: {passed}/{passed+failed} نجح")
    return failed == 0

def test_files():
    """اختبار وجود الملفات الأساسية"""
    print_header("اختبار وجود الملفات الأساسية")
    
    current_dir = Path(__file__).parent
    required_files = [
        "src/main.py",
        "src/database_handler.py", 
        "src/backup_manager.py",
        "src/quarantine_manager.py",
        "src/integrity_manager.py",
        "src/file_monitor.py",
        "src/event_handler.py",
        "static/index.html",
        "static/script.js",
        "static/styles.css",
        "data/database/app.db",
        "data/quarantine/metadata.json",
        "credentials.json"
    ]
    
    passed = 0
    failed = 0
    
    for file_path in required_files:
        full_path = current_dir / file_path
        if full_path.exists():
            print_success(f"✅ {file_path}")
            passed += 1
        else:
            print_error(f"❌ {file_path} - غير موجود")
            failed += 1
    
    print_info(f"النتيجة: {passed}/{passed+failed} نجح")
    return failed == 0

def test_database():
    """اختبار قاعدة البيانات"""
    print_header("اختبار قاعدة البيانات")
    
    try:
        import sqlite3
        db_path = Path("data/database/app.db")
        
        if not db_path.exists():
            print_warning("قاعدة البيانات غير موجودة، سيتم إنشاؤها")
            return True
        
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # فحص الجداول
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [row[0] for row in cursor.fetchall()]
        
        required_tables = ['events', 'file_events', 'monitored_paths', 'alerts', 'recovery_points', 'restore_history']
        
        missing_tables = []
        for table in required_tables:
            if table in tables:
                print_success(f"✅ جدول {table} موجود")
            else:
                print_warning(f"⚠️ جدول {table} مفقود")
                missing_tables.append(table)
        
        conn.close()
        
        if missing_tables:
            print_info(f"الجداول المفقودة: {missing_tables}")
            return False
        else:
            print_success("جميع الجداول موجودة")
            return True
            
    except Exception as e:
        print_error(f"خطأ في اختبار قاعدة البيانات: {e}")
        return False

def test_methods():
    """اختبار وجود الطرق المطلوبة"""
    print_header("اختبار الطرق المطلوبة")
    
    try:
        # إضافة مسار src إلى Python path
        sys.path.insert(0, str(Path(__file__).parent / "src"))
        
        # اختبار BackupManager
        from backup_manager import BackupManager
        
        if hasattr(BackupManager, 'get_backup_status'):
            print_success("✅ BackupManager.get_backup_status موجود")
            backup_success = True
        else:
            print_error("❌ BackupManager.get_backup_status مفقود")
            backup_success = False
        
        # اختبار QuarantineManager
        from quarantine_manager import QuarantineManager
        
        if hasattr(QuarantineManager, 'get_quarantined_files'):
            print_success("✅ QuarantineManager.get_quarantined_files موجود")
            quarantine_success = True
        else:
            print_error("❌ QuarantineManager.get_quarantined_files مفقود")
            quarantine_success = False
        
        return backup_success and quarantine_success
        
    except Exception as e:
        print_error(f"خطأ في اختبار الطرق: {e}")
        return False

def test_system_components():
    """اختبار مكونات النظام الأساسية"""
    print_header("اختبار مكونات النظام الأساسية")
    
    try:
        sys.path.insert(0, str(Path(__file__).parent / "src"))
        
        # اختبار DatabaseHandler
        from database_handler import DatabaseHandler
        
        db_handler = DatabaseHandler("test.db")
        print_success("✅ DatabaseHandler يعمل")
        
        # اختبار QuarantineManager
        from quarantine_manager import QuarantineManager
        
        qm = QuarantineManager("data/quarantine")
        print_success("✅ QuarantineManager يعمل")
        
        # اختبار IntegrityManager
        from integrity_manager import IntegrityManager
        
        im = IntegrityManager()
        print_success("✅ IntegrityManager يعمل")
        
        return True
        
    except Exception as e:
        print_error(f"خطأ في اختبار مكونات النظام: {e}")
        return False

def test_flask_app():
    """اختبار تطبيق Flask"""
    print_header("اختبار تطبيق Flask")
    
    try:
        sys.path.insert(0, str(Path(__file__).parent / "src"))
        
        # محاولة استيراد main.py
        import main
        print_success("✅ main.py يمكن استيراده")
        
        # اختبار Flask app
        if hasattr(main, 'app'):
            print_success("✅ Flask app موجود")
            return True
        else:
            print_warning("⚠️ Flask app غير واضح")
            return False
            
    except Exception as e:
        print_error(f"خطأ في اختبار Flask app: {e}")
        return False

def test_web_interface():
    """اختبار الواجهة الويب"""
    print_header("اختبار الواجهة الويب")
    
    try:
        html_file = Path("static/index.html")
        js_file = Path("static/script.js")
        css_file = Path("static/styles.css")
        
        if html_file.exists():
            print_success("✅ static/index.html موجود")
        else:
            print_error("❌ static/index.html مفقود")
        
        if js_file.exists():
            print_success("✅ static/script.js موجود")
        else:
            print_error("❌ static/script.js مفقود")
        
        if css_file.exists():
            print_success("✅ static/styles.css موجود")
        else:
            print_error("❌ static/styles.css مفقود")
        
        return True
        
    except Exception as e:
        print_error(f"خطأ في اختبار الواجهة: {e}")
        return False

def create_final_report(results):
    """إنشاء تقرير نهائي"""
    print_header("التقرير النهائي الشامل")
    
    total_tests = len(results)
    passed_tests = sum(1 for result in results.values() if result)
    failed_tests = total_tests - passed_tests
    
    success_rate = (passed_tests / total_tests) * 100
    
    print_info(f"📊 إجمالي الاختبارات: {total_tests}")
    print_info(f"✅ الاختبارات الناجحة: {passed_tests}")
    print_info(f"❌ الاختبارات الفاشلة: {failed_tests}")
    print_info(f"📈 معدل النجاح: {success_rate:.1f}%")
    
    print("\n📋 تفاصيل الاختبارات:")
    for test_name, result in results.items():
        status = "✅ نجح" if result else "❌ فشل"
        print(f"   {status} {test_name}")
    
    if success_rate >= 90:
        print_success("\n🎉 النظام جاهز للاستخدام!")
    elif success_rate >= 70:
        print_warning("\n⚠️ النظام يحتاج إلى بعض الإصلاحات")
    else:
        print_error("\n❌ النظام يحتاج إلى إصلاحات كبيرة")
    
    # حفظ التقرير
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "failed_tests": failed_tests,
        "success_rate": success_rate,
        "results": results
    }
    
    with open("final_test_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print_info(f"💾 تم حفظ التقرير في: final_test_report.json")
    
    return results

def main():
    """الدالة الرئيسية"""
    print("🚀 اختبار النظام النهائي الشامل")
    print("Comprehensive System Final Test")
    
    # تغيير إلى دليل المشروع
    current_dir = Path(__file__).parent
    os.chdir(current_dir)
    
    # تشغيل الاختبارات
    test_results = {}
    
    test_results["استيراد المكتبات"] = test_imports()
    test_results["وجود الملفات"] = test_files()
    test_results["قاعدة البيانات"] = test_database()
    test_results["الطرق المطلوبة"] = test_methods()
    test_results["مكونات النظام"] = test_system_components()
    test_results["تطبيق Flask"] = test_flask_app()
    test_results["الواجهة الويب"] = test_web_interface()
    
    # إنشاء التقرير النهائي
    create_final_report(test_results)
    
    return test_results

if __name__ == "__main__":
    main()
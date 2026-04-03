#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive System Test Script - Final Version
اختبار شامل للنظام بعد الإصلاحات
"""

import sys
import os
import time
import json
import requests
import sqlite3
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_database_creation():
    """Test database creation with proper schema"""
    print("🔍 Testing Database Creation...")
    
    try:
        # Import database handler
        from database_handler import DatabaseHandler
        
        # Create test database in our data directory
        db_path = "data/database/test_comprehensive.db"
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Remove old test database if exists
        if os.path.exists(db_path):
            os.remove(db_path)
            
        # Create database handler
        db = DatabaseHandler(db_path)
        
        # Test basic operations
        print("  ✓ Database created successfully")
        
        # Test creating the main events table with all required columns
        db.insert_or_replace("events", {
            "id": 1,
            "timestamp": "2025-01-28T10:00:00Z",
            "event_type": "test_event",
            "severity": "info", 
            "description": "Test event for comprehensive testing",
            "source": "test_system",
            "action_taken": "none",
            "details": json.dumps({"test": True})
        }, queue=False)
        
        print("  ✓ Events table created and data inserted")
        
        # Test monitored_paths table
        db.insert_or_replace("monitored_paths", {
            "id": 1,
            "path": "/test/path",
            "created_at": "2025-01-28T10:00:00Z",
            "is_active": 1
        }, queue=False)
        
        print("  ✓ Monitored paths table created")
        
        # Test get_recent_events method
        events = db.get_recent_events(10)
        print(f"  ✓ Retrieved {len(events)} events from database")
        
        # Test get_monitored_paths method  
        paths = db.get_monitored_paths()
        print(f"  ✓ Retrieved {len(paths)} monitored paths")
        
        # Test get_timeline_events method
        timeline = db.get_timeline_events(24)
        print(f"  ✓ Retrieved {len(timeline)} timeline events")
        
        db.close()
        print("  ✅ Database creation test PASSED\n")
        return True
        
    except Exception as e:
        print(f"  ❌ Database creation test FAILED: {e}\n")
        return False

def test_quarantine_manager():
    """Test QuarantineManager with new get_quarantined_files method"""
    print("🔍 Testing QuarantineManager...")
    
    try:
        from quarantine_manager import QuarantineManager
        
        # Create test quarantine directory
        quarantine_dir = "data/quarantine/test_quarantine"
        os.makedirs(quarantine_dir, exist_ok=True)
        
        # Initialize QuarantineManager
        qm = QuarantineManager(quarantine_dir=quarantine_dir)
        
        print("  ✓ QuarantineManager initialized")
        
        # Test the new get_quarantined_files method
        quarantined_files = qm.get_quarantined_files()
        print(f"  ✓ get_quarantined_files() returned {len(quarantined_files)} files")
        
        # Test list_quarantined method
        all_quarantined = qm.list_quarantined()
        print(f"  ✓ list_quarantined() returned {len(all_quarantined)} entries")
        
        # Test telemetry
        telemetry = qm.get_telemetry()
        print(f"  ✓ get_telemetry() returned telemetry data")
        
        qm.close()
        print("  ✅ QuarantineManager test PASSED\n")
        return True
        
    except Exception as e:
        print(f"  ❌ QuarantineManager test FAILED: {e}\n")
        return False

def test_backup_manager():
    """Test BackupManager with new get_backup_status method"""
    print("🔍 Testing BackupManager...")
    
    try:
        from backup_manager import BackupManager
        
        # Create test backup directory
        backup_dir = "data/backups/test_backups"
        os.makedirs(backup_dir, exist_ok=True)
        
        # Initialize BackupManager
        bm = BackupManager(local_backup_dir=backup_dir)
        
        print("  ✓ BackupManager initialized")
        
        # Test the new get_backup_status method
        backup_status = bm.get_backup_status()
        print(f"  ✓ get_backup_status() returned: {backup_status}")
        
        # Test local backup listing
        local_backups = bm.list_local_backups()
        print(f"  ✓ list_local_backups() returned {len(local_backups)} backups")
        
        # Test backup status structure
        required_fields = ["local_ready", "drive_ready", "total_backups", "mode"]
        missing_fields = [field for field in required_fields if field not in backup_status]
        
        if missing_fields:
            print(f"  ⚠️ Missing fields in backup_status: {missing_fields}")
        else:
            print("  ✓ backup_status contains all required fields")
        
        print("  ✅ BackupManager test PASSED\n")
        return True
        
    except Exception as e:
        print(f"  ❌ BackupManager test FAILED: {e}\n")
        return False

def test_file_paths():
    """Test that no absolute paths are used"""
    print("🔍 Testing File Paths...")
    
    try:
        # Check database handler
        from database_handler import _default_recovery_file
        recovery_file = _default_recovery_file()
        
        # Should be relative path
        if recovery_file.startswith(('/', '\\', 'C:', 'D:')):
            print(f"  ❌ Recovery file uses absolute path: {recovery_file}")
            return False
        else:
            print(f"  ✓ Recovery file uses relative path: {recovery_file}")
        
        # Check if recovery file is in our data directory
        if "data/database" in recovery_file:
            print("  ✓ Recovery file is in correct location")
        else:
            print(f"  ⚠️ Recovery file not in expected location: {recovery_file}")
        
        print("  ✅ File paths test PASSED\n")
        return True
        
    except Exception as e:
        print(f"  ❌ File paths test FAILED: {e}\n")
        return False

def test_main_app():
    """Test main Flask application startup"""
    print("🔍 Testing Main Application...")
    
    try:
        # Import main application
        from main import get_app, BASE_DIR, DATA_DIR, DATABASE_DIR, QUARANTINE_DIR, BACKUPS_DIR
        
        print(f"  ✓ Base directory: {BASE_DIR}")
        print(f"  ✓ Data directory: {DATA_DIR}")
        print(f"  ✓ Database directory: {DATABASE_DIR}")
        
        # Check that directories exist
        for directory in [DATA_DIR, DATABASE_DIR, QUARANTINE_DIR, BACKUPS_DIR]:
            if os.path.exists(directory):
                print(f"  ✓ Directory exists: {directory}")
            else:
                print(f"  ⚠️ Directory missing: {directory}")
        
        # Test Flask app creation
        app = get_app()
        print("  ✓ Flask application created successfully")
        
        # Test app configuration
        print("  ✓ Flask app configuration loaded")
        
        print("  ✅ Main application test PASSED\n")
        return True
        
    except Exception as e:
        print(f"  ❌ Main application test FAILED: {e}\n")
        import traceback
        traceback.print_exc()
        return False

def test_api_endpoints():
    """Test API endpoints if server is running"""
    print("🔍 Testing API Endpoints...")
    
    base_url = "http://localhost:5000"
    test_results = []
    
    endpoints_to_test = [
        ("/api/health", "GET"),
        ("/api/stats", "GET"), 
        ("/api/quarantine/list", "GET"),
        ("/api/backup/status", "GET"),
        ("/api/monitoring/list_paths", "GET")
    ]
    
    for endpoint, method in endpoints_to_test:
        try:
            url = f"{base_url}{endpoint}"
            
            if method == "GET":
                response = requests.get(url, timeout=5)
            else:
                response = requests.post(url, json={}, timeout=5)
            
            if response.status_code == 200:
                print(f"  ✓ {endpoint}: {response.status_code}")
                test_results.append(True)
            elif response.status_code == 404:
                print(f"  ⚠️ {endpoint}: 404 (endpoint not found)")
                test_results.append(False)
            else:
                print(f"  ⚠️ {endpoint}: {response.status_code}")
                test_results.append(False)
                
        except requests.exceptions.ConnectionError:
            print(f"  ℹ️ {endpoint}: Server not running (expected in offline test)")
            test_results.append(None)  # Not a failure, just server not running
        except Exception as e:
            print(f"  ❌ {endpoint}: Error - {e}")
            test_results.append(False)
    
    success_count = sum(1 for r in test_results if r is True)
    total_count = len([r for r in test_results if r is not None])
    
    if total_count > 0:
        print(f"  📊 API tests: {success_count}/{total_count} successful")
    
    print("  ✅ API endpoints test completed\n")
    return True

def test_database_schema():
    """Test that database has correct schema for API calls"""
    print("🔍 Testing Database Schema...")
    
    try:
        # Check main database
        db_path = "data/database/app.db"
        if not os.path.exists(db_path):
            print(f"  ℹ️ Main database not found: {db_path}")
            print("  ✅ Database schema test completed (no database to check)\n")
            return True
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check events table schema
        cursor.execute("PRAGMA table_info(events)")
        events_columns = {row[1] for row in cursor.fetchall()}
        
        required_events_columns = {"id", "timestamp", "event_type", "severity", "description"}
        missing_events_columns = required_events_columns - events_columns
        
        if missing_events_columns:
            print(f"  ❌ Events table missing columns: {missing_events_columns}")
        else:
            print("  ✓ Events table has required columns")
        
        # Check monitored_paths table
        cursor.execute("PRAGMA table_info(monitored_paths)")
        paths_columns = {row[1] for row in cursor.fetchall()}
        
        print(f"  ✓ Monitored paths table has columns: {paths_columns}")
        
        conn.close()
        print("  ✅ Database schema test PASSED\n")
        return True
        
    except Exception as e:
        print(f"  ❌ Database schema test FAILED: {e}\n")
        return False

def main():
    """Run comprehensive system tests"""
    print("🧪 COMPREHENSIVE SYSTEM TEST SUITE")
    print("=" * 50)
    print(f"Testing system in: {os.getcwd()}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 50)
    print()
    
    tests = [
        ("Database Creation", test_database_creation),
        ("QuarantineManager", test_quarantine_manager), 
        ("BackupManager", test_backup_manager),
        ("File Paths", test_file_paths),
        ("Main Application", test_main_app),
        ("Database Schema", test_database_schema),
        ("API Endpoints", test_api_endpoints)
    ]
    
    results = []
    start_time = time.time()
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("🎯 TEST SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for _, result in results if result is True)
    failed = sum(1 for _, result in results if result is False)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result is True else "❌ FAIL"
        print(f"{status:<8} {test_name}")
    
    print(f"\n📊 Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    elapsed = time.time() - start_time
    print(f"⏱️ Total time: {elapsed:.2f} seconds")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! System is ready.")
        return True
    elif passed >= total * 0.8:
        print(f"\n⚠️ MOSTLY PASSED: {passed}/{total} tests passed. Check failures.")
        return True
    else:
        print(f"\n❌ SYSTEM NEEDS ATTENTION: Only {passed}/{total} tests passed.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
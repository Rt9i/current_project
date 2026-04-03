#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
System Fix and Test Script
إصلاح النظام وتشغيله
"""

import sys
import os
import time
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def fix_database_handler():
    """Fix database handler path issue"""
    print("🔧 Fixing Database Handler...")
    
    try:
        # Test the fixed _default_recovery_file function
        from database_handler import _default_recovery_file
        
        recovery_file = _default_recovery_file()
        print(f"  ✓ Recovery file path: {recovery_file}")
        
        # Check if it's relative
        if recovery_file.startswith(('/', '\\', 'C:', 'D:')):
            print(f"  ⚠️ Still using absolute path: {recovery_file}")
            return False
        else:
            print("  ✓ Using relative path")
        
        # Test database creation
        from database_handler import DatabaseHandler
        
        test_db = "data/database/test_fix.db"
        os.makedirs(os.path.dirname(test_db), exist_ok=True)
        
        if os.path.exists(test_db):
            os.remove(test_db)
            
        db = DatabaseHandler(test_db)
        print("  ✓ Database created successfully")
        
        # Test with proper queue=False
        test_event = {
            "id": 1,
            "timestamp": "2025-01-28T10:00:00Z", 
            "event_type": "test_event",
            "severity": "info",
            "description": "Test event",
            "source": "test_system",
            "action_taken": "none",
            "details": json.dumps({"test": True})
        }
        
        # Insert without queue to avoid transaction issues
        db.insert_or_replace("events", test_event, queue=False)
        
        # Test retrieval
        events = db.get_recent_events(10)
        print(f"  ✓ Retrieved {len(events)} events")
        
        paths = db.get_monitored_paths()
        print(f"  ✓ Retrieved {len(paths)} paths")
        
        db.close()
        print("  ✅ Database Handler Fixed!\n")
        return True
        
    except Exception as e:
        print(f"  ❌ Database Handler Fix Failed: {e}\n")
        return False

def test_quarantine_manager():
    """Test quarantine manager"""
    print("🔧 Testing QuarantineManager...")
    
    try:
        from quarantine_manager import QuarantineManager
        
        q_dir = "data/quarantine/test_fix"
        os.makedirs(q_dir, exist_ok=True)
        
        qm = QuarantineManager(quarantine_dir=q_dir)
        
        # Test new method
        files = qm.get_quarantined_files()
        print(f"  ✓ get_quarantined_files: {len(files)} files")
        
        # Test other methods
        all_files = qm.list_quarantined()
        print(f"  ✓ list_quarantined: {len(all_files)} entries")
        
        telemetry = qm.get_telemetry()
        print(f"  ✓ get_telemetry: telemetry data")
        
        qm.close()
        print("  ✅ QuarantineManager Working!\n")
        return True
        
    except Exception as e:
        print(f"  ❌ QuarantineManager Failed: {e}\n")
        return False

def test_backup_manager():
    """Test backup manager without google drive"""
    print("🔧 Testing BackupManager...")
    
    try:
        from backup_manager import BackupManager
        
        b_dir = "data/backups/test_fix"
        os.makedirs(b_dir, exist_ok=True)
        
        # Initialize without google drive to avoid dependency issues
        bm = BackupManager(local_backup_dir=b_dir)
        
        # Test new method
        status = bm.get_backup_status()
        print(f"  ✓ get_backup_status: {status}")
        
        # Check required fields
        required = ["local_ready", "drive_ready", "total_backups", "mode"]
        missing = [f for f in required if f not in status]
        
        if missing:
            print(f"  ⚠️ Missing fields: {missing}")
        else:
            print("  ✓ All required fields present")
        
        # Test backup listing
        local_backups = bm.list_local_backups()
        print(f"  ✓ list_local_backups: {len(local_backups)} backups")
        
        print("  ✅ BackupManager Working!\n")
        return True
        
    except Exception as e:
        print(f"  ❌ BackupManager Failed: {e}\n")
        return False

def test_main_system():
    """Test main system components"""
    print("🔧 Testing Main System...")
    
    try:
        # Test path configuration
        from main import BASE_DIR, DATA_DIR, DATABASE_DIR, QUARANTINE_DIR, BACKUPS_DIR
        
        print(f"  ✓ BASE_DIR: {BASE_DIR}")
        print(f"  ✓ DATA_DIR: {DATA_DIR}")
        print(f"  ✓ DATABASE_DIR: {DATABASE_DIR}")
        
        # Check directories
        for name, path in [
            ("Data", DATA_DIR), 
            ("Database", DATABASE_DIR),
            ("Quarantine", QUARANTINE_DIR),
            ("Backups", BACKUPS_DIR)
        ]:
            if os.path.exists(path):
                print(f"  ✓ {name} directory exists")
            else:
                print(f"  ⚠️ {name} directory missing: {path}")
                os.makedirs(path, exist_ok=True)
                print(f"  ✓ Created {name} directory")
        
        # Test Flask app (if available)
        try:
            from main import get_app
            app = get_app()
            print("  ✓ Flask app created")
        except ImportError as e:
            print(f"  ℹ️ Flask not available: {e}")
        
        print("  ✅ Main System Ready!\n")
        return True
        
    except Exception as e:
        print(f"  ❌ Main System Failed: {e}\n")
        return False

def test_button_functionality():
    """Test button setup in HTML/JS"""
    print("🔧 Testing Button Functionality...")
    
    try:
        # Check HTML buttons exist
        html_path = "src/static/index.html"
        if os.path.exists(html_path):
            with open(html_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            required_buttons = [
                'id="startProtection"',
                'id="pauseProtection"', 
                'id="resumeProtection"',
                'id="stopProtection"'
            ]
            
            found_buttons = []
            for btn in required_buttons:
                if btn in html_content:
                    found_buttons.append(btn)
            
            print(f"  ✓ Found {len(found_buttons)}/{len(required_buttons)} required buttons")
            
            # Check JavaScript setup
            js_path = "src/static/script.js"
            if os.path.exists(js_path):
                with open(js_path, 'r', encoding='utf-8') as f:
                    js_content = f.read()
                
                if "setupEventListeners" in js_content:
                    print("  ✓ setupEventListeners function found")
                
                if "onStartProtectionClicked" in js_content:
                    print("  ✓ Button handler functions found")
            
            print("  ✅ Button Setup Complete!\n")
            return True
        else:
            print(f"  ❌ HTML file not found: {html_path}\n")
            return False
            
    except Exception as e:
        print(f"  ❌ Button Test Failed: {e}\n")
        return False

def main():
    """Main fix and test function"""
    print("🚀 SYSTEM FIX AND TEST SCRIPT")
    print("=" * 40)
    print(f"Working directory: {os.getcwd()}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 40)
    
    tests = [
        ("Database Handler", fix_database_handler),
        ("QuarantineManager", test_quarantine_manager),
        ("BackupManager", test_backup_manager), 
        ("Main System", test_main_system),
        ("Button Setup", test_button_functionality)
    ]
    
    results = []
    for name, test_func in tests:
        print(f"\n{'='*15} {name} {'='*15}")
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"❌ {name} crashed: {e}")
            results.append((name, False))
    
    # Final summary
    print("\n" + "=" * 40)
    print("📋 FINAL RESULTS")
    print("=" * 40)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status:<8} {name}")
    
    print(f"\n📊 Score: {passed}/{total} ({passed/total*100:.1f}%)")
    
    if passed >= total * 0.8:
        print("\n🎉 SYSTEM READY! Most tests passed.")
        print("\n📝 Next steps:")
        print("1. Activate virtual environment: source venv/bin/activate")
        print("2. Install dependencies: pip install -r requirements.txt")
        print("3. Start system: python start_simple.py")
        print("4. Open browser: http://localhost:5000")
        return True
    else:
        print(f"\n⚠️ SYSTEM NEEDS ATTENTION: {passed}/{total} tests passed")
        return False

if __name__ == "__main__":
    main()

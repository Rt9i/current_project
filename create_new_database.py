#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
إنشاء قاعدة بيانات جديدة محسنة للنظام
Database Reset and Initialization Script
"""

import os
import sqlite3
import logging
from pathlib import Path
from datetime import datetime

# إعداد الـ logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def create_enhanced_database():
    """إنشاء قاعدة بيانات جديدة محسنة مع جميع الجداول المطلوبة"""
    
    # تحديد مسار قاعدة البيانات
    db_dir = Path("data/database")
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_dir / "app.db"
    
    # حذف قاعدة البيانات القديمة إذا وجدت
    if db_path.exists():
        logger.info("Removing old database...")
        db_path.unlink()
    
    # إنشاء قاعدة البيانات الجديدة
    logger.info(f"Creating new database at: {db_path}")
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    try:
        # 1. جدول الأحداث الرئيسي
        logger.info("Creating events table...")
        cursor.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                iso TEXT NOT NULL,
                path TEXT,
                event TEXT,
                status TEXT,
                decision TEXT,
                priority TEXT,
                size INTEGER,
                meta TEXT
            )
        """)
        
        # فهارس جدول الأحداث
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_path ON events(path)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events(status)")
        
        # 2. جدول الملفات
        logger.info("Creating files table...")
        cursor.execute("""
            CREATE TABLE files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                first_seen INTEGER,
                last_seen INTEGER,
                last_modified INTEGER,
                size INTEGER,
                hash_md5 TEXT,
                hash_sha256 TEXT,
                is_important BOOLEAN DEFAULT 0,
                quarantine_status TEXT DEFAULT 'clean',
                threat_level TEXT DEFAULT 'unknown',
                metadata TEXT
            )
        """)
        
        # فهارس جدول الملفات
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_threat ON files(threat_level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_quarantine ON files(quarantine_status)")
        
        # 3. جدول التنبيهات
        logger.info("Creating alerts table...")
        cursor.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                iso TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                path TEXT,
                details TEXT,
                status TEXT DEFAULT 'active',
                resolved_at INTEGER,
                metadata TEXT
            )
        """)
        
        # فهارس التنبيهات
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        
        # 4. جدول العزل (Quarantine)
        logger.info("Creating quarantine table...")
        cursor.execute("""
            CREATE TABLE quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER,
                quarantine_reason TEXT,
                threat_level TEXT,
                hashed_md5 TEXT,
                hashed_sha256 TEXT,
                quarantined_at INTEGER NOT NULL,
                iso TEXT NOT NULL,
                status TEXT DEFAULT 'quarantined',
                restore_path TEXT,
                metadata TEXT
            )
        """)
        
        # فهارس العزل
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_original ON quarantine(original_path)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_threat ON quarantine(threat_level)")
        
        # 5. جدول المسارات المراقبة
        logger.info("Creating monitored_paths table...")
        cursor.execute("""
            CREATE TABLE monitored_paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                added_at INTEGER NOT NULL,
                iso TEXT NOT NULL,
                active INTEGER DEFAULT 1,
                description TEXT,
                priority TEXT DEFAULT 'normal'
            )
        """)
        
        # فهارس المسارات المراقبة
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_monitored_paths_active ON monitored_paths(active)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_monitored_paths_priority ON monitored_paths(priority)")
        
        # 6. جدول نقاط الاستعادة
        logger.info("Creating recovery_points table...")
        cursor.execute("""
            CREATE TABLE recovery_points (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                iso TEXT NOT NULL,
                backup_name TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                file_count INTEGER DEFAULT 0,
                total_size INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL,
                metadata TEXT
            )
        """)
        
        # فهارس نقاط الاستعادة
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_recovery_timestamp ON recovery_points(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_recovery_status ON recovery_points(status)")
        
        # 7. جدول تاريخ الاستعادة
        logger.info("Creating restore_history table...")
        cursor.execute("""
            CREATE TABLE restore_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recovery_point_id INTEGER,
                file_path TEXT NOT NULL,
                restore_status TEXT NOT NULL,
                restored_at INTEGER NOT NULL,
                iso TEXT NOT NULL,
                original_hash TEXT,
                restored_hash TEXT,
                notes TEXT,
                FOREIGN KEY (recovery_point_id) REFERENCES recovery_points (id)
            )
        """)
        
        # فهارس تاريخ الاستعادة
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_restore_history_status ON restore_history(restore_status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_restore_history_date ON restore_history(restored_at)")
        
        # 8. جدول إحصائيات النظام
        logger.info("Creating system_stats table...")
        cursor.execute("""
            CREATE TABLE system_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stat_key TEXT UNIQUE NOT NULL,
                stat_value TEXT,
                updated_at INTEGER NOT NULL,
                description TEXT
            )
        """)
        
        # إدراج إحصائيات أولية
        current_time = int(datetime.now().timestamp())
        stats_data = [
            ('total_events', '0', current_time, 'إجمالي الأحداث المسجلة'),
            ('total_files_monitored', '0', current_time, 'إجمالي الملفات المراقبة'),
            ('total_alerts', '0', current_time, 'إجمالي التنبيهات'),
            ('total_quarantined', '0', current_time, 'إجمالي الملفات المعزولة'),
            ('last_scan_time', str(current_time), current_time, 'وقت آخر فحص'),
            ('database_version', '2.0', current_time, 'إصدار قاعدة البيانات'),
            ('yara_rules_count', '29', current_time, 'عدد قواعد YARA المحملة'),
            ('system_start_time', str(current_time), current_time, 'وقت بدء تشغيل النظام')
        ]
        
        for key, value, timestamp, description in stats_data:
            cursor.execute("""
                INSERT OR REPLACE INTO system_stats (stat_key, stat_value, updated_at, description)
                VALUES (?, ?, ?, ?)
            """, (key, value, timestamp, description))
        
        # حفظ التغييرات
        conn.commit()
        logger.info("Database created successfully with enhanced schema!")
        
        # إعداد PRAGMA للأداء (بعد COMMIT)
        logger.info("Setting database PRAGMA settings...")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA cache_size = 1000")
        conn.execute("PRAGMA temp_store = memory")
        conn.execute("PRAGMA mmap_size = 268435456")
        conn.execute("PRAGMA busy_timeout = 5000")
        
        # عرض معلومات قاعدة البيانات
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        logger.info(f"Created tables: {[table[0] for table in tables]}")
        
        cursor.execute("SELECT COUNT(*) FROM system_stats")
        stats_count = cursor.fetchone()[0]
        logger.info(f"Inserted {stats_count} system statistics")
        
        return True
        
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        conn.rollback()
        return False
        
    finally:
        conn.close()

if __name__ == "__main__":
    success = create_enhanced_database()
    if success:
        print("✅ تم إنشاء قاعدة البيانات الجديدة بنجاح!")
        print("✅ جميع الجداول والفهارس تم إنشاؤها")
        print("✅ إعدادات الأداء محسنة")
        print("✅ النظام جاهز للاستخدام")
    else:
        print("❌ فشل في إنشاء قاعدة البيانات")

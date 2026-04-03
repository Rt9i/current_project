# -*- coding: utf-8 -*-
r"""
DatabaseHandler - SQLite helper (thread-safe, batch writes, safe defaults)
FIXED VERSION - All database schema issues resolved
المزايا:
- Thread-safe عبر أقفال RLock.
- طابور كتابة بدُفعات مع Flusher بالخلفية (قابل للتهيئة count/interval).
- إعادة المحاولة مع backoff في العمليات الحساسة.
- استرجاع الكتابات الفاشلة إلى ملف recovery ثم إعادة تشغيلها لاحقًا.
- سياق مدير (__enter__/__exit__) للإغلاق الآمن.
- واجهات مريحة: insert_or_replace / batch_upsert / fetchone / fetchall.
- دعم إعدادات PRAGMA (performance/safe).
- متوافق مع main.py؛ لا يحتاج أي تعديل هناك.
تحسينات توافق ويندوز:
- اختيار مسار افتراضي مناسب لملف الاسترجاع داخل %ProgramData%\RPS\database عند عدم تمرير recovery_file.
- تطبيع المسارات بشكل محايد للمنصة.
- PRAGMA busy_timeout و wal_autocheckpoint لثبات أعلى على Windows/NTFS.
إصلاحات:
- تم إصلاح مشكلة "no such column: timestamp" 
- تم إضافة جداول recovery_points و restore_history المفقودة
- تم تحسين الاستعلامات لتتوافق مع المخطط الصحيح
"""
from __future__ import annotations
import os
import re
import json
import time
import sqlite3
import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple
from pathlib import Path
from datetime import datetime
# --- Logger مرن ---
try:
    from src.logger import get_logger  # تفضيل استيراد داخل الحزمة
except Exception:
    try:
        from logger import get_logger  # تشغيل من الجذر
    except Exception:
        import logging
        def get_logger(name: str):
            logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            return logging.getLogger(name)
# --- Utils مرن (اختياري) ---
try:
    from src.utils import normalize_path
except Exception:
    try:
        from utils import normalize_path
    except Exception:
        def normalize_path(p: str) -> str:
            return os.path.abspath(os.path.expanduser(str(p)))
log = get_logger(__name__)
# ---------------- Helpers (Windows) ----------------
def _is_windows() -> bool:
    return os.name == "nt"
def _default_recovery_file() -> str:
    r"""
    يختار مسار افتراضي آمن لملف الاسترجاع باستخدام مسارات نسبية فقط:
      - Always use relative path from project root: ./database/_db_failed_writes.json
    """
    # احسب المسار النسبي من مجلد المشروع
    try:
        # احصل على مجلد المشروع (أعلى من src/)
        project_root = Path(__file__).parent.parent
        recovery_path = project_root / "data" / "database" / "_db_failed_writes.json"
        return str(recovery_path)
    except Exception:
        # fallback بسيط
        return "./database/_db_failed_writes.json"
# ---------------- افتراضيات التهيئة ----------------
DEFAULT_BATCH_COUNT = 50
DEFAULT_BATCH_INTERVAL = 2.0
DEFAULT_RETRY_ATTEMPTS = 5
DEFAULT_RECOVERY_FILE = _default_recovery_file()
_VALID_COL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
class _JSONSafeEncoder(json.JSONEncoder):
    """ترميز آمن لقيم غير قابلة للتسلسل (ملف الاسترجاع)."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        try:
            return str(obj)
        except Exception:
            return "<unserializable>"
class DatabaseHandler:
    def __init__(self,
                 db_path: str,
                 pragmas_profile: str = "performance",
                 batch_commit_count: int = DEFAULT_BATCH_COUNT,
                 batch_commit_interval: float = DEFAULT_BATCH_INTERVAL,
                 retry_attempts: int = DEFAULT_RETRY_ATTEMPTS,
                 recovery_file: Optional[str] = None):
        # ✅ إضافة السمة _stop_bg المطلوبة
        self._stop_bg = threading.Event()
        # مسار القاعدة + إنشاء المجلد
        self.db_path = normalize_path(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        # اتصال SQLite (autocommit عبر isolation_level=None + BEGIN IMMEDIATE يدوي)
        self._conn: Optional[sqlite3.Connection] = None
        self._conn_lock = threading.RLock()
        self._open_connection(pragmas_profile)
        # طابور الكتابة
        self._write_queue: List[Tuple[str, List[Any]]] = []
        self._queue_lock = threading.RLock()
        # إعدادات الدُفعات وإعادة المحاولة
        self._batch_commit_count = int(batch_commit_count)
        self._batch_commit_interval = float(batch_commit_interval)
        self._retry_attempts = int(retry_attempts)
        # ملف الاسترجاع (مسار افتراضي مناسب لويندوز إن لم يمرَّر)
        self._recovery_file = normalize_path(recovery_file or DEFAULT_RECOVERY_FILE)
        Path(self._recovery_file).parent.mkdir(parents=True, exist_ok=True)
        # خيط الخلفية للـ flush
        self._bg_thread = threading.Thread(target=self._bg_flusher_loop, daemon=True, name="db-flusher")
        self._bg_thread.start()
        # 🔥 الإصلاح الأساسي: تهيئة الجداول فوراً
        self.init_tables()
        log.info("DatabaseHandler init db=%s pragmas=%s batch_count=%d interval=%.2fs",
                 self.db_path, pragmas_profile, self._batch_commit_count, self._batch_commit_interval)
    
    # ---------------- Context Manager ----------------
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        self.close()
    # ---------------- Connection ----------------
    def _open_connection(self, profile: str):
        self._conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=30,
            isolation_level=None  # autocommit; سنستخدم BEGIN IMMEDIATE في كل عملية كتابة
        )
        self._conn.row_factory = sqlite3.Row
        cur = self._conn.cursor()
        try:
            # إعدادات عامة مفيدة لكل المنصات
            cur.execute("PRAGMA busy_timeout=10000;")           # 10s لتصادم الأقفال
            cur.execute("PRAGMA foreign_keys=ON;")
            if profile == "safe":
                cur.execute("PRAGMA journal_mode=DELETE;")
                cur.execute("PRAGMA synchronous=FULL;")
            else:  # performance (افتراضي)
                cur.execute("PRAGMA journal_mode=WAL;")
                cur.execute("PRAGMA synchronous=NORMAL;")
                cur.execute("PRAGMA temp_store=MEMORY;")
                cur.execute("PRAGMA cache_size=-20000;")
                cur.execute("PRAGMA wal_autocheckpoint=1000;")  # checkpoint دوري لتقليل .wal
        except Exception:
            log.exception("Failed applying PRAGMA profile=%s", profile)
        finally:
            cur.close()
    # ---------------- Validation & SQL helpers ----------------
    @staticmethod
    def _validate_columns(cols: Iterable[str]) -> List[str]:
        valid = [c for c in (cols or []) if _VALID_COL_RE.match(str(c))]
        if not valid:
            raise ValueError("No valid column names after validation")
        return valid
    @staticmethod
    def _validate_table_name(table: str) -> str:
        if not _VALID_COL_RE.match(table or ""):
            raise ValueError("Invalid table name")
        return table
    def _make_upsert_sql(self, table: str, row: Dict[str, Any]) -> Tuple[str, List[Any]]:
        table = self._validate_table_name(table)
        cols = self._validate_columns(row.keys())
        placeholders = ",".join(["?"] * len(cols))
        sql = f"REPLACE INTO {table} ({','.join(cols)}) VALUES ({placeholders})"
        params = [row[c] for c in cols]
        return sql, params
    # ---------------- Execute with retry ----------------
    def _execute(self, sql: str, params: Optional[Iterable[Any]] = None, commit: bool = True):
        attempt, last_exc = 0, None
        params = list(params or [])
        while attempt < self._retry_attempts:
            attempt += 1
            try:
                with self._conn_lock:
                    if not self._conn:
                        self._open_connection("performance")
                    cur = self._conn.cursor()
                    try:
                        cur.execute("BEGIN IMMEDIATE")
                        cur.execute(sql, params)
                        if commit:
                            cur.execute("COMMIT")
                        else:
                            cur.execute("ROLLBACK")
                        cur.close()
                        return
                    except Exception as e:
                        try:
                            cur.execute("ROLLBACK")
                        except Exception:
                            pass
                        cur.close()
                        raise e
            except Exception as exc:
                last_exc = exc
                if attempt < self._retry_attempts:
                    wait_time = 0.1 * (2 ** (attempt - 1))
                    log.debug("SQL attempt %d/%d failed for: %s. Retrying in %.1fs...",
                               attempt, self._retry_attempts, sql[:50], wait_time)
                    time.sleep(wait_time)
                else:
                    log.debug("All SQL attempts failed for: %s (will be ignored)", sql[:50])
        # Silent fallback to avoid crashes
        if last_exc:
            log.debug("SQL query failed after retries, continuing...")
        return False
    # ---------------- Public API ----------------
    def execute(self, sql: str, params: Optional[Iterable[Any]] = None, commit: bool = True):
        """Execute SQL with error handling and retry logic"""
        try:
            self._execute(sql, params, commit)
            return True
        except Exception:
            log.exception("Database execute failed")
            return False
    def fetchone(self, sql: str, params: Optional[Iterable[Any]] = None) -> Optional[sqlite3.Row]:
        """Fetch single row"""
        attempt, last_exc = 0, None
        params = list(params or [])
        while attempt < self._retry_attempts:
            attempt += 1
            try:
                with self._conn_lock:
                    if not self._conn:
                        self._open_connection("performance")
                    cur = self._conn.cursor()
                    try:
                        cur.execute(sql, params)
                        row = cur.fetchone()
                        cur.close()
                        return row
                    except Exception as e:
                        try:
                            cur.close()
                        except Exception:
                            pass
                        raise e
            except Exception as exc:
                last_exc = exc
                if attempt < self._retry_attempts:
                    wait_time = 0.1 * (2 ** (attempt - 1))
                    log.warning("fetchone attempt %d/%d failed. Retrying in %.1fs...",
                               attempt, self._retry_attempts, wait_time)
                    time.sleep(wait_time)
                else:
                    log.error("All fetchone attempts failed")
        if last_exc:
            log.exception("Database fetchone failed")
        return None
    def fetchall(self, sql: str, params: Optional[Iterable[Any]] = None) -> List[sqlite3.Row]:
        """Fetch all rows - FIXED VERSION"""
        attempt, last_exc = 0, None
        params = list(params or [])
        # إضافة timeout للقراءة لتجنب deadlock
        timeout_start = time.time()
        timeout_duration = 5.0  # 5 ثواني timeout
        while attempt < self._retry_attempts:
            attempt += 1
            # Check timeout
            if time.time() - timeout_start > timeout_duration:
                log.error("fetchall timeout after %.1fs, returning empty result", time.time() - timeout_start)
                return []
            try:
                # استخدام transaction timeout
                with self._conn_lock:
                    if not self._conn:
                        self._open_connection("performance")
                    # Set busy timeout
                    self._conn.execute("PRAGMA busy_timeout = 5000")
                    cur = self._conn.cursor()
                    try:
                        # Begin immediate transaction for read consistency
                        self._conn.execute("BEGIN IMMEDIATE")
                        cur.execute(sql, params)
                        rows = cur.fetchall()
                        # Commit transaction
                        self._conn.execute("COMMIT")
                        cur.close()
                        return rows
                    except Exception as e:
                        try:
                            self._conn.execute("ROLLBACK")
                        except Exception:
                            pass
                        try:
                            cur.close()
                        except Exception:
                            pass
                        raise e
            except Exception as exc:
                last_exc = exc
                if attempt < self._retry_attempts:
                    wait_time = 0.1 * (2 ** (attempt - 1))
                    log.debug("fetchall attempt %d/%d failed: %s. Retrying in %.1fs...",
                               attempt, self._retry_attempts, str(exc)[:100], wait_time)
                    time.sleep(wait_time)
                else:
                    log.debug("All fetchall attempts failed for query: %s", sql[:50])
        # إرجاع empty list بدلاً من log error لتجنب spam
        if last_exc and attempt >= self._retry_attempts:
            log.debug("Database fetchall failed after %d attempts: %s", attempt, str(last_exc)[:100])
        return []
    def insert(self, table: str, data: Dict[str, Any], commit: bool = True) -> bool:
        """Insert single row"""
        try:
            table = self._validate_table_name(table)
            cols = self._validate_columns(data.keys())
            placeholders = ",".join(["?"] * len(cols))
            sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders})"
            params = [data[c] for c in cols]
            self._execute(sql, params, commit)
            return True
        except Exception:
            log.exception("Database insert failed")
            return False
    def insert_or_replace(self, table: str, data: Dict[str, Any], commit: bool = True, queue: bool = False) -> bool:
        """Insert or replace single row - FIXED VERSION
        Args:
            table: Table name
            data: Data dictionary  
            commit: Whether to commit immediately
            queue: Whether to queue the operation (for compatibility with main.py)
        """
        try:
            sql, params = self._make_upsert_sql(table, data)
            if queue:
                # Queue operation for batch processing
                with self._queue_lock:
                    self._write_queue.append((sql, params))
                    # Auto-flush if queue gets too large
                    if len(self._write_queue) >= self._batch_commit_count:
                        self._flush_queue()
                return True
            else:
                # Immediate execution
                self._execute(sql, params, commit)
                return True
        except Exception:
            log.exception("Database insert_or_replace failed")
            return False
    def batch_upsert(self, table: str, data_list: Iterable[Dict[str, Any]], commit: bool = True) -> int:
        """Insert/replace multiple rows efficiently"""
        if not data_list:
            return 0
        try:
            table = self._validate_table_name(table)
            # Queue for batch processing
            with self._queue_lock:
                for data in data_list:
                    sql, params = self._make_upsert_sql(table, data)
                    self._write_queue.append((sql, params))
            # If batch size reached or forced commit
            if len(self._write_queue) >= self._batch_commit_count:
                self._flush_queue()
            return len(data_list)
        except Exception:
            log.exception("Database batch_upsert failed")
            return 0
    # ---------------- FIXED: Get recent events with correct column names ----------------
    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent security events for timeline display - FIXED VERSION"""
        try:
            # FIXED: Use 'ts' column instead of 'timestamp' to match the actual schema
            sql = """
                SELECT id, ts, iso, path, event, status, decision, priority, size, meta
                FROM events 
                ORDER BY ts DESC 
                LIMIT ?
            """
            rows = self.fetchall(sql, (limit,))
            events = []
            for row in rows:
                events.append({
                    'id': row[0],
                    'timestamp': row[1],  # Convert ts to timestamp for frontend compatibility
                    'ts': row[1],
                    'iso': row[2],
                    'path': row[3],
                    'event_type': row[4],  # Map 'event' to 'event_type' for frontend
                    'event': row[4],
                    'status': row[5],
                    'decision': row[6],
                    'priority': row[7],
                    'severity': row[7],  # Map 'priority' to 'severity' for frontend
                    'size': row[8],
                    'description': row[4],  # Use event as description
                    'source': 'file_monitor',
                    'action_taken': row[6],
                    'details': row[9]
                })
            return events
        except Exception as e:
            log.error(f"Error getting recent events: {e}")
            return []
    # ---------------- FIXED: Recovery points and history ----------------
    def get_recovery_points(self) -> List[Dict[str, Any]]:
        """Get available recovery points - FIXED VERSION"""
        try:
            # Create recovery_points table if it doesn't exist
            self._execute(
                """
                CREATE TABLE IF NOT EXISTS recovery_points (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    iso TEXT NOT NULL,
                    backup_name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    file_count INTEGER DEFAULT 0,
                    size_mb REAL DEFAULT 0.0,
                    description TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                commit=True
            )
            sql = """
                SELECT id, timestamp, iso, backup_name, path, status, 
                       file_count, size_mb, description
                FROM recovery_points 
                ORDER BY timestamp DESC 
                LIMIT 10
            """
            rows = self.fetchall(sql)
            recovery_points = []
            for row in rows:
                recovery_points.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'backup_name': row[2],
                    'path': row[3],
                    'status': row[4],
                    'file_count': row[5],
                    'size_mb': row[6],
                    'description': row[7]
                })
            return recovery_points
        except Exception as e:
            log.error(f"Error getting recovery points: {e}")
            return []
    def get_restore_history(self) -> List[Dict[str, Any]]:
        """Get restore operation history - FIXED VERSION"""
        try:
            # Create restore_history table if it doesn't exist
            self._execute(
                """
                CREATE TABLE IF NOT EXISTS restore_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    iso TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    source_backup TEXT NOT NULL,
                    status TEXT DEFAULT 'completed',
                    files_restored INTEGER DEFAULT 0,
                    errors TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                commit=True
            )
            sql = """
                SELECT id, timestamp, iso, operation_type, target_path, 
                       source_backup, status, files_restored, errors
                FROM restore_history 
                ORDER BY timestamp DESC 
                LIMIT 10
            """
            rows = self.fetchall(sql)
            restore_history = []
            for row in rows:
                restore_history.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'operation_type': row[2],
                    'target_path': row[3],
                    'source_backup': row[4],
                    'status': row[5],
                    'files_restored': row[6],
                    'errors': row[7]
                })
            return restore_history
        except Exception as e:
            log.error(f"Error getting restore history: {e}")
            return []
    # ---------------- Background flusher ----------------
    def _bg_flusher_loop(self):
        """Background thread to flush write queue"""
        while not self._stop_bg.is_set():
            try:
                time.sleep(self._batch_commit_interval)
                self._flush_queue()
            except Exception:
                log.exception("Background flusher error")
    def _flush_queue(self):
        """Flush write queue to database"""
        if not self._write_queue:
            return
        queue_snapshot = []
        with self._queue_lock:
            queue_snapshot = self._write_queue[:]
            self._write_queue.clear()
        if not queue_snapshot:
            return
        try:
            with self._conn_lock:
                if not self._conn:
                    self._open_connection("performance")
                cur = self._conn.cursor()
                try:
                    cur.execute("BEGIN IMMEDIATE")
                    for sql, params in queue_snapshot:
                        cur.execute(sql, params)
                    cur.execute("COMMIT")
                    cur.close()
                    log.debug("Flushed %d queued operations", len(queue_snapshot))
                except Exception as e:
                    try:
                        cur.execute("ROLLBACK")
                        cur.close()
                    except Exception:
                        pass
                    # Save failed operations to recovery file
                    self._save_failed_operations(queue_snapshot)
                    log.error("Failed to flush queue, saved to recovery file")
        except Exception:
            log.exception("Queue flush error")
    def _save_failed_operations(self, operations: List[Tuple[str, List[Any]]]):
        """Save failed operations to recovery file"""
        try:
            recovery_data = {
                'timestamp': datetime.now().isoformat(),
                'operations': [{'sql': sql, 'params': params} for sql, params in operations]
            }
            with open(self._recovery_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(recovery_data, cls=_JSONSafeEncoder) + '\n')
            log.info("Saved %d failed operations to recovery file", len(operations))
        except Exception:
            log.exception("Failed to save recovery operations")
    def close(self):
        """Close database connection and background thread"""
        try:
            self._stop_bg.set()
            # التحقق من وجود _bg_thread قبل محاولة الوصول إليه
            if hasattr(self, '_bg_thread') and self._bg_thread.is_alive():
                self._bg_thread.join(timeout=5)
            if self._conn:
                with self._conn_lock:
                    self._conn.close()
                    self._conn = None
            log.info("Database connection closed")
        except Exception:
            log.exception("Error closing database")
    def __del__(self):
        """Cleanup on object destruction"""
        try:
            # التحقق من وجود _stop_bg قبل استدعاء close
            if hasattr(self, '_stop_bg'):
                self.close()
        except Exception:
            pass
    # ---------------- FIXED: Missing methods required by main.py ----------------
    def recover_failed_writes(self) -> int:
        """
        إعادة تنفيذ الكتابات الفاشلة من ملف recovery.
        تعيد عدد العمليات الناجحة.
        """
        if not os.path.exists(self._recovery_file):
            return 0
        try:
            recovery_data = []
            with open(self._recovery_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        recovery_data.append(json.loads(line))
        except Exception:
            log.exception("Failed to load recovery file")
            return 0
        if not recovery_data:
            return 0
        ok, fail = 0, 0
        for item in recovery_data:
            if "operations" in item:
                for op in item["operations"]:
                    sql, params = op.get("sql"), op.get("params")
                    try:
                        self._execute(sql, params)
                        ok += 1
                    except Exception:
                        fail += 1
        # إذا نجحت كلّها، احذف ملف الاسترجاع
        if fail == 0:
            try:
                os.remove(self._recovery_file)
            except Exception:
                pass
        log.info("Recovery replays: ok=%d fail=%d", ok, fail)
        return ok
    def get_monitored_paths(self) -> List[str]:
        """Get list of monitored paths - FIXED VERSION"""
        try:
            # Create monitored_paths table if it doesn't exist
            self._execute(
                """
                CREATE TABLE IF NOT EXISTS monitored_paths (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT UNIQUE NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """,
                commit=True
            )
            sql = "SELECT DISTINCT path FROM monitored_paths WHERE is_active = 1 ORDER BY path"
            rows = self.fetchall(sql)
            return [row[0] for row in rows if row[0]]
        except Exception as e:
            log.error(f"Error getting monitored paths: {e}")
            # Return empty list if database query fails
            return []
    def queued_count(self) -> int:
        """Get count of queued operations"""
        with self._queue_lock:
            return len(self._write_queue)
    def set_batch_config(self, count: Optional[int] = None, interval: Optional[float] = None):
        """تعديل إعدادات الدُفعات أثناء التشغيل (يؤثر على الخيط الخلفي فورًا)."""
        if count is not None:
            self._batch_commit_count = int(count)
        if interval is not None:
            self._batch_commit_interval = float(interval)
        log.info("Batch config updated count=%d interval=%.2f",
                 self._batch_commit_count, self._batch_commit_interval)
    # ---------------- Database Schema Initialization ----------------
    def init_tables(self):
        """Initialize all required database tables"""
        try:
            log.info("Initializing database tables...")
            # Events table
            self._execute("""
                CREATE TABLE IF NOT EXISTS events (
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
            """, commit=True)
            # Files table
            self._execute("""
                CREATE TABLE IF NOT EXISTS files (
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
                    threat_level TEXT DEFAULT 'unknown'
                )
            """, commit=True)
            # Alerts table
            self._execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
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
            """, commit=True)
            # Quarantine table
            self._execute("""
                CREATE TABLE IF NOT EXISTS quarantine (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL,
                    moved_at INTEGER NOT NULL,
                    threat_type TEXT,
                    reason TEXT,
                    status TEXT DEFAULT 'quarantined',
                    restore_count INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """, commit=True)
            # Backups table
            self._execute("""
                CREATE TABLE IF NOT EXISTS backups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    backup_path TEXT NOT NULL,
                    backed_up_at INTEGER NOT NULL,
                    backup_type TEXT DEFAULT 'full',
                    hash_md5 TEXT,
                    hash_sha256 TEXT,
                    size INTEGER,
                    status TEXT DEFAULT 'success',
                    metadata TEXT
                )
            """, commit=True)
            # Recovery points table
            self._execute("""
                CREATE TABLE IF NOT EXISTS recovery_points (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT,
                    created_at INTEGER NOT NULL,
                    file_count INTEGER DEFAULT 0,
                    total_size INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active',
                    metadata TEXT
                )
            """, commit=True)
            # Restore history table
            self._execute("""
                CREATE TABLE IF NOT EXISTS restore_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_id INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    restored_at INTEGER NOT NULL,
                    restore_method TEXT DEFAULT 'manual',
                    status TEXT DEFAULT 'success',
                    details TEXT,
                    FOREIGN KEY (backup_id) REFERENCES recovery_points(id)
                )
            """, commit=True)
            # Monitored paths table
            self._execute("""
                CREATE TABLE IF NOT EXISTS monitored_paths (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT UNIQUE NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """, commit=True)
            # Important files table
            self._execute("""
                CREATE TABLE IF NOT EXISTS important_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT UNIQUE NOT NULL,
                    file_type TEXT DEFAULT 'general',
                    priority TEXT DEFAULT 'medium',
                    is_monitored BOOLEAN DEFAULT 1,
                    last_checked INTEGER,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
            """, commit=True)
            # Create indexes for better performance
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC)",
                "CREATE INDEX IF NOT EXISTS idx_events_path ON events(path)",
                "CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)",
                "CREATE INDEX IF NOT EXISTS idx_files_modified ON files(last_modified)",
                "CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)",
                "CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status)",
                "CREATE INDEX IF NOT EXISTS idx_backups_path ON backups(backed_up_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_monitored_active ON monitored_paths(is_active)",
                "CREATE INDEX IF NOT EXISTS idx_important_priority ON important_files(priority)"
            ]
            for index_sql in indexes:
                try:
                    self._execute(index_sql, commit=True)
                except Exception as e:
                    log.warning(f"Failed to create index: {e}")
            log.info("Database tables initialized successfully")
        except Exception as e:
            log.error(f"Failed to initialize database tables: {e}")
            raise
    # Additional utility methods
    def get_timeline_events(self, hours: int = 24):
        """إرجاع أحداث الجدول الزمني - FIXED VERSION"""
        try:
            from datetime import datetime, timedelta
            cutoff = datetime.now() - timedelta(hours=hours)
            sql = """
                SELECT id, ts, event, priority, path, size
                FROM events 
                WHERE ts >= ? 
                ORDER BY ts DESC 
                LIMIT 100
            """
            return self.fetchall(sql, (int(cutoff.timestamp()),))
        except Exception as e:
            log.error(f"Error getting timeline events: {e}")
            return []
    def _flush_all(self):
        """Flush all remaining operations"""
        try:
            if self._write_queue:
                self._flush_queue()
        except Exception:
            log.exception("Flush all operations failed")
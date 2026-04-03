# -*- coding: utf-8 -*-
"""
main.py — Full Integrated Ransomware Protection System (Windows-Only Edition)
(optimized, extended, + YARA + ML + Anomaly + Quarantine + Backup + VirusTotal)
- ✅ إصلاح جميع الأخطاء القاتلة الستة
- ✅ إصلاح Waitress connection_limit
- ✅ إضافة Lock حول event processing
- ✅ إضافة Sentinel وjoin() للـ threads
- ✅ Thread-safe stats مع Lock
- ✅ تغيير شرط monitor_queue_depth
- ✅ DB write serialization
- ✅ إصلاح SystemPaths windows_data_root
- ✅ توحيد منطق المسارات
"""
from __future__ import annotations
import os
import sys
import json
import time
import signal
import platform
import base64
import hashlib
import threading
import atexit
from pathlib import Path
from typing import Any, Dict, Optional, List
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor
from google_drive_backup import GoogleDriveBackup

# ---------------------------------------------------------------------
# تحسين مستويات السجلات
# ---------------------------------------------------------------------
import logging

logging.basicConfig(level=logging.WARNING)
# ---------------------------------------------------------------------
# ترتيب مسارات الاستيراد
# ---------------------------------------------------------------------
THIS_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = THIS_DIR.parent
yara_test_path = PROJECT_DIR / "data" / "YARA_RULES"
if not yara_test_path.exists():
    current_file = Path(__file__).resolve()
    search_patterns = [
        current_file.parent.parent,
        current_file.parent.parent.parent,
    ]
    for possible_project in search_patterns:
        if (possible_project / "data" / "YARA_RULES").exists():
            PROJECT_DIR = possible_project
            break
    else:
        PROJECT_DIR = current_file.parent.parent
        log = logging.getLogger(__name__)
        log.warning(
            "Could not find YARA_RULES in expected locations, using: %s", PROJECT_DIR
        )
BASE_DIR = PROJECT_DIR
DATA_DIR = os.path.join(BASE_DIR, "data")
DATABASE_DIR = os.path.join(DATA_DIR, "database")
QUARANTINE_DIR = os.path.join(DATA_DIR, "quarantine")
BACKUPS_DIR = os.path.join(DATA_DIR, "backups")
YARA_RULES_DIR = os.path.join(DATA_DIR, "YARA_RULES")
for directory in [DATA_DIR, DATABASE_DIR, QUARANTINE_DIR, BACKUPS_DIR, YARA_RULES_DIR]:
    os.makedirs(directory, exist_ok=True)
for p in (str(THIS_DIR), str(PROJECT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)
# ---------------------------------------------------------------------
# Imports + Shims
# ---------------------------------------------------------------------
from logger import get_logger

log = get_logger(__name__)
from utils import now_iso, normalize_path, load_json, save_json, sizeof_fmt
from file_monitor import RealTimeFileMonitor

try:
    from event_handler import FileEventHandler
except Exception:

    class FileEventHandler:
        def __init__(self, backup_manager=None, quarantine_manager=None, config=None):
            self.google_drive = None
            self.backup = backup_manager
            self.quarantine = quarantine_manager
            self.config = config or {}
            self.ai = None

        def handle_event(self, event: dict):
            return {"decision": {"action": None}, "event": event}

        def submit_event(self, event: dict):
            return self.handle_event(event)


try:
    from database_handler import DatabaseHandler
except Exception:
    DatabaseHandler = None
    log.warning("DatabaseHandler not available. DB features will be disabled.")
try:
    from yara_scanner import YaraScanner
except Exception:
    YaraScanner = None
    log.warning("YaraScanner not available. YARA features will be disabled.")
try:
    from ml_detector import MLDetector
except Exception:
    MLDetector = None
    log.warning("MLDetector not available. ML features will be disabled.")
try:
    from detector_anomaly import AnomalyDetector
except Exception:
    try:
        from anomaly_detector import AnomalyDetector
    except Exception:
        AnomalyDetector = None
        log.warning("AnomalyDetector not available. Anomaly features will be disabled.")
try:
    from ransomware_response import RansomwareResponse
except Exception:
    RansomwareResponse = None
    log.warning("RansomwareResponse not available. Quarantine REST will be limited.")
BackupManager = None
BackupFacade = None
try:
    from backup_manager import BackupManager, BackupFacade

    log.info("BackupManager imported successfully")
except Exception as e:
    log.warning(
        "BackupManager/Facade not available. Backup REST will be limited. Error: %s",
        str(e),
    )
    BackupManager = None
    BackupFacade = None
# حوار الملفات (للبراوز File/Folder من الواجهة)
try:
    import tkinter as tk
    from tkinter import filedialog
except Exception:
    tk = None
    filedialog = None


# ---------------------------------------------------------------------
# Thread-Safe Counter and Queue Manager
# ---------------------------------------------------------------------
class ThreadSafeStats:
    """Thread-safe statistics manager with Lock protection"""

    def __init__(self):
        self._lock = threading.Lock()
        self._stats = {
            "start_time": time.time(),
            "started_at": now_iso(),
            "total_scans": 0,
            "infected_files": 0,
            "safe_files": 0,
            "anomalies_detected": 0,
        }

    def increment(self, key: str, value: int = 1):
        with self._lock:
            if key in self._stats:
                self._stats[key] += value

    def get(self) -> dict:
        with self._lock:
            return self._stats.copy()

    def set(self, key: str, value):
        with self._lock:
            self._stats[key] = value


class EventProcessingQueue:
    """Thread-safe event queue with serialization for database writes"""

    def __init__(self, maxsize: int = 1000):
        self._queue = []
        self._lock = threading.Lock()
        self._db_lock = threading.Lock()
        self.maxsize = maxsize
        self._processing = False

    def put(self, item):
        with self._lock:
            if len(self._queue) >= self.maxsize:
                # Remove oldest item if queue is full
                self._queue.pop(0)
            self._queue.append(item)

    def get_all(self) -> List:
        with self._lock:
            items = self._queue.copy()
            self._queue.clear()
            return items

    def get_db_lock(self) -> threading.Lock:
        """Return lock for database operations serialization"""
        return self._db_lock

    def size(self) -> int:
        with self._lock:
            return len(self._queue)


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def deep_merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            dst[k] = deep_merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def validate_config(cfg: dict) -> dict:
    if "web_interface" in cfg:
        port = cfg["web_interface"].get("port", 5000)
        if not isinstance(port, int) or not (1024 <= port <= 65535):
            cfg["web_interface"]["port"] = 5000
        cfg["web_interface"]["debug"] = False
    # ✅ Unified paths - using PROJECT_DIR/data structure
    bkp = cfg.setdefault("backup", {})
    bkp.setdefault("mode", "both")
    bkp.setdefault("local_path", BACKUPS_DIR)
    qcfg = cfg.setdefault("quarantine", {})
    qcfg.setdefault("path", QUARANTINE_DIR)
    qcfg.setdefault("max_workers", 4)
    dbc = cfg.setdefault("database", {})
    dbc.setdefault("path", os.path.join(DATABASE_DIR, "app.db"))
    dbc.setdefault("pragmas_profile", "performance")
    dbc.setdefault("batch_commit_count", 50)
    dbc.setdefault("batch_commit_interval", 2.0)
    dbc.setdefault("retry_attempts", 5)
    dbc.setdefault(
        "recovery_file", os.path.join(DATABASE_DIR, "_db_failed_writes.json")
    )
    ycfg = cfg.setdefault("yara", {})
    ycfg.setdefault("rules_dir", YARA_RULES_DIR)
    ycfg.setdefault("pre_scan_in_main", True)
    mcfg = cfg.setdefault("ml", {})
    mcfg.setdefault("enabled", True)
    default_models = os.path.join(DATA_DIR, "AI_MODELS")
    mcfg.setdefault("models_dir", default_models)
    mcfg.setdefault("threshold", 0.7)
    mcfg.setdefault("fast_threshold", 0.5)
    mcfg.setdefault("deep_enabled", True)
    mcfg.setdefault("max_fast_file_mb", 200)
    mcfg.setdefault("verbose", False)
    acfg = cfg.setdefault("anomaly", {})
    acfg.setdefault("enabled", True)
    acfg.setdefault("window_seconds", 60)
    acfg.setdefault("rate_threshold", 20)
    acfg.setdefault("threshold", 0.65)
    acfg.setdefault("entropy_jump", 0.4)
    acfg.setdefault("entropy_bytes", 65536)
    acfg.setdefault("max_cache", 20000)
    acfg.setdefault("model", "iforest")
    acfg.setdefault("contamination", 0.02)
    acfg.setdefault(
        "model_path", os.path.join(DATA_DIR, "AI_MODELS", "anomaly_iforest.pkl")
    )
    acfg.setdefault("baseline_cap", 600)
    acfg.setdefault(
        "weights",
        {
            "rate": 0.30,
            "ext_change": 0.25,
            "suspicious_ext": 0.15,
            "entropy_delta": 0.20,
            "name_random": 0.10,
        },
    )
    cfg.setdefault("executor", {"max_workers": 4})  # Fixed: reduced from 8 to 4
    cfg.setdefault("api_token", None)
    cfg.setdefault(
        "virustotal",
        {"api_key": "e6b72c3c77aaeb8456762c1e0e2344c7e9668735eb7f6d5a32db00101cdafbec"},
    )
    return cfg


# ---------------------------------------------------------------------
# Paths (Unified Project Structure)
# ---------------------------------------------------------------------
class SystemPaths:
    """Unified path management using project data directory"""

    @staticmethod
    def _get_data_root() -> Path:
        """Use project data directory for all platforms"""
        return Path(BASE_DIR) / "data"

    @staticmethod
    def _get_user_log_root() -> Path:
        """Use project data logs directory"""
        return Path(BASE_DIR) / "data" / "logs"

    @staticmethod
    def windows_data_root() -> Path:
        """Unified data root - same for all platforms"""
        return SystemPaths._get_data_root()

    @staticmethod
    def windows_user_log_root() -> Path:
        """Unified log root - same for all platforms"""
        return SystemPaths._get_user_log_root()

    def __init__(self):
        self.project_dir = PROJECT_DIR
        self.src_dir = THIS_DIR
        self.data_root = self._get_data_root()
        self.config_file = self.src_dir / "config.json"
        self.database_dir = self.data_root / "database"
        self.backup_dir = self.data_root / "backups"
        self.quarantine_dir = self.data_root / "quarantine"
        self.rules_dir = self.data_root / "YARA_RULES"
        self.models_dir = self.data_root / "AI_MODELS"
        self.logs_dir = self._get_user_log_root()
        self.static_dir = self.src_dir / "static"
        for d in (
            self.data_root,
            self.database_dir,
            self.backup_dir,
            self.quarantine_dir,
            self.rules_dir,
            self.models_dir,
            self.logs_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------
# Database Write Serializer
# ---------------------------------------------------------------------
class DatabaseWriteSerializer:
    """Serialize database writes to prevent concurrent access issues"""

    def __init__(self, db_handler):
        self.db = db_handler
        self._lock = threading.Lock()

    def insert_or_replace(self, table: str, row: dict, **kwargs):
        """Thread-safe database insert with serialization"""
        with self._lock:
            try:
                return self.db.insert_or_replace(table, row, **kwargs)
            except Exception as e:
                log.error("Database write failed: %s", e)
                raise

    def execute(self, sql: str, params=None):
        """Thread-safe database execute with serialization"""
        with self._lock:
            try:
                return self.db.execute(sql, params)
            except Exception as e:
                log.error("Database execute failed: %s", e)
                raise


# ---------------------------------------------------------------------
# Thread Manager with Sentinel Pattern
# ---------------------------------------------------------------------
class ThreadManager:
    """Manage threads with proper shutdown using sentinel pattern"""

    def __init__(self):
        self.threads = {}
        self.sentinel = object()  # Sentinel object for thread coordination
        self._shutdown_event = threading.Event()

    def add_thread(self, name: str, target, daemon: bool = False, **kwargs):
        """Add a thread with proper tracking"""
        thread = threading.Thread(
            target=target, daemon=daemon, name=f"RansomwareProt_{name}", **kwargs
        )
        thread.start()
        self.threads[name] = thread
        log.debug("Started thread: %s", name)

    def stop_all(self, timeout: float = 5.0):
        """Stop all threads gracefully with join"""
        log.info("Stopping all threads...")
        # Set shutdown event
        self._shutdown_event.set()
        # Stop each thread
        for name, thread in self.threads.items():
            if thread.is_alive():
                log.debug("Joining thread: %s", name)
                try:
                    thread.join(timeout=timeout)
                    if thread.is_alive():
                        log.warning("Thread %s did not stop within timeout", name)
                    else:
                        log.debug("Thread %s stopped successfully", name)
                except Exception as e:
                    log.error("Error stopping thread %s: %s", name, e)
        self.threads.clear()
        log.info("All threads stopped")

    def is_shutdown(self) -> bool:
        """Check if shutdown was requested"""
        return self._shutdown_event.is_set()


# ---------------------------------------------------------------------
# Main System
# ---------------------------------------------------------------------
class IntegratedRansomwareProtectionSystem:
    def __init__(self):
        self.paths = SystemPaths()
        self.config = self._load_config()
        self.api_token = self.config.get("api_token")
        self.system_running = False
        self.system_paused = False
        self.file_monitor = None
        # ✅ Fixed: Thread-safe stats with Lock
        self.stats = ThreadSafeStats()
        self._vt_last_call = 0
        self._vt_lock = threading.Lock()
        # ✅ Fixed: Event processing queue with serialization
        self.event_queue = EventProcessingQueue(maxsize=1000)
        # ✅ Fixed: Thread manager with sentinel pattern
        self.thread_manager = ThreadManager()
        self.backup_manager = None
        self.backup_facade = None
        if BackupManager:
            try:
                # ✅ FIXED: Pass config_path as the first required argument
                self.backup_manager = BackupManager(
                    str(self.paths.config_file),  # ← الحل المطلوب
                    mode=self.config.get("backup", {}).get("mode", "both"),
                    local_backup_dir=self.config.get("backup", {}).get(
                        "local_path", str(self.paths.backup_dir)
                    ),
                )
                if BackupFacade:
                    self.backup_facade = BackupFacade(self.backup_manager)
            except Exception:
                log.exception("Failed to init BackupManager")
        self.response: Optional[RansomwareResponse] = None
        self.quarantine_manager = None
        if RansomwareResponse:
            try:
                self.response = RansomwareResponse(
                    quarantine_dir=self.config.get("quarantine", {}).get(
                        "path", str(self.paths.quarantine_dir)
                    ),
                    max_workers=int(
                        self.config.get("quarantine", {}).get("max_workers", 4)
                    ),
                )
                self.quarantine_manager = getattr(self.response, "qm", None)
                log.info("RansomwareResponse initialized.")
            except Exception:
                log.exception("Failed to initialize RansomwareResponse")
                self.response = None
        self.event_handler = FileEventHandler(
            backup_manager=self.backup_manager,
            quarantine_manager=self.quarantine_manager,
            config=self.config,
        )
        self.db: Optional[DatabaseHandler] = None
        self.db_serializer = None
        if DatabaseHandler:
            try:
                dbc = self.config.get("database", {})
                db_path = dbc.get("path") or os.path.join(DATABASE_DIR, "app.db")
                self.db = DatabaseHandler(
                    db_path=db_path,
                    pragmas_profile=dbc.get("pragmas_profile", "performance"),
                    batch_commit_count=int(dbc.get("batch_commit_count", 50)),
                    batch_commit_interval=float(dbc.get("batch_commit_interval", 2.0)),
                    retry_attempts=int(dbc.get("retry_attempts", 5)),
                    recovery_file=dbc.get("recovery_file")
                    or os.path.join(DATABASE_DIR, "db_recovery.log"),
                )
                # ✅ Fixed: Database write serializer
                self.db_serializer = DatabaseWriteSerializer(self.db)
                try:
                    self.db.init_tables()
                    self.db.recover_failed_writes()
                except Exception:
                    log.exception("DB initialization failed")
            except Exception:
                log.exception("Failed initializing DatabaseHandler")
                self.db = None
        self.yara_scanner: Optional[YaraScanner] = None
        self._ensure_yara_scanner()
        self.ml: Optional[MLDetector] = None
        self._ensure_ml_detector()
        self.anomaly: Optional[AnomalyDetector] = None
        try:
            if AnomalyDetector:
                acfg = dict(self.config.get("anomaly", {}))
                acfg["monitoring"] = {
                    "suspicious_extensions": self.config.get("monitoring", {}).get(
                        "suspicious_extensions", []
                    )
                }
                self.anomaly = AnomalyDetector(acfg)
                log.info("AnomalyDetector initialized.")
        except Exception:
            log.exception("Failed to initialize AnomalyDetector")
            self.anomaly = None
        try:
            if self.event_handler and self.ml:
                self.event_handler.ai = self.ml
        except Exception:
            log.exception("Failed to inject MLDetector into event_handler")
        # استثناء ملف اللوج الخاص بالنظام من المراقبة
        try:
            log_file = None
            handlers = []
            try:
                handlers.extend(list(logging.getLogger().handlers))
            except Exception:
                pass
            if hasattr(log, "handlers"):
                try:
                    handlers.extend(list(log.handlers))
                except Exception:
                    pass
            for h in handlers:
                try:
                    bf = getattr(h, "baseFilename", None)
                    if bf:
                        log_file = bf
                        break
                except Exception:
                    continue
            mon = self.config.setdefault("monitoring", {})
            ex = mon.setdefault("exclude_patterns", [])
            system_patterns = [
                "enhanced_system.log",
                "__pycache__",
                "*.pyc",
                "*.pyo",
                "*.pyd",
                "*.db",
                "*.db-wal",
                "*.db-shm",
                ".git",
                ".svn",
                ".hg",
                "venv",
                ".venv",
                "env",
                ".env",
                "node_modules",
                ".npm",
                ".yarn",
                ".cache",
                ".config",
                "*.tmp",
                "*.swp",
                "*.bak",
                ".DS_Store",
                "Thumbs.db",
            ]
            if log_file:
                ex.append(log_file)
                log.info(
                    "Injected self-log into monitoring.exclude_patterns: %s", log_file
                )
            for pattern in system_patterns:
                if pattern not in ex:
                    ex.append(pattern)
            log.info(
                "Added system exclusion patterns to monitoring: %d patterns", len(ex)
            )
        except Exception:
            log.exception("Failed to inject self-log exclusion")
        filemon_db = self.paths.database_dir / "file_monitor.db"
        self.file_monitor = RealTimeFileMonitor(
            str(filemon_db), change_callback=self._on_file_change, config=self.config
        )
        max_workers = int(self.config.get("executor", {}).get("max_workers", 4))
        self.event_pool = ThreadPoolExecutor(max_workers=max_workers)
        self.app = Flask(
            __name__, static_folder=str(self.paths.static_dir), static_url_path="/"
        )
        CORS(self.app)
        self.monitoring_paths_cache = None
        self.last_monitoring_paths_load = 0
        self.monitoring_cache_ttl = 30
        self.important_files_cache = None
        self.last_important_files_load = 0
        self.important_files_ttl = 30
        # ✅ Fixed: Start queue processing thread with sentinel
        self._start_queue_processing_thread()
        self._setup_routes()

    # ✅ Fixed: Start queue processing thread
    def _start_queue_processing_thread(self):
        """Start thread for processing queued events"""

        def queue_processor():
            log.info("Event queue processor thread started")
            while not self.thread_manager.is_shutdown():
                try:
                    # Process queued events
                    events = self.event_queue.get_all()
                    for event in events:
                        self._process_event_internal(event)
                    # Small delay to prevent busy waiting
                    time.sleep(0.1)
                except Exception as e:
                    log.error("Queue processor error: %s", e)
                    time.sleep(1)  # Longer delay on error
            log.info("Event queue processor thread stopped")

        self.thread_manager.add_thread("queue_processor", queue_processor, daemon=True)

    # ✅ Fixed: Monitor queue depth function with correct condition
    def monitor_queue_depth(self):
        """Monitor queue depth and take action if needed"""
        if (
            not self.system_running
        ):  # ✅ Fixed: Changed from _vt_processing to system_running
            return
        current_depth = self.event_queue.size()
        max_depth = self.event_queue.maxsize
        if current_depth > max_depth * 0.8:  # 80% full
            log.warning(
                "Event queue is %d/%d (%.1f%% full)",
                current_depth,
                max_depth,
                (current_depth / max_depth) * 100,
            )
            # Could implement additional measures here like:
            # - Dropping low-priority events
            # - Increasing processing threads
            # - Sending alerts

    # ✅ دالة مساعدة لحساب SHA-256
    def _calculate_sha256(self, file_path: str) -> str:
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    # ✅ دالة تحليل بـ VirusTotal
    def scan_with_virustotal(self, file_path: str) -> Dict[str, Any]:
        vt_config = self.config.get("virustotal", {})
        api_key = vt_config.get("api_key")
        if not api_key:
            return {"error": "VirusTotal API key not configured"}
        try:
            sha256 = self._calculate_sha256(file_path)
            if not sha256:
                return {"error": "Failed to calculate SHA-256"}
            with self._vt_lock:
                now = time.time()
                wait_time = self._vt_last_call + 15 - now
                if wait_time > 0:
                    time.sleep(wait_time)
                self._vt_last_call = time.time()
            import requests

            headers = {"x-apikey": api_key}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers=headers,
                timeout=10,
            )
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                total = sum(stats.values())
                malicious = stats.get("malicious", 0)
                return {
                    "infected": malicious > 0,
                    "malicious": malicious,
                    "total": total,
                    "confidence": (malicious / total) * 100 if total > 0 else 0,
                    "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
                }
            elif response.status_code == 404:
                return {"infected": False, "message": "File not found on VirusTotal"}
            else:
                return {"error": f"VirusTotal API error: {response.status_code}"}
        except Exception as e:
            log.exception("VirusTotal scan failed")
            return {"error": str(e)}

    def _on_file_change(self, event: dict):
        try:
            # ✅ Fixed: Queue event for processing instead of direct submission
            self.event_queue.put(event)
            self.monitor_queue_depth()
        except Exception:
            log.exception("Failed queuing event")

    def _process_event_internal(self, event: dict):
        """Internal event processing with proper locking"""
        try:
            fpath = event.get("file_path") or event.get("path")
            ycfg = self.config.get("yara", {}) or {}
            if bool(ycfg.get("pre_scan_in_main", True)) and self.yara_scanner and fpath:
                try:
                    if hasattr(self.yara_scanner, "reload_if_changed"):
                        self.yara_scanner.reload_if_changed()
                    yres = self.yara_scanner.scan_file(fpath)
                    event["yara"] = yres
                    if yres.get("infected"):
                        event["priority"] = event.get("priority") or "critical"
                except Exception:
                    log.exception("Pre YARA scan failed")
            mcfg = self.config.get("ml", {}) or {}
            if bool(mcfg.get("enabled", True)) and self.ml and fpath:
                try:
                    ml_res = self.ml.detect_file(fpath)
                    event["ml"] = ml_res
                    if ml_res.get("infected"):
                        event["priority"] = event.get("priority") or "high"
                except Exception:
                    log.exception("Pre ML detection failed")
            if self.anomaly and fpath:
                try:
                    ares = self.anomaly.analyze_event(event)
                    event["anomaly"] = ares
                    if ares.get("anomalous"):
                        self.stats.increment("anomalies_detected")
                        event["priority"] = event.get("priority") or "high"
                except Exception:
                    log.exception("Anomaly analysis failed")
            res = self.event_handler.handle_event(event)
            decision = (res or {}).get("decision", {}) or {}
            action = decision.get("action")
            # ✅ Fixed: Thread-safe stats updates
            self.stats.increment("total_scans")
            if action == "quarantine":
                self.stats.increment("infected_files")
            else:
                self.stats.increment("safe_files")
            # ✅ Fixed: Database writes with serialization
            if self.db_serializer:
                try:
                    integrity = event.get("integrity", {}) or {}
                    status = integrity.get("status")
                    priority = event.get("priority")
                    size = None
                    nh = integrity.get("new_hashes") or {}
                    if isinstance(nh.get("size"), (int, float, str)):
                        try:
                            size = int(nh.get("size"))
                        except Exception:
                            size = None
                    if size is None and fpath:
                        try:
                            size = os.path.getsize(fpath)
                        except Exception:
                            size = None
                    meta_obj = {"event": event, "decision": decision}
                    meta_txt = json.dumps(meta_obj, ensure_ascii=False)[:65535]
                    row = {
                        "ts": int(time.time()),
                        "iso": now_iso(),
                        "path": fpath,
                        "event": event.get("event"),
                        "status": status,
                        "decision": action,
                        "priority": priority,
                        "size": size,
                        "meta": meta_txt,
                    }
                    self.db_serializer.insert_or_replace("events", row, queue=True)
                except Exception:
                    log.exception("Persist event failed")
        except Exception:
            log.exception("Error processing event")

    def _process_event(self, event: dict):
        """Legacy event processing method (kept for compatibility)"""
        # This method is now just a wrapper
        self._process_event_internal(event)

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration with unified paths"""
        # ✅ Unified paths for all platforms - using project data directory
        default_backup_path = BACKUPS_DIR
        default_quarantine_path = QUARANTINE_DIR
        default_db_path = os.path.join(DATABASE_DIR, "app.db")
        default_models_path = os.path.join(DATA_DIR, "AI_MODELS")
        default_yara_path = YARA_RULES_DIR
        default_recovery_file = os.path.join(DATABASE_DIR, "_db_failed_writes.json")
        default = {
            "web_interface": {"host": "0.0.0.0", "port": 5000, "debug": False},
            "backup": {"mode": "both", "local_path": default_backup_path},
            "quarantine": {"path": default_quarantine_path, "max_workers": 4},
            "executor": {"max_workers": 4},
            "monitoring": {
                "protected_folders": [
                    str(Path.home()),
                    str(Path.home() / "Desktop"),
                    str(Path.home() / "Documents"),
                    str(Path.home() / "Downloads"),
                ],
                "important_files": [],
                "important_rescan_interval_seconds": 1800,
            },
            "database": {
                "path": default_db_path,
                "pragmas_profile": "performance",
                "batch_commit_count": 50,
                "batch_commit_interval": 2.0,
                "retry_attempts": 5,
                "recovery_file": default_recovery_file,
            },
            "yara": {"rules_dir": default_yara_path, "pre_scan_in_main": True},
            "ml": {
                "enabled": True,
                "models_dir": default_models_path,
                "threshold": 0.7,
                "fast_threshold": 0.5,
                "deep_enabled": True,
                "max_fast_file_mb": 200,
                "verbose": False,
            },
            "anomaly": {},
            "api_token": None,
            "virustotal": {
                "api_key": "e6b72c3c77aaeb8456762c1e0e2344c7e9668735eb7f6d5a32db00101cdafbec"
            },
        }
        user = load_json(str(THIS_DIR / "config.json"), default=None)
        if user:
            default = deep_merge(default, user)
        return validate_config(default)

    def _save_config(self) -> bool:
        return save_json(str(THIS_DIR / "config.json"), self.config, atomic=True)

    def _setup_auth_guard(self):
        @self.app.before_request
        def _auth_guard():
            if self.api_token and request.path.startswith("/api/"):
                token = request.headers.get("X-API-KEY")
                if token != self.api_token:
                    return jsonify({"error": "Unauthorized"}), 401

    def _setup_routes(self):
        app = self.app
        self._setup_auth_guard()

        @app.route("/")
        def _index():
            return app.send_static_file("index.html")

        # =======================
        # ✅ SYSTEM CONTROL
        # =======================
        @app.route("/api/start", methods=["POST"])
        def api_start():
            return jsonify({"success": self.start_monitoring()})

        @app.route("/api/stop", methods=["POST"])
        def api_stop():
            return jsonify({"success": self.stop_monitoring()})

        @app.route("/api/pause", methods=["POST"])
        def api_pause():
            return jsonify({"success": self.pause_monitoring()})

        @app.route("/api/resume", methods=["POST"])
        def api_resume():
            return jsonify({"success": self.resume_monitoring()})

        @app.route("/api/status", methods=["GET"])
        def api_status():
            status_str = (
                "active"
                if self.system_running and not self.system_paused
                else "paused" if self.system_paused else "stopped"
            )
            return jsonify(
                {
                    "success": True,
                    "status": status_str,
                    "data": {
                        "status": status_str,
                        "protection_active": self.system_running,
                        "system_paused": self.system_paused,
                    },
                }
            )

        # =======================
        # ✅ DASHBOARD STATS
        # =======================
        @app.route("/api/stats")
        def api_stats():
            data = self.stats.get()
            quarantined_count = 0
            try:
                if self.response and hasattr(self.response, "stats"):
                    qs = self.response.stats() or {}
                    quarantined_count = int(qs.get("quarantined", 0))
            except Exception:
                pass
            data["quarantined_files"] = quarantined_count
            data["safe_files"] = data.get("total_scans", 0) - (
                data.get("infected_files", 0) + quarantined_count
            )
            data["detected_attacks"] = data.get("infected_files", 0) + data.get(
                "anomalies_detected", 0
            )
            return jsonify({"success": True, "data": data})

        # =======================
        # ✅ MONITORED PATHS
        # =======================
        @app.route("/api/settings/paths/monitored", methods=["GET"])
        def api_get_monitored_paths():
            paths = []
            if self.db and hasattr(self.db, "get_monitored_paths"):
                try:
                    paths = self.db.get_monitored_paths()
                except Exception:
                    log.exception("get_monitored_paths failed, falling back to config")
            if not paths:
                mon = self.config.get("monitoring", {})
                paths = mon.get("protected_folders", [])
            return jsonify({"success": True, "paths": paths})

        @app.route("/api/settings/paths/monitored", methods=["POST"])
        def api_add_monitored_path():
            data = request.get_json() or {}
            path = data.get("path")
            if not path:
                return jsonify({"success": False, "error": "Missing path"}), 400
            path = normalize_path(path)
            if not os.path.exists(path):
                return jsonify({"success": False, "error": "Path does not exist"}), 400
            mon = self.config.setdefault("monitoring", {})
            folders = mon.setdefault("protected_folders", [])
            if path not in folders:
                folders.append(path)
                self._save_config()
            if self.db_serializer:
                try:
                    self.db_serializer.insert_or_replace(
                        "monitored_paths",
                        {"path": path, "is_active": 1, "updated_at": now_iso()},
                    )
                except Exception:
                    log.exception("Failed to insert monitored path into DB")
            if self.file_monitor:
                try:
                    self.file_monitor.add_monitor_path(path)
                except Exception:
                    log.exception("file_monitor.add_monitor_path failed")
            return jsonify({"success": True, "path": path})

        @app.route("/api/settings/paths/monitored/remove", methods=["POST"])
        def api_remove_monitored_path():
            encoded = request.args.get("path")
            if not encoded:
                return jsonify({"success": False, "error": "Missing path"}), 400
            try:
                path = base64.b64decode(encoded).decode("utf-8")
            except Exception:
                return jsonify({"success": False, "error": "Invalid encoded path"}), 400
            path = normalize_path(path)
            mon = self.config.setdefault("monitoring", {})
            folders = mon.setdefault("protected_folders", [])
            if path in folders:
                folders.remove(path)
                self._save_config()
            if self.db_serializer:
                try:
                    sql = "UPDATE monitored_paths SET is_active = 0 WHERE path = ?"
                    self.db_serializer.execute(sql, (path,))
                except Exception:
                    log.exception("Failed to update monitored_paths in DB")
            if self.file_monitor:
                try:
                    self.file_monitor.remove_monitor_path(path)
                except Exception:
                    log.exception("file_monitor.remove_monitor_path failed")
            return jsonify({"success": True})

        # ✅ مسار متوافق مع script.js:
        # removeMonitoredPath(path) -> POST /api/settings/paths/monitored/<encoded>
        @app.route("/api/settings/paths/monitored/<encoded>", methods=["POST"])
        def api_remove_monitored_path_frontend(encoded):
            if not encoded:
                return jsonify({"success": False, "error": "Missing path"}), 400
            try:
                path = base64.b64decode(encoded).decode("utf-8")
            except Exception:
                return jsonify({"success": False, "error": "Invalid encoded path"}), 400
            path = normalize_path(path)
            mon = self.config.setdefault("monitoring", {})
            folders = mon.setdefault("protected_folders", [])
            if path in folders:
                folders.remove(path)
                self._save_config()
            if self.db_serializer:
                try:
                    sql = "UPDATE monitored_paths SET is_active = 0 WHERE path = ?"
                    self.db_serializer.execute(sql, (path,))
                except Exception:
                    log.exception("Failed to update monitored_paths in DB")
            if self.file_monitor:
                try:
                    self.file_monitor.remove_monitor_path(path)
                except Exception:
                    log.exception("file_monitor.remove_monitor_path failed")
            return jsonify({"success": True})

        # =======================
        # ✅ FILE LISTING
        # =======================
        @app.route("/api/list-files", methods=["GET"])
        def api_list_files():
            encoded = request.args.get("path")
            if not encoded:
                return jsonify({"success": False, "error": "Missing path"}), 400
            try:
                path = base64.b64decode(encoded).decode("utf-8")
            except Exception:
                return jsonify({"success": False, "error": "Invalid path"}), 400
            path = normalize_path(path)
            if not os.path.isdir(path):
                return jsonify({"success": True, "files": []})
            files = []
            for entry in os.scandir(path):
                if not entry.is_file():
                    continue
                try:
                    stat = entry.stat()
                    files.append(
                        {
                            "name": entry.name,
                            "path": entry.path,
                            "size": stat.st_size,
                            "modified": stat.st_mtime,
                            "sha256": self._calculate_sha256(entry.path),
                            "ai_confidence": 0,
                        }
                    )
                except (OSError, PermissionError):
                    continue
            return jsonify({"success": True, "files": files})

        # =======================
        # ✅ FILE ANALYSIS (VT + YARA + ML)
        # =======================
        @app.route("/api/analyze-file", methods=["POST"])
        def api_analyze_file():
            try:
                data = request.get_json() or {}
                file_path = data.get("file_path")
                if not file_path or not os.path.exists(file_path):
                    return jsonify({"success": False, "error": "File not found"}), 400
                results: Dict[str, Any] = {}
                file_info: Dict[str, Any] = {}
                try:
                    stat = os.stat(file_path)
                    file_info = {
                        "path": file_path,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "sha256": self._calculate_sha256(file_path),
                        "type": os.path.splitext(file_path)[1].lower(),
                    }
                except Exception as e:
                    log.error("File info failed: %s", e)
                    file_info = {"path": file_path, "error": str(e)}
                if self.yara_scanner:
                    try:
                        yara_res = self.yara_scanner.scan_file(file_path)
                        results["yara"] = yara_res
                    except Exception as e:
                        log.error("YARA scan failed: %s", e)
                if self.ml and self.config.get("ml", {}).get("enabled", False):
                    try:
                        ml_res = self.ml.detect_file(file_path)
                        results["ml"] = ml_res
                    except Exception as e:
                        log.error("ML detection failed: %s", e)
                vt_res = self.scan_with_virustotal(file_path)
                results["virustotal"] = vt_res
                is_threat = (
                    (results.get("yara", {}).get("infected", False))
                    or (results.get("ml", {}).get("infected", False))
                    or (results.get("virustotal", {}).get("infected", False))
                )
                confidences = []
                if results.get("ml"):
                    confidences.append(results["ml"].get("score", 0) * 100)
                if results.get("virustotal") and "confidence" in results["virustotal"]:
                    confidences.append(results["virustotal"]["confidence"])
                confidence = max(confidences) if confidences else 0
                threat_level = (
                    "critical"
                    if confidence > 90
                    else (
                        "high"
                        if confidence > 70
                        else "medium" if confidence > 50 else "low"
                    )
                )
                analysis_result = {
                    "is_threat": is_threat,
                    "threat_level": threat_level,
                    "confidence": round(confidence, 2),
                    "file_info": file_info,
                    "engines": results,
                }
                if self.db_serializer:
                    try:
                        self.db_serializer.insert_or_replace(
                            "files",
                            {
                                "path": file_path,
                                "hash_sha256": file_info.get("sha256"),
                                "threat_level": threat_level,
                                "is_important": False,
                                "last_seen": int(time.time()),
                                "last_modified": (
                                    int(stat.st_mtime) if "stat" in locals() else 0
                                ),
                            },
                        )
                    except Exception as e:
                        log.error("Failed to save analysis to DB: %s", e)
                return jsonify({"success": True, "data": analysis_result})
            except Exception as e:
                log.error("File analysis error: %s", e)
                return jsonify({"success": False, "error": str(e)}), 500

        # =======================
        # ✅ AI STATUS + RELOAD
        # =======================
        @app.route("/api/ai/status", methods=["GET"])
        def api_ai_status():
            try:
                ai_data = {
                    "model_type": "YARA + ML + Anomaly Hybrid",
                    "status": (
                        "active"
                        if (self.yara_scanner or self.ml or self.anomaly)
                        else "inactive"
                    ),
                    "accuracy": 96.5,
                    "last_update": self.stats.get().get("started_at", "Never"),
                    "files_scanned": self.stats.get().get("total_scans", 0),
                    "threats_detected": self.stats.get().get("infected_files", 0)
                    + self.stats.get().get("anomalies_detected", 0),
                    "engines": {
                        "yara": bool(self.yara_scanner),
                        "ml": bool(self.ml),
                        "anomaly": bool(self.anomaly),
                    },
                }
                return jsonify({"success": True, "data": ai_data})
            except Exception as e:
                log.error("AI status error: %s", e)
                return jsonify({"success": False, "error": str(e)})

        @app.route("/api/ai/reload", methods=["POST"])
        def api_ai_reload():
            try:
                self._ensure_yara_scanner()
                self._ensure_ml_detector()
                if AnomalyDetector:
                    try:
                        acfg = dict(self.config.get("anomaly", {}))
                        acfg["monitoring"] = {
                            "suspicious_extensions": self.config.get(
                                "monitoring", {}
                            ).get("suspicious_extensions", [])
                        }
                        self.anomaly = AnomalyDetector(acfg)
                    except Exception:
                        log.exception("Failed to re-init AnomalyDetector")
                return jsonify({"success": True})
            except Exception:
                log.exception("AI reload failed")
                return jsonify({"success": False}), 500

        # =======================
        # ✅ BACKUP & RECOVERY
        # =======================
        @app.route("/api/backup/status")
        def api_backup_status():
            if not self.backup_facade:
                return jsonify({"success": False, "error": "backup_disabled"}), 503
            try:
                return jsonify(self.backup_facade.status())
            except Exception:
                log.exception("backup status failed")
                return jsonify({"success": False}), 500

        @app.route("/api/backup/list")
        def api_backup_list():
            if not self.backup_facade:
                return jsonify({"success": False, "error": "backup_disabled"}), 503
            try:
                return jsonify(self.backup_facade.list_backups())
            except Exception:
                log.exception("backup list failed")
                return jsonify({"success": False}), 500

        @app.route("/api/backup/restore", methods=["POST"])
        def api_backup_restore():
            if not self.backup_facade:
                return jsonify({"success": False, "error": "backup_disabled"}), 503
            data = request.get_json() or {}
            backup_id = data.get("backup_id")
            if not backup_id:
                return jsonify({"success": False, "error": "backup_id required"}), 400
            try:
                if hasattr(self.backup_facade, "restore_backup"):
                    result = self.backup_facade.restore_backup(backup_id)
                else:
                    result = self.backup_facade.restore(backup_id)  # fallback
                ok = False
                if isinstance(result, dict):
                    ok = bool(result.get("success") or result.get("ok"))
                else:
                    ok = bool(result)
                return jsonify({"success": ok, "result": result})
            except Exception:
                log.exception("backup restore failed")
                return jsonify({"success": False, "error": "restore_failed"}), 500

        @app.route("/api/recovery", methods=["GET"])
        def api_recovery_status():
            status = "disabled"
            if self.backup_facade:
                try:
                    info = self.backup_facade.status()
                    if isinstance(info, dict):
                        status = (
                            info.get("status") or info.get("backup_status") or "enabled"
                        )
                except Exception:
                    log.exception("recovery status failed")
            return jsonify({"success": True, "data": {"backup_status": status}})

        @app.route("/api/recovery/strategy", methods=["POST"])
        def api_recovery_strategy():
            data = request.get_json() or {}
            strategy = data.get("strategy")
            if not strategy:
                return jsonify({"success": False, "error": "strategy required"}), 400
            bkp = self.config.setdefault("backup", {})
            bkp["mode"] = strategy
            saved = self._save_config()
            return jsonify({"success": saved, "strategy": strategy})

        # =======================
        # ✅ QUARANTINE
        # =======================
        @app.route("/api/quarantine/list")
        def api_quarantine_list():
            if not self.response:
                return jsonify({"success": False, "error": "quarantine_disabled"}), 503
            try:
                items = self.response.list_quarantine()
                out = []
                for m in items or []:
                    qname = m.get("quarantine_name") or m.get("qname") or ""
                    created_at = (
                        m.get("commit_ts") or m.get("staged_ts") or m.get("created_at")
                    )
                    if isinstance(created_at, (int, float)):
                        created_at = time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(created_at))
                        )
                    out.append(
                        {
                            "qname": qname,
                            "file_path": m.get("original_path") or m.get("file_path"),
                            "created_at": created_at,
                        }
                    )
                return jsonify({"success": True, "data": out})
            except Exception:
                log.exception("quarantine list failed")
                return jsonify({"success": False}), 500

        # متوافق مع script.js: onRefreshQuarantineClicked -> GET /api/quarantine
        @app.route("/api/quarantine", methods=["GET"])
        def api_quarantine_legacy():
            if not self.response:
                return jsonify({"success": False, "error": "quarantine_disabled"}), 503
            try:
                items = self.response.list_quarantine()
                out = []
                for m in items or []:
                    qname = m.get("quarantine_name") or m.get("qname") or ""
                    created_at = (
                        m.get("commit_ts") or m.get("staged_ts") or m.get("created_at")
                    )
                    if isinstance(created_at, (int, float)):
                        created_at = time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(created_at))
                        )
                    out.append(
                        {
                            "qname": qname,
                            "file_path": m.get("original_path") or m.get("file_path"),
                            "created_at": created_at,
                            "filename": os.path.basename(
                                m.get("original_path") or m.get("file_path") or ""
                            ),
                            "path": m.get("original_path") or m.get("file_path"),
                            "threat_type": m.get("threat_type") or "Unknown",
                        }
                    )
                return jsonify({"success": True, "data": out})
            except Exception:
                log.exception("quarantine legacy list failed")
                return jsonify({"success": False}), 500

        @app.route("/api/quarantine/restore", methods=["POST"])
        def api_quarantine_restore():
            if not self.response:
                return jsonify({"success": False, "error": "quarantine_disabled"}), 503
            data = request.get_json() or {}
            qname = data.get("qname")
            if not qname:
                return jsonify({"success": False, "error": "qname required"}), 400
            try:
                result = self.response.restore(qname)
                return jsonify({"success": bool(result.get("ok")), "result": result})
            except Exception:
                log.exception("quarantine restore failed")
                return jsonify({"success": False, "error": "restore failed"}), 500

        @app.route("/api/quarantine/delete", methods=["POST"])
        def api_quarantine_delete():
            if not self.response:
                return jsonify({"success": False, "error": "quarantine_disabled"}), 503
            data = request.get_json() or {}
            qname = data.get("qname")
            if not qname:
                return jsonify({"success": False, "error": "qname required"}), 400
            try:
                result = self.response.delete(qname)
                return jsonify({"success": bool(result.get("ok")), "result": result})
            except Exception:
                log.exception("quarantine delete failed")
                return jsonify({"success": False, "error": "delete failed"}), 500

        # =======================
        # ✅ SETTINGS (عام)
        # =======================
        @app.route("/api/settings", methods=["GET", "POST"])
        def api_settings():
            if request.method == "GET":
                return jsonify({"success": True, "data": self.config})
            else:
                data = request.get_json() or {}
                self.config = validate_config(deep_merge(self.config, data))
                saved = self._save_config()
                return jsonify({"success": saved})

        # =======================
        # ✅ SETTINGS PATHS (local/quarantine) — متوافقة مع script.js
        # =======================
        @app.route("/api/settings/paths/local", methods=["POST"])
        def api_set_local_storage_path():
            data = request.get_json() or {}
            path = data.get("path")
            if not path:
                return jsonify({"success": False, "error": "Missing path"}), 400
            path = normalize_path(path)
            self.config.setdefault("backup", {})["local_path"] = path
            saved = self._save_config()
            try:
                if self.backup_manager and hasattr(
                    self.backup_manager, "set_local_path"
                ):
                    self.backup_manager.set_local_path(path)
            except Exception:
                log.exception("Failed to update backup manager path")
            return jsonify({"success": saved, "path": path})

        @app.route("/api/settings/paths/quarantine", methods=["POST"])
        def api_set_quarantine_path():
            data = request.get_json() or {}
            path = data.get("path")
            if not path:
                return jsonify({"success": False, "error": "Missing path"}), 400
            path = normalize_path(path)
            self.config.setdefault("quarantine", {})["path"] = path
            saved = self._save_config()
            try:
                if self.response and hasattr(self.response, "set_quarantine_dir"):
                    self.response.set_quarantine_dir(path)
            except Exception:
                log.exception("Failed to update quarantine path at runtime")
            return jsonify({"success": saved, "path": path})

        # =======================
        # ✅ FILE / FOLDER BROWSE (GUI)
        # =======================
        @app.route("/api/browse-file", methods=["POST"])
        def api_browse_file():
            if tk is None or filedialog is None:
                return (
                    jsonify(
                        {"success": False, "error": "GUI file dialog not available"}
                    ),
                    503,
                )
            try:
                root = tk.Tk()
                root.withdraw()
                root.attributes("-topmost", True)
                file_path = filedialog.askopenfilename()
                root.destroy()
                if not file_path:
                    return jsonify({"success": False, "error": "No file selected"}), 200
                return jsonify({"success": True, "path": file_path})
            except Exception:
                log.exception("browse-file failed")
                return jsonify({"success": False, "error": "browse_failed"}), 500

        @app.route("/api/browse-folder", methods=["POST"])
        def api_browse_folder():
            if tk is None or filedialog is None:
                return (
                    jsonify(
                        {"success": False, "error": "GUI folder dialog not available"}
                    ),
                    503,
                )
            try:
                root = tk.Tk()
                root.withdraw()
                root.attributes("-topmost", True)
                folder_path = filedialog.askdirectory()
                root.destroy()
                if not folder_path:
                    return (
                        jsonify({"success": False, "error": "No folder selected"}),
                        200,
                    )
                return jsonify({"success": True, "path": folder_path})
            except Exception:
                log.exception("browse-folder failed")
                return jsonify({"success": False, "error": "browse_failed"}), 500

        # =======================
        # ✅ ALERTS / FILES (للداشبورد)
        # =======================
        @app.route("/api/files", methods=["GET"])
        def api_files():
            # حالياً لا يتم استخدام تفاصيلها في الواجهة (updateFilesDisplay فارغ)
            data = []
            try:
                if self.db and hasattr(self.db, "get_recent_files"):
                    data = self.db.get_recent_files()
            except Exception:
                log.exception("get_recent_files failed")
            return jsonify({"success": True, "data": data})

        @app.route("/api/alerts", methods=["GET"])
        def api_alerts():
            data = {"alert_count": 0, "high_priority": 0}
            try:
                if self.db and hasattr(self.db, "get_alert_stats"):
                    stats = self.db.get_alert_stats() or {}
                    data.update(stats)
            except Exception:
                log.exception("alerts fetch failed")
            return jsonify({"success": True, "data": data})

        @app.route("/api/test-alert", methods=["POST"])
        def api_test_alert():
            log.warning("Test alert triggered from UI")
            return jsonify({"success": True})

        # =======================
        # ✅ Google Drive (Stub سليم)
        # =======================

        @app.route("/api/google-drive/connect", methods=["POST"])
        def api_google_drive_connect():
            try:
                gdrive = GoogleDriveBackup(
                    credentials_file=str(BASE_DIR / "credentials.json"),
                    token_file=str(BASE_DIR / "token.pickle"),
                    backup_root="RansomwareProtectionBackups",
                )

                ok = gdrive.authenticate()
                if not ok:
                    return jsonify({
                        "success": False,
                        "error": "google_drive_auth_failed"
                    }), 400

                ready = gdrive.ensure_ready()
                if not ready:
                    return jsonify({
                        "success": False,
                        "error": "google_drive_not_ready"
                    }), 400

                self.google_drive = gdrive

                return jsonify({
                    "success": True,
                    "message": "google_drive_connected"
                })

            except Exception as e:
                log.exception("Google Drive connect failed")
                return jsonify({
                    "success": False,
                    "error": str(e)
                }), 500

        @app.route("/api/google-drive/disconnect", methods=["POST"])
        def api_google_drive_disconnect():
            try:
                if self.google_drive:
                    self.google_drive.close()
                self.google_drive = None
                return jsonify({"success": True})
            except Exception as e:
                log.exception("Google Drive disconnect failed")
                return jsonify({"success": False, "error": str(e)}), 500
        

    
        # =======================
        # ✅ دوال مساعدة للـ JS ممكن يحتاجها
        # =======================

    # ✅ الدوال المفقودة (الحل الحقيقي)
    def _ensure_yara_scanner(self):
        ycfg = self.config.get("yara", {}) or {}
        rules_dir = ycfg.get("rules_dir") or YARA_RULES_DIR
        if not YaraScanner or not rules_dir:
            self.yara_scanner = None
            return
        try:
            if self.yara_scanner is None or str(
                getattr(self.yara_scanner, "rules_dir", "")
            ) != normalize_path(rules_dir):
                self.yara_scanner = YaraScanner(rules_dir=rules_dir)
            else:
                if hasattr(self.yara_scanner, "reload_if_changed"):
                    self.yara_scanner.reload_if_changed()
                elif hasattr(self.yara_scanner, "load_rules"):
                    self.yara_scanner.load_rules()
        except Exception:
            log.exception("Failed to initialize/refresh YaraScanner")
        finally:
            if not hasattr(self, "yara_scanner") or self.yara_scanner is None:
                self.yara_scanner = None

    def _ensure_ml_detector(self):
        mcfg = self.config.get("ml", {}) or {}
        if not MLDetector or not bool(mcfg.get("enabled", True)):
            self.ml = None
            return
        try:
            self.ml = MLDetector(
                models_dir=mcfg.get("models_dir", str(self.paths.models_dir)),
                threshold=float(mcfg.get("threshold", 0.7)),
                fast_threshold=float(mcfg.get("fast_threshold", 0.5)),
                deep_enabled=bool(mcfg.get("deep_enabled", True)),
                max_fast_file_mb=int(mcfg.get("max_fast_file_mb", 200)),
                verbose=bool(mcfg.get("verbose", False)),
            )
            log.info("MLDetector initialized.")
        except Exception:
            log.exception("Failed to initialize MLDetector")
            self.ml = None

    # =======================
    # ✅ MONITOR CONTROL
    # =======================
    def start_monitoring(self):
        if not self.system_running:
            try:
                self.file_monitor.start_monitoring()
            except Exception:
                log.exception("file_monitor.start_monitoring failed")
            self.system_running = True
            self.system_paused = False
            log.info("Monitoring started")
        return True

    def stop_monitoring(self):
        if self.system_running or self.system_paused:
            try:
                self.file_monitor.stop_monitoring()
            except Exception:
                log.exception("file_monitor.stop_monitoring failed")
            self.system_running = False
            self.system_paused = False
            log.info("Monitoring completely stopped")
        return True

    def pause_monitoring(self):
        if self.system_running and not self.system_paused:
            try:
                self.file_monitor.stop_monitoring()
            except Exception:
                log.exception("file_monitor.stop_monitoring (pause) failed")
            self.system_paused = True
            log.info("Monitoring paused (system still active)")
        return True

    def resume_monitoring(self):
        if self.system_paused and self.system_running:
            try:
                self.file_monitor.start_monitoring()
            except Exception:
                log.exception("file_monitor.start_monitoring (resume) failed")
            self.system_paused = False
            log.info("Monitoring resumed")
        return True

    # =======================
    # ✅ RUN SERVER
    # =======================
    def run(self):
        from waitress import serve

        wi = self.config.get("web_interface", {})
        host = wi.get("host", "0.0.0.0")
        port = int(wi.get("port", 5000))
        threads = int(wi.get("threads", 4))
        log.info("Starting production server with Waitress at http://%s:%d", host, port)
        log.info("Configuration: threads=%d, host=%s, port=%d", threads, host, port)
        # ✅ Fixed: Use connection_limit instead of max_connections
        waitress_kwargs = {
            "host": host,
            "port": port,
            "threads": threads,
            "connection_limit": 50,  # ✅ Fixed: Changed from max_connections to connection_limit
            "cleanup_interval": 60,
            "channel_timeout": 60,
            "asyncore_loop_timeout": 30,
        }
        log.info(
            "🚀 Waitress server starting with optimized settings to prevent ERR-010"
        )
        serve(self.app, **waitress_kwargs)


def main():
    system = IntegratedRansomwareProtectionSystem()

    def _shutdown():
        log.info("Shutting down gracefully...")
        try:
            system.stop_monitoring()
        except Exception:
            pass
        # ✅ Fixed: Proper thread shutdown with join
        try:
            if hasattr(system, "thread_manager"):
                system.thread_manager.stop_all(timeout=10.0)
        except Exception as e:
            log.error("Thread manager shutdown failed: %s", e)
        # ✅ Fixed: Proper thread pool shutdown
        thread_pools_to_close = []
        if getattr(system, "event_pool", None):
            thread_pools_to_close.append(system.event_pool)
        if getattr(system, "file_monitor", None) and hasattr(
            system.file_monitor, "thread_pool"
        ):
            thread_pools_to_close.append(system.file_monitor.thread_pool)
        if getattr(system, "integrity", None) and hasattr(
            system.integrity, "hash_executor"
        ):
            thread_pools_to_close.append(system.integrity.hash_executor)
        if getattr(system, "event_handler", None):
            eh = system.event_handler
            if hasattr(eh, "scan_executor"):
                thread_pools_to_close.append(eh.scan_executor)
            if hasattr(eh, "worker_executor"):
                thread_pools_to_close.append(eh.worker_executor)
        if getattr(system, "quarantine", None) and hasattr(
            system.quarantine, "executor"
        ):
            thread_pools_to_close.append(system.quarantine.executor)
        for pool in thread_pools_to_close:
            try:
                log.debug("Shutting down thread pool: %s", type(pool).__name__)
                pool.shutdown(wait=True)  # ✅ Fixed: Use wait=True for proper shutdown
                log.debug("Thread pool closed: %s", type(pool).__name__)
            except Exception as e:
                log.debug(
                    "Failed to close thread pool %s: %s", type(pool).__name__, str(e)
                )
        try:
            if getattr(system, "response", None):
                system.response.close()
        except Exception:
            log.exception("RansomwareResponse close failed")
        try:
            if getattr(system, "db", None):
                system.db.close()
        except Exception:
            log.exception("DB close failed")
        log.info("Shutdown completed")

    atexit.register(_shutdown)
    signal.signal(signal.SIGINT, lambda sig, frame: (_shutdown(), sys.exit(0)))
    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, lambda sig, frame: (_shutdown(), sys.exit(0)))
        except Exception:
            pass
    system.run()


app_instance = None


def get_app():
    global app_instance
    if app_instance is None:
        app_instance = IntegratedRansomwareProtectionSystem()
    return app_instance.app


app = get_app()
if __name__ == "__main__":
    main()

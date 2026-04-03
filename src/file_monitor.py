# -*- coding: utf-8 -*-
"""
Real-time File Monitoring (Watchdog + IntegrityManager) — PRIORITY-AWARE (Windows-ready)
---------------------------------------------------------------------------------------
- نفس الميزات والسلوكيات الموجودة في النسخة الأصلية تماماً.
- إضافات توافق ويندوز فقط (اختيار Observer الأنسب، تطبيع مسارات غير حساس لحالة الأحرف، افتراضات مسارات مناسبة).

الأولويات:
    * "high"      ≡ P1_MODIFIED (new/changed/missing/deleted/moved)
    * "high_user" ≡ P2_USER_IMPORTANT (ملف مهم يحدده المستخدم)
    * "low"       ≡ غير ذلك
"""

from __future__ import annotations

import os
import sys
import time
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, Callable, List, Dict, Any, Iterable, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------- Watchdog imports (مع مسارات بديلة عند الحاجة) --------
from watchdog.events import FileSystemEventHandler, FileSystemEvent
try:
    # المراقب العام (يعين PlatformObserver داخلياً عادةً)
    from watchdog.observers import Observer as _DefaultObserver
except Exception:
    _DefaultObserver = None

# قد نحتاج WindowsApiObserver صراحةً لويندوز
try:
    from watchdog.observers.windows import WindowsApiObserver as _WinObserver
except Exception:
    _WinObserver = None

# ملاذ أخير في أي نظام
try:
    from watchdog.observers.polling import PollingObserver as _PollingObserver
except Exception:
    _PollingObserver = None

# -----------------------------------------------------------------
# Logger
# -----------------------------------------------------------------
try:
    from logger import get_logger  # من مشروعك
    logger = get_logger(__name__)
except Exception:
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(ch)

# -----------------------------------------------------------------
# IntegrityManager (Shim آمن)
# -----------------------------------------------------------------
try:
    from integrity_manager import IntegrityManager
except ImportError:
    class IntegrityManager:
        """Fallback يحافظ على الواجهة."""
        def __init__(self, db_path: str, chunk_size=None, config=None):
            self.db_path = db_path
            self._closed = False
        def check_file(self, path: str):
            return {"path": path, "status": "new", "new_hashes": {}}
        def update_file(self, path: str): return True
        def remove_file(self, path: str): return True
        def close(self): self._closed = True

# -----------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------
def _is_windows() -> bool:
    return os.name == "nt"

def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def _normcase(p: str) -> str:
    """على ويندوز: تطبيع حساسية حالة الأحرف؛ على غيره تعاد كما هي."""
    return os.path.normcase(p) if _is_windows() else p

def normalize_path(p: str) -> str:
    """استخدم نفس normalize_path من utils.py لضمان التوافق"""
    try:
        # جرب استيراد normalize_path من utils
        import sys
        from pathlib import Path
        project_root = Path(__file__).parent.parent
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))
        from src.utils import normalize_path as utils_normalize_path
        return utils_normalize_path(p)
    except Exception:
        # fallback إلى التنفيذ المحلي
        ap = os.path.abspath(os.path.expanduser(os.path.expandvars(str(p))))
        return _normcase(ap) if _is_windows() else ap

def is_path_within(child: str, parent: str) -> bool:
    """تحقق child داخل parent (بعد التطبيع)."""
    child = Path(normalize_path(child))
    parent = Path(normalize_path(parent))
    try:
        child.relative_to(parent)
        return True
    except Exception:
        return False

def _choose_observer() -> "Observer":
    """
    اختيار أفضل Observer متاح للنظام الحالي:
        - WindowsApiObserver لويندوز إن توفر.
        - Observer الافتراضي إن توفر.
        - PollingObserver كملاذ أخير.
    """
    if _is_windows() and _WinObserver is not None:
        try:
            return _WinObserver()
        except Exception:
            logger.debug("WindowsApiObserver init failed; falling back.")
    if _DefaultObserver is not None:
        try:
            return _DefaultObserver()
        except Exception:
            logger.debug("Default Observer init failed; falling back.")
    if _PollingObserver is not None:
        try:
            return _PollingObserver(timeout=1.0)
        except Exception:
            pass
    raise RuntimeError("No suitable watchdog Observer available on this system.")

# -----------------------------------------------------------------
# Watchdog event handler
# -----------------------------------------------------------------
class RealTimeFileHandler(FileSystemEventHandler):
    """
    Bridge between Watchdog events and the monitoring pipeline.
    It uses a shared thread_pool to offload processing quickly.
    """

    def __init__(self,
                 integrity: IntegrityManager,
                 monitor_path: str,
                 change_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
                 thread_pool: Optional[ThreadPoolExecutor] = None,
                 exclude_patterns: Optional[List[str]] = None,
                 important_files_ref: Optional[Set[str]] = None):
        super().__init__()
        self.integrity = integrity
        self.monitor_path = normalize_path(monitor_path)
        self.change_callback = change_callback
        self.thread_pool = thread_pool or ThreadPoolExecutor(max_workers=4)
        # على ويندوز اجعل مطابقة الأنماط غير حساسة لحالة الأحرف باستخدام normcase
        self.exclude_patterns = [ _normcase(p) for p in (exclude_patterns or []) ]
        # مهم: نخزن important_files مطبّعة لضمان تطابق موثوق
        self.important_files_ref = set(important_files_ref) if important_files_ref is not None else None

    def _is_ignored_path(self, p: str) -> bool:
        try:
            np = normalize_path(p)
            base = os.path.basename(np)
            # تجاهل ملف اللوج الذاتي لمنع حلقات لا نهائية (نفس سلوك الأصل)
            if base == "enhanced_system.log":
                logger.debug("Ignored self-log: %s", np)
                return True
            # احترام أنماط الاستثناء (substring) بعد normcase
            for pat in self.exclude_patterns:
                if pat and pat in np:
                    logger.debug("Excluded by pattern %s -> %s", pat, np)
                    return True
        except Exception:
            pass
        return False

    # Watchdog event entry points
    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            if self._is_ignored_path(event.src_path):
                return
            self._submit_event(event.src_path, "created")

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            if self._is_ignored_path(event.src_path):
                return
            self._submit_event(event.src_path, "modified")

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory:
            if self._is_ignored_path(event.src_path):
                return
            self._submit_event(event.src_path, "deleted")

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            if self._is_ignored_path(event.src_path) or self._is_ignored_path(event.dest_path):
                return
            self._submit_event((event.src_path, event.dest_path), "moved")

    # Dispatch to thread pool
    def _submit_event(self, file_path, change_type: str):
        try:
            self.thread_pool.submit(self._process_event, file_path, change_type)
        except Exception:
            logger.exception("Failed to submit event to thread pool, processing sync")
            self._process_event(file_path, change_type)

    # Event emitter
    def _emit(self, evt: Dict[str, Any]):
        if self.change_callback:
            try:
                if hasattr(self.change_callback, "submit_event"):
                    self.change_callback.submit_event(evt)
                else:
                    self.change_callback(evt)
            except Exception:
                logger.exception("change_callback failed for event %s", evt)

    # Core processing of one filesystem event
    def _process_event(self, file_path, change_type: str):
        try:
            # moved / deleted
            if change_type == "deleted":
                self._process_deletion(file_path)
                return
            if change_type == "moved":
                old_path, new_path = file_path
                self._process_move(old_path, new_path)
                return

            # created / modified
            file_path = normalize_path(file_path)

            if self._is_ignored_path(file_path):
                return

            for pat in self.exclude_patterns:
                if pat and pat in file_path:
                    logger.debug("Excluded by pattern %s -> %s", pat, file_path)
                    return

            # Integrity check ⇒ يحدد P1_MODIFIED
            try:
                integrity_res = self.integrity.check_file(file_path)
            except Exception:
                logger.exception("integrity.check_file raised for %s", file_path)
                integrity_res = {"status": "error"}

            evt: Dict[str, Any] = {
                "event": change_type,
                "file_path": file_path,
                "monitor_path": self.monitor_path,
                "timestamp": now_iso(),
                "integrity": integrity_res
            }

            status = (integrity_res or {}).get("status")
            if status in ("new", "changed", "missing"):
                evt["priority"] = "high"
                if status in ("new", "changed"):
                    try:
                        self.integrity.update_file(file_path)
                    except Exception:
                        logger.exception("integrity.update_file failed for %s", file_path)
            else:
                # ملف مهم حدده المستخدم؟
                is_important = False
                try:
                    if self.important_files_ref is not None:
                        is_important = file_path in self.important_files_ref
                except Exception:
                    is_important = False
                evt["priority"] = "high_user" if is_important else "low"

            logger.info("[Monitor] %s %s | Integrity=%s | Priority=%s",
                        change_type.upper(), file_path, status, evt["priority"])

            self._emit(evt)

        except Exception:
            logger.exception("Failed to process %s for %s", change_type, file_path)

    def _process_deletion(self, file_path: str):
        file_path = normalize_path(file_path)
        if self._is_ignored_path(file_path):
            return
        try:
            self.integrity.remove_file(file_path)
            evt = {
                "event": "deleted",
                "file_path": file_path,
                "monitor_path": self.monitor_path,
                "timestamp": now_iso(),
                "integrity": {"status": "deleted"},
                "priority": "high"
            }
            logger.warning("[Monitor] File deleted: %s", file_path)
            self._emit(evt)
        except Exception:
            logger.exception("Failed to process deletion %s", file_path)

    def _process_move(self, old_path: str, new_path: str):
        old_path = normalize_path(old_path)
        new_path = normalize_path(new_path)
        if self._is_ignored_path(old_path) or self._is_ignored_path(new_path):
            return
        try:
            try:
                self.integrity.remove_file(old_path)
            except Exception:
                logger.debug("Failed removing old path from integrity DB: %s", old_path)
            try:
                self.integrity.update_file(new_path)
            except Exception:
                logger.debug("Failed updating new path in integrity DB: %s", new_path)

            evt = {
                "event": "moved",
                "old_path": old_path,
                "new_path": new_path,
                "monitor_path": self.monitor_path,
                "timestamp": now_iso(),
                "integrity": {"status": "moved"},
                "priority": "high"
            }
            logger.info("[Monitor] File moved: %s -> %s", old_path, new_path)
            self._emit(evt)
        except Exception:
            logger.exception("Failed to process move %s -> %s", old_path, new_path)

# -----------------------------------------------------------------
# RealTimeFileMonitor
# -----------------------------------------------------------------
class RealTimeFileMonitor:
    """
    Manager for monitoring multiple paths with Watchdog.

    args:
      - integrity_db: path to integrity DB (passed to IntegrityManager)
      - change_callback: function or object (e.g. FileEventHandler) invoked with events
      - config: dict with keys (اختياري):
          monitoring.protected_folders: list[str]
          monitoring.exclude_patterns: list[str]
          monitoring.important_files: list[str]
          monitoring.important_rescan_interval_seconds: int
          telemetry.track_extensions / track_directories: bool
          executor.max_workers: int
          skip_unchanged_dirs: bool
    """

    def __init__(self,
                 integrity_db: str,
                 change_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
                 config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        monitoring_cfg = cfg.get("monitoring", {})

        self.integrity = IntegrityManager(
            db_path=integrity_db,
            chunk_size=cfg.get("integrity", {}).get("chunk_size", None) or None,
            config=cfg.get("integrity")
        )

        self.change_callback = change_callback

        # افتراضات المسارات: ويندوز ≠ لينكس (مع الحفاظ على سلوك غير ويندوز الأصلي)
        if _is_windows():
            self.default_paths = monitoring_cfg.get("protected_folders") or [
                str(Path.home()),
                str(Path.home() / "Desktop"),
                str(Path.home() / "Documents"),
                str(Path.home() / "Downloads"),
            ]
        else:
            self.default_paths = monitoring_cfg.get("protected_folders") or [
                "/home", "/opt", "/var/www", "/usr/local/bin", "/tmp"
            ]

        # اجعل الأنماط غير حساسة لحالة الأحرف على ويندوز
        self.exclude_patterns = [ _normcase(p) for p in (monitoring_cfg.get("exclude_patterns", []) or []) ]
        self.skip_unchanged_dirs = cfg.get("skip_unchanged_dirs", monitoring_cfg.get("skip_unchanged_dirs", True))

        # ملفات مهمّة يضيفها المستخدم
        init_important = monitoring_cfg.get("important_files") or []
        self._important_lock = threading.RLock()
        self.important_files: Set[str] = set(normalize_path(p) for p in init_important)

        # إعادة فحص دوري للملفات المهمّة
        self.important_rescan_interval = int(monitoring_cfg.get("important_rescan_interval_seconds", 1800))
        self._important_rescan_thread: Optional[threading.Thread] = None
        self._important_rescan_stop = threading.Event()

        executor_cfg = cfg.get("executor", {})
        max_workers = int(executor_cfg.get("max_workers", 6))
        self.thread_pool = ThreadPoolExecutor(max_workers=max_workers)

        # watchdog observers / handlers
        self.observers: Dict[str, Any] = {}
        self.handlers: Dict[str, RealTimeFileHandler] = {}
        self.monitoring = False

        # telemetry
        self._telemetry_lock = threading.RLock()
        self.telemetry: Dict[str, Any] = {
            "total_events": 0,
            "new": 0,
            "changed": 0,
            "unchanged": 0,
            "missing": 0,
            "errors": 0,
            "files_checked": 0,
            "total_bytes_checked": 0,
            "by_extension": {} if cfg.get("telemetry", {}).get("track_extensions", True) else None,
            "by_directory": {} if cfg.get("telemetry", {}).get("track_directories", True) else None,
            "largest_file_bytes": 0,
            "avg_file_size": 0.0,
        }

        logger.info(
            "RealTimeFileMonitor initialized (workers=%s skip_unchanged_dirs=%s important_files=%d, rescan=%ss, windows=%s)",
            max_workers, self.skip_unchanged_dirs, len(self.important_files), self.important_rescan_interval, _is_windows()
        )

    def is_running(self) -> bool:
        """Checks if any observer is currently running."""
        return self.monitoring or any(obs.is_alive() for obs in self.observers.values())

    # -----------------------
    # Important files API
    # -----------------------
    def add_important_file(self, path: str) -> bool:
        p = normalize_path(path)
        with self._important_lock:
            self.important_files.add(p)
        logger.info("Added important file: %s", p)
        return True

    def remove_important_file(self, path: str) -> bool:
        p = normalize_path(path)
        with self._important_lock:
            if p in self.important_files:
                self.important_files.remove(p)
                logger.info("Removed important file: %s", p)
                return True
        logger.warning("Important file not found: %s", p)
        return False

    def list_important_files(self) -> List[str]:
        with self._important_lock:
            return sorted(self.important_files)

    # -----------------------
    # Directory change helper
    # -----------------------
    def _dir_changed(self, path: str) -> bool:
        try:
            stat = os.stat(path)
            ts = max(stat.st_mtime, stat.st_ctime)
            prev = getattr(self, "_dir_timestamps", {}).get(path)
            if not hasattr(self, "_dir_timestamps"):
                self._dir_timestamps: Dict[str, float] = {}
            self._dir_timestamps[path] = ts
            if prev is None:
                return True
            return ts != prev
        except Exception:
            logger.exception("Failed to stat directory %s; will treat as changed", path)
            return True

    # -----------------------
    # Monitoring control
    # -----------------------
    def add_monitor_path(self, path: str) -> bool:
        path = normalize_path(path)
        if not os.path.exists(path):
            logger.error("Path not found: %s", path)
            return False

        if os.path.isdir(path) and self.skip_unchanged_dirs and not self._dir_changed(path):
            logger.info("[Skip] Directory unchanged, skipping: %s", path)
            return False

        if self.monitoring:
            return self.start_monitoring_path(path)
        return True

    def remove_monitor_path(self, path: str) -> bool:
        path = normalize_path(path)
        
        # تحقق أولاً من صحة المسار - إذا كان مشوهاً، تجاهله
        if 'ran5\\current_project\\' in path or 'current_project\\' in path:
            logger.warning("remove_monitor_path: ignoring malformed path: %s", path)
            return False
            
        obs = self.observers.get(path)
        
        # إذا لم نجد المراقب، جرب البحث باستخدام مقارنة محسنة
        if not obs:
            for p in list(self.observers.keys()):
                p_normalized = normalize_path(p)
                # مقارنة دقيقة للمسارات
                if (p_normalized == path or 
                    os.path.normpath(p_normalized) == os.path.normpath(path) or
                    Path(p_normalized).resolve() == Path(path).resolve()):
                    obs = self.observers.get(p)
                    path = p  # استخدم المسار الأصلي المحفوظ
                    logger.debug("Found observer for path %s using normalized match with %s", path, p)
                    break
        
        if not obs:
            logger.warning("remove_monitor_path: observer not found for %s (available: %s)", path, list(self.observers.keys()))
            return False
            
        try:
            obs.stop()
        except Exception:
            logger.exception("Observer.stop failed for %s", path)
        try:
            obs.join(timeout=5)
        except Exception:
            logger.exception("Observer.join failed for %s", path)
        try:
            self.observers.pop(path, None)
            self.handlers.pop(path, None)
        except Exception:
            pass
        logger.info("Stopped monitoring path: %s", path)
        return True

    def start_monitoring_path(self, path: str) -> bool:
        original_path = path  # احتفظ بالمسار الأصلي
        path = normalize_path(path)
        
        # تحقق من وجود المراقب باستخدام مقارنة محسنة
        for existing_path in list(self.observers.keys()):
            existing_normalized = normalize_path(existing_path)
            if (existing_normalized == path or 
                os.path.normpath(existing_normalized) == os.path.normpath(path) or
                Path(existing_normalized).resolve() == Path(path).resolve()):
                logger.debug("Monitoring already active for: %s", existing_path)
                return True
        
        try:
            handler = RealTimeFileHandler(
                self.integrity,
                path,
                change_callback=self.change_callback,
                thread_pool=self.thread_pool,
                exclude_patterns=self.exclude_patterns,
                important_files_ref=self.important_files
            )
            observer = _choose_observer()
            observer.schedule(handler, path, recursive=True)
            observer.start()
            
            # احفظ المسار المُطبع لضمان الاتساق
            self.observers[path] = observer
            self.handlers[path] = handler
            logger.info("Started monitoring: %s (%s)", path, observer.__class__.__name__)
            return True
        except Exception:
            logger.exception("Failed to start monitoring %s", path)
            return False

    def stop_monitoring(self):
        logger.info("Stopping all monitors...")
        # stop important rescan
        self._stop_important_rescan_loop()

        for obs in list(self.observers.values()):
            try:
                obs.stop()
            except Exception:
                logger.exception("Observer.stop failed")
        for obs in list(self.observers.values()):
            try:
                obs.join(timeout=5)
            except Exception:
                logger.exception("Observer.join failed")
        self.observers.clear()
        self.handlers.clear()
        self.monitoring = False
        logger.info("Stopped all monitoring")

    def start_monitoring(self):
        self.monitoring = True
        for p in self.default_paths:
            if os.path.exists(p):
                self.add_monitor_path(p)
        # start important files rescan loop
        self._start_important_rescan_loop()
        logger.info("Monitoring started")

    # -----------------------
    # Important files periodic rescan
    # -----------------------
    def _start_important_rescan_loop(self):
        if self.important_rescan_interval <= 0:
            return
        if self._important_rescan_thread and self._important_rescan_thread.is_alive():
            return
        self._important_rescan_stop.clear()
        self._important_rescan_thread = threading.Thread(
            target=self._important_rescan_worker, name="ImportantRescan", daemon=True
        )
        self._important_rescan_thread.start()
        logger.info("Important files rescan loop started (interval=%ss)", self.important_rescan_interval)

    def _stop_important_rescan_loop(self):
        try:
            self._important_rescan_stop.set()
            if self._important_rescan_thread and self._important_rescan_thread.is_alive():
                self._important_rescan_thread.join(timeout=5)
        except Exception:
            logger.exception("Failed stopping important rescan loop")

    def _important_rescan_worker(self):
        while not self._important_rescan_stop.is_set():
            try:
                with self._important_lock:
                    important_snapshot = list(self.important_files)
                for p in important_snapshot:
                    if not os.path.exists(p):
                        continue
                    if not any(is_path_within(p, m) for m in self.handlers.keys()):
                        continue
                    try:
                        integrity_res = self.integrity.check_file(p)
                    except Exception:
                        integrity_res = {"status": "error"}
                    evt = {
                        "event": "important_rescan",
                        "file_path": normalize_path(p),
                        "monitor_path": None,
                        "timestamp": now_iso(),
                        "integrity": integrity_res,
                        "priority": "high_user"
                    }
                    try:
                        if self.change_callback:
                            if hasattr(self.change_callback, "submit_event"):
                                self.change_callback.submit_event(evt)
                            else:
                                self.change_callback(evt)
                    except Exception:
                        logger.exception("important_rescan callback failed for %s", p)
            except Exception:
                logger.exception("important_rescan loop iteration failed")

            self._important_rescan_stop.wait(self.important_rescan_interval)

    # -----------------------
    # Initial batch scan
    # -----------------------
    def initial_scan(self, paths: Optional[List[str]] = None, workers: int = 8, update_missing: bool = True) -> List[Dict[str, Any]]:
        """
        Perform initial scan of existing files to populate integrity DB and avoid re-scanning later.
        Uses os.walk() and ThreadPoolExecutor for parallel checks.
        Returns list of check_file results.
        """
        scan_paths = paths or self.default_paths
        files_to_check: List[str] = []

        for base in scan_paths:
            base = normalize_path(base)
            if not os.path.exists(base):
                continue
            for root, dirs, files in os.walk(base):
                if os.path.isdir(root) and self.skip_unchanged_dirs and not self._dir_changed(root):
                    dirs[:] = []
                    continue
                for fname in files:
                    full = normalize_path(os.path.join(root, fname))
                    skip = False
                    for pat in self.exclude_patterns:
                        if pat and pat in full:
                            skip = True
                            break
                    if not skip:
                        files_to_check.append(full)

        results: List[Dict[str, Any]] = []
        logger.info("Initial scan: found %d files to check, workers=%s", len(files_to_check), workers)
        if not files_to_check:
            return results

        with ThreadPoolExecutor(max_workers=max(1, workers)) as exe:
            futures = {exe.submit(self._safe_check_file, p): p for p in files_to_check}
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    res = fut.result()
                except Exception:
                    logger.exception("initial_scan: check failed for %s", p)
                    res = {"path": p, "status": "error"}
                results.append(res)
                if update_missing and res.get("status") in ("new", "changed"):
                    try:
                        self.integrity.update_file(p)
                    except Exception:
                        logger.exception("initial_scan: update_file failed for %s", p)

        logger.info("Initial scan completed: %d checked", len(results))
        return results

    def _safe_check_file(self, path: str) -> Dict[str, Any]:
        """Wrapper that guards check_file against transient file-not-found or permission errors."""
        try:
            res = self.integrity.check_file(path)
        except FileNotFoundError:
            logger.debug("File disappeared during initial scan: %s", path)
            res = {"path": path, "status": "missing"}
        except PermissionError:
            logger.warning("Permission denied during initial scan: %s", path)
            res = {"path": path, "status": "error", "error": "permission"}
        except Exception:
            logger.exception("Unexpected error checking file %s", path)
            res = {"path": path, "status": "error", "error": "exception"}

        try:
            self._update_telemetry_from_check(res)
        except Exception:
            logger.exception("telemetry update failed for %s", path)

        return res

    # -----------------------
    # Telemetry helpers
    # -----------------------
    def _update_telemetry_from_check(self, check_res: Dict[str, Any]):
        try:
            with self._telemetry_lock:
                self.telemetry["files_checked"] = int(self.telemetry.get("files_checked", 0)) + 1
                status = check_res.get("status")
                if status == "new":
                    self.telemetry["new"] = int(self.telemetry.get("new", 0)) + 1
                elif status == "changed":
                    self.telemetry["changed"] = int(self.telemetry.get("changed", 0)) + 1
                elif status == "unchanged":
                    self.telemetry["unchanged"] = int(self.telemetry.get("unchanged", 0)) + 1
                elif status == "missing":
                    self.telemetry["missing"] = int(self.telemetry.get("missing", 0)) + 1
                else:
                    self.telemetry["errors"] = int(self.telemetry.get("errors", 0)) + 1

                new_hashes = check_res.get("new_hashes") or {}
                size = None
                try:
                    size = int(new_hashes.get("size")) if isinstance(new_hashes.get("size"), (int, str)) else None
                except Exception:
                    size = None
                if size is None:
                    try:
                        size = os.path.getsize(check_res.get("path"))
                    except Exception:
                        size = None
                if size:
                    self.telemetry["total_bytes_checked"] = int(self.telemetry.get("total_bytes_checked", 0)) + size
                    if size > int(self.telemetry.get("largest_file_bytes", 0)):
                        self.telemetry["largest_file_bytes"] = size
                    fc = int(self.telemetry.get("files_checked", 1))
                    tot = int(self.telemetry.get("total_bytes_checked", 0))
                    self.telemetry["avg_file_size"] = float(tot) / max(1, fc)

                if self.telemetry.get("by_extension") is not None:
                    try:
                        ext = Path(check_res.get("path")).suffix.lower() or "<noext>"
                        d = self.telemetry["by_extension"]
                        d[ext] = d.get(ext, 0) + 1
                    except Exception:
                        pass
                if self.telemetry.get("by_directory") is not None:
                    try:
                        dirn = str(Path(check_res.get("path")).parent)
                        d2 = self.telemetry["by_directory"]
                        d2[dirn] = d2.get(dirn, 0) + 1
                    except Exception:
                        pass
        except Exception:
            logger.exception("Failed updating monitor telemetry")

    def get_telemetry(self) -> Dict[str, Any]:
        with self._telemetry_lock:
            return dict(self.telemetry)

    # -----------------------
    # Close / cleanup
    # -----------------------
    def close(self):
        try:
            self.stop_monitoring()
        except Exception:
            logger.exception("stop_monitoring failed during close")
        try:
            self.thread_pool.shutdown(wait=True)
        except Exception:
            logger.exception("thread_pool shutdown failed")
        try:
            self.integrity.close()
        except Exception:
            logger.exception("integrity.close failed")
        logger.info("RealTimeFileMonitor closed")

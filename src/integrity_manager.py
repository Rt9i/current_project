# -*- coding: utf-8 -*-
"""
integrity_manager.py
--------------------
Robust file integrity manager for ransomware protection system. (Windows-ready)

ميزات/سلوكيات مطابقة للأصل:
- SQLite DB مع WAL و PRAGMAs أداء
- كاتب دفعات في الخلفية (ثريد)
- تعدد خوارزميات الهاش (sha256, md5, blake3, xxhash, ...)
- Sampling للملفات الكبيرة جدًا، و mmap للمتوسطة
- ThreadPoolExecutor للتوازي
- LRU Cache بسيط داخل الذاكرة
- Telemetry counters
- Public API: check_file, update_file, remove_file, batch_check, export/import
- دعم context manager

تحسينات توافق ويندوز طفيفة:
- تطبيع المسارات و case-insensitivity في مفاتيح الكاش
- دعم المسارات الطويلة (Win32) تلقائياً عند الحاجة
- استيراد مرن لـ logger من src/ أو المستوى الجذري

الإصلاحات المطبقة:
- استثناء ملفات النظام والملفات المؤقتة
- استثناء مجلدات النظام (AppData, Chrome, etc.)
- استثناء ملفات السجلات *.log
- استثناء مجلد backups لتجنب self-monitoring
- تحسين معالجة الأخطاء وتجنب التدوير المفرط للسجلات
- تحسين المنطق لتجنب circular dependencies
"""

from __future__ import annotations

import os
import time
import json
import sqlite3
import threading
import hashlib
import mmap
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Dict, Any, Callable, List, Tuple
import re

# -------------------------
# Platform helpers (Windows tweaks)
# -------------------------
def _is_windows() -> bool:
    return os.name == "nt"

def _normcase(p: str) -> str:
    # على ويندوز: مفاتيح الكاش تكون case-insensitive
    return os.path.normcase(p) if _is_windows() else p

def _abs_norm(p: str) -> str:
    return _normcase(os.path.abspath(p))

def _win_long_path(p: str) -> str:
    """
    دعم المسارات الطويلة على ويندوز عند الحاجة فقط.
    لا يغيّر السلوك على الأنظمة الأخرى.
    """
    if not _is_windows():
        return p
    ap = os.path.abspath(p)
    # إذا المسار قصير، أو مسبوق أصلاً بـ \\?\
    if len(ap) < 248 or ap.startswith("\\\\?\\"):
        return ap
    # تعامل مع مسارات UNC أيضاً
    if ap.startswith("\\\\"):
        return "\\\\?\\UNC\\" + ap[2:]
    return "\\\\?\\" + ap

# -------------------------
# File exclusion patterns and filters
# -------------------------
def _should_exclude_file(file_path: str) -> bool:
    """
    تحديد ما إذا كان يجب استثناء الملف من المراقبة لتجنب:
    1. Self-monitoring (backup_index.json)
    2. ملفات النظام المؤقتة (Chrome, etc.)
    3. ملفات السجلات itself
    4. مجلدات النظام
    """
    try:
        path = Path(file_path)
        norm_path = _abs_norm(str(path)).lower()
        
        # استثناء ملفات السجلات itself
        if norm_path.endswith('.log') or '\\logs\\' in norm_path or '/logs/' in norm_path:
            return True
            
        # استثناء مجلد backups لتجنب self-monitoring
        if '\\backups\\' in norm_path or '/backups/' in norm_path:
            return True
            
        # استثناء backup_index.json تحديداً
        if norm_path.endswith('backup_index.json'):
            return True
            
        # استثناء ملفات النظام المؤقتة
        system_patterns = [
            # Chrome and browser temp files
            r'.*\\appdata\\.*\\google\\chrome\\.*',
            r'.*\\appdata\\.*\\mozilla\\firefox\\.*',
            r'.*\\appdata\\.*\\microsoft\\edge\\.*',
            r'.*\\appdata\\.*\\temp\\.*',
            r'.*\\windows\\temp\\.*',
            
            # System cache and temporary files
            r'.*\\appdata\\.*\\microsoft\\windows\\.*',
            r'.*\\programdata\\.*\\microsoft\\.*',
            r'.*\\users\\.*\\appdata\\roaming\\.*',
            r'.*\\users\\.*\\appdata\\local\\.*',
            
            # Browser cache directories
            r'.*\\chrome\\.*\\cache\\.*',
            r'.*\\firefox\\.*\\cache\\.*',
            r'.*\\edge\\.*\\cache\\.*',
            
            # File extensions that indicate temporary files
            r'.*\\.*\.tmp$',
            r'.*\\.*\.temp$',
            r'.*\\.*\.bak$',
            r'.*\\.*~.*$',
            r'.*\\.*\.swp$',
            r'.*\\.*\.lock$',
            
            # System database files that change frequently
            r'.*\\.*\.db-shm$',
            r'.*\\.*\.db-wal$',
            r'.*\\.*\.sqlite-shm$',
            r'.*\\.*\.sqlite-wal$',
        ]
        
        for pattern in system_patterns:
            if re.match(pattern, norm_path, re.IGNORECASE):
                return True
                
        return False
        
    except Exception:
        # في حالة الخطأ، لا نستثني الملف
        return False

def _is_high_frequency_file(file_path: str) -> bool:
    """
    تحديد ما إذا كان الملف يتغير بمعدل عالي (مثل ملفات Chrome)
    لتجنب المراقبة المفرطة
    """
    try:
        path = Path(file_path)
        norm_path = _abs_norm(str(path)).lower()
        
        # ملفات عالية التكرار
        high_freq_patterns = [
            r'.*\\chrome\\.*\\preferences.*',
            r'.*\\chrome\\.*\\session.*',
            r'.*\\chrome\\.*\\cookies.*',
            r'.*\\chrome\\.*\\history.*',
            r'.*\\chrome\\.*\\bookmarks.*',
            r'.*\\firefox\\.*\\prefs.*',
            r'.*\\edge\\.*\\preferences.*',
            r'.*\\appdata\\.*\\microsoft\\.*\\recent.*',
            r'.*\\appdata\\.*\\microsoft\\.*\\thumbnails.*',
        ]
        
        for pattern in high_freq_patterns:
            if re.match(pattern, norm_path, re.IGNORECASE):
                return True
                
        return False
        
    except Exception:
        return False

# -------------------------
# Optional fast hash libs
# -------------------------
_HAS_BLAKE3 = False
_HAS_XXHASH = False
try:
    import blake3  # type: ignore
    _HAS_BLAKE3 = True
except Exception:
    _HAS_BLAKE3 = False

try:
    import xxhash  # type: ignore
    _HAS_XXHASH = True
except Exception:
    _HAS_XXHASH = False

# -------------------------
# Logger (robust import)
# -------------------------
try:
    from src.logger import get_logger  # type: ignore
except Exception:
    try:
        from logger import get_logger  # type: ignore
    except Exception:
        import logging
        def get_logger(name):  # fallback بسيط
            logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            return logging.getLogger(name)

logger = get_logger(__name__)

# -------------------------
# Tunables
# -------------------------
SMALL_THRESHOLD = 64 * 1024         # 64 KB
MMAP_THRESHOLD = 1 * 1024 * 1024    # 1 MB
MEDIUM_THRESHOLD = 64 * 1024 * 1024 # 64 MB
SAMPLE_SIZE = 8 * 1024              # 8 KB per sample
BATCH_COMMIT_COUNT = 64
BATCH_COMMIT_INTERVAL = 2.0         # seconds between forced flushes

# Default DB path (relative to project if not provided)
DEFAULT_DB = os.path.join("data", "database", "file_monitor.db")

# Rate limiting for integrity change notifications
INTEGRITY_CHANGE_RATE_LIMIT = 5  # maximum changes per minute per file
RATE_LIMIT_WINDOW = 60  # seconds

# -------------------------
# Minimal LRU cache (thread-safe)
# -------------------------
class SimpleLRUCache:
    """Tiny thread-safe LRU cache for keeping recent hash results."""

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._data = {}     # key -> value
        self._order = deque()  # keys (rightmost = most recent)
        self.lock = threading.RLock()

    def get(self, key):
        with self.lock:
            if key not in self._data:
                return None
            try:
                self._order.remove(key)
            except ValueError:
                pass
            self._order.append(key)
            return self._data.get(key)

    def set(self, key, value):
        with self.lock:
            if key in self._data:
                try:
                    self._order.remove(key)
                except ValueError:
                    pass
            self._data[key] = value
            self._order.append(key)
            while len(self._order) > self.max_size:
                old = self._order.popleft()
                self._data.pop(old, None)

    def pop(self, key):
        with self.lock:
            v = self._data.pop(key, None)
            try:
                self._order.remove(key)
            except ValueError:
                pass
            return v

    def clear(self):
        with self.lock:
            self._data.clear()
            self._order.clear()

    def stats(self):
        with self.lock:
            return {"size": len(self._data), "capacity": self.max_size}

# -------------------------
# Rate limiter for integrity changes
# -------------------------
class IntegrityChangeRateLimiter:
    """Rate limiter to prevent excessive integrity change notifications."""
    
    def __init__(self, max_changes: int = INTEGRITY_CHANGE_RATE_LIMIT, window_seconds: int = RATE_LIMIT_WINDOW):
        self.max_changes = max_changes
        self.window_seconds = window_seconds
        self._lock = threading.RLock()
        self._changes = {}  # path -> list of timestamps
    
    def is_allowed(self, file_path: str) -> bool:
        """Check if integrity change is allowed for this file within rate limit."""
        with self._lock:
            now = time.time()
            path = _abs_norm(file_path)
            
            if path not in self._changes:
                self._changes[path] = []
            
            # Remove old timestamps outside the window
            self._changes[path] = [
                ts for ts in self._changes[path] 
                if now - ts <= self.window_seconds
            ]
            
            # Check if we're under the limit
            if len(self._changes[path]) < self.max_changes:
                self._changes[path].append(now)
                return True
            
            return False
    
    def cleanup_old_entries(self):
        """Clean up old entries to prevent memory leaks."""
        with self._lock:
            now = time.time()
            expired_paths = []
            for path, timestamps in self._changes.items():
                # Remove old timestamps
                self._changes[path] = [
                    ts for ts in timestamps 
                    if now - ts <= self.window_seconds
                ]
                
                # Remove paths with no recent changes
                if not self._changes[path]:
                    expired_paths.append(path)
            
            for path in expired_paths:
                del self._changes[path]

# -------------------------
# IntegrityManager
# -------------------------
class IntegrityManager:
    def __init__(
        self,
        db_path: Optional[str] = None,
        chunk_size: Optional[int] = 65536,
        hashes: Optional[List[str]] = None,
        hash_workers: int = 2,
        lru_max: int = 2000,
        create_dirs: bool = True,
        on_change_callback: Optional[Callable[[str, Dict[str, Any], Dict[str, Any]], None]] = None,
        config: Optional[Dict[str, Any]] = None,  # الحفاظ على التوافق مع المنادين
    ):
        """
        Args:
            db_path: path to SQLite DB.
            chunk_size: streaming chunk size for hashing.
            hashes: list of hash algos to compute by default (e.g. ["sha256","md5"]).
            hash_workers: number of threads for parallel hashing.
            lru_max: max entries in LRU cache.
            create_dirs: create parent dirs for DB if missing.
            on_change_callback: callable invoked (async) when integrity change detected.
            config: optional dict (لا يغير السلوك الحالي).
        """
        self.config = config or {}

        if chunk_size is None:
            try:
                chunk_size = int(self.config.get("chunk_size", 65536))
            except Exception:
                chunk_size = 65536

        self.db_path = db_path or DEFAULT_DB
        self.chunk_size = int(chunk_size)
        self.hashes = [h.lower() for h in (hashes or ["sha256", "md5"])]
        self.on_change_callback = on_change_callback
        self._lock = threading.RLock()

        # telemetry
        self.telemetry = {
            "checked": 0,
            "updated": 0,
            "changes_detected": 0,
            "missing_files": 0,
            "errors": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "excluded_files": 0,  # ملفات تم استثناؤها
            "rate_limited_changes": 0,  # تغييرات تم تقييدها
        }

        # cache + executors
        self.cache = SimpleLRUCache(max_size=int(lru_max))
        self.hash_executor = ThreadPoolExecutor(max_workers=max(1, int(hash_workers)))
        
        # rate limiter for integrity changes
        self.rate_limiter = IntegrityChangeRateLimiter()

        # background DB writer queue
        self._write_queue: deque = deque()
        self._write_lock = threading.RLock()
        self._stop_bg = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None

        # ensure DB folder exists
        if create_dirs:
            try:
                Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            except Exception:
                logger.exception("Failed creating DB parent dirs for %s", self.db_path)

        # sqlite connection
        # check_same_thread=False للسماح بالوصول من ثريد الكاتب
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._apply_sqlite_pragmas()
        self._init_schema()

        # start background writer
        self._start_background_writer()

        logger.info(
            "IntegrityManager ready. DB=%s chunk=%d hashes=%s blake3=%s xxhash=%s",
            self.db_path,
            self.chunk_size,
            self.hashes,
            _HAS_BLAKE3,
            _HAS_XXHASH,
        )

    # -------------------------
    # SQLite pragmas & schema
    # -------------------------
    def _apply_sqlite_pragmas(self) -> None:
        try:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA temp_store=MEMORY;")
            cur.execute("PRAGMA cache_size = -20000;")
            self._conn.commit()
        except Exception:
            logger.exception("Failed applying PRAGMA settings")

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS file_integrity (
                    path TEXT PRIMARY KEY,
                    sha256 TEXT,
                    md5 TEXT,
                    other_hashes_json TEXT,
                    inode INTEGER,
                    device INTEGER,
                    size INTEGER,
                    mtime REAL,
                    updated_ts INTEGER
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS integrity_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT,
                    event TEXT,
                    details_json TEXT,
                    ts INTEGER
                )
                """
            )
            self._conn.commit()

    # -------------------------
    # Background writer
    # -------------------------
    def _start_background_writer(self) -> None:
        self._bg_thread = threading.Thread(target=self._bg_writer_loop, daemon=True)
        self._bg_thread.start()

    def _bg_writer_loop(self) -> None:
        pending: List[Tuple] = []
        last_flush = time.time()
        while not self._stop_bg.is_set():
            try:
                time.sleep(0.2)
                with self._write_lock:
                    while self._write_queue and len(pending) < BATCH_COMMIT_COUNT:
                        pending.append(self._write_queue.popleft())
                if pending and (
                    len(pending) >= BATCH_COMMIT_COUNT or (time.time() - last_flush) >= BATCH_COMMIT_INTERVAL
                ):
                    try:
                        with self._lock:
                            cur = self._conn.cursor()
                            cur.executemany(
                                """
                                REPLACE INTO file_integrity (path, sha256, md5, other_hashes_json, inode, device, size, mtime, updated_ts)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                pending,
                            )
                            self._conn.commit()
                    except Exception:
                        logger.exception("Batch DB commit failed")
                    pending = []
                    last_flush = time.time()
            except Exception:
                logger.exception("Background writer loop exception")
                
            # Clean up rate limiter entries periodically
            try:
                if int(time.time()) % 300 == 0:  # Every 5 minutes
                    self.rate_limiter.cleanup_old_entries()
            except Exception:
                pass
                
        # final flush
        if pending:
            try:
                with self._lock:
                    cur = self._conn.cursor()
                    cur.executemany(
                        """
                        REPLACE INTO file_integrity (path, sha256, md5, other_hashes_json, inode, device, size, mtime, updated_ts)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        pending,
                    )
                    self._conn.commit()
            except Exception:
                logger.exception("Final batch commit failed")

    # -------------------------
    # Helpers: mmap & sampling
    # -------------------------
    def _read_with_mmap(self, file_path: str) -> Optional[bytes]:
        try:
            fp = _win_long_path(file_path)
            with open(fp, "rb") as f:
                st = os.fstat(f.fileno())
                if st.st_size == 0:
                    return b""
                mm = mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ)
                data = mm[:]
                mm.close()
                return data
        except Exception:
            logger.exception("mmap read failed for %s", file_path)
            return None

    def _sample_file_chunks(self, file_path: str, file_size: int) -> List[bytes]:
        samples: List[bytes] = []
        try:
            fp = _win_long_path(file_path)
            with open(fp, "rb") as f:
                # first chunk
                f.seek(0)
                samples.append(f.read(SAMPLE_SIZE))
                if file_size <= SAMPLE_SIZE * 2:
                    return samples
                # last chunk
                f.seek(max(0, file_size - SAMPLE_SIZE))
                samples.append(f.read(SAMPLE_SIZE))
                # middle samples
                if file_size > SAMPLE_SIZE * 4:
                    for off in (file_size // 3, (2 * file_size) // 3):
                        f.seek(off)
                        samples.append(f.read(SAMPLE_SIZE))
        except Exception:
            logger.exception("sampling failed for %s", file_path)
        return samples

    # -------------------------
    # Low-level hashing over bytes/iterables
    # -------------------------
    def _hash_bytes_algo(self, algo: str, chunks) -> Optional[str]:
        hn = algo.lower()
        try:
            if hn == "blake3" and _HAS_BLAKE3:
                h = blake3.blake3()
                if isinstance(chunks, (bytes, bytearray)):
                    h.update(chunks)
                else:
                    for c in chunks:
                        h.update(c)
                return h.hexdigest()

            if hn in ("xxh64",) and _HAS_XXHASH:
                h = xxhash.xxh64()
                if isinstance(chunks, (bytes, bytearray)):
                    h.update(chunks)
                else:
                    for c in chunks:
                        h.update(c)
                return h.hexdigest()

            if hn in ("sha256", "md5", "sha1", "sha512", "blake2b", "blake2s"):
                hasher = hashlib.new(hn)
                if isinstance(chunks, (bytes, bytearray)):
                    hasher.update(chunks)
                else:
                    for c in chunks:
                        hasher.update(c)
                return hasher.hexdigest()

            logger.warning("unsupported algo: %s", algo)
            return None
        except Exception:
            logger.exception("hashing failed for algo=%s", algo)
            return None

    def _hash_full_streamed(
        self,
        file_path: str,
        algo: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Optional[str]:
        """Stream file and compute full hash. Optionally call progress_callback(processed, total)."""
        hn = algo.lower()
        try:
            if hn == "blake3" and _HAS_BLAKE3:
                hobj = blake3.blake3()
            elif hn.startswith("xxh") and _HAS_XXHASH:
                hobj = xxhash.xxh64()
            else:
                hobj = hashlib.new(hn)
            fp = _win_long_path(file_path)
            total = os.path.getsize(fp)
            processed = 0
            with open(fp, "rb", buffering=self.chunk_size * 2) as f:
                for chunk in iter(lambda: f.read(self.chunk_size), b""):
                    hobj.update(chunk)
                    processed += len(chunk)
                    if progress_callback and total > 0:
                        try:
                            progress_callback(processed, total)
                        except Exception:
                            logger.debug("progress_callback raised in _hash_full_streamed")
            return hobj.hexdigest()
        except Exception:
            logger.exception("full streamed hash failed %s for %s", algo, file_path)
            return None

    # -------------------------
    # Main size-aware compute_hashes
    # -------------------------
    def compute_hashes(
        self,
        file_path: str,
        require_full_sha256: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Optional[Dict[str, Optional[str]]]:
        """
        Compute requested hashes for a file using a size-aware strategy:
          - small files: read full into memory
          - medium files: mmap or chunked streaming
          - very large files: sampling and optional full sha256 if requested
        """
        try:
            # Check if file should be excluded
            if _should_exclude_file(file_path):
                with self._lock:
                    self.telemetry["excluded_files"] += 1
                return None
                
            fp = _win_long_path(file_path)
            st = os.stat(fp)
            size = st.st_size
            # على ويندوز قد تكون inode/device صفرية — نُبقيها للاستخدام غير الحرج
            inode = getattr(st, "st_ino", 0) or 0
            device = getattr(st, "st_dev", 0) or 0
            mtime = st.st_mtime
        except FileNotFoundError:
            with self._lock:
                self.telemetry["missing_files"] += 1
            return None
        except Exception:
            logger.exception("stat failed for %s", file_path)
            with self._lock:
                self.telemetry["errors"] += 1
            return None

        # cache key: path(case-insensitive on Windows) + stat tuple + requested algos
        cache_key = (_abs_norm(str(Path(file_path))), int(inode), int(device), int(size), float(mtime), tuple(self.hashes))
        cached = self.cache.get(cache_key)
        if cached is not None:
            with self._lock:
                self.telemetry["cache_hits"] += 1
            return dict(cached)
        with self._lock:
            self.telemetry["cache_misses"] += 1

        results: Dict[str, Optional[str]] = {}

        # SMALL files: read fully into memory
        if size < SMALL_THRESHOLD:
            try:
                with open(fp, "rb") as f:
                    data = f.read()
                if _HAS_XXHASH:
                    results["xxh64"] = self._hash_bytes_algo("xxh64", data)
                else:
                    results["md5"] = self._hash_bytes_algo("md5", data)
                if "sha256" in self.hashes or require_full_sha256:
                    results["sha256"] = self._hash_bytes_algo("sha256", data)
                for algo in self.hashes:
                    key = algo.lower()
                    if key not in results:
                        results[key] = self._hash_bytes_algo(key, data)
                self.cache.set(cache_key, results)
                with self._lock:
                    self.telemetry["checked"] += 1
                return results
            except Exception:
                logger.exception("small-file hashing failed for %s", file_path)
                with self._lock:
                    self.telemetry["errors"] += 1
                return None

        # VERY LARGE files: sampling
        if size >= MEDIUM_THRESHOLD:
            try:
                samples = self._sample_file_chunks(fp, size)
                algos_to_run: List[str] = []
                if _HAS_BLAKE3:
                    algos_to_run.append("blake3")
                elif _HAS_XXHASH:
                    algos_to_run.append("xxh64")
                with ThreadPoolExecutor(max_workers=min(len(algos_to_run) or 1, os.cpu_count() or 2)) as exe:
                    futs = {}
                    for algo in algos_to_run:
                        futs[exe.submit(self._hash_bytes_algo, algo, samples)] = algo
                    for fut in as_completed(futs):
                        algo = futs[fut]
                        try:
                            results[algo] = fut.result()
                        except Exception:
                            results[algo] = None
                if require_full_sha256 and "sha256" not in results:
                    results["sha256"] = self._hash_full_streamed(fp, "sha256", progress_callback=progress_callback)
                for algo in self.hashes:
                    key = algo.lower()
                    if key not in results:
                        if key == "sha256" and not require_full_sha256:
                            continue
                        results[key] = self._hash_full_streamed(fp, key, progress_callback=progress_callback)
                self.cache.set(cache_key, results)
                with self._lock:
                    self.telemetry["checked"] += 1
                return results
            except Exception:
                logger.exception("sampling hashing failed for %s", file_path)
                with self._lock:
                    self.telemetry["errors"] += 1
                return None

        # MEDIUM files: mmap if big enough else chunked streaming
        try:
            use_mmap = (size >= MMAP_THRESHOLD)
            if use_mmap:
                data = self._read_with_mmap(fp)
                if data is None:
                    return None
                futs = {}
                algos = list(set(self.hashes + ["sha256"]))
                for algo in algos:
                    futs[self.hash_executor.submit(self._hash_bytes_algo, algo, data)] = algo
                for fut in as_completed(futs):
                    algo = futs[fut]
                    try:
                        results[algo] = fut.result()
                    except Exception:
                        results[algo] = None
                self.cache.set(cache_key, results)
                with self._lock:
                    self.telemetry["checked"] += 1
                return results
            else:
                # chunked streaming single-pass
                hashers: Dict[str, Optional[Any]] = {}
                for algo in self.hashes:
                    hn = algo.lower()
                    try:
                        if hn == "blake3" and _HAS_BLAKE3:
                            hashers[hn] = blake3.blake3()
                        elif hn.startswith("xxh") and _HAS_XXHASH:
                            hashers[hn] = xxhash.xxh64()
                        else:
                            hashers[hn] = hashlib.new(hn)
                    except Exception:
                        hashers[hn] = None
                with open(fp, "rb", buffering=self.chunk_size * 2) as f:
                    for chunk in iter(lambda: f.read(self.chunk_size), b""):
                        for hn, obj in list(hashers.items()):
                            if obj is not None:
                                try:
                                    obj.update(chunk)
                                except Exception:
                                    logger.exception("Failed hash update %s for %s", hn, file_path)
                                    hashers[hn] = None
                for hn, obj in hashers.items():
                    try:
                        results[hn] = obj.hexdigest() if obj is not None else None
                    except Exception:
                        results[hn] = None
                self.cache.set(cache_key, results)
                with self._lock:
                    self.telemetry["checked"] += 1
                return results
        except Exception:
            logger.exception("medium-file hashing failed for %s", file_path)
            with self._lock:
                self.telemetry["errors"] += 1
            return None

    # -------------------------
    # DB row helper
    # -------------------------
    def _row_from_hashes(self, path: str, hashes: Dict[str, str]) -> Tuple[str, Optional[str], Optional[str], Optional[str], int, int, int, float, int]:
        try:
            fp = _win_long_path(path)
            st = os.stat(fp)
            inode = int(getattr(st, "st_ino", 0) or 0)
            device = int(getattr(st, "st_dev", 0) or 0)
            size = int(st.st_size)
            mtime = float(st.st_mtime)
        except Exception:
            inode = device = size = 0
            mtime = 0.0
        sha256 = hashes.get("sha256")
        md5 = hashes.get("md5")
        other = {k: v for k, v in hashes.items() if k not in ("sha256", "md5")}
        other_json = json.dumps(other) if other else None
        return (str(Path(path)), sha256, md5, other_json, inode, device, size, mtime, int(time.time()))

    # -------------------------
    # Public API
    # -------------------------
    def check_file(self, file_path: str) -> Dict[str, Any]:
        path = str(Path(file_path))
        norm_path = _abs_norm(path)
        out: Dict[str, Any] = {"path": path, "status": "error", "new_hashes": None, "prev_hashes": None, "updated_ts": None}
        
        # Check if file should be excluded
        if _should_exclude_file(path):
            out["status"] = "excluded"
            with self._lock:
                self.telemetry["excluded_files"] += 1
            return out
            
        try:
            fp = _win_long_path(path)
            if not os.path.exists(fp):
                out["status"] = "missing"
                with self._lock:
                    self.telemetry["missing_files"] += 1
                return out
            with self._lock:
                cur = self._conn.cursor()
                cur.execute("SELECT sha256, md5, other_hashes_json, updated_ts FROM file_integrity WHERE path = ?", (norm_path,))
                row = cur.fetchone()
            prev = None
            if row:
                other = {}
                try:
                    other = json.loads(row["other_hashes_json"]) if row["other_hashes_json"] else {}
                except Exception:
                    other = {}
                prev = {"sha256": row["sha256"], "md5": row["md5"], **other}
                out["prev_hashes"] = prev
                out["updated_ts"] = int(row["updated_ts"]) if row["updated_ts"] else None
            new_hashes = self.compute_hashes(path, require_full_sha256=False)
            if new_hashes is None:
                out["status"] = "error"
                with self._lock:
                    self.telemetry["errors"] += 1
                return out
            out["new_hashes"] = new_hashes
            with self._lock:
                self.telemetry["checked"] += 1
            if not prev:
                out["status"] = "new"
                return out
            changed = False
            for h in self.hashes:
                if prev.get(h.lower()) != new_hashes.get(h.lower()):
                    changed = True
                    break
            out["status"] = "changed" if changed else "unchanged"
            if changed:
                with self._lock:
                    self.telemetry["changes_detected"] += 1
            return out
        except Exception:
            logger.exception("check_file error for %s", path)
            with self._lock:
                self.telemetry["errors"] += 1
            out["status"] = "error"
            return out

    def update_file(
        self,
        file_path: str,
        require_full_sha256: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Dict[str, Any]:
        """
        Compute hashes and queue DB upsert. If change detected -> on_change_callback invoked asynchronously.
        """
        path = str(Path(file_path))
        norm_path = _abs_norm(path)
        
        # Check if file should be excluded
        if _should_exclude_file(path):
            return {"path": path, "status": "excluded", "saved": False}
            
        try:
            fp = _win_long_path(path)
            if not os.path.exists(fp):
                return {"path": path, "status": "missing", "saved": False}
            new_hashes = self.compute_hashes(path, require_full_sha256=require_full_sha256, progress_callback=progress_callback)
            if new_hashes is None:
                return {"path": path, "status": "error", "saved": False, "error": "hash_compute_failed"}
            with self._lock:
                cur = self._conn.cursor()
                cur.execute("SELECT sha256, md5, other_hashes_json FROM file_integrity WHERE path = ?", (norm_path,))
                row = cur.fetchone()
            prev_hashes = None
            if row:
                other = {}
                try:
                    other = json.loads(row["other_hashes_json"]) if row["other_hashes_json"] else {}
                except Exception:
                    other = {}
                prev_hashes = {"sha256": row["sha256"], "md5": row["md5"], **other}
            row_tuple = self._row_from_hashes(path, new_hashes)
            # نخزن المسار الطبيعي normed في العمود الأساسي للحفاظ على اتساق ويندوز
            row_tuple = (norm_path,) + row_tuple[1:]
            with self._write_lock:
                self._write_queue.append(row_tuple)
            with self._lock:
                self.telemetry["updated"] += 1
            # determine change
            changed = False
            if prev_hashes:
                for h in self.hashes:
                    if prev_hashes.get(h.lower()) != new_hashes.get(h.lower()):
                        changed = True
                        break
            # log event & callback with rate limiting
            if changed:
                with self._lock:
                    self.telemetry["changes_detected"] += 1
                
                # Check rate limiting for high-frequency files
                if _is_high_frequency_file(path):
                    if not self.rate_limiter.is_allowed(path):
                        with self._lock:
                            self.telemetry["rate_limited_changes"] += 1
                        logger.debug("Integrity change rate limited for high-frequency file: %s", path)
                        return {"path": path, "status": "saved", "saved": True, "new_hashes": new_hashes, "prev_hashes": prev_hashes, "changed": changed, "rate_limited": True}
                
                # Use INFO level instead of WARNING to reduce log volume
                logger.info("Integrity change detected: %s", path)
                
                try:
                    ev = {"path": path, "event": "changed", "details": {"prev": prev_hashes, "new": new_hashes}}
                    with self._lock:
                        cur = self._conn.cursor()
                        cur.execute(
                            "INSERT INTO integrity_events (path, event, details_json, ts) VALUES (?, ?, ?, ?)",
                            (norm_path, "changed", json.dumps(ev, ensure_ascii=False), int(time.time())),
                        )
                        self._conn.commit()
                except Exception:
                    logger.exception("Failed to log integrity_event for %s", path)
                if callable(self.on_change_callback):
                    try:
                        threading.Thread(target=self.on_change_callback, args=(path, prev_hashes or {}, new_hashes), daemon=True).start()
                    except Exception:
                        try:
                            self.on_change_callback(path, prev_hashes or {}, new_hashes)
                        except Exception:
                            logger.exception("on_change_callback failed for %s", path)
            return {"path": path, "status": "saved", "saved": True, "new_hashes": new_hashes, "prev_hashes": prev_hashes, "changed": changed}
        except Exception:
            logger.exception("update_file error for %s", path)
            with self._lock:
                self.telemetry["errors"] += 1
            return {"path": path, "status": "error", "saved": False}

    def remove_file(self, file_path: str) -> Dict[str, Any]:
        path = str(Path(file_path))
        norm_path = _abs_norm(path)
        try:
            with self._lock:
                cur = self._conn.cursor()
                cur.execute("SELECT sha256, md5, other_hashes_json FROM file_integrity WHERE path = ?", (norm_path,))
                row = cur.fetchone()
            prev_entry = None
            if row:
                other = {}
                try:
                    other = json.loads(row["other_hashes_json"]) if row["other_hashes_json"] else {}
                except Exception:
                    other = {}
                prev_entry = {"sha256": row["sha256"], "md5": row["md5"], **other}
            with self._lock:
                self._conn.execute("DELETE FROM file_integrity WHERE path = ?", (norm_path,))
                self._conn.commit()
            # evict cache entries matching path
            with self.cache.lock:
                keys = [k for k in list(self.cache._data.keys()) if k[0] == norm_path]
                for k in keys:
                    self.cache.pop(k)
            return {"path": path, "removed": True, "prev_entry": prev_entry}
        except Exception:
            logger.exception("remove_file error for %s", path)
            return {"path": path, "removed": False}

    def batch_check(self, paths: List[str], update_missing: bool = False, workers: int = 4) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=max(1, workers)) as exe:
            futures = {exe.submit(self.check_file, p): p for p in paths}
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    res = fut.result()
                except Exception:
                    logger.exception("batch_check failed for %s", p)
                    res = {"path": p, "status": "error"}
                results.append(res)
                if update_missing and res.get("status") == "new":
                    try:
                        self.update_file(p)
                    except Exception:
                        logger.exception("update_file failed in batch for %s", p)
        return results

    def export_to_json(self, out_path: str) -> bool:
        try:
            with self._lock:
                cur = self._conn.cursor()
                cur.execute("SELECT path, sha256, md5, other_hashes_json, inode, device, size, mtime, updated_ts FROM file_integrity")
                rows = []
                for r in cur.fetchall():
                    rows.append(
                        {
                            "path": r["path"],
                            "sha256": r["sha256"],
                            "md5": r["md5"],
                            "other_hashes": json.loads(r["other_hashes_json"]) if r["other_hashes_json"] else {},
                            "inode": r["inode"],
                            "device": r["device"],
                            "size": r["size"],
                            "mtime": r["mtime"],
                            "updated_ts": r["updated_ts"],
                        }
                    )
            fp = _win_long_path(out_path)
            Path(fp).parent.mkdir(parents=True, exist_ok=True)
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(rows, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            logger.exception("export_to_json failed")
            return False

    def import_from_json(self, in_path: str, overwrite: bool = False) -> bool:
        try:
            fp = _win_long_path(in_path)
            with open(fp, "r", encoding="utf-8") as f:
                rows = json.load(f)
            with self._lock:
                cur = self._conn.cursor()
                for r in rows:
                    raw_path = r.get("path")
                    path = _abs_norm(raw_path) if raw_path else None
                    sha = r.get("sha256")
                    md5 = r.get("md5")
                    other = r.get("other_hashes", {}) or {}
                    ts = int(r.get("updated_ts", time.time()))
                    if not path or not sha:
                        continue
                    if not overwrite:
                        cur.execute("SELECT 1 FROM file_integrity WHERE path = ?", (path,))
                        if cur.fetchone():
                            continue
                    cur.execute(
                        "REPLACE INTO file_integrity (path, sha256, md5, other_hashes_json, inode, device, size, mtime, updated_ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            path,
                            sha,
                            md5,
                            json.dumps(other) if other else None,
                            int(r.get("inode", 0)),
                            int(r.get("device", 0)),
                            int(r.get("size", 0)),
                            float(r.get("mtime", 0.0)),
                            ts,
                        ),
                    )
                self._conn.commit()
                self.cache.clear()
            return True
        except Exception:
            logger.exception("import_from_json failed")
            return False

    def get_telemetry(self) -> Dict[str, Any]:
        with self._lock:
            data = dict(self.telemetry)
            data.update(self.cache.stats())
            return data

    def close(self) -> None:
        # stop background writer
        self._stop_bg.set()
        if self._bg_thread and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=5)

        # flush pending writes
        try:
            with self._write_lock:
                pending = list(self._write_queue)
                self._write_queue.clear()
            if pending:
                with self._lock:
                    cur = self._conn.cursor()
                    cur.executemany(
                        """
                        REPLACE INTO file_integrity (path, sha256, md5, other_hashes_json, inode, device, size, mtime, updated_ts)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        pending,
                    )
                    self._conn.commit()
        except Exception:
            logger.exception("Final flush failed")

        # shutdown executors
        try:
            self.hash_executor.shutdown(wait=True)
        except Exception:
            logger.exception("hash_executor shutdown failed")

        # close DB
        try:
            with self._lock:
                self._conn.commit()
                self._conn.close()
        except Exception:
            logger.exception("closing DB failed")

    # context manager
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
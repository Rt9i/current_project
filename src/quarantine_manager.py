# ransomware_protection_system/src/quarantine_manager.py
# -*- coding: utf-8 -*-
"""
QuarantineManager (local-only, robust) + REST Facade — Windows-ready
--------------------------------------------------------------------
- نفس الميزات تماماً:
  * حجر محلي فقط + مرحلتين (staging ثم commit)
  * whitelist (مسارات/امتدادات/sha256)
  * Heuristics قبل الحجر (Entropy + YARA اختياري)
  * تشديد صلاحيات الملفات
  * كاش SHA256 (LRU)
  * Metadata + لقطات دورية
  * Bulk عبر ThreadPoolExecutor
  * نتائج موحّدة + Telemetry + Alert hook مُقيّد المعدّل
  * update_settings() لتغيير المسار أثناء التشغيل

- توافق ويندوز:
  * المقارنات الخاصة بالمسارات غير حسّاسة لحالة الأحرف (normcase)
  * تشديد صلاحيات بديل باستخدام icacls (أفضلية) + إخفاء المجلدات كـ Hidden عند الإنشاء
  * الإبقاء على chmod للمِنصّات غير ويندوز (وأيضًا محاولة على ويندوز دون كسر السلوك)

لم يتم حذف أو تعطيل أي ميزة؛ أضفنا فقط بدائل تحقق نفس السلوك على ويندوز.
"""

from __future__ import annotations

import os
import shutil
import json
import time
import math
import hashlib
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import subprocess

# مشروعك
try:
    from src.logger import get_logger
except Exception:
    from logger import get_logger  # type: ignore

log = get_logger(__name__)

# YARA (اختياري)
_YARA_AVAILABLE = False
YaraScanner = None
try:
    try:
        from src.yara_scanner import YaraScanner as _YS  # type: ignore
    except Exception:
        from yara_scanner import YaraScanner as _YS  # type: ignore
    YaraScanner = _YS
    _YARA_AVAILABLE = True
except Exception:
    _YARA_AVAILABLE = False


# -----------------------
# Platform helpers
# -----------------------
def _is_windows() -> bool:
    return os.name == "nt"

def _normcase(p: str) -> str:
    return os.path.normcase(p) if _is_windows() else p


# -----------------------
# Helpers & defaults
# -----------------------
def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _result(ok: bool, code: str, msg: str, data: Any = None) -> Dict[str, Any]:
    return {"ok": bool(ok), "code": code, "msg": msg, "data": data, "ts": int(time.time())}


def compute_sha256(path: str, chunk_size: int = 4 * 1024 * 1024) -> Optional[str]:
    """Compute SHA256, return None if unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        log.debug("compute_sha256 failed for %s: %s", path, e)
        return None


def file_entropy(path: str, sample_bytes: int = 65536) -> Optional[float]:
    """Estimate file entropy using first `sample_bytes` bytes (0..8)."""
    try:
        with open(path, "rb") as f:
            data = f.read(sample_bytes)
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        entropy = 0.0
        length = float(len(data))
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy
    except Exception as e:
        log.debug("entropy calc failed for %s: %s", path, e)
        return None


def human_size(num: int) -> str:
    try:
        size = float(num)
        for unit in ["Bytes", "KB", "MB", "GB", "TB"]:
            if size < 1024 or unit == "TB":
                return f"{int(size)} {unit}" if unit == "Bytes" else f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    except Exception:
        return str(num)


# Simple thread-safe LRU cache for sha256
class SimpleLRU:
    def __init__(self, max_size: int = 2000):
        self.lock = threading.RLock()
        self.max_size = max_size
        self._d = OrderedDict()
        self.hits = 0
        self.misses = 0

    def get(self, key):
        with self.lock:
            v = self._d.get(key)
            if v is None:
                self.misses += 1
                return None
            self._d.move_to_end(key)
            self.hits += 1
            return v

    def set(self, key, value):
        with self.lock:
            if key in self._d:
                self._d.move_to_end(key)
            self._d[key] = value
            while len(self._d) > self.max_size:
                self._d.popitem(last=False)

    def pop(self, key):
        with self.lock:
            return self._d.pop(key, None)

    def clear(self):
        with self.lock:
            self._d.clear()

    def stats(self):
        with self.lock:
            return {"size": len(self._d), "hits": self.hits, "misses": self.misses}


# -----------------------
# Windows ACL hardening (best-effort)
# -----------------------
def _win_harden_path(path: str):
    """
    تشديد الصلاحيات على ويندوز باستخدام icacls (أفضل جهد):
      - تعطيل الوراثة /INHERITANCE:d
      - منح التحكم الكامل للمستخدم الحالي + Administrators
      - إزالة Everyone
    قد تفشل على بعض الأنظمة؛ في هذه الحالة نكتفي بتسجيل تحذير.
    """
    if not _is_windows():
        return
    try:
        # اجلب اسم المستخدم الحالي لـ icacls
        user = os.getlogin()
    except Exception:
        user = None

    try:
        # Disable inheritance
        subprocess.run(["icacls", path, "/inheritance:d"], capture_output=True, check=False)
        # Grant full to Administrators and current user (if available)
        subprocess.run(["icacls", path, "/grant", "Administrators:F"], capture_output=True, check=False)
        if user:
            subprocess.run(["icacls", path, "/grant", f"{user}:F"], capture_output=True, check=False)
        # Remove Everyone (best-effort)
        subprocess.run(["icacls", path, "/remove:g", "Everyone"], capture_output=True, check=False)
    except Exception as e:
        log.debug("icacls harden failed for %s: %s", path, e)

def _win_mark_hidden(path: str):
    """وضع سمة Hidden للمجلدات على ويندوز لتقليل العبث العرضي."""
    if not _is_windows():
        return
    try:
        subprocess.run(["attrib", "+h", path], capture_output=True, check=False)
    except Exception:
        pass


# -----------------------
# QuarantineManager
# -----------------------
class QuarantineManager:
    def __init__(self,
                 quarantine_dir: Optional[str] = None,
                 staging_subdir: str = "_pending",
                 metadata_filename: str = "metadata.json",
                 whitelist_filename: str = "whitelist.json",
                 snapshot_count: int = 3,
                 staging_ttl_seconds: int = 600,
                 hash_cache_size: int = 5000,
                 max_workers: int = 4,
                 entropy_threshold: float = 7.0,
                 yara_rules_dir: Optional[str] = None,
                 alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
                 alert_rate_per_minute: int = 10,
                 telemetry_hook: Optional[Callable[[Dict[str, Any]], None]] = None,
                 **compat):
        """
        Compatibility:
          - Accepts base_dir=<path> (alias of quarantine_dir)
          - Accepts config=dict and uses config.get("path") if provided
          - Unknown kwargs are ignored (logged once)
        """
        # ---- Compat inputs ----
        base_dir = compat.pop("base_dir", None)
        config = compat.pop("config", None)
        if compat:
            try:
                log.warning("QuarantineManager: unused kwargs ignored: %s", list(compat.keys()))
            except Exception:
                pass

        # ---- Resolve root dir ----
        cfg_path = None
        try:
            if isinstance(config, dict):
                cfg_path = config.get("path") or config.get("quarantine_dir") or config.get("base_dir")
        except Exception:
            cfg_path = None

        root = quarantine_dir or base_dir or cfg_path or os.path.expanduser("~/Quarantine")
        self.quarantine_dir = str(Path(root).expanduser().resolve())
        self.base_dir = self.quarantine_dir  # expose base_dir attribute for callers expecting it
        self.config = config or {}

        self.staging_dir = os.path.join(self.quarantine_dir, staging_subdir)
        self.metadata_path = os.path.join(self.quarantine_dir, metadata_filename)
        self.whitelist_path = os.path.join(self.quarantine_dir, whitelist_filename)
        self.snapshot_count = max(1, int(snapshot_count))
        self.staging_ttl = int(staging_ttl_seconds)
        self.hash_cache = SimpleLRU(max_size=hash_cache_size)
        self._lock = threading.RLock()
        self._meta_lock = threading.RLock()
        self.alert_callback = alert_callback
        self.alert_rate_per_minute = max(1, int(alert_rate_per_minute))
        self._alert_timestamps = deque()
        self.telemetry_hook = telemetry_hook

        # telemetry counters
        self.telemetry = {
            "quarantined": 0,
            "restored": 0,
            "deleted": 0,
            "failed_ops": 0,
            "bulk_ops": 0,
            "avg_entropy": 0.0,
            "entropy_samples": 0
        }

        # heuristics
        self.entropy_threshold = float(entropy_threshold)
        self.yara = None
        if yara_rules_dir and _YARA_AVAILABLE:
            try:
                self.yara = YaraScanner(yara_rules_dir)
            except Exception:
                log.exception("Failed to init YARA scanner")

        # create dirs
        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.staging_dir, exist_ok=True)
        # على ويندوز: إخفاء المجلدين + تشديد صلاحيات عامة (أفضل جهد)
        _win_mark_hidden(self.quarantine_dir)
        _win_mark_hidden(self.staging_dir)
        _win_harden_path(self.quarantine_dir)
        _win_harden_path(self.staging_dir)

        # load metadata & whitelist
        self._metadata: Dict[str, Dict[str, Any]] = {}  # qname -> meta
        self._whitelist = {"paths": [], "extensions": [], "sha256": []}
        self._load_metadata()
        self._load_whitelist()

        # ThreadPool for bulk operations
        self.executor = ThreadPoolExecutor(max_workers=max(1, int(max_workers)))

        log.info("QuarantineManager initialized at %s (staging=%s)", self.quarantine_dir, self.staging_dir)

    # -----------------------
    # Dynamic settings (for /api/config)
    # -----------------------
    def update_settings(self,
                        quarantine_dir: Optional[str] = None,
                        base_dir: Optional[str] = None):
        """تحديث مسار الحجر الصحي أثناء التشغيل (يدعم quarantine_dir أو base_dir)."""
        new_req = quarantine_dir or base_dir
        if not new_req:
            return
        with self._lock:
            new_root = str(Path(new_req).expanduser().resolve())
            if _normcase(new_root) == _normcase(self.quarantine_dir):
                return
            self.quarantine_dir = new_root
            self.base_dir = self.quarantine_dir
            self.staging_dir = os.path.join(self.quarantine_dir, "_pending")
            self.metadata_path = os.path.join(self.quarantine_dir, "metadata.json")
            self.whitelist_path = os.path.join(self.quarantine_dir, "whitelist.json")
            os.makedirs(self.quarantine_dir, exist_ok=True)
            os.makedirs(self.staging_dir, exist_ok=True)
            _win_mark_hidden(self.quarantine_dir)
            _win_mark_hidden(self.staging_dir)
            _win_harden_path(self.quarantine_dir)
            _win_harden_path(self.staging_dir)
            # Reload data from new root (do not auto-migrate old root)
            self._load_metadata()
            self._load_whitelist()
            log.info("QuarantineManager root changed to %s", self.quarantine_dir)

    # -----------------------
    # Metadata handling
    # -----------------------
    def _load_metadata(self):
        with self._meta_lock:
            if os.path.exists(self.metadata_path):
                try:
                    with open(self.metadata_path, "r", encoding="utf-8") as f:
                        self._metadata = json.load(f)
                except Exception:
                    log.exception("Failed to load metadata, starting fresh")
                    self._metadata = {}
            else:
                self._metadata = {}

    def _snapshot_metadata(self):
        """Rotate metadata snapshots and write current metadata safely."""
        with self._meta_lock:
            try:
                # rotate .bakN
                for i in range(self.snapshot_count - 1, 0, -1):
                    src = f"{self.metadata_path}.bak{i - 1}" if i - 1 > 0 else self.metadata_path
                    dst = f"{self.metadata_path}.bak{i}"
                    if os.path.exists(src):
                        try:
                            shutil.copy2(src, dst)
                        except Exception:
                            pass
                # write new
                tmp = f"{self.metadata_path}.tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self._metadata, f, indent=2, ensure_ascii=False)
                os.replace(tmp, self.metadata_path)
            except Exception:
                log.exception("Failed to snapshot metadata")

    def _save_metadata(self):
        """Persist metadata with snapshot (call within meta lock)."""
        with self._meta_lock:
            self._snapshot_metadata()

    # -----------------------
    # Whitelist
    # -----------------------
    def _load_whitelist(self):
        with self._meta_lock:
            if os.path.exists(self.whitelist_path):
                try:
                    with open(self.whitelist_path, "r", encoding="utf-8") as f:
                        w = json.load(f)
                    self._whitelist["paths"] = w.get("paths", [])
                    self._whitelist["extensions"] = w.get("extensions", [])
                    self._whitelist["sha256"] = w.get("sha256", [])
                except Exception:
                    log.exception("Failed to load whitelist")
                    self._whitelist = {"paths": [], "extensions": [], "sha256": []}
            else:
                self._whitelist = {"paths": [], "extensions": [], "sha256": []}
                try:
                    with open(self.whitelist_path, "w", encoding="utf-8") as f:
                        json.dump(self._whitelist, f, indent=2)
                except Exception:
                    pass

    def reload_whitelist(self):
        self._load_whitelist()

    def add_whitelist_sha(self, sha: str):
        with self._meta_lock:
            if sha and sha not in self._whitelist["sha256"]:
                self._whitelist["sha256"].append(sha)
                self._save_whitelist()

    def add_whitelist_prefix(self, prefix: str):
        with self._meta_lock:
            if prefix not in self._whitelist["paths"]:
                self._whitelist["paths"].append(prefix)
                self._save_whitelist()

    def add_whitelist_extension(self, ext: str):
        if not ext.startswith("."):
            ext = f".{ext}"
        with self._meta_lock:
            if ext not in self._whitelist["extensions"]:
                self._whitelist["extensions"].append(ext)
                self._save_whitelist()

    def _save_whitelist(self):
        with self._meta_lock:
            try:
                tmp = f"{self.whitelist_path}.tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self._whitelist, f, indent=2, ensure_ascii=False)
                os.replace(tmp, self.whitelist_path)
            except Exception:
                log.exception("Failed to save whitelist")

    # -----------------------
    # Pre-quarantine heuristics
    # -----------------------
    def _is_whitelisted(self, src_path: str, sha: Optional[str]) -> bool:
        # path prefix (case-insensitive on Windows)
        try:
            sp = _normcase(os.path.abspath(src_path))
            for prefix in self._whitelist.get("paths", []):
                if sp.startswith(_normcase(os.path.abspath(prefix))):
                    return True
        except Exception:
            pass
        # extension (case-insensitive compare)
        _, ext = os.path.splitext(src_path)
        try:
            if ext and ext.lower() in [e.lower() for e in self._whitelist.get("extensions", [])]:
                return True
        except Exception:
            pass
        # sha
        if sha and sha in self._whitelist.get("sha256", []):
            return True
        return False

    def _yara_match(self, src_path: str) -> bool:
        if not self.yara:
            return False
        try:
            res = self.yara.scan_file(src_path)
            return bool(res and res.get("infected"))
        except Exception:
            log.exception("YARA scan error for %s", src_path)
            return False

    def _pre_quarantine_check(self, src_path: str, sha: Optional[str]) -> Dict[str, Any]:
        # returns {"suspicious": bool, "reasons": [..], "entropy": float|None}
        reasons = []
        ent = file_entropy(src_path)
        # update telemetry average
        if ent is not None:
            with self._lock:
                self.telemetry["entropy_samples"] += 1
                prev_avg = self.telemetry.get("avg_entropy", 0.0)
                n = self.telemetry["entropy_samples"]
                self.telemetry["avg_entropy"] = ((prev_avg * (n - 1)) + ent) / n
        if ent is not None and ent >= self.entropy_threshold:
            reasons.append(f"high_entropy:{ent:.2f}")
        # YARA
        if _YARA_AVAILABLE and self.yara:
            try:
                if self._yara_match(src_path):
                    reasons.append("yara_match")
            except Exception:
                pass
        return {"suspicious": len(reasons) > 0, "reasons": reasons, "entropy": ent}

    # -----------------------
    # Core file operations
    # -----------------------
    def _hardening_permissions(self, target_path: str):
        """Linux/Mac: chmod 700 ; Windows: icacls (best-effort) + keep chmod attempt."""
        try:
            os.chmod(target_path, 0o700)
        except Exception:
            # على ويندوز قد لا يكون ذا أثر؛ نتجاهل الخطأ
            pass
        # ويندوز: تشديد إضافي
        _win_harden_path(target_path)

    def _unique_quarantine_name(self, src_path: str) -> str:
        """Unique name under quarantine_dir (keep original basename)"""
        base = os.path.basename(src_path)
        ts = int(time.time())
        name = f"{ts}_{base}"
        candidate = name
        i = 0
        while os.path.exists(os.path.join(self.quarantine_dir, candidate)) or \
              os.path.exists(os.path.join(self.staging_dir, candidate)):
            i += 1
            candidate = f"{name}_{i}"
        return candidate

    def _register_metadata(self, qname: str, meta: Dict[str, Any]):
        with self._meta_lock:
            self._metadata[qname] = meta
            try:
                self._save_metadata()
            except Exception:
                log.exception("Failed to persist metadata for %s", qname)

    def _telemetry_emit(self, payload: Dict[str, Any]):
        if not self.telemetry_hook:
            return
        try:
            self.telemetry_hook(payload)
        except Exception as e:
            log.warning("telemetry hook failed: %s", e)

    # -----------------------
    # Public API: single quarantine
    # -----------------------
    def quarantine_file(self, src_path: str, reason: Optional[str] = None, do_stage: bool = True) -> Dict[str, Any]:
        """
        Quarantine a single file (soft by default).
        - if do_stage True: move to staging_dir first
        - computes SHA (cached), performs whitelist check and heuristics
        Returns standardized dict with metadata
        """
        src_path = str(Path(src_path).expanduser())
        if not os.path.exists(src_path):
            return _result(False, "not_found", f"Source not found: {src_path}")

        # compute sha (cache key: path,inode,size,mtime)
        try:
            st = os.stat(src_path)
            cache_key = (_normcase(os.path.abspath(src_path)), getattr(st, "st_ino", None), st.st_size, int(st.st_mtime))
        except Exception:
            cache_key = (_normcase(os.path.abspath(src_path)), None, None, None)
        sha = self.hash_cache.get(cache_key)
        if not sha:
            sha = compute_sha256(src_path)
            if sha:
                self.hash_cache.set(cache_key, sha)

        # whitelist
        if self._is_whitelisted(src_path, sha):
            return _result(False, "whitelisted", "File is whitelisted", {"sha": sha})

        # heuristics
        pre = self._pre_quarantine_check(src_path, sha)
        if (not pre["suspicious"]) and do_stage:
            # افتراضياً لا نعزل ملفات غير مُريبة (تحسين تجربة/أداء) — نفس سلوك الإصدار الأصلي
            return _result(False, "not_suspicious", "File does not appear suspicious by heuristics",
                           {"reasons": pre.get("reasons", []), "sha": sha})

        # move -> staging
        qname = self._unique_quarantine_name(src_path)
        try:
            dest = os.path.join(self.staging_dir, qname)
            try:
                shutil.move(src_path, dest)
            except Exception:
                shutil.copy2(src_path, dest)
                try:
                    os.remove(src_path)
                except Exception:
                    pass

            self._hardening_permissions(dest)

            meta = {
                "original_path": os.path.abspath(src_path),
                "quarantine_name": qname,
                "staged_path": dest,
                "sha256": sha,
                "reasons": pre.get("reasons", []),
                "staged_ts": int(time.time()),
                "committed": False,
                "commit_ts": None,
                "final_path": None,
                "restored": False,
                "deleted": False,
                "user_reason": reason or "automated",
            }
            self._register_metadata(qname, meta)
            with self._lock:
                self.telemetry["quarantined"] += 1
            self._maybe_alert({"type": "quarantine_staged", "qname": qname, "meta": meta})
            self._telemetry_emit({"action": "quarantine_staged", "qname": qname, "ok": True})
            return _result(True, "staged", "File staged for quarantine", meta)
        except Exception as e:
            log.exception("Failed to stage quarantine for %s: %s", src_path, e)
            with self._lock:
                self.telemetry["failed_ops"] += 1
            self._telemetry_emit({"action": "quarantine_stage_error", "path": src_path, "error": str(e)})
            return _result(False, "stage_error", f"Failed to move to staging: {e}")

    # -----------------------
    # Commit staged -> final quarantine
    # -----------------------
    def commit_staged(self, qname: str) -> Dict[str, Any]:
        """Commit a staged file into final quarantine area."""
        with self._meta_lock:
            meta = self._metadata.get(qname)
            if not meta:
                return _result(False, "not_found", "Staged entry not found", {"qname": qname})
            if meta.get("committed"):
                return _result(False, "already_committed", "Already committed", {"qname": qname})
            staged_path = meta.get("staged_path")
            if not staged_path or not os.path.exists(staged_path):
                return _result(False, "staged_missing", "Staged file missing", {"qname": qname})

            try:
                final_path = os.path.join(self.quarantine_dir, qname)
                try:
                    shutil.move(staged_path, final_path)
                except Exception:
                    shutil.copy2(staged_path, final_path)
                    try:
                        os.remove(staged_path)
                    except Exception:
                        pass
                self._hardening_permissions(final_path)

                meta["committed"] = True
                meta["commit_ts"] = int(time.time())
                meta["final_path"] = final_path
                self._register_metadata(qname, meta)
                self._maybe_alert({"type": "quarantine_committed", "qname": qname, "meta": meta})
                self._telemetry_emit({"action": "quarantine_committed", "qname": qname, "ok": True})
                return _result(True, "committed", "Staged file committed to quarantine",
                               {"qname": qname, "final_path": final_path})
            except Exception as e:
                log.exception("Failed to commit staged file %s: %s", qname, e)
                self._telemetry_emit({"action": "quarantine_commit_error", "qname": qname, "error": str(e)})
                return _result(False, "commit_error", f"Commit failed: {e}", {"qname": qname})

    # -----------------------
    # Auto-commit staged older than TTL
    # -----------------------
    def auto_commit_staged(self):
        """Commit all staged entries older than TTL."""
        now = int(time.time())
        to_commit = []
        with self._meta_lock:
            for qname, meta in list(self._metadata.items()):
                if meta.get("committed"):
                    continue
                ts = int(meta.get("staged_ts", 0))
                if (now - ts) >= self.staging_ttl:
                    to_commit.append(qname)
        results = {}
        for q in to_commit:
            results[q] = self.commit_staged(q)
        return results

    # -----------------------
    # Restore (false-positive)
    # -----------------------
    def restore_file(self, qname: str, dest_path: Optional[str] = None, mark_false_positive: bool = True) -> Dict[str, Any]:
        """Restore a quarantined file back to dest_path (or original_path)."""
        with self._meta_lock:
            meta = self._metadata.get(qname)
            if not meta:
                return _result(False, "not_found", "Quarantine entry not found", {"qname": qname})

            location = meta.get("final_path") if meta.get("committed") else meta.get("staged_path")
            if not location or not os.path.exists(location):
                return _result(False, "file_missing", "Quarantine file missing", {"qname": qname})

            dest = dest_path or meta.get("original_path") or os.path.join(os.path.expanduser("~"), "restored_files", qname)
            try:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                try:
                    shutil.move(location, dest)
                except Exception:
                    shutil.copy2(location, dest)
                    try:
                        os.remove(location)
                    except Exception:
                        pass
                # permissive for user (owner only)
                try:
                    os.chmod(dest, 0o600)
                except Exception:
                    pass

                meta["restored"] = True
                meta["restored_ts"] = int(time.time())
                meta["restored_to"] = dest
                self._register_metadata(qname, meta)

                if mark_false_positive:
                    sha = meta.get("sha256")
                    if sha:
                        self.add_whitelist_sha(sha)

                with self._lock:
                    self.telemetry["restored"] += 1

                self._maybe_alert({"type": "restored", "qname": qname, "meta": meta})
                self._telemetry_emit({"action": "quarantine_restored", "qname": qname, "ok": True, "dest": dest})
                return _result(True, "restored", "File restored from quarantine",
                               {"qname": qname, "restored_to": dest})
            except Exception as e:
                log.exception("Failed to restore %s: %s", qname, e)
                with self._lock:
                    self.telemetry["failed_ops"] += 1
                self._telemetry_emit({"action": "quarantine_restore_error", "qname": qname, "error": str(e)})
                return _result(False, "restore_error", f"Restore failed: {e}", {"qname": qname})

    # -----------------------
    # Delete permanently
    # -----------------------
    def delete_file(self, qname: str) -> Dict[str, Any]:
        """Delete quarantined file and mark metadata deleted."""
        with self._meta_lock:
            meta = self._metadata.get(qname)
            if not meta:
                return _result(False, "not_found", "Quarantine entry not found", {"qname": qname})
            path = meta.get("final_path") or meta.get("staged_path")
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    try:
                        shutil.rmtree(path)
                    except Exception:
                        log.exception("Failed to remove file %s", path)
            meta["deleted"] = True
            meta["deleted_ts"] = int(time.time())
            self._register_metadata(qname, meta)
            with self._lock:
                self.telemetry["deleted"] += 1
            self._maybe_alert({"type": "deleted", "qname": qname, "meta": meta})
            self._telemetry_emit({"action": "quarantine_deleted", "qname": qname, "ok": True})
            return _result(True, "deleted", "Quarantine file deleted", {"qname": qname})

    # -----------------------
    # Listing & query
    # -----------------------
    def list_quarantined(self, committed_only: Optional[bool] = None) -> List[Dict[str, Any]]:
        """Return list of metadata entries. If committed_only True => only committed ones."""
        out = []
        with self._meta_lock:
            for qname, meta in self._metadata.items():
                if committed_only is True and not meta.get("committed"):
                    continue
                if committed_only is False and meta.get("committed"):
                    continue
                out.append({**meta})
        return out

    def get_entry(self, qname: str) -> Optional[Dict[str, Any]]:
        with self._meta_lock:
            ent = self._metadata.get(qname)
            return dict(ent) if ent else None

    # -----------------------
    # Bulk operations
    # -----------------------
    def bulk_quarantine(self, paths: List[str], reason: Optional[str] = None) -> Dict[str, Any]:
        """Quarantine many files using thread pool, return mapping path -> result."""
        results = {}
        futures = {self.executor.submit(self.quarantine_file, p, reason, True): p for p in paths}
        with self._lock:
            self.telemetry["bulk_ops"] += 1
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                res = fut.result()
            except Exception:
                log.exception("bulk_quarantine failed for %s", p)
                res = _result(False, "exception", "Exception during bulk quarantine", {"path": p})
            results[p] = res
        return {"ok": True, "code": "bulk_complete", "data": results, "ts": int(time.time())}

    # -----------------------
    # Alerts (simple rate-limited)
    # -----------------------
    def _maybe_alert(self, payload: Dict[str, Any]):
        if not self.alert_callback:
            return
        now = time.time()
        window = 60.0
        with self._lock:
            while self._alert_timestamps and (now - self._alert_timestamps[0]) > window:
                self._alert_timestamps.popleft()
            if len(self._alert_timestamps) >= self.alert_rate_per_minute:
                return
            self._alert_timestamps.append(now)
        try:
            threading.Thread(target=self.alert_callback, args=(payload,), daemon=True).start()
        except Exception:
            try:
                self.alert_callback(payload)
            except Exception:
                log.exception("alert_callback failed")

    # -----------------------
    # Telemetry & housekeeping
    # -----------------------
    def get_telemetry(self) -> Dict[str, Any]:
        with self._lock:
            data = dict(self.telemetry)
            data.update(self.hash_cache.stats())
            return data
    
    # دالة get_quarantined_files المطلوبة لـ main.py
    def get_quarantined_files(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        إرجاع قائمة بالملفات المحجوزة - متوافق مع main.py
        """
        try:
            quarantined_list = self.list_quarantined(committed_only=True)
            return quarantined_list[:limit]
        except Exception as e:
            log.error(f"Error getting quarantined files: {e}")
            return []

    def close(self):
        try:
            self.executor.shutdown(wait=True)
        except Exception:
            pass
        try:
            with self._meta_lock:
                self._save_metadata()
        except Exception:
            pass


# -----------------------
# Facade for REST (متوافق مع main.py و static/script.js)
# -----------------------
class QuarantineFacade:
    """
    تُقدّم مخرجات JSON بالشكل الذي يستهلكه الـ frontend:
      - /quarantine/list    -> {"success": true, "data": [ ... ]}
      - /quarantine/restore -> {"success": true, "restored_to": "...", "qname": "..."}
      - /quarantine/delete  -> {"success": true}
    """

    def __init__(self, manager: QuarantineManager):
        self.mgr = manager

    def _meta_to_item(self, qname: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        # created_at: ISO من commit_ts أو staged_ts
        ts = meta.get("commit_ts") or meta.get("staged_ts") or int(time.time())
        created_iso = datetime.utcfromtimestamp(int(ts)).isoformat() + "Z"
        size = 0
        fpath = meta.get("final_path") or meta.get("staged_path")
        try:
            if fpath and os.path.exists(fpath):
                size = int(os.stat(fpath).st_size)
        except Exception:
            size = 0

        return {
            "id": qname,                      # يُستخدم في script.js كـ file_id
            "qname": qname,                   # زيادةً في التوافق
            "file_path": meta.get("original_path"),
            "created_at": created_iso,
            "committed": bool(meta.get("committed")),
            "size": size,
            "size_h": human_size(size),
            "sha256": meta.get("sha256"),
        }

    # -------- List --------
    def list_items(self) -> Dict[str, Any]:
        try:
            entries = self.mgr.list_quarantined()
            items = []
            for meta in entries:
                q = meta.get("quarantine_name")
                if not q:
                    # fallback: if metadata key lost; try infer from paths
                    q = (meta.get("final_path") or meta.get("staged_path") or "").split(os.sep)[-1]
                items.append(self._meta_to_item(q, meta))
            return {"success": True, "data": items}
        except Exception as e:
            log.error("quarantine list error: %s", e)
            return {"success": False, "error": str(e)}

    # -------- Restore --------
    def restore(self, file_id: str, dest_path: Optional[str] = None) -> Dict[str, Any]:
        try:
            if not file_id:
                return {"success": False, "error": "file_id is required"}
            r = self.mgr.restore_file(file_id, dest_path=dest_path, mark_false_positive=True)
            return {
                "success": bool(r.get("ok")),
                "qname": file_id,
                "restored_to": r.get("data", {}).get("restored_to"),
                "error": None if r.get("ok") else r.get("msg"),
            }
        except Exception as e:
            log.error("quarantine restore error: %s", e)
            return {"success": False, "error": str(e)}

    # -------- Delete --------
    def delete(self, file_id: str) -> Dict[str, Any]:
        try:
            if not file_id:
                return {"success": False, "error": "file_id is required"}
            r = self.mgr.delete_file(file_id)
            return {"success": bool(r.get("ok")), "error": None if r.get("ok") else r.get("msg")}
        except Exception as e:
            log.error("quarantine delete error: %s", e)
            return {"success": False, "error": str(e)}

    # إضافة دالة get_quarantined_files المطلوبة
    def get_quarantined_files(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        إرجاع قائمة بالملفات المحجوزة
        """
        try:
            quarantined_list = self.list_quarantined(committed_only=True)
            return quarantined_list[:limit]  # إرجاع العدد المطلوب
        except Exception as e:
            log.error("Error getting quarantined files: %s", e)
            return []

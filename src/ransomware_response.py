# ransomware_protection_system/src/ransomware_response.py
# -*- coding: utf-8 -*-
r"""
RansomwareResponse (Windows-ready)
----------------------------------
Facade around QuarantineManager to:
- Isolate suspicious files (quarantine)
- Restore / Delete / Bulk operations
- Use centralized logging (via src.logger)
- Supports context manager for safe lifecycle

تحسينات توافق ويندوز:
- اختيار مجلد حجر افتراضي مناسب لويندوز (%ProgramData%\RPS\quarantine)
  بدل /var/lib/ransom_quarantine عند عدم تمرير قيمة من المستخدم.
- تطبيع المسارات + دعم case-insensitive في الكاش على ويندوز.
- دعم المسارات الطويلة عند الحاجة (بدون تغيير واجهات أو سلوك).
"""

from __future__ import annotations

import os
import threading
from typing import Dict, Any, List, Optional

# --- Logger (robust import) ---
try:
    from src.logger import get_logger  # type: ignore
except Exception:  # pragma: no cover
    try:
        from logger import get_logger  # type: ignore
    except Exception:
        import logging
        def get_logger(name: str):
            logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            return logging.getLogger(name)

# --- Quarantine manager (robust import) ---
try:
    from src.quarantine_manager import QuarantineManager  # type: ignore
except Exception:  # pragma: no cover
    from quarantine_manager import QuarantineManager  # type: ignore

log = get_logger(__name__)


# ---------------------
# Platform helpers
# ---------------------
def _is_windows() -> bool:
    return os.name == "nt"

def _norm_abs(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p))

def _normcase(p: str) -> str:
    return os.path.normcase(p) if _is_windows() else p

def _win_long_path(p: str) -> str:
    """دعم المسارات الطويلة على ويندوز عند الحاجة فقط (لا يغير سلوك الأنظمة الأخرى)."""
    if not _is_windows():
        return p
    ap = _norm_abs(p)
    if ap.startswith("\\\\?\\") or len(ap) < 248:
        return ap
    if ap.startswith("\\\\"):  # UNC
        return "\\\\?\\UNC\\" + ap[2:]
    return "\\\\?\\" + ap

def _default_quarantine_dir() -> str:
    """اختيار مسار افتراضي آمن قابل للكتابة حسب المنصة."""
    if _is_windows():
        base = (os.environ.get("ProgramData")
                or os.environ.get("PUBLIC")
                or os.path.expanduser("~"))
        return _norm_abs(os.path.join(base, "RPS", "quarantine"))
    # الأنظمة الأخرى تبقى على المسار التقليدي
    return "/var/lib/ransom_quarantine"


class RansomwareResponse:
    """
    High-level interface to manage ransomware response actions.
    Wraps QuarantineManager with caching, logging, and context management.
    """

    def __init__(self,
                 quarantine_dir: str = "data/quarantine",
                 max_workers: int = 4):
        # إن لم يمرر المستخدم مسارًا (أو ترك الافتراضي اللينُكسي)، نضبط مسارًا افتراضيًا مناسبًا لويندوز.
        if quarantine_dir == "/var/lib/ransom_quarantine" and _is_windows():
            quarantine_dir = _default_quarantine_dir()

        # تطبيع المسار (لا نمرر \\?\ إلا عند الوصول الفعلي إذا احتاج الأمر داخل QuarantineManager)
        self.quarantine_dir = _norm_abs(quarantine_dir)

        self.qm = QuarantineManager(quarantine_dir=self.quarantine_dir,
                                    max_workers=max_workers)

        # كاش داخلي للنتائج الأخيرة (case-insensitive على ويندوز)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        log.info("RansomwareResponse initialized with quarantine_dir=%s", self.quarantine_dir)

    # ---------------------
    # Context Manager
    # ---------------------
    def __enter__(self):
        log.debug("Entering RansomwareResponse context.")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        if exc_type:
            log.error("Exception in RansomwareResponse context: %s", exc_val, exc_info=True)

    # ---------------------
    # Internal cache helpers
    # ---------------------
    def _cache_key(self, path: str) -> str:
        # على ويندوز: مفاتيح الكاش تكون case-insensitive
        return _normcase(_norm_abs(path))

    def _get_cache(self, path: str) -> Optional[Dict[str, Any]]:
        key = self._cache_key(path)
        with self._lock:
            return self._cache.get(key)

    def _set_cache(self, path: str, result: Dict[str, Any]):
        key = self._cache_key(path)
        with self._lock:
            self._cache[key] = result

    # ---------------------
    # Core operations
    # ---------------------
    def isolate(self, path: str, reason: Optional[str] = None) -> Dict[str, Any]:
        """Quarantine a single suspicious file."""
        cached = self._get_cache(path)
        if cached:
            log.debug("Cache hit for %s", path)
            return {"ok": True, "code": "cached", "msg": "Result from cache", "data": cached}

        npath = _norm_abs(path)
        log.info("Isolating file: %s (reason=%s)", npath, reason)

        # نمرر المسار الطبيعي—أي دعم long path (إن لزم) ينبغي أن يكون داخل QuarantineManager نفسه.
        res = self.qm.quarantine_file(npath, reason=reason, do_stage=True)
        self._set_cache(npath, res)

        if res.get("ok"):
            log.debug("File %s isolated successfully", npath)
        else:
            log.warning("Failed to isolate %s: %s", npath, res)
        return res

    def bulk_isolate(self, paths: List[str], reason: Optional[str] = None) -> Dict[str, Any]:
        """Bulk quarantine many files."""
        npaths = [ _norm_abs(p) for p in paths ]
        log.info("Bulk isolation requested for %d files", len(npaths))
        results = {}
        try:
            results = self.qm.bulk_quarantine(npaths, reason=reason)
            log.debug("Bulk isolation completed with %d results", len(results.get("data", {})))
        except Exception as e:
            log.error("Bulk isolation failed: %s", e, exc_info=True)
        return results

    def restore(self, qname: str, dest_path: Optional[str] = None) -> Dict[str, Any]:
        """Restore a quarantined file."""
        nq = _norm_abs(qname)
        d = _norm_abs(dest_path) if dest_path else None
        log.info("Restoring file %s", nq)
        res = self.qm.restore_file(nq, dest_path=d)
        if res.get("ok"):
            log.debug("File %s restored to %s", nq, res.get("data", {}).get("restored_to"))
        else:
            log.warning("Failed to restore %s: %s", nq, res)
        return res

    def delete(self, qname: str) -> Dict[str, Any]:
        """Delete a quarantined file permanently."""
        nq = _norm_abs(qname)
        log.info("Deleting quarantined file %s", nq)
        res = self.qm.delete_file(nq)
        if res.get("ok"):
            log.debug("File %s deleted", nq)
        else:
            log.warning("Failed to delete %s: %s", nq, res)
        return res

    def list_quarantine(self, committed_only: Optional[bool] = None) -> List[Dict[str, Any]]:
        """List quarantined items (staged/committed)."""
        log.debug("Listing quarantined files (committed_only=%s)", committed_only)
        return self.qm.list_quarantined(committed_only=committed_only)

    def stats(self) -> Dict[str, Any]:
        """Get telemetry stats."""
        s = self.qm.get_telemetry()
        log.debug("Telemetry stats collected: %s", s)
        return s

    # ---------------------
    # Shutdown
    # ---------------------
    def close(self):
        """Cleanly shutdown the underlying QuarantineManager."""
        try:
            self.qm.close()
            log.info("RansomwareResponse closed successfully.")
        except Exception as e:
            log.error("Error while closing RansomwareResponse: %s", e, exc_info=True)

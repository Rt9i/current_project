# src/utils.py
# -*- coding: utf-8 -*-
"""
Utilities (Helpers)
-------------------
- Common helper functions for the system
- Windows-safe I/O (long paths, gentle retry on locked files)
"""

import os
import time
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any

# ---------- logger (robust import) ----------
try:
    from src.logger import get_logger  # type: ignore
except Exception:
    try:
        from logger import get_logger  # type: ignore
    except Exception:
        import logging
        def get_logger(name):
            logging.basicConfig(level=logging.INFO)
            return logging.getLogger(name)

log = get_logger(__name__)


# ---------- platform helpers ----------
def _is_windows() -> bool:
    return os.name == "nt"

def _win_long_path(p: str) -> str:
    """
    دعم المسارات الطويلة على ويندوز عند الحاجة فقط. لا يؤثر على الأنظمة الأخرى.
    نستخدمه فقط عند الفتح/القراءة وليس في normalize_path حتى لا نغيّر
    سلوك بقية أجزاء النظام التي قد تعتمد على الشكل الطبيعي للمسار.
    """
    if not _is_windows():
        return p
    ap = os.path.abspath(os.path.expanduser(p))
    if ap.startswith("\\\\?\\") or len(ap) < 248:
        return ap
    if ap.startswith("\\\\"):  # UNC
        return "\\\\?\\UNC\\" + ap[2:]
    return "\\\\?\\" + ap


# ---------- public helpers ----------
def now_iso() -> str:
    """Return current UTC time in ISO format (with Z suffix)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_path(path: str) -> str:
    """
    Expand ~ and return absolute path (لا نضيف بادئة \\?\\ هنا).
    استخدم _win_long_path فقط عند الفتح الفعلي للملفات لتجنّب مفاجآت.
    """
    return os.path.abspath(os.path.expanduser(path))


def compute_sha256(file_path: str, chunk_size: int = 8192) -> Optional[str]:
    """
    Compute SHA256 hash of a file, return None on failure.
    - Windows-safe (long-path support)
    - محاولات إعادة قصيرة في حال كان الملف مقفلاً مؤقتًا (AV/Writer).
    """
    try:
        fp = _win_long_path(file_path)
        if not os.path.isfile(fp):
            log.debug("SHA256 skipped, file not found: %s", file_path)
            return None

        # retry خفيف جداً لسيناريوهات القفل المؤقت
        attempts = 3
        delay_s = 0.05
        while attempts:
            try:
                h = hashlib.sha256()
                with open(fp, "rb") as f:
                    for chunk in iter(lambda: f.read(chunk_size), b""):
                        h.update(chunk)
                return h.hexdigest()
            except PermissionError as e:
                attempts -= 1
                if attempts == 0:
                    log.debug("SHA256 permission error for %s: %s", file_path, e)
                    return None
                time.sleep(delay_s)
                delay_s *= 2
            except Exception as e:
                log.debug("SHA256 failed for %s: %s", file_path, e)
                return None
    except Exception as e:
        log.debug("SHA256 outer failure for %s: %s", file_path, e)
        return None


def load_json(path: str, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Load JSON file safely (Windows long-path aware)."""
    try:
        fp = _win_long_path(path)
        with open(fp, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log.warning("Failed to load JSON %s: %s", path, e)
        return (default.copy() if default else {})


def save_json(path: str, data: Dict[str, Any], atomic: bool = True) -> bool:
    """
    Save dict as JSON file safely.
    If atomic=True, writes to temp file then renames (os.replace).
    - Windows-safe (long-path support)
    - محاولات إعادة قصيرة عند تعذّر الاستبدال (قفل لحظي).
    """
    try:
        fp = _win_long_path(path)
        Path(fp).parent.mkdir(parents=True, exist_ok=True)

        if atomic:
            tmp_path = _win_long_path(f"{path}.tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            # retry خفيف في حال كان الهدف مقفلاً لفترة وجيزة
            attempts = 3
            delay_s = 0.05
            while attempts:
                try:
                    os.replace(tmp_path, fp)
                    break
                except PermissionError as e:
                    attempts -= 1
                    if attempts == 0:
                        log.error("Failed to atomically save JSON %s: %s", path, e)
                        try:
                            os.remove(tmp_path)
                        except Exception:
                            pass
                        return False
                    time.sleep(delay_s)
                    delay_s *= 2
                except Exception as e:
                    log.error("Failed to atomically save JSON %s: %s", path, e)
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
                    return False
        else:
            with open(fp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        return True
    except Exception as e:
        log.error("Failed to save JSON %s: %s", path, e)
        return False


def sizeof_fmt(num: float, suffix: str = "B") -> str:
    """Human readable file size (e.g., 1.0KB, 2.3MB)."""
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Y{suffix}"

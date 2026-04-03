# -*- coding: utf-8 -*-
r"""
paths.py — Windows-aware paths (no feature removal)

- يحافظ على نفس واجهة الملف الأصلي ويضيف دوال مساعدة مطلوبة من باقي الموديولات:
  get_local_backup_path(), get_quarantine_path(), get_database_dir(),
  get_models_dir(), get_rules_dir(), get_logs_dir(), expand_path()

- توافق ويندوز:
  * مسارات افتراضية تحت ProgramData و LocalAppData.
  * توسيع ~ ومتغيرات البيئة وإرجاع مسارات مطلقة.
  * دعم المسارات الطويلة (\\?\ و \\?\UNC\...) داخلياً عند الإنشاء فقط.
  * اختبار كتابة فعلي بإنشاء ملف مؤقت (أدق من os.access).

- لا حذف لأي ميزة؛ فقط بدائل متوافقة على ويندوز مع الحفاظ على السلوك.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import List, Optional

__all__ = [
    "get_local_backup_path",
    "get_quarantine_path",
    "get_database_dir",
    "get_models_dir",
    "get_rules_dir",
    "get_logs_dir",
    "expand_path",
]

# =========================
# Helpers: platform & paths
# =========================

def _is_windows() -> bool:
    return os.name == "nt"


def expand_path(p: str) -> str:
    """توسيع ~ ومتغيرات البيئة وتحويل إلى مسار مطلق."""
    return os.path.abspath(os.path.expanduser(os.path.expandvars(p)))


def _to_long_path(p: str) -> str:
    """
    تجهيز بادئة \\?\ لمسارات ويندوز الطويلة (داخلياً فقط).
    - لا نُعيد المسار بهذه البادئة للمستدعي؛ نستخدمها لمحاولات الإنشاء/الكتابة.
    """
    if not _is_windows():
        return p

    # مسار UNC: \\server\share\...  ->  \\?\UNC\server\share\...
    if p.startswith("\\\\"):
        return "\\\\?\\UNC" + p[1:]

    # مسار محلي عادي: C:\... -> \\?\C:\...
    if p.startswith("\\\\?\\"):
        return p
    return "\\\\?\\" + p


def _ensure_dir(path: str) -> bool:
    """
    إنشاء المجلد إن لم يكن موجودًا.
    على ويندوز نُجرّب long path عند الحاجة.
    """
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception:
        if _is_windows():
            try:
                os.makedirs(_to_long_path(path), exist_ok=True)
                return True
            except Exception:
                return False
        return False


def _can_write_dir(path: str) -> bool:
    """
    التحقق من قابلية الكتابة عملياً بإنشاء ملف مؤقت صغير.
    يُحاول أيضاً نسخة long path على ويندوز عند الحاجة.
    """
    try:
        if not os.path.isdir(path):
            return False

        # اختبار كتابة فعلي
        probe = os.path.join(path, f".rps_write_test_{uuid.uuid4().hex}.tmp")
        try:
            with open(probe, "wb") as f:
                f.write(b"\x00")
            os.remove(probe)
            return True
        except Exception:
            if _is_windows():
                lp = _to_long_path(probe)
                try:
                    os.makedirs(os.path.dirname(lp), exist_ok=True)
                    with open(lp, "wb") as f:
                        f.write(b"\x00")
                    os.remove(lp)
                    return True
                except Exception:
                    return False
            return False
    except Exception:
        return False


def _first_viable_dir(candidates: List[str]) -> str:
    """
    يجرّب المرشحين بالترتيب:
      - توسعة إلى مسارات مطلقة
      - إنشاء المجلد إن لزم
      - اختبار الكتابة
    يعيد أول مسار صالح. وإن فشل الجميع، يستخدم Fallback في مجلد HOME.
    """
    for raw in candidates:
        if not raw:
            continue
        path = expand_path(raw)
        if _ensure_dir(path) and _can_write_dir(path):
            return path

    home = str(Path.home())
    last_resort = expand_path(os.path.join(home, "RPS_Backups_Fallback"))
    _ensure_dir(last_resort)
    return last_resort


# =========================
# Defaults per platform
# =========================

def _windows_default_candidates_backups() -> List[str]:
    """
    مرشّحات منطقية للنسخ الاحتياطي على ويندوز (من الأكثر ثباتاً للأقل):
      1) %ProgramData%\RansomwareProtectionSystem\backups
      2) %LOCALAPPDATA%\RansomwareProtectionSystem\backups
      3) %USERPROFILE%\Backups\RansomwareProtection
      4) %USERPROFILE%\RPS_Backups
    """
    program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    local_appdata = os.environ.get("LOCALAPPDATA", os.path.join(str(Path.home()), "AppData", "Local"))
    userprofile = os.environ.get("USERPROFILE", str(Path.home()))
    return [
        os.path.join(program_data, "RansomwareProtectionSystem", "backups"),
        os.path.join(local_appdata, "RansomwareProtectionSystem", "backups"),
        os.path.join(userprofile, "Backups", "RansomwareProtection"),
        os.path.join(userprofile, "RPS_Backups"),
    ]


def _posix_default_candidates_backups() -> List[str]:
    """مرشّحات النسخ الاحتياطي على لينكس/ماك للحفاظ على السلوك الأصلي."""
    home = str(Path.home())
    return [
        os.path.join(home, "Backups", "RansomwareProtection"),
        os.path.join(home, ".local", "share", "ransomware_protection", "backups"),
        os.path.join(home, "RPS_Backups"),
    ]


def _windows_root() -> Path:
    return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "RansomwareProtectionSystem"


def _logs_root() -> Path:
    if _is_windows():
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "RansomwareProtectionSystem" / "logs"
    # POSIX-ish fallback
    return Path.home() / ".local" / "share" / "ransomware_protection" / "logs"


# =========================
# Public API
# =========================

def get_local_backup_path(custom: Optional[str] = None) -> str:
    """
    يعيد مسار النسخ الاحتياطي المحلي النهائي.
    - إن تم تمرير custom: يُجرّب أولاً بعد التوسعة والإنشاء.
    - إن لم يُمرّر: يختار أفضل مرشح حسب النظام.
    """
    candidates: List[str] = []
    if custom:
        candidates.append(custom)

    if _is_windows():
        candidates.extend(_windows_default_candidates_backups())
    else:
        candidates.extend(_posix_default_candidates_backups())

    return _first_viable_dir(candidates)


def get_quarantine_path() -> str:
    """مسار الحجر الصحي الافتراضي، مع ضمان الإنشاء."""
    base = _windows_root() if _is_windows() else (Path.home() / ".local" / "share" / "ransomware_protection")
    qdir = str((base / "quarantine").resolve())
    _ensure_dir(qdir)
    return qdir


def get_database_dir() -> str:
    """مسار مجلد قواعد بيانات التطبيق، مع ضمان الإنشاء."""
    base = _windows_root() if _is_windows() else (Path.home() / ".local" / "share" / "ransomware_protection")
    ddir = str((base / "database").resolve())
    _ensure_dir(ddir)
    return ddir


def get_models_dir() -> str:
    """مسار نماذج الذكاء الاصطناعي، مع ضمان الإنشاء."""
    base = _windows_root() if _is_windows() else (Path.home() / ".local" / "share" / "ransomware_protection")
    mdir = str((base / "AI_MODELS").resolve())
    _ensure_dir(mdir)
    return mdir


def get_rules_dir() -> str:
    """مسار قواعد YARA، مع ضمان الإنشاء."""
    base = _windows_root() if _is_windows() else (Path.home() / ".local" / "share" / "ransomware_protection")
    rdir = str((base / "YARA_RULES").resolve())
    _ensure_dir(rdir)
    return rdir


def get_logs_dir() -> str:
    """مسار سجلات التطبيق للمستخدم الحالي، مع ضمان الإنشاء."""
    ldir = str(_logs_root().resolve())
    _ensure_dir(ldir)
    return ldir

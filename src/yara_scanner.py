# ransomware_protection_system/src/yara_scanner.py
# -*- coding: utf-8 -*-
# pip install yara-python
"""
YARA Scanner Module — Windows-ready
===================================
- تحميل وتجميع كل قواعد YARA من مجلد محدد (*.yar, *.yara)
- فحص أي ملف يُمرَّر وإرجاع نتيجة منظّمة (infected/matches/…)
- متكامل مع main.py و event_handler.py

تحسينات التوافق مع ويندوز:
- fallback للفحص بالذاكرة (data=...) عند تعذّر فتح الملف مباشرة بسبب القفل/الصلاحيات.
- تطبيع المسارات (مع تحمّل اختلاف الأقراص).
- قفل خفيف حول match() لتعدد الخيوط.

المزايا كما هي:
- يتحمّل غياب مكتبة yara-python دون كسر البرنامج (yara_not_available)
- إعادة تحميل ذكي عند تغيّر ملفات القواعد (reload_if_changed)
- status() تُبلغ عن الحالة وعدد القواعد وآخر تحميل
- سجل تفصيلي + تطبيع المسارات
- عدم تغيير واجهات load_rules() و scan_file() (توافق تام)
"""

from __future__ import annotations

import os
import time
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

# --- Logger (مرن) ---
try:
    from src.logger import get_logger  # التشغيل من src
except Exception:
    try:
        from logger import get_logger  # التشغيل من الجذر
    except Exception:
        import logging
        get_logger = logging.getLogger  # Fallback بسيط

# --- Utils (normalize_path مرن) ---
def _default_normalize_path(p: str) -> str:
    return os.path.abspath(os.path.expanduser(str(p)))

try:
    from src.utils import normalize_path  # type: ignore
except Exception:
    try:
        from utils import normalize_path  # type: ignore
    except Exception:
        normalize_path = _default_normalize_path  # type: ignore

log = get_logger(__name__)

# --- YARA availability check ---
_YARA_IMPORT_ERROR: Optional[str] = None
try:
    import yara  # type: ignore
    YARA_AVAILABLE = True
except Exception as e:  # ImportError أو بيئات بدون yara
    YARA_AVAILABLE = False
    _YARA_IMPORT_ERROR = str(e)

DEFAULT_RULE_GLOBS = ("*.yar", "*.yara")
_ENGINE_NAME = "yara"

def _is_windows() -> bool:
    return os.name == "nt"

def _normcase(p: str) -> str:
    return os.path.normcase(p) if _is_windows() else p


class YaraScanner:
    """
    ماسح YARA بسيط وموثوق:
    - rules_dir: مجلد القواعد.
    - compiled_rules: Ruleset مجمّع (أو None إذا لم يُحمَّل).
    """
    def __init__(self, rules_dir: str):
        self.rules_dir: Path = Path(normalize_path(rules_dir))
        self.compiled_rules = None  # type: ignore
        self._last_loaded_ts: Optional[float] = None
        self._rules_mtime_index: Dict[str, float] = {}
        # قفل خفيف لسلامة match() في بيئات متعددة الخيوط
        self._lock = threading.RLock()

        if not self.rules_dir.exists():
            log.warning("YARA rules directory not found: %s (will create)", self.rules_dir)
            try:
                self.rules_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                log.error("Failed to create rules directory %s: %s", self.rules_dir, e)

        # تحميل مبدئي
        self.load_rules()

    # ---------------- Internals ----------------
    def _collect_rule_files(self) -> List[Path]:
        files: List[Path] = []
        try:
            for pattern in DEFAULT_RULE_GLOBS:
                files.extend(self.rules_dir.glob(pattern))
        except Exception:
            log.exception("Failed listing YARA rules in %s", self.rules_dir)
        # إزالة التكرار وترتيب ثابت
        uniq = sorted({str(p.resolve()): p for p in files}.values(), key=lambda p: str(p))
        return uniq

    def _build_mtime_index(self, files: List[Path]) -> Dict[str, float]:
        idx: Dict[str, float] = {}
        for f in files:
            try:
                idx[str(f)] = os.path.getmtime(f)
            except Exception:
                idx[str(f)] = 0.0
        return idx

    def _rules_changed(self) -> bool:
        """هل تغيّرت ملفات القواعد منذ آخر تحميل؟"""
        files = self._collect_rule_files()
        curr = self._build_mtime_index(files)
        if not self._rules_mtime_index:
            # أول مرة نعتبرها تغيّرًا ليفرض التحميل
            return True
        return curr != self._rules_mtime_index

    # ---------------- Public API ----------------
    def load_rules(self) -> bool:
        """
        تحميل وتجميع قواعد YARA من المجلد.
        يُرجع True إذا تم التحميل بنجاح، False إذا لا توجد قواعد أو فشل.
        """
        if not YARA_AVAILABLE:
            log.warning("YARA not available: %s", _YARA_IMPORT_ERROR)
            self.compiled_rules = None
            self._last_loaded_ts = None
            self._rules_mtime_index = {}
            return False

        rule_files = self._collect_rule_files()
        if not rule_files:
            log.warning("No YARA rules found in %s", self.rules_dir)
            self.compiled_rules = None
            self._last_loaded_ts = None
            self._rules_mtime_index = {}
            return False

        try:
            # Compile multiple rule files into one ruleset
            rule_dict = {os.path.basename(str(f)): str(f) for f in rule_files}
            # compile قد لا تكون thread-safe كليًا؛ نحصرها بالقفل للاحتياط
            with self._lock:
                # تمرير external 'filename' فارغًا كقيمة افتراضية
                self.compiled_rules = yara.compile(filepaths=rule_dict, externals={"filename": ""})  # type: ignore
            self._last_loaded_ts = time.time()
            self._rules_mtime_index = self._build_mtime_index(rule_files)
            log.info("Loaded %d YARA rule files from %s", len(rule_files), self.rules_dir)
            return True
        except Exception as e:
            log.error("Failed to load YARA rules: %s", e)
            self.compiled_rules = None
            self._last_loaded_ts = None
            self._rules_mtime_index = {}
            return False

    def reload_if_changed(self) -> bool:
        """
        يعيد التحميل فقط إذا تغيّرت ملفات القواعد.
        يُرجع True إذا أعاد التحميل، False إذا لم يتغير شيء أو فشل.
        """
        try:
            if self._rules_changed():
                log.info("YARA rules changed on disk — reloading")
                return self.load_rules()
            return False
        except Exception:
            log.exception("reload_if_changed failed")
            return False

    def status(self) -> Dict[str, Any]:
        """
        تقرير حالة سريع يمكن عرضه في REST (/api/yara/status)
        """
        count = None
        try:
            count = len(self._collect_rule_files())
        except Exception:
            pass
        return {
            "engine": _ENGINE_NAME,
            "enabled": YARA_AVAILABLE and self.compiled_rules is not None,
            "yara_available": YARA_AVAILABLE,
            "rules_dir": str(self.rules_dir),
            "rules_files": count,
            "last_loaded_ts": self._last_loaded_ts,
        }

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        فحص ملف بواسطة قواعد YARA.
        :param file_path: مسار الملف
        :return: dict => {engine, infected, matches, scan_time_ms, reason?/error?}
        """
        # التحمّل في حال عدم توفّر yara
        if not YARA_AVAILABLE:
            return {
                "engine": _ENGINE_NAME,
                "infected": False,
                "matches": [],
                "reason": "yara_not_available",
                "error": _YARA_IMPORT_ERROR,
            }

        # محاولة إعادة التحميل الذكي قبل الفحص (التقاط تغييرات القواعد)
        try:
            self.reload_if_changed()
        except Exception:
            # غير حرِج؛ نتابع بالفحص إن أمكن
            pass

        # لا قواعد مُحمّلة
        if not self.compiled_rules:
            return {
                "engine": _ENGINE_NAME,
                "infected": False,
                "matches": [],
                "reason": "no_rules_loaded",
            }

        # تحقق من وجود الملف
        fpath = normalize_path(file_path)
        if not os.path.exists(fpath):
            return {
                "engine": _ENGINE_NAME,
                "infected": False,
                "matches": [],
                "reason": "file_not_found",
            }

        # فحص
        try:
            t0 = time.time()
            filename_external = os.path.basename(fpath)

            # بعض أنظمة ويندوز قد تمنع فتح الملف (قفل/AV). نجرب match بالمسار أولاً،
            # ثم نلجأ إلى القراءة بالذاكرة data=... إن فشل فتح الملف.
            with self._lock:
                try:
                    matches = self.compiled_rules.match(  # type: ignore[attr-defined]
                        fpath, externals={"filename": filename_external}
                    )
                except Exception:
                    # Fallback: اقرأ المحتوى وافحصه بالذاكرة
                    with open(fpath, "rb") as fh:
                        data = fh.read()
                    matches = self.compiled_rules.match(  # type: ignore[attr-defined]
                        data=data, externals={"filename": filename_external}
                    )

            infected = len(matches) > 0
            match_details = [
                {
                    "rule": m.rule,
                    "tags": list(getattr(m, "tags", [])),
                    "meta": dict(getattr(m, "meta", {})),
                }
                for m in matches
            ]
            dt_ms = int((time.time() - t0) * 1000)
            return {
                "engine": _ENGINE_NAME,
                "infected": infected,
                "matches": match_details,
                "scan_time_ms": dt_ms,
            }
        except Exception as e:
            log.error("YARA scan failed for %s: %s", fpath, e)
            return {
                "engine": _ENGINE_NAME,
                "infected": False,
                "matches": [],
                "error": str(e),
            }

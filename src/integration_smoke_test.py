#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
integration_smoke_test.py (Windows-ready)
اختبار تجميعي سريع (smoke) لربط الموديولات الأساسية:
- YARA (yara_scanner)
- ML (ml_detector)
- IntegrityManager
- BackupManager + paths
- QuarantineManager
- FileEventHandler (تشغيل مسار _process_event على ملف تجريبي إذا توفر)

الفكرة:
- نحاول استيراد كل مكون من src/ مع Fallbacks (Shims) آمنة إن لم تتوفر الوحدات
- نحمّل config.json إن وجد ونحقن إعدادات آمنة للاختبار (تعطيل VT, Alerts)
- ننشئ ملف تجريبي بمحتوى يوحي بأنه مشبوه
- نشغّل فحوصات: سلامة (Integrity) + YARA + ML + (اختياريًا) FileEventHandler
- نقرر: نسخ احتياطي أم حجر، ثم نطبع تقريرًا مختصرًا بالنتائج والأخطاء

ملاحظات:
- يتم تعطيل VirusTotal تلقائيًا أثناء هذا الاختبار (api_key="") لتفادي أي اتصالات خارجية.
- مخرجات النسخ/الحجر (إن وُجدت) تُترك على القرص للفحص اليدوي اللاحق.
- مُهيأ للتعامل مع مسارات ويندوز الطويلة تلقائيًا.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import shutil
import json
from pathlib import Path
from pprint import pprint

# ---------------------------
# Windows helpers (long paths + normalization)
# ---------------------------
def _is_windows() -> bool:
    return os.name == "nt"

def _win_long_path(p: str) -> str:
    if not _is_windows():
        return p
    ap = os.path.abspath(os.path.expanduser(p))
    if ap.startswith("\\\\?\\") or len(ap) < 248:
        return ap
    if ap.startswith("\\\\"):  # UNC
        return "\\\\?\\UNC\\" + ap[2:]
    return "\\\\?\\" + ap

def _norm(p: str | Path) -> str:
    return _win_long_path(str(Path(p).expanduser().resolve()))

def _safe_copy2(src: str | Path, dst: str | Path):
    return shutil.copy2(_norm(src), _norm(dst))

# ---------------------------
# Project root detection
# ---------------------------
THIS_FILE = Path(__file__).resolve()
CANDIDATES = [THIS_FILE.parents[1], THIS_FILE.parents[0]]
ROOT = None
for cand in CANDIDATES:
    if (cand / "src").exists():
        ROOT = cand
        break
if ROOT is None:
    ROOT = THIS_FILE.parents[0]

# غيّر مجلد العمل للجذر لضمان إيجاد config.json والمجلدات القياسية
os.chdir(_norm(ROOT))
print("Project root:", ROOT)
print("Python:", sys.executable)
print("CWD:", os.getcwd())

# ---------------------------
# Try import helpers
# ---------------------------
def try_import(name: str):
    try:
        mod = __import__(name, fromlist=["*"])
        print(f"[OK] import {name}")
        return mod
    except Exception as e:
        print(f"[IMPORT FAIL] {name}: {e}")
        return None

def load_json_safe(path: Path):
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to load JSON {path}: {e}")
    return None

def deep_update(dst: dict, src: dict) -> dict:
    for k, v in (src or {}).items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            deep_update(dst[k], v)
        else:
            dst[k] = v
    return dst

# ---------------------------
# Imports from src with fallbacks
# ---------------------------
YaraScanner = None
MLDetector = None
IntegrityManager = None
BackupManager = None
QuarantineManager = None
FileEventHandler = None
get_local_backup_path = None

try:
    from src.yara_scanner import YaraScanner
    print("[OK] imported src.yara_scanner.YaraScanner")
except Exception as e:
    print("[WARN] src.yara_scanner import failed:", e)
    try:
        from yara_scanner import YaraScanner  # type: ignore
        print("[OK] imported yara_scanner.YaraScanner (fallback)")
    except Exception as e2:
        print("[WARN] yara_scanner fallback failed:", e2)
        YaraScanner = None

try:
    from src.ml_detector import MLDetector
    print("[OK] imported src.ml_detector.MLDetector")
except Exception as e:
    print("[WARN] src.ml_detector import failed:", e)
    try:
        from ml_detector import MLDetector  # type: ignore
        print("[OK] imported ml_detector.MLDetector (fallback)")
    except Exception as e2:
        print("[WARN] ml_detector fallback failed:", e2)
        MLDetector = None

try:
    from src.integrity_manager import IntegrityManager
    print("[OK] imported src.integrity_manager.IntegrityManager")
except Exception as e:
    print("[WARN] src.integrity_manager import failed:", e)
    try:
        from integrity_manager import IntegrityManager  # type: ignore
        print("[OK] imported integrity_manager.IntegrityManager (fallback)")
    except Exception as e2:
        print("[WARN] integrity_manager fallback failed:", e2)
        IntegrityManager = None

try:
    from src.backup_manager import BackupManager
    print("[OK] imported src.backup_manager.BackupManager")
except Exception as e:
    print("[WARN] src.backup_manager import failed:", e)
    try:
        from backup_manager import BackupManager  # type: ignore
        print("[OK] imported backup_manager.BackupManager (fallback)")
    except Exception as e2:
        print("[WARN] backup_manager fallback failed:", e2)
        BackupManager = None

try:
    from src.quarantine_manager import QuarantineManager
    print("[OK] imported src.quarantine_manager.QuarantineManager")
except Exception as e:
    print("[WARN] src.quarantine_manager import failed:", e)
    try:
        from quarantine_manager import QuarantineManager  # type: ignore
        print("[OK] imported quarantine_manager.QuarantineManager (fallback)")
    except Exception as e2:
        print("[WARN] quarantine_manager fallback failed:", e2)
        QuarantineManager = None

try:
    from src.event_handler import FileEventHandler
    print("[OK] imported src.event_handler.FileEventHandler")
except Exception as e:
    print("[WARN] src.event_handler import failed:", e)
    try:
        from event_handler import FileEventHandler  # type: ignore
        print("[OK] imported event_handler.FileEventHandler (fallback)")
    except Exception as e2:
        print("[WARN] event_handler fallback failed:", e2)
        FileEventHandler = None

try:
    from src.paths import get_local_backup_path
    print("[OK] imported src.paths.get_local_backup_path")
except Exception as e:
    print("[WARN] src.paths import failed:", e)
    try:
        from paths import get_local_backup_path  # type: ignore
        print("[OK] imported paths.get_local_backup_path (fallback)")
    except Exception as e2:
        print("[WARN] paths fallback failed:", e2)
        get_local_backup_path = None

# ---------------------------
# Shims (fallbacks) — تحافظ على السلوك الأصلي لكن متوافقة مع ويندوز
# ---------------------------
class DummyYara:
    def __init__(self, rules_dir):
        print("[SHIM] Using DummyYara (no yara available)")
    def status(self):
        return {"engine": "yara_shim", "enabled": False, "rules_files": 0}
    def reload_if_changed(self):
        return None
    def scan_file(self, path):
        suspicious_ext = {".encrypted", ".locked", ".ransom"}
        p = Path(path)
        infected = p.suffix.lower() in suspicious_ext
        return {"engine": "yara_shim", "infected": infected, "matches": ["shim_ext_flag"] if infected else [], "scan_time_ms": 0}

class DummyML:
    def __init__(self, models_dir=None, **kw):
        print("[SHIM] Using DummyML")
    def predict_file(self, path, deep=False, chunk_size=65536):
        suspicious_ext = {".encrypted", ".locked", ".ransom"}
        p = Path(path)
        pred = 0.6 if p.suffix.lower() in suspicious_ext else 0.1
        return {"prediction": pred, "infected": pred >= 0.5}

class DummyIntegrity:
    def __init__(self, db_path=None, chunk_size=65536, **kw):
        self.db_path = _norm(db_path or (Path.home() / ".rps_integrity_shim.db"))
        print("[SHIM] Using DummyIntegrity:", self.db_path)
    def check_file(self, p):
        return {"path": _norm(p), "status": "new", "new_hashes": {}}
    def update_file(self, p, **kw):
        return {"path": _norm(p), "status": "saved", "saved": True}
    def remove_file(self, p):
        return {"path": _norm(p), "removed": True}
    def close(self): pass

class DummyBackup:
    def __init__(self, local_backup_dir=None, **kw):
        self.local_backup_dir = _norm(local_backup_dir or (Path.home() / "RPS_Backups_Shim"))
        Path(self.local_backup_dir).mkdir(parents=True, exist_ok=True)
        print(f"[SHIM] DummyBackup using {self.local_backup_dir}")
    def backup_file(self, path, relative_to=None):
        try:
            dest_dir = Path(self.local_backup_dir)
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / Path(path).name
            _safe_copy2(path, dest)
            return {"ok": True, "path": str(dest), "relative_to": relative_to}
        except Exception as e:
            return {"ok": False, "error": str(e)}

class DummyQuarantine:
    def __init__(self, base_dir=None, path=None, **kw):
        base = base_dir or path or (Path.home() / "Quarantine_Shim")
        self.base_dir = _norm(base)
        Path(self.base_dir).mkdir(parents=True, exist_ok=True)
        Path(self.base_dir, "_pending").mkdir(parents=True, exist_ok=True)
        print(f"[SHIM] DummyQuarantine using {self.base_dir}")
    def quarantine_file(self, file_path, reason="test", do_stage=True):
        try:
            suffix = ".staged" if do_stage else ".quarantined"
            dest = Path(self.base_dir) / (Path(file_path).name + suffix)
            _safe_copy2(file_path, dest)
            return {"ok": True, "path": str(dest), "reason": reason, "staged": do_stage}
        except Exception as e:
            return {"ok": False, "error": str(e)}

# Effective classes
YaraCls = YaraScanner if YaraScanner is not None else DummyYara
MLCls = MLDetector if MLDetector is not None else DummyML
IntegrityCls = IntegrityManager if IntegrityManager is not None else DummyIntegrity
BackupCls = BackupManager if BackupManager is not None else DummyBackup
QuarantineCls = QuarantineManager if QuarantineManager is not None else DummyQuarantine
FileEventHandlerCls = FileEventHandler  # may be None

# ---------------------------
# Load config.json (optional) and override for safe smoke test
# ---------------------------
default_cfg = {
    "monitoring": {
        "protected_folders": [],
        "event_types": ["create", "modify"],
        "exclude_patterns": [".tmp", ".swp"]
    },
    "virustotal": {
        "api_key": "",  # مهم: تعطيل VT أثناء الاختبار
        "rate_limit_per_minute": 4,
        "cache_ttl_hours": 24,
        "cache_db": str((ROOT / "database" / "vt_cache.db").resolve()),
        "max_requests_per_minute": 4,
        "retries": 0,
        "timeout_seconds": 5,
        "retry_delay_seconds": 0.5
    },
    "alerts": {
        "max_per_minute": 10,
        "email": {"enabled": False},
        "slack": {"enabled": False},
        "webhook": {"enabled": False}
    },
    "executor": {
        "max_workers": 4
    },
    "bulk_processing": {
        "bulk_workers": 2,
        "bulk_batch_size": 10,
        "bulk_batch_timeout_seconds": 1,
        "bulk_suspicious_threshold": 10
    },
    "ml": {
        "enabled": True,
        "models_dir": str((ROOT / "AI_MODELS").resolve()),
        "threshold": 0.7,
        "fast_threshold": 0.5,
        "deep_enabled": True,
        "max_fast_file_mb": 200,
        "verbose": False
    },
    "yara": {
        "rules_dir": str((ROOT / "YARA_RULES").resolve()),
        "pre_scan_in_main": False
    },
    "telemetry": {
        "enabled": True,
        "stats_file": str((ROOT / "database" / "telemetry_smoke.json").resolve()),
        "max_samples": 200,
        "flush_every_n_events": 10
    },
    "detection": {
        "weights": {"yara": 0.3, "ml": 0.5, "vt": 0.2, "deep": 0.3},
        "final_threshold": 0.5,
        "min_votes_for_quarantine": 2,
        "vote_mode": "weighted"
    }
}

cfg_path = ROOT / "config.json"
user_cfg = load_json_safe(cfg_path) or {}
config = deep_update(default_cfg.copy(), user_cfg)

print("\n--- Config loaded (with safe VT/alerts overrides for smoke test) ---")
print("VT enabled? =>", bool(config.get("virustotal", {}).get("api_key")))

# ---------------------------
# Initialize components
# ---------------------------
print("\n--- Initializing components ---")
rules_dir = config.get("yara", {}).get("rules_dir", str(ROOT / "YARA_RULES"))
models_dir = config.get("ml", {}).get("models_dir", str(ROOT / "AI_MODELS"))
db_dir = Path(ROOT) / "database"
Path(_norm(db_dir)).mkdir(parents=True, exist_ok=True)

# YARA
try:
    Path(_norm(rules_dir)).mkdir(parents=True, exist_ok=True)  # لا يؤثر إن كانت موجودة
    ys = YaraCls(str(rules_dir))
    ystatus = ys.status() if hasattr(ys, "status") else {"note": "no status() method"}
    print("YARA status:", ystatus)
except Exception as e:
    print("YARA init failed:", e)
    ys = DummyYara(str(rules_dir))

# ML
try:
    Path(_norm(models_dir)).mkdir(parents=True, exist_ok=True)
    ml = MLCls(models_dir=models_dir, enabled=True)
    print("ML ready")
except Exception as e:
    print("ML init failed:", e)
    ml = DummyML(models_dir)

# Integrity
integrity_db = str((db_dir / "integrity_test.db").resolve())
try:
    im = IntegrityCls(db_path=integrity_db, chunk_size=65536)
    print("Integrity DB:", integrity_db)
except Exception as e:
    print("Integrity init failed:", e)
    im = DummyIntegrity(integrity_db)

# Backup
try:
    if get_local_backup_path:
        bdir = get_local_backup_path()
    else:
        bdir = str((Path.home() / "RPS_Backups_Test").resolve())
    Path(_norm(bdir)).mkdir(parents=True, exist_ok=True)
    bm = BackupCls(local_backup_dir=bdir)
    print("Backup dir:", getattr(bm, "local_backup_dir", bdir))
except Exception as e:
    print("Backup init failed:", e)
    bm = DummyBackup(local_backup_dir=str((Path.home() / "RPS_Backups_Shim").resolve()))

# Quarantine
try:
    qdir = str((Path.home() / "Quarantine_Test").resolve())
    Path(_norm(qdir)).mkdir(parents=True, exist_ok=True)
    try:
        qm = QuarantineCls(base_dir=qdir)
    except TypeError:
        qm = QuarantineCls(path=qdir)  # type: ignore
    print("Quarantine dir:", getattr(qm, "base_dir", qdir))
except Exception as e:
    print("Quarantine init failed:", e)
    qm = DummyQuarantine(base_dir=str((Path.home() / "Quarantine_Shim").resolve()))

# FileEventHandler
handler = None
if FileEventHandlerCls is not None:
    try:
        safe_handler_cfg = json.loads(json.dumps(config))  # deep copy
        safe_handler_cfg.setdefault("virustotal", {})["api_key"] = ""  # تعطيل VT
        safe_handler_cfg.setdefault("alerts", {})
        safe_handler_cfg["alerts"]["email"] = {"enabled": False}
        safe_handler_cfg["alerts"]["slack"] = {"enabled": False}
        safe_handler_cfg["alerts"]["webhook"] = {"enabled": False}

        handler = FileEventHandlerCls(
            backup_manager=bm,
            quarantine_manager=qm,
            config=safe_handler_cfg,
            notifiers=[]
        )
        print("FileEventHandler initialized")
    except Exception as e:
        print("FileEventHandler init failed:", e)
        handler = None
else:
    print("[WARN] FileEventHandler class not available - will run component-level checks")

# ---------------------------
# Create test file
# ---------------------------
print("\n--- Create test file ---")
tmpf = None
try:
    tmp_dir = Path(tempfile.gettempdir())
    tmpf = tempfile.NamedTemporaryFile(delete=False, suffix=".encrypted", prefix="rps_smoke_", dir=str(tmp_dir))
    tmpf.write(b"Your files have been encrypted\nBitcoin address: 1ABCDEF1234567890ABCDEFGH1234567\n")
    tmpf.flush()
    tmpf.close()
    test_path = _norm(tmpf.name)
    print("Test file:", test_path)
except Exception as e:
    print("Failed creating test file:", e)
    sys.exit(1)

# أضف مجلد الملف المؤقت إلى protected_folders ليستفيد أي منطق يعتمد عليها
try:
    mon = config.setdefault("monitoring", {})
    pf = mon.setdefault("protected_folders", [])
    tdir = str(Path(test_path).parent)
    if tdir not in pf:
        pf.append(tdir)
except Exception:
    pass

# ---------------------------
# Run the scan path
# ---------------------------
print("\n--- Running scan path ---")
result = {
    "yara": None,
    "ml": None,
    "integrity": None,
    "action": None,
    "backup": None,
    "quarantine": None,
    "handler_result": None,
    "errors": []
}

try:
    # 1) Integrity check
    try:
        result["integrity"] = im.check_file(test_path)
        print("Integrity check:", result["integrity"])
    except Exception as e:
        result["errors"].append(f"integrity_check_error: {e}")
        print("integrity.check_file error:", e)

    # 2) Prefer FileEventHandler pipeline if available (unified flow)
    if handler is not None:
        try:
            evt = {"file_path": test_path}
            print("Calling handler._process_event(...) (synchronous)")
            hres = handler._process_event(evt)  # استخدام المسار الداخلي عمداً للاختبار
            result["handler_result"] = hres
            print("Handler decision:", (hres or {}).get("decision"))
        except Exception as e:
            result["errors"].append(f"handler_error: {e}")
            print("handler._process_event raised:", e)
    else:
        # 3) Fallback: manual step-by-step
        try:
            if hasattr(ys, "reload_if_changed"):
                ys.reload_if_changed()
        except Exception:
            pass

        try:
            print("Manual YARA scan...")
            yres = ys.scan_file(test_path) if hasattr(ys, "scan_file") else {"infected": False}
            result["yara"] = yres
            print("YARA infected:", yres.get("infected"))
        except Exception as e:
            result["errors"].append(f"yara_error: {e}")
            print("yara scan failed:", e)

        try:
            print("Manual ML scan...")
            mres = ml.predict_file(test_path, deep=False, chunk_size=65536) if hasattr(ml, "predict_file") else {"prediction": 0.0}
            result["ml"] = mres
            print("ML result:", mres)
        except Exception as e:
            result["errors"].append(f"ml_error: {e}")
            print("ml scan failed:", e)

        # decide: if yara or ml indicates suspicious => quarantine else backup
        infected_flag = False
        if result.get("yara") and result["yara"].get("infected"):
            infected_flag = True
        if result.get("ml") and float(result["ml"].get("prediction", 0.0)) >= float(config.get("ml", {}).get("fast_threshold", 0.5)):
            infected_flag = True

        if infected_flag:
            try:
                qres = qm.quarantine_file(test_path, reason="smoke_test", do_stage=True)
                result["quarantine"] = qres
                result["action"] = "quarantine"
                print("Quarantine:", qres)
            except Exception as e:
                result["errors"].append(f"quarantine_error: {e}")
                print("quarantine failed:", e)
        else:
            try:
                bres = bm.backup_file(test_path, relative_to=None)
                result["backup"] = bres
                result["action"] = "backup"
                print("Backup:", bres)
            except Exception as e:
                result["errors"].append(f"backup_error: {e}")
                print("backup failed:", e)

except Exception as e:
    result["errors"].append(str(e))
    print("Unexpected error during scan path:", e)

# ---------------------------
# Summary
# ---------------------------
print("\n=== Integration smoke test summary ===")
pprint(result)

# ---------------------------
# Cleanup (optional)
# ---------------------------
print("\n--- Cleanup ---")
try:
    if tmpf:
        os.remove(test_path)
        print("Removed test file")
except Exception as e:
    print("Failed removing test file:", e)

print("NOTE: backup/quarantine outputs (if any) are left for manual inspection.")
print("Test finished.")

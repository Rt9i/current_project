# ransomware_protection_system/src/anomaly_detector.py
# -*- coding: utf-8 -*-
"""
detector_anomaly.py — Unsupervised + Heuristic Anomaly Detector (Windows-ready)
- إشارات فورية: معدل تعديلات، تغير امتداد، انتروبي، نمط اسم ملف عشوائي (garbled)
- نموذج غير خاضع للإشراف (IsolationForest / OneClassSVM) اختياري
- Baseline تلقائي: يتعلم من الأحداث “السليمة” ثم يحفَظ على القرص (joblib)
- API:
    AnomalyDetector(config).analyze_event(event) -> dict:
        {
          "anomalous": bool,
          "score": float,            # 0..1
          "signals": {...},          # إشارات مفصّلة
          "features": {...},         # المميزات العددية
          "model": {"used": bool, "trained": bool, "size": int},
          "ts": int, "path": "..."
        }
    AnomalyDetector.status(), .reload(cfg), .reset_baseline(), .save(), .load()

- التكامل: استدعِ analyze_event(event) قبل تمرير الحدث إلى event_handler.

توافق ويندوز:
- دعم المسارات الطويلة \\?\\ عند الوصول الفعلي للملفات (لا يغير الواجهات).
- تطبيع المسارات عبر utils.normalize_path.
"""

from __future__ import annotations

import os
import re
import math
import time
import threading
from pathlib import Path
from collections import deque, defaultdict
from typing import Optional, Dict, Any, Deque, List
from datetime import datetime, timezone  # لتحويل ISO timestamps بأمان

# -------- Platform helpers (Windows long-path) --------
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

# -------- أُطُر اختيارية --------
try:
    import numpy as np
except Exception:
    np = None

try:
    import joblib
except Exception:
    joblib = None

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
except Exception:
    IsolationForest = None
    OneClassSVM = None

# -------- لوجر المشروع --------
try:
    from src.logger import get_logger  # تفضيل نمط المشروع
except Exception:  # pragma: no cover
    try:
        from logger import get_logger  # تشغيل من الجذر
    except Exception:
        import logging
        def get_logger(name: str):
            logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            return logging.getLogger(name)

log = get_logger(__name__)

# -------- أدوات مساعدة من utils --------
try:
    from src.utils import normalize_path, now_iso  # type: ignore
except Exception:
    try:
        from utils import normalize_path, now_iso  # type: ignore
    except Exception:
        def normalize_path(p: str) -> str:
            return str(Path(p).resolve())
        def now_iso() -> str:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

# -----------------------------
# Helpers: Entropy & IO
# -----------------------------
def _byte_histogram(path: str, max_bytes: int = 65536):
    """إرجاع هيستوجرام 256 خانة لأول max_bytes من الملف (Windows long-path aware)."""
    try:
        import numpy as _np
    except Exception:
        return None, 0
    counts = _np.zeros(256, dtype=_np.uint64)
    read = 0
    fp = _win_long_path(path)
    with open(fp, "rb") as f:
        while read < max_bytes:
            chunk = f.read(min(8192, max_bytes - read))
            if not chunk:
                break
            a = _np.frombuffer(chunk, dtype=_np.uint8)
            bincount = _np.bincount(a, minlength=256)
            counts += bincount
            read += len(chunk)
    return counts, read

def _shannon_entropy_from_counts(counts):
    if counts is None:
        return None
    try:
        import numpy as _np
    except Exception:
        return None
    total = counts.sum()
    if total == 0:
        return 0.0
    probs = counts / total
    probs = probs[probs > 0]
    return -float((probs * _np.log2(probs)).sum())

def _filename_randomness_score(name: str) -> float:
    """يعطي 0..1: كلما الاسم “مخربط” أكثر، ارتفع السكور."""
    base = os.path.splitext(os.path.basename(name))[0]
    if not base:
        return 0.0
    long_digit = bool(re.search(r"\d{6,}", base))
    long_hex = bool(re.search(r"[0-9a-fA-F]{8,}", base))
    long_base64ish = bool(re.search(r"[A-Za-z0-9+/]{12,}", base))
    has_delims = bool(re.search(r"[_\-\.\+]{2,}", base))
    parts = re.split(r"[_\-\.\+]", base)
    avg_len = sum(len(p) for p in parts) / max(1, len(parts))
    score = 0.0
    score += 0.25 if long_digit else 0.0
    score += 0.25 if long_hex else 0.0
    score += 0.2 if long_base64ish else 0.0
    score += 0.15 if avg_len >= 10 else 0.0
    score += 0.15 if has_delims else 0.0
    return min(1.0, score)

def _ext(path: str) -> str:
    return (os.path.splitext(path)[1] or "").lower()

def _dirkey(path: str) -> str:
    try:
        return str(Path(path).resolve().parent)
    except Exception:
        return str(Path(path).parent)

# -----------------------------
# Timestamp coercion
# -----------------------------
def _to_epoch_seconds(primary: Any, fallback: Any = None) -> float:
    """
    يحوّل قيمة زمنية (رقمية أو ISO-8601 كسلسلة) إلى Epoch seconds (float).
    يقبل: float/int أو str رقمية أو ISO-8601 مع/بدون Z.
    """
    val = primary if (primary is not None) else fallback
    if val is None:
        return time.time()

    if isinstance(val, (int, float)):
        try:
            return float(val)
        except Exception:
            return time.time()

    if isinstance(val, str):
        s = val.strip()
        try:
            return float(s)
        except Exception:
            pass
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return float(dt.timestamp())
        except Exception:
            return time.time()

    return time.time()

# -----------------------------
# Core
# -----------------------------
class AnomalyDetector:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", True))

        # نافذة زمنيّة وعتبات
        self.window_seconds = int(cfg.get("window_seconds", 60))
        self.rate_threshold = int(cfg.get("rate_threshold", 20))        # تعديلات/دقيقة لكل مجلد
        self.anomaly_threshold = float(cfg.get("threshold", 0.65))      # قرار نهائي 0..1
        self.entropy_jump = float(cfg.get("entropy_jump", 0.4))         # قفزة انتروبي تُعتبر مرتفعة
        self.entropy_bytes = int(cfg.get("entropy_bytes", 65536))
        self.max_cache = int(cfg.get("max_cache", 20000))

        # أوزان الإشارات
        self.weights = dict(cfg.get("weights", {
            "rate": 0.30,
            "ext_change": 0.25,
            "suspicious_ext": 0.15,
            "entropy_delta": 0.20,
            "name_random": 0.10
        }))

        # قائمة امتدادات مشبوهة
        mon = cfg.get("monitoring", {})
        self.suspicious_exts: List[str] = [e.lower() for e in (mon.get("suspicious_extensions") or cfg.get("suspicious_extensions") or [])]

        # نموذج غير خاضع للإشراف
        self.model_name = str(cfg.get("model", "iforest"))  # iforest | oneclass | none
        self.contamination = float(cfg.get("contamination", 0.02))
        self.model_path = str(cfg.get("model_path", str(Path("AI_MODELS") / "anomaly_iforest.pkl")))
        self.model = None
        self.model_trained = False

        # ذاكرات داخلية
        self._lock = threading.RLock()
        self._dir_rate: Dict[str, Deque[float]] = defaultdict(deque)  # dir -> deque of timestamps
        self._last_entropy: Dict[str, float] = {}
        self._last_ext: Dict[str, str] = {}
        self._feature_buffer: List[List[float]] = []   # baseline buffer
        self._feature_cap = int(cfg.get("baseline_cap", 600))  # عدد أحداث لتدريب baseline
        self._last_gc = time.time()

        # تحميل النموذج إن وُجد
        self.load()

    # --------------------- Model I/O ---------------------
    def load(self):
        if not joblib:
            return
        try:
            p = Path(self.model_path)
            if p.exists():
                obj = joblib.load(str(p))
                self.model = obj.get("model")
                self.model_trained = bool(obj.get("trained", False))
                log.info("AnomalyDetector: Loaded model from %s (trained=%s)", p, self.model_trained)
        except Exception:
            log.exception("AnomalyDetector: load() failed")

    def save(self):
        if not (joblib and self.model):
            return False
        try:
            Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
            joblib.dump({"model": self.model, "trained": self.model_trained}, self.model_path)
            return True
        except Exception:
            log.exception("AnomalyDetector: save() failed")
            return False

    def reset_baseline(self):
        with self._lock:
            self._feature_buffer.clear()
            self.model = None
            self.model_trained = False
        try:
            if Path(self.model_path).exists():
                Path(self.model_path).unlink()
        except Exception:
            pass

    # --------------------- Public API ---------------------
    def reload(self, cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """تحديث الإعدادات + إعادة تحميل/تهيئة النموذج."""
        if cfg:
            self.__init__(cfg)  # إعادة تهيئة بسيطة وآمنة دون كسر الواجهات
        else:
            self.load()
        return self.status()

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "threshold": self.anomaly_threshold,
            "window_seconds": self.window_seconds,
            "rate_threshold": self.rate_threshold,
            "entropy_jump": self.entropy_jump,
            "model": {
                "name": self.model_name,
                "trained": self.model_trained,
                "path": self.model_path,
                "available": bool(self.model is not None)
            },
            "weights": dict(self.weights),
            "suspicious_exts": self.suspicious_exts
        }

    def analyze_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        يُفضَّل استدعاؤها لكل حدث ملف (create/modify).
        تُرجِع score مُطَبَّع 0..1 وقرار anomalous.
        """
        res = {
            "anomalous": False,
            "score": 0.0,
            "signals": {},
            "features": {},
            "model": {"used": False, "trained": self.model_trained},
            "ts": int(time.time()),  # نُبقيها صحيحة التوافق
            "path": None
        }
        if not self.enabled:
            return res

        path = event.get("file_path") or event.get("path")
        if not path:
            return res
        path = normalize_path(path)
        res["path"] = path

        # تحويل آمن للطابع الزمني (يدعم ISO-8601 مع Z أو قيَم رقمية)
        ts = _to_epoch_seconds(event.get("ts"), event.get("timestamp"))

        dkey = _dirkey(path)
        ext_now = _ext(path)

        # تحديث نافذة معدل التعديلات للمجلد
        with self._lock:
            dq = self._dir_rate[dkey]
            dq.append(ts)
            cut = ts - self.window_seconds
            while dq and dq[0] < cut:
                dq.popleft()
            dir_rate = len(dq)

        # قياس انتروبي سريع
        entropy_now = None
        fp = _win_long_path(path)
        if os.path.exists(fp) and np is not None:
            try:
                counts, read = _byte_histogram(fp, max_bytes=self.entropy_bytes)
                entropy_now = _shannon_entropy_from_counts(counts)
            except Exception:
                entropy_now = None

        # دلتا انتروبي
        with self._lock:
            prev_entropy = self._last_entropy.get(path)
            self._last_entropy[path] = entropy_now if entropy_now is not None else prev_entropy
        entropy_delta = 0.0
        if (entropy_now is not None) and (prev_entropy is not None):
            entropy_delta = max(0.0, float(entropy_now - prev_entropy))

        # تغير الامتداد؟
        with self._lock:
            prev_ext = self._last_ext.get(path)
            self._last_ext[path] = ext_now
        ext_changed = bool(prev_ext and prev_ext != ext_now)

        suspicious_ext = ext_now in self.suspicious_exts
        name_random = _filename_randomness_score(path)

        # ----- إشارات مُطبَّعة 0..1 -----
        signals = {}
        signals["rate"] = min(1.0, dir_rate / float(max(1, self.rate_threshold)))
        signals["entropy_delta"] = min(1.0, entropy_delta / max(1e-6, self.entropy_jump))
        signals["ext_change"] = 1.0 if ext_changed else 0.0
        signals["suspicious_ext"] = 1.0 if suspicious_ext else 0.0
        signals["name_random"] = float(name_random)

        # ميزات رقمية للنموذج
        size_mb = 0.0
        try:
            st = os.stat(fp)
            size_mb = st.st_size / (1024.0 * 1024.0)
        except Exception:
            pass

        rate_norm = signals["rate"]
        ext_flag = 1.0 if ext_changed else 0.0
        susp_flag = 1.0 if suspicious_ext else 0.0
        entropy_val = entropy_now if (entropy_now is not None) else 0.0

        features_vec = [
            size_mb, entropy_val, rate_norm,
            ext_flag, susp_flag, name_random
        ]
        res["features"] = {
            "size_mb": size_mb,
            "entropy": entropy_val,
            "rate_norm": rate_norm,
            "ext_changed": bool(ext_changed),
            "suspicious_ext": bool(suspicious_ext),
            "name_random": name_random
        }

        # ----- تجميع Rule-based -----
        wsum = sum(self.weights.values()) or 1.0
        rule_score = sum(self.weights[k] * signals.get(k, 0.0) for k in self.weights.keys()) / wsum

        # ----- نموذج غير خاضع للإشراف (لو متوفر/مدرّب) -----
        model_score = None
        model_used = False
        if self.model_name != "none" and self._model_available():
            try:
                x = self._as_matrix(features_vec)
                if self.model is None and not self.model_trained:
                    # تجميع baseline
                    with self._lock:
                        if len(self._feature_buffer) < self._feature_cap:
                            self._feature_buffer.append(features_vec)
                        if len(self._feature_buffer) >= self._feature_cap:
                            self._train_model(self._feature_buffer)
                            self._feature_buffer.clear()
                            self.save()
                if self.model is not None and self.model_trained:
                    model_used = True
                    model_score = self._predict_anomaly_score(x)
            except Exception:
                log.exception("AnomalyDetector: model predict failed")

        res["model"]["used"] = model_used
        # دمج السكور
        if (model_score is not None):
            final_score = 0.5 * rule_score + 0.5 * float(model_score)
        else:
            final_score = float(rule_score)

        final_score = max(0.0, min(1.0, final_score))
        anomalous = final_score >= self.anomaly_threshold

        res["signals"] = signals
        res["score"] = final_score
        res["anomalous"] = bool(anomalous)

        # تنظيف كاش خفيف
        self._gc_if_needed()

        return res

    # --------------------- Internals ---------------------
    def _as_matrix(self, vec: List[float]):
        if np is None:
            return [vec]
        return np.asarray(vec, dtype=float).reshape(1, -1)

    def _model_available(self) -> bool:
        if self.model_name == "iforest":
            return IsolationForest is not None
        if self.model_name == "oneclass":
            return OneClassSVM is not None
        return False

    def _train_model(self, Xbuf: List[List[float]]):
        if np is None or not self._model_available():
            return
        X = np.asarray(Xbuf, dtype=float)
        if self.model_name == "iforest" and IsolationForest:
            self.model = IsolationForest(
                n_estimators=150,
                contamination=self.contamination,
                max_features=1.0,
                n_jobs=1,
                random_state=42
            ).fit(X)
            self.model_trained = True
            log.info("AnomalyDetector: IsolationForest trained on %d samples", X.shape[0])
        elif self.model_name == "oneclass" and OneClassSVM:
            self.model = OneClassSVM(nu=self.contamination, kernel="rbf", gamma="scale").fit(X)
            self.model_trained = True
            log.info("AnomalyDetector: OneClassSVM trained on %d samples", X.shape[0])

    def _predict_anomaly_score(self, X):
        """خرّج 0..1 بحيث 1 = شذوذ أعلى."""
        if self.model is None:
            return None
        if IsolationForest and isinstance(self.model, IsolationForest):
            try:
                d = self.model.decision_function(X)  # أعلى = طبيعي
                z = 5.0
                val = 1.0 / (1.0 + math.exp(z * float(d[0])))
                return float(val)
            except Exception:
                return None
        if OneClassSVM and isinstance(self.model, OneClassSVM):
            try:
                d = self.model.decision_function(X)
                z = 5.0
                val = 1.0 / (1.0 + math.exp(z * float(d[0])))
                return float(val)
            except Exception:
                return None
        return None

    def _gc_if_needed(self):
        now = time.time()
        if (now - self._last_gc) < 10:
            return
        self._last_gc = now
        try:
            if len(self._last_entropy) > self.max_cache:
                for i, k in enumerate(list(self._last_entropy.keys())):
                    if i % 2 == 0:
                        self._last_entropy.pop(k, None)
            if len(self._last_ext) > self.max_cache:
                for i, k in enumerate(list(self._last_ext.keys())):
                    if i % 2 == 0:
                        self._last_ext.pop(k, None)
            if len(self._dir_rate) > self.max_cache:
                for i, k in enumerate(list(self._dir_rate.keys())):
                    if i % 2 == 0:
                        self._dir_rate.pop(k, None)
        except Exception:
            pass

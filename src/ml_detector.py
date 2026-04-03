# ransomware_protection_system/src/ml_detector.py
# -*- coding: utf-8 -*-
r"""
ML Detector — Windows-ready (keeps all original features)
---------------------------------------------------------
- Multi-stage ML detection:
  * fast-stage: lightweight features -> RandomForest / SVM
  * deep-stage: CNN + XGBoost (only if escalated)
- Public API:
  MLDetector(models_dir, threshold, fast_threshold, deep_enabled).detect_file(path)
  + status()  -> {"enabled": bool, "loaded": bool, "config": {...}}
  + reload()  -> يعيد تحميل النماذج ويُرجع status()
- Output shape (unchanged):
  { "infected": bool, "score": float, "fast": {...}, "deep": {...}, "sha256": "..." }

Windows tweaks (non-breaking):
- Path normalization + long-path prefix support (\\?\) when needed.
- Safe file-open with retries to tolerate transient sharing/AV locks.
"""

from __future__ import annotations

import io
import json
import math
import os
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any
import threading

import numpy as np

# pandas اختياري لدعم DataFrame عندما تكون أسماء الخصائص معروفة
try:
    import pandas as pd  # type: ignore
except Exception:
    pd = None

# ML libs - نحاول التحميل مع degraceful fallback
try:
    import joblib
except Exception:
    joblib = None

try:
    import xgboost as xgb
except Exception:
    xgb = None

try:
    # tensorflow.keras
    from tensorflow.keras.models import load_model as keras_load_model
except Exception:
    keras_load_model = None

# Robust logger import
try:
    from src.logger import get_logger  # type: ignore
except Exception:
    try:
        from logger import get_logger  # type: ignore
    except Exception:
        import logging
        def get_logger(name: str):
            logging.basicConfig(level=logging.INFO)
            return logging.getLogger(name)

log = get_logger(__name__)


# ---------------- Platform helpers ----------------
def _is_windows() -> bool:
    return os.name == "nt"


def _normcase(p: str) -> str:
    return os.path.normcase(p) if _is_windows() else p


def _normalize_path(p: str) -> str:
    """expanduser + abspath + long-path prefix on Windows if needed."""
    try:
        ap = os.path.abspath(os.path.expanduser(str(p)))
    except Exception:
        ap = str(p)
    if _is_windows():
        # لا نكرر البادئة
        if ap.startswith("\\\\?\\") or ap.startswith("\\\\"):
            return ap
        # اقتربنا من الحد؟ أضف \\?\
        if len(ap) >= 248:
            ap = "\\\\?\\" + ap
    return ap


# ---------------- Safe open with retry ----------------
def _open_binary_retry(path: str, attempts: int = 3, delay: float = 0.15) -> io.BufferedReader:
    """
    محاولة فتح الملف عدة مرات لتجاوز مشاكل القفل/المشاركة على ويندوز.
    يرفع الاستثناء الأخير إذا فشل.
    """
    last_err = None
    fpath = _normalize_path(path)
    for i in range(attempts):
        try:
            return open(fpath, "rb")
        except Exception as e:
            last_err = e
            if i < attempts - 1:
                time.sleep(delay)
    raise last_err  # type: ignore[misc]


# ---------------- Feature helpers ----------------
def _sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with _open_binary_retry(path) as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _shannon_entropy(byte_counts: np.ndarray) -> float:
    total = byte_counts.sum()
    if total == 0:
        return 0.0
    probs = byte_counts / total
    probs = probs[probs > 0]
    return -float((probs * np.log2(probs)).sum())


def _byte_histogram(path: str, max_bytes: int = 65536) -> np.ndarray:
    """Return 256-bin histogram from first max_bytes bytes (int64 counts) with safe open."""
    counts = np.zeros(256, dtype=np.int64)
    read = 0
    with _open_binary_retry(path) as f:
        while read < max_bytes:
            chunk = f.read(min(8192, max_bytes - read))
            if not chunk:
                break
            a = np.frombuffer(chunk, dtype=np.uint8)
            bincount = np.bincount(a, minlength=256).astype(counts.dtype, copy=False)
            counts += bincount
            read += len(chunk)
    return counts


def _aggregate_bins(hist256: np.ndarray, target_bins: int = 64) -> np.ndarray:
    """Aggregate 256 bins into target_bins (simple grouping)."""
    if target_bins <= 0:
        return hist256.astype(float)
    if target_bins == 256:
        return hist256.astype(float)

    factor = 256 // target_bins
    remainder = 256 % target_bins
    if factor == 0:
        return hist256.astype(float)

    agg = []
    idx = 0
    for i in range(target_bins):
        step = factor + (1 if i < remainder else 0)
        if idx + step <= 256:
            agg.append(hist256[idx:idx + step].sum())
        else:
            agg.append(hist256[idx:].sum())
        idx += step
        if idx >= 256:
            break

    agg = np.array(agg, dtype=np.float64)
    if len(agg) < target_bins:
        pad = np.zeros(target_bins - len(agg), dtype=np.float64)
        agg = np.concatenate([agg, pad])
    return agg


def _build_feature_vector(size_mb: float, entropy: float, agg_bins: np.ndarray) -> np.ndarray:
    vec = np.concatenate(([size_mb, entropy], agg_bins.astype(float))).astype(float)
    return vec.reshape(1, -1)


def _align_to_length(vec: np.ndarray, expected_len: Optional[int]) -> np.ndarray:
    """Align feature vector (1, N) to expected_len by truncation or zero-padding."""
    if expected_len is None:
        return vec
    cur = vec.shape[1]
    if cur == expected_len:
        return vec
    if cur > expected_len:
        return vec[:, :expected_len]
    pad = np.zeros((vec.shape[0], expected_len - cur), dtype=vec.dtype)
    return np.hstack([vec, pad])


# ---------------- XGBoost helpers (إصلاح عدد الأعمدة) ----------------
def _get_xgb_expected_features(xgb_model) -> Optional[int]:
    """استنتاج عدد الميزات المتوقع من موديل XGBoost (sklearn أو Booster)."""
    try:
        if hasattr(xgb_model, "n_features_in_"):
            return int(getattr(xgb_model, "n_features_in_"))
        if hasattr(xgb_model, "get_booster"):
            booster = xgb_model.get_booster()
            if booster is not None:
                try:
                    return int(booster.num_features())
                except Exception:
                    attrs = booster.attributes() or {}
                    nf = attrs.get("num_feature")
                    if nf is not None:
                        return int(nf)
        if hasattr(xgb_model, "num_features"):
            return int(xgb_model.num_features())  # type: ignore[attr-defined]
    except Exception:
        pass
    return None


def _reshape_features_for_expected(features_2d: np.ndarray, expected: Optional[int]) -> np.ndarray:
    """
    مواءمة طول المتجه مع العدد المتوقع:
      - إن كان None: نرجع كما هو.
      - إن كان expected < current: نقصّ من النهاية للحفاظ على ترتيب الميزات (size_mb, entropy ثم bins).
      - إن كان expected > current: نكمّل بصفر.
    """
    X = np.asarray(features_2d, dtype=np.float32)
    if X.ndim == 1:
        X = X.reshape(1, -1)
    if expected is None:
        return X
    cur = X.shape[1]
    if cur == expected:
        return X
    if cur > expected:
        return X[:, :expected]
    pad = np.zeros((X.shape[0], expected - cur), dtype=X.dtype)
    return np.hstack([X, pad])


class MLDetector:
    def __init__(self,
                 models_dir: str = "AI_MODELS",
                 threshold: float = 0.7,
                 fast_threshold: float = 0.5,
                 deep_enabled: bool = True,
                 max_fast_file_mb: int = 200,
                 verbose: bool = False,
                 enabled: bool = True):
        """
        models_dir: directory holding model files (RF, SVM, XGBoost, CNN, scalers)
        threshold: final decision threshold (>= => infected)
        fast_threshold: threshold on fast-stage score to escalate to deep-stage
        deep_enabled: whether to run deep stage when escalated
        max_fast_file_mb: if file larger than this, skip deep stage (or mark for manual review)
        enabled: toggle ML detector globally (status endpoint uses it)
        """
        self.models_dir = Path(_normalize_path(models_dir))
        self.threshold = float(threshold)
        self.fast_threshold = float(fast_threshold)
        self.deep_enabled = bool(deep_enabled)
        self.max_fast_file_mb = max_fast_file_mb
        self.verbose = verbose
        self.enabled = bool(enabled)

        # models (may be None if not found/importable)
        self.rf = None
        self.svm = None
        self.xgb = None
        self.cnn = None
        self.nn_scaler = None
        self.svm_scaler = None

        # feature names (اختياري)
        self.feature_names: Optional[list] = None

        # loaded flag
        self.loaded = False

        # simple in-memory cache: sha256 -> (timestamp, result)
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = threading.Lock()
        self._cache_ttl = 60 * 60  # 1 hour

        # Load models on init
        self._load_models()

    # --------------------
    # Model loading / lifecycle
    # --------------------
    def _refresh_loaded_flag(self):
        self.loaded = any([
            self.rf is not None,
            self.svm is not None,
            self.xgb is not None,
            self.cnn is not None,
        ])

    def _clear_models(self):
        self.rf = None
        self.svm = None
        self.xgb = None
        self.cnn = None
        self.nn_scaler = None
        self.svm_scaler = None
        self.feature_names = None
        self._refresh_loaded_flag()

    def _load_feature_names_file(self):
        """حمّل أسماء الخصائص من AI_MODELS/feature_names.json (اختياري)."""
        try:
            p = self.models_dir / "feature_names.json"
            if p.exists():
                with open(p, "r", encoding="utf-8") as f:
                    names = json.load(f)
                if isinstance(names, list) and all(isinstance(x, str) for x in names):
                    self.feature_names = names
                    if self.verbose:
                        log.info("MLDetector: Loaded feature names from %s (len=%d)", str(p), len(names))
        except Exception:
            log.exception("Failed loading feature_names.json")

    def _load_models(self):
        """Try loading common model files from models_dir; warn if missing."""
        self._clear_models()
        self._load_feature_names_file()

        # Sklearn / XGB
        try:
            if joblib:
                rf_path = self.models_dir / "RandomForest_model.pkl"
                svm_path = self.models_dir / "ransomware_svm_model.pkl"
                xgb_path = self.models_dir / "xgboost_model.pkl"
                nn_scaler_path = self.models_dir / "nn_scaler.pkl"
                svm_scaler_path = self.models_dir / "svm_scaler.pkl"

                if rf_path.exists():
                    try:
                        self.rf = joblib.load(str(rf_path))
                        log.info("MLDetector: Loaded RandomForest model.")
                    except Exception as e:
                        log.exception("Failed loading RF model: %s", e)

                if svm_path.exists():
                    try:
                        self.svm = joblib.load(str(svm_path))
                        log.info("MLDetector: Loaded SVM model.")
                    except Exception as e:
                        log.exception("Failed loading SVM model: %s", e)

                if xgb_path.exists() and xgb is not None:
                    try:
                        try:
                            # sklearn-like wrapper
                            self.xgb = joblib.load(str(xgb_path))
                        except Exception:
                            # raw booster
                            booster = xgb.Booster()
                            booster.load_model(str(xgb_path))
                            self.xgb = booster
                        log.info("MLDetector: Loaded XGBoost model.")
                    except Exception as e:
                        log.exception("Failed loading XGBoost model: %s", e)

                if nn_scaler_path.exists():
                    try:
                        self.nn_scaler = joblib.load(str(nn_scaler_path))
                        log.info("MLDetector: Loaded NN scaler.")
                    except Exception as e:
                        log.exception("Failed loading NN scaler: %s", e)

                if svm_scaler_path.exists():
                    try:
                        self.svm_scaler = joblib.load(str(svm_scaler_path))
                        log.info("MLDetector: Loaded SVM scaler.")
                    except Exception as e:
                        log.exception("Failed loading SVM scaler: %s", e)
            else:
                log.warning("joblib not installed: sklearn models won't be loaded (install scikit-learn).")
        except Exception:
            log.exception("Unexpected error while loading sklearn/xgboost models")

        # CNN
        try:
            cnn_path = self.models_dir / "ransomware_CNNs_model.hdf5"
            if cnn_path.exists() and keras_load_model is not None:
                try:
                    self.cnn = keras_load_model(str(cnn_path))
                    log.info("MLDetector: Loaded CNN model.")
                except Exception as e:
                    log.exception("Failed loading CNN model: %s", e)
            elif cnn_path.exists():
                log.warning("Found CNN model file but tensorflow.keras not available.")
        except Exception:
            log.exception("Unexpected error while loading CNN")

        self._refresh_loaded_flag()

    def reload(self) -> Dict[str, Any]:
        """إعادة تحميل النماذج من المسار الحالي + تفريغ الكاش."""
        try:
            self._load_models()
            self.clear_cache()
            st = self.status()
            log.info("MLDetector: models reloaded (loaded=%s)", st.get("loaded"))
            return st
        except Exception as e:
            log.exception("MLDetector.reload failed: %s", e)
            return {"enabled": self.enabled, "loaded": self.loaded, "config": self._config_dict(), "error": str(e)}

    # --------------------
    # Feature extraction
    # --------------------
    def _compute_hist_and_meta(self, path: str) -> Dict[str, Any]:
        p = _normalize_path(path)
        st = Path(p).stat()
        size_bytes = st.st_size
        size_mb = size_bytes / (1024.0 * 1024.0)
        hist256 = _byte_histogram(p, max_bytes=65536)
        entropy = _shannon_entropy(hist256)
        return {"size_mb": size_mb, "entropy": entropy, "hist256": hist256}

    def _vector_with_bins(self, meta: Dict[str, Any], bins: int) -> np.ndarray:
        agg = _aggregate_bins(meta["hist256"], target_bins=bins)
        return _build_feature_vector(meta["size_mb"], meta["entropy"], agg)

    def _preprocess_for_cnn(self, path: str) -> Optional[np.ndarray]:
        """
        تجهيز إدخال بسيط لـ CNN من هيستوجرام 256:
        - نعيد تشكيله إلى 16x16 قناة واحدة، مع تطبيع بسيط.
        - هذا اختياري ولن يُستخدم إلا إذا كان CNN متاحًا.
        """
        try:
            meta = self._compute_hist_and_meta(path)
            h = meta["hist256"].astype(np.float32)
            total = float(h.sum()) if float(h.sum()) > 0 else 1.0
            h = h / total
            img = h.reshape(16, 16)
            img = np.expand_dims(img, axis=2)  # (H, W, C=1)
            return img
        except Exception:
            log.exception("preprocess_for_cnn failed")
            return None

    # --------------------
    # Input builder (حل تحذير SVC جذريًا)
    # --------------------
    def _to_model_input(self, features_2d: np.ndarray, model=None):
        """
        - إن كان للموديل feature_names_in_ => نُنشئ DataFrame بنفس الأسماء (إن وجد pandas).
        - غير ذلك => نُعيد NumPy array (بدون أسماء) لتجنّب تحذير سكيت-ليرن
          "X has feature names, but SVC was fitted without feature names".
        """
        if features_2d is None or getattr(features_2d, "ndim", 1) != 2:
            arr = np.array(features_2d, dtype=float).reshape(1, -1)
        else:
            arr = np.asarray(features_2d, dtype=float)

        # إذا الموديل يعرف أسماء الخصائص، مررها له (RF/XGB أحيانًا)
        try:
            if pd is not None and model is not None and hasattr(model, "feature_names_in_"):
                names = list(getattr(model, "feature_names_in_"))
                if isinstance(names, list) and len(names) == arr.shape[1]:
                    return pd.DataFrame(arr, columns=names)  # type: ignore
        except Exception:
            pass

        # عكس ذلك: ارجع NumPy array من غير أسماء (هذا ما يريده SVC المتدرب بلا أسماء)
        return arr

    # --------------------
    # Prediction helpers
    # --------------------
    def _predict_rf(self, features: np.ndarray) -> Optional[float]:
        try:
            if self.rf is None:
                return None
            X = self._to_model_input(features, model=self.rf)
            if hasattr(self.rf, "predict_proba"):
                return float(self.rf.predict_proba(X)[0, 1])
            else:
                return float(self.rf.predict(X)[0])
        except Exception:
            log.exception("RF predict failed")
            return None

    def _predict_svm(self, features: np.ndarray) -> Optional[float]:
        try:
            if self.svm is None:
                return None
            X = self._to_model_input(features, model=self.svm)
            if hasattr(self.svm, "predict_proba"):
                return float(self.svm.predict_proba(X)[0, 1])
            elif hasattr(self.svm, "decision_function"):
                df = float(self.svm.decision_function(X)[0])
                prob = 1.0 / (1.0 + math.exp(-df))
                return prob
            else:
                return float(self.svm.predict(X)[0])
        except Exception:
            log.exception("SVM predict failed")
            return None

    def _predict_xgb(self, features: np.ndarray) -> Optional[float]:
        """
        إصلاح عدم تطابق عدد الأعمدة وأسماء الخصائص مع XGBoost:
        - استنتاج عدد الميزات المتوقع من الموديل ثم مواءمة المتجه تلقائيًا.
        - تمرير NumPy array وتعطيل validate_features لتجنب فحص الأسماء.
        - دعم كلٍ من XGBClassifier (sklearn-like) وBooster الخام.
        """
        try:
            if self.xgb is None or xgb is None:
                return None

            expected = _get_xgb_expected_features(self.xgb)
            X_np = _reshape_features_for_expected(features, expected)

            # sklearn-like wrapper
            if hasattr(self.xgb, "predict_proba"):
                # validate_features=False لتجاوز فحص أسماء الأعمدة
                return float(self.xgb.predict_proba(X_np, validate_features=False)[0, 1])

            # Booster خام
            if hasattr(self.xgb, "predict"):
                dmat = xgb.DMatrix(X_np)
                preds = self.xgb.predict(dmat)  # type: ignore
                if hasattr(preds, "__len__"):
                    return float(preds[0])
                return float(preds)

            return None

        except Exception as e:
            log.error("XGBoost predict failed")
            log.exception(e)
            return None

    def _predict_cnn(self, cnn_input: np.ndarray) -> Optional[float]:
        try:
            if self.cnn is None:
                return None
            inp = cnn_input
            input_shape = getattr(self.cnn, "input_shape", None)
            if input_shape and len(input_shape) >= 3:
                expected_h = input_shape[1]
                expected_w = input_shape[2] if len(input_shape) >= 3 else input_shape[1]
                expected_c = input_shape[3] if len(input_shape) >= 4 else 1
                if inp.shape[0] != expected_h or inp.shape[1] != expected_w:
                    resized = np.zeros((expected_h, expected_w, expected_c), dtype=np.float32)
                    h = min(expected_h, inp.shape[0])
                    w = min(expected_w, inp.shape[1])
                    c = min(expected_c, inp.shape[2]) if inp.ndim == 3 else 1
                    resized[:h, :w, :c] = inp[:h, :w, :c]
                    inp = resized
            batch = np.expand_dims(inp, axis=0)
            preds = self.cnn.predict(batch)
            if isinstance(preds, np.ndarray):
                val = float(preds[0].ravel()[0])
                if val < 0:
                    val = 1.0 / (1.0 + math.exp(-val))
                val = max(0.0, min(1.0, val))
                return val
            else:
                return None
        except Exception:
            log.exception("CNN predict failed")
            return None

    # --------------------
    # Public API
    # --------------------
    def detect_file(self, path: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {"file": path, "sha256": None, "infected": False, "score": 0.0, "fast": {}, "deep": {}}

        p = _normalize_path(path)
        if not os.path.exists(p):
            result["reason"] = "not_found"
            return result

        if not self.enabled:
            try:
                result["sha256"] = _sha256_of_file(p)
            except Exception:
                pass
            result["reason"] = "disabled"
            return result

        try:
            sha = _sha256_of_file(p)
            result["sha256"] = sha

            with self._cache_lock:
                cached = self._cache.get(sha)
                if cached and (time.time() - cached.get("_ts", 0)) < self._cache_ttl:
                    if self.verbose:
                        log.info("MLDetector: cache hit for %s", sha)
                    return cached["value"]

            # === استخراج "خام" ثم توليد متجهات تلائم كل موديل/سكلر ===
            start_fast = time.time()
            meta = self._compute_hist_and_meta(p)

            # المتجه الافتراضي (2 + 64 = 66)
            base_vec = self._vector_with_bins(meta, bins=64)
            fast_info = {"features_shape": base_vec.shape, "elapsed_ms": None}

            # --- RF path ---
            rf_vec = base_vec
            try:
                if self.nn_scaler is not None:
                    sc_exp = getattr(self.nn_scaler, "n_features_in_", None)
                    rf_vec = _align_to_length(rf_vec, sc_exp)
                    rf_vec = self.nn_scaler.transform(rf_vec)
                if self.rf is not None:
                    rf_exp = getattr(self.rf, "n_features_in_", None)
                    rf_vec = _align_to_length(rf_vec, rf_exp)
                rf_p = self._predict_rf(rf_vec)
            except Exception:
                log.exception("RF pipeline failed")
                rf_p = None

            # --- SVM path ---
            svm_vec = base_vec
            try:
                if self.svm_scaler is not None:
                    sc_exp = getattr(self.svm_scaler, "n_features_in_", None)
                    svm_vec = _align_to_length(svm_vec, sc_exp)
                    svm_vec = self.svm_scaler.transform(svm_vec)
                if self.svm is not None:
                    svm_exp = getattr(self.svm, "n_features_in_", None)
                    svm_vec = _align_to_length(svm_vec, svm_exp)
                svm_p = self._predict_svm(svm_vec)
            except Exception:
                log.exception("SVM pipeline failed")
                svm_p = None

            probs = [p for p in (rf_p, svm_p) if p is not None]
            fast_score = float(np.mean(probs)) if probs else 0.0
            fast_info.update({
                "rf_prob": rf_p,
                "svm_prob": svm_p,
                "score": fast_score,
                "elapsed_ms": int((time.time() - start_fast) * 1000),
            })
            result["fast"] = fast_info

            st = Path(p).stat()
            size_mb = st.st_size / (1024.0 * 1024.0)
            escalate_due_to_size = size_mb > self.max_fast_file_mb
            escalate = (fast_score >= self.fast_threshold)

            if escalate_due_to_size and self.deep_enabled:
                result["reason"] = "too_large_for_deep_scan"
                final_score = fast_score
                infected = final_score >= self.threshold
                result.update({"infected": infected, "score": float(final_score)})
                with self._cache_lock:
                    self._cache[sha] = {"_ts": time.time(), "value": result}
                return result

            deep_info: Dict[str, Any] = {}
            if escalate and self.deep_enabled and (self.cnn is not None or self.xgb is not None):
                start_deep = time.time()
                cnn_score = None
                if self.cnn is not None:
                    cnn_input = self._preprocess_for_cnn(p)
                    if cnn_input is not None:
                        cnn_score = self._predict_cnn(cnn_input)

                xgb_score = None
                if self.xgb is not None:
                    try:
                        xgb_score = self._predict_xgb(base_vec)
                    except Exception:
                        log.exception("XGB predict failed at deep stage")
                        xgb_score = None

                deep_probs = [pp for pp in (cnn_score, xgb_score) if pp is not None]
                deep_score = float(np.mean(deep_probs)) if deep_probs else 0.0
                deep_info.update({
                    "cnn_prob": cnn_score,
                    "xgb_prob": xgb_score,
                    "score": deep_score,
                    "elapsed_ms": int((time.time() - start_deep) * 1000),
                })
                result["deep"] = deep_info

                final_score = 0.4 * fast_score + 0.6 * deep_score
            else:
                final_score = float(fast_score)

            infected = final_score >= self.threshold
            result.update({"infected": bool(infected), "score": float(final_score)})

            with self._cache_lock:
                self._cache[sha] = {"_ts": time.time(), "value": result}

            return result

        except Exception as e:
            log.exception("MLDetector.detect_file failed for %s: %s", p, e)
            return {"file": path, "sha256": None, "infected": False, "score": 0.0,
                    "fast": {}, "deep": {}, "error": str(e)}

    # --- Backward-compat wrapper (to match event_handler usage) ---
    def predict_file(self, file_path: str, deep: bool = False, chunk_size: int = 65536, **kwargs) -> Dict[str, Any]:
        """
        Compatibility wrapper expected by event_handler:
        - deep=False: behave like detect_file()
        - deep=True : force running deep-stage (if enabled & models available) even if fast score < fast_threshold
        Preserves same output shape: {infected, score, fast, deep, sha256, file, ...}
        """
        base = self.detect_file(file_path)

        try:
            if (deep is True
                and self.enabled
                and self.deep_enabled
                and base.get("deep") in (None, {}, [])
                and (self.cnn is not None or self.xgb is not None)
                and os.path.exists(_normalize_path(file_path))):

                meta = self._compute_hist_and_meta(file_path)
                base_vec = self._vector_with_bins(meta, bins=64)

                cnn_score = None
                if self.cnn is not None:
                    cnn_in = self._preprocess_for_cnn(file_path)
                    if cnn_in is not None:
                        cnn_score = self._predict_cnn(cnn_in)

                xgb_score = None
                if self.xgb is not None:
                    try:
                        xgb_score = self._predict_xgb(base_vec)
                    except Exception:
                        log.exception("XGB predict failed at deep wrapper")
                        xgb_score = None

                deep_probs = [pp for pp in (cnn_score, xgb_score) if pp is not None]
                deep_score = float(np.mean(deep_probs)) if deep_probs else 0.0
                deep_info: Dict[str, Any] = {
                    "cnn_prob": cnn_score,
                    "xgb_prob": xgb_score,
                    "score": deep_score
                }
                base["deep"] = deep_info

                try:
                    fast_score = float(base.get("fast", {}).get("score", 0.0))
                except Exception:
                    fast_score = 0.0
                final_score = 0.4 * fast_score + 0.6 * deep_score
                base["score"] = float(final_score)
                base["infected"] = bool(final_score >= self.threshold)

                sha = base.get("sha256")
                if sha:
                    with self._cache_lock:
                        self._cache[sha] = {"_ts": time.time(), "value": base}

        except Exception:
            log.exception("MLDetector.predict_file (deep wrapper) failed for %s", file_path)

        return base

    # --------------------
    # Status / config helpers (للـ /ml/status و /ml/reload)
    # --------------------
    def _config_dict(self) -> Dict[str, Any]:
        return {
            "threshold": self.threshold,
            "fast_threshold": self.fast_threshold,
            "deep_enabled": self.deep_enabled,
            "max_fast_file_mb": self.max_fast_file_mb,
        }

    def status(self) -> Dict[str, Any]:
        """شكل متوافق مع script.js: {enabled, loaded, config}"""
        return {
            "enabled": self.enabled,
            "loaded": self.loaded,
            "config": self._config_dict(),
        }

    # --------------------
    # Utilities
    # --------------------
    def clear_cache(self):
        with self._cache_lock:
            self._cache.clear()

    def purge_old_cache(self):
        with self._cache_lock:
            now = time.time()
            keys = [k for k, v in self._cache.items() if (now - v["_ts"]) > self._cache_ttl]
            for k in keys:
                self._cache.pop(k, None)

    def set_thresholds(self, threshold: Optional[float] = None, fast_threshold: Optional[float] = None):
        if threshold is not None:
            self.threshold = float(threshold)
        if fast_threshold is not None:
            self.fast_threshold = float(fast_threshold)

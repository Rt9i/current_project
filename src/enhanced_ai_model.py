# ransomware_protection_system/src/enhanced_ai_model.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced AI Models for Ransomware Detection (Windows-ready)
- يحافظ على جميع الميزات ويضيف بدائل متوافقة مع ويندوز عند غياب تبعيات معينة.
"""

from __future__ import annotations

import os
import sys
import math
import logging
import struct
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional

# -------- Logger (robust import) --------
try:
    from src.logger import get_logger  # type: ignore
except Exception:  # pragma: no cover
    try:
        from logger import get_logger  # type: ignore
    except Exception:
        def get_logger(name: str):
            logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            return logging.getLogger(name)
log = get_logger(__name__)

# -------- Windows helpers (long path) --------
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

def _norm_abs(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p))

def _default_models_dir() -> Path:
    if _is_windows():
        base = os.environ.get("ProgramData") or os.environ.get("PUBLIC") or str(Path.home())
        return Path(base) / "RPS" / "AI_MODELS" / "enhanced"
    return Path.cwd() / "AI_MODELS" / "enhanced"

# -------- Imports with fallbacks --------
import numpy as np
import pandas as pd  # مذكور في الكود الأصلي؛ لا يُستخدم مباشرة ولكن لا نحذفه

# libmagic قد لا يتوافر بسهولة على ويندوز
try:
    import magic  # python-magic (يتطلب libmagic)
    _HAS_MAGIC = True
except Exception:
    import mimetypes
    _HAS_MAGIC = False

from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
import joblib

# TensorFlow بديل إلى MLPClassifier عند عدم توفره
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    _HAS_TF = True
except Exception:
    _HAS_TF = False
    keras = None
    layers = None

# XGBoost بديل إلى GradientBoostingClassifier عند عدم توفره
try:
    import xgboost as xgb
    _HAS_XGB = True
except Exception:
    _HAS_XGB = False
    xgb = None

# ===================== Feature Extractor =====================
class EnhancedFeatureExtractor:
    """مستخرج الميزات المحسن للملفات (Windows-safe I/O)."""

    def __init__(self):
        self.logger = log

    # --- Public ---
    def extract_file_features(self, file_path: str) -> Dict[str, Any]:
        """استخراج ميزات شاملة من الملف (يقرأ أول 8KB فقط)."""
        try:
            fp = _win_long_path(file_path)
            stat = os.stat(fp)
            features: Dict[str, Any] = {
                'file_size': stat.st_size,
                'file_size_log': math.log10(stat.st_size + 1),
                'creation_time': getattr(stat, "st_ctime", 0.0),
                'modification_time': getattr(stat, "st_mtime", 0.0),
                'access_time': getattr(stat, "st_atime", 0.0),
            }

            file_name = os.path.basename(fp)
            file_ext = os.path.splitext(file_name)[1].lower()

            features.update({
                'filename_length': len(file_name),
                'extension_length': len(file_ext),
                'has_extension': 1 if file_ext else 0,
                'extension_entropy': self._entropy_bytes(file_ext.encode() if file_ext else b""),
                'filename_entropy': self._entropy_bytes(file_name.encode()),
            })

            content = b""
            try:
                with open(fp, 'rb') as f:
                    content = f.read(8192)  # 8KB
            except Exception as e:
                self.logger.warning("Failed to read %s: %s", file_path, e)

            # محتوى
            features.update({
                'content_entropy': self._entropy_bytes(content),
                'null_byte_ratio': (content.count(b'\x00') / len(content)) if content else 0.0,
                'printable_ratio': (sum(1 for b in content if 32 <= b <= 126) / len(content)) if content else 0.0,
                'high_entropy_blocks': self._count_high_entropy_blocks(content),
                'repeated_patterns': self._detect_repeated_patterns(content),
            })

            # هيكل
            features.update(self._analyze_file_structure(fp, content))
            # تشفير
            features.update(self._detect_encryption_patterns(content))
            # امتدادات
            features.update(self._analyze_extension_patterns(fp))
            # مؤشرات فدية
            features.update(self._detect_ransomware_indicators(fp, content))

            return features
        except Exception as e:
            self.logger.error("خطأ في استخراج الميزات من %s: %s", file_path, e, exc_info=False)
            return self.get_default_features()

    # --- Helpers ---
    @staticmethod
    def _entropy_bytes(data: bytes) -> float:
        if not data:
            return 0.0
        counts = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        total = float(len(data))
        ent = 0.0
        for c in counts.values():
            p = c / total
            ent -= p * math.log2(p)
        return ent

    def _count_high_entropy_blocks(self, content: bytes, block_size: int = 256) -> int:
        if len(content) < block_size:
            return 0
        cnt = 0
        for i in range(0, len(content) - block_size + 1, block_size):
            if self._entropy_bytes(content[i:i + block_size]) > 7.0:
                cnt += 1
        return cnt

    def _detect_repeated_patterns(self, content: bytes) -> float:
        if len(content) < 16:
            return 0.0
        pattern_size = 4
        patterns: Dict[bytes, int] = {}
        for i in range(len(content) - pattern_size + 1):
            p = content[i:i + pattern_size]
            patterns[p] = patterns.get(p, 0) + 1
        return (sum(1 for v in patterns.values() if v > 1) / len(patterns)) if patterns else 0.0

    def _guess_mime_fallback(self, path: str, content: bytes) -> str:
        # بديل لـ libmagic على ويندوز
        if _HAS_MAGIC:
            try:
                return magic.from_buffer(content, mime=True) if content else "application/octet-stream"
            except Exception:
                pass
        # توقيعات بسيطة
        if content.startswith(b"MZ"):
            return "application/vnd.microsoft.portable-executable"
        if content.startswith(b"%PDF"):
            return "application/pdf"
        if content.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if content.startswith(b"\xFF\xD8\xFF"):
            return "image/jpeg"
        if content[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            return "application/zip"
        # mimetypes
        mtype, _ = mimetypes.guess_type(path)
        return mtype or "application/octet-stream"

    def _analyze_file_structure(self, file_path: str, content: bytes) -> Dict[str, Any]:
        try:
            mime = self._guess_mime_fallback(file_path, content)
            header = content[:16] if len(content) >= 16 else content
            footer = content[-16:] if len(content) >= 16 else content
            return {
                'file_type_known': 0 if mime in ("unknown", "application/octet-stream") else 1,
                'header_entropy': self._entropy_bytes(header),
                'header_null_ratio': (header.count(b'\x00') / len(header)) if header else 0.0,
                'footer_entropy': self._entropy_bytes(footer),
            }
        except Exception as e:
            self.logger.error("خطأ في تحليل الهيكل: %s", e)
            return {
                'file_type_known': 0,
                'header_entropy': 0.0,
                'header_null_ratio': 0.0,
                'footer_entropy': 0.0
            }

    def _detect_encryption_patterns(self, content: bytes) -> Dict[str, Any]:
        if not content:
            return {
                'encryption_likelihood': 0.0,
                'base64_patterns': 0.0,
                'hex_patterns': 0.0,
                'random_data_blocks': 0
            }
        base64_chars = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        hex_chars = set(b'0123456789ABCDEFabcdef')
        base64_ratio = sum(1 for b in content if b in base64_chars) / len(content)
        hex_ratio = sum(1 for b in content if b in hex_chars) / len(content)
        entropy = self._entropy_bytes(content)
        return {
            'encryption_likelihood': min(entropy / 8.0, 1.0),
            'base64_patterns': base64_ratio,
            'hex_patterns': hex_ratio,
            'random_data_blocks': 1 if entropy > 7.5 else 0
        }

    def _analyze_extension_patterns(self, file_path: str) -> Dict[str, Any]:
        file_name = os.path.basename(file_path)
        ext = os.path.splitext(file_name)[1].lower()
        suspicious_extensions = {
            '.locked', '.encrypted', '.crypto', '.crypt', '.enc', '.ransom',
            '.vault', '.secure', '.protected', '.coded', '.sealed'
        }
        ransomware_extensions = {
            '.wannacry', '.locky', '.cerber', '.cryptolocker', '.teslacrypt',
            '.cryptowall', '.reveton', '.petya', '.badrabbit', '.ryuk'
        }
        return {
            'suspicious_extension': 1 if ext in suspicious_extensions else 0,
            'ransomware_extension': 1 if ext in ransomware_extensions else 0,
            'double_extension': 1 if file_name.count('.') > 1 else 0,
            'long_extension': 1 if len(ext) > 5 else 0
        }

    def _detect_ransomware_indicators(self, file_path: str, content: bytes) -> Dict[str, Any]:
        name = os.path.basename(file_path).lower()
        ransom_keywords = [
            'decrypt', 'ransom', 'payment', 'bitcoin', 'crypto', 'locked',
            'encrypted', 'restore', 'recover', 'key', 'unlock', 'readme'
        ]
        kw_name = sum(1 for k in ransom_keywords if k in name)
        if content:
            s = content.decode('utf-8', errors='ignore').lower()
            kw_content = sum(1 for k in ransom_keywords if k in s)
            btc_hits = s.count('bc1') + s.count(' bitcoin ') + s.count('btc')
            ransom_phrases = [
                'your files have been encrypted', 'pay ransom', 'bitcoin payment',
                'decryption key', 'contact us for', 'time limit', 'all your files'
            ]
            phrase_count = sum(1 for p in ransom_phrases if p in s)
        else:
            kw_content = 0
            btc_hits = 0
            phrase_count = 0
        return {
            'ransom_keywords_in_name': kw_name,
            'ransom_keywords_in_content': kw_content,
            'bitcoin_addresses': min(btc_hits / 10.0, 1.0),
            'ransom_message_indicators': phrase_count
        }

    @staticmethod
    def get_default_features() -> Dict[str, Any]:
        return {
            'file_size': 0, 'file_size_log': 0, 'creation_time': 0,
            'modification_time': 0, 'access_time': 0, 'filename_length': 0,
            'extension_length': 0, 'has_extension': 0, 'extension_entropy': 0,
            'filename_entropy': 0, 'content_entropy': 0, 'null_byte_ratio': 0,
            'printable_ratio': 0, 'high_entropy_blocks': 0, 'repeated_patterns': 0,
            'file_type_known': 0, 'header_entropy': 0, 'header_null_ratio': 0,
            'footer_entropy': 0, 'encryption_likelihood': 0, 'base64_patterns': 0,
            'hex_patterns': 0, 'random_data_blocks': 0, 'suspicious_extension': 0,
            'ransomware_extension': 0, 'double_extension': 0, 'long_extension': 0,
            'ransom_keywords_in_name': 0, 'ransom_keywords_in_content': 0,
            'bitcoin_addresses': 0, 'ransom_message_indicators': 0
        }

# مفاتيح الميزات المستخدمة فعليًا في التدريب/التنبؤ للحفاظ على أبعاد ثابتة
FEATURES_USED: List[str] = [
    'file_size_log',
    'content_entropy',
    'null_byte_ratio',
    'printable_ratio',
    'high_entropy_blocks',
    'repeated_patterns',
    'encryption_likelihood',
    'suspicious_extension',
    'ransomware_extension',
    'ransom_keywords_in_name',
    'ransom_keywords_in_content',
    'bitcoin_addresses',
    'ransom_message_indicators',
]

def _vector_from_features(features: Dict[str, Any], keys: List[str]) -> np.ndarray:
    return np.array([float(features.get(k, 0.0)) for k in keys], dtype=float).reshape(1, -1)

# ===================== Model Manager =====================
class EnhancedAIModelManager:
    """مدير نماذج الذكاء الاصطناعي المحسن (Windows-safe)."""

    def __init__(self, models_dir: Optional[str] = None):
        base_dir = Path(models_dir) if models_dir else _default_models_dir()
        self.models_dir = base_dir
        self.feature_extractor = EnhancedFeatureExtractor()
        self.models: Dict[str, Any] = {}
        self.scalers: Dict[str, Any] = {}
        self.logger = log

        # إنشاء مجلد النماذج المحسنة
        self.enhanced_models_dir = self.models_dir
        self.enhanced_models_dir.mkdir(parents=True, exist_ok=True)

    # -------- Training orchestration --------
    def create_enhanced_models(self):
        self.logger.info("إنشاء نماذج ذكاء اصطناعي محسنة...")
        X_train, y_train = self.generate_training_data()
        self.train_enhanced_svm(X_train, y_train)
        self.train_enhanced_random_forest(X_train, y_train)
        self.train_enhanced_xgboost(X_train, y_train)
        self.train_enhanced_neural_network(X_train, y_train)
        self.train_anomaly_detector(X_train)
        self.logger.info("تم إنشاء جميع النماذج المحسنة بنجاح")

    def generate_training_data(self, n_samples: int = 10000):
        """بيانات محاكية تلتزم بترتيب FEATURES_USED."""
        self.logger.info("إنشاء بيانات تدريب محاكية...")
        rng = np.random.default_rng(42)

        normal_rows = []
        for _ in range(n_samples // 2):
            row = {
                'file_size_log': rng.normal(4, 2),
                'content_entropy': rng.normal(4, 1.5),
                'null_byte_ratio': rng.beta(2, 8),
                'printable_ratio': rng.beta(8, 2),
                'high_entropy_blocks': rng.poisson(1),
                'repeated_patterns': rng.beta(5, 5),
                'encryption_likelihood': rng.beta(1, 9),
                'suspicious_extension': 0,
                'ransomware_extension': 0,
                'ransom_keywords_in_name': 0,
                'ransom_keywords_in_content': rng.poisson(0.1),
                'bitcoin_addresses': 0,
                'ransom_message_indicators': 0
            }
            normal_rows.append([row[k] for k in FEATURES_USED])

        infected_rows = []
        for _ in range(n_samples // 2):
            row = {
                'file_size_log': rng.normal(3, 1),
                'content_entropy': rng.normal(7.5, 0.5),
                'null_byte_ratio': rng.beta(1, 9),
                'printable_ratio': rng.beta(1, 9),
                'high_entropy_blocks': rng.poisson(5),
                'repeated_patterns': rng.beta(1, 9),
                'encryption_likelihood': rng.beta(9, 1),
                'suspicious_extension': rng.choice([0, 1], p=[0.3, 0.7]),
                'ransomware_extension': rng.choice([0, 1], p=[0.8, 0.2]),
                'ransom_keywords_in_name': rng.poisson(2),
                'ransom_keywords_in_content': rng.poisson(5),
                'bitcoin_addresses': rng.beta(3, 7),
                'ransom_message_indicators': rng.poisson(3)
            }
            infected_rows.append([row[k] for k in FEATURES_USED])

        X = np.asarray(normal_rows + infected_rows, dtype=float)
        y = np.asarray([0] * (n_samples // 2) + [1] * (n_samples // 2), dtype=int)
        idx = rng.permutation(len(X))
        X, y = X[idx], y[idx]
        self.logger.info("تم إنشاء %d عينة تدريب", len(X))
        return X, y

    # -------- Individual trainers --------
    def train_enhanced_svm(self, X_train, y_train):
        try:
            self.logger.info("تدريب نموذج SVM محسن...")
            scaler = StandardScaler()
            Xs = scaler.fit_transform(X_train)
            model = SVC(kernel='rbf', probability=True, C=1.0, gamma='scale', random_state=42)
            model.fit(Xs, y_train)
            joblib.dump(model, self.enhanced_models_dir / "enhanced_svm.pkl")
            joblib.dump(scaler, self.enhanced_models_dir / "svm_scaler.pkl")
            self.models['enhanced_svm'] = model
            self.scalers['enhanced_svm'] = scaler
            self.logger.info("تم تدريب نموذج SVM المحسن بنجاح")
        except Exception as e:
            self.logger.error("خطأ في تدريب نموذج SVM: %s", e)

    def train_enhanced_random_forest(self, X_train, y_train):
        try:
            self.logger.info("تدريب نموذج Random Forest محسن...")
            model = RandomForestClassifier(
                n_estimators=200, max_depth=15, min_samples_split=5, min_samples_leaf=2,
                random_state=42, n_jobs=-1
            )
            model.fit(X_train, y_train)
            joblib.dump(model, self.enhanced_models_dir / "enhanced_random_forest.pkl")
            self.models['enhanced_random_forest'] = model
            self.logger.info("تم تدريب نموذج Random Forest المحسن بنجاح")
        except Exception as e:
            self.logger.error("خطأ في تدريب نموذج Random Forest: %s", e)

    def train_enhanced_xgboost(self, X_train, y_train):
        try:
            self.logger.info("تدريب نموذج XGBoost محسن...")
            if _HAS_XGB:
                model = xgb.XGBClassifier(
                    n_estimators=200, max_depth=8, learning_rate=0.1,
                    subsample=0.8, colsample_bytree=0.8, random_state=42, eval_metric='logloss'
                )
            else:
                # بديل متوافق مع نفس الهدف
                model = GradientBoostingClassifier(random_state=42)
            model.fit(X_train, y_train)
            joblib.dump(model, self.enhanced_models_dir / "enhanced_xgboost.pkl")
            self.models['enhanced_xgboost'] = model
            self.logger.info("تم تدريب نموذج XGBoost المحسن بنجاح" if _HAS_XGB else "تم تدريب بديل XGBoost (GradientBoosting)")
        except Exception as e:
            self.logger.error("خطأ في تدريب نموذج XGBoost: %s", e)

    def train_enhanced_neural_network(self, X_train, y_train):
        try:
            self.logger.info("تدريب الشبكة العصبية المحسنة...")
            scaler = StandardScaler()
            Xs = scaler.fit_transform(X_train)

            if _HAS_TF:
                model = keras.Sequential([
                    layers.Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
                    layers.Dropout(0.3),
                    layers.Dense(64, activation='relu'),
                    layers.Dropout(0.3),
                    layers.Dense(32, activation='relu'),
                    layers.Dropout(0.2),
                    layers.Dense(16, activation='relu'),
                    layers.Dense(1, activation='sigmoid')
                ])
                model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
                model.fit(Xs, y_train, epochs=50, batch_size=32, validation_split=0.2, verbose=0)
                model.save(self.enhanced_models_dir / "enhanced_neural_network.h5")
                self.models['enhanced_neural_network'] = model
            else:
                # بديل متوافق: MLPClassifier
                mlp = MLPClassifier(hidden_layer_sizes=(128, 64, 32, 16), activation='relu',
                                    solver='adam', random_state=42, max_iter=200)
                mlp.fit(Xs, y_train)
                joblib.dump(mlp, self.enhanced_models_dir / "enhanced_neural_network_sklearn.pkl")
                self.models['enhanced_neural_network'] = mlp

            joblib.dump(scaler, self.enhanced_models_dir / "nn_scaler.pkl")
            self.scalers['enhanced_neural_network'] = scaler
            self.logger.info("تم تدريب الشبكة العصبية المحسنة بنجاح" + ("" if _HAS_TF else " (بديل scikit-learn)"))
        except Exception as e:
            self.logger.error("خطأ في تدريب الشبكة العصبية: %s", e)

    def train_anomaly_detector(self, X_train):
        try:
            self.logger.info("تدريب كاشف الشذوذ (IsolationForest)...")
            model = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
            model.fit(X_train)
            joblib.dump(model, self.enhanced_models_dir / "anomaly_detector.pkl")
            self.models['anomaly_detector'] = model
            self.logger.info("تم تدريب كاشف الشذوذ بنجاح")
        except Exception as e:
            self.logger.error("خطأ في تدريب كاشف الشذوذ: %s", e)

    # -------- Load models --------
    def load_enhanced_models(self):
        try:
            self.logger.info("تحميل النماذج المحسنة...")
            p = self.enhanced_models_dir

            # SVM
            if (p / "enhanced_svm.pkl").exists():
                self.models['enhanced_svm'] = joblib.load(p / "enhanced_svm.pkl")
                self.scalers['enhanced_svm'] = joblib.load(p / "svm_scaler.pkl")
                self.logger.info("تم تحميل نموذج SVM المحسن")

            # Random Forest
            if (p / "enhanced_random_forest.pkl").exists():
                self.models['enhanced_random_forest'] = joblib.load(p / "enhanced_random_forest.pkl")
                self.logger.info("تم تحميل نموذج Random Forest المحسن")

            # XGBoost (أو بديله)
            if (p / "enhanced_xgboost.pkl").exists():
                self.models['enhanced_xgboost'] = joblib.load(p / "enhanced_xgboost.pkl")
                self.logger.info("تم تحميل نموذج XGBoost المحسن")

            # NN (TF أو بديله)
            if _HAS_TF and (p / "enhanced_neural_network.h5").exists():
                from tensorflow import keras as _k
                self.models['enhanced_neural_network'] = _k.models.load_model(p / "enhanced_neural_network.h5")
                self.logger.info("تم تحميل الشبكة العصبية (TensorFlow)")
            elif (p / "enhanced_neural_network_sklearn.pkl").exists():
                self.models['enhanced_neural_network'] = joblib.load(p / "enhanced_neural_network_sklearn.pkl")
                self.logger.info("تم تحميل الشبكة العصبية (بديل scikit-learn)")

            # NN scaler
            if (p / "nn_scaler.pkl").exists():
                self.scalers['enhanced_neural_network'] = joblib.load(p / "nn_scaler.pkl")

            # IsolationForest
            if (p / "anomaly_detector.pkl").exists():
                self.models['anomaly_detector'] = joblib.load(p / "anomaly_detector.pkl")
                self.logger.info("تم تحميل كاشف الشذوذ")

            if not self.models:
                self.create_enhanced_models()

            self.logger.info("تم تحميل %d نموذج محسن", len(self.models))
        except Exception as e:
            self.logger.error("خطأ في تحميل النماذج المحسنة: %s", e)
            self.create_enhanced_models()

    # -------- Predict --------
    def predict_with_enhanced_models(self, file_path: str) -> Optional[Dict[str, Any]]:
        try:
            feats = self.feature_extractor.extract_file_features(file_path)
            vec = _vector_from_features(feats, FEATURES_USED)

            predictions: Dict[str, Any] = {}

            for model_name, model in self.models.items():
                try:
                    if model_name == 'enhanced_svm':
                        scaler = self.scalers.get('enhanced_svm')
                        x = scaler.transform(vec) if scaler is not None else vec
                        prob = model.predict_proba(x)[0]
                        predictions[model_name] = {'probability': float(prob[1]), 'prediction': int(prob[1] > 0.5)}

                    elif model_name == 'enhanced_neural_network':
                        scaler = self.scalers.get('enhanced_neural_network')
                        x = scaler.transform(vec) if scaler is not None else vec
                        if _HAS_TF and hasattr(model, "predict"):
                            prob = float(model.predict(x, verbose=0)[0][0])
                        else:
                            # بديل scikit-learn
                            if hasattr(model, "predict_proba"):
                                prob = float(model.predict_proba(x)[0][1])
                            else:
                                # بعض إصدارات MLP لا تحفظ predict_proba إلا بعد fit؛ نحسب من decision_function إن وجدت
                                if hasattr(model, "decision_function"):
                                    d = float(model.decision_function(x)[0])
                                    prob = 1.0 / (1.0 + math.exp(-d))
                                else:
                                    prob = float(model.predict(x)[0])
                        predictions[model_name] = {'probability': prob, 'prediction': int(prob > 0.5)}

                    elif model_name == 'anomaly_detector':
                        score = float(model.decision_function(vec)[0])
                        is_anom = bool(model.predict(vec)[0] == -1)
                        predictions[model_name] = {'anomaly_score': score, 'is_anomaly': is_anom}

                    else:  # RF / XGB / GB
                        if hasattr(model, "predict_proba"):
                            prob = model.predict_proba(vec)[0]
                            predictions[model_name] = {'probability': float(prob[1]), 'prediction': int(prob[1] > 0.5)}
                        else:
                            # احتياط
                            pred = int(model.predict(vec)[0])
                            predictions[model_name] = {'probability': float(pred), 'prediction': pred}

                except Exception as e:
                    self.logger.error("خطأ في التنبؤ مع نموذج %s: %s", model_name, e)

            ensemble = self.calculate_ensemble_prediction(predictions)

            return {
                'individual_predictions': predictions,
                'ensemble_result': ensemble,
                'features_extracted': feats
            }
        except Exception as e:
            self.logger.error("خطأ في التنبؤ المحسن: %s", e)
            return None

    def calculate_ensemble_prediction(self, predictions: Dict[str, Any]) -> Dict[str, Any]:
        if not predictions:
            return {'probability': 0.0, 'prediction': 0, 'confidence': 0.0, 'anomaly_detected': False}

        probs: List[float] = [v['probability'] for v in predictions.values() if isinstance(v, dict) and 'probability' in v]
        anomaly_detected = bool(predictions.get('anomaly_detector', {}).get('is_anomaly', False))

        if probs:
            avg_prob = float(np.mean(probs))
            if anomaly_detected:
                avg_prob = max(avg_prob, 0.7)  # رفع احتمالية الخطر عند الشذوذ
            conf = float(1.0 - np.std(probs)) if len(probs) > 1 else 0.8
            return {'probability': avg_prob, 'prediction': int(avg_prob > 0.5), 'confidence': conf, 'anomaly_detected': anomaly_detected}

        return {'probability': 0.0, 'prediction': 0, 'confidence': 0.0, 'anomaly_detected': anomaly_detected}

# ===================== Main (smoke test) =====================
def main():
    logging.basicConfig(level=logging.INFO)
    mgr = EnhancedAIModelManager()  # مسار افتراضي آمن على ويندوز/لينكس
    mgr.create_enhanced_models()
    mgr.load_enhanced_models()
    log.info("تم تحميل %d نموذج محسن", len(mgr.models))

if __name__ == "__main__":
    main()

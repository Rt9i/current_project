# ransomware_protection_system/src/__init__.py
# -*- coding: utf-8 -*-
"""
Package bootstrap for ransomware_protection_system.src (Windows-ready)

- خفيف جدًا لتجنّب الاستيراد الدائري
- يدعم الاستيراد الكسول للوحدات الثقيلة عند الحاجة فقط
- يحافظ على __version__ لاستخدامه في الواجهات أو السجلات
- لا يغيّر أي أسماء أو واجهات عامة موجودة مسبقًا
"""

from __future__ import annotations

import importlib
from typing import List

__version__ = "2.0.0"

# لا نستورد وحدات ثقيلة هنا؛ نعلن أسماءها فقط لتمكين الاستيراد الكسول.
# أضفنا فقط وحدات تُستخدم فعليًا في المشروع (مثل logger / anomaly_detector / enhanced_ai_model)
# دون تغيير أسماء موجودة أو حذف أي شيء.
_LAZY_MODULES: List[str] = [
    # وحدات شائعة داخل المشروع — لن تُستورد الآن، بل عند أول وصول فقط
    "event_handler",
    "backup_manager",
    "file_monitor",
    "integrity_manager",
    "quarantine_manager",
    "google_drive_backup",
    "yara_scanner",
    "ml_detector",
    "database_handler",
    "ransomware_response",

    # إضافات مفيدة للاستيراد الكسول (لا تغيّر أسماء ولا واجهات):
    "logger",                 # بعض الوحدات تستخدم: from src.logger import get_logger
    "anomaly_detector",       # لتوافق الاستدعاءات من src.*
    "enhanced_ai_model",      # نفس الاسم كما في السورس
]

# نحافظ على الشفافية: لا نصدّر أي شيء افتراضيًا.
__all__: List[str] = []


def __getattr__(name: str):
    """
    Lazy import: عند محاولة الوصول إلى src.<module>، نقوم باستيراده عند الطلب فقط.
    هذا يمنع الاستيراد الدائري عند تشغيل التطبيق، ويبقي التوافق مع الاستيراد السابق.
    يعمل بسلاسة سواء تم تثبيت الحزمة كـ 'src' أو 'ransomware_protection_system.src'
    لأننا نستخدم __name__ ديناميكيًا.
    """
    if name in _LAZY_MODULES:
        mod = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = mod  # تخزين في الذاكرة لتسريع الوصول لاحقًا
        return mod
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def __dir__() -> List[str]:
    """
    تحسين تجربة الإكمال التلقائي: نظهر أسماء الـ lazy modules بالإضافة إلى الأسماء القياسية.
    """
    default = list(globals().keys())
    return sorted(set(default + _LAZY_MODULES))

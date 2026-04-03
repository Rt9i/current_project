# -*- coding: utf-8 -*-
"""
FileEventHandler (Fully Compatible Version - Windows-ready, All Features Preserved)
-----------------------------------------------------------------------------------
Production-grade event handling system with enhanced security features,
AI-driven threat detection, file monitoring, and backup integration.
Author: MiniMax Agent
Version: 4.0.4 (Fully Compatible with SecureBackupManager v2.4.1 + All Critical Fixes)
Created: 2025-12-16T16:30:00Z
Fully Compatible with: config.json v4.0.0 + SecureBackupManager v2.4.1
Critical Fixes Applied:
✅ FIXED: Removed invalid `relative_to` parameter (not supported by SecureBackupManager)
✅ FIXED: Ensured BackupOperationType enum consistency
✅ FIXED: Missing MIMEText import for email notifications
✅ FIXED: ThreadPoolExecutor shutdown without timeout (Python compatibility)
✅ FIXED: Safe EventType fallback for invalid event types
✅ Preserved all original features and logic
"""
from __future__ import annotations
import os
import time
import json
import sqlite3
import threading
import smtplib
import hashlib
import logging
import queue
import weakref
from pathlib import Path
from typing import Optional, Dict, Any, List, Union, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
from collections import Counter
from datetime import datetime
from enum import Enum
import requests
from email.mime.text import MIMEText  # ✅ FIXED: Added missing import
# Import BackupOperationType for type safety — must match SecureBackupManager
try:
    from backup_manager import BackupOperationType
except Exception:
    # Fallback definition if import fails (should not happen in real use)
    class BackupOperationType(Enum):
        CREATE = "create"
        MODIFY = "modify"
        DELETE = "delete"
        RENAME = "rename"
        EVENT_HOOK = "event_hook"
        VERSION = "version"
# Windows compatibility helpers
def _is_windows() -> bool:
    return os.name == "nt"
def _normcase(p: str) -> str:
    return os.path.normcase(p) if _is_windows() else p
# Project modules (robust imports: src.* or root)
try:
    from src.logger import get_logger
except Exception:
    try:
        import logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)
        def get_logger(name: str):
            return logger
    except Exception:
        print("⚠️ Using basic logger fallback")
        def get_logger(name: str):
            import logging
            return logging.getLogger(name)
log = get_logger(__name__)
try:
    from src.utils import (
        compute_sha256,
        normalize_path,
        now_iso,
        load_json, save_json, sizeof_fmt,
        save_json as utils_save_json, load_json as utils_load_json
    )
except Exception:
    def compute_sha256(file_path: str, chunk_size: int = 65536) -> str:
        """Compute SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return ""
    def normalize_path(path: str) -> str:
        """Normalize path"""
        return os.path.normpath(os.path.abspath(path))
    def now_iso() -> str:
        """Get current time in ISO format"""
        return datetime.now().isoformat()
    def load_json(file_path: str) -> Dict[str, Any]:
        """Load JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    def save_json(file_path: str, data: Dict[str, Any]) -> bool:
        """Save JSON file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False
    def sizeof_fmt(num: Union[int, float]) -> str:
        """Format size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if num < 1024.0:
                return f"{num:.1f} {unit}"
            num /= 1024.0
        return f"{num:.1f} PB"
# BackupManager integration - Compatible with SecureBackupManager v2.4.1
try:
    from src.backup_manager import SecureBackupManager as BackupManager
except Exception:
    try:
        from backup_manager import SecureBackupManager as BackupManager
    except Exception:
        print("⚠️ Using mock BackupManager")
        class BackupManager:
            def __init__(self, config_path: str):
                self.config_path = config_path
                self.config = {}
            def create_backup(self, file_path: str, **kwargs) -> Dict[str, Any]:
                return {"success": True, "backup_id": "mock_backup", "message": "Mock backup created"}
            def restore_backup(self, backup_id: str, restore_path: str) -> Dict[str, Any]:
                return {"success": True, "message": "Mock restore completed"}
            def verify_backup_integrity(self, backup_id: str) -> Dict[str, Any]:
                return {"success": True, "verified": True}
# QuarantineManager integration
try:
    from src.quarantine_manager import QuarantineManager
except Exception:
    try:
        from quarantine_manager import QuarantineManager
    except Exception:
        print("⚠️ Using mock QuarantineManager")
        class QuarantineManager:
            def quarantine_file(self, file_path: str, reason: str = "", do_stage: bool = True) -> Dict[str, Any]:
                return {"ok": True, "code": "mock_quarantine", "message": "Mock quarantine completed"}
            def restore_file(self, quarantine_id: str, restore_path: str) -> Dict[str, Any]:
                return {"ok": True, "message": "Mock restore completed"}
# YARA / ML integration (optional)
try:
    from src.yara_scanner import YaraScanner
except Exception:
    try:
        from yara_scanner import YaraScanner
    except Exception:
        print("⚠️ YaraScanner not available")
        class YaraScanner:
            def __init__(self, rules_dir: str):
                self.rules_dir = rules_dir
            def scan_file(self, file_path: str) -> Dict[str, Any]:
                return {"infected": False, "matches": []}
            def reload_if_changed(self):
                pass
try:
    from src.ml_detector import MLDetector
except Exception:
    try:
        from ml_detector import MLDetector
    except Exception:
        print("⚠️ MLDetector not available")
        class MLDetector:
            def __init__(self, **kwargs):
                self.enabled = kwargs.get("enabled", True)
                self.threshold = kwargs.get("threshold", 0.7)
                self.fast_threshold = kwargs.get("fast_threshold", 0.5)
            def predict_file(self, file_path: str, deep: bool = False, chunk_size: int = 65536) -> Dict[str, Any]:
                return {"prediction": 0.1, "score": 0.1, "infected": False}
            def deep_analyze(self, file_path: str, chunk_size: int = 65536) -> Dict[str, Any]:
                return {"ensemble_score": 0.1, "infected": False}
            def shutdown(self):
                pass
# Approx project root (for default paths)
BASE_DIR = Path(__file__).resolve().parents[1] if hasattr(Path(__file__).resolve(), 'parents') else Path.cwd()
# ---------------------------
# VT Cache (sqlite-backed) - Enhanced
# ---------------------------
class VtCache:
    def __init__(self, path: str, ttl_seconds: int = 24 * 3600):
        self.path = normalize_path(path)
        self.ttl = int(ttl_seconds)
        self._lock = threading.Lock()
        try:
            parent = Path(self.path).parent
            parent.mkdir(parents=True, exist_ok=True)
            if not self.path or self.path == ":":
                self.path = ":memory:"
        except Exception:
            self.path = ":memory:"
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._init_db()
    def _init_db(self):
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS vt_cache (
                    sha TEXT PRIMARY KEY,
                    result_json TEXT,
                    ts INTEGER
                )
            """)
            self._conn.commit()
    def get(self, sha: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT result_json, ts FROM vt_cache WHERE sha=?", (sha,))
            row = cur.fetchone()
            if not row:
                return None
            result_json, ts = row
            if (int(time.time()) - int(ts)) > self.ttl:
                try:
                    cur.execute("DELETE FROM vt_cache WHERE sha=?", (sha,))
                    self._conn.commit()
                except Exception:
                    pass
                return None
            try:
                return json.loads(result_json)
            except Exception:
                return None
    def set(self, sha: str, result: Dict[str, Any]):
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "REPLACE INTO vt_cache (sha, result_json, ts) VALUES (?, ?, ?)",
                (sha, json.dumps(result, ensure_ascii=False), int(time.time()))
            )
            self._conn.commit()
    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass
# ---------------------------
# Simple Rate Limiter (token-bucket-ish) - Enhanced
# ---------------------------
class SimpleRateLimiter:
    def __init__(self, max_calls: int, per_seconds: int):
        self.max_calls = max_calls
        self.per_seconds = per_seconds
        self._lock = threading.Lock()
        self._tokens = float(max_calls)
        self._last = time.time()
    def acquire(self, block: bool = True, timeout: Optional[float] = None) -> bool:
        deadline = None if timeout is None else time.time() + timeout
        while True:
            with self._lock:
                now = time.time()
                elapsed = now - self._last
                refill = (elapsed / self.per_seconds) * self.max_calls
                if refill >= 1.0:
                    self._tokens = min(self.max_calls, self._tokens + refill)
                    self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            if not block:
                return False
            if deadline and time.time() > deadline:
                return False
            time.sleep(0.05)
# ---------------------------
# Notifiers (Slack / Email / Webhook / custom) - Enhanced
# ---------------------------
class BaseNotifier:
    def send(self, alert: Dict[str, Any]):
        raise NotImplementedError
class SlackNotifier(BaseNotifier):
    def __init__(self, webhook_url: str, timeout: int = 5):
        self.url = webhook_url
        self.timeout = timeout
    def send(self, alert: Dict[str, Any]):
        try:
            payload = {"text": format_slack_markdown(alert)}
            requests.post(self.url, json=payload, timeout=self.timeout)
        except Exception as e:
            log.exception("SlackNotifier error: %s", e)
class EmailNotifier(BaseNotifier):
    def __init__(self, smtp_host: str, smtp_port: int, user: str, password: str, to_addr: str,
                 use_tls: bool = True, from_addr: Optional[str] = None, timeout: int = 10):
        self.smtp_host = smtp_host
        self.smtp_port = int(smtp_port)
        self.user = user
        self.password = password
        self.to_addr = to_addr
        self.use_tls = use_tls
        self.from_addr = from_addr or user
        self.timeout = timeout
    def send(self, alert: Dict[str, Any]):
        # ✅ FIXED: MIMEText is now imported
        try:
            html = format_email_html(alert)
            msg = MIMEText(html, "html", "utf-8")
            msg["Subject"] = f"Alert: {alert.get('type','alert')}"
            msg["From"] = self.from_addr
            msg["To"] = self.to_addr
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout) as s:
                if self.use_tls:
                    try:
                        s.starttls()
                    except Exception:
                        log.debug("SMTP starttls not supported / failed; continuing without TLS")
                if self.user and self.password:
                    try:
                        s.login(self.user, self.password)
                    except Exception:
                        log.exception("SMTP login failed")
                s.sendmail(self.from_addr, [self.to_addr], msg.as_string())
        except Exception:
            log.exception("EmailNotifier error")
class WebhookNotifier(BaseNotifier):
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 6):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout
    def send(self, alert: Dict[str, Any]):
        try:
            requests.post(self.url, headers=self.headers, json=alert, timeout=self.timeout)
        except Exception as e:
            log.exception("WebhookNotifier error: %s", e)
# ---------------------------
# Alert Rate Limiter - Enhanced
# ---------------------------
class AlertRateLimiter:
    def __init__(self, max_per_minute: int = 60):
        self.rate_limiter = SimpleRateLimiter(max_calls=max_per_minute, per_seconds=60)
    def allow(self) -> bool:
        return self.rate_limiter.acquire(block=False)
# ---------------------------
# Formatting helpers - Enhanced
# ---------------------------
def format_slack_markdown(alert: Dict[str, Any]) -> str:
    typ = alert.get("type", "alert").upper()
    file = alert.get("file", "n/a")
    score = alert.get("score")
    details = alert.get("details") or {}
    md = f"*{typ}* — `{file}`\n"
    if score is not None:
        md += f"> *score*: `{score}`\n"
    if details:
        try:
            details_to_dump = dict(details)
            if isinstance(details_to_dump.get("raw"), (dict, list)):
                details_to_dump["raw_summary"] = "<omitted - large raw JSON>"
                details_to_dump.pop("raw", None)
            md += "```json\n" + json.dumps(details_to_dump, ensure_ascii=False, indent=2) + "\n```\n"
        except Exception:
            md += "`(could not format details)`\n"
    md += f"_time: {now_iso()}_"
    return md
def format_email_html(alert: Dict[str, Any]) -> str:
    typ = alert.get("type", "alert").upper()
    file = alert.get("file", "n/a")
    score = alert.get("score")
    details = alert.get("details") or {}
    html = f"<h2>{typ} - {file}</h2>"
    if score is not None:
        html += f"<p><b>Score:</b> {score}</p>"
    if details:
        try:
            details_to_dump = dict(details)
            if isinstance(details_to_dump.get("raw"), (dict, list)):
                details_to_dump["raw_summary"] = "<omitted - large raw JSON>"
                details_to_dump.pop("raw", None)
            html += "<pre>{}</pre>".format(json.dumps(details_to_dump, ensure_ascii=False, indent=2))
        except Exception:
            html += "<p>Could not format details</p>"
    html += f"<p><small>Time: {now_iso()}</small></p>"
    return html
# ---------------------------
# Helper: file size safe - Enhanced
# ---------------------------
def get_file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except Exception:
        return 0
# ---------------------------
# Threat Zones Integration - FIXED: Use SUSPICIOUS only (no GRAY)
# ---------------------------
class ThreatZone(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    RED = "red"
class EventType(Enum):
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    RENAME = "rename"
    MOVE = "move"
# ✅ FIXED: Safe EventType → BackupOperationType Mapping using the imported enum
EVENT_TO_BACKUP_OP = {
    EventType.CREATE: BackupOperationType.CREATE,
    EventType.MODIFY: BackupOperationType.MODIFY,
    EventType.DELETE: BackupOperationType.DELETE,
    EventType.RENAME: BackupOperationType.RENAME,
}
class BackupEvent:
    def __init__(self, event_type: EventType, file_path: str, 
                 src_path: str = None, dest_path: str = None, 
                 is_directory: bool = False):
        self.event_type = event_type
        self.file_path = file_path
        self.src_path = src_path
        self.dest_path = dest_path
        self.is_directory = is_directory
        self.timestamp = datetime.now()
        self.event_id = f"{event_type.value}_{int(time.time() * 1000)}"
        self.status = "pending"
        self.threat_score = 0.0
        self.threat_zone = ThreatZone.SAFE
        self.backup_id = None
        self.error_message = None
        self.processing_time = 0.0
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "file_path": self.file_path,
            "src_path": self.src_path,
            "dest_path": self.dest_path,
            "is_directory": self.is_directory,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "threat_score": self.threat_score,
            "threat_zone": self.threat_zone.value,
            "backup_id": self.backup_id,
            "error_message": self.error_message,
            "processing_time": self.processing_time
        }
# ---------------------------
# FileEventHandler - Fully Compatible Version with All Critical Fixes
# ---------------------------
class FileEventHandler:
    def __init__(self,
                 backup_manager: BackupManager,
                 quarantine_manager: QuarantineManager,
                 config: Optional[Dict[str, Any]] = None,
                 notifiers: Optional[List[BaseNotifier]] = None):
        self.backup_manager = backup_manager
        self.quarantine_manager = quarantine_manager
        self.quarantine = quarantine_manager
        self.config = config or {}
        self.notifiers = notifiers or []
        self._load_compatible_config()
        # YARA
        yara_rules_dir = (self.config.get("yara", {}) or {}).get(
            "rules_dir", self.config.get("yara_rules_dir", "YARA_RULES")
        )
        self.yara = YaraScanner(yara_rules_dir)
        # ML
        ml_cfg = (self.config.get("ml") or {})
        ml_models_dir = ml_cfg.get("models_dir", (self.config.get("ai_models_dir") or "AI_MODELS"))
        ml_verbose = bool(ml_cfg.get("verbose", (self.config.get("ai_models", {}) or {}).get("verbose", False)))
        self.ml = MLDetector(
            models_dir=ml_models_dir,
            threshold=float(ml_cfg.get("threshold", 0.7)),
            fast_threshold=float(ml_cfg.get("fast_threshold", 0.5)),
            deep_enabled=bool(ml_cfg.get("deep_enabled", True)),
            max_fast_file_mb=int(ml_cfg.get("max_fast_file_mb", 200)),
            verbose=ml_verbose,
            enabled=bool(ml_cfg.get("enabled", True))
        )
        self.ai = self.ml
        # VirusTotal
        vt_cfg = self.config.get("virustotal", {}) or {}
        self.vt_api_key = vt_cfg.get("api_key", "") or self.config.get("virustotal_api_key", "")
        ttl_seconds = vt_cfg.get("cache_ttl_seconds")
        if ttl_seconds is None:
            ttl_seconds = int(vt_cfg.get("cache_ttl_hours", 24)) * 3600
        default_vt_cache_dir = getattr(self.backup_manager, "local_backup_dir", str(BASE_DIR / "database"))
        vt_cache_db = vt_cfg.get("cache_db", os.path.join(default_vt_cache_dir, "vt_cache.db"))
        self.vt_cache = VtCache(vt_cache_db, ttl_seconds=int(ttl_seconds))
        vt_rpm = vt_cfg.get("max_requests_per_minute", vt_cfg.get("rate_limit_per_minute", 4))
        self.vt_rate_limiter = SimpleRateLimiter(int(vt_rpm), 60)
        self._vt_retries = int(vt_cfg.get("retries", 2))
        self._vt_timeout_seconds = int(vt_cfg.get("timeout_seconds", 10))
        self._vt_retry_delay = float(vt_cfg.get("retry_delay_seconds", 1.0))
        # Executors
        max_scan_workers = int(self.config.get("executor", {}).get("max_workers", 4))
        self.scan_executor = ThreadPoolExecutor(max_workers=max_scan_workers)
        bp = self.config.get("bulk_processing", {}) or {}
        bulk_workers = int((self.config.get("executor", {}) or {}).get("bulk_workers", bp.get("bulk_workers", 4)))
        self.worker_executor = ThreadPoolExecutor(max_workers=bulk_workers)
        # Bulk queue
        self._bulk_queue: Queue = Queue()
        self._batch_size = int(bp.get("bulk_batch_size", self.config.get("bulk_batch_size", 50)))
        self._batch_timeout = float(bp.get("bulk_batch_timeout_seconds", self.config.get("bulk_batch_timeout_seconds", 1.0)))
        # Shutdown flag
        self._shutdown = threading.Event()
        self._bulk_thread = threading.Thread(target=self._bulk_worker_loop, daemon=True)
        self._bulk_thread.start()
        # Decision config
        det_cfg = self.config.get("detection", {}) or {}
        self.weights = det_cfg.get("weights", {"yara": 0.3, "ml": 0.5, "vt": 0.2})
        self.deep_weight = float(det_cfg.get("weights", {}).get("deep", 0.3))
        self.final_threshold = float(det_cfg.get("decision_commit_threshold", det_cfg.get("final_threshold", 0.5)))
        self.min_votes = int(det_cfg.get("min_votes_for_quarantine", 2))
        self.vote_mode = det_cfg.get("vote_mode", "weighted")
        # Threat zone thresholds from config v4.0.0 → map "gray_zone" to SUSPICIOUS
        self.threat_thresholds = det_cfg.get("thresholds", {})
        self.red_zone_threshold = self.threat_thresholds.get("red_zone", 0.8)
        self.gray_zone_threshold = self.threat_thresholds.get("gray_zone", 0.4)
        # Telemetry
        self.telemetry_lock = threading.RLock()
        self.telemetry = {
            "total_events": 0,
            "fast_stage_times_ms": [],
            "deep_stage_times_ms": [],
            "vt_times_ms": [],
            "quarantined": 0,
            "backed_up": 0,
            "total_bytes": 0,
            "max_file_size": 0,
            "per_extension": Counter(),
            "per_directory": Counter(),
        }
        tel_cfg = self.config.get("telemetry", {}) or {}
        self._telemetry_max_samples = int(tel_cfg.get("max_samples", 2000))
        self._telemetry_flush_every = int(tel_cfg.get("flush_every_n_events", 100))
        self._telemetry_file = tel_cfg.get("stats_file")
        # Alerts
        alert_cfg = self.config.get("alerts", {}) or {}
        self.alert_rate_limiter = AlertRateLimiter(int(alert_cfg.get("max_per_minute", 60)))
        self._notifiers = list(self.notifiers)
        # Build notifiers from config
        try:
            scfg = alert_cfg.get("slack", {}) or {}
            if scfg.get("enabled") and scfg.get("webhook_url"):
                self._notifiers.append(SlackNotifier(scfg["webhook_url"], timeout=int(scfg.get("timeout", 5))))
            ecfg = alert_cfg.get("email", {}) or {}
            if ecfg.get("enabled") and (ecfg.get("smtp_host") or ecfg.get("smtp_server")) and (ecfg.get("to") or ecfg.get("recipient")):
                smtp_host = ecfg.get("smtp_host", ecfg.get("smtp_server"))
                to_addr = ecfg.get("to", ecfg.get("recipient"))
                user = ecfg.get("user", ecfg.get("username", ""))
                password = ecfg.get("password", "")
                self._notifiers.append(EmailNotifier(
                    smtp_host=smtp_host,
                    smtp_port=int(ecfg.get("smtp_port", 587)),
                    user=user,
                    password=password,
                    to_addr=to_addr,
                    use_tls=bool(ecfg.get("use_tls", True)),
                    from_addr=ecfg.get("from_addr"),
                    timeout=int(ecfg.get("timeout", 10))
                ))
            wcfg = alert_cfg.get("webhook", {}) or {}
            if wcfg.get("enabled") and wcfg.get("url"):
                self._notifiers.append(WebhookNotifier(
                    url=wcfg["url"],
                    headers=wcfg.get("headers"),
                    timeout=int(wcfg.get("timeout", 6))
                ))
        except Exception:
            log.exception("Failed to build notifiers from config")
        self.chunk_size = int(self.config.get("file_read_chunk", 65536))
        # Event integration config v4.0.0
        self.event_integration = self.config.get("event_integration", {})
        self.backup_before_delete = self.event_integration.get("backup_before_delete", True)
        self.backup_before_rename = self.event_integration.get("backup_before_rename", True)
        self.backup_before_modify = self.event_integration.get("backup_before_modify", False)
        self.rollback_on_failure = self.event_integration.get("rollback_on_failure", True)
        self.version_on_modify = self.event_integration.get("version_on_modify", True)
        log.info("FileEventHandler initialized (scan_workers=%s, bulk_workers=%s)", max_scan_workers, bulk_workers)
    def _load_compatible_config(self):
        """Load and validate compatible config structure"""
        required_sections = ["monitoring", "detection", "event_integration", "performance", "backup", "notifications"]
        for sec in required_sections:
            if sec not in self.config:
                self.config[sec] = {}
        monitoring = self.config["monitoring"]
        if not monitoring.get("paths_to_monitor"):
            monitoring["paths_to_monitor"] = []
    # Synchronous interface
    def handle_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        return self._process_event(event)
    def create_backup_event(self, event_data: Dict[str, Any]) -> BackupEvent:
        file_path = event_data.get("file_path") or event_data.get("file") or event_data.get("path")
        event_type_str = event_data.get("event_type", "create")
        try:
            event_type = EventType(event_type_str)
        except ValueError:
            # ✅ FIXED: Safe fallback for invalid event types
            log.warning(f"Unknown event type '{event_type_str}', defaulting to CREATE")
            event_type = EventType.CREATE
        backup_event = BackupEvent(
            event_type=event_type,
            file_path=file_path,
            src_path=event_data.get("src_path"),
            dest_path=event_data.get("dest_path"),
            is_directory=event_data.get("is_directory", False)
        )
        if "threat_score" in event_data:
            backup_event.threat_score = event_data["threat_score"]
            backup_event.threat_zone = self._get_threat_zone(backup_event.threat_score)
        return backup_event
    def _get_threat_zone(self, threat_score: float) -> ThreatZone:
        """Get threat zone based on score — map gray_zone to SUSPICIOUS"""
        if threat_score >= self.red_zone_threshold:
            return ThreatZone.RED
        elif threat_score >= self.gray_zone_threshold:
            return ThreatZone.SUSPICIOUS
        else:
            return ThreatZone.SAFE
    # ---------------------------
    # Backup helpers - ✅ FIXED: removed invalid relative_to
    # ---------------------------
    def _pick_relative_root(self, fpath: str) -> Optional[str]:
        try:
            mon = self.config.get("monitoring", {}) or {}
            # ✅ Use "paths_to_monitor" from config v4.0.0
            roots = mon.get("paths_to_monitor") or []
            f_abs = _normcase(os.path.abspath(fpath))
            candidates = []
            for r in roots:
                try:
                    r_abs = _normcase(os.path.abspath(r))
                    if f_abs.startswith(r_abs + os.sep) or f_abs == r_abs:
                        candidates.append(r_abs)
                except Exception:
                    continue
            if not candidates:
                return None
            return max(candidates, key=len)
        except Exception:
            return None
    def _backup_with_relative(self, fpath: str, threat_score: float = 0.1, operation_type_str: str = "create"):
        """Perform backup — SecureBackupManager handles paths_to_monitor internally."""
        try:
            if not getattr(self, "backup_manager", None):
                return None
            # Do NOT pass rel_root — SecureBackupManager.create_backup() does not accept it
            # rel_root = self._pick_relative_root(fpath)  # ❌ Not used
            # ✅ FIXED: Safe enum mapping with fallback
            try:
                event_type = EventType(operation_type_str)
            except ValueError:
                log.warning(f"Invalid event type '{operation_type_str}', using CREATE")
                event_type = EventType.CREATE
            op_enum = EVENT_TO_BACKUP_OP.get(event_type, BackupOperationType.CREATE)
            # ✅ FIXED: Removed relative_to — it's not supported
            return self.backup_manager.create_backup(
                fpath,
                threat_score=threat_score,
                operation_type=op_enum,  # Ensure it's the same enum
                enable_versioning=True
                # relative_to=rel_root  # ❌ REMOVED
            )
        except Exception:
            log.exception("backup_with_relative failed for %s", fpath)
            return None
    # ---------------------------
    # Bulk worker - Enhanced
    # ---------------------------
    def _bulk_worker_loop(self):
        while not self._shutdown.is_set():
            batch = []
            start = time.time()
            try:
                evt = self._bulk_queue.get(timeout=self._batch_timeout)
                batch.append(evt)
            except Empty:
                continue
            while len(batch) < self._batch_size and (time.time() - start) < self._batch_timeout:
                try:
                    evt = self._bulk_queue.get_nowait()
                    batch.append(evt)
                except Empty:
                    time.sleep(0.01)
                    continue
            if not batch:
                continue
            futures = {self.worker_executor.submit(self._process_event, evt): evt for evt in batch}
            results = []
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                except Exception:
                    log.exception("Error processing event in batch")
                    res = None
                results.append(res)
            try:
                dir_quarantine_counts = Counter()
                for r in results:
                    if not r:
                        continue
                    action = (r.get("decision") or {}).get("action")
                    fp = r.get("file")
                    if action == "quarantine" and fp:
                        dir_quarantine_counts[os.path.dirname(fp)] += 1
                bp = self.config.get("bulk_processing", {}) or {}
                bulk_threshold = int(bp.get("bulk_suspicious_threshold", self.config.get("bulk_suspicious_threshold", 10)))
                for d, cnt in dir_quarantine_counts.items():
                    if cnt >= bulk_threshold:
                        alert = {
                            "type": "bulk_suspected_ransomware",
                            "directory": d,
                            "count": cnt,
                            "details": {"files_affected": cnt},
                        }
                        self._send_alert(alert)
            except Exception:
                log.exception("Post-batch analysis failed")
            for _ in batch:
                try:
                    self._bulk_queue.task_done()
                except Exception:
                    pass
    def submit_event(self, event: Dict[str, Any]):
        if self._shutdown.is_set():
            log.debug("Handler shutting down; rejecting new event")
            return
        self._bulk_queue.put(event)
    # ---------------------------
    # Core event processing - Enhanced for v4.0.0 compatibility
    # ---------------------------
    def _process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        start_total = time.perf_counter()
        file_path = event.get("file_path") or event.get("file") or event.get("path")
        result: Dict[str, Any] = {"file": file_path, "timestamp": now_iso(), "stages": {}, "decision": None}
        if not file_path:
            result["error"] = "no_path"
            return result
        p = Path(file_path)
        if not p.exists():
            result["error"] = "not_found"
            return result
        backup_event = self.create_backup_event(event)
        size = get_file_size(file_path)
        ext = p.suffix.lower() or "<noext>"
        dname = str(p.parent)
        with self.telemetry_lock:
            self.telemetry["total_events"] += 1
            self.telemetry["total_bytes"] += size
            if size > self.telemetry["max_file_size"]:
                self.telemetry["max_file_size"] = size
            self.telemetry["per_extension"][ext] += 1
            self.telemetry["per_directory"][dname] += 1
        sha = compute_sha256(file_path, chunk_size=self.chunk_size)
        result["sha256"] = sha
        if not sha:
            result["error"] = "unreadable"
            return result
        yara_in = event.get("yara")
        ml_in = event.get("ml")
        anomaly_in = event.get("anomaly")
        try:
            futs = {}
            if yara_in is None:
                futs["yara"] = self.scan_executor.submit(self.scan_with_yara, file_path)
            if ml_in is None:
                futs["ml"] = self.scan_executor.submit(self.scan_with_ml, file_path)
            fut_vt = self.scan_executor.submit(self.scan_with_virustotal, file_path, sha)
            yara_res = yara_in if yara_in is not None else futs["yara"].result()
            ml_res = ml_in if ml_in is not None else futs["ml"].result()
            vt_res = fut_vt.result()
            result["stages"]["fast"] = {"yara": yara_res, "ml": ml_res, "virustotal": vt_res}
            if anomaly_in is not None:
                result["stages"]["anomaly"] = anomaly_in
            vt_latency = vt_res.get("latency_ms")
            if vt_latency is not None:
                with self.telemetry_lock:
                    self.telemetry["vt_times_ms"].append(vt_latency)
                    self._cap_list(self.telemetry["vt_times_ms"])
            score, infected = self._decide_from_stage(yara_res, ml_res, vt_res)
            result["decision_score"] = score
            result["fast_infected"] = infected
            backup_event.threat_score = score
            backup_event.threat_zone = self._get_threat_zone(score)
            # ✅ FIXED: Make ThreatZone drive actual decision logic
            if backup_event.threat_zone == ThreatZone.RED:
                infected = True
            escalate = False
            fast_stage_cfg = (self.config.get("fast_stage") or {})
            require_escalation_flag = bool(fast_stage_cfg.get("require_escalation_if_any_flag", True))
            fast_ml_threshold = float(
                fast_stage_cfg.get(
                    "fast_ml_threshold",
                    (self.config.get("ml", {}) or {}).get("fast_threshold", 0.5)
                )
            )
            if require_escalation_flag and (bool(yara_res.get("infected")) or bool(vt_res.get("infected"))):
                escalate = True
            elif float(ml_res.get("prediction", ml_res.get("score", 0.0)) or 0.0) >= fast_ml_threshold:
                escalate = True
            if event.get("meta", {}).get("integrity_changed", False):
                escalate = True
            if anomaly_in and anomaly_in.get("anomalous"):
                escalate = True
            deep_enabled_global = bool((self.config.get("deep_stage", {}) or {}).get(
                "enabled",
                (self.config.get("ml", {}) or {}).get("deep_enabled", True)
            ))
            if escalate and deep_enabled_global:
                t0 = time.perf_counter()
                deep_res = self.run_deep_stage(file_path)
                t1 = time.perf_counter()
                with self.telemetry_lock:
                    self.telemetry["deep_stage_times_ms"].append((t1 - t0) * 1000.0)
                    self._cap_list(self.telemetry["deep_stage_times_ms"])
                result["stages"]["deep"] = deep_res
                if self.vote_mode != "count":
                    deep_score = float(deep_res.get("ensemble_score", deep_res.get("score", 0.0)) or 0.0)
                    score = (score * (1.0 - self.deep_weight)) + (deep_score * self.deep_weight)
                    result["decision_score"] = score
                    backup_event.threat_score = score
                    backup_event.threat_zone = self._get_threat_zone(score)
                    if backup_event.threat_zone == ThreatZone.RED:
                        infected = True
            if infected:
                qm = getattr(self, "quarantine", None) or self.quarantine_manager
                qres = qm.quarantine_file(file_path, reason="engine_decision", do_stage=True)
                if not qres.get("ok") and qres.get("code") in {"not_suspicious"}:
                    try:
                        qres = qm.quarantine_file(file_path, reason="engine_decision_forced", do_stage=False)
                    except Exception:
                        log.exception("Forced quarantine attempt failed")
                result["decision"] = {"action": "quarantine", "result": qres}
                with self.telemetry_lock:
                    self.telemetry["quarantined"] += 1
                log.warning("[DECISION] quarantine %s score=%.3f", file_path, float(score))
                alert = {"type": "quarantine", "file": file_path, "score": score, "details": result}
                try:
                    alert.setdefault("details", {}).setdefault("meta", {})
                    alert["details"]["meta"].update({"size": size, "ext": ext})
                except Exception:
                    pass
                self._send_alert(alert)
            else:
                backup_action = self._handle_safe_file_backup(backup_event, file_path, score)
                result["decision"] = backup_action
                with self.telemetry_lock:
                    self.telemetry["backed_up"] += 1
                log.info("[DECISION] backup %s score=%.3f", file_path, float(score))
            t_end = time.perf_counter()
            with self.telemetry_lock:
                self.telemetry["fast_stage_times_ms"].append((t_end - start_total) * 1000.0)
                self._cap_list(self.telemetry["fast_stage_times_ms"])
            result["processing_time_ms"] = (t_end - start_total) * 1000.0
            backup_event.status = "completed" if result.get("decision") else "failed"
            backup_event.processing_time = result["processing_time_ms"]
            self._maybe_flush_telemetry_file()
            return result
        except Exception as e:
            log.exception("Error in _process_event for %s: %s", file_path, e)
            result["error"] = str(e)
            backup_event.status = "failed"
            backup_event.error_message = str(e)
            return result
    def _handle_safe_file_backup(self, backup_event: BackupEvent, file_path: str, threat_score: float) -> Dict[str, Any]:
        should_backup = True
        if backup_event.event_type == EventType.DELETE and not self.backup_before_delete:
            should_backup = False
        elif backup_event.event_type == EventType.RENAME and not self.backup_before_rename:
            should_backup = False
        elif backup_event.event_type == EventType.MODIFY and not self.backup_before_modify:
            should_backup = False
        if not should_backup:
            return {"action": "skip", "result": {"message": "Backup skipped based on config"}}
        try:
            bres = self._backup_with_relative(
                file_path,
                threat_score=threat_score,
                operation_type_str=backup_event.event_type.value
            )
            if bres and bres.get("success"):
                backup_event.backup_id = bres.get("backup_id")
                return {"action": "backup", "result": bres}
            else:
                return {"action": "backup_failed", "result": bres or {"error": "Backup failed"}}
        except Exception as e:
            log.exception("Backup failed for %s: %s", file_path, e)
            return {"action": "backup_failed", "result": {"error": str(e)}}
    def _decide_from_stage(self, yara_res: Dict[str, Any], ml_res: Dict[str, Any], vt_res: Dict[str, Any]):
        yara_flag = bool(yara_res.get("infected"))
        ml_score = float(ml_res.get("prediction", ml_res.get("score", 0.0)) or 0.0)
        vt_flag = bool(vt_res.get("infected"))
        if self.vote_mode == "count":
            votes = sum([1 if yara_flag else 0, 1 if ml_score >= self.final_threshold else 0, 1 if vt_flag else 0])
            return votes / 3.0, votes >= self.min_votes
        else:
            score = (self.weights.get("yara", 0.0) * (1.0 if yara_flag else 0.0) +
                     self.weights.get("ml", 0.0) * ml_score +
                     self.weights.get("vt", 0.0) * (1.0 if vt_flag else 0.0))
            return score, score >= self.final_threshold
    def scan_with_yara(self, file_path: str) -> Dict[str, Any]:
        try:
            try:
                if hasattr(self.yara, "reload_if_changed"):
                    self.yara.reload_if_changed()
            except Exception:
                pass
            t0 = time.perf_counter()
            res = self.yara.scan_file(file_path)
            t1 = time.perf_counter()
            log.debug("[YARA] %s took %.2fms infected=%s", file_path, (t1 - t0) * 1000.0, res.get("infected"))
            return res
        except Exception:
            log.exception("YARA scan failed for %s", file_path)
            return {"infected": False, "error": "yara_failed"}
    def scan_with_ml(self, file_path: str) -> Dict[str, Any]:
        try:
            t0 = time.perf_counter()
            res = self.ml.predict_file(file_path, deep=False, chunk_size=self.chunk_size)
            t1 = time.perf_counter()
            log.debug("[ML] %s took %.2fms pred=%s", file_path, (t1 - t0) * 1000.0, res.get("prediction"))
            return res
        except Exception:
            log.exception("ML scan failed for %s", file_path)
            return {"infected": False, "error": "ml_failed"}
    def scan_with_virustotal(self, file_path: str, sha: str) -> Dict[str, Any]:
        t0 = time.perf_counter()
        try:
            cached = self.vt_cache.get(sha)
            if cached:
                return {**cached, "cached": True, "latency_ms": 0}
        except Exception:
            log.exception("VT cache get failed")
        if not self.vt_api_key:
            return {"infected": False, "reason": "no_api_key", "sha256": sha, "latency_ms": 0}
        url = f"https://www.virustotal.com/api/v3/files/{sha}"
        headers = {"x-apikey": self.vt_api_key}
        if not self.vt_rate_limiter.acquire(block=True, timeout=5):
            return {"infected": False, "reason": "vt_rate_limited", "sha256": sha, "latency_ms": 0}
        resp = None
        retries = self._vt_retries
        timeout_seconds = self._vt_timeout_seconds
        retry_delay = self._vt_retry_delay
        for attempt in range(1, retries + 2):
            try:
                resp = requests.get(url, headers=headers, timeout=timeout_seconds)
                if resp.status_code == 200:
                    break
                if resp.status_code == 404:
                    latency_ms = (time.perf_counter() - t0) * 1000.0
                    return {"infected": False, "reason": "vt_not_found", "sha256": sha, "cached": False, "latency_ms": latency_ms}
                log.debug("VT non-200 status %s attempt=%s", resp.status_code, attempt)
            except requests.RequestException as e:
                log.debug("VT request exception attempt=%s %s", attempt, e)
            time.sleep(retry_delay)
        if not resp:
            return {"infected": False, "reason": "vt_unreachable", "sha256": sha, "latency_ms": 0}
        try:
            data = resp.json()
        except Exception:
            log.exception("VT returned invalid JSON for %s", sha)
            return {"infected": False, "reason": "invalid_json", "sha256": sha, "latency_ms": 0}
        attrs = data.get("data", {}).get("attributes", {}) if isinstance(data, dict) else {}
        stats = attrs.get("last_analysis_stats", {}) if attrs else {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        infected = (malicious > 0 or suspicious > 0)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        res = {
            "infected": infected,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "sha256": sha,
            "cached": False,
            "raw": data,
            "latency_ms": latency_ms
        }
        try:
            self.vt_cache.set(sha, res)
        except Exception:
            log.exception("Failed to write vt_cache for %s", sha)
        return res
    def run_deep_stage(self, file_path: str) -> Dict[str, Any]:
        try:
            if hasattr(self.ml, "deep_analyze"):
                return self.ml.deep_analyze(file_path, chunk_size=self.chunk_size)
            else:
                return self.ml.predict_file(file_path, deep=True, chunk_size=self.chunk_size)
        except Exception:
            log.exception("Deep analysis failed for %s", file_path)
            return {"error": "deep_failed"}
    def _send_alert(self, alert: Dict[str, Any]):
        if not self.alert_rate_limiter.allow():
            log.debug("Alert throttled: %s", alert.get("type"))
            return
        for notifier in self._notifiers:
            try:
                threading.Thread(target=self._safe_send_notifier, args=(notifier, alert), daemon=True).start()
            except Exception:
                log.exception("Failed to spawn notifier thread")
    def _safe_send_notifier(self, notifier: BaseNotifier, alert: Dict[str, Any]):
        try:
            notifier.send(alert)
        except Exception:
            log.exception("Notifier.send raised exception")
    def _cap_list(self, lst: list):
        if len(lst) > self._telemetry_max_samples:
            del lst[: len(lst) - self._telemetry_max_samples]
    def _maybe_flush_telemetry_file(self):
        if not self._telemetry_file:
            return
        try:
            total = self.telemetry.get("total_events", 0)
            if total % max(1, self._telemetry_flush_every) != 0:
                return
            snap = self.get_telemetry()
            path = Path(self._telemetry_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"updated_at": now_iso(), **snap}, f, ensure_ascii=False, indent=2)
        except Exception:
            log.exception("telemetry flush failed")
    def get_telemetry(self) -> Dict[str, Any]:
        with self.telemetry_lock:
            tel = dict(self.telemetry)
            tel_out = {
                "total_events": tel.get("total_events", 0),
                "avg_fast_ms": (sum(tel.get("fast_stage_times_ms", [])) / max(1, len(tel.get("fast_stage_times_ms", [])))) if tel.get("fast_stage_times_ms") else 0.0,
                "avg_deep_ms": (sum(tel.get("deep_stage_times_ms", [])) / max(1, len(tel.get("deep_stage_times_ms", [])))) if tel.get("deep_stage_times_ms") else 0.0,
                "avg_vt_ms": (sum(tel.get("vt_times_ms", [])) / max(1, len(tel.get("vt_times_ms", [])))) if tel.get("vt_times_ms") else 0.0,
                "quarantined": tel.get("quarantined", 0),
                "backed_up": tel.get("backed_up", 0),
                "total_bytes": tel.get("total_bytes", 0),
                "avg_file_size": (tel.get("total_bytes", 0) // max(1, tel.get("total_events", 1))),
                "max_file_size": tel.get("max_file_size", 0),
                "per_extension": dict(tel.get("per_extension", {})),
                "per_directory_top": tel.get("per_directory", {}).most_common(10) if isinstance(tel.get("per_directory"), Counter) else {},
            }
            return tel_out
    def _safe_chmod(self, path: str, mode: int) -> bool:
        try:
            os.chmod(path, mode)
            return True
        except Exception:
            log.debug("chmod operation failed on %s (likely Windows permission restriction)", path)
            return False
    def shutdown(self, wait_seconds: float = 10.0):
        log.info("Shutting down FileEventHandler, waiting up to %.1fs", wait_seconds)
        self._shutdown.set()
        try:
            if self._bulk_thread.is_alive():
                self._bulk_thread.join(timeout=1.0)
        except Exception:
            pass
        # ✅ FIXED: Remove timeout from ThreadPoolExecutor shutdown (not supported in Python standard)
        try:
            self.worker_executor.shutdown(wait=True)
        except Exception:
            log.exception("worker_executor shutdown issue")
        try:
            self.scan_executor.shutdown(wait=True)
        except Exception:
            log.exception("scan_executor shutdown issue")
        try:
            self.vt_cache.close()
        except Exception:
            log.exception("vt_cache close failed")
        try:
            if hasattr(self.ml, "shutdown"):
                self.ml.shutdown()
        except Exception:
            log.exception("ml.shutdown failed")
        log.info("FileEventHandler shutdown complete")
    def process_file_event(self, event_type: str, file_path: str, **kwargs) -> Dict[str, Any]:
        event_data = {
            "event_type": event_type,
            "file_path": file_path,
            **kwargs
        }
        return self._process_event(event_data)
    def get_compatible_config_summary(self) -> Dict[str, Any]:
        return {
            "backup_integration": {
                "backup_before_delete": self.backup_before_delete,
                "backup_before_rename": self.backup_before_rename,
                "backup_before_modify": self.backup_before_modify,
                "version_on_modify": self.version_on_modify,
                "rollback_on_failure": self.rollback_on_failure
            },
            "threat_thresholds": {
                "red_zone": self.red_zone_threshold,
                "gray_zone": self.gray_zone_threshold
            },
            "detection": {
                "final_threshold": self.final_threshold,
                "vote_mode": self.vote_mode,
                "weights": self.weights
            },
            "monitoring": {
                "paths_to_monitor": self.config.get("monitoring", {}).get("paths_to_monitor", []),
                "recursive_monitoring": self.config.get("monitoring", {}).get("recursive_monitoring", True)
            }
        }
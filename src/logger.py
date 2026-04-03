# src/logger.py
# -*- coding: utf-8 -*-
"""
Central logging helper for Enhanced Ransomware Protection System (Windows-ready).
Usage:
    from src.logger import get_logger
    log = get_logger(__name__)
    log.info("hello")
"""

import logging
import os
import sys
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# -------------------------
# Platform helpers
# -------------------------
def _is_windows() -> bool:
    return os.name == "nt"

def _norm_abs(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p))

def _win_long_path(p: str) -> str:
    """Support long paths on Windows when needed, noop elsewhere."""
    if not _is_windows():
        return p
    ap = os.path.abspath(p)
    if ap.startswith("\\\\?\\") or len(ap) < 248:
        return ap
    if ap.startswith("\\\\"):  # UNC
        return "\\\\?\\UNC\\" + ap[2:]
    return "\\\\?\\" + ap

# -------------------------
# Defaults & env
# -------------------------
def _default_logfile() -> str:
    """Choose a writable default log path per platform."""
    env_override = os.environ.get("LOG_FILE")
    if env_override:
        return _norm_abs(env_override)

    try:
        if _is_windows():
            base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
            return str(Path(base) / "RPS" / "logs" / "enhanced_system.log")
        else:
            # still works cross-platform if needed
            return str(Path.home() / ".cache" / "rps" / "logs" / "enhanced_system.log")
    except Exception:
        # last resort: CWD
        return str(Path.cwd() / "enhanced_system.log")

DEFAULT_LOGFILE = _default_logfile()

def _ensure_log_dir(path: str) -> None:
    """Ensure that the log directory exists (best-effort)."""
    try:
        d = os.path.dirname(path)
        if d:
            Path(d).mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

def _get_log_level() -> int:
    """Resolve log level from environment (LOG_LEVEL) or fallback to INFO."""
    env_level = (os.environ.get("LOG_LEVEL") or "").upper().strip()
    levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    return levels.get(env_level, logging.INFO)

# -------------------------
# Public API
# -------------------------
def get_logger(name: Optional[str] = None,
               logfile: Optional[str] = None,
               level: Optional[int] = None) -> logging.Logger:
    """
    Return a configured logger (console + rotating file).
    - Prevents duplicate handlers.
    - Windows-safe (delay=True for file handler, long-path support, writable defaults).
    - Honors LOG_LEVEL and LOG_FILE env vars.
    """
    logger = logging.getLogger(name)
    lvl = level or _get_log_level()
    logger.setLevel(lvl)

    # If already configured, just return it
    if logger.handlers:
        return logger

    # Rich formatter
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | "
        "%(process)d:%(thread)d | %(filename)s:%(lineno)d | %(message)s"
    )

    # Console handler
    ch = logging.StreamHandler(stream=sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler (rotating)
    target = _norm_abs(logfile or DEFAULT_LOGFILE)
    _ensure_log_dir(target)

    fh = None
    try:
        # delay=True opens file lazily on first emit, reducing Windows lock errors
        path_for_open = _win_long_path(target)
        fh = RotatingFileHandler(
            path_for_open,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
            delay=True,
        )
    except Exception:
        # Fallback to temp dir if target not writable
        try:
            tmp_log = os.path.join(tempfile.gettempdir(), "enhanced_system.log")
            _ensure_log_dir(tmp_log)
            path_for_open = _win_long_path(tmp_log)
            fh = RotatingFileHandler(
                path_for_open,
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8",
                delay=True,
            )
            logger.warning("⚠ Failed to open log file at %s — using temp log: %s", target, tmp_log)
        except Exception:
            # If file logging fails entirely, keep console-only
            logger.warning("⚠ Failed to initialize file handler; using console only.", exc_info=True)
            fh = None

    if fh:
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # Avoid double-printing via parent handlers
    logger.propagate = False
    return logger

# Default root logger for modules that don't request explicitly
root_logger = get_logger("ransomware_protection_system")

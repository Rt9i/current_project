# ransomware_protection_system/src/google_drive_backup.py
# -*- coding: utf-8 -*-
"""
Google Drive Backup Module (Enhanced)
====================================
Features:
- Robust authentication (OAuth client_secrets + token refresh) with safe file paths
- Thread-safe, retry with exponential backoff for Google API calls
- Create/find main backup folder (configurable)
- Recreate local folder structure on Drive
- Resumable uploads (configurable chunk size)
- Duplicate-avoidance (checks by name/size/md5Checksum before upload)
- List recent backups (paginated), delete old backups (keep-N)
- Restore/download a file
- Delete a specific file
- Helpers for metadata lookups
- Compatible with BackupManager usage (backup_file_with_structure / download_file)

Requires:
    pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib
"""

from __future__ import annotations

import os
import io
import sys
import time
import pickle
import logging
import mimetypes
import threading
from functools import wraps
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable, Tuple

# -------- Logger (robust import) --------
try:
    from src.logger import get_logger  # type: ignore
except Exception:  # pragma: no cover

    def get_logger(name: str):
        log = logging.getLogger(name)
        if not log.handlers:
            h = logging.StreamHandler(sys.stdout)
            h.setFormatter(
                logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
            )
            log.addHandler(h)
            log.setLevel(logging.INFO)
        return log


log = get_logger(__name__)

# -------- Utils (normalize_path, compute_sha256) --------
try:
    from src.utils import normalize_path, compute_sha256  # type: ignore
except Exception:  # pragma: no cover

    def normalize_path(p: str) -> str:
        return os.path.abspath(os.path.expanduser(str(p)))

    import hashlib

    def compute_sha256(path: str, chunk_size: int = 1024 * 1024) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None


# -------- Google API --------
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request


# =========================================
# Retry / Backoff helper
# =========================================
def _is_retryable_http_error(e: Exception) -> bool:
    """Return True for retryable Drive errors (rate limit / transient)."""
    if isinstance(e, HttpError):
        code = None
        try:
            code = int(
                getattr(e, "status_code", None)
                or getattr(getattr(e, "resp", None), "status", 0)
            )
        except Exception:
            code = None
        if code in (429, 500, 502, 503, 504):
            return True
    return False


def with_backoff(
    retries: int = 5,
    base_delay: float = 0.5,
    max_delay: float = 8.0,
    jitter: float = 0.2,
):
    """Exponential backoff decorator for Google API calls."""

    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    attempt += 1
                    if attempt > retries or not _is_retryable_http_error(e):
                        raise
                    delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
                    delta = delay * jitter
                    # jitter within ±jitter*delay
                    rand = os.urandom(1)[0] / 255.0
                    sleep_for = max(0.0, delay + (delta * (2 * (rand - 0.5))))
                    log.warning(
                        "API call failed (attempt %s/%s): %s — backing off %.2fs",
                        attempt,
                        retries,
                        getattr(e, "message", str(e)),
                        sleep_for,
                    )
                    time.sleep(sleep_for)

        return wrapper

    return deco


# =========================================
# Query escaping helper (IMPORTANT)
# =========================================
def _escape_q(s: str) -> str:
    """
    Escape single quotes for Google Drive 'q' parameter.
    According to Drive query syntax, single quotes inside string literals
    must be escaped as \\'.
    """
    return (s or "").replace("'", "\\'")


# =========================================
# Main class
# =========================================
class GoogleDriveBackup:
    def __init__(
        self,
        credentials_file: str = "~/.config/rps/credentials.json",
        token_file: str = "~/.config/rps/token.pickle",
        backup_root: str = "RansomwareProtectionBackups",
        scopes: Optional[List[str]] = None,
        chunk_size_mb: int = 8,
    ):
        """
        :param credentials_file: Path to client_secrets.json
        :param token_file: Path to OAuth token pickle
        :param backup_root: Drive folder name to store backups
        :param scopes: OAuth scopes list (default: Drive file scope)
        :param chunk_size_mb: Resumable upload chunk size (MB), multiple of 256KB
        """
        self.credentials_file = normalize_path(credentials_file)
        self.token_file = normalize_path(token_file)
        self.backup_root = backup_root
        self.scopes = scopes or ["https://www.googleapis.com/auth/drive.file"]

        # ensure token dir exists
        try:
            Path(self.token_file).parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        self._lock = threading.RLock()
        self.service = None
        self.backup_folder_id: Optional[str] = None

        # chunk size must be multiple of 256KB
        self.chunk_size = max(256 * 1024, int(chunk_size_mb * 1024 * 1024))
        self.chunk_size -= self.chunk_size % (256 * 1024)

        log.info(
            "GoogleDriveBackup initialized (root=%s, chunk=%dKB)",
            self.backup_root,
            self.chunk_size // 1024,
        )

    # ---------------------------
    # Authentication
    # ---------------------------
    def authenticate(self) -> bool:
        """Authenticate and build Drive service (thread-safe)."""
        with self._lock:
            if self.service is not None:
                return True

            creds = None
            if os.path.exists(self.token_file):
                try:
                    with open(self.token_file, "rb") as token:
                        creds = pickle.load(token)
                except Exception:
                    log.exception("Failed reading token file; will re-auth")

            if not creds or not getattr(creds, "valid", False):
                if (
                    creds
                    and getattr(creds, "expired", False)
                    and getattr(creds, "refresh_token", None)
                ):
                    try:
                        creds.refresh(Request())
                    except Exception as e:
                        log.error("Failed to refresh Google token: %s", e)
                        creds = None
                if not creds:
                    if not os.path.exists(self.credentials_file):
                        log.error(
                            "Credentials file not found: %s", self.credentials_file
                        )
                        return False
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self.credentials_file, self.scopes
                    )
                    # Note: opens local server; adjust if running headless/CI.
                    creds = flow.run_local_server(port=0)

                try:
                    with open(self.token_file, "wb") as token:
                        pickle.dump(creds, token)
                except Exception:
                    log.exception("Failed to persist token file (non-fatal)")

            self.service = build("drive", "v3", credentials=creds)
            return True

    def is_ready(self) -> bool:
        """
        Compatibility helper for BackupManager._is_drive_ready().
        Returns True if we can at least authenticate (build service).
        """
        try:
            return self.authenticate()
        except Exception:
            return False

    # ---------------------------
    # Folders
    # ---------------------------
    @with_backoff()
    def _find_folder(self, name: str, parent_id: Optional[str] = None) -> Optional[str]:
        if not self.authenticate():
            return None
        q = [
            f"name='{_escape_q(name)}'",
            "mimeType='application/vnd.google-apps.folder'",
            "trashed=false",
        ]
        if parent_id:
            q.append(f"'{parent_id}' in parents")
        query = " and ".join(q)
        res = (
            self.service.files()
            .list(q=query, spaces="drive", fields="files(id, name)", pageSize=10)
            .execute()
        )
        items = res.get("files", [])
        return items[0]["id"] if items else None

    @with_backoff()
    def _create_folder(
        self, name: str, parent_id: Optional[str] = None
    ) -> Optional[str]:
        if not self.authenticate():
            return None
        body = {"name": name, "mimeType": "application/vnd.google-apps.folder"}
        if parent_id:
            body["parents"] = [parent_id]
        folder = self.service.files().create(body=body, fields="id").execute()
        return folder.get("id")

    def create_backup_folder(self, folder_name: Optional[str] = None) -> Optional[str]:
        """Create or get the main backup folder in Drive (cached)."""
        if not self.authenticate():
            return None
        with self._lock:
            if self.backup_folder_id:
                return self.backup_folder_id
            name = folder_name or self.backup_root
            fid = self._find_folder(name)
            if not fid:
                fid = self._create_folder(name)
                if fid:
                    log.info("Created backup root: %s (ID=%s)", name, fid)
            else:
                log.info("Found backup root: %s (ID=%s)", name, fid)
            self.backup_folder_id = fid
            return fid

    def create_folder_structure(
        self, path: str, parent_id: Optional[str] = None
    ) -> Optional[str]:
        """
        Recreate folder structure on Drive.
        path: relative path (e.g., 'project/sub/dir') or '' for root-level under backup_root
        """
        if not self.authenticate():
            return None

        if not parent_id and not self.backup_folder_id:
            parent_id = self.create_backup_folder()
        elif not parent_id:
            parent_id = self.backup_folder_id

        if not parent_id:
            return None

        if not path or path in (".", "./"):
            return parent_id

        current_parent = parent_id
        for part in Path(path).parts:
            if part in (".", ""):
                continue
            found = self._find_folder(part, parent_id=current_parent)
            if found:
                current_parent = found
            else:
                created = self._create_folder(part, parent_id=current_parent)
                if not created:
                    return None
                current_parent = created
        return current_parent

    # ---------------------------
    # Metadata helpers
    # ---------------------------
    @with_backoff()
    def _get_file_by_name_in_parent(
        self, name: str, parent_id: str
    ) -> Optional[Dict[str, Any]]:
        """Find file by name within a parent folder."""
        if not self.authenticate():
            return None
        q = f"name='{_escape_q(name)}' and '{parent_id}' in parents and trashed=false"
        res = (
            self.service.files()
            .list(
                q=q,
                spaces="drive",
                fields="files(id, name, size, md5Checksum, createdTime, mimeType)",
                pageSize=10,
            )
            .execute()
        )
        files = res.get("files", [])
        return files[0] if files else None

    @with_backoff()
    def get_metadata(
        self,
        file_id: str,
        fields: str = "id, name, size, md5Checksum, createdTime, mimeType, parents",
    ) -> Optional[Dict[str, Any]]:
        if not self.authenticate():
            return None
        return self.service.files().get(fileId=file_id, fields=fields).execute()

    # ---------------------------
    # Upload
    # ---------------------------
    def _guess_mime(self, file_path: str) -> str:
        mtype, _ = mimetypes.guess_type(file_path)
        return mtype or "application/octet-stream"

    def _should_skip_upload(
        self, local_path: str, parent_id: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a file with the same base name and same content exists in parent to avoid duplicate uploads.
        Returns (skip, existing_file_id)
        """
        name = os.path.basename(local_path)
        meta = self._get_file_by_name_in_parent(name, parent_id)
        if not meta:
            return False, None
        try:
            local_size = os.path.getsize(local_path)
        except Exception:
            local_size = None
        md5_remote = meta.get("md5Checksum")
        size_remote = int(meta.get("size", 0) or 0)
        if (local_size is not None and size_remote == int(local_size)) and md5_remote:
            return True, meta.get("id")
        if local_size is not None and size_remote == int(local_size):
            return True, meta.get("id")
        return False, None

    @with_backoff()
    def _drive_create(
        self, body: Dict[str, Any], media: MediaFileUpload, fields: str = "id"
    ):
        return (
            self.service.files()
            .create(body=body, media_body=media, fields=fields)
            .execute()
        )

    def upload_file(
        self,
        file_path: str,
        parent_folder_id: Optional[str] = None,
        display_timestamp_suffix: bool = True,
    ) -> Optional[str]:
        """Upload a single file (resumable) to Drive."""
        if not self.authenticate():
            return None
        file_path = normalize_path(file_path)
        if not os.path.exists(file_path):
            log.error("File does not exist: %s", file_path)
            return None

        parent_id = (
            parent_folder_id or self.backup_folder_id or self.create_backup_folder()
        )
        if not parent_id:
            log.error("No parent folder available for upload")
            return None

        file_name = os.path.basename(file_path)
        backup_name = file_name
        if display_timestamp_suffix:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{file_name}_{timestamp}"

        # Avoid duplicate upload if identical exists
        try:
            skip, existing_id = self._should_skip_upload(file_path, parent_id)
        except Exception:
            skip, existing_id = (False, None)

        if skip and existing_id:
            log.info(
                "Skipping upload (already present): %s (ID=%s)", file_name, existing_id
            )
            return existing_id

        media = MediaFileUpload(
            file_path,
            mimetype=self._guess_mime(file_path),
            resumable=True,
            chunksize=self.chunk_size,
        )
        body = {"name": backup_name, "parents": [parent_id]}

        try:
            uploaded = self._drive_create(body=body, media=media, fields="id, name")
            file_id = uploaded.get("id")
            log.info("Uploaded file %s -> %s (ID=%s)", file_path, backup_name, file_id)
            return file_id
        except Exception as e:
            log.exception("Upload failed for %s: %s", file_path, e)
            return None

    def backup_file_with_structure(
        self, file_path: str, relative_to: Optional[str] = None
    ) -> Optional[str]:
        """
        Upload file keeping original folder structure under the backup root.
        Compatible signature with BackupManager.
        """
        file_path = normalize_path(file_path)
        if not os.path.exists(file_path):
            log.error("File not found: %s", file_path)
            return None

        if relative_to:
            try:
                relative_path = os.path.relpath(
                    os.path.dirname(file_path), normalize_path(relative_to)
                )
            except ValueError:
                relative_path = os.path.dirname(file_path)
        else:
            relative_path = os.path.dirname(file_path)

        parent_folder_id = self.create_folder_structure(relative_path)
        return self.upload_file(file_path, parent_folder_id)

    # ---------------------------
    # Listing and Deleting
    # ---------------------------
    @with_backoff()
    def _list_children(
        self, parent_id: str, max_results: int = 50, order_by: str = "createdTime desc"
    ) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        page_token = None
        while True:
            res = (
                self.service.files()
                .list(
                    q=f"'{parent_id}' in parents and trashed=false",
                    spaces="drive",
                    orderBy=order_by,
                    fields="nextPageToken, files(id, name, createdTime, size, md5Checksum, mimeType)",
                    pageSize=max_results,
                    pageToken=page_token,
                )
                .execute()
            )
            it = res.get("files", []) or []
            items.extend(it)
            page_token = res.get("nextPageToken")
            if not page_token:
                break
        return items

    def list_backups(self, max_results: int = 10) -> List[dict]:
        """List latest backups in the root backup folder."""
        if not self.authenticate():
            return []
        if not self.backup_folder_id:
            self.create_backup_folder()
        if not self.backup_folder_id:
            return []
        try:
            all_items = self._list_children(
                self.backup_folder_id, max_results=max_results
            )
            return all_items[:max_results]
        except Exception:
            log.exception("list_backups failed")
            return []

    @with_backoff()
    def _delete_file(self, file_id: str) -> bool:
        self.service.files().delete(fileId=file_id).execute()
        return True

    def delete_old_backups(self, max_backups: int = 5) -> bool:
        """
        Delete oldest backups in root folder, keeping only max_backups (by createdTime desc).
        If subfolders are used (structure), this acts only on the root folder's direct children.
        """
        if not self.authenticate():
            return False
        if not self.backup_folder_id:
            self.create_backup_folder()
        if not self.backup_folder_id:
            return False
        try:
            files = self._list_children(
                self.backup_folder_id, max_results=200, order_by="createdTime desc"
            )
            if len(files) > max_backups:
                for f in files[max_backups:]:
                    try:
                        self._delete_file(f["id"])
                        log.info(
                            "Deleted old backup: %s (ID=%s)", f.get("name"), f.get("id")
                        )
                    except Exception:
                        log.exception("Failed deleting old backup %s", f.get("id"))
            return True
        except Exception:
            log.exception("delete_old_backups failed")
            return False

    def delete_file(self, file_id: str) -> bool:
        """Delete a specific file from Drive."""
        if not self.authenticate():
            return False
        try:
            return self._delete_file(file_id)
        except Exception as e:
            log.error("Failed to delete file %s: %s", file_id, e)
            return False

    # ---------------------------
    # Restore / Download
    # ---------------------------
    @with_backoff()
    def _get_media_request(self, file_id: str):
        return self.service.files().get_media(fileId=file_id)

    def restore_file(
        self,
        file_id: str,
        destination: str,
        progress_cb: Optional[Callable[[float], None]] = None,
        chunk_size: int = 2 * 1024 * 1024,
    ) -> Optional[str]:
        """
        Download a file from Drive to local path.
        :param file_id: Drive file id
        :param destination: local path to write
        :param progress_cb: optional callback(progress_float_0_1)
        :param chunk_size: download chunk size (bytes)
        """
        if not self.authenticate():
            return None
        try:
            request = self._get_media_request(file_id)
            destination = normalize_path(destination)
            os.makedirs(os.path.dirname(destination), exist_ok=True)
            with io.FileIO(destination, "wb") as fh:
                downloader = MediaIoBaseDownload(
                    fh, request, chunksize=max(256 * 1024, chunk_size)
                )
                done = False
                last_progress = -1
                while not done:
                    status, done = downloader.next_chunk()
                    if status:
                        prog = float(status.progress())
                        if progress_cb and (int(prog * 100) != last_progress):
                            last_progress = int(prog * 100)
                            try:
                                progress_cb(prog)
                            except Exception:
                                pass
                        log.debug("Download %d%%", int(prog * 100))
            log.info("Restored file %s -> %s", file_id, destination)
            return destination
        except Exception as e:
            log.error("Failed to restore file %s: %s", file_id, e)
            return None

    # Alias for BackupManager compatibility
    def download_file(self, file_id: str, destination: str) -> Optional[str]:
        return self.restore_file(file_id, destination)

    # ---------------------------
    # Housekeeping
    # ---------------------------
    def ensure_ready(self) -> bool:
        """Make sure service and root folder exist (handy for app startup)."""
        if not self.authenticate():
            return False
        return self.create_backup_folder() is not None

    def close(self):
        """Placeholder for symmetry with other backends."""
        with self._lock:
            self.service = None

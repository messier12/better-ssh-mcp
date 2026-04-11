"""Audit log implementing IAuditLog."""
from __future__ import annotations

import io
import logging
import os
from pathlib import Path

from .models import AuditEvent, GlobalSettings

logger = logging.getLogger(__name__)


def _expand_path(raw: str) -> Path:
    """Expand ~ and environment variables in a path string."""
    return Path(os.path.expandvars(os.path.expanduser(raw)))


class AuditLog:
    """Appends JSON audit events to a log file, implementing IAuditLog.

    Each log() call writes one JSON line immediately (unbuffered).
    Passwords and secrets must never appear in audit events.
    """

    def __init__(self, settings: GlobalSettings | None = None) -> None:
        self._settings = settings or GlobalSettings()
        self._path: Path = _expand_path(self._settings.audit_log)
        self._fh: io.TextIOWrapper | None = None
        self._open()

    # ------------------------------------------------------------------
    # IAuditLog interface
    # ------------------------------------------------------------------

    def log(self, event: AuditEvent) -> None:
        """Append *event* as a single JSON line, flushed immediately."""
        if self._fh is None or self._fh.closed:
            self._open()
        fh = self._fh
        assert fh is not None  # for mypy
        fh.write(event.model_dump_json() + "\n")
        fh.flush()

    def close(self) -> None:
        """Flush and close the underlying file handle."""
        if self._fh is not None and not self._fh.closed:
            self._fh.flush()
            self._fh.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _open(self) -> None:
        """Open (or create) the audit log file in append mode with mode 0o600."""
        self._path.parent.mkdir(parents=True, exist_ok=True)

        existed = self._path.exists()
        self._fh = self._path.open("a", encoding="utf-8", buffering=1)
        if not existed:
            # Restrict newly created file to owner-read/write only.
            os.chmod(self._path, 0o600)

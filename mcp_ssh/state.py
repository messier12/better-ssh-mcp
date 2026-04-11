"""Persistent state store implementing IStateStore."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from .exceptions import McpSshError
from .models import GlobalSettings, ProcessRecord, ProcessStatus, SessionRecord

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


def _expand_path(raw: str) -> Path:
    """Expand ~ and environment variables in a path string."""
    return Path(os.path.expandvars(os.path.expanduser(raw)))


class StateStore:
    """Persists process and session records to a JSON state file, implementing IStateStore.

    Supports atomic writes, schema versioning, and graceful handling of
    missing or corrupt state files.

    Security note: this implementation assumes single-user operation. Process and
    session IDs are UUIDs; there is no access control between different OS users.
    If multi-user support is ever added, per-user namespacing must be enforced here.
    The state file is created with mode 0o600 (owner read/write only).
    """

    def __init__(self, settings: GlobalSettings | None = None) -> None:
        self._settings = settings or GlobalSettings()
        self._path: Path = _expand_path(self._settings.state_file)
        self._processes: dict[str, ProcessRecord] = {}
        self._sessions: dict[str, SessionRecord] = {}

    # ------------------------------------------------------------------
    # IStateStore interface
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Read state from disk.  Missing / corrupt files → empty state."""
        if not self._path.exists():
            logger.warning("State file not found at %s; starting with empty state.", self._path)
            self._processes = {}
            self._sessions = {}
            return

        try:
            raw = self._path.read_text(encoding="utf-8")
            data: Any = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "State file %s is unreadable or corrupt (%s); starting with empty state.",
                self._path,
                exc,
            )
            self._processes = {}
            self._sessions = {}
            return

        if not isinstance(data, dict):
            logger.warning(
                "State file %s has unexpected structure; starting with empty state.", self._path
            )
            self._processes = {}
            self._sessions = {}
            return

        file_version = data.get("schema_version", 1)
        if not isinstance(file_version, int):
            logger.warning(
                "State file %s has non-integer schema_version; starting with empty state.",
                self._path,
            )
            self._processes = {}
            self._sessions = {}
            return

        if file_version > SCHEMA_VERSION:
            raise McpSshError(
                f"State file {self._path} uses schema_version {file_version}, "
                f"but this version of mcp-ssh only supports up to {SCHEMA_VERSION}. "
                "Please upgrade mcp-ssh or remove the state file."
            )

        processes: dict[str, ProcessRecord] = {}
        for pid, pdata in data.get("processes", {}).items():
            try:
                prec = ProcessRecord.model_validate(pdata)
                prec = prec.model_copy(update={"status": ProcessStatus.unknown})
                processes[pid] = prec
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping corrupt process record %s: %s", pid, exc)

        sessions: dict[str, SessionRecord] = {}
        for sid, sdata in data.get("sessions", {}).items():
            try:
                srec = SessionRecord.model_validate(sdata)
                srec = srec.model_copy(update={"status": ProcessStatus.unknown})
                sessions[sid] = srec
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipping corrupt session record %s: %s", sid, exc)

        self._processes = processes
        self._sessions = sessions

    def upsert_process(self, record: ProcessRecord) -> None:
        """Insert or update a process record, then persist atomically."""
        self._processes[record.id] = record
        self._persist()

    def upsert_session(self, record: SessionRecord) -> None:
        """Insert or update a session record, then persist atomically."""
        self._sessions[record.id] = record
        self._persist()

    def get_process(self, process_id: str) -> ProcessRecord | None:
        """Return the process record for *process_id*, or None if not found."""
        return self._processes.get(process_id)

    def get_session(self, session_id: str) -> SessionRecord | None:
        """Return the session record for *session_id*, or None if not found."""
        return self._sessions.get(session_id)

    def list_processes(self, server: str | None = None) -> list[ProcessRecord]:
        """Return all process records, optionally filtered by server name."""
        records = list(self._processes.values())
        if server is not None:
            records = [r for r in records if r.server == server]
        return records

    def list_sessions(self, server: str | None = None) -> list[SessionRecord]:
        """Return all session records, optionally filtered by server name."""
        records = list(self._sessions.values())
        if server is not None:
            records = [r for r in records if r.server == server]
        return records

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _persist(self) -> None:
        """Write current in-memory state to disk atomically."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(".tmp")

        payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "processes": {
                pid: json.loads(rec.model_dump_json())
                for pid, rec in self._processes.items()
            },
            "sessions": {
                sid: json.loads(rec.model_dump_json())
                for sid, rec in self._sessions.items()
            },
        }

        existed = self._path.exists()
        tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp_path, self._path)
        if not existed:
            # Restrict newly created file to owner-read/write only.
            os.chmod(self._path, 0o600)

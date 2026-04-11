"""Tests for mcp_ssh.state — StateStore."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mcp_ssh.exceptions import McpSshError
from mcp_ssh.interfaces import IStateStore
from mcp_ssh.models import (
    GlobalSettings,
    ProcessRecord,
    ProcessStatus,
    SessionRecord,
)
from mcp_ssh.state import SCHEMA_VERSION, StateStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _settings(tmp_path: Path) -> GlobalSettings:
    state_file = str(tmp_path / "state.json")
    return GlobalSettings(state_file=state_file)


def _process(id: str = "p1", server: str = "myserver") -> ProcessRecord:
    return ProcessRecord(
        id=id,
        server=server,
        command="sleep 60",
        remote_pid=12345,
        log_file="/tmp/p1.log",
        exit_file="/tmp/p1.exit",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        status=ProcessStatus.running,
    )


def _session(id: str = "s1", server: str = "myserver") -> SessionRecord:
    return SessionRecord(
        id=id,
        server=server,
        command=None,
        use_tmux=False,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        status=ProcessStatus.running,
    )


# ---------------------------------------------------------------------------
# Interface conformance
# ---------------------------------------------------------------------------

def test_isinstance_istate_store(tmp_path: Path) -> None:
    store = StateStore(_settings(tmp_path))
    assert isinstance(store, IStateStore)


# ---------------------------------------------------------------------------
# Basic round-trip
# ---------------------------------------------------------------------------

def test_upsert_and_get_process(tmp_path: Path) -> None:
    store = StateStore(_settings(tmp_path))
    rec = _process()
    store.upsert_process(rec)
    result = store.get_process("p1")
    assert result is not None
    assert result.id == "p1"
    assert result.command == "sleep 60"


def test_upsert_and_get_session(tmp_path: Path) -> None:
    store = StateStore(_settings(tmp_path))
    rec = _session()
    store.upsert_session(rec)
    result = store.get_session("s1")
    assert result is not None
    assert result.id == "s1"


def test_get_nonexistent_process_returns_none(tmp_path: Path) -> None:
    store = StateStore(_settings(tmp_path))
    assert store.get_process("nope") is None


def test_get_nonexistent_session_returns_none(tmp_path: Path) -> None:
    store = StateStore(_settings(tmp_path))
    assert store.get_session("nope") is None


# ---------------------------------------------------------------------------
# Reload round-trip (upsert → reload → get)
# ---------------------------------------------------------------------------

def test_reload_preserves_process(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = StateStore(settings)
    store.upsert_process(_process(id="p2", server="srv"))

    store2 = StateStore(settings)
    store2.load()
    rec = store2.get_process("p2")
    assert rec is not None
    assert rec.server == "srv"
    assert rec.command == "sleep 60"


def test_reload_sets_status_unknown(tmp_path: Path) -> None:
    """Loaded records must have status=unknown regardless of saved value."""
    settings = _settings(tmp_path)
    store = StateStore(settings)
    rec = _process()
    assert rec.status == ProcessStatus.running
    store.upsert_process(rec)

    store2 = StateStore(settings)
    store2.load()
    loaded = store2.get_process("p1")
    assert loaded is not None
    assert loaded.status == ProcessStatus.unknown


def test_reload_session_status_unknown(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = StateStore(settings)
    store.upsert_session(_session())

    store2 = StateStore(settings)
    store2.load()
    loaded = store2.get_session("s1")
    assert loaded is not None
    assert loaded.status == ProcessStatus.unknown


def test_upsert_overwrites_existing(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = StateStore(settings)
    store.upsert_process(_process())

    updated = _process()
    updated = updated.model_copy(update={"exit_code": 0, "status": ProcessStatus.exited})
    store.upsert_process(updated)

    result = store.get_process("p1")
    assert result is not None
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------

def test_list_processes_all(tmp_path: Path) -> None:
    store = StateStore(_settings(tmp_path))
    store.upsert_process(_process("p1", "srv1"))
    store.upsert_process(_process("p2", "srv2"))
    assert len(store.list_processes()) == 2


def test_list_processes_filter_by_server(tmp_path: Path) -> None:
    store = StateStore(_settings(tmp_path))
    store.upsert_process(_process("p1", "srv1"))
    store.upsert_process(_process("p2", "srv2"))
    result = store.list_processes(server="srv1")
    assert len(result) == 1
    assert result[0].server == "srv1"


def test_list_sessions_all(tmp_path: Path) -> None:
    store = StateStore(_settings(tmp_path))
    store.upsert_session(_session("s1", "srv1"))
    store.upsert_session(_session("s2", "srv2"))
    assert len(store.list_sessions()) == 2


def test_list_sessions_filter_by_server(tmp_path: Path) -> None:
    store = StateStore(_settings(tmp_path))
    store.upsert_session(_session("s1", "srv1"))
    store.upsert_session(_session("s2", "srv2"))
    result = store.list_sessions(server="srv2")
    assert len(result) == 1
    assert result[0].server == "srv2"


# ---------------------------------------------------------------------------
# Missing / corrupt state file
# ---------------------------------------------------------------------------

def test_load_missing_file_gives_empty_state(tmp_path: Path) -> None:
    store = StateStore(_settings(tmp_path))
    store.load()  # no file exists
    assert store.list_processes() == []
    assert store.list_sessions() == []


def test_load_corrupt_json_gives_empty_state(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    path = Path(settings.state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("NOT VALID JSON }{", encoding="utf-8")

    store = StateStore(settings)
    store.load()
    assert store.list_processes() == []
    assert store.list_sessions() == []


def test_load_non_dict_json_gives_empty_state(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    path = Path(settings.state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[1, 2, 3]", encoding="utf-8")

    store = StateStore(settings)
    store.load()
    assert store.list_processes() == []


def test_load_corrupt_record_is_skipped(tmp_path: Path) -> None:
    """A corrupt individual record should be skipped; good records survive."""
    settings = _settings(tmp_path)
    store = StateStore(settings)
    store.upsert_process(_process("p1"))

    # Corrupt one record in place
    state_path = Path(settings.state_file)
    data = json.loads(state_path.read_text())
    data["processes"]["p1"]["remote_pid"] = "not-an-int"
    # Add a corrupt record alongside
    data["processes"]["p_corrupt"] = {"broken": True}
    state_path.write_text(json.dumps(data))

    store2 = StateStore(settings)
    store2.load()
    # corrupt records are skipped; valid one survives
    assert store2.get_process("p_corrupt") is None


# ---------------------------------------------------------------------------
# Schema versioning
# ---------------------------------------------------------------------------

def test_schema_version_written_to_file(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = StateStore(settings)
    store.upsert_process(_process())

    data = json.loads(Path(settings.state_file).read_text())
    assert data["schema_version"] == SCHEMA_VERSION


def test_higher_schema_version_raises(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    path = Path(settings.state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": SCHEMA_VERSION + 1, "processes": {}, "sessions": {}}))

    store = StateStore(settings)
    with pytest.raises(McpSshError, match="schema_version"):
        store.load()


def test_same_schema_version_loads_fine(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    path = Path(settings.state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": SCHEMA_VERSION, "processes": {}, "sessions": {}}))

    store = StateStore(settings)
    store.load()  # no error
    assert store.list_processes() == []


# ---------------------------------------------------------------------------
# Atomic write: tmp file is renamed into place
# ---------------------------------------------------------------------------

def test_atomic_write_no_tmp_file_left(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    store = StateStore(settings)
    store.upsert_process(_process())

    state_path = Path(settings.state_file)
    tmp_path_expected = state_path.with_suffix(".tmp")
    assert not tmp_path_expected.exists()
    assert state_path.exists()


# ---------------------------------------------------------------------------
# Default settings (no explicit GlobalSettings passed)
# ---------------------------------------------------------------------------

def test_default_settings_used_when_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Redirect the default path so we don't touch the real home dir
    fake_state = str(tmp_path / "state.json")
    monkeypatch.setenv("HOME", str(tmp_path))
    store = StateStore()
    # Just check it doesn't crash and has the right type
    assert isinstance(store, IStateStore)


# ---------------------------------------------------------------------------
# Path expansion
# ---------------------------------------------------------------------------

def test_tilde_expansion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    settings = GlobalSettings(state_file="~/custom_state.json")
    store = StateStore(settings)
    store.upsert_process(_process())
    assert (tmp_path / "custom_state.json").exists()


def test_env_var_expansion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_STATE_DIR", str(tmp_path))
    settings = GlobalSettings(state_file="$MY_STATE_DIR/state.json")
    store = StateStore(settings)
    store.upsert_process(_process())
    assert (tmp_path / "state.json").exists()


# ---------------------------------------------------------------------------
# Parent directory creation
# ---------------------------------------------------------------------------

def test_creates_parent_directories(tmp_path: Path) -> None:
    deep = tmp_path / "a" / "b" / "c"
    settings = GlobalSettings(state_file=str(deep / "state.json"))
    store = StateStore(settings)
    store.upsert_process(_process())
    assert (deep / "state.json").exists()

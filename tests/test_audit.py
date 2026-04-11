"""Tests for mcp_ssh.audit — AuditLog."""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mcp_ssh.audit import AuditLog
from mcp_ssh.interfaces import IAuditLog
from mcp_ssh.models import AuditEvent, GlobalSettings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _settings(tmp_path: Path) -> GlobalSettings:
    audit_file = str(tmp_path / "audit.jsonl")
    return GlobalSettings(audit_log=audit_file)


def _event(
    tool: str = "ssh_exec",
    outcome: str = "success",
    server: str | None = "myserver",
) -> AuditEvent:
    return AuditEvent(
        ts=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        tool=tool,
        server=server,
        outcome=outcome,
    )


def _read_lines(path: Path) -> list[dict]:  # type: ignore[type-arg]
    """Read all JSONL lines from an audit log file."""
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Interface conformance
# ---------------------------------------------------------------------------

def test_isinstance_iaudit_log(tmp_path: Path) -> None:
    audit = AuditLog(_settings(tmp_path))
    try:
        assert isinstance(audit, IAuditLog)
    finally:
        audit.close()


# ---------------------------------------------------------------------------
# Basic append
# ---------------------------------------------------------------------------

def test_log_creates_file(tmp_path: Path) -> None:
    audit = AuditLog(_settings(tmp_path))
    try:
        audit.log(_event())
    finally:
        audit.close()
    assert (tmp_path / "audit.jsonl").exists()


def test_log_writes_valid_json(tmp_path: Path) -> None:
    audit = AuditLog(_settings(tmp_path))
    try:
        audit.log(_event())
    finally:
        audit.close()

    lines = _read_lines(tmp_path / "audit.jsonl")
    assert len(lines) == 1
    entry = lines[0]
    assert entry["tool"] == "ssh_exec"
    assert entry["outcome"] == "success"
    assert "ts" in entry


def test_log_multiple_events_appended(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    audit = AuditLog(settings)
    try:
        audit.log(_event(tool="tool_a"))
        audit.log(_event(tool="tool_b"))
        audit.log(_event(tool="tool_c"))
    finally:
        audit.close()

    lines = _read_lines(tmp_path / "audit.jsonl")
    assert len(lines) == 3
    tools = [l["tool"] for l in lines]
    assert tools == ["tool_a", "tool_b", "tool_c"]


def test_each_line_is_valid_json(tmp_path: Path) -> None:
    """Every line in the log file must be independently parseable JSON."""
    audit = AuditLog(_settings(tmp_path))
    try:
        for i in range(5):
            audit.log(_event(tool=f"tool_{i}"))
    finally:
        audit.close()

    log_path = tmp_path / "audit.jsonl"
    for line in log_path.read_text().splitlines():
        parsed = json.loads(line)
        assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Append-only across multiple AuditLog instances
# ---------------------------------------------------------------------------

def test_append_across_instances(tmp_path: Path) -> None:
    """Opening the file a second time must append, not overwrite."""
    settings = _settings(tmp_path)

    audit1 = AuditLog(settings)
    audit1.log(_event(tool="first"))
    audit1.close()

    audit2 = AuditLog(settings)
    audit2.log(_event(tool="second"))
    audit2.close()

    lines = _read_lines(tmp_path / "audit.jsonl")
    assert len(lines) == 2
    assert lines[0]["tool"] == "first"
    assert lines[1]["tool"] == "second"


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------

def test_close_is_idempotent(tmp_path: Path) -> None:
    """Calling close() twice should not raise."""
    audit = AuditLog(_settings(tmp_path))
    audit.log(_event())
    audit.close()
    audit.close()  # second call must not raise


def test_log_after_close_reopens(tmp_path: Path) -> None:
    """Logging after close() should still work by reopening the file."""
    settings = _settings(tmp_path)
    audit = AuditLog(settings)
    audit.log(_event(tool="before_close"))
    audit.close()
    audit.log(_event(tool="after_close"))
    audit.close()

    lines = _read_lines(tmp_path / "audit.jsonl")
    assert len(lines) == 2


# ---------------------------------------------------------------------------
# File mode 0o600
# ---------------------------------------------------------------------------

def test_file_created_with_mode_0600(tmp_path: Path) -> None:
    audit = AuditLog(_settings(tmp_path))
    try:
        audit.log(_event())
    finally:
        audit.close()

    log_path = tmp_path / "audit.jsonl"
    file_mode = stat.S_IMODE(os.stat(log_path).st_mode)
    assert file_mode == 0o600


# ---------------------------------------------------------------------------
# Parent directory creation
# ---------------------------------------------------------------------------

def test_creates_parent_directories(tmp_path: Path) -> None:
    deep = tmp_path / "x" / "y" / "z"
    settings = GlobalSettings(audit_log=str(deep / "audit.jsonl"))
    audit = AuditLog(settings)
    try:
        audit.log(_event())
    finally:
        audit.close()
    assert (deep / "audit.jsonl").exists()


# ---------------------------------------------------------------------------
# Required fields present in every log entry
# ---------------------------------------------------------------------------

def test_required_fields_present(tmp_path: Path) -> None:
    audit = AuditLog(_settings(tmp_path))
    try:
        ev = AuditEvent(
            ts=datetime(2026, 6, 1, tzinfo=timezone.utc),
            tool="ssh_start_process",
            server="boxA",
            command="ls -la",
            process_id="proc-001",
            outcome="started",
            detail={"note": "test"},
        )
        audit.log(ev)
    finally:
        audit.close()

    lines = _read_lines(tmp_path / "audit.jsonl")
    entry = lines[0]
    assert "ts" in entry
    assert "tool" in entry
    assert "outcome" in entry
    assert entry["server"] == "boxA"
    assert entry["command"] == "ls -la"
    assert entry["process_id"] == "proc-001"
    assert entry["detail"]["note"] == "test"


# ---------------------------------------------------------------------------
# Default settings (no explicit GlobalSettings passed)
# ---------------------------------------------------------------------------

def test_default_settings_used_when_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    audit = AuditLog()
    try:
        assert isinstance(audit, IAuditLog)
    finally:
        audit.close()


# ---------------------------------------------------------------------------
# Path expansion
# ---------------------------------------------------------------------------

def test_tilde_expansion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    settings = GlobalSettings(audit_log="~/custom_audit.jsonl")
    audit = AuditLog(settings)
    try:
        audit.log(_event())
    finally:
        audit.close()
    assert (tmp_path / "custom_audit.jsonl").exists()


def test_env_var_expansion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_AUDIT_DIR", str(tmp_path))
    settings = GlobalSettings(audit_log="$MY_AUDIT_DIR/audit.jsonl")
    audit = AuditLog(settings)
    try:
        audit.log(_event())
    finally:
        audit.close()
    assert (tmp_path / "audit.jsonl").exists()


# ---------------------------------------------------------------------------
# Security: no passwords/secrets in log
# ---------------------------------------------------------------------------

def test_audit_event_has_no_password_field(tmp_path: Path) -> None:
    """AuditEvent model must not have a password field — checked structurally."""
    ev = _event()
    ev_dict = ev.model_dump()
    for key in ev_dict:
        assert "password" not in key.lower()
        assert "passphrase" not in key.lower()


def test_detail_dict_does_not_appear_in_env_values(tmp_path: Path) -> None:
    """Callers should not put env-var *values* in detail. This test documents
    that the detail dict is passed through verbatim — callers are responsible
    for not including secrets, and the model has no automatic scrubbing."""
    audit = AuditLog(_settings(tmp_path))
    try:
        ev = AuditEvent(
            ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
            tool="test",
            outcome="ok",
            detail={"env_keys": ["HOME", "PATH"]},  # only keys, not values
        )
        audit.log(ev)
    finally:
        audit.close()

    lines = _read_lines(tmp_path / "audit.jsonl")
    entry = lines[0]
    # We stored only the env key names, not their values — correct pattern.
    assert entry["detail"]["env_keys"] == ["HOME", "PATH"]

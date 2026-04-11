"""Real SSH server smoke tests.

These tests connect to an actual SSH server and require:
    MCP_SSH_SMOKE_HOST=10.150.1.138
    MCP_SSH_SMOKE_USER=formulatrix
    MCP_SSH_SMOKE_PASSWORD=<set in environment>

Tests are skipped automatically if these env vars are not set.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
import pytest_asyncio

from mcp_ssh.audit import AuditLog
from mcp_ssh.models import (
    AuthType,
    GlobalSettings,
    ServerConfig,
)
from mcp_ssh.pool import ConnectionPool
from mcp_ssh.session import SessionManager
from mcp_ssh.state import StateStore
from mcp_ssh.tools.exec_tools import ssh_check_process, ssh_exec, ssh_exec_stream, ssh_read_process

SMOKE_HOST = os.environ.get("MCP_SSH_SMOKE_HOST", "10.150.1.138")
SMOKE_USER = os.environ.get("MCP_SSH_SMOKE_USER", "formulatrix")
SMOKE_PASS_ENV = "MCP_SSH_SMOKE_PASSWORD"

requires_smoke = pytest.mark.skipif(
    SMOKE_PASS_ENV not in os.environ,
    reason=f"Set {SMOKE_PASS_ENV} env var to run smoke tests against {SMOKE_HOST}",
)


@pytest_asyncio.fixture
async def smoke_stack(tmp_path: Path):  # type: ignore[no-untyped-def]
    """Build a full stack pointed at the real SSH server."""
    cfg = ServerConfig(
        name="smoke",
        host=SMOKE_HOST,
        port=22,
        user=SMOKE_USER,
        auth_type=AuthType.password,
        password_env=SMOKE_PASS_ENV,
    )
    settings = GlobalSettings(
        known_hosts_file=str(tmp_path / "known_hosts"),
        state_file=str(tmp_path / "state.json"),
        audit_log=str(tmp_path / "audit.jsonl"),
        # Use tofu so we auto-accept on first connect
    )
    pool = ConnectionPool({"smoke": cfg}, settings)
    state = StateStore(settings)
    state.load()
    audit = AuditLog(settings)
    sm = SessionManager(pool=pool, state=state, audit=audit, settings=settings, servers={"smoke": cfg})

    yield pool, sm, state, audit, settings, cfg
    audit.close()
    await pool.close_all()


# ---------------------------------------------------------------------------
# Smoke tests
# ---------------------------------------------------------------------------

@requires_smoke
@pytest.mark.asyncio
async def test_smoke_ssh_exec(smoke_stack: tuple, monkeypatch: pytest.MonkeyPatch) -> None:
    """ssh_exec: run 'echo hello' on real server and get expected output."""
    import unittest.mock as mock
    pool, sm, state, audit, settings, cfg = smoke_stack

    reg = mock.MagicMock()
    reg.get.return_value = cfg
    audit_mock = mock.MagicMock()

    result = await ssh_exec(
        server="smoke",
        command="echo hello",
        registry=reg,
        pool=pool,
        audit=audit_mock,
        timeout=15,
    )
    assert "error" not in result, f"Unexpected error: {result}"
    assert "hello" in result["output"]
    assert result["exit_code"] == 0


@requires_smoke
@pytest.mark.asyncio
async def test_smoke_ssh_exec_stream_and_read(smoke_stack: tuple) -> None:
    """ssh_exec_stream + ssh_read_process: start a quick job and poll to completion."""
    import asyncio
    import unittest.mock as mock

    pool, sm, state, audit, settings, cfg = smoke_stack
    audit_mock = mock.MagicMock()

    stream_result = await ssh_exec_stream(
        server="smoke",
        command="sleep 1 && echo done_from_smoke",
        session_manager=sm,
        audit=audit_mock,
    )
    assert "error" not in stream_result, str(stream_result)
    pid = stream_result["process_id"]

    # Poll until finished (max 15 s)
    for _ in range(30):
        read_result = await ssh_read_process(pid, sm)
        if not read_result["running"]:
            break
        await asyncio.sleep(0.5)

    assert read_result["running"] is False
    assert read_result["exit_code"] == 0
    assert "done_from_smoke" in read_result["output"]


@requires_smoke
@pytest.mark.asyncio
async def test_smoke_ssh_check_process(smoke_stack: tuple) -> None:
    """ssh_check_process: verify exit code after a completed process."""
    import asyncio
    import unittest.mock as mock

    pool, sm, state, audit, settings, cfg = smoke_stack
    audit_mock = mock.MagicMock()

    stream = await ssh_exec_stream(
        server="smoke",
        command="exit 42",
        session_manager=sm,
        audit=audit_mock,
    )
    pid = stream["process_id"]
    await asyncio.sleep(2)  # let it finish

    result = await ssh_check_process(pid, sm)
    assert result["running"] is False
    assert result["exit_code"] == 42

"""Tests for mcp_ssh.tools.exec_tools (T3b)."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_ssh.exceptions import (
    McpSshError,
    ProcessNotFound,
    RemoteCommandError,
    ServerNotFound,
)
from mcp_ssh.models import (
    AuthType,
    GlobalSettings,
    ProcessOutput,
    ProcessRecord,
    ProcessStatus,
    ServerConfig,
)
from mcp_ssh.tools.exec_tools import (
    ssh_check_process,
    ssh_exec,
    ssh_exec_stream,
    ssh_kill_process,
    ssh_list_processes,
    ssh_read_process,
    ssh_write_process,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _cfg(name: str = "srv1") -> ServerConfig:
    return ServerConfig(
        name=name,
        host="1.2.3.4",
        port=22,
        user="admin",
        auth_type=AuthType.agent,
        default_cwd="/home/admin",
        default_env={"LANG": "C.UTF-8"},
    )


def _make_registry(cfg: ServerConfig | None = None) -> MagicMock:
    reg = MagicMock()
    _cfg_obj = cfg or _cfg()

    def _get(name: str) -> ServerConfig:
        if name == _cfg_obj.name:
            return _cfg_obj
        raise ServerNotFound(f"Not found: {name!r}")

    reg.get.side_effect = _get
    return reg


def _make_pool(run_output: str = "", exit_status: int = 0) -> AsyncMock:
    pool = AsyncMock()
    conn = AsyncMock()
    result = MagicMock()
    result.stdout = run_output
    result.stderr = ""
    result.exit_status = exit_status
    conn.run = AsyncMock(return_value=result)
    pool.get_connection = AsyncMock(return_value=conn)
    return pool


def _make_session_manager() -> AsyncMock:
    return AsyncMock()


def _make_audit() -> MagicMock:
    return MagicMock()


def _process_record(id: str = "p1") -> ProcessRecord:
    return ProcessRecord(
        id=id,
        server="srv1",
        command="sleep 60",
        remote_pid=9999,
        log_file=f"/tmp/mcp-{id}.log",
        exit_file=f"/tmp/mcp-{id}.exit",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        status=ProcessStatus.running,
    )


# ---------------------------------------------------------------------------
# ssh_exec
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_exec_success() -> None:
    reg = _make_registry()
    pool = _make_pool(run_output="hello world\n", exit_status=0)
    audit = _make_audit()
    result = await ssh_exec("srv1", "echo hello", reg, pool, audit)
    assert result["output"] == "hello world\n"
    assert result["exit_code"] == 0
    assert result["server"] == "srv1"
    audit.log.assert_called()


@pytest.mark.asyncio
async def test_ssh_exec_server_not_found() -> None:
    reg = _make_registry()
    pool = _make_pool()
    audit = _make_audit()
    result = await ssh_exec("nonexistent", "echo hi", reg, pool, audit)
    assert result["error"] == "server_not_found"


@pytest.mark.asyncio
async def test_ssh_exec_timeout() -> None:
    reg = _make_registry()
    pool = AsyncMock()
    conn = AsyncMock()

    async def slow_run(*args: object, **kwargs: object) -> None:
        await asyncio.sleep(10)

    conn.run = slow_run
    pool.get_connection = AsyncMock(return_value=conn)
    audit = _make_audit()

    result = await ssh_exec("srv1", "sleep 10", reg, pool, audit, timeout=0.01)
    assert result["error"] == "timeout"


@pytest.mark.asyncio
async def test_ssh_exec_no_timeout_logs_warning() -> None:
    reg = _make_registry()
    pool = _make_pool(run_output="ok\n", exit_status=0)
    audit = _make_audit()
    result = await ssh_exec("srv1", "echo ok", reg, pool, audit, timeout=None)
    # Should complete successfully despite no timeout
    assert result["exit_code"] == 0
    # Audit log called twice: warn_no_timeout + completed
    assert audit.log.call_count == 2


@pytest.mark.asyncio
async def test_ssh_exec_applies_default_cwd() -> None:
    """default_cwd from ServerConfig is prepended to the remote command."""
    cfg = _cfg()
    reg = _make_registry(cfg)
    pool = _make_pool()
    audit = _make_audit()
    conn = pool.get_connection.return_value
    await ssh_exec("srv1", "pwd", reg, pool, audit, cwd=None)
    # The command run on conn.run should contain the default cwd
    call_args = conn.run.call_args[0][0]
    assert "/home/admin" in call_args


@pytest.mark.asyncio
async def test_ssh_exec_applies_default_env() -> None:
    cfg = _cfg()
    reg = _make_registry(cfg)
    pool = _make_pool()
    audit = _make_audit()
    conn = pool.get_connection.return_value
    await ssh_exec("srv1", "env", reg, pool, audit, env=None)
    call_args = conn.run.call_args[0][0]
    assert "LANG" in call_args


# ---------------------------------------------------------------------------
# ssh_exec_stream
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_exec_stream_returns_process_id() -> None:
    sm = _make_session_manager()
    sm.start_process = AsyncMock(return_value="pid-123")
    audit = _make_audit()
    result = await ssh_exec_stream("srv1", "sleep 60", sm, audit)
    assert result["process_id"] == "pid-123"
    assert result["server"] == "srv1"


@pytest.mark.asyncio
async def test_exec_stream_error_from_manager() -> None:
    sm = _make_session_manager()
    sm.start_process = AsyncMock(side_effect=RemoteCommandError("Remote died"))
    audit = _make_audit()
    result = await ssh_exec_stream("srv1", "sleep 60", sm, audit)
    assert result["error"] == "start_error"


# ---------------------------------------------------------------------------
# ssh_read_process
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_read_process_success() -> None:
    sm = _make_session_manager()
    sm.read_process = AsyncMock(
        return_value=ProcessOutput(
            output="output data",
            running=True,
            exit_code=None,
            remote_pid=9999,
            server="srv1",
        )
    )
    result = await ssh_read_process("p1", sm)
    assert result["output"] == "output data"
    assert result["running"] is True


@pytest.mark.asyncio
async def test_read_process_not_found() -> None:
    sm = _make_session_manager()
    sm.read_process = AsyncMock(side_effect=ProcessNotFound("nope"))
    result = await ssh_read_process("p_gone", sm)
    assert result["error"] == "process_not_found"


# ---------------------------------------------------------------------------
# ssh_write_process
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_write_process_error_no_stdin() -> None:
    """nohup processes cannot receive stdin; this should return an error."""
    sm = _make_session_manager()
    sm.write_process = AsyncMock(side_effect=RemoteCommandError("no stdin"))
    result = await ssh_write_process("p1", "data", sm)
    assert result["error"] == "write_error"


# ---------------------------------------------------------------------------
# ssh_kill_process
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_kill_process_success() -> None:
    sm = _make_session_manager()
    sm.kill_process = AsyncMock(return_value=None)
    result = await ssh_kill_process("p1", sm, signal="SIGTERM")
    assert result["killed"] is True
    assert result["signal"] == "SIGTERM"


@pytest.mark.asyncio
async def test_kill_process_not_found() -> None:
    sm = _make_session_manager()
    sm.kill_process = AsyncMock(side_effect=ProcessNotFound("nope"))
    result = await ssh_kill_process("p_gone", sm)
    assert result["error"] == "process_not_found"


# ---------------------------------------------------------------------------
# ssh_list_processes
# ---------------------------------------------------------------------------

def test_list_processes_all() -> None:
    sm = _make_session_manager()
    sm.list_processes = MagicMock(return_value=[_process_record("p1"), _process_record("p2")])
    result = ssh_list_processes(sm)
    assert len(result["processes"]) == 2


def test_list_processes_empty_for_nonexistent_server() -> None:
    sm = _make_session_manager()
    sm.list_processes = MagicMock(return_value=[])
    result = ssh_list_processes(sm, server="nonexistent")
    assert result == {"processes": []}
    # Not an error — empty list
    assert "error" not in result


def test_list_processes_has_last_checked_ago_field() -> None:
    sm = _make_session_manager()
    rec = _process_record("p1")
    rec = rec.model_copy(
        update={"last_checked": datetime.now(timezone.utc) - timedelta(seconds=45)}
    )
    sm.list_processes = MagicMock(return_value=[rec])
    result = ssh_list_processes(sm)
    items = result["processes"]
    assert "last_checked_ago" in items[0]
    assert items[0]["last_checked_ago"].endswith("s ago")


def test_list_processes_never_checked() -> None:
    sm = _make_session_manager()
    rec = _process_record("p1")
    sm.list_processes = MagicMock(return_value=[rec])
    result = ssh_list_processes(sm)
    assert result["processes"][0]["last_checked_ago"] == "never"


# ---------------------------------------------------------------------------
# ssh_check_process
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_check_process_success() -> None:
    sm = _make_session_manager()
    sm.check_process = AsyncMock(
        return_value=ProcessOutput(
            output="log",
            running=False,
            exit_code=0,
            remote_pid=9999,
            server="srv1",
        )
    )
    result = await ssh_check_process("p1", sm)
    assert result["running"] is False
    assert result["exit_code"] == 0


@pytest.mark.asyncio
async def test_check_process_not_found() -> None:
    sm = _make_session_manager()
    sm.check_process = AsyncMock(side_effect=ProcessNotFound("nope"))
    result = await ssh_check_process("p_gone", sm)
    assert result["error"] == "process_not_found"

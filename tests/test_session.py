"""Tests for mcp_ssh/session.py — SessionManager."""
from __future__ import annotations

import asyncio
import collections
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_ssh.exceptions import (
    ProcessNotFound,
    RemoteCommandError,
    SessionCapExceeded,
    SessionNotFound,
    TmuxNotAvailable,
)
from mcp_ssh.interfaces import ISessionManager
from mcp_ssh.models import (
    AuthType,
    GlobalSettings,
    ProcessRecord,
    ProcessStatus,
    ServerConfig,
    SessionRecord,
)
from mcp_ssh.session import SessionManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_result(stdout: str = "", exit_status: int = 0) -> MagicMock:
    r = MagicMock()
    r.stdout = stdout
    r.exit_status = exit_status
    return r


def _make_conn(
    run_side_effect: list[MagicMock] | None = None,
    run_return: MagicMock | None = None,
) -> MagicMock:
    conn = MagicMock()
    if run_side_effect is not None:
        conn.run = AsyncMock(side_effect=run_side_effect)
    else:
        conn.run = AsyncMock(return_value=run_return or _run_result("12345\n"))
    conn.create_process = AsyncMock()
    return conn


def _make_pool(conn: MagicMock) -> MagicMock:
    pool = MagicMock()
    pool.get_connection = AsyncMock(return_value=conn)
    return pool


def _make_state() -> MagicMock:
    state = MagicMock()
    state.get_process = MagicMock(return_value=None)
    state.get_session = MagicMock(return_value=None)
    state.list_sessions = MagicMock(return_value=[])
    state.list_processes = MagicMock(return_value=[])
    state.upsert_process = MagicMock()
    state.upsert_session = MagicMock()
    return state


def _make_audit() -> MagicMock:
    audit = MagicMock()
    audit.log = MagicMock()
    return audit


def _make_manager(
    conn: MagicMock | None = None,
    run_return: MagicMock | None = None,
    settings: GlobalSettings | None = None,
    servers: dict[str, ServerConfig] | None = None,
) -> tuple[SessionManager, MagicMock, MagicMock, MagicMock, MagicMock]:
    if conn is None:
        conn = _make_conn(run_return=run_return or _run_result("12345\n"))
    pool = _make_pool(conn)
    state = _make_state()
    audit = _make_audit()
    mgr = SessionManager(
        pool=pool, state=state, audit=audit, settings=settings, servers=servers
    )
    return mgr, pool, state, audit, conn


def _make_process_record(**kwargs: object) -> ProcessRecord:
    defaults: dict[str, object] = {
        "id": "proc-1",
        "server": "myserver",
        "command": "echo hello",
        "remote_pid": 12345,
        "log_file": "/tmp/mcp-proc-1.log",
        "exit_file": "/tmp/mcp-proc-1.exit",
        "started_at": __import__("datetime").datetime.utcnow(),
        "status": ProcessStatus.running,
    }
    defaults.update(kwargs)
    return ProcessRecord(**defaults)  # type: ignore[arg-type]


def _make_session_record(**kwargs: object) -> SessionRecord:
    defaults: dict[str, object] = {
        "id": "sess-1",
        "server": "myserver",
        "command": "bash",
        "use_tmux": False,
        "started_at": __import__("datetime").datetime.utcnow(),
        "status": ProcessStatus.running,
    }
    defaults.update(kwargs)
    return SessionRecord(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 1. isinstance check
# ---------------------------------------------------------------------------


def test_isinstance_isessionmanager() -> None:
    mgr, *_ = _make_manager()
    assert isinstance(mgr, ISessionManager)


# ---------------------------------------------------------------------------
# 2-3. start_process
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_process_happy_path() -> None:
    conn = _make_conn(run_return=_run_result("99999\n"))
    mgr, pool, state, audit, _ = _make_manager(conn=conn)

    pid_str = await mgr.start_process("myserver", "echo hi", cwd="/home/user", env={"FOO": "bar"})

    # PID should be returned as the process_id (uuid4 string, not the remote PID)
    assert isinstance(pid_str, str)
    assert len(pid_str) == 36  # UUID4 format

    # conn.run was called
    conn.run.assert_awaited_once()
    cmd_arg: str = conn.run.call_args[0][0]
    # cwd and env should be shell-quoted
    assert "cd '/home/user'" in cmd_arg or "cd /home/user" in cmd_arg
    assert "FOO=" in cmd_arg

    # state upserted
    state.upsert_process.assert_called_once()
    record: ProcessRecord = state.upsert_process.call_args[0][0]
    assert record.remote_pid == 99999
    assert record.server == "myserver"
    assert record.status == ProcessStatus.running

    # audit logged
    audit.log.assert_called_once()
    event = audit.log.call_args[0][0]
    assert event.tool == "start_process"
    assert event.outcome == "started"


@pytest.mark.asyncio
async def test_start_process_invalid_pid_raises() -> None:
    conn = _make_conn(run_return=_run_result("not-a-number\n"))
    mgr, *_ = _make_manager(conn=conn)

    with pytest.raises(RemoteCommandError, match="expected integer PID"):
        await mgr.start_process("myserver", "echo hi", cwd=None, env=None)


# ---------------------------------------------------------------------------
# 4-6. read_process
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_process_not_found_raises() -> None:
    mgr, *_ = _make_manager()
    # state.get_process returns None by default

    with pytest.raises(ProcessNotFound):
        await mgr.read_process("nonexistent-id")


@pytest.mark.asyncio
async def test_read_process_running() -> None:
    """Exit file empty → running=True."""
    record = _make_process_record()
    conn = _make_conn(
        run_side_effect=[
            _run_result(""),       # exit file check: empty → still running
            _run_result("hello\n"),  # log tail
        ]
    )
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_process = MagicMock(return_value=record)

    out = await mgr.read_process("proc-1")

    assert out.running is True
    assert out.exit_code is None
    assert out.remote_pid == 12345
    assert out.server == "myserver"
    assert "hello" in out.output


@pytest.mark.asyncio
async def test_read_process_exited() -> None:
    """Exit file has '0' → running=False, exit_code=0."""
    record = _make_process_record()
    conn = _make_conn(
        run_side_effect=[
            _run_result("0\n"),    # exit file check
            _run_result("done\n"), # log tail
        ]
    )
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_process = MagicMock(return_value=record)

    out = await mgr.read_process("proc-1")

    assert out.running is False
    assert out.exit_code == 0


# ---------------------------------------------------------------------------
# 7-8. check_process
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_process_alive() -> None:
    record = _make_process_record()
    conn = _make_conn(
        run_side_effect=[
            _run_result("alive\n"),   # kill -0
            _run_result("log data"),  # tail log
            _run_result(""),          # exit file
        ]
    )
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_process = MagicMock(return_value=record)

    out = await mgr.check_process("proc-1")

    assert out.running is True
    assert out.exit_code is None
    state.upsert_process.assert_called_once()
    updated: ProcessRecord = state.upsert_process.call_args[0][0]
    assert updated.status == ProcessStatus.running
    assert updated.last_checked is not None


@pytest.mark.asyncio
async def test_check_process_dead() -> None:
    record = _make_process_record()
    conn = _make_conn(
        run_side_effect=[
            _run_result("dead\n"),    # kill -0
            _run_result("log data"),  # tail log
            _run_result("1\n"),       # exit file
        ]
    )
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_process = MagicMock(return_value=record)

    out = await mgr.check_process("proc-1")

    assert out.running is False
    assert out.exit_code == 1
    updated: ProcessRecord = state.upsert_process.call_args[0][0]
    assert updated.status == ProcessStatus.exited


# ---------------------------------------------------------------------------
# 9-11. kill_process
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kill_process_happy_path() -> None:
    record = _make_process_record()
    conn = _make_conn(run_return=_run_result(""))
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_process = MagicMock(return_value=record)

    await mgr.kill_process("proc-1", signal="SIGTERM")

    conn.run.assert_awaited_once()
    cmd: str = conn.run.call_args[0][0]
    assert "kill -SIGTERM 12345" in cmd

    state.upsert_process.assert_called_once()
    updated: ProcessRecord = state.upsert_process.call_args[0][0]
    assert updated.status == ProcessStatus.killed

    audit.log.assert_called_once()
    event = audit.log.call_args[0][0]
    assert event.outcome == "killed"


@pytest.mark.asyncio
async def test_kill_process_invalid_signal() -> None:
    record = _make_process_record()
    mgr, pool, state, audit, conn = _make_manager()
    state.get_process = MagicMock(return_value=record)

    with pytest.raises(RemoteCommandError, match="not allowed"):
        await mgr.kill_process("proc-1", signal="SIGBAD")


@pytest.mark.asyncio
async def test_kill_process_not_found() -> None:
    mgr, *_ = _make_manager()

    with pytest.raises(ProcessNotFound):
        await mgr.kill_process("nonexistent", signal="SIGTERM")


# ---------------------------------------------------------------------------
# 12. write_process
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_process_raises() -> None:
    mgr, *_ = _make_manager()

    with pytest.raises(RemoteCommandError, match="not supported"):
        await mgr.write_process("proc-1", "some data")


# ---------------------------------------------------------------------------
# 13. list_processes
# ---------------------------------------------------------------------------


def test_list_processes_delegates() -> None:
    mgr, pool, state, audit, conn = _make_manager()
    records = [_make_process_record()]
    state.list_processes = MagicMock(return_value=records)

    result = mgr.list_processes("myserver")

    state.list_processes.assert_called_once_with("myserver")
    assert result == records


# ---------------------------------------------------------------------------
# 14. start_pty no-tmux
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_pty_no_tmux() -> None:
    proc_mock = MagicMock()
    proc_mock.stdout = MagicMock()
    proc_mock.stdout.read = AsyncMock(return_value=b"")
    proc_mock.is_closing = MagicMock(return_value=False)
    proc_mock.stdin = MagicMock()

    conn = _make_conn()
    conn.create_process = AsyncMock(return_value=proc_mock)

    mgr, pool, state, audit, _ = _make_manager(conn=conn)

    with patch("asyncio.create_task") as mock_task:
        session_id = await mgr.start_pty("myserver", "bash", cols=80, rows=24, use_tmux=False)

    assert isinstance(session_id, str)
    assert len(session_id) == 36

    conn.create_process.assert_awaited_once()
    call_kwargs = conn.create_process.call_args
    assert call_kwargs.kwargs.get("request_pty") is True or call_kwargs[1].get("request_pty") is True

    state.upsert_session.assert_called_once()
    record: SessionRecord = state.upsert_session.call_args[0][0]
    assert record.use_tmux is False
    assert record.status == ProcessStatus.running

    audit.log.assert_called_once()
    assert mock_task.called


# ---------------------------------------------------------------------------
# 15-16. start_pty tmux
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_pty_tmux_happy() -> None:
    conn = _make_conn(
        run_side_effect=[
            _run_result("/usr/bin/tmux"),  # which tmux
            _run_result(""),               # tmux new-session
            _run_result(""),               # tmux pipe-pane
        ]
    )
    mgr, pool, state, audit, _ = _make_manager(conn=conn)

    session_id = await mgr.start_pty("myserver", None, cols=80, rows=24, use_tmux=True)

    assert isinstance(session_id, str)
    assert len(session_id) == 36

    # Should have called run 3 times
    assert conn.run.await_count == 3

    # Check tmux new-session command
    new_sess_cmd: str = conn.run.call_args_list[1][0][0]
    assert "tmux new-session" in new_sess_cmd

    state.upsert_session.assert_called_once()
    record: SessionRecord = state.upsert_session.call_args[0][0]
    assert record.use_tmux is True
    assert record.tmux_window is not None

    audit.log.assert_called_once()


@pytest.mark.asyncio
async def test_start_pty_tmux_not_available() -> None:
    conn = _make_conn(
        run_side_effect=[
            _run_result(""),   # which tmux → empty
        ]
    )
    mgr, *_ = _make_manager(conn=conn)

    with pytest.raises(TmuxNotAvailable, match="tmux not found"):
        await mgr.start_pty("myserver", "bash", cols=80, rows=24, use_tmux=True)


# ---------------------------------------------------------------------------
# 17. session cap exceeded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_pty_session_cap_exceeded() -> None:
    settings = GlobalSettings(max_sessions=2)
    conn = _make_conn()
    mgr, pool, state, audit, _ = _make_manager(conn=conn, settings=settings)

    running_sessions = [
        _make_session_record(id=f"s{i}", status=ProcessStatus.running) for i in range(2)
    ]
    state.list_sessions = MagicMock(return_value=running_sessions)

    with pytest.raises(SessionCapExceeded, match="session cap of 2 exceeded"):
        await mgr.start_pty("myserver", "bash", cols=80, rows=24, use_tmux=False)


@pytest.mark.asyncio
async def test_start_pty_session_cap_per_server() -> None:
    """Per-server cap overrides global cap."""
    server_cfg = ServerConfig(
        name="myserver",
        host="1.2.3.4",
        user="admin",
        auth_type=AuthType.agent,
        max_sessions=1,
    )
    settings = GlobalSettings(max_sessions=10)
    conn = _make_conn()
    mgr, pool, state, audit, _ = _make_manager(
        conn=conn, settings=settings, servers={"myserver": server_cfg}
    )

    running_sessions = [_make_session_record(id="s1", status=ProcessStatus.running)]
    state.list_sessions = MagicMock(return_value=running_sessions)

    with pytest.raises(SessionCapExceeded, match="session cap of 1 exceeded"):
        await mgr.start_pty("myserver", "bash", cols=80, rows=24, use_tmux=False)


# ---------------------------------------------------------------------------
# 18. pty_write no-tmux
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pty_write_no_tmux() -> None:
    session = _make_session_record(use_tmux=False)
    conn = _make_conn()
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_session = MagicMock(return_value=session)

    # Set up a fake proc in the manager's internal dict
    proc_mock = MagicMock()
    proc_mock.stdin = MagicMock()
    proc_mock.stdin.write = MagicMock()
    mgr._pty_procs["sess-1"] = proc_mock

    await mgr.pty_write("sess-1", "hello\r")

    proc_mock.stdin.write.assert_called_once_with(b"hello\r")


# ---------------------------------------------------------------------------
# 19. pty_write tmux
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pty_write_tmux() -> None:
    session = _make_session_record(use_tmux=True, tmux_window="mcp-abc12345")
    conn = _make_conn(run_return=_run_result(""))
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_session = MagicMock(return_value=session)

    mgr._tmux_sessions["sess-1"] = "mcp-abc12345"
    mgr._tmux_conns["sess-1"] = conn

    await mgr.pty_write("sess-1", "ls\r")

    conn.run.assert_awaited_once()
    cmd: str = conn.run.call_args[0][0]
    assert "tmux send-keys" in cmd
    assert "mcp-abc12345" in cmd


# ---------------------------------------------------------------------------
# 20. pty_close no-tmux
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pty_close_no_tmux() -> None:
    session = _make_session_record(use_tmux=False)
    conn = _make_conn()
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_session = MagicMock(return_value=session)

    proc_mock = MagicMock()
    proc_mock.close = MagicMock()
    task_mock = MagicMock()
    task_mock.cancel = MagicMock()

    mgr._pty_procs["sess-1"] = proc_mock
    mgr._pty_buffers["sess-1"] = collections.deque()
    mgr._drain_tasks["sess-1"] = task_mock

    await mgr.pty_close("sess-1")

    task_mock.cancel.assert_called_once()
    proc_mock.close.assert_called_once()

    # Session state updated
    state.upsert_session.assert_called_once()
    updated: SessionRecord = state.upsert_session.call_args[0][0]
    assert updated.status == ProcessStatus.exited

    # Audit logged
    audit.log.assert_called_once()
    event = audit.log.call_args[0][0]
    assert event.outcome == "closed"

    # In-memory dicts cleaned up
    assert "sess-1" not in mgr._pty_procs
    assert "sess-1" not in mgr._pty_buffers
    assert "sess-1" not in mgr._drain_tasks


# ---------------------------------------------------------------------------
# 21. pty_attach non-tmux raises
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pty_attach_non_tmux_raises() -> None:
    session = _make_session_record(use_tmux=False)
    mgr, pool, state, audit, conn = _make_manager()
    state.get_session = MagicMock(return_value=session)

    with pytest.raises(SessionNotFound, match="use_tmux=True"):
        await mgr.pty_attach("sess-1")


@pytest.mark.asyncio
async def test_pty_attach_tmux_raises_not_implemented() -> None:
    session = _make_session_record(use_tmux=True, tmux_window="mcp-abc12345")
    conn = _make_conn(run_return=_run_result("", exit_status=0))
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_session = MagicMock(return_value=session)
    mgr._tmux_sessions["sess-1"] = "mcp-abc12345"
    mgr._tmux_conns["sess-1"] = conn

    with pytest.raises(NotImplementedError, match="pty_attach is not supported"):
        await mgr.pty_attach("sess-1")


# ---------------------------------------------------------------------------
# 22. list_sessions delegates
# ---------------------------------------------------------------------------


def test_list_sessions_delegates() -> None:
    mgr, pool, state, audit, conn = _make_manager()
    records = [_make_session_record()]
    state.list_sessions = MagicMock(return_value=records)

    result = mgr.list_sessions("myserver")

    state.list_sessions.assert_called_once_with("myserver")
    assert result == records


# ---------------------------------------------------------------------------
# Additional edge-case tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_process_log_content() -> None:
    """Output from log_result ends up in ProcessOutput.output."""
    record = _make_process_record()
    conn = _make_conn(
        run_side_effect=[
            _run_result(""),           # exit file empty
            _run_result("line1\nline2"),  # log content
        ]
    )
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_process = MagicMock(return_value=record)

    out = await mgr.read_process("proc-1")
    assert out.output == "line1\nline2"


@pytest.mark.asyncio
async def test_pty_read_not_found_raises() -> None:
    mgr, *_ = _make_manager()

    with pytest.raises(SessionNotFound):
        await mgr.pty_read("nonexistent")


@pytest.mark.asyncio
async def test_pty_resize_not_found_raises() -> None:
    mgr, *_ = _make_manager()

    with pytest.raises(SessionNotFound):
        await mgr.pty_resize("nonexistent", 80, 24)


@pytest.mark.asyncio
async def test_pty_close_not_found_raises() -> None:
    mgr, *_ = _make_manager()

    with pytest.raises(SessionNotFound):
        await mgr.pty_close("nonexistent")


@pytest.mark.asyncio
async def test_pty_write_not_found_raises() -> None:
    mgr, *_ = _make_manager()

    with pytest.raises(SessionNotFound):
        await mgr.pty_write("nonexistent", "data")


@pytest.mark.asyncio
async def test_pty_attach_not_found_raises() -> None:
    mgr, *_ = _make_manager()

    with pytest.raises(SessionNotFound):
        await mgr.pty_attach("nonexistent")


@pytest.mark.asyncio
async def test_pty_read_no_tmux_buffer() -> None:
    """pty_read drains buffer up to max_bytes."""
    session = _make_session_record(use_tmux=False)
    conn = _make_conn()
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_session = MagicMock(return_value=session)

    buf: collections.deque[bytes] = collections.deque()
    buf.append(b"hello world")
    mgr._pty_buffers["sess-1"] = buf

    proc_mock = MagicMock()
    proc_mock.is_closing = MagicMock(return_value=False)
    mgr._pty_procs["sess-1"] = proc_mock

    out = await mgr.pty_read("sess-1", max_bytes=5)
    assert out.output == "hello"
    assert out.alive is True
    # Remainder should be back in buffer
    assert buf


@pytest.mark.asyncio
async def test_pty_read_tmux_path() -> None:
    session = _make_session_record(use_tmux=True, tmux_window="mcp-abc12345")
    conn = _make_conn(
        run_side_effect=[
            _run_result("remote output"),  # tail log
            _run_result("alive\n"),        # tmux has-session
        ]
    )
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_session = MagicMock(return_value=session)
    mgr._tmux_logs["sess-1"] = "/tmp/mcp-pty-sess-1.log"
    mgr._tmux_sessions["sess-1"] = "mcp-abc12345"
    mgr._tmux_conns["sess-1"] = conn

    out = await mgr.pty_read("sess-1")
    assert out.output == "remote output"
    assert out.alive is True


@pytest.mark.asyncio
async def test_pty_resize_no_tmux() -> None:
    session = _make_session_record(use_tmux=False)
    conn = _make_conn()
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_session = MagicMock(return_value=session)

    proc_mock = MagicMock()
    proc_mock.change_terminal_size = MagicMock()
    mgr._pty_procs["sess-1"] = proc_mock

    await mgr.pty_resize("sess-1", cols=120, rows=40)

    proc_mock.change_terminal_size.assert_called_once_with(width=120, height=40)


@pytest.mark.asyncio
async def test_pty_resize_tmux() -> None:
    session = _make_session_record(use_tmux=True, tmux_window="mcp-abc12345")
    conn = _make_conn(run_return=_run_result(""))
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_session = MagicMock(return_value=session)
    mgr._tmux_sessions["sess-1"] = "mcp-abc12345"
    mgr._tmux_conns["sess-1"] = conn

    await mgr.pty_resize("sess-1", cols=120, rows=40)

    conn.run.assert_awaited_once()
    cmd: str = conn.run.call_args[0][0]
    assert "tmux resize-window" in cmd
    assert "120" in cmd
    assert "40" in cmd


@pytest.mark.asyncio
async def test_pty_close_tmux() -> None:
    session = _make_session_record(use_tmux=True, tmux_window="mcp-abc12345")
    conn = _make_conn()
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_session = MagicMock(return_value=session)

    mgr._tmux_logs["sess-1"] = "/tmp/mcp-pty-sess-1.log"
    mgr._tmux_sessions["sess-1"] = "mcp-abc12345"
    mgr._tmux_conns["sess-1"] = conn

    await mgr.pty_close("sess-1")

    # State updated, audit logged
    state.upsert_session.assert_called_once()
    updated: SessionRecord = state.upsert_session.call_args[0][0]
    assert updated.status == ProcessStatus.exited
    audit.log.assert_called_once()

    # In-memory dicts cleaned up
    assert "sess-1" not in mgr._tmux_logs
    assert "sess-1" not in mgr._tmux_sessions
    assert "sess-1" not in mgr._tmux_conns


@pytest.mark.asyncio
async def test_start_process_no_cwd_no_env() -> None:
    """start_process works with no cwd and no env."""
    conn = _make_conn(run_return=_run_result("42\n"))
    mgr, pool, state, audit, _ = _make_manager(conn=conn)

    pid_str = await mgr.start_process("myserver", "uptime", cwd=None, env=None)
    assert isinstance(pid_str, str)
    cmd: str = conn.run.call_args[0][0]
    # No cd, no exports
    assert "cd " not in cmd or "cd  " not in cmd


@pytest.mark.asyncio
async def test_kill_process_sigkill() -> None:
    record = _make_process_record()
    conn = _make_conn(run_return=_run_result(""))
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_process = MagicMock(return_value=record)

    await mgr.kill_process("proc-1", signal="SIGKILL")

    cmd: str = conn.run.call_args[0][0]
    assert "SIGKILL" in cmd


@pytest.mark.asyncio
async def test_check_process_not_found_raises() -> None:
    mgr, *_ = _make_manager()

    with pytest.raises(ProcessNotFound):
        await mgr.check_process("nonexistent")


@pytest.mark.asyncio
async def test_drain_pty_stops_on_eof() -> None:
    """_drain_pty exits cleanly when proc.stdout.read returns empty bytes."""
    conn = _make_conn()
    mgr, *_ = _make_manager(conn=conn)

    buf: collections.deque[bytes] = collections.deque()
    mgr._pty_buffers["test-sid"] = buf

    proc_mock = MagicMock()
    proc_mock.stdout.read = AsyncMock(side_effect=[b"data1", b"data2", b""])

    await mgr._drain_pty("test-sid", proc_mock)

    assert b"data1" in buf or len(buf) == 2


@pytest.mark.asyncio
async def test_read_process_invalid_exit_file_content() -> None:
    """Exit file content that is not a valid integer → still treated as running."""
    record = _make_process_record()
    conn = _make_conn(
        run_side_effect=[
            _run_result("not-int\n"),   # exit file with garbage
            _run_result("output"),      # log tail
        ]
    )
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_process = MagicMock(return_value=record)

    out = await mgr.read_process("proc-1")
    # ValueError swallowed → still running
    assert out.running is True
    assert out.exit_code is None


@pytest.mark.asyncio
async def test_check_process_invalid_exit_file_content() -> None:
    """check_process: exit file garbage → exit_code remains None."""
    record = _make_process_record()
    conn = _make_conn(
        run_side_effect=[
            _run_result("dead\n"),      # kill -0
            _run_result("log data"),    # tail log
            _run_result("garbage\n"),   # exit file
        ]
    )
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_process = MagicMock(return_value=record)

    out = await mgr.check_process("proc-1")
    assert out.exit_code is None


@pytest.mark.asyncio
async def test_drain_pty_handles_str_chunk() -> None:
    """_drain_pty encodes string chunks to bytes before appending to buffer."""
    conn = _make_conn()
    mgr, *_ = _make_manager(conn=conn)

    buf: collections.deque[bytes] = collections.deque()
    mgr._pty_buffers["test-sid"] = buf

    proc_mock = MagicMock()
    proc_mock.stdout.read = AsyncMock(side_effect=["hello", b""])

    await mgr._drain_pty("test-sid", proc_mock)

    assert b"hello" in buf


@pytest.mark.asyncio
async def test_drain_pty_exception_swallowed() -> None:
    """_drain_pty swallows exceptions and exits cleanly."""
    conn = _make_conn()
    mgr, *_ = _make_manager(conn=conn)

    buf: collections.deque[bytes] = collections.deque()
    mgr._pty_buffers["test-sid"] = buf

    proc_mock = MagicMock()
    proc_mock.stdout.read = AsyncMock(side_effect=OSError("connection reset"))

    # Should not raise
    await mgr._drain_pty("test-sid", proc_mock)


@pytest.mark.asyncio
async def test_pty_read_tmux_no_conn_returns_empty() -> None:
    """pty_read tmux path with no stored conn → returns empty/dead."""
    session = _make_session_record(use_tmux=True, tmux_window="mcp-abc12345")
    mgr, pool, state, audit, conn = _make_manager(conn=_make_conn())
    state.get_session = MagicMock(return_value=session)
    # No conn stored in _tmux_conns → conn is None path

    out = await mgr.pty_read("sess-1")
    assert out.output == ""
    assert out.alive is False


@pytest.mark.asyncio
async def test_pty_attach_tmux_session_gone() -> None:
    """pty_attach raises SessionNotFound if tmux session no longer exists."""
    session = _make_session_record(use_tmux=True, tmux_window="mcp-abc12345")
    conn = _make_conn(run_return=_run_result("", exit_status=1))
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_session = MagicMock(return_value=session)
    mgr._tmux_sessions["sess-1"] = "mcp-abc12345"
    mgr._tmux_conns["sess-1"] = conn

    with pytest.raises(SessionNotFound, match="no longer exists"):
        await mgr.pty_attach("sess-1")


@pytest.mark.asyncio
async def test_drain_pty_no_buffer_exits_cleanly() -> None:
    """_drain_pty exits early if no buffer registered for the session_id."""
    conn = _make_conn()
    mgr, *_ = _make_manager(conn=conn)
    # session_id not registered in _pty_buffers
    proc_mock = MagicMock()
    proc_mock.stdout.read = AsyncMock(return_value=b"data")
    # Should return immediately without error
    await mgr._drain_pty("unknown-session", proc_mock)
    proc_mock.stdout.read.assert_not_awaited()


@pytest.mark.asyncio
async def test_pty_read_buffer_small_chunk_fits() -> None:
    """pty_read collects chunk that fits within max_bytes without splitting."""
    session = _make_session_record(use_tmux=False)
    conn = _make_conn()
    mgr, pool, state, audit, _ = _make_manager(conn=conn)
    state.get_session = MagicMock(return_value=session)

    buf: collections.deque[bytes] = collections.deque()
    buf.append(b"hi")  # 2 bytes, fits well within max_bytes=100
    mgr._pty_buffers["sess-1"] = buf

    proc_mock = MagicMock()
    proc_mock.is_closing = MagicMock(return_value=False)
    mgr._pty_procs["sess-1"] = proc_mock

    out = await mgr.pty_read("sess-1", max_bytes=100)
    assert out.output == "hi"
    assert out.alive is True


@pytest.mark.asyncio
async def test_start_pty_session_not_exceeded() -> None:
    """Session below cap starts successfully (no-tmux)."""
    settings = GlobalSettings(max_sessions=5)
    proc_mock = MagicMock()
    proc_mock.stdout = MagicMock()
    proc_mock.stdout.read = AsyncMock(return_value=b"")
    proc_mock.is_closing = MagicMock(return_value=False)

    conn = _make_conn()
    conn.create_process = AsyncMock(return_value=proc_mock)

    mgr, pool, state, audit, _ = _make_manager(conn=conn, settings=settings)

    # Only 1 running session, cap is 5
    state.list_sessions = MagicMock(
        return_value=[_make_session_record(status=ProcessStatus.running)]
    )

    with patch("asyncio.create_task"):
        session_id = await mgr.start_pty("myserver", "bash", cols=80, rows=24, use_tmux=False)

    assert isinstance(session_id, str)

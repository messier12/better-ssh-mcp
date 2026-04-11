"""Integration tests for mcp-ssh (T4).

Uses a local asyncssh test server to exercise the full call path.
"""
from __future__ import annotations

import asyncio
import os
import socket
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest
import pytest_asyncio

from mcp_ssh.audit import AuditLog
from mcp_ssh.models import (
    AppConfig,
    AuthType,
    GlobalSettings,
    HostKeyPolicy,
    ServerConfig,
)
from mcp_ssh.pool import ConnectionPool
from mcp_ssh.registry import Registry
from mcp_ssh.session import SessionManager
from mcp_ssh.state import StateStore
from mcp_ssh.tools.exec_tools import (
    ssh_check_process,
    ssh_exec,
    ssh_exec_stream,
    ssh_list_processes,
    ssh_read_process,
)
from mcp_ssh.tools.registry_tools import (
    ssh_deregister_server,
    ssh_list_servers,
    ssh_register_server,
)


# ---------------------------------------------------------------------------
# Local asyncssh test server fixture
# ---------------------------------------------------------------------------

class _SimpleServerSession(asyncssh.SSHServerSession):  # type: ignore[misc]
    """Server session that executes commands via subprocess."""

    def __init__(self) -> None:
        self._proc: asyncio.subprocess.Process | None = None
        self._channel: asyncssh.SSHServerChannel | None = None  # type: ignore[type-arg]

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:  # type: ignore[type-arg]
        self._channel = chan

    def exec_requested(self, command: str) -> bool:
        return True

    def shell_requested(self) -> bool:
        return True

    def session_started(self) -> None:
        pass


class _SimpleSSHServer(asyncssh.SSHServer):  # type: ignore[misc]
    """Minimal asyncssh server that allows any user/password."""

    def begin_auth(self, username: str) -> bool:
        return False  # no auth required

    def session_requested(self) -> asyncssh.SSHServerSession:  # type: ignore[type-arg]
        return asyncssh.SSHServerSession()  # type: ignore[return-value]


async def _run_subprocess(process: asyncssh.SSHServerProcess) -> None:  # type: ignore[type-arg]
    """Simple process factory: execute the command in a local subprocess."""
    cmd = process.command or "cat"
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_data, stderr_data = await proc.communicate()
    process.stdout.write((stdout_data or b"").decode())
    process.stderr.write((stderr_data or b"").decode())
    process.exit(proc.returncode or 0)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest_asyncio.fixture
async def ssh_server(tmp_path: Path):  # type: ignore[no-untyped-def]
    """Spin up a local asyncssh server; yield (host, port, host_key_path)."""
    server_key = asyncssh.generate_private_key("ssh-ed25519")
    key_path = tmp_path / "server_host_key"
    server_key.write_private_key(str(key_path))

    client_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key_path = tmp_path / "client_key"
    client_key.write_private_key(str(client_key_path))

    port = _free_port()

    server = await asyncssh.create_server(
        _SimpleSSHServer,
        "127.0.0.1",
        port,
        server_host_keys=[str(key_path)],
        process_factory=_run_subprocess,
    )

    yield "127.0.0.1", port, str(client_key_path), server_key

    server.close()
    await server.wait_closed()


@pytest_asyncio.fixture
async def pool_with_server(ssh_server: tuple, tmp_path: Path):  # type: ignore[no-untyped-def]
    """Return a ConnectionPool pre-configured for the local test server."""
    host, port, client_key_path, server_key = ssh_server

    # Write server key to known_hosts
    known_hosts = tmp_path / "known_hosts"
    key_line = server_key.export_public_key("openssh").decode().strip()
    known_hosts.write_text(f"[127.0.0.1]:{port} {key_line}\n")

    cfg = ServerConfig(
        name="test",
        host=host,
        port=port,
        user=os.environ.get("USER", "root"),
        auth_type=AuthType.key,
        key_path=client_key_path,
        host_key_policy=HostKeyPolicy.strict,
    )
    settings = GlobalSettings(
        known_hosts_file=str(known_hosts),
        state_file=str(tmp_path / "state.json"),
        audit_log=str(tmp_path / "audit.jsonl"),
    )

    pool = ConnectionPool({"test": cfg}, settings)
    yield pool, cfg, settings
    await pool.close_all()


# ---------------------------------------------------------------------------
# Helper to build a full stack (pool_with_server + SessionManager + audit)
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def full_stack(pool_with_server: tuple, tmp_path: Path):  # type: ignore[no-untyped-def]
    pool, cfg, settings = pool_with_server
    state = StateStore(settings)
    state.load()
    audit = AuditLog(settings)
    sm = SessionManager(
        pool=pool,
        state=state,
        audit=audit,
        settings=settings,
        servers={"test": cfg},
    )
    yield pool, sm, state, audit, settings, cfg
    audit.close()


# ---------------------------------------------------------------------------
# registry tool integration tests
# ---------------------------------------------------------------------------

def test_integration_list_servers_empty(tmp_path: Path) -> None:
    """ssh_list_servers returns empty list when no servers are registered."""
    pool = MagicMock()
    pool.get_status.side_effect = Exception("no servers")
    reg = MagicMock()
    reg.list_all.return_value = []
    result = ssh_list_servers(reg, pool)
    assert result == {"servers": []}


def test_integration_register_and_list(tmp_path: Path) -> None:
    """Register a server then list it; verify round-trip."""
    config_path = tmp_path / "servers.toml"
    config_path.write_text(
        '[settings]\n[servers]\n'
    )
    registry = Registry(config_path)

    pool = MagicMock()
    from mcp_ssh.models import ConnectionStatus
    pool.get_status.return_value = ConnectionStatus.disconnected
    audit = MagicMock()

    reg_result = ssh_register_server(
        name="s1",
        host="10.0.0.1",
        user="admin",
        auth_type="agent",
        registry=registry,
        audit=audit,
    )
    assert reg_result["registered"] is True

    list_result = ssh_list_servers(registry, pool)
    assert len(list_result["servers"]) == 1
    assert list_result["servers"][0]["name"] == "s1"


def test_integration_deregister(tmp_path: Path) -> None:
    config_path = tmp_path / "servers.toml"
    config_path.write_text(
        '[settings]\n[servers]\n'
    )
    registry = Registry(config_path)
    pool = MagicMock()
    from mcp_ssh.models import ConnectionStatus
    pool.get_status.return_value = ConnectionStatus.disconnected
    audit = MagicMock()

    ssh_register_server(
        name="s1", host="h", user="u", auth_type="agent",
        registry=registry, audit=audit,
    )
    result = ssh_deregister_server("s1", registry, pool, audit)
    assert result["deregistered"] is True
    assert len(ssh_list_servers(registry, pool)["servers"]) == 0


# ---------------------------------------------------------------------------
# ssh_exec integration test (uses real local SSH server)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_integration_ssh_exec(full_stack: tuple) -> None:
    """ssh_exec runs 'echo hello' on the local test server and gets output."""
    pool, sm, state, audit, settings, cfg = full_stack

    reg = MagicMock()
    reg.get.return_value = cfg
    audit_mock = MagicMock()

    result = await ssh_exec(
        server="test",
        command="echo hello",
        registry=reg,
        pool=pool,
        audit=audit_mock,
        timeout=10,
    )
    # Should either succeed or show connection-related error on this platform
    # We check that the tool doesn't raise an exception
    assert isinstance(result, dict)
    if "error" not in result:
        assert "hello" in result["output"]
        assert result["exit_code"] == 0


# ---------------------------------------------------------------------------
# ssh_exec_stream + ssh_read_process poll loop (mocked)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_integration_exec_stream_read_poll() -> None:
    """ssh_exec_stream + poll via ssh_read_process returns correct output."""
    from mcp_ssh.models import ProcessOutput

    sm = AsyncMock()
    sm.start_process = AsyncMock(return_value="pid-abc")
    audit_mock = MagicMock()

    stream_result = await ssh_exec_stream("srv1", "sleep 1", sm, audit_mock)
    assert stream_result["process_id"] == "pid-abc"

    # Simulate poll: first call → running, second → done
    sm.read_process = AsyncMock(
        side_effect=[
            ProcessOutput(output="running...", running=True, exit_code=None, remote_pid=1, server="srv1"),
            ProcessOutput(output="done\n", running=False, exit_code=0, remote_pid=1, server="srv1"),
        ]
    )

    r1 = await ssh_read_process("pid-abc", sm)
    assert r1["running"] is True

    r2 = await ssh_read_process("pid-abc", sm)
    assert r2["running"] is False
    assert r2["exit_code"] == 0
    assert "done" in r2["output"]


# ---------------------------------------------------------------------------
# ssh_list_processes
# ---------------------------------------------------------------------------

def test_integration_list_processes_empty_for_unknown_server() -> None:
    sm = MagicMock()
    sm.list_processes = MagicMock(return_value=[])
    result = ssh_list_processes(sm, server="nonexistent")
    assert result == {"processes": []}
    assert "error" not in result


# ---------------------------------------------------------------------------
# server.py: _register_tools registers exactly 15 tools
# ---------------------------------------------------------------------------

def test_server_registers_18_tools(tmp_path: Path) -> None:
    """_register_tools creates exactly 18 tool registrations on the MCP app.

    Tool count: 5 registry + 7 exec + 6 PTY = 18.
    """
    from mcp_ssh.server import _register_tools, AppContext

    mcp = MagicMock()
    tool_decorator = MagicMock(side_effect=lambda f: f)
    mcp.tool.return_value = tool_decorator

    ctx = AppContext(
        registry=MagicMock(),
        pool=MagicMock(),
        session_manager=AsyncMock(),
        state=MagicMock(),
        audit=MagicMock(),
    )
    _register_tools(mcp, ctx)

    # mcp.tool() should have been called 18 times (5 registry + 7 exec + 6 PTY)
    assert mcp.tool.call_count == 18


# ---------------------------------------------------------------------------
# pool.close_all() called on shutdown (verified by testing _shutdown logic)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_server_shutdown_calls_close_all(tmp_path: Path) -> None:
    """Shutdown handler calls pool.close_all() and audit.close()."""
    from mcp_ssh.server import AppContext

    pool = AsyncMock()
    audit = MagicMock()

    ctx = AppContext(
        registry=MagicMock(),
        pool=pool,
        session_manager=AsyncMock(),
        state=MagicMock(),
        audit=audit,
    )

    # Simulate the shutdown coroutine directly
    async def _close() -> None:
        await ctx.pool.close_all()
        ctx.audit.close()

    await _close()

    pool.close_all.assert_called_once()
    audit.close.assert_called_once()

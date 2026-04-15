"""Tests for mcp_ssh.tools.scp_tools (ssh_get / ssh_put / ssh_transfer)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest

from mcp_ssh.exceptions import McpSshError, ServerNotFound
from mcp_ssh.models import AuthType, ServerConfig
from mcp_ssh.tools.scp_tools import ssh_get, ssh_put, ssh_transfer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg(name: str = "srv1") -> ServerConfig:
    return ServerConfig(
        name=name, host="1.2.3.4", port=22, user="admin",
        auth_type=AuthType.agent,
    )


def _make_registry(*names: str) -> MagicMock:
    cfgs = {n: _cfg(n) for n in names}
    reg = MagicMock()

    def _get(name: str) -> ServerConfig:
        if name in cfgs:
            return cfgs[name]
        raise ServerNotFound(f"Not found: {name!r}")

    reg.get.side_effect = _get
    return reg


def _run_result(exit_status: int = 0, stderr: str = "") -> MagicMock:
    r = MagicMock()
    r.exit_status = exit_status
    r.stderr = stderr
    return r


def _make_conn(exit_status: int = 0, stderr: str = "") -> AsyncMock:
    conn = AsyncMock()
    conn.run = AsyncMock(return_value=_run_result(exit_status, stderr))
    return conn


def _make_pool(*conns: AsyncMock) -> AsyncMock:
    pool = AsyncMock()
    pool.get_connection = AsyncMock(side_effect=list(conns))
    return pool


def _make_audit() -> MagicMock:
    return MagicMock()


# ---------------------------------------------------------------------------
# ssh_transfer — cross-server
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_transfer_cross_server_success() -> None:
    reg = _make_registry("srv1", "srv2")
    src_conn = _make_conn()
    dst_conn = _make_conn()
    pool = _make_pool(src_conn, dst_conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock) as mock_scp:
        result = await ssh_transfer("srv1", "/src/file", "srv2", "/dst/file",
                                    registry=reg, pool=pool, audit=audit)

    assert result == {
        "src_server": "srv1", "src_path": "/src/file",
        "dst_server": "srv2", "dst_path": "/dst/file",
    }
    # single streaming scp call — no temp file
    assert mock_scp.call_count == 1
    call = mock_scp.call_args
    assert call.args[0] == (src_conn, "/src/file")
    assert call.args[1] == (dst_conn, "/dst/file")
    # audit: start + ok
    calls = [c.args[0].outcome for c in audit.log.call_args_list]
    assert calls == ["start", "ok"]


@pytest.mark.asyncio
async def test_ssh_transfer_cross_server_recurse() -> None:
    reg = _make_registry("srv1", "srv2")
    pool = _make_pool(_make_conn(), _make_conn())
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock) as mock_scp:
        await ssh_transfer("srv1", "/src/dir", "srv2", "/dst/dir",
                           registry=reg, pool=pool, audit=audit, recurse=True)

    assert mock_scp.call_count == 1
    assert mock_scp.call_args.kwargs.get("recurse") is True


# ---------------------------------------------------------------------------
# ssh_transfer — same-server
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_transfer_same_server_success() -> None:
    reg = _make_registry("srv1")
    conn = _make_conn(exit_status=0)
    pool = _make_pool(conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock) as mock_scp:
        result = await ssh_transfer("srv1", "/src/file", "srv1", "/dst/file",
                                    registry=reg, pool=pool, audit=audit)

    assert result["src_server"] == "srv1"
    assert result["dst_server"] == "srv1"
    mock_scp.assert_not_called()
    conn.run.assert_awaited_once()
    cmd = conn.run.call_args.args[0]
    assert "cp" in cmd
    assert "/src/file" in cmd
    assert "/dst/file" in cmd


@pytest.mark.asyncio
async def test_ssh_transfer_same_server_recurse_flag() -> None:
    reg = _make_registry("srv1")
    conn = _make_conn()
    pool = _make_pool(conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock):
        await ssh_transfer("srv1", "/src/dir", "srv1", "/dst/dir",
                           registry=reg, pool=pool, audit=audit, recurse=True)

    cmd = conn.run.call_args.args[0]
    assert "-r" in cmd


# ---------------------------------------------------------------------------
# ssh_transfer — error paths
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_transfer_src_server_not_found() -> None:
    reg = _make_registry("srv2")
    pool = _make_pool()
    audit = _make_audit()

    result = await ssh_transfer("missing", "/f", "srv2", "/f",
                                registry=reg, pool=pool, audit=audit)

    assert result["error"] == "server_not_found"
    assert result["server"] == "missing"
    audit.log.assert_not_called()


@pytest.mark.asyncio
async def test_ssh_transfer_dst_server_not_found() -> None:
    reg = _make_registry("srv1")
    pool = _make_pool()
    audit = _make_audit()

    result = await ssh_transfer("srv1", "/f", "missing", "/f",
                                registry=reg, pool=pool, audit=audit)

    assert result["error"] == "server_not_found"
    assert result["server"] == "missing"


@pytest.mark.asyncio
async def test_ssh_transfer_connection_error() -> None:
    reg = _make_registry("srv1", "srv2")
    pool = AsyncMock()
    pool.get_connection = AsyncMock(side_effect=McpSshError("conn failed"))
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock):
        result = await ssh_transfer("srv1", "/f", "srv2", "/f",
                                    registry=reg, pool=pool, audit=audit)

    assert result["error"] == "connection_error"
    calls = [c.args[0].outcome for c in audit.log.call_args_list]
    assert "error" in calls


@pytest.mark.asyncio
async def test_ssh_transfer_sftp_error() -> None:
    reg = _make_registry("srv1", "srv2")
    pool = _make_pool(_make_conn(), _make_conn())
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock,
               side_effect=asyncssh.SFTPError(asyncssh.FX_FAILURE, "transfer fail")):
        result = await ssh_transfer("srv1", "/f", "srv2", "/f",
                                    registry=reg, pool=pool, audit=audit)

    assert result["error"] == "transfer_error"
    calls = [c.args[0].outcome for c in audit.log.call_args_list]
    assert "error" in calls


@pytest.mark.asyncio
async def test_ssh_transfer_same_server_cp_fails() -> None:
    reg = _make_registry("srv1")
    conn = _make_conn(exit_status=1, stderr="No such file")
    pool = _make_pool(conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock):
        result = await ssh_transfer("srv1", "/missing", "srv1", "/dst",
                                    registry=reg, pool=pool, audit=audit)

    assert result["error"] == "transfer_error"


@pytest.mark.asyncio
async def test_ssh_transfer_unexpected_error() -> None:
    reg = _make_registry("srv1", "srv2")
    pool = AsyncMock()
    pool.get_connection = AsyncMock(side_effect=RuntimeError("boom"))
    audit = _make_audit()

    result = await ssh_transfer("srv1", "/f", "srv2", "/f",
                                registry=reg, pool=pool, audit=audit)

    assert result["error"] == "unexpected_error"


# ---------------------------------------------------------------------------
# ssh_get / ssh_put — basic coverage
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_get_success() -> None:
    reg = _make_registry("srv1")
    conn = AsyncMock()
    pool = AsyncMock()
    pool.get_connection = AsyncMock(return_value=conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock):
        result = await ssh_get("srv1", "/remote/file", "/local/file",
                               registry=reg, pool=pool, audit=audit)

    assert result["server"] == "srv1"
    assert result["remote_path"] == "/remote/file"
    calls = [c.args[0].outcome for c in audit.log.call_args_list]
    assert calls == ["start", "ok"]


@pytest.mark.asyncio
async def test_ssh_get_server_not_found() -> None:
    reg = _make_registry()
    pool = _make_pool()
    audit = _make_audit()

    result = await ssh_get("missing", "/f", "/local", registry=reg, pool=pool, audit=audit)

    assert result["error"] == "server_not_found"
    audit.log.assert_not_called()


@pytest.mark.asyncio
async def test_ssh_get_transfer_error() -> None:
    reg = _make_registry("srv1")
    pool = AsyncMock()
    pool.get_connection = AsyncMock(return_value=AsyncMock())
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock,
               side_effect=asyncssh.SFTPError(asyncssh.FX_FAILURE, "fail")):
        result = await ssh_get("srv1", "/f", "/local", registry=reg, pool=pool, audit=audit)

    assert result["error"] == "transfer_error"


@pytest.mark.asyncio
async def test_ssh_put_success() -> None:
    reg = _make_registry("srv1")
    pool = AsyncMock()
    pool.get_connection = AsyncMock(return_value=AsyncMock())
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock), \
         patch("os.path.expanduser", side_effect=lambda p: p):
        result = await ssh_put("srv1", "/local/file", "/remote/file",
                               registry=reg, pool=pool, audit=audit)

    assert result["server"] == "srv1"
    assert result["local_path"] == "/local/file"
    calls = [c.args[0].outcome for c in audit.log.call_args_list]
    assert calls == ["start", "ok"]


@pytest.mark.asyncio
async def test_ssh_put_server_not_found() -> None:
    reg = _make_registry()
    pool = _make_pool()
    audit = _make_audit()

    result = await ssh_put("missing", "/local", "/f", registry=reg, pool=pool, audit=audit)

    assert result["error"] == "server_not_found"
    audit.log.assert_not_called()


@pytest.mark.asyncio
async def test_ssh_put_connection_error() -> None:
    reg = _make_registry("srv1")
    pool = AsyncMock()
    pool.get_connection = AsyncMock(side_effect=McpSshError("no conn"))
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock):
        result = await ssh_put("srv1", "/local", "/remote", registry=reg, pool=pool, audit=audit)

    assert result["error"] == "connection_error"

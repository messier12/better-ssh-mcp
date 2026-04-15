"""Tests for mcp_ssh.tools.scp_tools (ssh_copy / ssh_move)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest

from mcp_ssh.exceptions import McpSshError, ServerNotFound
from mcp_ssh.models import AuthType, ServerConfig
from mcp_ssh.tools.scp_tools import ssh_copy, ssh_get, ssh_move, ssh_put

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
# ssh_copy — cross-server
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_copy_cross_server_success() -> None:
    reg = _make_registry("srv1", "srv2")
    src_conn = _make_conn()
    dst_conn = _make_conn()
    pool = _make_pool(src_conn, dst_conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock) as mock_scp:
        result = await ssh_copy("srv1", "/src/file", "srv2", "/dst/file",
                                registry=reg, pool=pool, audit=audit)

    assert result == {
        "src_server": "srv1", "src_path": "/src/file",
        "dst_server": "srv2", "dst_path": "/dst/file",
    }
    assert mock_scp.call_count == 2
    # audit: start + ok
    calls = [c.args[0].outcome for c in audit.log.call_args_list]
    assert calls == ["start", "ok"]


@pytest.mark.asyncio
async def test_ssh_copy_cross_server_recurse() -> None:
    reg = _make_registry("srv1", "srv2")
    pool = _make_pool(_make_conn(), _make_conn())
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock) as mock_scp:
        await ssh_copy("srv1", "/src/dir", "srv2", "/dst/dir",
                       registry=reg, pool=pool, audit=audit, recurse=True)

    first_call = mock_scp.call_args_list[0]
    assert first_call.kwargs.get("recurse") is True


# ---------------------------------------------------------------------------
# ssh_copy — same-server
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_copy_same_server_success() -> None:
    reg = _make_registry("srv1")
    conn = _make_conn(exit_status=0)
    pool = _make_pool(conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock) as mock_scp:
        result = await ssh_copy("srv1", "/src/file", "srv1", "/dst/file",
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
async def test_ssh_copy_same_server_recurse_flag() -> None:
    reg = _make_registry("srv1")
    conn = _make_conn()
    pool = _make_pool(conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock):
        await ssh_copy("srv1", "/src/dir", "srv1", "/dst/dir",
                       registry=reg, pool=pool, audit=audit, recurse=True)

    cmd = conn.run.call_args.args[0]
    assert "-r" in cmd


# ---------------------------------------------------------------------------
# ssh_copy — error paths
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_copy_src_server_not_found() -> None:
    reg = _make_registry("srv2")
    pool = _make_pool()
    audit = _make_audit()

    result = await ssh_copy("missing", "/f", "srv2", "/f",
                            registry=reg, pool=pool, audit=audit)

    assert result["error"] == "server_not_found"
    assert result["server"] == "missing"
    audit.log.assert_not_called()


@pytest.mark.asyncio
async def test_ssh_copy_dst_server_not_found() -> None:
    reg = _make_registry("srv1")
    pool = _make_pool()
    audit = _make_audit()

    result = await ssh_copy("srv1", "/f", "missing", "/f",
                            registry=reg, pool=pool, audit=audit)

    assert result["error"] == "server_not_found"
    assert result["server"] == "missing"


@pytest.mark.asyncio
async def test_ssh_copy_connection_error() -> None:
    reg = _make_registry("srv1", "srv2")
    pool = AsyncMock()
    pool.get_connection = AsyncMock(side_effect=McpSshError("conn failed"))
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock):
        result = await ssh_copy("srv1", "/f", "srv2", "/f",
                                registry=reg, pool=pool, audit=audit)

    assert result["error"] == "connection_error"
    calls = [c.args[0].outcome for c in audit.log.call_args_list]
    assert "error" in calls


@pytest.mark.asyncio
async def test_ssh_copy_sftp_download_error() -> None:
    reg = _make_registry("srv1", "srv2")
    pool = _make_pool(_make_conn(), _make_conn())
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock,
               side_effect=asyncssh.SFTPError(asyncssh.FX_FAILURE, "download fail")):
        result = await ssh_copy("srv1", "/f", "srv2", "/f",
                                registry=reg, pool=pool, audit=audit)

    assert result["error"] == "transfer_error"
    calls = [c.args[0].outcome for c in audit.log.call_args_list]
    assert "error" in calls


@pytest.mark.asyncio
async def test_ssh_copy_sftp_upload_error() -> None:
    reg = _make_registry("srv1", "srv2")
    pool = _make_pool(_make_conn(), _make_conn())
    audit = _make_audit()

    call_count = 0

    async def _scp_side_effect(*args: object, **kwargs: object) -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise asyncssh.SFTPError(asyncssh.FX_FAILURE, "upload fail")

    with patch("asyncssh.scp", side_effect=_scp_side_effect):
        result = await ssh_copy("srv1", "/f", "srv2", "/f",
                                registry=reg, pool=pool, audit=audit)

    assert result["error"] == "transfer_error"


# ---------------------------------------------------------------------------
# ssh_move — cross-server
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_move_cross_server_success() -> None:
    reg = _make_registry("srv1", "srv2")
    src_conn = _make_conn()
    dst_conn = _make_conn()
    pool = _make_pool(src_conn, dst_conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock):
        result = await ssh_move("srv1", "/src/file", "srv2", "/dst/file",
                                registry=reg, pool=pool, audit=audit)

    assert result == {
        "src_server": "srv1", "src_path": "/src/file",
        "dst_server": "srv2", "dst_path": "/dst/file",
    }
    # rm -rf called on src_conn
    src_conn.run.assert_awaited_once()
    cmd = src_conn.run.call_args.args[0]
    assert "rm -rf" in cmd
    assert "/src/file" in cmd
    calls = [c.args[0].outcome for c in audit.log.call_args_list]
    assert calls == ["start", "ok"]


# ---------------------------------------------------------------------------
# ssh_move — same-server
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_move_same_server_success() -> None:
    reg = _make_registry("srv1")
    conn = _make_conn(exit_status=0)
    pool = _make_pool(conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock) as mock_scp:
        result = await ssh_move("srv1", "/src/file", "srv1", "/dst/file",
                                registry=reg, pool=pool, audit=audit)

    assert result["src_server"] == "srv1"
    mock_scp.assert_not_called()
    conn.run.assert_awaited_once()
    cmd = conn.run.call_args.args[0]
    assert "mv" in cmd


# ---------------------------------------------------------------------------
# ssh_move — error paths
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_move_copy_fails_no_delete() -> None:
    reg = _make_registry("srv1", "srv2")
    src_conn = _make_conn()
    dst_conn = _make_conn()
    pool = _make_pool(src_conn, dst_conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock,
               side_effect=asyncssh.SFTPError(asyncssh.FX_FAILURE, "oops")):
        result = await ssh_move("srv1", "/src/file", "srv2", "/dst/file",
                                registry=reg, pool=pool, audit=audit)

    assert result["error"] == "transfer_error"
    # rm should NOT have been called
    src_conn.run.assert_not_awaited()


@pytest.mark.asyncio
async def test_ssh_move_copy_ok_delete_fails() -> None:
    reg = _make_registry("srv1", "srv2")
    src_conn = _make_conn(exit_status=1, stderr="Permission denied")
    dst_conn = _make_conn()
    pool = _make_pool(src_conn, dst_conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock):
        result = await ssh_move("srv1", "/src/file", "srv2", "/dst/file",
                                registry=reg, pool=pool, audit=audit)

    assert result["warning"] == "copy_succeeded_delete_failed"
    assert "delete_error" in result
    assert result["dst_server"] == "srv2"
    calls = [c.args[0].outcome for c in audit.log.call_args_list]
    assert "warn_no_timeout" in calls


# ---------------------------------------------------------------------------
# ssh_copy — same-server cp failure
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_copy_same_server_cp_fails() -> None:
    reg = _make_registry("srv1")
    conn = _make_conn(exit_status=1, stderr="No such file")
    pool = _make_pool(conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock):
        result = await ssh_copy("srv1", "/missing", "srv1", "/dst",
                                registry=reg, pool=pool, audit=audit)

    assert result["error"] == "transfer_error"


@pytest.mark.asyncio
async def test_ssh_copy_unexpected_error() -> None:
    reg = _make_registry("srv1", "srv2")
    pool = AsyncMock()
    pool.get_connection = AsyncMock(side_effect=RuntimeError("boom"))
    audit = _make_audit()

    result = await ssh_copy("srv1", "/f", "srv2", "/f",
                            registry=reg, pool=pool, audit=audit)

    assert result["error"] == "unexpected_error"


# ---------------------------------------------------------------------------
# ssh_move — server not found + same-server mv failure + unexpected error
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssh_move_src_server_not_found() -> None:
    reg = _make_registry("srv2")
    pool = _make_pool()
    audit = _make_audit()

    result = await ssh_move("missing", "/f", "srv2", "/f",
                            registry=reg, pool=pool, audit=audit)

    assert result["error"] == "server_not_found"
    assert result["server"] == "missing"


@pytest.mark.asyncio
async def test_ssh_move_dst_server_not_found() -> None:
    reg = _make_registry("srv1")
    pool = _make_pool()
    audit = _make_audit()

    result = await ssh_move("srv1", "/f", "missing", "/f",
                            registry=reg, pool=pool, audit=audit)

    assert result["error"] == "server_not_found"
    assert result["server"] == "missing"


@pytest.mark.asyncio
async def test_ssh_move_same_server_mv_fails() -> None:
    reg = _make_registry("srv1")
    conn = _make_conn(exit_status=1, stderr="Permission denied")
    pool = _make_pool(conn)
    audit = _make_audit()

    with patch("asyncssh.scp", new_callable=AsyncMock):
        result = await ssh_move("srv1", "/src", "srv1", "/dst",
                                registry=reg, pool=pool, audit=audit)

    assert result["error"] == "transfer_error"


@pytest.mark.asyncio
async def test_ssh_move_unexpected_error() -> None:
    reg = _make_registry("srv1", "srv2")
    pool = AsyncMock()
    pool.get_connection = AsyncMock(side_effect=RuntimeError("boom"))
    audit = _make_audit()

    result = await ssh_move("srv1", "/f", "srv2", "/f",
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

"""Tests for mcp_ssh.tools.proxy_tools (ssh_proxy) and mcp_ssh.proxy.ProxyManager."""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_ssh.exceptions import McpSshError, ProxyNotFound
from mcp_ssh.models import ProxyRecord, ProxyType
from mcp_ssh.proxy import ProxyManager
from mcp_ssh.tools.proxy_tools import ssh_proxy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _record(
    proxy_id: str = "prx-abc123",
    server: str = "gateway",
    proxy_type: ProxyType = ProxyType.local,
    remote_host: str | None = "192.168.1.50",
    remote_port: int | None = 8080,
) -> ProxyRecord:
    return ProxyRecord(
        id=proxy_id,
        server=server,
        type=proxy_type,
        local_host="127.0.0.1",
        local_port=8080,
        remote_host=remote_host,
        remote_port=remote_port,
        started_at=datetime.now(UTC),
    )


def _proxy_manager_mock() -> MagicMock:
    pm = MagicMock()
    pm.start_proxy = AsyncMock()
    pm.stop_proxy = AsyncMock()
    pm.list_proxies = MagicMock(return_value=[])
    return pm


# ---------------------------------------------------------------------------
# ssh_proxy tool — start
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssh_proxy_start_local() -> None:
    pm = _proxy_manager_mock()
    pm.start_proxy.return_value = _record()
    audit = MagicMock()

    result = await ssh_proxy(
        action="start",
        proxy_manager=pm,
        audit=audit,
        server="gateway",
        proxy_type_str="local",
        local_port=8080,
        remote_host="192.168.1.50",
        remote_port=8080,
    )

    assert result["proxy_id"] == "prx-abc123"
    assert result["server"] == "gateway"
    assert result["type"] == "local"
    assert result["local_host"] == "127.0.0.1"
    assert result["local_port"] == 8080
    assert result["remote_host"] == "192.168.1.50"
    assert result["remote_port"] == 8080
    assert "started_at" in result
    pm.start_proxy.assert_awaited_once()


@pytest.mark.asyncio
async def test_ssh_proxy_start_socks5() -> None:
    pm = _proxy_manager_mock()
    pm.start_proxy.return_value = _record(
        proxy_type=ProxyType.socks5, remote_host=None, remote_port=None
    )
    audit = MagicMock()

    result = await ssh_proxy(
        action="start",
        proxy_manager=pm,
        audit=audit,
        server="gateway",
        proxy_type_str="socks5",
        local_port=8080,
    )

    assert result["type"] == "socks5"
    assert result["remote_host"] is None
    assert result["remote_port"] is None
    assert result["proxy_id"] == "prx-abc123"


@pytest.mark.asyncio
async def test_ssh_proxy_start_missing_server() -> None:
    pm = _proxy_manager_mock()
    result = await ssh_proxy(
        action="start",
        proxy_manager=pm,
        audit=MagicMock(),
        proxy_type_str="local",
        local_port=8080,
    )
    assert result["error"] == "missing_param"
    pm.start_proxy.assert_not_awaited()


@pytest.mark.asyncio
async def test_ssh_proxy_start_missing_local_port() -> None:
    pm = _proxy_manager_mock()
    result = await ssh_proxy(
        action="start",
        proxy_manager=pm,
        audit=MagicMock(),
        server="gateway",
        proxy_type_str="local",
    )
    assert result["error"] == "missing_param"
    assert "local_port" in result["message"]


@pytest.mark.asyncio
async def test_ssh_proxy_start_local_missing_remote_host() -> None:
    pm = _proxy_manager_mock()
    # ProxyManager raises McpSshError when remote_host/remote_port missing.
    pm.start_proxy.side_effect = McpSshError(
        "type='local' requires remote_host and remote_port"
    )
    result = await ssh_proxy(
        action="start",
        proxy_manager=pm,
        audit=MagicMock(),
        server="gateway",
        proxy_type_str="local",
        local_port=8080,
    )
    assert result["error"] == "proxy_error"
    assert "remote_host" in result["message"]


@pytest.mark.asyncio
async def test_ssh_proxy_start_unexpected_error() -> None:
    pm = _proxy_manager_mock()
    pm.start_proxy.side_effect = RuntimeError("boom")
    result = await ssh_proxy(
        action="start",
        proxy_manager=pm,
        audit=MagicMock(),
        server="gateway",
        proxy_type_str="socks5",
        local_port=8080,
    )
    assert result["error"] == "unexpected_error"
    assert "boom" in result["message"]


@pytest.mark.asyncio
async def test_ssh_proxy_start_invalid_type() -> None:
    pm = _proxy_manager_mock()
    result = await ssh_proxy(
        action="start",
        proxy_manager=pm,
        audit=MagicMock(),
        server="gateway",
        proxy_type_str="bogus",
        local_port=8080,
    )
    assert result["error"] == "invalid_type"
    pm.start_proxy.assert_not_awaited()


# ---------------------------------------------------------------------------
# ssh_proxy tool — stop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssh_proxy_stop_ok() -> None:
    pm = _proxy_manager_mock()
    pm.stop_proxy.return_value = _record()
    result = await ssh_proxy(
        action="stop",
        proxy_manager=pm,
        audit=MagicMock(),
        proxy_id="prx-abc123",
    )
    assert result == {"stopped": True, "proxy_id": "prx-abc123"}
    pm.stop_proxy.assert_awaited_once()


@pytest.mark.asyncio
async def test_ssh_proxy_stop_missing_id() -> None:
    pm = _proxy_manager_mock()
    result = await ssh_proxy(
        action="stop",
        proxy_manager=pm,
        audit=MagicMock(),
    )
    assert result["error"] == "missing_param"
    pm.stop_proxy.assert_not_awaited()


@pytest.mark.asyncio
async def test_ssh_proxy_stop_not_found() -> None:
    pm = _proxy_manager_mock()
    pm.stop_proxy.side_effect = ProxyNotFound("Proxy 'prx-x' not found.")
    result = await ssh_proxy(
        action="stop",
        proxy_manager=pm,
        audit=MagicMock(),
        proxy_id="prx-x",
    )
    assert result["error"] == "proxy_not_found"
    assert result["proxy_id"] == "prx-x"


# ---------------------------------------------------------------------------
# ssh_proxy tool — list / invalid
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssh_proxy_list_all() -> None:
    pm = _proxy_manager_mock()
    pm.list_proxies.return_value = [
        _record("prx-1", server="a"),
        _record("prx-2", server="b", proxy_type=ProxyType.socks5,
                remote_host=None, remote_port=None),
    ]
    result = await ssh_proxy(
        action="list",
        proxy_manager=pm,
        audit=MagicMock(),
    )
    assert len(result["proxies"]) == 2
    assert result["proxies"][0]["proxy_id"] == "prx-1"
    assert result["proxies"][1]["type"] == "socks5"
    assert result["proxies"][0]["status"] == "active"
    pm.list_proxies.assert_called_once_with(server=None)


@pytest.mark.asyncio
async def test_ssh_proxy_list_filtered() -> None:
    pm = _proxy_manager_mock()
    pm.list_proxies.return_value = [_record("prx-1", server="a")]
    result = await ssh_proxy(
        action="list",
        proxy_manager=pm,
        audit=MagicMock(),
        server="a",
    )
    assert len(result["proxies"]) == 1
    pm.list_proxies.assert_called_once_with(server="a")


@pytest.mark.asyncio
async def test_ssh_proxy_invalid_action() -> None:
    pm = _proxy_manager_mock()
    result = await ssh_proxy(
        action="frobnicate",
        proxy_manager=pm,
        audit=MagicMock(),
    )
    assert result["error"] == "invalid_action"
    assert result["action"] == "frobnicate"


# ---------------------------------------------------------------------------
# ProxyManager unit tests (mocked pool / connection / listener)
# ---------------------------------------------------------------------------


def _pool_and_conn() -> tuple[MagicMock, MagicMock, MagicMock]:
    listener = MagicMock()
    listener.close = MagicMock()
    listener.wait_closed = AsyncMock()

    conn = MagicMock()
    conn.forward_local_port = AsyncMock(return_value=listener)
    conn.forward_socks = AsyncMock(return_value=listener)

    pool = MagicMock()
    pool.get_connection = AsyncMock(return_value=conn)
    pool.pin = MagicMock()
    pool.unpin = MagicMock()
    return pool, conn, listener


@pytest.mark.asyncio
async def test_manager_start_local_pins_and_forwards() -> None:
    pool, conn, _ = _pool_and_conn()
    pm = ProxyManager(pool=pool)
    audit = MagicMock()

    record = await pm.start_proxy(
        server="gateway",
        proxy_type=ProxyType.local,
        local_port=8080,
        local_host="127.0.0.1",
        remote_host="192.168.1.50",
        remote_port=8080,
        audit=audit,
    )

    assert record.id.startswith("prx-")
    assert record.server == "gateway"
    pool.pin.assert_called_once_with("gateway")
    conn.forward_local_port.assert_awaited_once_with(
        "127.0.0.1", 8080, "192.168.1.50", 8080
    )
    audit.log.assert_called_once()
    # audit event must never leak sensitive material; detail is structural only
    event = audit.log.call_args[0][0]
    assert event.proxy_id == record.id
    assert event.outcome == "started"


@pytest.mark.asyncio
async def test_manager_start_socks5() -> None:
    pool, conn, _ = _pool_and_conn()
    pm = ProxyManager(pool=pool)

    record = await pm.start_proxy(
        server="gateway",
        proxy_type=ProxyType.socks5,
        local_port=1080,
        local_host="127.0.0.1",
        remote_host=None,
        remote_port=None,
        audit=MagicMock(),
    )

    assert record.type == ProxyType.socks5
    conn.forward_socks.assert_awaited_once_with("127.0.0.1", 1080)


@pytest.mark.asyncio
async def test_manager_start_local_missing_remote_unpins() -> None:
    pool, conn, _ = _pool_and_conn()
    pm = ProxyManager(pool=pool)

    with pytest.raises(McpSshError):
        await pm.start_proxy(
            server="gateway",
            proxy_type=ProxyType.local,
            local_port=8080,
            local_host="127.0.0.1",
            remote_host=None,
            remote_port=None,
            audit=MagicMock(),
        )
    pool.pin.assert_called_once_with("gateway")
    pool.unpin.assert_called_once_with("gateway")
    conn.forward_local_port.assert_not_awaited()


@pytest.mark.asyncio
async def test_manager_stop_closes_and_unpins() -> None:
    pool, _, listener = _pool_and_conn()
    pm = ProxyManager(pool=pool)
    audit = MagicMock()

    record = await pm.start_proxy(
        server="gateway",
        proxy_type=ProxyType.socks5,
        local_port=1080,
        local_host="127.0.0.1",
        remote_host=None,
        remote_port=None,
        audit=audit,
    )

    stopped = await pm.stop_proxy(record.id, audit=audit)
    assert stopped.status == "stopped"
    listener.close.assert_called_once()
    listener.wait_closed.assert_awaited_once()
    pool.unpin.assert_called_with("gateway")


@pytest.mark.asyncio
async def test_manager_stop_not_found_raises() -> None:
    pool, _, _ = _pool_and_conn()
    pm = ProxyManager(pool=pool)
    with pytest.raises(ProxyNotFound):
        await pm.stop_proxy("prx-nope", audit=MagicMock())


@pytest.mark.asyncio
async def test_manager_list_and_filter() -> None:
    pool, _, _ = _pool_and_conn()
    pm = ProxyManager(pool=pool)
    await pm.start_proxy(
        server="a", proxy_type=ProxyType.socks5, local_port=1,
        local_host="127.0.0.1", remote_host=None, remote_port=None,
        audit=MagicMock(),
    )
    await pm.start_proxy(
        server="b", proxy_type=ProxyType.socks5, local_port=2,
        local_host="127.0.0.1", remote_host=None, remote_port=None,
        audit=MagicMock(),
    )
    assert len(pm.list_proxies()) == 2
    assert len(pm.list_proxies(server="a")) == 1
    assert pm.list_proxies(server="a")[0].server == "a"


@pytest.mark.asyncio
async def test_manager_close_all() -> None:
    pool, _, listener = _pool_and_conn()
    pm = ProxyManager(pool=pool)
    await pm.start_proxy(
        server="a", proxy_type=ProxyType.socks5, local_port=1,
        local_host="127.0.0.1", remote_host=None, remote_port=None,
        audit=MagicMock(),
    )
    await pm.close_all()
    listener.close.assert_called()
    pool.unpin.assert_called_with("a")
    assert pm.list_proxies() == []


@pytest.mark.asyncio
async def test_manager_close_all_swallows_wait_closed_error() -> None:
    pool, _, listener = _pool_and_conn()
    listener.wait_closed.side_effect = RuntimeError("already gone")
    pm = ProxyManager(pool=pool)
    await pm.start_proxy(
        server="a", proxy_type=ProxyType.socks5, local_port=1,
        local_host="127.0.0.1", remote_host=None, remote_port=None,
        audit=MagicMock(),
    )
    # Must not raise even if wait_closed fails.
    await pm.close_all()
    assert pm.list_proxies() == []

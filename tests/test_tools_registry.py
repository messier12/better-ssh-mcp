"""Tests for mcp_ssh.tools.registry_tools (T3a)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_ssh.exceptions import ServerAlreadyExists, ServerNotFound
from mcp_ssh.models import (
    AppConfig,
    AuthType,
    ConnectionStatus,
    GlobalSettings,
    ServerConfig,
)
from mcp_ssh.tools.registry_tools import (
    async_ssh_add_known_host,
    ssh_deregister_server,
    ssh_list_servers,
    ssh_register_server,
    ssh_show_known_host,
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
    )


def _make_registry(servers: list[ServerConfig] | None = None) -> MagicMock:
    reg = MagicMock()
    _servers = {s.name: s for s in (servers or [])}
    reg.list_all.return_value = list(_servers.values())
    reg.get_config.return_value = AppConfig(
        settings=GlobalSettings(
            known_hosts_file="/tmp/test_known_hosts"
        )
    )

    def _get(name: str) -> ServerConfig:
        if name in _servers:
            return _servers[name]
        raise ServerNotFound(f"Not found: {name!r}")

    reg.get.side_effect = _get
    return reg


def _make_pool(status: ConnectionStatus = ConnectionStatus.disconnected) -> MagicMock:
    pool = MagicMock()
    pool.get_status.return_value = status
    return pool


def _make_audit() -> MagicMock:
    return MagicMock()


# ---------------------------------------------------------------------------
# ssh_list_servers
# ---------------------------------------------------------------------------

def test_list_servers_empty() -> None:
    reg = _make_registry()
    pool = _make_pool()
    result = ssh_list_servers(reg, pool)
    assert result == {"servers": []}


def test_list_servers_shows_status() -> None:
    cfg = _cfg("s1")
    reg = _make_registry([cfg])
    pool = _make_pool(ConnectionStatus.connected)
    result = ssh_list_servers(reg, pool)
    assert len(result["servers"]) == 1
    entry = result["servers"][0]
    assert entry["name"] == "s1"
    assert entry["status"] == "connected"
    assert entry["host"] == "1.2.3.4"


def test_list_servers_unknown_from_pool() -> None:
    """Pool.get_status raising ServerNotFound → status = 'unknown'."""
    cfg = _cfg("s1")
    reg = _make_registry([cfg])
    pool = MagicMock()
    pool.get_status.side_effect = ServerNotFound("nope")
    result = ssh_list_servers(reg, pool)
    assert result["servers"][0]["status"] == "unknown"


def test_list_servers_multiple() -> None:
    cfgs = [_cfg("a"), _cfg("b"), _cfg("c")]
    reg = _make_registry(cfgs)
    pool = _make_pool()
    result = ssh_list_servers(reg, pool)
    assert len(result["servers"]) == 3


def test_list_servers_includes_note_when_set() -> None:
    cfg = ServerConfig(
        name="noted", host="1.2.3.4", port=22, user="admin",
        auth_type=AuthType.agent,
        note="Windows 11, solan user, no sudo",
    )
    reg = _make_registry([cfg])
    pool = _make_pool()
    result = ssh_list_servers(reg, pool)
    assert result["servers"][0]["note"] == "Windows 11, solan user, no sudo"


def test_list_servers_note_is_none_when_unset() -> None:
    reg = _make_registry([_cfg("s1")])
    pool = _make_pool()
    result = ssh_list_servers(reg, pool)
    assert result["servers"][0]["note"] is None


# ---------------------------------------------------------------------------
# ssh_register_server
# ---------------------------------------------------------------------------

def test_register_new_server() -> None:
    reg = _make_registry()
    audit = _make_audit()
    result = ssh_register_server(
        name="new",
        host="10.0.0.1",
        user="root",
        auth_type="agent",
        registry=reg,
        audit=audit,
    )
    assert result["registered"] is True
    assert result["server"] == "new"
    reg.add.assert_called_once()
    audit.log.assert_called_once()


def test_register_with_note() -> None:
    reg = _make_registry()
    audit = _make_audit()
    result = ssh_register_server(
        name="ci",
        host="10.0.0.2",
        user="solan",
        auth_type="key",
        registry=reg,
        audit=audit,
        note="Windows 11 CI runner",
    )
    assert result["registered"] is True
    cfg_saved: ServerConfig = reg.add.call_args.args[0]
    assert cfg_saved.note == "Windows 11 CI runner"


def test_register_duplicate_returns_error() -> None:
    reg = _make_registry([_cfg("existing")])
    audit = _make_audit()
    result = ssh_register_server(
        name="existing",
        host="10.0.0.1",
        user="root",
        auth_type="agent",
        registry=reg,
        audit=audit,
    )
    assert result["error"] == "server_already_exists"
    reg.add.assert_not_called()
    audit.log.assert_not_called()


def test_register_invalid_auth_type_returns_error() -> None:
    reg = _make_registry()
    audit = _make_audit()
    result = ssh_register_server(
        name="bad",
        host="10.0.0.1",
        user="root",
        auth_type="not_a_valid_type",
        registry=reg,
        audit=audit,
    )
    assert result["error"] == "invalid_config"


def test_register_audit_event_logged() -> None:
    reg = _make_registry()
    audit = _make_audit()
    ssh_register_server(
        name="s",
        host="h",
        user="u",
        auth_type="agent",
        registry=reg,
        audit=audit,
    )
    assert audit.log.call_count == 1


# ---------------------------------------------------------------------------
# ssh_deregister_server
# ---------------------------------------------------------------------------

def test_deregister_existing_server() -> None:
    reg = _make_registry([_cfg("s1")])
    pool = _make_pool()
    audit = _make_audit()
    result = ssh_deregister_server("s1", reg, pool, audit)
    assert result["deregistered"] is True
    reg.remove.assert_called_once_with("s1")
    audit.log.assert_called_once()


def test_deregister_nonexistent_returns_error() -> None:
    reg = _make_registry()
    pool = _make_pool()
    audit = _make_audit()
    result = ssh_deregister_server("ghost", reg, pool, audit)
    assert result["error"] == "server_not_found"
    reg.remove.assert_not_called()


def test_deregister_with_active_connection_returns_warning() -> None:
    reg = _make_registry([_cfg("s1")])
    pool = _make_pool(ConnectionStatus.connected)
    audit = _make_audit()
    result = ssh_deregister_server("s1", reg, pool, audit)
    assert result["deregistered"] is True
    assert "warning" in result


def test_deregister_without_active_connection_no_warning() -> None:
    reg = _make_registry([_cfg("s1")])
    pool = _make_pool(ConnectionStatus.disconnected)
    audit = _make_audit()
    result = ssh_deregister_server("s1", reg, pool, audit)
    assert "warning" not in result


# ---------------------------------------------------------------------------
# ssh_show_known_host
# ---------------------------------------------------------------------------

def test_show_known_host_file_missing() -> None:
    reg = _make_registry([_cfg("s1")])
    with patch("asyncssh.read_known_hosts", side_effect=OSError("no file")):
        result = ssh_show_known_host("s1", reg)
    assert result["known"] is False


def test_show_known_host_server_not_found() -> None:
    reg = _make_registry()
    result = ssh_show_known_host("ghost", reg)
    assert result["error"] == "server_not_found"


def test_show_known_host_no_entry() -> None:
    reg = _make_registry([_cfg("s1")])
    mock_kh = MagicMock()
    mock_kh.match.return_value = ([], [], None, None, None, None, None)
    with patch("asyncssh.read_known_hosts", return_value=mock_kh):
        result = ssh_show_known_host("s1", reg)
    assert result["known"] is False


def test_show_known_host_with_entry() -> None:
    reg = _make_registry([_cfg("s1")])
    mock_key = MagicMock()
    mock_key.get_algorithm.return_value = "ssh-ed25519"
    mock_key.get_fingerprint.return_value = "SHA256:abc123"
    mock_kh = MagicMock()
    mock_kh.match.return_value = ([mock_key], [], None, None, None, None, None)
    with patch("asyncssh.read_known_hosts", return_value=mock_kh):
        result = ssh_show_known_host("s1", reg)
    assert result["known"] is True
    assert len(result["keys"]) == 1
    assert result["keys"][0]["algorithm"] == "ssh-ed25519"


# ---------------------------------------------------------------------------
# async_ssh_add_known_host
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_async_add_known_host_server_not_found() -> None:
    reg = _make_registry()
    pool = AsyncMock()
    audit = _make_audit()
    result = await async_ssh_add_known_host("ghost", reg, pool, audit)
    assert result["error"] == "server_not_found"


@pytest.mark.asyncio
async def test_async_add_known_host_records_key(tmp_path: Path) -> None:

    kh_file = tmp_path / "known_hosts"
    reg = _make_registry([_cfg("s1")])
    reg.get_config.return_value = AppConfig(
        settings=GlobalSettings(known_hosts_file=str(kh_file))
    )

    mock_key = MagicMock()
    mock_key.export_public_key.return_value = b"ssh-ed25519 AAAA fake_key\n"

    mock_conn = MagicMock()  # sync MagicMock so get_server_host_key() returns a value directly
    mock_conn.get_server_host_key.return_value = mock_key

    pool = AsyncMock()
    pool.get_connection = AsyncMock(return_value=mock_conn)
    audit = _make_audit()

    result = await async_ssh_add_known_host("s1", reg, pool, audit)
    assert "error" not in result
    assert result["key_already_known"] is False
    assert kh_file.exists()
    audit.log.assert_called_once()


@pytest.mark.asyncio
async def test_async_add_known_host_already_present(tmp_path: Path) -> None:

    kh_file = tmp_path / "known_hosts"
    kh_file.write_text("1.2.3.4 ssh-ed25519 AAAA fake_key\n")

    reg = _make_registry([_cfg("s1")])
    reg.get_config.return_value = AppConfig(
        settings=GlobalSettings(known_hosts_file=str(kh_file))
    )

    mock_key = MagicMock()
    mock_key.export_public_key.return_value = b"ssh-ed25519 AAAA fake_key\n"

    mock_conn = MagicMock()  # sync so get_server_host_key() returns directly
    mock_conn.get_server_host_key.return_value = mock_key

    pool = AsyncMock()
    pool.get_connection = AsyncMock(return_value=mock_conn)
    audit = _make_audit()

    result = await async_ssh_add_known_host("s1", reg, pool, audit)
    assert result["key_already_known"] is True

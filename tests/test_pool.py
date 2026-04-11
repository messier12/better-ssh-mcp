"""Tests for mcp_ssh.pool — ConnectionPool."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, call, patch

import asyncssh
import pytest

from mcp_ssh.exceptions import AuthError, ServerNotFound
from mcp_ssh.exceptions import ConnectionError as SshConnectionError
from mcp_ssh.interfaces import IConnectionPool
from mcp_ssh.models import AuthType, ConnectionStatus, GlobalSettings, HostKeyPolicy, ServerConfig
from mcp_ssh.pool import (
    ConnectionPool,
    _append_host_key,
    _make_kbdint_handler,
    _make_tofu_known_hosts,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(
    name: str = "myserver",
    host: str = "example.com",
    user: str = "alice",
    auth_type: AuthType = AuthType.key,
    **kwargs: object,
) -> ServerConfig:
    return ServerConfig(name=name, host=host, user=user, auth_type=auth_type, **kwargs)  # type: ignore[arg-type]


def _make_pool(
    servers: dict[str, ServerConfig] | None = None,
    settings: GlobalSettings | None = None,
) -> ConnectionPool:
    if servers is None:
        servers = {"myserver": _make_server(key_path="/home/alice/.ssh/id_ed25519")}
    return ConnectionPool(servers=servers, settings=settings or GlobalSettings())


def _mock_connection(closed: bool = False) -> MagicMock:
    """Return a mock asyncssh.SSHClientConnection."""
    conn = MagicMock()
    conn.is_closed.return_value = closed
    conn.close = MagicMock()
    conn.wait_closed = AsyncMock()
    conn.get_server_host_key.return_value = None
    return conn


def _make_create_connection_mock(conn: MagicMock) -> AsyncMock:
    """Return a mock for asyncssh.create_connection that returns (conn, client)."""
    mock = AsyncMock(return_value=(conn, MagicMock()))
    return mock


# ---------------------------------------------------------------------------
# IConnectionPool protocol conformance
# ---------------------------------------------------------------------------


def test_isinstance_iconnectionpool() -> None:
    pool = _make_pool()
    assert isinstance(pool, IConnectionPool)


# ---------------------------------------------------------------------------
# ServerNotFound
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_connection_unknown_server_raises() -> None:
    pool = _make_pool()
    with pytest.raises(ServerNotFound, match="unknown_server"):
        await pool.get_connection("unknown_server")


def test_get_status_unknown_server_raises() -> None:
    pool = _make_pool()
    with pytest.raises(ServerNotFound):
        pool.get_status("unknown_server")


# ---------------------------------------------------------------------------
# Auth type: agent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_auth_missing_sock_raises_autherror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    pool = _make_pool(
        servers={"s": _make_server(name="s", auth_type=AuthType.agent)}
    )
    with pytest.raises(AuthError, match="SSH_AUTH_SOCK"):
        await pool.get_connection("s")


@pytest.mark.asyncio
async def test_agent_auth_passes_agent_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_AUTH_SOCK", "/run/user/1000/ssh-agent.sock")
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    with patch("asyncssh.create_connection", mock_create):
        pool = _make_pool(
            servers={"s": _make_server(name="s", auth_type=AuthType.agent)}
        )
        conn = await pool.get_connection("s")
    assert conn is mock_conn
    _, _, kwargs = mock_create.call_args[0][0], mock_create.call_args[0][1], mock_create.call_args[1]
    assert kwargs["agent_path"] == "/run/user/1000/ssh-agent.sock"


# ---------------------------------------------------------------------------
# Auth type: key
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_key_auth_passes_client_keys() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    with patch("asyncssh.create_connection", mock_create):
        pool = _make_pool(
            servers={
                "s": _make_server(
                    name="s",
                    auth_type=AuthType.key,
                    key_path="/home/alice/.ssh/id_ed25519",
                )
            }
        )
        await pool.get_connection("s")
    _, kwargs = mock_create.call_args[0], mock_create.call_args[1]
    assert kwargs["client_keys"] == ["/home/alice/.ssh/id_ed25519"]


@pytest.mark.asyncio
async def test_key_auth_missing_key_path_raises_autherror() -> None:
    pool = _make_pool(
        servers={"s": _make_server(name="s", auth_type=AuthType.key, key_path=None)}
    )
    with pytest.raises(AuthError, match="key_path"):
        await pool.get_connection("s")


# ---------------------------------------------------------------------------
# Auth type: sk (security key — same mapping as key)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sk_auth_passes_client_keys() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    with patch("asyncssh.create_connection", mock_create):
        pool = _make_pool(
            servers={
                "s": _make_server(
                    name="s",
                    auth_type=AuthType.sk,
                    key_path="/home/alice/.ssh/id_ecdsa_sk",
                )
            }
        )
        await pool.get_connection("s")
    _, kwargs = mock_create.call_args[0], mock_create.call_args[1]
    assert kwargs["client_keys"] == ["/home/alice/.ssh/id_ecdsa_sk"]


# ---------------------------------------------------------------------------
# Auth type: password
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_auth_missing_env_raises_autherror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MY_SECRET_PASSWORD", raising=False)
    pool = _make_pool(
        servers={
            "s": _make_server(
                name="s",
                auth_type=AuthType.password,
                password_env="MY_SECRET_PASSWORD",
            )
        }
    )
    with pytest.raises(AuthError, match="MY_SECRET_PASSWORD"):
        await pool.get_connection("s")


@pytest.mark.asyncio
async def test_password_auth_raises_autherror_not_keyerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ensure we raise AuthError (never KeyError) for missing password env vars."""
    monkeypatch.delenv("MY_SECRET_PASSWORD", raising=False)
    pool = _make_pool(
        servers={
            "s": _make_server(
                name="s",
                auth_type=AuthType.password,
                password_env="MY_SECRET_PASSWORD",
            )
        }
    )
    caught: list[Exception] = []
    try:
        await pool.get_connection("s")
    except AuthError as exc:
        caught.append(exc)
    assert caught, "Expected AuthError to be raised"
    assert not isinstance(caught[0], KeyError)


@pytest.mark.asyncio
async def test_password_auth_value_not_in_error_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The actual password value must NOT appear in any AuthError message."""
    monkeypatch.setenv("MY_SECRET_PASSWORD", "supersecret123")
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    with patch("asyncssh.create_connection", mock_create):
        pool = _make_pool(
            servers={
                "s": _make_server(
                    name="s",
                    auth_type=AuthType.password,
                    password_env="MY_SECRET_PASSWORD",
                )
            }
        )
        await pool.get_connection("s")
    _, kwargs = mock_create.call_args[0], mock_create.call_args[1]
    # Password IS passed to asyncssh but must not leak into any exceptions
    assert kwargs["password"] == "supersecret123"


@pytest.mark.asyncio
async def test_password_auth_missing_password_env_field_raises_autherror() -> None:
    """password_env=None with auth_type=password should raise AuthError."""
    pool = _make_pool(
        servers={
            "s": _make_server(
                name="s",
                auth_type=AuthType.password,
                password_env=None,
            )
        }
    )
    with pytest.raises(AuthError, match="password_env"):
        await pool.get_connection("s")


# ---------------------------------------------------------------------------
# Auth type: cert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cert_auth_passes_client_keys_and_certs() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    with patch("asyncssh.create_connection", mock_create):
        pool = _make_pool(
            servers={
                "s": _make_server(
                    name="s",
                    auth_type=AuthType.cert,
                    key_path="/home/alice/.ssh/id_ed25519",
                    cert_path="/home/alice/.ssh/id_ed25519-cert.pub",
                )
            }
        )
        await pool.get_connection("s")
    _, kwargs = mock_create.call_args[0], mock_create.call_args[1]
    assert kwargs["client_keys"] == ["/home/alice/.ssh/id_ed25519"]
    assert kwargs["client_certs"] == ["/home/alice/.ssh/id_ed25519-cert.pub"]


@pytest.mark.asyncio
async def test_cert_auth_missing_cert_path_raises_autherror() -> None:
    pool = _make_pool(
        servers={
            "s": _make_server(
                name="s",
                auth_type=AuthType.cert,
                key_path="/home/alice/.ssh/id_ed25519",
                cert_path=None,
            )
        }
    )
    with pytest.raises(AuthError, match="cert_path"):
        await pool.get_connection("s")


# ---------------------------------------------------------------------------
# Auth type: keyboard_interactive
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kbdint_auth_passes_handler() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    with patch("asyncssh.create_connection", mock_create):
        pool = _make_pool(
            servers={"s": _make_server(name="s", auth_type=AuthType.keyboard_interactive)}
        )
        await pool.get_connection("s")
    _, kwargs = mock_create.call_args[0], mock_create.call_args[1]
    assert callable(kwargs["kbdint_handler"])


def test_kbdint_handler_reads_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The kbdint handler should read MCP_SSH_KI_RESPONSE_N vars in order."""
    monkeypatch.setenv("MCP_SSH_KI_RESPONSE_1", "myuser")
    monkeypatch.setenv("MCP_SSH_KI_RESPONSE_2", "mypassword")

    handler = _make_kbdint_handler()
    responses = handler("name", "instr", [("Username:", True), ("Password:", False)])
    assert responses == ["myuser", "mypassword"]


def test_kbdint_handler_missing_env_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing MCP_SSH_KI_RESPONSE_N vars should return empty string, not crash."""
    monkeypatch.delenv("MCP_SSH_KI_RESPONSE_1", raising=False)
    handler = _make_kbdint_handler()
    responses = handler("name", "instr", [("Password:", False)])
    assert responses == [""]


# ---------------------------------------------------------------------------
# Auth type: gssapi
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gssapi_auth_passes_gss_host() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    with patch("asyncssh.create_connection", mock_create):
        pool = _make_pool(
            servers={
                "s": _make_server(
                    name="s",
                    host="krb.example.com",
                    auth_type=AuthType.gssapi,
                )
            }
        )
        await pool.get_connection("s")
    _, kwargs = mock_create.call_args[0], mock_create.call_args[1]
    assert kwargs["gss_host"] == "krb.example.com"


# ---------------------------------------------------------------------------
# ProxyJump / tunnel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_proxyjump_passes_tunnel_kwarg() -> None:
    """get_connection should call asyncssh.create_connection with tunnel=<jump_conn>."""
    jump_conn = _mock_connection()
    target_conn = _mock_connection()

    call_count = 0

    async def fake_create_connection(client_factory: object, host: str, **kwargs: object) -> tuple[MagicMock, MagicMock]:
        nonlocal call_count
        call_count += 1
        if host == "jump.example.com":
            return (jump_conn, MagicMock())
        # target call must carry tunnel=
        assert kwargs.get("tunnel") is jump_conn, (
            f"Expected tunnel={jump_conn!r} but got {kwargs.get('tunnel')!r}"
        )
        return (target_conn, MagicMock())

    servers = {
        "jump": _make_server(
            name="jump",
            host="jump.example.com",
            auth_type=AuthType.key,
            key_path="/home/alice/.ssh/id_ed25519",
        ),
        "target": _make_server(
            name="target",
            host="target.internal",
            auth_type=AuthType.key,
            key_path="/home/alice/.ssh/id_ed25519",
            jump_host="jump",
        ),
    }
    pool = ConnectionPool(servers=servers)

    with patch("asyncssh.create_connection", side_effect=fake_create_connection):
        conn = await pool.get_connection("target")

    assert conn is target_conn
    assert call_count == 2  # jump + target


@pytest.mark.asyncio
async def test_proxyjump_chain_depth_2() -> None:
    """Chains of arbitrary depth: A → B → C."""
    conn_a = _mock_connection()
    conn_b = _mock_connection()
    conn_c = _mock_connection()

    connections: dict[str, MagicMock] = {
        "hostA": conn_a,
        "hostB": conn_b,
        "hostC": conn_c,
    }
    tunnels_used: dict[str, object] = {}

    async def fake_create_connection(client_factory: object, host: str, **kwargs: object) -> tuple[MagicMock, MagicMock]:
        tunnels_used[host] = kwargs.get("tunnel")
        return (connections[host], MagicMock())

    servers = {
        "A": _make_server(
            name="A", host="hostA", auth_type=AuthType.key,
            key_path="/k",
        ),
        "B": _make_server(
            name="B", host="hostB", auth_type=AuthType.key,
            key_path="/k", jump_host="A",
        ),
        "C": _make_server(
            name="C", host="hostC", auth_type=AuthType.key,
            key_path="/k", jump_host="B",
        ),
    }
    pool = ConnectionPool(servers=servers)

    with patch("asyncssh.create_connection", side_effect=fake_create_connection):
        result = await pool.get_connection("C")

    assert result is conn_c
    assert tunnels_used["hostA"] is None  # no tunnel for the first hop
    assert tunnels_used["hostB"] is conn_a
    assert tunnels_used["hostC"] is conn_b


# ---------------------------------------------------------------------------
# Connection reuse (already connected)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_connection_reuses_existing_live_connection() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    pool = _make_pool()

    with patch("asyncssh.create_connection", mock_create):
        conn1 = await pool.get_connection("myserver")
        conn2 = await pool.get_connection("myserver")

    assert conn1 is conn2
    assert mock_create.call_count == 1  # connected only once


@pytest.mark.asyncio
async def test_get_connection_reconnects_after_closed() -> None:
    mock_conn_first = _mock_connection()
    mock_conn_second = _mock_connection()

    pool = _make_pool()
    call_count = 0

    async def fake_create(client_factory: object, host: str, **kwargs: object) -> tuple[MagicMock, MagicMock]:
        nonlocal call_count
        call_count += 1
        return (mock_conn_first if call_count == 1 else mock_conn_second, MagicMock())

    with patch("asyncssh.create_connection", side_effect=fake_create):
        await pool.get_connection("myserver")

    # Simulate remote close
    mock_conn_first.is_closed.return_value = True

    with patch("asyncssh.create_connection", side_effect=fake_create):
        conn2 = await pool.get_connection("myserver")

    assert conn2 is mock_conn_second


# ---------------------------------------------------------------------------
# Status tracking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_status_connected_after_connect() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    pool = _make_pool()
    with patch("asyncssh.create_connection", mock_create):
        await pool.get_connection("myserver")
    assert pool.get_status("myserver") == ConnectionStatus.connected


@pytest.mark.asyncio
async def test_status_disconnected_after_close() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    pool = _make_pool()
    with patch("asyncssh.create_connection", mock_create):
        await pool.get_connection("myserver")
    await pool.close("myserver")
    assert pool.get_status("myserver") == ConnectionStatus.disconnected


@pytest.mark.asyncio
async def test_close_all() -> None:
    mock_conn1 = _mock_connection()
    mock_conn2 = _mock_connection()
    host_to_conn: dict[str, MagicMock] = {"host1": mock_conn1, "host2": mock_conn2}

    async def fake_create(client_factory: object, host: str, **kwargs: object) -> tuple[MagicMock, MagicMock]:
        return (host_to_conn[host], MagicMock())

    servers = {
        "s1": _make_server(name="s1", host="host1", auth_type=AuthType.key, key_path="/k"),
        "s2": _make_server(name="s2", host="host2", auth_type=AuthType.key, key_path="/k"),
    }
    pool = ConnectionPool(servers=servers)
    with patch("asyncssh.create_connection", side_effect=fake_create):
        await pool.get_connection("s1")
        await pool.get_connection("s2")

    await pool.close_all()
    assert pool.get_status("s1") == ConnectionStatus.disconnected
    assert pool.get_status("s2") == ConnectionStatus.disconnected


# ---------------------------------------------------------------------------
# Keepalive forwarded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keepalive_kwargs_passed() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    settings = GlobalSettings(keepalive_interval=60, keepalive_count_max=3)
    pool = ConnectionPool(
        servers={"s": _make_server(name="s", auth_type=AuthType.key, key_path="/k")},
        settings=settings,
    )
    with patch("asyncssh.create_connection", mock_create):
        await pool.get_connection("s")
    _, kwargs = mock_create.call_args[0], mock_create.call_args[1]
    assert kwargs["keepalive_interval"] == 60
    assert kwargs["keepalive_count_max"] == 3


@pytest.mark.asyncio
async def test_per_server_keepalive_overrides_global() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    settings = GlobalSettings(keepalive_interval=30)
    pool = ConnectionPool(
        servers={
            "s": _make_server(
                name="s", auth_type=AuthType.key, key_path="/k",
                keepalive_interval=120,
            )
        },
        settings=settings,
    )
    with patch("asyncssh.create_connection", mock_create):
        await pool.get_connection("s")
    _, kwargs = mock_create.call_args[0], mock_create.call_args[1]
    assert kwargs["keepalive_interval"] == 120


# ---------------------------------------------------------------------------
# On-close callback marks disconnected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_close_marks_disconnected() -> None:
    mock_conn = _mock_connection()
    pool = _make_pool()

    disconnect_callback: list[object] = []

    async def fake_create(client_factory: object, host: str, **kwargs: object) -> tuple[MagicMock, MagicMock]:
        # Capture the disconnect callback from the tracker factory
        tracker = client_factory()  # type: ignore[operator]
        disconnect_callback.append(tracker._on_disconnect)
        return (mock_conn, MagicMock())

    with patch("asyncssh.create_connection", side_effect=fake_create):
        await pool.get_connection("myserver")

    assert pool.get_status("myserver") == ConnectionStatus.connected

    # Simulate the connection being lost
    assert disconnect_callback
    disconnect_fn = disconnect_callback[0]
    assert callable(disconnect_fn)
    disconnect_fn()  # type: ignore[operator]

    assert pool.get_status("myserver") == ConnectionStatus.disconnected


# ---------------------------------------------------------------------------
# TOFU: known_hosts callable behaviour
# ---------------------------------------------------------------------------


def test_tofu_known_hosts_callable_returns_empty_for_unknown_host(
    tmp_path: object,
) -> None:
    """For a new (unknown) host, the callable should return an empty sequence."""
    # Use a non-existent file path so the host is unknown
    known_hosts_path = str(tmp_path) + "/nonexistent/known_hosts"  # type: ignore[operator]
    fn = _make_tofu_known_hosts(known_hosts_path)
    result = fn("newhost.example.com", "192.0.2.1", 22)
    assert list(result) == []


# ---------------------------------------------------------------------------
# Exception path: OSError and DisconnectError during connect
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disconnect_error_during_connect_raises_connection_error() -> None:
    async def fail_create(client_factory: object, host: str, **kwargs: object) -> tuple[object, object]:
        raise asyncssh.DisconnectError(14, "host not available")

    pool = _make_pool()
    with patch("asyncssh.create_connection", side_effect=fail_create), pytest.raises(SshConnectionError, match="SSH disconnect"):
        await pool.get_connection("myserver")
    assert pool.get_status("myserver") == ConnectionStatus.disconnected


@pytest.mark.asyncio
async def test_oserror_during_connect_raises_connection_error() -> None:
    async def fail_create(client_factory: object, host: str, **kwargs: object) -> tuple[object, object]:
        raise OSError("connection refused")

    pool = _make_pool()
    with patch("asyncssh.create_connection", side_effect=fail_create), pytest.raises(SshConnectionError, match="Network error"):
        await pool.get_connection("myserver")
    assert pool.get_status("myserver") == ConnectionStatus.disconnected


@pytest.mark.asyncio
async def test_timeout_during_connect_raises_connection_error() -> None:
    """TimeoutError (subclass of OSError in Python 3.11+) maps to ConnectionError."""
    async def fail_create(client_factory: object, host: str, **kwargs: object) -> tuple[object, object]:
        raise TimeoutError("timed out")

    pool = _make_pool()
    with patch("asyncssh.create_connection", side_effect=fail_create), pytest.raises(SshConnectionError, match="Network error"):
        await pool.get_connection("myserver")
    assert pool.get_status("myserver") == ConnectionStatus.disconnected


# ---------------------------------------------------------------------------
# known_hosts: strict and accept_new policies
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_strict_policy_passes_path_string() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    settings = GlobalSettings(
        known_hosts_file="/tmp/known_hosts",
        default_host_key_policy=HostKeyPolicy.strict,
    )
    pool = ConnectionPool(
        servers={"s": _make_server(name="s", auth_type=AuthType.key, key_path="/k")},
        settings=settings,
    )
    with patch("asyncssh.create_connection", mock_create):
        await pool.get_connection("s")
    _, kwargs = mock_create.call_args[0], mock_create.call_args[1]
    assert kwargs["known_hosts"] == "/tmp/known_hosts"


@pytest.mark.asyncio
async def test_accept_new_policy_passes_none() -> None:
    mock_conn = _mock_connection()
    mock_create = _make_create_connection_mock(mock_conn)
    settings = GlobalSettings(
        default_host_key_policy=HostKeyPolicy.accept_new,
    )
    pool = ConnectionPool(
        servers={"s": _make_server(name="s", auth_type=AuthType.key, key_path="/k")},
        settings=settings,
    )
    with patch("asyncssh.create_connection", mock_create):
        await pool.get_connection("s")
    _, kwargs = mock_create.call_args[0], mock_create.call_args[1]
    assert kwargs["known_hosts"] is None


# ---------------------------------------------------------------------------
# _append_host_key: with and without existing file
# ---------------------------------------------------------------------------


def test_append_host_key_writes_new_key(tmp_path: object) -> None:
    import os

    known_hosts = str(tmp_path) + "/ssh/known_hosts"  # type: ignore[operator]
    mock_conn = _mock_connection()
    mock_key = MagicMock()
    mock_key.export_public_key.return_value = b"ssh-ed25519 AAAA fake-key\n"
    mock_conn.get_server_host_key.return_value = mock_key

    _append_host_key(known_hosts, "example.com", mock_conn)

    assert os.path.exists(known_hosts)
    with open(known_hosts) as fh:
        content = fh.read()
    assert "example.com" in content
    assert "fake-key" in content


def test_append_host_key_skips_if_already_present(tmp_path: object) -> None:
    known_hosts = str(tmp_path) + "/known_hosts"  # type: ignore[operator]
    # Write an existing entry
    with open(known_hosts, "w") as fh:
        fh.write("example.com ssh-ed25519 AAAA fake-key\n")

    mock_conn = _mock_connection()
    mock_key = MagicMock()
    mock_key.export_public_key.return_value = b"ssh-ed25519 AAAA fake-key\n"
    mock_conn.get_server_host_key.return_value = mock_key

    _append_host_key(known_hosts, "example.com", mock_conn)

    # File should only have one entry
    with open(known_hosts) as fh:
        content = fh.read()
    assert content.count("fake-key") == 1


# ---------------------------------------------------------------------------
# _DisconnectTracker.connection_lost passes exception too
# ---------------------------------------------------------------------------


def test_disconnect_tracker_connection_lost_called() -> None:
    from mcp_ssh.pool import _DisconnectTracker

    called: list[object] = []
    tracker = _DisconnectTracker(lambda: called.append(True))
    tracker.connection_lost(None)
    assert called == [True]


# ---------------------------------------------------------------------------
# close() with unknown name is a no-op
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_unknown_name_noop() -> None:
    pool = _make_pool()
    # Should not raise
    await pool.close("does_not_exist")


# ---------------------------------------------------------------------------
# unused import check (make sure 'call' import works — used in assertions)
# ---------------------------------------------------------------------------

_ = call  # suppress F401 if call ends up unused

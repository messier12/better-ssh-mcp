"""SSH connection pool implementing IConnectionPool."""
from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

import asyncssh

from .exceptions import AuthError, HostKeyError, ServerNotFound
from .models import AuthType, ConnectionStatus, GlobalSettings, HostKeyPolicy, ServerConfig


class _ConnectionEntry:
    """Internal state for a single server's connection slot."""

    def __init__(self) -> None:
        self.connection: asyncssh.SSHClientConnection | None = None
        self.status: ConnectionStatus = ConnectionStatus.disconnected


def _make_tofu_known_hosts(
    known_hosts_path: str,
) -> Callable[[str, str, int | None], tuple[list[str], list[str], list[str]]]:
    """Return a known_hosts callable implementing TOFU (trust-on-first-use).

    asyncssh 2.14+ expects the callable to return a 3-tuple of key-string lists:
        (trusted_host_keys, trusted_ca_keys, revoked_keys)

    - Unknown host → return ([], [], []) so asyncssh accepts any presented key.
      The key is then recorded by _append_host_key() after a successful connect.
    - Known host → return ([stored_key_str, ...], [], []) so asyncssh verifies
      the server key; a mismatch raises HostKeyNotVerifiable.
    """

    def callable_impl(
        host: str, addr: str, port: int | None
    ) -> tuple[list[str], list[str], list[str]]:
        os.makedirs(os.path.dirname(os.path.expanduser(known_hosts_path)), exist_ok=True)
        path = os.path.expanduser(known_hosts_path)
        try:
            known = asyncssh.read_known_hosts(path)
        except OSError:
            # File doesn't exist or is unreadable → new host, accept any key
            return ([], [], [])

        host_keys, ca_keys, _rev, _x509, _revx, _subj, _revsubj = known.match(
            host, addr, port
        )
        if host_keys or ca_keys:
            # Host is known; return OpenSSH-format key strings so asyncssh
            # can verify the presented key against them.
            trusted: list[str] = [
                key.export_public_key("openssh").decode()
                for key in list(host_keys) + list(ca_keys)
            ]
            return (trusted, [], [])

        # Host not yet recorded → accept any key (TOFU first connect)
        return ([], [], [])

    return callable_impl


def _append_host_key(
    known_hosts_path: str,
    host: str,
    conn: asyncssh.SSHClientConnection,
) -> None:
    """Append the server's host key to the known_hosts file if not already present."""
    path = os.path.expanduser(known_hosts_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    server_key = conn.get_server_host_key()
    if server_key is None:
        return

    key_line = server_key.export_public_key("openssh").decode().strip()
    host_entry = f"{host} {key_line}\n"

    # Check whether this exact line is already present
    try:
        with open(path) as fh:
            existing = fh.read()
        if key_line in existing:
            return
    except OSError:
        pass

    with open(path, "a") as fh:
        fh.write(host_entry)


class _DisconnectTracker(asyncssh.SSHClient):
    """Minimal SSHClient that notifies the pool when the connection drops."""

    def __init__(self, on_disconnect: Callable[[], None]) -> None:
        self._on_disconnect = on_disconnect

    def connection_lost(self, exc: Exception | None) -> None:
        self._on_disconnect()


class ConnectionPool:
    """Manages a pool of asyncssh SSH client connections, implementing IConnectionPool.

    Handles connection lifecycle, keepalive, auth-type mapping, ProxyJump
    resolution, and known-hosts policy.

    Security notes:
    - ``HostKeyPolicy.accept_new`` disables all host key verification and is
      vulnerable to machine-in-the-middle attacks. It must not be used as the
      default and should only be used in isolated, trusted environments.
    - ``HostKeyPolicy.tofu`` accepts any key on first connect and enforces it
      on all subsequent connections. It provides protection against MITM after
      the initial trust establishment.
    - This implementation assumes single-user operation. Auth credentials are
      read from the process environment; no per-user access control is enforced.
    """

    def __init__(
        self,
        servers: dict[str, ServerConfig],
        settings: GlobalSettings | None = None,
    ) -> None:
        self._servers = servers
        self._settings = settings or GlobalSettings()
        self._entries: dict[str, _ConnectionEntry] = {
            name: _ConnectionEntry() for name in servers
        }

    # ------------------------------------------------------------------
    # IConnectionPool interface
    # ------------------------------------------------------------------

    async def get_connection(self, name: str) -> asyncssh.SSHClientConnection:
        """Return an active connection for *name*, reconnecting if necessary.

        Raises:
            ServerNotFound: if *name* is not a registered server.
            AuthError: for authentication configuration problems.
            HostKeyError: if the host key has changed.
        """
        if name not in self._servers:
            raise ServerNotFound(f"Unknown server: {name!r}")

        entry = self._entries[name]

        if entry.status == ConnectionStatus.connected and entry.connection is not None:
            if not entry.connection.is_closed():
                return entry.connection
            entry.status = ConnectionStatus.disconnected

        # (Re)connect
        entry.status = ConnectionStatus.connecting
        try:
            conn = await self._connect(name)
        except (AuthError, HostKeyError, ServerNotFound):
            entry.status = ConnectionStatus.disconnected
            raise
        except asyncssh.DisconnectError as exc:
            entry.status = ConnectionStatus.disconnected
            from .exceptions import ConnectionError as SshConnectionError
            raise SshConnectionError(
                f"SSH disconnect while connecting to {name!r}: {exc}"
            ) from exc
        except OSError as exc:
            entry.status = ConnectionStatus.disconnected
            from .exceptions import ConnectionError as SshConnectionError
            raise SshConnectionError(
                f"Network error connecting to {name!r}: {exc}"
            ) from exc

        entry.connection = conn
        entry.status = ConnectionStatus.connected
        return conn

    async def close(self, name: str) -> None:
        """Close the connection to *name* if open."""
        if name not in self._entries:
            return
        entry = self._entries[name]
        if entry.connection is not None and not entry.connection.is_closed():
            entry.connection.close()
            await entry.connection.wait_closed()
        entry.connection = None
        entry.status = ConnectionStatus.disconnected

    async def close_all(self) -> None:
        """Close all open connections."""
        for name in list(self._entries):
            await self.close(name)

    def get_status(self, name: str) -> ConnectionStatus:
        """Return the current connection status for *name*."""
        if name not in self._entries:
            raise ServerNotFound(f"Unknown server: {name!r}")
        return self._entries[name].status

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _on_close(self, name: str) -> None:
        """Called by _DisconnectTracker when the connection closes."""
        if name in self._entries:
            self._entries[name].status = ConnectionStatus.disconnected
            self._entries[name].connection = None

    async def _connect(self, name: str) -> asyncssh.SSHClientConnection:
        """Build kwargs and call asyncssh.connect for *name*."""
        cfg = self._servers[name]
        kwargs = await self._build_connect_kwargs(cfg)
        conn, _ = await asyncssh.create_connection(
            lambda: _DisconnectTracker(lambda: self._on_close(name)),
            cfg.host,
            **kwargs,
        )

        # For TOFU: if the host was new, append its key now that we've connected
        policy = cfg.host_key_policy or self._settings.default_host_key_policy
        if policy in (HostKeyPolicy.tofu, HostKeyPolicy.accept_new):
            _append_host_key(
                self._settings.known_hosts_file,
                cfg.host,
                conn,
            )

        return conn

    async def _build_connect_kwargs(
        self, cfg: ServerConfig
    ) -> dict[str, Any]:
        """Translate a ServerConfig into asyncssh.create_connection keyword arguments."""
        settings = self._settings
        kwargs: dict[str, Any] = {
            "port": cfg.port,
            "username": cfg.user,
            "known_hosts": self._make_known_hosts_arg(cfg),
            "keepalive_interval": (
                cfg.keepalive_interval
                if cfg.keepalive_interval is not None
                else settings.keepalive_interval
            ),
            "keepalive_count_max": settings.keepalive_count_max,
            "connect_timeout": settings.connect_timeout,
        }

        # --- Auth mapping ------------------------------------------------
        auth = cfg.auth_type
        if auth == AuthType.agent:
            sock = os.environ.get("SSH_AUTH_SOCK")
            if not sock:
                raise AuthError(
                    "auth_type='agent' requires SSH_AUTH_SOCK to be set, "
                    "but the variable is missing or empty. "
                    "Start ssh-agent and run 'ssh-add' to load your key."
                )
            kwargs["agent_path"] = sock

        elif auth in (AuthType.key, AuthType.sk):
            if cfg.key_path is None:
                raise AuthError(
                    f"auth_type={auth.value!r} requires 'key_path' to be set "
                    f"in the server config for {cfg.name!r}."
                )
            kwargs["client_keys"] = [cfg.key_path]
            kwargs["agent_path"] = None

        elif auth == AuthType.password:
            env_var = cfg.password_env
            if env_var is None:
                raise AuthError(
                    f"auth_type='password' requires 'password_env' to be set "
                    f"in the server config for {cfg.name!r}."
                )
            password = os.environ.get(env_var)
            if password is None:
                raise AuthError(
                    f"auth_type='password' requires environment variable "
                    f"{env_var!r} to be set, but it is missing."
                )
            kwargs["password"] = password
            kwargs["agent_path"] = None

        elif auth == AuthType.cert:
            if cfg.key_path is None or cfg.cert_path is None:
                raise AuthError(
                    f"auth_type='cert' requires both 'key_path' and 'cert_path' "
                    f"to be set in the server config for {cfg.name!r}."
                )
            kwargs["client_keys"] = [cfg.key_path]
            kwargs["client_certs"] = [cfg.cert_path]
            kwargs["agent_path"] = None

        elif auth == AuthType.keyboard_interactive:
            kwargs["kbdint_handler"] = _make_kbdint_handler()
            kwargs["agent_path"] = None

        elif auth == AuthType.gssapi:
            kwargs["gss_host"] = cfg.host
            kwargs["agent_path"] = None

        # --- ProxyJump / tunnel -----------------------------------------
        if cfg.jump_host is not None:
            tunnel_conn = await self.get_connection(cfg.jump_host)
            kwargs["tunnel"] = tunnel_conn

        return kwargs

    def _is_host_known(self, host: str, known_hosts_path: str) -> bool:
        """Return True if *host* already has an entry in the known_hosts file.

        Scans the file line-by-line rather than using asyncssh's match() API
        (which requires a resolved IP address as the *addr* argument).
        """
        path = os.path.expanduser(known_hosts_path)
        try:
            with open(path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    # "@cert-authority <host> <keytype> <key>" vs "<host> <keytype> <key>"
                    host_token = parts[1] if parts[0].startswith("@") else parts[0]
                    if host_token == host or host_token.startswith(f"{host},"):
                        return True
            return False
        except OSError:
            return False

    def _make_known_hosts_arg(
        self, cfg: ServerConfig
    ) -> Callable[[str, str, int | None], tuple[list[str], list[str], list[str]]] | str | None:
        """Return an appropriate known_hosts value for asyncssh.create_connection."""
        settings = self._settings
        policy = cfg.host_key_policy or settings.default_host_key_policy
        known_hosts_path = settings.known_hosts_file

        if policy == HostKeyPolicy.strict:
            return os.path.expanduser(known_hosts_path)

        if policy == HostKeyPolicy.tofu:
            if self._is_host_known(cfg.host, known_hosts_path):
                # Known host: enforce strict verification against stored key
                return os.path.expanduser(known_hosts_path)
            # Unknown host: accept any key; _append_host_key() saves it after connect
            return None

        # accept_new: accept any key
        return None


# ---------------------------------------------------------------------------
# Keyboard-interactive handler
# ---------------------------------------------------------------------------


def _make_kbdint_handler() -> Callable[
    [str, str, list[tuple[str, bool]]], list[str]
]:
    """Return a kbdint_handler that reads responses from MCP_SSH_KI_RESPONSE_N env vars."""

    def handler(
        name: str,  # noqa: ARG001
        instructions: str,  # noqa: ARG001
        fields: list[tuple[str, bool]],
    ) -> list[str]:
        responses: list[str] = []
        for i in range(len(fields)):
            env_var = f"MCP_SSH_KI_RESPONSE_{i + 1}"
            value = os.environ.get(env_var, "")
            responses.append(value)
        return responses

    return handler

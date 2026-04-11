"""MCP tools for server registry management (T3a)."""
from __future__ import annotations

import os
from typing import Any

from ..exceptions import (
    McpSshError,
    ServerNotFound,
)
from ..interfaces import IAuditLog, IConnectionPool, IRegistry
from ..models import AuditEvent, ServerConfig
from ..utils import now


def ssh_list_servers(
    registry: IRegistry,
    pool: IConnectionPool,
) -> dict[str, Any]:
    """List all registered SSH servers and their connection status.

    Returns a structured dict with a ``servers`` list.
    Each entry includes name, host, port, user, auth_type, and connection status.
    """
    servers = registry.list_all()
    result = []
    for cfg in servers:
        try:
            status = pool.get_status(cfg.name)
            status_value = status.value
        except ServerNotFound:
            status_value = "unknown"
        result.append(
            {
                "name": cfg.name,
                "host": cfg.host,
                "port": cfg.port,
                "user": cfg.user,
                "auth_type": cfg.auth_type.value,
                "status": status_value,
            }
        )
    return {"servers": result}


def ssh_register_server(
    name: str,
    host: str,
    user: str,
    auth_type: str,
    registry: IRegistry,
    audit: IAuditLog,
    port: int = 22,
    key_path: str | None = None,
    cert_path: str | None = None,
    password_env: str | None = None,
    jump_host: str | None = None,
    host_key_policy: str | None = None,
    default_cwd: str | None = None,
    default_env: dict[str, str] | None = None,
    max_sessions: int | None = None,
    keepalive_interval: int | None = None,
) -> dict[str, Any]:
    """Register a new SSH server configuration.

    Validates the config with Pydantic before writing.
    Returns a structured result or a structured error payload.
    """
    # Validate that name is not already taken
    try:
        registry.get(name)
        # If we get here, the server already exists
        return {
            "error": "server_already_exists",
            "server": name,
            "message": f"Server {name!r} is already registered. "
            "Use ssh_deregister_server first to replace it.",
        }
    except ServerNotFound:
        pass  # expected — we can proceed

    try:
        from ..models import AuthType, HostKeyPolicy

        cfg = ServerConfig(
            name=name,
            host=host,
            port=port,
            user=user,
            auth_type=AuthType(auth_type),
            key_path=key_path,
            cert_path=cert_path,
            password_env=password_env,
            jump_host=jump_host,
            host_key_policy=HostKeyPolicy(host_key_policy) if host_key_policy else None,
            default_cwd=default_cwd,
            default_env=default_env or {},
            max_sessions=max_sessions,
            keepalive_interval=keepalive_interval,
        )
    except (ValueError, Exception) as exc:  # noqa: BLE001
        return {
            "error": "invalid_config",
            "message": str(exc),
        }

    try:
        registry.add(cfg)
    except McpSshError as exc:
        return {"error": "registry_error", "message": str(exc)}

    audit.log(
        AuditEvent(
            ts=now(),
            tool="ssh_register_server",
            server=name,
            outcome="registered",
            detail={"host": host, "port": port, "user": user, "auth_type": auth_type},
        )
    )
    return {
        "registered": True,
        "server": name,
        "host": host,
        "port": port,
        "user": user,
        "auth_type": auth_type,
    }


def ssh_deregister_server(
    name: str,
    registry: IRegistry,
    pool: IConnectionPool,
    audit: IAuditLog,
) -> dict[str, Any]:
    """Remove a registered server configuration.

    Returns a warning payload (not an error) if active sessions exist.
    The server is removed regardless.
    """
    try:
        registry.get(name)
    except ServerNotFound:
        return {
            "error": "server_not_found",
            "server": name,
            "message": f"Server {name!r} is not registered.",
        }

    # Check for active sessions (pool status)
    try:
        from ..models import ConnectionStatus

        status = pool.get_status(name)
        warning: str | None = None
        if status == ConnectionStatus.connected:
            warning = (
                f"Server {name!r} has an active connection. "
                "Existing PTY sessions or exec processes may be affected."
            )
    except ServerNotFound:
        warning = None

    try:
        registry.remove(name)
    except McpSshError as exc:
        return {"error": "registry_error", "message": str(exc)}

    audit.log(
        AuditEvent(
            ts=now(),
            tool="ssh_deregister_server",
            server=name,
            outcome="deregistered",
            detail={"warning": warning},
        )
    )

    result: dict[str, Any] = {"deregistered": True, "server": name}
    if warning:
        result["warning"] = warning
    return result



async def async_ssh_add_known_host(
    name: str,
    registry: IRegistry,
    pool: IConnectionPool,
    audit: IAuditLog,
) -> dict[str, Any]:
    """Async implementation: connect, capture host key, write to known_hosts.

    This is the real implementation used by the MCP server.
    """

    try:
        cfg = registry.get(name)
    except ServerNotFound:
        return {
            "error": "server_not_found",
            "server": name,
            "message": f"Server {name!r} is not registered.",
        }

    app_config = registry.get_config()
    known_hosts_path = os.path.expanduser(app_config.settings.known_hosts_file)
    os.makedirs(os.path.dirname(known_hosts_path), exist_ok=True)

    try:
        conn = await pool.get_connection(name)
        server_key = conn.get_server_host_key()
        if server_key is None:
            return {
                "error": "no_host_key",
                "server": name,
                "message": "Could not retrieve host key from server.",
            }

        key_line = server_key.export_public_key("openssh").decode().strip()
        host_entry = f"{cfg.host} {key_line}\n"

        # Append if not already present
        try:
            with open(known_hosts_path) as fh:
                existing = fh.read()
            already_present = key_line in existing
        except OSError:
            already_present = False

        if not already_present:
            with open(known_hosts_path, "a") as fh:
                fh.write(host_entry)

        audit.log(
            AuditEvent(
                ts=now(),
                tool="ssh_add_known_host",
                server=name,
                outcome="key_recorded" if not already_present else "key_already_known",
                detail={"host": cfg.host, "already_present": already_present},
            )
        )
        return {
            "server": name,
            "host": cfg.host,
            "key_already_known": already_present,
            "known_hosts_file": known_hosts_path,
        }

    except McpSshError as exc:
        return {"error": "connection_error", "server": name, "message": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"error": "unexpected_error", "server": name, "message": str(exc)}


def ssh_show_known_host(
    name: str,
    registry: IRegistry,
) -> dict[str, Any]:
    """Show the known host key entry for a registered server.

    Reads from the known_hosts file; returns key info if present.
    """
    import asyncssh

    try:
        cfg = registry.get(name)
    except ServerNotFound:
        return {
            "error": "server_not_found",
            "server": name,
            "message": f"Server {name!r} is not registered.",
        }

    app_config = registry.get_config()
    known_hosts_path = os.path.expanduser(app_config.settings.known_hosts_file)

    try:
        known = asyncssh.read_known_hosts(known_hosts_path)
    except OSError:
        return {
            "server": name,
            "host": cfg.host,
            "known": False,
            "message": "known_hosts file does not exist or is not readable.",
        }

    host_keys, ca_keys, *_ = known.match(cfg.host, cfg.host, cfg.port)
    all_keys = list(host_keys) + list(ca_keys)

    if not all_keys:
        return {
            "server": name,
            "host": cfg.host,
            "known": False,
            "message": f"No key found for host {cfg.host!r} in {known_hosts_path}.",
        }

    key_infos = []
    for key in all_keys:
        try:
            fingerprint = key.get_fingerprint()
        except Exception:  # noqa: BLE001
            fingerprint = "(unavailable)"
        key_infos.append(
            {
                "algorithm": key.get_algorithm(),
                "fingerprint": fingerprint,
            }
        )

    return {
        "server": name,
        "host": cfg.host,
        "known": True,
        "known_hosts_file": known_hosts_path,
        "keys": key_infos,
    }

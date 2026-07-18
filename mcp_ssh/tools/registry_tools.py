"""MCP tools for server registry management (T3a)."""
from __future__ import annotations

import contextlib
import os
from typing import Any

from ..exceptions import (
    McpSshError,
    ServerAlreadyExists,
    ServerNotFound,
)
from ..interfaces import IAuditLog, IConnectionPool, IRegistry
from ..models import AuditEvent, ServerConfig
from ..utils import now


def ssh_list_servers(
    registry: IRegistry,
    pool: IConnectionPool,
) -> str:
    """List all registered SSH servers and their connection status.

    Returns a compact plain-text table: one server per line with columns
    NAME, USER@HOST:PORT, AUTH, STATUS, and an optional note.
    """
    servers = registry.list_all()
    if not servers:
        return "no servers registered"

    rows: list[tuple[str, str, str, str, str]] = []
    for cfg in servers:
        try:
            status_value = pool.get_status(cfg.name).value
        except ServerNotFound:
            status_value = "unknown"

        port_suffix = f":{cfg.port}" if cfg.port != 22 else ""
        target = f"{cfg.user}@{cfg.host}{port_suffix}"
        note = f"# {cfg.note}" if cfg.note else ""
        rows.append((cfg.name, target, cfg.auth_type.value, status_value, note))

    # Column widths from data (no header — columns are self-evident)
    w = [max(len(r[i]) for r in rows) for i in range(5)]
    lines = [
        f"{name:<{w[0]}}  {target:<{w[1]}}  {auth:<{w[2]}}  {status:<{w[3]}}"
        + (f"  {note}" if note else "")
        for name, target, auth, status, note in rows
    ]
    return "\n".join(lines)


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
    note: str | None = None,
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
            note=note,
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


def _hop_name(alias: str, index: int, total: int) -> str:
    """Return the registry name for hop *index* of a jump chain.

    The final hop is exposed under the user-facing *alias*; intermediate hops
    get generated names so a chain can be torn down as a unit.
    """
    return alias if index == total - 1 else f"_{alias}_hop{index}"


def _parse_hop(element: str) -> tuple[str, str | None, int | None]:
    """Parse a chain element ``"server"`` / ``"server@host"`` / ``"server@host:port"``.

    Returns ``(server_name, host_override, port_override)``. The override values
    are ``None`` when not supplied.
    """
    server_part, _, addr = element.partition("@")
    server_name = server_part.strip()
    host_override: str | None = None
    port_override: int | None = None
    addr = addr.strip()
    if addr:
        host_str, sep, port_str = addr.rpartition(":")
        if sep and port_str.isdigit():
            host_override = host_str.strip()
            port_override = int(port_str)
        else:
            host_override = addr
    return server_name, host_override, port_override


def setup_jump(
    name: str,
    chain: list[str],
    registry: IRegistry,
    audit: IAuditLog,
    persist: bool = False,
    note: str | None = None,
) -> dict[str, Any]:
    """Create a jump-chain server *name* that tunnels through existing servers.

    Each element of *chain* names an already-registered server whose
    credentials (user, key, port, host-key policy) are reused — you never
    respecify key paths. ``chain[0]`` is the first hop (directly reachable);
    ``chain[-1]`` is the final target, exposed under *name*. Append
    ``@host`` or ``@host:port`` to any element to override just the dial
    address for that hop (needed when a host has a different address depending
    on the vantage point, e.g. a WireGuard IP seen only from the prior hop).

    Ephemeral by default (in-memory, gone on restart, never written to
    servers.toml). Pass ``persist=True`` to write real config entries instead.

    Once created, *name* works with every SSH tool (ssh_exec, ssh_start_pty,
    ssh_get, …) transparently. Remove it with ``teardown_jump``.
    """
    if not chain:
        return {"error": "invalid_chain", "message": "chain must have at least one hop."}

    try:
        registry.get(name)
        return {
            "error": "server_already_exists",
            "server": name,
            "message": f"Server {name!r} already exists. Pick another jump name "
            "or tear it down first.",
        }
    except ServerNotFound:
        pass

    total = len(chain)
    hops: list[ServerConfig] = []
    prev_name: str | None = None
    for i, element in enumerate(chain):
        server_name, host_override, port_override = _parse_hop(element)
        try:
            base = registry.get(server_name)
        except ServerNotFound:
            return {
                "error": "server_not_found",
                "server": server_name,
                "message": f"Chain hop {server_name!r} is not a registered server.",
            }
        hop_name = _hop_name(name, i, total)
        hop_note = (
            note
            if (note and i == total - 1)
            else f"jump chain {name!r} hop {i} via {server_name}"
        )
        hops.append(
            base.model_copy(
                update={
                    "name": hop_name,
                    "host": host_override or base.host,
                    "port": port_override or base.port,
                    "jump_host": prev_name,
                    "note": hop_note,
                }
            )
        )
        prev_name = hop_name

    # Register all hops, rolling back on any collision so we never leave a
    # half-built chain behind.
    add = registry.add if persist else registry.add_ephemeral  # type: ignore[attr-defined]
    remove = registry.remove if persist else registry.remove_ephemeral  # type: ignore[attr-defined]
    added: list[str] = []
    for cfg in hops:
        try:
            add(cfg)
        except (ServerAlreadyExists, McpSshError) as exc:
            for done in reversed(added):
                with contextlib.suppress(McpSshError):
                    remove(done)
            return {
                "error": "registry_error",
                "server": cfg.name,
                "message": f"Failed to build jump chain: {exc}",
            }
        added.append(cfg.name)

    hop_summary = [
        {"name": h.name, "target": f"{h.user}@{h.host}:{h.port}", "via": h.jump_host}
        for h in hops
    ]
    audit.log(
        AuditEvent(
            ts=now(),
            tool="setup_jump",
            server=name,
            outcome="created",
            detail={
                "persist": persist,
                "hops": [h["target"] for h in hop_summary],
            },
        )
    )
    return {
        "jump": name,
        "persist": persist,
        "ephemeral": not persist,
        "hops": hop_summary,
    }


def teardown_jump(
    name: str,
    registry: IRegistry,
    audit: IAuditLog,
) -> dict[str, Any]:
    """Remove a jump chain created by ``setup_jump`` (the alias + its hops).

    Removes both ephemeral and persisted entries. Safe to call whether the
    chain was created ephemeral or persisted.
    """
    prefix = f"_{name}_hop"
    targets = [
        cfg.name
        for cfg in registry.list_all()
        if cfg.name == name or cfg.name.startswith(prefix)
    ]
    if not targets:
        return {
            "error": "server_not_found",
            "server": name,
            "message": f"No jump chain named {name!r} found.",
        }

    removed: list[str] = []
    for target in targets:
        for remover in (registry.remove_ephemeral, registry.remove):  # type: ignore[attr-defined]
            try:
                remover(target)
                removed.append(target)
                break
            except (ServerNotFound, McpSshError):
                continue

    audit.log(
        AuditEvent(
            ts=now(),
            tool="teardown_jump",
            server=name,
            outcome="removed",
            detail={"removed": removed},
        )
    )
    return {"torn_down": name, "removed": removed}


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

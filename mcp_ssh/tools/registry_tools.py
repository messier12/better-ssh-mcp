"""MCP tools for server registry management (T3a)."""
from __future__ import annotations

import contextlib
import os
from typing import Any

from ..discovery import discover as _discover
from ..discovery import teardown_discovery as _teardown_discovery
from ..exceptions import (
    McpSshError,
    ServerAlreadyExists,
    ServerNotFound,
)
from ..interfaces import IAuditLog, IConnectionPool, IRegistry, IStateStore
from ..models import AuditEvent, ServerConfig
from ..topology import (
    LOCAL_NODE,
    find_path,
    path_gap_report,
    scan_topology,
)
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


async def setup_jump(
    name: str,
    chain: list[str] | None = None,
    *,
    registry: IRegistry,
    audit: IAuditLog,
    persist: bool = False,
    note: str | None = None,
    target: str | None = None,
    pool: IConnectionPool | None = None,
    state: IStateStore | None = None,
    max_age: float | None = None,
    force_rescan: bool = False,
) -> dict[str, Any]:
    """Create a jump-chain server *name* that tunnels through existing servers.

    Two modes:

    **Manual (``chain=``)** — each element names an already-registered server
    whose credentials (user, key, port, host-key policy) are reused. ``chain[0]``
    is the first hop (directly reachable); ``chain[-1]`` is the final target,
    exposed under *name*. Append ``@host`` or ``@host:port`` to any element to
    override just the dial address for that hop (needed when a host has a
    vantage-specific address, e.g. a WireGuard IP seen only from the prior hop).

    **Auto (``target=``)** — pathfind a chain to registered server *target* over
    the cached reachability matrix (see ``ssh_scan_topology``). Fewest hops wins,
    latency as tiebreaker. Pass ``max_age`` (seconds) to reject a stale cache and
    ``force_rescan=True`` to run a fresh scan first. The built alias is verified
    with a real connect; on failure it is torn down. Requires *pool* and *state*.

    Ephemeral by default (in-memory, gone on restart, never written to
    servers.toml). Pass ``persist=True`` to write real config entries instead.

    Once created, *name* works with every SSH tool (ssh_exec, ssh_start_pty,
    ssh_get, …) transparently. Remove it with ``teardown_jump``.
    """
    if target is not None:
        return await _setup_jump_auto(
            name=name,
            target=target,
            registry=registry,
            audit=audit,
            pool=pool,
            state=state,
            persist=persist,
            note=note,
            max_age=max_age,
            force_rescan=force_rescan,
        )

    if not chain:
        return {
            "error": "invalid_chain",
            "message": "Provide either a non-empty 'chain' or a 'target'.",
        }
    return _build_chain(name, chain, registry, audit, persist, note)


def _build_chain(
    name: str,
    chain: list[str],
    registry: IRegistry,
    audit: IAuditLog,
    persist: bool,
    note: str | None,
) -> dict[str, Any]:
    """Register the hops of *chain* under *name*, rolling back on any failure."""
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
    # Parallel to *hops*: the underlying registered server name and host of each
    # hop, so we can report whether the dial address was harvested vs registered.
    hop_meta: list[tuple[str, str]] = []
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
        hop_meta.append((server_name, base.host))
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
        {
            "name": h.name,
            "node": server_name,
            "target": f"{h.user}@{h.host}:{h.port}",
            "via": h.host,
            # The address dialed for this hop. "registered" if it matches the
            # node's registered host; "harvested" if it is a vantage-specific
            # address discovered by the scan (first-connect / tofu-trusted).
            "via_source": "registered" if h.host == registered_host else "harvested",
            # Preserve the previous-hop jump linkage (was previously "via").
            "jump_host": h.jump_host,
        }
        for h, (server_name, registered_host) in zip(hops, hop_meta, strict=True)
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


async def _setup_jump_auto(
    name: str,
    target: str,
    registry: IRegistry,
    audit: IAuditLog,
    pool: IConnectionPool | None,
    state: IStateStore | None,
    persist: bool,
    note: str | None,
    max_age: float | None,
    force_rescan: bool,
) -> dict[str, Any]:
    """Auto-build a chain to *target* by pathfinding over the cached matrix."""
    if pool is None or state is None:
        return {
            "error": "unavailable",
            "message": "Auto-chain (target=) requires the connection pool and state store.",
        }

    try:
        registry.get(target)
    except ServerNotFound:
        return {
            "error": "server_not_found",
            "server": target,
            "message": f"Target {target!r} is not a registered server.",
        }

    topology = state.get_topology()
    if force_rescan:
        # An explicit rescan is the only path that triggers a fresh scan.
        topology = await scan_topology(registry, pool)
        state.set_topology(topology)
    elif topology is None:
        return {
            "error": "no_topology",
            "message": (
                "No cached topology available. Run ssh_scan_topology first, "
                "or pass force_rescan=True to scan now."
            ),
        }
    elif max_age is not None:
        age = (now() - topology.scanned_at).total_seconds()
        if age > max_age:
            return {
                "error": "stale_topology",
                "message": (
                    f"Cached topology is {age:.0f}s old (max_age={max_age:.0f}s). "
                    "Re-run with force_rescan=True or call ssh_scan_topology."
                ),
                "scanned_at": topology.scanned_at.isoformat(),
            }

    path = find_path(topology, target)
    if path is None:
        return {
            "error": "no_path",
            "target": target,
            "message": f"No reachable jump chain from {LOCAL_NODE!r} to {target!r}.",
            "gap": path_gap_report(topology, target),
        }

    # Build chain elements as ``node@via`` using each hop's winning address from
    # the previous vantage (harvested addresses are not in the registry).
    chain = [f"{node}@{via}" for node, via in path]

    build_result = _build_chain(name, chain, registry, audit, persist, note)
    if "error" in build_result:
        return build_result

    # Verify with a real connect to the target through the built chain.
    try:
        await pool.get_connection(name)
    except Exception as exc:  # noqa: BLE001 - any failure means a dead alias
        teardown_jump(name, registry=registry, audit=audit)
        return {
            "error": "verify_failed",
            "jump": name,
            "target": target,
            "chain": chain,
            "message": f"Built chain to {target!r} but the verification connect failed: {exc}",
        }

    audit.log(
        AuditEvent(
            ts=now(),
            tool="setup_jump",
            server=name,
            outcome="auto_chained",
            detail={"target": target, "chain": chain},
        )
    )
    build_result["target"] = target
    build_result["auto_chain"] = chain
    build_result["verified"] = True
    return build_result


async def ssh_scan_topology(
    registry: IRegistry,
    pool: IConnectionPool,
    state: IStateStore,
    audit: IAuditLog,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    probe_timeout: float = 5.0,
    harvest_timeout: float = 15.0,
    force: bool = False,  # noqa: ARG001 - reserved; a scan is always fresh
) -> dict[str, Any]:
    """Probe server-to-server reachability and cache the resulting matrix.

    For every ordered pair of registered servers (plus the synthetic ``local``
    source), opens a direct-tcpip channel from the source to each of the
    target's candidate addresses (its registered host plus harvested interface
    IPs), from the source's own network vantage. Produces a directed N×N matrix
    that ``setup_jump(target=...)`` can pathfind over.

    ``include`` / ``exclude`` bound which servers are scanned (internal jump-chain
    hops are always excluded). The full result is cached via the state store and
    returned as a structured dict.
    """
    try:
        topology = await scan_topology(
            registry,
            pool,
            include=include,
            exclude=exclude,
            probe_timeout=probe_timeout,
            harvest_timeout=harvest_timeout,
        )
    except McpSshError as exc:
        return {"error": "scan_error", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"error": "unexpected_error", "message": str(exc)}

    state.set_topology(topology)
    audit.log(
        AuditEvent(
            ts=now(),
            tool="ssh_scan_topology",
            outcome="scanned",
            detail={
                "nodes": len(topology.nodes),
                "edges": len(topology.edges),
            },
        )
    )
    return topology.model_dump(mode="json", by_alias=True)


async def ssh_discover(
    registry: IRegistry,
    pool: IConnectionPool,
    audit: IAuditLog,
    seeds: list[str] | None = None,
    keys: list[str] | None = None,
    harvest_keys: bool = False,
    injected_candidates: list[str] | None = None,
    subnet_sweep: bool = False,
    sweep_cidr: str | None = None,
    port: int = 22,
    max_depth: int = 4,
    max_nodes: int = 128,
    timeout: float = 120.0,
    concurrency: int = 16,
    name_prefix: str = "disc",
    persist: bool = False,
) -> dict[str, Any]:
    """Recursively discover reachable SSH hosts from a seed frontier.

    Follows each host's own breadcrumbs (known_hosts, ARP cache, ssh config,
    shell history, /etc/hosts) instead of scanning address ranges, tunnelling
    from the MCP host through each discoverer. Every confirmed host is
    auto-registered as an ephemeral server (``disc-<fp8>``) reachable through
    its discoverer, and can be torn down as a unit with ``teardown_discovery``.

    Discovery is inherently TOFU (trust-on-first-use) regardless of the global
    host-key policy: the first connect is what captures the fingerprint used to
    dedup hosts. This accepts the MITM risk for the own-fleet use case.

    v1 notes: ``keys`` is effectively required — pass at least one key path (no
    config/agent fallback yet); with an empty key set nothing authenticates. A
    host is only pool-reachable after the scan when exactly one shared key was
    supplied (its path is threaded onto the ephemeral); harvest-key-only hosts
    are registered report-only (``pool_reachable=false``).

    Returns a structured ``DiscoveryResult`` (session id, discovered hosts,
    discoverer→discovered graph, skipped encrypted keys, truncated flag, stats).
    """
    try:
        result = await _discover(
            registry,
            pool,
            audit,
            seeds=seeds,
            keys=keys,
            harvest_keys=harvest_keys,
            injected_candidates=injected_candidates,
            subnet_sweep=subnet_sweep,
            sweep_cidr=sweep_cidr,
            port=port,
            max_depth=max_depth,
            max_nodes=max_nodes,
            timeout=timeout,
            concurrency=concurrency,
            name_prefix=name_prefix,
            persist=persist,
        )
    except McpSshError as exc:
        return {"error": "discover_error", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"error": "unexpected_error", "message": str(exc)}

    return result.model_dump(mode="json")


def teardown_discovery(
    session: str,
    registry: IRegistry,
    audit: IAuditLog,
) -> dict[str, Any]:
    """Remove every ephemeral host registered by an ``ssh_discover`` session.

    The ``teardown_jump`` analog for discovery. Finds all entries carrying the
    session id in their note and removes them (ephemeral or persisted).
    """
    return _teardown_discovery(session, registry=registry, audit=audit)


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

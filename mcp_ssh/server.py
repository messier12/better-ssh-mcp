"""MCP server entrypoint for mcp-ssh (T4).

Wires together all components and registers 9 consolidated MCP tools.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import logging
import os
import signal
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

logger = logging.getLogger(__name__)


def _build_app() -> tuple[Any, AppContext]:
    """Build and return the FastMCP app and the shared AppContext."""
    from mcp.server.fastmcp import FastMCP

    from .audit import AuditLog
    from .config import resolve_config_path
    from .pool import ConnectionPool
    from .registry import Registry
    from .session import SessionManager
    from .state import StateStore

    # Load config
    config_path = resolve_config_path()
    registry = Registry(config_path)
    app_config = registry.get_config()

    state = StateStore(app_config.settings)
    state.load()

    audit = AuditLog(app_config.settings)
    # Pass the live registry (not a startup snapshot) so servers registered at
    # runtime — including ephemeral jump chains — are visible immediately.
    pool = ConnectionPool(registry, app_config.settings)

    session_manager = SessionManager(
        pool=pool,
        state=state,
        audit=audit,
        settings=app_config.settings,
        # Registry.watch is an async generator; the frozen IRegistry Protocol
        # declares it as `async def`, so mypy sees a spurious signature conflict.
        registry=registry,  # type: ignore[arg-type]
    )

    ctx = AppContext(
        registry=registry,
        pool=pool,
        session_manager=session_manager,
        state=state,
        audit=audit,
    )

    @asynccontextmanager
    async def _lifespan(app: Any) -> AsyncIterator[None]:  # noqa: ARG001
        """Start background tasks on startup; clean up on shutdown."""
        async def _watch() -> None:
            try:
                async for _ in ctx.registry.watch():
                    pass  # registry reloads internally on each yield
            except asyncio.CancelledError:
                pass

        watch_task = asyncio.create_task(_watch())
        try:
            yield
        finally:
            watch_task.cancel()
            await asyncio.gather(watch_task, return_exceptions=True)
            await ctx.pool.close_all()
            ctx.audit.close()

    mcp = FastMCP("mcp-ssh", lifespan=_lifespan)
    _register_tools(mcp, ctx)

    return mcp, ctx


class AppContext:
    """Shared context holding all service singletons."""

    def __init__(
        self,
        registry: Any,
        pool: Any,
        session_manager: Any,
        state: Any,
        audit: Any,
    ) -> None:
        self.registry = registry
        self.pool = pool
        self.session_manager = session_manager
        self.state = state
        self.audit = audit


def _register_tools(mcp: Any, ctx: AppContext) -> None:
    """Register the 9 consolidated SSH MCP tools on the FastMCP app."""
    from .tools.exec_tools import (
        ssh_check_process as _check_process,
    )
    from .tools.exec_tools import (
        ssh_exec as _exec,
    )
    from .tools.exec_tools import (
        ssh_exec_stream as _exec_stream,
    )
    from .tools.exec_tools import (
        ssh_kill_process as _kill_process,
    )
    from .tools.exec_tools import (
        ssh_list_processes as _list_processes,
    )
    from .tools.exec_tools import (
        ssh_read_process as _read_process,
    )
    from .tools.exec_tools import (
        ssh_write_process as _write_process,
    )
    from .tools.pty_tools import (
        ssh_pty_attach as _pty_attach,
    )
    from .tools.pty_tools import (
        ssh_pty_close as _pty_close,
    )
    from .tools.pty_tools import (
        ssh_pty_read as _pty_read,
    )
    from .tools.pty_tools import (
        ssh_pty_resize as _pty_resize,
    )
    from .tools.pty_tools import (
        ssh_pty_write as _pty_write,
    )
    from .tools.pty_tools import (
        ssh_start_pty as _start_pty,
    )
    from .tools.registry_tools import (
        async_ssh_add_known_host as _add_known_host,
    )
    from .tools.registry_tools import (
        setup_jump as _setup_jump,
    )
    from .tools.registry_tools import (
        ssh_deregister_server as _deregister,
    )
    from .tools.registry_tools import (
        ssh_discover as _discover,
    )
    from .tools.registry_tools import (
        ssh_list_servers as _list_servers,
    )
    from .tools.registry_tools import (
        ssh_register_server as _register,
    )
    from .tools.registry_tools import (
        ssh_scan_topology as _scan_topology,
    )
    from .tools.registry_tools import (
        ssh_show_known_host as _show_known_host,
    )
    from .tools.registry_tools import (
        teardown_discovery as _teardown_discovery,
    )
    from .tools.registry_tools import (
        teardown_jump as _teardown_jump,
    )
    from .tools.scp_tools import (
        ssh_get as _get,
    )
    from .tools.scp_tools import (
        ssh_put as _put,
    )
    from .tools.scp_tools import (
        ssh_sync as _sync,
    )
    from .tools.scp_tools import (
        ssh_transfer as _transfer,
    )

    # ── 1. ssh_exec ──────────────────────────────────────────────────────────

    @mcp.tool()
    async def ssh_exec(  # type: ignore[return]
        server: str,
        command: str,
        cwd: str | None = None,
        timeout: float | None = 30.0,
    ) -> dict[str, Any]:
        """Run a command on a remote server and wait for completion.

        Returns ``{output, exit_code, server}``.
        Pass ``timeout=None`` to wait indefinitely (logs a warning).
        """
        return await _exec(
            server=server, command=command,
            registry=ctx.registry, pool=ctx.pool, audit=ctx.audit,
            cwd=cwd, timeout=timeout,
        )

    # ── 2. ssh_process ───────────────────────────────────────────────────────

    @mcp.tool()
    async def ssh_process(  # type: ignore[return]
        action: str,
        server: str | None = None,
        command: str | None = None,
        process_id: str | None = None,
        cwd: str | None = None,
        data: str | None = None,
        signal: str = "SIGTERM",
        max_bytes: int = 65536,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Manage long-running background processes (nohup-backed).

        action="start"  — server, command required; cwd optional.
                          Returns {process_id, server, command}.
        action="read"   — process_id required; max_bytes, offset optional.
                          Returns {output, next_offset, running, exit_code, remote_pid, server}.
                          Pass offset=next_offset from previous call to stream incrementally.
        action="write"  — process_id, data required.
                          Note: nohup processes have no stdin; always returns an error.
        action="kill"   — process_id required; signal optional (SIGTERM default).
                          Allowed: SIGTERM SIGKILL SIGINT SIGHUP SIGQUIT SIGUSR1 SIGUSR2.
        action="list"   — server optional filter. Returns {processes: [...]}.
        action="check"  — process_id required. Runs kill -0 + reads exit file.
                          Returns {output, running, exit_code, remote_pid, server}.
        """
        if action == "start":
            return await _exec_stream(
                server=server or "", command=command or "",
                session_manager=ctx.session_manager, audit=ctx.audit,
                cwd=cwd,
            )
        if action == "read":
            return await _read_process(
                process_id=process_id or "",
                session_manager=ctx.session_manager,
                max_bytes=max_bytes, offset=offset,
            )
        if action == "write":
            return await _write_process(
                process_id=process_id or "", data=data or "",
                session_manager=ctx.session_manager,
            )
        if action == "kill":
            return await _kill_process(
                process_id=process_id or "",
                session_manager=ctx.session_manager, signal=signal,
            )
        if action == "list":
            return _list_processes(session_manager=ctx.session_manager, server=server)
        if action == "check":
            return await _check_process(
                process_id=process_id or "",
                session_manager=ctx.session_manager,
            )
        return {"error": "invalid_action", "action": action,
                "message": f"Unknown action {action!r}. Use: start read write kill list check"}

    # ── 3. ssh_pty ───────────────────────────────────────────────────────────

    @mcp.tool()
    async def ssh_pty(  # type: ignore[return]
        action: str,
        session_id: str | None = None,
        server: str | None = None,
        command: str | None = None,
        cols: int = 220,
        rows: int = 50,
        use_tmux: bool = False,
        data: str | None = None,
        max_bytes: int = 65536,
    ) -> dict[str, Any]:
        """PTY session lifecycle.

        action="start"  — server required; command, cols, rows, use_tmux optional.
                          With use_tmux=True the session survives MCP reconnects.
                          Returns {session_id, use_tmux, server, command}.
        action="read"   — session_id required; max_bytes optional.
                          Returns {output, alive}.
        action="write"  — session_id, data required.
                          Use \\r (not \\n) to submit a command line.
        action="resize" — session_id, cols, rows required.
        action="close"  — session_id required. Cleans up local channel
                          (tmux window left alive on remote).
        action="attach" — session_id required. Tmux-backed sessions only.
        """
        if action == "start":
            return await _start_pty(
                server=server or "",
                session_manager=ctx.session_manager, audit=ctx.audit,
                command=command, cols=cols, rows=rows, use_tmux=use_tmux,
            )
        if action == "read":
            return await _pty_read(
                session_id=session_id or "",
                session_manager=ctx.session_manager, max_bytes=max_bytes,
            )
        if action == "write":
            return await _pty_write(
                session_id=session_id or "", data=data or "",
                session_manager=ctx.session_manager,
            )
        if action == "resize":
            return await _pty_resize(
                session_id=session_id or "", cols=cols, rows=rows,
                session_manager=ctx.session_manager,
            )
        if action == "close":
            return await _pty_close(
                session_id=session_id or "",
                session_manager=ctx.session_manager, audit=ctx.audit,
            )
        if action == "attach":
            return await _pty_attach(
                session_id=session_id or "",
                session_manager=ctx.session_manager,
            )
        return {"error": "invalid_action", "action": action,
                "message": f"Unknown action {action!r}. Use: start read write resize close attach"}

    # ── 4. ssh_files ─────────────────────────────────────────────────────────

    @mcp.tool()
    async def ssh_files(  # type: ignore[return]
        action: str,
        server: str | None = None,
        remote_path: str | None = None,
        local_path: str | None = None,
        src_server: str | None = None,
        src_path: str | None = None,
        dst_server: str | None = None,
        dst_path: str | None = None,
        recurse: bool = False,
        preserve: bool = False,
        delete: bool = False,
    ) -> dict[str, Any]:
        """File transfer between local and remote servers.

        action="get"      — server, remote_path, local_path required.
                            Download from remote to local.
        action="put"      — server, local_path, remote_path required.
                            Upload from local to remote.
        action="transfer" — src_server, src_path, dst_server, dst_path required.
                            Copy between two remotes via memory (no local disk).
                            Same-server copies run cp remotely.
        action="sync"     — src_server, src_path, dst_server, dst_path required.
                            Copy only changed files; src_path may be a glob.
                            Same-server uses rsync if available, else cp -u.
                            Cross-server compares size+mtime via SFTP.
                            Set delete=True to remove dest files absent from src.
                            Returns {copied, skipped, deleted, method}.

        recurse and preserve apply to all actions.
        """
        if action == "get":
            return await _get(
                server=server or "", remote_path=remote_path or "",
                local_path=local_path or "",
                recurse=recurse, preserve=preserve,
                registry=ctx.registry, pool=ctx.pool, audit=ctx.audit,
            )
        if action == "put":
            return await _put(
                server=server or "", local_path=local_path or "",
                remote_path=remote_path or "",
                recurse=recurse, preserve=preserve,
                registry=ctx.registry, pool=ctx.pool, audit=ctx.audit,
            )
        if action == "transfer":
            return await _transfer(
                src_server=src_server or "", src_path=src_path or "",
                dst_server=dst_server or "", dst_path=dst_path or "",
                recurse=recurse, preserve=preserve,
                registry=ctx.registry, pool=ctx.pool, audit=ctx.audit,
            )
        if action == "sync":
            return await _sync(
                src_server=src_server or "", src_path=src_path or "",
                dst_server=dst_server or "", dst_path=dst_path or "",
                delete=delete, preserve=preserve,
                registry=ctx.registry, pool=ctx.pool, audit=ctx.audit,
            )
        return {"error": "invalid_action", "action": action,
                "message": f"Unknown action {action!r}. Use: get put transfer sync"}

    # ── 5. ssh_jump ──────────────────────────────────────────────────────────

    @mcp.tool()
    async def ssh_jump(  # type: ignore[return]
        action: str,
        name: str,
        chain: list[str] | None = None,
        persist: bool = False,
        note: str | None = None,
        target: str | None = None,
        max_age: float | None = None,
        force_rescan: bool = False,
    ) -> dict[str, Any]:
        """Create or remove SSH jump-chain tunnels.

        action="setup"    — name required; then either:
                              Manual: chain=[server1, server2, ...] — reuses each
                                server's credentials; chain[0] is first hop,
                                chain[-1] the final target. Append @host or
                                @host:port to override a hop's dial address.
                              Auto: target=<server> — pathfinds over the cached
                                reachability matrix (see ssh_scan_topology).
                                max_age rejects a stale cache;
                                force_rescan=True runs a fresh scan first.
                            persist=True writes to servers.toml (default: ephemeral).
                            Use name with any SSH tool afterward.
        action="teardown" — name required. Removes the alias and all hop entries.
        """
        if action == "setup":
            return await _setup_jump(
                name=name, chain=chain, registry=ctx.registry, audit=ctx.audit,
                persist=persist, note=note, target=target,
                pool=ctx.pool, state=ctx.state,
                max_age=max_age, force_rescan=force_rescan,
            )
        if action == "teardown":
            return _teardown_jump(name=name, registry=ctx.registry, audit=ctx.audit)
        return {"error": "invalid_action", "action": action,
                "message": f"Unknown action {action!r}. Use: setup teardown"}

    # ── 6. ssh_discover ──────────────────────────────────────────────────────

    @mcp.tool()
    async def ssh_discover(  # type: ignore[return]
        action: str,
        session: str | None = None,
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
        """Recursively discover and register reachable SSH hosts.

        action="start"    — Crawls from seeds (default: local + connected servers),
                            harvests known_hosts/ARP/ssh config/history for
                            candidate neighbours, tunnels to probe+connect them
                            with the given keys, auto-registers every confirmed
                            host as an ephemeral server reachable through its
                            discoverer. Inherently TOFU.
                            Set harvest_keys=True to fold in unencrypted keys
                            found on each host (encrypted keys are reported only).
                            Returns a session ID for cleanup.
        action="teardown" — session required. Removes every ephemeral host
                            registered by that discovery session.
        """
        if action == "start":
            return await _discover(
                registry=ctx.registry, pool=ctx.pool, audit=ctx.audit,
                seeds=seeds, keys=keys, harvest_keys=harvest_keys,
                injected_candidates=injected_candidates,
                subnet_sweep=subnet_sweep, sweep_cidr=sweep_cidr,
                port=port, max_depth=max_depth, max_nodes=max_nodes,
                timeout=timeout, concurrency=concurrency,
                name_prefix=name_prefix, persist=persist,
            )
        if action == "teardown":
            return _teardown_discovery(
                session=session or "", registry=ctx.registry, audit=ctx.audit,
            )
        return {"error": "invalid_action", "action": action,
                "message": f"Unknown action {action!r}. Use: start teardown"}

    # ── 7. ssh_known_host ────────────────────────────────────────────────────

    @mcp.tool()
    async def ssh_known_host(  # type: ignore[return]
        action: str,
        name: str,
    ) -> dict[str, Any]:
        """Manage known host keys for a registered server.

        action="add"  — Connect and record the server's host key in known_hosts.
        action="show" — Return the stored host key entry.
        """
        if action == "add":
            return await _add_known_host(
                name=name, registry=ctx.registry, pool=ctx.pool, audit=ctx.audit,
            )
        if action == "show":
            return _show_known_host(name=name, registry=ctx.registry)
        return {"error": "invalid_action", "action": action,
                "message": f"Unknown action {action!r}. Use: add show"}

    # ── 8. ssh_server ────────────────────────────────────────────────────────

    @mcp.tool(structured_output=False)
    def ssh_server(  # type: ignore[return]
        action: str,
        name: str | None = None,
        host: str | None = None,
        user: str | None = None,
        auth_type: str | None = None,
        port: int = 22,
        key_path: str | None = None,
        cert_path: str | None = None,
        password_env: str | None = None,
        jump_host: str | None = None,
        host_key_policy: str | None = None,
        default_cwd: str | None = None,
        max_sessions: int | None = None,
        keepalive_interval: int | None = None,
        note: str | None = None,
    ) -> Any:
        """Manage the SSH server registry.

        action="list"       — No required args. Returns all registered servers
                              and their connection statuses.
        action="register"   — name, host, user, auth_type required.
                              auth_type: "key" | "cert" | "password" | "agent".
                              key_path required for auth_type="key";
                              password_env required for auth_type="password".
        action="deregister" — name required. Removes the server config and
                              closes any open connections.
        """
        if action == "list":
            return _list_servers(registry=ctx.registry, pool=ctx.pool)
        if action == "register":
            return _register(
                name=name or "", host=host or "", user=user or "",
                auth_type=auth_type or "",
                registry=ctx.registry, audit=ctx.audit,
                port=port, key_path=key_path, cert_path=cert_path,
                password_env=password_env, jump_host=jump_host,
                host_key_policy=host_key_policy, default_cwd=default_cwd,
                max_sessions=max_sessions, keepalive_interval=keepalive_interval,
                note=note,
            )
        if action == "deregister":
            return _deregister(
                name=name or "", registry=ctx.registry, pool=ctx.pool, audit=ctx.audit,
            )
        return {"error": "invalid_action", "action": action,
                "message": f"Unknown action {action!r}. Use: list register deregister"}

    # ── 9. ssh_scan_topology ─────────────────────────────────────────────────

    @mcp.tool()
    async def ssh_scan_topology(  # type: ignore[return]
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        probe_timeout: float = 5.0,
        harvest_timeout: float = 15.0,
        force: bool = False,
    ) -> dict[str, Any]:
        """Probe server-to-server reachability and cache the N×N matrix.

        Opens a direct-tcpip channel from each source's own vantage to every
        target's candidate addresses (registered host + harvested interface IPs).
        Feeds ssh_jump(action="setup", target=...). Use include/exclude to bound
        which servers are scanned.
        """
        return await _scan_topology(
            registry=ctx.registry, pool=ctx.pool, state=ctx.state, audit=ctx.audit,
            include=include, exclude=exclude,
            probe_timeout=probe_timeout, harvest_timeout=harvest_timeout,
            force=force,
        )


def main() -> None:
    """Entrypoint for the mcp-ssh server."""
    parser = argparse.ArgumentParser(
        prog="better-ssh-mcp",
        description="MCP server exposing SSH operations as tools",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {importlib.metadata.version('better-ssh-mcp')}",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Path to servers.toml config file (overrides MCP_SSH_CONFIG env var)",
    )
    args = parser.parse_args()

    if args.config:
        os.environ["MCP_SSH_CONFIG"] = args.config

    # Set up basic logging to stderr so it doesn't pollute MCP stdio
    logging.basicConfig(
        level=logging.WARNING,
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )

    mcp, ctx = _build_app()

    # Graceful shutdown on SIGTERM
    loop = asyncio.get_event_loop()

    def _shutdown() -> None:
        logger.warning("Received SIGTERM; shutting down.")
        async def _close() -> None:
            await ctx.pool.close_all()
            ctx.audit.close()
        loop.create_task(_close())

    loop.add_signal_handler(signal.SIGTERM, _shutdown)

    mcp.run(transport="stdio")

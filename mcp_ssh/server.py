"""MCP server entrypoint for mcp-ssh (T4).

Wires together all components and registers all 18 MCP tools.
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
    pool = ConnectionPool(app_config.servers, app_config.settings)

    session_manager = SessionManager(
        pool=pool,
        state=state,
        audit=audit,
        settings=app_config.settings,
        servers=app_config.servers,
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
    """Register all 15 SSH MCP tools on the FastMCP app."""
    from .tools.exec_tools import (
        ssh_check_process,
        ssh_exec,
        ssh_exec_stream,
        ssh_kill_process,
        ssh_list_processes,
        ssh_read_process,
        ssh_write_process,
    )
    from .tools.pty_tools import (
        ssh_pty_attach,
        ssh_pty_close,
        ssh_pty_read,
        ssh_pty_resize,
        ssh_pty_write,
        ssh_start_pty,
    )
    from .tools.registry_tools import async_ssh_add_known_host

    # --- Registry tools (T3a) ---

    @mcp.tool()
    def ssh_list_servers_tool() -> dict[str, Any]:  # type: ignore[return]
        """List all registered SSH servers and their connection statuses."""
        from .tools.registry_tools import ssh_list_servers as _fn
        return _fn(registry=ctx.registry, pool=ctx.pool)

    @mcp.tool()
    def ssh_register_server_tool(  # type: ignore[return]
        name: str,
        host: str,
        user: str,
        auth_type: str,
        port: int = 22,
        key_path: str | None = None,
        cert_path: str | None = None,
        password_env: str | None = None,
        jump_host: str | None = None,
        host_key_policy: str | None = None,
        default_cwd: str | None = None,
        max_sessions: int | None = None,
        keepalive_interval: int | None = None,
    ) -> dict[str, Any]:
        """Register a new SSH server configuration."""
        from .tools.registry_tools import ssh_register_server as _fn
        return _fn(
            name=name, host=host, user=user, auth_type=auth_type,
            registry=ctx.registry, audit=ctx.audit,
            port=port, key_path=key_path, cert_path=cert_path,
            password_env=password_env, jump_host=jump_host,
            host_key_policy=host_key_policy, default_cwd=default_cwd,
            max_sessions=max_sessions, keepalive_interval=keepalive_interval,
        )

    @mcp.tool()
    def ssh_deregister_server_tool(name: str) -> dict[str, Any]:  # type: ignore[return]
        """Deregister a previously registered SSH server."""
        from .tools.registry_tools import ssh_deregister_server as _fn
        return _fn(name=name, registry=ctx.registry, pool=ctx.pool, audit=ctx.audit)

    @mcp.tool()
    async def ssh_add_known_host_tool(name: str) -> dict[str, Any]:  # type: ignore[return]
        """Connect and record the server's host key in known_hosts."""
        return await async_ssh_add_known_host(
            name=name, registry=ctx.registry, pool=ctx.pool, audit=ctx.audit
        )

    @mcp.tool()
    def ssh_show_known_host_tool(name: str) -> dict[str, Any]:  # type: ignore[return]
        """Show the stored known host key for a registered server."""
        from .tools.registry_tools import ssh_show_known_host as _fn
        return _fn(name=name, registry=ctx.registry)

    # --- Exec tools (T3b) ---

    @mcp.tool()
    async def ssh_exec_tool(  # type: ignore[return]
        server: str,
        command: str,
        cwd: str | None = None,
        timeout: float | None = 30.0,
    ) -> dict[str, Any]:
        """Run a command on a remote server and wait for completion."""
        return await ssh_exec(
            server=server, command=command,
            registry=ctx.registry, pool=ctx.pool, audit=ctx.audit,
            cwd=cwd, timeout=timeout,
        )

    @mcp.tool()
    async def ssh_exec_stream_tool(  # type: ignore[return]
        server: str,
        command: str,
        cwd: str | None = None,
    ) -> dict[str, Any]:
        """Start a long-running background process (nohup-backed)."""
        return await ssh_exec_stream(
            server=server, command=command,
            session_manager=ctx.session_manager, audit=ctx.audit,
            cwd=cwd,
        )

    @mcp.tool()
    async def ssh_read_process_tool(  # type: ignore[return]
        process_id: str,
        max_bytes: int = 65536,
    ) -> dict[str, Any]:
        """Read buffered output from a background process."""
        return await ssh_read_process(
            process_id=process_id,
            session_manager=ctx.session_manager,
            max_bytes=max_bytes,
        )

    @mcp.tool()
    async def ssh_write_process_tool(process_id: str, data: str) -> dict[str, Any]:  # type: ignore[return]
        """Write data to a background process's stdin."""
        return await ssh_write_process(
            process_id=process_id, data=data, session_manager=ctx.session_manager
        )

    @mcp.tool()
    async def ssh_kill_process_tool(  # type: ignore[return]
        process_id: str, signal: str = "SIGTERM"
    ) -> dict[str, Any]:
        """Send a signal to a background process."""
        return await ssh_kill_process(
            process_id=process_id, session_manager=ctx.session_manager, signal=signal
        )

    @mcp.tool()
    def ssh_list_processes_tool(server: str | None = None) -> dict[str, Any]:  # type: ignore[return]
        """List tracked background processes, optionally filtered by server."""
        return ssh_list_processes(session_manager=ctx.session_manager, server=server)

    @mcp.tool()
    async def ssh_check_process_tool(process_id: str) -> dict[str, Any]:  # type: ignore[return]
        """Check liveness of a background process and return its status."""
        return await ssh_check_process(
            process_id=process_id, session_manager=ctx.session_manager
        )

    # --- PTY tools (T3c) ---

    @mcp.tool()
    async def ssh_start_pty_tool(  # type: ignore[return]
        server: str,
        command: str | None = None,
        cols: int = 220,
        rows: int = 50,
        use_tmux: bool = False,
    ) -> dict[str, Any]:
        """Open a PTY session on a remote server."""
        return await ssh_start_pty(
            server=server, session_manager=ctx.session_manager, audit=ctx.audit,
            command=command, cols=cols, rows=rows, use_tmux=use_tmux,
        )

    @mcp.tool()
    async def ssh_pty_read_tool(  # type: ignore[return]
        session_id: str, max_bytes: int = 65536
    ) -> dict[str, Any]:
        """Read buffered output from a PTY session."""
        return await ssh_pty_read(
            session_id=session_id, session_manager=ctx.session_manager, max_bytes=max_bytes
        )

    @mcp.tool()
    async def ssh_pty_write_tool(session_id: str, data: str) -> dict[str, Any]:  # type: ignore[return]
        """Write data to a PTY session (use \\r to submit a line)."""
        return await ssh_pty_write(
            session_id=session_id, data=data, session_manager=ctx.session_manager
        )

    @mcp.tool()
    async def ssh_pty_resize_tool(  # type: ignore[return]
        session_id: str, cols: int, rows: int
    ) -> dict[str, Any]:
        """Resize a PTY session."""
        return await ssh_pty_resize(
            session_id=session_id, cols=cols, rows=rows,
            session_manager=ctx.session_manager,
        )

    @mcp.tool()
    async def ssh_pty_close_tool(session_id: str) -> dict[str, Any]:  # type: ignore[return]
        """Close a PTY session and clean up resources."""
        return await ssh_pty_close(
            session_id=session_id, session_manager=ctx.session_manager, audit=ctx.audit
        )

    @mcp.tool()
    async def ssh_pty_attach_tool(session_id: str) -> dict[str, Any]:  # type: ignore[return]
        """Attach to an existing tmux-backed PTY session."""
        return await ssh_pty_attach(
            session_id=session_id, session_manager=ctx.session_manager
        )


def main() -> None:
    """Entrypoint for the mcp-ssh server."""
    parser = argparse.ArgumentParser(
        prog="mcp-ssh",
        description="MCP server exposing SSH operations as tools",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {importlib.metadata.version('mcp-ssh')}",
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

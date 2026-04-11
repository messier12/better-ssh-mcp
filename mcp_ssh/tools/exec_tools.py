"""MCP tools for non-interactive exec process management (T3b)."""
from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from ..exceptions import McpSshError, ProcessNotFound, ServerNotFound
from ..interfaces import IAuditLog, IConnectionPool, IRegistry, ISessionManager
from ..models import AuditEvent
from ..utils import now

logger = logging.getLogger(__name__)

DEFAULT_EXEC_TIMEOUT = 30  # seconds


async def ssh_exec(
    server: str,
    command: str,
    registry: IRegistry,
    pool: IConnectionPool,
    audit: IAuditLog,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout: float | None = DEFAULT_EXEC_TIMEOUT,
) -> dict[str, Any]:
    """Run a command on *server* and wait for it to complete.

    Falls back to ``ServerConfig.default_cwd`` and ``ServerConfig.default_env``
    when *cwd* / *env* are not provided.

    Returns ``{output, exit_code, server}`` on success or a structured error dict.
    ``timeout`` defaults to 30 s; pass ``None`` to wait indefinitely (logged at WARN).
    """
    if timeout is None:
        logger.warning(
            "ssh_exec called with timeout=None for command %r on server %r. "
            "The operation may hang indefinitely.",
            command,
            server,
        )
        audit.log(
            AuditEvent(
                ts=now(),
                tool="ssh_exec",
                server=server,
                command=command,
                outcome="warn_no_timeout",
                detail={"cwd": cwd, "env_keys": list((env or {}).keys())},
            )
        )

    try:
        cfg = registry.get(server)
    except ServerNotFound:
        return {
            "error": "server_not_found",
            "server": server,
            "message": f"Server {server!r} is not registered.",
        }

    # Apply defaults from ServerConfig
    effective_cwd = cwd if cwd is not None else cfg.default_cwd
    effective_env: dict[str, str] = {**cfg.default_env, **(env or {})}

    try:
        conn = await pool.get_connection(server)
    except McpSshError as exc:
        return {"error": "connection_error", "server": server, "message": str(exc)}

    try:
        import shlex

        env_exports = " ".join(
            f"{shlex.quote(k)}={shlex.quote(v)}" for k, v in effective_env.items()
        )
        cd_part = f"cd {shlex.quote(effective_cwd)} && " if effective_cwd else ""
        full_cmd = cd_part + (env_exports + " " if env_exports else "") + command

        coro = conn.run(full_cmd)
        if timeout is not None:
            result = await asyncio.wait_for(coro, timeout=timeout)
        else:
            result = await coro
    except TimeoutError:
        audit.log(
            AuditEvent(
                ts=now(),
                tool="ssh_exec",
                server=server,
                command=command,
                outcome="timeout",
                detail={"timeout_s": timeout},
            )
        )
        return {
            "error": "timeout",
            "server": server,
            "command": command,
            "message": f"Command timed out after {timeout} s.",
        }
    except McpSshError as exc:
        return {"error": "execution_error", "server": server, "message": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"error": "unexpected_error", "server": server, "message": str(exc)}

    output = str(result.stdout or "") + str(result.stderr or "")
    exit_code: int = result.exit_status if result.exit_status is not None else -1

    audit.log(
        AuditEvent(
            ts=now(),
            tool="ssh_exec",
            server=server,
            command=command,
            outcome="completed",
            detail={"exit_code": exit_code},
        )
    )
    return {
        "output": output,
        "exit_code": exit_code,
        "server": server,
    }


async def ssh_exec_stream(
    server: str,
    command: str,
    session_manager: ISessionManager,
    audit: IAuditLog,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Start a long-running background process on *server* (nohup-backed).

    Returns ``{process_id, server, command}`` immediately; use
    ``ssh_read_process`` to poll for output.
    """
    try:
        process_id = await session_manager.start_process(
            server=server,
            command=command,
            cwd=cwd,
            env=env,
        )
    except McpSshError as exc:
        return {"error": "start_error", "server": server, "message": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"error": "unexpected_error", "server": server, "message": str(exc)}

    return {
        "process_id": process_id,
        "server": server,
        "command": command,
    }


async def ssh_read_process(
    process_id: str,
    session_manager: ISessionManager,
    max_bytes: int = 65536,
) -> dict[str, Any]:
    """Read buffered output from a background process.

    Returns ``{output, running, exit_code, remote_pid, server}``
    or a structured error if *process_id* is unknown.
    """
    try:
        out = await session_manager.read_process(process_id, max_bytes=max_bytes)
    except ProcessNotFound:
        return {
            "error": "process_not_found",
            "process_id": process_id,
            "message": f"Process {process_id!r} not found.",
        }
    except McpSshError as exc:
        return {"error": "read_error", "process_id": process_id, "message": str(exc)}

    return {
        "output": out.output,
        "running": out.running,
        "exit_code": out.exit_code,
        "remote_pid": out.remote_pid,
        "server": out.server,
    }


async def ssh_write_process(
    process_id: str,
    data: str,
    session_manager: ISessionManager,
) -> dict[str, Any]:
    """Write *data* to a background process's stdin.

    Note: nohup-backed processes do not have stdin; this always returns an error.
    """
    try:
        await session_manager.write_process(process_id, data)
    except ProcessNotFound:
        return {
            "error": "process_not_found",
            "process_id": process_id,
            "message": f"Process {process_id!r} not found.",
        }
    except McpSshError as exc:
        return {"error": "write_error", "process_id": process_id, "message": str(exc)}

    return {"written": True, "process_id": process_id}


async def ssh_kill_process(
    process_id: str,
    session_manager: ISessionManager,
    signal: str = "SIGTERM",
) -> dict[str, Any]:
    """Send *signal* to a background process.

    Allowed signals: SIGTERM, SIGKILL, SIGINT, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2.
    """
    try:
        await session_manager.kill_process(process_id, signal=signal)
    except ProcessNotFound:
        return {
            "error": "process_not_found",
            "process_id": process_id,
            "message": f"Process {process_id!r} not found.",
        }
    except McpSshError as exc:
        return {"error": "kill_error", "process_id": process_id, "message": str(exc)}

    return {"killed": True, "process_id": process_id, "signal": signal}


def ssh_list_processes(
    session_manager: ISessionManager,
    server: str | None = None,
) -> dict[str, Any]:
    """List tracked background processes, optionally filtered by *server*.

    Always returns a list (empty if *server* has no processes or is unknown).
    Each entry includes a human-readable ``last_checked_ago`` field.
    """
    records = session_manager.list_processes(server=server)
    items = []
    ref = datetime.now(UTC)
    for rec in records:
        last_checked_ago: str
        if rec.last_checked is None:
            last_checked_ago = "never"
        else:
            lc = rec.last_checked
            if lc.tzinfo is None:
                lc = lc.replace(tzinfo=UTC)
            delta = ref - lc
            secs = int(delta.total_seconds())
            if secs < 60:
                last_checked_ago = f"{secs}s ago"
            elif secs < 3600:
                last_checked_ago = f"{secs // 60}m ago"
            else:
                last_checked_ago = f"{secs // 3600}h ago"

        items.append(
            {
                "process_id": rec.id,
                "server": rec.server,
                "command": rec.command,
                "remote_pid": rec.remote_pid,
                "status": rec.status.value,
                "exit_code": rec.exit_code,
                "started_at": rec.started_at.isoformat(),
                "last_checked_ago": last_checked_ago,
            }
        )
    return {"processes": items}


async def ssh_check_process(
    process_id: str,
    session_manager: ISessionManager,
) -> dict[str, Any]:
    """Check liveness of a background process and return its status.

    Runs ``kill -0`` on the remote and reads the exit file.
    Returns ``{output, running, exit_code, remote_pid, server}``
    or a structured error if *process_id* is unknown.
    """
    try:
        out = await session_manager.check_process(process_id)
    except ProcessNotFound:
        return {
            "error": "process_not_found",
            "process_id": process_id,
            "message": f"Process {process_id!r} not found.",
        }
    except McpSshError as exc:
        return {"error": "check_error", "process_id": process_id, "message": str(exc)}

    return {
        "output": out.output,
        "running": out.running,
        "exit_code": out.exit_code,
        "remote_pid": out.remote_pid,
        "server": out.server,
    }

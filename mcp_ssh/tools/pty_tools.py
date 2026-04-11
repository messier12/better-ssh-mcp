"""MCP tools for PTY session management (T3c)."""
from __future__ import annotations

from typing import Any

from ..exceptions import (
    McpSshError,
    SessionCapExceeded,
    SessionNotFound,
    TmuxNotAvailable,
)
from ..interfaces import IAuditLog, ISessionManager
from ..models import AuditEvent
from ..utils import now


async def ssh_start_pty(
    server: str,
    session_manager: ISessionManager,
    audit: IAuditLog,
    command: str | None = None,
    cols: int = 220,
    rows: int = 50,
    use_tmux: bool = False,
) -> dict[str, Any]:
    """Open a PTY session on *server*.

    With ``use_tmux=True`` the session is backed by a tmux window; output is
    persisted and the session survives MCP reconnects. If tmux is not installed
    on the remote host a structured error is returned — there is **no** silent
    fallback to a non-tmux session.

    Returns ``{session_id, use_tmux, server, command}`` on success.
    """
    try:
        session_id = await session_manager.start_pty(
            server=server,
            command=command,
            cols=cols,
            rows=rows,
            use_tmux=use_tmux,
        )
    except TmuxNotAvailable as exc:
        return {
            "error": "tmux_not_available",
            "server": server,
            "message": str(exc),
        }
    except SessionCapExceeded as exc:
        return {
            "error": "session_cap_exceeded",
            "server": server,
            "message": str(exc),
        }
    except McpSshError as exc:
        return {"error": "start_error", "server": server, "message": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"error": "unexpected_error", "server": server, "message": str(exc)}

    audit.log(
        AuditEvent(
            ts=now(),
            tool="ssh_start_pty",
            server=server,
            command=command,
            session_id=session_id,
            outcome="started",
            detail={"use_tmux": use_tmux, "cols": cols, "rows": rows},
        )
    )
    return {
        "session_id": session_id,
        "use_tmux": use_tmux,
        "server": server,
        "command": command,
    }


async def ssh_pty_read(
    session_id: str,
    session_manager: ISessionManager,
    max_bytes: int = 65536,
) -> dict[str, Any]:
    """Read buffered output from a PTY session.

    Returns ``{output, alive}`` or a structured error if *session_id* is unknown.
    """
    try:
        out = await session_manager.pty_read(session_id, max_bytes=max_bytes)
    except SessionNotFound:
        return {
            "error": "session_not_found",
            "session_id": session_id,
            "message": f"Session {session_id!r} not found.",
        }
    except McpSshError as exc:
        return {"error": "read_error", "session_id": session_id, "message": str(exc)}

    return {"output": out.output, "alive": out.alive}


async def ssh_pty_write(
    session_id: str,
    data: str,
    session_manager: ISessionManager,
) -> dict[str, Any]:
    """Write *data* to a PTY session.

    Note: use ``\\r`` (not ``\\n``) to submit a command line in interactive shells
    and tmux sessions.

    Returns ``{written: true}`` or a structured error.
    """
    try:
        await session_manager.pty_write(session_id, data)
    except SessionNotFound:
        return {
            "error": "session_not_found",
            "session_id": session_id,
            "message": f"Session {session_id!r} not found.",
        }
    except McpSshError as exc:
        return {"error": "write_error", "session_id": session_id, "message": str(exc)}

    return {"written": True, "session_id": session_id}


async def ssh_pty_resize(
    session_id: str,
    cols: int,
    rows: int,
    session_manager: ISessionManager,
) -> dict[str, Any]:
    """Resize the PTY terminal for *session_id* to *cols* × *rows*.

    Returns ``{resized: true}`` or a structured error.
    """
    try:
        await session_manager.pty_resize(session_id, cols=cols, rows=rows)
    except SessionNotFound:
        return {
            "error": "session_not_found",
            "session_id": session_id,
            "message": f"Session {session_id!r} not found.",
        }
    except McpSshError as exc:
        return {"error": "resize_error", "session_id": session_id, "message": str(exc)}

    return {"resized": True, "session_id": session_id, "cols": cols, "rows": rows}


async def ssh_pty_close(
    session_id: str,
    session_manager: ISessionManager,
    audit: IAuditLog,
) -> dict[str, Any]:
    """Close a PTY session and clean up local resources.

    For tmux-backed sessions the remote tmux window is left alive; only the
    local channel is cleaned up.

    Returns ``{closed: true}`` or a structured error.
    """
    try:
        await session_manager.pty_close(session_id)
    except SessionNotFound:
        return {
            "error": "session_not_found",
            "session_id": session_id,
            "message": f"Session {session_id!r} not found.",
        }
    except McpSshError as exc:
        return {"error": "close_error", "session_id": session_id, "message": str(exc)}

    audit.log(
        AuditEvent(
            ts=now(),
            tool="ssh_pty_close",
            session_id=session_id,
            outcome="closed",
            detail={},
        )
    )
    return {"closed": True, "session_id": session_id}


async def ssh_pty_attach(
    session_id: str,
    session_manager: ISessionManager,
) -> dict[str, Any]:
    """Attach to an existing tmux-backed PTY session.

    Only supported for sessions created with ``use_tmux=True``. Returns a
    structured error for non-tmux sessions or if the tmux window no longer exists.
    """
    try:
        await session_manager.pty_attach(session_id)
    except SessionNotFound as exc:
        return {
            "error": "session_not_found",
            "session_id": session_id,
            "message": str(exc),
        }
    except NotImplementedError as exc:
        # pty_attach is not supported in the MCP stdio transport context
        return {
            "error": "not_supported_in_mcp",
            "session_id": session_id,
            "message": str(exc),
        }
    except McpSshError as exc:
        return {"error": "attach_error", "session_id": session_id, "message": str(exc)}

    return {"attached": True, "session_id": session_id}

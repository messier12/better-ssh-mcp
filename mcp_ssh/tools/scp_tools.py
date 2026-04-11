"""MCP tools for SCP file transfer (ssh_get / ssh_put)."""
from __future__ import annotations

import logging
import os
from typing import Any

import asyncssh

from ..exceptions import McpSshError, ServerNotFound
from ..interfaces import IAuditLog, IConnectionPool, IRegistry
from ..models import AuditEvent
from ..utils import now

logger = logging.getLogger(__name__)


async def ssh_get(
    server: str,
    remote_path: str,
    local_path: str,
    registry: IRegistry,
    pool: IConnectionPool,
    audit: IAuditLog,
    recurse: bool = False,
    preserve: bool = False,
) -> dict[str, Any]:
    """Download a file or directory from *server* to *local_path*.

    Returns ``{server, remote_path, local_path}`` on success or a structured error dict.
    Set *recurse=True* to copy directories recursively.
    Set *preserve=False* to keep original timestamps and permissions.
    """
    try:
        registry.get(server)
    except ServerNotFound:
        return {"error": "server_not_found", "server": server,
                "message": f"Server {server!r} is not registered."}

    local_path = os.path.expanduser(local_path)

    audit.log(AuditEvent(
        ts=now(), tool="ssh_get", server=server,
        outcome="start",
        detail={"remote_path": remote_path, "local_path": local_path, "recurse": recurse},
    ))

    try:
        conn = await pool.get_connection(server)
        await asyncssh.scp(
            (conn, remote_path),
            local_path,
            recurse=recurse,
            preserve=preserve,
        )
    except McpSshError as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_get", server=server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "connection_error", "server": server, "message": str(exc)}
    except (asyncssh.SFTPError, OSError) as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_get", server=server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "transfer_error", "server": server, "message": str(exc)}
    except Exception as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_get", server=server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "unexpected_error", "server": server, "message": str(exc)}

    audit.log(AuditEvent(
        ts=now(), tool="ssh_get", server=server,
        outcome="ok",
        detail={"remote_path": remote_path, "local_path": local_path},
    ))
    return {"server": server, "remote_path": remote_path, "local_path": local_path}


async def ssh_put(
    server: str,
    local_path: str,
    remote_path: str,
    registry: IRegistry,
    pool: IConnectionPool,
    audit: IAuditLog,
    recurse: bool = False,
    preserve: bool = False,
) -> dict[str, Any]:
    """Upload a file or directory from *local_path* to *server*:*remote_path*.

    Returns ``{server, local_path, remote_path}`` on success or a structured error dict.
    Set *recurse=True* to copy directories recursively.
    Set *preserve=True* to keep original timestamps and permissions.
    """
    try:
        registry.get(server)
    except ServerNotFound:
        return {"error": "server_not_found", "server": server,
                "message": f"Server {server!r} is not registered."}

    local_path = os.path.expanduser(local_path)

    audit.log(AuditEvent(
        ts=now(), tool="ssh_put", server=server,
        outcome="start",
        detail={"local_path": local_path, "remote_path": remote_path, "recurse": recurse},
    ))

    try:
        conn = await pool.get_connection(server)
        await asyncssh.scp(
            local_path,
            (conn, remote_path),
            recurse=recurse,
            preserve=preserve,
        )
    except McpSshError as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_put", server=server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "connection_error", "server": server, "message": str(exc)}
    except (asyncssh.SFTPError, OSError) as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_put", server=server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "transfer_error", "server": server, "message": str(exc)}
    except Exception as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_put", server=server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "unexpected_error", "server": server, "message": str(exc)}

    audit.log(AuditEvent(
        ts=now(), tool="ssh_put", server=server,
        outcome="ok",
        detail={"local_path": local_path, "remote_path": remote_path},
    ))
    return {"server": server, "local_path": local_path, "remote_path": remote_path}

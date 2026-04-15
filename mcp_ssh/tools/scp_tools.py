"""MCP tools for SCP file transfer (ssh_get / ssh_put / ssh_copy / ssh_move)."""
from __future__ import annotations

import logging
import os
import shlex
import tempfile
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


async def ssh_copy(
    src_server: str,
    src_path: str,
    dst_server: str,
    dst_path: str,
    registry: IRegistry,
    pool: IConnectionPool,
    audit: IAuditLog,
    recurse: bool = False,
    preserve: bool = False,
) -> dict[str, Any]:
    """Copy a file or directory from *src_server*:*src_path* to *dst_server*:*dst_path*.

    When both servers are the same, runs ``cp -r`` remotely without a local relay.
    For different servers, relays through a local temporary directory.
    Returns ``{src_server, src_path, dst_server, dst_path}`` on success.
    """
    try:
        registry.get(src_server)
    except ServerNotFound:
        return {"error": "server_not_found", "server": src_server,
                "message": f"Server {src_server!r} is not registered."}
    try:
        registry.get(dst_server)
    except ServerNotFound:
        return {"error": "server_not_found", "server": dst_server,
                "message": f"Server {dst_server!r} is not registered."}

    audit.log(AuditEvent(
        ts=now(), tool="ssh_copy", server=src_server,
        outcome="start",
        detail={"src_path": src_path, "dst_server": dst_server,
                "dst_path": dst_path, "recurse": recurse},
    ))

    try:
        if src_server == dst_server:
            conn = await pool.get_connection(src_server)
            flag = "-r " if recurse else ""
            result = await conn.run(
                f"cp {flag}{shlex.quote(src_path)} {shlex.quote(dst_path)}",
                check=False,
            )
            if result.exit_status != 0:
                raise OSError(result.stderr.strip() if result.stderr else "cp failed")
        else:
            src_conn = await pool.get_connection(src_server)
            dst_conn = await pool.get_connection(dst_server)
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = os.path.join(tmp, os.path.basename(src_path))
                await asyncssh.scp(
                    (src_conn, src_path), tmp,
                    recurse=recurse, preserve=preserve,
                )
                await asyncssh.scp(
                    tmp_path, (dst_conn, dst_path),
                    recurse=recurse, preserve=preserve,
                )
    except McpSshError as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_copy", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "connection_error", "server": src_server, "message": str(exc)}
    except (asyncssh.SFTPError, OSError) as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_copy", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "transfer_error", "server": src_server, "message": str(exc)}
    except Exception as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_copy", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "unexpected_error", "server": src_server, "message": str(exc)}

    audit.log(AuditEvent(
        ts=now(), tool="ssh_copy", server=src_server,
        outcome="ok",
        detail={"src_path": src_path, "dst_server": dst_server, "dst_path": dst_path},
    ))
    return {
        "src_server": src_server, "src_path": src_path,
        "dst_server": dst_server, "dst_path": dst_path,
    }


async def ssh_move(
    src_server: str,
    src_path: str,
    dst_server: str,
    dst_path: str,
    registry: IRegistry,
    pool: IConnectionPool,
    audit: IAuditLog,
    recurse: bool = False,
    preserve: bool = False,
) -> dict[str, Any]:
    """Move a file or directory from *src_server*:*src_path* to *dst_server*:*dst_path*.

    Same-server moves use ``mv`` (atomic on the same filesystem).
    Cross-server moves copy via a local temp relay then delete the source.
    If the copy succeeds but the source delete fails, returns a warning dict
    rather than an error — the data is safe at the destination.
    Returns ``{src_server, src_path, dst_server, dst_path}`` on full success.
    """
    try:
        registry.get(src_server)
    except ServerNotFound:
        return {"error": "server_not_found", "server": src_server,
                "message": f"Server {src_server!r} is not registered."}
    try:
        registry.get(dst_server)
    except ServerNotFound:
        return {"error": "server_not_found", "server": dst_server,
                "message": f"Server {dst_server!r} is not registered."}

    audit.log(AuditEvent(
        ts=now(), tool="ssh_move", server=src_server,
        outcome="start",
        detail={"src_path": src_path, "dst_server": dst_server,
                "dst_path": dst_path, "recurse": recurse},
    ))

    try:
        if src_server == dst_server:
            conn = await pool.get_connection(src_server)
            result = await conn.run(
                f"mv {shlex.quote(src_path)} {shlex.quote(dst_path)}",
                check=False,
            )
            if result.exit_status != 0:
                raise OSError(result.stderr.strip() if result.stderr else "mv failed")
        else:
            src_conn = await pool.get_connection(src_server)
            dst_conn = await pool.get_connection(dst_server)

            # Copy phase
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = os.path.join(tmp, os.path.basename(src_path))
                await asyncssh.scp(
                    (src_conn, src_path), tmp,
                    recurse=recurse, preserve=preserve,
                )
                await asyncssh.scp(
                    tmp_path, (dst_conn, dst_path),
                    recurse=recurse, preserve=preserve,
                )

            # Delete phase — non-fatal if it fails
            del_result = await src_conn.run(
                f"rm -rf {shlex.quote(src_path)}", check=False
            )
            if del_result.exit_status != 0:
                del_err = del_result.stderr.strip() if del_result.stderr else "rm failed"
                audit.log(AuditEvent(
                    ts=now(), tool="ssh_move", server=src_server,
                    outcome="warn_no_timeout",
                    detail={"warning": "copy_succeeded_delete_failed",
                            "delete_error": del_err},
                ))
                return {
                    "warning": "copy_succeeded_delete_failed",
                    "src_server": src_server, "src_path": src_path,
                    "dst_server": dst_server, "dst_path": dst_path,
                    "delete_error": del_err,
                }
    except McpSshError as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_move", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "connection_error", "server": src_server, "message": str(exc)}
    except (asyncssh.SFTPError, OSError) as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_move", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "transfer_error", "server": src_server, "message": str(exc)}
    except Exception as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_move", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "unexpected_error", "server": src_server, "message": str(exc)}

    audit.log(AuditEvent(
        ts=now(), tool="ssh_move", server=src_server,
        outcome="ok",
        detail={"src_path": src_path, "dst_server": dst_server, "dst_path": dst_path},
    ))
    return {
        "src_server": src_server, "src_path": src_path,
        "dst_server": dst_server, "dst_path": dst_path,
    }

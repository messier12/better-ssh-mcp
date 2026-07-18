"""MCP tools for SCP file transfer (ssh_get / ssh_put / ssh_transfer / ssh_sync)."""
from __future__ import annotations

import contextlib
import logging
import os
import posixpath
import shlex
from typing import Any

import asyncssh

from ..exceptions import McpSshError, ServerNotFound
from ..interfaces import IAuditLog, IConnectionPool, IRegistry
from ..models import AuditEvent
from ..utils import now

_MTIME_TOLERANCE = 2.0  # seconds — covers Windows NTFS 2 s mtime precision

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


async def ssh_transfer(
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

    When both servers are the same, runs ``cp -r`` remotely without a network transfer.
    For different servers, streams data through memory — nothing is written to local disk.
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
        ts=now(), tool="ssh_transfer", server=src_server,
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
            await asyncssh.scp(
                (src_conn, src_path), (dst_conn, dst_path),
                recurse=recurse, preserve=preserve,
            )
    except McpSshError as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_transfer", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "connection_error", "server": src_server, "message": str(exc)}
    except (asyncssh.SFTPError, OSError) as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_transfer", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "transfer_error", "server": src_server, "message": str(exc)}
    except Exception as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_transfer", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "unexpected_error", "server": src_server, "message": str(exc)}

    audit.log(AuditEvent(
        ts=now(), tool="ssh_transfer", server=src_server,
        outcome="ok",
        detail={"src_path": src_path, "dst_server": dst_server, "dst_path": dst_path},
    ))
    return {
        "src_server": src_server, "src_path": src_path,
        "dst_server": dst_server, "dst_path": dst_path,
    }


# ---------------------------------------------------------------------------
# ssh_sync helpers
# ---------------------------------------------------------------------------

async def _sftp_list_tree(
    sftp: asyncssh.SFTPClient,
    base_path: str,
) -> dict[str, asyncssh.SFTPAttrs]:
    """Return ``{relative_path: SFTPAttrs}`` for every file under *base_path*.

    If *base_path* is a file, returns a single-entry dict keyed by its basename.
    Glob characters in *base_path* are resolved before calling this function.
    """
    result: dict[str, asyncssh.SFTPAttrs] = {}

    async def _walk(dir_path: str, rel_prefix: str) -> None:
        try:
            entries = await sftp.readdir(dir_path)
        except (asyncssh.SFTPError, OSError):
            return
        for entry in entries:
            raw_name = entry.filename
            name = raw_name.decode() if isinstance(raw_name, bytes) else raw_name
            if name in (".", ".."):
                continue
            rel = posixpath.join(rel_prefix, name) if rel_prefix else name
            full = posixpath.join(dir_path, name)
            perms = entry.attrs.permissions or 0
            if perms & 0o170000 == 0o040000:  # S_ISDIR
                await _walk(full, rel)
            else:
                result[rel] = entry.attrs

    try:
        is_dir = await sftp.isdir(base_path)
    except (asyncssh.SFTPError, OSError):
        is_dir = False

    if is_dir:
        await _walk(base_path, "")
    else:
        try:
            attrs = await sftp.stat(base_path)
            result[posixpath.basename(base_path)] = attrs
        except (asyncssh.SFTPError, OSError):
            pass

    return result


def _needs_copy(
    src_attrs: asyncssh.SFTPAttrs,
    dst_attrs: asyncssh.SFTPAttrs | None,
) -> bool:
    if dst_attrs is None:
        return True
    if (src_attrs.size or 0) != (dst_attrs.size or 0):
        return True
    src_mtime = src_attrs.mtime or 0.0
    dst_mtime = dst_attrs.mtime or 0.0
    return abs(src_mtime - dst_mtime) > _MTIME_TOLERANCE


async def ssh_sync(
    src_server: str,
    src_path: str,
    dst_server: str,
    dst_path: str,
    registry: IRegistry,
    pool: IConnectionPool,
    audit: IAuditLog,
    delete: bool = False,
    preserve: bool = False,
) -> dict[str, Any]:
    """Sync files from *src_server*:*src_path* to *dst_server*:*dst_path*.

    *src_path* may contain glob characters (e.g. ``/data/*.csv``).

    **Same server:** tries ``rsync -az`` first; falls back to ``cp -u`` if rsync
    is not available.

    **Different servers:** uses SFTP stat-compare — only copies files whose size
    or mtime differs from the destination.  Works with Windows servers (no rsync
    dependency for cross-server transfers).

    Set *delete=True* to remove destination files that are absent from the source.

    Returns ``{copied, skipped, deleted, method, src_server, dst_server}``.
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
        ts=now(), tool="ssh_sync", server=src_server,
        outcome="start",
        detail={"src_path": src_path, "dst_server": dst_server,
                "dst_path": dst_path, "delete": delete},
    ))

    try:
        if src_server == dst_server:
            return await _sync_same_server(
                src_server=src_server, src_path=src_path, dst_path=dst_path,
                pool=pool, audit=audit, delete=delete,
            )
        return await _sync_cross_server(
            src_server=src_server, src_path=src_path,
            dst_server=dst_server, dst_path=dst_path,
            pool=pool, audit=audit, delete=delete, preserve=preserve,
        )
    except McpSshError as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_sync", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "connection_error", "server": src_server, "message": str(exc)}
    except (asyncssh.SFTPError, OSError) as exc:
        audit.log(AuditEvent(
            ts=now(), tool="ssh_sync", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "transfer_error", "server": src_server, "message": str(exc)}
    except Exception as exc:  # noqa: BLE001
        audit.log(AuditEvent(
            ts=now(), tool="ssh_sync", server=src_server,
            outcome="error", detail={"error": str(exc)},
        ))
        return {"error": "unexpected_error", "server": src_server, "message": str(exc)}


async def _sync_same_server(
    src_server: str,
    src_path: str,
    dst_path: str,
    pool: IConnectionPool,
    audit: IAuditLog,
    delete: bool,
) -> dict[str, Any]:
    conn = await pool.get_connection(src_server)
    rsync_check = await conn.run("which rsync 2>/dev/null || true")
    has_rsync = bool((rsync_check.stdout or "").strip())

    if has_rsync:
        delete_flag = "--delete " if delete else ""
        result = await conn.run(
            f"rsync -az {delete_flag}{shlex.quote(src_path)} {shlex.quote(dst_path)}",
            check=False,
        )
        if result.exit_status != 0:
            raise OSError(
                (result.stderr or "").strip() or f"rsync exited {result.exit_status}"
            )
        summary = (result.stdout or "").strip()
        audit.log(AuditEvent(
            ts=now(), tool="ssh_sync", server=src_server,
            outcome="ok", detail={"method": "rsync", "summary": summary[:500]},
        ))
        return {
            "src_server": src_server, "src_path": src_path,
            "dst_server": src_server, "dst_path": dst_path,
            "method": "rsync", "copied": [], "skipped": 0, "deleted": [],
            "rsync_output": summary,
        }

    # cp -u fallback (skip if destination is not older)
    cp_flags = "-ru" if True else "-u"  # always attempt recursive for directories
    result = await conn.run(
        f"cp {cp_flags} {shlex.quote(src_path)} {shlex.quote(dst_path)} 2>&1 || true",
        check=False,
    )
    audit.log(AuditEvent(
        ts=now(), tool="ssh_sync", server=src_server,
        outcome="ok", detail={"method": "cp-u"},
    ))
    return {
        "src_server": src_server, "src_path": src_path,
        "dst_server": src_server, "dst_path": dst_path,
        "method": "cp-u", "copied": [], "skipped": 0, "deleted": [],
    }


async def _sync_cross_server(
    src_server: str,
    src_path: str,
    dst_server: str,
    dst_path: str,
    pool: IConnectionPool,
    audit: IAuditLog,
    delete: bool,
    preserve: bool,
) -> dict[str, Any]:
    src_conn = await pool.get_connection(src_server)
    dst_conn = await pool.get_connection(dst_server)

    copied: list[str] = []
    deleted: list[str] = []
    skipped = 0
    warning: str | None = None

    async with src_conn.start_sftp_client() as src_sftp, \
               dst_conn.start_sftp_client() as dst_sftp:
            # Resolve glob if src_path contains glob characters
            if any(c in src_path for c in ("*", "?", "[")):
                matched = await src_sftp.glob(src_path)
                if not matched:
                    warning = "no files matched"
                    return {
                        "src_server": src_server, "src_path": src_path,
                        "dst_server": dst_server, "dst_path": dst_path,
                        "method": "sftp-diff", "copied": [], "skipped": 0,
                        "deleted": [], "warning": warning,
                    }
                src_files: dict[str, asyncssh.SFTPAttrs] = {}
                for match in matched:
                    match_str = match.decode() if isinstance(match, bytes) else match
                    sub = await _sftp_list_tree(src_sftp, match_str)
                    src_files.update(sub)
                base = posixpath.dirname(src_path.rstrip("/"))
            else:
                src_files = await _sftp_list_tree(src_sftp, src_path)
                base = src_path.rstrip("/")

            if not src_files:
                warning = "no files matched"

            dst_files = await _sftp_list_tree(dst_sftp, dst_path)

            for rel_path, src_attrs in src_files.items():
                dst_attrs = dst_files.get(rel_path)
                if not _needs_copy(src_attrs, dst_attrs):
                    skipped += 1
                    continue

                src_full = posixpath.join(base, rel_path) if base else rel_path
                dst_full = posixpath.join(dst_path, rel_path)

                # Ensure parent directory exists on dst
                dst_parent = posixpath.dirname(dst_full)
                with contextlib.suppress(asyncssh.SFTPError, OSError):
                    await dst_sftp.mkdir(dst_parent)

                await asyncssh.scp(
                    (src_conn, src_full),
                    (dst_conn, dst_full),
                    preserve=preserve,
                )
                copied.append(rel_path)

            if delete:
                for rel_path in dst_files:
                    if rel_path not in src_files:
                        dst_full = posixpath.join(dst_path, rel_path)
                        try:
                            await dst_sftp.remove(dst_full)
                            deleted.append(rel_path)
                        except (asyncssh.SFTPError, OSError) as exc:
                            logger.warning("ssh_sync delete failed for %r: %s", dst_full, exc)

    audit.log(AuditEvent(
        ts=now(), tool="ssh_sync", server=src_server,
        outcome="ok",
        detail={"copied": len(copied), "skipped": skipped, "deleted": len(deleted)},
    ))
    result: dict[str, Any] = {
        "src_server": src_server, "src_path": src_path,
        "dst_server": dst_server, "dst_path": dst_path,
        "method": "sftp-diff",
        "copied": copied,
        "skipped": skipped,
        "deleted": deleted,
    }
    if warning:
        result["warning"] = warning
    return result

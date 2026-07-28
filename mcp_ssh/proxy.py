"""Proxy manager: SSH local port-forward and SOCKS5 proxies."""
from __future__ import annotations

import contextlib
import logging
import secrets
from datetime import UTC, datetime

import asyncssh

from .exceptions import McpSshError, ProxyNotFound
from .interfaces import IAuditLog, IConnectionPool
from .models import AuditEvent, ProxyRecord, ProxyType

logger = logging.getLogger(__name__)


def _new_proxy_id() -> str:
    return "prx-" + secrets.token_hex(4)


class ProxyManager:
    def __init__(self, pool: IConnectionPool) -> None:
        self._pool = pool
        # proxy_id → (record, listener)
        self._proxies: dict[str, tuple[ProxyRecord, asyncssh.SSHListener]] = {}

    async def start_proxy(
        self,
        server: str,
        proxy_type: ProxyType,
        local_port: int,
        local_host: str,
        remote_host: str | None,
        remote_port: int | None,
        audit: IAuditLog,
    ) -> ProxyRecord:
        conn = await self._pool.get_connection(server)
        self._pool.pin(server)

        try:
            if proxy_type == ProxyType.local:
                if remote_host is None or remote_port is None:
                    raise McpSshError(
                        "type='local' requires remote_host and remote_port"
                    )
                listener = await conn.forward_local_port(
                    local_host, local_port, remote_host, remote_port
                )
            else:  # socks5
                listener = await conn.forward_socks(local_host, local_port)
        except Exception:
            self._pool.unpin(server)
            raise

        record = ProxyRecord(
            id=_new_proxy_id(),
            server=server,
            type=proxy_type,
            local_host=local_host,
            local_port=local_port,
            remote_host=remote_host,
            remote_port=remote_port,
            started_at=datetime.now(UTC),
        )
        self._proxies[record.id] = (record, listener)

        audit.log(AuditEvent(
            ts=datetime.now(UTC),
            tool="ssh_proxy",
            server=server,
            proxy_id=record.id,
            outcome="started",
            detail={
                "type": proxy_type.value,
                "local_host": local_host,
                "local_port": local_port,
                "remote_host": remote_host,
                "remote_port": remote_port,
            },
        ))
        return record

    async def stop_proxy(self, proxy_id: str, audit: IAuditLog) -> ProxyRecord:
        entry = self._proxies.pop(proxy_id, None)
        if entry is None:
            raise ProxyNotFound(f"Proxy {proxy_id!r} not found.")
        record, listener = entry
        record.status = "stopped"
        listener.close()
        await listener.wait_closed()
        self._pool.unpin(record.server)
        audit.log(AuditEvent(
            ts=datetime.now(UTC),
            tool="ssh_proxy",
            server=record.server,
            proxy_id=proxy_id,
            outcome="stopped",
            detail={},
        ))
        return record

    def list_proxies(self, server: str | None = None) -> list[ProxyRecord]:
        records = [r for r, _ in self._proxies.values()]
        if server is not None:
            records = [r for r in records if r.server == server]
        return records

    async def close_all(self) -> None:
        for _proxy_id, (record, listener) in list(self._proxies.items()):
            listener.close()
            with contextlib.suppress(Exception):
                await listener.wait_closed()
            self._pool.unpin(record.server)
        self._proxies.clear()

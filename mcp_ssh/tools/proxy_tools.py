"""MCP tool for SSH port-forward / SOCKS5 proxy management."""
from __future__ import annotations

from typing import Any

from ..exceptions import McpSshError, ProxyNotFound
from ..interfaces import IAuditLog, IProxyManager
from ..models import ProxyType


async def ssh_proxy(
    action: str,
    proxy_manager: IProxyManager,
    audit: IAuditLog,
    server: str | None = None,
    proxy_type_str: str | None = None,
    local_port: int | None = None,
    local_host: str = "127.0.0.1",
    remote_host: str | None = None,
    remote_port: int | None = None,
    proxy_id: str | None = None,
) -> dict[str, Any]:
    if action == "start":
        if server is None:
            return {"error": "missing_param", "message": "server is required"}
        if proxy_type_str not in ("local", "socks5"):
            return {"error": "invalid_type",
                    "message": "type must be 'local' or 'socks5'"}
        if local_port is None:
            return {"error": "missing_param", "message": "local_port is required"}

        try:
            proxy_type = ProxyType(proxy_type_str)
            record = await proxy_manager.start_proxy(
                server=server,
                proxy_type=proxy_type,
                local_port=local_port,
                local_host=local_host,
                remote_host=remote_host,
                remote_port=remote_port,
                audit=audit,
            )
        except McpSshError as exc:
            return {"error": "proxy_error", "message": str(exc)}
        except Exception as exc:  # noqa: BLE001
            return {"error": "unexpected_error", "message": str(exc)}

        return {
            "proxy_id": record.id,
            "server": record.server,
            "type": record.type.value,
            "local_host": record.local_host,
            "local_port": record.local_port,
            "remote_host": record.remote_host,
            "remote_port": record.remote_port,
            "started_at": record.started_at.isoformat(),
        }

    if action == "stop":
        if proxy_id is None:
            return {"error": "missing_param", "message": "proxy_id is required"}
        try:
            await proxy_manager.stop_proxy(proxy_id=proxy_id, audit=audit)
        except ProxyNotFound:
            return {"error": "proxy_not_found", "proxy_id": proxy_id,
                    "message": f"Proxy {proxy_id!r} not found."}
        except McpSshError as exc:
            return {"error": "stop_error", "message": str(exc)}
        return {"stopped": True, "proxy_id": proxy_id}

    if action == "list":
        records = proxy_manager.list_proxies(server=server)
        return {
            "proxies": [
                {
                    "proxy_id": r.id,
                    "server": r.server,
                    "type": r.type.value,
                    "local_host": r.local_host,
                    "local_port": r.local_port,
                    "remote_host": r.remote_host,
                    "remote_port": r.remote_port,
                    "started_at": r.started_at.isoformat(),
                    "status": r.status,
                }
                for r in records
            ]
        }

    return {"error": "invalid_action", "action": action,
            "message": f"Unknown action {action!r}. Use: start stop list"}

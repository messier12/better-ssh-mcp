# ssh_proxy — implementation spec

## Goal

Add a 10th MCP tool `ssh_proxy` that opens a persistent SSH port-forward or
SOCKS5 proxy through a registered server, so a local process can reach a
service on that server's private LAN.

**Typical use case:**
- `gateway` is a registered server reachable by the MCP host
- `http://192.168.1.50:8080` is on gateway's LAN, not reachable from the MCP host
- After `ssh_proxy(action="start", server="gateway", type="local", local_port=8080, remote_host="192.168.1.50", remote_port=8080)`, the MCP host can `curl http://localhost:8080` and it routes through gateway.

---

## Tool interface

```python
ssh_proxy(
    action: str,          # "start" | "stop" | "list"
    # start — type="local"
    server: str | None = None,
    type: str | None = None,           # "local" | "socks5"
    local_port: int | None = None,
    local_host: str = "127.0.0.1",    # bind address on MCP host
    remote_host: str | None = None,   # required for type="local"
    remote_port: int | None = None,   # required for type="local"
    # stop
    proxy_id: str | None = None,
    # list — no extra params; server optional filter
) -> dict[str, Any]
```

### action="start", type="local"

Required: `server`, `type="local"`, `local_port`, `remote_host`, `remote_port`.

Opens an SSH local port forward equivalent to:
```
ssh -L local_host:local_port:remote_host:remote_port user@server
```

Returns:
```json
{
  "proxy_id": "prx-abc123",
  "server": "gateway",
  "type": "local",
  "local_host": "127.0.0.1",
  "local_port": 8080,
  "remote_host": "192.168.1.50",
  "remote_port": 8080,
  "started_at": "2026-07-28T12:00:00Z"
}
```

### action="start", type="socks5"

Required: `server`, `type="socks5"`, `local_port`.

Opens a SOCKS5 proxy equivalent to `ssh -D local_host:local_port user@server`.
After start: `curl --proxy socks5h://localhost:local_port http://192.168.1.50:8080`.

Returns same shape as above (no `remote_host`/`remote_port` fields).

### action="stop"

Required: `proxy_id`. Closes the listener and unpins the connection.

Returns: `{"stopped": true, "proxy_id": "prx-abc123"}`

### action="list"

Optional: `server` to filter. Returns:
```json
{"proxies": [{"proxy_id": ..., "server": ..., "type": ..., "local_port": ..., ...}]}
```

---

## Files to create / modify

### 1. `mcp_ssh/models.py` — add ProxyRecord

Add after `SessionRecord`:

```python
class ProxyType(str, Enum):  # noqa: UP042
    local  = "local"
    socks5 = "socks5"


class ProxyRecord(BaseModel):
    id:          str
    server:      str
    type:        ProxyType
    local_host:  str
    local_port:  int
    remote_host: str | None = None   # None for socks5
    remote_port: int | None = None   # None for socks5
    started_at:  datetime
    status:      str = "active"      # "active" | "stopped"
```

Also add `proxy_id: str | None = None` field to `AuditEvent`.

### 2. `mcp_ssh/interfaces.py` — extend IConnectionPool + add IProxyManager

Add two methods to `IConnectionPool`:
```python
def pin(self, name: str) -> None: ...
def unpin(self, name: str) -> None: ...
```

Add new protocol:
```python
@runtime_checkable
class IProxyManager(Protocol):
    async def start_proxy(
        self,
        server: str,
        proxy_type: ProxyType,
        local_port: int,
        local_host: str,
        remote_host: str | None,
        remote_port: int | None,
        audit: IAuditLog,
    ) -> ProxyRecord: ...

    async def stop_proxy(self, proxy_id: str, audit: IAuditLog) -> ProxyRecord: ...

    def list_proxies(self, server: str | None = None) -> list[ProxyRecord]: ...

    async def close_all(self) -> None: ...
```

Import `ProxyRecord`, `ProxyType` from `.models` at the top of interfaces.py.

### 3. `mcp_ssh/pool.py` — add pin/unpin to ConnectionPool

Add to `ConnectionPool.__init__`:
```python
self._pinned: set[str] = set()
```

Add two methods:
```python
def pin(self, name: str) -> None:
    self._pinned.add(name)

def unpin(self, name: str) -> None:
    self._pinned.discard(name)
```

Modify `close()` to skip pinned connections:
```python
async def close(self, name: str) -> None:
    if name in self._pinned:
        return
    # ... existing logic unchanged
```

### 4. `mcp_ssh/proxy.py` — new file, ProxyManager

```python
"""Proxy manager: SSH local port-forward and SOCKS5 proxies."""
from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime
from typing import Any

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
        for proxy_id, (record, listener) in list(self._proxies.items()):
            listener.close()
            try:
                await listener.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self._pool.unpin(record.server)
        self._proxies.clear()
```

### 5. `mcp_ssh/exceptions.py` — add ProxyNotFound

Add alongside `ProcessNotFound` and `SessionNotFound`:
```python
class ProxyNotFound(McpSshError):
    """Raised when a proxy_id is not found in the ProxyManager."""
```

### 6. `mcp_ssh/tools/proxy_tools.py` — new file, MCP tool function

```python
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
```

### 7. `mcp_ssh/server.py` — wire ProxyManager, add ssh_proxy tool

**In `_build_app()`**, import and construct `ProxyManager`:
```python
from .proxy import ProxyManager
proxy_manager = ProxyManager(pool=pool)
```

Add to `AppContext.__init__` and `AppContext` fields:
```python
self.proxy_manager = proxy_manager
```

In `_lifespan` teardown (the `finally` block), add before `pool.close_all()`:
```python
await ctx.proxy_manager.close_all()
```

**In `_register_tools()`**, add the 10th tool:

```python
from .tools.proxy_tools import ssh_proxy as _ssh_proxy_fn

@mcp.tool()
async def ssh_proxy(  # type: ignore[return]
    action: str,
    server: str | None = None,
    type: str | None = None,
    local_port: int | None = None,
    local_host: str = "127.0.0.1",
    remote_host: str | None = None,
    remote_port: int | None = None,
    proxy_id: str | None = None,
) -> dict[str, Any]:
    """Open, close, or list SSH port-forward / SOCKS5 proxies.

    action="start"  — server, type, local_port required.
                      type="local": also requires remote_host, remote_port.
                        Forwards localhost:local_port → remote_host:remote_port
                        through server (ssh -L equivalent).
                      type="socks5": dynamic SOCKS5 proxy on local_port
                        through server (ssh -D equivalent). Use with
                        curl --proxy socks5h://localhost:<port>.
                      local_host defaults to "127.0.0.1".
                      Returns {proxy_id, server, type, local_host, local_port,
                               remote_host, remote_port, started_at}.
    action="stop"   — proxy_id required. Closes listener, unpins connection.
    action="list"   — server optional filter. Returns {proxies: [...]}.
    """
    return await _ssh_proxy_fn(
        action=action,
        proxy_manager=ctx.proxy_manager,
        audit=ctx.audit,
        server=server,
        proxy_type_str=type,
        local_port=local_port,
        local_host=local_host,
        remote_host=remote_host,
        remote_port=remote_port,
        proxy_id=proxy_id,
    )
```

Also update the docstring on `_register_tools` from "9" to "10".

### 8. `tests/test_tools_proxy.py` — new test file

Write unit tests (no real SSH needed — mock ProxyManager and IAuditLog):

- `test_ssh_proxy_start_local` — valid start, returns expected dict with proxy_id
- `test_ssh_proxy_start_socks5` — valid socks5 start
- `test_ssh_proxy_start_missing_server` — returns error dict
- `test_ssh_proxy_start_local_missing_remote_host` — error on missing remote_host (caught inside ProxyManager)
- `test_ssh_proxy_start_invalid_type` — returns invalid_type error
- `test_ssh_proxy_stop_ok` — stop returns `{stopped: true}`
- `test_ssh_proxy_stop_not_found` — stop unknown id returns proxy_not_found
- `test_ssh_proxy_list_all` — list returns all proxies
- `test_ssh_proxy_list_filtered` — list with server filter
- `test_ssh_proxy_invalid_action` — unknown action returns invalid_action error

Also add a test that verifies the server registers 10 tools (update the existing
`test_server_registers_24_tools` in `tests/test_integration.py` from 9 → 10 and
update its docstring).

---

## Constraints

- All code must pass `mypy --strict` and `ruff check`.
- Test coverage ≥ 80% for `mcp_ssh/proxy.py` and `mcp_ssh/tools/proxy_tools.py`.
- `ProxyNotFound` must be caught and returned as a structured error dict (not raised through MCP).
- Passwords/passphrases must never appear in audit log events (existing rule).
- Work on a **new branch** named `feat/ssh-proxy`.
- Run `nix develop --command make check` at the end and fix any failures before finishing.
- Do NOT change `models.py` or `interfaces.py` field names/types that already exist — only additions are allowed.

---

## asyncssh API reference

```python
# Local port forward
listener: asyncssh.SSHListener = await conn.forward_local_port(
    listen_host,   # str, e.g. "127.0.0.1"
    listen_port,   # int
    dest_host,     # str, e.g. "192.168.1.50"
    dest_port,     # int
)

# SOCKS5 dynamic proxy
listener: asyncssh.SSHListener = await conn.forward_socks(
    listen_host,   # str
    listen_port,   # int
)

# Teardown
listener.close()
await listener.wait_closed()
```

Both methods are on `asyncssh.SSHClientConnection` and are available in asyncssh ≥ 2.0.

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol, runtime_checkable

import asyncssh

from .models import (
    AppConfig,
    AuditEvent,
    ConnectionStatus,
    ProcessOutput,
    ProcessRecord,
    PtyOutput,
    ServerConfig,
    SessionRecord,
)


@runtime_checkable
class IRegistry(Protocol):
    def get(self, name: str) -> ServerConfig: ...
    def list_all(self) -> list[ServerConfig]: ...
    def add(self, config: ServerConfig) -> None: ...
    def remove(self, name: str) -> None: ...
    def get_config(self) -> AppConfig: ...
    async def watch(self) -> AsyncIterator[None]: ...  # yields on each reload


@runtime_checkable
class IConnectionPool(Protocol):
    async def get_connection(self, name: str) -> asyncssh.SSHClientConnection: ...
    async def close(self, name: str) -> None: ...
    async def close_all(self) -> None: ...
    def get_status(self, name: str) -> ConnectionStatus: ...


@runtime_checkable
class ISessionManager(Protocol):
    # Non-interactive exec (nohup-backed, remote process persists)
    async def start_process(
        self, server: str, command: str,
        cwd: str | None, env: dict[str, str] | None,
    ) -> str: ...   # returns process_id

    async def read_process(
        self, process_id: str, max_bytes: int = 65536,
    ) -> ProcessOutput: ...

    async def write_process(self, process_id: str, data: str) -> None: ...

    async def kill_process(
        self, process_id: str, signal: str = "SIGTERM",
    ) -> None: ...

    async def check_process(self, process_id: str) -> ProcessOutput: ...

    def list_processes(
        self, server: str | None = None,
    ) -> list[ProcessRecord]: ...

    # PTY sessions
    async def start_pty(
        self, server: str, command: str | None,
        cols: int, rows: int, use_tmux: bool,
    ) -> str: ...   # returns session_id

    async def pty_read(
        self, session_id: str, max_bytes: int = 65536,
    ) -> PtyOutput: ...

    async def pty_write(self, session_id: str, data: str) -> None: ...

    async def pty_resize(
        self, session_id: str, cols: int, rows: int,
    ) -> None: ...

    async def pty_close(self, session_id: str) -> None: ...

    async def pty_attach(self, session_id: str) -> None: ...

    def list_sessions(
        self, server: str | None = None,
    ) -> list[SessionRecord]: ...


@runtime_checkable
class IStateStore(Protocol):
    def load(self) -> None: ...
    def upsert_process(self, record: ProcessRecord) -> None: ...
    def upsert_session(self, record: SessionRecord) -> None: ...
    def get_process(self, process_id: str) -> ProcessRecord | None: ...
    def get_session(self, session_id: str) -> SessionRecord | None: ...
    def list_processes(
        self, server: str | None = None,
    ) -> list[ProcessRecord]: ...
    def list_sessions(
        self, server: str | None = None,
    ) -> list[SessionRecord]: ...


@runtime_checkable
class IAuditLog(Protocol):
    def log(self, event: AuditEvent) -> None: ...
    def close(self) -> None: ...

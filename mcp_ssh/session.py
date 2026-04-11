"""Session manager implementing ISessionManager."""
from __future__ import annotations

import asyncio
import collections
import contextlib
import shlex
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import asyncssh

from .exceptions import (
    ProcessNotFound,
    RemoteCommandError,
    SessionCapExceeded,
    SessionNotFound,
    TmuxNotAvailable,
)
from .models import (
    AuditEvent,
    GlobalSettings,
    ProcessOutput,
    ProcessRecord,
    ProcessStatus,
    PtyOutput,
    ServerConfig,
    SessionRecord,
)

if TYPE_CHECKING:
    from .interfaces import IAuditLog, IConnectionPool, IStateStore

# Signal allowlist
ALLOWED_SIGNALS = {
    "SIGTERM",
    "SIGKILL",
    "SIGINT",
    "SIGHUP",
    "SIGQUIT",
    "SIGUSR1",
    "SIGUSR2",
}


class SessionManager:
    """Manages SSH exec processes and PTY sessions, implementing ISessionManager.

    Provides nohup-backed non-interactive exec and PTY session management,
    including optional tmux integration.
    """

    def __init__(
        self,
        pool: IConnectionPool,
        state: IStateStore,
        audit: IAuditLog,
        settings: GlobalSettings | None = None,
        servers: dict[str, ServerConfig] | None = None,
    ) -> None:
        self._pool = pool
        self._state = state
        self._audit = audit
        self._settings = settings or GlobalSettings()
        self._servers = servers or {}

        # In-memory state for live PTY processes (no-tmux path)
        self._pty_procs: dict[str, asyncssh.SSHClientProcess[bytes]] = {}
        self._pty_buffers: dict[str, collections.deque[bytes]] = {}
        self._drain_tasks: dict[str, asyncio.Task[None]] = {}

        # In-memory state for tmux sessions
        self._tmux_logs: dict[str, str] = {}
        self._tmux_sessions: dict[str, str] = {}
        self._tmux_conns: dict[str, asyncssh.SSHClientConnection] = {}

    # ------------------------------------------------------------------
    # Process (nohup exec) interface
    # ------------------------------------------------------------------

    async def start_process(
        self,
        server: str,
        command: str,
        cwd: str | None,
        env: dict[str, str] | None,
    ) -> str:
        """Launch a nohup background process on *server* and return its process_id."""
        process_id = str(uuid.uuid4())
        log_file = f"/tmp/mcp-{process_id}.log"
        exit_file = f"/tmp/mcp-{process_id}.exit"

        env_exports = " ".join(
            f"{shlex.quote(k)}={shlex.quote(v)}" for k, v in (env or {}).items()
        )
        cd_part = f"cd {shlex.quote(cwd)} && " if cwd else ""
        inner = cd_part + (env_exports + " " if env_exports else "") + command
        # BUG-1 fix: inner includes the exit-code capture so the whole nohup is
        # backgrounded with & and echo $! captures nohup's PID, not a subshell.
        # Wrap inner in (...) so that a user `exit N` only exits the subshell;
        # the outer shell still runs `echo $? > exitfile`.
        inner_with_exit = f"({inner}); echo $? > {exit_file}"
        remote_cmd = (
            f"nohup bash -c {shlex.quote(inner_with_exit)} "
            f"> {log_file} 2>&1 & echo $!"
        )

        conn = await self._pool.get_connection(server)
        result = await conn.run(remote_cmd)
        stdout = (result.stdout or "").strip()
        try:
            pid = int(stdout)
        except (ValueError, TypeError) as exc:
            raise RemoteCommandError(
                f"start_process: expected integer PID from remote, got {stdout!r}"
            ) from exc
        # BUG-2 fix: reject PID of 0 which would send signals to the whole process group
        if pid <= 0:
            raise RemoteCommandError(
                f"start_process: invalid PID {pid!r} returned by remote (must be > 0)"
            )

        record = ProcessRecord(
            id=process_id,
            server=server,
            command=command,
            remote_pid=pid,
            log_file=log_file,
            exit_file=exit_file,
            started_at=datetime.utcnow(),
            status=ProcessStatus.running,
        )
        self._state.upsert_process(record)
        self._audit.log(
            AuditEvent(
                ts=datetime.utcnow(),
                tool="start_process",
                server=server,
                command=command,
                process_id=process_id,
                outcome="started",
                detail={"remote_pid": pid},
            )
        )
        return process_id

    async def read_process(
        self, process_id: str, max_bytes: int = 65536
    ) -> ProcessOutput:
        """Return current log output and status for *process_id*."""
        record = self._state.get_process(process_id)
        if record is None:
            raise ProcessNotFound(f"Process {process_id!r} not found")

        conn = await self._pool.get_connection(record.server)
        exit_result = await conn.run(
            f"test -f {record.exit_file} && cat {record.exit_file} || true"
        )
        log_result = await conn.run(
            f"tail -c {max_bytes} {record.log_file} 2>/dev/null || true"
        )

        exit_stdout = (exit_result.stdout or "").strip()
        exit_code: int | None = None
        running = True
        if exit_stdout:
            try:
                exit_code = int(exit_stdout)
                running = False
            except ValueError:
                pass

        log_content = str(log_result.stdout or "")

        return ProcessOutput(
            output=log_content,
            running=running,
            exit_code=exit_code,
            remote_pid=record.remote_pid,
            server=record.server,
        )

    async def write_process(self, process_id: str, data: str) -> None:
        """Not supported for nohup background processes."""
        raise RemoteCommandError(
            "write_process is not supported for nohup background processes; "
            "they have no stdin"
        )

    async def kill_process(
        self, process_id: str, signal: str = "SIGTERM"
    ) -> None:
        """Send *signal* to the remote process identified by *process_id*."""
        record = self._state.get_process(process_id)
        if record is None:
            raise ProcessNotFound(f"Process {process_id!r} not found")

        if signal not in ALLOWED_SIGNALS:
            raise RemoteCommandError(f"Signal {signal!r} not allowed")

        conn = await self._pool.get_connection(record.server)
        await conn.run(f"kill -{signal} {record.remote_pid}")

        updated = record.model_copy(update={"status": ProcessStatus.killed})
        self._state.upsert_process(updated)
        self._audit.log(
            AuditEvent(
                ts=datetime.utcnow(),
                tool="kill_process",
                server=record.server,
                process_id=process_id,
                outcome="killed",
                detail={"signal": signal, "remote_pid": record.remote_pid},
            )
        )

    async def check_process(self, process_id: str) -> ProcessOutput:
        """Check liveness of *process_id* and return its current output/status."""
        record = self._state.get_process(process_id)
        if record is None:
            raise ProcessNotFound(f"Process {process_id!r} not found")

        conn = await self._pool.get_connection(record.server)
        liveness_result = await conn.run(
            f"kill -0 {record.remote_pid} 2>/dev/null && echo alive || echo dead"
        )
        alive_str = (liveness_result.stdout or "").strip()
        alive = alive_str == "alive"

        log_result = await conn.run(
            f"tail -c 4096 {record.log_file} 2>/dev/null || true"
        )
        exit_result = await conn.run(
            f"test -f {record.exit_file} && cat {record.exit_file} || true"
        )

        exit_stdout = (exit_result.stdout or "").strip()
        exit_code: int | None = None
        if exit_stdout:
            with contextlib.suppress(ValueError):
                exit_code = int(exit_stdout)

        new_status = ProcessStatus.running if alive else ProcessStatus.exited
        updated = record.model_copy(
            update={
                "status": new_status,
                "exit_code": exit_code,
                "last_checked": datetime.utcnow(),
            }
        )
        self._state.upsert_process(updated)

        log_content = str(log_result.stdout or "")
        return ProcessOutput(
            output=log_content,
            running=alive,
            exit_code=exit_code,
            remote_pid=record.remote_pid,
            server=record.server,
        )

    def list_processes(self, server: str | None = None) -> list[ProcessRecord]:
        """Return all tracked process records, optionally filtered by *server*."""
        return self._state.list_processes(server)

    # ------------------------------------------------------------------
    # PTY session interface
    # ------------------------------------------------------------------

    async def start_pty(
        self,
        server: str,
        command: str | None,
        cols: int,
        rows: int,
        use_tmux: bool,
    ) -> str:
        """Open a PTY session on *server* and return its session_id."""
        # Check session cap
        per_server_limit: int | None = None
        if server in self._servers:
            per_server_limit = self._servers[server].max_sessions
        limit = per_server_limit if per_server_limit is not None else self._settings.max_sessions

        active = len(
            [s for s in self._state.list_sessions(server) if s.status == ProcessStatus.running]
        )
        if active >= limit:
            raise SessionCapExceeded(
                f"Server {server!r} session cap of {limit} exceeded ({active} active)"
            )

        session_id = str(uuid.uuid4())
        conn = await self._pool.get_connection(server)

        if not use_tmux:
            proc = await conn.create_process(
                command or "$SHELL",
                request_pty=True,
                term_type="xterm-256color",
                term_size=(cols, rows),
            )
            self._pty_procs[session_id] = proc
            self._pty_buffers[session_id] = collections.deque(maxlen=65536)
            task = asyncio.create_task(self._drain_pty(session_id, proc))
            self._drain_tasks[session_id] = task

            record = SessionRecord(
                id=session_id,
                server=server,
                command=command,
                use_tmux=False,
                started_at=datetime.utcnow(),
                status=ProcessStatus.running,
            )
            self._state.upsert_session(record)
            self._audit.log(
                AuditEvent(
                    ts=datetime.utcnow(),
                    tool="start_pty",
                    server=server,
                    command=command,
                    session_id=session_id,
                    outcome="started",
                    detail={"use_tmux": False, "cols": cols, "rows": rows},
                )
            )
            return session_id

        # tmux path
        tmux_check = await conn.run("which tmux 2>/dev/null || true")
        if not (tmux_check.stdout or "").strip():
            raise TmuxNotAvailable(f"tmux not found on server {server!r}")

        log_file = f"/tmp/mcp-pty-{session_id}.log"
        tmux_session = f"mcp-{session_id[:8]}"

        await conn.run(
            f"tmux new-session -d -s {shlex.quote(tmux_session)} "
            f"{shlex.quote(command or '$SHELL')}"
        )
        await conn.run(
            f"tmux pipe-pane -o -t {shlex.quote(tmux_session)} 'cat >> {log_file}'"
        )

        self._tmux_logs[session_id] = log_file
        self._tmux_sessions[session_id] = tmux_session
        self._tmux_conns[session_id] = conn

        record = SessionRecord(
            id=session_id,
            server=server,
            command=command,
            use_tmux=True,
            tmux_window=tmux_session,
            started_at=datetime.utcnow(),
            status=ProcessStatus.running,
        )
        self._state.upsert_session(record)
        self._audit.log(
            AuditEvent(
                ts=datetime.utcnow(),
                tool="start_pty",
                server=server,
                command=command,
                session_id=session_id,
                outcome="started",
                detail={"use_tmux": True, "tmux_session": tmux_session},
            )
        )
        return session_id

    async def _drain_pty(
        self, session_id: str, proc: asyncssh.SSHClientProcess[bytes]
    ) -> None:
        """Background task: read chunks from PTY stdout into the session buffer."""
        buf = self._pty_buffers.get(session_id)
        if buf is None:
            return
        try:
            while True:
                chunk = await proc.stdout.read(4096)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    buf.append(chunk.encode())
                else:
                    buf.append(chunk)
        except Exception:  # noqa: BLE001
            pass

    async def pty_read(
        self, session_id: str, max_bytes: int = 65536
    ) -> PtyOutput:
        """Read buffered output from the PTY session *session_id*."""
        session = self._state.get_session(session_id)
        if session is None:
            raise SessionNotFound(f"Session {session_id!r} not found")

        if not session.use_tmux:
            buf = self._pty_buffers.get(session_id, collections.deque())
            collected = bytearray()
            while buf and len(collected) < max_bytes:
                chunk = buf.popleft()
                remaining = max_bytes - len(collected)
                if len(chunk) <= remaining:
                    collected.extend(chunk)
                else:
                    # Put the remainder back
                    collected.extend(chunk[:remaining])
                    buf.appendleft(chunk[remaining:])
                    break
            proc = self._pty_procs.get(session_id)
            alive = proc is not None and not proc.is_closing()
            output = collected.decode("utf-8", errors="replace")
            return PtyOutput(output=output, alive=alive)

        # tmux path
        log_file = self._tmux_logs.get(session_id, "")
        tmux_session = self._tmux_sessions.get(session_id, "")
        conn = self._tmux_conns.get(session_id)
        if conn is None:
            return PtyOutput(output="", alive=False)

        log_result = await conn.run(
            f"tail -c {max_bytes} {log_file} 2>/dev/null || true"
        )
        alive_result = await conn.run(
            f"tmux has-session -t {shlex.quote(tmux_session)} 2>/dev/null "
            f"&& echo alive || echo dead"
        )
        alive = str(alive_result.stdout or "").strip() == "alive"
        output = str(log_result.stdout or "")
        return PtyOutput(output=output, alive=alive)

    async def pty_write(self, session_id: str, data: str) -> None:
        """Write *data* to the PTY session *session_id*.

        Note: use \\r (not \\n) to submit a command line in a tmux session.
        """
        session = self._state.get_session(session_id)
        if session is None:
            raise SessionNotFound(f"Session {session_id!r} not found")

        if not session.use_tmux:
            proc = self._pty_procs.get(session_id)
            if proc is not None:
                proc.stdin.write(data.encode())
        else:
            # tmux path
            tmux_session = self._tmux_sessions.get(session_id, "")
            conn = self._tmux_conns.get(session_id)
            if conn is not None:
                await conn.run(
                    f"tmux send-keys -t {shlex.quote(tmux_session)} -- {shlex.quote(data)}"
                )

        self._audit.log(
            AuditEvent(
                ts=datetime.utcnow(),
                tool="pty_write",
                server=session.server,
                session_id=session_id,
                outcome="written",
                detail={"bytes": len(data)},
            )
        )

    async def pty_resize(self, session_id: str, cols: int, rows: int) -> None:
        """Resize the PTY session *session_id* to *cols* x *rows*."""
        session = self._state.get_session(session_id)
        if session is None:
            raise SessionNotFound(f"Session {session_id!r} not found")

        if not session.use_tmux:
            proc = self._pty_procs.get(session_id)
            if proc is not None:
                proc.change_terminal_size(width=cols, height=rows)
        else:
            # tmux path
            tmux_session = self._tmux_sessions.get(session_id, "")
            conn = self._tmux_conns.get(session_id)
            if conn is not None:
                await conn.run(
                    f"tmux resize-window -t {shlex.quote(tmux_session)} "
                    f"-x {cols} -y {rows}"
                )

        self._audit.log(
            AuditEvent(
                ts=datetime.utcnow(),
                tool="pty_resize",
                server=session.server,
                session_id=session_id,
                outcome="resized",
                detail={"cols": cols, "rows": rows},
            )
        )

    async def pty_close(self, session_id: str) -> None:
        """Close the PTY session *session_id* and clean up resources."""
        session = self._state.get_session(session_id)
        if session is None:
            raise SessionNotFound(f"Session {session_id!r} not found")

        if not session.use_tmux:
            task = self._drain_tasks.pop(session_id, None)
            if task is not None:
                task.cancel()
            proc = self._pty_procs.pop(session_id, None)
            if proc is not None:
                proc.close()
            self._pty_buffers.pop(session_id, None)
        else:
            # tmux: leave the session alive on the remote, just clean up locally
            self._tmux_logs.pop(session_id, None)
            self._tmux_sessions.pop(session_id, None)
            self._tmux_conns.pop(session_id, None)

        updated = session.model_copy(update={"status": ProcessStatus.exited})
        self._state.upsert_session(updated)
        self._audit.log(
            AuditEvent(
                ts=datetime.utcnow(),
                tool="pty_close",
                server=session.server,
                session_id=session_id,
                outcome="closed",
                detail={"use_tmux": session.use_tmux},
            )
        )

    async def pty_attach(self, session_id: str) -> None:
        """Attach to an existing tmux-backed PTY session (not supported in MCP context)."""
        session = self._state.get_session(session_id)
        if session is None:
            raise SessionNotFound(f"Session {session_id!r} not found")

        if not session.use_tmux:
            raise SessionNotFound(
                f"pty_attach requires use_tmux=True; "
                f"session {session_id!r} was opened without tmux"
            )

        tmux_session = self._tmux_sessions.get(session_id, "")
        conn = self._tmux_conns.get(session_id)
        if conn is not None and tmux_session:
            result = await conn.run(
                f"tmux has-session -t {shlex.quote(tmux_session)} 2>/dev/null"
            )
            if result.exit_status != 0:
                raise SessionNotFound(
                    f"tmux session {tmux_session!r} no longer exists on remote"
                )

        raise NotImplementedError(
            "pty_attach is not supported in the MCP stdio transport context; "
            "use tmux attach in a local terminal instead"
        )

    def list_sessions(self, server: str | None = None) -> list[SessionRecord]:
        """Return all tracked session records, optionally filtered by *server*."""
        return self._state.list_sessions(server)

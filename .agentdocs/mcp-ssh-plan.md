# mcp-ssh — Implementation Plan

## Agent roles

| Role | Symbol | Responsibilities |
|---|---|---|
| **Impl** | I | Write production code and unit tests for the assigned module |
| **Arch** | A | Review component interfaces, async patterns, cross-module consistency |
| **Sec** | S | Review credential handling, command injection, audit completeness, file permissions |
| **Pkg** | P | Write packaging files: pyproject.toml, flake.nix, CI, install docs |

**Rules for all agents:**
- A task may only start when every listed dependency is marked **done**.
- A gate may only be passed when every listed blocking task is **done** and the
  responsible review agent has signed off (written comment in PR / issue).
- No agent may alter the interface contracts in `models.py` or `interfaces.py`
  after T0 completes without reopening Gate 1.
- All code must pass `mypy --strict` and `ruff check` before a task is marked done.
- Test coverage for each module must reach ≥ 80% before the task is marked done.

---

## Toolchain (all agents use the same setup)

```
python      >= 3.11
uv          (package management + venv)
pytest      (tests)
mypy        (strict type checking)
ruff        (lint + format)
pytest-asyncio  (async tests)
pytest-cov      (coverage)
```

Makefile targets that every agent can rely on:
```
make test        # pytest with coverage
make lint        # ruff check + mypy
make install     # uv sync
make check       # lint + test
```

---

## Interface contracts (defined in T0, immutable after Gate 1)

These are the shared contracts that let T1a, T1b, and T1c be built in parallel
without stepping on each other. Implementation agents code to these. Review
agents verify against them.

### `mcp_ssh/models.py`

```python
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Literal
from pydantic import BaseModel, Field


class AuthType(str, Enum):
    agent               = "agent"
    key                 = "key"
    password            = "password"
    cert                = "cert"
    sk                  = "sk"
    keyboard_interactive = "keyboard_interactive"
    gssapi              = "gssapi"


class HostKeyPolicy(str, Enum):
    tofu       = "tofu"
    strict     = "strict"
    accept_new = "accept_new"


class ConnectionStatus(str, Enum):
    connected    = "connected"
    disconnected = "disconnected"
    connecting   = "connecting"


class ProcessStatus(str, Enum):
    running = "running"
    exited  = "exited"
    killed  = "killed"
    unknown = "unknown"


class ServerConfig(BaseModel):
    name:              str
    host:              str
    port:              int = 22
    user:              str
    auth_type:         AuthType
    key_path:          str | None = None
    cert_path:         str | None = None
    password_env:      str | None = None
    jump_host:         str | None = None       # name of another ServerConfig
    host_key_policy:   HostKeyPolicy | None = None  # None → use global default
    default_cwd:       str | None = None
    default_env:       dict[str, str] = Field(default_factory=dict)
    max_sessions:      int | None = None
    keepalive_interval: int | None = None


class GlobalSettings(BaseModel):
    known_hosts_file:        str = "~/.local/share/mcp-ssh/known_hosts"
    default_host_key_policy: HostKeyPolicy = HostKeyPolicy.tofu
    audit_log:               str = "~/.local/share/mcp-ssh/audit.jsonl"
    state_file:              str = "~/.local/share/mcp-ssh/state.json"
    max_sessions:            int = 10
    keepalive_interval:      int = 30
    keepalive_count_max:     int = 5
    connect_timeout:         int = 15
    default_encoding:        str = "utf-8"


class ProcessRecord(BaseModel):
    id:           str
    type:         Literal["exec"] = "exec"
    server:       str
    command:      str
    remote_pid:   int
    log_file:     str
    exit_file:    str
    started_at:   datetime
    last_checked: datetime | None = None
    status:       ProcessStatus = ProcessStatus.unknown
    exit_code:    int | None = None


class SessionRecord(BaseModel):
    id:           str
    type:         Literal["pty"] = "pty"
    server:       str
    command:      str | None
    use_tmux:     bool
    tmux_window:  str | None = None
    started_at:   datetime
    last_checked: datetime | None = None
    status:       ProcessStatus = ProcessStatus.unknown


class ProcessOutput(BaseModel):
    output:     str
    running:    bool
    exit_code:  int | None = None
    remote_pid: int
    server:     str


class PtyOutput(BaseModel):
    output: str
    alive:  bool


class AuditEvent(BaseModel):
    ts:         datetime
    tool:       str
    server:     str | None = None
    command:    str | None = None
    process_id: str | None = None
    session_id: str | None = None
    outcome:    str
    detail:     dict = Field(default_factory=dict)
    # IMPORTANT: passwords, passphrases, env var values must NEVER appear here


class AppConfig(BaseModel):
    settings: GlobalSettings = Field(default_factory=GlobalSettings)
    servers:  dict[str, ServerConfig] = Field(default_factory=dict)
```

### `mcp_ssh/interfaces.py`

```python
from __future__ import annotations
from typing import AsyncIterator, Protocol, runtime_checkable
from .models import (
    AppConfig, ServerConfig, ProcessRecord, SessionRecord,
    ProcessOutput, PtyOutput, AuditEvent, ConnectionStatus,
)
import asyncssh


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
```

### `mcp_ssh/exceptions.py`

```python
class McpSshError(Exception):
    """Base for all mcp-ssh errors. Always includes a human-readable message."""

class ServerNotFound(McpSshError): ...
class ServerAlreadyExists(McpSshError): ...
class ConnectionError(McpSshError): ...       # noqa: A001 (shadows builtin intentionally)
class AuthError(McpSshError): ...
class HostKeyError(McpSshError): ...
class SessionNotFound(McpSshError): ...
class SessionCapExceeded(McpSshError): ...
class ProcessNotFound(McpSshError): ...
class TmuxNotAvailable(McpSshError): ...
class RemoteCommandError(McpSshError):
    def __init__(self, msg: str, exit_code: int | None = None) -> None:
        super().__init__(msg)
        self.exit_code = exit_code
```

---

## Phase 0 — Scaffold

### T0 — Project scaffold
**Role**: Impl &nbsp;|&nbsp; **Depends on**: nothing &nbsp;|&nbsp; **Estimate**: 3–5 h

#### Files to produce
```
mcp-ssh/
├── flake.nix               # builds without error (app not yet runnable)
├── pyproject.toml          # complete, all deps pinned
├── Makefile                # install / test / lint / check targets
├── .python-version         # 3.11
├── mcp_ssh/
│   ├── __init__.py
│   ├── models.py           # full content from this plan (authoritative)
│   ├── interfaces.py       # full content from this plan (authoritative)
│   ├── exceptions.py       # full content from this plan (authoritative)
│   ├── config.py           # STUB — empty class bodies with docstrings
│   ├── registry.py         # STUB
│   ├── pool.py             # STUB
│   ├── session.py          # STUB
│   ├── state.py            # STUB
│   ├── audit.py            # STUB
│   ├── server.py           # STUB
│   └── tools/
│       ├── __init__.py
│       ├── registry_tools.py   # STUB
│       ├── exec_tools.py       # STUB
│       └── pty_tools.py        # STUB
└── tests/
    ├── conftest.py
    ├── test_smoke.py           # one passing smoke test only
    └── fixtures/
        └── servers.toml        # example config for tests
```

#### Acceptance criteria
- `uv run python -c "from mcp_ssh import models, interfaces, exceptions"` succeeds
- `uv run pytest tests/test_smoke.py` passes
- `uv run mypy mcp_ssh/` passes with no errors (stubs use `...` bodies)
- `uv run ruff check mcp_ssh/` passes
- `nix build` completes (may warn about missing app entrypoint)

---

## Phase 1 — Core components (all depend on T0, run in parallel)

### T1a — Config + Registry
**Role**: Impl &nbsp;|&nbsp; **Depends on**: T0

#### Files to produce
- `mcp_ssh/config.py` — TOML loading, Pydantic validation, XDG path expansion
- `mcp_ssh/registry.py` — `Registry` implementing `IRegistry`
- `tests/test_config.py`
- `tests/test_registry.py`

#### Key behaviours
- Load `servers.toml` using `tomllib` (stdlib). Validate into `AppConfig`.
- Expand `~` and `$XDG_CONFIG_HOME` in all path fields at load time.
- Config path resolution order: `MCP_SSH_CONFIG` env var → `--config` CLI arg →
  `$XDG_CONFIG_HOME/mcp-ssh/servers.toml` → `~/.config/mcp-ssh/servers.toml`.
- `Registry.watch()` uses `watchfiles.awatch` to yield on file changes and
  re-parse. On parse error, log the error and retain the previous valid config —
  never leave the registry in a broken state.
- `Registry.add()` / `Registry.remove()` write the updated TOML back to disk
  atomically (write to `.tmp`, then `os.replace`).
- Circular jump-host chains (A→B→A) must be detected at load time and raise
  `McpSshError`.

#### Acceptance criteria
- All 4 auth types, jump_host chains, and default_env fields round-trip through
  load → write → reload.
- Circular jump chains raise `McpSshError`.
- Malformed TOML retains previous valid config (does not crash).
- Passes `isinstance(registry, IRegistry)` check.

---

### T1b — State + Audit
**Role**: Impl &nbsp;|&nbsp; **Depends on**: T0

#### Files to produce
- `mcp_ssh/state.py` — `StateStore` implementing `IStateStore`
- `mcp_ssh/audit.py` — `AuditLog` implementing `IAuditLog`
- `tests/test_state.py`
- `tests/test_audit.py`

#### Key behaviours

**State store:**
- On `load()`, read `state.json` (if present). All loaded records get
  `status = ProcessStatus.unknown`.
- On `upsert_*()`, write the full state atomically (write to `.tmp`, rename).
- State file path resolved from `GlobalSettings.state_file` with XDG expansion.
- If the state file is missing or corrupt, start with an empty state (log a
  warning, do not crash).
- Schema version field: reject files with a higher `schema_version` than
  supported, with a clear error message.

**Audit log:**
- Append one JSON line per `log()` call. Never buffer; flush immediately.
- File is opened in append mode. Created if missing, including parent dirs.
- Passwords, passphrases, and env var values must never appear in any field.
- `close()` flushes and closes the file handle.

#### Acceptance criteria
- Upsert → reload → get round-trip preserves all fields.
- Corrupt state file → fresh empty state (no crash).
- Audit log is append-only; each line is valid JSON with all required fields.
- Passes `isinstance(store, IStateStore)` and `isinstance(audit, IAuditLog)`.

---

### T1c — Connection Pool
**Role**: Impl &nbsp;|&nbsp; **Depends on**: T0

#### Files to produce
- `mcp_ssh/pool.py` — `ConnectionPool` implementing `IConnectionPool`
- `tests/test_pool.py` (uses `asyncssh` test server or mocks)

#### Key behaviours
- One persistent `asyncssh.SSHClientConnection` per server name.
- `get_connection(name)` returns the existing connection if alive, reconnects
  if in `disconnected` state, raises `ServerNotFound` if name is unknown.
- **ProxyJump resolution**: if `ServerConfig.jump_host` is set, `get_connection`
  recursively gets the jump host's connection first and passes it as the
  `tunnel` argument to `asyncssh.connect`. Chains of arbitrary depth are
  supported; cycles are prevented by the registry validation in T1a.
- **Auth mapping** (asyncssh kwargs):
  - `agent`: `agent_path` from `SSH_AUTH_SOCK`; raise `AuthError` if socket
    missing.
  - `key`: `client_keys=[key_path]`. If key is encrypted and not in agent,
    raise `AuthError` with a message directing the user to `ssh-add`.
  - `password`: read `os.environ[password_env]`; raise `AuthError` if var
    missing.
  - `cert`: `client_keys=[key_path]`, `client_certs=[cert_path]`.
  - `sk`: same as `key`; asyncssh 2.14+ handles sk natively with libfido2.
  - `keyboard_interactive`: supply `kbdint_handler` reading from env vars
    `MCP_SSH_KI_RESPONSE_1`, `_2`, … in order.
  - `gssapi`: `gss_host=host`, delegated by asyncssh.
- **Known hosts**: use `GlobalSettings.known_hosts_file`. On `tofu` policy,
  auto-accept and append on first connect using asyncssh's
  `known_hosts_file` param plus a custom `host_key_accepted_callback`.
- **Keepalive**: pass `keepalive_interval` and `keepalive_count_max` to
  `asyncssh.connect`.
- On disconnect, mark status `disconnected`; next `get_connection` call
  reconnects.

#### Acceptance criteria
- `get_connection` for an unknown server raises `ServerNotFound`.
- Missing `SSH_AUTH_SOCK` with `auth_type="agent"` raises `AuthError` with
  a descriptive message.
- Missing `password_env` raises `AuthError` (not `KeyError`).
- ProxyJump: `ConnectionPool` calls `asyncssh.connect` with `tunnel=` set to
  the jump host's connection.
- Passes `isinstance(pool, IConnectionPool)`.

---

## Gate 1 — Architecture review

**Role**: Arch &nbsp;|&nbsp; **Triggered by**: T1a + T1b + T1c all done &nbsp;|&nbsp; **Blocks**: T2

### Checklist
The Arch agent must verify every item. Any failing item blocks T2.

1. **Protocol compliance**: `isinstance(registry, IRegistry)`,
   `isinstance(store, IStateStore)`, `isinstance(audit, IAuditLog)`,
   `isinstance(pool, IConnectionPool)` all return `True` for the concrete
   implementations.

2. **Async hygiene**: no blocking I/O (`open`, `json.load`, `os.stat`) is
   called from within a coroutine. File I/O in `state.py` and `audit.py` must
   use `asyncio.to_thread` or be documented as acceptable sync operations
   (brief, under lock) if they are always fast.

3. **Error taxonomy**: every raised exception is a subclass of `McpSshError`.
   No bare `Exception`, `RuntimeError`, or asyncssh exceptions leak to callers
   of `IConnectionPool`.

4. **Atomic writes**: `StateStore` and `Registry.add/remove` must use the
   write-to-`.tmp`-then-`os.replace` pattern. Direct writes to the target
   file are a blocking item.

5. **Circular dependency detection** in registry is tested and documented.

6. **Config hot-reload**: `Registry.watch()` retains the last valid config on
   parse failure. Verified by test.

7. **No credentials in audit log**: verify by inspection that `AuditEvent`
   serialisation never includes `password_env` values, key passphrases, or
   env var contents.

8. **Interface stability**: confirm `models.py` and `interfaces.py` are
   unchanged from T0 output. If any change is needed, document it in a PR
   comment and re-review.

**Sign-off format**: comment `GATE-1-APPROVED: <date> <arch-agent-id>` in the
PR. List any issues filed as follow-ups (non-blocking items become tasks in a
future sprint).

---

## Phase 2 — Session Manager

### T2 — Session Manager
**Role**: Impl &nbsp;|&nbsp; **Depends on**: Gate 1 &nbsp;|&nbsp; **Estimate**: 6–10 h

#### Files to produce
- `mcp_ssh/session.py` — `SessionManager` implementing `ISessionManager`
- `tests/test_session.py`

#### Key behaviours

**Process sessions (exec_stream):**
- Build a remote nohup command:
  ```
  nohup bash -c 'cd {cwd} && {env_exports} {command} \
    > {log_file} 2>&1; echo $? > {exit_file}' &
  echo $!
  ```
  where `log_file = /tmp/mcp-{uuid}.log`, `exit_file = /tmp/mcp-{uuid}.exit`.
- Capture the remote PID from stdout. If stdout is not a valid integer,
  raise `RemoteCommandError`.
- Write a `ProcessRecord` to `StateStore` immediately.
- `read_process`: SSH `cat` (or `tail -c {max_bytes}`) the log file. Check for
  exit file with `test -f && cat`. Return `ProcessOutput`.
- `check_process`: run `kill -0 {pid}` (check liveness without signalling),
  read last 4 KB of log, check exit file. Update `StateStore`.
- `kill_process`: run `kill -{signal} {pid}`. Update `StateStore`.
- **Command sanitisation**: `command`, `cwd`, and env var names must be
  validated before shell interpolation. Use `shlex.quote` for all user-supplied
  strings embedded in shell commands. Remote PIDs must be validated as
  positive integers before use in `kill` commands.

**PTY sessions (start_pty):**
- Without tmux: open `asyncssh` process with `request_pty=True`, given cols/rows.
  Run a background asyncio task draining the channel into a `collections.deque`
  (max `deque` size = `maxlen` calculated from `GlobalSettings` buffer limit).
- With tmux: run `tmux new-session -d -s mcp-{id} 'cmd'` first. Then pipe
  output via `tmux pipe-pane -o -t mcp-{id} 'cat >> {log_file}'`. PTY writes
  go via `tmux send-keys -t mcp-{id} -- {input}`.
- `pty_attach`: run `tmux has-session -t mcp-{id}` first. If the session does
  not exist, raise `SessionNotFound` with a clear message. Then attach.
- `pty_close`: non-tmux — close the SSH channel (remote gets SIGHUP).
  tmux — leave the tmux session alive; only close the local channel.
- Session cap: before starting any new session, check the count against
  `ServerConfig.max_sessions` (or `GlobalSettings.max_sessions`). Raise
  `SessionCapExceeded` if over limit.
- Write a `SessionRecord` to `StateStore` on start and on close.
- Every mutating operation writes an `AuditEvent`.

#### Acceptance criteria
- `start_process` + `read_process` poll loop returns correct output and
  `running=False` after process exits (tested with a mock SSH server or
  integration fixture).
- `check_process` after process exit returns correct `exit_code` and
  `running=False`.
- `kill_process` updates `StateStore` status to `killed`.
- Session cap: `SessionCapExceeded` raised when over limit.
- `pty_attach` raises `SessionNotFound` when tmux window is missing.
- All shell-interpolated user input passes through `shlex.quote`.
- Passes `isinstance(manager, ISessionManager)`.

---

## Gate 2 — Security audit

**Role**: Sec &nbsp;|&nbsp; **Triggered by**: T2 done (reviews T0–T2) &nbsp;|&nbsp; **Blocks**: T3a, T3b, T3c

### Checklist
The Sec agent must verify every item. Any failing item blocks T3s.

1. **No secrets on disk**: scan all files for hardcoded passwords or
   passphrases. Confirm `AuditEvent` serialisation does not include password
   values, env var contents, or key material.

2. **No secrets in logs**: `audit.py` and any log statements must not log
   `password_env` values, key content, or `os.environ` dumps.

3. **Command injection**: confirm every user-supplied string that reaches a
   remote shell command passes through `shlex.quote`. Remote PIDs used in
   `kill` commands must be validated as positive integers (`int(pid) > 0`).
   Spot-check `pool.py` for any `asyncssh.run()` calls that interpolate
   unquoted strings.

4. **Remote temp file paths**: `log_file` and `exit_file` paths are
   `/tmp/mcp-{uuid}.log` where `uuid` is generated with `uuid.uuid4()`.
   Confirm no path-traversal is possible (UUID contains only hex + hyphens).

5. **Known hosts**: confirm that `HostKeyPolicy.accept_new` is documented as
   insecure and is not the default. Confirm `tofu` policy writes the
   fingerprint on first connect and enforces it thereafter.

6. **Host key downgrade**: verify that `pool.py` never silently ignores a
   changed host key. A changed key must raise `HostKeyError`.

7. **State file and audit log permissions**: confirm files are created with
   mode `0o600` (readable only by owner). `audit.py` and `state.py` must call
   `os.chmod(path, 0o600)` after creation.

8. **Auth error messages**: confirm that `AuthError` messages never include
   the actual password value, only the env var name.

9. **Session isolation**: verify that one user's `process_id` cannot be used
   to read or kill another user's process (relevant if multi-user mode is
   ever added; document the current single-user assumption explicitly).

10. **Tmux injection**: confirm that `tmux send-keys` input is quoted/escaped
    to prevent tmux key sequence injection (e.g. a user sending `q` to quit
    tmux should not be possible).

**Sign-off format**: comment `GATE-2-APPROVED: <date> <sec-agent-id>` in the
PR. Any issue that cannot be fixed before Gate 2 must be filed as a
`security` labeled issue and acknowledged by the project owner before the
gate can be passed.

---

## Phase 3 — Tools layer (all depend on Gate 2, run in parallel)

### T3a — Registry tools
**Role**: Impl &nbsp;|&nbsp; **Depends on**: Gate 2

#### File to produce
- `mcp_ssh/tools/registry_tools.py`
- `tests/test_tools_registry.py`

#### Tools to implement
`ssh_list_servers()`, `ssh_register_server(...)`, `ssh_deregister_server(name)`,
`ssh_add_known_host(name)`, `ssh_show_known_host(name)`.

#### Key behaviours
- All tools receive `registry: IRegistry` and `pool: IConnectionPool` injected
  at call time (no globals).
- `ssh_register_server` validates the new config with Pydantic before writing.
  Returns a structured dict, not a string.
- `ssh_deregister_server` returns a warning payload (not an error) if active
  sessions exist.
- `ssh_add_known_host` calls `pool.get_connection(name)` with a temporary
  `accept_new` policy override, captures the host key, writes it to the
  known_hosts file, then re-enables the standard policy. The connection is
  closed immediately after capture.
- Every tool that mutates state writes an `AuditEvent`.
- Tool return values follow the MCP tool response format (dict with a
  structured result, never bare strings for data).

#### Acceptance criteria
- `ssh_list_servers` returns correct connection status for each server.
- `ssh_register_server` with a duplicate name raises `ServerAlreadyExists`
  (returned as a structured error, not an exception to the MCP layer).
- `ssh_deregister_server` with active sessions returns a warning.
- All tools produce an audit log entry.

---

### T3b — Exec tools
**Role**: Impl &nbsp;|&nbsp; **Depends on**: Gate 2

#### File to produce
- `mcp_ssh/tools/exec_tools.py`
- `tests/test_tools_exec.py`

#### Tools to implement
`ssh_exec(...)`, `ssh_exec_stream(...)`, `ssh_read_process(...)`,
`ssh_write_process(...)`, `ssh_kill_process(...)`, `ssh_list_processes(...)`,
`ssh_check_process(...)`.

#### Key behaviours
- `ssh_exec` applies `cwd` and `env` from the tool call, falling back to
  `ServerConfig.default_cwd` and `ServerConfig.default_env`.
- `ssh_exec` timeout defaults to 30 s; `timeout=None` is allowed but must
  be logged at WARN level in the audit log.
- `ssh_exec_stream` delegates fully to `SessionManager.start_process`.
- `ssh_read_process` returns `{output, running, exit_code, remote_pid, server}`.
- `ssh_list_processes` returns all records from `StateStore` with a
  human-readable `last_checked_ago` field derived from `last_checked`.
- Every tool that mutates state writes an `AuditEvent`.

#### Acceptance criteria
- `ssh_exec` with a command that takes 5 s and `timeout=2` returns a timeout
  error, not a hanging coroutine.
- `ssh_read_process` for an unknown `process_id` returns a structured error.
- `ssh_list_processes` with `server="nonexistent"` returns an empty list (not
  an error).
- All tools produce an audit log entry.

---

### T3c — PTY tools
**Role**: Impl &nbsp;|&nbsp; **Depends on**: Gate 2

#### File to produce
- `mcp_ssh/tools/pty_tools.py`
- `tests/test_tools_pty.py`

#### Tools to implement
`ssh_start_pty(...)`, `ssh_pty_read(...)`, `ssh_pty_write(...)`,
`ssh_pty_resize(...)`, `ssh_pty_close(...)`, `ssh_pty_attach(...)`.

#### Key behaviours
- `ssh_start_pty` returns `{session_id, use_tmux, server, command}`.
- `ssh_start_pty` with `use_tmux=True` on a server without tmux installed
  returns a structured error `{error: "tmux_not_available", ...}` — it does
  NOT fall back silently to a non-tmux session.
- `ssh_pty_write` documents (in its docstring) that `\r` is required to submit
  a command line, not `\n`.
- `ssh_pty_attach` raises `SessionNotFound` if the session was not created
  with `use_tmux=True`.
- Every tool that mutates state writes an `AuditEvent`.

#### Acceptance criteria
- `ssh_start_pty` without `use_tmux` and `ssh_pty_close` produce correct
  audit events.
- `ssh_pty_attach` on a non-tmux session returns a structured error.
- `ssh_pty_resize` passes correct `cols/rows` to `SessionManager.pty_resize`.
- Session cap: `ssh_start_pty` returns `SessionCapExceeded` error when over
  limit.

---

## Phase 4 — Integration

### T4 — Server entrypoint + integration tests
**Role**: Impl &nbsp;|&nbsp; **Depends on**: T3a + T3b + T3c &nbsp;|&nbsp; **Estimate**: 4–6 h

#### Files to produce
- `mcp_ssh/server.py` — MCP server entrypoint using `fastmcp` or `mcp` SDK
- `tests/test_integration.py` — end-to-end tests (uses a local `asyncssh`
  test server)

#### Key behaviours
- `server.py` constructs one instance each of `Registry`, `ConnectionPool`,
  `SessionManager`, `StateStore`, `AuditLog` and injects them into all tools
  via a shared context object.
- The MCP server starts the `Registry.watch()` background task on startup.
- On SIGTERM / broken stdio pipe, the server calls `pool.close_all()` and
  `audit.close()` before exiting.
- All 15 MCP tools are registered. Tool names match exactly the names in the
  design doc (snake_case, `ssh_` prefix).
- Integration tests spin up a local `asyncssh` test server (`asyncssh.create_server`)
  and exercise the full call path for at least: `ssh_exec`, `ssh_exec_stream`
  + `ssh_read_process` poll loop, `ssh_start_pty` + `ssh_pty_write` +
  `ssh_pty_read`, and `ssh_check_process` after simulated disconnect.

#### Acceptance criteria
- `uv run mcp-ssh` starts without error and outputs MCP handshake on stdio.
- All 15 tools appear in the MCP tool listing.
- Integration tests pass against the local test server.
- `pool.close_all()` called on shutdown (verified by test).
- `make check` passes (lint + type check + tests).

---

## Phase 5 — Packaging (start after T0, both required at Gate 3)

### T5a — Debian packaging
**Role**: Pkg &nbsp;|&nbsp; **Depends on**: T0 &nbsp;|&nbsp; **May update based on**: T4 (final deps)

#### Files to produce
- `pyproject.toml` (finalised — update from T0 skeleton with pinned deps)
- `INSTALL.md` — step-by-step for Debian/Ubuntu
- `.github/workflows/release.yml` — build sdist + wheel, publish to PyPI
  (or internal index)

#### Key behaviours
- `uv tool install mcp-ssh` must work on a clean Debian 12 system.
- `libfido2` system dep is documented as optional (only needed for sk keys).
- Claude Desktop config snippet is included in `INSTALL.md`.
- `mcp-ssh --version` must print the version from `pyproject.toml`.

#### Acceptance criteria
- `pip install dist/mcp_ssh-*.whl && mcp-ssh --help` succeeds in a fresh
  Debian venv.
- `INSTALL.md` covers: apt deps, install, config file location, Claude Desktop
  integration.

---

### T5b — NixOS packaging
**Role**: Pkg &nbsp;|&nbsp; **Depends on**: T0 &nbsp;|&nbsp; **May update based on**: T4 (final deps)

#### Files to produce
- `flake.nix` (complete — update from T0 skeleton)
- `nix/` directory with any helper expressions
- `INSTALL-NIX.md`

#### Key behaviours
- `nix build` produces a working `mcp-ssh` binary.
- `libfido2` in `buildInputs` so sk keys work out of the box.
- `homeManagerModules.default` provides `programs.mcp-ssh.enable` option.
- `nixosModules.default` provides system-level install option.
- NixOS and home-manager module options are documented in `INSTALL-NIX.md`.
- `nix flake check` passes.

#### Acceptance criteria
- `nix run .# -- --help` succeeds.
- `nix flake check` passes.
- `INSTALL-NIX.md` covers: flake input, home-manager usage, Claude Desktop
  config (noting full store path requirement).

---

## Gate 3 — Final review

**Role**: Arch + Sec (joint) &nbsp;|&nbsp; **Triggered by**: T4 + T5a + T5b all done &nbsp;|&nbsp; **Blocks**: release

### Arch checklist
1. All 15 MCP tool signatures match the design doc exactly.
2. `server.py` shutdown path is clean: no dangling tasks, no unclosed files.
3. `Registry.watch()` background task does not leak on shutdown.
4. Integration test coverage includes the disconnect-reconnect-check_process
   scenario.
5. `make check` passes clean (zero warnings).

### Sec checklist
1. Re-run Gate 2 checklist against the final integrated codebase.
2. Verify no new secrets-in-logs issues introduced by the tool layer.
3. Confirm `ssh_exec_stream` temp file cleanup path exists (even if deferred
   to v2, the design decision is documented).
4. Audit log rotation strategy is documented (even if delegated to logrotate /
   systemd).
5. Confirm `0o600` permissions on state file and audit log are verified by an
   integration test.

**Sign-off format**: both agents comment
`GATE-3-APPROVED: <date> <agent-id>` in the release PR. Release is blocked
until both comments appear.

---

## Conventions for all agents

### File ownership
Each agent works only in the files listed under their task. If a change to a
shared file (e.g., `models.py`) is needed, open a separate PR and tag the
Arch agent for review before merging.

### Error returns vs exceptions
MCP tools must **never** raise Python exceptions to the MCP layer. All errors
are caught inside the tool function and returned as structured dicts:
```python
{"error": "server_not_found", "server": name, "message": "..."}
```
Python exceptions are only used internally between modules.

### Async conventions
- Use `asyncio.to_thread(...)` for any blocking file I/O longer than a stat
  call.
- Never `await` inside a `with` lock unless the lock is an `asyncio.Lock`.
- All public async functions in `pool.py` and `session.py` must have a
  timeout parameter (default 30 s). Use `asyncio.wait_for`.

### Test doubles
- `pool.py` tests: use `asyncssh.create_server` in a fixture for a real local
  server, or `unittest.mock.AsyncMock` for unit tests of pool logic only.
- `session.py` tests: mock `IConnectionPool` using `AsyncMock`.
- Tool tests: mock both `IConnectionPool` and `ISessionManager`.

### ID generation
All `process_id` and `session_id` values are `str(uuid.uuid4())`.
The prefix `mcp-` is prepended only for remote resource names (tmux windows,
temp files): `mcp-{uuid}`.

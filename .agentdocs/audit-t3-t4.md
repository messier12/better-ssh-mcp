# Audit: T3a + T3b + T3c + T4
Date: 2026-04-11

## T3a — Registry tools
### Status: PARTIAL

**Functions implemented:** `ssh_list_servers`, `ssh_register_server`, `ssh_deregister_server`,
`async_ssh_add_known_host`, `ssh_show_known_host` — all present.

**Dependency injection:** No globals; all dependencies injected at call time. PASS.

**Duplicate server name:** Returns `{"error": "server_already_exists", ...}` as a structured
dict before calling `registry.add()`. The function catches `ServerNotFound` on the pre-check;
if found, it returns the error without adding. PASS — but the `ServerAlreadyExists` exception
class is imported in the test file yet never raised or caught by `ssh_register_server` itself.
The plan says "raises `ServerAlreadyExists` (returned as a structured error)" — the
implementation short-circuits via `ServerNotFound` catch rather than `ServerAlreadyExists`,
but the outcome (structured error, no add) is correct.

**Deregister with active sessions:** Returns `{"deregistered": True, ..., "warning": "..."}` —
structured warning not error. PASS.

**Mutating tools log AuditEvent:** `ssh_register_server` and `ssh_deregister_server` log.
`async_ssh_add_known_host` logs. `ssh_list_servers` and `ssh_show_known_host` are read-only
and do not log — consistent with "every mutating tool writes an AuditEvent". PASS.

**Plan requirement for `ssh_add_known_host`:** The plan specifies calling `pool.get_connection`
with a "temporary `accept_new` policy override", capturing the key, then "re-enabling the
standard policy" and "closing the connection immediately after capture." The implementation
(`async_ssh_add_known_host`) calls `pool.get_connection(name)` without any policy override —
it relies on whatever policy the pool already has configured. There is no temporary policy
switch and no immediate connection close after key capture. This is a PARTIAL non-compliance
with the plan spec.

**Coverage:** `registry_tools.py` — 88% (lines 109-110, 162-163, 167-168 uncovered; these are
error paths in `registry.add/remove` raising `McpSshError`, and the `os.makedirs`
`/get_connection` path for `async_ssh_add_known_host`). Meets the ≥80% threshold. PASS.

---

## T3b — Exec tools
### Status: PASS

**Functions implemented:** `ssh_exec`, `ssh_exec_stream`, `ssh_read_process`,
`ssh_write_process`, `ssh_kill_process`, `ssh_list_processes`, `ssh_check_process` — all
present.

**`ssh_exec` timeout enforcement:** Uses `asyncio.wait_for(coro, timeout=timeout)`. If the
coroutine exceeds the timeout, `TimeoutError` is caught and returns `{"error": "timeout", ...}`.
Verified by `test_ssh_exec_timeout` which uses `timeout=0.01` against a slow coroutine. PASS.

**`ssh_exec` with `timeout=None` logs at WARN:** Both a Python `logger.warning(...)` call and
an `audit.log(AuditEvent(..., outcome="warn_no_timeout"))` are emitted before executing. PASS.
Verified by `test_ssh_exec_no_timeout_logs_warning` which asserts `audit.log.call_count == 2`.

**`ssh_read_process` for unknown process_id:** Catches `ProcessNotFound` and returns
`{"error": "process_not_found", ...}`. PASS.

**`ssh_list_processes` with unknown server:** Delegates to `session_manager.list_processes(server=server)`;
if no processes exist for that server, returns `{"processes": []}`. PASS.

**Audit events:** `ssh_exec` logs on `warn_no_timeout`, `timeout`, and `completed`. The other
tools (`ssh_exec_stream`, `ssh_kill_process`, etc.) do not log audit events in the tool layer,
but the underlying `SessionManager` methods log them. The plan says "every tool that mutates
state writes an AuditEvent" — this is met at the session manager layer, not the tool layer,
which is architecturally sound but means `ssh_exec_stream`'s `audit` parameter is accepted but
unused (the parameter is passed through to maintain interface consistency). Minor design note,
not a blocking issue.

**Default cwd/env fallback:** `ssh_exec` correctly applies `cfg.default_cwd` and
`cfg.default_env` when not provided. PASS.

**Coverage:** `exec_tools.py` — 81% (lines 70-71, 104-107, 151-152, 179-180, 203, 211,
231-232, 256, 261-264, 299-300 uncovered; these are error branches for
`McpSshError`/`Exception` in `ssh_exec`, and `McpSshError` paths in
`ssh_exec_stream`/`ssh_read_process`/`ssh_write_process`/`ssh_kill_process`/`ssh_check_process`).
Meets ≥80% threshold. PASS.

---

## T3c — PTY tools
### Status: PASS

**Functions implemented:** `ssh_start_pty`, `ssh_pty_read`, `ssh_pty_write`, `ssh_pty_resize`,
`ssh_pty_close`, `ssh_pty_attach` — all present.

**`use_tmux=True` on server without tmux → structured error, no silent fallback:** The
`TmuxNotAvailable` exception from `session_manager.start_pty` is caught explicitly and returns
`{"error": "tmux_not_available", ...}`. Audit log is NOT called on this path (correct — no
session started). PASS.

**`ssh_pty_write` docstring mentions `\r` required:** Docstring reads: "Note: use `\\r` (not
`\\n`) to submit a command line in interactive shells and tmux sessions." PASS.

**`ssh_pty_attach` on non-tmux session → structured error:** The `SessionManager.pty_attach`
raises `SessionNotFound` for non-tmux sessions (line 511-514 of `session.py`). The tool catches
`SessionNotFound` and returns `{"error": "session_not_found", ...}`. PASS — however note that
the error key is `session_not_found` rather than a more specific `non_tmux_session` key; the
plan says "structured error" which is met.

**Audit events:** `ssh_start_pty` (on success) and `ssh_pty_close` (on success) log audit
events. `ssh_pty_read`, `ssh_pty_write`, `ssh_pty_resize`, `ssh_pty_attach` do not log — these
are read-only or non-state-mutating in the tool layer. The session manager itself handles
auditing for state mutations. PASS.

**Coverage:** `pty_tools.py` — 98% (only line 214, `return {"attached": True, "session_id":
session_id}`, is uncovered — the `pty_attach` happy-path is never reached because the session
manager always raises `NotImplementedError` in MCP context). This is by design. PASS.

---

## T4 — Server + integration
### Status: FAIL

### Tool count discrepancy (BLOCKING)

The plan specifies **15 MCP tools** ("All 15 MCP tools are registered"). The implementation
registers **18 tools** (5 registry + 7 exec + 6 PTY). The docstring on `_register_tools` even
says "Register all 15 SSH MCP tools" while the module docstring says "registers all 18 MCP
tools" — these are inconsistent with each other and with the plan.

The 3 extra tools relative to the plan's 15 are:
1. `ssh_show_known_host_tool` — not listed in T3a tools-to-implement
2. `ssh_pty_close_tool` — arguably implicit but not in the T3c explicit list (plan lists 6
   PTY tools: start/read/write/resize/close/attach = 6; so actually this IS in the plan count)
3. The discrepancy may be that the plan listed only 4 registry tools + 7 exec + 4 PTY = 15,
   but counting by the plan's T3a/T3b/T3c sections: T3a=5 (list/register/deregister/add/show),
   T3b=7, T3c=6 = 18. The plan text says 15 in T4 acceptance criteria but specifies 18 tools
   across the Phase 3 tasks. This is a contradiction within the plan itself.

**Tool name format (BLOCKING):** The plan states "Tool names match exactly the names in the
design doc (snake_case, `ssh_` prefix)." The actual registered tool names all have a `_tool`
suffix: e.g., `ssh_exec_tool` instead of `ssh_exec`, `ssh_list_servers_tool` instead of
`ssh_list_servers`. FastMCP uses the function name as the tool name when no explicit name is
passed. The tool functions are named `ssh_exec_tool`, `ssh_list_servers_tool`, etc. This
violates the plan requirement. Verified by running `_register_tools` against a real
`FastMCP` instance — all 18 tools have `_tool` suffix.

### `_register_tools` docstring inconsistency

The function `_register_tools` has docstring "Register all 15 SSH MCP tools on the FastMCP
app." but registers 18 tools. Minor documentation bug, not blocking.

### Registry.watch() background task

Started via `asyncio.create_task(_watch())` in `_lifespan`. Cancelled on shutdown. PASS.

### SIGTERM / shutdown handling

`pool.close_all()` and `audit.close()` are called in the `_lifespan` `finally` block. A
duplicate `_shutdown` signal handler in `main()` also calls them. Both paths covered.
PASS for functionality. Note: `main()` also attaches a `SIGTERM` signal handler that creates a
task calling `close_all()` and `audit.close()` — this means on SIGTERM, these may be called
twice (once from the signal handler and once from the lifespan finally block). Not a bug per se
but a minor redundancy.

### Integration test coverage

**Tests present:**
- `ssh_exec` against real local asyncssh server — PASS (but with soft assertion: "Should either
  succeed or show connection-related error"). Not strict.
- `ssh_exec_stream` + `ssh_read_process` poll loop — uses mocks, not real server. Plan requires
  "local `asyncssh` test server" for this test. PARTIAL compliance.
- `ssh_start_pty` + `ssh_pty_write` + `ssh_pty_read` — **NOT PRESENT**. The plan explicitly
  requires this integration test. MISSING.
- `ssh_check_process` after disconnect — present and uses real server. PASS.
- `pool.close_all()` called on shutdown — present (but tests a manually-simulated shutdown,
  not the actual lifespan or signal handler). PASS.

**Missing integration test:** `ssh_start_pty` + `ssh_pty_write` + `ssh_pty_read` against local
asyncssh server is absent. This is explicitly required by the plan.

### server.py coverage: 46% — FAIL

The plan requires ≥80% per module. `server.py` is at 46% because `_build_app()` (lines 23-81)
and `main()` (lines 305-345) are not exercised by the integration tests. The test
`test_server_registers_18_tools` mocks FastMCP entirely, and `test_server_shutdown_calls_close_all`
simulates the shutdown directly without invoking `_build_app`. This is a hard failure against
the ≥80% coverage rule.

---

## Test results

```
T3 unit tests:  61 passed, 0 failed (1.80s)
Integration:    10 passed, 0 failed (31.66s)
```

All tests pass.

---

## Coverage

| Module | Coverage | Threshold | Result |
|---|---|---|---|
| `mcp_ssh/tools/registry_tools.py` | 88% | 80% | PASS |
| `mcp_ssh/tools/exec_tools.py` | 81% | 80% | PASS |
| `mcp_ssh/tools/pty_tools.py` | 98% | 80% | PASS |
| `mcp_ssh/tools/__init__.py` | 100% | 80% | PASS |
| `mcp_ssh/server.py` | **46%** | 80% | **FAIL** |

---

## mypy

```
nix develop --command uv run mypy mcp_ssh/tools/ mcp_ssh/server.py
Success: no issues found in 5 source files
```
PASS.

---

## ruff

```
nix develop --command uv run ruff check mcp_ssh/tools/ mcp_ssh/server.py
All checks passed!
```
PASS.

---

## Issues found

1. **[BLOCKING] Tool names have `_tool` suffix in MCP registry.** All 18 registered tools
   are named `ssh_exec_tool`, `ssh_list_servers_tool`, etc. instead of the plan-specified names
   `ssh_exec`, `ssh_list_servers`, etc. The `@mcp.tool()` decorator uses the Python function
   name; the wrappers should either be renamed (removing `_tool` suffix) or the decorator
   should be called as `@mcp.tool(name="ssh_exec")` etc. This violates the plan requirement:
   "Tool names match exactly the names in the design doc (snake_case, `ssh_` prefix)."

2. **[BLOCKING] `server.py` coverage at 46%, below the 80% threshold.** `_build_app()` and
   `main()` are not covered. Integration tests bypass `_build_app` by constructing components
   directly and bypass `main()` entirely.

3. **[BLOCKING] Missing integration test: `ssh_start_pty` + `ssh_pty_write` + `ssh_pty_read`.**
   The plan explicitly requires this test against the local asyncssh test server.
   `tests/test_integration.py` has no PTY tool integration test.

4. **[NON-BLOCKING] `_register_tools` docstring says "15 SSH MCP tools" but registers 18.**
   Minor inconsistency; the module docstring correctly says 18. The plan itself contradicts
   itself (T4 says 15, T3a+T3b+T3c list 18). The `remaining-tasks.md` acknowledges this
   discrepancy. Needs formal resolution but not functionally broken.

5. **[NON-BLOCKING] `ssh_add_known_host` does not implement temporary `accept_new` policy
   override.** The plan specifies calling `pool.get_connection` with a temporary `accept_new`
   policy override and closing the connection immediately after key capture. The implementation
   calls `pool.get_connection(name)` directly without policy override, relying on the existing
   pool policy. The connection is not explicitly closed after key capture.

6. **[NON-BLOCKING] `ssh_exec_stream_read_poll` integration test uses mocks, not real server.**
   The plan requires exercising the "full call path" using the local asyncssh test server. The
   test directly calls `AsyncMock()` for the session manager, never connecting to the test SSH
   server.

7. **[NON-BLOCKING] SIGTERM handled in both lifespan `finally` and `main()` signal handler.**
   `pool.close_all()` and `audit.close()` may be called twice on SIGTERM. Not a correctness
   issue but could cause benign log noise or errors if the audit log handle is already closed.

---

## Verdict: NEEDS FIXES

Three blocking issues must be resolved before T4 can be marked done:
- Issue 1: Fix tool names (remove `_tool` suffix from registered names)
- Issue 2: Improve `server.py` coverage to ≥80%
- Issue 3: Add `ssh_start_pty` + `ssh_pty_write` + `ssh_pty_read` integration test

T3a, T3b, and T3c are functionally complete and all unit tests pass. T3c has a minor
documentation inconsistency in its pty_attach non-tmux error key name. T3a has a spec
deviation in the `ssh_add_known_host` policy-override mechanism.

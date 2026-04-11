# Master Audit Report
Date: 2026-04-11
Auditors: 4 parallel agents (T0+T1a, T1b+T1c, T2+Gates, T3+T4)

## Overall verdict: NEEDS FIXES

3 blocking issues must be resolved before the codebase can be considered complete.
See detailed reports: audit-t0-t1a.md, audit-t1b-t1c.md, audit-t2-gates.md, audit-t3-t4.md

---

## Summary by module

| Module | Status | Tests | Coverage | mypy | ruff |
|---|---|---|---|---|---|
| T0 scaffold | PASS | 3/3 | n/a | clean | clean |
| T1a config+registry | PASS | 50/50 | 98%/96% | clean | clean |
| T1b state+audit | PASS | 42/42 | 93%/100% | clean | clean |
| T1c pool | PASS | 38/38 | 94% | clean | clean |
| T2 session | NEEDS FIXES | 48/48 | 100% | clean | clean |
| T3a registry tools | PARTIAL | 17/17 | 88% | clean | clean |
| T3b exec tools | PASS | 22/22 | 81% | clean | clean |
| T3c pty tools | PASS | 15/15 | 98% | clean | clean |
| T4 server+integration | FAIL | 71/71 | 46% server | clean | clean |

---

## Issues — BLOCKING (must fix)

### BUG-1 [CRITICAL] session.py — nohup not backgrounded
**File**: `mcp_ssh/session.py` ~L99–101
**Problem**: The nohup command is structured as:
```
nohup bash -c 'INNER' > logfile 2>&1; echo $? > exitfile & echo $!
```
Only the `echo $!` is backgrounded. The `nohup` runs synchronously — `start_process` blocks until the user's command exits. The `echo $!` captures the PID of the echo process, not the user's command.
**Required structure**:
```
nohup bash -c 'cd CWD && ENV_EXPORTS CMD > logfile 2>&1; echo $? > exitfile' &
echo $!
```
**Impact**: All background process functionality is broken. Unit tests pass only because they mock the SSH layer.

### BUG-2 [SECURITY] session.py — PID not validated as positive integer
**File**: `mcp_ssh/session.py` ~L108
**Problem**: `pid = int(stdout)` with no `> 0` check. A PID of 0 would cause `kill -SIGTERM 0`, killing the entire process group. Gate 2 checklist item 3 requires this check explicitly.
**Fix**: `pid = int(stdout.strip()); if pid <= 0: raise RemoteCommandError(...)`

### BUG-3 [CORRECTNESS] server.py — all tool names have `_tool` suffix
**File**: `mcp_ssh/server.py`
**Problem**: FastMCP registers tools using the Python function name. All wrapper functions are named `ssh_exec_tool`, `ssh_list_servers_tool`, etc. instead of `ssh_exec`, `ssh_list_servers`. Plan requires exact snake_case `ssh_` prefix names with no suffix.
**Fix**: Rename all 18 wrapper functions (or use `@mcp.tool(name="ssh_exec")` decorator arg).

---

## Issues — NON-BLOCKING (should fix)

### BUG-4 [MODERATE] session.py — pty_write and pty_resize write no AuditEvents
Plan: "Every mutating operation writes an AuditEvent." Both `pty_write` and `pty_resize` mutate remote state but emit no audit events.

### BUG-5 [MODERATE] T3a — ssh_add_known_host missing temporary accept_new override
Plan: "calls `pool.get_connection(name)` with a temporary `accept_new` policy override, captures the host key, writes it to known_hosts, then re-enables the standard policy. The connection is closed immediately after capture."
Current implementation uses pool's existing policy without override and does not close the connection after key capture.

### BUG-6 [MODERATE] T4 — server.py coverage 46% (below 80% requirement)
`_build_app()` and `main()` are not exercised by any test. Need tests for startup/shutdown lifecycle.

### BUG-7 [MODERATE] T4 — no PTY integration test
Plan explicitly requires `ssh_start_pty` + `ssh_pty_write` + `ssh_pty_read` against the local asyncssh server. Test is entirely absent from `tests/test_integration.py`.

### BUG-8 [LOW] pool.py — TOFU second-connect enforcement untested
The branch where a known host key is verified on reconnect (TOFU enforcement) is never exercised. Security-relevant; code is correct but untested.

### BUG-9 [LOW] gate2-review.md — inaccurate PASS claim
Gate 2 review claims PID positive-integer validation is in place (Item 3). It is not (see BUG-2).

### BUG-10 [LOW] Various minor coverage gaps
- state.py L76-82: non-integer schema_version path untested
- state.py L106-107: corrupt session record skip path untested
- test_pool.py: `test_password_auth_value_not_in_error_message` tests success path, not failure path

---

## Pending: real SSH smoke tests
Tests against `formulatrix@10.150.1.138` (password auth) have not been run yet.
File `tests/test_smoke_real.py` exists — run after BUG-1/2/3 are fixed.

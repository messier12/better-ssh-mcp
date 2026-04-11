# Audit: T2 + Gate Reviews
Date: 2026-04-11

---

## T2 — Session Manager (`mcp_ssh/session.py`)

### Status: PARTIAL — functional with notable issues

---

### Finding 1 — FAIL: nohup command does not background the process

**Criterion**: `start_process` must run the command in a nohup background process and
capture its PID.

**Plan specification** (`.agentdocs/mcp-ssh-plan.md`, T2 section):
```
nohup bash -c 'cd {cwd} && {env_exports} {command} \
  > {log_file} 2>&1; echo $? > {exit_file}' &
echo $!
```
The `&` backgrounds the entire `nohup` invocation; `echo $!` prints the nohup PID.

**Actual implementation** (`session.py:99–101`):
```python
remote_cmd = (
    f"nohup bash -c {shlex.quote(inner)} > {log_file} 2>&1; "
    f"echo $? > {exit_file} & echo $!"
)
```
The actual shell command produced is:
```
nohup bash -c 'INNER' > logfile 2>&1; echo $? > exitfile & echo $!
```
In bash, this runs `nohup bash -c 'INNER' > logfile 2>&1` **synchronously** (the
nohup is not backgrounded), then backgrounds `echo $? > exitfile`, then runs
`echo $!` which prints the PID of the `echo` background process — not of the
command. Two direct consequences:
1. The SSH `conn.run(remote_cmd)` call **blocks** until the user command completes,
   rather than returning immediately.
2. The stored `remote_pid` is the PID of a transient `echo` process, not the
   actual user command — making `kill_process` and `check_process` meaningless.

**Why not caught by tests**: All unit tests mock `conn.run` to return a fixed string.
The integration test (`test_disconnect_reconnect_check_process`) uses `sleep 30` and
the test still "passes" because the assertion is permissive (`"error" not in
check_result`). The total integration test suite runtime of ~31s is consistent with
`sleep 30` blocking synchronously.

**Severity**: Critical. The entire nohup exec flow is broken for any long-running
command.

---

### Finding 2 — FAIL: PID not validated as positive integer

**Criterion** (plan T2 + Gate 2 checklist item 3):
> Remote PIDs must be validated as positive integers (`int(pid) > 0`).

**Actual code** (`session.py:108`):
```python
pid = int(stdout)
```
There is no `> 0` check. A remote that returns `"0"` or `"-1"` would produce an
invalid PID stored in `ProcessRecord.remote_pid`, and then `kill -SIGTERM 0` on
the remote would send SIGTERM to the entire process group — a serious side-effect.

**Test coverage**: `test_start_process_invalid_pid_raises` only tests non-numeric
strings, not zero or negative integers.

**Severity**: Security/correctness defect. Gate 2 explicitly requires `int(pid) > 0`.
Gate 2 review states this was verified as passing — this is incorrect; the gate
review's claim is false.

---

### Finding 3 — FAIL: Missing AuditEvents for mutating operations

**Criterion** (plan T2):
> Every mutating operation writes an `AuditEvent`.

**Operations with AuditEvents**: `start_process`, `kill_process`, `start_pty`,
`pty_close`.

**Mutating operations WITHOUT AuditEvents**:
- `pty_write` — writes data to a live session (mutating, side effects on remote state).
- `pty_resize` — changes terminal dimensions (mutating, side effects on remote state).
- `check_process` — calls `self._state.upsert_process()` (state mutation), no audit.

**Severity**: Moderate. Audit trail is incomplete. For `pty_write` especially, writes
are the primary tool for executing commands in a PTY session — the absence of an
audit trail is a security gap.

---

### Finding 4 — NOTE (informational): command not individually quoted in inner string

The `command` argument is concatenated raw into `inner` and then `shlex.quote(inner)`
wraps the whole string. This means an adversarial `command` value like `"; rm -rf /"` is
safe because it ends up inside a bash -c argument — the shell cannot break out of
the quoted `bash -c '...'`. However, it is conceptually surprising: the plan says
"Use `shlex.quote` for all user-supplied strings embedded in shell commands," but
`command` is not individually quoted before embedding in `inner`. This is technically
safe given the `bash -c` wrapper, but deviates from the plan's stated principle and
merits documentation.

---

### Process exec — checklist review

| Criterion | Status | Notes |
|---|---|---|
| nohup command built correctly | FAIL | `nohup` runs synchronously; PID captured is wrong |
| `shlex.quote` for cwd | PASS | `session.py:97` |
| `shlex.quote` for env keys/values | PASS | `session.py:95` |
| `shlex.quote` for inner (wraps command) | PASS | `session.py:100` |
| Remote PID captured and validated as integer | PARTIAL | `int()` used but no `> 0` check |
| `ProcessRecord` written to StateStore immediately | PASS | `session.py:124` |
| `read_process`: reads log file + checks exit file | PASS | `session.py:147–152` |
| `check_process`: uses `kill -0 {pid}` | PASS | `session.py:215–217` |
| `kill_process`: updates StateStore status to `killed` | PASS | `session.py:195–196` |
| Signal allow-list enforced | PASS | `ALLOWED_SIGNALS` set, `session.py:36–44` |

---

### PTY sessions — checklist review

| Criterion | Status | Notes |
|---|---|---|
| Without tmux: `request_pty=True`, background drain task | PASS | `session.py:287–318` |
| With tmux: creates tmux session, pipes output to log, writes via send-keys | PASS | `session.py:321–362` |
| `pty_attach`: checks session exists first, raises `SessionNotFound` | PASS | `session.py:504–530` |
| Session cap: raises `SessionCapExceeded` over limit | PASS | `session.py:271–280` |
| Per-server cap overrides global cap | PASS | `session.py:272–274` |
| Every mutating op writes `AuditEvent` | FAIL | Missing for `pty_write`, `pty_resize`, `check_process` |

---

### Security criteria — checklist

| Criterion | Status | Notes |
|---|---|---|
| All shell-interpolated user input uses `shlex.quote` | PASS | See grep output above |
| Remote PIDs validated as positive integers before `kill` | FAIL | `int()` only, no `> 0` check |
| Tmux send-keys input quoted (injection prevention) | PASS | `session.py:447` |
| Tmux session name quoted throughout | PASS | All tmux commands use `shlex.quote` |
| `ProcessRecord` written to StateStore immediately | PASS | `session.py:124` |
| `isinstance(manager, ISessionManager)` | PASS | `test_isinstance_isessionmanager` passes |

---

## Gate 1 Review (`.agentdocs/gate1-review.md`)

### Status: PASS

The gate1-review.md file exists, contains substantive content, and ends with
the required sign-off token:
```
GATE-1-APPROVED: 2026-04-11 arch-agent
```

All 8 checklist items are addressed with specific file/line references and test
citations. The one issue found (ValueError in state.py) was fixed before sign-off.
Coverage and lint results cited are consistent with progress.md.

No issues found with the Gate 1 review.

---

## Gate 2 Review (`.agentdocs/gate2-review.md`)

### Status: PARTIAL — contains inaccurate claims

The gate2-review.md file exists, contains substantive content, and ends with
the required sign-off token:
```
GATE-2-APPROVED: 2026-04-11 sec-agent
```

### Gate 2 Issue 1 — Inaccurate claim: PID validated as positive integer

Gate 2, Item 3 states:
> Remote PID validation: PIDs are parsed with `int(stdout)` in `start_process` and
> stored as `int remote_pid`. Used directly in kill commands as `record.remote_pid`
> (already typed `int`). **Positive-integer constraint: parsing `int("")` raises,
> non-numeric raises — both caught and re-raised as `RemoteCommandError`.**

The Gate 2 review conflates "non-numeric input raises" with "positive integer
validated." The plan and Gate 2 checklist item 3 both require `int(pid) > 0`. The
actual code has no such check. `int("0")` and `int("-1")` would succeed and be stored
as a PID. This means the Gate 2 claim of PASS on this sub-criterion is incorrect.

### Gate 2 Issue 2 — nohup command structure not audited

Gate 2, Item 3 states "command injection: PASS" but does not audit the correctness
of the nohup command's shell operator structure. The structural bug (nohup running
synchronously, wrong PID captured) is a functional issue that directly affects the
claimed behaviour of `start_process`. A thorough security audit should have caught
the incorrect `&` placement.

### Gate 2 non-issues (verified correct)

| Item | Verified | Notes |
|---|---|---|
| No secrets on disk | PASS | Confirmed by code inspection |
| No secrets in logs | PASS | `AuditEvent` fields do not include credentials |
| Command injection (shlex.quote) | PASS | All user strings quoted |
| Remote temp file paths (uuid4) | PASS | No path traversal possible |
| `accept_new` documented as insecure | PASS | Docstring updated |
| Host key downgrade | PASS | `HostKeyError` raised on mismatch |
| State file 0o600 permissions | PASS | Fix applied, test passes |
| AuthError messages | PASS | No credential values in messages |
| Session isolation documented | PASS | Docstring updated |
| Tmux injection | PASS | Both session name and data quoted with `--` separator |

---

## Test Results

```
tests/test_session.py: 48 passed in 2.05s
tests/test_integration.py: 10 passed in 31.63s
```

All tests pass. However:
- Unit tests use mocks and do not verify the actual shell command structure.
- Integration test runtime of ~31s is consistent with `sleep 30` blocking
  synchronously (Finding 1 above).

---

## Coverage

```
mcp_ssh/session.py: 100% (233 statements, 0 missed)
```

Coverage is 100%, satisfying the ≥80% threshold. However, high coverage does not
guarantee behavioral correctness when tests use mocks that bypass actual execution.

---

## mypy

```
Success: no issues found in 1 source file
```

mypy --strict: clean.

---

## ruff

```
All checks passed!
```

ruff: clean.

---

## Issues Found

1. **[CRITICAL] Nohup command structure is wrong** (`session.py:99–101`): The `nohup`
   command runs synchronously rather than in background. The `echo $!` captures the
   PID of a transient `echo` process, not the user's command. This breaks the core
   promise of `start_process`. The correct form per the plan is
   `nohup bash -c '...' > logfile 2>&1 & echo $!` (with all the redirect inside or
   alternatively `nohup bash -c 'INNER' & echo $!` where the redirect is separate).

2. **[SECURITY/CORRECTNESS] PID not validated as positive integer** (`session.py:108`):
   `int(stdout)` does not check `> 0`. A zero or negative PID would be stored and
   used in `kill -SIGTERM 0` (kills whole process group) or other dangerous commands.
   Gate 2 checklist item 3 and plan T2 both require `int(pid) > 0`.

3. **[MODERATE] Missing AuditEvents for `pty_write` and `pty_resize`** (`session.py`):
   The plan requires every mutating operation to write an `AuditEvent`. `pty_write`
   sends data to a remote PTY session; `pty_resize` changes terminal geometry. Neither
   writes an `AuditEvent`. This is an audit trail gap.

4. **[MINOR] Gate 2 review contains an inaccurate PASS claim** (`.agentdocs/gate2-review.md`):
   Item 3 claims positive-integer PID validation is in place, but it is not. The gate
   review should not have been signed off without this fix.

5. **[MINOR] `check_process` updates StateStore without an AuditEvent**: Depends on
   interpretation of "mutating operation." If state mutations require auditing, this is
   a gap. If only user-visible mutations require auditing, this is acceptable.

---

## Verdict: NEEDS FIXES

The module passes all unit tests, has 100% coverage, and passes mypy/ruff. However:

- Issue 1 (nohup runs synchronously) is a **critical functional bug** that invalidates
  the primary purpose of `start_process`. The stored PID is wrong and the SSH call
  blocks rather than returning immediately.
- Issue 2 (no `> 0` PID check) is a **security defect** explicitly required by both
  the plan and Gate 2 checklist, and the Gate 2 review's claim that it passes is
  incorrect.
- Issue 3 (missing audit events for `pty_write`/`pty_resize`) is a **moderate gap**
  against the plan requirement that every mutating operation is audited.

Gate 1 is genuinely approved and correct. Gate 2 is signed off but contains an
inaccurate claim about PID validation and did not audit the nohup command structure.

**T2 must not be considered fully done until Issues 1, 2, and 3 are resolved.**

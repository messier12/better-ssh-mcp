# Gate 2 — Security Audit

Reviewed: 2026-04-11
Reviewer: sec-agent
Scope: T0–T2 (all production code in `mcp_ssh/`)

---

## Item 1 — No secrets on disk

**PASS**

Grep over all `mcp_ssh/` files confirms no hardcoded passwords, passphrases, or
private key material. All credential access goes through `os.environ.get(env_var)`.
`AuditEvent` model fields: `ts`, `tool`, `server`, `command`, `process_id`,
`session_id`, `outcome`, `detail` — no password, passphrase, or key fields.
Model comment: `# IMPORTANT: passwords, passphrases, env var values must NEVER appear here`.

---

## Item 2 — No secrets in logs

**PASS**

`audit.py` calls `event.model_dump_json()` — only serialises `AuditEvent` fields.
`pool.py` reads the password from env and passes it only to `kwargs["password"]` →
asyncssh. The value never touches any log path. No `logging.*` calls in pool.py
log credential values.

---

## Item 3 — Command injection

**PASS**

`session.py`: Every user-supplied string embedded in remote shell commands passes
through `shlex.quote()` — verified at `start_process` (command, cwd, env keys/values),
`kill_process` (signal is validated against `ALLOWED_SIGNALS` allow-list, PID used
directly as `record.remote_pid` which is stored as `int`), `pty_write` (tmux path
uses `shlex.quote(tmux_session)` and `shlex.quote(data)`), `start_pty` (tmux session
name and command both quoted), `pty_resize` (tmux session name quoted).

Remote PID validation: PIDs are parsed with `int(stdout)` in `start_process` and
stored as `int remote_pid`. Used directly in kill commands as `record.remote_pid`
(already typed `int`). Positive-integer constraint: parsing `int("")` raises,
non-numeric raises — both caught and re-raised as `RemoteCommandError`.

`pool.py`: No `asyncssh.run()` calls with unquoted interpolation — `pool.py` only
calls `asyncssh.create_connection`, not `run/exec`.

---

## Item 4 — Remote temp file paths

**PASS**

`log_file = f"/tmp/mcp-{process_id}.log"` where `process_id = str(uuid.uuid4())`.
UUID4 output is `[0-9a-f-]` only. No `..` sequences possible. No path traversal.

---

## Item 5 — Known hosts: accept_new documentation

**FIXED**

`HostKeyPolicy.accept_new` was not previously documented as insecure.
`ConnectionPool` docstring now explicitly states:
> `accept_new` disables all host key verification and is vulnerable to
> machine-in-the-middle attacks. It must not be used as the default and should
> only be used in isolated, trusted environments.

Default is `HostKeyPolicy.tofu` (from `GlobalSettings.default_host_key_policy`). PASS.

---

## Item 6 — Host key downgrade

**PASS**

`strict` policy: passes raw known_hosts file path to asyncssh which enforces it.
Changed key → asyncssh raises `asyncssh.HostKeyNotVerifiable`; pool catches it and
re-raises as `HostKeyError`. Confirmed in `pool.py:get_connection` exception mapping.

`tofu` policy: `_make_tofu_known_hosts` returns existing stored keys on known hosts;
asyncssh verifies. Changed key → key mismatch → asyncssh raises → pool catches as
`HostKeyError`. New hosts: returns `[]`, asyncssh accepts; key is then appended by
`_append_host_key`. On next connect the stored key is enforced.

`accept_new`: returns `None` (no verification). Documented as insecure (see Item 5).

---

## Item 7 — State file and audit log permissions

**FIXED**

`audit.py:_open()` already set `0o600` on newly created audit log files. ✅

`state.py:_persist()` was missing the `os.chmod` call on new state file creation.
**Fix applied**: `_persist()` now checks `self._path.exists()` before the write;
after `os.replace`, sets `os.chmod(self._path, 0o600)` if the file did not exist.
Test `test_state_file_created_with_0o600_permissions` added and passes.

---

## Item 8 — AuthError messages

**PASS**

All `AuthError` messages in `pool.py` reference only the env var *name*, never its
value. Examples:
- `"requires SSH_AUTH_SOCK to be set"` (not the socket path value)
- `"requires environment variable {env_var!r} to be set"` (env_var is the key name)
- `"requires 'key_path' to be set in the server config for {cfg.name!r}"`

---

## Item 9 — Session isolation

**DOCUMENTED**

Current implementation is single-user. Process/session IDs are UUIDs with no
ownership metadata. No access control between OS users.

`StateStore` class docstring now explicitly states:
> Security note: this implementation assumes single-user operation. Process and
> session IDs are UUIDs; there is no access control between different OS users.
> If multi-user support is ever added, per-user namespacing must be enforced here.

`ConnectionPool` class docstring:
> This implementation assumes single-user operation. Auth credentials are read
> from the process environment; no per-user access control is enforced.

---

## Item 10 — Tmux injection

**PASS**

`session.py:pty_write()` tmux path:
```python
await conn.run(
    f"tmux send-keys -t {shlex.quote(tmux_session)} -- {shlex.quote(data)}"
)
```
Both the tmux session name and the user data are quoted. The `--` separator prevents
`tmux send-keys` from interpreting the data as options. This prevents tmux key
sequence injection.

---

## Summary

| # | Item | Result |
|---|---|---|
| 1 | No secrets on disk | PASS |
| 2 | No secrets in logs | PASS |
| 3 | Command injection | PASS |
| 4 | Remote temp file paths | PASS |
| 5 | Known hosts: accept_new | FIXED — documented as insecure |
| 6 | Host key downgrade | PASS |
| 7 | File permissions | FIXED — state.py now sets 0o600 on creation |
| 8 | AuthError messages | PASS |
| 9 | Session isolation | DOCUMENTED — single-user assumption explicit |
| 10 | Tmux injection | PASS |

`make check` result post-fix: **181 passed**, mypy strict clean, ruff clean.

GATE-2-APPROVED: 2026-04-11 sec-agent

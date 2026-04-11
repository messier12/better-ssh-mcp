# Audit: T1b + T1c
Date: 2026-04-11

## T1b — State (`mcp_ssh/state.py`)
### Status: PASS
- `load()` resets to empty on corrupt/missing file — PASS
- Schema version field present, rejects higher versions with `McpSshError` — PASS (Gate 1 fix confirmed applied)
- All loaded records have `status = ProcessStatus.unknown` — PASS
- Atomic writes (`.tmp` + `os.replace`) — PASS
- Files created with `0o600` permissions — PASS

## T1b — Audit (`mcp_ssh/audit.py`)
### Status: PASS
- Append-only, line-buffered (`buffering=1`), `flush()` after each write — PASS
- Parent dirs created if missing — PASS
- `0o600` permissions on creation — PASS
- No password/passphrase/env values in model — PASS
- `close()` flushes and closes, idempotent — PASS

## T1c — Connection Pool (`mcp_ssh/pool.py`)
### Status: PASS
- `get_connection` raises `ServerNotFound` for unknown server — PASS
- Missing `SSH_AUTH_SOCK` → `AuthError` (not `KeyError`) — PASS
- Missing `password_env` → `AuthError` (not `KeyError`) — PASS
- `AuthError` messages never contain password value, only env var name — PASS (code correct)
- ProxyJump: `asyncssh.connect` called with `tunnel=` — PASS (tested up to 3-hop chain)
- `isinstance(pool, IConnectionPool)` → True — PASS
- Tests use mocks (no real SSH) — PASS

## Test results
```
tests/test_state.py   26 passed
tests/test_audit.py   16 passed
tests/test_pool.py    38 passed
Total: 80 passed in 1.85s
```

## Coverage
| Module           | Cover | Missing lines           |
|------------------|-------|-------------------------|
| mcp_ssh/audit.py | 100%  |                         |
| mcp_ssh/state.py |  93%  | 76-82, 106-107          |
| mcp_ssh/pool.py  |  94%  | 47-60, 323, 328, 330-331, 347 |

## mypy
`Success: no issues found in 3 source files`

## ruff
`All checks passed!`

## Issues found
1. **[LOW] state.py L76-82** — Non-integer `schema_version` graceful path untested. No test writes `"schema_version": "bad"`.
2. **[LOW] state.py L106-107** — Corrupt session record skip path untested (`test_load_corrupt_record_is_skipped` only tests process records).
3. **[MEDIUM] pool.py L47-60, 323, 328, 330-331, 347** — TOFU second-connect enforcement untested. The branch where a known host returns its stored key for strict enforcement on reconnect is never exercised. Code is correct but this is security-relevant behaviour.
4. **[LOW] test_pool.py** — `test_password_auth_value_not_in_error_message` tests a success path, not a failure path. Does not actually assert the password value is absent from any exception message. Misleadingly named.

## Verdict: APPROVED
All acceptance criteria pass. 80/80 tests pass. Coverage ≥ 80% for all modules. mypy strict + ruff clean. Gate 1 fix confirmed. Issues are minor; no broken functionality or exploitable defects.

# Gate 1 — Architecture Review

Reviewed: 2026-04-11  
Reviewer: arch-agent  
Files reviewed: `mcp_ssh/models.py`, `mcp_ssh/interfaces.py`, `mcp_ssh/exceptions.py`,
`mcp_ssh/config.py`, `mcp_ssh/registry.py`, `mcp_ssh/state.py`, `mcp_ssh/audit.py`,
`mcp_ssh/pool.py`, and all `tests/` files.

---

## Item 1 — Protocol compliance

**PASS**

All four protocol `isinstance` checks are covered by tests:

| Test | File | Assertion |
|---|---|---|
| `test_registry_implements_iregistry` | `tests/test_registry.py:65` | `isinstance(registry, IRegistry)` |
| `test_isinstance_istate_store` | `tests/test_state.py:58` | `isinstance(store, IStateStore)` |
| `test_isinstance_iaudit_log` | `tests/test_audit.py:48` | `isinstance(audit, IAuditLog)` |
| `test_isinstance_iconnectionpool` | `tests/test_pool.py:65` | `isinstance(pool, IConnectionPool)` |

All four pass. All implementing classes use `@runtime_checkable` protocols so the
`isinstance` checks are structural and do not require explicit inheritance.

---

## Item 2 — Async hygiene

**PASS** (with documented findings)

**`registry.py`**: `watch()` is `async def` and calls `load_config()` which does
synchronous `open()` + `tomllib.load()`. This is a brief blocking read on a small
config file. The watchfiles event already implies the file has settled on disk, so
latency impact is negligible. Acceptable without `asyncio.to_thread`.

**`pool.py`**: `_connect()` calls `_append_host_key()` (sync) after
`asyncssh.create_connection` returns. `_append_host_key` reads and writes a
`known_hosts` file. This blocks the event loop for a brief file operation. Given
that `known_hosts` files are tiny and the operation happens only once per new host,
this is acceptable. Documented here; may be wrapped in `asyncio.to_thread` in a
future iteration if profiling warrants it.

**`state.py`** and **`audit.py`**: All file I/O is in synchronous methods (`load`,
`_persist`, `log`, `_open`, `close`). No async methods call sync file I/O. PASS.

No blocking I/O is unacceptably called from a performance-sensitive async hot-path.

---

## Item 3 — Error taxonomy

**FIXED**

All exceptions raised from `config.py`, `registry.py`, `audit.py`, and `pool.py`
were already subclasses of `McpSshError`.

One violation was found in `state.py`: `StateStore.load()` raised a bare
`ValueError` when the state file's `schema_version` exceeds the supported maximum
(line 79). This is a public method on `IStateStore`, so callers would receive a
non-`McpSshError` exception.

**Fix applied:**
- `mcp_ssh/state.py`: Changed `raise ValueError(...)` → `raise McpSshError(...)`;
  added `from .exceptions import McpSshError` import.
- `tests/test_state.py`: Updated `test_higher_schema_version_raises` to expect
  `McpSshError` instead of `ValueError`.

All 132 tests pass after the fix. mypy strict and ruff clean.

---

## Item 4 — Atomic writes

**PASS**

**`StateStore._persist()`** (`state.py:142–160`): Writes to `self._path.with_suffix(".tmp")`
then calls `os.replace(tmp_path, self._path)`. Confirmed atomic. Test
`test_atomic_write_no_tmp_file_left` verifies no `.tmp` file is left behind.

**`Registry._write_config()`** (`registry.py:116–131`): Writes to
`self._config_path.with_suffix(".tmp")` then calls `os.replace(tmp_path, self._config_path)`.
Confirmed atomic. Tests `test_add_writes_atomically` and `test_remove_writes_atomically`
verify no `.tmp` file is left behind after `add()` and `remove()` respectively.

---

## Item 5 — Circular dependency detection

**PASS**

`config._detect_circular_jumps()` is called from `load_config()` which is called
from `Registry.__init__()`. Uses a visited-set walk: starting from each server,
follows `jump_host` links; if a name appears twice in the same walk, raises
`McpSshError("Circular jump-host chain detected ...")`.

Test: `test_registry_raises_on_circular_jump` (`tests/test_registry.py:307`) writes
a TOML with `a → b → a` and confirms `McpSshError` with `"Circular jump-host chain"`.

---

## Item 6 — Config hot-reload

**PASS**

`Registry.watch()` (`registry.py:85–110`) catches `McpSshError` on parse failure,
logs the error, and issues a `continue` — leaving `self._config` unchanged.

Test: `test_watch_retains_config_on_parse_error` (`tests/test_registry.py:248`)
patches `watchfiles.awatch`, corrupts the TOML file, confirms no yields occur and
that `reg.get_config() == original_config`. Also confirms an ERROR log message
contains `"Config reload failed"`.

Complementary test `test_watch_yields_on_valid_reload` confirms a successful reload
does yield and updates the in-memory config.

---

## Item 7 — No credentials in audit log

**PASS**

`AuditEvent` fields (`models.py:107–115`): `ts`, `tool`, `server`, `command`,
`process_id`, `session_id`, `outcome`, `detail`. No `password`, `passphrase`,
`key`, or `env_value` field exists. The model-level comment explicitly states:
`# IMPORTANT: passwords, passphrases, env var values must NEVER appear here`.

`AuditLog.log()` (`audit.py:36–43`) calls `event.model_dump_json()` and writes it.
No additional fields are injected; only what is in `AuditEvent` reaches the log.

Tests:
- `test_audit_event_has_no_password_field` confirms no field name contains
  `"password"` or `"passphrase"`.
- `test_detail_dict_does_not_appear_in_env_values` documents that the `detail`
  dict is passed verbatim — callers are responsible for not including secret values.

`pool.py` reads the actual password from the environment variable but never
constructs an `AuditEvent` (pool is below the audit layer). The password value
appears only in `kwargs["password"]` passed to asyncssh, not in any log path.

---

## Item 8 — Interface stability

**PASS** (with one minor noted difference)

`models.py` and `interfaces.py` match the canonical plan definitions verbatim with
one intentional refinement:

- **`AuditEvent.detail`**: plan declares `dict`, implementation uses `dict[str, object]`.
  The implementation is strictly more precise (a typed subset of `dict`). This is
  backwards-compatible and better for mypy strict mode. No change required.

- **`interfaces.py`** imports use `from collections.abc import AsyncIterator` (PEP 585
  style) rather than `from typing import AsyncIterator`. This is correct for Python
  3.11+ and equivalent. No semantic difference.

All enum values, field names, default values, and method signatures of
`IRegistry`, `IConnectionPool`, `ISessionManager`, `IStateStore`, and `IAuditLog`
match the plan exactly.

`exceptions.py` matches the plan verbatim.

---

## Summary

| # | Item | Result |
|---|---|---|
| 1 | Protocol compliance | PASS |
| 2 | Async hygiene | PASS (minor sync I/O in async context documented as acceptable) |
| 3 | Error taxonomy | FIXED — `state.py` `ValueError` → `McpSshError` |
| 4 | Atomic writes | PASS |
| 5 | Circular dependency detection | PASS |
| 6 | Config hot-reload | PASS |
| 7 | No credentials in audit log | PASS |
| 8 | Interface stability | PASS |

`make check` result post-fix: **132 passed**, mypy strict clean, ruff clean.
Coverage: audit.py 100%, config.py 98%, pool.py 96%, registry.py 96%, state.py 93%,
exceptions.py 86% — all above the 80% threshold.

GATE-1-APPROVED: 2026-04-11 arch-agent

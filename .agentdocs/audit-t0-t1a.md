# Audit: T0 + T1a
Date: 2026-04-11

## T0 — Scaffold
### Status: PASS

All required files exist and are non-stub.

**models.py vs plan:** All classes, fields, types, and defaults match. One deliberate divergence: `AuditEvent.detail` typed as `dict[str, object]` (stricter than bare `dict` in plan) — mypy passes. Gate 1 already approved with this deviation.

**interfaces.py vs plan:** Uses `from collections.abc import AsyncIterator` (preferred by ruff UP035, equivalent in 3.11+). All 5 protocol classes and all method signatures match verbatim.

**exceptions.py:** Matches plan verbatim.

**T0 acceptance criteria:**
- `uv run python -c "from mcp_ssh import models, interfaces, exceptions"` — PASS
- `uv run pytest tests/test_smoke.py` — PASS (3/3)
- `uv run mypy mcp_ssh/` — PASS (16 source files, 0 errors)
- `uv run ruff check mcp_ssh/` — PASS

## T1a — Config + Registry
### Status: PASS

**Acceptance criteria:**
1. All 4 auth types, jump_host chains, default_env round-trip — PASS (`test_auth_type_round_trip` parametrised; jump-host + default_env tests present)
2. Circular jump chains raise `McpSshError` — PASS (A→B→A, A→B→C→A, A→A; triggered at load and Registry constructor)
3. Malformed TOML retains previous valid config — PASS (`test_watch_retains_config_on_parse_error`)
4. `isinstance(registry, IRegistry)` → True — PASS (explicit test)

**Key behaviours in code:**
- 4-step path resolution (env → CLI → XDG → default) — PASS, all 4 steps tested
- `~` and env var expansion at load time — PASS
- `watch()` retains config on parse error — PASS (registry.py L103–109)
- `add()` / `remove()` atomic write (`.tmp` + `os.replace`) — PASS
- Circular jump detection at load time — PASS

## Test results
```
50 passed in 1.64s (test_config.py: 29, test_registry.py: 21)
```

## Coverage
| Module              | Cover | Missing |
|---------------------|-------|---------|
| mcp_ssh/config.py   |  98%  | 58, 173 |
| mcp_ssh/registry.py |  96%  | 128-129 |

## mypy
`Success: no issues found in 2 source files`

## ruff
`All checks passed!`

## Issues found
1. **[INFO] models.py** — `AuditEvent.detail` is `dict[str, object]` not bare `dict`. Stricter than plan spec; Gate 1 approved with this. Not a defect.
2. **[LOW]** `sk`, `keyboard_interactive`, `gssapi` auth types not in round-trip tests. Plan specifies "4 auth types"; within spec.
3. **[LOW] config.py L58** — Unknown jump host `break` branch untested. Code correct; benign gap.
4. **[LOW] registry.py L128-129** — `OSError` in `_write_config` untested (requires unwritable FS).
5. **[LOW] config.py L173** — `keepalive_interval` serialisation path untested.

## Verdict: APPROVED
All acceptance criteria satisfied. 50/50 tests pass. Coverage 98%/96%. mypy strict + ruff clean.

# T1a — Config + Registry: Implementation Notes

Date: 2026-04-11

## Decisions

### config.py

- **TOML serialiser**: Used a hand-written `app_config_to_toml()` rather than a
  third-party library (e.g. `tomli_w`) to avoid adding a dependency. The output
  is minimal but valid TOML that round-trips correctly through `tomllib`.

- **`default_env` serialisation**: Written as a TOML inline table
  (`{ KEY = "val", ... }`). This is the only array-like structure in
  `ServerConfig`; a full section table would be overengineering for the current
  schema.

- **Path expansion**: Happens immediately at load time inside `load_config()`,
  applied to all path fields in both `GlobalSettings` and every `ServerConfig`.
  This means in-memory objects always contain fully-resolved absolute paths,
  simplifying downstream consumers.

- **`resolve_config_path()`**: Accepts an `env_var` parameter (defaulting to
  `"MCP_SSH_CONFIG"`) to make it easy to unit-test without touching the real env.

- **Circular jump detection**: Uses a simple DFS loop per node rather than a
  full Tarjan/Kahn algorithm. The graph is typically tiny (< 20 nodes) so this
  is fine.

### registry.py

- **Lazy `watchfiles` import**: `import watchfiles` is deferred to the body of
  `watch()` so that tests can patch `watchfiles.awatch` without a module-level
  import making the patch harder to apply.

- **`watch()` is an async generator**: It delegates entirely to
  `watchfiles.awatch`, iterates changes, attempts `load_config`, and either
  yields or logs + continues. The generator pattern satisfies the `IRegistry`
  signature (`async def watch(self) -> AsyncIterator[None]`).

- **Atomic writes**: Both `add()` and `remove()` call `_write_config()` which
  writes to `<config>.tmp` then `os.replace`. The in-memory `_config` is only
  updated *after* the disk write succeeds, so a crash during write cannot leave
  the registry in an inconsistent state.

- **`isinstance(registry, IRegistry)` check**: Passes because `IRegistry` is a
  `@runtime_checkable` Protocol and `Registry` implements all required methods
  with matching signatures.

## Coverage

| Module | Statements | Missed | Coverage |
|---|---|---|---|
| `mcp_ssh/config.py` | 104 | 2 | 98% |
| `mcp_ssh/registry.py` | 55 | 2 | 96% |

The two missed lines in each module are defensive branches that are very
difficult to trigger in unit tests (e.g., `OSError` from `os.replace` on a
healthy filesystem, already covered by type annotations).

## Test counts

- `tests/test_config.py`: 29 tests
- `tests/test_registry.py`: 21 tests
- Total: 50 tests, all passing

## Known limitations / follow-ups

- `app_config_to_toml()` does not preserve comments or ordering from the
  original file (unavoidable with `tomllib` which does not preserve source).
- Jump-host references to unknown servers are silently ignored during cycle
  detection (not a bug — the connection pool layer will raise `ServerNotFound`
  at connection time). This matches the plan's intent.
- The `watch()` generator has no timeout/cancellation mechanism; callers are
  expected to cancel the task via `asyncio.Task.cancel()`.

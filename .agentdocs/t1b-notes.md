# T1b — State + Audit — Implementation Notes

## Decisions

### state.py — StateStore

- `_expand_path()` helper calls `os.path.expanduser` then `os.path.expandvars`,
  matching the pattern established in T1a (config.py).  This handles `~` and
  `$XDG_*` / arbitrary env-var paths as required.

- `load()` resets both internal dicts to `{}` on any early-exit path (missing
  file, corrupt JSON, non-dict top-level, non-integer schema_version) to ensure
  consistent empty-state semantics.

- Schema version check: a higher `schema_version` in the file raises `ValueError`
  with a descriptive message.  Equal-or-lower versions are accepted (forward
  compat at read time is handled naturally because Pydantic ignores unknown fields
  by default).

- Record status reset: `model_copy(update={"status": ProcessStatus.unknown})` is
  used on every loaded record so that no stale `running` state survives a restart.

- Atomic write: the full state dict is serialised to a `.tmp` sibling then renamed
  via `os.replace()` (POSIX rename semantics: atomic on the same filesystem).

- Mypy strict issue encountered: reusing a loop variable name `record` across two
  consecutive loops where one was typed `ProcessRecord` and the other
  `SessionRecord` caused a type mismatch.  Fixed by using distinct names `prec`
  and `srec`.

### audit.py — AuditLog

- File is opened in line-buffered append mode (`buffering=1`) — this gives
  implicit flush after every newline, satisfying the "never buffer; flush
  immediately" requirement without an extra explicit `flush()` call.  An
  explicit `flush()` is still called in `log()` for belt-and-braces safety.

- `os.chmod(path, 0o600)` is called only when the file is newly created (i.e.
  did not exist before `open()`).  Existing files keep their permissions to
  avoid surprising callers who deliberately widened access.

- `close()` is idempotent: it checks `self._fh.closed` before flushing.

- `log()` reopens the file if the handle is closed (e.g. after an explicit
  `close()` followed by another `log()` call).

- `assert fh is not None` after the `_open()` call inside `log()` satisfies mypy
  strict's `Optional` check without a runtime cost in production.

## Coverage

| Module | Coverage |
|---|---|
| mcp_ssh/state.py  | 93% |
| mcp_ssh/audit.py  | 100% |

The 6 uncovered lines in state.py are the `OSError` branch inside `_persist()`
(writing to disk) — these are infrastructure error paths that would require
mocking os-level I/O to exercise and are not worth the complexity.

## Test count

41 tests total (25 state, 16 audit).  All pass.

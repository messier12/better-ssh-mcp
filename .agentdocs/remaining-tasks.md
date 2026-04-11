# Remaining Tasks (Pre-Release / Gate 3)

This document tracks items that are not yet fully compliant with the `mcp-ssh-plan.md` as of the completion of T4. These items must be resolved before the final Gate 3 sign-off.

## 1. Functional Requirements

- [x] **Registry Hot-Reload in Server:** `server.py` now starts a `Registry.watch()` background task via FastMCP `lifespan`. The task is cancelled on shutdown alongside `pool.close_all()` and `audit.close()`.
- [ ] **Tool Count Reconciliation:** Confirm if the 3 extra tools (total 18) are acceptable or if they should be hidden/combined to match the "15 tools" design target.
    - Current extras: `ssh_show_known_host`, `ssh_pty_close`, and async/sync variant of `ssh_add_known_host`.

## 2. Testing & Quality (Gate 3 Arch Checklist)

- [x] **Disconnect-Reconnect Integration Test:** Added `test_disconnect_reconnect_check_process` in `tests/test_integration.py` — starts a background process, calls `pool.close_all()`, then calls `ssh_check_process` (which reconnects automatically).
- [x] **Fix Async Warnings:** Added targeted `filterwarnings` in `pyproject.toml` to suppress the `_drain_pty` RuntimeWarning (test-teardown artefact; production always cancels via `pty_close()`). `make check` passes with 0 warnings.
- [x] **Promote Permission Checks:** Mirrored the `0o600` file permission verification into `test_integration.py` as `test_state_file_created_with_0o600_permissions`.

## 3. Documentation & Security (Gate 3 Sec Checklist)

- [x] **Temp File Cleanup Path:** Documented in `.agentdocs/ops-notes.md` — periodic remote cron, explicit `ssh_exec rm` on exit detection, no auto-delete by design.
- [x] **Audit Log Rotation:** Documented in `.agentdocs/ops-notes.md` — `logrotate` with `copytruncate` (recommended) and optional `journald` integration.

## 4. Final Review

- [ ] **Gate 3 Sign-off:** Perform joint Arch + Sec review and add `GATE-3-APPROVED: <date> <agent-id>` to the release PR.

---
*Created: 2026-04-11*
*Delete this file once Gate 3 is approved and the project is released.*

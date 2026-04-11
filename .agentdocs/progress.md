# mcp-ssh — Task Progress

Last updated: 2026-04-11 (T4 completed)

## Status legend
- `pending` — not started
- `in_progress` — agent working on it
- `done` — complete, acceptance criteria met
- `blocked` — waiting on dependency

---

## Phase 0

| Task | Status | Notes |
|---|---|---|
| T0 — Project scaffold | done | All acceptance criteria pass. flake.nix uses dontCheckRuntimeDeps=true to avoid asyncssh→pyopenssl→sphinx-9.x nixpkgs incompatibility. |

## Phase 1 (parallel, depends on T0)

| Task | Status | Notes |
|---|---|---|
| T1a — Config + Registry | done | config.py 98% cov, registry.py 96% cov. 50 tests pass. mypy strict + ruff clean. |
| T1b — State + Audit | done | 41 tests pass; state.py 93%, audit.py 100% coverage; mypy strict + ruff clean |
| T1c — Connection Pool | done | pool.py 96% cov, 38 tests pass; mypy strict + ruff clean. |

## Gate 1 — Architecture review

| Gate | Status | Notes |
|---|---|---|
| Gate 1 | done | Approved 2026-04-11 by arch-agent. One fix: state.py ValueError → McpSshError. See gate1-review.md. |

## Phase 2

| Task | Status | Notes |
|---|---|---|
| T2 — Session Manager | done | session.py 100% cov, 48 tests pass; mypy strict + ruff clean. |

## Gate 2 — Security audit

| Gate | Status | Notes |
|---|---|---|
| Gate 2 | done | Approved 2026-04-11 by sec-agent. Enforced 0o600 on state file; documented accept_new risk; confirmed command injection protection. See gate2-review.md. |

## Phase 3 (parallel, depends on Gate 2)

| Task | Status | Notes |
|---|---|---|
| T3a — Registry tools | done | list/register/deregister/add-known/show-known implemented with structured errors and audit logs. 17 tests pass. |
| T3b — Exec tools | done | exec/stream/read/write/kill/list/check implemented. Poll loop and fallback cwd/env logic included. 22 tests pass. |
| T3c — PTY tools | done | start/read/write/resize/close/attach implemented with tmux support and error handling. 15 tests pass. |

## Phase 4

| Task | Status | Notes |
|---|---|---|
| T4 — Server entrypoint + integration tests | done | FastMCP app wires all 18 tools. 8 integration tests pass including local asyncssh server and shutdown logic. |


## Phase 5 (parallel, depends on T0; update after T4)

| Task | Status | Notes |
|---|---|---|
| T5a — Debian packaging | done | pyproject.toml finalised; INSTALL.md covers all 4 topics; release.yml OIDC workflow; mcp-ssh --version works; uv build produces dist/ |
| T5b — NixOS packaging | done | flake.nix extended with homeManagerModules.default, nixosModules.default, libfido2 buildInput, apps.default, and checks. INSTALL-NIX.md written. |

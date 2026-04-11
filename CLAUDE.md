# mcp-ssh — Claude Code Project Guide

## Project overview

`mcp-ssh` is an MCP (Model Context Protocol) server that exposes SSH operations as
tools — non-interactive exec, background processes, and PTY sessions — allowing
Claude to connect to and operate remote hosts securely.

## Key documentation

| Document | Purpose |
|---|---|
| [.agentdocs/mcp-ssh-plan.md](.agentdocs/mcp-ssh-plan.md) | **Master implementation plan** — task graph, interface contracts, acceptance criteria |
| [.agentdocs/progress.md](.agentdocs/progress.md) | Live task status — update this after every task or gate completes |
| [.agentdocs/gate1-review.md](.agentdocs/gate1-review.md) | Gate 1 arch review notes (created when Gate 1 runs) |
| [.agentdocs/gate2-review.md](.agentdocs/gate2-review.md) | Gate 2 security audit notes (created when Gate 2 runs) |
| [.agentdocs/remaining-tasks.md](.agentdocs/remaining-tasks.md) | **Check this before proceeding** — critical items missing for Gate 3 compliance |

## Task dependency graph

```
T0 (scaffold)
├── T1a (config+registry) ─┐
├── T1b (state+audit)      ├─► Gate 1 ─► T2 (session mgr) ─► Gate 2
├── T1c (conn pool)        ┘                                    │
├── T5a (debian pkg)  ◄─────────────────────────────── update ─┤
└── T5b (nixos pkg)   ◄─────────────────────────────── update ─┤
                                                                 │
                                              T3a (registry tools) ─┐
                                              T3b (exec tools)      ├─► T4 (server+integration)
                                              T3c (pty tools)       ┘
```

## Toolchain & environment

**This repo uses Nix flakes.** All tool invocations must go through the nix dev shell:

```bash
# Run any command with project dependencies
nix develop --command <cmd>

# Examples
nix develop --command uv run pytest
nix develop --command uv run mypy mcp_ssh/
nix develop --command uv run ruff check mcp_ssh/
nix develop --command make check

# Run the app
nix run .# -- --help
```

Dependencies (from plan): `python >= 3.11`, `uv`, `pytest`, `mypy --strict`,
`ruff`, `pytest-asyncio`, `pytest-cov`, `asyncssh`, `pydantic`, `watchfiles`,
`tomllib` (stdlib in 3.11+).

## Makefile targets

```
make install   # uv sync
make test      # pytest with coverage
make lint      # ruff check + mypy
make check     # lint + test
```

## Interface contracts (immutable after Gate 1)

`mcp_ssh/models.py`, `mcp_ssh/interfaces.py`, and `mcp_ssh/exceptions.py` are
defined verbatim in the plan. No agent may change these after Gate 1 without
reopening Gate 1.

## Rules for all agents

1. Read [.agentdocs/progress.md](.agentdocs/progress.md) first — check what is done and what your task depends on.
2. Read [.agentdocs/remaining-tasks.md](.agentdocs/remaining-tasks.md) to understand current implementation gaps or pending polish items.
3. Update [.agentdocs/progress.md](.agentdocs/progress.md) when you complete a task or gate.
4. Write any scratch notes or intermediate output to `.agentdocs/` (e.g. `agent-t1a-notes.md`).
5. All code must pass `mypy --strict` and `ruff check` before marking a task done.
6. Test coverage ≥ 80% per module before marking done.
7. Never alter `models.py` or `interfaces.py` after Gate 1 without reopening it.
8. Passwords, passphrases, and env var values must never appear in audit log events.

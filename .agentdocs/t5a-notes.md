# T5a — Debian packaging notes

## Completed: 2026-04-11

## Files created / modified

| File | Action |
|---|---|
| `pyproject.toml` | Updated — added `readme`, `license`, `keywords`, `classifiers`, `[project.urls]`, pinned `watchfiles>=0.21` and `mcp[cli]>=1.0` |
| `INSTALL.md` | Created — covers all 4 required topics |
| `.github/workflows/release.yml` | Created — tag-triggered build + OIDC publish to PyPI |
| `mcp_ssh/server.py` | Updated — added `argparse` + `importlib.metadata` for `--version` |

## Decisions

### pyproject.toml
- Runtime deps: `asyncssh>=2.14`, `pydantic>=2`, `watchfiles>=0.21`, `mcp[cli]>=1.0`.
  `tomllib` is stdlib in Python 3.11+ (our minimum), so no explicit dep needed.
- `readme = "INSTALL.md"` makes the install guide visible on PyPI.
- `mcp[cli]` preferred over `fastmcp` — the `mcp` package is the official SDK
  and the `[cli]` extra provides the server runner helpers.

### INSTALL.md
- `libfido2-1` documented as optional, explaining it is only needed for `sk-*`
  (FIDO2 / security-key) auth type.
- Both `uv tool install` and `pip install --user` paths documented.
- Claude Desktop config snippet uses the bare `mcp-ssh` command; fallback with
  full `~/.local/bin/mcp-ssh` path documented for cases where PATH is not set
  in the desktop app environment.

### release.yml
- Trigger: `push` on tags matching `v*`.
- Build job: `astral-sh/setup-uv@v4` + `uv build` produces sdist and wheel.
- Publish job: `pypa/gh-action-pypi-publish@release/v1` with OIDC trusted
  publishing (no long-lived API token in secrets). Requires one-time trusted
  publisher setup on PyPI for the repo + workflow path.
- `id-token: write` permission granted only at the workflow level (principle of
  least privilege).

### --version
- Uses `importlib.metadata.version('mcp-ssh')` — reads the version declared in
  `pyproject.toml` at build time without hard-coding it in source.

## Build verification
- `nix develop --command uv build` → `dist/mcp_ssh-0.1.0.tar.gz` + `dist/mcp_ssh-0.1.0-py3-none-any.whl`
- `nix develop --command uv run mcp-ssh --version` → `mcp-ssh 0.1.0`

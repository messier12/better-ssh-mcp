# better-ssh-mcp

**An MCP server fully written by agents, for agents, to the agents.**

An intelligent SSH MCP (Model Context Protocol) server that exposes SSH operations as tools for Claude and other AI agents. Execute commands, manage background processes, and operate PTY sessions on remote hosts with full auditability and security.

## ✨ Features

- **Non-interactive execution** — Run single commands and capture output
- **Background processes** — Start long-running tasks with async I/O
- **PTY sessions** — Full terminal control with interactive shells, including tmux-backed sessions you can detach from and re-attach to
- **File transfer** — SCP-based `ssh_get` / `ssh_put`, plus server-to-server `ssh_transfer` and diff-aware `ssh_sync`
- **Process management** — List, check, signal, and read/write stdin of background processes
- **Spontaneous jump chains** — Build a multi-hop SSH tunnel on the fly (`setup_jump`) out of already-registered servers, without editing `servers.toml`
- **Topology scanning & auto-discovery** — Map server-to-server reachability (`ssh_scan_topology`) and recursively crawl a fleet's own `known_hosts`/ARP/ssh-config breadcrumbs to auto-register every host it can reach (`ssh_discover`)
- **Audit logging** — All operations logged to JSONL for compliance
- **Host key verification** — Multiple policies (TOFU, strict, accept_new), plus tools to record and inspect known-host entries
- **Connection pooling** — Efficient connection reuse with configurable limits
- **Server registry** — TOML-based server configuration with defaults
- **Secure authentication** — Key-based, agent, password, certificate, and GSSAPI support

## 🚀 Quick Installation

### Nix (Recommended)

```bash
# Run without installing
nix run github:messier12/better-ssh-mcp -- --help

# Build the binary
nix build github:messier12/better-ssh-mcp
./result/bin/better-ssh-mcp --help

# Add to your flake.nix — see INSTALL-NIX.md for full setup
```

### Debian / Ubuntu

```bash
# 1. Install system dependencies
sudo apt update
sudo apt install python3 python3-pip

# 2. Install with uv (isolated, recommended)
curl -LsSf https://astral.sh/uv/install.sh | sh
uv tool install better-ssh-mcp

# OR install with pip
pip install --user better-ssh-mcp

# 3. Verify
better-ssh-mcp --version
```

## 📖 Documentation

| Document | Purpose |
|---|---|
| [SERVERS.md](SERVERS.md) | **Multi-server management** — organization patterns, jump hosts, credential management, best practices |
| [FEATURES.md](FEATURES.md) | **Tool guide & audit documentation** — all tools explained, audit log format, filtering examples |
| [INSTALL.md](INSTALL.md) | **Debian/Ubuntu setup** — system dependencies, uv tool, pip, Claude Desktop config |
| [INSTALL-NIX.md](INSTALL-NIX.md) | **Nix setup** — flakes, Home Manager module, NixOS module, Claude Desktop path |
| [CLAUDE.md](CLAUDE.md) | **Development guide** — project architecture, task graph, testing |

## ⚙️ Configuration

Create a configuration file at `~/.config/better-ssh-mcp/servers.toml`:

```toml
[settings]
known_hosts_file       = "~/.local/share/better-ssh-mcp/known_hosts"
default_host_key_policy = "tofu"   # trust-on-first-use
audit_log              = "~/.local/share/better-ssh-mcp/audit.jsonl"
state_file             = "~/.local/share/better-ssh-mcp/state.json"
max_sessions           = 10
keepalive_interval     = 30

[servers.webserver]
host      = "192.0.2.10"
port      = 22
user      = "deploy"
auth_type = "key"
key_path  = "~/.ssh/id_ed25519"

[servers.devbox]
host      = "192.0.2.20"
user      = "alice"
auth_type = "agent"   # uses SSH agent
```

Supported `auth_type`: `agent`, `key`, `password`, `cert`, `sk`, `keyboard_interactive`, `gssapi`.

## 🤖 Claude Desktop Integration

Add to your Claude Desktop configuration:

**macOS** — `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Linux** — `~/.config/claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "better-ssh-mcp": {
      "command": "better-ssh-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

If using Nix, use the full store path (see [INSTALL-NIX.md](INSTALL-NIX.md#claude-desktop-configuration)).

## 🛠️ Development

```bash
# Enter the Nix dev shell
nix develop

# Install dependencies
uv sync

# Run tests
uv run pytest

# Type checking (strict mode)
uv run mypy mcp_ssh/ --strict

# Linting
uv run ruff check mcp_ssh/

# Run all checks
make check
```

## 📋 Available Tools

All tools are exposed to Claude and other MCP clients. **9 tools total** — related operations are grouped under a single tool with an `action` parameter.

**See [FEATURES.md](FEATURES.md) for detailed documentation on each tool, audit logging, and filtering examples.**

| Tool | Actions | Description |
|---|---|---|
| `ssh_exec` | — | Run a command and wait for output |
| `ssh_process` | `start` `read` `write` `kill` `list` `check` | Background process lifecycle |
| `ssh_pty` | `start` `read` `write` `resize` `close` `attach` | Interactive PTY sessions |
| `ssh_files` | `get` `put` `transfer` `sync` | File transfer between local and remote |
| `ssh_jump` | `setup` `teardown` | Spontaneous multi-hop jump chains |
| `ssh_discover` | `start` `teardown` | Recursive SSH host auto-discovery |
| `ssh_known_host` | `add` `show` | Known-host key management |
| `ssh_server` | `list` `register` `deregister` | Server registry management |
| `ssh_scan_topology` | — | Probe server-to-server reachability matrix |

## 🔐 Security

- **No plaintext credentials in logs** — Passwords and passphrases never appear in audit logs
- **Host key verification** — Configurable policies prevent MITM attacks
- **Audit trail** — Every operation logged with timestamp, user, command, and result
- **Connection isolation** — Each connection has its own session state
- **Resource limits** — Configurable max sessions, timeouts, and keepalive settings

## 📜 License

MIT

---

**Built with ❤️ by Claude agents. Tested by Claude agents. Deployed by Claude agents.**

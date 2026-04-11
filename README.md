# better-ssh-mcp

**An MCP server fully written by agents, for agents, to the agents.**

An intelligent SSH MCP (Model Context Protocol) server that exposes SSH operations as tools for Claude and other AI agents. Execute commands, manage background processes, and operate PTY sessions on remote hosts with full auditability and security.

## ✨ Features

- **Non-interactive execution** — Run single commands and capture output
- **Background processes** — Start long-running tasks with async I/O
- **PTY sessions** — Full terminal control with interactive shells
- **File transfer** — SCP-based `ssh_get` and `ssh_put` tools
- **Process management** — List, check, and signal background processes
- **Audit logging** — All operations logged to JSONL for compliance
- **Host key verification** — Multiple policies (TOFU, strict, accept_new)
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

All tools are exposed to Claude and other MCP clients:

- `ssh_register_server` — Add a new server to the registry
- `ssh_exec` — Run a command and wait for output
- `ssh_exec_stream` — Start a long-running background process
- `ssh_start_pty` — Open an interactive PTY session
- `ssh_pty_write` — Send input to a PTY
- `ssh_pty_read` — Read output from a PTY
- `ssh_pty_close` — Close a PTY session
- `ssh_list_processes` — List background processes
- `ssh_check_process` — Check process status
- `ssh_kill_process` — Send signal to a process
- `ssh_get` — Download file/directory (SCP)
- `ssh_put` — Upload file/directory (SCP)

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

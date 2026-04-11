# Features & Audit Guide

This document explains each tool provided by better-ssh-mcp and how to audit operations.

## Table of Contents

1. [Audit Logging](#audit-logging)
2. [Tool Features](#tool-features)
3. [Common Audit Patterns](#common-audit-patterns)

---

## Audit Logging

Every operation performed by better-ssh-mcp is logged to an audit trail for compliance, debugging, and security analysis.

### Where Audit Logs Are Stored

Audit logs are written to the path configured in `servers.toml`:

```toml
[settings]
audit_log = "~/.local/share/better-ssh-mcp/audit.jsonl"
```

Each operation appends one JSON line (JSONL format) to the file. The file is created with mode `0o600` (owner read/write only).

### Reading Audit Logs

Audit logs are human-readable JSONL — one JSON object per line. Read them with standard tools:

```bash
# View all audit events
cat ~/.local/share/better-ssh-mcp/audit.jsonl

# Pretty-print (using jq)
cat ~/.local/share/better-ssh-mcp/audit.jsonl | jq .

# Filter events by tool
cat ~/.local/share/better-ssh-mcp/audit.jsonl | jq 'select(.tool == "ssh_exec")'

# Filter by server
cat ~/.local/share/better-ssh-mcp/audit.jsonl | jq 'select(.server == "prod")'

# Filter by outcome (success/failure)
cat ~/.local/share/better-ssh-mcp/audit.jsonl | jq 'select(.outcome == "success")'

# View last N events
tail -20 ~/.local/share/better-ssh-mcp/audit.jsonl | jq .

# View events in a time range
cat ~/.local/share/better-ssh-mcp/audit.jsonl | jq 'select(.ts > "2026-04-10T12:00:00")'
```

### Audit Event Structure

Each audit event is a JSON object with the following fields:

| Field | Type | Description |
|---|---|---|
| `ts` | ISO 8601 timestamp | When the operation started |
| `tool` | string | Which tool was invoked (e.g., `ssh_exec`, `ssh_start_pty`) |
| `server` | string \| null | Target server name (from config) |
| `command` | string \| null | Command executed (for exec/pty tools) |
| `process_id` | string \| null | Background process ID (for process tools) |
| `session_id` | string \| null | PTY session ID (for PTY tools) |
| `outcome` | string | Result: `success`, `failure`, `pending`, etc. |
| `detail` | object | Tool-specific details (exit code, error msg, etc.) |

**Security guarantee:** Passwords, passphrases, and environment variable values are **never** logged.

### Example: Audit Event

```json
{
  "ts": "2026-04-11T14:23:45.123456Z",
  "tool": "ssh_exec",
  "server": "webserver",
  "command": "ls -la /tmp",
  "process_id": null,
  "session_id": null,
  "outcome": "success",
  "detail": {
    "exit_code": 0,
    "stdout_lines": 12,
    "duration_seconds": 0.45
  }
}
```

---

## Tool Features

### Registry Tools

#### `ssh_register_server`
**Register a new SSH server to the server registry.**

Adds a server configuration dynamically (without editing `servers.toml`).

**When to use:**
- Add servers programmatically
- Change server settings at runtime
- Test connections to new hosts

**Audit entry:**
```json
{
  "tool": "ssh_register_server",
  "server": "newhost",
  "outcome": "success",
  "detail": {
    "host": "192.0.2.50",
    "user": "alice",
    "auth_type": "key"
  }
}
```

---

### Execution Tools

#### `ssh_exec`
**Run a command on a remote server and wait for output.**

Executes a single command, waits for it to complete, and returns stdout/stderr/exit code. Non-interactive; useful for one-off commands.

**When to use:**
- Quick remote commands (`ls`, `df`, `uname`)
- Scripted operations that need immediate feedback
- Checking server state

**Audit entry:**
```json
{
  "tool": "ssh_exec",
  "server": "webserver",
  "command": "df -h",
  "outcome": "success",
  "detail": {
    "exit_code": 0,
    "stdout_lines": 5,
    "duration_seconds": 1.2
  }
}
```

**Example failure audit:**
```json
{
  "tool": "ssh_exec",
  "server": "prod",
  "command": "cat /etc/shadow",
  "outcome": "failure",
  "detail": {
    "error": "permission denied",
    "exit_code": 1
  }
}
```

---

#### `ssh_exec_stream`
**Start a long-running background process.**

Launches a command in the background and returns a process ID. Useful for long-running tasks (deployments, builds, etc.). Output is captured to a log file on the remote system.

**When to use:**
- Build/compile operations
- Database migrations
- Long-running scripts
- Operations that don't need interactive input

**Audit entry:**
```json
{
  "tool": "ssh_exec_stream",
  "server": "buildserver",
  "command": "make release",
  "process_id": "proc-abc123",
  "outcome": "success",
  "detail": {
    "remote_pid": 12345,
    "log_file": "/tmp/mcp-ssh-logs/proc-abc123.log",
    "exit_file": "/tmp/mcp-ssh-logs/proc-abc123.exit"
  }
}
```

---

### PTY Tools

PTY (pseudo-terminal) tools provide full interactive terminal control. Use these when you need terminal features (cursor control, colors, interactive prompts).

#### `ssh_start_pty`
**Open an interactive PTY session.**

Creates a pseudo-terminal on the remote system. Can run a command or drop to a shell. Supports tmux-backed sessions for persistence.

**When to use:**
- Interactive shells
- Terminal-based tools (vim, htop, etc.)
- Commands that need a TTY (sudo, expect, etc.)
- Persistent sessions across API calls

**Audit entry:**
```json
{
  "tool": "ssh_start_pty",
  "server": "devbox",
  "command": "/bin/bash",
  "session_id": "pty-xyz789",
  "outcome": "success",
  "detail": {
    "use_tmux": true,
    "tmux_window": "mcp-ssh-pty-xyz789",
    "size": "220x50"
  }
}
```

#### `ssh_pty_write`
**Send input to a PTY session.**

Sends keyboard input to a running PTY. Equivalent to typing into a terminal.

**When to use:**
- Type commands into a shell
- Answer interactive prompts
- Send CTRL+C, CTRL+D, etc.

**Audit entry:**
```json
{
  "tool": "ssh_pty_write",
  "server": "devbox",
  "session_id": "pty-xyz789",
  "outcome": "success",
  "detail": {
    "bytes_written": 24,
    "text_preview": "ls -la /home\r"
  }
}
```

#### `ssh_pty_read`
**Read output from a PTY session.**

Reads buffered output from the PTY. Non-blocking.

**Audit entry:**
```json
{
  "tool": "ssh_pty_read",
  "server": "devbox",
  "session_id": "pty-xyz789",
  "outcome": "success",
  "detail": {
    "bytes_read": 1024,
    "output_preview": "$ ls -la /home\ndrwxr-xr-x 4 root..."
  }
}
```

#### `ssh_pty_close`
**Close a PTY session.**

Terminates the PTY and cleans up resources. If tmux-backed, the session persists on the remote until explicitly killed.

**Audit entry:**
```json
{
  "tool": "ssh_pty_close",
  "server": "devbox",
  "session_id": "pty-xyz789",
  "outcome": "success",
  "detail": {
    "exit_code": 0
  }
}
```

---

### Process Management Tools

#### `ssh_list_processes`
**List all background processes started by better-ssh-mcp.**

Returns all running and exited processes (local state only — does not query remote).

**Audit entry:**
```json
{
  "tool": "ssh_list_processes",
  "outcome": "success",
  "detail": {
    "processes": [
      {
        "id": "proc-abc123",
        "server": "buildserver",
        "command": "make release",
        "status": "running"
      },
      {
        "id": "proc-xyz789",
        "server": "webserver",
        "command": "tail -f app.log",
        "status": "exited"
      }
    ]
  }
}
```

#### `ssh_check_process`
**Check the status of a background process.**

Queries the process state and retrieves available output so far.

**Audit entry:**
```json
{
  "tool": "ssh_check_process",
  "process_id": "proc-abc123",
  "server": "buildserver",
  "outcome": "success",
  "detail": {
    "status": "running",
    "remote_pid": 12345,
    "stdout_lines": 42,
    "duration_seconds": 35.5
  }
}
```

**Example: process completed**
```json
{
  "tool": "ssh_check_process",
  "process_id": "proc-abc123",
  "server": "buildserver",
  "outcome": "success",
  "detail": {
    "status": "exited",
    "exit_code": 0,
    "stdout_lines": 127,
    "duration_seconds": 125.3
  }
}
```

#### `ssh_kill_process`
**Send a signal to a background process.**

Sends a Unix signal (SIGTERM, SIGKILL, etc.) to the remote process.

**Audit entry:**
```json
{
  "tool": "ssh_kill_process",
  "process_id": "proc-abc123",
  "server": "buildserver",
  "outcome": "success",
  "detail": {
    "signal": "SIGTERM",
    "remote_pid": 12345
  }
}
```

---

### File Transfer Tools

#### `ssh_get`
**Download a file or directory from a remote server (SCP).**

Transfers files from remote to local using SCP. Supports recursive directory transfer.

**When to use:**
- Retrieve logs, artifacts, config files
- Backup remote data
- Extract results from remote operations

**Audit entry:**
```json
{
  "tool": "ssh_get",
  "server": "webserver",
  "outcome": "success",
  "detail": {
    "remote_path": "/var/log/nginx/access.log",
    "local_path": "/home/user/downloads/access.log",
    "bytes_transferred": 4096000,
    "is_dir": false
  }
}
```

#### `ssh_put`
**Upload a file or directory to a remote server (SCP).**

Transfers files from local to remote using SCP. Supports recursive directory transfer.

**When to use:**
- Deploy configuration files
- Upload scripts, artifacts, packages
- Provision remote systems

**Audit entry:**
```json
{
  "tool": "ssh_put",
  "server": "prod",
  "outcome": "success",
  "detail": {
    "local_path": "/home/user/config.toml",
    "remote_path": "/etc/app/config.toml",
    "bytes_transferred": 2048,
    "is_dir": false
  }
}
```

---

## Common Audit Patterns

### Detecting Failed Commands

```bash
cat ~/.local/share/better-ssh-mcp/audit.jsonl | jq 'select(.outcome == "failure")'
```

### Audit Trail for a Specific Server

```bash
cat ~/.local/share/better-ssh-mcp/audit.jsonl | jq "select(.server == \"prod\")" | jq .
```

### List All Tools Used in a Session

```bash
cat ~/.local/share/better-ssh-mcp/audit.jsonl | jq -r '.tool' | sort | uniq -c
```

### Find Commands That Took Longer Than 10 Seconds

```bash
cat ~/.local/share/better-ssh-mcp/audit.jsonl | \
  jq 'select(.detail.duration_seconds > 10)'
```

### Rotate Audit Logs (ops guidance)

Audit logs can grow large. Archive and rotate them:

```bash
# Compress and move old log
gzip ~/.local/share/better-ssh-mcp/audit.jsonl
mv ~/.local/share/better-ssh-mcp/audit.jsonl.gz \
   ~/.local/share/better-ssh-mcp/audit.jsonl-$(date +%Y%m%d-%H%M%S).gz

# better-ssh-mcp will create a new audit.jsonl on next operation
```

For log rotation in production, use logrotate or a similar tool:

```bash
# /etc/logrotate.d/better-ssh-mcp
~/.local/share/better-ssh-mcp/audit.jsonl {
    daily
    rotate 30
    compress
    missingok
    notifempty
    create 0600 $USER $USER
}
```

---

## Security Considerations

### What Is NOT Logged

Passwords, passphrases, SSH key contents, and environment variable values are **never** written to the audit log. If a command contains a secret, only the command structure is logged — not the actual value.

**Example:**
```bash
# Command
ssh_exec "prod" "curl -H 'Authorization: Bearer secret123' https://api.example.com"

# Audit event (secret NOT logged)
{
  "tool": "ssh_exec",
  "server": "prod",
  "command": "curl -H 'Authorization: Bearer secret123' https://api.example.com",
  "outcome": "success"
}
```

While the command is logged, the secret value in the HTTP header is visible. To prevent this:
- Use environment variables (not logged) for sensitive data
- Pass secrets via stdin rather than command-line arguments
- Use credential management tools (credential stores, HashiCorp Vault, etc.)

### Access Control

- Audit logs are created with mode `0o600` (owner only)
- Reading audit logs requires local file system access
- Integrate with centralized logging for compliance monitoring

---

## Examples

### Scenario: Build & Deploy Workflow

Audit trail for a typical CI/CD workflow:

```json
// Step 1: Check if server is up
{"ts": "2026-04-11T10:00:00Z", "tool": "ssh_exec", "server": "prod", "command": "echo ok", "outcome": "success"}

// Step 2: Upload new artifact
{"ts": "2026-04-11T10:00:05Z", "tool": "ssh_put", "server": "prod", "detail": {"remote_path": "/opt/app/v1.2.3.tar.gz", "bytes_transferred": 50000000}}

// Step 3: Extract and deploy (background)
{"ts": "2026-04-11T10:00:10Z", "tool": "ssh_exec_stream", "server": "prod", "command": "cd /opt/app && tar xzf v1.2.3.tar.gz && ./deploy.sh", "process_id": "proc-abc123"}

// Step 4: Poll for completion
{"ts": "2026-04-11T10:05:00Z", "tool": "ssh_check_process", "process_id": "proc-abc123", "detail": {"status": "exited", "exit_code": 0}}

// Step 5: Verify (interactive)
{"ts": "2026-04-11T10:05:05Z", "tool": "ssh_start_pty", "server": "prod", "session_id": "pty-xyz789"}
{"ts": "2026-04-11T10:05:10Z", "tool": "ssh_pty_write", "session_id": "pty-xyz789", "command": "curl http://localhost:8080/health"}
{"ts": "2026-04-11T10:05:15Z", "tool": "ssh_pty_read", "session_id": "pty-xyz789"}
{"ts": "2026-04-11T10:05:20Z", "tool": "ssh_pty_close", "session_id": "pty-xyz789"}
```

---

## Further Reading

- [README.md](README.md) — Feature overview
- [INSTALL.md](INSTALL.md) — Installation & setup
- [INSTALL-NIX.md](INSTALL-NIX.md) — Nix installation
- [CLAUDE.md](CLAUDE.md) — Development & testing

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

Tools are organized into 9 consolidated tools. Related operations share a single tool name and are dispatched by an `action` parameter.

---

### `ssh_exec`
**Run a command on a remote server and wait for output.**

Non-interactive; returns stdout + stderr + exit code in one call.
Pass `timeout=None` to wait indefinitely (logs a warning).

**When to use:**
- Quick remote commands (`ls`, `df`, `uname`)
- Scripted operations that need immediate feedback

**Audit entry:**
```json
{
  "tool": "ssh_exec",
  "server": "webserver",
  "command": "df -h",
  "outcome": "completed",
  "detail": { "exit_code": 0 }
}
```

---

### `ssh_process`
**Background process lifecycle (nohup-backed).**

| action | Required params | Returns |
|---|---|---|
| `start` | `server`, `command` | `{process_id, server, command}` |
| `read` | `process_id` | `{output, next_offset, running, exit_code, remote_pid, server}` |
| `write` | `process_id`, `data` | always an error — nohup has no stdin |
| `kill` | `process_id` | `{killed, signal}` |
| `list` | — | `{processes: [...]}` |
| `check` | `process_id` | `{output, running, exit_code, remote_pid, server}` |

Pass `offset=next_offset` from a previous `read` to stream output incrementally.
Allowed signals for `kill`: `SIGTERM SIGKILL SIGINT SIGHUP SIGQUIT SIGUSR1 SIGUSR2`.

**When to use:**
- Build/compile operations, database migrations, long-running scripts
- Anything that doesn't need interactive input

**Audit entry (start):**
```json
{
  "tool": "ssh_exec_stream",
  "server": "buildserver",
  "command": "make release",
  "process_id": "proc-abc123",
  "outcome": "success",
  "detail": {
    "remote_pid": 12345,
    "log_file": "/tmp/mcp-ssh-logs/proc-abc123.log"
  }
}
```

---

### `ssh_pty`
**Interactive PTY session lifecycle.**

| action | Required params | Notes |
|---|---|---|
| `start` | `server` | `command`, `cols`, `rows`, `use_tmux` optional |
| `read` | `session_id` | `max_bytes` optional |
| `write` | `session_id`, `data` | Use `\r` not `\n` to submit a line |
| `resize` | `session_id`, `cols`, `rows` | Redraw full-screen TUIs after resize |
| `close` | `session_id` | Cleans up local channel; tmux window stays alive on remote |
| `attach` | `session_id` | tmux-backed sessions only |

With `use_tmux=True` the session survives MCP reconnects — resume with `attach`.

**When to use:**
- Interactive shells, vim, htop
- Commands that require a TTY (`sudo`, `expect`)
- Persistent sessions across API calls

**Audit entry (start):**
```json
{
  "tool": "ssh_start_pty",
  "server": "devbox",
  "command": "/bin/bash",
  "session_id": "pty-xyz789",
  "outcome": "started",
  "detail": { "use_tmux": true, "cols": 220, "rows": 50 }
}
```

---

### `ssh_files`
**File transfer between local and remote servers.**

| action | Required params | Notes |
|---|---|---|
| `get` | `server`, `remote_path`, `local_path` | SCP download |
| `put` | `server`, `local_path`, `remote_path` | SCP upload |
| `transfer` | `src_server`, `src_path`, `dst_server`, `dst_path` | Server-to-server via memory; same-server uses `cp` |
| `sync` | `src_server`, `src_path`, `dst_server`, `dst_path` | Copies only changed files; `src_path` may be a glob |

All actions accept `recurse` and `preserve`. `sync` also accepts `delete=True`
to remove destination files absent from the source.
Cross-server `sync` uses SFTP diff — no rsync dependency (works against Windows).

**Audit entry (sync):**
```json
{
  "tool": "ssh_sync",
  "server": "db-primary",
  "outcome": "ok",
  "detail": { "copied": 3, "skipped": 41, "deleted": 0 }
}
```

---

### `ssh_jump`
**Spontaneous multi-hop SSH jump chains.**

| action | Required params | Notes |
|---|---|---|
| `setup` | `name` + `chain` or `target` | Manual or auto-pathfound |
| `teardown` | `name` | Removes alias + all hop entries |

**Manual** (`chain=[server1, server2, ...]`): reuses each server's registered
credentials; `chain[0]` is the first hop, `chain[-1]` the final target exposed
as `name`. Append `@host` or `@host:port` to override a hop's dial address.

**Auto** (`target=<server>`): pathfinds over the cached reachability matrix
from `ssh_scan_topology`. Pass `max_age` to reject a stale cache or
`force_rescan=True` to scan fresh first. Verifies with a real connect and
tears down on failure.

Ephemeral by default; `persist=True` writes to `servers.toml`. Use `name`
with any SSH tool after setup.

**Audit entry (setup):**
```json
{
  "tool": "setup_jump",
  "server": "winali",
  "outcome": "created",
  "detail": {
    "persist": false,
    "hops": ["jumpuser@alibaba.example.com:22", "admin@11.11.0.4:22"]
  }
}
```

---

### `ssh_discover`
**Recursive SSH host auto-discovery.**

| action | Required params | Notes |
|---|---|---|
| `start` | — | `seeds`, `keys`, options optional |
| `teardown` | `session` | Removes all hosts registered by that session |

Starting from a seed frontier (default: local + connected servers), harvests
each host's `known_hosts`, ARP cache, ssh config, and shell history for
candidate neighbors, probes them with the supplied `keys`, and auto-registers
every confirmed host as an ephemeral server reachable through its discoverer.
Inherently TOFU. Set `harvest_keys=True` to fold in unencrypted keys found on
hosts (encrypted keys are reported, not used). Bounded by `max_depth`,
`max_nodes`, `timeout`, and `concurrency`.

**When to use:**
- Map and register an entire fleet sharing one SSH key
- Onboard freshly-provisioned cloud servers without knowing their addresses

**Audit entry (start):**
```json
{
  "tool": "ssh_discover",
  "outcome": "success",
  "detail": { "session": "disc-7f3a1c", "discovered": 5, "truncated": false }
}
```

---

### `ssh_known_host`
**Known-host key management.**

| action | Required params | Notes |
|---|---|---|
| `add` | `name` | Connects, captures key, appends to `known_hosts_file` |
| `show` | `name` | Returns algorithm + fingerprint of stored key. Read-only. |

Use `add` to pre-populate `known_hosts` for `strict` policy without an
out-of-band `ssh-keyscan`, or to pin a key the first time under TOFU.

**Audit entry (add):**
```json
{
  "tool": "ssh_add_known_host",
  "server": "prod-db",
  "outcome": "key_recorded",
  "detail": { "host": "db.prod.example.com", "already_present": false }
}
```

---

### `ssh_server`
**Server registry management.**

| action | Required params | Notes |
|---|---|---|
| `list` | — | Returns compact plain-text table. Not audited. |
| `register` | `name`, `host`, `user`, `auth_type` | Adds server dynamically without editing `servers.toml` |
| `deregister` | `name` | Removes config; non-fatal `warning` if active sessions exist |

`auth_type`: `agent` `key` `password` `cert` `sk` `keyboard_interactive` `gssapi`.
`key_path` required for `key`; `password_env` required for `password`.

**Audit entry (register):**
```json
{
  "tool": "ssh_register_server",
  "server": "newhost",
  "outcome": "success",
  "detail": { "host": "192.0.2.50", "user": "alice", "auth_type": "key" }
}
```

---

### `ssh_scan_topology`
**Probe server-to-server reachability and cache the N×N matrix.**

For every ordered pair of registered servers (plus a synthetic `local` source),
opens a direct-tcpip channel from the source to each target's candidate
addresses (registered host + harvested interface IPs) from the source's own
network vantage. The cached result feeds `ssh_jump(action="setup", target=...)`
pathfinding. Use `include`/`exclude` to bound which servers are scanned.

**When to use:**
- Refresh the reachability picture before an auto-chained `ssh_jump`
- Discover vantage-specific addresses only visible from a particular hop

**Audit entry:**
```json
{
  "tool": "ssh_scan_topology",
  "outcome": "scanned",
  "detail": { "nodes": 6, "edges": 14 }
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
// Step 1: Check if server is up  →  ssh_exec
{"ts": "2026-04-11T10:00:00Z", "tool": "ssh_exec", "server": "prod", "command": "echo ok", "outcome": "completed", "detail": {"exit_code": 0}}

// Step 2: Upload new artifact  →  ssh_files(action="put")
{"ts": "2026-04-11T10:00:05Z", "tool": "ssh_put", "server": "prod", "outcome": "ok", "detail": {"remote_path": "/opt/app/v1.2.3.tar.gz", "bytes_transferred": 50000000}}

// Step 3: Extract and deploy (background)  →  ssh_process(action="start")
{"ts": "2026-04-11T10:00:10Z", "tool": "ssh_exec_stream", "server": "prod", "command": "cd /opt/app && tar xzf v1.2.3.tar.gz && ./deploy.sh", "process_id": "proc-abc123", "outcome": "success"}

// Step 4: Poll for completion  →  ssh_process(action="check")
{"ts": "2026-04-11T10:05:00Z", "tool": "ssh_check_process", "process_id": "proc-abc123", "outcome": "success", "detail": {"status": "exited", "exit_code": 0}}

// Step 5: Verify (interactive)  →  ssh_pty(action=start/write/read/close)
{"ts": "2026-04-11T10:05:05Z", "tool": "ssh_start_pty", "server": "prod", "session_id": "pty-xyz789", "outcome": "started"}
{"ts": "2026-04-11T10:05:10Z", "tool": "ssh_pty_write", "session_id": "pty-xyz789", "outcome": "success"}
{"ts": "2026-04-11T10:05:15Z", "tool": "ssh_pty_read", "session_id": "pty-xyz789", "outcome": "success"}
{"ts": "2026-04-11T10:05:20Z", "tool": "ssh_pty_close", "session_id": "pty-xyz789", "outcome": "closed"}
```

---

## Further Reading

- [README.md](README.md) — Feature overview
- [INSTALL.md](INSTALL.md) — Installation & setup
- [INSTALL-NIX.md](INSTALL-NIX.md) — Nix installation
- [CLAUDE.md](CLAUDE.md) — Development & testing

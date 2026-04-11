# Operational Notes

## Temp file lifecycle (`/tmp/mcp-*.log` and `/tmp/mcp-*.exit`)

Background processes launched via `ssh_exec_stream` create two files on the
**remote host**:

| Pattern | Purpose |
|---|---|
| `/tmp/mcp-{uuid}.log` | stdout+stderr of the nohup process |
| `/tmp/mcp-{uuid}.exit` | exit code written by the shell wrapper |

PTY sessions using tmux pipe-pane create:

| Pattern | Purpose |
|---|---|
| `/tmp/mcp-pty-{uuid}.log` | captured PTY output (remote host) |

### Cleanup strategy

1. **On `ssh_check_process`**: when a process is found to have exited, the
   caller should use `ssh_exec` to remove the files:
   ```
   rm -f /tmp/mcp-{uuid}.log /tmp/mcp-{uuid}.exit
   ```
   (mcp-ssh intentionally does not auto-delete on check — the files stay readable
   until the LLM no longer needs them.)

2. **Periodic remote cleanup**: add a cron job on the remote host to purge stale
   files older than N hours:
   ```cron
   0 * * * *  find /tmp -name 'mcp-*.log' -o -name 'mcp-*.exit' -mtime +1 -delete
   ```

3. **Session end**: `ssh_pty_close` cleans up the local asyncssh channel and drain
   task. The remote `/tmp/mcp-pty-*.log` file is **not** removed automatically
   (same rationale as above). Add it to the remote cron if desired.

---

## Audit log rotation (`audit.jsonl`)

The audit log is a newline-delimited JSON file at the path configured in
`settings.audit_log` (default `~/.config/mcp-ssh/audit.jsonl`).

### Recommended rotation strategies

**`logrotate` (recommended for system installs):**

```
/home/<user>/.config/mcp-ssh/audit.jsonl {
    daily
    rotate 30
    compress
    missingok
    notifempty
    copytruncate   # safe: AuditLog holds an open append-mode file handle
}
```

`copytruncate` is required because `AuditLog` keeps the file open. It copies
the current log then truncates in place, so no SIGHUP/restart of the MCP
process is needed.

**`journald` integration (optional):**

Set `audit_log` to `/dev/stderr` and redirect stderr to journald when
launching the server. Example systemd unit fragment:

```ini
[Service]
StandardError=journal
Environment=MCP_SSH_AUDIT_LOG=/dev/stderr
```

Note: journald truncates very long lines; structured JSONL fields may be split.
Prefer `logrotate` for compliance use cases where full record fidelity matters.

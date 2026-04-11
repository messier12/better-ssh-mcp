# mcp-ssh — Design Document

## Resolved open questions

### Host key verification
**TOFU (Trust On First Use), strict thereafter.**

On first connection, accept and persist the host fingerprint to a dedicated file
(`~/.local/share/mcp-ssh/known_hosts`). Every subsequent connection verifies
strictly against it. A per-server `host_key_policy` field overrides the global:
`tofu` | `strict` | `accept_new` (always accept — only for ephemeral/trusted infra).
No global `accept_all` default. A `ssh_add_known_host` tool handles explicit
pre-registration before switching a server to `strict`.

### Credentials and passphrase storage
**ssh-agent as the primary path. Env var references for everything else.
No secrets ever written to config files.**

- `auth_type = "agent"` — delegate to a running `ssh-agent` or `gpg-agent`.
- `auth_type = "key"` — key loaded from `key_path`. If the key is encrypted,
  asyncssh tries the agent for the passphrase first; if not available, the
  connection fails with a clear message directing the user to `ssh-add`.
- `auth_type = "password"` — `password_env = "MY_VAR"` is read from the
  environment at connect time. Never stored on disk.
- `auth_type = "cert"` — certificate + key; both paths in config.
- `auth_type = "sk"` — FIDO2 hardware key; requires `libfido2` at runtime
  (see Packaging). asyncssh 2.14+ supports sk keys natively.
- `auth_type = "keyboard_interactive"` — for PAM/2FA challenges. asyncssh
  handles the prompt/response exchange; responses come from a configurable
  env var list.
- `auth_type = "gssapi"` — Kerberos; asyncssh + system GSSAPI library.

Config files are safe to version-control: they contain key paths and env var
names, not secrets.

### Output encoding
**UTF-8 with replacement characters by default.** Every exec and pty-read tool
accepts an optional `encoding` parameter: `"utf-8"` (default), `"utf-8-replace"`,
or `"bytes"` (base64-encodes the raw output). Covers the vast majority of cases
without surprising the caller.

### Environment variables and working directory
**First-class parameters on every exec tool.** Too commonly needed to omit.
Per-server registry defaults (`default_cwd`, `default_env`) apply when not
overridden per-call.

### Connection error handling
**Eager reconnect on next tool call; structured error on failure.**

The pool maintains one persistent `asyncssh.SSHClientConnection` per server.
On connection loss the entry is marked `disconnected`. The next tool call
targeting that server triggers a reconnect attempt (configurable timeout,
default 15 s). If the reconnect fails, the tool returns a structured error
object — not an exception — with server name, last-seen timestamp, and error
message. The AI gets actionable information.

### Max concurrent sessions
**Global default: 10 sessions. Per-server override in config.**

---

## Full desiderata

### Core (original)
1. Register and deregister SSH servers by name without modifying the MCP
   server registration.
2. Support all OpenSSH authentication methods including FIDO2/sk keys,
   certificates, keyboard-interactive, and GSSAPI.
3. AI accesses servers by registered name. A `list_servers` tool is provided.
4. Long-running commands stream output (polling model, compatible with stdio
   transport).
5. Interactive PTY sessions: start, write, read, resize, close.

### Additions
6. **ProxyJump / bastion host chains.** A server entry may reference another
   registered server as its `jump_host`. Chains (A → B → C) are supported.
   asyncssh resolves the chain and handles the tunnel natively.

7. **Session persistence across MCP server restarts.** Processes launched via
   `ssh_exec_stream` use `nohup` on the remote and are tracked by remote PID
   + log file path. The local state file survives MCP server restarts.
   On reconnect, `ssh_list_processes` surfaces all previously known processes
   with their last-known status. `ssh_check_process` re-queries the remote to
   get the current alive/exited state and tail of output.

8. **Reconnectable PTY sessions (tmux-backed).** `ssh_start_pty` accepts
   `use_tmux=True`. When set, the session lives inside a named tmux window
   (`mcp-{id}`) on the remote and survives SSH disconnection. `ssh_pty_attach`
   reattaches to the window. Falls back to an ephemeral PTY with a warning if
   tmux is not installed on the remote.

9. **Audit log.** Every tool call that executes a command, writes to stdin, or
   kills a process is appended to a JSONL file. Each record contains:
   timestamp, server, tool, command, process_id, outcome. Append-only; the
   MCP server never truncates it. Location:
   `~/.local/share/mcp-ssh/audit.jsonl`.

10. **Persistent session state file.** A JSON file at
    `~/.local/share/mcp-ssh/state.json` tracks all known processes and PTY
    sessions: remote PID, log path, server, command, exit code (if known),
    started_at, last_checked. Written atomically (write to `.tmp`, rename).
    XDG-compliant; overridable via `MCP_SSH_DATA_DIR` env var.

11. **Per-server environment defaults.** Registry entries may specify
    `default_env` (dict) and `default_cwd` (string), applied to all exec calls
    on that server unless overridden at call time.

12. **Connection keepalive.** `keepalive_interval` and `keepalive_count_max`
    prevent idle connections from being silently dropped by NAT/firewalls.
    Configured globally with per-server override.

13. **Host key management tools.** `ssh_add_known_host(name)` connects once
    and records the fingerprint. `ssh_show_known_host(name)` displays it for
    verification.

14. **Output encoding control.** Default UTF-8 with replacement. `encoding=
    "bytes"` returns base64 for binary output.

15. **Session cap.** Global `max_sessions = 10`; per-server override. Exec
    and PTY tools return a structured error (not an exception) when the cap
    is hit.

16. **NixOS flake + Debian packaging.** `flake.nix` provides a package, a
    NixOS module, and a home-manager module. `pyproject.toml` supports
    `pip install` / `uv tool install` on Debian. `libfido2` declared as a
    runtime dependency for sk-key support.

17. **Config hot-reload.** The registry file is watched with `watchfiles`.
    Adding or removing a server takes effect without restarting the MCP
    process. Active sessions on deregistered servers are not forcibly
    terminated; new sessions on them are rejected with a clear error.

18. **SFTP file transfer (v2).** `ssh_upload` and `ssh_download` are out of
    scope for v1 but the registry schema is forward-compatible (no breaking
    changes needed to add them).

---

## Architecture

### Package layout

```
mcp-ssh/
├── flake.nix
├── pyproject.toml
├── mcp_ssh/
│   ├── __init__.py
│   ├── server.py          # MCP entrypoint (stdio), tool registration
│   ├── config.py          # Pydantic models for TOML schema
│   ├── registry.py        # Load, watch, runtime CRUD
│   ├── pool.py            # asyncssh connection pool, jump-host resolution
│   ├── session.py         # ProcessSession + PtySession, ring buffers
│   ├── state.py           # state.json read/write (atomic)
│   ├── audit.py           # JSONL audit writer
│   └── tools/
│       ├── registry_tools.py   # list/register/deregister/known_host
│       ├── exec_tools.py       # exec, exec_stream, read/write/kill/list/check
│       └── pty_tools.py        # start, read, write, resize, close, attach
```

### Runtime components

**Registry** — Pydantic `ServerConfig` models loaded from TOML. `watchfiles.
awatch` monitors the config file and triggers incremental reload.

**Connection pool** — one persistent `asyncssh.SSHClientConnection` per
registered server. ProxyJump is resolved recursively: the jump server's entry
is looked up, its connection is obtained first, and passed as `tunnel=` to the
target connection. Keepalive is configured per asyncssh's native options.
Connection state: `connected | disconnected | connecting`.

**Session manager** — in-memory dict mapping `process_id` / `session_id` to
`ProcessSession` or `PtySession` objects. Each holds an asyncio background
task draining remote output into a `collections.deque` ring buffer (max size
configurable, default 1 MB). Every status change flushes to `state.json`.

**State file** — plain JSON, written atomically. Read on startup; processes
load in `unknown` status until `ssh_check_process` is called.

**Audit log** — append-only JSONL, one record per mutating tool call.
Never touched by the server after writing. Log rotation is the user's
responsibility (logrotate on Debian, systemd timer / log rotation service
on NixOS).

---

## Config schema (TOML)

```toml
# Default location: ~/.config/mcp-ssh/servers.toml
# Override: MCP_SSH_CONFIG=/path/to/servers.toml

[settings]
known_hosts_file     = "~/.local/share/mcp-ssh/known_hosts"
default_host_key_policy = "tofu"   # tofu | strict | accept_new
audit_log            = "~/.local/share/mcp-ssh/audit.jsonl"
state_file           = "~/.local/share/mcp-ssh/state.json"
max_sessions         = 10
keepalive_interval   = 30          # seconds
keepalive_count_max  = 5
connect_timeout      = 15          # seconds
default_encoding     = "utf-8"

# --- server examples ---

[servers.prod-web]
host             = "10.0.1.5"
port             = 22
user             = "deploy"
auth_type        = "agent"
host_key_policy  = "strict"        # override global
default_cwd      = "/srv/app"
default_env      = { APP_ENV = "production" }
max_sessions     = 3

[servers.dev-box]
host      = "dev.internal"
user      = "alice"
auth_type = "key"
key_path  = "~/.ssh/id_ed25519"
# Encrypted key: add to agent with ssh-add; no passphrase in config.

[servers.sk-server]
host      = "secure.internal"
user      = "ops"
auth_type = "key"
key_path  = "~/.ssh/id_ecdsa_sk"   # FIDO2 hardware key; needs libfido2

[servers.cert-server]
host      = "cert.internal"
user      = "alice"
auth_type = "cert"
key_path  = "~/.ssh/id_ed25519"
cert_path = "~/.ssh/id_ed25519-cert.pub"

[servers.password-legacy]
host         = "legacy.internal"
user         = "admin"
auth_type    = "password"
password_env = "LEGACY_SERVER_PASS"  # read from environment at connect time

[servers.2fa-server]
host      = "mfa.internal"
user      = "alice"
auth_type = "keyboard_interactive"
# Responses come from env vars: MCP_SSH_KI_RESPONSE_1, _2, ...

[servers.bastion]
host      = "bastion.example.com"
user      = "jump"
auth_type = "agent"
port      = 22

[servers.app-prod]
host      = "app.internal"
user      = "deploy"
auth_type = "agent"
jump_host = "bastion"              # resolved to the [servers.bastion] entry

[servers.deep-internal]
host      = "deep.app.internal"
user      = "admin"
auth_type = "key"
key_path  = "~/.ssh/id_ed25519"
jump_host = "app-prod"             # chain: deep → app-prod → bastion
```

---

## MCP tool API

### Registry tools

**`ssh_list_servers()`**
Returns all registered servers: name, host, user, auth_type, jump_host (if
any), connection status (`connected | disconnected | unknown`), active session
count.

**`ssh_register_server(name, host, user, auth_type, port?, key_path?,
cert_path?, password_env?, jump_host?, host_key_policy?, default_cwd?,
default_env?, max_sessions?)`**
Adds a new entry and writes to the config file. Returns the validated entry.
Triggers a hot-reload so the entry is immediately usable.

**`ssh_deregister_server(name)`**
Removes the entry. Returns a warning if active sessions exist on that server
(they are not forcibly terminated).

**`ssh_add_known_host(name)`**
Connects using the current auth config, captures the host key, appends to
`known_hosts_file`. Call once before using a new server with `strict` policy.

**`ssh_show_known_host(name)`**
Returns the stored fingerprint for a server. Useful for manual verification.

### Exec tools

**`ssh_exec(server, command, cwd?, env?, timeout?, encoding?)`**
Blocking execute. Waits for exit (default timeout: 30 s; `null` = no limit).
Returns `{stdout, stderr, exit_code}`. Use for short commands only.

**`ssh_exec_stream(server, command, cwd?, env?, encoding?)`**
Launches a long-running non-interactive process using `nohup` with stdout/
stderr redirected to a temp file on the remote (`/tmp/mcp-{id}.log`). Captures
the remote PID via `echo $!`. Returns a `process_id`. The remote process
survives SSH disconnection.

```
# What runs on the remote:
nohup bash -c 'cd {cwd} && {env_exports} {command} \
  > /tmp/mcp-{id}.log 2>&1; \
  echo $? > /tmp/mcp-{id}.exit' &
echo $!
```

**`ssh_read_process(process_id, max_bytes?, offset?)`**
Reads from the remote log file via SSH (`tail -c` or a byte-range read).
Returns `{output, running, exit_code?, remote_pid, server}`. `running=false`
+ `exit_code` means the process has terminated (exit file exists).

**`ssh_write_process(process_id, input)`**
Writes to the process's stdin. Only valid when the process was launched without
`nohup` (stdin still attached). Returns an error for nohup processes.

**`ssh_kill_process(process_id, signal?)`**
Sends `kill -{signal} {remote_pid}` on the remote. Default: `SIGTERM`. Updates
the state file.

**`ssh_list_processes(server?)`**
Lists all known processes from the state file (optionally filtered by server).
Fields: `process_id`, `server`, `command`, `remote_pid`, `status`
(`running | exited | unknown`), `started_at`, `last_checked`.

**`ssh_check_process(process_id)`**
Re-queries the remote: runs `kill -0 {pid}` to check liveness; reads the tail
of the log file; reads the exit file if present. Updates `state.json`.
Returns current status and recent output. The correct tool to call after a
reconnect to reconcile state.

### PTY tools

**`ssh_start_pty(server, command?, cols?, rows?, use_tmux?)`**
Opens a PTY session. `command` defaults to the user's login shell if omitted.
If `use_tmux=True`, the session is created inside a named tmux window
(`mcp-{id}`) on the remote. Returns `{session_id, use_tmux}`.

**`ssh_pty_read(session_id, max_bytes?)`**
Reads from the local ring buffer. Returns `{output, alive}`. Output is decoded
per the server's configured `default_encoding`. Poll in a loop with a short
sleep between calls (suggest ~0.5–1 s intervals).

**`ssh_pty_write(session_id, input)`**
Sends raw bytes to the PTY. Note: terminals expect `\r` (CR), not `\n` (LF),
to submit a command line. Control characters (Ctrl-C = `\x03`, Ctrl-D = `\x04`,
Ctrl-Z = `\x1a`) are passed through as-is.

**`ssh_pty_resize(session_id, cols, rows)`**
Sends a terminal resize event (SIGWINCH). Needed for programs like vim, htop,
and tmux to re-render correctly.

**`ssh_pty_close(session_id)`**
Closes the local PTY channel and SSH connection for this session. The remote
process receives SIGHUP unless it is tmux-backed (in which case the tmux
session continues running).

**`ssh_pty_attach(session_id)`**
Re-attaches to a previously detached tmux-backed PTY session. Returns an error
if the session was not created with `use_tmux=True` or if the tmux window no
longer exists on the remote.

---

## Session persistence model

### Non-interactive processes (`ssh_exec_stream`)

```
LAUNCH
  AI: ssh_exec_stream("prod-web", "make deploy")
    ├─ pool opens SSH channel to prod-web
    ├─ runs: nohup bash -c 'make deploy > /tmp/mcp-abc.log 2>&1;
    │         echo $? > /tmp/mcp-abc.exit' & echo $!
    ├─ captures remote PID: 9182
    ├─ state.json ← {id: abc, server: prod-web, pid: 9182,
    │               log: /tmp/mcp-abc.log, status: running, ...}
    └─ returns: {process_id: "abc"}

POLL
  AI: ssh_exec_stream("abc") — no, ssh_read_process("abc")
    ├─ SSH: tail -c 4096 /tmp/mcp-abc.log   → returns output
    ├─ SSH: test -f /tmp/mcp-abc.exit        → not yet
    └─ returns: {output: "...", running: true}

DISCONNECT (MCP server process exits, stdio pipe breaks)
  → asyncssh connections close
  → state.json persists on disk with status: running (last known)
  → nohup process continues on remote, log file grows

RECONNECT (new MCP server process starts)
  → state.json loaded; "abc" appears as status: unknown
  AI: ssh_list_processes() → sees "abc" with status: unknown
  AI: ssh_check_process("abc")
    ├─ SSH: kill -0 9182           → process alive? yes/no
    ├─ SSH: tail -c 4096 /tmp/mcp-abc.log  → latest output
    ├─ SSH: cat /tmp/mcp-abc.exit  → exit code if done
    ├─ state.json updated
    └─ returns: {running: true/false, exit_code?, recent_output}

  AI decides: kill, keep tailing, or mark as done and clean up
  AI: ssh_kill_process("abc")     ← optional
    └─ SSH: kill -15 9182
       state.json ← status: killed
```

### Interactive sessions (`ssh_start_pty` with `use_tmux=True`)

```
LAUNCH
  AI: ssh_start_pty("prod-web", "vim app.py", use_tmux=True)
    ├─ SSH: tmux new-session -d -s mcp-xyz 'vim app.py'
    ├─ SSH: tmux attach-session -t mcp-xyz  (second channel, PTY)
    ├─ state.json ← {id: xyz, type: pty, tmux: true, window: mcp-xyz, ...}
    └─ returns: {session_id: "xyz", use_tmux: true}

INTERACT
  AI: ssh_pty_read("xyz")   → buffered terminal output
  AI: ssh_pty_write("xyz", ":wq\r")  → save and quit vim

DISCONNECT
  → PTY channel closes; tmux session survives on remote

RECONNECT
  AI: ssh_list_processes()   → sees "xyz" with status: unknown (pty)
  AI: ssh_pty_attach("xyz")
    ├─ SSH: tmux has-session -t mcp-xyz  → exists?
    ├─ SSH: tmux attach-session -t mcp-xyz
    └─ PTY interaction resumes
```

### State file shape

```json
{
  "schema_version": 1,
  "processes": {
    "abc": {
      "type": "exec",
      "server": "prod-web",
      "command": "make deploy",
      "remote_pid": 9182,
      "log_file": "/tmp/mcp-abc.log",
      "exit_file": "/tmp/mcp-abc.exit",
      "started_at": "2026-04-11T08:00:00Z",
      "last_checked": "2026-04-11T08:05:00Z",
      "status": "running",
      "exit_code": null
    },
    "xyz": {
      "type": "pty",
      "server": "prod-web",
      "command": "vim app.py",
      "use_tmux": true,
      "tmux_window": "mcp-xyz",
      "started_at": "2026-04-11T09:00:00Z",
      "last_checked": "2026-04-11T09:10:00Z",
      "status": "unknown"
    }
  }
}
```

### Audit log shape (JSONL)

```jsonl
{"ts":"2026-04-11T08:00:00Z","tool":"ssh_exec_stream","server":"prod-web","command":"make deploy","process_id":"abc","outcome":"started","remote_pid":9182}
{"ts":"2026-04-11T08:05:00Z","tool":"ssh_read_process","process_id":"abc","outcome":"ok","running":true}
{"ts":"2026-04-11T09:00:00Z","tool":"ssh_start_pty","server":"prod-web","command":"vim app.py","session_id":"xyz","outcome":"started"}
{"ts":"2026-04-11T09:10:00Z","tool":"ssh_kill_process","process_id":"abc","signal":"SIGTERM","outcome":"sent"}
```

---

## Packaging

### pyproject.toml (Debian / pip / uv)

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "mcp-ssh"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
    "mcp>=1.0",
    "asyncssh>=2.14",      # 2.14+ for FIDO2/sk native support
    "pydantic>=2.0",
    "watchfiles>=0.21",
]

[project.scripts]
mcp-ssh = "mcp_ssh.server:main"

[project.optional-dependencies]
# sk keys also need: apt install libfido2-1
fido2 = ["fido2>=1.0"]
```

**Debian install:**
```bash
# uv (recommended)
uv tool install mcp-ssh

# or pip
pip install mcp-ssh

# sk / FIDO2 key support needs the system library:
sudo apt install libfido2-1
```

### flake.nix (NixOS)

```nix
{
  description = "MCP SSH server";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
  let
    forAllSystems = nixpkgs.lib.genAttrs
      [ "x86_64-linux" "aarch64-linux" ];
  in {
    packages = forAllSystems (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.python3Packages.buildPythonApplication {
        pname   = "mcp-ssh";
        version = "0.1.0";
        pyproject = true;
        src = ./.;
        build-system = [ pkgs.python3Packages.hatchling ];
        dependencies = with pkgs.python3Packages; [
          mcp
          asyncssh
          pydantic
          watchfiles
        ];
        # libfido2 for sk-key / FIDO2 hardware key support
        buildInputs = [ pkgs.libfido2 ];
      };
    });

    # NixOS module (system-level, if desired)
    nixosModules.default = { config, lib, pkgs, ... }: {
      options.programs.mcp-ssh.enable =
        lib.mkEnableOption "MCP SSH server";
      config = lib.mkIf config.programs.mcp-ssh.enable {
        environment.systemPackages =
          [ self.packages.${pkgs.system}.default ];
      };
    };

    # home-manager module (per-user, recommended)
    homeManagerModules.default = { config, lib, pkgs, ... }: {
      options.programs.mcp-ssh = {
        enable = lib.mkEnableOption "MCP SSH server";
        configFile = lib.mkOption {
          type    = lib.types.path;
          default =
            "${config.xdg.configHome}/mcp-ssh/servers.toml";
          description = "Path to servers.toml";
        };
      };
      config = lib.mkIf config.programs.mcp-ssh.enable {
        home.packages = [ self.packages.${pkgs.system}.default ];
        xdg.configFile."mcp-ssh/servers.toml" =
          lib.mkIf (config.programs.mcp-ssh.configFile
            != "${config.xdg.configHome}/mcp-ssh/servers.toml") {
          source = config.programs.mcp-ssh.configFile;
        };
      };
    };
  };
}
```

### Claude Desktop config (both platforms)

```json
{
  "mcpServers": {
    "ssh": {
      "command": "mcp-ssh",
      "args": [],
      "env": {
        "MCP_SSH_CONFIG": "/home/alice/.config/mcp-ssh/servers.toml",
        "LEGACY_SERVER_PASS": "...",
        "MCP_SSH_KI_RESPONSE_1": "..."
      }
    }
  }
}
```

On NixOS, `command` should be the full store path if `mcp-ssh` is not in the
default shell PATH used by the desktop session, e.g.:
`"/etc/profiles/per-user/alice/bin/mcp-ssh"`.

---

## Deferred to v2

- SFTP: `ssh_upload(server, local_path, remote_path)` and `ssh_download`.
  Registry schema is already forward-compatible.
- Port forwarding / tunnel management.
- Certificate authority integration (auto-renew short-lived certs).
- `ssh_clean_remote(process_id)` — remove `/tmp/mcp-{id}.*` files from the
  remote after a process is confirmed done.
- Web UI or TUI for audit log viewing and session monitoring.
- Multi-user / shared-daemon mode (single asyncssh daemon, multiple MCP
  stdio clients).
- `known_hosts` export/import for syncing across machines.
- Automatic remote temp-file cleanup policy (TTL-based, configurable).

---

## Key dependency versions

| Package | Min version | Why |
|---|---|---|
| Python | 3.11 | `tomllib` stdlib, `asyncio` improvements |
| asyncssh | 2.14 | Native FIDO2/sk-key support |
| pydantic | 2.0 | Config model validation |
| watchfiles | 0.21 | Cross-platform file watching (inotify on Linux) |
| mcp / fastmcp | 1.0 | MCP SDK |
| libfido2 (system) | 1.x | sk-key hardware authentication |
| tmux (remote, optional) | any | Reconnectable PTY sessions |

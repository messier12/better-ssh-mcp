# Installing better-ssh-mcp on Debian / Ubuntu

## 1. System dependencies

```bash
sudo apt update
sudo apt install python3 python3-pip
```

`libfido2` is **optional** — only required if you use hardware-backed SSH keys
(`sk-*` key types such as `sk-ecdsa-sha2-nistp256` or `sk-ssh-ed25519`):

```bash
# Optional — only needed for FIDO2 / security-key (sk) authentication
sudo apt install libfido2-1
```

## 2. Install better-ssh-mcp

### Recommended: uv tool (isolated, self-contained)

```bash
# Install uv if you don't already have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install better-ssh-mcp into an isolated tool environment
uv tool install better-ssh-mcp
```

### Alternative: pip

```bash
pip install --user better-ssh-mcp
```

Verify the installation:

```bash
better-ssh-mcp --version
```

## 3. Configuration file

Create the configuration directory and a `servers.toml` file:

```bash
mkdir -p ~/.config/better-ssh-mcp
```

**`~/.config/better-ssh-mcp/servers.toml`** — example with two servers:

```toml
[settings]
known_hosts_file       = "~/.local/share/better-ssh-mcp/known_hosts"
default_host_key_policy = "tofu"   # trust-on-first-use; use "strict" in production
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
auth_type = "agent"   # uses SSH agent forwarded from the local machine
```

Supported `auth_type` values: `agent`, `key`, `password`, `cert`, `sk`,
`keyboard_interactive`, `gssapi`.

The `password` auth type reads the password from an environment variable named
by `password_env` (e.g. `password_env = "MY_SERVER_PASS"`). The variable value
is never written to the audit log.

## 4. Claude Desktop integration

Add the following block to your Claude Desktop configuration file.

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

If you installed with `uv tool install`, the `better-ssh-mcp` binary is placed in
`~/.local/bin/` (added to `PATH` by the uv installer). If Claude Desktop cannot
find it, use the full path:

```json
{
  "mcpServers": {
    "better-ssh-mcp": {
      "command": "/home/YOUR_USER/.local/bin/better-ssh-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

Restart Claude Desktop after editing the config file.

## Upgrading

```bash
uv tool upgrade better-ssh-mcp
```

## Uninstalling

```bash
uv tool uninstall better-ssh-mcp
```

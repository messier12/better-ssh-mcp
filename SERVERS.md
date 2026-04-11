# Managing Multiple SSH Servers

This guide covers configuring, organizing, and managing multiple SSH servers with better-ssh-mcp.

## Table of Contents

1. [Configuration Basics](#configuration-basics)
2. [Server Organization](#server-organization)
3. [Jump Hosts (Bastion Hosts)](#jump-hosts-bastion-hosts)
4. [Global vs Server-Level Defaults](#global-vs-server-level-defaults)
5. [Dynamic Server Registration](#dynamic-server-registration)
6. [Common Patterns](#common-patterns)
7. [Credential Management](#credential-management)
8. [Best Practices](#best-practices)

---

## Configuration Basics

Server configuration lives in `servers.toml`. The file has two sections:

- `[settings]` — Global defaults applied to all servers
- `[servers.<name>]` — Individual server configurations

### Minimal Example

```toml
[settings]
default_host_key_policy = "tofu"
audit_log = "~/.local/share/better-ssh-mcp/audit.jsonl"

[servers.prod]
host = "api.example.com"
port = 22
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/prod_ed25519"

[servers.staging]
host = "staging.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/staging_ed25519"

[servers.dev]
host = "localhost"
port = 2222
user = "alice"
auth_type = "key"
key_path = "~/.ssh/id_ed25519"
```

### Server Configuration Fields

| Field | Required | Type | Default | Description |
|---|---|---|---|---|
| `name` | ✓ | string | — | Server identifier (from `[servers.name]`) |
| `host` | ✓ | string | — | Hostname or IP address |
| `port` | | int | 22 | SSH port |
| `user` | ✓ | string | — | SSH username |
| `auth_type` | ✓ | string | — | `agent`, `key`, `password`, `cert`, `sk`, `keyboard_interactive`, `gssapi` |
| `key_path` | | string | — | Path to private key (for `key` auth) |
| `cert_path` | | string | — | Path to certificate (for `cert` auth) |
| `password_env` | | string | — | Env var name containing password (for `password` auth) |
| `jump_host` | | string | — | Name of another server to use as bastion |
| `host_key_policy` | | string | — | `tofu`, `strict`, or `accept_new` (overrides global) |
| `default_cwd` | | string | — | Working directory when connected |
| `default_env` | | dict | `{}` | Environment variables to set on every command |
| `max_sessions` | | int | — | Max concurrent sessions (overrides global) |
| `keepalive_interval` | | int | — | Keepalive interval in seconds (overrides global) |

---

## Server Organization

### By Environment (Recommended)

Organize servers by deployment tier:

```toml
[settings]
default_host_key_policy = "tofu"

# Production
[servers.prod-api]
host = "api.prod.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/prod_ed25519"
host_key_policy = "strict"  # Strict verification for prod

[servers.prod-db]
host = "db.prod.example.com"
user = "dbadmin"
auth_type = "key"
key_path = "~/.ssh/prod_db_ed25519"
host_key_policy = "strict"

# Staging
[servers.staging-api]
host = "api.staging.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/staging_ed25519"

[servers.staging-db]
host = "db.staging.example.com"
user = "dbadmin"
auth_type = "key"
key_path = "~/.ssh/staging_db_ed25519"

# Development
[servers.dev-local]
host = "localhost"
port = 2222
user = "alice"
auth_type = "key"
key_path = "~/.ssh/id_ed25519"
default_cwd = "~/projects/myapp"
```

### By Service Role

```toml
[servers.webserver-1]
host = "web1.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/web_key"

[servers.webserver-2]
host = "web2.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/web_key"

[servers.cache-1]
host = "redis1.example.com"
user = "redis"
auth_type = "key"
key_path = "~/.ssh/cache_key"

[servers.database-primary]
host = "db-primary.example.com"
user = "postgres"
auth_type = "key"
key_path = "~/.ssh/db_key"
host_key_policy = "strict"

[servers.database-replica]
host = "db-replica.example.com"
user = "postgres"
auth_type = "key"
key_path = "~/.ssh/db_key"
host_key_policy = "strict"
```

### By Region

```toml
[servers.us-east-api]
host = "api.us-east.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/us_east_key"

[servers.us-west-api]
host = "api.us-west.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/us_west_key"

[servers.eu-api]
host = "api.eu.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/eu_key"
```

---

## Jump Hosts (Bastion Hosts)

Use jump hosts to route connections through a bastion/jump server. Useful when:
- Application servers are not directly accessible from the internet
- You must tunnel through a bastion host
- You want centralized SSH logging

### Configuration

```toml
[servers.bastion]
host = "bastion.example.com"
user = "jumpuser"
auth_type = "key"
key_path = "~/.ssh/bastion_key"

[servers.internal-api]
host = "api.internal"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/internal_key"
jump_host = "bastion"  # ← Route through bastion

[servers.internal-db]
host = "db.internal"
user = "postgres"
auth_type = "key"
key_path = "~/.ssh/internal_key"
jump_host = "bastion"
```

### How It Works

When you connect to `internal-api`:
1. better-ssh-mcp opens a connection to `bastion` first
2. Establishes a forwarded connection from bastion → `api.internal`
3. Authenticates on both hops
4. Returns a unified connection to the target

### Multi-Hop Chains

You can chain jump hosts (but watch for circular references):

```toml
[servers.external-bastion]
host = "jump1.example.com"
user = "jumpuser"
auth_type = "key"
key_path = "~/.ssh/key1"

[servers.internal-bastion]
host = "jump2.internal"
user = "jumpuser"
auth_type = "key"
key_path = "~/.ssh/key2"
jump_host = "external-bastion"  # 2-hop chain

[servers.deeply-internal]
host = "app.private"
user = "appuser"
auth_type = "key"
key_path = "~/.ssh/key3"
jump_host = "internal-bastion"  # 3-hop chain: external → internal → app
```

**Note:** Circular jump-host chains are detected and rejected at config load time.

---

## Global vs Server-Level Defaults

### Global Settings

Apply to all servers unless overridden:

```toml
[settings]
known_hosts_file       = "~/.local/share/better-ssh-mcp/known_hosts"
default_host_key_policy = "tofu"      # Applied to all servers
audit_log              = "~/.local/share/better-ssh-mcp/audit.jsonl"
state_file             = "~/.local/share/better-ssh-mcp/state.json"
max_sessions           = 10            # Default max sessions per server
keepalive_interval     = 30            # Default keepalive
connect_timeout        = 15            # Connection timeout
```

### Server-Level Overrides

Override specific settings for a server:

```toml
[settings]
default_host_key_policy = "tofu"
max_sessions = 10

[servers.prod]
host = "prod.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/prod_key"
host_key_policy = "strict"     # ← Override: stricter for prod
max_sessions = 5               # ← Override: fewer concurrent sessions

[servers.dev]
host = "dev.example.com"
user = "alice"
auth_type = "key"
key_path = "~/.ssh/dev_key"
# Uses global defaults (tofu policy, max_sessions=10)
```

### Server Environment Variables

Set environment variables for every command on a server:

```toml
[servers.prod-api]
host = "api.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/prod_key"
default_env = {
    APP_ENV = "production",
    LOG_LEVEL = "info"
}

[servers.staging-api]
host = "staging.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/staging_key"
default_env = {
    APP_ENV = "staging",
    LOG_LEVEL = "debug"
}
```

When you execute `ssh_exec` on `staging-api`, the command runs with `APP_ENV=staging LOG_LEVEL=debug`.

---

## Dynamic Server Registration

In addition to `servers.toml`, you can register servers programmatically using `ssh_register_server`.

### Use Cases

- Add servers at runtime without editing config files
- Create temporary server entries for testing
- Programmatic server discovery (from inventory systems, APIs, etc.)

### Syntax

```python
# Register a server dynamically
ssh_register_server(
    name="temp-test-server",
    host="192.0.2.100",
    port=22,
    user="testuser",
    auth_type="key",
    key_path="~/.ssh/test_key",
    host_key_policy="accept_new"
)
```

### Audit Trail

Each registration is audited:

```json
{
  "ts": "2026-04-11T14:00:00Z",
  "tool": "ssh_register_server",
  "server": "temp-test-server",
  "outcome": "success",
  "detail": {
    "host": "192.0.2.100",
    "user": "testuser",
    "auth_type": "key"
  }
}
```

### Priority

Dynamically registered servers have the same priority as `servers.toml` entries. If you register a server with the same name as one in the config file, the runtime registration takes precedence for that session.

---

## Common Patterns

### Pattern 1: Production → Staging → Development Symmetry

Mirror production setup in staging and dev to catch environment issues early:

```toml
[servers.prod-api]
host = "api.prod.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/prod_key"
host_key_policy = "strict"
default_env = { APP_ENV = "production" }
max_sessions = 5

[servers.staging-api]
host = "api.staging.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/staging_key"
default_env = { APP_ENV = "staging" }
max_sessions = 10

[servers.dev-api]
host = "localhost"
port = 8022
user = "alice"
auth_type = "key"
key_path = "~/.ssh/id_ed25519"
default_cwd = "/home/alice/myapp"
default_env = { APP_ENV = "development" }
```

### Pattern 2: Read-Only Access for Monitoring

Set up read-only accounts for monitoring/observability:

```toml
[servers.prod-monitor]
host = "api.prod.example.com"
user = "monitor"           # ← Read-only account
auth_type = "key"
key_path = "~/.ssh/monitor_key"
host_key_policy = "strict"
default_env = { ROLE = "monitor" }
```

### Pattern 3: Credential-Separated Access

Use different keys for different access levels:

```toml
[servers.prod-deploy]
host = "api.prod.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/prod_deploy_key"  # ← Deploy key (limited permissions)

[servers.prod-admin]
host = "api.prod.example.com"
user = "root"
auth_type = "key"
key_path = "~/.ssh/prod_admin_key"   # ← Admin key (full access)
```

### Pattern 4: Database Replication Setup

```toml
[servers.db-primary]
host = "db1.prod.example.com"
user = "postgres"
auth_type = "key"
key_path = "~/.ssh/db_key"
host_key_policy = "strict"
default_env = { PGHOST = "db1.prod.example.com" }

[servers.db-replica]
host = "db2.prod.example.com"
user = "postgres"
auth_type = "key"
key_path = "~/.ssh/db_key"
host_key_policy = "strict"
default_env = { PGHOST = "db2.prod.example.com" }

[servers.db-standby]
host = "db3.prod.example.com"
user = "postgres"
auth_type = "key"
key_path = "~/.ssh/db_key"
host_key_policy = "strict"
default_env = { PGHOST = "db3.prod.example.com" }
```

---

## Credential Management

### SSH Keys

Use separate keys per environment or role:

```bash
# Structure keys logically
~/.ssh/
├── prod_deploy_ed25519      # Deploy to production
├── prod_admin_ed25519       # Admin access to production
├── staging_ed25519          # Staging environment
├── dev_ed25519              # Local dev
└── bastion_ed25519          # Jump host

# Restrict key permissions
chmod 600 ~/.ssh/prod_*
chmod 600 ~/.ssh/staging_*
chmod 600 ~/.ssh/dev_*
```

### Password Authentication (Not Recommended)

If you must use passwords, store them in environment variables:

```toml
[servers.legacy-host]
host = "legacy.example.com"
user = "legacyuser"
auth_type = "password"
password_env = "LEGACY_HOST_PASSWORD"
```

Set the environment variable:

```bash
export LEGACY_HOST_PASSWORD="your_password_here"
```

**Important:** Passwords are never logged to audit trails. The value is read from the environment variable only when needed.

### SSH Agent

Use SSH agent for key management without plaintext keys on disk:

```toml
[servers.prod]
host = "api.prod.example.com"
user = "deploy"
auth_type = "agent"  # ← Uses local SSH agent
```

Start your SSH agent and add keys:

```bash
eval $(ssh-agent)
ssh-add ~/.ssh/prod_key
# Now connections to prod will use the agent
```

### Vault / Secrets Management

For production, integrate with HashiCorp Vault or similar:

```bash
# Example: fetch secret at runtime
export PROD_KEY_PASS=$(vault read -field=password secret/prod/ssh-key)
```

Then reference in config via environment variable.

---

## Best Practices

### 1. Use Descriptive Server Names

❌ Bad:
```toml
[servers.s1]
[servers.s2]
[servers.s3]
```

✅ Good:
```toml
[servers.prod-api-us-east-1]
[servers.prod-db-primary]
[servers.staging-api]
```

### 2. Set Host Key Policies by Environment

```toml
[settings]
default_host_key_policy = "tofu"  # Reasonable default

[servers.prod]
host_key_policy = "strict"        # Production: verify against known_hosts

[servers.dev]
host_key_policy = "accept_new"    # Dev: relax for convenience
```

### 3. Separate Secrets from Config

Store sensitive paths/passwords in environment variables:

```toml
[servers.prod]
host = "api.prod.example.com"
user = "deploy"
auth_type = "key"
key_path = "${SSH_KEY_PROD}"       # ← Environment variable
```

```bash
export SSH_KEY_PROD="~/.ssh/prod_ed25519"
```

### 4. Limit Session Concurrency in Production

```toml
[settings]
max_sessions = 10  # Default

[servers.prod]
max_sessions = 3   # Production: stricter limits
```

### 5. Set Working Directories for Common Tasks

```toml
[servers.appserver]
host = "app.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/app_key"
default_cwd = "/opt/myapp"        # Commands run from here
```

Now `ssh_exec` commands run from `/opt/myapp` by default.

### 6. Use Jump Hosts for Internal Servers

Don't expose internal servers directly; always route through bastion:

```toml
[servers.bastion]
host = "jump.example.com"
user = "jumpuser"
auth_type = "key"
key_path = "~/.ssh/bastion_key"

[servers.internal-api]
host = "api.internal"              # Not directly accessible
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/internal_key"
jump_host = "bastion"              # ← Always go through bastion
```

### 7. Document Your Infrastructure

Add comments to `servers.toml`:

```toml
# Production infrastructure
[servers.prod-api]
host = "api.prod.example.com"
user = "deploy"
auth_type = "key"
key_path = "~/.ssh/prod_key"
# Managed by Terraform (prod-infrastructure repo)
# On-call: page prod-eng-oncall

[servers.prod-db]
host = "db.prod.example.com"
user = "postgres"
auth_type = "key"
key_path = "~/.ssh/prod_db_key"
# Primary database — read-only connections through replica preferred
# Backups managed by backup service
```

### 8. Monitor Connection Patterns

Use audit logs to detect unusual activity:

```bash
# Find all failed connection attempts
cat ~/.local/share/better-ssh-mcp/audit.jsonl | jq 'select(.outcome == "failure")'

# Which servers were accessed most?
cat ~/.local/share/better-ssh-mcp/audit.jsonl | jq -r '.server' | sort | uniq -c | sort -rn

# Connections to prod servers in the last hour
cat ~/.local/share/better-ssh-mcp/audit.jsonl | \
  jq "select(.server | startswith(\"prod\")) and (.ts > now - 3600)"
```

---

## Troubleshooting

### Can't Connect to a Server

1. **Check the server entry exists:**
   ```bash
   grep "servers.myserver" ~/.config/better-ssh-mcp/servers.toml
   ```

2. **Verify SSH key permissions:**
   ```bash
   ls -la ~/.ssh/mykey
   # Should be -rw------- (mode 0600)
   ```

3. **Test with native SSH:**
   ```bash
   ssh -i ~/.ssh/mykey myuser@example.com
   ```

4. **Check audit logs for errors:**
   ```bash
   cat ~/.local/share/better-ssh-mcp/audit.jsonl | jq 'select(.server == "myserver")'
   ```

### Jump Host Connection Fails

1. **Verify bastion is reachable:**
   ```bash
   ssh -i ~/.ssh/bastion_key jumpuser@bastion.example.com
   ```

2. **Test bastion → target connection:**
   ```bash
   ssh -i ~/.ssh/bastion_key jumpuser@bastion.example.com \
     ssh -i ~/.ssh/internal_key deploy@api.internal
   ```

3. **Check jump_host name matches server entry:**
   ```toml
   [servers.internal-api]
   jump_host = "bastion"  # ← Must match [servers.bastion] name
   ```

### Host Key Verification Fails

If you get a host key verification error:

```json
{
  "tool": "ssh_exec",
  "outcome": "failure",
  "detail": {
    "error": "Host key verification failed"
  }
}
```

**Option 1: Accept the new key (TOFU policy)**
```toml
[servers.myserver]
host_key_policy = "tofu"  # Trust-on-first-use
```

**Option 2: Pre-populate known_hosts**
```bash
ssh-keyscan -H example.com >> ~/.local/share/better-ssh-mcp/known_hosts
```

**Option 3: Disable verification (dev only)**
```toml
[servers.dev]
host_key_policy = "accept_new"  # Accept any key (not secure!)
```

---

## See Also

- [README.md](README.md) — Feature overview
- [FEATURES.md](FEATURES.md) — Tool documentation & audit logging
- [INSTALL.md](INSTALL.md) — Installation & setup

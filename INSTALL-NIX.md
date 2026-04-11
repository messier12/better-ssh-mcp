# Installing mcp-ssh with Nix

`mcp-ssh` ships a Nix flake with:

- A buildable package (`nix build`)
- A dev shell with `uv` and `python311` (`nix develop`)
- A **Home Manager module** for per-user installation
- A **NixOS module** for system-wide installation

---

## Quick start

```bash
# Build the binary
nix build github:messier12/better-ssh-mcp

# Run without installing
nix run github:messier12/better-ssh-mcp -- --help
```

---

## Adding the flake input

In your `flake.nix`:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    mcp-ssh.url = "github:messier12/better-ssh-mcp";
    # Pin mcp-ssh to the same nixpkgs to avoid duplicate copies:
    mcp-ssh.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, mcp-ssh, ... }: { ... };
}
```

---

## Home Manager module

The Home Manager module installs `mcp-ssh` for a single user and optionally
writes a configuration file to `~/.config/mcp-ssh/config.toml`.

### Minimal usage (enable only)

```nix
{ inputs, ... }:
{
  imports = [ inputs.mcp-ssh.homeManagerModules.default ];

  programs.mcp-ssh.enable = true;
}
```

### Full example with settings

```nix
{ inputs, ... }:
{
  imports = [ inputs.mcp-ssh.homeManagerModules.default ];

  programs.mcp-ssh = {
    enable = true;

    # Override the package (e.g. to use a local checkout):
    # package = inputs.mcp-ssh.packages.${pkgs.system}.default;

    settings = {
      default_host_key_policy = "tofu";   # tofu | strict | accept_new
      audit_log_path = "/home/alice/.local/share/mcp-ssh/audit.log";

      # Additional freeform TOML keys are passed through unchanged.
      # Example server block (exact schema depends on mcp-ssh version):
      # servers.myhost = {
      #   host = "192.168.1.10";
      #   user = "alice";
      #   auth_type = "agent";
      # };
    };
  };
}
```

### Using a pre-existing config file

```nix
programs.mcp-ssh = {
  enable = true;
  configFile = ./mcp-ssh-config.toml;
};
```

When `configFile` is set it takes precedence and `settings` is ignored.

---

## NixOS module

The NixOS module installs `mcp-ssh` system-wide
(`environment.systemPackages`) and optionally writes the config to
`/etc/mcp-ssh/config.toml`.

### Minimal usage

```nix
{ inputs, ... }:
{
  imports = [ inputs.mcp-ssh.nixosModules.default ];

  programs.mcp-ssh.enable = true;
}
```

### Full example

```nix
{ inputs, ... }:
{
  imports = [ inputs.mcp-ssh.nixosModules.default ];

  programs.mcp-ssh = {
    enable = true;

    settings = {
      default_host_key_policy = "strict";
      audit_log_path = "/var/log/mcp-ssh/audit.log";
    };
  };
}
```

---

## Module options reference

Both modules expose the same `programs.mcp-ssh` option tree:

| Option | Type | Default | Description |
|---|---|---|---|
| `enable` | bool | `false` | Install `mcp-ssh` and write config |
| `package` | package | flake default | Override the package |
| `settings` | attrset (TOML) | `{}` | Written to the config file (TOML format) |
| `settings.default_host_key_policy` | `"tofu"` \| `"strict"` \| `"accept_new"` | `"tofu"` | Host-key verification policy |
| `settings.audit_log_path` | str \| null | `null` | Audit log path (`null` = disabled) |
| `configFile` | path \| null | `null` | Use a pre-existing TOML file instead of `settings` |

---

## Claude Desktop configuration

Claude Desktop requires the **full Nix store path** to the binary — the
`mcp-ssh` wrapper script in your PATH is a shell wrapper and may not work
directly as an MCP server command.

1. Find the store path after building:

   ```bash
   nix build github:messier12/better-ssh-mcp
   readlink -f result/bin/mcp-ssh
   # Example output: /nix/store/abc123...-python3.11-mcp-ssh-0.1.0/bin/mcp-ssh
   ```

2. Add to `~/Library/Application Support/Claude/claude_desktop_config.json`
   (macOS) or `~/.config/Claude/claude_desktop_config.json` (Linux):

   ```json
   {
     "mcpServers": {
       "mcp-ssh": {
         "command": "/nix/store/abc123...-python3.11-mcp-ssh-0.1.0/bin/mcp-ssh",
         "args": [],
         "env": {}
       }
     }
   }
   ```

   Replace the store path with the actual output of `readlink -f result/bin/mcp-ssh`.

3. If you manage your system with Home Manager or NixOS you can use the
   package path from your profile instead:

   ```bash
   # Home Manager users
   which mcp-ssh
   # /home/alice/.nix-profile/bin/mcp-ssh  ← use this path
   ```

   Because `~/.nix-profile` is a symlink tree pointing into the store, the
   exact store path is not required in this case.

---

## Security-key (FIDO2 / sk) authentication

`libfido2` is included in the package's build closure so that `asyncssh`'s
FIDO/U2F (`sk-*` key types) support is available at runtime without any extra
configuration on your part.

---

## Development shell

```bash
# Enter the dev shell (provides uv + python311)
nix develop

# Install Python dependencies and run tests
uv sync
uv run pytest
uv run mypy mcp_ssh/ --strict
uv run ruff check mcp_ssh/
```

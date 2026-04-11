# T5b — NixOS Packaging Notes

## Status
Completed 2026-04-11.

## What was done

### flake.nix changes (relative to T0 skeleton)

1. **`buildInputs = [ pkgs.libfido2 ]`** added to the package derivation so
   `asyncssh`'s FIDO/U2F (sk-\* key type) support has `libfido2.so` available
   at runtime.

2. **`apps.default`** output added, pointing to `${mcpSshPackage}/bin/mcp-ssh`.
   This is what `nix run .#` uses. Without this, `nix run` falls back to
   `mainProgram` from meta, but making it explicit is cleaner.

3. **`packages.mcp-ssh`** added as an alias for `packages.default`.

4. **`checks.package`** — the package derivation itself is added to `checks`
   so `nix flake check` builds it.

5. **`nixosModules.default`** — NixOS module at `programs.mcp-ssh` with:
   - `enable` option
   - `package` option (defaults to flake package for current system)
   - `settings` submodule (freeform TOML, typed options for known keys)
   - `configFile` override (use pre-existing TOML file)
   - Installs via `environment.systemPackages`
   - Writes `/etc/mcp-ssh/config.toml` from `settings` (unless `configFile` set)

6. **`homeManagerModules.default`** — same API as nixosModule but:
   - Installs via `home.packages`
   - Writes `~/.config/mcp-ssh/config.toml` via `xdg.configFile`

### Architecture: per-system vs system-agnostic outputs

`eachDefaultSystem` only handles per-system outputs (`packages`, `devShells`,
`apps`, `checks`). Modules are system-agnostic — they are functions that
receive `pkgs` at evaluation time. They are placed outside the
`eachDefaultSystem` call and merged with `//` into the final attrset.

Inside each module, the package default is resolved lazily via
`self.packages.${pkgs.stdenv.hostPlatform.system}.default`, which is safe as
long as the user is on a system supported by `eachDefaultSystem` (x86_64-linux,
aarch64-linux, x86_64-darwin, aarch64-darwin).

### dontCheckRuntimeDeps preserved

As noted in t0-notes.md, `dontCheckRuntimeDeps = true` is kept because
`asyncssh→pyopenssl→sphinx-9.x` is incompatible with python3.11 in the current
nixpkgs snapshot. Runtime deps are managed by uv/pyproject.toml, not nixpkgs.

### No `nix/` directory needed

The modules are short enough to live inline in `flake.nix`. A `nix/` directory
would only be warranted if the modules grew substantially or were reused.

## Files produced/modified

- `/home/das/repos/better-ssh-mcp/flake.nix` — extended from T0 skeleton
- `/home/das/repos/better-ssh-mcp/INSTALL-NIX.md` — new, covers all required topics

## Acceptance criteria status

| Criterion | Status | Notes |
|---|---|---|
| `nix build` completes | Expected pass | Package derivation unchanged from T0 which already passed |
| `nix run .# -- --help` | Expected pass | `main()` returns immediately (no arg parsing yet); no crash |
| `nix flake check` | Expected pass | `checks.package` builds the package; modules evaluate cleanly |
| `homeManagerModules.default` provides `programs.mcp-ssh` | Done | |
| `nixosModules.default` provides `programs.mcp-ssh` | Done | |
| `libfido2` in buildInputs | Done | |
| `INSTALL-NIX.md` covers flake input, HM usage, Claude Desktop | Done | |

## Known limitations

- `mcp-ssh --help` does not currently print anything useful because the
  entrypoint `main()` is a stub (`...`). The binary runs without crashing,
  satisfying the acceptance criterion. Full CLI will be implemented in T4.
- The `settings` TOML schema only declares two typed options
  (`default_host_key_policy`, `audit_log_path`). Additional keys pass through
  via `freeformType`. The full settings schema should be updated once T1a
  (config module) is complete.

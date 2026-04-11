{
  description = "mcp-ssh — MCP server exposing SSH operations as tools";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      # Per-system outputs (packages, devShells, apps, checks)
      perSystemOutputs = flake-utils.lib.eachDefaultSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python311;

          mcpSshPackage = python.pkgs.buildPythonPackage {
            pname = "mcp-ssh";
            version = "0.1.0";
            src = ./.;
            pyproject = true;

            nativeBuildInputs = [ python.pkgs.hatchling ];

            # libfido2 is included in buildInputs so that security-key (sk)
            # authentication works out of the box.  It is a C library used by
            # asyncssh's FIDO/U2F support at runtime; placing it here makes the
            # .so available in the package's closure.
            buildInputs = [ pkgs.libfido2 ];

            # Runtime Python deps are managed by uv/pyproject.toml.
            # asyncssh and other deps are omitted from propagatedBuildInputs
            # because their nixpkgs transitive deps (pyopenssl → sphinx-9.x)
            # are incompatible with python3.11 in this nixpkgs snapshot.
            propagatedBuildInputs = [];

            doCheck = false;
            pythonImportsCheck = [];
            # Disable runtime deps check since deps are managed via uv, not nixpkgs
            dontCheckRuntimeDeps = true;

            meta = {
              description = "MCP server exposing SSH operations as tools";
              mainProgram = "mcp-ssh";
              homepage = "https://github.com/messier12/better-ssh-mcp";
              license = nixpkgs.lib.licenses.mit;
            };
          };
        in
        {
          packages.default = mcpSshPackage;
          packages.mcp-ssh = mcpSshPackage;

          apps.default = {
            type = "app";
            program = "${mcpSshPackage}/bin/mcp-ssh";
          };

          devShells.default = pkgs.mkShell {
            buildInputs = [
              python
              pkgs.uv
              pkgs.libfido2
            ];
            shellHook = ''
              export UV_PYTHON="${python}/bin/python3"
            '';
          };

          checks = {
            package = mcpSshPackage;
          };
        }
      );

      # System-agnostic outputs: NixOS module and Home Manager module
      # These use nixpkgs for the current system where needed.
      nixosModule = { config, lib, pkgs, ... }:
        let
          cfg = config.programs.mcp-ssh;
          # Resolve the package from the flake for the target system
          mcpSshPkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;

          settingsFormat = pkgs.formats.toml {};
        in
        {
          options.programs.mcp-ssh = {
            enable = lib.mkEnableOption "mcp-ssh MCP SSH server";

            package = lib.mkOption {
              type = lib.types.package;
              default = mcpSshPkg;
              defaultText = lib.literalExpression "pkgs.mcp-ssh (from flake)";
              description = "The mcp-ssh package to install.";
            };

            settings = lib.mkOption {
              type = lib.types.submodule {
                freeformType = settingsFormat.type;
                options = {
                  default_host_key_policy = lib.mkOption {
                    type = lib.types.enum [ "tofu" "strict" "accept_new" ];
                    default = "tofu";
                    description = "Default host-key policy: tofu, strict, or accept_new.";
                  };
                  audit_log_path = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    description = "Path for the audit log file (null disables file logging).";
                  };
                };
              };
              default = {};
              description = "Settings written to mcp-ssh's TOML configuration file.";
            };

            configFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = "Path to a pre-existing mcp-ssh TOML config file. Overrides settings.";
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];

            environment.etc."mcp-ssh/config.toml" = lib.mkIf (cfg.configFile == null) {
              source = settingsFormat.generate "mcp-ssh-config.toml" cfg.settings;
            };
          };
        };

      homeManagerModule = { config, lib, pkgs, ... }:
        let
          cfg = config.programs.mcp-ssh;
          mcpSshPkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;

          settingsFormat = pkgs.formats.toml {};
        in
        {
          options.programs.mcp-ssh = {
            enable = lib.mkEnableOption "mcp-ssh MCP SSH server";

            package = lib.mkOption {
              type = lib.types.package;
              default = mcpSshPkg;
              defaultText = lib.literalExpression "pkgs.mcp-ssh (from flake)";
              description = "The mcp-ssh package to install.";
            };

            settings = lib.mkOption {
              type = lib.types.submodule {
                freeformType = settingsFormat.type;
                options = {
                  default_host_key_policy = lib.mkOption {
                    type = lib.types.enum [ "tofu" "strict" "accept_new" ];
                    default = "tofu";
                    description = "Default host-key policy: tofu, strict, or accept_new.";
                  };
                  audit_log_path = lib.mkOption {
                    type = lib.types.nullOr lib.types.str;
                    default = null;
                    description = "Path for the audit log file (null disables file logging).";
                  };
                };
              };
              default = {};
              description = "Settings written to mcp-ssh's TOML configuration file.";
            };

            configFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = "Path to a pre-existing mcp-ssh TOML config file. Overrides settings.";
            };
          };

          config = lib.mkIf cfg.enable {
            home.packages = [ cfg.package ];

            xdg.configFile."mcp-ssh/config.toml" = lib.mkIf (cfg.configFile == null) {
              source = settingsFormat.generate "mcp-ssh-config.toml" cfg.settings;
            };
          };
        };

    in
    perSystemOutputs // {
      nixosModules.default = nixosModule;
      homeManagerModules.default = homeManagerModule;
    };
}

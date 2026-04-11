"""Configuration loading and path resolution for mcp-ssh."""
from __future__ import annotations

import os
import tomllib
from pathlib import Path

from .exceptions import McpSshError
from .models import AppConfig, GlobalSettings, ServerConfig


def _expand_path(p: str) -> str:
    """Expand ~ and $XDG_CONFIG_HOME (and other env vars) in a path string."""
    return str(Path(os.path.expandvars(p)).expanduser())


def _expand_paths_in_server(server: ServerConfig) -> ServerConfig:
    """Return a copy of *server* with all path fields expanded."""
    updates: dict[str, str | None] = {}
    if server.key_path is not None:
        updates["key_path"] = _expand_path(server.key_path)
    if server.cert_path is not None:
        updates["cert_path"] = _expand_path(server.cert_path)
    if server.default_cwd is not None:
        updates["default_cwd"] = _expand_path(server.default_cwd)
    if not updates:
        return server
    return server.model_copy(update=updates)


def _expand_paths_in_settings(settings: GlobalSettings) -> GlobalSettings:
    """Return a copy of *settings* with all path fields expanded."""
    return settings.model_copy(
        update={
            "known_hosts_file": _expand_path(settings.known_hosts_file),
            "audit_log": _expand_path(settings.audit_log),
            "state_file": _expand_path(settings.state_file),
        }
    )


def _detect_circular_jumps(servers: dict[str, ServerConfig]) -> None:
    """Raise McpSshError if any circular jump-host chain is found.

    Uses DFS to detect cycles in the jump_host graph.
    """
    # Build adjacency: name -> jump_host name (or None)
    def _has_cycle(start: str) -> bool:
        visited: set[str] = set()
        current: str | None = start
        while current is not None:
            if current in visited:
                return True
            visited.add(current)
            cfg = servers.get(current)
            if cfg is None:
                # Jump host refers to unknown server — not a cycle issue here
                break
            current = cfg.jump_host
        return False

    for name in servers:
        if _has_cycle(name):
            raise McpSshError(
                f"Circular jump-host chain detected starting from server '{name}'"
            )


def load_config(path: Path) -> AppConfig:
    """Parse *path* as TOML, validate into ``AppConfig``, and expand all paths.

    Raises:
        McpSshError: if the file cannot be parsed or validation fails, or if a
            circular jump-host chain is found.
    """
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise McpSshError(f"Failed to load config from {path}: {exc}") from exc

    try:
        cfg = AppConfig.model_validate(raw)
    except Exception as exc:
        raise McpSshError(f"Config validation error in {path}: {exc}") from exc

    # Expand paths in global settings
    cfg = cfg.model_copy(update={"settings": _expand_paths_in_settings(cfg.settings)})

    # Expand paths in each server and rebuild the dict
    expanded_servers = {
        name: _expand_paths_in_server(srv) for name, srv in cfg.servers.items()
    }
    cfg = cfg.model_copy(update={"servers": expanded_servers})

    # Validate jump-host graph
    _detect_circular_jumps(cfg.servers)

    return cfg


def resolve_config_path(env_var: str = "MCP_SSH_CONFIG", cli_arg: str | None = None) -> Path:
    """Return the config file path using the resolution order:

    1. ``MCP_SSH_CONFIG`` environment variable
    2. *cli_arg* (``--config`` CLI argument)
    3. ``$XDG_CONFIG_HOME/mcp-ssh/servers.toml``
    4. ``~/.config/mcp-ssh/servers.toml``
    """
    env_val = os.environ.get(env_var)
    if env_val:
        return Path(env_val)

    if cli_arg is not None:
        return Path(cli_arg)

    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return Path(xdg_config_home) / "mcp-ssh" / "servers.toml"

    return Path.home() / ".config" / "mcp-ssh" / "servers.toml"


def app_config_to_toml(cfg: AppConfig) -> str:
    """Serialise *cfg* back to a TOML string.

    This is used by ``Registry.add`` / ``Registry.remove`` to write the updated
    config to disk.  Only a minimal subset of TOML is produced (no fancy
    formatting), but it is always valid and round-trips correctly.
    """
    lines: list[str] = []

    # [settings]
    lines.append("[settings]")
    s = cfg.settings
    lines.append(f'known_hosts_file = "{s.known_hosts_file}"')
    lines.append(f'default_host_key_policy = "{s.default_host_key_policy.value}"')
    lines.append(f'audit_log = "{s.audit_log}"')
    lines.append(f'state_file = "{s.state_file}"')
    lines.append(f"max_sessions = {s.max_sessions}")
    lines.append(f"keepalive_interval = {s.keepalive_interval}")
    lines.append(f"keepalive_count_max = {s.keepalive_count_max}")
    lines.append(f"connect_timeout = {s.connect_timeout}")
    lines.append(f'default_encoding = "{s.default_encoding}"')
    lines.append("")

    for name, srv in cfg.servers.items():
        lines.append(f"[servers.{name}]")
        lines.append(f'name = "{srv.name}"')
        lines.append(f'host = "{srv.host}"')
        lines.append(f"port = {srv.port}")
        lines.append(f'user = "{srv.user}"')
        lines.append(f'auth_type = "{srv.auth_type.value}"')
        if srv.key_path is not None:
            lines.append(f'key_path = "{srv.key_path}"')
        if srv.cert_path is not None:
            lines.append(f'cert_path = "{srv.cert_path}"')
        if srv.password_env is not None:
            lines.append(f'password_env = "{srv.password_env}"')
        if srv.jump_host is not None:
            lines.append(f'jump_host = "{srv.jump_host}"')
        if srv.host_key_policy is not None:
            lines.append(f'host_key_policy = "{srv.host_key_policy.value}"')
        if srv.default_cwd is not None:
            lines.append(f'default_cwd = "{srv.default_cwd}"')
        if srv.default_env:
            # Inline table: { KEY = "val", ... }
            pairs = ", ".join(f'{k} = "{v}"' for k, v in srv.default_env.items())
            lines.append(f"default_env = {{ {pairs} }}")
        if srv.max_sessions is not None:
            lines.append(f"max_sessions = {srv.max_sessions}")
        if srv.keepalive_interval is not None:
            lines.append(f"keepalive_interval = {srv.keepalive_interval}")
        lines.append("")

    return "\n".join(lines)

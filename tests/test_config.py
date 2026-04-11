"""Tests for mcp_ssh.config — TOML loading, path expansion, and serialisation."""
from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from mcp_ssh.config import (
    _detect_circular_jumps,
    _expand_path,
    app_config_to_toml,
    load_config,
    resolve_config_path,
)
from mcp_ssh.exceptions import McpSshError
from mcp_ssh.models import AppConfig, AuthType, GlobalSettings, HostKeyPolicy, ServerConfig


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

MINIMAL_TOML = textwrap.dedent("""\
    [servers.web]
    name = "web"
    host = "web.example.com"
    user = "alice"
    auth_type = "agent"
""")

FULL_TOML = textwrap.dedent("""\
    [settings]
    known_hosts_file = "~/.local/share/mcp-ssh/known_hosts"
    default_host_key_policy = "tofu"
    audit_log = "~/.local/share/mcp-ssh/audit.jsonl"
    state_file = "~/.local/share/mcp-ssh/state.json"
    max_sessions = 10
    keepalive_interval = 30
    keepalive_count_max = 5
    connect_timeout = 15
    default_encoding = "utf-8"

    [servers.dev]
    name = "dev"
    host = "dev.example.com"
    port = 22
    user = "alice"
    auth_type = "key"
    key_path = "~/.ssh/id_ed25519"
    default_cwd = "/home/alice"

    [servers.prod]
    name = "prod"
    host = "prod.example.com"
    port = 2222
    user = "deploy"
    auth_type = "agent"
    host_key_policy = "strict"
    default_env = { APP_ENV = "production" }
    max_sessions = 5
""")


@pytest.fixture()
def tmp_config(tmp_path: Path) -> Path:
    """Write FULL_TOML to a temp file and return its path."""
    p = tmp_path / "servers.toml"
    p.write_text(FULL_TOML, encoding="utf-8")
    return p


@pytest.fixture()
def minimal_config(tmp_path: Path) -> Path:
    """Write MINIMAL_TOML to a temp file and return its path."""
    p = tmp_path / "servers.toml"
    p.write_text(MINIMAL_TOML, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _expand_path
# ---------------------------------------------------------------------------


def test_expand_path_tilde() -> None:
    result = _expand_path("~/.ssh/id_ed25519")
    assert result.startswith(str(Path.home()))
    assert "~" not in result


def test_expand_path_xdg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", "/custom/config")
    result = _expand_path("$XDG_CONFIG_HOME/mcp-ssh/servers.toml")
    assert result == "/custom/config/mcp-ssh/servers.toml"


def test_expand_path_plain() -> None:
    result = _expand_path("/absolute/path")
    assert result == "/absolute/path"


# ---------------------------------------------------------------------------
# load_config — happy path
# ---------------------------------------------------------------------------


def test_load_minimal(minimal_config: Path) -> None:
    cfg = load_config(minimal_config)
    assert "web" in cfg.servers
    assert cfg.servers["web"].auth_type == AuthType.agent


def test_load_full(tmp_config: Path) -> None:
    cfg = load_config(tmp_config)
    assert len(cfg.servers) == 2
    assert cfg.servers["dev"].auth_type == AuthType.key
    assert cfg.servers["prod"].default_env == {"APP_ENV": "production"}
    assert cfg.settings.max_sessions == 10


def test_load_expands_key_path(tmp_config: Path) -> None:
    cfg = load_config(tmp_config)
    assert "~" not in cfg.servers["dev"].key_path  # type: ignore[operator]


def test_load_expands_settings_paths(tmp_config: Path) -> None:
    cfg = load_config(tmp_config)
    assert "~" not in cfg.settings.known_hosts_file
    assert "~" not in cfg.settings.audit_log
    assert "~" not in cfg.settings.state_file


def test_load_default_settings_when_section_absent(minimal_config: Path) -> None:
    """No [settings] section → GlobalSettings defaults are used."""
    cfg = load_config(minimal_config)
    defaults = GlobalSettings()
    assert cfg.settings.max_sessions == defaults.max_sessions
    assert cfg.settings.keepalive_interval == defaults.keepalive_interval


# ---------------------------------------------------------------------------
# load_config — error cases
# ---------------------------------------------------------------------------


def test_load_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(McpSshError, match="Failed to load config"):
        load_config(tmp_path / "nonexistent.toml")


def test_load_malformed_toml(tmp_path: Path) -> None:
    bad = tmp_path / "servers.toml"
    bad.write_text("this is not [ valid toml ===", encoding="utf-8")
    with pytest.raises(McpSshError, match="Failed to load config"):
        load_config(bad)


def test_load_validation_error(tmp_path: Path) -> None:
    """Missing required fields → validation error wrapped in McpSshError."""
    bad = tmp_path / "servers.toml"
    bad.write_text("[servers.broken]\nname = \"broken\"\n", encoding="utf-8")
    with pytest.raises(McpSshError, match="Config validation error"):
        load_config(bad)


# ---------------------------------------------------------------------------
# _detect_circular_jumps
# ---------------------------------------------------------------------------


def _make_server(name: str, jump_host: str | None = None) -> ServerConfig:
    return ServerConfig(
        name=name,
        host=f"{name}.example.com",
        user="alice",
        auth_type=AuthType.agent,
        jump_host=jump_host,
    )


def test_no_circular_jumps_passes() -> None:
    servers = {
        "a": _make_server("a", jump_host="b"),
        "b": _make_server("b"),
    }
    _detect_circular_jumps(servers)  # should not raise


def test_circular_jump_raises() -> None:
    servers = {
        "a": _make_server("a", jump_host="b"),
        "b": _make_server("b", jump_host="a"),
    }
    with pytest.raises(McpSshError, match="Circular jump-host chain"):
        _detect_circular_jumps(servers)


def test_circular_jump_three_nodes_raises() -> None:
    servers = {
        "a": _make_server("a", jump_host="b"),
        "b": _make_server("b", jump_host="c"),
        "c": _make_server("c", jump_host="a"),
    }
    with pytest.raises(McpSshError, match="Circular jump-host chain"):
        _detect_circular_jumps(servers)


def test_self_referential_jump_raises() -> None:
    servers = {
        "a": _make_server("a", jump_host="a"),
    }
    with pytest.raises(McpSshError, match="Circular jump-host chain"):
        _detect_circular_jumps(servers)


def test_load_config_raises_on_circular_jump(tmp_path: Path) -> None:
    toml = textwrap.dedent("""\
        [servers.a]
        name = "a"
        host = "a.example.com"
        user = "alice"
        auth_type = "agent"
        jump_host = "b"

        [servers.b]
        name = "b"
        host = "b.example.com"
        user = "bob"
        auth_type = "agent"
        jump_host = "a"
    """)
    p = tmp_path / "servers.toml"
    p.write_text(toml, encoding="utf-8")
    with pytest.raises(McpSshError, match="Circular jump-host chain"):
        load_config(p)


# ---------------------------------------------------------------------------
# All 4 auth types round-trip through load → serialise → reload
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "auth_type,extra",
    [
        ("agent", ""),
        ("key", 'key_path = "~/.ssh/id_ed25519"'),
        ("password", 'password_env = "MY_SSH_PASS"'),
        ("cert", 'key_path = "~/.ssh/id_ed25519"\ncert_path = "~/.ssh/id_ed25519-cert.pub"'),
    ],
)
def test_auth_type_round_trip(tmp_path: Path, auth_type: str, extra: str) -> None:
    toml = textwrap.dedent(f"""\
        [servers.s]
        name = "s"
        host = "s.example.com"
        user = "alice"
        auth_type = "{auth_type}"
        {extra}
    """)
    p = tmp_path / "servers.toml"
    p.write_text(toml, encoding="utf-8")
    cfg = load_config(p)

    # Serialise and reload
    reloaded_path = tmp_path / "reloaded.toml"
    reloaded_path.write_text(app_config_to_toml(cfg), encoding="utf-8")
    cfg2 = load_config(reloaded_path)

    assert cfg2.servers["s"].auth_type.value == auth_type


# ---------------------------------------------------------------------------
# jump_host chains round-trip
# ---------------------------------------------------------------------------


def test_jump_host_round_trip(tmp_path: Path) -> None:
    toml = textwrap.dedent("""\
        [servers.bastion]
        name = "bastion"
        host = "bastion.example.com"
        user = "ops"
        auth_type = "agent"

        [servers.internal]
        name = "internal"
        host = "internal.local"
        user = "alice"
        auth_type = "key"
        key_path = "~/.ssh/id_ed25519"
        jump_host = "bastion"
    """)
    p = tmp_path / "servers.toml"
    p.write_text(toml, encoding="utf-8")
    cfg = load_config(p)

    reloaded_path = tmp_path / "reloaded.toml"
    reloaded_path.write_text(app_config_to_toml(cfg), encoding="utf-8")
    cfg2 = load_config(reloaded_path)

    assert cfg2.servers["internal"].jump_host == "bastion"


# ---------------------------------------------------------------------------
# default_env round-trip
# ---------------------------------------------------------------------------


def test_default_env_round_trip(tmp_path: Path) -> None:
    toml = textwrap.dedent("""\
        [servers.s]
        name = "s"
        host = "s.example.com"
        user = "alice"
        auth_type = "agent"
        default_env = { APP_ENV = "production", LOG_LEVEL = "debug" }
    """)
    p = tmp_path / "servers.toml"
    p.write_text(toml, encoding="utf-8")
    cfg = load_config(p)

    reloaded_path = tmp_path / "reloaded.toml"
    reloaded_path.write_text(app_config_to_toml(cfg), encoding="utf-8")
    cfg2 = load_config(reloaded_path)

    assert cfg2.servers["s"].default_env == {"APP_ENV": "production", "LOG_LEVEL": "debug"}


# ---------------------------------------------------------------------------
# resolve_config_path
# ---------------------------------------------------------------------------


def test_resolve_env_var_takes_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_path = tmp_path / "via_env.toml"
    monkeypatch.setenv("MCP_SSH_CONFIG", str(env_path))
    result = resolve_config_path(cli_arg=str(tmp_path / "via_cli.toml"))
    assert result == env_path


def test_resolve_cli_arg_second(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MCP_SSH_CONFIG", raising=False)
    cli = tmp_path / "via_cli.toml"
    result = resolve_config_path(cli_arg=str(cli))
    assert result == cli


def test_resolve_xdg_config_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MCP_SSH_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    result = resolve_config_path()
    assert result == tmp_path / "mcp-ssh" / "servers.toml"


def test_resolve_default_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_SSH_CONFIG", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    result = resolve_config_path()
    assert result == Path.home() / ".config" / "mcp-ssh" / "servers.toml"


# ---------------------------------------------------------------------------
# app_config_to_toml — spot checks
# ---------------------------------------------------------------------------


def test_serialise_contains_server_section(tmp_config: Path) -> None:
    cfg = load_config(tmp_config)
    toml_str = app_config_to_toml(cfg)
    assert "[servers.dev]" in toml_str
    assert "[servers.prod]" in toml_str
    assert "[settings]" in toml_str


def test_serialise_host_key_policy(tmp_config: Path) -> None:
    cfg = load_config(tmp_config)
    toml_str = app_config_to_toml(cfg)
    assert 'host_key_policy = "strict"' in toml_str


def test_full_round_trip(tmp_config: Path, tmp_path: Path) -> None:
    """load → serialise → reload preserves all fields."""
    cfg1 = load_config(tmp_config)
    toml_str = app_config_to_toml(cfg1)
    p2 = tmp_path / "round_trip.toml"
    p2.write_text(toml_str, encoding="utf-8")
    cfg2 = load_config(p2)

    assert set(cfg1.servers.keys()) == set(cfg2.servers.keys())
    for name in cfg1.servers:
        s1 = cfg1.servers[name]
        s2 = cfg2.servers[name]
        assert s1.host == s2.host
        assert s1.user == s2.user
        assert s1.auth_type == s2.auth_type
        assert s1.default_env == s2.default_env

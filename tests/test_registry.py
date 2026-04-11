"""Tests for mcp_ssh.registry — Registry implementing IRegistry."""
from __future__ import annotations

import asyncio
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from mcp_ssh.exceptions import McpSshError, ServerAlreadyExists, ServerNotFound
from mcp_ssh.interfaces import IRegistry
from mcp_ssh.models import AuthType, ServerConfig
from mcp_ssh.registry import Registry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BASIC_TOML = textwrap.dedent("""\
    [servers.dev]
    name = "dev"
    host = "dev.example.com"
    user = "alice"
    auth_type = "key"
    key_path = "~/.ssh/id_ed25519"

    [servers.prod]
    name = "prod"
    host = "prod.example.com"
    user = "deploy"
    auth_type = "agent"
    default_env = { APP_ENV = "production" }
""")


@pytest.fixture()
def config_file(tmp_path: Path) -> Path:
    p = tmp_path / "servers.toml"
    p.write_text(BASIC_TOML, encoding="utf-8")
    return p


@pytest.fixture()
def registry(config_file: Path) -> Registry:
    return Registry(config_file)


def _make_server(name: str, jump_host: str | None = None) -> ServerConfig:
    return ServerConfig(
        name=name,
        host=f"{name}.example.com",
        user="alice",
        auth_type=AuthType.agent,
        jump_host=jump_host,
    )


# ---------------------------------------------------------------------------
# isinstance check
# ---------------------------------------------------------------------------


def test_registry_implements_iregistry(registry: Registry) -> None:
    assert isinstance(registry, IRegistry)


# ---------------------------------------------------------------------------
# get / list_all
# ---------------------------------------------------------------------------


def test_get_existing_server(registry: Registry) -> None:
    srv = registry.get("dev")
    assert srv.host == "dev.example.com"
    assert srv.user == "alice"


def test_get_missing_server_raises(registry: Registry) -> None:
    with pytest.raises(ServerNotFound, match="'missing'"):
        registry.get("missing")


def test_list_all_returns_all(registry: Registry) -> None:
    servers = registry.list_all()
    names = {s.name for s in servers}
    assert names == {"dev", "prod"}


# ---------------------------------------------------------------------------
# get_config
# ---------------------------------------------------------------------------


def test_get_config_returns_app_config(registry: Registry) -> None:
    cfg = registry.get_config()
    assert "dev" in cfg.servers
    assert cfg.settings is not None


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------


def test_add_new_server(registry: Registry, config_file: Path) -> None:
    new = _make_server("staging")
    registry.add(new)

    assert registry.get("staging").host == "staging.example.com"
    # Verify persisted to disk
    from mcp_ssh.config import load_config
    cfg_on_disk = load_config(config_file)
    assert "staging" in cfg_on_disk.servers


def test_add_duplicate_raises(registry: Registry) -> None:
    dup = _make_server("dev")  # already exists
    with pytest.raises(ServerAlreadyExists, match="'dev'"):
        registry.add(dup)


def test_add_writes_atomically(registry: Registry, config_file: Path) -> None:
    """The .tmp file should not be left behind after a successful write."""
    new = _make_server("canary")
    registry.add(new)
    tmp = config_file.with_suffix(".tmp")
    assert not tmp.exists()


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------


def test_remove_existing(registry: Registry, config_file: Path) -> None:
    registry.remove("dev")
    with pytest.raises(ServerNotFound):
        registry.get("dev")

    # Check persisted
    from mcp_ssh.config import load_config
    cfg_on_disk = load_config(config_file)
    assert "dev" not in cfg_on_disk.servers


def test_remove_missing_raises(registry: Registry) -> None:
    with pytest.raises(ServerNotFound, match="'ghost'"):
        registry.remove("ghost")


def test_remove_writes_atomically(registry: Registry, config_file: Path) -> None:
    registry.remove("prod")
    tmp = config_file.with_suffix(".tmp")
    assert not tmp.exists()


# ---------------------------------------------------------------------------
# round-trip: add → remove → verify
# ---------------------------------------------------------------------------


def test_add_then_remove_round_trip(registry: Registry) -> None:
    new = _make_server("temp")
    registry.add(new)
    assert "temp" in {s.name for s in registry.list_all()}
    registry.remove("temp")
    assert "temp" not in {s.name for s in registry.list_all()}


# ---------------------------------------------------------------------------
# All auth types round-trip via add → reload
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "auth_type,extra",
    [
        (AuthType.agent, {}),
        (AuthType.key, {"key_path": "~/.ssh/id_ed25519"}),
        (AuthType.password, {"password_env": "MY_SSH_PASS"}),
        (AuthType.cert, {"key_path": "~/.ssh/id_ed25519", "cert_path": "~/.ssh/id_ed25519-cert.pub"}),
    ],
)
def test_auth_type_add_reload(
    config_file: Path,
    auth_type: AuthType,
    extra: dict[str, str],
) -> None:
    reg = Registry(config_file)
    srv = ServerConfig(
        name=f"srv_{auth_type.value}",
        host="h.example.com",
        user="u",
        auth_type=auth_type,
        **extra,  # type: ignore[arg-type]
    )
    reg.add(srv)

    # Reload from disk
    reg2 = Registry(config_file)
    found = reg2.get(f"srv_{auth_type.value}")
    assert found.auth_type == auth_type


# ---------------------------------------------------------------------------
# default_env round-trip
# ---------------------------------------------------------------------------


def test_default_env_preserved_after_add_reload(config_file: Path) -> None:
    reg = Registry(config_file)
    srv = ServerConfig(
        name="env_test",
        host="h.example.com",
        user="u",
        auth_type=AuthType.agent,
        default_env={"FOO": "bar", "BAZ": "qux"},
    )
    reg.add(srv)
    reg2 = Registry(config_file)
    assert reg2.get("env_test").default_env == {"FOO": "bar", "BAZ": "qux"}


# ---------------------------------------------------------------------------
# jump_host chain round-trip
# ---------------------------------------------------------------------------


def test_jump_host_chain_round_trip(config_file: Path) -> None:
    reg = Registry(config_file)
    bastion = _make_server("bastion")
    internal = _make_server("internal_host", jump_host="bastion")
    reg.add(bastion)
    reg.add(internal)

    reg2 = Registry(config_file)
    assert reg2.get("internal_host").jump_host == "bastion"


# ---------------------------------------------------------------------------
# Malformed TOML in watch() retains previous valid config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_watch_retains_config_on_parse_error(
    config_file: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Simulate a file-change event with bad TOML; config should be retained."""
    import logging

    reg = Registry(config_file)
    original_config = reg.get_config()

    # We'll use an async generator that yields one change then stops
    async def fake_awatch(_path: Path):  # type: ignore[no-untyped-def]
        yield {("modified", str(_path))}

    with patch("watchfiles.awatch", side_effect=fake_awatch):
        # Corrupt the config file before the watch loop runs
        config_file.write_text("this is not valid toml ===", encoding="utf-8")
        with caplog.at_level(logging.ERROR, logger="mcp_ssh.registry"):
            results = []
            async for _ in reg.watch():
                results.append(True)

    # No yields (error was swallowed)
    assert results == []
    # Config is unchanged
    assert reg.get_config() == original_config
    assert "Config reload failed" in caplog.text


@pytest.mark.asyncio
async def test_watch_yields_on_valid_reload(config_file: Path) -> None:
    """On a valid file change, watch() should yield once."""
    reg = Registry(config_file)

    new_toml = textwrap.dedent("""\
        [servers.fresh]
        name = "fresh"
        host = "fresh.example.com"
        user = "alice"
        auth_type = "agent"
    """)

    async def fake_awatch(_path: Path):  # type: ignore[no-untyped-def]
        yield {("modified", str(_path))}

    with patch("watchfiles.awatch", side_effect=fake_awatch):
        config_file.write_text(new_toml, encoding="utf-8")
        results = []
        async for _ in reg.watch():
            results.append(True)

    assert results == [True]
    assert "fresh" in {s.name for s in reg.list_all()}


# ---------------------------------------------------------------------------
# Circular jump detection at construction time
# ---------------------------------------------------------------------------


def test_registry_raises_on_circular_jump(tmp_path: Path) -> None:
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
        Registry(p)

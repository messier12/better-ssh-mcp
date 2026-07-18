"""Tests for setup_jump / teardown_jump (spontaneous jump chains)."""
from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mcp_ssh.registry import Registry
from mcp_ssh.tools.registry_tools import setup_jump, teardown_jump

TOML = textwrap.dedent("""\
    [servers.alibaba]
    name = "alibaba"
    host = "47.91.2.123"
    user = "root"
    auth_type = "key"
    key_path = "/home/das/.ssh/alibaba"

    [servers.windows]
    name = "windows"
    host = "10.150.1.71"
    port = 2222
    user = "solan"
    auth_type = "key"
    key_path = "/home/das/.ssh/winkey"
""")


@pytest.fixture()
def registry(tmp_path: Path) -> Registry:
    p = tmp_path / "servers.toml"
    p.write_text(TOML, encoding="utf-8")
    return Registry(p)


@pytest.fixture()
def audit() -> MagicMock:
    return MagicMock()


def test_setup_jump_builds_ephemeral_chain(registry: Registry, audit: MagicMock) -> None:
    res = setup_jump(
        "winali", ["alibaba", "windows@11.11.0.4"], registry=registry, audit=audit
    )
    assert res["jump"] == "winali"
    assert res["ephemeral"] is True

    # Alias resolves to the final target, tunneled through the first hop.
    alias = registry.get("winali")
    assert alias.host == "11.11.0.4"          # @addr override applied
    assert alias.user == "solan"              # creds reused from windows
    assert alias.key_path == "/home/das/.ssh/winkey"
    assert alias.jump_host == "_winali_hop0"  # points at the first hop

    hop0 = registry.get("_winali_hop0")
    assert hop0.host == "47.91.2.123"         # alibaba, unchanged
    assert hop0.user == "root"
    assert hop0.jump_host is None             # first hop is direct


def test_setup_jump_reuses_registered_address_when_no_override(
    registry: Registry, audit: MagicMock
) -> None:
    setup_jump("wj", ["alibaba", "windows"], registry=registry, audit=audit)
    alias = registry.get("wj")
    assert alias.host == "10.150.1.71"  # windows' own registered host
    assert alias.port == 2222           # windows' own port preserved


def test_setup_jump_host_port_override(registry: Registry, audit: MagicMock) -> None:
    setup_jump("wj", ["alibaba", "windows@11.11.0.4:2200"], registry=registry, audit=audit)
    alias = registry.get("wj")
    assert alias.host == "11.11.0.4"
    assert alias.port == 2200


def test_setup_jump_is_not_persisted_by_default(
    registry: Registry, audit: MagicMock, tmp_path: Path
) -> None:
    setup_jump("wj", ["alibaba", "windows"], registry=registry, audit=audit)
    assert "wj" not in (tmp_path / "servers.toml").read_text(encoding="utf-8")


def test_setup_jump_persist_writes_file(
    registry: Registry, audit: MagicMock, tmp_path: Path
) -> None:
    setup_jump(
        "wj", ["alibaba", "windows"], registry=registry, audit=audit, persist=True
    )
    content = (tmp_path / "servers.toml").read_text(encoding="utf-8")
    assert "wj" in content
    assert "_wj_hop0" in content


def test_setup_jump_three_hops(registry: Registry, audit: MagicMock) -> None:
    setup_jump(
        "deep",
        ["alibaba", "windows@10.0.0.2", "windows@10.0.0.3"],
        registry=registry,
        audit=audit,
    )
    assert registry.get("_deep_hop0").jump_host is None
    assert registry.get("_deep_hop1").jump_host == "_deep_hop0"
    assert registry.get("deep").jump_host == "_deep_hop1"
    assert registry.get("deep").host == "10.0.0.3"


def test_setup_jump_custom_note_on_final(registry: Registry, audit: MagicMock) -> None:
    setup_jump(
        "wj", ["alibaba", "windows"], registry=registry, audit=audit, note="prod box"
    )
    assert registry.get("wj").note == "prod box"


def test_setup_jump_rejects_unknown_hop(registry: Registry, audit: MagicMock) -> None:
    res = setup_jump("wj", ["alibaba", "ghost"], registry=registry, audit=audit)
    assert res["error"] == "server_not_found"
    # Nothing should have been left behind from the partial build.
    from mcp_ssh.exceptions import ServerNotFound
    with pytest.raises(ServerNotFound):
        registry.get("_wj_hop0")


def test_setup_jump_rejects_existing_name(registry: Registry, audit: MagicMock) -> None:
    res = setup_jump("alibaba", ["alibaba"], registry=registry, audit=audit)
    assert res["error"] == "server_already_exists"


def test_setup_jump_rejects_empty_chain(registry: Registry, audit: MagicMock) -> None:
    res = setup_jump("wj", [], registry=registry, audit=audit)
    assert res["error"] == "invalid_chain"


def test_teardown_jump_removes_alias_and_hops(
    registry: Registry, audit: MagicMock
) -> None:
    setup_jump("winali", ["alibaba", "windows@11.11.0.4"], registry=registry, audit=audit)
    res = teardown_jump("winali", registry=registry, audit=audit)
    assert set(res["removed"]) == {"winali", "_winali_hop0"}
    from mcp_ssh.exceptions import ServerNotFound
    with pytest.raises(ServerNotFound):
        registry.get("winali")
    with pytest.raises(ServerNotFound):
        registry.get("_winali_hop0")


def test_teardown_jump_persisted(
    registry: Registry, audit: MagicMock, tmp_path: Path
) -> None:
    setup_jump(
        "wj", ["alibaba", "windows"], registry=registry, audit=audit, persist=True
    )
    teardown_jump("wj", registry=registry, audit=audit)
    content = (tmp_path / "servers.toml").read_text(encoding="utf-8")
    assert "wj" not in content
    # Base servers remain.
    assert "alibaba" in content


def test_teardown_jump_missing(registry: Registry, audit: MagicMock) -> None:
    res = teardown_jump("nope", registry=registry, audit=audit)
    assert res["error"] == "server_not_found"

"""Tests for ssh_scan_topology and setup_jump auto-chain (target= mode)."""
from __future__ import annotations

import textwrap
from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from mcp_ssh.models import GlobalSettings
from mcp_ssh.registry import Registry
from mcp_ssh.state import StateStore
from mcp_ssh.tools.registry_tools import setup_jump, ssh_scan_topology
from mcp_ssh.topology import (
    LOCAL_NODE,
    AddressProbe,
    TopologyEdge,
    TopologyResult,
    _build_adjacency,
)
from mcp_ssh.utils import now

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
    port = 22
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


@pytest.fixture()
def state(tmp_path: Path) -> StateStore:
    return StateStore(GlobalSettings(state_file=str(tmp_path / "state.json")))


def _edge(frm: str, to: str, via: str | None, reachable: bool = True,
          latency: float = 10.0) -> TopologyEdge:
    addrs = [AddressProbe(addr=via, port=22, state="reachable", latency_ms=latency)] if via else []
    return TopologyEdge(from_node=frm, to_node=to, reachable=reachable, via=via, addresses=addrs)


def _topo(edges: list[TopologyEdge], scanned_at: Any = None) -> TopologyResult:
    return TopologyResult(scanned_at=scanned_at or now(), nodes=[], edges=edges,
                          adjacency=_build_adjacency(edges))


class _Pool:
    """Minimal pool double: records get_connection calls; optionally fails."""

    def __init__(self, fail_on: set[str] | None = None) -> None:
        self.fail_on = fail_on or set()
        self.calls: list[str] = []

    async def get_connection(self, name: str) -> Any:
        self.calls.append(name)
        if name in self.fail_on:
            raise ConnectionError(f"cannot connect to {name}")
        return MagicMock()


# ---------------------------------------------------------------------------
# ssh_scan_topology
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ssh_scan_topology_caches_result(
    registry: Registry, audit: MagicMock, state: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _topo([_edge(LOCAL_NODE, "alibaba", "47.91.2.123")])

    async def _fake_scan(*args: Any, **kwargs: Any) -> TopologyResult:
        return fake

    monkeypatch.setattr("mcp_ssh.tools.registry_tools.scan_topology", _fake_scan)

    pool = _Pool()
    result = await ssh_scan_topology(
        registry=registry, pool=pool, state=state, audit=audit  # type: ignore[arg-type]
    )
    assert "error" not in result
    assert result["edges"][0]["from"] == LOCAL_NODE
    # Cached in state
    assert state.get_topology() is not None
    audit.log.assert_called_once()


@pytest.mark.asyncio
async def test_ssh_scan_topology_handles_scan_error(
    registry: Registry, audit: MagicMock, state: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _boom(*args: Any, **kwargs: Any) -> TopologyResult:
        raise RuntimeError("scan exploded")

    monkeypatch.setattr("mcp_ssh.tools.registry_tools.scan_topology", _boom)
    result = await ssh_scan_topology(
        registry=registry, pool=_Pool(), state=state, audit=audit  # type: ignore[arg-type]
    )
    assert result["error"] == "unexpected_error"


# ---------------------------------------------------------------------------
# setup_jump auto-chain (target=)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_setup_jump_target_builds_and_verifies(
    registry: Registry, audit: MagicMock, state: StateStore
) -> None:
    # Cache a two-hop topology: local -> alibaba -> windows (harvested addr).
    topo = _topo([
        _edge(LOCAL_NODE, "alibaba", "47.91.2.123"),
        _edge("alibaba", "windows", "11.11.0.4"),
    ])
    state.set_topology(topo)
    pool = _Pool()

    res = await setup_jump(
        "auto_win", registry=registry, audit=audit, target="windows",
        pool=pool, state=state,  # type: ignore[arg-type]
    )
    assert res.get("verified") is True
    assert res["target"] == "windows"
    assert res["auto_chain"] == ["alibaba@47.91.2.123", "windows@11.11.0.4"]
    # Verification connected to the alias
    assert "auto_win" in pool.calls
    # Alias exists with the harvested address applied
    alias = registry.get("auto_win")
    assert alias.host == "11.11.0.4"


@pytest.mark.asyncio
async def test_setup_jump_target_no_path(
    registry: Registry, audit: MagicMock, state: StateStore
) -> None:
    # local can reach alibaba but nothing reaches windows.
    state.set_topology(_topo([_edge(LOCAL_NODE, "alibaba", "47.91.2.123")]))
    res = await setup_jump(
        "auto_win", registry=registry, audit=audit, target="windows",
        pool=_Pool(), state=state,  # type: ignore[arg-type]
    )
    assert res["error"] == "no_path"
    assert "gap" in res


@pytest.mark.asyncio
async def test_setup_jump_target_unknown_server(
    registry: Registry, audit: MagicMock, state: StateStore
) -> None:
    state.set_topology(_topo([_edge(LOCAL_NODE, "alibaba", "47.91.2.123")]))
    res = await setup_jump(
        "x", registry=registry, audit=audit, target="ghost",
        pool=_Pool(), state=state,  # type: ignore[arg-type]
    )
    assert res["error"] == "server_not_found"


@pytest.mark.asyncio
async def test_setup_jump_target_stale_cache(
    registry: Registry, audit: MagicMock, state: StateStore
) -> None:
    old = _topo([_edge(LOCAL_NODE, "alibaba", "47.91.2.123")],
                scanned_at=now() - timedelta(seconds=3600))
    state.set_topology(old)
    res = await setup_jump(
        "x", registry=registry, audit=audit, target="alibaba",
        pool=_Pool(), state=state, max_age=60.0,  # type: ignore[arg-type]
    )
    assert res["error"] == "stale_topology"


@pytest.mark.asyncio
async def test_setup_jump_target_force_rescan(
    registry: Registry, audit: MagicMock, state: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    fresh = _topo([_edge(LOCAL_NODE, "alibaba", "47.91.2.123")])

    async def _fake_scan(*args: Any, **kwargs: Any) -> TopologyResult:
        return fresh

    monkeypatch.setattr("mcp_ssh.tools.registry_tools.scan_topology", _fake_scan)
    res = await setup_jump(
        "auto_ali", registry=registry, audit=audit, target="alibaba",
        pool=_Pool(), state=state, force_rescan=True,  # type: ignore[arg-type]
    )
    assert res.get("verified") is True
    # Fresh scan was cached
    assert state.get_topology() is fresh


@pytest.mark.asyncio
async def test_setup_jump_target_no_cache_errors(
    registry: Registry, audit: MagicMock, state: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Per spec: a missing cache without force_rescan is a structured error,
    # never a silent auto-scan.
    scanned = False

    async def _fake_scan(*args: Any, **kwargs: Any) -> TopologyResult:
        nonlocal scanned
        scanned = True
        return _topo([])

    monkeypatch.setattr("mcp_ssh.tools.registry_tools.scan_topology", _fake_scan)
    # No cache set at all
    res = await setup_jump(
        "auto_ali", registry=registry, audit=audit, target="alibaba",
        pool=_Pool(), state=state,  # type: ignore[arg-type]
    )
    assert res["error"] == "no_topology"
    assert scanned is False


@pytest.mark.asyncio
async def test_setup_jump_target_verify_failure_tears_down(
    registry: Registry, audit: MagicMock, state: StateStore
) -> None:
    state.set_topology(_topo([_edge(LOCAL_NODE, "alibaba", "47.91.2.123")]))
    # Verification connect to the alias fails -> alias must be torn down.
    pool = _Pool(fail_on={"auto_ali"})
    res = await setup_jump(
        "auto_ali", registry=registry, audit=audit, target="alibaba",
        pool=pool, state=state,  # type: ignore[arg-type]
    )
    assert res["error"] == "verify_failed"
    from mcp_ssh.exceptions import ServerNotFound
    with pytest.raises(ServerNotFound):
        registry.get("auto_ali")


@pytest.mark.asyncio
async def test_setup_jump_target_multi_hop_verify_failure_removes_all_hops(
    registry: Registry, audit: MagicMock, state: StateStore
) -> None:
    # A 2-hop auto-chain (local -> alibaba -> windows). The post-build verify
    # connect to the alias fails, so BOTH the alias and the generated
    # intermediate hop must be removed — no orphans left in the registry.
    topo = _topo([
        _edge(LOCAL_NODE, "alibaba", "47.91.2.123"),
        _edge("alibaba", "windows", "11.11.0.4"),
    ])
    state.set_topology(topo)
    pool = _Pool(fail_on={"auto_win"})

    res = await setup_jump(
        "auto_win", registry=registry, audit=audit, target="windows",
        pool=pool, state=state,  # type: ignore[arg-type]
    )
    assert res["error"] == "verify_failed"

    from mcp_ssh.exceptions import ServerNotFound
    # The alias is gone.
    with pytest.raises(ServerNotFound):
        registry.get("auto_win")
    # The generated intermediate hop is gone too (no orphan).
    with pytest.raises(ServerNotFound):
        registry.get("_auto_win_hop0")
    # And nothing named like a hop of this chain survives anywhere.
    assert not [
        c.name for c in registry.list_all() if c.name.startswith("_auto_win_hop")
    ]


@pytest.mark.asyncio
async def test_setup_jump_target_hop_summary_reports_via_source(
    registry: Registry, audit: MagicMock, state: StateStore
) -> None:
    # alibaba is reached at its registered host; windows via a harvested addr.
    topo = _topo([
        _edge(LOCAL_NODE, "alibaba", "47.91.2.123"),
        _edge("alibaba", "windows", "11.11.0.4"),
    ])
    state.set_topology(topo)
    pool = _Pool()

    res = await setup_jump(
        "auto_win", registry=registry, audit=audit, target="windows",
        pool=pool, state=state,  # type: ignore[arg-type]
    )
    assert res.get("verified") is True
    hops = res["hops"]
    by_node = {h["node"]: h for h in hops}
    # alibaba's dial addr equals its registered host -> registered.
    assert by_node["alibaba"]["via"] == "47.91.2.123"
    assert by_node["alibaba"]["via_source"] == "registered"
    # windows is reached via a harvested (non-registered) address.
    assert by_node["windows"]["via"] == "11.11.0.4"
    assert by_node["windows"]["via_source"] == "harvested"


@pytest.mark.asyncio
async def test_setup_jump_target_requires_pool_and_state(
    registry: Registry, audit: MagicMock
) -> None:
    res = await setup_jump(
        "x", registry=registry, audit=audit, target="alibaba",
    )
    assert res["error"] == "unavailable"


@pytest.mark.asyncio
async def test_setup_jump_no_chain_no_target(
    registry: Registry, audit: MagicMock
) -> None:
    res = await setup_jump("x", registry=registry, audit=audit)
    assert res["error"] == "invalid_chain"

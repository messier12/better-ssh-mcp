"""Tests for mcp_ssh.topology — harvest parsing, probe verdicts, scan, pathfind."""
from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

import asyncssh
import pytest

from mcp_ssh.models import AuthType, ServerConfig
from mcp_ssh.topology import (
    _HARVEST_MAX_BYTES,
    LOCAL_NODE,
    AddressProbe,
    TopologyEdge,
    TopologyNode,
    TopologyResult,
    _aggregate_cell,
    _classify_error,
    _is_internal_hop,
    _run_capped,
    find_path,
    parse_linux_addrs,
    parse_windows_addrs,
    path_gap_report,
    probe_address,
    scan_topology,
    select_nodes,
)
from mcp_ssh.utils import now

# ---------------------------------------------------------------------------
# Harvest parsers
# ---------------------------------------------------------------------------

LINUX_OUTPUT = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever
2: eth0    inet 10.150.1.71/24 brd 10.150.1.255 scope global eth0\\       valid
3: wg0    inet 11.11.0.4/32 scope global wg0\\       valid_lft forever
4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
5: br-abc123    inet 172.18.0.1/16 scope global br-abc123
6: veth9f    inet 169.254.1.1/16 scope link veth9f
"""


def test_parse_linux_addrs_keeps_real_interfaces() -> None:
    addrs = parse_linux_addrs(LINUX_OUTPUT)
    assert addrs == ["10.150.1.71", "11.11.0.4"]


def test_parse_linux_addrs_drops_loopback_linklocal_and_bridges() -> None:
    addrs = parse_linux_addrs(LINUX_OUTPUT)
    assert "127.0.0.1" not in addrs
    assert "172.17.0.1" not in addrs  # docker0
    assert "172.18.0.1" not in addrs  # br-
    assert "169.254.1.1" not in addrs  # link-local / veth


def test_parse_linux_addrs_empty() -> None:
    assert parse_linux_addrs("") == []
    assert parse_linux_addrs("garbage line no match") == []


WINDOWS_OUTPUT = """\
InterfaceAlias IPAddress
Ethernet 10.150.1.80
Loopback Pseudo-Interface 1 127.0.0.1
vEthernet (WSL) 172.20.0.1
WireGuard 11.11.0.5
"""


def test_parse_windows_addrs_keeps_real_interfaces() -> None:
    addrs = parse_windows_addrs(WINDOWS_OUTPUT)
    assert "10.150.1.80" in addrs
    assert "11.11.0.5" in addrs


def test_parse_windows_addrs_drops_loopback_and_veth() -> None:
    addrs = parse_windows_addrs(WINDOWS_OUTPUT)
    assert "127.0.0.1" not in addrs
    # The vEthernet (WSL) alias case-insensitively prefix-matches "veth", so its
    # NAT address is dropped. This is critical: WSL/docker NAT ranges are
    # identical across hosts, and a surviving 172.20.0.1 would let a source dial
    # its own stack and record a false-positive edge attributed to another node.
    assert "172.20.0.1" not in addrs
    # Real routable interface addresses survive.
    assert "10.150.1.80" in addrs
    assert "11.11.0.5" in addrs


def test_parse_windows_addrs_empty() -> None:
    assert parse_windows_addrs("") == []


# ---------------------------------------------------------------------------
# Verdict mapping — the critical silent-failure surface
# ---------------------------------------------------------------------------


def test_classify_connect_failed_is_refused() -> None:
    exc = asyncssh.ChannelOpenError(2, "Connect failed")
    assert _classify_error(exc) == "refused"


def test_classify_admin_prohibited_is_forwarding_disabled() -> None:
    exc = asyncssh.ChannelOpenError(1, "administratively prohibited")
    assert _classify_error(exc) == "forwarding_disabled"


def test_classify_timeout_is_filtered() -> None:
    assert _classify_error(TimeoutError()) == "filtered"


def test_classify_os_error_is_refused() -> None:
    # asyncio.open_connection (local source) raises OSError, not ChannelOpenError.
    assert _classify_error(ConnectionRefusedError()) == "refused"
    assert _classify_error(OSError("no route")) == "refused"


# ---------------------------------------------------------------------------
# probe_address against a mocked dialer for every verdict branch
# ---------------------------------------------------------------------------


class _FakeReader:
    def __init__(self, data: bytes = b"", hang: bool = False) -> None:
        self._data = data
        self._hang = hang

    async def read(self, n: int = -1) -> bytes:  # noqa: ARG002
        if self._hang:
            await asyncio.sleep(60)
        return self._data


class _FakeWriter:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _dialer_returning(reader: _FakeReader) -> Any:
    writer = _FakeWriter()

    async def dial(addr: str, port: int) -> tuple[_FakeReader, _FakeWriter]:  # noqa: ARG001
        return reader, writer

    return dial, writer


def _dialer_raising(exc: BaseException) -> Any:
    async def dial(addr: str, port: int) -> tuple[Any, Any]:  # noqa: ARG001
        raise exc

    return dial


@pytest.mark.asyncio
async def test_probe_success_records_reachable_and_ssh() -> None:
    dial, writer = _dialer_returning(_FakeReader(b"SSH-2.0-OpenSSH_9.0\r\n"))
    sem = asyncio.Semaphore(4)
    probe = await probe_address(dial, "10.0.0.1", 22, sem, timeout=1.0)
    assert probe.state == "reachable"
    assert probe.is_ssh is True
    assert probe.latency_ms is not None
    assert writer.closed is True


@pytest.mark.asyncio
async def test_probe_success_non_ssh_service_still_reachable() -> None:
    # Open port but no SSH banner: reachable stays true, is_ssh false.
    dial, _ = _dialer_returning(_FakeReader(b"HTTP/1.1 200 OK\r\n"))
    sem = asyncio.Semaphore(4)
    probe = await probe_address(dial, "10.0.0.1", 80, sem, timeout=1.0)
    assert probe.state == "reachable"
    assert probe.is_ssh is False


@pytest.mark.asyncio
async def test_probe_banner_timeout_never_flips_reachable() -> None:
    # Channel opens but the banner read hangs -> is_ssh False, still reachable.
    dial, _ = _dialer_returning(_FakeReader(hang=True))
    sem = asyncio.Semaphore(4)
    probe = await probe_address(dial, "10.0.0.1", 22, sem, timeout=1.0)
    assert probe.state == "reachable"
    assert probe.is_ssh is False


@pytest.mark.asyncio
async def test_probe_connect_failed_is_refused() -> None:
    dial = _dialer_raising(asyncssh.ChannelOpenError(2, "Connect failed"))
    sem = asyncio.Semaphore(4)
    probe = await probe_address(dial, "10.0.0.1", 22, sem, timeout=1.0)
    assert probe.state == "refused"
    assert probe.latency_ms is None


@pytest.mark.asyncio
async def test_probe_admin_prohibited_is_forwarding_disabled() -> None:
    dial = _dialer_raising(asyncssh.ChannelOpenError(1, "prohibited"))
    sem = asyncio.Semaphore(4)
    probe = await probe_address(dial, "10.0.0.1", 22, sem, timeout=1.0)
    assert probe.state == "forwarding_disabled"


@pytest.mark.asyncio
async def test_probe_timeout_is_filtered() -> None:
    async def dial(addr: str, port: int) -> tuple[Any, Any]:  # noqa: ARG001
        await asyncio.sleep(60)
        raise AssertionError("should have timed out")

    sem = asyncio.Semaphore(4)
    probe = await probe_address(dial, "10.0.0.1", 22, sem, timeout=0.05)
    assert probe.state == "filtered"


@pytest.mark.asyncio
async def test_probe_local_os_error_is_refused() -> None:
    # Simulates asyncio.open_connection on a closed local port.
    dial = _dialer_raising(ConnectionRefusedError())
    sem = asyncio.Semaphore(4)
    probe = await probe_address(dial, "127.0.0.1", 22, sem, timeout=1.0)
    assert probe.state == "refused"


# ---------------------------------------------------------------------------
# Cell aggregation
# ---------------------------------------------------------------------------


def test_aggregate_cell_picks_lowest_latency_via() -> None:
    probes = [
        AddressProbe(addr="1.1.1.1", port=22, state="refused"),
        AddressProbe(addr="2.2.2.2", port=22, state="reachable", latency_ms=50.0),
        AddressProbe(addr="3.3.3.3", port=22, state="reachable", latency_ms=10.0),
    ]
    cell = _aggregate_cell("a", "b", probes)
    assert cell.reachable is True
    assert cell.via == "3.3.3.3"  # lowest latency


def test_aggregate_cell_unreachable_has_no_via() -> None:
    probes = [AddressProbe(addr="1.1.1.1", port=22, state="refused")]
    cell = _aggregate_cell("a", "b", probes)
    assert cell.reachable is False
    assert cell.via is None


# ---------------------------------------------------------------------------
# Node selection
# ---------------------------------------------------------------------------


def _cfg(name: str, host: str = "1.2.3.4", port: int = 22) -> ServerConfig:
    return ServerConfig(name=name, host=host, port=port, user="u", auth_type=AuthType.key,
                        key_path="/k")


class _FakeRegistry:
    def __init__(self, servers: list[ServerConfig]) -> None:
        self._servers = {s.name: s for s in servers}

    def list_all(self) -> list[ServerConfig]:
        return list(self._servers.values())

    def get(self, name: str) -> ServerConfig:
        from mcp_ssh.exceptions import ServerNotFound
        try:
            return self._servers[name]
        except KeyError:
            raise ServerNotFound(name) from None


def test_select_nodes_excludes_internal_hops() -> None:
    reg = _FakeRegistry([_cfg("a"), _cfg("_j_hop0"), _cfg("_j_hop1"), _cfg("b")])
    names = [c.name for c in select_nodes(reg, None, None)]
    assert names == ["a", "b"]


def test_select_nodes_include_exclude() -> None:
    reg = _FakeRegistry([_cfg("a"), _cfg("b"), _cfg("c")])
    inc = [c.name for c in select_nodes(reg, ["a", "b"], None)]
    assert inc == ["a", "b"]
    exc = [c.name for c in select_nodes(reg, None, ["b"])]
    assert exc == ["a", "c"]


def test_is_internal_hop() -> None:
    assert _is_internal_hop("_myjump_hop0")
    assert _is_internal_hop("_x_hop12")
    assert not _is_internal_hop("windows")
    assert not _is_internal_hop("_notahop")


# ---------------------------------------------------------------------------
# Full scan orchestration with a fake pool
# ---------------------------------------------------------------------------


class _FakeProcStdout:
    """Chunked stdout reader mimicking asyncssh SSHReader.read(n) semantics."""

    def __init__(self, out: str, chunk: int = 8192) -> None:
        self._buf = out
        self._chunk = chunk
        self.total_read = 0

    async def read(self, n: int = -1) -> str:
        if not self._buf:
            return ""
        take = self._chunk if n < 0 else min(n, self._chunk)
        piece, self._buf = self._buf[:take], self._buf[take:]
        self.total_read += len(piece)
        return piece


class _FakeProc:
    """Fake asyncssh SSHClientProcess supporting incremental stdout reads."""

    def __init__(self, out: str, chunk: int = 8192) -> None:
        self.stdout = _FakeProcStdout(out, chunk)
        self.terminated = False
        self.closed = False

    def terminate(self) -> None:
        self.terminated = True

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class _FakeConn:
    """Fake asyncssh connection: harvest via .create_process, probe via .open_connection."""

    def __init__(
        self,
        harvest_out: str = "",
        open_map: dict[str, Any] | None = None,
        harvest_chunk: int = 8192,
    ) -> None:
        self._harvest_out = harvest_out
        self._open_map = open_map or {}
        self._harvest_chunk = harvest_chunk
        self.last_proc: _FakeProc | None = None

    async def create_process(self, cmd: str, encoding: Any = None, errors: Any = None) -> Any:  # noqa: ARG002
        self.last_proc = _FakeProc(self._harvest_out, self._harvest_chunk)
        return self.last_proc

    async def open_connection(self, addr: str, port: int, encoding: Any = None) -> Any:  # noqa: ARG002
        behavior = self._open_map.get(addr)
        if behavior is None:
            raise asyncssh.ChannelOpenError(2, "refused")
        if isinstance(behavior, BaseException):
            raise behavior
        return _FakeReader(behavior), _FakeWriter()


class _FakePool:
    def __init__(self, conns: dict[str, Any]) -> None:
        self._conns = conns

    async def get_connection(self, name: str) -> Any:
        conn = self._conns.get(name)
        if conn is None or isinstance(conn, BaseException):
            raise conn if isinstance(conn, BaseException) else ConnectionError(f"no conn {name}")
        return conn


@pytest.mark.asyncio
async def test_scan_source_unreachable_row(monkeypatch: pytest.MonkeyPatch) -> None:
    # 'a' connects; 'b' source connection fails -> whole b row source_unreachable.
    reg = _FakeRegistry([_cfg("a", "10.0.0.1"), _cfg("b", "10.0.0.2")])
    conn_a = _FakeConn(harvest_out="", open_map={"10.0.0.2": b"SSH-2.0-x\r\n"})
    pool = _FakePool({"a": conn_a, "b": RuntimeError("boom")})

    # local dialer: refuse everything so it doesn't do real network I/O.
    async def _fake_local_dial(addr: str, port: int) -> Any:  # noqa: ARG001
        raise ConnectionRefusedError()

    monkeypatch.setattr("mcp_ssh.topology._local_dialer", lambda: _fake_local_dial)

    result = await scan_topology(reg, pool, probe_timeout=1.0, harvest_timeout=1.0)
    b_row = [e for e in result.edges if e.from_node == "b"]
    assert b_row, "b should have a source row"
    assert all(e.source_state == "source_unreachable" for e in b_row)
    assert all(e.addresses == [] for e in b_row)
    assert all(e.reachable is False for e in b_row)

    # 'a' can reach 'b'
    a_to_b = next(e for e in result.edges if e.from_node == "a" and e.to_node == "b")
    assert a_to_b.reachable is True
    assert a_to_b.via == "10.0.0.2"


@pytest.mark.asyncio
async def test_scan_forwarding_disabled_row(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _FakeRegistry([_cfg("a", "10.0.0.1"), _cfg("b", "10.0.0.2")])
    # 'a' has forwarding disabled: every open_connection -> ADMIN_PROHIBITED.
    conn_a = _FakeConn(open_map={"10.0.0.2": asyncssh.ChannelOpenError(1, "prohibited")})
    conn_b = _FakeConn(open_map={"10.0.0.1": b"SSH-2.0-x\r\n"})
    pool = _FakePool({"a": conn_a, "b": conn_b})

    async def _fake_local_dial(addr: str, port: int) -> Any:  # noqa: ARG001
        raise ConnectionRefusedError()

    monkeypatch.setattr("mcp_ssh.topology._local_dialer", lambda: _fake_local_dial)

    result = await scan_topology(reg, pool, probe_timeout=1.0, harvest_timeout=1.0)
    a_row = [e for e in result.edges if e.from_node == "a"]
    assert all(e.source_state == "forwarding_disabled" for e in a_row)
    assert all(e.reachable is False for e in a_row)


@pytest.mark.asyncio
async def test_scan_harvest_adds_candidate_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _FakeRegistry([_cfg("a", "10.0.0.1"), _cfg("b", "10.0.0.2")])
    # b harvests an extra wireguard IP; a can reach b only on the harvested IP.
    conn_a = _FakeConn(open_map={"11.11.0.2": b"SSH-2.0-x\r\n"})
    conn_b = _FakeConn(harvest_out="2: eth0    inet 11.11.0.2/32 scope global eth0")
    pool = _FakePool({"a": conn_a, "b": conn_b})

    async def _fake_local_dial(addr: str, port: int) -> Any:  # noqa: ARG001
        raise ConnectionRefusedError()

    monkeypatch.setattr("mcp_ssh.topology._local_dialer", lambda: _fake_local_dial)

    result = await scan_topology(reg, pool, probe_timeout=1.0, harvest_timeout=1.0)
    b_node = next(n for n in result.nodes if n.name == "b")
    assert b_node.harvested is True
    assert "11.11.0.2" in b_node.candidate_addrs
    a_to_b = next(e for e in result.edges if e.from_node == "a" and e.to_node == "b")
    assert a_to_b.reachable is True
    assert a_to_b.via == "11.11.0.2"


@pytest.mark.asyncio
async def test_scan_harvest_failure_falls_back_to_host(monkeypatch: pytest.MonkeyPatch) -> None:
    reg = _FakeRegistry([_cfg("a", "10.0.0.1")])

    class _BadHarvestConn(_FakeConn):
        async def create_process(self, cmd: str, encoding: Any = None, errors: Any = None) -> Any:  # noqa: ARG002
            raise OSError("harvest boom")

    pool = _FakePool({"a": _BadHarvestConn()})

    async def _fake_local_dial(addr: str, port: int) -> Any:  # noqa: ARG001
        raise ConnectionRefusedError()

    monkeypatch.setattr("mcp_ssh.topology._local_dialer", lambda: _fake_local_dial)

    result = await scan_topology(reg, pool, probe_timeout=1.0, harvest_timeout=1.0)
    a_node = next(n for n in result.nodes if n.name == "a")
    assert a_node.harvested is False
    assert a_node.harvest_error is not None
    assert a_node.candidate_addrs == ["10.0.0.1"]


@pytest.mark.asyncio
async def test_run_capped_stops_at_byte_cap() -> None:
    # A host that streams far more than the cap must not be read unbounded:
    # _run_capped reads at most ~_HARVEST_MAX_BYTES and terminates the process.
    flood = "x" * (_HARVEST_MAX_BYTES * 3)
    conn = _FakeConn(harvest_out=flood, harvest_chunk=65_536)
    out = await _run_capped(conn, "flood")  # type: ignore[arg-type]
    assert len(out) == _HARVEST_MAX_BYTES  # bounded prefix only
    assert conn.last_proc is not None
    # Reader was never driven past the cap, and the process was torn down.
    assert conn.last_proc.stdout.total_read == _HARVEST_MAX_BYTES
    assert conn.last_proc.terminated is True
    assert conn.last_proc.closed is True


@pytest.mark.asyncio
async def test_scan_harvest_flood_is_bounded_and_does_not_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A malicious host floods harvest output. The scan must stay bounded and not
    # crash; the capped prefix ("xxx…") is unparseable, so it degrades to the
    # registered host only.
    reg = _FakeRegistry([_cfg("a", "10.0.0.1")])
    flood = "x" * (_HARVEST_MAX_BYTES * 2)
    conn = _FakeConn(harvest_out=flood)
    pool = _FakePool({"a": conn})

    async def _fake_local_dial(addr: str, port: int) -> Any:  # noqa: ARG001
        raise ConnectionRefusedError()

    monkeypatch.setattr("mcp_ssh.topology._local_dialer", lambda: _fake_local_dial)

    result = await scan_topology(reg, pool, probe_timeout=1.0, harvest_timeout=5.0)
    a_node = next(n for n in result.nodes if n.name == "a")
    # Windows fallback also parsed the (unparseable) capped prefix -> no addrs.
    assert a_node.candidate_addrs == ["10.0.0.1"]
    # Each harvest attempt read at most the cap, never the full flood.
    assert conn.last_proc is not None
    assert conn.last_proc.stdout.total_read <= _HARVEST_MAX_BYTES


# ---------------------------------------------------------------------------
# Pathfinder
# ---------------------------------------------------------------------------


def _edge(frm: str, to: str, via: str | None, reachable: bool = True,
          latency: float = 10.0, source_state: str = "ok") -> TopologyEdge:
    addrs = []
    if via is not None:
        addrs = [AddressProbe(addr=via, port=22, state="reachable", latency_ms=latency)]
    return TopologyEdge(
        from_node=frm, to_node=to, reachable=reachable, via=via,
        addresses=addrs, source_state=source_state,  # type: ignore[arg-type]
    )


def _topo(edges: list[TopologyEdge]) -> TopologyResult:
    from mcp_ssh.topology import _build_adjacency
    return TopologyResult(scanned_at=now(), nodes=[], edges=edges,
                          adjacency=_build_adjacency(edges))


def test_find_path_direct() -> None:
    topo = _topo([_edge(LOCAL_NODE, "b", "10.0.0.2")])
    path = find_path(topo, "b")
    assert path == [("b", "10.0.0.2")]


def test_find_path_multi_hop() -> None:
    topo = _topo([
        _edge(LOCAL_NODE, "a", "10.0.0.1"),
        _edge("a", "b", "192.168.0.2"),
    ])
    path = find_path(topo, "b")
    assert path == [("a", "10.0.0.1"), ("b", "192.168.0.2")]


def test_find_path_prefers_fewest_hops() -> None:
    # local->b direct (1 hop, high latency) vs local->a->b (2 hops, low latency).
    topo = _topo([
        _edge(LOCAL_NODE, "b", "10.0.0.9", latency=500.0),
        _edge(LOCAL_NODE, "a", "10.0.0.1", latency=1.0),
        _edge("a", "b", "192.168.0.2", latency=1.0),
    ])
    path = find_path(topo, "b")
    assert path == [("b", "10.0.0.9")]  # fewest hops wins despite latency


def test_find_path_latency_tiebreak() -> None:
    # Two 2-hop paths to c; pick the lower total latency.
    topo = _topo([
        _edge(LOCAL_NODE, "a", "10.0.0.1", latency=1.0),
        _edge(LOCAL_NODE, "b", "10.0.0.2", latency=1.0),
        _edge("a", "c", "192.168.0.3", latency=100.0),
        _edge("b", "c", "192.168.0.3", latency=5.0),
    ])
    path = find_path(topo, "c")
    assert path == [("b", "10.0.0.2"), ("c", "192.168.0.3")]


def test_find_path_no_path() -> None:
    topo = _topo([_edge(LOCAL_NODE, "a", "10.0.0.1")])
    assert find_path(topo, "unreachable") is None


def test_find_path_ignores_forwarding_disabled_edges() -> None:
    topo = _topo([
        _edge(LOCAL_NODE, "a", "10.0.0.1"),
        _edge("a", "b", None, reachable=False, source_state="forwarding_disabled"),
    ])
    assert find_path(topo, "b") is None


def test_path_gap_report() -> None:
    topo = _topo([
        _edge(LOCAL_NODE, "a", "10.0.0.1"),
        _edge("a", "b", "192.168.0.2"),
    ])
    gap = path_gap_report(topo, "z")
    assert gap["target_reachable_anywhere"] is False
    assert "a" in gap["reachable_from_local"]
    assert "b" in gap["reachable_anywhere"]


# ---------------------------------------------------------------------------
# Model serialization round-trip (from/to alias)
# ---------------------------------------------------------------------------


def test_edge_serializes_with_from_to_alias() -> None:
    edge = _edge("a", "b", "1.2.3.4")
    dumped = edge.model_dump(mode="json", by_alias=True)
    assert dumped["from"] == "a"
    assert dumped["to"] == "b"
    # round-trip
    restored = TopologyEdge.model_validate(dumped)
    assert restored.from_node == "a"
    assert restored.to_node == "b"


def test_topology_result_roundtrip() -> None:
    node = TopologyNode(name="a", host="1.2.3.4", port=22, candidate_addrs=["1.2.3.4"])
    result = TopologyResult(scanned_at=now(), nodes=[node],
                            edges=[_edge("a", "b", "1.2.3.4")], adjacency={"a": ["b"]})
    dumped = result.model_dump(mode="json")
    restored = TopologyResult.model_validate(dumped)
    assert restored.nodes[0].name == "a"
    assert restored.edges[0].from_node == "a"


def test_staleness_math() -> None:
    # Sanity: scanned_at in the past yields a positive age.
    result = TopologyResult(scanned_at=now() - timedelta(seconds=120))
    age = (now() - result.scanned_at).total_seconds()
    assert age >= 119

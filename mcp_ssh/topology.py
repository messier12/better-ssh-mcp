"""Server-to-server reachability topology scanning.

Probes reachability between every ordered pair of registered servers, from each
source's own network vantage, producing a directed N×N matrix. Reachability of
B from A is judged by opening an SSH ``direct-tcpip`` channel from A to each of
B's candidate addresses (same primitive as ``ssh -L``); the synthetic ``local``
node (the MCP host) dials directly with ``asyncio.open_connection``.

New Pydantic models live here (not in the frozen ``models.py``) plus the scan
orchestration: harvest interface IPs per reachable node, probe every candidate
address, aggregate into cells. ``setup_jump``'s ``target=`` mode pathfinds over
the cached matrix produced here.
"""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import re
from collections.abc import Awaitable
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol

import asyncssh
from pydantic import BaseModel, Field

from .models import ServerConfig
from .utils import now

if TYPE_CHECKING:
    from .interfaces import IConnectionPool, IRegistry

logger = logging.getLogger(__name__)

# The synthetic source node representing the MCP host itself. Source-only:
# reachability is probed *from* local, but local is never a jump target.
LOCAL_NODE = "local"

# asyncssh ChannelOpenError reason codes (verified against asyncssh 2.22.0):
#   OPEN_ADMINISTRATIVELY_PROHIBITED = 1  -> TCP forwarding disabled on source
#   OPEN_CONNECT_FAILED              = 2  -> source's stack could not connect
_CODE_ADMIN_PROHIBITED = 1
_CODE_CONNECT_FAILED = 2

DEFAULT_PROBE_TIMEOUT = 5.0
DEFAULT_HARVEST_TIMEOUT = 15.0
DEFAULT_CONCURRENCY = 16
_BANNER_TIMEOUT = 2.0
_BANNER_BYTES = 256

# Hard cap on harvest command output. A compromised/malicious host can stream
# unbounded bytes into memory; ``conn.run`` buffers with no limit
# (``communicate`` sets its internal limit to 0), so we read incrementally
# ourselves and stop at this cap. 1 MiB is far more than any real ``ip addr`` /
# Get-NetIPAddress output.
_HARVEST_MAX_BYTES = 1_048_576
_HARVEST_READ_CHUNK = 65_536

# Interface names whose addresses are container bridges / loopback — pure noise
# for cross-host reachability. Matched by prefix.
_SKIP_IFACE_PREFIXES = ("lo", "docker", "br-", "veth")

AddressState = Literal["reachable", "refused", "forwarding_disabled", "filtered"]
SourceState = Literal["ok", "source_unreachable", "forwarding_disabled"]


class AddressProbe(BaseModel):
    """Result of probing a single candidate address of a target from one source."""

    addr:       str
    port:       int
    state:      AddressState
    latency_ms: float | None = None
    is_ssh:     bool = False


class TopologyEdge(BaseModel):
    """A single matrix cell: aggregated probes for the ordered pair (from -> to)."""

    from_node:    str = Field(serialization_alias="from", validation_alias="from")
    to_node:      str = Field(serialization_alias="to", validation_alias="to")
    reachable:    bool
    via:          str | None = None
    addresses:    list[AddressProbe] = Field(default_factory=list)
    source_state: SourceState = "ok"

    model_config = {"populate_by_name": True}


class TopologyNode(BaseModel):
    """A scanned node with its candidate addresses and harvest status."""

    name:               str
    host:               str
    port:               int
    candidate_addrs:    list[str] = Field(default_factory=list)
    harvested:          bool = False
    harvest_error:      str | None = None
    source_only:        bool = False


class TopologyResult(BaseModel):
    """Full topology scan: nodes, directed edges, and a compact adjacency summary."""

    scanned_at: datetime
    nodes:      list[TopologyNode] = Field(default_factory=list)
    edges:      list[TopologyEdge] = Field(default_factory=list)
    adjacency:  dict[str, list[str]] = Field(default_factory=dict)


# A dialer opens a raw TCP-ish stream to (addr, port) and returns the reader and
# a closeable writer. It abstracts over asyncssh direct-tcpip (source = server)
# and asyncio.open_connection (source = local). Exceptions propagate to the
# verdict mapper unchanged.
_Reader = Any
_Writer = Any


class _Dialer(Protocol):
    def __call__(self, addr: str, port: int) -> Awaitable[tuple[_Reader, _Writer]]: ...


# ---------------------------------------------------------------------------
# Pure harvest parsers (unit-tested directly against captured command output)
# ---------------------------------------------------------------------------

_LINUX_ADDR_RE = re.compile(r"^\d+:\s+(\S+)\s+inet\s+([0-9.]+)")


def _skip_iface(name: str) -> bool:
    """Return True if interface *name* is a bridge/loopback we never probe.

    Matched case-insensitively so Windows aliases (``vEthernet``, ``Docker``)
    are dropped the same as their lowercase Linux counterparts. Otherwise a
    WSL/docker NAT address (e.g. 172.20.0.1, identical across hosts) would
    survive and let a source dial its own stack, recording a false-positive
    edge attributed to the wrong node.
    """
    lowered = name.lower()
    return any(lowered == p or lowered.startswith(p) for p in _SKIP_IFACE_PREFIXES)


def _skip_addr(addr: str) -> bool:
    """Return True if *addr* is loopback or link-local (never cross-host reachable)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True
    return ip.is_loopback or ip.is_link_local


def _keep_addr(name: str, addr: str) -> bool:
    """Filter predicate: keep only real, cross-host-plausible interface addresses."""
    return not _skip_iface(name) and not _skip_addr(addr)


def parse_linux_addrs(output: str) -> list[str]:
    """Parse ``ip -o -4 addr`` output into a filtered, de-duplicated address list.

    Lines look like: ``2: eth0    inet 10.0.0.5/24 brd ... scope global eth0``.
    Loopback, link-local, and container-bridge interfaces are dropped.
    """
    addrs: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        m = _LINUX_ADDR_RE.match(line.strip())
        if not m:
            continue
        name, addr = m.group(1), m.group(2)
        if _keep_addr(name, addr) and addr not in seen:
            seen.add(addr)
            addrs.append(addr)
    return addrs


def parse_windows_addrs(output: str) -> list[str]:
    """Parse PowerShell ``Get-NetIPAddress`` output into a filtered address list.

    Expects rows of ``<InterfaceAlias> <IPAddress>`` (e.g. from
    ``Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias,IPAddress``
    or a CSV export). Tokenised loosely so header/blank lines are ignored.
    """
    addrs: list[str] = []
    seen: set[str] = set()
    for raw in output.splitlines():
        line = raw.strip().strip('"')
        if not line:
            continue
        tokens = re.split(r"[\s,]+", line)
        name = tokens[0].strip('"')
        for tok in tokens[1:]:
            tok = tok.strip('"')
            try:
                ipaddress.IPv4Address(tok)
            except (ipaddress.AddressValueError, ValueError):
                continue
            if _keep_addr(name, tok) and tok not in seen:
                seen.add(tok)
                addrs.append(tok)
    return addrs


_HARVEST_LINUX_CMD = "ip -o -4 addr"
_HARVEST_WINDOWS_CMD = (
    "powershell -NoProfile -Command "
    '"Get-NetIPAddress -AddressFamily IPv4 | '
    'ForEach-Object { $_.InterfaceAlias + \' \' + $_.IPAddress }"'
)


async def _run_capped(conn: asyncssh.SSHClientConnection, cmd: str) -> str:
    """Run *cmd* and return at most ``_HARVEST_MAX_BYTES`` of stdout.

    Reads stdout incrementally and stops at the cap so a compromised host that
    streams unbounded output cannot exhaust memory. ``conn.run`` buffers with
    no client-side limit, so we drive the process ourselves via
    ``create_process`` and terminate it on cap. The bounded prefix is returned
    (real harvest output is far under the cap, so a truncated prefix only ever
    results from a misbehaving host, which then simply fails to parse).
    """
    proc = await conn.create_process(cmd, encoding="utf-8", errors="replace")
    try:
        chunks: list[str] = []
        total = 0
        while total < _HARVEST_MAX_BYTES:
            want = min(_HARVEST_READ_CHUNK, _HARVEST_MAX_BYTES - total)
            data = await proc.stdout.read(want)
            if not data:  # EOF
                break
            chunks.append(data)
            total += len(data)
        return "".join(chunks)
    finally:
        # Stop a still-streaming process and reclaim the channel. Cleanup errors
        # must never mask the harvest result.
        with contextlib.suppress(Exception):
            proc.terminate()
        with contextlib.suppress(Exception):
            proc.close()
        with contextlib.suppress(Exception):
            await proc.wait_closed()


async def harvest_addresses(
    conn: asyncssh.SSHClientConnection,
    timeout: float = DEFAULT_HARVEST_TIMEOUT,
) -> list[str]:
    """SSH into a node and collect its real interface IPv4 addresses.

    Tries the Linux ``ip`` command first; falls back to PowerShell on empty /
    failed output (Windows nodes). Output is read client-side with a hard byte
    cap (``_HARVEST_MAX_BYTES``) so a malicious host cannot stream unbounded
    bytes into memory, and the whole read is bounded in time by *timeout*.
    Raises on a total failure so the caller can record the harvest error and
    fall back to the registered host only.
    """
    # Linux attempt.
    try:
        out = await asyncio.wait_for(_run_capped(conn, _HARVEST_LINUX_CMD), timeout=timeout)
        addrs = parse_linux_addrs(out)
        if addrs:
            return addrs
    except (TimeoutError, asyncssh.Error, OSError) as exc:
        logger.debug("Linux harvest failed: %s", exc)

    # Windows fallback. Same byte-capped, time-bounded read; the caller's
    # harvest error handling degrades to "keep registered host only" on any
    # raise here.
    out = await asyncio.wait_for(_run_capped(conn, _HARVEST_WINDOWS_CMD), timeout=timeout)
    return parse_windows_addrs(out)


# ---------------------------------------------------------------------------
# Probe: single address, then aggregate to a cell
# ---------------------------------------------------------------------------


def _classify_error(exc: Exception) -> AddressState:
    """Map a dial exception to an address verdict.

    Handles both asyncssh ``ChannelOpenError`` (server sources) and the
    ``OSError`` family raised by ``asyncio.open_connection`` (local source).
    """
    if isinstance(exc, asyncssh.ChannelOpenError):
        if exc.code == _CODE_ADMIN_PROHIBITED:
            return "forwarding_disabled"
        return "refused"  # CONNECT_FAILED (2) and any other channel-open code
    if isinstance(exc, TimeoutError):
        return "filtered"
    # ConnectionRefusedError etc. from asyncio.open_connection.
    return "refused"


async def _read_banner(reader: _Reader) -> bool:
    """Read the SSH banner with its own short timeout.

    Isolated from reachability: a banner-read timeout returns ``False`` (not
    SSH / unknown) but must never flip ``reachable`` back to false. Reads bytes
    so a non-SSH service cannot trigger a decode error.
    """
    try:
        data: Any = await asyncio.wait_for(reader.read(_BANNER_BYTES), timeout=_BANNER_TIMEOUT)
    except (TimeoutError, asyncssh.Error, OSError):
        return False
    if isinstance(data, str):
        data = data.encode("latin-1", "replace")
    return bool(data) and data.startswith(b"SSH-")


async def probe_address(
    dialer: _Dialer,
    addr: str,
    port: int,
    sem: asyncio.Semaphore,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
) -> AddressProbe:
    """Probe a single (addr, port) via *dialer* under the concurrency semaphore.

    ``reachable`` is decided the instant the channel/stream opens; the SSH
    banner is read separately into ``is_ssh``.
    """
    async with sem:
        loop = asyncio.get_event_loop()
        start = loop.time()
        try:
            reader, writer = await asyncio.wait_for(dialer(addr, port), timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - mapped to a verdict; cancellation propagates
            return AddressProbe(addr=addr, port=port, state=_classify_error(exc))

        latency_ms = (loop.time() - start) * 1000.0
        try:
            is_ssh = await _read_banner(reader)
        finally:
            # Close errors must never affect the verdict.
            with contextlib.suppress(Exception):
                writer.close()
        return AddressProbe(
            addr=addr,
            port=port,
            state="reachable",
            latency_ms=round(latency_ms, 2),
            is_ssh=is_ssh,
        )


def _aggregate_cell(
    from_node: str,
    to_node: str,
    probes: list[AddressProbe],
) -> TopologyEdge:
    """Aggregate per-address probes into a directed matrix cell.

    ``via`` is the lowest-latency reachable address (deterministic tiebreak).
    """
    reachable_probes = [p for p in probes if p.state == "reachable"]
    via: str | None = None
    if reachable_probes:
        best = min(reachable_probes, key=lambda p: (p.latency_ms if p.latency_ms is not None else float("inf")))
        via = best.addr
    return TopologyEdge(
        from_node=from_node,
        to_node=to_node,
        reachable=bool(reachable_probes),
        via=via,
        addresses=probes,
        source_state="ok",
    )


# ---------------------------------------------------------------------------
# Dialer factories
# ---------------------------------------------------------------------------


def _server_dialer(conn: asyncssh.SSHClientConnection) -> _Dialer:
    """Build a dialer that opens a direct-tcpip channel from *conn*'s vantage."""

    async def dial(addr: str, port: int) -> tuple[_Reader, _Writer]:
        return await conn.open_connection(addr, port, encoding=None)

    return dial


def _local_dialer() -> _Dialer:
    """Build a dialer that connects directly from the MCP host (local source)."""

    async def dial(addr: str, port: int) -> tuple[_Reader, _Writer]:
        return await asyncio.open_connection(addr, port)

    return dial


# ---------------------------------------------------------------------------
# Node selection
# ---------------------------------------------------------------------------


def _is_internal_hop(name: str) -> bool:
    """Return True for generated jump-chain hop names (``_<alias>_hopN``)."""
    return bool(re.match(r"^_.+_hop\d+$", name))


def select_nodes(
    registry: IRegistry,
    include: list[str] | None,
    exclude: list[str] | None,
) -> list[ServerConfig]:
    """Return the registered servers to scan, applying include/exclude filters.

    Internal jump-chain hops are excluded by default. ``include`` (if given)
    restricts to exactly those names; ``exclude`` removes names.
    """
    include_set = set(include) if include else None
    exclude_set = set(exclude or [])
    selected: list[ServerConfig] = []
    for cfg in registry.list_all():
        if _is_internal_hop(cfg.name):
            continue
        if include_set is not None and cfg.name not in include_set:
            continue
        if cfg.name in exclude_set:
            continue
        selected.append(cfg)
    return selected


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


async def _harvest_node(
    cfg: ServerConfig,
    pool: IConnectionPool,
    harvest_timeout: float,
    sem: asyncio.Semaphore,
) -> TopologyNode:
    """Harvest a node's candidate addresses. Falls back to the registered host.

    Gated behind *sem* so the scan opens at most ``concurrency`` harvest
    connections at once, bounding the connection fan-out.
    """
    candidates: list[str] = [cfg.host]
    node = TopologyNode(name=cfg.name, host=cfg.host, port=cfg.port, candidate_addrs=candidates)
    async with sem:
        try:
            conn = await pool.get_connection(cfg.name)
        except Exception as exc:  # noqa: BLE001 - harvest is best-effort
            node.harvest_error = str(exc)
            return node
        try:
            harvested = await harvest_addresses(conn, timeout=harvest_timeout)
        except Exception as exc:  # noqa: BLE001 - harvest is best-effort
            node.harvest_error = str(exc)
            return node
    for addr in harvested:
        if addr not in candidates:
            candidates.append(addr)
    node.candidate_addrs = candidates
    node.harvested = True
    return node


async def _scan_row(
    source: str,
    dialer: _Dialer | None,
    targets: list[TopologyNode],
    port_of: dict[str, int],
    sem: asyncio.Semaphore,
    probe_timeout: float,
) -> list[TopologyEdge]:
    """Probe every target's candidate addresses from *source*.

    ``dialer is None`` means the source connection could not be established:
    the whole row is emitted as ``source_unreachable`` with no probes run.
    If any probe returns ``forwarding_disabled``, the row is relabelled
    ``forwarding_disabled`` (a source-global property of the sshd).
    """
    if dialer is None:
        return [
            TopologyEdge(
                from_node=source,
                to_node=t.name,
                reachable=False,
                via=None,
                addresses=[],
                source_state="source_unreachable",
            )
            for t in targets
            if t.name != source
        ]

    edges: list[TopologyEdge] = []
    forwarding_disabled = False
    for target in targets:
        if target.name == source:
            continue
        port = port_of[target.name]
        probes = await asyncio.gather(
            *(probe_address(dialer, addr, port, sem, probe_timeout) for addr in target.candidate_addrs)
        )
        if any(p.state == "forwarding_disabled" for p in probes):
            forwarding_disabled = True
        edges.append(_aggregate_cell(source, target.name, list(probes)))

    if forwarding_disabled:
        # TCP forwarding off is a property of the source sshd: its out-edges are
        # indeterminate and it is unusable as a jump hop.
        for edge in edges:
            edge.source_state = "forwarding_disabled"
            edge.reachable = False
            edge.via = None
    return edges


def _build_adjacency(edges: list[TopologyEdge]) -> dict[str, list[str]]:
    """Compact ``source -> [reachable targets]`` summary for quick reading."""
    adj: dict[str, list[str]] = {}
    for edge in edges:
        if edge.reachable:
            adj.setdefault(edge.from_node, []).append(edge.to_node)
    for targets in adj.values():
        targets.sort()
    return adj


async def scan_topology(
    registry: IRegistry,
    pool: IConnectionPool,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
    harvest_timeout: float = DEFAULT_HARVEST_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> TopologyResult:
    """Run a full server-to-server reachability scan and return the matrix.

    For each selected node A (plus the synthetic ``local`` source), probes
    every candidate address of every other node B from A's own vantage and
    aggregates the verdicts into an N×N directed matrix.
    """
    configs = select_nodes(registry, include, exclude)
    sem = asyncio.Semaphore(concurrency)

    # Harvest candidate addresses per node concurrently.
    nodes = list(
        await asyncio.gather(*(_harvest_node(c, pool, harvest_timeout, sem) for c in configs))
    )
    port_of = {n.name: n.port for n in nodes}

    edges: list[TopologyEdge] = []

    # local is a source-only node: it probes every target but is never a target.
    local_edges = await _scan_row(
        LOCAL_NODE, _local_dialer(), nodes, port_of, sem, probe_timeout
    )
    edges.extend(local_edges)

    # Each server node as a source.
    for node in nodes:
        try:
            conn = await pool.get_connection(node.name)
            dialer: _Dialer | None = _server_dialer(conn)
        except Exception as exc:  # noqa: BLE001 - unreachable source -> whole row
            logger.info("Source %s unreachable: %s", node.name, exc)
            dialer = None
        edges.extend(
            await _scan_row(node.name, dialer, nodes, port_of, sem, probe_timeout)
        )

    return TopologyResult(
        scanned_at=now(),
        nodes=nodes,
        edges=edges,
        adjacency=_build_adjacency(edges),
    )


# ---------------------------------------------------------------------------
# Pathfinding over a cached matrix (consumed by setup_jump target= mode)
# ---------------------------------------------------------------------------


def find_path(topology: TopologyResult, target: str) -> list[tuple[str, str]] | None:
    """Find the fewest-hops path from ``local`` to *target* over reachable edges.

    Latency is the tiebreaker (a chain with fewer tunnels is preferred even if
    its total RTT is marginally higher). Returns a list of
    ``(node, via_address)`` hop tuples excluding ``local``, or ``None`` if no
    path exists.
    """
    # Adjacency of reachable edges: from -> [(to, via, latency)].
    graph: dict[str, list[tuple[str, str, float]]] = {}
    for edge in topology.edges:
        if not edge.reachable or edge.via is None or edge.source_state != "ok":
            continue
        lat = _edge_latency(edge)
        graph.setdefault(edge.from_node, []).append((edge.to_node, edge.via, lat))

    # Dijkstra with lexicographic cost (hop_count, summed_latency).
    import heapq

    # (hop_count, latency_sum, node, path_of_(node, via))
    start: tuple[int, float, str, list[tuple[str, str]]] = (0, 0.0, LOCAL_NODE, [])
    heap: list[tuple[int, float, str, list[tuple[str, str]]]] = [start]
    best: dict[str, tuple[int, float]] = {LOCAL_NODE: (0, 0.0)}

    while heap:
        hops, lat_sum, node, path = heapq.heappop(heap)
        if node == target:
            return path
        for to_node, via, lat in graph.get(node, []):
            if to_node == LOCAL_NODE:
                continue
            cost = (hops + 1, lat_sum + lat)
            if to_node not in best or cost < best[to_node]:
                best[to_node] = cost
                heapq.heappush(heap, (cost[0], cost[1], to_node, [*path, (to_node, via)]))
    return None


def _edge_latency(edge: TopologyEdge) -> float:
    """Latency (ms) of the winning address of *edge*, or 0.0 if unknown."""
    for probe in edge.addresses:
        if probe.addr == edge.via and probe.latency_ms is not None:
            return probe.latency_ms
    return 0.0


def path_gap_report(topology: TopologyResult, target: str) -> dict[str, Any]:
    """Describe why no path to *target* exists (which nodes are reachable)."""
    reachable_from_local = sorted(topology.adjacency.get(LOCAL_NODE, []))
    all_reachable = sorted({e.to_node for e in topology.edges if e.reachable})
    return {
        "reachable_from_local": reachable_from_local,
        "reachable_anywhere": all_reachable,
        "target_reachable_anywhere": target in all_reachable,
    }

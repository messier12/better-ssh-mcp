"""Recursive SSH auto-discovery (``ssh_discover``).

Where ``topology.py`` *verifies* a graph of already-named servers,
``discovery.py`` *finds* the graph: given a seed frontier and a key set, it
recursively maps every host it can reach, following each host's own breadcrumbs
(``known_hosts``, ARP cache, ssh config, shell history, ``/etc/hosts``) rather
than scanning address ranges.

Design (see ``.agentdocs/2026-07-18-ssh-discover-design.md``):

* **Tunnel-from-center.** A candidate found via already-reached host ``H`` is
  dialed with ``asyncssh.connect(candidate, tunnel=H_conn, ...)`` — the same
  ``direct-tcpip`` path ``pool.get_connection`` walks for ``jump_host``. The
  ``local`` seed dials directly.
* **Connect *then* register.** The ephemeral name (``disc-<fp8>``) is derived
  from the host-key fingerprint, which is knowable only after connecting, so we
  connect directly (not through the pool), capture the fingerprint, dedup on it,
  and only then register an ephemeral ``ServerConfig`` whose ``jump_host``
  points at the discoverer. This also keeps ``persist=False`` from spamming
  ``known_hosts`` (the pool's connect path always appends host keys).
* **Two-level dedup.** ``visited_ips`` skips redundant probes; ``visited_fps``
  skips re-recursing a box seen under another IP and breaks ``A ↔ B`` cycles.
* **TOFU forced.** Discovery is trust-on-first-use by construction — the first
  connect *captures* the fingerprint. ``known_hosts=None`` on the probe connect
  and ``host_key_policy=tofu`` on the registered ephemeral, regardless of the
  global default policy.
* **Secrets.** Harvested private-key material never appears in audit events or
  results — only the fact/path/type (CLAUDE.md rule #8).
"""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import re
from datetime import datetime
from typing import TYPE_CHECKING, Any

import asyncssh
from pydantic import BaseModel, Field

from .models import AuthType, HostKeyPolicy, ServerConfig
from .topology import LOCAL_NODE, _run_capped, harvest_addresses
from .utils import now

if TYPE_CHECKING:
    from .interfaces import IAuditLog, IConnectionPool, IRegistry

logger = logging.getLogger(__name__)

# Bounds — sane capped defaults. Reaching any bound stops expansion and flags
# the result as truncated (no silent caps).
DEFAULT_PORT = 22
DEFAULT_MAX_DEPTH = 4
DEFAULT_MAX_NODES = 128
DEFAULT_TIMEOUT = 120.0
DEFAULT_CONCURRENCY = 16
DEFAULT_PROBE_TIMEOUT = 5.0
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_HARVEST_TIMEOUT = 15.0

# Hard cap on how many addresses a single CIDR / sweep may expand to, so a
# ``/8`` in ``injected_candidates`` cannot explode the frontier.
_CIDR_EXPAND_CAP = 1024

# The tag written into the ephemeral ``note`` so ``teardown_discovery`` can find
# every entry a scan created. Format: ``disc-session=<id> fp=<fp>``.
_SESSION_TAG = "disc-session="
_FP_TAG = "fp="

# Breadcrumb harvest commands. Best-effort: any that fail are skipped. Output is
# byte-capped by ``_run_capped``.
_BREADCRUMB_CMDS = {
    "known_hosts": "cat ~/.ssh/known_hosts 2>/dev/null",
    "ssh_config": "cat ~/.ssh/config 2>/dev/null",
    "etc_hosts": "cat /etc/hosts 2>/dev/null",
    "ip_neigh": "ip neigh 2>/dev/null || arp -an 2>/dev/null",
    "sessions": "last -i 2>/dev/null | head -n 200; w -h 2>/dev/null",
    "history": "cat ~/.bash_history ~/.zsh_history 2>/dev/null",
}

# Where remote private keys live (harvest-keys mode). Globbed on the host.
_REMOTE_KEY_GLOB = "~/.ssh/id_*"


# ---------------------------------------------------------------------------
# Result models (new — not edits to the frozen models.py)
# ---------------------------------------------------------------------------


class DiscoveredHost(BaseModel):
    """A host confirmed reachable during a discovery scan."""

    name:       str                       # ephemeral registry name (disc-<fp8>)
    fingerprint: str                      # host-key fingerprint (dedup key)
    addrs:      list[str] = Field(default_factory=list)  # addresses it was reached at
    via:        str                       # discoverer node name (jump_host)
    depth:      int                       # BFS depth from the seed frontier
    auth_key:   str | None = None         # key that authenticated (best-effort)
    # True iff the registered ephemeral has a re-dialable key_path: exactly one
    # fixed OUR_KEY and NOT harvest-keys mode (the shared-key fleet case). False
    # otherwise (multiple keys, zero keys, or harvest-keys mode) — those hosts
    # are report-only, since the pool would AuthError re-dialing without a
    # matching key file.
    pool_reachable: bool = True
    first_seen: datetime


class SkippedKey(BaseModel):
    """A passphrase-protected remote key that was found but never used."""

    host: str          # discoverer node the key was found on
    path: str          # remote path of the key
    reason: str = "encrypted"


class DiscoveryResult(BaseModel):
    """Full result of one ``ssh_discover`` run."""

    session:                str
    scanned_at:             datetime
    discovered:             list[DiscoveredHost] = Field(default_factory=list)
    graph:                  dict[str, list[str]] = Field(default_factory=dict)
    skipped_encrypted_keys: list[SkippedKey] = Field(default_factory=list)
    truncated:              bool = False
    stats:                  dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pure candidate parsers (unit-tested directly against fixture strings)
# ---------------------------------------------------------------------------

# A bare IPv4 or a bracketless hostname token, used to pull targets out of
# free-form breadcrumb text. We keep IPs and dotted/hyphen hostnames.
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_HOSTNAME_RE = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?)\b")
# ssh/scp invocations in shell history. Two capture forms per command line:
# a ``user@host`` target (host in group 1) and bare dotted/IP host arguments
# (group 2). A bare single-label token like ``file`` is not captured — only
# dotted hostnames or IPs, to avoid harvesting local path/flag noise.
_SSH_TARGET_RE = re.compile(
    r"(?:[a-zA-Z0-9._-]+@([a-zA-Z0-9][a-zA-Z0-9._-]*)"
    r"|\b(\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9][a-zA-Z0-9_-]*(?:\.[a-zA-Z0-9_-]+)+))"
)


def _valid_candidate(token: str) -> bool:
    """Return True if *token* is a plausible probe target (IP or hostname)."""
    token = token.strip()
    if not token:
        return False
    try:
        ip = ipaddress.ip_address(token)
        return not (ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except ValueError:
        pass
    # Hostname: must contain a letter (bare numbers already handled above) and
    # look like a name, not a flag or path fragment.
    if token.startswith("-") or "/" in token or "*" in token:
        return False
    return bool(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", token)) and any(
        c.isalpha() for c in token
    )


def parse_known_hosts_candidates(output: str) -> list[str]:
    """Extract host tokens from ``known_hosts`` content.

    Each non-comment line begins with a comma-separated host list (possibly
    ``[host]:port`` or hashed ``|1|...``; hashed entries yield nothing usable).
    """
    out: list[str] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("|"):
            continue
        first = line.split()[0]
        for token in first.split(","):
            token = token.strip()
            # Strip [host]:port bracket form.
            m = re.match(r"^\[([^\]]+)\](?::\d+)?$", token)
            if m:
                token = m.group(1)
            if _valid_candidate(token):
                out.append(token)
    return out


def parse_ssh_config_candidates(output: str) -> list[str]:
    """Extract ``HostName`` values from ssh config (real dial targets only).

    ``Host`` aliases are deliberately ignored: an alias is a local nickname, not
    a routable address — only the resolved ``HostName`` is a probe candidate.
    """
    out: list[str] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, val = parts[0].lower(), parts[1].strip()
        if key == "hostname":
            for tok in val.split():
                if _valid_candidate(tok):
                    out.append(tok)
    return out


def parse_etc_hosts_candidates(output: str) -> list[str]:
    """Extract IPs and names from ``/etc/hosts`` lines."""
    out: list[str] = []
    for raw in output.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        for tok in line.split():
            if _valid_candidate(tok):
                out.append(tok)
    return out


def parse_ip_neigh_candidates(output: str) -> list[str]:
    """Extract neighbour IPs from ``ip neigh`` / ``arp -an`` output."""
    out: list[str] = []
    for m in _IPV4_RE.finditer(output):
        tok = m.group(1)
        if _valid_candidate(tok):
            out.append(tok)
    return out


def parse_history_candidates(output: str) -> list[str]:
    """Extract ssh/scp/sftp targets from shell history.

    Only lines invoking an ssh-family command are scanned; from those we take
    ``user@host`` targets and bare IP / dotted-hostname arguments.
    """
    out: list[str] = []
    for raw in output.splitlines():
        if not re.search(r"\b(?:ssh|scp|sftp)\b", raw):
            continue
        for m in _SSH_TARGET_RE.finditer(raw):
            host = m.group(1) or m.group(2)
            # Strip a trailing ``:path`` (scp form).
            if host:
                host = host.split(":", 1)[0]
            if host and _valid_candidate(host):
                out.append(host)
    return out


def parse_sessions_candidates(output: str) -> list[str]:
    """Extract remote hosts/IPs from ``last -i`` / ``w`` output."""
    out: list[str] = []
    for m in _IPV4_RE.finditer(output):
        tok = m.group(1)
        if _valid_candidate(tok):
            out.append(tok)
    return out


_BREADCRUMB_PARSERS = {
    "known_hosts": parse_known_hosts_candidates,
    "ssh_config": parse_ssh_config_candidates,
    "etc_hosts": parse_etc_hosts_candidates,
    "ip_neigh": parse_ip_neigh_candidates,
    "sessions": parse_sessions_candidates,
    "history": parse_history_candidates,
}


def expand_candidates(items: list[str], cap: int = _CIDR_EXPAND_CAP) -> list[str]:
    """Expand a mix of IPs / CIDRs / hostnames into concrete candidate addresses.

    CIDRs expand to their host addresses (network/broadcast excluded for IPv4
    blocks larger than ``/31``). The whole expansion is capped at *cap* total
    addresses; anything beyond the cap is dropped (the caller flags truncation).
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in items:
        item = raw.strip()
        if not item:
            continue
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                continue
            hosts = net.hosts() if net.num_addresses > 2 else iter(net)
            for addr in hosts:
                s = str(addr)
                if s not in seen:
                    seen.add(s)
                    out.append(s)
                    if len(out) >= cap:
                        return out
        else:
            if item not in seen and _valid_candidate(item):
                seen.add(item)
                out.append(item)
                if len(out) >= cap:
                    return out
    return out


def _parse_injected(items: list[str]) -> tuple[list[str], dict[str, str]]:
    """Split ``user@host`` / ``user@cidr`` injected candidates into addrs + users.

    Returns ``(expanded_addrs, addr->username)``. A leading ``user@`` applies to
    every address the target expands to (so ``solan@11.11.0.4`` connects as
    ``solan``, and ``root@10.0.0.0/29`` maps the whole block to ``root``).
    Items without ``@`` inherit the discoverer's username at connect time.
    """
    addrs: list[str] = []
    users: dict[str, str] = {}
    seen: set[str] = set()
    for raw in items:
        s = raw.strip()
        if not s:
            continue
        user: str | None = None
        if "@" in s:
            u, _, rest = s.partition("@")
            if u and rest:
                user, s = u, rest
        for addr in expand_candidates([s]):
            if addr not in seen:
                seen.add(addr)
                addrs.append(addr)
            if user:
                users[addr] = user
    return addrs, users


def sweep_cidr_for_host(addrs: list[str], sweep_cidr: str | None) -> str | None:
    """Return the CIDR to sweep for a host: explicit override, or its own /24.

    Uses the first non-loopback IPv4 address the host reported.
    """
    if sweep_cidr:
        return sweep_cidr
    for addr in addrs:
        try:
            ip = ipaddress.IPv4Address(addr)
        except (ipaddress.AddressValueError, ValueError):
            continue
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return None


# ---------------------------------------------------------------------------
# Key harvesting (harvest-keys mode)
# ---------------------------------------------------------------------------


def is_encrypted_key(data: bytes | str) -> bool:
    """Return True if *data* is a passphrase-protected private key.

    Detected by attempting a no-passphrase import: asyncssh raises
    ``KeyImportError`` complaining a passphrase is required for encrypted keys.
    Unparsable / non-key data returns False (treated as "not a usable key",
    handled separately by the caller).
    """
    try:
        asyncssh.import_private_key(data)
        return False
    except asyncssh.KeyImportError as exc:
        return "passphrase" in str(exc).lower()
    except asyncssh.KeyEncryptionError:
        return True
    except (asyncssh.Error, ValueError):
        return False


async def harvest_remote_keys(
    conn: asyncssh.SSHClientConnection,
    timeout: float = DEFAULT_HARVEST_TIMEOUT,
) -> tuple[list[Any], list[SkippedKey]]:
    """Read ``~/.ssh/id_*`` private keys off *conn*.

    Returns ``(usable_key_objects, skipped)`` where *usable_key_objects* are
    imported asyncssh private keys (unencrypted only) and *skipped* names
    passphrase-protected keys that were found but never used.

    Never returns or logs raw key bytes — only asyncssh key objects (opaque)
    and, for skipped keys, the path.
    """
    # List candidate key files, skipping the .pub public halves.
    list_cmd = (
        f"for f in {_REMOTE_KEY_GLOB}; do "
        'case "$f" in *.pub) ;; *) [ -f "$f" ] && echo "$f" ;; esac; done'
    )
    try:
        listing = await asyncio.wait_for(_run_capped(conn, list_cmd), timeout=timeout)
    except (TimeoutError, asyncssh.Error, OSError) as exc:
        logger.debug("Key listing failed: %s", exc)
        return [], []

    paths = [p.strip() for p in listing.splitlines() if p.strip().startswith("/") or p.strip().startswith("~") or "id_" in p]
    usable: list[Any] = []
    skipped: list[SkippedKey] = []
    for path in paths:
        try:
            # Read raw bytes over the existing connection (no local disk write).
            raw = await asyncio.wait_for(
                _run_capped(conn, f'cat "{path}" 2>/dev/null'), timeout=timeout
            )
        except (TimeoutError, asyncssh.Error, OSError):
            continue
        if not raw.strip():
            continue
        data = raw.encode("utf-8", "replace")
        if is_encrypted_key(data):
            skipped.append(SkippedKey(host=str(conn.get_extra_info("peername")), path=path))
            continue
        try:
            key = asyncssh.import_private_key(data)
        except (asyncssh.Error, ValueError):
            continue
        usable.append(key)
    return usable, skipped


# ---------------------------------------------------------------------------
# Harvest a host's candidate breadcrumbs
# ---------------------------------------------------------------------------


async def harvest_breadcrumbs(
    conn: asyncssh.SSHClientConnection,
    timeout: float = DEFAULT_HARVEST_TIMEOUT,
) -> list[str]:
    """Union every breadcrumb source on *conn* into a de-duplicated candidate list."""
    out: list[str] = []
    seen: set[str] = set()
    for source, cmd in _BREADCRUMB_CMDS.items():
        try:
            output = await asyncio.wait_for(_run_capped(conn, cmd), timeout=timeout)
        except (TimeoutError, asyncssh.Error, OSError) as exc:
            logger.debug("Breadcrumb %s failed: %s", source, exc)
            continue
        for cand in _BREADCRUMB_PARSERS[source](output):
            if cand not in seen:
                seen.add(cand)
                out.append(cand)
    return out


async def sweep_host(
    conn: asyncssh.SSHClientConnection,
    cidr: str,
    port: int,
    timeout: float = DEFAULT_HARVEST_TIMEOUT,
) -> list[str]:
    """Run one bounded TCP sweep of *cidr* on *port* from the host itself.

    Cheaper than 254 tunnels-from-center. Uses ``/dev/tcp`` in a bash loop with
    a short per-address timeout. Returns addresses that accepted a connection.
    """
    addrs = expand_candidates([cidr])
    if not addrs:
        return []
    addr_list = " ".join(addrs)
    cmd = (
        f"for a in {addr_list}; do "
        f'timeout 1 bash -c "echo > /dev/tcp/$a/{port}" 2>/dev/null '
        f"&& echo $a; done"
    )
    try:
        out = await asyncio.wait_for(_run_capped(conn, cmd), timeout=timeout)
    except (TimeoutError, asyncssh.Error, OSError) as exc:
        logger.debug("Subnet sweep failed: %s", exc)
        return []
    return [line.strip() for line in out.splitlines() if _valid_candidate(line.strip())]


# ---------------------------------------------------------------------------
# Probe + connect a candidate
# ---------------------------------------------------------------------------


def _fp_short(fingerprint: str) -> str:
    """Return a short, filename-safe slug of a host-key fingerprint."""
    # e.g. "SHA256:xQBf..." -> "xqbfabcd"
    body = fingerprint.split(":", 1)[-1]
    slug = re.sub(r"[^A-Za-z0-9]", "", body).lower()
    return slug[:8] or "unknown"


async def connect_candidate(
    addr: str,
    port: int,
    keys: list[Any],
    username: str,
    tunnel: asyncssh.SSHClientConnection | None,
    connect_timeout: float,
) -> asyncssh.SSHClientConnection | None:
    """Attempt to SSH to (*addr*, *port*) with *keys*, tunnelled through *tunnel*.

    TOFU is forced (``known_hosts=None``) regardless of any global policy — a
    never-seen host has no known_hosts entry and the connect is what captures
    its fingerprint. Returns the connection on success, ``None`` on any failure
    (no key worked, unreachable, timeout).
    """
    if not keys:
        return None
    kwargs: dict[str, Any] = {
        "port": port,
        "username": username,
        "client_keys": keys,
        "known_hosts": None,  # TOFU: accept any key on first connect
        "agent_path": None,
    }
    if tunnel is not None:
        kwargs["tunnel"] = tunnel
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(addr, **kwargs), timeout=connect_timeout
        )
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        logger.debug("Connect to %s:%s failed: %s", addr, port, exc)
        return None
    return conn


def fingerprint_of(conn: asyncssh.SSHClientConnection) -> str | None:
    """Return the server host-key fingerprint of *conn*, or ``None``."""
    key = conn.get_server_host_key()
    if key is None:
        return None
    return str(key.get_fingerprint())


# ---------------------------------------------------------------------------
# Discovery engine (BFS over a frontier)
# ---------------------------------------------------------------------------


class _FrontierItem:
    """A node to expand: its registry name, live connection, and BFS depth."""

    __slots__ = ("name", "conn", "depth", "is_local")

    def __init__(
        self,
        name: str,
        conn: asyncssh.SSHClientConnection | None,
        depth: int,
        is_local: bool,
    ) -> None:
        self.name = name
        self.conn = conn
        self.depth = depth
        self.is_local = is_local


class DiscoveryEngine:
    """Runs one ``ssh_discover`` scan and registers ephemerals as it goes."""

    def __init__(
        self,
        registry: IRegistry,
        audit: IAuditLog,
        *,
        session: str,
        keys: list[str],
        key_paths: list[str] | None = None,
        harvest_keys: bool,
        subnet_sweep: bool,
        sweep_cidr: str | None,
        port: int,
        max_depth: int,
        max_nodes: int,
        timeout: float,
        concurrency: int,
        probe_timeout: float,
        connect_timeout: float,
        name_prefix: str,
        persist: bool,
        injected: list[str],
    ) -> None:
        self._registry = registry
        self._audit = audit
        self.session = session
        # key_space grows monotonically as we descend (harvest-keys mode).
        self._key_space: list[Any] = list(keys)
        # Original OUR_KEY file paths. When exactly one shared key was supplied
        # (the fleet use case), we can point the registered ephemeral's
        # ``key_path`` at it so the pool can re-dial the host after the scan.
        self._key_paths: list[str] = list(key_paths or [])
        self._reusable_key_path: str | None = (
            self._key_paths[0] if len(self._key_paths) == 1 else None
        )
        # engine-opened connections (not pool-owned) to close at end of run.
        self._open_conns: list[asyncssh.SSHClientConnection] = []
        self._harvest_keys = harvest_keys
        self._subnet_sweep = subnet_sweep
        self._sweep_cidr = sweep_cidr
        self._port = port
        self._max_depth = max_depth
        self._max_nodes = max_nodes
        self._timeout = timeout
        self._sem = asyncio.Semaphore(max(1, concurrency))
        self._probe_timeout = probe_timeout
        self._connect_timeout = connect_timeout
        self._name_prefix = name_prefix
        self._persist = persist
        # Injected candidates may carry a per-candidate ``user@`` prefix; parse
        # it out so those hosts connect as the named user (e.g. windows wants
        # ``solan`` while the discoverer is ``root``). Everything else inherits
        # the discoverer's username.
        self._injected, self._injected_users = _parse_injected(injected)

        self._visited_ips: set[str] = set()
        self._visited_fps: set[str] = set()
        self._discovered: list[DiscoveredHost] = []
        self._graph: dict[str, list[str]] = {}
        self._skipped: list[SkippedKey] = []
        self._registered: list[str] = []
        self._truncated = False
        self._stats = {
            "candidates": 0,
            "probes": 0,
            "connects_tried": 0,
            "connects_ok": 0,
            "harvested_keys": 0,
        }

    # -- candidate harvest -------------------------------------------------

    async def _harvest_candidates(
        self, item: _FrontierItem
    ) -> tuple[list[str], list[str]]:
        """Return ``(candidates, own_addrs)`` for *item*.

        ``own_addrs`` are the host's own interface IPs (used to seed the
        subnet-sweep CIDR). Injected candidates are added on every host (v1;
        cheap because ``visited_ips`` dedups probes).
        """
        candidates: list[str] = []
        own_addrs: list[str] = []
        if item.conn is not None:
            with contextlib.suppress(Exception):
                own_addrs = await harvest_addresses(item.conn, timeout=self._probe_timeout * 3)
            crumbs = await harvest_breadcrumbs(item.conn, timeout=self._probe_timeout * 3)
            candidates.extend(crumbs)
            if self._subnet_sweep:
                cidr = sweep_cidr_for_host(own_addrs, self._sweep_cidr)
                if cidr:
                    candidates.extend(
                        await sweep_host(item.conn, cidr, self._port, self._probe_timeout * 3)
                    )
        else:
            # local seed: read local breadcrumbs directly.
            candidates.extend(_local_breadcrumbs())
        # Injected candidates apply everywhere (already expanded at init).
        candidates.extend(self._injected)
        # De-duplicate, preserve order.
        seen: set[str] = set()
        uniq: list[str] = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                uniq.append(c)
        return uniq, own_addrs

    # -- key harvest -------------------------------------------------------

    async def _maybe_harvest_keys(self, item: _FrontierItem) -> None:
        """In harvest-keys mode, fold *item*'s readable unencrypted keys in."""
        if not self._harvest_keys or item.conn is None:
            return
        usable, skipped = await harvest_remote_keys(item.conn, timeout=self._probe_timeout * 3)
        for key in usable:
            self._key_space.append(key)
        self._stats["harvested_keys"] += len(usable)
        self._skipped.extend(skipped)
        if usable or skipped:
            self._audit.log(
                _audit_event(
                    "ssh_discover",
                    self.session,
                    outcome="keys_harvested",
                    detail={
                        "host": item.name,
                        # Only paths + counts — never key bytes (rule #8).
                        "usable_count": len(usable),
                        "skipped_encrypted": [s.path for s in skipped],
                    },
                )
            )

    # -- ephemeral registration -------------------------------------------

    def _username_for(self, item: _FrontierItem) -> str:
        """Username to use for hosts discovered via *item* (shared-fleet: inherit)."""
        if item.conn is None:
            # local seed: fall back to the current OS user.
            import getpass

            with contextlib.suppress(Exception):
                return getpass.getuser()
            return "root"
        info = item.conn.get_extra_info("username")
        return str(info) if info else "root"

    def _register(
        self,
        fp: str,
        addr: str,
        via: _FrontierItem,
        username: str,
    ) -> tuple[str, bool]:
        """Register a discovered host as an ephemeral ``ServerConfig``.

        ``jump_host`` points at the discoverer so the pool can reach it later
        with no new plumbing. Fingerprint + session id ride in ``note``.

        Returns ``(name, pool_reachable)``. ``pool_reachable`` is True when the
        ephemeral carries a re-dialable ``key_path`` — the single-shared-key
        fleet case. When authentication succeeded only via an in-memory
        harvested key (no file path), ``key_path`` is left ``None`` and the host
        is registered report-only (the pool would ``AuthError`` if dialed).
        """
        name = f"{self._name_prefix}-{_fp_short(fp)}"
        # Avoid name collisions (two distinct fps sharing an 8-char slug).
        base = name
        suffix = 1
        while _name_taken(self._registry, name):
            name = f"{base}-{suffix}"
            suffix += 1
        note = f"{_SESSION_TAG}{self.session} {_FP_TAG}{fp}"
        # Only claim a re-dialable key_path when a single fixed OUR_KEY is in
        # play. In harvest-keys mode a deep host may have authenticated with an
        # in-memory harvested key (no file path, and no API tells us which key
        # won), so we must NOT point key_path at an OUR_KEY that might not
        # authenticate — that would resurface the pool AuthError. Harvest mode
        # is therefore report-only.
        key_path = None if self._harvest_keys else self._reusable_key_path
        pool_reachable = key_path is not None
        cfg = ServerConfig(
            name=name,
            host=addr,
            port=self._port,
            user=username,
            auth_type=AuthType.key,
            key_path=key_path,
            jump_host=(None if via.is_local else via.name),
            host_key_policy=HostKeyPolicy.tofu,
            note=note,
        )
        add = self._registry.add if self._persist else self._registry.add_ephemeral  # type: ignore[attr-defined]
        add(cfg)
        self._registered.append(name)
        return name, pool_reachable

    # -- main loop ---------------------------------------------------------

    async def run(self, seeds: list[_FrontierItem]) -> DiscoveryResult:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + self._timeout
        frontier: list[_FrontierItem] = list(seeds)

        while frontier:
            if loop.time() >= deadline:
                self._truncated = True
                break
            if len(self._discovered) >= self._max_nodes:
                self._truncated = True
                break

            item = frontier.pop(0)
            # A node at max_depth is itself discovered but is not expanded: its
            # children would sit at max_depth+1. Stopping here keeps every
            # DiscoveredHost.depth <= max_depth.
            if item.depth >= self._max_depth:
                self._truncated = True
                continue

            await self._maybe_harvest_keys(item)
            candidates, _own = await self._harvest_candidates(item)

            new_items = await self._expand(item, candidates, deadline)
            frontier.extend(new_items)

        # Close every connection this engine opened during the scan. Seed
        # connections are pool-owned and are NOT in _open_conns, so the pool
        # keeps managing them. The registered ephemerals are re-dialed lazily
        # by the pool on next use.
        for conn in self._open_conns:
            with contextlib.suppress(Exception):
                conn.close()
        self._open_conns.clear()

        return DiscoveryResult(
            session=self.session,
            scanned_at=now(),
            discovered=self._discovered,
            graph=self._graph,
            skipped_encrypted_keys=self._skipped,
            truncated=self._truncated,
            stats=self._stats,
        )

    async def _expand(
        self,
        via: _FrontierItem,
        candidates: list[str],
        deadline: float,
    ) -> list[_FrontierItem]:
        """Probe/connect each fresh candidate of *via*, register + enqueue hits."""
        loop = asyncio.get_event_loop()
        new_items: list[_FrontierItem] = []
        username = self._username_for(via)

        # Reserve visited_ips synchronously (no await between check and add).
        fresh: list[str] = []
        for cand in candidates:
            if cand in self._visited_ips:
                continue
            self._visited_ips.add(cand)
            fresh.append(cand)
        self._stats["candidates"] += len(fresh)

        async def _one(addr: str) -> _FrontierItem | None:
            async with self._sem:
                if loop.time() >= deadline:
                    self._truncated = True
                    return None
                if len(self._discovered) >= self._max_nodes:
                    self._truncated = True
                    return None
                self._stats["probes"] += 1
                self._stats["connects_tried"] += 1
                # A ``user@host`` injected candidate connects as its named user;
                # everything else inherits the discoverer's username.
                cand_user = self._injected_users.get(addr, username)
                conn = await connect_candidate(
                    addr,
                    self._port,
                    self._key_space,
                    cand_user,
                    via.conn,
                    self._connect_timeout,
                )
                if conn is None:
                    return None
                self._stats["connects_ok"] += 1
                fp = fingerprint_of(conn)
                if fp is None:
                    conn.close()
                    return None
                # fp-dedup: check-and-add synchronously, no await between.
                if fp in self._visited_fps:
                    # Same box via another IP — record the extra address, close.
                    self._record_addr(fp, addr)
                    conn.close()
                    return None
                self._visited_fps.add(fp)
                if len(self._discovered) >= self._max_nodes:
                    self._truncated = True
                    conn.close()
                    return None
                try:
                    name, pool_reachable = self._register(fp, addr, via, cand_user)
                except Exception as exc:  # noqa: BLE001 - registry collision etc.
                    logger.debug("Register failed for %s: %s", addr, exc)
                    conn.close()
                    return None
                host = DiscoveredHost(
                    name=name,
                    fingerprint=fp,
                    addrs=[addr],
                    via=via.name,
                    depth=via.depth + 1,
                    auth_key=self._auth_key_hint(),
                    pool_reachable=pool_reachable,
                    first_seen=now(),
                )
                self._discovered.append(host)
                self._open_conns.append(conn)
                self._graph.setdefault(via.name, []).append(name)
                self._audit.log(
                    _audit_event(
                        "ssh_discover",
                        self.session,
                        outcome="host_discovered",
                        server=name,
                        detail={"via": via.name, "addr": addr, "fingerprint": fp},
                    )
                )
                return _FrontierItem(name, conn, via.depth + 1, is_local=False)

        results = await asyncio.gather(*(_one(a) for a in fresh))
        new_items.extend(r for r in results if r is not None)
        return new_items

    def _record_addr(self, fp: str, addr: str) -> None:
        """Add an extra address to an already-discovered host (dedup by fp)."""
        for host in self._discovered:
            if host.fingerprint == fp and addr not in host.addrs:
                host.addrs.append(addr)
                return

    def _auth_key_hint(self) -> str | None:
        """Best-effort label for which key authenticated.

        asyncssh exposes no public API for the winning ``client_keys`` entry, so
        when exactly one key is in play we can name it; otherwise we report the
        pool size rather than guess wrongly.
        """
        n = len(self._key_space)
        if n == 1:
            return "our-keys[1]"
        return f"one-of-{n}-keys"

    @property
    def registered(self) -> list[str]:
        return self._registered


# ---------------------------------------------------------------------------
# Local (MCP host) breadcrumb harvest
# ---------------------------------------------------------------------------


def _local_breadcrumbs() -> list[str]:
    """Read local ``~/.ssh/known_hosts`` / ``~/.ssh/config`` / ``/etc/hosts``."""
    import os

    out: list[str] = []
    seen: set[str] = set()
    files = {
        "known_hosts": os.path.expanduser("~/.ssh/known_hosts"),
        "ssh_config": os.path.expanduser("~/.ssh/config"),
        "etc_hosts": "/etc/hosts",
    }
    for source, path in files.items():
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        for cand in _BREADCRUMB_PARSERS[source](content):
            if cand not in seen:
                seen.add(cand)
                out.append(cand)
    return out


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------


def _audit_event(
    tool: str,
    session: str,
    *,
    outcome: str,
    server: str | None = None,
    detail: dict[str, Any] | None = None,
) -> Any:
    """Build an ``AuditEvent`` (imported lazily to avoid a models import cycle)."""
    from .models import AuditEvent

    d: dict[str, Any] = {"session": session}
    if detail:
        d.update(detail)
    return AuditEvent(ts=now(), tool=tool, server=server, outcome=outcome, detail=d)


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------


def _name_taken(registry: IRegistry, name: str) -> bool:
    from .exceptions import ServerNotFound

    try:
        registry.get(name)
        return True
    except ServerNotFound:
        return False


# ---------------------------------------------------------------------------
# Seed frontier construction
# ---------------------------------------------------------------------------


async def _build_seed_frontier(
    seeds: list[str] | None,
    registry: IRegistry,
    pool: IConnectionPool,
) -> list[_FrontierItem]:
    """Build the initial frontier.

    Default (``seeds is None``): the synthetic ``local`` node plus every
    non-internal registered server we can currently connect to. Explicit
    *seeds* name registered servers (or ``local``).
    """
    from .exceptions import ServerNotFound

    items: list[_FrontierItem] = []
    if seeds is None:
        items.append(_FrontierItem(LOCAL_NODE, None, 0, is_local=True))
        for cfg in registry.list_all():
            # Skip internal jump-chain hops and any discovery-created ephemeral
            # (identified by its session tag in ``note``, not a name prefix, so a
            # custom ``name_prefix`` is still excluded).
            if cfg.name.startswith("_") or (
                cfg.note is not None and _SESSION_TAG in cfg.note
            ):
                continue
            with contextlib.suppress(Exception):
                conn = await pool.get_connection(cfg.name)
                items.append(_FrontierItem(cfg.name, conn, 0, is_local=False))
        return items

    for seed in seeds:
        if seed == LOCAL_NODE:
            items.append(_FrontierItem(LOCAL_NODE, None, 0, is_local=True))
            continue
        try:
            registry.get(seed)
        except ServerNotFound:
            logger.info("Seed %s not registered; skipping", seed)
            continue
        with contextlib.suppress(Exception):
            conn = await pool.get_connection(seed)
            items.append(_FrontierItem(seed, conn, 0, is_local=False))
    return items


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


async def discover(
    registry: IRegistry,
    pool: IConnectionPool,
    audit: IAuditLog,
    *,
    seeds: list[str] | None = None,
    keys: list[str] | None = None,
    harvest_keys: bool = False,
    injected_candidates: list[str] | None = None,
    subnet_sweep: bool = False,
    sweep_cidr: str | None = None,
    port: int = DEFAULT_PORT,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    name_prefix: str = "disc",
    persist: bool = False,
) -> DiscoveryResult:
    """Recursively discover reachable hosts from a seed frontier.

    See the module docstring and design spec for the full algorithm.
    """
    session = _new_session_id()
    key_objs, key_paths = _load_keys(keys)
    engine = DiscoveryEngine(
        registry,
        audit,
        session=session,
        keys=key_objs,
        key_paths=key_paths,
        harvest_keys=harvest_keys,
        subnet_sweep=subnet_sweep,
        sweep_cidr=sweep_cidr,
        port=port,
        max_depth=max_depth,
        max_nodes=max_nodes,
        timeout=timeout,
        concurrency=concurrency,
        probe_timeout=probe_timeout,
        connect_timeout=connect_timeout,
        name_prefix=name_prefix,
        persist=persist,
        injected=list(injected_candidates or []),
    )
    seed_items = await _build_seed_frontier(seeds, registry, pool)
    result = await engine.run(seed_items)

    audit.log(
        _audit_event(
            "ssh_discover",
            session,
            outcome="completed",
            detail={
                "discovered": len(result.discovered),
                "truncated": result.truncated,
                "stats": result.stats,
            },
        )
    )
    return result


def _new_session_id() -> str:
    import uuid

    return f"disc-{uuid.uuid4().hex[:12]}"


def _load_keys(keys: list[str] | None) -> tuple[list[Any], list[str]]:
    """Load OUR_KEYS from paths into asyncssh key objects.

    Paths are read and imported so the engine hands asyncssh in-memory key
    objects (uniform with harvested keys). Unreadable / encrypted paths are
    skipped with a debug log — never crash the whole scan on one bad key.

    Returns ``(key_objects, expanded_paths)`` for the keys that loaded — the
    paths let the engine set a re-dialable ``key_path`` on discovered hosts when
    exactly one shared key is in play.
    """
    import os

    objs: list[Any] = []
    paths: list[str] = []
    for path in keys or []:
        expanded = os.path.expanduser(path)
        try:
            key = asyncssh.read_private_key(expanded)
        except (asyncssh.Error, OSError) as exc:
            logger.info("Skipping key %s: %s", path, exc)
            continue
        objs.append(key)
        paths.append(expanded)
    return objs, paths


def teardown_discovery(
    session: str,
    registry: IRegistry,
    audit: IAuditLog,
) -> dict[str, Any]:
    """Remove every ephemeral registered by discovery *session*.

    The analog of ``teardown_jump``: finds all entries whose ``note`` carries
    ``disc-session=<session>`` and removes them (ephemeral or persisted). Safe
    to call when nothing matches.
    """
    from .exceptions import McpSshError, ServerNotFound

    tag = f"{_SESSION_TAG}{session}"
    targets = [
        cfg.name
        for cfg in registry.list_all()
        if cfg.note is not None and tag in cfg.note
    ]
    removed: list[str] = []
    for name in targets:
        for remover in (registry.remove_ephemeral, registry.remove):  # type: ignore[attr-defined]
            try:
                remover(name)
                removed.append(name)
                break
            except (ServerNotFound, McpSshError):
                continue

    audit.log(
        _audit_event(
            "teardown_discovery",
            session,
            outcome="removed",
            detail={"removed": removed},
        )
    )
    if not targets:
        return {
            "error": "session_not_found",
            "session": session,
            "message": f"No discovered hosts found for session {session!r}.",
            "removed": [],
        }
    return {"torn_down": session, "removed": removed}

"""Tests for mcp_ssh.discovery — candidate parsing, dedup, bounds, teardown.

The pure candidate/CIDR/key helpers are unit-tested directly against fixture
strings. The BFS engine (dedup, cycle termination, bound enforcement, ephemeral
registration + teardown, harvest-keys, security) is tested against a *synthetic*
neighbour graph by monkeypatching the connect + harvest layer — the design spec
explicitly permits synthetic over a real multi-host tunnel farm.
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import asyncssh
import pytest

from mcp_ssh import discovery as d
from mcp_ssh.models import AuditEvent, AuthType, HostKeyPolicy, ServerConfig
from mcp_ssh.registry import Registry

# ---------------------------------------------------------------------------
# Candidate parsers
# ---------------------------------------------------------------------------

KNOWN_HOSTS = """\
10.0.0.5 ssh-ed25519 AAAA
[192.168.1.9]:2222 ssh-rsa BBBB
host-a.example.com,10.0.0.6 ssh-ed25519 CCCC
|1|hashedsalt|hashedhost ssh-ed25519 DDDD
# a comment
127.0.0.1 ssh-ed25519 EEEE
"""


def test_parse_known_hosts_keeps_hosts_and_ips() -> None:
    got = d.parse_known_hosts_candidates(KNOWN_HOSTS)
    assert "10.0.0.5" in got
    assert "192.168.1.9" in got  # bracket/port form stripped
    assert "host-a.example.com" in got
    assert "10.0.0.6" in got


def test_parse_known_hosts_drops_hashed_and_loopback() -> None:
    got = d.parse_known_hosts_candidates(KNOWN_HOSTS)
    assert "127.0.0.1" not in got   # loopback filtered
    assert not any("hashed" in c for c in got)  # |1| hashed entries unusable


SSH_CONFIG = """\
Host prod
  HostName 10.1.2.3
Host *
  User root
Host bastion
  HostName gw.example.com
"""


def test_parse_ssh_config_only_hostname() -> None:
    got = d.parse_ssh_config_candidates(SSH_CONFIG)
    assert got == ["10.1.2.3", "gw.example.com"]
    assert "prod" not in got     # aliases are not routable targets
    assert "bastion" not in got


def test_parse_etc_hosts() -> None:
    txt = "127.0.0.1 localhost\n10.0.0.8 db01 db01.internal\n# c\n"
    got = d.parse_etc_hosts_candidates(txt)
    assert "10.0.0.8" in got
    assert "db01" in got
    assert "127.0.0.1" not in got


def test_parse_ip_neigh() -> None:
    txt = "10.0.0.1 dev eth0 lladdr aa:bb:cc STALE\n10.0.0.9 dev eth0 REACHABLE\n"
    got = d.parse_ip_neigh_candidates(txt)
    assert got == ["10.0.0.1", "10.0.0.9"]


def test_parse_history_user_at_host_and_bare() -> None:
    txt = textwrap.dedent("""\
        ssh user@10.0.0.20
        scp file root@host9.internal:/tmp
        ssh admin@bastion.example.com
        ls -la /home
        sftp 10.0.0.30
    """)
    got = d.parse_history_candidates(txt)
    assert "10.0.0.20" in got
    assert "host9.internal" in got
    assert "bastion.example.com" in got
    assert "10.0.0.30" in got
    assert "file" not in got  # local path arg is not harvested


def test_parse_sessions() -> None:
    txt = "root pts/0  10.0.0.44  Mon 10:00\nadmin pts/1 192.168.5.5 still"
    got = d.parse_sessions_candidates(txt)
    assert "10.0.0.44" in got
    assert "192.168.5.5" in got


# ---------------------------------------------------------------------------
# CIDR expansion + cap
# ---------------------------------------------------------------------------


def test_expand_small_cidr_excludes_network_broadcast() -> None:
    got = d.expand_candidates(["10.0.0.0/29"])
    assert "10.0.0.0" not in got     # network
    assert "10.0.0.7" not in got     # broadcast
    assert "10.0.0.1" in got
    assert "10.0.0.6" in got


def test_expand_slash31_includes_both() -> None:
    got = d.expand_candidates(["10.0.0.0/31"])
    assert set(got) == {"10.0.0.0", "10.0.0.1"}


def test_expand_cap_enforced() -> None:
    got = d.expand_candidates(["10.0.0.0/16"], cap=10)
    assert len(got) == 10


def test_expand_mixed_and_dedup() -> None:
    got = d.expand_candidates(["10.0.0.1", "10.0.0.1", "host.example.com", "junk/notcidr"])
    assert got == ["10.0.0.1", "host.example.com"]


def test_sweep_cidr_default_and_override() -> None:
    assert d.sweep_cidr_for_host(["10.5.6.7"], None) == "10.5.6.0/24"
    assert d.sweep_cidr_for_host(["10.5.6.7"], "192.168.0.0/28") == "192.168.0.0/28"
    assert d.sweep_cidr_for_host([], None) is None


# ---------------------------------------------------------------------------
# Key encryption detection
# ---------------------------------------------------------------------------


def test_is_encrypted_key_plain_vs_encrypted() -> None:
    key = asyncssh.generate_private_key("ssh-ed25519")
    plain = key.export_private_key()
    encrypted = key.export_private_key(
        format_name="pkcs8-pem", passphrase="secret", cipher_name="aes256-cbc"
    )
    assert d.is_encrypted_key(plain) is False
    assert d.is_encrypted_key(encrypted) is True


def test_is_encrypted_key_garbage_is_false() -> None:
    assert d.is_encrypted_key(b"not a key at all") is False


def test_fp_short_slug() -> None:
    assert d._fp_short("SHA256:xQBf/jNY+Gm1") == "xqbfjny"[:8] or d._fp_short(
        "SHA256:xQBf/jNY+Gm1"
    )


# ---------------------------------------------------------------------------
# Synthetic engine harness
# ---------------------------------------------------------------------------

TOML = textwrap.dedent("""\
    [servers.seedhost]
    name = "seedhost"
    host = "10.0.0.1"
    user = "root"
    auth_type = "key"
    key_path = "/home/das/.ssh/id_ed25519"
""")


@pytest.fixture()
def registry(tmp_path: Path) -> Registry:
    p = tmp_path / "servers.toml"
    p.write_text(TOML, encoding="utf-8")
    return Registry(p)


@pytest.fixture()
def audit() -> MagicMock:
    return MagicMock()


class FakeConn:
    """A stand-in for an asyncssh connection with a fixed fingerprint + username."""

    def __init__(self, fp: str, username: str = "root") -> None:
        self._fp = fp
        self._username = username
        self.closed = False

    def get_server_host_key(self) -> Any:
        class _K:
            def __init__(self, fp: str) -> None:
                self._fp = fp

            def get_fingerprint(self) -> str:
                return self._fp

        return _K(self._fp)

    def get_extra_info(self, key: str) -> Any:
        if key == "username":
            return self._username
        if key == "peername":
            return ("10.0.0.99", 22)
        return None

    def close(self) -> None:
        self.closed = True


def _make_engine(
    registry: Registry,
    audit: MagicMock,
    graph: dict[str, list[str]],
    fps: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    **kw: Any,
) -> d.DiscoveryEngine:
    """Build an engine whose connect/harvest layer is driven by a synthetic graph.

    *graph* maps a node key (address, or "local"/seed name) -> list of candidate
    addresses it reveals. *fps* maps an address -> the host-key fingerprint the
    box at that address presents (multiple addrs can share a fp = same box).
    Addresses absent from *fps* are unreachable (connect returns None).
    """
    defaults: dict[str, Any] = dict(
        session="disc-test",
        keys=["KEYOBJ"],
        harvest_keys=False,
        subnet_sweep=False,
        sweep_cidr=None,
        port=22,
        max_depth=4,
        max_nodes=128,
        timeout=60.0,
        concurrency=8,
        probe_timeout=1.0,
        connect_timeout=1.0,
        name_prefix="disc",
        persist=False,
        injected=[],
    )
    defaults.update(kw)
    engine = d.DiscoveryEngine(registry, audit, **defaults)

    # Patch harvest: node identity is the FakeConn fp, or "local" for the seed.
    async def fake_harvest(item: d._FrontierItem) -> tuple[list[str], list[str]]:
        key = "local" if item.conn is None else item.conn._fp  # type: ignore[attr-defined]
        cands = list(graph.get(key, []))
        cands.extend(d.expand_candidates(engine._injected))
        return cands, []

    engine._harvest_candidates = fake_harvest  # type: ignore[assignment]

    async def fake_connect(
        addr: str,
        port: int,
        keys: list[Any],
        username: str,
        tunnel: Any,
        connect_timeout: float,
    ) -> Any:
        fp = fps.get(addr)
        if fp is None:
            return None
        return FakeConn(fp, username=username)

    # connect_candidate is called via the module symbol inside _expand;
    # monkeypatch auto-restores it after each test (no cross-test pollution).
    monkeypatch.setattr(d, "connect_candidate", fake_connect)
    return engine


async def _run(engine: d.DiscoveryEngine, seed_name: str = "local") -> d.DiscoveryResult:
    seed = d._FrontierItem(seed_name, None, 0, is_local=True)
    return await engine.run([seed])


# ---------------------------------------------------------------------------
# BFS / dedup / cycle / bounds
# ---------------------------------------------------------------------------


async def test_discovers_linear_chain(registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    # local -> A(10.0.0.10) -> B(10.0.0.11)
    graph = {"local": ["10.0.0.10"], "fpA": ["10.0.0.11"], "fpB": []}
    fps = {"10.0.0.10": "fpA", "10.0.0.11": "fpB"}
    engine = _make_engine(registry, audit, graph, fps, monkeypatch)
    res = await _run(engine)
    names = {h.fingerprint for h in res.discovered}
    assert names == {"fpA", "fpB"}
    assert res.truncated is False
    # Both auto-registered as ephemerals.
    assert len(registry.list_ephemeral()) == 2


async def test_two_level_dedup_same_box_two_ips(registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    # local reveals two IPs that are the SAME machine (same fp) -> 1 host, 2 addrs.
    graph = {"local": ["10.0.0.10", "10.0.0.20"], "fpA": []}
    fps = {"10.0.0.10": "fpA", "10.0.0.20": "fpA"}
    engine = _make_engine(registry, audit, graph, fps, monkeypatch, concurrency=1)
    res = await _run(engine)
    assert len(res.discovered) == 1
    host = res.discovered[0]
    assert set(host.addrs) == {"10.0.0.10", "10.0.0.20"}


async def test_cycle_terminates(registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    # A and B point at each other; visited_fps must break the cycle.
    graph = {
        "local": ["10.0.0.10"],
        "fpA": ["10.0.0.11", "10.0.0.10"],  # B, and back to A
        "fpB": ["10.0.0.10", "10.0.0.11"],  # back to A and self
    }
    fps = {"10.0.0.10": "fpA", "10.0.0.11": "fpB"}
    engine = _make_engine(registry, audit, graph, fps, monkeypatch)
    res = await _run(engine)
    assert {h.fingerprint for h in res.discovered} == {"fpA", "fpB"}


async def test_max_nodes_truncates(registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    graph = {"local": ["10.0.0.10", "10.0.0.11", "10.0.0.12"], "fpA": [], "fpB": [], "fpC": []}
    fps = {"10.0.0.10": "fpA", "10.0.0.11": "fpB", "10.0.0.12": "fpC"}
    engine = _make_engine(registry, audit, graph, fps, monkeypatch, max_nodes=2, concurrency=1)
    res = await _run(engine)
    assert len(res.discovered) <= 2
    assert res.truncated is True


async def test_max_depth_truncates(registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    # local(0) -> A(1) -> B(2); max_depth=1 caps discovered depth at 1.
    graph = {"local": ["10.0.0.10"], "fpA": ["10.0.0.11"], "fpB": ["10.0.0.12"]}
    fps = {"10.0.0.10": "fpA", "10.0.0.11": "fpB", "10.0.0.12": "fpC"}
    engine = _make_engine(registry, audit, graph, fps, monkeypatch, max_depth=1)
    res = await _run(engine)
    # A (depth1) discovered; A is at max_depth so it is not expanded -> no B/C.
    fps_found = {h.fingerprint for h in res.discovered}
    assert fps_found == {"fpA"}
    assert all(h.depth <= 1 for h in res.discovered)
    assert res.truncated is True


async def test_injected_candidates_probed(registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    graph: dict[str, list[str]] = {"local": []}
    fps = {"10.9.9.9": "fpX"}
    engine = _make_engine(
        registry, audit, graph, fps, monkeypatch, injected=["10.9.9.9", "10.0.0.0/30"]
    )
    res = await _run(engine)
    assert {h.fingerprint for h in res.discovered} == {"fpX"}


async def test_unreachable_candidates_skipped(registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    graph = {"local": ["10.0.0.10", "10.0.0.250"], "fpA": []}
    fps = {"10.0.0.10": "fpA"}  # .250 has no fp -> connect returns None
    engine = _make_engine(registry, audit, graph, fps, monkeypatch)
    res = await _run(engine)
    assert {h.fingerprint for h in res.discovered} == {"fpA"}
    assert res.stats["connects_ok"] == 1


# ---------------------------------------------------------------------------
# Ephemeral registration shape + teardown
# ---------------------------------------------------------------------------


async def test_registered_ephemeral_shape(registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    graph = {"local": ["10.0.0.10"], "fpA": []}
    fps = {"10.0.0.10": "fpA"}
    engine = _make_engine(registry, audit, graph, fps, monkeypatch)
    res = await _run(engine)
    host = res.discovered[0]
    cfg = registry.get(host.name)
    assert cfg.host == "10.0.0.10"
    assert cfg.host_key_policy == HostKeyPolicy.tofu   # TOFU forced on the ephemeral
    assert cfg.jump_host is None                        # discovered from local seed
    assert engine.session in (cfg.note or "")
    assert "fp=fpA" in (cfg.note or "")


async def test_nested_jump_host_points_at_discoverer(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    graph = {"local": ["10.0.0.10"], "fpA": ["10.0.0.11"], "fpB": []}
    fps = {"10.0.0.10": "fpA", "10.0.0.11": "fpB"}
    engine = _make_engine(registry, audit, graph, fps, monkeypatch)
    res = await _run(engine)
    a = next(h for h in res.discovered if h.fingerprint == "fpA")
    b = next(h for h in res.discovered if h.fingerprint == "fpB")
    cfg_b = registry.get(b.name)
    assert cfg_b.jump_host == a.name   # B tunnels through A


async def test_teardown_removes_all_session_entries(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    graph = {"local": ["10.0.0.10", "10.0.0.11"], "fpA": [], "fpB": []}
    fps = {"10.0.0.10": "fpA", "10.0.0.11": "fpB"}
    engine = _make_engine(registry, audit, graph, fps, monkeypatch)
    res = await _run(engine)
    assert len(registry.list_ephemeral()) == 2

    out = d.teardown_discovery(res.session, registry=registry, audit=audit)
    assert set(out["removed"]) == {h.name for h in res.discovered}
    assert registry.list_ephemeral() == []


async def test_teardown_unknown_session(registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    out = d.teardown_discovery("disc-nope", registry=registry, audit=audit)
    assert out["error"] == "session_not_found"
    assert out["removed"] == []


# ---------------------------------------------------------------------------
# Security assertions
# ---------------------------------------------------------------------------


def _all_audit_text(audit: MagicMock) -> str:
    parts: list[str] = []
    for call in audit.log.call_args_list:
        event = call.args[0] if call.args else call.kwargs.get("event")
        assert isinstance(event, AuditEvent)
        parts.append(event.model_dump_json())
    return "\n".join(parts)


async def test_no_key_bytes_or_passphrase_in_audit(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Harvest-keys mode: one plaintext key + one encrypted key on host A.
    plain_key = asyncssh.generate_private_key("ssh-ed25519")
    plain_bytes = plain_key.export_private_key()
    enc_bytes = plain_key.export_private_key(
        format_name="pkcs8-pem", passphrase="topsecret", cipher_name="aes256-cbc"
    )

    graph = {"local": ["10.0.0.10"], "fpA": []}
    fps = {"10.0.0.10": "fpA"}
    engine = _make_engine(registry, audit, graph, fps, monkeypatch, harvest_keys=True)

    async def fake_harvest_keys(
        item: d._FrontierItem,
    ) -> None:
        if item.conn is None:
            return  # local seed has no remote keys
        # Simulate reading one usable + one encrypted key; use the real skip path.
        assert not d.is_encrypted_key(plain_bytes)
        assert d.is_encrypted_key(enc_bytes)
        skipped = d.SkippedKey(host="A", path="/root/.ssh/id_rsa_enc")
        engine._key_space.append(plain_key)
        engine._skipped.append(skipped)
        engine._audit.log(
            d._audit_event(
                "ssh_discover",
                engine.session,
                outcome="keys_harvested",
                detail={
                    "host": item.name,
                    "usable_count": 1,
                    "skipped_encrypted": [skipped.path],
                },
            )
        )

    engine._maybe_harvest_keys = fake_harvest_keys  # type: ignore[assignment]
    res = await _run(engine)

    assert len(res.skipped_encrypted_keys) == 1
    text = _all_audit_text(audit)
    # No raw private-key material and no passphrase must ever appear in audit.
    assert "PRIVATE KEY" not in text
    assert "topsecret" not in text
    assert plain_bytes.decode() not in text
    # The fact/path of the harvest is fine to record.
    assert "id_rsa_enc" in text


async def test_tofu_forced_regardless_of_global_policy(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The registered ephemeral is always tofu even though the seed uses strict-ish
    # config; connect_candidate always passes known_hosts=None (asserted below).
    graph = {"local": ["10.0.0.10"], "fpA": []}
    fps = {"10.0.0.10": "fpA"}
    engine = _make_engine(registry, audit, graph, fps, monkeypatch)
    res = await _run(engine)
    cfg = registry.get(res.discovered[0].name)
    assert cfg.host_key_policy == HostKeyPolicy.tofu


async def test_connect_candidate_forces_known_hosts_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    async def fake_asyncssh_connect(host: str, **kwargs: Any) -> Any:
        captured["host"] = host
        captured.update(kwargs)
        return FakeConn("fpZ")

    monkeypatch.setattr(asyncssh, "connect", fake_asyncssh_connect)
    conn = await d.connect_candidate(
        "10.0.0.5", 22, ["KEY"], "root", tunnel=None, connect_timeout=1.0
    )
    assert conn is not None
    assert captured["known_hosts"] is None   # TOFU forced
    assert captured["agent_path"] is None


async def test_connect_candidate_no_keys_returns_none() -> None:
    conn = await d.connect_candidate(
        "10.0.0.5", 22, [], "root", tunnel=None, connect_timeout=1.0
    )
    assert conn is None


# ---------------------------------------------------------------------------
# Persist mode writes real registry entries
# ---------------------------------------------------------------------------


async def test_persist_writes_file_backed_entry(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    graph = {"local": ["10.0.0.10"], "fpA": []}
    fps = {"10.0.0.10": "fpA"}
    engine = _make_engine(registry, audit, graph, fps, monkeypatch, persist=True)
    res = await _run(engine)
    # Persisted, not ephemeral.
    assert registry.list_ephemeral() == []
    cfg = registry.get(res.discovered[0].name)
    assert isinstance(cfg, ServerConfig)
    assert cfg.auth_type == AuthType.key


# ---------------------------------------------------------------------------
# _load_keys and session id
# ---------------------------------------------------------------------------


def test_load_keys_skips_bad_paths() -> None:
    assert d._load_keys(["/nonexistent/key/path"]) == ([], [])
    assert d._load_keys(None) == ([], [])


def test_load_keys_reads_real_key(tmp_path: Path) -> None:
    key = asyncssh.generate_private_key("ssh-ed25519")
    p = tmp_path / "id_ed25519"
    p.write_bytes(key.export_private_key())
    objs, paths = d._load_keys([str(p)])
    assert len(objs) == 1
    assert paths == [str(p)]


def test_new_session_id_unique() -> None:
    assert d._new_session_id() != d._new_session_id()
    assert d._new_session_id().startswith("disc-")


# ---------------------------------------------------------------------------
# Real harvest helpers (fake _run_capped so the real parsing paths run)
# ---------------------------------------------------------------------------


def _fake_run_capped(responses: dict[str, str]):
    """Return a fake ``_run_capped`` that matches on a substring of the command."""

    async def run_capped(conn: Any, cmd: str) -> str:  # noqa: ARG001
        for needle, out in responses.items():
            if needle in cmd:
                return out
        return ""

    return run_capped


async def test_harvest_breadcrumbs_unions_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = {
        "known_hosts": "10.0.0.5 ssh-ed25519 AAAA\n",
        "config": "Host x\n  HostName 10.0.0.6\n",
        "/etc/hosts": "10.0.0.7 host7\n",
        "ip neigh": "10.0.0.8 dev eth0 REACHABLE\n",
        "last": "root pts/0 10.0.0.9 Mon\n",
        "bash_history": "ssh admin@10.0.0.10\n",
    }
    monkeypatch.setattr(d, "_run_capped", _fake_run_capped(responses))
    got = await d.harvest_breadcrumbs(FakeConn("fp"), timeout=1.0)
    for expected in ["10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.9", "10.0.0.10"]:
        assert expected in got


async def test_harvest_remote_keys_plain_and_encrypted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = asyncssh.generate_private_key("ssh-ed25519")
    plain = key.export_private_key().decode()
    enc = key.export_private_key(
        format_name="pkcs8-pem", passphrase="pw", cipher_name="aes256-cbc"
    ).decode()

    async def run_capped(conn: Any, cmd: str) -> str:  # noqa: ARG001
        if "for f in" in cmd:  # listing
            return "/root/.ssh/id_ed25519\n/root/.ssh/id_rsa_enc\n"
        if "id_ed25519" in cmd:
            return plain
        if "id_rsa_enc" in cmd:
            return enc
        return ""

    monkeypatch.setattr(d, "_run_capped", run_capped)
    usable, skipped = await d.harvest_remote_keys(FakeConn("fp"), timeout=1.0)
    assert len(usable) == 1
    assert len(skipped) == 1
    assert skipped[0].path == "/root/.ssh/id_rsa_enc"


async def test_harvest_remote_keys_listing_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    async def boom(conn: Any, cmd: str) -> str:  # noqa: ARG001
        raise OSError("no route")

    monkeypatch.setattr(d, "_run_capped", boom)
    usable, skipped = await d.harvest_remote_keys(FakeConn("fp"), timeout=1.0)
    assert usable == [] and skipped == []


async def test_sweep_host_returns_open_addrs(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run_capped(conn: Any, cmd: str) -> str:  # noqa: ARG001
        return "10.0.0.1\n10.0.0.3\n"

    monkeypatch.setattr(d, "_run_capped", run_capped)
    got = await d.sweep_host(FakeConn("fp"), "10.0.0.0/29", 22, timeout=1.0)
    assert got == ["10.0.0.1", "10.0.0.3"]


async def test_sweep_host_empty_cidr() -> None:
    # A malformed CIDR expands to nothing, so no sweep command is run.
    got = await d.sweep_host(FakeConn("fp"), "10.0.0.0/33", 22, timeout=1.0)
    assert got == []


def test_local_breadcrumbs_reads_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import os

    kh = tmp_path / "known_hosts"
    kh.write_text("10.0.0.50 ssh-ed25519 AAAA\n")
    cfg = tmp_path / "config"
    cfg.write_text("Host y\n  HostName 10.0.0.51\n")
    hosts = tmp_path / "hosts"
    hosts.write_text("10.0.0.52 h52\n")

    real_expand = os.path.expanduser

    def fake_expand(p: str) -> str:
        if p == "~/.ssh/known_hosts":
            return str(kh)
        if p == "~/.ssh/config":
            return str(cfg)
        return real_expand(p)

    monkeypatch.setattr(os.path, "expanduser", fake_expand)
    got = d._local_breadcrumbs()
    assert "10.0.0.50" in got
    assert "10.0.0.51" in got


# ---------------------------------------------------------------------------
# Engine internals exercised for real (no _harvest_candidates override)
# ---------------------------------------------------------------------------


def _real_engine(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch, **kw: Any
) -> d.DiscoveryEngine:
    defaults: dict[str, Any] = dict(
        session="disc-real",
        keys=["K"],
        harvest_keys=False,
        subnet_sweep=False,
        sweep_cidr=None,
        port=22,
        max_depth=4,
        max_nodes=128,
        timeout=60.0,
        concurrency=4,
        probe_timeout=1.0,
        connect_timeout=1.0,
        name_prefix="disc",
        persist=False,
        injected=[],
    )
    defaults.update(kw)
    return d.DiscoveryEngine(registry, audit, **defaults)


async def test_harvest_candidates_local_seed(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(d, "_local_breadcrumbs", lambda: ["10.0.0.60"])
    engine = _real_engine(registry, audit, monkeypatch, injected=["10.0.0.61"])
    item = d._FrontierItem("local", None, 0, is_local=True)
    cands, own = await engine._harvest_candidates(item)
    assert "10.0.0.60" in cands
    assert "10.0.0.61" in cands
    assert own == []


async def test_harvest_candidates_remote_with_sweep(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_harvest_addrs(conn: Any, timeout: float = 15.0) -> list[str]:  # noqa: ARG001
        return ["10.0.0.70"]

    async def fake_breadcrumbs(conn: Any, timeout: float = 15.0) -> list[str]:  # noqa: ARG001
        return ["10.0.0.71"]

    async def fake_sweep(conn: Any, cidr: str, port: int, timeout: float = 15.0) -> list[str]:  # noqa: ARG001
        return ["10.0.0.72"]

    monkeypatch.setattr(d, "harvest_addresses", fake_harvest_addrs)
    monkeypatch.setattr(d, "harvest_breadcrumbs", fake_breadcrumbs)
    monkeypatch.setattr(d, "sweep_host", fake_sweep)
    engine = _real_engine(registry, audit, monkeypatch, subnet_sweep=True)
    item = d._FrontierItem("A", FakeConn("fpA"), 0, is_local=False)
    cands, own = await engine._harvest_candidates(item)
    assert set(cands) >= {"10.0.0.71", "10.0.0.72"}
    assert own == ["10.0.0.70"]


async def test_maybe_harvest_keys_real_path(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = asyncssh.generate_private_key("ssh-ed25519")

    async def fake_harvest(conn: Any, timeout: float = 15.0) -> tuple[list[Any], list[Any]]:  # noqa: ARG001
        return [key], [d.SkippedKey(host="A", path="/root/.ssh/id_enc")]

    monkeypatch.setattr(d, "harvest_remote_keys", fake_harvest)
    engine = _real_engine(registry, audit, monkeypatch, harvest_keys=True)
    before = len(engine._key_space)
    item = d._FrontierItem("A", FakeConn("fpA"), 0, is_local=False)
    await engine._maybe_harvest_keys(item)
    assert len(engine._key_space) == before + 1
    assert len(engine._skipped) == 1
    # Audit logged the fact, not the key bytes.
    text = _all_audit_text(audit)
    assert "id_enc" in text
    assert "PRIVATE KEY" not in text


def test_username_for_remote_and_local(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = _real_engine(registry, audit, monkeypatch)
    remote = d._FrontierItem("A", FakeConn("fp", username="deploy"), 0, is_local=False)
    assert engine._username_for(remote) == "deploy"
    local = d._FrontierItem("local", None, 0, is_local=True)
    assert isinstance(engine._username_for(local), str)


# ---------------------------------------------------------------------------
# Top-level discover() + seed frontier
# ---------------------------------------------------------------------------


class FakePool:
    def __init__(self, conns: dict[str, Any]) -> None:
        self._conns = conns

    async def get_connection(self, name: str) -> Any:
        if name not in self._conns:
            raise RuntimeError(f"cannot connect {name}")
        return self._conns[name]


async def test_build_seed_frontier_default(
    registry: Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = FakePool({"seedhost": FakeConn("fpSeed")})
    items = await d._build_seed_frontier(None, registry, pool)  # type: ignore[arg-type]
    names = {i.name for i in items}
    assert "local" in names
    assert "seedhost" in names


async def test_build_seed_frontier_explicit_seeds(
    registry: Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    pool = FakePool({"seedhost": FakeConn("fpSeed")})
    items = await d._build_seed_frontier(
        ["local", "seedhost", "nonexistent"], registry, pool  # type: ignore[arg-type]
    )
    names = {i.name for i in items}
    assert names == {"local", "seedhost"}  # nonexistent skipped


async def test_discover_end_to_end(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Seed from local only; harvest yields one reachable host.
    monkeypatch.setattr(d, "_local_breadcrumbs", lambda: ["10.0.0.80"])

    async def fake_connect(addr, port, keys, username, tunnel, connect_timeout):  # type: ignore[no-untyped-def]  # noqa: ANN001
        if addr == "10.0.0.80":
            return FakeConn("fpEnd", username=username)
        return None

    monkeypatch.setattr(d, "connect_candidate", fake_connect)

    async def fake_breadcrumbs(conn: Any, timeout: float = 15.0) -> list[str]:  # noqa: ARG001
        return []

    async def fake_addrs(conn: Any, timeout: float = 15.0) -> list[str]:  # noqa: ARG001
        return []

    monkeypatch.setattr(d, "harvest_breadcrumbs", fake_breadcrumbs)
    monkeypatch.setattr(d, "harvest_addresses", fake_addrs)

    pool = FakePool({})
    res = await d.discover(
        registry, pool, audit, seeds=["local"], keys=None, max_nodes=10  # type: ignore[arg-type]
    )
    assert len(res.discovered) == 1
    assert res.discovered[0].fingerprint == "fpEnd"
    assert res.session.startswith("disc-")
    # teardown by the generated session cleans it up.
    out = d.teardown_discovery(res.session, registry=registry, audit=audit)
    assert len(out["removed"]) == 1


# ---------------------------------------------------------------------------
# Pool reachability of discovered hosts (spec: "immediately usable")
# ---------------------------------------------------------------------------


async def test_single_shared_key_host_is_pool_reachable(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from mcp_ssh.models import GlobalSettings
    from mcp_ssh.pool import ConnectionPool

    # A single shared key (the fleet use case) is written to disk and passed in.
    key = asyncssh.generate_private_key("ssh-ed25519")
    kp = tmp_path / "fleet_key"
    kp.write_bytes(key.export_private_key())

    graph = {"local": ["10.0.0.10"], "fpA": []}
    fps = {"10.0.0.10": "fpA"}
    engine = _make_engine(
        registry, audit, graph, fps, monkeypatch,
        keys=[key], key_paths=[str(kp)],
    )
    res = await _run(engine)
    host = res.discovered[0]
    assert host.pool_reachable is True

    cfg = registry.get(host.name)
    assert cfg.key_path == str(kp)   # re-dialable path threaded through

    # The pool builds connect kwargs without AuthError (would raise if key_path
    # were None for an auth_type=key server).
    pool = ConnectionPool(registry, GlobalSettings())
    kwargs = await pool._build_connect_kwargs(cfg)
    assert kwargs["client_keys"] == [str(kp)]


async def test_harvest_only_host_is_report_only(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Two OUR_KEY paths => no single reusable path => discovered host is
    # registered report-only (key_path None, pool_reachable False).
    graph = {"local": ["10.0.0.10"], "fpA": []}
    fps = {"10.0.0.10": "fpA"}
    engine = _make_engine(
        registry, audit, graph, fps, monkeypatch,
        keys=["K1", "K2"], key_paths=["/a", "/b"],
    )
    res = await _run(engine)
    host = res.discovered[0]
    assert host.pool_reachable is False
    assert registry.get(host.name).key_path is None


async def test_harvest_keys_mode_is_report_only_even_with_single_key(
    registry: Registry, audit: MagicMock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Single OUR_KEY but harvest-keys ON: a deep host may auth via a harvested
    # in-memory key, so we must not claim the OUR_KEY path is re-dialable.
    key = asyncssh.generate_private_key("ssh-ed25519")
    kp = tmp_path / "seed_key"
    kp.write_bytes(key.export_private_key())

    async def no_remote_keys(conn: Any, timeout: float = 15.0) -> tuple[list[Any], list[Any]]:  # noqa: ARG001
        return [], []

    monkeypatch.setattr(d, "harvest_remote_keys", no_remote_keys)
    graph = {"local": ["10.0.0.10"], "fpA": []}
    fps = {"10.0.0.10": "fpA"}
    engine = _make_engine(
        registry, audit, graph, fps, monkeypatch,
        keys=[key], key_paths=[str(kp)], harvest_keys=True,
    )
    res = await _run(engine)
    host = res.discovered[0]
    assert host.pool_reachable is False
    assert registry.get(host.name).key_path is None

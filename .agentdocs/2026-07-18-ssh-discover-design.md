# Design: `ssh_discover` — recursive SSH auto-discovery

**Date:** 2026-07-18
**Status:** Proposed (awaiting spec review)
**Branch:** `ssh_crawl`

## Problem

`ssh_scan_topology` *verifies* a graph we already know: it takes the set of
**named, registered** servers, harvests each one's interface IPs, and probes
`named-source → named-target` to build a reachability matrix.

That is the wrong tool when we don't yet know the nodes. Concretely: you spin up
N cloud servers that all share one key, and naming each one to the agent by hand
is tedious and error-prone. We want the inverse operation — **discovery**: given
a set of credentials and a starting point, recursively map out every host we can
reach, including hosts we never named.

### Why the naive algorithm doesn't work

The sketched approach —

```
scan(keys_from_source, keys_from_this_server):
  key_space = keys_from_source + keys_from_this_server
  for (candidate_ip × port × key) in full product:
    if can connect: connect and recurse
```

— has two fatal problems:

1. **`candidate_ip × port` is unbounded.** Brute-forcing address space is
   infeasible and abusive. The cleverness cannot be in *how* we scan a range; it
   must be in *never scanning a range*. A host **already knows its neighbors**
   (`known_hosts`, ARP cache, ssh config, shell history). We harvest candidate
   *targets* from each host we land on — turning "brute-force the network" into
   "follow each host's breadcrumbs".

2. **The `× key` inner loop is redundant.** asyncssh accepts a *list* of
   `client_keys` per connection and tries them itself. We loop candidates and
   hand asyncssh the whole key set — no nested key loop.

## Goals

- Recursively discover reachable hosts from a starting frontier, following
  breadcrumbs rather than scanning ranges.
- Reuse existing machinery: ephemeral registry entries + `jump_host`
  tunnel-from-center + the harvest/probe helpers in `topology.py`.
- Make every discovered host **immediately usable** (auto-registered) and
  **cleanly removable** (session-scoped teardown).
- Support two credential modes: our fixed keys, and keys harvested off hosts as
  we go.

## Non-goals

- Replacing `ssh_scan_topology`. This is **additive**; the verify-known-graph
  tool keeps its role.
- Cloud-provider metadata/API integration (explicitly dropped — too
  provider-specific for v1).
- Hop-in-place / driving `ssh` remotely. We tunnel from the center for
  centralized control and auditing.

## Mechanism

**Tunnel-from-center.** To reach a discovered host `H2` found via already-reached
host `H1`, we open a `direct-tcpip` channel through `H1`'s connection and run SSH
over it from the MCP host — the exact path `pool.get_connection()` already walks
when a `ServerConfig` has `jump_host` set.

Each confirmed host is auto-registered as an **ephemeral `ServerConfig`** whose
`jump_host` points at its discoverer. Consequences:

- The pool can reach it immediately with no new plumbing.
- It participates in the same lifecycle as `setup_jump` chains.
- Deeper hops nest naturally (`jump_host` chains compose recursively).

## Algorithm (BFS over a frontier)

```
seed frontier = {local} ∪ already-connected named servers   (configurable)
key_space     = OUR_KEYS            # fixed set from config / agent
visited_ips   = {}                  # cheap dedup: skip re-probing an address
visited_fps   = {}                  # authoritative dedup: skip re-recursing a host

while frontier not empty and within bounds:
    H = frontier.pop()
    candidates = harvest(H)         # breadcrumbs ∪ injected ∪ optional sweep
    if harvest_keys and H is remote:
        key_space ∪= readable unencrypted keys on H     # see Credential modes
    for c in candidates - visited_ips:
        visited_ips.add(c)
        if not probe(c, port) through H:        # direct-tcpip; closed → skip
            continue
        conn = try_connect(c, port, key_space, policy=TOFU) through H
        if conn is None:                        # no key worked
            continue
        fp = host_key_fingerprint(conn)
        if fp in visited_fps:                   # same box via a different IP
            continue
        visited_fps.add(fp)
        name = "disc-" + fp[:8]                 # or "<prefix>-<fp8>"
        register_ephemeral(name, jump_host=H, host=c, note=fp + session_id)
        frontier.push(name)
```

### Two-level dedup (required)

A host's fingerprint is knowable only *after* connecting, and one machine has
many IPs and appears in many neighbors' caches. So:

- **`visited_ips`** prevents redundant *probes* to an address we've already
  tried.
- **`visited_fps`** prevents re-*recursing* into a machine already mapped under
  another IP, and breaks `A ↔ B` cycles.

## Candidate sources

Per-host `harvest(H)` unions these:

| Source | Default | Notes |
|---|---|---|
| Passive breadcrumbs | **on** | `~/.ssh/known_hosts`, `~/.ssh/config` (`HostName`), `/etc/hosts`, `ip neigh` / `arp -a`, `last` / `w`, shell history (`ssh`/`scp` targets). Bounded output size, like existing harvest. |
| Injected candidates | on if supplied | Caller passes explicit IPs / CIDRs / hostnames to check. Expanded (CIDR → addresses) with a hard cap. |
| Bounded subnet sweep | **off** (opt-in) | Runs **one sweep command on the host itself** over its own `/24` (or configured CIDR) on the target port — cheaper than 254 tunnels-from-center, reuses harvest infra. Capped address count + short per-probe timeout. |

## Credential modes

`key_space` starts as `OUR_KEYS` (paths from config and/or agent identities).

- **our-keys-only** (`harvest_keys=False`, default): `key_space` is fixed. No
  remote key material is ever read. Clean, no exfiltration.
- **harvest-keys** (`harvest_keys=True`): at each remote host, read `~/.ssh/id_*`
  private keys over the existing connection into center memory.
  - Unencrypted keys are added to `key_space` for all deeper hops (`key_space`
    grows monotonically as we descend).
  - Passphrase-protected keys are **skipped and reported** (name + host), never
    used, since we hold no passphrase.
  - **Key bytes are never written to the audit log** — CLAUDE.md rule #8
    (passwords/passphrases/secrets out of audit events) extends to private-key
    material. Audit records the *fact* of harvesting and the key's path/type
    only.

## Host-key policy

Discovery is inherently **TOFU** (trust-on-first-use). No `known_hosts` entry can
exist for a never-seen host, and the first connect is precisely what *captures*
the fingerprint we dedup on. `strict` is impossible here by construction.

- The scan uses TOFU regardless of the global default policy.
- MITM implication is accepted for the own-fleet use case and documented on the
  tool.
- Captured fingerprints are recorded (in the ephemeral `note`, and optionally
  appended to `known_hosts` on `persist=True`).

## Bounds & lifecycle

- **Bounds** (all with sane capped defaults): `max_depth`, `max_nodes`,
  `timeout` (whole-scan wall clock), `concurrency`, `port` (default 22),
  `probe_timeout`. Reaching any bound stops expansion and the result flags that
  it was truncated (no silent caps).
- **Session id.** Each `ssh_discover` run gets a `discovery_session` id. Every
  ephemeral it registers carries that id in `note`.
- **Teardown.** `teardown_discovery(session)` removes every ephemeral created by
  that scan — the `teardown_jump` analog. Without it the registry/pool bloats
  with no cleanup path.

## Tool surface

New tools (additive; no change to existing tools):

```python
async def ssh_discover(
    seeds: list[str] | None = None,          # frontier seed; default local + connected
    keys: list[str] | None = None,           # OUR_KEYS override; default config/agent
    harvest_keys: bool = False,
    injected_candidates: list[str] | None = None,   # IPs / CIDRs / hostnames
    subnet_sweep: bool = False,
    sweep_cidr: str | None = None,           # default: host's own /24
    port: int = 22,
    max_depth: int = 4,
    max_nodes: int = 128,
    timeout: float = 120.0,
    concurrency: int = 16,
    name_prefix: str = "disc",
    persist: bool = False,
) -> DiscoveryResult: ...

def teardown_discovery(session: str) -> dict: ...
```

### Result shape

```python
class DiscoveryResult:
    session: str
    scanned_at: datetime
    discovered: list[DiscoveredHost]   # name, fp, addrs, via, depth, auth_key, first_seen
    graph: dict[str, list[str]]        # discoverer -> [discovered names]
    skipped_encrypted_keys: list[...]  # host + key path (harvest-keys mode)
    truncated: bool                    # any bound hit
    stats: {...}                       # candidates probed, connects tried, etc.
```

`DiscoveryResult` / `DiscoveredHost` are **new** models in a discovery module,
not edits to `models.py`.

## Gate-1 immutability

No changes to `models.py` or `interfaces.py`:

- Discovered hosts reuse the existing `ServerConfig` (ephemeral). The
  fingerprint and session id ride in the existing free-form `note` field.
- `visited_ips` / `visited_fps` are transient scan state, not persisted schema.
- New result models live in a new module (e.g. `discovery.py`), parallel to
  `topology.py`.

No Gate-1 reopening required.

## Testing

- **Unit:** candidate parsing (known_hosts / ssh config / `ip neigh` / history
  fixtures), CIDR expansion + cap, two-level dedup logic, bound enforcement,
  key-encryption detection (encrypted vs. plain PEM).
- **Integration (asyncssh loopback / container):** a small synthetic topology
  (local → A → {B, C}, B ↔ C cycle) asserting: full discovery, cycle
  termination via `visited_fps`, ephemeral auto-registration + reachability,
  `teardown_discovery` full cleanup, harvest-keys picking up an unencrypted key
  on A to reach B, passphrased key on A reported-not-used.
- **Security:** assert no key bytes and no passphrase ever appear in audit
  events; assert TOFU is forced regardless of global policy.
- Coverage ≥ 80% per module (CLAUDE.md rule #6).

## Open questions / deferred

- Ranking/scoring of candidates within a host (which to try first) — v1 tries
  all up to the cap; smarter ordering is a later optimization.
- Cloud metadata/API sources — deferred (out of scope for v1).

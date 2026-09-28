# Decision registry

Every point where the node exercises local judgment — who may connect, what is
relayed, what is served, what is stored — is listed here. This document is the
contract behind the decision-point law in `docs/ARCHITECTURE.md`: a decision
that exists in code but not in this registry is a defect.

The registry covers **local policy only**. Consensus rules, block and
transaction validity, chain selection, and trust-shortcut choices that touch
verification completeness (e.g. assumevalid-style skips) are governed by the
kernel and the untrusted-advice invariants — they never appear as knobs here.

## Conventions

- **Knob** — a `NodeConfig`-reachable setting. Defaults track Core-compatible
  behavior unless noted. Names are dotted namespaces (`relay.tx.min_fee`).
- **Hook** — an optional external verdict program consulted at that point.
- **Status** — `const` marks a hardcoded constant that must become a knob;
  `field` marks an existing knob; `new` marks surface not yet implemented.
- Every decision emits the deciding rule and knob into explanations
  (`Mempool::explain_tx` is the existing pattern) and into the event stream,
  so shadow evaluation can attribute every verdict. **Stream status:**
  the wire is `<datadir>/<network>/events.ndjson` — an append-only NDJSON
  file (`{"seq","time","kind",...}` per line, rotated at 4 MiB with one
  backup; `seq` is monotonic across runs). `avila-node events [--follow]
  [--after N]` tails it. Emitted today: `run_started`, `run_stopped`,
  `hook_verdict`, `hook_spawn_failed`, `shadow_divergence` (one per
  changed `(profile, reason)` counter), `extrapool_stored` (per changed
  `reason` total), `extrapool_evicted`, `extrapool_expired`,
  `extrapool_promoted` (per changed counter), `extrapool_relayed`
  (per announce pass), `extrapool_promotion_pass` (per trigger),
  `hook_events_dropped` (bounded-channel drop counter),
  `config_risk` (per unacknowledged finding), and every `NetEvent` kind
  (`peer_connected`, `peer_disconnected`, `tip_advanced`,
  `eclipse_suspected`, `proxy_unreachable`, `v2_downgraded`,
  `cpu_throttled`, `blocks_announced`, `recon_divergence`). The GUI's
  activity log follows this file via `events::EventTail` — the same
  wire `--follow` sees.

## External verdict programs

A hook is a command line spawned once per decision point. The node writes one
JSON object per line to the helper's stdin and reads one verdict object back
per line on stdout. Requests are strictly serialized — one outstanding per
helper — so answers cannot be misattributed; `seq` is informational.

```text
→ {"point":"peer.accept","seq":7,"facts":{"remote":"1.2.3.4:8333",
   "services":1033,"protocol_version":70016,"user_agent":"/Satoshi:28.0.0.1/",
   "start_height":880000,"relay":true,"wtxid_relay":true,"addrv2":true,
   "transport":"v2"}}
← {"verdict":"accept"}                    # or "reject", "defer"
← {"verdict":"reject","reason":"asn-blocklist"}
```

Semantics:

- `accept` permits the candidate *subject to all built-in rules*; `reject`
  denies it; `defer` abstains. Verdicts combine by conjunction — a hook can
  only narrow what the node accepts, never widen it. This is what makes
  operator-written policy code safe to consult on live traffic.
- Configuration per point (`[[hooks.<point>]]`, point name with `_` for
  `.`): `program`, `args`, `timeout_ms` (slow = dead, bounded 1..=10_000),
  `on_timeout` and `on_defer` (`accept`|`reject`; per-point defaults),
  `max_restarts` (exhausted → the point runs on `on_timeout` forever;
  a helper that never spawned behaves the same).
- The helper is operator-trusted code run as the node's user. It is a policy
  surface, not a sandbox boundary; operators wanting isolation wrap it with
  `tools/guard_run.sh`-style cgroup limits. Helper stderr passes through to
  the node's stderr.
- Throughput: helpers are long-lived (no spawn per decision), verdicts are
  consulted only when a hook is configured, and each consult is bounded by
  `timeout_ms` — a slow helper counts as dead, is killed and restarted
  within budget. Consultation never blocks consensus work.

**Status:** six points wired. `peer.accept` (`[[hooks.peer_accept]]`)
consults in `PeerManager::drain_inbounds`, after the ban check and
before slot/eviction. `tx.admit` (`[[hooks.tx_admit]]`) consults in
`Mempool::accept_tx` before any built-in check, narrowing only
(`reject` → `MempoolReject::PolicyHook`, counted in
`lifecycle.rejected`, surfaced as "rejected by tx.admit hook" through
`sendrawtransaction`); facts are `txid`, `wtxid`, `version`,
`lock_time`, `vbytes`, `weight`, `inputs`, `outputs`, `output_value`,
`fee`, `feerate` (sat/kvB; both null when a prevout is unresolvable),
`rbf`, `has_witness`, `spk_types`. This is a hot path: admission
throughput is bounded by helper latency. `tx.announce`
(`[[hooks.tx_announce]]`) consults once per tx×peer link in
`send_tx_inv` (fan-out + broadcast) and at the stem hop — narrowing
only per link; a reject suppresses that peer's inv, never the entry.
Facts are `txid`, `wtxid`, `source` (inbound|outbound|local|extrapool),
`source_peer`, `peer`, `peer_addr`, `peer_inbound`, `peer_user_agent`.
`extrapool.admit` and `extrapool.promote` (`[[hooks.extrapool_admit]]`,
`[[hooks.extrapool_promote]]`) see `{txid, reason}` — the former drops
the observation record only (the tx is rejected regardless), the latter
keeps the entry on reject. `tx.serve` (`[[hooks.tx_serve]]`) consults
per tx item in a peer's `getdata` — `reject` answers `notfound` for
that item, indistinguishable from never holding it; facts are `txid`,
`wtxid`, `peer`, `peer_addr`, `peer_inbound`, `peer_user_agent`.
All six fire `hook_verdict` events;
verdict delivery is bounded (sync_channel 4096, drops emit
`hook_events_dropped`). `peer.accept`'s richer facts (`netgroup`,
`asn`) arrive when the addrman/asmap lookups expose them at accept
time.

Shadow mode: `policy.shadow = ["strict"]` (wired — named presets
`strict`, `core`, `permissive`, several concurrent) evaluates counterfactual
policies alongside live admission without gating, and reports
divergences through `getmempoolinfo`'s `shadow.profiles` and
`shadow_divergence` events — "what this profile would have filtered"
on real traffic before the operator commits. `avila-mempool`'s
`ShadowRules`/`shadow_eval` is the first instance; every registry
point gains the same treatment, and custom profiles via hook commands
are planned.

**Pools are first-class objects.** The mempool — what the node admits,
relays, and mines from — is one pool among several. The *extrapool*
observes consensus-valid transactions that local policy rejects; a *private
pool* holds locally-originated transactions under stricter announcement
rules. Each pool has its own admission, capacity, expiry, and visibility
rules, and declared transition rules between them (extrapool → mempool
promotion). A policy rejection is therefore not "the transaction vanished"
— it is a routed, counted, explainable event, and operators can inspect the
traffic their policy is actually filtering.

**Provenance is a policy input.** Every pool entry records how it arrived
— which peer class announced it, whether the wallet submitted it, which
pool promoted it — and relay decisions may key on provenance. This makes
compartmentalization expressible ("inbound-sourced transactions announce
only to outbound peers") instead of implicit.

## Config namespaces

`net` · `peers` · `addr` · `mempool` · `extrapool` · `policy` · `relay.tx`
· `relay.block` · `sync` · `filters` · `indexes` · `mining` · `services.rpc`
· `services.electrum` · `services.sv2` · `privacy` · `storage` · `diag`

`config describe` dumps the full tree — knob, type, default, range, doc line —
generated from the serde schema so documentation cannot rot. `config lint`
flags mutually breaking combinations. `deny_unknown_fields` stays: a large
schema, but a closed one.

## A. Peer admission and lifecycle

| Point | Today | Knobs | Hook |
| --- | --- | --- | --- |
| Inbound accept | `MAX_PENDING_ACCEPTS=32` (const) | `peers.max_inbound`, `peers.max_per_netgroup`, `peers.max_per_asn` (asmap), `peers.listen` | `peer.accept` |
| Outbound dial | `DEFAULT_MAX_PEERS=8`, `DIAL_TIMEOUT=5s` | `peers.max_outbound`, `peers.connection_types` (full-relay / block-relay-only / addr-fetch / feeler counts), `peers.dial_timeout` | `peer.dial` |
| Required services | `OUR_SERVICES=NODE_NETWORK\|NODE_WITNESS` | `peers.require_services`, `peers.reject_services`, `peers.min_protocol_version` | — |
| Identity filtering | — | `peers.subver_allow` / `subver_deny`, `peers.allow_nets` / `deny_nets` (clearnet, tor, i2p, cjdns), fixed `peers.addnode` / `connect-only` | `peer.accept` |
| Misbehavior | `DISCOURAGE_FOR=24h`, `DEFAULT_BANTIME=86400` | `peers.ban_time`, `peers.ban_score` table, `peers.whitelist` peers/subnets exempt from limits+ban | `peer.ban` |
| Eviction protection | `USEFUL_PROTECTION_WINDOW=20min` | `peers.protect_window`, protect-by-latency/netgroup counts | — |
| Liveness | `PING_INTERVAL=120s`, `HANDSHAKE_TIMEOUT=60s` | `peers.ping_interval`, `peers.handshake_timeout`, `peers.idle_timeout` | — |
| Anchor peers | — (new) | `peers.anchor_on_restart` | — |

## B. Address manager and addr relay

| Point | Today | Knobs | Hook |
| --- | --- | --- | --- |
| Table | `ADDR_TABLE_CAP=4096` | `addr.table_cap`, `addr.persist` | — |
| getaddr service | `GETADDR_REPLY_MAX=1000` | `addr.getaddr_reply_max`, `addr.serve_getaddr` (off = no addr service) | `addr.serve` |
| addr intake rate | `0.1/s`, bucket 1000 | `addr.rate_per_sec`, `addr.burst` | `addr.relay` |
| Self-announcement | — | `addr.self_announce` (`off` = never gossip own addr), `addr.self_interval` | — |

## C. Mempool policy — admission, economics, lifecycle

The mempool is the pool the node admits, relays, and mines from. Every
constant in `avila-mempool` becomes a knob: `policy.*` holds standardness,
`mempool.*` holds pool economics.

| Point | Today | Knobs | Hook |
| --- | --- | --- | --- |
| Presets | — | `policy.preset` (core / strict / permissive / custom — `custom` honors every `policy.*` knob; presets are named bundles, not modes) | — |
| Fee floor | `DEFAULT_MIN_RELAY_FEE=100`, `INCREMENTAL_RELAY_FEE=100`, 12h rolling halflife | `mempool.min_relay_fee`, `mempool.incremental_relay_fee`, `mempool.fee_halflife` | `tx.admit` |
| Standardness | `policy.rs` full gate | `policy.datacarrier`, `policy.datacarrier_size`, `policy.permit_bare_multisig`, `policy.max_tx_version`, `policy.max_scriptsig`, `policy.max_tx_weight` (400k), `policy.max_tx_sigops`, `policy.dust_relay_fee`, `policy.max_dust_outputs` (ephemeral), `policy.min_nonwitness_size`, `policy.tapscript_item_size`, `policy.reject_annex` | `tx.admit` |
| Witness rules | `is_witness_standard` | `policy.max_p2wsh_stack_items`, `policy.max_p2wsh_item_size`, `policy.max_p2wsh_script` | — |
| Pool limits | `DEFAULT_MAX_BYTES=300M`, `MAX_ENTRIES=25k`, `MEMPOOL_EXPIRY=336h` | `mempool.max_bytes`, `mempool.max_entries`, `mempool.expiry`, `mempool.persist`, `mempool.reaccept_on_load` | — |
| Packages | ancestor/descendant 25 / 101kvB | `mempool.limit_ancestor_count/size`, `limit_descendant_count/size`, `policy.truc_enforcement`, `mempool.package_accept` (single / 1p1c / package-rbf), `mempool.cpfp_carveout` | `tx.admit` |
| RBF | `MAX_REPLACEMENT_CANDIDATES=100`, sequence ≤ `0xfffffffd` | `mempool.full_rbf`, `mempool.max_replacement_candidates`, `policy.rbf_rule_*` (BIP125 rules toggled individually) | `tx.replace` |
| Orphans | `MAX_ORPHANS=100`, `ORPHAN_EXPIRE=20min` | `mempool.max_orphans`, `mempool.orphan_expire`, `mempool.orphan_per_peer`, `mempool.max_disconnected_bytes` | — |
| Eviction | feerate-ascending trim (Core) | `mempool.eviction_order`, `mempool.evict_batch`, `mempool.eviction_floor` (`min_mempool_fee` behavior) | `tx.evict` |
| Rebroadcast buffer | `BROADCAST_POOL_BYTES=300k` | `mempool.broadcast_bytes`, `mempool.rebroadcast_interval` | — |
| Explainability | `explain_tx`, per-gate trace | `policy.explain` (off / verdict / trace) — verdicts carry deciding rule, knob, and counterfactual ("needed ≥1.0 sat/vB") | — |
| Shadow | `shadow_standard` counters | `policy.shadow[]` — named profiles or hook commands, N concurrent, divergence counters + events | — |

## D. Extrapool and auxiliary pools

Consensus-valid transactions that fail local policy are evidence about the
network, not noise. Core drops rejects outright; the extrapool keeps them
in a bounded, inspectable pool with declared rules. Whether observed
transactions may promote, relay, or mine is operator policy — never
consensus, and never automatic.

**Status:** fully wired. `Mempool::accept_tx` routes every policy-class
reject (`NotStandard`, fee floors, `PolicyHook`, RBF conflicts, package
limits, `NotFinal`, capacity, sigops, weight, TRUC) into `Extrapool` when
`extrapool.observe` is on (default true). Consensus failures, duplicates,
and orphans never store — structural noise isn't signal. Bounds:
`extrapool.max_entries`/`max_bytes` (FIFO evict), `extrapool.expiry_secs`
(0 = never age), `extrapool.caps` (per-reject-class FIFO bounds —
classes: nonstandard, fee, hook, rbf, package, finality, capacity,
weight, sigops, truc, other). `extrapoolpromote "txid"` re-runs the full
admission path (hooks included) after a policy change;
`extrapool.promote_on = ["tip"]` retries up to 256 entries per connected
block. `extrapool.relay` (never|outbound|all) propagates observed txs
through the announce gates with `extrapool` provenance — default never.
`getextrapoolinfo` reports size/bytes/counters/`by_reason`/`by_class`/
`pending_relay`/entries. Events: `extrapool_stored`, `extrapool_evicted`,
`extrapool_expired`, `extrapool_promoted`, `extrapool_relayed`,
`extrapool_promotion_pass`.

| Point | Today | Knobs | Hook |
| --- | --- | --- | --- |
| Observation pool | policy rejects → bounded store | `extrapool.observe`, `max_bytes`/`max_entries`/`expiry_secs`, `extrapool.caps` (per-class bounds — wired) | `extrapool.admit` (wired — drops the record only) |
| Promotion | manual RPC + tip trigger | `extrapoolpromote "txid"`, `extrapool.promote_on` (`[]` / `["tip"]` — wired) | `extrapool.promote` (wired — reject keeps the entry) |
| Private pool | stem-only + RPC-hidden | `mempool.private` (bool — wired): local submissions never fluff and are absent from `getrawmempool`/`getmempoolentry`; `getmempoolinfo` reports `private` count | — |
| Extrapool relay | — | `extrapool.relay` (never / outbound / all — wired); announce gates + deny_pairs apply | `tx.announce` |
| Reporting | counters + events | `getextrapoolinfo` + `extrapool_*` events (wired) | — |

## E. Relay policy — per-peer wire behavior

Admission decides what enters pools; relay decides what crosses each link.
A relay verdict is a function of `(object, peer, direction, provenance)` —
uniform defaults, per-peer overrides, provenance rules, and hooks at every
transition.

| Point | Today | Knobs | Hook |
| --- | --- | --- | --- |
| Tx announce | wtxid inv; stem on, `STEM_EPOCH=600s` | `relay.tx.stem` (wired); `relay.tx.announce` (inv / none / private-only), `stem.epoch`, `stem.hop` planned | `tx.announce` (wired — verdict per tx×peer link, fan-out + stem hop) |
| Per-peer matrix | compartment matrix | `relay.tx.deny_pairs` (wired — `"src->dst"` pairs never announce; src: inbound/outbound/local/extrapool, dst: inbound/outbound); `relay.tx.to_inbound`, `to_blocks_only_peers`, `peer_override` planned | `tx.announce` |
| Provenance rules | `TxSource` in announce facts | `relay.tx.min_observed_announces` planned | `tx.announce` (facts carry `source`, `source_peer`, `peer_inbound`, `peer_user_agent`) |
| Tx serving | `MEMPOOL_REQ_INTERVAL=60s`, `MAX_MEMPOOL_INV=50k`; getdata serves mempool + extrapool | `relay.tx.serve_mempool`, `mempool_req.interval`, `mempool_req.max_inv`, `relay.tx.serve_bip37` (bloom serving, off default) | `tx.serve` (wired — verdict per tx item per getdata; reject answers `notfound`) |
| feefilter | honored inbound — peer's advertised minimum suppresses sub-rate invs in `send_tx_inv`; reported via `getpeerinfo.minfeefilter`. We never send one ourselves | `relay.tx.send_feefilter` (send our floor outbound) planned | — |
| Shape / timing | recon 4s | `relay.tx.trickle_ms`, announce jitter, per-peer announce rate cap | `relay.schedule` |
| Reconciliation | `RECON_INTERVAL=4s`, req ≥250ms, ≤8 violations | `relay.tx.recon`, `recon.interval`, `recon.min_req_interval`, `recon.max_violations` | — |
| Rebroadcast | broadcast pool exists | `relay.tx.rebroadcast_local`, `relay.tx.rebroadcast_interval` | — |
| Block serving | `SEND_BUDGET_PER_PEER=8MiB` | `relay.block.serve` (none / tip / full), `send_budget`, `relay.block.blocks_only_mode` | `block.serve` |
| Compact blocks | — | `relay.block.compact`, `compact.high_bandwidth`, `compact.serve` | `block.announce` |
| Block announce | sendheaders | `relay.block.announce` (headers / inv / none) | — |

## F. Sync scheduling

Fetching — distinct from serving. In-flight budgets and timeouts are
performance policy, not correctness.

| Point | Today | Knobs | Hook |
| --- | --- | --- | --- |
| In-flight window | `MAX_BLOCKS_IN_TRANSIT_TOTAL=1024` | `sync.max_in_transit`, `sync.per_peer_in_flight` | `block.fetch` |
| Headers timeout | base 15min + 1ms/header | `sync.headers_timeout_base/per_header` | — |
| Freshness | `RECENT_HEADER_WINDOW=24h` | `sync.recent_window` | — |
| Mode | — | `net.blocks_only` (skip tx relay entirely) | — |

## G. Filters, indexes, and data serving

| Point | Today | Knobs | Hook |
| --- | --- | --- | --- |
| Compact filters | `CFILTER_RATE=1/s`, bucket 20 | `filters.build`, `filters.serve` (`-peerblockfilters`), `filters.rate` | `filter.serve` |
| Indexes | txindex/cfilters/scindex append-logs | `indexes.txindex`, `indexes.cfilters`, `indexes.scripthash`, `indexes.coinstats` | — |
| Pruning | `prune_mb` (field) | `storage.prune_mb`, `storage.prune_to` | — |

## H. Mining and templates

| Point | Today | Knobs | Hook |
| --- | --- | --- | --- |
| Template shape | `next_block.rs` | `mining.max_weight`, `mining.min_tx_fee`, `mining.reserved_weight`, `mining.refresh_ms` | `template.build` |
| Extrapool coupling | — | `mining.include_extrapool` (wired, boolean — mine what you won't relay; candidates revalidated under consensus flags, confirmed inputs only, ≤512 auditions, leftover budget) | — |
| Stratum V2 | `sv2.rs` | `services.sv2.listen`, `sv2.job_declaration`, `sv2.template_provider` | — |

## I. Services and permissions

| Point | Today | Knobs | Hook |
| --- | --- | --- | --- |
| RPC | cookie + user/pass + per-user method whitelist | `services.rpc.bind`, `rpc.users`, `rpc.whitelist_default`, `rpc.max_pending`, `rpc.timeout` | `rpc.authorize` |
| Electrum | `electrum.rs` | `services.electrum.listen`, `electrum.max_subs`, `electrum.private_mode` | — |
| Event journal | `event_capacity` (field), ring 4096 | `diag.event_capacity`, `diag.log_level` per subsystem, `diag.redact_addrs` | — |

## J. Privacy routing

| Point | Today | Knobs | Hook |
| --- | --- | --- | --- |
| Route selection | `proxy.rs` | `privacy.proxy` (socks5), `privacy.onlynet`, `privacy.fail_closed` (route down = no traffic, never leak) | — |
| Origin privacy | stem relay on by default | `privacy.tx_origin` (stem / direct / tor-only-broadcast), stream isolation per destination type | `tx.origin` |
| Discovery | — | `net.dns_seeds`, `net.fixed_seeds`, `net.external_ip` | — |

## Exclusions

- Consensus rules, activation heights, sighash semantics, chain selection:
  kernel. Never configurable, never hookable.
- assumevalid-style verification skips and snapshot trust: governed by the
  untrusted-advice invariants in `docs/ARCHITECTURE.md`, not this registry.
- A hook returning `accept` can never rescue a candidate the built-in rules
  rejected. The narrowing rule is enforced in the verdict combiner, tested,
  and not itself configurable.

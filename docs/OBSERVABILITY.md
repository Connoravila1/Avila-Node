# Observability surface — the event-stream API

Status: shipped. This documents the node's machine-readable
observability layer — the thing Bitcoin Core issue #34901 calls out
("block processing is a black box"). Everything below is live JSON-RPC;
no tracing framework, no log scraping.

## The event ring — `getevents`

`PeerManager` keeps a bounded ring of the last **1024** `NetEvent`s.
`getevents ( count )` returns newest-first, up to `count` (max 1024).
Events are dropped oldest-first under pressure — this is a telemetry
ring, not a journal; consumers that need every event must poll.

| `event` | Fields | Meaning |
|---|---|---|
| `connected` | `peer`, `subver` | Handshake complete; peer id assigned. |
| `disconnected` | `peer`, `reason` | `Session(..)` (transport), `Misbehavior(..)` (sync-proved), or `Stalled` (stopped answering block requests). |
| `tip_advanced` | `height` | Connected chain advanced. |
| `announced` | `peer`, `missing` | A peer announced blocks we lack — the fetch frontier moved. |
| `eclipse_suspected` | `signals` | Advisory eclipse indicators fired — see below. |
| `recon_divergence` | `peer`, `rounds`, `their_misses`, `our_misses` | A recon peer persistently lacks txs we hold — censorship/filtered-view signal (queue #19). Edge-triggered: fires once per sustained streak, not per round. |
| `proxy_unreachable` | — | With `--proxy` set, 3 consecutive outbound dials failed — the private route itself is down. Edge-triggered. |
| `v2_downgraded` | `addr` | An outbound dial requested BIP324 but landed cleartext v1 — forced-downgrade signal (a MITM can strip the v2 attempt). Advisory. |
| `cpu_throttled` | `peer`, `rate_ns` | A peer dominated dispatch CPU (>50% share at >200 ms/s) and lost a tick's poll — backpressure, not a ban (queue #14). |

### Eclipse signals (`eclipse_suspected.signals`)

Advisory, never a verdict (queue #12):

- `TipStale` — our tip >24h old while ≥4 established peers all claim
  higher `start_height`.
- `DiversityCollapse` — ≥4 outbound peers all in one /16 net group.
- `AllInbound` — every established peer is inbound.

## Per-peer telemetry — `getpeerinfo`

Beyond Core's fields, each peer reports:

- `cpu_ms`, `cpu_rate_ms` — cumulative and decayed-per-second dispatch
  CPU (the throttle input, PEER_BUDGETS).
- `recon`, `recon_rounds`, `recon_misses`, `recon_their_misses` —
  BIP-330 link state and cumulative diff sizes.
- `addr_processed`, `addr_rate_limited` — the address token bucket's
  consumption and rejections.
- `synced_headers`, `synced_blocks`, `in_flight`, `in_flight_hashes` —
  claims-vs-delivered per peer.
- `last_block_time`, `last_transaction`, `last_announce` — liveness.

## Pool transparency — `getmempoolinfo`

- `lifecycle` — admission verdicts and per-cause removal counters
  (confirmed, block-conflict, replaced, evicted, expired, reorg-drop).
- `shadow` — the strict-ruleset observatory (queue #8): `evaluated`,
  `divergent`, `by_reason` — how much accepted traffic a Knots-style
  policy would refuse. Never gates.
- `getmempoolhistory ( count )` — the bounded removal ring with
  per-event cause and (for RBF) the replacing txid.
- `getmempoolblocks` — the next-block template projection over the
  ancestor-feerate sort (queue #32).

## Validation transparency

- `getblockreceipt ( hash )` / `getblockreceipts ( from to )` — the
  per-connect receipt ring (2016 deep): script flags enforced, fee
  and sigop totals, checks queued vs verified-cache hits, spent/
  created counts, wall time, and `delta_commitment` — a SHA-256
  commitment to the exact UTXO transition, replayable.
- `getvalidationreport` — the node's own trust state as a typed
  value: connected/header heights, snapshot base and commitment,
  replay progress, assumed vs verified fractions.

## Sync artifacts

- `emitswiftsynchints "path"` — write the current survivor set +
  tag aggregate as a hints artifact (checkpoint height included).
- `verifyswiftsynchints "path"` — verify a hints file against the
  live set: `verified | aggregate_mismatch | survivor_mismatch`.
  Wrong hints can only waste the optimization, never corrupt state.

## Consumption pattern

Poll `getevents` each interval; the ring's bounded depth means a
slow consumer sees a gap, not a stall. `getpeerinfo` +
`getmempoolinfo` are point-in-time snapshots — pair them with the
event stream for the full picture: *who claimed, who delivered,
what it cost, what the node did about it.*

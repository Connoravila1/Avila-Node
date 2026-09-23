# Experiment: end-to-end sync pipeline timing

**Date:** 2026-09-23 · **Status:** decisive — prices the whole arc
**Artifacts:** `examples/sync_bench.rs`, drain-wait timer in
`connect.rs`/`chainstate.rs`.

## Question

Sixteen experiments optimized pieces of `connect_block` (storage)
and its script path (speculative pipelining) — but nothing had
measured the *whole* accept path: decode → headers → contextual →
connect → flush. If connect were only a third of sync, the arc
polished the small end.

## Setup

`sync_bench` replays the spend-dense regtest fixture (625 blocks,
15,989 txs) through `accept_header` + `accept_block` —
`over_budget` flushes included — with per-phase wall-clock split
and the inside-connect breakdown. `spec-drain` isolates
`drain_pending_to` waits so the residual is really
flush+contextual, not deferred script work.

## Numbers (512 MiB cache)

| phase | no-spec | spec |
|---|---|---|
| decode | 0.2% | 0.6% |
| headers | 1.0% | 2.0% |
| connect | **96.8%** | 22.7% (serial) |
| spec-drain | — | **73.2%** (script work, awaited lazily) |
| flush+contextual | 1.6% | ~1.5% |
| **wall** | 3.0 s (207 blk/s) | 1.4 s (453 blk/s) |

At 32 MiB the profile is unchanged — the fixture's dirty set
(~1.6 MB) never pressures the cache; flush stays ~1.5%.

## Verdict

**Connect *is* sync.** 97% of end-to-end wall-clock; inside it,
scripts are ~95%. Everything else — decode, headers, contextual,
flush — is 3% combined. The experimental arc was pointed at the
right layer, and speculative connect's win is real end-to-end
(~2× wall, not just inside connect).

The sharper reading: at this scale *storage is 1.5–4% of the node*,
full stop. The hash engine's wins (capacity, ingest) are real but
invisible to per-block latency — they matter for disk footprint
and snapshot/IBD write volume, not wall-clock validation. And
post-spec, ~70% of wall is *still* signature verification — the
next honest lever on the dominant share is algorithmic
(Schnorr batch / batch ECDSA), not scheduling.

## Caveats

- 26-tx regtest blocks — per-block overhead is exaggerated vs
  mainnet (~3k tx/blk); shares will shift somewhat at real density.
- Single-process replay: no p2p download, no mempool, no RPC —
  real IBD adds network on top of this validation floor.
- 32 MiB hash run showed script-time variance (~+20% vs redb) —
  laptop noise; engine doesn't change script work.

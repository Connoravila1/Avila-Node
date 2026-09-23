# Net-effect write elision in the coins write-back cache

**Date**: 2026-09-23 · **Status**: ADOPTED (tombstone elision); deferred (age-aware partial flush)

## Question

The UtxoSet write-back cache already amortizes commits (flushes only
on `over_budget`, not per block). But how much of the committed delta
is *wasted work* — writes whose effect never materializes on disk?

## Method

`churn_bench` (new example): 4000 synthetic blocks × 2000 creates,
spending 25% of the cohort 40 blocks old — the modern-chain spend-age
pattern. `CoinsBackend::write_stats()` counts commits/puts/deletes
actually executed. Gross ops vs executed ops = cache absorption.

## Finding 1 — tombstone deletes were 20–25% of all disk ops

A coin created and spent inside one cache epoch leaves a `None`
tombstone in the dirty map; commit then issued a backend **delete for
a key never inserted** — pure waste.

| budget | before | after elision |
|---|---|---|
| 2048M (one epoch) | 8.00M ops → disk/gross 0.80 | 6.02M → **0.60** (−25%) |
| 64M (10 flushes) | 8.20M → 0.82 | 6.42M → **0.64** (−22%) |

Mechanism: `UtxoSet.born` — a HashSet of outpoints created this epoch
with no lower-layer presence (reuses `put`'s existing `lower_live`
check → zero extra disk reads). At flush, `map.retain` drops
tombstones over born keys before commit. Consensus-neutral: the
elided delete was a no-op anyway.

Edge handled: tombstone→`Some` re-create on a backend-resident key
(BIP30 overwrite class) re-checks `lower_live` — must not be born,
else a real delete would be skipped and the coin would resurrect.

## Finding 2 — the young-puts residual (~2–6%)

At 64M: 6.22M puts vs 6.02M ideal — 200k coins flushed to disk while
young, then spent in a later epoch (a real put + real delete that a
patient policy would never have written). Fixing it needs
generation-aware partial flush — commit only aged entries, retain the
young — but that breaks the coins+undos+tip atomicity invariant
(partial flush can't advance the tip while young entries hold state).
**Deferred**: ~2–6% write savings doesn't yet buy the ordering
complexity. Revisit if low-RAM profiles make flush frequency high.

## Verification

- `cargo test -p avila-consensus`: 467 passed
- `diff_segment.py --every 1`, hash engine, elision active: **PASS —
  501 real blocks, byte-identical UTXO state vs Knots at every height**
- Elision sits above the engine dispatch — both engines see the same
  filtered delta; hash and redb both verified through the bench.

## Honest limits

- Synthetic spend-age distribution (25% at 40-block age). Real
  mainnet's young-spend fraction varies by era — early blocks
  ~nothing, modern blocks much more. The mechanism's win scales with
  that fraction; the differential proves correctness, not magnitude.
- The overlay/reorg path (`UtxoSet::restore`) merges entries without
  born bookkeeping — a missed elision (wasted delete), never a wrong
  one.

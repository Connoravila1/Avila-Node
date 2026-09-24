# Speculative block pre-validation — subsumed by the verified-tx cache

**Date:** 2026-09-24 · **Status:** SUBSUMED — the win already ships in #20

## Hypothesis

Mempool contents predict the next block (~90% overlap on mainnet). Pre-validate
the predicted block (script checks + coin fetches) so real connect is mostly
cache hits → faster block accept/relay.

## Method

`examples/predict_bench.rs` — connect_bench variant with a pre-connect
prediction pass per block:

- `verified` — mark every non-coinbase tx verified with the standard flag set
  right before connect (models a perfectly predicted mempool template)
- `verified+prefetch` — additionally `utxo().get()` every input's prevout
  before connect (models the full speculative path)

Fixture: `spend-fixture.dat` — 625 spend-dense regtest blocks, 8.5MB.
512MiB dbcache, no spec-connect.

## Results

| mode | wall | blocks/s | script | read | apply | bip30 | other |
|---|---|---|---|---|---|---|---|
| baseline | 6.6s | 94 | 6268ms | 17ms | 157ms | 48ms | 17ms |
| verified | 256.8ms | 2434 | **0ms** | 9ms | 117ms | 34ms | 16ms |
| verified+prefetch | 289.1ms | 2162 | 0ms | 6ms | 123ms | 37ms | 17ms |

## Findings

1. **The prediction win is already realized.** The verified-tx cache (#20)
   marks scripts verified at mempool-accept; connect then skips them. On a
   ~100%-overlap fixture that turns connect into a 25.7× speedup — scripts
   go to literally zero. A separate "predicted block" machinery would verify
   the same work the mempool already verified.

2. **Prefetch is a real negative.** With scripts covered, residual connect is
   ~257ms/625 blocks — 117ms `apply` + bookkeeping. The read share was already
   9ms (coins are in the dirty map from prior blocks); explicit prefetch just
   pays a duplicate lookup per input and came out 12% slower.

3. **The residual has no lever.** What's left is inherent connect cost:
   applying the UTXO map and bookkeeping — not prefetchable, not skippable.

4. **Mainnet caveat (honest).** Fixture overlap is ~100% by construction;
   real mainnet sees ~90% (compact-block literature). The ~10% unseen txs
   still need real verification — that work is intrinsic, not a prediction
   failure a template can fix. The verified-cache hit-rate on live traffic is
   the live-sync experiment's job to measure.

## Verdict

**Rejected as a novel mechanism — the value was already captured.** Building a
block-template speculation engine buys nothing beyond what mempool-accept
marking already does. The interesting question it leaves is not "can we
predict" but "what's the real-world verified-cache hit rate" — deferred to the
live-sync experiment (#3 in the queue).

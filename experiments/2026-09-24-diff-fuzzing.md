# Differential fuzzing vs Knots — seeded mutation harness

**Date:** 2026-09-24 · **Status:** WORKING — 1080 mutations, 0 consensus
divergences; one strictness difference documented

## Hypothesis

Randomized block mutations judged by both engines surface verdict
divergences that crafted corpora miss — "we're compatible" becomes a
monitored property, not a claim.

## What was built

`tools/diff_fuzz.py` — seeded-mutation differential harness:

- Spins an isolated Knots regtest daemon (reuses
  `check_blocks_core.Daemon`); drives Avila over its identical
  cookie-auth JSON-RPC.
- Corpus: ~125 real mined regtest blocks, all accepted identically
  (valid-block parity gate).
- Mutations (seeded RNG): merkle-root byte flips, tx-data byte flips,
  zeroed windows in non-zero regions, truncations, tx-count inflation,
  tail-appends.
- Each mutation judged by BOTH `submitblock`s; verdict disagreements
  dumped for reproduction.

## Results — 3 seeds × ~360 mutations = 1080 trials

- **0 consensus verdict divergences.**
- **1 strictness class, explained:** mutations preserving the 80-byte
  header produce the same block hash — Knots short-circuits
  "duplicate → accept" (plus ignores trailing bytes) *before* decoding
  the mauled tx data, while Avila strictly decodes wire bytes first
  and returns `decode`. Ordering/strictness difference, not a
  consensus-rule difference — Core would reject the same content once
  it actually reached validation. Worth knowing for P2P edge cases
  (a peer sending header-identical garbage gets different responses)
  but not an acceptance divergence.

## Bugs found and fixed in the harness itself

- `zero` mutation could hit already-zero bytes → no-op "mutation" —
  now picks non-zero regions.
- Initial run lacked a wallet (`getnewaddress` fails on modern Core —
  needs `createwallet`).

## Verdict

The property "verdict-compatible with Knots on random corruption" now
has a reproducible check. Next: seeded *valid* mutations (malleated
witness with recomputed commitments — consensus-level, not just wire),
tx-level `sendrawtransaction` fuzz, and a CI cadence.

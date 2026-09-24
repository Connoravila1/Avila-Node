# Utreexo spike — accumulator validates without storing the UTXO set

**Date:** 2026-09-24 · **Status:** PROMISING — the primitive works;
integration is a program, not a patch

## Hypothesis

An accumulator (Utreexo) could replace the stored UTXO set with ~KB of
root state + proofs carried alongside blocks/txs. BIPs 181-183 got
assigned numbers Sept 2025; `rustreexo` 0.6.0 exists pure-Rust. Question:
does the primitive actually work on our data shapes, and at what cost?

## Method

`examples/utreexo_bench.rs` — two-sided model on a 1M-leaf synthetic
UTXO set: `MemForest` as the bridge (holds the forest, generates
proofs), `Stump` as the light node (roots only, verifies+applies).
Leaf = SHA-256d of the coin's compact serialization (same bytes the
snapshot commits — derivable by anyone).

## Results

| metric | value |
|---|---|
| bridge forest build | 566k leaves/s (170M ≈ 5 min) |
| **node state (Stump)** | **247 B for 1M leaves** — ~864 B projected at 170M vs ~12 GB UTXO set |
| single spend proof | 651 B, verified+applied ~18 µs |
| 64-spend proof | 1.1 KB |
| **2000-spend block batch** | **16.5 KB proof, 17.9 ms verify+apply** (~110k leaves/s) |

Mainnet projection: ~2-4k spends/block → ~16-33 KB proof per block —
**~1% bandwidth overhead** on top of block size. Node state <1 KB vs
12 GB. Both sides must advance in lockstep (bridge deletes what the
proof spends — the accumulator is shared state).

## API notes (honest)

- `stump.modify(adds, del_hashes, proof)` is the real operation —
  re-verifies internally and applies; all spends succeeded through it.
- Bare `stump.verify` returned false on multi-leaf proofs despite valid
  proofs (del_hashes ordering contract is stricter than modify's) —
  use `modify`'s success as the validity signal, or sort del_hashes to
  the proof's target order.

## Verdict

The primitive is real, pure-Rust, and fast enough. The win is
architectural: consensus state drops to ~1 KB. The costs are the
program-sized ones: proofs must come from somewhere (bridge nodes —
centralization surface unless many run them), P2P needs a proof-carrying
block/tx format (BIP-181 does exist), and our own UTXO layer would need
a proof-consuming variant. It's the biggest-ceiling item on the map —
and now it's measured rather than hypothetical.

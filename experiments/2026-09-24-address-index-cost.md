# Address-index cost model — cheap to build, memory-bound to serve

**Date:** 2026-09-24 · **Status:** measured — log format fine; in-memory
map won't scale to mainnet

## Hypothesis

A built-in scripthash index / Electrum-style serving profile is the
feature wallet users actually want. Question: what does it cost?

## Method

`examples/scindex_bench.rs` — spend fixture (625 blocks) through a
persistent chainstate with `enable_scripthashindex` on vs off.

## Results

| metric | value |
|---|---|
| connect-time delta | 8.64s → 8.56s (**~0%**, within noise) |
| `scindex.dat` (append log) | 3.73 MB / 625 blocks — **~38 B/entry** |
| index contents | 55,911 unique scripts, 99,560 history entries |

## Findings

1. **Build cost is negligible.** Indexing rides the connect pass —
   script extraction + append write are amortized noise on this fixture.
2. **The on-disk log format is right.** ~38B per `(height, txidx, txid)`
   record; the append-log survives restarts and backfills.
3. **The in-memory `by_script` map does not scale.** ~46B/entry in a
   HashMap → at mainnet scale (~1.1B txs, ~4-5B touched-script entries)
   that's ~150-230GB RAM — infeasible. The query structure must be
   disk-backed.
4. **The right backing already exists.** `hashstore` (48B-slot keyed
   index, experiment #25/#26-era work) is exactly the serving shape:
   script-hash → slot → append-log offsets. The profile's real work is
   swapping `by_script: HashMap` for a hashstore-backed index — a
   bounded refactor, not new research.

## Verdict

Opt-in profile is practical — the format costs ~nothing to maintain;
the serving layer needs the hashstore backend before mainnet claims.
Electrum serving itself already ships (`--electrum`).

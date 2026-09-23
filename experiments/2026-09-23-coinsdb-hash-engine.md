# Coins engine experiment: hash-indexed store vs redb B-tree

2026-09-23 — second coinsdb experiment. The first changed the *record
codec* inside redb's ordered B-tree; this one replaces the structure.

## Hypothesis

The UTXO set has no range queries in the consensus path — every
access is a point lookup by outpoint. An ordered store (LevelDB,
redb) pays B-tree costs — O(log n) descent, page splits, tree
maintenance — to preserve an ordering only `dumptxoutset` /
`gettxoutsetinfo` need, and those are rare. A hash-indexed store
should win on commit cost and compactness at scale.

## Design

`CoinsBackend` gains an engine marker in `meta` (`engine` byte;
absent = `Redb`, so existing datadirs open unchanged). Under
`Engine::Hash` the coins table moves out of redb entirely:

- `coins.idx` — 64 B header + open-addressed slots, 48 B each:
  `[key 36 | offset u64 | len u32]`. `offset == 0` means empty.
  Linear probing, grow ×2 at 70 % load, backward-shift deletes.
- `coins.dat` — append-only log of Compact-encoded coin records;
  in-place overwrite when a replacement fits its allocation.
- `coinsdb.redb` — still owns undo + meta; commits order
  log → index → fsync → meta tx, so a torn index is replayed
  idempotently from the sidecar (updates are keyed by outpoint).

Keyed hashing: SipHash-1-3 with per-database random keys in the
index header. Unkeyed would be a probe-length DoS — outpoints are
attacker-influenced.

Reads go through a single 4 KiB page cache — a probe walks adjacent
slots sharing one page, so a get costs ~1 index `pread` + 1 record
`pread`. (mmap would be zero syscalls but the workspace forbids
`unsafe`.) Iteration reads `coins.dat` in one sequential sweep.

Canonical-order consumers (`coinstats`, dumps) sort externally —
the unordered physical layout is invisible to them.

## Method

- `coinsdb_layout` bench — 500k realistic-mix coins: bulk insert,
  point reads, full iteration, block-shaped commits, allocated bytes.
- `snapshot_bench synthetic 5000000` — 5M random-order ingest,
  whole-dir allocated size (`st_blocks`), under each engine.
- Correctness gate: `diff_segment.py --every 1`, all 501 real
  2009-era mainnet blocks replayed through the hash engine vs Knots.

## Results

`coinsdb_layout`, 500k coins:

| engine | bulk ins/s | point reads/s | iter | block commits/s | file |
|---|---|---|---|---|---|
| redb-compact | 420k | 714k | 69 ms | 119 | 94.5 MiB |
| **hash** | 342k | 557k | 124 ms | **234** | **63.4 MiB** |

`snapshot_bench synthetic 5000000`, random-order ingest:

| engine | import | datadir |
|---|---|---|
| redb-compact | 198k coins/s | 1.0 GiB |
| **hash** | **229k coins/s (+16 %)** | **0.5 GiB (−50 %)** |

Differential correctness: PASS — all 501 blocks, identical verdicts
and byte-identical UTXO state at every height under the hash engine.

## Analysis

- **Commits: hash wins decisively (+97 %)** — a block's dirty set is
  a few thousand staged slot writes vs B-tree page churn.
- **Ingest crossover**: hash loses at 500k (−20 %, per-key syscall
  overhead beats tree-descent cost when the whole B-tree is cached)
  but wins at 5M (+16 %) — depth grows the tree's cost while the
  hash stays flat. The trend favors hash at real scale.
- **Reads: hash still loses (−23 %)** — two `pread` syscalls vs
  redb's zero-syscall mmap. The workspace `unsafe` forbid blocks
  mmap; a per-crate exception would likely flip this.
- **Iteration: hash loses ~1.8×** — sequential whole-log sweep vs
  redb's page walk (was 5× when each record was a separate pread).
  Affects coinstats/dumps only.
- **Size: hash halves the store** — packed 48 B slots + append log
  vs B-tree page overhead.

## Honest gaps

- No 170M-coin run yet — the win at 5M projects but isn't proven.
- Read regression needs the mmap variant to settle.
- Undo/meta still in redb — the hybrid is deliberate (atomic
  bookkeeping) but means the sidecar's write cost is shared.
- Crash-path replay is designed-for, not fault-injected yet.

## Status

Opt-in via `AVILA_COINS_ENGINE=hash` on fresh datadirs; redb remains
the default. Not a replacement — a measured alternative with a real
tradeoff profile.

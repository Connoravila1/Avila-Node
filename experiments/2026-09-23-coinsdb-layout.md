# Experiment: coinsdb record layout (encoding, commit order, cache)

Status: complete — Compact adopted as the default format for fresh
databases; sorted-key commits adopted unconditionally.

Roadmap gate/workstream: W4 (storage) — the first layout experiment
under the kernel/profile architecture.

Scorecard rows: P4 (storage), P1 (validation)

## Question and hypothesis

The coinsdb record layout is a free internal choice — nothing in
consensus or RPC observes it. How much does it cost to store coins
naively (`i64 value | varbytes(script) | u32 height | u8 coinbase`,
~39 B for a P2PKH coin) versus compactly, and what do commit order and
the redb cache budget do independently?

Hypothesis going in: (a) Core's `Coin` serialization (VARINT
height/code + `CompressAmount` + `CompressScript` type-ids) roughly
halves record size on standard outputs and pays for it with varint
decode cost on point reads; (b) committing a dirty map in key order
beats HashMap-random insert order on B-tree leaf fills; (c) the redb
cache budget matters mostly for full-table scans, not point work.

## Variants

- **Legacy** (baseline): original field order, ~39 B/coin.
- **Compact**: byte-identical to Core's `Coin` serialization —
  `VARINT(height<<1|coinbase)` + `VARINT(CompressAmount)` +
  `VARINT(size_id) | payload` — reusing the `utxo_snapshot` codec
  already proven byte-exact against Core's `dumptxoutset` format
  (commit d98509a). ~26 B for the same P2PKH coin; witness/nonstandard
  scripts take the raw-payload fallback.
- **Commit order**: `commit_inner` sorts the dirty map by key before
  inserting (sequential leaf fills vs random splits).
- **Cache**: redb `set_cache_size` — default 1 GiB vs 32 MiB vs 4 GiB.

Format persistence: a `format` byte in the `meta` table, stamped at
database creation. Existing databases (no marker) open as Legacy —
no migration, no silent mixing; `open_with_format` errors on a
stored/requested mismatch.

## Workload and method

- `examples/coinsdb_layout.rs`: 500k coins, mainnet-shaped mix
  (~45% P2PKH, 25% P2WPKH, 12% P2SH, 12% P2TR, 4% bare P2PK, 2%
  OP_RETURN-ish), varied amounts incl. dust and coinbase-era 50 BTC.
  Measures: 100k-entry bulk commits, 60k point reads, `iter_coins`
  full scan, 50 block-shaped 2k-entry commits, file size.
- `examples/snapshot_bench synthetic 5000000`: 5M random-order coins
  through the real `insert_synthetic`/`flush_partial` ingest path —
  the scale test (SNAP_BENCH_FORMAT selects the codec).
- Correctness: `tools/diff_segment.py --every 1` on the real
  `mainnet-blocks-000000-000500.dat` fixture — 501 blocks, UTXO state
  compared against Knots after *every* block.

## Results

coinsdb_layout (500k coins, single run, tmpfs — ±10% run noise):

| format | bulk ins/s | point reads/s | iter 500k | block commits/s |
|---|---|---|---|---|
| legacy (unsorted) | 321–331k | 635–714k | 65 ms | 101–107 |
| compact (unsorted) | 358–427k | 668–776k | 68–78 ms | 101–124 |
| compact @32 MiB cache | 341k | 671k | **125 ms** | 88 |
| compact @4 GiB cache | 424k | 665k | 74 ms | 113 |

Sorted-key commits alone (measured by patching order, both formats):
bulk 321k→400k legacy, 358k→427k compact — **+20–25%**, now
unconditional.

snapshot_bench `synthetic 5000000` (random-order ingest, real path):

| format | import | coinsdb.redb |
|---|---|---|
| legacy | 193k coins/s | **2.0 GiB** |
| compact | 201k coins/s (+4%) | **1.0 GiB** |

Differential correctness: 501 real 2009-era mainnet blocks through
both engines under Compact — identical verdicts and UTXO state at
every height (`diff_segment.py --every 1`, PASS).

## Analysis

- **Compact halves the database file** at scale — 2.0→1.0 GiB at 5M
  coins. At 500k the file sizes were identical (128.5 MiB): redb's
  region-granularity allocation hides record deltas until the tree
  dominates the file.
- Compact writes are *faster*, not slower — fewer bytes per record
  beats the encode cost. Bulk +12–25%.
- Point reads are roughly neutral (within noise): varint decode ≈ the
  saved page-fetch bytes at this scale. A cold-cache regression may
  exist at larger depth (snapshot_bench showed 202k→167k/s on a tiny
  77-read sample — inconclusive).
- **Small caches punish scans**: 32 MiB cache doubles `iter_coins`
  cost — the snapshot-dump/`gettxoutsetinfo` path streams the whole
  table. Point reads unaffected. Cache size is a real profile knob.
- redb page size is file-format-fixed at 4 KiB (test-only knob) —
  not a tunable dimension.

## Verdict

Adopted. Compact is now the default for fresh databases (Legacy still
reads/writes correctly via the meta marker), and commits insert in
key order unconditionally. Net effect at scale: ~50% smaller UTXO
database, faster ingest, identical consensus state — proven on real
historical blocks, not synthetic agreement.

Honest gaps: no measurement at true mainnet scale (170M coins — the
sorted-ingest collapse documented in `2026-09-22-coinsdb-snapshot-ingest`
may behave differently under compact; worth a dedicated 20M+ run);
point-read cost on cold cache is unresolved sign/magnitude.

# Experiment: coinsdb snapshot ingest at scale

Status: complete (preliminary — synthetic data, single machine, single run per mode)

Roadmap gate/workstream: W4 (storage), W3 (snapshot bootstrapping input)

Scorecard rows: P1 (initial validation), P4 (storage)

Operating profile: archival full validation; single NVMe node, storage-ingest focus

## Question and hypothesis

Can the redb-backed coins view ingest a full-scale UTXO snapshot through
`loadtxoutset`'s import path (`insert_synthetic` → 2M-entry dirty-map batches →
`commit_partial`) at usable speed, and what does the resulting database cost on
disk?

Hypothesis going in: throughput is set by B-tree insert cost and degrades with
tree depth; key arrival order determines whether inserts hit the append fast
path or pay random page splits. Observation that would disprove the storage
choice: collapse to unusable ingest rates on the *sorted* stream that real
`dumptxoutset` files provide.

## Baseline and candidate

- Candidate: `avila-consensus` coinsdb (redb 2.x B-tree, `&[u8]→&[u8]` coins
  table, 36-byte `txid||vout-LE` keys) at the commit being measured, with the
  new bounded-batch partial-commit path.
- Reference points: Bitcoin Core's LevelDB chainstate (~66 B/coin effective,
  LSM compaction ingest) and Gocoin's RAM-resident set as the two design-axis
  ends from docs/NODE_LANDSCAPE.md. No Core ingest time measured this run —
  disk budget foreclosed a live `dumptxoutset` (needs ~11 GiB dump +
  ~GiB-scale output on a host with ~13 GiB free).
- Build: `cargo build --release --example snapshot_bench`, rustc per
  rust-toolchain, Linux x86-64, NVMe (ext4, 99%-full filesystem during parts
  of the random run — noted as a confound for that run's tail).

## Workload and method

`examples/snapshot_bench` drives the same `UtxoSet` ingest path
`Chainstate::load_snapshot` uses. Three modes:

- `file <path> <base_height>` — real Core dump (not run: no dump file).
- `synthetic <count>` — generated coins, uniform-random 256-bit txids
  (xorshift64*, fixed seed), vout 0–3, mainnet-shaped script mix
  (~35% P2PKH, ~18% P2SH, ~25% P2WPKH, ~7% P2WSH, ~13% P2TR, ~2% bare),
  heights uniform below base. **Adversarial bound**: random key order.
- `synthetic-sorted <count>` — identical generated set, sorted by the
  36-byte coinsdb key before ingest. **The real-dump case**: Core writes
  snapshots iterating its chainstate in key order, so dump files arrive
  sorted by construction.

Synthetic caveat: generated data measures the storage/ingest path only — no
wire decompression, no real tx graph. Key/value sizes and key ordering match
the real workload's properties.

Runs: `synthetic 50000000` (killed at ~40M coins / 26 min — rate collapse
made completion non-informative) and `synthetic-sorted 20000000` (completed).

## Correctness evidence

- `coins_len` after sorted run: 19,999,950 — consistent with 20,000,000
  inserts + measurement-commit deltas (306 sampled spends, 255 unique
  inserted keys after test-txid wraparound). No lost or double-counted
  coins.
- Point-read sample: all 306 sampled outpoints hit after ingest.
- Partial commits leave `tip_height` unadvanced by design; a torn import
  reads tip=old with orphaned coins overwritten on re-import. `coins_len`
  delta accounting verified overwrite-aware (reinsert = no double count).

## Results

| Run | Coins | Time | Throughput | File |
|---|---|---|---|---|
| synthetic (random order) | ~40M of 50M (killed) | 26 min | ~234k/s at shallow depth → ~10–15k/s at ~40M | ~6.3 GiB at kill |
| synthetic-sorted | 20M | 140 s | **~142k/s sustained** | 4.0 GiB |

Post-load on the sorted set: 306 point reads in 72 ms (~4.3k reads/s,
~230 µs/read uncached); mixed 306-spend + 306-insert commit = 89 ms.

Derived: ~200 B/coin on disk (~3× Core LevelDB's ~66 B/coin — redb stores
full keys and uncompressed records plus page slack). Sorted extrapolation
to the real ~166M set: ~20 min ingest, ~33 GiB file.

## Interpretation and reuse

1. **The production path is fine.** `loadtxoutset` feeds coinsdb the sorted
   stream real dumps provide; that case sustains ~142k coins/s — a full
   mainnet snapshot imports in tens of minutes, bounded by sequential
   write bandwidth, not B-tree random I/O.
2. **Ordering is the whole game.** Random-order ingest collapses ~15× by
   ~40M depth — B-tree page splits on random keys dominate. Any future
   ingest path that can't guarantee sorted input (mempool-bulk loads,
   foreign dumps) needs a presort or an LSM.
3. **Disk cost is the honest tradeoff.** ~3× Core's chainstate density —
   acceptable for archival profiles, argues against redb as the
   low-resource profile's coins store without compaction work.
4. **Follow-ups**: rerun `file` mode on a real dump when ~25 GiB scratch
   exists; measure crash-torn import recovery; test whether batching to
   4M/8M or a bulk-load API changes the sorted rate; compare fjall/LSM
   backend on the identical synthetic streams (the ordering sensitivity
   result predicts LSM wins the random case).

Smallest reusable piece: the 2M-entry `commit_partial` batching pattern
(`UtxoSet::flush_partial_to_backend`) — any large B-tree bulk load benefits
from bounded write transactions regardless of backend.

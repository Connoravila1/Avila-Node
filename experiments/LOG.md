# Experiment log

Running record of every experiment tried — adopted, rejected, blocked,
or inconclusive. One line per attempt; details live in the dated docs.
A "failed" or "inconclusive" row is a result, not a gap — write it down.

| # | Date | Experiment | Hypothesis | Verdict | Key numbers | Doc |
|---|------|-----------|------------|---------|-------------|-----|
| 1 | 09-14 | RPC compat matrix vs Core 29.4 | RPC surface can be made byte-compatible | **adopted** | 75 calls exact-match | [rpc-compat-matrix](2026-09-14-rpc-compat-matrix.md) |
| 2 | ~09-20 | Header acceptance baseline | Header-chain parity is provable offline | **adopted** | `check_headers_core.py` 0 mismatches | [header-acceptance](2026-09-header-acceptance-baseline.md) |
| 3 | 09-22 | coinsdb snapshot ingest | redb can absorb AssumeUTXO-scale writes | **adopted w/ caveat** | 20M sorted OK; random ingest collapses ~40M | [snapshot-ingest](2026-09-22-coinsdb-snapshot-ingest.md) |
| 4 | 09-23 | Compact coin codec (Core `Coin` format) | Core's codec halves record size at scale | **adopted** | 2.0→1.0 GiB at 5M; +12–25% bulk | [coinsdb-layout](2026-09-23-coinsdb-layout.md) |
| 5 | 09-23 | Sorted-key commits | Sorting dirty map removes B-tree churn | **adopted** | +20–25% bulk commits | same doc |
| 6 | 09-23 | redb cache knob | Cache size is a real profile dial | **adopted (as knob)** | 32M cache doubles full-scan cost; reads unaffected | same doc |
| 7 | 09-23 | redb page size | Page size tunable | **rejected — impossible** | redb pins 4 KiB in file format | same doc |
| 8 | 09-23 | Hash-indexed coins engine | UTXO set has no range queries; O(1) probe beats O(log n) tree | **adopted (opt-in)** | 40M: 2.0× ingest, 2.5× reads, 5.3× commits, −44% disk; loses below ~1M | [hash-engine](2026-09-23-coinsdb-hash-engine.md) |
| 9 | 09-23 | mmap index reads (hashstore) | mmap kills the 2-syscall probe cost | **blocked — unsafe forbid** | workspace `-F unsafe-code`; page-cache fallback instead | same doc |
| 10 | 09-23 | Windowed bulk scans | 1 MiB read windows for iter/rehash | **failed — bug caught** | `1 MiB % 48 ≠ 0` misaligned every slot past 1 MiB; fixed to whole-slot windows | same doc |

| 11 | 09-23 | Real-disk 40M ingest | tmpfs numbers should hold on NVMe | **partial — caveat was real** | hash 1.9× ingest / 2.8× commits / −44% disk hold, but cold reads lose 0.4× (append-log scatters placement → no locality) | [hash-engine](2026-09-23-coinsdb-hash-engine.md) |

| 12 | 09-23 | Slot-order log compaction | Clustered placement restores cold-read locality | **partial — bar not met** | 15.8k→22.6k/s (+43%) post-compact; still 2× behind redb 46k/s. Placement helps, per-lookup page touches dominate | [hash-engine](2026-09-23-coinsdb-hash-engine.md) |

| 13 | 09-23 | Net-effect writes: tombstone elision | Same-epoch create+spend tombstones are pure waste | **adopted** | −22–25% backend ops; 501-block diff PASS | [net-effect](2026-09-23-net-effect-writes.md) |
| 16 | 09-23 | Crash fault-injection on hash engine | Commit ordering survives torn writes | **2 findings, both fixed** | torn records decoded to wrong-but-valid coins (silent corruption) → +4B keyed record tag, tears now misses; coins-ahead-of-tip tear invisible → index-header watermark, open errors loudly. File-level sim; compact() still unsafe | [fault-inject](2026-09-23-fault-injection.md) |


| 32 | 09-24 | Parallel ECDSA advice with bounded recovery | Does the replay gain survive eight workers, bad hints and durable state? | **qualified offline prototype; not enabled in production** | 3 repeats: mainnet Script CPU 25.05 → 19.29 s (−23.0%), elapsed 19.80 → 16.43 s (−17.0%); complete regtest CPU −7.2% RAM / −5.3% disk+reopen. All-corrupt advice retries 7,351/183,782 checks in 8 bounded groups, +2.5% CPU vs ordinary. 93 replay runs + 10 additional checks; invalid-spend rollback and UTXO hashes pass; 479 unit tests pass, 2 existing ignores. Tradeoffs: sampled summed RSS 59 → 180 MiB; framed sidecar 3.57 MB; two-pass preparation 54.38 s. Full mainnet IBD unmeasured. | [parallel-replay](2026-09-24-ecdsa-parallel-replay.md) |

| 34 | 09-24 | Address-index cost model | What does the Electrum-style index cost? | **measured — build ~free, serve needs disk-backing** | Spend fixture: connect delta ~0% (8.56s vs 8.64s); scindex.dat ~38B/entry. In-mem by_script map ~46B/entry → ~200GB at mainnet — the query layer needs hashstore backing (bounded refactor, already designed). | [addr-index](2026-09-24-address-index-cost.md) |

| 32 | 09-24 | Live network sync (signet) | Can the node sync against real peers? | **works — fetch scheduling is the limiter** | Signet, DNS-seeded: 208 blocks connected in 15.4s; resumed run reached 1124 blocks/66k headers in 640s (~1.7 blk/s — in-flight stays 0-96, scheduler conservative; validation never the bottleneck). Resume works. Mainnet-scale unproven. | [live-signet](2026-09-24-live-signet-sync.md) |
| 33 | 09-24 | Delta overlay — snapshot as lowest UTXO layer | Can SnapshotRun serve as the read base under the delta? | **partial adopt — read shim done, tested** | `UtxoSet.snapshot` fourth layer; `SnapshotRun::index` portable fallback indexer. Overlay test found 2 real get() bugs: EOF window clamp + zero-count-group underflow on misses. 480 tests pass. activate integration (attach+snapverify+persist) deferred — touches Claude's patch area. | [delta-overlay](2026-09-24-delta-overlay-shim.md) |

| 31 | 09-24 | Verification-transparency ledger | Can the node report its own trust state as a typed value? | **adopted** | `Chainstate::validation_report()` + `getvalidationreport` RPC: connected/header heights, snapshot base+commitment+replayed_height, assumed/unproven ranges, verified_fraction. Snapshot test: fresh→replay→verified 0.0→1.0; full node 1.0. | [validation-report](2026-09-24-validation-report.md) |

| 30 | 09-24 | Speculative block pre-validation | Can a predicted mempool template pre-pay connect work? | **SUBSUMED by #20** | 625-block spend fixture, 512MiB cache: baseline 6.6s (script 6268ms) → verified-prediction 257ms (script 0ms, 25.7×); +prefetch 289ms — worse, read was already 9ms. Verified-tx cache captures the whole win; residual is apply+bookkeeping, no lever. Mainnet ~90% overlap untested — live-sync's job. | [predict](2026-09-24-spec-block-prediction.md) |

| 29 | 09-23 | One-byte ECDSA advice through real Script and chainstate replay | Does #27's kernel gain survive recipient overhead and false signature results? | **replay win; full mainnet IBD unmeasured** | One script thread, 3 repeats: 24 actual mainnet blocks / 183,782 ECDSA attempts, including 6,137 false results: 27.65 → 18.41 s (−33.4% elapsed, −29.0% combined CPU). Complete 625-block regtest replay: 6.17 → 4.22 s, identical 12,995-coin UTXO hash. Early 501-block mainnet loses 22.9% elapsed (only 10 checks). Mainnet hints 183,782 B; two-pass preparation 57.18 s separately; bad parity + whole-sample retry 61.66 s. Script edge cases, hostile/missing hints, worker exit and sanitizer/protocol tests pass. Isolated copied workspace, probabilistic batching, no production changes by this experiment. | [historical-replay](2026-09-23-ecdsa-historical-replay.md) |

| 27 | 09-23 | Native ECDSA batching with untrusted nonce advice; deterministic batch inversion | Does #19 rule out faster local signature verification? | **kernel win; not integrated IBD** | Same pinned libsecp, 16,384 synthetic signatures, 3 repeats: 127.56 CPU µs/sig ordinary → 70.06 with 1 B advice (1.82×) or 56.11 with 33 B (2.27×), batch 8,192. Helper generation 130.60 µs/sig separately; random batch acceptance. Bad advice + fallback costs 44–58% extra CPU. Deterministic no-advice batch inversion saves only 0–3%. Adversarial, cancellation and rare-x tests pass with ASan/UBSan/VERIFY. | [ecdsa-advice](2026-09-23-ibd-ecdsa-advice.md) |

| 26 | 09-23 | Audit read floor; authenticated snapshot directory | Can startup avoid the whole-file index scan? | **prototype: prepared open 0.14–0.25 s** | Same synthetic 170M coins / 9.31 GB: raw cold-advised reads 11.4–13.1 s; 38.96 MB authenticated directory opens in 0.14–0.25 s across six runs, with 2,594/2,594 coin-body checks each. Preparation costs 23.55 s separately and requires a trusted root; not integrated node startup. Pipelined full scan 21–56 s: no reliable sub-20 s win. Revises #25's physical-floor interpretation. | [read-floor](2026-09-23-snapshot-read-floor.md) |

| 25 | 09-23 | Index-only load (SnapshotRun) | Is the copy itself the cost? The snapshot file is already the right format | **170M in 20s — ~8.3M coins/s** | Original interpretation (see #26 correction): ~130MB/s writes → the 11.4GB run can't go faster (~85s). Sparse index over txid-group starts (442k entries, ~19MB) + seek-reads into the file itself → 20s index build, 2.8k/s point reads. Usable node ~3-4min was an estimate, not an integrated-node measurement. File must persist + delta layer for writes. | [sortedrun](../crates/avila-consensus/src/sortedrun.rs) |

| 28 | 09-23 | Snapshot load at disk speed + midstate-hint verification | The 20 s "read floor" is a page-cache/CPU artifact, and Core's sequential hash check can be split across cores without new trust | **scan 25 s → 5.1 s; verified load 13.8 s** | Drive is NVMe (990 EVO Plus, PCIe 3.0 x4), not SATA: O_DIRECT reads 9.3 GB in 3.5 s (2.5–2.7 GB/s) vs 16.7 s buffered single-thread. Writes really are slow (0.15–0.32 GB/s O_DIRECT), so index-only stays right. 170M file, same box, load ~12: parallel exact scan (resync + stitching, 8 thr) **5.1 s**, 0 fallbacks, vs old `runindex` 25 s cold. Streaming `hash_serialized_3` straight from the file (no 170M-coin materialization; matches `coinstats` in tests) 18.8 s sequential; **13.8 s** with untrusted SHA-256 midstate hints (140 hints = 17 KB, same hash; ~20 CPU-s, so ~3–4 s idle-box est., unmeasured). Found: old byte walkers skip Core's VARINT `n++` (desync on scripts ≥122 B), `decompress_amount` can panic under overflow-checks. Zero-scan (interpolation) lookups: **unfinished** — phantom resync inside big groups; tests ignored | [snapverify](../crates/avila-consensus/src/snapverify.rs) |


| 24 | 09-23 | SortedRun bulk-load (LSM base layer) | Can the B-tree be bypassed? The stream is already key-sorted | **12.4× ingest — 170M in 106s** | decode-only 4.06M/s (42s) proved insert = 97% of time; redb ceiling ~140k/s (4 shards → 109k/s, worse — I/O bound). SortedRun: sequential append + sparse index (512 stride, ~15MB RAM) → **1.6M coins/s, 11.4GiB, 3.7k/s reads**. Usable node ≈ ~4-6min vs Core ~10min+. Needs delta overlay to go live | [sortedrun](../crates/avila-consensus/src/sortedrun.rs) |

| 23 | 09-23 | Snapshot load at 100M→170M scale (hash vs redb) | Does snapshot ingest scale to mainnet size? | **hash cache-cliffs; redb 129k/s at 170M** | redb: 100M in 653s (153k/s, 7.4GiB) → **170M in 1315s (129k/s, 12.5GiB, 3.5k/s reads)** — measured at real mainnet scale. hash: ~18k/s — random probes on 12.9GB index miss page cache; `reserve()` pre-size 7ms vs ~17 resize rewrites. **Headline: usable node ~25min (headers + 22min load + 8.7GB file)** | [snapshot_bench](../crates/avila-consensus/examples/snapshot_bench.rs) |

| 22 | 09-23 | assumeutxo time-to-usable (end-to-end) | Does snapshot load beat full sync? | **144× to usable tip** | 625-blk fixture: full sync 4.4s vs headers+snapshot-load 0.03s; background_step verifies all 625 pre-snapshot blocks in 4.2s (honest, not trusted). Load ~650k coins/s → mainnet est ~4-5min for 170M + ~4GB snapshot file; **pooled background_step: 4.4s→1.7s (2.6×)** — snapshot path now beats classic sync on *both* time-to-usable AND time-to-fully-verified | [assumeutxo_bench](../crates/avila-consensus/examples/assumeutxo_bench.rs) |

| 21 | 09-23 | Head-to-head vs Knots 29.3 (same fixture) | Is Avila actually faster than Core-family? | **1.76× validation throughput** | Knots Connect total 2456ms/628blk (256 blk/s); Avila spec-connect ~1.4s wall (~450 blk/s); sequential ~215 blk/s (~0.84× serial). Edge = cross-block barrier elimination, not crypto. On mainnet-dense blocks the gain shrinks toward tail-overlap bound | — |

| 20 | 09-23 | Verified-tx cache (mempool→block dedup) | Mempool-verified txs re-verify at connect — skip them | **adopted** | 15,364 hits/0 misses on spend fixture; connect script share → ~0 for seen txs (2.9s→0.17s per 625 blocks); flag-containment rule (block_flags ⊆ verified_flags) keeps it sound across softfork boundaries | see sigchecker::mark_scripts_verified |

| 19 | 09-23 | ECDSA batch cost model (k256 primitives) | Can SP-batch beat libsecp's 92µs/sig? | **REJECTED for tested implementation** | batch-of-8 ≈43ms vs 736µs individual (~60× slower): k256 scalar mul alone (120µs) exceeds a whole libsecp verify; SP resultant ~41ms. This rejected the k256/SP path, not all ECDSA batching. The original fixed-floor interpretation is superseded by #27's isolated native/advice experiment; production integration remains open. | [probe](../crates/avila-consensus/examples/ecdsa_batch_probe.rs) |

| 18 | 09-23 | ECDSA batch feasibility (research spike) | Can standard (r,s)-only ECDSA batch-verify? | **feasible-bounded; scope corrected by #27** | Original SP proposal: ~2× at batch ≤9, unmeasured whole-node gain and high implementation risk. The missing-R objection applies without advice; #27 tests locally checked out-of-band hints for unchanged historical signatures. Changing on-chain encodings is not required for that experiment; randomized acceptance and helper costs must be explicit. | [ecdsa-batch](2026-09-23-ecdsa-batch-feasibility.md) |

| 17 | 09-23 | End-to-end sync pipeline timing | Is connect the bottleneck of the whole accept path? | **adopted — decisive** | connect=97% of wall (scripts ~92%); decode+headers+flush ~3%. Spec-connect's 2× is real end-to-end; storage is ~1.5–4% of the node at this scale; next lever on the dominant share is algorithmic (batch sig verify) | [sync-pipeline](2026-09-23-sync-pipeline.md) |

| 15 | 09-23 | Speculative cross-block script pipelining | Persistent pool + deferred wait overlaps serial N+1 with drain N | **adopted (exp-grade)** | 205→520 blocks/s (2.5×) on 26-tx/blk fixture — density-flattered; mainnet-dense expected 5–15%; rollback+mark_invalid on pending failure verified | [spec-connect](2026-09-23-speculative-connect.md) |

| 14 | 09-23 | Connect phase timing | UTXO storage share of validation unknown | **adopted — decisive** | 625 spend-dense regtest blocks: scripts ~95%, read+apply ~3.5%, 0 backend commits under cache; engines identical. Storage wins are capacity/ingest, not latency; cross-block script overlap is the real lever | [connect-timing](2026-09-23-connect-timing.md) |

## Pending / running

- Inline small records into the slot (wide-slot variant) — the 2-page
  touch per read is structural; only colocating record with index
  slot cuts it to 1.

## Queued candidates (proposed, not started)

Listed in rough priority; each entry has the hypothesis and the cheapest
first measurement that would kill or confirm it.

1. **Live network sync.** The credibility gate — fixtures have carried all
   claims so far. First step: signet/testnet headers+blocks against real
   peers; measure tip-follow latency and peer misbehavior handling.

2. **Delta overlay integration for SnapshotRun.** The ~90s-to-usable path
   is bench-proven; making it real needs reads to fall through to the
   indexed snapshot file with spends/inserts in the mutable layer, plus
   `activate_snapshot` streaming (no 170M materialization — OOMs at scale).
   First step: `UtxoSet` read-path shim + diff-test vs current backend.

2. **ECDSA advice on real history.** #27's kernel win (1.8-2.3×) is
   synthetic. First step: extract real sig-check traces from a historical
   segment and replay them through the advice machinery — tests sighash
   variants, codeseparator, and edge script forms the kernel bench skipped.

3. **Built-in address index / electrum-style serving (profile).** Point a
   wallet at your own node, no external indexer. Controversial storage cost
   is exactly what profiles are for — opt-in distro, consensus untouched.
   First step: cost model — index size + write overhead on the fixture.

3. **Erlay-style tx reconciliation (BIP-330).** ~44% relay-bandwidth
   savings; Core hasn't shipped it (simplified recon-only variant is in
   Warnet testing upstream). Interop is the open question — today ~no peers
   speak it. First step: implement BIP-330 recon-only message handling and
   measure reconciliation rounds between two Avila nodes.

4. **Differential fuzzing vs Core/Knots.** Continuous random-block/tx
   generation with byte-exact comparison — turns "compatible" into a
   monitored property rather than a claim. First step: fuzz harness on the
   existing diff fixture generator, seeded corpus from past bugs.

5. **Utreexo research program.** BIPs 181-183 now have assigned numbers;
   rustreexo 0.6.0 exists. Validate blocks against accumulator + proofs —
   ~KB of state vs 12GB UTXO set. Months, not days; needs bridge-node
   proof supply. First step: rustreexo spike — add/delete/prove round-trip
   on the fixture's UTXO set, costed against CoinsBackend.

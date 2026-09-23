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

| 15 | 09-23 | Speculative cross-block script pipelining | Persistent pool + deferred wait overlaps serial N+1 with drain N | **adopted (exp-grade)** | 205→520 blocks/s (2.5×) on 26-tx/blk fixture — density-flattered; mainnet-dense expected 5–15%; rollback+mark_invalid on pending failure verified | [spec-connect](2026-09-23-speculative-connect.md) |

| 14 | 09-23 | Connect phase timing | UTXO storage share of validation unknown | **adopted — decisive** | 625 spend-dense regtest blocks: scripts ~95%, read+apply ~3.5%, 0 backend commits under cache; engines identical. Storage wins are capacity/ingest, not latency; cross-block script overlap is the real lever | [connect-timing](2026-09-23-connect-timing.md) |

## Pending / running

- Inline small records into the slot (wide-slot variant) — the 2-page
  touch per read is structural; only colocating record with index
  slot cuts it to 1.
- ~170M-scale ingest — the full-depth proof.
- Crash fault-injection on the hash commit ordering (incl. the
  compact() rename torn-write gap).

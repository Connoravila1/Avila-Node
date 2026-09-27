# IBD capacity measurements — 2026-09-27

Laptop: 8 script workers, sustained clocks ~2.4–3.4 GHz (recorded per-run).
All measurements under `tools/guard_run.sh` (kernel cgroup caps); every
receipt line records exit/cap/peak/wall/cpu_s/mhz min-mean-max/load/memavail.
Build `9986ea5` clean — `build_rev` has no `+dirty`.

## Dedicated window run (454001–454301, complete comparison)

`run-manifest.json` → `wall_s_total` covers receipt hashing; outer guard
wall **98 s** vs internal `wall_s` 83.1 s (delta = manifest hashing of
corpus/boundary/headers/export). Process RSS HWM **7,057,682,432 B =
6,729 MiB**; cgroup sampled peak 10,239 MiB vs 10,240 MiB cap (page cache
for the streamed 3.6 GB export counts inside the cgroup). Full completion
flags true; export sha256 `865d32cf…44cd3168` unchanged.

## Era workload scaling (full-slice diagnostics, headers bound)

| era | blocks | txs | non-cb inputs | exec inputs | script s | verified in/s |
|---|---:|---:|---:|---:|---:|---:|
| ~232k | 3,993 | 1,366,474 | 3,074,093 | 2,564,033 | 31.7 | 80,989 |
| ~310k | 1,723 | 678,784 | 1,943,716 | 1,294,680 | 16.7 | 77,745 |
| ~345k | 1,637 | 1,101,058 | 3,374,835 | 1,982,898 | 26.2 | 75,594 |
| ~380k | 475 | 504,532 | 1,362,984 | 674,086 | 10.0 | 67,173 |
| ~421k | 623 | 1,032,100 | 2,399,736 | 1,122,845 | 28.4 | 39,528 |
| ~454k | 301 | 615,804 | 1,303,682 | 1,303,682 | 31.8 | 41,041 |
| ~956k (Core pruned tail, xor) | 662 | 2,932,455 | 5,123,793 | 3,746,089 | 95.0 | 39,451 |

Every slice: `known_invalid:false`, zero violations, all present blocks
contextually checked. Corpora: `experiments/results/gate4/era/corpus-*`.

Notes:
- Verified-inputs rate halves from early to dense pre-segwit era
  (~81k→41k/s); the measured taproot-era rate (39.5k/s) matches dense
  pre-segwit — witness-era per-input cost ≈ late-legacy.
- The 956k slice ran with mean clocks ~2.38 GHz (clamped vs 3.0 GHz on
  earlier runs) and loadavg ~7–11 — its rate understates dedicated
  capacity somewhat.
- `headers_chain_missing:662` at 956k is correct incompleteness: the
  saved CHAIN manifest ends at 456,082 (export predates tip).
- Segwit era (481,824–709,631) block bodies are absent from both
  datadirs (blk store spans 229k–455k + strays; Core pruned tail covers
  956,060–957,073) — no local measurement. Per-input estimate 45k/s.
- Zero-height BIP34 data below 227,931 (genesis sparse era) is
  unmeasurable via corpus (heights undecodable) — estimated ~35–45M
  inputs at simplest-script rate.

## Full-IBD forecast (this laptop, current architecture)

| cost class | basis | estimate |
|---|---|---|
| script verification | measured rates × era inputs (≈3.7B total: 40M gen, 500M preSW, 1.2G SW, 2.0G tap) | **~24 h** |
| join/emit/predicate | ~6 µs/input measured | ~6 h (partially overlapped) |
| parse + I/O | ~500 GB @ ~240 MB/s | ~0.6 h |
| header index | measured 968,778 inserts | ~3.4 s |
| UTXO materialize+export at tip | ~140M coins ≈ 3× the 45.6M boundary | ~1 min |
| **pipeline total** | serial | **~28–30 h** |

Acquisition (~500 GB blocks): 1.4 h @ 100 MB/s, 5.6 h @ 25 MB/s — the
network alone exceeds the one-hour objective on most connections.

## What reaching one hour requires (~25–30× aggregate)

1. **Batch ECDSA verify** (3–5× on legacy/P2WPKH inputs) and **batch
   Schnorr** (2–4× on taproot-era inputs) — the dominant lever.
2. **Higher thread count**: 8→32 workers ≈ 4× on script stage.
   This laptop cannot provide it; a workstation could.
3. **Stage overlap**: parse+join+scripts pipelined vs sequential ≈ 1.2×.
4. **Bandwidth**: ≥140 MB/s sustained to fit 500 GB inside the hour —
   possible on datacenter links, not typical broadband.

Realistic path: this laptop + batch crypto ≈ 5–8 h; a 32-core machine ≈
1.5–2 h. One hour on commodity hardware is not supported by these
measurements; the objective should be restated as
"as fast as the machine allows without weakening validation" unless
higher-core hardware or substantially faster signature verification
enters scope.

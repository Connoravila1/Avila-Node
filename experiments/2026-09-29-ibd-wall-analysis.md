# IBD Wall Analysis — 2026-09-29 overnight session

## Objective

Determine whether Avila Node can do a fully-validating mainnet IBD
from an empty datadir materially faster than the assumed 4–6h floor,
without weakening any consensus check. The night's work attacked the
measured bottleneck chain end-to-end: signature deferral → peer
delivery → UTXO write-back → storage layout.

## The verdict

**The wall is the UTXO working set, not any single component.**
At ~460k the live set is ~180M coins — ~12–16GB as a readable map,
33GB on disk. Every block connect performs thousands of random
prevout lookups plus writes. All three storage postures cost:

| Posture            | Reads                        | Writes                          | Memory            |
|--------------------|------------------------------|---------------------------------|-------------------|
| RAM mirror (flat)  | fast                         | delta must still reach disk     | 12–16GB resident  |
| B-tree (redb)      | cold page-cache thrash       | 60–240s commits per ~1M entries | ~2–5GB            |
| Sorted-run files   | N-layer probe per miss       | 229ms sequential epoch writes   | small per layer   |

Under a 16GB cgroup cap the machine cannot hold flat (fast reads)
AND runs (fast writes) AND the async double-buffer at once. Each
optimization moved the pain; none removed it.

## What was proven tonight

**Signature deferral (advice stack) — proven, but not the wall:**
- Batch engine (k256 R-reconstruction, FS coefficients, bucket MSM):
  2.06–2.17× on corpus A/B, 2.50× on connect bench.
- Full wire pipeline: `sendadvice`/`getadvice`/`advice` negotiated
  over real TCP between two regtest nodes; `adv[d=1 b=1 f=0]` —
  one deferred batch verified clean, zero fallback.
- Per-record fallback to ordinary verify is intact — nothing trusted.
- Caveat: peers must serve advice; the public network does not.
- Caveat: live telemetry showed sig time ≈ 0 during connect — the
  mechanism works but wasn't the bottleneck.

**Async flush — proven, modest gain:**
- Double-buffered commit overlapping connect; `fl=` telemetry showed
  1.4M-entry commits in-flight while blocks connect.
- Bench residual 2061→470ms per commit (redb), 2773→248 (hash).
- Live rate ~1.6–3 blk/s — the commit still outlasted its window.

**Sorted-run flush — proven correct, rate unproven:**
- Epochs land as sequential files (`.sr`/`.del`/`.und`/`.ok`);
  `.ok` written last, markerless epochs dropped on restore.
- 3-way lockstep (redb/flat/runs) over the real corpus:
  2.45M spends, 3.4M creates, ~22 flushes — identical reads, `iter`
  equality. 569 consensus tests green.
- churn_bench @2048M: **229ms/commit residual, zero backend commits.**
- Live deployment confirmed epochs landing (5 `.ok` at 464k), but
  with flat refused for memory, reads hit disk — rate ~1.5 blk/s,
  flat-to-slower than baseline.

**Failed attempts — all predictable in advance:**
- 24 peers vs 8: no rate change — connect-bound, not delivery-bound.
- `AVILA_COINS_CACHE_MB=4096`: OOM — page cache + double buffer +
  replay map exceeds 12GB.
- Uncapped flat mirror: 16.3GB RSS during restore — the night's
  actual OOM driver (fixed via `AVILA_FLAT_MIB` cap override).
  Each of these outcomes was computable from memory/arrival-rate
  arithmetic before running the experiment; none required the
  laptop's hours to discover.

**Real bugs found by the harness:**
- `mark_invalid` never demoted tip → phantom invalid header stayed
  best-tip → `getheaders` served a dead-end branch → every fresh
  peer stalled. Fixed, plus `restore_tip` re-promotion guard. Both
  pushed (`f6bab34`).
- `UtxoSet::get`/`have` skipped the runs layer (test caught it).
- `SortedRun::scan_window` read past EOF on tail windows.
- In-flight flush budget missed the snapshot's bytes → OOM vector,
  now bounded (`map + flushing` together).

## Where the run stands

- Live node syncing under `AVILA_RUNS=1 AVILA_FLAT_MIB=6144` at
  ~464,975, 5 epochs attached, RSS ~3.5GB.
- Pushed: `63d0106` (async flush), `4373da1` (budget+knob), `feebeae`
  (dbcache), `9a70a1d`+`9a3f51f` (runs), `44e9656` (this log),
  `f6bab34`/`7726d11` (wire + invalid-tip fixes + dedupe).

## The remaining avenues, ranked

1. **Bounded flat mirror** — cap flat at ~4–6GB as a *partial* mirror
   (hot recent coins) so runs+flat+map fit in 12GB. The read-side
   win returns without the OOM. `rebuild_flat` currently refuses
   rather than partially building — it would need an incremental/
   capped-fill mode.
2. **Bloom/prefix filters per run layer** — a miss currently costs a
   bounded ~43KB window read per layer; a filter makes misses ~free.
   Cheap to add (`SortedRun` already has sparse indexes to slot it).
3. **Compaction** — merge run epochs back into redb (or run↔run) at
   low tip-rate so probe depth stays bounded on a full IBD.
4. **Swiftsync transient mode** (`AVILA_SWIFTSYNC=1` exists) — during
   IBD keep only a coin-tag aggregate, never materialize set members.
   This is the only design that *shrinks* the working set rather than
   relocating it. Verify-side plumbing exists; needs the full
   verification pass to be safe to use end-to-end.
5. **Utreexo** — spends carry their coins as proofs; removes the set
   from validation entirely. In-tree shadow exists; requires
   proof-serving peers (chicken-and-egg: only useful Avila↔Avila or
   once the network serves proofs).

## Honest bottom line

No component tonight proved a faster end-to-end IBD. The diagnosis
is now precise — the working set is larger than the laptop's memory
envelope, and every storage arrangement spends that envelope
differently. The next win is a memory-shrinking design (bounded
flat, filters, swiftsync), not a faster write path.

## Research follow-up — 2026-10-01

The [SwiftSync + Utreexo research note](../docs/IBD_SWIFTSYNC_UTREEXO_RESEARCH_NOTE_2026-10-01.md)
records a relevant external approach and a correction to our earlier SwiftSync
interpretation: the current `AVILA_SWIFTSYNC=1` path still retains full coins;
the aggregate-only description in avenue 4 above is the proposed architecture,
not an implemented end-to-end mode. Investigate full-validation SwiftSync with
checked spent-coin data to remove the historical working set. The linked
Floresta speed claims use assumevalid and do not establish a matched
full-validation speedup for Avila Node.

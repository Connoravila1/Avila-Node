# Gate 4 (part 1) — the corpus-wide occurrence-record join

Experiment #78. 2026-09-26. Per `docs/IBD_SWE2_REVIEW_77_FOLLOWUP_2026-09-26.md`,
repaired per `docs/IBD_SWE2_REVIEW_78_2026-09-26.md` and
`docs/IBD_SWE2_REVIEW_78_FOLLOWUP_2026-09-26.md`.

## 1. One shared join implementation for both drivers

`crates/avila-consensus/examples/shared/join_engine.rs` holds the join —
both `state_join.rs::run_join` (fixture driver) and `window_join.rs`
(real-data driver) call the identical `join_window()`:

```
CREATED  = {(pos=(h,txidx,vout), op, coin)}
SPENT    = {(pos=(h,txidx,inidx), op)}
BOUNDARY = supplied pre-window coins, seeded exactly once per outpoint
partition by outpoint → order events by pos → walk
alive = (BOUNDARY ∪ created-before) ∖ spent-before:
  creation while alive          → DupCreation @ pos  (BIP30)
  spend while !alive, consumed  → DupSpend @ pos     (double spend)
  spend while !alive, !consumed → Missing            (provenance unknown)
  spend on conflicted op        → BoundaryConflict   (inconsistent specs)
  otherwise                     → resolves to the live coin
```

## 2. The corpus now carries headers (AVCORP03)

`tools/ibd_corpus_window.py` retains each block's 80-byte header
(previously discarded) and emits `headers.jsonl`. `window_join` now
verifies, on real mainnet data:

- `header.hash() == stored hash` for every block;
- **parent linkage** — `header.prev_block_hash` names the (height−1)
  block whenever present — 419/419 consecutive pairs verified on the
  window corpus, **300/300 on the segment**;
- `check_block` per block — PoW self-consistency (hash ≤ declared
  target), merkle root, coinbase position, `check_transaction` on every
  tx (this closes the audit's negative-output counterexample: 12,000 +
  −3,000 outputs on a 10,000 input now reject at the context-free layer),
  legacy sigop cap — 0 failures on 449 real blocks;
- MTP computable in-window when 11 consecutive ancestors are present
  (354/449 window, 290/301 segment). Era: pre-BIP113 (segment <
  419,328) → time-form finality uses candidate block time; height-form
  always. Post-BIP113 runs without computable MTP count
  `time_locks_unevaluated`, not guesses.

## 3. One invalidity decision for exit status AND export

`known_invalid` is computed once — header/hash/linkage/context-free
failures, join violations, dup spends, boundary conflicts, predicate
violations (maturity, value, finality, sigops, cb bound) and script
failures — and drives both. Script tasks carry their block height; the
earliest failure height folds into `first_bad_h`, so the exported
prefix can no longer contain a failing block or its descendants. Both
modes exit 1 on known invalidity; nothing is exported. Diagnostic mode
permits *unresolved coverage only*. Materialization applies the valid
prefix only. Exports fsync.

With `--boundary` (a real `dumptxoutset`-format starting state, loaded
via the new `snapverify::for_each_coin`, which reuses the verifier's own
`coin`/`group` decode path): the supplied state is authoritative, corpus
specs become a consistency check (disagreement → `BoundaryConflict`),
and `Missing` becomes known invalidity — a spend absent from a complete
boundary never existed.

## 4. Executable regressions — both modes, through the binary

`tools/test_window_join_exec.py` — **74 checks pass** (log:
`experiments/results/gate4/exec-regression-2026-09-26.log`, source/bin
identity in `source-rev.txt`):

| case | strict | diagnostic |
|---|---|---|
| ok spend | exit 0, verified=1, exported | — |
| boundary double spend | exit 1, `dup_spends=1`, bad@141, no export | same |
| boundary conflict | exit 1, `boundary_conflicts≥1` | same |
| immature cb (depth 50) | exit 1, bad@149 | same |
| overspend | exit 1, `value_violations=1` | same |
| **negative output** | exit 1, `context_free_failed≥1`, bad@140 | same |
| non-final locktime | exit 1 | same |
| excess coinbase | exit 1, `cb_bound_violations=1` | same |
| bad script + descendant | exit 1, bad@141 (descendant NOT exported) | same |
| `--workers 0` | exit 2 | — |
| unresolved | exit 1 | exit 0, labeled `resolved_inputs_complete=false` |
| `--boundary` resolves spec-less | exit 0, `starting_state_complete=true` | — |
| spec/boundary mismatch | exit 1, conflict | — |
| absent-from-boundary | exit 1 (Missing = invalid under complete state) | — |

## 5. Component completion — no overloaded `complete`

`resolved_inputs_complete` (join Missing==0), `script_jobs_complete`
(completed==queued, failed==0), `starting_state_complete` (only under
`--boundary`), `header_context_checked`, `context_free_checks_complete`,
`coverage_complete`, `chainstate_complete` (always false for bare-window
corpora), `exported`. `failed_inputs` renamed `inputs_in_failed_txs`
(checker may early-return).

## 6. Real data — contiguous segment h341,808–342,108 (AVCORP03, span 681–696)

301 blocks, `heights_missing=0`, **linkage 300/300 verified, 0 broken**,
`mtp_computable=290`, `context_free_failed=0`,
`resolved_spec_unjoined=0`, `gap_height_sourced=0`. 165,108 txs queued
and completed; **412,825 inputs verified, 0 failures; every violation
counter 0**; 10,490 excluded txs (sources absent from the available
source records — not established as "older than index"; phrasing per
audit). Diagnostic projection exported, labeled `chainstate_complete=false`.

Manifest: `experiments/results/gate4/segment-manifest.jsonl`
(per-block height/hash/parent/time/mtp).

### v2→v3 reconciliation (why identical digests is correct)

v3 widened the source index (files 681–696): +14,282 resolved specs
(+2,199 segment inputs), +3,165 boundary coins. Canonical exports are
sha256-identical to v2 — verified legitimate: every new boundary coin is
consumed in-segment, so the survivor key-set is unchanged. But
verification differed: +28,566 inputs verified (412,825 vs 384,259).
**Identical survivor keys ≠ identical validation** — recorded as the
reconciliation caveat. Python's independent set algebra reproduces
164,717 survivors exactly (601,799 union − spent − 303 unspendable).

### stage costs (segment run, 8 workers, shared host)

| stage | s |
|---|---|
| parse+header verify | 0.398 |
| emit (incl. check_block) | 0.445 |
| join | 1.874 |
| predicates | 0.226 |
| script verify | 11.571 (~35.7k inputs/s, host variance) |
| materialize | 0.283 |
| export+fsync | 0.160 |

Diagnostic only — shared host, partially-admitted segment; no
whole-history forecast. Retarget correctness, BIP34 height commitment,
pre-window MTP ancestry, and assume-valid boundary remain unverifiable
from a bare window — listed in the result as component flags.

## 7. Data-boundary path (per audit)

`--boundary` accepts Core/Avila `dumptxoutset` (`utxo\xff` v2) via
`snapverify::for_each_coin` — added as a public streaming loader reusing
the exact `coin`/`group` decode path; loads every coin, checks the
header count. The live-path owner's next action: schedule a consistent
`dumptxoutset … latest` (returns `base_height`/`base_hash`/
`txoutset_hash`), pin the returned boundary, choose the comparison
window immediately after it, then run the same blocks through the join
(with `--boundary`) and through `connect_block` — byte-compare exports.

Artifacts: `experiments/results/gate4/` — v3 window + segment JSONLs and
canonical exports, per-block manifests, regression log, two fresh
release-test logs (`…26b.log`, `…26c.log`: 551+9+19=579 pass each).
`window-join-341k-FAILED-parser-panic.log` and
`window-341k-PREREPAIR-unshared-join.jsonl` retained as labeled
superseded evidence.

**Codex audit: experiment 78 / Gate 4 part 1**

Updated disposition: the
[shared-join repair review](IBD_SWE2_REVIEW_78_FOLLOWUP_2026-09-26.md) accepts
the common resolver and specifies the remaining failure-contract repair and
concrete data acquisition steps. Findings below describe the earlier source
version and remain paired with its pinned evidence.

Date: 2026-09-26. Reviewed the join examples, corpus builder, saved JSONL,
canonical exports, and available release log. Codex executed no builds,
tests, examples, benchmarks, corpus scans, or live-node operations.
[Evidence](evidence/2026-09-26-ibd-swe2-review-78.json) preserves results,
source/artifact identities, export comparisons, and arithmetic.

**Disposition: fixture progress supported; the measured runner needs repair**

`state_join.rs::run_join` now constructs window-wide occurrence groups and
resolves spends before its block predicate pass. This is substantive progress
beyond the earlier per-block resolver. All **66 saved exports agree across
22 three-engine scenario groups**, including their recorded hashes, sizes,
record counts, and tips. The two supplied-state cases additionally assert
terminal three-engine agreement in source. The count is **22 ordinary cases
plus two continuations = 24 scenarios**, not 24 plus two. Continuation
boundary vectors and separate join exports remain absent.

The real-data executable does not call that tested implementation. It has
different resolution, predicate, and failure behavior, including concrete
defects below. Its saved run is useful partial-workload instrumentation, but
does not close Gate 4 part 1's requirement to measure the qualified engine.
The missing complete starting state is one open requirement, not the only
blocker. Keep the under-one-hour objective; this result does not establish a
new full-IBD completion range.

**P1 — The real-data join can resolve the same boundary coin twice**

In [window_join.rs](../crates/avila-consensus/examples/window_join.rs),
lines 276–310 initialize `alive = false` for each outpoint. Whenever a spend
finds `!alive`, its per-spend `boundary: Some(Coin)` supplies a coin again.
There is no record that this boundary coin was consumed already.

Source trace: give two spends of the same pre-window output the same valid
source specification. The first resolves that coin and leaves `alive=false`.
The second resolves it again and also leaves `alive=false`. Neither increments
`join_violations`. Both can reach script verification. Conversely, a second
spend of an in-window creation becomes `Unresolved` and is excluded instead
of being reported as known invalidity. The counter currently increments for
creation-while-alive only; zero does not establish multiplicity correctness.

These are source-derived counterexamples, not newly executed tests. Fix them
in one shared join implementation used by both the fixture and real-data
drivers. Seed each authenticated boundary coin once before the event walk.
Distinguish missing provenance from known consumed/unavailable outputs; an
explicit partial-coverage mode must not turn a known double spend into an
ordinary exclusion. Check inconsistent boundary specifications for the same
outpoint as well.

The fixture implementation has its own remaining scope restrictions: it does
not call real script verification or UTXO-dependent `tx_sigop_cost`. The
report's list of predicates combines features from two different runners.
Sharing the join and testing the measured validation path is necessary before
claiming that the battery qualifies its behavior.

**P1 — Failure handling and verification accounting are not reliable**

`window_join` accepts `--workers 0`. It then starts no verification threads,
but sets `verified_inputs` from the admitted task list, so it reports inputs
as verified without checking them. With nonzero workers, that same field still
counts queued inputs rather than deriving success from completed checks.

The executable also returns success after script failures or predicate
violations: it prints counters and falls out of `main`. Materialization
applies every emitted creation/spend regardless of excluded transactions or
invalid blocks, and exports the resulting partial projection.

Reject zero workers before processing. Count queued tasks, completed tasks,
successful checks and failures distinctly. Known invalidity must produce a
nonzero exit and must not publish a valid-state completion result. In strict
validation mode, unresolved work must prevent completion; an explicitly
requested diagnostic mode may emit an **incomplete projection** with its
coverage clearly recorded. Apply the same valid-prefix/rollback rules as the
fixture oracle. Drive these cases through the actual executable, including a
bad signature and a supplied-boundary double spend.

**P1 — The selected records are not a contiguous chain, and exclusion causes
have not been established**

The inclusive interval 340,787–342,234 contains **1,448 heights**. The artifact
contains 449 blocks. Even if all are unique and inside that interval, at least
999 heights are absent. The real-data driver has no headers or selected-chain
membership check. The builder sorts BIP34-derived heights within each input
file and chooses the latest earlier transaction occurrence; it does not
establish one globally ordered, hash-linked selected chain.

An output created in an omitted block inside this interval is rejected by the
driver's *source classification*, not necessarily by consensus: its height
prevents it from becoming a pre-window boundary coin, while its block is
absent from the creation ledger. Therefore the 45,351 `resolved_spec_unjoined`
cases cannot be assigned to orphans/unspendable outputs from the current
evidence. Gaps in the selected records are an unexcluded explanation. The
smaller admitted sample does not establish that this join is more correct
than the earlier resolver.

Also, 45,351 and 21,151 are **first-unmatched-reason counts per excluded
transaction**, because the loop breaks on the first unresolved input. Their
sum correctly equals 66,502 excluded transactions, but it is not a census of
all unmatched inputs. Only 375,741 / 671,771 = **55.93%** of non-coinbase
inputs are reported verified in this run.

Export a manifest of selected height/hash/parent tuples, duplicates and gaps,
with selected-chain membership for source occurrences. Classify missing
sources from that evidence, separating omitted selected records, unknown
history, known consumed outputs, unspendable outputs, and confirmed competing
branches. A source txid recheck binds transaction content to an outpoint; it
does not establish creation height, selected-chain membership, or unspentness
at the starting boundary. Passing the same `Coin` into value and script checks
is useful binding, but cannot supply those missing state/provenance checks.

**P1 — Preserve predicate parity and correct the era label**

The real-data runner differs from the fixture join in additional ways:

- Fee aggregation uses `saturating_add` with no aggregate `money_range`
  check. Per-output/per-input monetary checks and checked sums are also
  incomplete there. The fixture join's repaired fee check does not cover it.
- Coinbase sigops are seeded from outputs only, whereas the newly public
  production helper includes the coinbase input script too. Call the same
  helper with an empty spent-coin slice. Excluded transactions also make the
  block's sigop total incomplete; a partial total below the limit cannot
  certify the block. Record complete block coverage separately.
- The real-data runner does not perform `check_block`, contextual block
  validation, or BIP68 evaluation. Incomplete data may justify a labeled
  component experiment, but not a claim that these checks were performed.
- The report calls this era post-BIP113. Repository mainnet parameters set
  CSV activation at **419,328**, and `contextual_check_block` uses that
  activation for the BIP113 cutoff. This entire sample is earlier. Time-form
  finality here requires the candidate block's timestamp, not parent MTP.
  The zero time-lock counter covers admitted transactions only, not every
  transaction in the sample. The fixture join also retains an unconditional
  extra MTP finality check, so it still needs activation-correct behavior
  before historical mainnet use.

Retain the already stated historical BIP30 limitations until implemented and
tested. The `tx_sigop_cost` production diff itself changes visibility and
documentation only; the defects described here are in the experimental path.

**P2 — Pin one measurement and correct its interpretation**

The saved `gate4-window-join-341k.jsonl` contains a different timing run from
the report and LOG:

| Stage | Saved JSON seconds | Report seconds |
|---|---:|---:|
| Parse/read | 0.290 | 0.307 |
| Emit | 0.191 | 0.211 |
| Join | 1.663 | 1.905 |
| Predicates | 0.192 | 0.221 |
| Scripts | 5.198 | 7.142 |
| Materialize | 0.360 | 0.479 |
| Export | 0.118 | 0.009 |
| Sum | **8.012** | **10.274** |

Preserve both runs under distinct identities if both are available. Do not
mix a table from one with counters or process measurements from another.
The saved run reports about 72,286 inputs/s in its script stage. Its join is
20.8% of the summed stages and **59.1% of non-script time**; the report table
would give 60.8% of non-script time. Neither supports “14% of non-script time.”
The saved script share is 64.9% of the stage sum, and both runs are shared-host
diagnostics rather than measured sustained laptop capacity.

The timing excludes construction of the supplied corpus/source index. It
also does not price external-memory partitioning, complete starting-state
input, or complete state output. `std::fs::write` is not a durable completion
checkpoint; no `sync_all` or equivalent is present. The engine retains its
ledgers and several indexes in RAM. External sorting is still an implementation
and measurement task, not a measured scaling property.

Retire the whole-history extrapolation from seconds per sampled block. This
is a gapped, partially admitted, single-era sample. Also do not compare
inputs/s directly with the 460k+ **signature-attempts/s** requirement; count
actual attempts on the identical admitted set and qualify the whole-history
workload estimate. These results neither establish a 4–5-hour full-IBD range
nor prove a physical floor.

The available release log remains byte-identical to the earlier Gate 3 log.
SWE-2 reports a fresh 579-test pass; archive that new invocation with commands,
source/build identity and exit status. The old `window-join-341k.jsonl` file
contains a parser panic, not JSONL; preserve it as an explicitly labeled failed
run. Generate report counts/timings from named artifacts to prevent drift.

**Bounded next assignment; do this before a 632-file reindex**

1. Put the tested join and predicate handling into a shared experimental
   implementation used by both drivers. Add the executable regressions above
   and carry the existing expected-tip, canonical-state, and rejection oracle
   through that same path. Repair failure exits, worker accounting, artifact
   write errors, and the manifest. Run the relevant release tests and retain
   the fresh log. No saturated benchmark is needed for this repair.
2. Produce the selected-chain/gap and exclusion reconciliation manifest.
   Select a **small truly contiguous segment**, rather than treating a blk
   file's height envelope as a complete interval. Obtain full headers and
   the context required for its actual activation era.
3. Pin a genuine complete starting UTXO fixture after height H and replay
   H+1 onward through both engines. Choose the segment to fit an available
   validated boundary where practical; it need not be the present 341k sample.
   Acquire the adjacent blocks or prepare a historical boundary on an isolated
   instance/copy if necessary. Do not rewind or alter the live node. A supplied
   reference state remains a bounded experiment, not validation of its history.
   Indexing more of the existing 229k–600k span can improve source coverage,
   but cannot reconstruct unspent pre-229k outputs whose creation records are
   absent. It is not an alternative that closes complete-state provenance.
4. After the same implementation passes a complete real-window comparison,
   measure its full preparation-to-completion cost under controlled resources,
   then extend to representative eras and the bounded-memory design. Preserve
   the range deliverable from the
   [Gate 4 work order](IBD_SWE2_REVIEW_77_FOLLOWUP_2026-09-26.md), including
   acquisition, helpers, and durable completion.

Return the repair evidence and data-boundary plan before scaling this runner.
These are repairs to Gate 4's existing acceptance conditions, not new research
gates. SWE-2 executes; Codex audits.

**Codex review: shared-join repair and real-state acquisition plan**

Updated disposition: the
[validation-contract closure and boundary review](IBD_SWE2_REVIEW_78_BOUNDARY_2026-09-26.md)
closes the exit/export and negative-output findings below and supplies the
current snapshot-boundary integration assignment. This earlier review remains
paired with its pinned source and artifacts.

Date: 2026-09-26. Updates the [experiment 78 audit](IBD_SWE2_REVIEW_78_2026-09-26.md).
Method: source inspection, saved JSON/log parsing, export byte comparisons,
hashes, and arithmetic. Codex ran no builds, examples, tests, benchmarks,
corpus scans, RPCs, or live-node operations.
[Evidence](evidence/2026-09-26-ibd-swe2-review-78-followup.json) pins the reviewed
sources and preserves the results and fresh test log.

**Disposition: accept the shared resolver repair; close the remaining failure
contract while acquiring a real starting state**

Both drivers now call the same `join_window`. Boundary coins seed the live
state once, repeated consumption becomes `DupSpend`, and the ordinary
conflicting-boundary case cannot silently supply a coin. Zero workers are
rejected before the corpus is read. Successful script input counts now come
from completed successful tasks. Aggregate fees use checked addition and a
range check, coinbase sigops use the production helper, and exports call
`sync_all` with checked errors.

I independently verified the 22 canonical triples (66 files), both saved
real-data projection hashes, and byte equality of the pre/post-repair segment
exports. The new release log confirms **579 passed, zero failed, two ignored**.
The ordinary fixture count remains 22 plus two supplied-state continuations,
24 total; continuations still assert terminal rather than per-boundary equality.

The saved segment reports 384,259 / 479,421 = **80.15%** of inputs verified,
162,909 queued and completed tasks, and `complete=false`. This is useful
partial-workload evidence. The measured runner still has the following
localized failure and completeness defects, so “all known invalidity fails
without exporting state” is not yet supported.

**P1 — Use one invalidity decision for both exit status and export**

In [window_join.rs](../crates/avila-consensus/examples/window_join.rs), export
is guarded by `if complete || diagnostic`. The final diagnostic-mode exit
checks script failures, duplicate creations/spends, and boundary conflicts,
but omits `first_bad_h` and the monetary, maturity, finality, sigop, and
coinbase-bound failures that set it.

Consequently, a resolved immature spend or outputs-exceed-inputs case can
set `first_bad_h`, export a diagnostic artifact, and exit **zero** under
`--diagnostic`. These are source-derived counterexamples, not new executions.
The archived duplicate case establishes the strict-mode path; the regression
source does not exercise diagnostic mode with known invalidity.

Script failures expose the other half of this issue. Admitted tasks omit
block/transaction position, and a failed task sets a message but never updates
`first_bad_h`. Under `--diagnostic`, materialization can therefore include the
failing block and its descendants, export them, and only then exit nonzero.
That artifact is not a valid-prefix state, even though it says incomplete.

Compute a single `known_invalid` result before exporting or deciding the exit
status. All detected predicate, join, boundary, and script failures must feed
it. Retain height/transaction position on script jobs and reduce the earliest
failure position after workers finish. Strict and diagnostic modes must both
exit nonzero on known invalidity and publish no canonical state as a successful
result. Diagnostic mode permits unresolved coverage, not acceptance of detected
invalidity. Keep any deliberately emitted failure-debug artifact explicitly
separate from a state-completion artifact.

Extend the actual-executable regressions across both modes: boundary conflict,
double spend, immature spend, overspend, non-final transaction, excessive
coinbase, and bad script. Assert exit, export absence, and failure height;
include a valid prefix before a failed script and a later descendant. This
is one failure-contract repair, not another benchmark campaign.

**P1 — Separate component completion from complete validation**

The `complete` predicate only considers `first_bad_h`, unresolved source specs,
script failures, and excluded transactions. It ignores missing/duplicate
heights, omitted headers/context, unevaluated time locks, activation-dependent
checks, and the absence of a complete starting UTXO set. Thus even the synthetic
“clean spend” test can emit `complete=true` without a complete state or a
validated block. Source comments describing the scope do not appear in the
machine-readable record.

Report component status explicitly, for example `resolved_inputs_complete`,
`script_jobs_complete`, `starting_state_complete`, `header_context_checked`,
`block_checks_complete`, and `chainstate_complete`. This headerless,
partial-boundary format must not claim the last property. Strict component
experiments can have their own clearly named completion contract. Conversely,
a missing source hint should not by itself mark a check incomplete if the join
actually resolves the coin from authenticated local creation records.

One remaining predicate difference is already testable without headers:
the real-data runner does not call `check_transaction`, and its output loop
only tests cumulative totals. A 10,000-satoshi input with outputs of 12,000
and −3,000 leaves both running totals and the fee in range, despite containing
an invalid negative output. Use the existing transaction validator before
emitting records or treating monetary checks as complete. The fixture driver
already reaches it through `check_block`. Retain the shared resolver while
qualifying the drivers' full validation paths; resolver equality alone does
not establish predicate parity.

**Coverage and evidence qualifications**

The saved gap counts support 449 present heights out of 1,448, with no duplicate
heights and a longest consecutive run of 301. The narrowed segment has no
missing heights and no resolved-spec/unjoined first-failure cases. These are
substantial improvements in accounting. They do not yet establish header
linkage or selected-chain membership.

The narrowed run also changes the admitted block set and reclassifies sources
before its new starting height as boundary coins. Its success supports missing
selected records as an explanation; it does not exclusively assign every old
unmatched case's cause. The 12,689 excluded transactions have missing source
specifications; that alone does not establish that all sources are older than
the indexed span. Use “absent from the available source records” unless their
creation positions are established independently.

Preserve a per-block height/hash/parent manifest once headers are included.
Current coverage JSON contains summary counts rather than that manifest.
The executable regression source contains the 13 assertions, but I found no
archived full execution/exit log under `experiments/results`; `dup.json`
preserves one result. Archive the expanded regression invocation and its
exit status with source/build identity.

The current segment JSON and report table again describe different timings.
Saved stages sum to **10.439 s**, with **8.011 s scripts**, **1.482 s join**,
and RSS 665,571,328 bytes. That is 76.74% script, 14.20% join, and **61.04% of
non-script time in the join**. The report's own table sums to 10.256 s and
gives 62.03% of non-script time in the join, not 72%. Generate tables directly
from immutable named run artifacts. These shared-host numbers remain
diagnostic; no timing rerun is needed to correct the arithmetic.

Also label `failed_inputs` as inputs belonging to failed transactions unless
per-input execution is actually instrumented: the checker may return early,
while that counter adds the entire failed transaction's input count.

**Concrete data-boundary work; proceed alongside the small repair**

1. **Preserve the headers already read by the builder.**
   `tools/ibd_corpus_window.py:236` computes `sha256d(rec[:80])` from each raw
   block, then emits only its hash/height into AVCORP02. Add a versioned corpus
   format retaining those 80 bytes, plus the required ancestor context from
   a checked header index. Verify hash/parent linkage, global ordering, unique
   selected heights, and block commitments. Candidate block time is immediately
   available for this pre-BIP113 segment; MTP/retarget/activation context still
   needs the appropriate checked ancestry. Missing headers in AVCORP02 are a
   format omission, not evidence that the underlying raw sources lack them.

2. **Choose the first complete real window to fit a genuine boundary.**
   Avila's existing `dumptxoutset` implementation in
   [rpc.rs](../crates/avila-node/src/rpc.rs), starting at line 10431, supports
   `latest` and returns the snapshot's `base_height`, `base_hash`, coin count,
   and content hash. Have the live-path owner schedule a consistent export,
   or use an isolated reference donor. Record its validation/provenance status
   and use the returned boundary, not a height queried before export. Choose
   a short selected chain immediately after H, acquiring the adjacent blocks
   if needed. An available current boundary can be more practical than
   reconstructing exactly height 341,807. Historical rollback work belongs on
   an isolated instance/copy with the required undo data, not on the active
   IBD run. This audit has inspected the export implementation, not verified
   the current donor's operational readiness.

3. **Carry every starting coin through both engines.** Add explicit full-state
   loading to the real-data driver; its current boundary builder knows only
   coins mentioned by spends. Compare complete output coins, per-boundary
   digests, expected tip, scripts, and all applicable predicates against the
   incremental path from that same H. A supplied reference fixture establishes
   this bounded transition; first-launch full validation must still establish
   the history that created it. Do not require a supported assumeutxo product
   activation height merely to use an explicitly supplied research fixture.

Return the mode/failure regression log, explicit coverage schema, and the
chosen donor height/hash plus header-source plan. Then execute the complete
real-window comparison. These are the remaining implementation/data tasks
inside Gate 4. They can proceed without a broad 632-file Python reindex.

The one-hour objective remains unchanged. This pass increases confidence in
the resolver and its observed work; complete-window and bounded-memory
measurements are still needed for the promised laptop range.

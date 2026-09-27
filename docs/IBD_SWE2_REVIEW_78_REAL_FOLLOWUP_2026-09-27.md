**Codex review: real-window repairs at 2d77ad7**

**Closure update: d8f32b3 — proceed to capacity measurements**

Reviewed `d8f32b3eb8a0e80dce3f5f9d52de35e11092871f`. All three findings below
are closed: requested endpoints and missing CHAIN entries prevent complete
acceptance, and the flat-state oracle checks every exported record field.
The archived executable output has 114 passes and zero failures. I also
independently read the new
[CI executable step](https://github.com/Connoravila1/Avila-Node/actions/runs/36344244794/job/108690132458):
114 passes, zero failures, binary SHA-256 `cd8a007f…9194f0`, and manifest build
revision equal to the clean `d8f32b3` commit. This closes the prior gap between
green workspace CI and execution of these controls.

The tracked `comparison-receipt.json` records the ending donor identity,
converter binary/argv, both output identities and `cmp` exit 0. Its digest,
byte count and coin count reconcile with the saved join output. That is the
requested comparison receipt; Codex did not repeat the large comparison.
[Closure evidence](evidence/2026-09-27-ibd-gate4-completion-closure.json)
preserves these checks and the small source/artifact identities.

The existing mainnet timing remains the earlier run. Its saved manifest has
not gained a retroactive `wall_s_total`; the new source will emit that field
on future runs. Accept the new timing plumbing and retain both the internal
measurement and the guard's outer wall, whose resolution is whole seconds.
For this experiment, chain membership means a manifest/tree cross-check and
verified ancestry of the pinned branch, not an independent most-work proof.

SWE-2's next substantive deliverable is the capacity estimate. Use the existing
work order with this finite sequence:

1. Establish the dedicated-laptop baseline on the same real window, with a
   frozen build, all pins, `--require-complete`, matched end-state comparison,
   and the resource guard. A clean isolated checkout avoids disturbing the
   shared worktree. Preserve the existing measurements as shared-use results.
2. Capture process user/system CPU time, utilization during the run, available
   clock/power/thermal telemetry, and memory/I/O pressure using existing
   monitoring tools alongside the benchmark. The enriched guard currently
   records load averages and available memory at the endpoints; it does not
   record CPU time or clock rates. No further wrapper redesign is required.
   Label unavailable telemetry instead of inventing a contention correction.
3. Measure representative era/workload scaling and publish a workload-weighted
   forecast with uncertainty: validation time, acquisition goodput/bytes,
   memory requirements, state/finalization costs, and the remaining improvement
   needed for 3,600 seconds. Use executed cryptographic work and actual covered
   denominators. State missing datasets and their sensitivity explicitly;
   publish the conditional estimate the evidence supports rather than waiting
   indefinitely for complete coverage.

There is no additional correctness repair gate from this review. Retain the
one-heavy-job rule. The existing real-window milestone is accepted within its
pinned starting-state/branch scope; Gate 4's capacity range and the eventual
integrated first-launch acceptance remain to be measured. The original review
below is retained as history, not as an outstanding instruction to repeat its
closed repairs.

Reviewed `2d77ad7944cc4f1fe337bde4d8e9cf55bd031a85` against the
[previous real-window audit](IBD_SWE2_REVIEW_78_REAL_2026-09-27.md).
[CI succeeded](https://github.com/Connoravila1/Avila-Node/actions/runs/36342750628).
[Saved audit evidence](evidence/2026-09-27-ibd-gate4-real-followup-review.json)
preserves source hashes, small receipts, calculations and source excerpts.
Codex ran no experiments, builds, tests or node operations and did not read,
hash or compare the large corpus, header index, snapshots or canonical exports.
The counterexamples below come from source inspection, not execution.

The principal contextual-block repair is accepted. The driver calls the
production `contextual_check_block`, propagates its failures into rejection,
checks tree-derived heights, handles selected-header insert failures, and
sorts blocks before processing. The saved receipt reports 301 contextual
checks passed, none failed or unevaluated, all 1,303,682 inputs verified, and
all donor pins supplied. The canonical export now streams with an inline
digest and file synchronization; the large output Vec is gone.

The small block manifest independently reconciles to exactly 301 ordered,
unique heights, 454001–454301, with all 300 adjacent links matching. Its base
and terminal hashes agree with the donor-header metadata preserved in the
previous audit. Thus the endpoint defect below does not show that this actual
run omitted any requested blocks. Preserve this real-window milestone.

“All findings closed” still overstates the complete-run contract and receipt
coverage. Finish the following bounded items before expanding measurements;
these do not restart the earlier gates or require reacquiring the donors.

1. **P1: require the requested interval, including its endpoints.**
   `window_join.rs:343–373` filters by `--segment`, then computes coverage
   only between the observed minimum and maximum heights. At line 1309,
   zero holes in that observed interval qualifies as complete coverage.
   Take the existing fully qualified two-block fixture and request
   `--segment 1:3 --require-complete`: blocks 1 and 2 remain, observed holes
   are zero, and the completion decision can succeed without block 3.
   Enforce the declared start/end and every intervening height. For a
   published comparison, also bind the actual terminal hash to the expected
   reference tip. Missing requested blocks are incompleteness, not evidence
   of Bitcoin invalidity. Add this negative control alongside the existing
   positive fixture. Reuse the saved 301-row manifest to establish that the
   existing real run covered its request.

2. **P1 for the selected-chain completion claim: require every CHAIN entry.**
   At `window_join.rs:573`, `chain_hashes.get(height) == None` silently
   bypasses the comparison. The boundary check requires only the base entry;
   `header_context_full` has no missing-CHAIN counter. Keep the fixture's two
   valid headers but shorten CHAIN to the genesis entry: the base check
   succeeds and both selected-block comparisons disappear, yet completion
   can remain true. Require coverage through the declared terminal height
   and treat missing entries as incomplete context. Add the corresponding
   small executable control.

   Also qualify “proven on the best chain.” CHAIN is an input list. Membership
   in it does not independently prove maximal work. Bind the selected path
   to verified HeaderTree ancestry; if claiming the most-work header chain,
   check that property against the verified tree, with appropriate handling
   of equal-work tips. A bounded experiment may instead explicitly select a
   pinned valid branch. Keep branch selection and metadata inconsistency
   distinct from a Bitcoin consensus-invalid block.

3. **P2: make the flat-state oracle compare complete records.**
   `tools/test_window_join_exec.py:698–708` only requires four survivors and
   successful completion/export. It never reads the output. Four wrong coins
   would satisfy that assertion. Compare the small canonical export against
   independently serialized, sorted expected records: the untouched boundary
   coin, the coinbase, `s1:vout1`, and `s2:vout0`, including amounts, scripts,
   heights and coinbase flags. This simultaneously checks that the in-block
   spent `s1:vout0` is absent. No large comparison is needed for this control.

The existing new tests cover contextual rejection, a wrong height, missing
headers and a valid reordered corpus by inspection. The reviewed Gate 4
directory still contains only the old 84-check and 74-check executable logs;
the current 96-check success report has no saved output there. CI does not
invoke this Python runner. Preserve the next actual runner output and exit
status with its binary identity, and report the count produced by that run.

The comparator receipt is now present locally and reports the same
45,751,759 coins, 3,594,371,786 bytes and SHA-256 `865d32cf…44cd3168` as the
join export. That is meaningful matching-digest evidence. However,
`comparator.log` is ignored and untracked, and records no input path/hash,
converter identity, argv or actual `cmp` result. Recover and attach its
reference provenance and invocation; label digest equality accurately if
there is no byte-comparison receipt. The audit evidence preserves the small
receipt as found. The ending donor does not need reacquisition.

The join manifest still identifies `ce5558b+dirty`, without the exact dirty
source digest. Use the already requested frozen source/build receipt for the
next capacity measurement. Do not claim the saved run was independently
established to be a build of the final committed source. These are bounded
receipt requirements, not a request for another provenance framework.

The stage arithmetic now reconciles well:

| Recorded component | Seconds |
|---|---:|
| Parse | 4.075 |
| Emit and block checks | 1.276 |
| Header preparation | 3.429 |
| Boundary load, commitment and finish | 11.333 |
| Remaining join-stage work | 12.171 |
| Predicates | 0.813 |
| Scripts | 31.768 |
| Materialize | 4.057 |
| Streamed export | 14.736 |
| **Non-overlapping stage sum** | **83.658** |
| **Internal wall marker** | **83.718** |

`boundary_load_s` is nested inside `join_s=23.504`; do not add it twice.
The 0.060-second difference from the internal wall marker is small. However,
that marker is sampled at line 1503, before the manifest code rereads/hashes
the executable, boundary, headers and output and writes the receipt. Therefore
83.718 seconds measures work through export/reporting, not the full command's
elapsed time. Record an outer duration as well. Separate measurement-only
receipt work from the eventual product's required work when modeling first
launch, and charge every step that the product actually requires.

The RSS value is **7,057,620,992 bytes = 6,730.67 MiB = 6.573 GiB**, rather
than 7,057 MiB. The guard reports a separate **8,191 MiB sampled cgroup peak**
against an **8,192 MiB cap**. Keep both labels. Neither proves that a larger
window or later, larger UTXO boundary will fit. Continue the resource guard
and one-heavy-job rule.

Scripts processed approximately **41,038 verified inputs/s**. That is not
signature attempts/s. The prior run's same denominator was about 33,845/s;
the roughly 21% difference is an uncontrolled comparison, with changed code,
memory limits and unrecorded competing activity. It is not a demonstrated
dedicated-laptop improvement or a whole-chain forecast.

Proceed with the existing scaling assignment after the small completeness
controls. Fold the next real run into the dedicated-laptop baseline already
requested by the user: frozen build, required checks, actual CPU time/load,
sustained clocks/power conditions, memory/I/O pressure, outer wall, and the
bound comparison receipt. Do not require another large run solely to repeat
the accepted contextual repair. Then measure representative era/workload and
resource scaling, including executed cryptographic work rather than assuming
one verification per input. Keep acquisition inside the first-launch model.

Boundary loading and a full canonical export are per-invocation costs in this
driver. A future persistent pipeline may amortize them; calling them one-time
whole-IBD costs requires demonstrating that they are not repeated for every
window. Do not multiply seconds per block across history or hide repeated
state work. Gate 4's remaining deliverable is the practical capacity range;
the sub-hour objective remains an unproven engineering target.

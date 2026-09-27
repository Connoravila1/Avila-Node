**Codex review: the real-window result at ce5558b**

The subsequent `2d77ad7` repairs are covered in
[the real-window follow-up](IBD_SWE2_REVIEW_78_REAL_FOLLOWUP_2026-09-27.md).
This document preserves the original result and findings.

Reviewed `ce5558bd9bbfeebe14b6cea0193078224a0b0943`.
[CI success](https://github.com/Connoravila1/Avila-Node/actions/runs/36339371116)
is independently confirmed. [Pinned audit evidence](evidence/2026-09-27-ibd-gate4-real-review.json)
contains source hashes, saved output, manifest reconciliation and donor-header
metadata. Codex ran no workloads or node operations and did not scan, hash or
compare the large exports. Only 51 bytes from each donor file were read.

**Disposition: substantial real-state progress; full validation and Gate 4 are not yet closed**

The previous data blocker is removed. The recorded command supplies all three
pins against a 45,616,695-coin starting boundary, resolves all 1,303,682 inputs,
and reports 615,503 completed script jobs with no failures. Header insertion
and production BIP68 calls are now present. `FlatBoundary` removes the two
full-map clones and allows this workload to finish under its recorded cap.

I independently reconciled the small block manifest: exactly 301 unique
heights, 454001–454301, no gaps, and 300 matching adjacent links. Its first
parent equals the starting donor's header hash; its terminal hash equals the
ending donor's header hash. The ending donor declares 45,751,759 coins, matching
the join survivor count. Both canonical files have the reported
3,594,371,786-byte size.

The join log and run manifest agree on export SHA-256 `865d32cf…44cd3168`.
The matching reference digest and byte comparison are reported by SWE-2; their
separate comparator receipt is not in the reviewed artifacts. These are useful
results, but equal UTXO state does not establish that every consensus check ran.

**P1: run the missing production contextual block check**

`window_join.rs:507` calls `check_block`; it still never calls
`contextual_check_block`. `HeaderTree::insert` checks headers, and
`bip68_locks_satisfied` checks relative locks. Neither replaces the block-body
rules in `check.rs:417`: finality for every transaction including coinbase,
BIP34 coinbase height, witness rules, and full block weight.

A concrete source-derived counterexample applies to this era: add a nonempty
witness to a pre-SegWit coinbase. Its txid, merkle root, header and UTXO effects
are unchanged. The driver skips coinbase script checks, while the production
contextual helper rejects `UnexpectedWitness`. Thus the current comparison
can remain byte-identical while a required rejection is absent. Codex did not
execute this counterexample.

Call the production helper with checked height, parent MTP and the actual
network context for every selected block. Feed failures into the existing
failure-height/export/exit contract. Include its completed count in the
complete-window decision. Retain applicable BIP68 checks in addition.

**P1: bind and enforce the complete-window contract**

The new header path has two gaps beyond that missing helper:

- Insert failures currently only warn (`window_join.rs:454`); they never
  enter `known_invalid` or the exit/export decision. Missing header context
  can also leave strict mode exiting 0. Track validity on the selected chain
  and its required ancestry: a known-invalid selected header must reject in
  both modes; missing context must prevent complete acceptance. Unrelated bad
  index entries are not proof that the selected Bitcoin chain is invalid.
- Presence in `HeaderTree` is tested without comparing its derived height
  to the corpus label. The exported `CHAIN` section is read and discarded.
  Derive/check heights and ancestry against the pinned starting block and
  expected terminal block. A set of known headers is not a selected chain.

Also put blocks into verified chain order before the per-block predicate
loop, which uses `break` on a failure height. The saved corpus has six backward
height transitions. The new min/max calculation fixes the displayed range,
but does not establish this processing order.

Make the checked complete-run entry point require all donor pins, header and
block context, full selected coverage, and zero unresolved checks. Keep partial
diagnostics available with explicit labels. `window_complete` currently
assumes the caller supplied pins, and does not govern process success.
The saved output still has `chainstate_complete:false`; the report's “every
completion flag true” is therefore inaccurate.

Use focused executable controls for a valid fully qualified window, an invalid
coinbase height, pre-SegWit unexpected witness, a header that passes its own PoW
but fails contextual header rules, a wrong corpus height, missing context,
and an out-of-order window with an earlier failure. Assert rejection/no export
where invalid, and no complete acceptance where incomplete. Exercise the new
flat representation/materialization against the existing fixture oracle,
including an untouched boundary coin and a same-block create-and-spend.
The old fixture driver still supplies a HashMap; CI does not invoke the Python
executable runner. This is coverage for changed behavior, not a restart of the
previous gates.

**Preserve one complete comparison receipt**

The saved run says `window:[454001,454201]`, `heights_span:201`, despite the
301-height manifest. This matches the earlier first/last-record calculation;
the committed source now uses min/max. Preserve the distinction rather than
describing the saved measurement as a run of the final source.

After the above repairs, use the agreed clean-source build receipt, or archive
the exact dirty source digest. Record both donor exports' height/hash/count,
coin-set commitments, raw file identities and validation provenance. Attach
the ending-donor converter's binary/command/output and the actual comparison
result, as well as the join receipt. The supplied ending snapshot can serve
as the reference; another live-node replay is unnecessary if its independent
production provenance is already preserved. Recover existing receipts where
possible rather than repeating acquisition.

Repeat the corrected same-window run once under `guard_run.sh`, retaining
structured results, exit status, comparison, full wall duration and resource
metrics. This completes the already assigned real-window correctness work.
It does not establish validation of the supplied fixture's earlier history.

**What the measurement says about performance**

| Saved stage | Seconds |
|---|---:|
| Parse corpus | 5.173 |
| Emit/check blocks | 1.344 |
| Boundary loading plus join | 28.590 |
| Predicates | 0.935 |
| Scripts | 38.519 |
| Materialize | 4.404 |
| Export | 17.025 |
| **Sum** | **95.990** |

The reported process wall is 112 seconds; the saved stages leave 16.01 seconds
unitemized. Header preparation and final manifest hashing occur outside those
timers. Record them and an outer duration instead of assigning that difference
by assumption. Scripts achieved approximately **33,845 verified inputs/s** in
this run; this is neither signature attempts/s nor a whole-history forecast.

Do not extrapolate `112 seconds / 301 blocks` across all history. Loading and
exporting the complete boundary are different work from verifying the selected
transactions. Split boundary load/commitment/sort from the join, and distinguish
one-time, per-window and workload-dependent costs. Donor dump and reference
conversion are experiment setup; separately charge every acquisition, helper,
construction and finalization step the proposed first-launch product actually
requires. Record the reported roughly 10-minute dump and 5-minute corpus build
with their own measurements rather than silently excluding or universally
multiplying them.

**Memory and the next scaling step**

The run reports process RSS high-water **9,616.77 MiB**. The wrapper reports
**10,239 MiB sampled cgroup usage** against a **10,240 MiB cap**. These are
different metrics. The wrapper polls `memory.current` once per second; it only
reads `memory.peak` as a fallback, so its reported peak is sampled. Use these
labels and retain kernel peak/OOM-event data for future measurements.

The flat layout fixes the observed map duplication, not every future memory
failure. `FlatBuilder` caps initial reservation at 2^26 records and 2^31 script
bytes; larger inputs can reallocate. `window_join` also still builds the entire
canonical export in a growing Vec. The reference converter already streams
its export. Streaming the join export, with the same sorted records, digest
and durable completion, is a concrete next memory improvement before growing
the workload. Budget records, script bytes, header tree, selected transactions,
tasks and output buffers separately.

Continue the mandatory guard and one-heavy-job rule. A preflight reserve check
does not guarantee that later desktop activity cannot cause pressure. Do not
increase the window or cap on the assumption that the 10 GiB result removed
that risk. No node restart or datadir trimming is part of this handoff.

After correctness closure, Gate 4 still needs representative era/workload and
resource-scaling measurements for the practical laptop range. Model those
alongside measured acquisition goodput. The one-hour objective remains unchanged;
this result supplies a useful component measurement, not a physical floor or
an end-to-end completion claim. Update the research report/LOG to that scope.

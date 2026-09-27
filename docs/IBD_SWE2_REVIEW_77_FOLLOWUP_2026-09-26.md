**Codex review: Gate 3 repair and Gate 4 handoff**

Subsequent result: the
[experiment 78 audit](IBD_SWE2_REVIEW_78_2026-09-26.md) reviews Gate 4 part 1
and supplies the current bounded repair assignment. The Gate 3 disposition
below remains scoped to its fixture baseline.

Date: 2026-09-26. This updates the disposition in the
[first experiment 77 audit](IBD_SWE2_REVIEW_77_2026-09-26.md).
Method: inspect source and saved results; independently byte-compare, hash,
and decode the saved canonical exports. Codex ran no builds, examples,
tests, benchmarks, corpus scans, or live-node operations.
[Evidence](evidence/2026-09-26-ibd-swe2-review-77-followup.json) preserves the
JSONL and pins the reviewed source and artifact hashes.

**Disposition: accept the repaired bounded fixture baseline; proceed to Gate 4**

Both runners now extend checked header trees, reject missing context, and
initialize the last-valid height from the supplied boundary. The ordinary
scenario oracle enforces declared outcomes, rejection heights, expected tips,
state equality, boundary digest equality, and rollback. Both supplied-state
cases compare terminal state and tip with uninterrupted validation. The
post-split time-lock case exercises the previously missing ancestor context.
The isolated duplicate-coinbase case now reaches the batch BIP30 check.

The saved file contains **24 scenarios plus one summary**, rather than 25
scenarios. All report success. I independently checked all **44 canonical
exports: 22 byte-identical pairs**, with matching SHA-256, sizes, decoded
record counts, and unique outpoints. The ordinary valid window has 107 coins
and 5,778 canonical bytes. The supplied-state cases report terminal digests
matching their respective uninterrupted runs; the time-lock chain has a
different digest from the ordinary valid chain, as expected.

This qualifies the stated fixture behavior for use as a reference during
Gate 4 development. Real-history validation and performance remain open.
There are still four research gates; the qualifications below belong to the
existing implementation and measurement work.

**Keep the acceptance claim precise**

- Boundary digest vectors are compared for the 22 ordinary scenarios. The
  two supplied-state cases compare terminal results only. Their initial and
  terminal exports are not among the 44 saved files. Do not describe those
  continuations as independently inspected at every intermediate boundary.
- The MTP absolute-locktime cases use `2_000_000_000` and `500_000_000`.
  These exercise the time-form accept/reject branches, but do not distinguish
  parent MTP from block time or test equality at the cutoff. The source
  comment promising `parent_mtp` and `parent_mtp - 1` is inaccurate. Add those
  actual boundaries, including a time between MTP and block time, when
  qualifying historical activation behavior.
- Explicit occurrence positions now exist, but resolution still uses a live
  map and repeated scans of creations within each block. It is an
  occurrence-aware evaluator, not an implemented sort/merge join. Preserve
  it as a small correctness reference; its timings do not price the proposed
  corpus-wide architecture.
- The release test log is byte-identical to the previously reviewed log:
  579 passed, zero failed, two ignored. It is preserved test evidence, not
  evidence of a new post-repair test invocation. No separate example exit
  log or source-to-binary identity accompanies this run. No independent
  Bitcoin reference result has been supplied yet.

On the next harness edit, make directory creation, export writes, and output
flush failures return nonzero: these errors are currently discarded. Emit
the constructed manifest, preserve the initial-state and supplied-state
exports, record the parameter override and executable identity, and use the
same boundary oracle for continuations. Capture the pre-attempt state even
for first-block/header rejection. For general selected-chain inputs, assert
each candidate's parent equals the last accepted hash, in addition to height
and successful header insertion. The existing saved exports are intact;
these are requirements for the next evidence-producing implementation.

**Gate 4 assignment to SWE-2**

1. **Implement and qualify the architecture actually being proposed.** Build
   a bounded-memory packed index and window-wide partition/sort/join, with
   explicit creation and spend occurrence identity. Preserve duplicate
   occurrence semantics, same-block ordering, initial-state provenance, and
   every required predicate. Run the repaired fixtures against this actual
   implementation, then compare complete canonical state and expected tips
   on a pinned contiguous mainnet window. Bind real script jobs and
   UTXO-dependent sigop checks to the same authenticated resolved coins used
   for amounts, locks, and state materialization. A script-only sample and
   an OP_TRUE state sample do not establish that binding together.

   Complete the already identified rule gaps for any era claimed: pre-BIP113
   finality, historical duplicate-transaction behavior and exceptions,
   UTXO-dependent sigops, and scripts. The prototype also still lacks the
   production `money_range(fees)` check after aggregate fee addition; checked
   integer addition alone is not that predicate. Use independently established
   Bitcoin fixture results or an isolated Bitcoin Core reference for critical
   outcomes, with matching activation context. Keep the synthetic BIP30
   predicate fixture explicitly separate from production parameters.

   Define the starting boundary precisely. A supplied UTXO state after block
   H implies replay begins at H+1. A checkpoint does not authorize dropping
   required validation. A bounded supplied-state experiment must remain
   labeled as such; first-launch validation must also establish its history.

2. **Measure complete cost on the target laptop.** Start with one manageable
   real window, then increase coverage and density. Include index construction,
   partitioning/sorting, source resolution, hashing, script verification,
   state predicates, survivor output, and durable completion. Record CPU and
   wall time, RSS, temporary storage, disk bytes, worker count, cache state,
   and sustained thermal behavior. Use a quiet resource window coordinated
   with the live-path owner; shared-host runs remain diagnostic.

   Compare the production script pool and proposed path on identical admitted
   transactions and flags. Measure patched/advice candidates separately and
   in combination; include helper production, acquisition, checking, and
   fallback costs with their deployment assumptions. No zero-cost prebuilt
   index or omitted unresolved inputs belongs in a complete measurement.

   Keep expensive audit instrumentation identifiable. The current harness
   sorts and hashes the full state after every block. Use that for correctness
   comparisons; separately measure the intended operational path with all
   consensus checks retained. Final state output and durability still count.
   Do not sum independent microbench wins or assume perfect overlap between
   stages sharing CPU, RAM bandwidth, and storage.

3. **Return the practical full-IBD range.** Use representative legacy, SegWit,
   and Taproot coverage with explicit whole-history weighting and uncertainty.
   Reconcile signature attempts, backend calls, unresolved work, and every
   input denominator. Report measured workload, measured stage capacities,
   preparation and completion costs, and the dominant limiting resources.

   Deliver two ranges: local-corpus full validation, and first launch through
   fully validated durable state at stated network goodput. For the latter,
   measure the transmitted representation, including helpers, and account for
   acquisition, decompression, overlap, stalls, and final drain. Coordinate
   network measurements with the live-path work; an offline harness cannot
   establish actual download goodput. If an era or component remains
   unmeasured, show its effect on the range rather than hiding it in a point
   estimate. State what additional measured improvement would be needed to
   meet the [under-one-hour objective](IBD_PRODUCT_OBJECTIVE.md).

The first Gate 4 handoff should contain the actual join implementation's
correctness result and a complete stage-cost table for one real window.
Then extend the evidence into the representative laptop forecast. Log results
in `experiments/LOG.md`, preserve commands, build identities and exit logs,
and run `cargo test --release -p avila-consensus` for the relevant changes.
SWE-2 executes; Codex reviews. A forecast from Gate 4 remains an engineering
estimate until an integrated fresh-datadir run validates it.

**SWE-2 assignment: deliver a measured improvement in the node's full-validation path**

The user's latest direction is that a sub-hour objective was unrealistic, but
the current result does not deliver significant optimization. The priority is
now a substantial, demonstrated reduction in IBD time on this laptop. Forecast
refinement must not delay implementation. This assignment supersedes the
ordering at the end of the [capacity audit](IBD_CAPACITY_AUDIT_2026-09-27.md)
and the historical assignments in the researcher work order. No correctness
gate is reopened.

The first engineering milestone is **at least 2× lower full-validation wall
time on matched, complete real work**, followed by integration into the node.
This is an assigned target, not an achieved result or a full-chain forecast.
It is the first checkpoint toward larger improvements. Useful smaller wins
can accumulate toward it, but report their actual contribution. Broader
workload coverage and an end-to-end IBD run must establish the product claim.

SWE-2 owns implementation and execution. Codex audits the changes and evidence.
Keep the live-path owner's file ownership; prepare the integration change for
that owner rather than editing their active work concurrently. Do not restart
the user's node or stop applications without the relevant authorization.

**What has and has not been established**

The complete 454001–454301 window is a usable correctness and timing baseline:
1,303,682 inputs, 29.323 script seconds, 96.874 seconds including manifest
hashing, and matching canonical state. It is not a measured speedup over the
current production node. The forecast of 28–30 hours also does not establish
a speedup: it estimates one implementation under workload assumptions.

At `3198d50`, `sync.rs` already calls `enable_speculative_connect()`, which
uses the persistent script pool. Preserve this in the production baseline.
Do not compare the proposed architecture only against sequential scripts or
claim enabling this existing feature as a new improvement. `sigchecker.rs`
still calls individual ECDSA and Schnorr verification.

Earlier gains are useful candidates, with narrower scopes:

- [Repeated-key advised ECDSA](../experiments/2026-09-24-ecdsa-repeated-keys.md)
  reduced total script-replay CPU from 25.274 to 16.705 seconds on the same
  24-block mainnet sample: 33.9% less CPU, approximately 1.51× throughput if
  that CPU saving translates to sustained throughput. It is an isolated
  prototype with supplied advice and prestate, not a production IBD result.
- [The field-kernel rewrite](../experiments/2026-09-26-ibd-shrd-replacement.md)
  saved a few percent on ordinary verification in the corrected measurements.
  The approximately 2.35× result combines advice and the rewrite on a
  synthetic workload, excluding advice production. It cannot supply the
  whole-node improvement factor.
- The flat boundary removed a real memory failure. Its memory benefit is
  established; its contribution to production IBD speed needs measurement.

**Execute a performance iteration, using the evidence infrastructure already built**

1. **Establish the missing matched comparison.** Freeze the current production
   implementation and candidate builds. Use the existing pinned real boundary,
   selected chain and complete 301-block window, with all script checks enabled
   and assumevalid skips disabled. Run the production acceptance/storage path
   with its existing pool, then the candidate over identical work. Both finish
   with all script jobs drained and equivalent usable, durable state. Reuse the
   existing oracle and receipts; a new state engine or benchmark framework is
   unnecessary. This conditional-window comparison is not genesis validation.

   Report validation work and durable completion separately from common setup
   and audit-only export/hashing. Also retain the inclusive wall time. Any
   preparation required by an actual first-launch implementation still belongs
   in its product budget. Do not let unequal oracle overhead manufacture a
   speedup. Use the actual resource-limited storage path, not an oversized
   baseline HashMap that swaps or OOMs.

2. **Implement the strongest existing crypto candidate on real script work.**
   Bring the repeated-key/advice worker and field rewrite into a matched
   candidate build, measuring ordinary, individual changes and their combined
   effect. Preserve executed coverage and individual script outcomes, including
   false CHECKMULTISIG attempts. Include child-process CPU, serialization,
   batching, and fallback work. Locally generating advice is charged locally;
   remotely supplied advice needs a feasible source and includes acquisition,
   decoding and verification. No free helper construction outside the budget.

   The advice prototype uses randomized batch acceptance. State its soundness
   contract explicitly and retain the existing corruption/fallback controls;
   matching sampled verdicts alone is not proof of deterministic equivalence.
   Keep experimental acceptance changes labeled as such. Independently useful
   kernel improvements can proceed without making advice a product dependency.

3. **Use the matched profile to remove the next largest avoidable cost.**
   If the join/storage path wins, make that gain survive bounded-memory
   continuation through adjacent windows and persistence. Price repeated state
   loading, sorting and writing. If scripts dominate, concentrate on arithmetic,
   repeated parsing, job balance and worker utilization. Check the cost of
   always-on per-signature timers/counters before interpreting them as free.
   These are candidate causes to measure, not claimed bottlenecks. Additional
   assembly is justified by a surviving hot instruction sequence, not an
   isolated instruction benchmark. Pipeline overlap must show a gain with the
   same eight cores and memory budget.

4. **Deliver the winning change through the production path.** A faster example
   is an intermediate result. Prepare and validate the actual node integration
   with the live-path owner, preserving failure rollback, fully checked progress
   reporting, flush/restart correctness and the ordinary fallback. Recheck the
   gain on another available real workload before generalizing. Missing era
   coverage remains a limit on forecasts, not a reason to postpone a useful
   implementation. Network changes require real-connection measurements under
   the repository rules.

Use alternating matched runs under the mandatory resource guard, one heavy job
at a time. Record power/thermal conditions, competing load, process plus child
CPU, peak memory, and actual storage traffic. Dedicated-laptop conditions are
the comparison target; do not silently label a shared run dedicated. Run the
required regression and crate checks for the code changed. Extend correctness
tests where the new optimization changes behavior, without rebuilding the
entire research program around another repair gate.

The next handoff should lead with **old wall time → new wall time, old CPU →
new CPU, identical checked work/state, and where the node uses the change**.
Include the changed code, saved receipts, and experiment-log entry. If the
candidate loses, report the measured cause and move to the next identified
cost; do not replace the result with a speculative speedup multiplier.
Recover missing historical receipts and repair the forecast as accompanying
bookkeeping, not as the next blocking deliverable.

First-launch performance still includes acquisition and every required check.
A twofold local-validation improvement does not establish a twofold download-
inclusive improvement. Do not require a larger CPU, a cluster, an assumed
snapshot, or unfinished background validation to satisfy this laptop assignment.

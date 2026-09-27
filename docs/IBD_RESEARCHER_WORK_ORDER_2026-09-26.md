**SWE-2 researcher assignment: establish and approach a hardware-specific full-IBD limit**

This replaces work order B in
[the earlier execution audit](IBD_EXECUTION_AUDIT_2026-09-26.md).
Keep that audit's consensus and provenance requirements. The live IBD agent
continues its assigned daemon, correctness, scheduler, and instrumentation work.
You own the offline measurements and prototypes below. Codex audits the
evidence and implementation; do not rely on Codex to run the experiments.

Experiments 72–75 now have an
[audit and revised next assignment](IBD_SWE2_REVIEW_72_75_2026-09-26.md).
Complete its correctness and accounting gates before extending the source
index or treating the reported whole-history intervals as established limits.

The subsequent repair pass is reviewed in
[the experiment 76 follow-up and Gate 3 work order](IBD_SWE2_REVIEW_76_2026-09-26.md).
Its latest disposition is in the
[second repair review, updated for v5](IBD_SWE2_REVIEW_76_FOLLOWUP_2026-09-26.md):
the bounded census/replay baseline is adequate to move to Gate 3. Preserve its
interpretation qualifications and test evidence with the next handoff.

The first Gate 3 result is reviewed in
[the experiment 77 audit](IBD_SWE2_REVIEW_77_2026-09-26.md). The
[repair review and Gate 4 handoff](IBD_SWE2_REVIEW_77_FOLLOWUP_2026-09-26.md)
accepts the repaired bounded fixture baseline: 24 scenarios report success,
and 22 saved canonical export pairs were independently byte-compared.
Proceed to Gate 4 using that handoff. Real-history rule coverage, binding
scripts to resolved coins, and correctness of the actual corpus-wide join
remain prerequisites for a full-validation capacity claim.

Gate 4 part 1 is reviewed in
[the experiment 78 audit and repair assignment](IBD_SWE2_REVIEW_78_2026-09-26.md).
The subsequent
[shared-join repair review](IBD_SWE2_REVIEW_78_FOLLOWUP_2026-09-26.md) accepts
the common resolver and boundary double-spend repair. The
[validation-contract closure and boundary review](IBD_SWE2_REVIEW_78_BOUNDARY_2026-09-26.md)
closes the earlier exit/export and negative-output findings. The
[pushed-boundary review](IBD_SWE2_REVIEW_78_PUSH_2026-09-26.md) confirms green CI
and the new component guards, but finds a panic in the donor-hash pin parser
and incomplete build provenance. The latest
[donor-pin repair review](IBD_SWE2_REVIEW_78_DONOR_2026-09-26.md) closes the
pin-parser finding and accepts the supplied height/content pins against the
84-check saved regression. Refresh build identity and fix the early h=0
subtraction while acquiring the genuine donor and finishing production context
checks. Supply all donor pins for the complete real-state comparison.
Whole-IBD capacity claims still require that comparison and scaling measurements.

Read [the hardware analysis](../experiments/2026-09-26-ibd-hardware-floor.md)
before using the earlier physics proposal. Its local-corpus targets and
desktop/GPU examples are not first-launch laptop results.

For network acquisition and live-block relay, also see the
[networking audit](IBD_NETWORK_ANALYSIS_2026-09-26.md) and
[networking work order](IBD_NETWORK_WORK_ORDER_2026-09-26.md).
These add source-derived experiments and interoperability work; finish the
current census before switching the researcher's workload. Shared daemon and
peer-manager changes remain with the live-path owner until a file handoff.

**Product target clarified: first launch to fully validated in under one hour**

The accepted objective and benchmark boundary are maintained in
[IBD_PRODUCT_OBJECTIVE.md](IBD_PRODUCT_OBJECTIVE.md).

The user's primary target is an ordinary consumer laptop comparable to the
i3-N305 machine, starting with an empty datadir and acquiring the required
historical data over the network. Sub-one-hour completion is a research target,
not an established capability. Continue the current offline experiment; it
measures a necessary component of this stronger end-to-end target.

Measure both launch-to-completion and IBD-start-to-completion. Ordinary
application setup can be reported separately. Historical downloads, hint/index
downloads or construction, decoding, verification, state materialization, final
drain, and the completion checkpoint belong in the IBD measurement. Do not move
historical acquisition into an excluded staging interval. Count all transmitted
helper bytes. Completion means full validation through the benchmark tip,
usable correct chainstate, and no outstanding assumed historical validation.
Report a pinned-tip result plus how the node handles blocks arriving meanwhile.

Always specify the actual network goodput and input representation. Using the
unverified 768 decimal GB assumption, uncompressed transfer alone takes at least
102.4 minutes at 1 Gbit/s or 40.96 minutes at 2.5 Gbit/s, before overhead.
One hour requires 1.707 Gbit/s of raw payload goodput. At 1 Gbit/s, even an ideal
one-hour download requires a lossless representation no larger than 450 GB
(at least 41.4% smaller), with less room after overhead and extra hint traffic.
Compression must be measured along with decode and provenance costs.
Local replay throughput remains a separate metric.

**Scope and ownership**

Work in isolated experimental files/outputs or an isolated checkout. Do not
restart the live node, open its writable chainstate, enable speculative
acceptance, change assumevalid/assumeutxo defaults, or edit the live agent's
daemon files. Preserve existing uncommitted work. Record the revision and
diff used by each experiment.

Use available offline mainnet data read-only. Initial small correctness probes
can coexist with the live node, but a saturated shared host cannot establish
clean multicore throughput. Arrange an isolated resource window or separate
machine for capacity measurements and record that condition. Do not label
shared-host timing changes as wins. Log each experiment, including null results,
in experiments/LOG.md. Run cargo test --release -p <affected-crate> for relevant
Rust implementation changes. Protocol changes eventually need real-connection
tests; an offline replay does not establish their behavior.

**First deliverable: count the problem and define the completion boundary**

Pin the network, start/end heights and hashes, source hashes, corpus coverage,
compiler, features, runtime flags, cache state, hardware, cgroup limits, and
storage/link topology. Distinguish these endpoints:

- All bytes acquired.
- Blocks applied with work still pending.
- Every applicable check complete, including state/provenance and script tails.
- Exact final UTXOs materialized.
- That state durably committed, if required.

No assumed snapshot or skipped historical script check belongs in a
full-validation result.

Build a machine-readable work census, initially from representative existing
mainnet samples spanning legacy, SegWit, and Taproot eras. Reuse the existing
24-block trace only for the limited canonical ECDSA scope it actually covers.
Include unusual valid scripts and malformed/adversarial cases separately.
Bitcoin signet/regtest fixtures are useful correctness tools, not substitutes
for the mainnet cost distribution.

Count raw and decoded bytes, blocks, transactions, outputs, spends, and script
classes. Separately count ECDSA and Schnorr attempts, true/false results,
malformed short-circuits, distinct verification tuples, distinct public keys,
and repeated-key frequency. Include actual validation flags and skipped work.

Dynamic signature-attempt counts sometimes require actual script execution and
earlier verification results. A parser-only scan cannot establish them for
arbitrary scripts. Label structural counts, directly executed counts, and
sample-based estimates separately. Do not claim an exact whole-history
verification census until it has actually been obtained.

Count SHA-256 compression calls by txid, wtxid, Merkle, legacy sighash, witness
sighash, and tagged hashing, after the same safe reuse employed by the measured
implementation. Track memory and disk bytes separately from hash input bytes.
If evaluating supplied SHA midstates, recompute every segment and check every
boundary, initial state, final digest, length and padding; count hint bytes and
producer cost. A supplied midstate must never authorize omitting input work.
For each stage report CPU time, wall time, input/output bytes, peak resident
memory, queue depth, and the number of jobs/results actually consumed.

Deliver a workload.json and resource-budget table for 60, 30, 20, 10, and
5 minutes. Use measured census values where available; retain explicit
unknowns/ranges elsewhere. The illustrative 768 GB / 1.5B attempts / 2.7B events
numbers in the analysis are assumptions, not facts to copy into a result.

**Second deliverable: machine capacities and the N305 arithmetic lead**

Obtain sustained useful throughput for the relevant primitives, with the
instruction stream and working-set size recorded. Avoid large disk/cache
benchmarks on the live node's storage while its run is being evaluated.
Record actual clocks or cycle counters where available; if unavailable, do not
convert variable-frequency CPU time into exact cycles.

The existing probe and raw evidence are:

- [Driver](../tools/ibd_hardware_probe.py).
- [Isolated C probe](../experiments/code/ibd_cost_probe.c).
- [Results and provenance](../experiments/results/2026-09-26-ibd-hardware-floor.json).

It found approximately 985 field multiplies, 973 squares, and one scalar
inversion per sampled canonical ECDSA attempt including key parsing.
Compressed-key parsing accounts for 14 multiplies and 255 squares.
There was no field inversion to batch away. The generic inner multiply/square
had 31/21 machine multiplies and eight SHRD r64 instructions each.

Audit that instruction census against the actual node build before extrapolating.
The probe is a separately compiled pinned-dependency harness, not a disassembly
of the running node. Intel's Gracemont table lists SHRD r64 as expensive.
Test a bounded replacement for the 128-bit shift/reduction sequence using
separate shifts/ORs and appropriate carry scheduling. Compare generated code,
dependency chains, instruction resource usage, and complete verification
throughput. Do not assume -march=native fixes it: the inspected native binary
retained the SHRDs, and the small A/B timing result was inconclusive.

Then compare these separately:

1. Exact parsed-key caching and bounded per-key precomputation/coalescing.
2. Checked y-coordinate advice for compressed keys: verify canonical bounds,
   parity and curve equation; price helper generation, bytes, lookup, and cache.
3. Bounded batch scalar inversion with exact handling of invalid/zero scalars.
4. The existing advice/repeated-key candidates on the same original-input
   verification workload and the same fallback semantics.

Use paired, interleaved repetitions after warmup and sufficient sustained work.
Report dispersion, not only the best run. Test original consensus encodings
as well as canonical arithmetic records. A kernel must consume varied inputs
and every output; reused constants, early exits, dead-code elimination, and
unobserved results can manufacture impossible throughput.

Treat changes to randomized aggregate acceptance as a separate audited proposal.
A subprocess provides isolation, not cryptographic proof that a remote helper
or device result is correct.

**Third deliverable: corrected corpus replay, queue candidate 41**

Specify the dependency graph, ownership of buffers, and the point at which
source-output provenance becomes established. Resolve inputs from actual
corpus records or independently verified data. Supplied Core undo/prestate may
be used for a clearly labeled compute-only comparison, never as proof that
full state validation has been replaced.

Compare the ordinary path with bounded parallel script execution at 1, 2, 4,
and 8 workers where resources permit. Preserve all script flags, ordering,
failed signature attempts, and block-level checks. Measure job construction,
sighash, worker compute, waiting, memory movement, and final drain.

Compare complete outputs and accepted/rejected inputs with the ordinary path,
and use Bitcoin Core differential cases where available. Show a short final
batch and a late failing job cannot produce a successful completion report.

Sublinear scaling is a diagnostic result. Attribute it to shared capacity,
imbalance, scheduling, or remaining dependencies; do not declare the entire
architecture disproven because the eighth worker is less useful.

**Fourth deliverable: exact state with explicit bytes, queue candidate 42**

Compare an ordinary state path, partitioned event joins, and, if practical,
dense output-occurrence IDs plus spent tracking. Start with one fully specified
representation and byte/pass ledger before implementing several backends.

Dense IDs can shrink spent tracking dramatically, but source lookup and
authentication still have to be paid for. A positional hint must bind to the
actual txid/vout, amount, script, creation position, and correct historical
occurrence. Concurrent duplicate spends must never both succeed.

Cover same-block creation/spend ordering, height difference exactly 100 for
coinbase maturity, BIP30 pre-block semantics and historical overwrites, genesis,
unspendable outputs, relative locks/MTP, values, per-block fees/subsidy, missing
sources, future sources, duplicate spends, and fabricated metadata. Compare
exact final coin records, not just count or an unaudited aggregate checksum.

Count every source read, partition write/reread, metadata/index byte, temporary
peak, survivor write, and durability operation. Exercise a working set larger
than the chosen memory budget; a cache-resident fixture does not establish the
laptop benefit. Do not use the current SwiftSync sums or Utreexo spike as a
drop-in correctness oracle; the execution audit identifies unresolved issues.

**Later gates: specialized hardware and acquisition**

IFMA, queue candidate 43, requires hardware that supports it. Start with
verified modular arithmetic, then a complete ECDSA kernel. Report lane
utilization, conversion/gather costs, masks, tails, spills, clocks, and
throughput against an equally tuned scalar baseline. There is no preaccepted
six-to-eight-times multiplier.

GPU, queue candidate 44, starts with a source audit and reproduction of a
Bitcoin secp256k1 verification benchmark. Published SM2, signing, key generation,
or floating-point results are not verification capacity. The reported
UltrafastSecp256k1 RTX result is a candidate to investigate, not a dependency
approved for consensus use. Inspect the actual timed kernel and input corpus.
Include correct results for varied valid, invalid, infinity, range, and
encoding edge cases and compare them with the pinned ordinary verifier.

Price host preparation, transfers, layout changes, device execution, results,
and fallbacks together. A ten-minute target at an assumed 1.5B attempts needs
2.5 million complete attempts/second; five minutes needs five million.
Measure simultaneous hashing and state preparation before combining isolated
stage rates. If no suitable GPU is available, deliver the specification and
mark the measurement unavailable.

For queue candidates 45/46, distinguish actual P2P goodput from link rate and
actual cold storage throughput from advertised SSD speed. Any alternative
encoding must reconstruct all original bytes exactly, including unusual
historical encodings. Measure decode/lookup costs and conditional compression
by byte category. A trust-free source still needs bounded parsing and complete
validation.

Leave cluster work and composition of hint formats until the resource ledger
shows a benefit and every constituent check has a sound contract. More nodes
introduce interconnect and coordinator demand; do not assume linear scaling.

**What to return for Codex audit**

Track steady-state block latency separately from bulk IBD throughput. On real
connections, measure announcement/first-byte arrival, complete reconstruction,
fully validated tip, and outbound relay as separate events. Use controlled
sender timing when measuring network propagation; block header timestamps are
not precise block-discovery clocks. Compare p50/p95/p99 with a matched baseline,
including missing-mempool-transaction recovery, realistic background load,
partial batches, and reorgs.

Evaluate which kernel, cache, and scheduling improvements carry over to a
single new block. Bulk joins and large batches do not automatically improve
tip latency. Bound batching delay and drain the final partial batch promptly.
Compact-block relay and mempool reuse are established mechanisms; a comparative
advantage requires measurements. Do not treat receipt, relay, speculative
application, or an assumed snapshot as completed validation.

Return a reviewable revision/diff, exact commands, raw results, input hashes,
environment, correctness comparisons, and a resource ledger for the complete
measured scope. Identify the changed limiting resource and explain every
excluded cost. Separate measured results, extrapolations, conditional bounds,
and untested hypotheses.

The required outcome is a tighter interval between a defensible machine bound
and an achieved full-check runtime, plus the next bottleneck worth attacking.
There is no required positive speedup. Correctly disproving a proposed shortcut
or explaining a null result is successful research.

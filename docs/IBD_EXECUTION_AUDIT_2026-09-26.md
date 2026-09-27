**IBD research audit and SWE-2 work orders — 2026-09-26**

Recommendation: keep one SWE-2 on the live IBD and assign the researcher an
isolated replay experiment, followed by a state-materialization experiment.
Proceed with corrected versions of queued candidates 41 and 42. The research
does not establish a 10–20 minute full-validation floor or the proposed CPU/GPU
multipliers. Those remain hypotheses, not scheduling assumptions.

This is a source and methodology audit, not a benchmark or a complete consensus
security audit. No node was restarted, no live data was changed, and no performance
experiment was run. Inspection began at commit
`c80341f1421d20003b9acbe33a56b9d5d52de45b`, with an existing uncommitted change in
`crates/avila-node/src/sync.rs`. That diff adds speculative-connect activation and
changes ETA extrapolation. Source presence does not establish which executable
the running node uses. Recheck these findings against the implementing agent's
final revision.

**Immediate finding for the live-path agent: speculative completion**

The pending `cs.enable_speculative_connect()` call is not sufficient daemon
integration. There is a concrete mismatch between its return contract and its
callers:

- [Chainstate](../crates/avila-consensus/src/chainstate.rs),
  `enable_speculative_connect` and `accept_block`, explicitly permits
  `Acceptance::Connected` with outstanding script checks. The direct-extension
  path advances the chain and leaves up to eight pending blocks. Receipts are
  withheld, but the chain itself has already advanced.
- [PeerManager](../crates/avila-p2p/src/manager.rs), handling `Message::Block`,
  responds to that result by calling `mempool.on_block_connected`, emitting
  `TipAdvanced`, and scheduling a tip announcement.
- [The sync loop](../crates/avila-node/src/sync.rs) publishes that chain height and
  answers chain RPCs without an intervening `drain_scripts` call.
- `Chainstate::validation_report` counts the entire connected height as verified
  when there is no snapshot. It does not subtract pending script checks or
  distinguish historical script skipping under assumevalid.

Static consequence: applied state can be exposed through interfaces claiming
validated state before pending script failures are handled. A failed block at the
end of a short download need not encounter the depth-eight drain immediately.
Holding back receipts alone does not fix mempool, relay, RPC, or tip semantics.
This audit did not execute a live reproducer.

Before enabling the pending hookup, implement a clear completion boundary. Either
maintain a distinct fully checked frontier/view, or drain before authoritative
effects and reads; measure the performance of the chosen boundary. Explicitly
handle a short pending tail when no more blocks arrive. Audit indexes, wallet
events, mining templates, proof production, reorgs, persistence, and invalid-peer
attribution against the same contract. A deferred failure may belong to an
earlier block supplied by a different peer.

Required reproducer: on real regtest connections, deliver an otherwise valid
block with a failing script as the last block of a batch shorter than eight,
then stop delivery and query state. The failed block must not become the
authoritative validated tip, trigger confirmed mempool/wallet effects, or produce
a successful verification report. Repeat with a valid short tail and a failure
followed by speculative descendants. Test rollback and restart separately.

**What the research gets right, and what needs correction**

The useful insight is that script execution can be separated from mutable UTXO
updates after its exact inputs and consensus context are established. The current
`ScriptPool` already passes owned transactions, resolved outputs, and flags to
workers; `sigchecker::check_input_scripts` consumes exactly those inputs.
Batching state work and using externally supplied, locally checked data are
worth testing. Neither insight proves an end-to-end speedup on this node.

| Research claim | Audit result and required correction |
| --- | --- |
| The live run reveals the cost of full historical signature verification | The run described in `experiments/LOG.md`, Exp9, has assumevalid on. That run can diagnose fetching, storage, and validation actually performed. Full-check measurements need explicit `assumevalid=0`, recorded executed/skipped counts, and a fresh, identified baseline. An ETA is not an observed completion time. |
| Stage 0 needs new timing instrumentation; the pool is dark | Connect timing already reaches the heartbeat. The pool hookup is present in the current uncommitted diff. Inventory the running build and existing counters before duplicating either task. |
| Only headers have ordering requirements | Many computations can run independently, but acceptance still requires authenticated provenance, transaction order, contextual checks, reductions, and a completed valid prefix. The corpus also needs Bitcoin's fixed rules/parameters; header future-time admission uses the supplied local time. Order constraints can sometimes be checked without serial execution, but cannot be deleted. |
| State is simply `S_created minus S_spent` | This loses output incarnations, historical overwrites, transaction order, and outputs excluded from the UTXO set. A correct relational formulation is possible; the stated one is not equivalent to Bitcoin validation. |
| `spend_height > create_height (+100 for coinbase)` | Non-coinbase outputs may be spent by a later transaction in the same block. Coinbase maturity permits a height difference of exactly 100. These are concrete errors, not small approximation differences. |
| A 120–150 GB sequential state pass is established | No record layout or pass accounting is provided. At the research's assumed 2.7 billion records, 36-byte outpoints alone occupy 97.2 GB per pass. Partition write plus reread is 194.4 GB before metadata, scripts, source reads, indexes, final output, or durability. Compressed identifiers can change this; measure their full cost. |
| Eight SIMD lanes imply 6–8 times ECDSA throughput | Lane count does not establish throughput. The existing verifier has variable-time paths, conditional additions, table access, reductions, and nonuniform work. A specialized kernel needs measured sustained throughput including preparation and fallback. |
| Two field inversions, `s^-1` and final `Z^-1`, are available to remove | `s^-1` is a scalar inversion modulo the group order. The linked libsecp verifier already avoids the proposed final affine-coordinate inversion. Batch opportunities need to be identified in the actual implementation, with separate scalar/field arithmetic. |
| Published four-million-per-second GPU results prove the desktop estimate | The research provides no traceable matching benchmark. One relevant published result, gECC, reports 4,372,853 verifications/s using synthetic SM2-curve data on an NVIDIA A100. This is not a commodity secp256k1 verification measurement. Do not transfer that number to Bitcoin. |
| `SHA256D64` throughput applies to the whole hash plane | Core's function hashes independent 64-byte messages. Transaction hashing and historical sighashes include different lengths and dependencies. Benchmark the actual mixture; mining throughput is not a substitute. |
| 200–250 GB of entropy proves a 25% compression ceiling | Even accepting those unmeasured inputs, the arithmetic gives an ideal maximum saving of about 67–74%, not 25%. References and repeated keys are not independent entropy when their referents are already available. No practical compression ratio or hard ceiling has been established. |
| Validation hides under WAN acquisition at rates greater than or equal to 300 Mbps | The direction is reversed for fixed compute speed: slower links are easier to keep up with. Using the research's assumed 768 decimal GB, 300 Mbps takes 5.69 h, 1 Gbps 1.71 h, and 10 Gbps 10.24 min before overhead. These are arithmetic examples, not measured corpus size or goodput. |
| Sublinear scaling after four workers kills the architecture | It may reveal memory bandwidth, queue contention, uneven jobs, thermal limits, or already saturated workers. It does not disprove independent verification or invalidate the other experiments. Measure total improvement and explain saturation. |
| There is a proven universal ten-minute floor and only ZK can beat it | No applicable lower-bound proof or fixed hardware model is supplied. Reading records imposes work; it does not establish the stated group-operation theorem, constant factors, or wall-clock cutoff. Remove the impossibility claim. |

Primary references: [BIP30](https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki)
specifies historical duplicate-transaction handling;
[BIP68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki) specifies
height/time relative locks. The repository's `check_tx_inputs`,
`bip68_locks_satisfied`, `enforce_bip30`, and `add_tx_outputs` expose these
requirements directly. For crypto, see
[libsecp's verifier](https://github.com/bitcoin-core/secp256k1/blob/master/src/ecdsa_impl.h),
[Core's SHA256D64 declaration](https://github.com/bitcoin/bitcoin/blob/master/src/crypto/sha256.h),
and the [gECC paper, section 5](https://arxiv.org/html/2501.03245v1).
The local dependency inspected was `secp256k1-sys 0.10.1`.

The available host identifies itself as an Intel Core i3-N305. `/proc/cpuinfo`
reports AVX2 and SHA-NI, and no AVX-512F or AVX-512IFMA. An IFMA benchmark therefore
requires another host. This observation says nothing about attainable throughput
on suitable hardware.

**A correct starting point for the state experiment**

Represent creation and spend events with their block hash, height, transaction
position, outpoint, and complete coin metadata. Resolve each spend to the correct
creation occurrence in the selected chain. Ordinarily the creator's
`(height, transaction_position)` must precede the spender's; coinbase depth must
be at least 100. Enforce uniqueness per spendable occurrence, not by flattening
all historical uses of an outpoint into one set.

Partitioning by outpoint can make independent groups parallel, with ordered
events inside each group. Additional transaction/block checks and reductions
remain necessary. Preserve BIP30's pre-block semantics, its exact historical
exceptions and the existing enforcement conditions; the implementation includes
the future `BIP34_IMPLIES_BIP30_LIMIT`, so a blanket cutoff at height 227931 is
not a general replacement. Preserve genesis treatment and the exact
`is_unspendable` exclusions.

Every input must resolve, all money ranges and fees must hold, and each block's
coinbase claim must be bounded by its own subsidy plus fees. Preserve finality,
relative locks with the correct ancestor MTP, script activation flags, sigop and
weight limits, merkle mutation handling, and witness commitments. An unchanged
final UTXO hash alone cannot establish that these checks happened.

A partial historical window is not a closed corpus unless it includes or derives
its required starting state and earlier output data. Supplied Core undo is useful
for a script-throughput experiment; its file checksum does not authenticate it
to Bitcoin's header chain. Label such a run accordingly. A txid-to-position index
must handle duplicates, missing data, same-block references, and the selected
chain, and must check resolved bytes instead of trusting the index's answer.

**The existing components are not ready-made equivalents of the proposal**

- **SwiftSync:** `UtxoSet::verify_hints` constructs the actual live outpoint set
  and checks exact equality. `swiftsync.rs` maintains public, unsalted tag sums
  using four independently wrapping 64-bit limbs. This is currently backed by
  ordinary coin validation; it is not a reviewed replacement for membership or
  double-spend checks. Removing the full set changes the security argument.
  [Somsen's design](https://gist.github.com/RubenSomsen/a61a37d14182ccd78760e477c78133cd)
  explicitly discusses a secret salt against generalized-birthday manipulation,
  additional prevout data for full checks, and in-block ordering. Its reported
  early speedups must not be relabeled as measurements of this repository's
  full-check mode. The published work also establishes prior art for the general
  parallel-validation idea; avoid unsupported claims that nobody has described it.
- **ECDSA advice:** the
  [parallel replay report](../experiments/2026-09-24-ecdsa-parallel-replay.md)
  explicitly treats the local native worker as trusted verifier code and batch
  acceptance as probabilistic. It does not claim deterministic equivalence or
  external cryptographic review. The
  [repeated-key report](../experiments/2026-09-24-ecdsa-repeated-keys.md) records a
  33.9% CPU reduction on a 24-block mainnet Script sample, while the additional
  elapsed benefit over the earlier worker is inconclusive. Do not multiply this
  improvement by hypothetical IFMA/GPU factors. Valid scripts can contain false
  signature results; the sample includes 6,137 false attempts.
- **Utreexo:** inspection of `connect_block_proven` found two specific blockers
  to treating it as the ready foundation for Stage 5. First, it requires every
  input to appear in a proof against the pre-block accumulator, including outputs
  created earlier in the same block that cannot be in that prestate. Second, its
  completeness check allows extra proven coins, but `acc.apply` deletes every
  entry in the supplied `spends` list, including extras the block never spends.
  These are static findings requiring focused reproduction and repair. The
  spend-only overlay also needs an explicit argument for BIP30 checks against
  coins outside the bundle. Current `drive_utreexo` is a shadow path and passes
  through the normal assumevalid decision; these findings do not establish an
  exploit of ordinary chainstate validation.
- **Artifact bundle:** `docs/ARTIFACT_BUNDLE.md` conflates several verification
  relationships. An assumeutxo commitment is pinned in software chainparams; it
  is not a UTXO commitment in Bitcoin block headers. Signature advice is checked
  against locally derived signature equations and script context, not through
  the snapshot hash. Its production requires historical transaction/prevout
  data; a producer need not have previously validated the entire chain to compute
  advice. The spec's promise that every artifact comes from the snapshot alone
  contradicts its later qualification. Correct these statements before packaging.

A subprocess contains native memory faults and provides an IPC boundary. It does
not prove the verifier's positive answers correct. Fallback handles detected
failures; it does not repair an arithmetic bug that silently says an invalid
signature is valid. An accelerated kernel remains part of the trusted verifier
unless its output has an independently sound verification mechanism.

**Work order A — give this to the SWE-2 handling the live IBD**

Own live synchronization, fetching, chainstate/persistence integration, and the
running node. Preserve the current run's usable evidence and coordinate any
restart. Do not accept projected ETA movement as evidence of increased throughput.

1. Identify the running executable and its source/build hash, release/debug mode,
   actual script-check settings, cache budget, pruning, indexes, cgroup limits,
   and competing load. Record network, height interval, block hashes and bytes.
   Determine which pending changes are actually running.
2. Address the speculative completion finding above before promoting the pool
   hookup. Produce live regtest evidence for successful and failing short tails,
   delayed failures, descendants, reorgs, restart, and authoritative observers.
   Restore both chainstate and affected mempool/index state on deferred failure.
3. Turn the existing counters into interval measurements. The current heartbeat
   divides `total` by block count but prints cumulative `read`, `apply`, `scripts`,
   and `drain` under the same `connect_ms/blk` label. Correct that accounting.
   Under the pool, `script_ns` measures submission; `drain_ns` measures waiting,
   not all worker CPU. Nested accept/reorg/connect timers must not be summed as
   disjoint work. `SIGHASH_NS` and `VERIFY_NS` exist; record their scope and add
   actual attempted/completed/skipped counts where needed.
4. Report interval end-to-end throughput and time spent in body acquisition or
   starvation, decode/hashing, ancestor/context checks, coin lookup/application,
   script preparation/verification, flushing, and recovery. Include worker
   utilization, queue age/depth/bytes, durable-height lag, RSS, page-cache/cgroup
   charge, disk I/O, and actual peer goodput. Start with instrumentation sufficient
   to name the dominant cost; do not build an observability subsystem first.
5. Measure the largest observed cost, change one mechanism, then compare a fixed
   corpus interval on matched prestate and storage conditions. Keep this run's
   assumevalid results separately labeled from bounded `assumevalid=0` replays.
   Use a matching Bitcoin Core baseline where available, including validation
   mode, prestate, cache, pruning, indexes, and hardware.
6. If fetching binds, do candidate 46 before changing the scheduler's limits.
   Compare useful payload goodput with bandwidth-delay product and ready-block
   starvation. For any adaptive byte window, preserve global/per-peer memory
   bounds, oldest-required-block priority, timeout/poaching behavior, duplicate
   accounting, and compatibility with real peers. A sixteen-block window alone
   does not prove a bottleneck.

Deliver a small reviewable diff, exact build and workload manifest, raw interval
measurements, a comparison table, correctness evidence, and a bounded next step.
Log actual experiments in `experiments/LOG.md`. Run
`cargo test --release -p <affected-crate>` for the affected crates and real
connection tests for protocol changes. Keep ETA/model changes separate from
throughput claims.

**Work order B — give this to the researcher SWE-2**

Start candidate 41 as an isolated script replay and prevout-resolution experiment.
The question is: does removing prevout production from the serial connect path
improve total validation throughput at a bounded memory cost, compared with the
existing worker-pool baseline? Do not attempt to prove that independent script
checks can be threaded; the repository already does that.

1. Use a pinned isolated checkout/copy and separate build directory. Initial
   ownership is new experiment drivers/results and documentation. Coordinate
   any required shared consensus interface change with agent A. Do not edit its
   sync/chainstate files or attach a mutable store to its datadir.
2. Inventory reusable harnesses: `connect_bench`, `sync_bench`, the ECDSA replay
   drivers and `tools/ecdsa_replay_corpus.py`. The latter already handles Core
   block/undo extraction and `xor.dat`; raw block-file ingestion is not an
   entirely new starting point. Preserve file framing, chain selection, exact
   original bytes, and incomplete/pruned-file handling. Core file order is not
   guaranteed to be active-chain order.
3. First write the dependency/context and workload manifest. State which
   consensus checks this experiment runs, which are still supplied by the
   ordinary baseline, and where its starting state comes from. Resolve prevouts
   using the corrected occurrence/ordering model above. Recompute txids and
   relevant metadata from source bytes; a lookup result is not proof of provenance.
4. Keep the ordinary script interpreter, sighash implementation, and libsecp
   verifier. No template shortcuts, new crypto, changed consensus flags, or
   assumed historical validity in this experiment. Use the correct flags for
   each block. Preserve both false and true signature outcomes inside Script.
5. Compare the current persistent-pool baseline with corpus-resolved jobs at
   1, 2, 4, and 8 workers where available. Bound queues by bytes/work as well as
   job count. Use separate processes or explicit cache controls so a preceding
   arm cannot pre-validate work for a later arm. Report cache hits.
6. Measure two clearly named scopes: prepared-data script throughput, and total
   preparation plus verification. The latter includes block reading, parsing,
   index construction/spills, prevout resolution, queueing, and final draining.
   If preparation is amortized, report its separate one-time cost and the
   assumed reuse count. If a producer supplies data, price that producer too.
7. Start with a complete small regtest chain and signet correctness replay. Then
   use mainnet samples spanning legacy, SegWit, and Taproot eras, including dense
   or expensive blocks. The existing 24-block sample is useful but cannot stand
   for all history. Supplied-undo samples establish script performance only;
   they must not be reported as full genesis validation.
8. Report elapsed time, parent-plus-child CPU, completed script/signature counts,
   false outcomes, result digests, peak memory, index size, temporary disk space,
   and bytes read/written. For complete replays, include canonical coin-state
   comparison and flush/reopen. Use repeated paired runs with order rotation;
   report dispersion and contention instead of extrapolating a best run.

Candidate 42 can then reuse this event corpus and resolver. Compare bounded
partitioned state construction with the actual cached incremental backend,
including final materialization, flush and reopen. Force a workload larger than
the allowed RAM/cache and identify whether the backing filesystem is real disk
or tmpfs. Vary useful memory budgets; do not call a small in-memory fixture a
laptop disk result. Count partition reads/writes, indexes, spills, output, and
peak temporary storage. Do not hold all blocks or the whole live set in RAM and
describe that as bounded external processing.

For candidates 41/42, add adversarial comparisons covering same-block spends and
reversed ordering, future/nonexistent outputs, duplicate inputs and double spends,
coinbase depth 99/100, duplicate transaction/output histories and BIP30 exceptions,
excluded outputs, wrong amounts/heights/scripts, lock boundaries, fee/subsidy
violations, changed witness data, malformed source/index data, and interrupted
materialization. Exercise relevant cases against Core as well as the existing
Avila path. Publish a rule-coverage table; equal final coins are necessary but
insufficient.

Success is a reproducible end-to-end improvement under a stated resource budget
with unchanged correctness, or an explained result showing where the candidate
loses. Select a material acceptance threshold after measuring the baseline's
optimizable share. Do not use exact linear scaling, an arbitrary fivefold gain,
or a synthetic signature-only multiplier as the universal go/no-go test.

**Execution and review gates**

Both agents may develop concurrently. Timing runs sharing this host's CPU, disk,
or page cache need an agreed schedule or resource isolation; otherwise label
them contended and avoid clean hardware-capacity claims. Never clear the host's
page cache globally during the live run. Record cgroup limits and charged memory,
not only process RSS. Keep changes from both workers individually identifiable.

Each handoff for Codex review should contain the commit/diff, exact commands,
binary/source and corpus hashes, correctness scope, raw results, and known
limitations. Review in this order: consensus equivalence and invalid inputs;
completion/durability/fallback; measurement validity; then whether the gain merits
integration. An optimization that does less validation does not pass the gate.

The later sequence should follow evidence:

| Work | Gate |
| --- | --- |
| 41: corpus replay | Correct source/context resolution, fixed worker-pool comparison, bounded memory, preparation-inclusive results. |
| 42: state materialization | Complete rule coverage and state parity, actual external-memory workload, durable output and full I/O accounting. Independent of perfect scaling in 41. |
| 46: fetch ceiling | Real peers, useful goodput and frontier-starvation evidence. Run earlier whenever agent A observes fetching as the limiter. |
| 43/44: IFMA/GPU | Only after profiling identifies enough crypto cost and matching hardware is available. Benchmark the same secp256k1 work against the existing CPU pool, including IPC/transfers, batches, and failure handling. Differential fuzzing and boundary tests precede integration; one mismatch fails the gate. |
| 45: encoding/source alternatives | Separate ingestion from compression. Require exact byte reconstruction, verified chain selection, bounded decoding, missing/corrupt-data recovery, and savings after hints/indexes/decompression costs. Historical signature encodings must round-trip exactly. |
| 47: cluster | First establish the single-host pipeline and price coordination/data duplication. Operator-owned machines expand the trusted execution boundary; untrusted remote positive verdicts are not locally verified work. |
| Proof-carrying stream | Repair and audit each primitive and its commitment context before composition. SwiftSync and Utreexo can offer alternative approaches to state work; stacking both requires a measured benefit. |

**Keep two completion times, and use a resource model**

Assumeutxo is a separate usability track. Measure time to activate/catch up and
time to finish historical validation independently. It is not the answer to the
user's request for faster full validation. Do not change the product default as
part of this performance experiment. In Avila's current background path,
`background_step` calls `script_checks`, so a snapshot being marked verified does
not by itself demonstrate that every historical script ran with assumevalid off.

[Core's snapshot documentation](https://github.com/bitcoin/bitcoin/blob/master/doc/assumeutxo.md)
requires a supported chainparams commitment and describes separate background
sync. A synced donor's arbitrary tip snapshot is not automatically a supported
snapshot. Its rollback export temporarily changes donor state and disconnects
network activity, so coordinate that operation with the owner of that running
process. Snapshot activation latency alone does not establish wallet/index
readiness or a particular time to usable node.

For full validation, use total resource demand as a lower-bound model:

```text
T >= max(
  required wire bytes / measured useful link throughput,
  total CPU work across all stages / available CPU capacity,
  total GPU work across all stages / available GPU capacity,
  total memory traffic / sustainable memory bandwidth,
  total storage traffic / sustainable mixed-I/O bandwidth,
  dependency critical path
)
```

Hashing, scripts, and joins share resources. Their standalone times cannot all
overlap for free; pipeline fill/drain, dependencies, buffering, and durable
completion also cost time. Use measured service rates to build an achievable
forecast and validate it on larger intervals. Full-chain completion remains the
gate for a full-IBD duration claim. A ten-minute target can motivate research
without being represented as an established physical floor.

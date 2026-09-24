# Experiment: parallel ECDSA advice with bounded recovery

Follow-up: [compact streams and producer economics](2026-09-24-ecdsa-advice-economics.md)
implements bounded block framing and verification-time production. The results
below describe the earlier witness-ID-map experiment.

Status: measured parallel prototype; production adoption withheld.

Roadmap: W2 validation throughput, W3 synchronization advice. Scorecard: P1
partial replay evidence, C1/C2 invalid inputs and recovery, P3 memory, P5 helpers.

## Question

Does [the single-thread replay win](2026-09-23-ecdsa-historical-replay.md)
survive the existing eight-worker Script pool, a bounded retry policy, and
durable chainstate? A result on signature-heavy scripts must not hide a
regression on a complete, smaller chain or be described as measured mainnet IBD.

## Implementation and guarantees

The [runner](../tools/ecdsa_parallel_bench.py) stages a copy of the workspace.
It replaces the copied pool's worker loop with
[bounded job groups](code/ecdsa_parallel_pool.rs), installs the
[parallel hook](code/ecdsa_parallel_hook.rs), and builds a
[replay driver](code/ecdsa_parallel_replay.rs). Production consensus sources,
dependencies, configuration, and live databases are unchanged by this experiment.
The copied build and every measured source are identified by hashes in the
results; concurrent changes to this repository do not identify the built binary.
The final copied build records revision `7954adb1ff4c0aba05944509bf57b629ec2b7442`,
Rust 1.98.1, and secp256k1-sys 0.10.1. The executable's SHA-256 is
`b99b808c151a828bf3ba508d804c732e4995d69f9edf689468431df95b90bbe3`.

The ordinary arm uses the existing persistent pool's one-transaction scheduling.
The candidate distributes queued transactions among available workers in groups
of at most 512. It preserves the eight-block speculative-connect depth and uses
eight Script threads in both arms. Each group can borrow one persistent native
worker; the Script thread waits while that worker computes. At most eight native
workers are active. This is not sixteen simultaneous verification lanes.

Hints are framed by the transaction's complete witness ID and the ordinal of an
ECDSA attempt within its Script execution. This removes global scheduling order
from hint lookup. The actual sighash, key and signature are still computed and
parsed locally; a frame ID is not evidence that its equations are valid.
Schnorr checks retain the existing ordinary verifier.

An ordinary check supplies every claimed false, missing, or unusable hint. A
plausible true hint is provisional until its locally constructed equation is
verified. A group never completes a `BlockCheck` before its equations pass or
ordinary replay supplies replacement results. Script errors after speculative
true results also cause ordinary replay: false signature results can be part of
valid scripts. A failed equation or worker communication error disables advice
for the rest of the run. Groups already in flight must still finish verification
or retry; a global disable does not excuse their pending work.

Recovery repeats only affected groups, with at most 512 transactions per group,
not the entire chain. The bound is in transactions, not a fixed number of
signature attempts. A batch contains at most 8,192 records. A single group may
contain multiple batches, so previously successful batches within a failed group
can be repeated. Each native worker has the existing 16 MiB scratch allocation.

Groups whose input count estimates fewer than 64 checks use ordinary verification
immediately, avoiding extra canonicalization and child startup. Any remaining
batch smaller than 64 gets exact individual verification instead of MSM.
Adversarial tests override this threshold to exercise batching even on tiny cases.

The native worker and equation kernel are unchanged from experiments #27/#29.
The local executable is trusted verification code; the advice producer is
untrusted. Fresh independent coefficients are sampled after each batch is fixed.
Acceptance remains probabilistic, with the previously stated prime-order
residual bound under the randomness and arithmetic assumptions. This is not a
claim of deterministic consensus equivalence or externally reviewed cryptography.

## Sidecar and preparation cost

The versioned experimental sidecar is `AVADVC03`, followed by frames containing
a 32-byte witness ID, a 4-byte attempt count, and one hint byte per attempt.
Only transactions with ECDSA attempts receive frames. Records may be reordered
without changing their association. Duplicate IDs, truncated records, impossible
counts, files over 32 MiB, and missing files select ordinary verification. The
parser additionally caps frames at 500,000 and hints per transaction at 80,000.
These are advice bounds; exceeding them does not change block validity.

The modern sample's payload is **183,782 bytes**, but its complete portable
sidecar is **3,570,094 bytes** for 94,064 transaction frames. Framing costs matter:
that is **9.19%** of the sample's 38,849,984 serialized block bytes. The earlier
one-byte ordinal stream did not include portable parallel association. No
compression or compact block-position framing is claimed here. The complete
regtest sidecar is 596,144 bytes for 43,032 attempts.

Advice is reused from the preparatory run, which is recorded separately:
mainnet trace capture took 24.92 seconds; nonce reconstruction, framing and
serialization took 29.46 seconds. Capture used 28.40 process-tree CPU seconds;
the second pass's native worker used 22.55 CPU seconds, excluding its Python
parent. Thus there is still substantial first-use helper work. A lone node
preparing its own advice and then replaying is slower than ordinary validation.
This prototype targets reuse of advice across recipients; a fused producer is
not implemented. Final comparisons include recipient sidecar loading and lookup.

## Workloads and measurement

- **Recent mainnet:** the same 24 linked blocks, heights 956105–956128, 99,198
  non-coinbase transactions and 183,782 ECDSA attempts, including 6,137 false
  results. Both arms decode original blocks, perform context-free block checks
  and linkage checks, decode supplied undo, and run actual input scripts with
  height-dependent flags. This validates scripts against supplied prestate. It
  does not derive historical UTXOs or validate the complete header ancestry.
- **Complete regtest:** 625 blocks from genesis, 15,989 transactions and 43,032
  ECDSA attempts; ordinary headers, contextual checks, state transitions and
  Script validation all run. Both arms compare the complete final UTXO hash and
  12,995-coin count.
- **Durable regtest:** the same complete chain, a fresh on-disk redb directory
  per run, a 1 MiB UTXO write-back budget, final flush, close, reopen and a second
  complete state/tip comparison. All are inside the wall timer. This is a small
  database workload with write-back pressure, not a 13 GB UTXO benchmark. Redb's
  own cache retains its 1 GiB default; the 1 MiB limit is the UTXO dirty map, not
  a whole-process memory budget. Every run ends with 17,048,904 bytes of database,
  block and state files.
- **Early mainnet:** complete heights 0–500 from genesis, only ten ECDSA attempts,
  including historical uncompressed-key/high-S handling. Startup dominates.
- **Invalid spends and Script cases:** separately measured correctness workloads
  described below, not averaged into throughput results.

Hardware is the shared i3-N305 desktop, eight available CPUs, with other desktop
work running. Three repetitions alternate ordinary/candidate order. Report every
sample and the median, with no outlier removal. Wall-time variation is substantial;
combined CPU is also reported. The Python runner measures child-resource CPU after
the Rust process has waited for all native children, including those killed on
failure. Native-worker CPU alone is not the recipient's total cost.

The source corpus is read into RAM before the inner wall timer in both arms;
process-tree CPU includes that read. No network download, cold-cache guarantee,
energy measurement, or full-history extrapolation is included.

## Results

Medians of all three runs, in seconds. Brackets give the full observed range,
not confidence intervals. CPU includes Rust and all reaped native workers.

| Workload | Ordinary wall | Advice wall | Ordinary CPU | Advice CPU | Wall / CPU reduction |
|---|---:|---:|---:|---:|---:|
| Recent mainnet scripts | 19.796 [16.950–20.738] | 16.432 [15.507–17.227] | 25.053 [24.970–25.058] | 19.289 [19.157–19.387] | **17.0% / 23.0%** |
| Complete regtest, RAM | 5.795 [4.858–6.699] | 4.824 [3.437–5.146] | 5.671 [5.665–5.674] | 5.264 [5.243–5.266] | **16.8% / 7.2%** |
| Complete regtest, disk + reopen | 5.454 [5.272–6.107] | 4.946 [4.748–6.788] | 5.891 [5.881–5.938] | 5.579 [5.560–5.620] | **9.3% / 5.3%** |
| Early mainnet, ten checks | 0.02355 [0.01344–0.03462] | 0.02158 [0.01435–0.04454] | 0.01635 [0.01605–0.01666] | 0.01665 [0.01604–0.01679] | 8.4% / **−1.8%** |

The meaningful dense-workload result is the **23.0% CPU reduction**. The wall
measurements are noisy; the median does not clear the earlier approximate 20%
elapsed-time target, and these three runs do not establish a statistical speedup
bound. The smaller complete chain saves less CPU, especially with storage.
Early mainnet has no useful batching work: its ten checks take the direct ordinary
path with zero child workers. Its roughly 0.30 ms median CPU regression remains
reported, despite the wide startup/scheduling variation.

A preliminary implementation used decreasing queue shares without accounting
for already active workers and speculated on every small group. Its mainnet
result was 25.56 → 20.60 CPU seconds, but regtest **regressed** 5.79 → 5.97 and
disk regressed 6.10 → 6.38 CPU seconds. Balancing against idle workers and bypassing
small groups reduced mainnet native batches from 441 to 221–222 and removed those
small-chain CPU regressions in the final three runs. That preliminary trial is
preserved in the result artifact; it is not substituted into final medians.

In separate instrumented runs, sampled summed RSS rose from **62,021,632 bytes
(59.1 MiB)** ordinary to **188,575,744 bytes (179.8 MiB)** with advice. The sampler
observed one process versus nine. It sampled every 20 ms and can miss brief
peaks; shared pages are counted in each process. This is a measured memory
tradeoff, not an improvement on every resource dimension. These profiling runs
are excluded from the timing table.

Bad advice now has bounded work amplification. On the mainnet sample:

| Advice case | Total CPU seconds | Retried groups | Repeated ECDSA attempts |
|---|---:|---:|---:|
| One wrong parity | 19.22 | 1 | 1,426 |
| One false check forged true | 22.41 | 1 | 677 |
| Every true-check hint corrupted | 25.69 | 8 | 7,351 |
| Native workers exit | 25.45 | 8 | 7,351 |

The all-corrupt case used about **2.5% more CPU** than the ordinary median and
repeated **4.0%** of the sample's check count, rather than restarting all 183,782
attempts. That is one observed attack, not a universal 2.5% worst-case bound.
Single-hint corruption can arrive late enough to retain savings from the verified
prefix, which explains its lower total CPU. Missing/malformed advice and false
claims all preserved the outcome.

The complete-chain UTXO hash, including every durable reopen and rollback run,
was `e5b0e2cbfffc9137ec750d631f05ad5d9bb74d0fba47be2f35c552c252633707`.
The mainnet Script digest remained
`63d23d5bae36386939c31d955fcc686266ae569d56ab3e9104dc23fe285aac92`.

Raw samples, build/source hashes, corpus provenance, preparation, the preliminary
trial and validation evidence are in
[the result artifact](results/2026-09-24-ecdsa-parallel-replay.json).

## Correctness and recovery

The ordinary/candidate comparisons require the same complete UTXO hash on chain
workloads and the same successful Script-outcome digest on the supplied-prestate
mainnet workload. Correct hints must produce no retries. Expected Script outcomes
are independently fixed for the nine Script cases: invalid signatures, valid
`CHECKSIG NOT`, failed multisig key matches, malformed and lax DER, high S, and
uncompressed/hybrid keys.

The runner checks wrong nonce parity, false claims for true checks, forged true
claims for false checks, all valid-check hints corrupted, partial absence,
reordered frames, truncation, empty advice, duplicates, impossible counts,
missing sidecars, and native worker exit. Reordered frames must preserve their
meaning; malformed or absent sidecars must select ordinary verification.

The [rollback case](code/ecdsa_parallel_rollback.rs) changes the final
transaction's output by one satoshi, updates witness/transaction commitments and
remines the regtest header. Inputs and block structure remain valid, but the
original signature no longer matches its sighash. It supplies the original nonce
hints under the modified transaction's witness ID. The block must fail specifically
at Script verification, restore the exact prior tip/UTXO hash, and be marked
invalid. The original valid final block must then connect to the reference hash.
All three candidate repetitions passed, retrying one group containing 1–3
transactions and 1–6 ECDSA attempts. This tests failed speculative connect and
subsequent valid connection, not every deep-reorganization scenario.

The [additional checker](../tools/check_ecdsa_parallel.py) exercises successful
and failing one-record flushes inside the signature callback, the small-work
bypass, a missing executable, an invalid local-worker verdict, an oversized
sidecar, and the existing ASan/UBSan/VERIFY worker. It separately samples RSS of
the Rust process and all its native children through `/proc`; summing RSS double
counts shared pages and is not a private-memory measurement.

The main runner completed **93 successful runs**: 36 ordinary/candidate
repetitions, including the rollback workload, and 57 hostile/unavailable-advice
variants. The additional checker passed eight boundary cases and two separate
memory profiles. ASan/UBSan/VERIFY reported no finding in the worker boundary
case; LeakSanitizer remains disabled under the managed ptrace environment. The
earlier native cancellation, rare-x, malformed-point and protocol tests still
apply to the unchanged native source.

The copied consensus library suite passed **479 tests, zero failures**, with
two existing snapshot tests ignored (one slow resynchronization probe and one
unfinished zero-scan test). The advice hook is unconfigured in that unit suite;
the 103 separate replay/boundary/profile runs exercise its configured modes.
Rust formatting, Python compilation, source-hash and outcome/path audits passed.

## Adoption boundary and reproduction

This completes an offline integration experiment, not a production IBD feature.
**Decision: retain the reproducible prototype; do not enable it by default.**
The receiver's computation improved under parallelism, so the claimed fixed
per-signature arithmetic floor is not supported. The evidence also rules out
carrying the earlier single-thread 33% wall gain directly into a whole-node claim.
It still depends on prepared advice, a private libsecp interface, probabilistic
verification, and an experimental process protocol. Sidecars are bounded whole
windows loaded into memory, not a deployed peer protocol or full-history stream.
There is no production timeout/supervision policy for a hung local arithmetic
worker. These limitations prevent enabling it in the node by default on the
strength of these measurements.

The source additions are reusable, and all fallbacks are exercised through the
actual interpreter and chainstate. Whether full mainnet IBD improves, and by how
much after network/disk costs, remains unmeasured.

```sh
AVILA_COINS_ENGINE=redb python3 tools/ecdsa_parallel_bench.py \
  --output target/ecdsa-parallel/reproduce \
  --historical-corpus target/ecdsa-replay/corpus-linked-24/corpus.bin \
  --chain-corpus /tmp/spend-fixture.dat --repetitions 3
```

Corpus extraction and provenance follow the preceding replay report. Public block
and undo bodies, trace files, and databases remain under ignored `target/` or
`/tmp`; no chain data or personal node state belongs in the committed results.

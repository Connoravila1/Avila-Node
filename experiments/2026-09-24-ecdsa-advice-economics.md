# ECDSA advice: compact streams and producer economics

This extends the [parallel replay experiment](2026-09-24-ecdsa-parallel-replay.md)
with bounded block-position framing and advice generation during verification.
It measures actual work at the producer as well as the recipient. All integration
remains in isolated copied workspaces; production consensus code is unchanged by
this experiment.

## Measurements

The mainnet sidecar is **24.42× smaller**. The streaming recipient retains a
**23.7% CPU-time reduction**. Producing and packing advice now costs **29.13 CPU
seconds**, versus **51.35** for the previous two-pass workflow: **43.3% less**.
The producer still costs more than ordinary verification alone; its benefit
depends on recipients reusing its output.

Three repeats per arm, eight Script workers, using the same final binary.
CPU includes native child processes. Times below are medians in seconds:

| Workload | Ordinary CPU | Stream CPU | CPU change | Ordinary elapsed | Stream elapsed |
|---|---:|---:|---:|---:|---:|
| 24 recent mainnet blocks, supplied undo | 25.176 | 19.203 | −23.7% | 20.498 | 18.338 |
| Complete 625-block regtest, RAM | 5.794 | 5.466 | −5.7% | 5.173 | 6.029 |
| Same regtest, disk + flush + reopen | 6.087 | 5.753 | −5.5% | 6.408 | 6.694 |
| Early mainnet, 501 blocks / 10 ECDSA checks | 0.0154 | 0.0159 | +0.0005 s | 0.0177 | 0.0173 |

Elapsed improvements do **not** hold across all workloads. The smaller chain
fixtures regress in median elapsed time despite using less CPU. On the modern
sample, ordinary CPU ranged 24.970–25.379 s and stream CPU 19.008–19.263 s;
elapsed ranges were 19.205–22.818 s and 18.007–19.296 s. The earlier comparison
phase also retained a legacy-map control: 25.247 s ordinary, 19.487 s with the
map, and 19.311 s with the stream. The compact format mainly fixes transport and
memory growth; it does not create another large cryptographic speedup.

The first batched producer replayed 137,316 Script attempts after provisional
false results. A preliminary run used 32.84 CPU seconds, slightly worse than
the per-call producer's 32.08 s in that run. Reusing already-completed
transactions reduced actual Script replay to **18,831 attempts**. Three repeats
then measured 28.95 s for the batched producer versus 32.24 s for per-call IPC.
All generated hints match the independent producer exactly, including false
results. The bounded cache really does fill on this sample: 568 insertions were
not retained in the 512-job profile. This selects recomputation, with the same
final output, rather than unbounded allocation.

Producer scheduling was measured separately, rotating three group sizes through
three repetitions. Recipient groups remain at 512 transactions:

| Maximum producer group | CPU median | Elapsed median | Elapsed range |
|---|---:|---:|---:|
| 512 transactions | 29.002 | 23.131 | 22.982–27.440 |
| 128 transactions | 28.935 | 22.236 | 18.051–23.418 |
| **64 transactions** | **28.912** | **18.675** | **17.756–19.728** |

Use **64** for the tested producer profile. Smaller groups preserve its CPU
savings and improve scheduling on this workload. This is the best of the tested
settings, not a claim of optimal scheduling on other histories or hardware.
Packing adds a median **0.217 CPU seconds**. The old workflow was freshly
remeasured once: 28.110 s for capture plus 23.026 s for separate production,
including the Python producer's CPU, plus packing.

## Whole-system cost

Let B = 25.176 s for ordinary validation, V = 19.203 s for an advised recipient,
and P = 29.128 s for production plus packing. These are a CPU accounting model
for this sample, excluding real network transport:

- A node already validating pays **P − B = 3.953 extra CPU seconds** to export
  advice. Each recipient saves **B − V = 5.973 seconds**. One additional
  recipient repays that incremental producer cost at these medians.
- A dedicated helper created solely to supply advice must repay all of P.
  The nominal crossover is **five recipients**. That fifth-recipient margin is
  small and should not be treated as a practical guarantee.
- A lone node creating advice solely for its own subsequent replay loses:
  it pays both production and recipient costs.

This is a measured argument for reusing a validating node's work across nodes.
It is not an end-to-end IBD duration forecast.

## Validation and memory

All **129 comparison runs**, **nine scheduling runs**, and **133 additional
boundary/memory checks** passed. The additional checks include eight packing
checks. The copied consensus library passed **482 tests**, with zero failures
and two pre-existing ignores. Three codec tests also passed independently,
including a file larger than 32 MiB whose decoded frames are released as it
streams. [Complete measurements and source/build identities](results/2026-09-24-ecdsa-advice-economics.json)
include the preliminary producer and both comparison phases.

Corrupting every mainnet hint caused seven groups to retry 6,597 checks, with
at most 465 transactions in any retried group. CPU was 25.816 s, about 2.5%
above the ordinary median; the final Script digest remained identical. Missing,
reordered, truncated, wrongly keyed and malformed frames preserved the ordinary
result. Worker startup failures, exits and malformed replies recovered through
ordinary checks. Failed producers emitted conservative unknown hints.

The invalid-spend test changes a transaction's amount, rebuilds commitments and
PoW, and supplies the original hint under the changed block identity. The stream
recipient rejected it, restored the exact prefix UTXO hash/tip, and accepted the
original valid branch; one group retried six checks. Both producer variants
also rejected the invalid branch correctly.

New synthetic Script cases construct **x(R) = n + 2** at both parities, using the
legacy SIGHASH_SINGLE out-of-range case and Q = (R − zG)/2. They exercise real
escape values 2 and 3 through capture, production, packing and batch reception.
Wrong parity and truncated escapes recover correctly. These paths and the
ordinary edge cases also pass with the ASan/UBSan/VERIFY native worker.

Separate 20 ms sampled process-tree RSS profiles measured 59.6 MiB ordinary,
208.6 MiB with the legacy map, 125.2 MiB with the stream, and 96.6 MiB for the
batched producer. The optimized arms each reached nine processes. These are
single sampled profiles, sum shared pages repeatedly, and are **not memory caps**
or an attribution of the whole difference to framing. The mainnet reader held
one decoded frame with at most 11,823 hint bytes. Complete chain runs briefly
held up to 11 frames as queued/finishing workers released references.

Two harness issues are recorded: the preliminary producer run stopped on an
over-strict assertion about cache saturation, despite correct output; the
standalone extras selector initially omitted its own attack fixture. Both were
repaired, and the complete and standalone suites passed. Neither repair changed
the signature kernel.

## Compact, streaming transport

`AVHINT04` starts with an eight-byte version marker. Each frame contains a local
block hash (32 bytes), a bounded body length (4 bytes), then:

1. A canonical CompactSize non-coinbase transaction count.
2. A CompactSize ECDSA-attempt count for each transaction, including zero counts.
3. One block-wide packed stream of two-bit symbols. `0` and `1` encode ordinary
   nonce parity, `2` means unknown/ordinary verification, and `3` selects an
   appended escape byte for the rare hints `2` and `3` where x(R) is at least n.

Counts, escapes, zero padding and the exact end of the frame are checked.
Frames are bounded to 1 MiB, 100,000 transactions, 80,000 attempts per transaction
and 500,000 attempts per block. These are optimization limits: exceeding one
selects ordinary validation. The reader retains one bounded frame as lookahead;
a missing block falls back while a later matching block can still use that frame.
A malformed bounded body can be skipped. A malformed length or truncated frame
ends the stream and the remaining work uses ordinary verification.

Script jobs hold immutable reference-counted frames and actual transaction
positions. The production-shaped connect bridge preserves positions even when
other transactions have been skipped by the verified-transaction cache. The
reader never builds a history-sized transaction-ID map. Frames live only while
queued/active jobs reference them; worker completion can briefly retain frames
beyond the eight pending blocks. The measured frame count is reported separately
from total process memory.

The 24-block mainnet sample shrinks from **3,570,094 to 146,202 bytes**: 24.42×
smaller, a 95.90% reduction, and **0.376%** of its 38,849,984 serialized block
bytes. The complete regtest stream is **49,456 bytes**, versus 596,144 bytes with
witness-ID framing. All numbers include framing. Actual network transfer was not
timed. Dense framing emits hintless blocks and grows the early sample from 306
to 18,524 bytes. A tested sparse export simply omits those frames: **320 bytes**
for early mainnet and **45,016 bytes** for regtest, with identical outcomes and
no reader changes. The mainnet sample has advice in every block. This optional
sparse export is exercised by the checker; the timed packer emits dense frames.

## Producing advice while verifying

Ordinary verification already constructs the point from which advice is derived.
The existing native `P` command verifies each equation individually and returns
both its exact result and the reconstruction bits. Calling it in the ordinary
Script path avoids the old workflow's second full curve calculation. The new
producer still computes local sighashes, parses keys/signatures, normalizes S and
preserves legitimate false results. Failed production uses the existing ordinary
verifier and emits unknown advice.

Extracting the point is not free: libsecp's ordinary verifier can compare the
x-coordinate in Jacobian form, whereas the producer extracts an affine point.
This prototype also crosses a process boundary and serializes records. See the
[upstream verifier](https://raw.githubusercontent.com/bitcoin-core/secp256k1/master/src/ecdsa_impl.h).
The experiment uses the pinned secp256k1-sys 0.10.1 kernel from the earlier work,
not an unpinned upstream checkout.

The first producer sends one request per attempted signature. A second variant
batches those requests within the existing bounded transaction groups. It uses
provisional true results until every pending equation has an exact answer. A
false answer requires the affected Script execution to be revisited because
CHECKMULTISIG and conditional scripts may follow a different path.

The initial batched version replayed entire groups. The refined version reuses
completed transactions whose provisional answers all proved true, and replays
only the affected transactions. Their cache keys contain the full canonical
message, signature and public key, not a truncated digest. Completed transaction
results are associated by position within the same immutable job group, avoiding
a transaction-ID-only prestate cache. No `BlockCheck` completes before exact
producer results or ordinary fallback establish its outcome.

The memo table holds at most 8,192 records per group. When it fills, uncached
checks can be calculated again during replay; speculation can also visit branches
absent from the final execution. Thus the batched producer avoids the systematic
second curve pass, but does not promise precisely one multiplication per final
attempt under all workloads. CPU accounting includes this extra work.

Both producer variants first emit the older bounded witness-ID format. A separate
cheap packing pass creates the stream and is charged separately. The recipient
is streaming; this producer/export pipeline still uses the earlier 32 MiB map
limit during packing. A historical-scale online exporter remains future work.

## What the results establish

The workloads and trust scope match the prior experiment: recent mainnet Scripts
use supplied undo outputs; complete regtest derives state from genesis; durable
regtest flushes and reopens a fresh redb database. All final state/Script digests
are compared with ordinary verification. The mainnet sample contains 183,782
ECDSA attempts, including 6,137 legitimate false results. This is not a full
mainnet IBD measurement. Schnorr verification uses the existing ordinary path.

Each executable is copied to an immutable per-run path. Manifests record the
copied sources, pinned lockfile, executable hashes and corpus hashes. Concurrent
repository changes are excluded by staging from the prior frozen workspace.
Repeated timing runs do not overlap our own compilation or other benchmark
processes. The shared desktop remains busy with unrelated work, and recorded
load averages accompany the results. Process-tree CPU includes waited native
children; separate RSS sampling sums resident pages across processes, counting
shared pages more than once. The initial corpus read precedes the driver's wall
timer; process-tree CPU includes it. These are local replay measurements, not
cold-download timings.

The native recipient kernel and its random coefficient policy are unchanged.
Hints are untrusted, but the local worker executable is trusted verification
code. Recipient batch acceptance retains the previously described probabilistic
soundness qualification. Producer answers are individual ordinary ECDSA results.
The role of extra witness data in ECDSA batching is also explicitly acknowledged
by [BIP 340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

## Reproduction

These commands require the recorded corpora, native worker and frozen parallel
workspace from the preceding experiment. They do not open the live node's
chainstate or wallet. Rebuilding against a newer production workspace is a new
comparison; a moving Git HEAD is not the identity of the measured code.

```sh
python3 tools/ecdsa_economics_bench.py \
  --output target/ecdsa-economics/final-1 --repetitions 3 --two-pass

python3 tools/ecdsa_batched_producer_bench.py \
  --base target/ecdsa-economics/final-1 \
  --output target/ecdsa-economics/batched-2 --repetitions 3

python3 tools/check_ecdsa_economics.py \
  --build-dir target/ecdsa-economics/batched-2 \
  --output target/ecdsa-economics/checks-2 \
  --producer-mode produce-batch --rare-cases \
  --checked-worker target/ecdsa-replay/final-1/worker-checked

python3 tools/check_ecdsa_economics.py \
  --build-dir target/ecdsa-economics/batched-2 \
  --output target/ecdsa-economics/checks-direct-2 \
  --producer-mode produce --rare-cases --only extras \
  --checked-worker target/ecdsa-replay/final-1/worker-checked

python3 tools/check_ecdsa_economics.py \
  --build-dir target/ecdsa-economics/batched-2 \
  --output target/ecdsa-economics/schedule-1 \
  --producer-mode produce-batch --only schedule
```

Use fresh output directories. Raw traces, sidecars, databases and executables stay
under ignored `target/`; only source, reports and measurement metadata belong in
the repository. The native worker's source and notices are unchanged from the
[original experiment](2026-09-23-ibd-ecdsa-advice.md).

The meaningful remaining qualification is a larger, era-diverse/full-IBD run,
an online exporter without the packing-map limit, and independent review of the
cryptographic and consensus boundary. The experiment does not enable the new
verifier in a production node. Its worker protocol also still lacks an internal
hang deadline; the lab harness uses external timeouts.

Follow-up: [repeated public-key aggregation](2026-09-24-ecdsa-repeated-keys.md)
reduces mainnet-sample recipient CPU another 12.7% with the same advice and Rust
replay binary. The added elapsed-time benefit remains inconclusive.

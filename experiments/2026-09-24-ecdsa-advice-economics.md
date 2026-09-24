# ECDSA advice: compact streams and producer economics

This extends the [parallel replay experiment](2026-09-24-ecdsa-parallel-replay.md)
with bounded block-position framing and advice generation during verification.
It measures actual work at the producer as well as the recipient. All integration
remains in isolated copied workspaces; production consensus code is unchanged by
this experiment.

## Measurements

Final measurements and validation results are recorded below after qualification.

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
timed. Dense framing also emits empty blocks; that tradeoff matters for the early
coinbase-heavy sample and is accounted for in the measurements.

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
```

Use fresh output directories. Raw traces, sidecars, databases and executables stay
under ignored `target/`; only source, reports and measurement metadata belong in
the repository. The native worker's source and notices are unchanged from the
[original experiment](2026-09-23-ibd-ecdsa-advice.md).

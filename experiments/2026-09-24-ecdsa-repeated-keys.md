# Repeated public keys in advised ECDSA verification

Combining repeated public-key terms removes another **12.7% of validation CPU**
from the previous streaming-advice implementation on the fixed 24-block mainnet
Script sample. Total CPU is **33.9% below ordinary verification**. This is a
further reduction in computation, using the same blocks and the same advice.
The additional elapsed-time benefit is inconclusive on the shared host.

This extends [the advice economics experiment](2026-09-24-ecdsa-advice-economics.md).
It remains an isolated experiment using untrusted nonce advice and randomized
batch acceptance. Production consensus sources and the original measured kernel
are unchanged. Full mainnet IBD is still unmeasured.

## Matched replay

The same immutable Rust executable runs all arms. Three repetitions per arm,
rotating their order, with eight Script workers, at most 512 transactions per
group, an 8,192-signature batch cap, and the existing 64-check small-group bypass.
The optimized arms use the identical 146,202-byte mainnet hint stream. Only the
local arithmetic worker changes.

CPU seconds include the Rust process and its native children. Elapsed seconds
cover the entire child invocation, including startup and input reading. These
are medians, not a full-IBD duration forecast:

| Workload | Ordinary CPU | Previous advice CPU | Repeated-key CPU | Additional CPU reduction |
|---|---:|---:|---:|---:|
| 24 mainnet blocks, supplied undo | 25.274 | 19.133 | **16.705** | **12.7%** |
| Complete 625-block regtest, RAM | 5.727 | 5.347 | 5.308 | 0.7% |
| Same regtest, disk + flush + reopen | 5.996 | 5.684 | 5.597 | 1.5% |

The modern sample contains 99,198 non-coinbase transactions and 183,782 ECDSA
attempts, including 6,137 false results. All arms preserve the Script verdict
digest and both attempt counts. It covers heights 956105–956128 with supplied
undo/prestate, rather than deriving that prestate from genesis. The complete
regtest runs preserve the same 12,995-coin UTXO hash, including after reopening
the database. The 501-block early-mainnet fixture also matches; its ten checks
all take the ordinary bypass, so it provides no evidence of a speedup.

Mainnet CPU ranges are 25.163–25.333 s ordinary, 18.824–19.512 s with the old
worker, and 16.649–16.838 s with the new worker. The CPU improvement is clear
across these trials. Elapsed medians are 16.751, 13.204 and 12.527 s respectively,
but the old/new advice ranges overlap substantially: 9.838–13.234 versus
11.861–15.370 s. Two of three corresponding repetitions take longer with the
new worker. An additional elapsed-time win over the previous implementation is
therefore **not established**. Regtest's small incremental CPU changes also
overlap run-to-run variation; its RAM elapsed median rises from 4.519 to 4.680 s.

The machine is the same shared i3-N305 host. The harness serializes benchmarks,
but does not control unrelated host load; load averages accompany every sample.
Actual group membership varies with worker scheduling under the same policy.
The mainnet run uses nearly every true hint, while many of the smaller regtest
groups take ordinary checks. Per-run counts are retained in the metadata.

## Why this removes work

The existing batch checks the equation

```text
sum_i a_i * (s_i R_i - r_i Q_i - z_i G) = infinity
```

When several records use the same public key Q, their public-key terms are
exactly equal to one term:

```text
-a_1*r_1*Q - a_2*r_2*Q - ... = -(sum_i a_i*r_i) * Q
```

Scalar addition is modulo the curve order. A batch with n signatures and u
distinct keys therefore needs n + u variable-point terms instead of 2n. Each
signature keeps its own nonce-point check and independently sampled coefficient.
The generator contribution still includes every message. A zero aggregate key
scalar is valid and contributes the identity.

The implementation sorts pointers by all 33 bytes of the compressed key, then
combines adjacent terms. Opposite-sign points share an x coordinate but have
different encodings and remain separate groups. A second variant additionally
parses each identical key once. Every signature's r/s bounds, normalization,
message and nonce lift are still checked. A failed first key parse rejects the
batch before any duplicate can reuse it.

Coefficients are sampled after the complete immutable batch is available, with
the same rejection sampling as before. Sorting preserves each coefficient's
association with its original record. Coefficients are never shared across
signatures, including identical signatures. The all-one test control still
demonstrates a cancellation attack; fresh independent weights reject it.

The extra pointer array is bounded to 8,192 entries, or 64 KiB on this host,
plus the C library's sorting workspace. The original preallocated point/scalar
arrays and scratch capacity remain; this experiment reduces arithmetic inputs,
not their allocation caps. There is no persistent key cache or new transport.

## Arithmetic controls

The historical trace has 177,645 true attempts and 92,284 distinct keys globally.
Global reuse alone is insufficient: terms must meet inside a bounded batch.
Grouping consecutive trace frames into 512-transaction groups, splitting at
8,192 checks, reduces the point count from 355,290 to 279,231: **21.4% fewer**.
The corresponding 64-frame grouping saves 20.7%. These are trace-order proxies;
capture completion order does not reproduce the live worker's exact grouping.
The matched replay above measures the actual scheduling policy separately.

Three native-worker repetitions per arm distinguish arithmetic aggregation from
parse reuse. Times are CPU seconds including worker input parsing. The historical
kernel concatenates true trace records into batches of at most 8,192; false
attempts remain covered by the full Script replay. Each synthetic workload has
8,192 different messages/signatures and repeats the batch four times per trial:

| Kernel workload | Previous kernel | Combine terms only | Also reuse key parse |
|---|---:|---:|---:|
| 177,645 true historical attempts | 11.664 | 10.279 | **9.104** |
| 32,768 checks, unique keys within each batch | 2.102 | 2.106 | 2.108 |
| 32,768 checks, 16 keys within each batch | 2.110 | 1.574 | 1.114 |

On the historical trace, aggregation alone saves 11.9%; adding parse reuse
increases the saving to **21.9%**. The unique-key control rises only 0.3% at the
medians, within its sample ranges. The deliberately repetitive synthetic case
saves 47.2%; that is a distribution-specific kernel result, not an IBD claim.

## Validation

All **27 kernel comparisons**, **33 replay comparisons**, **83 boundary runs**,
**three historical corruption runs**, and **nine native protocol checks** pass.
The original and new native self-test suites also pass under AddressSanitizer,
UndefinedBehaviorSanitizer and libsecp256k1 VERIFY assertions. LeakSanitizer is
disabled for the managed runner, as in the preceding experiments.

The new native suite covers unique and repeated keys, valid opposite-sign keys,
high S, invalid r/s and key encodings, wrong messages and nonce hints, the rare
x(R) >= n branch, zero key-coefficient sums, empty and oversized batches, and
the full 8,192-record batch. A same-key pair with opposing invalid residuals
passes the intentionally unsafe all-one control and fails repeated randomized
checks in both coalescing variants. No new field or group arithmetic is written.

The existing Script boundary suite runs against the new worker: false CHECKSIG
results, CHECKMULTISIG retries, historical key/DER forms, missing and malformed
streams, worker exits and bad replies, one-record batches, sparse streams, and
both rare nonce parities through the compact codec. Checked-worker Script and
producer cases pass as well. The producer and ordinary worker commands reuse
the original functions.

All-corrupt mainnet hints recover the ordinary Script result in 25.640 CPU
seconds, 1.4% above the ordinary median. Eight groups retry 7,351 checks, with at
most 465 transactions in a retried group. Single wrong-parity and forged-true
hints also recover the same result. The invalid-spend test rejects the altered
branch, restores the exact prefix, and accepts the original branch, for both the
stream recipient and producer. The recipient retries one group of one check in
this run; grouping is scheduling-dependent.

The Rust executable is byte-identical to the prior experiment's final build;
this follow-up does not claim a fresh run of its previously passed 482-test
consensus suite. New verification targets the changed native arithmetic and its
existing Script, state, fallback and rollback boundaries.

## Reproduction and remaining work

[Measurements and source/build identities](results/2026-09-24-ecdsa-repeated-keys.json)
include every run, compiler commands, the pinned vendor-source hash, corpus and
sidecar hashes, and the frozen Rust build manifest. The source is
[ecdsa_coalesced_worker.c](code/ecdsa_coalesced_worker.c); the runner is
[ecdsa_coalesced_bench.py](../tools/ecdsa_coalesced_bench.py).

The commands require the recorded corpus, advice and immutable replay build
from the preceding experiment. Use one fresh output directory, then run the
remaining phases against that build. Each phase verifies source and artifact
identities before use:

```sh
python3 tools/ecdsa_coalesced_bench.py --output target/ecdsa-coalesced/new-run --phase build
python3 tools/ecdsa_coalesced_bench.py --output target/ecdsa-coalesced/new-run --phase kernel
python3 tools/ecdsa_coalesced_bench.py --output target/ecdsa-coalesced/new-run --phase replay
python3 tools/ecdsa_coalesced_bench.py --output target/ecdsa-coalesced/new-run --phase checks
```

The next useful qualification is a larger, era-diverse/full-IBD run. Repeated-key
frequency, Schnorr share, storage and network costs will determine how much this
helps outside the sample. The online exporter, internal worker deadlines, and
independent cryptographic/consensus review from the preceding report remain
open. This experiment preserves the existing randomized equation and tests its
implementation; it does not establish deterministic acceptance equivalence or
production readiness. The ordinary verifier remains the production path.

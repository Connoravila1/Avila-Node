# Experiment: can historical ECDSA verification escape the individual-check floor?

Status: experiment complete; isolated research kernel, not integrated into the node.

Roadmap: W2 validation speed and W3 verified synchronization hints.
Scorecard: P1 kernel evidence only; C1/C2 adversarial checks; P5 advice costs.

Operating profile: one CPU thread on the existing x86-64 desktop; synthetic
ECDSA signatures, compressed public keys and precomputed message digests. No
snapshot, assumed-valid checkpoint, deferred verification, network traffic,
block decoding, Script execution, chainstate, or historical replay is measured.
This cannot establish a full-IBD speedup or full consensus equivalence.

## Question and hypothesis

The earlier k256/SP experiment established that one implementation was too slow.
It did not establish that 92 microseconds per ECDSA verification is a lower
bound, or that historical ECDSA can never benefit from batch verification.

Test two openings using the same arithmetic substrate as the ordinary verifier:

1. **Deterministic batch inversion, with no extra input.** Share the scalar
   inversions across signatures, then perform every individual point calculation
   and x-coordinate check. This changes the arithmetic schedule, not the
   acceptance predicate.
2. **Untrusted nonce-point advice.** Obtain the missing nonce-point information
   from a helper, check its binding to the original signature locally, and combine
   verification equations using fresh random coefficients. The original blocks
   and signatures remain unchanged. This adds helper data and probabilistic
   acceptance; it is a distinct verification profile from deterministic replay.

The first candidate fails its performance hypothesis if sharing inversions costs
more than it saves. The second fails if native multi-scalar multiplication plus
advice checking cannot beat the matched individual verifier. Neither hypothesis
assumes a particular whole-node speedup.

## Why the second opening exists

This is established cryptographic prior art, not a newly invented signature
scheme. [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
explicitly qualifies its ECDSA batching limitation with **"unless additional
witness data is added"**. [Hal Finney's 2011 discussion](https://bitcointalk.org/index.php?topic=3238.0)
already observes that the missing point is computed during ordinary verification
and can be recovered for existing signatures. [Tomescu's ECDSA exposition](https://alinush.github.io/ecdsa#batch-verification)
describes the randomized batch equations for the resulting point representation.

For signature `(r,s)`, digest scalar `z`, public key `Q` and generator `G`, a
valid nonce point satisfies:

```text
R is a finite point on secp256k1
x(R) mod n = r
s R - r Q - z G = infinity
```

Here `n` is the group order and `p` the field prime. Because `p < 2n`, the x
coordinate can only be `r` or `r+n` when the latter is below `p`. Two bits select
that choice and the y parity. The helper need not know a signing key or secret
nonce: it reconstructs `R = s^-1(zG + rQ)` using public information.

The prototype measures two advice encodings:

| Encoding | Bytes per signature | Local reconstruction |
| --- | ---: | --- |
| `hint1` | 1 | Two meaningful bits; recover y with a field square root |
| `y33` | 33 | The same header plus full y; check y range, parity and curve equation |

Then it verifies one equation for a batch:

```text
sum_i a_i (s_i R_i - r_i Q_i - z_i G) = infinity
```

Every `a_i` is a fresh nonzero scalar sampled uniformly by rejection sampling
from the verifier's `getrandom` output, after the complete input records are
fixed. Checking point encodings, scalar ranges and `x(R) mod n = r` is mandatory.
The group has prime order; fixing every other coefficient leaves at most one
choice for a coefficient on a nonzero residual that makes the sum vanish.
Consequently the algebraic false-accept bound for a fixed invalid batch is at
most `1/(n-1)`, assuming independent uniform coefficients and correct arithmetic.
This is not a claim of 256-bit system security or a proof of the C implementation.

Equal or attacker-predictable weights are unsafe. The harness contains two
deliberately invalid signatures whose residuals cancel under equal weights.
Fresh randomized weights reject that pair in the tests. Failed batches fall
back to ordinary verification of every record; incorrect advice must not make
a valid signature invalid. Missing advice would use the ordinary path in a node.

## Baseline and candidate

The [C harness](code/ecdsa_advice.c) is compiled against the read-only source
vendored by the repository's locked `secp256k1-sys 0.10.1`. Both baseline and
candidates use that exact field, scalar and group implementation. The batch
candidate calls its private `ecmult_multi_var` implementation with 16 MiB of
scratch space. The deterministic candidate mirrors the ordinary verifier's
Jacobian x comparison, including the rare `x = r+n` case.

All timed verification paths parse the same 33-byte public keys and compact
64-byte signatures and normalize high S before mathematical verification,
matching the node's mathematical convention. DER parsing, encoding rules,
Script flags, hashing transaction data and transaction lookup are outside every
timed path. The node's lax-DER parser and historical rules are not replaced.

The baseline is the local pinned libsecp verifier, not Core/Knots end-to-end.
The historical 92 microsecond number is not used as this run's denominator.
This experiment tests an arithmetic hypothesis; it does not rank node products.

The runner records source, runner, vendor and binary hashes, compiler flags,
Cargo checksum and base Git revision. It compiles the optimized harness with
`-O3`, and a separate checked build with `-DVERIFY`, AddressSanitizer and
UndefinedBehaviorSanitizer. No Cargo dependency, registry source, production
verifier, workspace lint, or unsafe-Rust policy is changed. These private C APIs
are experimental and are not a supported integration interface.

## Workload and method

- Intel Core i3-N305, eight available CPUs; one benchmark thread, about 30 GiB
  host RAM. Linux and compiler details are in the result manifest. The desktop
  is shared, frequency and load are uncontrolled, and no core is isolated.
- 16,384 distinct deterministic synthetic key/message pairs. The SHA256-based
  generator and deterministic signing routine are pinned by source hashes;
  data are generated locally, contain no wallet material, and are reproducible.
- Batches of 8, 32, 128, 512, 2,048 and 8,192; three repetitions per configuration.
  Every timed valid record must be accepted. Results are consumed and asserted.
- Generation, advice production and correctness checks happen before the timed
  verification rounds. They are separate measured work, not free preprocessing.
- Each round starts with ordinary verification. Batch-size order and the order
  of advice formats alternate between rounds. Batch inversion runs before the
  advice formats at each size. This is not a fully randomized run schedule.
- Report process CPU time and elapsed time separately. The tables give medians
  and full min/max ranges across three samples, not confidence intervals. No
  outliers are removed. Working data are in memory; this is not a cold-disk test.
- A hostile-helper workload negates one otherwise valid nonce point per batch
  of up to 8,192. It still passes curve/x checks, forces the expensive batch
  equation to fail, and charges the complete ordinary fallback.
- Scratch capacity is bounded at 16 MiB; arrays are bounded at 8,192 signatures,
  and corpus storage is 162 bytes per signature. Whole-process peak RSS, energy,
  disk I/O, actual helper transfer and mainnet signature counts are unmeasured.

## Correctness evidence

The checked build and optimized benchmark both assert:

- Agreement with ordinary verification on valid inputs and high-S normalization.
- A constructed valid `x(R) = r+n` case, rather than hoping random samples hit it.
- Rejection/fallback for altered digests, substituted keys, zero/out-of-range
  scalars, malformed keys, illegal hint headers, incorrect parity/carry, and
  invalid full-y encodings.
- Correct individual result masks after bad-advice fallback; all the same masks
  also match the deterministic batch-inversion path.
- A valid signature with a plausible but incorrect on-curve nonce hint remains
  valid through fallback.
- The equal-weight cancellation attack succeeds against the deliberately unsafe
  control and fails in eight randomized checks per advice format.
- Corruption at several positions in a 128-record batch, exercising the larger
  multi-scalar multiplication path as well as small batches.

These tests exercise meaningful failure modes but are not exhaustive tests or
independent cryptographic review. The reference shares arithmetic code with the
candidate. No historical Script/activation differential or UTXO-state comparison
has been performed for this kernel.

LeakSanitizer failed at process exit in the initial checked run because this
managed runner uses ptrace, which LeakSanitizer reports as unsupported. The
subsequent runs disabled leak detection only; ASan, UBSan and libsecp internal
VERIFY assertions remained enabled. Initial compilation failures concerned the
Rust-vendored source's removed stdio include and POSIX clock declarations; the
runner now supplies those explicitly.

## Results

The authoritative run is `measured-v3`, with 16,384 signatures and three samples
per verification configuration. [Raw results and build manifests](results/2026-09-23-ibd-ecdsa-advice.json)
include every sample, the preceding advice-only run, and unsuccessful-attempt
notes. Source and runner hashes were checked against the final measured build.
All 65 timing rows asserted the expected accepted count; checked and optimized
adversarial tests passed.

**Median process CPU microseconds per signature:**

| Batch size | Individual checks, batch inverse | Advice: 1 byte | Advice: 33 bytes |
| ---: | ---: | ---: | ---: |
| 8 | 126.53 | 123.73 | 106.34 |
| 32 | 125.10 | 114.56 | 99.75 |
| 128 | 123.98 | 100.43 | 85.85 |
| 512 | 124.35 | 84.30 | 66.70 |
| 2,048 | 125.40 | 74.76 | 59.36 |
| 8,192 | 127.43 | 70.06 | 56.11 |

The matched ordinary baseline is **127.56 CPU microseconds/signature**.
At batch size 8,192, advice gives **1.82x** or **2.27x** CPU throughput,
respectively: **45.1%** or **56.0%** less recipient CPU per signature. The
deterministic candidate saves only **0.1–2.8%** across the tested sizes, with
overlapping ranges and an uncontrolled shared host. That is not evidence of a
material deterministic breakthrough. Small advice batches also give much less
benefit; at size 8, the one-byte format saves only about 3% CPU.

**Selected distributions, microseconds per signature, median [min, max]:**

| Work | Process CPU | Elapsed wall time |
| --- | ---: | ---: |
| Ordinary individual verification | 127.56 [127.20, 129.61] | 140.60 [133.97, 153.16] |
| Batch inverse, size 128 | 123.98 [122.25, 126.29] | 152.42 [124.50, 155.30] |
| One-byte advice, size 8,192 | 70.06 [69.85, 70.20] | 87.59 [70.75, 94.30] |
| 33-byte advice, size 8,192 | 56.11 [55.04, 57.08] | 66.03 [58.12, 95.00] |
| Bad one-byte advice plus full fallback | 201.22 [200.99, 206.67] | 268.11 [237.56, 463.36] |
| Bad 33-byte advice plus full fallback | 183.60 [183.40, 184.06] | 199.63 [197.84, 326.64] |

Wall-time medians imply 1.61x and 2.13x at size 8,192, but the ranges make CPU
time the more useful measurement here. Several smaller configurations regress
in elapsed time under contention. All of them remain in the raw artifact; no
wall-time improvement is claimed for those cases. CPU time also remains
sensitive to clock frequency and contention, so neither number is a hardware
constant.

One plausible incorrect hint per batch adds **57.7% CPU** for the one-byte
format or **43.9%** for the 33-byte format after fallback, compared with ordinary
verification. All underlying signatures in that workload are valid, and all
remain accepted. This explicitly exposes a hostile-helper regression.

Synthetic corpus generation cost **127.42 CPU microseconds/record**, separately.
Producing advice from the public signature/key/digest cost **130.60 CPU
microseconds/signature** (**2.140 CPU seconds / 2.345 wall seconds** for 16,384),
measured once. Creating advice locally and then running the fastest batch path
therefore costs about **186.70 CPU microseconds/signature**, versus 127.56 for
ordinary checks. The recipient gain needs producer reuse or amortization.

The earlier advice-only `measured-v2` run measured 121.17 CPU microseconds for
ordinary verification versus 66.88/52.18 for the two advice formats at size
8,192: 1.81x/2.32x. Its separate source hash and full rows are retained as
preliminary evidence, not mixed into the final run's statistics. The final
source adds the deterministic candidate and hostile-helper cost measurement.

Decision: **continue investigation of nonce-point advice; retain deterministic
batch inversion as a marginal candidate, not a claimed major gain.** No
production integration or full-IBD capability is adopted by this experiment.

## Costs and limits of the advice architecture

Advice production repeats the ordinary curve multiplication and recovers an
affine point. A lone node that first produces its own hints solely for batching
pays that cost plus batch verification and loses. Sharing already produced
advice among many independent verifiers can amortize the producer work; capturing
it during an existing verification could reduce duplication, but that fused
producer has not been implemented or measured here.

For the user's illustrative one billion ECDSA checks, the measured formats add
1 GB or 33 GB of raw advice, before framing and association metadata. Packing
two bits per signature would reduce `hint1` to 250 MB; packing is not implemented.
These are arithmetic projections, not measurements of the chain's signature
count or an implemented network protocol. A large hint format can lose on a
slow connection even when it wins CPU time. Hints reveal only public information,
but fetching them still needs an explicit network privacy policy.

Bad helpers cost extra CPU before fallback. A real client needs bounded batches,
advice-size limits, a policy to stop using repeatedly bad advice, and an ordinary
verification path when helpers are absent. A fallback to individual checks
handles a failed batch; it does not turn successful probabilistic batch
acceptance into a deterministic check. The prototype aborts on resource/RNG
failure; production would need to fail closed or use ordinary verification.

## Interpretation and reuse

The result supports challenging an implementation floor with a different
computation and input representation. It does not support calling full IBD
solved, promising a tenfold node speedup, or skipping historical validation.
The node would still derive state from the original history and verify its
rules locally. Advice supplies algebraic data, not a trusted validation verdict.

The smallest reusable result is the isolated native benchmark and its failure
tests. Before integration, the next experiment must feed an actual historical
signature-check trace through these kernels, including uncompressed/hybrid keys,
lax DER, high S, real repeated-key distributions, and genuinely false checks.
Valid scripts may contain false `CHECKSIG` results; `CHECKMULTISIG` can try the
wrong key before the right one. Blindly assuming every attempted check must
succeed changes Script semantics. Batching needs a reviewed execution strategy,
ordinary fallback/re-execution and differential comparison of full outcomes.

Only after that should a node prototype measure original-block replay, all
historical checks, matching UTXO state, helper construction and delivery, absent
or hostile helpers, reorg behavior, queue memory, and time to **fully verified**
state. Network/UTXO bottlenecks may absorb much of the signature-kernel gain.

Independent avenues remain open: SIMD implementations of independent checks on
unchanged block inputs, repeated-key aggregation where measured key reuse helps,
and locally checked prevout-location hints or sequential joins to reduce random
UTXO reads. These were not implemented in this experiment. None justifies a
claimed speedup before a matched measurement.

Reproduce from the repository root, with the locked dependency already cached
and a Linux C compiler available (Python 3.11+):

```sh
python3 tools/ecdsa_advice_bench.py \
  --output target/ecdsa-advice/new-run --count 16384 --repetitions 3
```

The output directory must not already exist. The runner reads vendor source
without changing it, writes binaries/logs/manifests under the selected directory,
runs checked adversarial tests first, then records every benchmark sample.

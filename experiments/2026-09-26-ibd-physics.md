# IBD physics — how fast can full validation actually go?

**Date:** 2026-09-26 · **Status:** research/hypothesis — analysis only,
no measurements claimed. Every number below is an estimate derived
from known instruction/data costs; each maps to a queued experiment
(LOG #41–#47) that must produce the real figure before any claim lands.

Roadmap: W2/W3 (validation speed, verified synchronization hints).
Scorecard: P1 (initial validation).

## The question

What is the physical floor for **full validation** of the ~768 GB
mainnet corpus (~950k blocks, ~1.3–1.5B signature attempts,
~170–190M surviving UTXOs) — every consensus check executed locally,
assumevalid=0 semantics — and which terms are algorithm-bound vs
architecture-bound?

## Decomposition: the predicate splits into order-free parts

Full validation is a predicate over a closed corpus. The key
observation: **the corpus is closed under its own data dependencies.**
Everything a check needs is inside the block stream itself.

| Plane | Checks | Needs | Ordering |
|---|---|---|---|
| Serial spine | header chain, PoW, difficulty, MTP | headers (~76 MB) | **ordered — the only truly serial part** |
| Hash plane | txid/wtxid merkle roots, witness commitments, sighash hashing | all bytes | order-free per block |
| Sig plane | every CHECKSIG/CHECKMULTISIG attempt: sighash + curve verify | tx bytes + prevout (scriptPubKey, amount) — **both in corpus** | fully order-free |
| Interpreter | non-sig stack ops, CLTV/CSV | corpus + header heights | order-free per tx |
| State plane | prevout existence, unspentness, no double-spend, coinbase maturity | see below | **the reformulation** |

The conventional implementation runs V_state as a sequential
point-mutation loop (connect block → mutate UTXO set → repeat ×950k).
That ordering is a choice, not a law. Restated as a set problem:

- `S_created` = all outpoints ever created (~1.5B records)
- `S_spent` = all outpoints ever spent (~1.3B records)
- Validity: `S_spent ⊆ S_created` (existence), each spent outpoint
  appears **at most once** in the spend multiset (no double-spend),
  and per record `spend_height > create_height (+100 if coinbase)`
  — all checkable from corpus metadata (heights ride along).
- Output: `S_created \ S_spent` = the UTXO set, materialized **once**.

That is one anti-join over ~2.7B records — a batch analytics query,
not a transaction loop. IBD's actual shape is map-reduce:
*map* per-block (decode+hash+scripts, order-free), *reduce* the coin
multiset. The connect-per-block model is the architectural sin.

## Per-plane floors (2026 hardware, all parallelizable unless noted)

### Acquisition — the real floor for most users

Full validation requires receiving every byte once. Floor = fastest
available channel, and the source need not be trusted (everything is
verified locally):

| Channel | Time for 768 GB |
|---|---|
| 100 Mbps WAN | ~17 h |
| 300 Mbps | ~5.7 h |
| 1 Gbps | ~1.7 h |
| 2.5 Gbps | ~41 min |
| 10 Gbps LAN | ~10 min |
| NVMe Gen4 read | ~2 min |

Corpus re-encoding can shave ~20–30%: outpoint→positional encoding
(36B→~5–7B ≈ −40 GB), DER→compact sigs (−10 GB), script-template
tags (−30 GB), pubkey dictionary (−10 GB), compact amounts (−5 GB),
zstd residual. Ceiling is set by the chain's ~200–250 GB of
irreducible cryptographic entropy (sigs, keys, outpoint refs, hashes).

### Read — every committed byte must be hashed once

Sequential stream, single pass: NVMe ~2 min, SATA ~25 min, HDD ~1.5–2 h,
DRAM ~15 s. **Fuse it**: decompress→hash→parse→dispatch so each byte
is touched once (~15 s of DRAM traffic if perfectly fused; current
architectures re-touch each byte ~5–15×).

### Hash plane — ~2.5–3.5 TB total SHA256 input

(txid/wtxid merkle ~1.5 TB + legacy quadratic sighash ~0.4–0.7 TB +
BIP143/341 linear hashing)

- SHA-NI single-buffer: ~1.6 GB/s/core → ~30 min naive
- Multiway SIMD (independent leaf/interior hashes): ~8–12 GB/s/core
  (Core's 4/8-way SHA256D64 shape) → **~1 min on 8 cores**
- GPU (SHA256d is literally mining): ~50–100 GB/s → **~30–60 s**

### Sig plane — the dominant term, and its true limits

One ECDSA verify ≈ 160–180k cycles (~45–50 µs tuned scalar; our
measured 127 µs reflects the i3-N305's weak cores):

- `u1·G + u2·Q` via GLV endomorphism + Shamir interleaving:
  ~128 point-dbls + ~64–96 point-adds, ~12–16 field-mults each
- field mult ≈ 35–50 cycles (4×4 limb mulx/adcx + pseudo-Mersenne p)
- two field inversions per sig (s⁻¹, affine Z⁻¹) — **both batchable**

Headroom that exists, ranked:

1. **Batch inversion across the corpus** (Montgomery trick): N
   inversions → 1 + 3N mults. Saves ~10–15%/sig. Free, deterministic.
2. **SIMD-across-signatures**: ECDSA verify is *branch-free* — N sigs
   in SIMD lanes run identical instruction streams. AVX-512+IFMA
   (`vpmadd52`, 5×52-bit limbs, 8 lanes) → ~6–8× per core. On Zen4/5
   or IceLake+: ~1.5B sigs → **~20–30 min on an 8-core desktop**.
   Nobody ships this for Bitcoin validation. Workspace `unsafe` ban
   routes it through the existing subprocess-worker pattern.
3. **GPU crypto plane**: published ~4M ECDSA verifies/s on a midrange
   card (discount to ~1–2M). ~1.5B sigs → **~6–15 min**. Same
   subprocess shape. SHA plane rides it for free. Unshipped anywhere.
4. **Nonce-point advice + batched MSM** (our measured work):
   converts each verify into scalar terms of one aggregate equation —
   zero inversions, and GPUs excel at Pippenger. ~2–3× on top of the
   hardware path. Requires a hint source (producer cost ~+16% on a
   validating node — peers amortize it).
5. **Schnorr batching** (~25–30% of modern sigs): BIP340 batch is
   native ~2×; upstream secp module ~20–50%, still pre-merge.
6. **Trusted-cluster sharding**: ranges split across the operator's
   own machines — linear. Nobody ships it; nothing requires a node
   be one machine.

**Hard bound (honest):** verifying N independent ECDSA sigs is Ω(N)
group operations in the generic-group model — there is no sublinear
algorithm. Aggregated/advised forms only shrink the constant
(~2–4×). The order-of-magnitude levers are hardware parallelism and
not-doing-it (assumevalid). Any claimed path to sub-minute sig
verification of history that isn't ZK is numerology — flag it.

### State plane — one anti-join

Partition `S_created`/`S_spent` by outpoint-prefix into RAM-sized
buckets; per bucket, probe+emit survivors. Total traffic ~120–150 GB
of *sequential* I/O → ~2–4 min NVMe, ~35–50 min HDD, ~seconds if
RAM-resident. Versus the current random-access B-tree loop on an 8 GB
laptop — the regime that produces multi-day syncs.

SwiftSync aggregate variant (machinery shipped): 32 B running
aggregate + survivor hints → materialize only the ~180M survivors
(~8 GB written once), aggregate equality absorbs both existence and
double-spend. Ordering-sensitive rules (BIP30 window ≤227931,
coinbase maturity) reduce to per-record height predicates — parallel.

### Serial spine — the genuinely sequential floor

Header chain + difficulty + MTP ≈ seconds. Everything else is a
per-record predicate evaluated in parallel. **Sequential remainder:
<1% of runtime.**

## The wall-clock model

`wall ≈ max(acquire, read, sig-plane, state-plane) + spine` —
all planes overlap under one fused pass.

| Hardware | Binding term | Full-validation floor |
|---|---|---|
| Desktop + GPU + local corpus | sigs ~6–15 min | **~10–20 min** |
| Desktop 8c AVX-512/IFMA, corpus local | sigs ~20–30 min | **~25–45 min** |
| Laptop 4–6c AVX2, NVMe, corpus local | sigs ~1.5–2.5 h | **~1.5–3 h** |
| Any machine, WAN-only fresh | link rate | **= acquisition** — validation hides entirely underneath once compute < link time (holds ≥~300 Mbps for tuned hw) |
| Any machine + HDD | disk ~2 h read+write | ~2 h unless pruned stream avoids the store |

"Validation at line rate" is the engineering target: keep the pipe
full and IBD wall-clock becomes `corpus_size / link`.

## The absolute floors — where no more room exists

1. **Bytes-once**: every committed byte must be read (merkle
   commitments cover all of it). Only escapes: receive less (the
   ~25% re-encoding ceiling) or not receive it at all (assumeutxo /
   utreexo / ZK — a different trust posture, honestly labeled).
2. **Ω(N) group ops**: the sig plane's lower bound. Escapes:
   hardware parallelism (real), algebraic aggregation (constant
   factor only), proofs (immature), assumevalid (deployed standard).
3. **The anti-join**: ~2.7B records must be accounted. Floor is one
   sequential pass — already nearly free vs the rest.

Below ~10 min on commodity hardware there is no honest path for full
validation today. ZK chain proofs (sublinear verification) are the
only asymptotic escape — proof *production* costs more than replay
at current proving speeds; a watch item, not a plan.

## What nobody has shipped (the novel surface)

1. Single-pass fused pipeline — each byte touched exactly once.
2. UTXO set as one anti-join instead of ~3B point mutations.
3. IFMA lane-parallel sig verification (~6–8×/core).
4. GPU crypto-plane subprocess worker (~60–100× on the dominant term).
5. Canonical corpus encoding + trust-free any-source fetch.
6. Trusted-cluster sharded IBD.
7. Composition of already-built pieces into a proof-carrying
   corpus stream (swiftsync hints + ECDSA advice + utreexo proofs) —
   every Avila node that syncs becomes an acceleration source.

## Kill conditions / first measurements

- Corpus-parallel replay (LOG #41): prevouts resolved from the block
  store, sig-throughput scaling vs workers on the signet fixture.
  Kills the whole architecture claim if scaling is sub-linear.
- Anti-join materialization (#42): external partition+probe vs the
  incremental path on 22.4M-create signet window. Kill if sequential
  I/O doesn't beat random by ≥5×.
- IFMA kernel spike (#43): measure vs `ecdsa_advice` harness baseline
  on the same sig corpus. Kill <3×/core.
- GPU worker spike (#44): smallest verify-only kernel against CPU
  pool, bit-exact on the adversarial sig set. Kill <10× total
  throughput, or any differential on edge cases without fallback.
- Corpus encoding measure (#45): real bytes saved on the signet
  fixture, not estimates. Kill <15%.
- WAN reality (#46): fetch-rate ceiling from N real mainnet peers —
  establishes how much of the model is actually reachable over P2P.

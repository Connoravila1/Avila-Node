# Crypto Deep-Drill Ledger — complete measured record for handoff

Date: 2026-09-28 (continuation of 09-26/09-27 crypto plane work)
Scope: everything measured in the low-level ECDSA/field-arithmetic
investigation, what each artifact is worth, what died and why, and the
ranked list of unexplored directions.

## Objective reminder

First launch → full Bitcoin validation within one hour on an i3-N305
(8 Gracemont E-cores, ~3.4GHz, AVX2+FMA, no AVX-512/IFMA/AMX, 32-EU UHD
iGPU, SHA-NI present). Every signature equation must be locally verified.
No assume-anything. Experimental opt-in mode is acceptable if it
recomputes everything.

## THE MECHANISM (the deepest finding)

**Carry-flag consumption is a shared serial resource on Gracemont.**

- Every `adc`/`adcx`/`adox` — from any lane or independent stream —
  funnels through one flag-tracking structure. ~35 flag-hops per
  5×52 field mul ≈ ~40ns regardless of interleaving.
- Confirmed three ways: serial `fe_mul` ≈ 42.6ns; 4 independent chains
  ≈ 39.0ns (flat); hand-asm adcx/adox mul at parity (Gracemont couples
  ADX flags — Intel SDM §4.1.8.8 — so the "two independent carry
  chains" trick doesn't exist here).
- This single mechanism explains why every prior optimization attempt
  (merged-4, fused-dbl, ADX asm) converged to ~1.0×.
- **Caveat (new)**: mulx+__int128 accumulation interleaved-4 showed
  ~1.15× not flat — the flag resource is a strong but not absolute
  serializer; or __int128 codegen avoids some flag reads.

**Flag-free datapath works.** Emmart–Zheng–Weems construction
(ARITH'18): 52-bit limbs fit the 53-bit double mantissa; `fma_rz(a,b,
2^104)` lands the product's hi bits directly in a fixed binade so the
bit pattern *is* the integer (bias-extract via vpaddq/vpsrlq/vpand —
zero flags). Requires MXCSR round-to-zero bracketing (~few cyc per
kernel, AVX512 embedded-RZ absent here).

## VERIFIED ARTIFACTS (differential-tested vs libsecp)

| Kernel | Correctness | Cost | Notes |
|---|---|---|---|
| `fe_mul4_ezw` (5×52, 4 SIMD lanes) | 200K cases | ~95-113ns/group serial, flat-L | products+resolve 60ns, tail ~53ns |
| `fe_sqr4_ezw` | 100K cases | ~64ns/group | off-diag doubled accumulation |
| `gej4_double` fused-4 dbl | 2000 random cases, all lanes/coords | ~687ns/dbl4 (~172ns/dbl-equiv) | after dead-iteration cut |
| `gej4_add_ge4` | built, harness in progress | fused 7dbl+1add cadence 5879ns/8step/4lanes | **1.71× composite** vs scalar |
| helpers fe4_add/neg/mul_int/half | all emit <2^52 normalized | trivial int-lane | required for binade constraint |

Measured composite today: **fused-4 ladder-mix = 1.71×** vs libsecp
scalar (dbl4 serial ~687ns vs scalar ~278-343ns noisy).

## THE BOUNDS (measured or derived)

- **Fused op size vs ROB**: fused-4 mul ≈ ~520 insns ≈ ~900+ uops
  (ymm ops double-pump to 2 uops on Gracemont). > 256-entry ROB →
  dependency-distance flat at L=1..32 (~95ns always). Two fused ops
  can never coexist in the window → op-list/stream interleave **dead
  at this granularity**. Prior "~7-9ns/mul throughput" was a
  hoisted-input artifact — real throughput ≈ latency ≈ ~95ns.
- **Port analysis (analytic, perf locked paranoid=4)**: op mix
  ~109 FP + ~168 vec-int + ~119 moves + ~100 spill refs → port floor
  ~40ns vs measured ~95ns → latency/spill-bound, ~2× headroom real.
- **Batch-ECDSA is information-bound, not structure-bound**: SP
  (summation-polynomial, Karati-Das ACNS'14) derivation collapses to
  lifting r_i → point = ~1.5 mod-p sqrts/sig ≈ ~28% of verify cost —
  eats the MSM saving → ~1.2× standalone. The paper's ~2×@t≤9 needs
  exponential symbolic elimination (consensus-risk, days of work).
  **SP-batch ≡ advice-batch**: the existential lift IS what advice
  supplies free. The signature format lacks ~2 bits/sig (which of
  {r, r+n}×±y) — not derivable cheaply. This is the first-principles
  reason all batch paths converge on external data.
- **Schnorr batch**: clean (R in sig, canonical parity) but Schnorr ≈
  ~8% of sig mass at block ~956k census → ~1-2% end-to-end.
- **R-advice batch**: measured 1.82-2.27× kernel-side, ~17-23% CPU
  end-to-end in the 8-worker pipeline (MSM+association+memory ate
  the microbench win). Requires external advice — producing own
  advice ≈ verify cost (loses). Advice ~1GB total for full chain
  (1-byte hints), ~33GB for 33-byte y-form.
- **Node already runs 8-way parallel script verification** — per-core
  kernel gains stack multiplicatively.
- **SHA-NI already active** — sha2 0.11 runtime-dispatches
  `shani_cpuid`. No free hash-plane win from ISA alone.
- **iGPU killed on arithmetic**: 32 EUs ≈ ~256 int32 lanes ≈ ~2-3
  cores' worth of this workload → ~5% of total. Driver/correctness
  risk not worth it.

## PROBED-BUT-THIN (premise partially holds, unbuilt)

- **Carry-save (CSA/Wallace-tree) scalar mul**: flag-free redundant
  (sum,carry) accumulation via pure-logic carries `(a&b)|(c&(a^b))`.
  Premise real: interleaved flag-free chains overlap ~1.15× vs flat
  flag chains — but microbench margin ~15% and the array-based
  version measures 2× *slower* (needs fully unrolled register-resident
  tree, ~150 lines of index bookkeeping). EV: maybe 1.5-2× on the
  scalar mul primitive if the tree schedule lands — uncertain.
- **Interleaved SHA-NI sighash**: hash plane ~25-30% of wall; per-input
  sighash is serial but independent hashes interleave — SHA-NI has
  per-instruction latency that ILP can fill. Unmeasured, plausible
  ~1.5-2× on hash mass ≈ +15-20% end-to-end.
- **Shared-inversion affine adds** (Astra avenue): 8M+3S → 5M+S+I/B;
  with FMA muls cheap, amortized inversion becomes dominant term —
  ~1.3-1.5× on add mass. Untested.
- **Lazy/redundant limbs**: normalize less often (~15-20% of each
  fused op is normalization). Untested.
- **j=0 specialized formulas** (secp256k1 j-invariant is 0; EFD has
  tripling-oriented variants): ~5-10%. Untested.
- **Repeat-key point-tower cache**: `2^i·Q` towers per pubkey; ~30% of
  sigs repeat keys → tower lookup ~40 table-adds as a ~6-depth tree ≈
  ~5× on repeat-key verifies. Cache keyed by pubkey hash. Untested at
  scale (real key-reuse rate needs a census query — the 30% is
  anecdotal).

## THE HONEST CEILING (standalone, this chip)

| Layer | Number |
|---|---|
| Fused-4 today | 1.71× (measured composite) |
| + kernel scheduling to port floor | ~2.3-2.5× |
| + affine + lazy + cache multipliers | ~2.5-3× on sig mass |
| + hash-plane interleave | ~+15-20% |
| **End-to-end (crypto ~60% + hash ~30% of wall)** | **~2-2.5×** |

IBD ~8-10h → ~4-5h. Sub-hour (~8-10×) standalone is almost certainly
not in the physics — the algebra is information-bounded and the
hardware budget is 8 E-cores.

## THE ONE PATH PAST IT

**R-advice data plane** (peer-served or sidecar hints, locally bound +
randomized batch + individual fallback): the only mechanism that
removes the missing-information cost while keeping every check local.
Measured pieces exist (`ecdsa_advice.c` 1.8-2.3×). The value appears
only when advice comes from a peer that already verified — a
network-good, not a standalone speedup. Fits the experimental-mode
plan; requires a protocol extension to actually pay off.

## RECOMMENDED NEXT INVESTIGATIONS (ranked by EV × cheapness)

1. **Interleaved SHA-NI sighash batching** — cheapest real unexplored
   win; hash plane is ~30% of wall and nobody's measured whether
   multi-stream SHA-NI overlaps on Gracemont.
2. **Fused-4 kernel scheduling pass** — port floor ~40ns vs ~95ns
   measured; unrolled spill-free schedule (probably asm) is the
   biggest verified-available multiplier; ~1.5-2× on every fused op.
3. **Repeat-key census then tower-cache** — measure actual pubkey
   reuse across history first (cheap query), then decide if the
   ~5×-on-repeats is worth the cache machinery.
4. **Shared-inversion affine adds** — real algebra, bounded ~1.3×,
   days of work.
5. **CSA Wallace mul** — only if (2) lands and appetite remains;
   premise real, payoff uncertain.
6. **verify4 composite build** — the honest end-to-end number for the
   fused stack; everything else is extrapolation until this exists.

## Artifact index

- `experiments/code/` — all kernels and probes (46 files). Key ones:
  `fe_mul4_ezw.c`, `ezw_body_v2.c` (working fused-4 mul/sqr/dbl/add
  bodies), `dbl4_ezw.c`, `v4.inc`/`mul4_v4.c` (lag-1 column variant,
  ~parity), `depprobe*.c` (flat-L), `lat_probe.c` (latency split),
  `csa_mul.c`/`fp2.c`/`flagprobe.c` (CSA premise probes),
  `ecdsa_advice*.c` (advice path), `fe_mul_4x64_*` (ADX asm parity).
- Prior docs: `2026-09-23-ecdsa-batch-feasibility.md`,
  `2026-09-23-ibd-ecdsa-advice.md`, `2026-09-24-ecdsa-advice-economics.md`,
  `2026-09-24-ecdsa-parallel-replay.md`, `2026-09-26-ibd-workload-census.md`,
  `2026-09-27-crypto-ledger-review.md` (independent audit).
- `experiments/LOG.md` — dated entries 09-27f/g/h, 09-28/a/b/c/d/e.

## Known-invalidated numbers (do not reuse)

- "merged-4 1.19×" — compared unequal work (scalar included table prep).
- "independent-chain ILP 3.57×" — one-chain compiler artifact.
- "fe_mul4 7.1ns/mul independent" — hoisted-invariant artifact; real
  throughput ≈ latency ≈ ~95ns.
- Early "~8% Schnorr" is correct; earlier coarse hash-plane estimates
  were corrected by the census (legacy sighash amplification ~3.75×).
- ADX dual-carry-chain trick — doesn't exist on Gracemont (§4.1.8.8).

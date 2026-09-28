# Crypto Bottleneck Ledger — measured, not argued

Scope: script-stage ECDSA verify dominates IBD wall (~50% this window,
~75% full-IBD). This doc records every lever drilled at the verify layer
— probe file, numbers, disposition — so future work (human or agent)
starts from the measured map, not zero. Rule: nothing here is "probably
dead" — each entry has a probe or a proof. Bench harnesses live in
experiments/code/ and build against the vendored secp256k1-sys sources
with the same flags as build.rs (-O3 -mbmi2, ECMULT_WINDOW_SIZE=15,
ECMULT_GEN_PREC_BITS=4).


## CORRECTION — 2026-09-28 matched re-measurement

The headline numbers below ("2.04× locals unlock", "1.19× merged-4") were
**measurement artifacts** — see experiments/2026-09-27-crypto-ledger-review.md
(audit) and experiments/code/ecmult4_matched_bench.c (corrected harness):

- dbl fused-4 vs seq-4, MATCHED: **0.99×** — "2.04×" was the inf=1
  early-return artifact (dbl returned immediately = empty loop).
- merged-4 ecmult, MATCHED (both sides pay prep+tables+globalz+beta+ladder):
  **1.01×** — "1.19×" was the setup-exclusion artifact.
- asm 4x64 fe_mul (correct, 10K cases): **~parity-to-worse** vs libsecp
  5x52 — Gracemont couples adcx/adox flags (Intel opt manual §4.1.8.8).
- AVX2 field-mul rejection is INVALID — probe had 15K/16K mismatches
  (missing fold of bits 256-259). AVX2 is NOT ruled out.
- FMA throughput bench invalid — GCC collapsed the chains.

Revised live stack is in the review doc + LOG entry 2026-09-28: exact
wide-limb FMA (5x52 SIMD), tiled ready-op scheduling, affine+inversion
amortization, repeat-key combs. The sections below retain the invalidated
numbers for provenance — trust the corrected table.

---

## The cost model (measured)

- secp256k1_ecdsa_verify ≈ 86µs standalone / ~105µs in-harness w/ bench
  overhead: ~11µs pubkey parse (X-decompress+sqrt — partially cached,
  30.6% hit rate), ~3.5µs scalar_inverse_var (127-iter binary GCD),
  ~72µs ecmult_strauss_wnaf = ~129 serial gej_double (~340ns) + ~58
  conditional adds (~600ns) + ~8µs per-verify pre_a table+globalz.
- field mul serial chain: 43.5ns; independent back-to-back: 12.2ns —
  3.57× ILP exists in artificial chains.
- Gracemont (i3-N305) rename window ≈ ~250µops; one fe_mul ≈ ~60µops
  → at most ~4-5 independent mul chains in flight. This is the hard cap
  that binds every interleave scheme.

## DEAD — proven or measured

| Lever | Result | Why dead |
|---|---|---|
| Batch ECDSA across sigs | — | needs recovery ID R; computing R = the verify itself. Math, not impl. |
| Schnorr batch | n/a | real but only exists post-709632; not this era |
| GLV-4 scalar split | — | secp256k1 endo ring is degree-2 (λ only); no 4-fold split exists |
| AVX2 4-lane field mul (10x26 lanes) | **1.13–1.22×** measured (femul4_avx2_bench.c) | vpmuludq is 32×32→64; wrong shape. Needs AVX-512-IFMA — absent on N305 |
| FP/FMA field mul (4-lane doubles) | **0.44×** (fma + femul probes) | 10×26 repr → 4× product count; accumulator serial chains eat the FMA edge |
| Fused gej_double4 via pointer API | **0.98×** (ge_ilp_bench.c) | identical instr stream post-inline; DAG-bound |
| 4× indep gej calls | **~1.0–1.1×** | pointer-API memory traffic serializes; also DAG depth > ROB |
| 4× indep ecdsa_verify | **92.4µs/call** (verify_ilp_bench.c) | wnaf branch dispatch breaks OoO across calls |
| Branchless complete formulas | unbuilt | MORE ops (~15–17 muls vs 12) on an already-full window |
| >4 lanes merged | **~1.0×** (8-lane probe) | ROB cap ~4-5 chains — more lanes can't help |
| Bigger WINDOW_A | ~break-even | table-build cost ≈ adds saved |
| Split-ribbon u1G∥u2Q | ~parity | ecmult_gen's ~64 adds > the ~16 shared adds saved |
| Q-tower cached → Σ adds | dead standalone | tree of ~128 adds but each add is a ~750µop serial DAG → ~58µs ≈ no better than ladder. Only helps AFTER add-rate lifted (asm) |

## LIVE — the remaining stack, ranked  [SUPERSEDED — see correction above]

1. **Register-resident locals (THE unlock)** — gej state in named-local
   fe vars, not through gej* pointer API: gej_double 305.5→149.7ns/op
   (**2.04× measured**, dbl4_locals_bench.c). Pointer-API store→load
   traffic was silently occupying the latency budget.
2. **Merged-4 ecmult (C)** — 4 lanes' locals, fused dbl4, per-lane
   predicated adds, correct globalz/beta ordering: **1.19× measured**
   (ecmult4_merged_bench.c, differential-verified). Capped by add-DAG
   depth (>ROB). Baseline to beat.
3. **Var-time adds** — validation has no secrets; drop Brier–Joye for
   the classic var Jacobian add (8m+3s): 605→448ns/lane interleaved
   (**~1.35×**), AND already cheaper than production add serially.
4. **4×64 limb repr (asm-only)** — 16 mulx vs 25, ~20 carry-steps vs ~30
   per mul. C's __int128 bounds force 5×52; asm is free. UNMEASURED —
   first asm probe.
5. **Lazy inter-op reduction** — resolve carries ~2×/point-op not
   per-field-op: ~10–15% off critical path.
6. **Level-synchronous emission (asm-only)** — emit 4 lanes' DAG levels
   round-robin so every window position holds ≥4 indep mul chains
   THROUGH deep add-DAGs. THE mechanism that could lift the adds from
   ~1× toward the 3.5× mul bound. Not expressible in C.
7. **Batched inversions** — 4 lanes' s⁻¹ + pre_a globalz → 1 inverse +
   muls: ~-8% verify.
8. **Pre_a-table cache on repeat keys** (30.6% repeat): ~-8µs/hit.
   Wider WINDOW_A on cached keys: adds ~43→~25.

## Bound arithmetic (current honest model)

asm composite ≈ field-ops -30% × level-lock ~2.5-3× on the DAG-dense
mass × batched-inv -8% ≈ ecmult ~30-40µs → **verify ~1.8-2.5×** →
window ~1.2-1.4× → end-to-end stacked w/ structural ~1.3 ≈ **~1.7-2.2×
this-window wall**. Anything past ~3× verify needs a mul-count
algorithm change (none exists for fresh-Q ECDSA) or more silicon.

## For the next agent

- The artifact to beat: experiments/code/ecmult4_merged_bench.c (1.19×,
  correct). Build cmd at top of each file.
- Do not retry: batch-ECDSA, AVX2 lanes, FP datapath, >4 lanes,
  pointer-API fusion — all measured.
- The open question that matters: does level-synchronous emission beat
  the whole-formula emission the OoO composes today? Only asm answers.

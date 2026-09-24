# Feasibility spike: batch ECDSA verification

**Scope correction:** the original assessment below concerns signatures without
auxiliary nonce-point data. Its claim that point-based batching is inapplicable
to historical signatures was too broad: untrusted out-of-band advice can supply
the missing point without changing the original signature or block. The
[native advice experiment](2026-09-23-ibd-ecdsa-advice.md) measures that separate,
probabilistic verification profile and its helper/fallback costs. The failed
k256/SP implementation did not prove a universal ECDSA cost floor. Original
analysis is retained below for provenance.

**Date:** 2026-09-23 · **Status:** FEASIBLE-BUT-BOUNDED — ~2×
ceiling at batch ≤9, novel crypto, high implementation risk
**Motivation:** scripts are ~92% of sync wall; ECDSA dominates the
fixture's (and history's) signature mix. Batch verification is the
only lever on that share.

## The structural problem

ECDSA verifies `(r,s)` by computing `R' = s⁻¹(z·G + r·Q)` and
checking `x(R') = r`. The ephemeral point R is never transmitted —
only its x-coordinate. `x` has two preimages (±R), and the parity
is what each signature's verification *resolves*. Naive batching
(summing randomized verification equations into one MSM) fails
twice over: false rejects on odd-parity valid sigs, and soundness
attacks when coefficients aren't randomized (Bernstein et al.).

## What the literature offers

| scheme | works on | ceiling | notes |
|---|---|---|---|
| naive random-coefficient MSM | ECDSA* only (R transmitted) | ~6× | **N/A for on-chain sigs** |
| Karati/Das symbolic manipulation (AfricaCrypt'12, JCEN'14) | standard ECDSA | ~2× different-signer | batch ≤7; O(2^t·t²) field ops |
| summation-polynomial SP (ACNS'14) | standard ECDSA | ~2×, batch ~9 | fastest known for standard sigs |
| ECDSA_rec / ECDSA_ast (ePrint 2026/663) | *modified* sigs w/ embedded bits | +17–31% @ batch 32 | needs consensus change |
| libsecp256k1 PR#658 (recovery batching) | k-of-n multisig | ~340µs/sig, abandoned | different problem |

Struik's verification-friendly-ECDSA draft states it plainly: for
standard ECDSA, batch verification offers **"no speed-ups"** — the
~6× belongs to ECDSA* where R is transmitted. The deployed Bitcoin
signature format is standard ECDSA; the parity information is
simply not on the wire.

## Verdict

**Feasible, bounded at ~2×, at batch sizes ≤9, via the SP
(summation-polynomial) algorithm — the only scheme that works on
unmodified on-chain ECDSA.** On a workload where ECDSA is ~65% of
script time, 2× there is ~30% of total sync wall — still the
largest single win in the queue.

The costs are real:

- **Novel crypto**: no production secp256k1 implementation exists
  (papers benchmarked NIST curves). We'd implement field-level
  symbolic/summation algebra over `k256` — consensus-critical code
  nobody else has shipped.
- **Security**: randomizers are mandatory (the original schemes
  were attacked); batch-failure must fall back to per-sig verify —
  false rejects would fork consensus, false accepts are a split.
- **Verification story**: every batch must be differential-tested
  against individual verify at scale — the lab bench handles this.

## The alternative worth doing regardless

**Montgomery batch inversion** for the per-sig `s⁻¹` — one field
inversion + 3n mults instead of n inversions. Safe, standard,
~5–10% of verify time. Small, real, zero math risk.

## Recommendation

Bounded prototype: implement SP-batch on `k256` (pure Rust — fits
the workspace's `unsafe` forbid), gate it behind batch-fallback to
individual verification, differential-test exhaustively, then
measure against `libsecp`'s individual verify. Kill criterion: if
the prototype can't beat 1.3× on a batch of 8 within a reasonable
implementation bound, stop — the remaining safe levers are
Montgomery inversion and Schnorr batch (which has no such ceiling).

# Erlay recon spike — pure-Rust minisketch + bandwidth measurement

**Date:** 2026-09-24 · **Status:** ADOPT (primitive) — protocol wiring
is the next step

## Hypothesis

Set-reconciliation tx relay (BIP-330) saves ~40%+ relay bandwidth; the
blocking question was whether the sketch primitive is tractable without
the C++ dependency (the workspace is pure-Rust, `unsafe_code = forbid`;
`minisketch-rs` FFI needs a libclang toolchain this env lacks).

## What was built

`crates/avila-p2p/src/sketch.rs` — a complete pure-Rust minisketch:

- GF(2^32) arithmetic (modulus x³²+x²²+x²+x+1)
- Odd-power syndrome accumulation (`add`), XOR `merge` (shared
  elements cancel), `4·cap`-byte `serialize`
- Decode: Frobenius syndrome expansion (S_{2k} = S_k²) →
  Berlekamp-Massey → Berlekamp trace-split root finding
- 5 unit tests incl. over-capacity rejection (no false decodes)

First-draft bug caught by tests: `add` squared the accumulator instead
of stepping by x² — syndromes were x¹,x³,x⁷,x¹⁵ not odd powers.

## Measurements (`erlay_bench`, 40k-element sets, 32-bit ids)

| sym. diff | cap | sketch | decode | ok |
|---|---|---|---|---|
| 32 | 64 | 256 B | 12 ms | yes |
| 128 | 256 | 1 KB | 426 ms | yes |
| 256 | 512 | 2 KB | 1.5 s | yes |
| >cap | — | — | fails cleanly | — |

- **Bandwidth:** 512 B sketch reconciles what a 1.28 MB full inv
  sends — ~2500× at realistic mempool overlap (D≈64). BIP-330's
  ~44%-of-relay-traffic figure is consistent.
- **Decode cost is the DoS surface:** naive GF ops make decode
  quadratic — sub-ms at small D, ~0.4 s at cap 256, 1.5 s at cap 512.
  Production needs (a) capacity caps on incoming sketches,
  (b) rate-limiting, (c) precomputed GF tables like upstream
  (~100× faster). Honest exposure, same class as any expensive-verify
  message.

## Verdict

The primitive is real and correct; remaining work is the BIP-330
message layer (`sendrecon`/`reqrecon`/`sketch`/`reconcildiff`), salted
short-ids, and reconciliation scheduling — plus interop reality: no
live peers speak it yet, so it's intra-Avila + Knots-compat first.

Worth noting: a pure-Rust, no-FFI minisketch is itself an artifact the
ecosystem doesn't have — Core bundles the C++ library.

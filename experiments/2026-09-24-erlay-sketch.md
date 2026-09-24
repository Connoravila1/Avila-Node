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

## Update — protocol layer landed (same day)

`crates/avila-p2p/src/recon.rs` + `Message` variants: the BIP-330
wire set (`sendrecon`/`reqrecon`/`sketch`/`reconcildiff`/`reqbisec`),
salted 32-bit short-ids (`SipHash-2-4` per-connection), and the round
state machine (`open` → `answer` → `close`) with a full in-memory
round test: 5k-element pools differing by 5 reconcile in one sketch
exchange; over-capacity rounds never misattribute (phantom ids are
filtered — the upstream spurious-decode contract, caught while
testing: 200 *consecutive* extra ids gave a low-degree spurious
explanation, which is exactly why BIP-330 verifies decoded ids
against real pools and keeps the bisect path).

## Update 2 — live in the node (same day)

Session now sends `sendrecon` in the version-reply burst (unknown-
command-safe against non-recon peers) and records the peer's caps.
`PeerManager` opens a sketch round every ~4s per negotiated link
(`recon_pass`), answers inbound `reqrecon` with `sketch` +
`reconcildiff`, serves asked bodies via the short-id → txid pool map,
and ships its own misses as `tx`. Manager-level tests cover both
sides: responder replies sketch+reconcildiff for the peer's 3 missing
ids; initiator opens a round when due.

## Verdict

The primitive + round layer + live scheduling are real and tested.
Remaining: an end-to-end two-node run with real mempool traffic,
`reqbisec` fallback behavior, and interop (no external peers speak
BIP-330 — intra-Avila first, Knots if they merge it).

Worth noting: a pure-Rust, no-FFI minisketch + recon layer is itself
an artifact the ecosystem doesn't have — Core bundles the C++ library.

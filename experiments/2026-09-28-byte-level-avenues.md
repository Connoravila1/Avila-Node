# Byte-level avenues the deep-drill ledger did not price

Date: 2026-09-28. Status: review + analysis — no new measurements claimed.
Every load-bearing claim below is labeled derivable-or-unmeasured; the two
candidate experiments at the end exist to convert them into measurements.
Reviews
[the deep-drill ledger](2026-09-28-crypto-deep-drill-ledger.md),
[the census](2026-09-26-ibd-workload-census.md),
[corpus replay](2026-09-26-ibd-corpus-replay.md),
[window join](2026-09-26-ibd-window-join.md),
and the advice chain (09-23/09-24).

## What survives byte-level scrutiny (prior instance was right)

- The Gracemont carry-flag serialization mechanism and the EZW FMA
  datapath escape: triple-confirmed, differential-tested. Keep.
- Ω(N) group-op bound for unmodified ECDSA and the ~2-bit/sign
  information gap: I re-derived the SP/lift algebra — batching really
  does need R's parity, which is only free once someone did the scalar
  mul. "SP-batch ≡ advice-batch" is correct.
- The standalone honest envelope on this laptop stays ~4–6 h
  (fused-4 + advice + hash-plane work against ~1.6–3.5 B attempts at
  ~95–127 µs baseline). Sub-hour standalone remains out.

The rigid part was the framing: sighash, parse, join, and advice
production were each treated as fixed-cost stages, and the ~2 bits were
treated as a protocol problem. At the byte level none of them are fixed.

## 1. Legacy sighash is a splice family, not N independent messages

Current path (`sigchecker.rs:392`): for every input, serialize the whole
tx into a fresh `Vec`, append hashtype, `sha256d`. Allocation + a full
O(txsize) copy + a full O(txsize) hash — per input.

Byte-level fact: for one hashtype class, preimage_i =
`BLANKED[0..off_i] ‖ scriptCode_i ‖ BLANKED[off_i+1..end] ‖ tail`,
where `BLANKED` is the tx serialization with every scriptSig emptied
(and for SINGLE/NONE every other sequence zeroed). The prefix is a
single growing prefix shared by all inputs; the scriptCode slot is the
only per-input splice; the tail is a nested shared suffix.

- **Prefix midstates are free.** One streaming SHA-256 pass over
  `BLANKED`, snapshotting (state, partial-block) at each input boundary,
  yields every input's prefix state at O(txsize) total — not O(n·txsize).
- **The suffix cannot be shared backward** (Merkle–Damgård is
  forward-only) — but the n remaining per-input continuations are *n
  independent hash chains*: exactly the shape multiway SHA-256
  (SHA256D64-style 4–8 lane) exists for.
- **The preimage never needs to exist as bytes.** Feed the hash state
  directly while walking tx fields; kill both the per-input `Vec` and
  the copy.

Effect: ~½ the compression count on the SIGHASH_ALL family before any
parallelism, then 4–8× lane parallelism on the remainder. ANYONECANPAY
preimages are single-input already; SINGLE changes the tail per input
(same prefix-sharing applies; suffix stays per-input, smaller constant).

Sizing honestly: corpus-replay instrumented sighash at ~1.4% of
check-stage time on the ~341k window — the quadratic tail concentrates
in mega-input consolidation txs, so expect ~1.5–4% of script wall today,
rising to the binding term exactly when the sig plane accelerates
(advice path or otherwise). Cheap, principled, and the only piece of the
hash plane that is structurally quadratic. Same fused-midstate idea
covers txid/wtxid/merkle in one pass over each tx's bytes.

## 2. Advice production is ~free, not +16%

`produce_hint` (experiments/code/ecdsa_advice.c:184) costs a full ecmult
+ one Jacobian→affine extraction per signature, and the fused producer
paid +16% (29.13 s vs 25.18 s) mainly for `ge_set_gej_var`'s field
inversion per record. The inversion count is the byte-level soft spot:
**Montgomery-batch the Z⁻¹ extraction across each block's sigs** —
k inversions → 1 inversion + ~3k muls ≈ ~5 field muls/sig ≈ ~0.2% of a
verify, not +16%.

Consequence: any node already verifying emits the complete AVHINT04
stream as a near-free byproduct. The economics objection ("who pays to
produce") inverts — the producer is every previously-synced node,
including the user's own existing synced node on this network. The
advice plane becomes seedable infrastructure instead of a protocol
moonshot. (Standalone production for unverified sigs stays ~1 verify +
~free extract — the claim is only about production *while* verifying.)

## 3. Positional + template representation is a lossless internal model, not just wire compression

The ledger priced re-encoding as ~20–30% wire savings. The deeper
point: most consensus bytes are re-derivable from a much smaller object.

- **Outpoints (36 B → ~8 B positional `(height,txidx,vout)`):**
  lossless because the txid is *derivable* — hash the creating tx, which
  is in-corpus and always precedes the spend (topological order holds:
  prevouts only reference earlier positions). Not wire compression — a
  true reduction of the stored object. The anti-join compares u64s
  instead of 32 B hashes; sighash consumes the real txid inside the hash
  pass where the index resolves it anyway. Encoding caveat: decode needs
  the creating tx reachable (index or deferred patch) — fine in-order.
- **scriptPubKeys → (template_id, param):** the ~5 dominant templates
  are fixed byte patterns; the sighash `scriptCode` is *synthesized*,
  never stored. Same for scriptSig/witness push framing.
- What's left is the actual entropy: sigs (r,s ~64 B), keys, amounts,
  positions. That is the corpus's information content; everything else
  is a re-derivable view. Expected total lossless reduction: ~25–35%
  measured-needed (the 45%-at-940 Mbps one-hour scenario probably still
  fails; measure before claiming).

## 4. The transcript: the frame the ledger circled but didn't state

The corpus is closed under its own data dependencies *and* under
re-derivation. One fused pass (bytes → hash commitments checked →
canonical records emitted) produces the validation transcript:

- per attempt: {r, s, hashtype, key-ref, positional prevout, sighash
  context} — ~100–150 B
- headers + integer outpoint streams for the anti-join
- R-parity hints ride along as the only genuinely external bits
  (~0.3–0.6 GB for all history at 2 bits/attempt — the *entire*
  non-derivable information content of historical validation)

Every downstream stage consumes the transcript; raw serialization is
touched only by the hash pass that binds the transcript to committed
bytes. Same artifact works as the acquisition encoding (lossless
round-trip = self-authenticating under merkle checks) and as the
internal rep (integer join, spliced sighash, template dispatch).

Generalized principle, worth stating once: **any expensive deterministic
sub-computation over public data can be served as an untrusted hint iff
checking it is cheaper than computing it** — R points (2 bits), SHA
midstates (parallelizes the one-pass hash), positional prevouts (skips
index build for the lookup side), survivor hints (swiftsync, already
shipped). The prior instance applied this to sigs and state; the byte
level applies it to *every* stage.

## 5. The 40 µs advised number is an implementation — but so is its floor

Phase-decomposition probe (`experiments/code/msm_decomp_bench.c`,
N=8192, pinned, guard-capped): the measured 38 µs/sig advised batch is

| phase | µs/sig | share |
|---|---:|---|
| parse — pubkey decompress (field sqrt) | 10.99 | 29% |
| lift-y33 (curve check, no sqrt) | 0.17 | ~0% |
| lift-hint1 (per-sig mod-p sqrt) | 10.73 | — |
| coefficient prep (scalar muls/adds) | 0.17 | ~0% |
| **ecmult_multi_var MSM, 2n terms** | **26.14** | **69%** |

with scalar MSM marginal cost falling to ~13 µs/term at 16 k terms
(Pippenger amortizing) and ordinary verify at 90.7 µs. Two conclusions:

- The batch mass is *only* MSM + pubkey-parse. The G column is one
  scalar mul per batch (`Σa_i z_i·G`); per-sig variable mass is exactly
  2 terms (R_i, Q_i) ≈ ~40 bucket adds at window ~14.
- Both big pieces are field ops that fused-4 lanes can carry — IF the
  lane speedup applies to point adds, not just serial ladders.

### The fused-4 add answer (msm_add4_probe.c, measured)

| pattern | ns/lane-add |
|---|---:|
| scalar gej_add serial | 432–480 |
| fused-4 serial chain | ~270–285 |
| fused-4, K=4 independent streams | ~267–289 |
| fused bucket loop incl. gather/scatter | ~300–322 |
| il2 — two adds instruction-interleaved | ~317 |

**Independent fused-4 ops overlap ~0%.** The ~900-µop mul blob exceeds
the ROB window; interleaving two adds instruction-for-instruction gained
~2.6%. The EZW "independent muls ≈ 7 ns/mul-equiv" throughput figure is
real only below ~450-µop granularity — unreachable at whole-formula
level. Correctness note: `gej4_add_ge4` verified 0/16000 affine
mismatches on non-degenerate inputs; it *needs* a degenerate-lane fixup
(h≡0 ⇒ doubling or ∞; scalar gej_add_ge_var branches to handle it).

So the honest advised-batch floor on this chip:

| component | floor |
|---|---:|
| MSM ~40 adds/sig × ~300 ns lane-add | ~11–13 µs |
| pubkey parse: lane sqrt ~8.5 µs OR dedup-repeat ~7 µs scalar OR
  affine keys in transcript (~+32 B/key bytes) | ~3–8 µs |
| lift (y33) + scalars + association | ~1–2 µs |
| **advised batch total** | **~16–23 µs CPU/sig** |

→ **~0.9–2.3 h sig-plane wall @8 cores** for 1.65–3.5 B attempts —
versus 2.3–4.9 h at the unimproved rate. Window growth measured dead
(w=16: 30.9 µs/term vs 13.0 at w=12 — the 6.8 MB bucket table thrashes
cache; ~21 adds/term is priced-in on this hardware).

### Short-coefficient batching (measured, new structural win)

Re-deriving the batch equation instead of inheriting it: divide the
per-sig equation by s_i —

```
P_i = R_i - u_i·G - v_i·Q_i = 0,   u_i = z_i·s_i⁻¹,  v_i = r_i·s_i⁻¹
Σa_i·P_i = Σa_i·R_i - (Σa_i·u_i)·G - Σ(a_i·v_i)·Q_i = 0
```

The **R_i scalar is now the coefficient a_i itself**, which only needs
~96 bits for soundness (an advisor sees a_i only after committing the
batch; P_i ≠ 0 passes with probability ~2⁻⁹⁶). Adds/sig drops
(256+256)/w → (96+256)/w. The s_i⁻¹s cost one Montgomery batch inverse
≈ ~0.16 µs/sig amortized.

Measured in the same harness (`batch_short`, tamper check PASS):

| path | µs/sig |
|---|---:|
| batch(), 256-bit a_i | 36.9 |
| batch_short(), 96-bit R coeffs | **30.8** (−17% total) |

With repeat-key coalescing on the full-width Q side (~30% measured
repeat rate) the expected add count is ~8 + 0.7·21 ≈ **~23 adds/sig**
≈ ~45% under the ~42 baseline → MSM ≈ ~7 µs fused. With affine-y key
advice (parse → ~0.5 µs check) the advised sig models at **~9–13 µs
CPU/sig → ~0.45–1.2 h wall @8c** — the sig plane now grazes the
sub-hour boundary at low census, not as a promise but as an arithmetic
consequence.

## 6. The state join is 6 CPU-h measured — and it is reorganizable bytes

The capacity audit prices join/emit/predicate at ~6 µs/input ≈ **6.2
CPU-h** — larger than the *optimized* sig plane. That number is a
per-input hash-map implementation cost, not physics: the same document's
physics analysis priced the anti-join at ~2–4 min of sequential I/O.
Partition by outpoint-prefix (independent probes), replace 36-byte hash
keys with ~8-byte positional integers (§3), sort-merge instead of
random probe: parallelized at ~1–2 µs/input it is **~10–90 min wall**.
Nobody has built the partitioned version; the 6 µs figure is the
conventional implementation measured, then projected as a floor.

## Revised stack — measured pieces, honestly stacked

| plane | current path | measured/floored pieces | wall @8c |
|---|---|---|---|
| sig | ~24 h forecast | **measured 21.16 µs/sig on 3.2M real corpus sigs** (key-y + nonce-y + short-coeff + coalescing, tamper-checked, 32.2% real dup rate) | **~1.15–2.4 h** |
| hash | serial sighash+merkle | splice verified byte-equal; ~4× byte mass at n=2000 but only at SHA-NI-rate impl; ~1.4% of script wall — not the gate | ~10–30 min |
| join | 6 µs/input serial | **measured ~0.33–0.36 µs** overlay shape on the real `utxo.get` path (flat36 + dirty map) | ~2–8 min CPU |
| parse | per-input Vec preimage | extraction on real corpus ~0.2 µs/tx; decode already fast | overlapped |
| wire | raw block stream | **measured: transcript ~0.83–0.87× wire** (prevout dict ~16.5%, entropy floor ~63%) | ~1.45h @1Gbps |

CPU-demand total ≈ **~10–23 CPU-h → ~1.3–3 h wall** dedicated, corpus
local (sig plane measured end-to-end at 20.3 µs/sig; join probe
measured on the real get path — both no longer modeled).
Acquisition is the separate gate (768 GB @1 Gbps = 1.7 h; transcript-
encoded measured **~0.83–0.87× wire → ~1.45 h**, not the earlier
350–450 GB guess — sigs/keys are entropy and can't leave). **The
honest stacked envelope on this laptop is ~1.5–3 h — not 4–6 h, and
not sub-hour.** The earlier figure priced each plane at its unstacked
conventional implementation; the corrected figure now rests on
measured components end-to-end (21.16 µs/sig on real corpus sigs).

Where the remaining upside lives, if it exists: fold-fused MSM
(+~5–10%), and the acquisition path itself. Closed: repeat-key
coalescing (measured −22%), sub-mul scheduling (headroom exists at
4-way ILP but is the same floor EZW-4 already taps — no extra lever),
producer batching (−1.3% standalone; sound only as byproduct), sighash
splice (~4× on ~1.4% share — bounded). The affine-y advice costs ~32
B/sig of hint stream (~53–112 GB corpus-wide) — compressible since
the compressed pubkey's parity bit already implies the y (send once
per unique key, not per sig — 32.2% real dup rate measured).

## Ranked — where to go (updated by measured probes)

1. **Flat live-table + kill the cascade** — MEASURED AND INTEGRATED
   (09-28j/k probes, 09-28s/t integration): on the REAL
   `UtxoSet::get` spend path (3M committed + 200k dirty), the cascade
   runs **~2.5–3.0 µs/input**; the in-crate flat layer
   (`crates/avila-consensus/src/flatmap.rs`, `UtxoSet.flat`) lands
   **339 ns/input through the real path — 8.1×**, identical results.
   Semantics preserved: map→base→flat→backend→snapshot ordering,
   commit-delta mirroring at flush, overlay/clone/reorg behavior
   unchanged (clones drop the mirror and stay correct). Corpus
   lockstep on real data: 2.19M txs / 4.44M spends, `get`/`spend`/`iter`
   identical (flat_lockstep_corpus). Deployment: `enable_flat(cap)`
   at open; restart tax ~1.6 s / 3M coins streamed (~80 s at 150M);
   refuses politely over cap. CLI `--flat-utxo-mib`, GUI first-run
   Standard/Experimental picker.
2. **MSM-on-EZW batch engine** — BUILT + MEASURED (msm_ezw.c, 09-28h):
   fused-4 Pippenger is correct end-to-end (all gates green at
   BW=8–12, equality vs ecmult_multi_var at 16384 terms) and runs
   ~5–10% faster than scalar at BW=9–10 (~13.1–14.1 vs ~14–15 µs/term)
   — gather/transpose/normalize/degenerate plumbing + the still-scalar
   fold are the true cost, not the ~300 ns/lane-add microbench. Two
   latent kernel bugs fixed on the way: fe4_neg's borrow wrap counted
   twice (raw +2^{64+52i} error, ~2⁻¹⁸ hit rate — invisible in every
   earlier probe's sample sizes), and the fma_rz split's hard
   dependence on FE_TOWARDZERO ambient rounding (a caller that forgets
   fesetround corrupts ~half of all limb-products — ABI footgun).
   Remaining upside: fuse the fold sweep (~64 µs at BW=10), superbucket
   merge of the 4 lane tables (projected ~1.2–1.4× total), and the
   short-coeff coefficient split which the accumulate already exploits
   (leading-zero windows skip). Honest expectation: ~1.2–1.5× total
   with all of it — not the 3× first hoped.
3. **Batched-extraction advice producer** — per-block Montgomery batch
   on `ge_set_gej_var` → producer ~+0.2% not +16%; then AVHINT04 into
   sync as the experimental flag. Small edit, unlocks deployability.
4. **Pubkey-parse + repeat-key coalescing** — BOTH MEASURED (09-28i,
   09-28l): advised affine y collapses parse 12.4→0.22 µs/sig; key
   coalescing merges same-pubkey Q-terms (one open-addr group map in
   the timed loop) → **20.3 µs/sig** on 26%-dup data (−22%), tampers
   pass. Ordinary→advised+coalesced = **4.9×**. Sig plane is now ~75%
   MSM — only the fused engine's ~5–10% remains on it.
5. **Legacy sighash splice+stream** — MEASURED (09-28m): spliced
   continuation verified byte-equal per input; ~4× less byte mass at
   n=2000 but only pays at SHA-NI-rate impl (crate hits 1.45GB/s).
   Legacy sighash is ~1.4% of script wall — bounded win on a small
   share; deprioritized unless a midstate-capable sha256 lands anyway.
6. **Sub-mul op-schedule probe** (uncertain, last big kernel idea):
   interleave independent muls below ROB granularity — x2 whole-add
   interleave already measured ~flat, so this needs tile-level codegen.
7. Transcript/positional wire rep measured on captured windows.
8. verify4 composite for the honest end-to-end number.
9. Stay dead: CSA mul (uncertain), iGPU (~5%), SP-batch (≡ advice),
   Schnorr batch (~8% mass).

## Bottom line

The previous instance's physics was right; its ceiling was a ceiling of
its own stacking, not of the problem. Byte-level manipulation buys the
sig plane real multipliers *inside* the already-measured advice path —
measured so far: ~17% from short coefficients, ~5–10% from the fused-4
MSM itself (the ~3× sig-plane estimate was too optimistic on the MSM
plumbing; keep ~1.2–1.5× with fold-fusion + coalescing) — turns advice
production nearly free, halves the legacy hash plane structurally, and
turns the join's 6 CPU-h into a partition problem. Stacked honestly:
**~24–30 h current → ~1.5–3 h** on this exact laptop, corpus local;
the wire story then lives or dies on acquisition goodput and the
transcript encoding. That is the direction worth the next experiments —
in the order above.

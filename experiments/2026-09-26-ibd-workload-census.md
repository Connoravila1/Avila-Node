# IBD workload census — structural counts over real mainnet corpora

Date: 2026-09-26. Status: measured structural census over sampled windows;
full-history totals are labeled sample extrapolations, not an exact census.
Scope per [researcher work order](../docs/IBD_RESEARCHER_WORK_ORDER_2026-09-26.md)
deliverable 1. The earlier probe's 24-block executed trace remains the only
*executed* signature-attempt measurement; everything below is a structural
parse count (shapes/pushes/sizes) unless marked otherwise.

## Environment and provenance

- Host: Intel Core i3-N305 (8 cores, no SMT; AVX2, SHA-NI, BMI2, ADX, VAES;
  no AVX-512/IFMA — the IFMA gate stays closed on this machine). 32 GB RAM.
  NVMe Samsung 990 EVO Plus on PCIe 3.0 x4 (8 GT/s/lane → 3.938 GB/s
  coding-only bound).
- Tree: `c80341f1421d20003b9acbe33a56b9d5d52de45b` + uncommitted live-agent
  changes (sync/chainstate/rpc/manager/testchain). New files only:
  `tools/ibd_census.py`, `tools/ibd_workload.py`,
  `experiments/results/census-2026-09-26/`.
- Sources (read-only):
  - `data/mainnet/blk*.dat` — Avila blk store (Core-compatible framing, plain),
    sampled windows at heights ~276k, ~340k, ~364k, ~402k. Each input file's
    sha256 is recorded inside its window JSON.
  - `~/.bitcoin/blocks/blk0563{0,1,2}.dat` + `xor.dat` — Core blk records,
    xor-decode verified against mainnet magic, heights ~956.5k.
  - `fixtures/mainnet-blocks-000000-000500.dat` — genesis era.
- Shared-host caveat: all runs coexisted with the live IBD; census is
  I/O/CPU-insensitive for *counts* (not timings), so no timing claim is made
  from this data.

## Corpus coverage

| Era | Span | Local coverage | Windows measured |
|---|---|---|---|
| genesis_sparse | 0–227930 | fixture 0–500 only | 501 blocks |
| pre_segwit | 227931–481823 | `data/mainnet` contiguous ~229k–~408k | 1,728 blocks |
| segwit_era | 481824–709631 | **none** — explicit gap | 0 |
| taproot_era | 709632–tip | Core slice ~956468–956718 | 251 blocks |

`blk00925.dat` is 402k-dominant with one stray 968679 record (pre-fetch
leakage); it is bucketed by median height and the contamination is ~0.5% of
that window's sig-shaped items.

## Measured per-block densities

| Window | Era | Blocks | tx/blk | in/blk | out/blk | sig-shaped items/blk |
|---|---|---|---|---|---|---|
| blk00570 | ~278k | 879 | 303 | 731 | 863 | 732 DER |
| blk00690 | ~341k | 449 | 551 | 1,496 | 1,571 | 1,515 DER |
| blk00765 | ~365k | 189 | 868 | 3,900 | 2,403 | 3,971 DER |
| blk00925 | ~402k | 211 | 1,147 | 3,170 | 3,021 | ~3,484 (DER 3,446 + wit 51) |
| core05630–32 | ~956.6k | 251 | 4,765 | 7,645 | 10,835 | ~7,667 (540 DER + 6,521 wit-DER + 606 schnorr-sized) |

Structural sig-item estimate vs the executed 24-block trace (956105–956128):
7,960 shaped items/blk vs 7,658 executed attempts/blk — within ~4%.
Multi-push (multisig-shaped) inputs carry >1 sig item; the executed pass is
where false/retried attempts appear (the 24-block trace had 6,137 false
attempts, 3.3% of total).

Notes from the data that the averages hide:

- Input/tx ratio swings ~3× within the pre-segwit era (2.41 at 278k → 4.49
  at 365k). Full-history input totals need era-weighted extrapolation, not a
  single density.
- Taproot-era sig mix at h~956.6k: ~85.9% ECDSA-shaped, ~7.9%
  schnorr-sized, rest other. Schnorr is not yet half the workload.
- Byte categories: pre-segwit scriptSig is 61–65% of decoded bytes, outpoints
  ~18–20%; at 956k witness is 50.9% and scriptSig 4.2%.

## SHA-256 compression accounting (structural)

Compression calls are computed analytically per message: `ceil((L+9)/64)` per
SHA-256 pass, +1 for the second 32-byte pass of sha256d. Category totals per
block:

| Window | txid | wtxid | merkle interior | sighash est. (legacy / witness) | sha-comps/blk |
|---|---|---|---|---|---|
| blk00570 (~278k) | 2.52M | 2.52M | 0.80M | 43.9M / 0 | ~56.5k |
| blk00690 (~341k) | 2.48M | 2.48M | 0.74M | 49.1M / 0 | ~122k |
| blk00765 (~365k) | 2.35M | 2.35M | 0.49M | 145.1M / 0 | ~795k |
| blk00925 (~402k) | 2.45M | 2.48M | 0.73M | 167.2M / 58k | ~819k |
| core05631 (~956k) | 1.61M | 2.76M | 1.27M | 15.6M / 2.9M | ~289k |

**Finding:** legacy sighash is the dominant hash-plane term in pre-segwit
blocks — 9–11 GB of SHA-256 input per ~134 MB block file (≈35–75×
amplification), because each input's preimage reserializes most of the
transaction and the era contains multi-hundred-input transactions. In the
taproot window it falls to ~5× amplification (BIP143/341 fixed-size preimages +
shared per-tx components). Any "hashing is cheap" conclusion drawn from
recent-era data does not transfer to the legacy middle of the chain.

`wtxid` counts assume every tx is hashed under the segwit-era commitment tree;
pre-segwit blocks have no witness tree, so `sha_comps_wtxid` there is an
upper bound labeled accordingly.

## Synthesis (`workload.json`)

Per-era measured densities × era span, tagged `sample_extrapolation`; the
segwit gap is tagged `unmeasured_assumption` with a bounded carry range.
Aggregate full-history extrapolation is deliberately NOT collapsed to a point
estimate: era densities vary 3–12× and the segwit gap is unmeasured.
Illustrative range for total non-coinbase inputs: ~1.6B–3.4B (vs the 1.5B
assumption used in earlier arithmetic — now measured-informed but not
measured-exact). The exact census requires either the executed pass over a
complete corpus or the live node's full download.

## Completion boundary (work-order terminology, now binding)

A "full validation" result claims only the last of these when stated:

1. **acquired**: all block bytes present locally;
2. **applied**: blocks connected; deferred/absent work may remain;
3. **all-checks-complete**: every applicable consensus check executed,
   including script tails and state/provenance — no snapshot assumption, no
   skipped historical script check;
4. **state-materialized**: exact final UTXO set produced;
5. **durable**: that state committed to stable storage.

The 60/30/20/10/5-minute budget rows in
`experiments/results/census-2026-09-26/workload.json` must be read against
these endpoints; the earlier hardware-floor table's per-deadline rates apply
to whichever resource column the census eventually fills.

## Reproduce

```
python3 tools/ibd_census.py data/mainnet/blk00570.dat \
    --out experiments/results/census-2026-09-26/blk00570.json
python3 tools/ibd_census.py ~/.bitcoin/blocks/blk05630.dat \
    --xor-key ~/.bitcoin/blocks/xor.dat \
    --out experiments/results/census-2026-09-26/core05630.json
python3 tools/ibd_workload.py experiments/results/census-2026-09-26/*.json \
    --out experiments/results/census-2026-09-26/workload.json
```

## Next (assigned queue)

- Extend coverage: rerun when the live node's corpus crosses 481824+, or
  ingest a bounded Core segwit-era slice the same way.
- Executed counts per window (not just the one taproot trace): needs the
  staged-workspace replay with corpus-resolved prevouts — deliverable 3's
  machinery, which doubles as candidate 41's harness.
- Deliverable 2 next: audit the instruction census against the actual node
  build; bounded test of the SHRD-heavy reduction sequence.

## Rate-vs-deadline table (measured rates × extrapolated totals)

Sig-plane totals from the census windows are *sample extrapolations* over an
unmeasured segwit era — carry the range, not the midpoint. Non-coinbase
inputs ≈ signature-check attempts within ~4% (measured cross-check above);
multisig false-attempts add ~3%.

| Quantity | Low | High | Basis |
|---|---|---|---|
| Non-coinbase inputs (full chain) | ~1.6B | ~3.4B | measured era densities × era span; segwit era interpolated |
| Sig attempts (est.) | ~1.65B | ~3.5B | + ~4% false/multisig tail |
| SHA-256 compressions | ~60G | ~200G | per-category census; legacy-sighash-dominated range |

Measured rates on this i3-N305 (shared host, single-thread rates;
8-core scaling assumes ~linear, unmeasured):

| Path | µs/sig (measured) | 8-core sigs/s | 1.65B sigs | 3.5B sigs |
|---|---|---|---|---|
| ordinary verify | 94.7 | ~84k | 5.4 h | 11.6 h |
| batch_y33 patched (best CPU) | 40.3 | ~198k | 2.3 h | 4.9 h |

Required sustained sig throughput for deadlines (3.5B worst case):

| Deadline | sigs/s needed | Feasible on this CPU? |
|---|---|---|
| 60 min | ~0.97M | No — ~5× over best measured CPU path |
| 30 min | ~1.9M | No — GPU/cluster or sig-source change required |
| 20 min | ~2.9M | No |
| 10 min | ~5.8M | GPU-class hardware only; unmeasured here |
| 5 min | ~11.7M | Not plausible on commodity CPU; RTX-class claim unverified |

Secondary terms at those deadlines: corpus acquisition 768 GB reads in
~3.3 min at the measured PCIe3x4 coding bound (local) — so storage is NOT
the floor on this machine; WAN acquisition is (~2.1 h at 1 Gbps). Legacy
sighash hashing (60–200G compressions) is ~5–30 min at multiway SHA-NI
rates — real but secondary; it becomes *the* binding term if sigs move
to GPU and acquisition is local.

**Machine-bound statement, honest form:** on this hardware, the sig plane
floors full-IBD around ~2.3–4.9 h (advice-assisted CPU path, assuming
~linear 8-core scaling and ignoring the unmeasured state-plane cost). The
60-minute and under targets are unreachable on this CPU — they require the
GPU plane (unverified on-site) or a different machine. This is now a
measured interval, not a universal claim.

## Corrections (post-audit, experiment 72)

1. **Hash accounting regenerated.** The v1 model charged the full
   stripped tx per input and over-counted: corrected model counts
   per-DER-item preimages with blanked input scripts, SIGHASH_SINGLE/
   NONE/ANYONECANPAY cases, exact stripped lengths (witness section
   including item counts/length encodings), wtxid only for
   witness-serialized txs, real level-by-level merkle counts, and an
   executed merkle-root check vs the header (189/189 verified on
   blk00765). Corrected blk00765: sighash_legacy_comps_est 38.7M (v1:
   ~145M — the old formula overstated ~3.75×); preimage bytes 2.39 GB
   (v1: ~9–11 GB). Still the dominant hash plane but the "35–75×
   amplification" figure is retired; per-sig the quadratic tail lives in
   few mega-input txs (per-tx sighash work ∝ n_in²).
   scriptCode lengths remain approximations (prevouts unresolved in the
   census) — executed calibration comes from the corpus-replay pass.
2. **Calibration.** On the same window (blk00690): structural
   DER-attempt estimate 680,168 vs executed 526,534 — ratio 1.292 ≈ the
   unresolved-subset share (1/0.7708); scaled structural ≈ within ~0.5%
   of executed. DER-shaped attempt counting is calibrated ~exact;
   compression counts remain structural estimates.
3. **Floor statement — replaced.** Delete "unreachable on this CPU,"
   "GPU/cluster required," "measured interval," "physical floor".
   Correct form (audit-required):

   > Under the provisional workload range and ideal eight-core scaling,
   > the best tested synthetic advice-assisted ECDSA receiver path
   > projects roughly 2.3–4.9 hours for that modeled signature workload
   > alone. This implementation does not meet the one-hour target.
   > These measurements do not establish the fastest possible
   > implementation on this CPU.

   Requirements for the signature portion alone (1-hour deadline,
   provisional attempts): 1.65B → 458k attempts/s (17.45µs/attempt
   ideal-8c; 13.09µs with 6 sig cores); 3.5B → 972k/s (8.23µs; 6.17µs).
   The 40.265µs sample ⇒ ~198.7k/s ideal-8c ⇒ 2.3–4.9× more needed.
4. **Storage/network wording fixed.** PCIe3x4 coding bound is NOT
   measured SSD read throughput and cannot exclude storage as a
   bottleneck. 768 GB raw transfer at 1 Gbit/s = 102.4 min before
   overhead — larger estimates need explicit overhead/goodput
   assumptions.
5. **Whole-history model caveats added.** Pre-BIP34 sparse density,
   late-Taproot slice coverage, median-height bucketing, and the
   unpinned 970k endpoint are recorded as assumptions, not
   demonstrated bounds. workload.json's measured-era points already
   sum to ~2.391B inputs before the unmeasured SegWit era; the prose
   1.6–3.4B interval is scenario range, not a statistical bound.

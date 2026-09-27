# Bounded SHRD replacement in field kernels (Gracemont)

Date: 2026-09-26. Status: measured A/B on a private staged copy of the pinned
secp256k1-sys 0.10.1 source. Research-only; production sources untouched.

## Hypothesis

`u128_rshift(&acc, 52)` lowers to `shrd lo,hi,52` on this toolchain; SHRD is a
single-port, ~12+ cycle instruction on Gracemont per vendor tables. 16 sites
execute per verify (~8 per `fe_mul_inner` call + ~8 per `fe_sqr_inner` call ×
~985/973 calls/verify ≈ 15.7k SHRDs/verify). If throughput-bound, replacing
with `(lo>>52) ^ (hi<<12)` (bit-disjoint ⇒ XOR≡OR, defeats the compiler's
SHRD fusion pattern) should cut a large verify fraction.

## Microbenchmark (standalone, experiments/code/shrd_probe.c)

Pinned CPU7, nice 19, 40M iters × 3 reps: 4×SHRD group ≈ **19.3–20.0 ns**
(≈4.8 ns/SHRD ≈ 18 cyc) vs 4×(SHR+SHL+OR) ≈ **2.5–2.6 ns** (≈0.64 ns/group)
→ ~7.5× sequence-level. Caution: feedback chain in the probe makes this a
near-worst-case bound, not the in-context cost.

## Library A/B (real verify path)

Patched `u128_rshift` n==52 case only. Builds identical flags to the
hardware-floor probe (`cc -O3 -msha`, generic tune). Interleaved runs
A/B/A/B…, `taskset -c 7 nice -n 19`, trace `target/ecdsa-replay/final-1/
mainnet.trace` (sha256 recorded in results JSON), n=2048 records, 6 reps →
18 timing samples per variant per mode. Correctness: harness enforces every
record verdict on load; any divergence aborts — none did.

Disassembly (patched vs vanilla):
- `fe_mul_inner`: 8 → 1 SHRD; `fe_sqr_inner`: 8 → 1 SHRD; total binary
  404 → 102 SHRDs. Survivors: modinv64/modinv64_var (60), ecmult_pippenger
  (25), straggler sites — all outside the per-input hot path (~1 scalar
  inversion per verify).

Timing (cpu_seconds per 2048-verify pass, median over 18 samples):

| Mode | Vanilla | Patched | Δ median | Δ min |
|---|---|---|---|---|
| compressed_parse_and_verify | 0.1935 s | 0.1855 s | −4.2% | −7.8% |
| preparsed_verify | 0.1700 s | 0.1653 s | −2.8% | −6.5% |

≈ 4 µs/verify saved at the median → ≈0.3 ns per eliminated SHRD site per
call — i.e. the in-context marginal SHRD cost is ~1–2 cycles, not the 12–19
of the isolated sequence. Out-of-order execution absorbs most of it; the
uop pressure reduction still nets a few percent.

## Verdict

Bounded real win: **~3–8% on the ECDSA verify path on i3-N305** (95% CI
bands overlap on max but medians/min consistent across 18 interleaved reps).
Not the order-of-magnitude the isolated microbenchmark suggested. Direction
is worth upstreaming as a source-level rewrite *if* it also helps other CPUs;
worth keeping in the candidate list at this size. Remaining modinv64 SHRDs
are ~60 per binary in a once-per-verify path — sub-noise, skipped.

## Excluded / unmeasured

- Shared host (live IBD running); numbers are comparative, not capacity.
- No TLB/cache isolation; both binaries identical working set.
- Effect on other microarchitectures unknown (SHRD is ~1c on Intel P-cores;
  patch is expected neutral there — would need a different box to verify).
- Full-node integration effect unmeasured (script worker pool may hide a
  4% kernel win entirely or stack multiplicatively — unknown).

Artifacts: `tools/ibd_shrd_bench.py`, `experiments/code/shrd_probe.c`,
`target/ibd-shrd-bench/run-1/results.json` (commands, disasm census, all
timing samples, trace sha256).

## Follow-on: advice-mode comparison on the same patched/vanilla pair

Built the standalone `ecdsa_advice.c` harness against both dep copies
(synthetic 4,096-record workload, all-valid distribution, sequential runs
on CPU7 nice 19, 2 reps — medians, µs/sig):

| Mode (batch size) | Vanilla | Patched | Δ |
|---|---|---|---|
| ordinary | 94.45 | 92.41 | −2.2% |
| individual_batch_inverse[512] | 96.68 | 88.57 | −8.4% |
| batch_hint1[2048] | 57.88 | 52.30 | −9.6% |
| batch_hint1[8192] | 54.72 | 49.93 | −8.8% |
| batch_y33[2048] | 46.31 | 42.33 | −8.6% |
| batch_y33[8192] | 42.60 | 40.27 | −5.5% |
| bad_hint1_fallback[8192] | 151.31 | 142.43 | −5.9% |
| bad_y33_fallback[8192] | 138.81 | 133.43 | −3.9% |

Observations for deliverable 2b:
- The patch helps **every** mode (~2–12%) — field ops remain hot even in
  the advice path (which removes per-sig field inversions via batch
  inversion but keeps all point/field multiplies).
- Best config on this machine: `batch_y33` at large batches + patch →
  **40.3 µs/sig** vs vanilla ordinary 94.5 µs/sig = ~2.35× end-to-end on
  this synthetic set, with the adversarial-fallback safety net measured at
  133–142 µs/sig worst case (still ~1.5× ordinary — fallback economics hold).
- Patched batch sizes beyond ~512 converge; diminishing returns past 2048.
- Caveat: synthetic records skew uniform-valid; mainnet-trace behavior of
  the advice modes was already measured in the earlier advice experiments —
  the delta table above isolates the patch interaction.

## Corrections (post-audit, experiment 73)

- Recomputed medians from the saved results.json (all 18 pass samples
  per variant/mode): compressed parse+verify 0.193295s → 0.182924s
  (**5.37%**), preparsed 0.169977s → 0.164503s (**3.22%**). The earlier
  report's 4.2%/2.8% used a different aggregation; the audit numbers
  supersede. Two of six paired process comparisons regress slightly in
  each mode — preserve pairing; do not convert favorable minima into
  expected gains.
- The disasm_census JSON recorded all-zero mnemonics (parser matched
  raw byte columns). Fixed in ibd_shrd_bench.py: objdump
  --no-show-raw-insn + all-zero now fails loudly. Re-verified
  fe_mul_inner/fe_sqr_inner: 8→1 SHRD each (matching direct grep).
- batch_y33[8192] ran on 4,096 records — batch size 8192 was a
  parameter, not a demonstrated 8192-record batch. The advice producer
  (~91.4µs/record patched) runs before receiver timing: if advice is
  generated locally that cost must be counted; if remote, count helper
  bytes (provisional range: 54–115 GB at 33B/attempt before framing).
- "Out-of-order hides SHRD latency" is an inference, not measured
  counter evidence — labeled as such.
- This is a small keepable optimization candidate, not a full-node win.

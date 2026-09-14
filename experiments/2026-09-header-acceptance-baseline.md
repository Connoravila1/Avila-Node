# Experiment: header-acceptance correctness and throughput baseline

Status: complete

Roadmap gate/workstream: G1 (scorecard runner, baseline measurements); W1

Scorecard rows: C1 (correctness evidence); component-level baseline relevant to
P1's eventual scope — **this is not a P1 result**: header validation alone is
not full validation.

Operating profile: local replay of committed header fixtures; no network peers,
no storage engine, no services; single developer machine (manifest below).

## Question and hypothesis

Two questions: (1) does `avila-consensus`'s header acceptance agree with the
reference implementation on every header, including invalid cases; (2) what is
the baseline wall-time and memory cost of header acceptance, cold and warm, on
each network's fixture? A disagreement on any verdict, or a regression in
per-header cost after future changes, is the signal this baseline exists to
catch.

## Baseline and candidate

- Candidate: `avila-consensus` `HeaderTree::insert` via the `check_headers`
  example binary, release profile (`lto = "thin"`), workspace commit
  `940799b` lineage. Checks executed per header: PoW sanity + hash meets
  target, known-parent, required-`nBits` schedule (retarget, min-difficulty,
  BIP94 base), median-time-past, BIP94 timewarp floor, future drift,
  chainwork accumulation.
- Baseline: installed `bitcoind` — Bitcoin Knots v29.3.knots20260508
  (Core-derived; identical consensus code for the checked surface). Per-header
  validation via the `submitheader` RPC, which runs `AcceptBlockHeader` +
  `ContextualCheckBlockHeader` — the same check set — plus block-index
  bookkeeping and RPC overhead our side does not have. Version and sha256 are
  recorded in each run artifact; the adapter is not pinned to this build.

## Workload and method

- Workloads: `fixtures/` genesis-anchored header runs — mainnet 0–4031
  (uniform difficulty, two full periods), testnet4 0–4031 (BIP94 enforced,
  long min-difficulty runs), signet 0–2047 — plus a generated regtest corpus:
  289-header valid chain crossing two retarget boundaries, then named invalid
  mutations (bad-diffbits, high-hash, time-too-old, time-too-new, orphan,
  duplicate resubmission). Fixture provenance: `fixtures/manifest.json`.
- Runner: `tools/scorecard_headers.py` (stdlib only), which reuses
  `tools/check_headers_core.py` for the correctness gate and the daemon
  lifecycle. Daemons run with `-connect=0 -listen=0 -dnsseed=0 -fixedseeds=0`.
- Timing: `time.monotonic` wall time. Avila: one process per rep (rep 0 cold,
  reps 1+ warm), RSS via `wait4`. Reference: fresh daemon + datadir per rep
  (every rep is a cold run — resubmitting known headers exercises the
  duplicate path, not validation); submit-phase wall time only; daemon startup
  recorded separately; RSS via `/proc` VmHWM.
- Reproduction: `python3 tools/scorecard_headers.py` (options:
  `--suites`, `--reps`, `--ref-reps`, `--out`).

## Correctness evidence

Per-header verdicts compared on all suites before any timing row is reported;
the runner exits non-zero on disagreement. Result: **zero mismatches on all
10,404 compared headers** (index-0 genesis excluded — `submitheader` rejects
re-anchoring it as an orphan while `HeaderTree` pre-seeds it; a reporting
artifact, not a verdict difference). All seven named invalid cases produced
identical reject reasons on both sides.

## Results

Artifact: `target/scorecard/headers-1789357657.json` (gitignored; raw per-rep
times stored verbatim). Machine: x86-64 Linux, per the artifact manifest.

| Suite | Headers | Verdicts | Avila cold | Avila warm (×4) | Avila peak RSS | Reference submit (×2) | Reference peak RSS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| mainnet | 4032 | agree | 13 ms | 11 ms | 19 MiB | 0.04–0.05 s | 63 MiB |
| testnet4 | 4032 | agree | 123 ms | 123–126 ms | 19 MiB | 0.05 s | 63 MiB |
| signet | 2048 | agree | 7 ms | 6–7 ms | 19 MiB | 0.02 s | 59 MiB |
| regtest | 290 | agree | 4 ms | 4 ms | 19 MiB | 0.01 s | 53 MiB |

Throughput: ~370k headers/s on mainnet, ~33k/s on testnet4.

Notable: testnet4 is ~10× slower per header than mainnet on our side. Cause:
`required_bits` walks ancestors while preceding blocks carry minimum
difficulty (Core's `GetNextWorkRequired` does the same walk); early testnet4
is uniformly min-difficulty, making each insertion O(height) → O(n²) over the
run. This matches Core's algorithm structure; the reference daemon pays it in
a cheaper in-memory index, so the gap does not appear in its numbers.

## Interpretation and reuse

Evidence supports: header acceptance is verdict-equivalent to the reference on
the full committed corpus including all invalid cases; per-header cost is
sub-millisecond on public-network fixtures and bounded at 19 MiB RSS for the
in-memory tree. Limits: no block/tx validation, no storage, no network —
nothing about sync or full validation can be inferred. The min-difficulty
ancestor walk is the first measured hot spot for hypothetical long
min-difficulty runs; a memoized "last non-min-difficulty ancestor" index is
the obvious optimization if testnet4-scale inputs ever matter, at the cost of
diverging from Core's simpler structure.

Smallest reusable component for other projects: `check_headers` example +
`tools/check_headers_core.py` verdict comparison (any consensus implementation
can swap in its own verdict printer and reuse the daemon driver and corpus
generator).

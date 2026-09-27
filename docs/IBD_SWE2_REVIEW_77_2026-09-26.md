**Codex audit: experiment 77 / Gate 3 state closure**

Updated disposition: the
[repair review and Gate 4 handoff](IBD_SWE2_REVIEW_77_FOLLOWUP_2026-09-26.md)
accepts the repaired bounded fixture baseline and supports proceeding with
Gate 4 development. The original findings below describe the earlier version
and are retained with their pinned evidence.

Date: 2026-09-26. This reviews
[`state_join.rs`](../crates/avila-consensus/examples/state_join.rs), the
[researcher report](../experiments/2026-09-26-ibd-state-closure.md), and saved
scenario/test outputs against the existing
[Gate 3 acceptance requirements](IBD_SWE2_REVIEW_76_2026-09-26.md).

Method: source inspection, parsing saved JSONL, reading the complete release
test log, and arithmetic on recorded values. Codex ran no examples, tests,
benchmarks, corpus scans, or live-node operations.
[Evidence](evidence/2026-09-26-ibd-swe2-review-77.json) pins the reviewed source
and preserves the supplied results and test log.

**Disposition: the 14-case demonstration is supported; Gate 3 acceptance
remains open for specific correctness and coverage repairs**

The implementation compares complete canonical coin bytes, and the saved
outputs report equality for all 14 scenarios. The two engines also report
matching heights, and the saved supplied-state digest equals the uninterrupted
valid-run digest. This establishes more than the earlier set-overlap result.

The saved release log confirms **551 library + 9 fault-injection + 19 property
tests passed: 579 total, zero failed, two ignored**. The separate example's
JSONL supplies its result; Cargo's library/integration test totals do not mean
the example's acceptance conditions are complete.

Do not yet label this "exact closure under every state predicate" or a
validated corpus-wide anti-join. There is a concrete supplied-state header
context defect, the oracle lacks expected-outcome assertions, and several
claimed predicates are not exercised independently. These are finite repairs
to the existing gate. Gate 4 planning and representative-corpus selection can
proceed; capacity claims must wait for the relevant correctness checks.

**P1 — Extend and validate header context across the supplied-state boundary**

The supplied-state setup at `state_join.rs:874` builds `pre` only through
height 105, then passes it unchanged to `run_batch` for heights 106–108.
`run_batch` never inserts those suffix headers. At height 107 its parent
(height 106) is consequently absent from that tree. `parent_mtp` at line 273
converts missing context to zero with `unwrap_or(0)`.

This is an actual context defect, hidden by the current fixtures' use of
height-based locks. The shared `bip68_locks_satisfied` helper obtains time-lock
ancestors from the supplied tree and returns false if they are missing; the
local `create_mtp` map does not repair this because the collected per-coin MTP
values are discarded before the helper call. A correct helper still needs
the correct chain context.

SWE-2 should:

1. Extend the checked header tree as the suffix is evaluated, or provide a
   fully checked immutable index for the selected chain and assert each
   candidate's parent, height, and hash against it. Treat missing MTP/ancestor
   context as an explicit error; never substitute zero.
2. Replace ignored `tree.insert` results at lines 789, 876, and 880 with
   checked outcomes and selected-chain linkage assertions.
3. Add a supplied-state continuation that creates a coin after the split and
   spends it under a valid time-based BIP68 lock later in the suffix. Even a
   time-type lock with zero delay exercises ancestor resolution. Include
   early/satisfied positive-delay boundaries and non-final time-based absolute
   locktime cases; record the expected outcomes independently.
4. Initialize the incremental runner's last-valid height from the supplied
   boundary. It currently starts `tip_h = 0` at line 202 even when `pre_tree`
   and UTXOs represent height 105. A rejected first suffix block must leave
   the reported last-valid tip at height 105, including on header failure.

These are source-derived findings and regression specifications, not failures
observed in a new Codex execution.

**P1 — Make the comparison enforce the claimed acceptance conditions**

The main oracle at lines 793–800 requires the engines to agree with each
other. There is no per-scenario expected verdict or reject height. Two wrong
acceptances, or two premature rejections with the same state, can satisfy it.
The supplied-state comparison at lines 898–900 also omits tip equality and
does not compare either result with the uninterrupted run. The saved digests
happen to agree, but the harness does not enforce that claim.

Give each scenario a declared expected outcome, rejection height where
applicable, and last-valid height/hash. Require those expectations as well as
agreement. Add a batch tip hash and compare it with the incremental tip and
the selected chain. For supplied-state runs, assert both resumed exports and
tips equal the uninterrupted expected result. Compare state at each accepted
block boundary, and require a rejected block to preserve its pre-block state.

Preserve the serialized chain fixtures and initial-state export, their hashes,
and start/end heights and hashes in a run manifest. Cross-check the critical
fixture outcomes with Bitcoin Core on an isolated Bitcoin regtest instance,
or independently established Bitcoin fixture results. Shared rule helpers are
appropriate, but comparisons that share those helpers do not independently
validate their arguments, activation context, or expectations.

**P1 — Exercise the predicates the suite claims to cover**

- **BIP30 is masked.** In `dup_txid_unspent`, replaying the identical normal
  transaction also re-spends its already-consumed inputs. The saved incremental
  error is a BIP30 overwrite; the batch error is input unavailability, before
  the batch BIP30 branch. Different error ordering is acceptable for a block
  violating two rules, but this fixture cannot prove the batch BIP30 check
  works: removing that check would still leave this case rejected. Add an
  isolated duplicate-output predicate fixture with an independently checked
  expected result. Include the historical permitted duplicate/fully-spent
  behavior and exception handling in the explicitly labeled historical
  predicate coverage. Post-BIP34 fixture restrictions do not establish the
  earlier-history behavior required by full IBD. Do not change production
  consensus parameters to obtain a passing result.
- **Time locks are absent.** The version-2 fixtures set sequence to `5` or
  `1`, which exercise height locks. No fixture sets the time-type bit. The
  claim that the time-based branch was exercised is unsupported; add the
  boundary cases above. The supposed satisfied absolute-locktime fixture
  keeps final input sequences, which bypass that lock. Give the positive
  boundary case a non-final sequence and preserve a separate bypass case.
- **Fee-bearing coinbase bounds need a positive control.** Existing valid
  blocks claim only subsidy even when transactions pay fees; the overpay
  case has no fees. Add a block claiming exactly subsidy plus the aggregate
  fees, and a paired one-satoshi excess. The suite should catch a regression
  that checks the coinbase before accumulating fees.
- **Historical activation and remaining checks need explicit boundaries.**
  The batch path always calls BIP68 and repeats absolute finality against
  parent MTP. Production gates BIP68 on CSV and uses block time before
  BIP113 activation. The batch also omits the production aggregate fee-range
  check, UTXO-dependent P2SH/witness sigop accounting, and scripts. Its normal
  duplicate-output check has no mainnet exception handling. Keep unsupported
  contexts explicitly out of this prototype's claims and implement/test the
  required behavior before feeding historical mainnet windows through it.
  OP_TRUE fixtures legitimately isolate basic state transitions; their
  passing result does not qualify these omitted checks or the binding of
  real script jobs to the batch-resolved prevouts.

Do not require the two engines to use identical error strings or internal
rejection ordering. Require the expected validity, height, and last-valid
state, and use isolated fixtures to show each individual predicate fires.

**Architecture actually implemented, and what Gate 4 must measure**

The source contains `live` and `overlay` maps keyed by `OutPoint`, a
`Vec<OutPoint>` of spends, and a vector of created coins. It processes each
block and transaction in order and performs ordinary point lookups. The
claimed creation keys `(height, txidx, vout)` and spend keys
`(height, txidx, inidx)` are not stored as occurrence records. Transaction
position is implicit in the sequential loop. The final per-block
`created`-minus-`spent` filter is useful, but the full-window occurrence-aware
join from the research plan remains unimplemented.

Retain this as an independent per-block state evaluator and correctness
reference. Before calling a result a corpus-wide anti-join measurement,
implement explicit creation/spend occurrence identity and the chosen window
partition/sort/join strategy, then run the same repaired correctness suite
against that implementation. Otherwise Gate 4 would measure an additional
sequential UTXO algorithm rather than the proposed write-avoiding architecture.

`spent_keys.contains` inside the input loop and `spends.contains` for every
creation also perform linear scans; their worst-case aggregate work is
quadratic within a block. Do not extrapolate the tiny fixture timings to
dense historical blocks. Count index build, header/context preparation, all
reads and writes, script work, state output, peak memory and temporary storage,
and the durable completion boundary for the architecture actually measured.
The current incremental timer includes header insertion while the full-chain
batch header index is built before its timer. Keep these timings diagnostic.

Gate 4's eventual deliverable remains the requested practical laptop range:
representative era-weighted workload, measured capacity with all preparation
and helper costs, and a first-launch projection under stated measured network
conditions. Preserve remaining uncertainty and separate that forecast from a
completed integrated first-launch benchmark.

**P2 — Correct the result format and small reporting errors in the same pass**

- The saved `valid_window` has **107 records**, not 109: 107 records of
  54 bytes give the recorded 5,778-byte export. Its digest is
  `2e8cbd2d56326b44e9cbe524f46d933a99748293f7e2a062dad93a6237ffaa3d`.
- `fixture_coins` currently prints `base.canonical.len()` (5,670 bytes),
  not a coin count. The fixture has 105 of these 54-byte records. Report
  separate byte and record counts.
- The summary's `tip` is the genesis hash, not a scenario's terminal tip.
  Label it `genesis_hash` or record the actual scenario boundaries.
- `first_diff` inserts Rust `Debug` output for `Option<(OutPoint, Coin)>`
  directly into JSON (`Some(...)`/`None`), which is invalid JSON. The normal
  rejection strings are also interpolated without JSON escaping. Use a JSON
  serializer for all records and exercise a deliberate mismatch to verify
  the diagnostic stream parses and the harness exits nonzero.
- Preserve canonical exports as artifacts along with their digests so byte
  comparisons are independently reviewable. Record commands, source/build
  identities, and exit status; retain the full release log after the repair.

**Next handoff**

Return one bounded repair pass: correct header/MTP continuation, expected
outcome/tip/state assertions, the isolated predicate fixtures above, and valid
machine-readable failure diagnostics. Include the independent fixture
reference and updated raw results. Amend experiment 77's claim to the scope
actually exercised. No new broad corpus scan or saturated benchmark is needed
to close these defects. Proceed with Gate 4 implementation/planning in
parallel where it does not depend on the unchecked contexts; do not treat the
current 14-case result as full approval of historical mainnet state replay.

**Codex follow-up: experiment 76 and Gate 3 acceptance**

Date: 2026-09-26. This follows the
[audit of experiments 72–75](IBD_SWE2_REVIEW_72_75_2026-09-26.md).
The [one-hour product objective](IBD_PRODUCT_OBJECTIVE.md) is unchanged.

Update: the [second repair review](IBD_SWE2_REVIEW_76_FOLLOWUP_2026-09-26.md)
records the subsequent fixes and current disposition. Retain this review's
Gate 3 acceptance requirements.

Review method: read the repaired source, regression definitions, saved corpus
manifest, replay JSONL, and census outputs; recompute their arithmetic. No
tests, benchmarks, corpus scans, or live-node operations were executed by Codex.
[Evidence and source hashes](evidence/2026-09-26-ibd-swe2-review-76.json) pin the
review. SWE-2 owns corrective implementation and execution.

**Disposition**

The file-identity repair, inclusion of coinbase sources, revised format,
regression definitions, and observed replay accounting address substantial
parts of the prior audit. The disassembly parser now reads instruction
mnemonics rather than raw bytes. The saved run has:

| Quantity | Recorded value |
| --- | ---: |
| Non-coinbase inputs | 671,771 |
| Individually resolved | 599,840, or 89.292% |
| Missing sources | 71,931 |
| Resolved inputs in excluded transactions | 82,021 |
| Executed inputs | 517,819, or 77.083% |
| ECDSA verification-helper attempts | 526,534 |
| Script-failing transactions | 0 |

Both identities hold for this zero-immaturity sample:

```
71,931 + 82,021 + 517,819 = 671,771
82,021 + 517,819 = 599,840
```

Gate 1 remains partly open because the census has a witness-serialization
defect and the invalid-maturity path does not fail the run. Gate 2 remains
partly open because the claimed matched calibration is still a scaled-window
comparison. Gate 3 can proceed as an independent bounded state experiment
while these specific corrections are completed; it must not inherit their
unchecked claims.

**P1 — Correct the witness offset before accepting the census across eras**

In [`ibd_census.py`](../tools/ibd_census.py), `census_tx(block, tx_start)` walks
the whole block, so its returned `wit_start` is block-relative. Line 301 uses
it as the end index of `txraw[6:rec["wit_start"]]`, although `txraw` starts at
the transaction. This includes bytes that do not belong in the stripped
serialization and produces the wrong txid for witness transactions. The
separately calculated stripped *length* can be correct while the hashed bytes
are wrong.

Use one coordinate system consistently, for example a transaction-relative
witness offset, and assert that the reconstructed byte length matches the
calculated stripped length. Add a witness transaction at a nonzero offset
inside a multi-transaction block; compare its exact stripped bytes, txid,
wtxid, and block Merkle root with an independent existing decoder/reference.
A standalone transaction at offset zero is not sufficient to expose this bug.

The 189/189 Merkle checks were on a pre-SegWit file and do not exercise this
branch. I located the corrected output in `/tmp/census-fixed`: it records
38,658,394 estimated legacy compressions and 189 verified roots. That confirms
the reported output exists, not that its witness path was tested. Archive
this output and `/tmp/census-690` with versioned provenance; the similarly
named JSONs in `experiments/results/census-2026-09-26/` still contain v1 values.

The census also increments `merkle_mismatch` without making its command fail.
In a run claiming a valid corpus, a mismatch must yield nonzero status. Preserve
diagnostic output, and separately label any deliberate malformed-input mode.

**P1 — Invalid maturity must fail the correctness run**

[`corpus_replay.rs`](../crates/avila-consensus/examples/corpus_replay.rs)
increments `excluded_immature_txs` and continues at lines 185–188. Its later
`any_failed` flag is set only by script failures in admitted tasks. A corpus
containing an immature coinbase spend can therefore exit successfully after
silently excluding that transaction from the script workload.

This does not invalidate the supplied run's zero-immaturity measurements.
It does leave the negative correctness gate unfinished. In valid-corpus mode,
detected immature spends must cause failure even when other inputs are missing.
Keep missing-source incompleteness distinct from detected consensus invalidity.
Likewise, a source-txid mismatch is currently counted and converted into an
unresolved source by the builder; it should fail a run that claims successful
identity validation instead of merely shrinking its sample.

Add a replay-level regression with one mature and one immature input in the
same transaction. The present counters count the single immature input, but
drop both inputs without a bucket for all inputs excluded by immaturity.
Add that complete bucket and explicit reconciliation assertions. Test a
transaction containing both a missing source and an immature source as well.
The existing Python test verifies the builder's metadata/flagging, not the
Rust driver's final exit status.

Validate that source-vector length equals transaction input count and that
worker counts are positive. A zero-worker run must not report successful
completion without doing the declared work.

**P1 — Replace scaled-window agreement with an actual matched calibration**

The recorded calculation is:

```
whole-window structural DER items:              680,168
executed input share:                           517,819 / 671,771
structural items times that share:              524,291.632
observed verification-helper attempts:           526,534
relative difference:                            -0.426%
```

That arithmetic reproduces the reported approximately 0.5% difference. It
assumes excluded and executed transactions have the same signature density,
which is precisely what the calibration needs to test. Selection depends on
all inputs being available and is not a random sample.

Export the identities of the exact admitted transactions/inputs using block
hash and transaction/input position, not txid alone. Run the structural
counter only on that identical set and verify matching selection digests.
Compare ECDSA/Schnorr attempts, parse failures, early exits, false results,
multisig retries, and actual hash work by category. Explain the differences
rather than multiplying by a coverage ratio.

This can be done on the existing 517,819-input subset. It does **not** require
first building a complete historical index or reaching 100% resolution.
Until then, replace “calibrated approximately exact” in LOG/report conclusions
with “whole-window density extrapolation agrees within approximately 0.5%;
matched-subset calibration pending.”

**Measurement semantics to preserve**

The single-worker run records 59.465 seconds wall, 819.6 ms accumulated
sighash elapsed time, and 57,512.8 ms verification-helper elapsed time. The
ratios are approximately 1.378% and 96.717% for this selected workload. That
supports focusing on verification in this run. It is not an era-wide profile
or an executed SHA-compression census.

With eight workers, summed sighash plus helper elapsed time is 114.4595
seconds while wall time is 14.545 seconds. Intervals overlap across threads;
these totals must not be presented as wall-clock percentages. `Instant`
measures elapsed time, including descheduling, rather than thread CPU time.
Shared precomputation outside those timed regions needs separate accounting.

The new counters surround `verify_ecdsa_signature`/`verify_schnorr_signature`.
Those helpers can return during key/signature parsing without invoking the
curve verifier. Thus “helper attempts” is supported; comments calling these
actual libsecp verify calls are too strong. Add separate backend-entry and
early-return counters if backend work is the desired unit. A sighash function
call likewise does not count actual SHA compressions or cached work.

The two saved replay files represent different runs: `replay.jsonl` has
0.374/0.191 seconds preparation and four worker counts; `replay-v2.jsonl`
has 0.812/0.215 seconds preparation and instrumented 1/8-worker runs. Keep
each row tied to its own build and run rather than combining their setup
numbers. Record RSS high-water after the worker runs too; the current sample
is taken before they start. Builder/index creation remains outside this
replay timer and must be measured separately.

Global atomics in the hot path can affect throughput. Preserve an isolated
instrumentation build or measure its effect against the otherwise identical
uninstrumented build in the later quiet-host comparison. The slower shared-host
run alone does not identify whether counters, scheduling, or another factor
caused the difference.

**Other census corrections needed before calling Gate 1 complete**

- `pushes()` represents `OP_0` as `("push", b"")`, while
  `n_in_multisig_shape()` requires `("op", b"\x00")`. The multisig shape
  branch is therefore unreachable with this tokenizer, leaving the redeem
  script length estimate on the fallback path. Add a conventional multisig
  scriptSig regression and correct the classification contract.
- Witness shared hashes are charged a fixed six compressions inside the
  input loop even though the comment says per transaction. Account for real
  component lengths, reuse, applicable signature versions, and hash modes;
  otherwise keep this explicitly as an uncalibrated heuristic.
- The witness-commitment coinbase leaf is zero, not its ordinary wtxid.
  Avila already does this in
  [`Block::witness_merkle_root`](../crates/avila-consensus/src/block.rs).
  Do not count an unnecessary coinbase-wtxid computation as required work.
- `hashtype_of()` normalizes unrecognized low bits to `1`, potentially losing
  `ANYONECANPAY` semantics. Preserve the raw byte and model the actual
  interpreter behavior. BIP143's fixed hash slots remain present when filled
  with zero; its documentation should not describe them as removed slots.
- Retain structural labels where actual scriptCode or execution is unknown.
  The whole-history sampling gaps and range generator from the prior review
  remain open; this repaired window does not close them.

Retractions currently follow old unqualified claims in the reports. Mark those
older interpretation sections as superseded or rewrite the current conclusions,
while preserving raw historical measurements. Also remove the blanket claim
that script success authenticates a supplied scriptPubKey. Script verification
checks the supplied script; permissive replacement scripts can pass. Recomputing
the source txid binds both output amount and script to that transaction under
the hash assumption. Establishing selected-chain membership and spendability
is a separate job for the state/provenance checks.

**Gate 3 work order: close a bounded state transition exactly**

1. **Fix the boundary and corpus.** Pin the initial tip/hash and complete
   starting UTXO state. Select a contiguous chain ending at a pinned tip, with
   parent linkage and block identity established. Record how the initial state
   was produced and checked. A supplied state is a test fixture, not evidence
   of first-launch validation of the preceding history. Do not interpret raw
   block-file ranges or coinbase height guesses as a contiguous selected chain.
2. **Implement explicit state predicates.** Retain creation/spend position,
   occurrence identity, multiplicity, value, script, creation height, and
   coinbase status. Check input availability, duplicate spends, same-block
   ordering, maturity, permitted duplicate creation and historical exceptions,
   value ranges/conservation, per-block fees/subsidy, and applicable lock/sequence
   rules. Account for genesis and provably unspendable outputs consistently
   with normal validation. Reuse script results only under the exact checked
   transaction/prevout/flag context.
3. **Compare canonical state, not database layout.** Export both results as
   identically sorted complete coin records: outpoint, amount, exact script
   bytes, creation height, and coinbase flag, with explicitly fixed serialization.
   Require byte-for-byte equality of those exports and the expected final tip;
   include counts/totals/digests as diagnostics. Internal database pages can
   differ without a logical state difference.
4. **Test rejection as well as successful replay.** Include double spends,
   future outputs, earlier/later same-block sources, immature coinbases,
   wrong amounts, excess rewards, duplicate-transaction cases/exceptions,
   unspendable outputs, and lock/sequence boundaries. The batch and incremental
   paths must agree on rejection/validity and the last valid state; their
   internal detection order need not match. Use independently checked Bitcoin
   fixtures/reference results for critical rules so shared parser/helper bugs
   cannot make two implementations agree incorrectly.
5. **Separate correctness and scaling.** First establish the bounded result
   with zero unexplained differences. Then measure build, partition/sort/join,
   payload recovery, all reads/writes, peak RAM, temporary disk, and durable
   survivor output. A successful in-memory fixture establishes semantics for
   that case; external-memory throughput and full-chain cost remain separate
   gates. Preserve commands, build/source hashes, successful and failing exit
   logs, raw results, and relevant release-test output.

The next handoff should close the witness-offset and invalid-run regressions,
provide the exact-subset calibration, and report Gate 3 under this boundary.
There is no need to repeat the original CPU-floor debate or change hardware
targets while those concrete checks are pending.

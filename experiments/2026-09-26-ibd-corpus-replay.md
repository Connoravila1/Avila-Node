# Candidate 41 — corpus-parallel script replay (prevouts from blocks, not UTXO set)

Date: 2026-09-26. Status: measured on real mainnet data; correctness check
passed on the resolved subset. This is a replay experiment, not a production
change — no live code paths touched.

## Question (work order phrasing)

Does removing prevout production from the serial connect path improve total
validation throughput at bounded memory cost, vs the existing worker-pool
baseline?

## Method

- `tools/ibd_corpus_window.py` scans raw blk records (plain framing),
  indexes every txid → occurrences of `(height, tx_index, file, offset)`,
  then resolves each window input's prevout to the **latest occurrence
  strictly before the spend position** `(spend_height, spend_tx_index)` —
  same-block earlier-tx spends included, BIP30-style re-creation handled,
  future sources excluded. Emits `corpus.bin` + `manifest.json` (source
  sha256s, coverage stats).
- `examples/corpus_replay.rs` (new, isolated): decodes txs, applies exact
  `block_script_flags(params, height, block_hash)` per block, runs the
  ordinary `check_input_scripts` per tx — interpreter, sighash, and pinned
  verifier unchanged. Work-stealing counter across N threads.
- Window: `data/mainnet/blk00690.dat` (heights 340787–342234, 449 blocks,
  247,193 txs, 671,771 non-coinbase inputs).

## First result — self-resolved window (index = window file only)

Span: just blk00690 → 356,732 inputs (53.1% of window inputs) resolvable
entirely within this ~1,448-block window; 171,901 txs fully resolved.
All resolved scripts executed against corpus-extracted prevouts:

| workers | inputs/s | µs/input | scaling |
|---|---|---|---|
| 1 | 10,863 | 92.06 | 1.00× |
| 2 | 20,657 | 48.41 | 1.90× |
| 4 | 39,566 | 25.27 | 3.64× |
| 8 | 48,858 | 20.47 | 4.50× |

**failed = 0 across all 356,732 checks.** Any mis-resolved prevout (wrong
scriptPubKey or amount) breaks the sighash and fails verification — zero
failures is strong evidence the occurrence/ordering model is byte-exact.
Also measured: the same-era serial connect path does ~330 ms/block live;
449 blocks' resolved script work finished in 7.3 s at 8 workers
(~16 ms/block-equivalent) — but the resolved subset covers ~53% of inputs,
so per-input rates are the honest unit.

## Interpretation

- The premise behind corpus-parallel validation holds on real data: script
  checks need only `(tx, prevouts, flags)` and all of it lives in the block
  corpus — no UTXO store in the loop.
- 8-worker scaling flattens at ~4.5× on the N305 (8 E-cores, shared host
  with live IBD, single-channel-ish memory) — kernel throughput-bound, not
  coordination-bound. On a quiet host expect closer to 6–7×.
- ~47% of this window's prevouts are older than ~10 days — resolution
  coverage rises with span depth; the span-dependency curve is itself a
  finding (UTXO age distribution sets index memory and miss-rate).
- First failure mode found: memory/quota bounds — a 21-file Python index
  (~10M tx entries) exceeded /tmp capacity (tmpfs 16 GB, ~3 GB free).
  Indexing the full 58 GB corpus needs a disk-backed or packed format —
  noted for the production design (the real implementation would store a
  compact sorted index, not a Python dict).

## Second result — 10-file span (h~335.5k–342.2k as source corpus)

`target/ibd-corpus/341k` manifest: **598,267 / 671,771 inputs resolved
(89.1%)** — the ~5,000 preceding blocks (~5 weeks) lifted coverage from
67% → 89%; residual 11% spends UTXOs older than ~5 weeks. Replay over
222,745 fully-resolved txs / 515,779 inputs:

| workers | inputs/s | µs/input | scaling |
|---|---|---|---|
| 1 | 10,810 | 92.51 | 1.00× |
| 2 | 20,373 | 49.08 | 1.88× |
| 4 | 36,242 | 27.59 | 3.35× |
| 8 | 49,255 | 20.30 | 4.56× |

failed = 0 again. Consistent per-input cost (~92µs serial) matches the
measured ~95µs/verify on the ecdsa-replay trace — the corpus path does not
change the per-check cost, only removes the serial fetch.

## Coverage-vs-span relationship (measured)

| source span depth | resolved share of window inputs |
|---|---|
| window only (~1.4k blocks, ~10 days) | 67.2% |
| +5k blocks (~5 weeks) | 89.1% |

Extrapolation for full-history resolution at h~341k: the remaining ~11%
tail needs arbitrarily old sources — a full txid index of everything since
genesis is the production-shaped answer (or undo/UTXO bootstrap as the
cold-start source; either way the *query shape* is index lookup, not
serial maintenance).

## Next

- Extend replay to the taproot Core slice (undo-supplied prevouts there;
  different provenance label).
- Full-corpus index memory is the open cost — needs packed/sorted on-disk
  format for the real design.

## Corrections (post-audit, experiment 74)

The Codex audit (docs/IBD_SWE2_REVIEW_72_75_2026-09-26.md) found four
defects in this experiment's first pass. Status after repair:

1. **Source-identity bug — REAL, FIXED.** Pass-3 lookups keyed on
   `(record_offset, tx_offset, vout)` dropped the file index; identical
   offsets in different files could alias. Repaired: the full occurrence
   `(fi, off, tstart, tlen, vout)` is carried end-to-end and the source
   txid is recomputed and asserted at fetch time. A deterministic
   multi-file collision regression (`tools/test_ibd_corpus_window.py`)
   proves the fix. V2 corpus: 599,840 resolved, **0 identity mismatches**.
2. **Coinbase sources — FIXED.** Coinbase outputs were excluded from the
   index; they are spendable sources after maturity. Now indexed with
   creation height + flag carried into `AVCORP02`; maturity is enforced
   separately from availability. V2 manifest: 0 immature refs in-span.
3. **Executed-share wording — CORRECTED.** 89.1% is per-input resolution;
   executed inputs were 515,779/671,771 = **76.8%** (v2: 517,819/671,771
   = **77.08%**; 82,021 resolved inputs sat in partially-unresolved txs
   and were never executed). The new counters reconcile exactly.
4. **"0 failures ⇒ byte-exact prevouts" — CORRECTED.** In this
   pre-segwit window, legacy sighash does NOT commit the spent amount
   (BIP143 motivation): a wrong `value` survives script verification.
   Zero failures authenticate the supplied scriptPubKey (committed) but
   NOT the amount — amounts must be verified by state/provenance
   checks (Gate 3). Some inputs carry no signature at all and
   authenticate nothing.

   Withdraw "serial connect is dead". Supported: "parallel script
   replay over corpus-resolved prevouts executes this resolved subset
   at ~8.7k–35.6k inputs/s (1→8 workers, shared host) with zero script
   failures on supplied metadata." The script-stage timer excludes
   corpus build, parse, decode, and task allocation (prep: 0.37s parse +
   0.19s task build, 161.8 MB corpus, 451 MB RSS HWM — now reported).

   Executed-instrumented run (v2): 526,534 ECDSA sighash calls ==
   526,534 verify attempts (ratio to executed inputs: 1.017 — the
   multi-sig tail); 0 schnorr; sighash = 1.4% of check-stage time vs
   verify ~97%. Sighash-Ns wraps preimage serialization, so compression
   counts can't be recovered from it directly.

## Experiment 76 follow-up corrections

- **Witness-offset defect (census) — FIXED & VERIFIED.** `wit_start`
  was block-relative but used on a tx-relative slice. Now
  `wit_start_rel` with a byte-length assertion; re-run on the
  taproot-era Core slice: **83/83 merkle-verified** — the path that was
  previously unexercised now verifies end-to-end. Census exits nonzero
  on `merkle_mismatch`. Census outputs archived to
  `experiments/results/census-2026-09-26/` (v2 superseding v1 files).
- **Rejection paths — FIXED.** `corpus_replay` exits nonzero on
  detected consensus invalidity (immature coinbase sources) AND script
  failures; missing sources remain incompleteness, not invalidity.
  `ibd_corpus_window` exits nonzero on `txid_identity_mismatch` instead
  of silently shrinking the sample. New buckets:
  `inputs_excluded_by_immaturity` (ALL inputs of immature-excluded txs)
  and `resolved_inputs_in_immature_txs`; exact reconciliation asserts
  on both missing+resolved and resolved decomposition. Immature-first
  ordering puts a missing+immature tx in the immature bucket. Replay
  regression (actual binary): mature+immature in one tx and
  missing+immature in another → `excluded_immature_txs=2`, exit 1;
  `--workers 0` → exit 2. `outs.len() == tx.inputs.len()` asserted.
- **Matched-subset calibration — DONE.** `corpus_replay` emits
  `executed_set_digest` (sha256 over blockhash‖u32 txidx per admitted
  tx); `tools/ibd_matched_calib.py` reconstructs the identical set from
  the corpus and matches digests (both `2276ffea…`). Structural DER
  over the *identical* executed set: **524,092** vs executed
  **526,534** = ratio **0.9954** (−0.46%): the deficit is lax-parsed
  signatures that fail the strict DER-shape filter but still reach
  `verify_ecdsa_signature` — explained, not extrapolated. Backend split
  measured: 526,534 attempts → 526,528 backend calls (6 early-returns,
  0.001%).
- **Counter naming corrected.** "verify attempts" (helper entry) vs
  "backend calls" (libsecp entry) are now distinct counters —
  `ECDSA_VERIFY_CALLS` vs `ECDSA_VERIFY_BACKEND_CALLS`, schnorr same.
  sighash-Ns wraps preimage serialization + hash, not compressions.
  Post-run `final` record carries RSS HWM after worker runs.
- **Remaining census fixes:** OP_0-as-empty-push multisig shape
  (previously unreachable — now detects the dummy push); shared-hash
  comps moved per-tx with real component lengths and per-htype need
  union (hashPrevouts/Sequence/Outputs); coinbase wtxid leaf = zero,
  not hashed; `hashtype_of` preserves the raw byte (invalid base
  behaves as ALL under the interpreter; ACP applies independently).

## Follow-up audit items closed (2026-09-26, second pass)

- **0.46% cause measured, not hypothesized.** New callsite counters
  classify each `check_ecdsa_signature` attempt by strict DER shape
  (same predicate as the structural census). Result on the identical
  executed set: `ecdsa_attempts_der` = 526,534 = ALL attempts,
  `ecdsa_attempts_nonder` = **0**. Lax-parse is eliminated as a cause.
  The +2,442 excess over the 524,092 structural DER *items* is DER
  items verified more than once — CHECKMULTISIG/CFCS retries against
  successive keys each enter the helper. Attempts ≥ items is the
  correct expectation; the matched-set ratio is 0.9954.
- **Artifacts preserved:** `experiments/results/gate76-followup/`
  holds `matched-calib.json` (digest-matched Python comparison),
  `regression-exit-log.txt` (resolver + replay rejection + 0-worker
  runs), `replay-v5.jsonl` (full counter set incl. backend/attempts
  split). Census v3 output archived at
  `experiments/results/census-2026-09-26/blk05625-v3.json`.
- **Clean test rerun:** `cargo test --release -p avila-consensus` —
  551 lib + 9 fault-inject + 19 property, **all pass**. The earlier 32
  failures were `/tmp` tmpfs `QuotaExceeded` (13G/16G used by live-path
  probe dirs), not code.
- **BIP143 SIGHASH_SINGLE gap closed:** the shared-hash model now
  charges the per-input single-output hash (sha256d of output_i's
  serialization) for each SINGLE witness input with i < n_out —
  previously omitted. blk05625 re-run: shared comps 2,382,042 →
  2,382,147; merkle still 83/83.

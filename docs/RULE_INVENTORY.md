# Consensus rule and fixture inventory

**Status: header-chain rules, context-free and header-context block/transaction
structure, UTXO-state transition rules, and script execution (including
signature verification) are implemented and tested.** This inventory is the
G1 "rule-to-test inventory" required by the [roadmap](../ROADMAP.md). It enumerates
every consensus rule `avila-consensus` implements, the evidence backing it, and the
rules it deliberately does not yet implement. Header validation alone is not full
validation — a header tree that accepts a header says nothing about the block's
transactions.

Anchors name the Bitcoin Core source function the implementation reproduces.
"Fixture" coverage means committed real-chain data under `fixtures/` (see
`fixtures/manifest.json` for provenance and `fixtures/README.md` for regeneration
via `tools/fetch_fixtures.py`). "Differential" means checked against the pinned
`rust-bitcoin` dev-dependency (`bitcoin 0.32.102` in `Cargo.lock`). Property tests
live in `crates/avila-consensus/tests/property.rs` (`proptest`, deterministic
failure seeds in `tests/property.proptest-regressions`).

## Wire format and hashing

| Rule | Core anchor | Implementation | Valid coverage | Invalid coverage |
| --- | --- | --- | --- | --- |
| Fixed-width little-endian integers | `serialize.h` | `encode.rs` `Decoder` | Property round trips; all fixture decodes | Truncation errors; `read_bytes`/`read_array` bounded by input length |
| CompactSize, canonical (minimal) form required | `ReadCompactSize` (`serialize.h`) | `encode.rs` `read_compact_size`, `write_compact_size` | Differential vs `bitcoin::consensus::encode::VarInt` (encode + decode agreement); canonicality property (re-encode == consumed bytes) | Non-minimal encodings rejected; values `> MAX_SIZE` (0x02000000) rejected with `CompactSizeTooLarge`; truncated inputs rejected |
| Bounded vector decoding (no attacker-sized preallocation) | Core relies on `MAX_SIZE`/serialized limits | `encode.rs` `bounded_capacity`; applied in `transaction.rs`, `block.rs` | Fixture decodes; never-panic property tests | Declared-count-exceeds-input cases; preallocation bounded by remaining bytes (round-2 safety fix) |
| 80-byte block header serialization | `CBlockHeader` (`primitives/block.h`) | `header.rs` | Round-trip property over arbitrary 80 bytes; every fixture header; hash differential vs rust-bitcoin | Truncated input rejected |
| Transaction serialization, legacy and BIP144 marker/flag | `SerializeTransaction` (`primitives/transaction.h`) | `transaction.rs` | All block fixtures (incl. segwit- and taproot-era blocks with real witness data); stable-reencode property | Malformed bounded input never panics; superfluous-witness flag re-encodes canonically (shrinks) |
| `txid` / `wtxid` (BIP141) | `CTransaction::GetHash` / `GetWitnessHash` | `transaction.rs` | Fixture blocks incl. witness-carrying transactions; unit vectors | — |
| Double-SHA-256 hash types | `hash.h` | `hash.rs` | Header-hash differential property; fixture hash checks | — |
| Merkle root + CVE-2012-2459 mutation detection | `ComputeMerkleRoot` (`consensus/merkle.cpp`) | `merkle.rs`, `block.rs` | Differential property vs `bitcoin::merkle_tree::calculate_root` on arbitrary leaf sets; fixture blocks' `merkle_root` | Duplicated-subtree mutation flagged via the `mutated` out-param (unit tests) |
| Witness commitment structure (BIP141) | `GetWitnessCommitment` (`validation.cpp`) | `block.rs` `expected_witness_commitment`, `witness_commitment_output` | Segwit and taproot-era fixture blocks verify commitment | — |
| Hex | — | `hex.rs` | Round-trip property | Arbitrary strings never panic |

## Header-chain rules (per network `Params`)

`chain.rs` `HeaderTree::insert` applies these in Core's `AcceptBlockHeader` /
`ContextualCheckBlockHeader` order: known-header short-circuit → PoW → parent →
`bad-diffbits` → `time-too-old` → BIP94 timewarp → `time-too-new` → `bad-version`.

| Rule | Core anchor | Implementation | Valid coverage | Invalid coverage |
| --- | --- | --- | --- | --- |
| Proof-of-work sanity: non-negative, non-overflow, non-zero, ≤ `powLimit` | `CheckProofOfWork` (`pow.cpp`) | `pow.rs` `check_proof_of_work` | All fixture headers | Negative/overflow flag precedence, zero target, above-limit target each rejected (unit tests) |
| Header hash meets claimed target | `CheckProofOfWork` (`pow.cpp`) | `pow.rs` | All fixture headers; differential vs rust-bitcoin `is_met_by`-equivalent checks | Known header hashes rejected against tighter targets |
| Parent known / ancestry | `AcceptBlockHeader` | `chain.rs` | Fixture chains build to tips | `UnknownParent` on missing parent; `AlreadyKnown` on re-insert |
| Required `nBits` non-boundary: carry parent | `GetNextWorkRequired` (`pow.cpp`) | `pow.rs` `required_bits` | Every fixture header's observed `nBits` reproduced across all four runs | `WrongBits` on mismatch |
| Retarget at interval: new target from timespan ratio, clamped to ×4/÷4 | `GetNextWorkRequired`, `CalculateNextWorkRequired` | `pow.rs` | Mainnet's first real retarget (height 32256, `0x1d00ffff` → `0x1d00d86a`) replayed from the retarget-window fixture; differential vs rust-bitcoin retarget on all covered windows | Clamp edges unit-tested |
| Testnet minimum-difficulty exception (> 2× spacing ⇒ `nBits` = powLimit) | `GetNextWorkRequired` (`fPowAllowMinDifficultyBlocks`) | `pow.rs`, `Params::allow_min_difficulty_blocks` | testnet4 fixture run (which exercises min-difficulty blocks); regtest params | Boundary timing cases unit-tested |
| No-retarget networks | `fPowNoRetargeting` | `Params::no_retargeting` | regtest params carry it | — |
| BIP94 retarget base = *first* block of previous period | `GetNextWorkRequired` (`enforce_BIP94`) | `pow.rs`, `Params::enforce_bip94` | Synthetic regression separating first-vs-last base (fixtures mask it: early testnet4 is uniformly min-difficulty) | — |
| BIP94 timewarp floor: boundary `nTime ≥ parent.nTime − 600` | `ContextualCheckBlockHeader` (`MAX_TIMEWARP`) | `rules.rs` `check_block_time` | BIP94-off control on identical chain shape | `TimeError::Timewarp` at floor − 1; inclusive floor accepted |
| Median-time-past (`time-too-old`: `nTime > MTP(parent)`) | `ContextualCheckBlockHeader` | `rules.rs` `median_time_past` | All fixture headers | `TimeError::TooOld` boundary unit tests |
| Future drift (`time-too-new`: `nTime ≤ now + 2h`, caller-supplied clock) | `MAX_FUTURE_BLOCK_TIME` | `rules.rs` | All fixture headers | `TimeError::TooNew` unit tests |
| Header version floors: `nVersion < 2`/`< 3`/`< 4` once BIP34/BIP66/BIP65 govern the height (`bad-version`) | `ContextualCheckBlockHeader` (`validation.cpp`), heights from `DeploymentActiveAfter`/`DeploymentHeight` (`deploymentstatus.h`, `consensus/params.h`) | `chain.rs` `HeaderTree::insert` (`ChainError::BadVersion`), heights in `params.rs` `Params::bip34_height`/`bip66_height`/`bip65_height` | All fixture headers (real mainnet/testnet4/signet versions all clear every floor active at their heights); regtest version 4 accepted; mainnet-shaped params isolate a version-1 header below `bip34_height` | Regtest (all three floors buried at height 1) rejects versions 1, 2 and 3 each for the specific floor that first fires, and negative versions; genesis is exempt (never run through `insert`); `bad-diffbits` takes precedence when a header fails both |
| Cumulative chainwork; best tip = strictly greatest work | `CBlockIndex::nChainWork`, `ActivateBestChain` tip comparison | `arith.rs` `Work`, `chain.rs` | Fixture chains reproduce real cumulative work; differential per-block work vs rust-bitcoin | `ChainWorkOverflow` guard; equal-work fork does not displace tip |
| Height accumulation | `CBlockIndex::nHeight` | `chain.rs` | Fixture heights | `HeightOverflow` guard (`u32::MAX` parent) |

## Transaction and block structure (`check.rs`, `script.rs`)

`check.rs` ports the non-UTXO, non-execution parts of Core's `CheckTransaction`
(`consensus/tx_check.cpp`), `CheckBlock` and `ContextualCheckBlock`
(`validation.cpp`); `script.rs` provides the structural script model those rules
consult (`GetOp`-equivalent instruction iteration, `GetSigOpCount`, `IsPushOnly`,
`IsPayToScriptHash`, `IsWitnessProgram`, `CScriptNum`/push encodings). Every error
exposes Core's reject-reason string via `RuleError::reason`, and the block-level
differential adapter (`tools/check_blocks_core.py` + `examples/check_blocks.rs`)
verifies those reasons against a live daemon's `submitblock`: **259 corpus
submissions and 9 real block fixtures compared, zero unexplained mismatches**, plus
a contiguous **501-block real mainnet segment** (heights 0..=500,
`fixtures/mainnet-blocks-000000-000500.dat`) and a **301-block signet segment**
(heights 0..=300 — 300 real BIP325 challenge-spend verifications) replayed
through `Chainstate` and the daemon with zero mismatches —
every named violation above returns Core's exact reason, including the
order-dependent cases (`bad-blk-length` beats `bad-txns-oversize`;
`bad-txns-duplicate` fires only for a natural-pair leaf duplication, matching
Core's scan-before-padding merkle semantics). Valid controls include a height-2
child the daemon actually connects, a witness-committed block, a duplicate
resubmission (`accepted-known` ↔ `duplicate`), a 101-block baseline chain the
daemon connects end-to-end, a 104-block side branch that triggers a real reorg
(both sides disconnect 103 blocks and reconnect the fork identically), real
signed spends for every standard output type (P2PKH, P2SH-P2WPKH, P2WPKH,
P2WSH, taproot key-path and script-path — including one high-S P2PKH spend),
and a 501-block contiguous mainnet segment whose real historical spends
connect through our full UTXO path. The first run caught a real divergence: `push_int` used raw
data pushes for heights 1..=16 where `CScript() << nHeight` emits
`OP_1..OP_16` — fixed, with the daemon's `bad-cb-height` as the witness. The
segment replay caught a second: mainnet block 183's historical high-S ECDSA
signature failed verification until `check_ecdsa_signature` was aligned with
Core's `CPubKey::Verify` (parse DER-lax → `secp256k1_ecdsa_signature_normalize`
→ verify) — now pinned by the block-183 regression test and corpus case
`82-high-s-p2pkh`. One
documented layer difference: our 4,000,000-byte block-decode cap pre-rejects
what Core reports as `bad-blk-weight` (any block that size is necessarily
overweight, so the verdict is identical; only the layer differs). The signet
fixtures match too: genesis is exempt per Core's `CheckSignetBlockSolution`
short-circuit, and block 1's real BIP325 solution (a 1-of-2 bare-multisig
challenge spend) verifies through our interpreter on both sides.

| Rule | Core anchor | Implementation | Valid coverage | Invalid coverage |
| --- | --- | --- | --- | --- |
| `vin`/`vout` non-empty (`bad-txns-vin-empty`/`bad-txns-vout-empty`) | `CheckTransaction` | `check::check_transaction` | All fixture block transactions | unit tests |
| Base-size limit: `size(no-witness) × WITNESS_SCALE_FACTOR ≤ MAX_BLOCK_WEIGHT` (`bad-txns-oversize`) | `CheckTransaction` | `check_transaction` | All fixture transactions | 1 MB `scriptSig` unit test |
| Output value range: `0 ≤ v ≤ MAX_MONEY` per output and for the running total (`bad-txns-vout-negative`/`-toolarge`/`bad-txns-txouttotal-toolarge`, CVE-2010-5139) | `CheckTransaction`, `MoneyRange` | `check_transaction` (checked `i64` accumulation) | All fixture transactions | negative / over-limit / overflowing-total unit tests |
| Duplicate inputs (`bad-txns-inputs-duplicate`, CVE-2018-17144) | `CheckTransaction` | `check_transaction` (`HashSet<OutPoint>`) | All fixture transactions | duplicated-input unit test |
| Coinbase `scriptSig` length 2..=100 (`bad-cb-length`); non-coinbase inputs may not spend the null outpoint (`bad-txns-prevout-null`) | `CheckTransaction` | `check_transaction` | All fixture coinbases | boundary lengths 0/1/101; null prevout in a multi-input tx (single-input-null is a coinbase by definition) |
| Block header PoW inside `CheckBlock` (`high-hash`) | `CheckBlockHeader` | `check::check_block` → `pow::check_proof_of_work` | All fixture blocks | claimed `nBits` above a custom `pow_limit` |
| `hashMerkleRoot` match (`bad-txnmrklroot`) and CVE-2012-2459 mutation flag (`bad-txns-duplicate`) | `CheckMerkleRoot` | `check_block` via `block.rs` `merkle_root` | All fixture blocks | corrupted-root unit test; identical-coinbase duplication exercises the mutation path |
| Block size limits: non-empty, `tx_count × 4 ≤ MAX_BLOCK_WEIGHT`, `size(no-witness) × 4 ≤ MAX_BLOCK_WEIGHT` (`bad-blk-length`) | `CheckBlock` | `check_block` | All fixture blocks | — (empty-block case unreachable through the checked API: it fails `bad-blk-length` first) |
| First tx is coinbase (`bad-cb-missing`); no other tx is a coinbase (`bad-cb-multiple`) | `CheckBlock` | `check_block` | All fixture blocks | non-coinbase-first and two-coinbase unit tests |
| Per-transaction `CheckTransaction` inside `CheckBlock` | `CheckBlock` | `check_block` → `check_transaction` | All fixture blocks | propagated `TxRuleError` unit tests |
| Legacy sigop budget: `Σ legacy sigops × 4 ≤ MAX_BLOCK_SIGOPS_COST` (`bad-blk-sigops`) | `CheckBlock`, `GetLegacySigOpCount`, `CScript::GetSigOpCount` | `check_block`, `script.rs` `Script::sig_ops` (incl. accurate-multisig `OP_N` decode and malformed-script early stop) | All fixture blocks; opcode-counting unit tests | 20_001-op `scriptPubKey` unit test |
| Transaction finality vs `nLockTime` cutoff (`bad-txns-nonfinal`); BIP113 moves the cutoff to parent MTP once CSV is active | `ContextualCheckBlock`, `IsFinalTx` | `check::contextual_check_block`, `check::is_final_tx` | All fixture blocks; lock_time/sequence boundary unit tests | non-final height- and time-locked txs; missing-MTP context error |
| BIP34 height-in-coinbase prefix (`bad-cb-height`) | `ContextualCheckBlock` (`CScript() << nHeight`) | `contextual_check_block`, `script.rs` `push_int`/`encode_script_num` | Real post-activation fixture blocks; `encode_script_num` vs Core's `scriptnum_tests` vectors | wrong-height coinbase; pre-activation control (rule off below `bip34_height`) |
| BIP141 witness commitment: when segwit is active a present commitment must verify (`bad-witness-nonce-size` / `bad-witness-merkle-match`); an absent commitment — or inactive segwit — forbids witness data entirely (`unexpected-witness`) | `ContextualCheckBlock`, `CheckWitnessMalleation`, `GetWitnessCommitmentIndex` | `contextual_check_block`, `block.rs` `witness_commitment_output`/`expected_witness_commitment`/`witness_merkle_root` | Segwit-era and taproot-era fixture blocks (both carry real commitments and witness data) | nonce-stack arity/size, corrupted commitment hash, witness-without-commitment (segwit active and inactive) |
| Block weight ≤ `MAX_BLOCK_WEIGHT`, checked *after* witness-commitment verification (`bad-blk-weight`) | `ContextualCheckBlock` | `contextual_check_block` | All fixture blocks | ~4 MB-witness unit test |
| Signet block solution (BIP325) | `CheckSignetBlockSolution` in `CheckBlock` (genesis exempt; synthetic to_spend/to_sign construction; `FetchAndClearCommitmentSection`; modified merkle root; `VerifyScript` with P2SH\|WITNESS\|DERSIG\|NULLDUMMY) | `signet.rs` | signet genesis (exempt) and block 1's real 1-of-2-multisig solution verify identically to the daemon | corrupted-solution unit test; malformed/missing-commitment and trailing-data paths return `bad-signet-blksig` |

## UTXO-dependent rules (`connect.rs`)

`connect.rs` ports `ConnectBlock` in full, including `CheckInputScripts`: the
`UtxoSet` (`CCoinsView` semantics — unspendable outputs never stored, spent
coins removed), `Consensus::CheckTxInputs`, `CalculateSequenceLocks`/
`EvaluateSequenceLocks` (BIP68), `GetTransactionSigOpCost`, `GetBlockSubsidy`,
`GetBlockScriptFlags` (`ScriptFlags` + `block_script_flags` in `script.rs`),
and per-transaction script verification (`sigchecker.rs` —
`PrecomputedTransactionData`, legacy/BIP143/BIP341-BIP342 sighashes, ECDSA and
schnorr verification, taproot commitment checking). Two deliberate design
departures with identical verdicts:
atomicity comes from in-place rollback via recorded undo rather than a
discarded `CCoinsViewCache` layer, and `BlockUndo` keeps one entry per
transaction *including* the coinbase — which is why `disconnect_block`
restores even the BIP30-repeat overwrite cases that force Core's
`IsBIP30Unspendable` exceptions (Core's n−1 on-disk layout is a serialization
concern, not an in-memory one). Every error maps to Core's reject reason via
`ConnectError::reason`; the corpus's connect-phase cases (61–72 in
`gen-corpus`) exercise each rule on tip-extending blocks the daemon actually
connects, and the library `chainstate::Chainstate` runs `connect_block` on the
same boundary the daemon does.

| Rule | Core anchor | Implementation | Valid coverage | Invalid coverage |
| --- | --- | --- | --- | --- |
| Input availability — every input's outpoint names an unspent coin, all inputs checked before maturity/value (`bad-txns-inputs-missingorspent`) | `HaveInputs` + `CheckTxInputs` | `connect::check_tx_inputs` (two-pass: collect-then-check) | all connected corpus blocks | missing outpoint and already-spent input (corpus 62/63, unit tests) |
| Coinbase maturity: `spend_height - coin_height >= 100` (`bad-txns-premature-spend-of-coinbase`) | `CheckTxInputs` | `check_tx_inputs` | depth-100 spend at h102 (corpus 61, unit test) | depth-49/depth-99 spends (corpus 64, unit test) |
| Input values and running total inside `MoneyRange` (`bad-txns-inputvalues-outofrange`) | `CheckTxInputs`, `MoneyRange` | `check_tx_inputs` | all connected corpus blocks | over-`MAX_MONEY` coin and overflowing pair (unit tests) |
| `value_in >= value_out` (`bad-txns-in-belowout`) | `CheckTxInputs` | `check_tx_inputs` | all connected corpus blocks | output = input + 1 (corpus 65, unit test) |
| Fee in `MoneyRange`, accumulated fees in range (`bad-txns-fee-outofrange`, `bad-txns-accumulated-fee-outofrange`) | `CheckTxInputs`, `ConnectBlock` | `check_tx_inputs`, `connect_block` | all connected corpus blocks | checked-arithmetic overflow paths (unit-level) |
| BIP30 duplicate-output ban with the two repeat-block exceptions; skipped once the known chain passes `bip34_hash`, always on at height ≥ 1,983,702 (`bad-txns-BIP30`) | `ConnectBlock`, `IsBIP30Repeat`, `BIP34_IMPLIES_BIP30_LIMIT` | `enforce_bip30` + pre-application scan; `add_tx_outputs` permits coinbase overwrite with undo | repeat/overwrite permitted on a skipped-chain unit test | duplicate txid with unspent outputs (corpus 67, unit test) |
| BIP68 sequence locks when CSV is active: disable flag, height locks (`coin_height + seq - 1 < block_height`), time locks (`coin-ancestor-MTP + (seq<<9) - 1 < parent_MTP`), version < 2 exemption (`bad-txns-nonfinal`) | `SequenceLocks`/`CalculateSequenceLocks`/`EvaluateSequenceLocks`, `DeploymentActiveAt` | `connect::bip68_locks_satisfied` | satisfied height lock and disabled flag (corpus 72, unit tests) | unsatisfied height and time locks (corpus 68/69, unit test) |
| UTXO-dependent sigop cost: legacy × 4 always, P2SH × 4 under `SCRIPT_VERIFY_P2SH`, witness per `CountWitnessSigOps` under `SCRIPT_VERIFY_WITNESS`, block total ≤ `MAX_BLOCK_SIGOPS_COST` (`bad-blk-sigops`) | `GetTransactionSigOpCost`, `CountWitnessSigOps` | `tx_sigop_cost`, `Script::p2sh_sig_ops`, `count_witness_sig_ops` | all connected corpus blocks | 20_001-CHECKSIG P2SH redeem and 80_001-CHECKSIG P2WSH witness script (corpus 70/71, unit tests) |
| Coinbase pays at most `subsidy + fees` (`bad-cb-amount`) | `ConnectBlock`, `GetBlockSubsidy` | `connect_block`, `block_subsidy` | subsidy+fees payment (unit test); plain subsidy (whole corpus) | subsidy + 1 with no fees (corpus 66, unit test) |
| Subsidy halving: `50 BTC >> (h / halving_interval)`, zero at 64 halvings | `GetBlockSubsidy` | `block_subsidy` | halving-boundary unit tests incl. regtest interval 150 | — |
| Script flags per block: base `P2SH\|WITNESS\|TAPROOT`, historical exception blocks, buried `DERSIG`/`CLTV`/`CSV`/`NULLDUMMY` ORed on | `GetBlockScriptFlags`, `script_flag_exceptions` | `block_script_flags` | gating exercised by every connected corpus block | — (exception-block coverage is a mainnet-sync case, noted below) |
| Script execution | `CheckInputScripts`, `EvalScript`, `VerifyScript`, `VerifyWitnessProgram` | `interpreter.rs` ports the full stack machine: all opcodes incl. `CHECKSIG`/`CHECKMULTISIG`/`CHECKSIGADD`, `CLTV`/`CSV`, conditionals, altstack, `CODESEPARATOR`, `FindAndDelete`, signature/pubkey encoding checks (DERSIG/LOW_S/STRICTENC/WITNESS_PUBKEYTYPE/MINIMALIF/MINIMALDATA/NULLDUMMY/NULLFAIL/CONST_SCRIPTCODE), P2SH stack restore, witness v0 (P2WPKH/P2WSH), taproot key/script path incl. control block, annex and `OP_SUCCESSx`, `OP_CHECKSIGADD`, validation-weight accounting. `sigchecker.rs` ports `SignatureHash` (legacy + BIP143), `SignatureHashSchnorr` (BIP341/342), `PrecomputedTransactionData`, `GenericTransactionSignatureChecker`, `CheckInputScripts`, and taproot commitment verification; ECDSA/schnorr via `secp256k1` (libsecp256k1 — the library Core links). Wired into `connect_block` at Core's position (after sequence locks and sigop accounting, before UTXO update). | 500 vendored Core `sighash.json` legacy vectors; BIP143/BIP341 sighash differential vs `bitcoin::sighash::SighashCache`; signed-spend corpus cases the daemon actually connects: legacy P2PKH, P2WPKH, P2WSH, taproot key-path, taproot script-path, P2SH-P2WPKH (corpus 73–79) | corrupted-signature P2SH spend rejects with the daemon's exact `mandatory-script-verify-flag-failed (...)` string (corpus 81); always-false spend + rollback unit test; 29 interpreter unit tests |
| Undo / disconnect: exact state restoration incl. spent inputs and overwritten coins | `DisconnectBlock`, `CBlockUndo`/`CTxUndo` | `disconnect_block`, `BlockUndo` (one `TxUndo` per tx incl. coinbase) | disconnect→pre-state and reconnect→same-state unit tests | — |

## Block acceptance (`chainstate.rs`)

`chainstate.rs` is the stateful driver — Core's `ProcessNewBlock` →
`AcceptBlock` → `ActivateBestChain` pipeline over `HeaderTree` (the block
index) + `UtxoSet` (the coins view): `CheckBlock` *before* the header enters
the index (Core's CVE-2012-2459 caution — a CheckBlock failure is never
cached), `AcceptBlockHeader`/`ContextualCheckBlockHeader` insertion, then
`ContextualCheckBlock`, body retention, and activation — tip-extension
connects and heavier-branch reorgs that disconnect to the fork point and
reconnect forward, committed atomically only when the whole branch connects.

Failed-block bookkeeping matches `mapBlockIndex`: `ContextualCheckBlock` and
`ConnectBlock` failures mark `BLOCK_FAILED_VALID` (except `BLOCK_MUTATED`-class
rejections, which never mark); children of a failed block are `bad-prevblk`
at header insertion — the direct-parent check before contextual header rules
and the failed-ancestor walk after it, which also marks intermediates
`BLOCK_FAILED_CHILD`; resubmitting a failed block is `duplicate-invalid`; and
a heavier branch containing a failed block is pruned from activation without
touching the active tip. Corpus cases 82–85 exercise all of these against the
daemon (`duplicate-invalid` resubmission, `bad-prevblk` child, and the two
orphan cases — child of a header-rejected block and child of a CheckBlock
rejection are both `prev-blk-not-found`, since the parent never entered the
index).

Headers-first intake and the assumevalid optimization are also in place:
`accept_header` indexes a header without its body (Core's
`ProcessNewBlockHeaders`), and `ConnectBlock`'s `fScriptChecks` decision is
ported — `CheckInputScripts` is skipped only when the connected block is an
ancestor-or-self of the configured `assume_valid` block, an ancestor of the
best header, the best header's chainwork meets `minimum_chain_work`
(`nMinimumChainWork`), and the block sits more than two weeks of
proof-equivalent time (`GetBlockProofEquivalentTime`, ported to `chain.rs`)
below the best header. All non-script consensus checks always run. The
`assumevalid-regtest` differential suite drives this end-to-end: a
2160-header chain goes through `submitheader`, the daemon launches with
`-assumevalid=<block@120>`, and bodies 1..=130 arrive via `submitblock` —
block 110 spends an always-false `OP_0` output (below the assumed block:
checks skipped, connects on both sides) while block 130 spends the second
(above it: verified, both reject `mandatory-script-verify-flag-failed`).

`store.rs` adds the durable body store: Core's `blkNNNNN.dat` framing
(`message_start` magic + length + payload), rotation at
`MAX_BLOCKFILE_SIZE`, and a hash→position index rebuilt by scanning on open
— a partial tail frame from an interrupted write is truncated, foreign-magic
stores are refused, and corruption in a non-tail file is reported. Accepted
bodies are appended at `AcceptBlock`'s `WriteBlockToDisk` point (before the
connect decision, so failed bodies persist), and `Chainstate::with_store`
resumes by replaying stored bodies through the full pipeline — the coins
view, undo records and index are still rebuilt in memory, so restart means
re-validation, not re-download. `replay --store` exercises it; verdicts are
identical with and without the store on the 501-block segment.

## Network parameters (`params.rs`)

| Parameter | mainnet | testnet4 | signet | regtest |
| --- | --- | --- | --- | --- |
| `pow_limit` | 2²²⁴ − 1 (raw) | 2²²⁴ − 1 (raw) | `0x1d00ffff` target | `0x7fffff…` target |
| `pow_target_timespan` / spacing / interval | 14 d / 600 s / 2016 | 14 d / 600 s / 2016 | 14 d / 600 s / 2016 | 1 d / 600 s / 144 |
| `allow_min_difficulty_blocks` | false | true | false | true |
| `enforce_bip94` | false | true | false | false (Core default; Core exposes it as a regtest option) |
| `no_retargeting` | false | false | false | true |
| `bip34_height` / `bip66_height` / `bip65_height` | 227931 / 363725 / 388381 | 1 / 1 / 1 | 1 / 1 / 1 | 1 / 1 / 1 |
| `csv_height` / `segwit_height` / `taproot_height` | 419328 / 481824 / 709632 | 1 / 1 / 0 | 1 / 1 / 0 | 1 / 0 / 0 |
| `subsidy_halving_interval` | 210000 | 210000 | 210000 | 150 |
| `bip34_hash` | `…0808b8` | — | — | — |
| `script_flag_exceptions` | BIP16 + taproot blocks | — | — | — |
| `signet_challenge` | — | — | default 1-of-2 bare multisig | — |
| `minimum_chain_work` | `…b1f3b93b65b16d035a82be84` | `…0001d6dce8651b6094e4c1` | `…000002b517f3d1a1` | 0 |
| `assume_valid` | `…dd1120e82e66d2790811f89ede9742ada3ed6d77` | `…8dbdf6f7d6b271a6bcffce25675cb40aa9fa43179a89f3` | `…5a110f46e59eb82bbc5bfb67fa314656009c295509c21b4999f5180a` | none |
| Genesis header | ✓ fixture-pinned | ✓ fixture-pinned | ✓ fixture-pinned | ✓ canonical hash |

Mainnet/testnet4 `pow_limit` is Core's raw `uint256S` value; its canonical compact
`0x1d00ffff` is slightly smaller. The gap is unobservable on built-in networks
(every `nBits` expansion has ≤ 23 significant bits) and documented in `params.rs`.

The six buried-deployment heights are transcribed from `kernel/chainparams.cpp`
(`BIP34Height`/`BIP66Height`/`BIP65Height`/`CSVHeight`/`SegwitHeight`, and Taproot's
`min_activation_height`); `0` for `taproot_height` means Core's `ALWAYS_ACTIVE`, not
"never active". `bip34_height`/`bip66_height`/`bip65_height` drive the `bad-version`
floors in `chain.rs`; `bip34_height`, `csv_height` and `segwit_height` drive the
contextual rules in `check.rs`; `csv_height` additionally gates BIP68 sequence
locks in `connect.rs`, and `bip34_hash`/`subsidy_halving_interval`/
`script_flag_exceptions` drive `enforce_bip30`, `block_subsidy` and
`block_script_flags` there.

## Fixture corpus

Header fixtures (raw 80-byte headers concatenated, no prefixes): mainnet
heights 0–4031 (two full difficulty periods), mainnet 30229–32257 (first real
retarget), testnet4 0–4031, signet 0–2047. Block fixtures (full wire blocks):
mainnet 0, 1, 170 (first non-coinbase tx), 100000, 482229 (segwit-era, real
witness data), 709645 (taproot-era); testnet4 0; signet 0, 1.

Provenance: `fixtures/manifest.json` records per-file network, heights, hashes,
sha256, and the P2P peer (with user agent) or HTTPS URL that supplied it, plus
the sha256 of the contiguous 0–32257 header run the retarget window was cut
from. `fixtures/SHA256SUMS` is `sha256sum -c`-verifiable. Regenerate with
`python3 tools/fetch_fixtures.py` — do not commit larger ranges.

## Reference discrepancies found

| Input | Core / this crate | rust-bitcoin 0.32.102 | Notes |
| --- | --- | --- | --- |
| `nBits` `0x01800000` (compact size ≤ 3, sign bit set, zero mantissa) | expands to `0` (sign bit masked out by `0x7fffff` before shifting) | `128` (keeps sign bit in `0xFFFFFF` mantissa; it survives the shift as a value bit) | Sign-bit encodings are rejected by both (`negative` flag vs `Target::ZERO`→`is_met_by` fails), but for `size <= 3` rust-bitcoin computes a *different value* than Core. Recorded by `compact_expand_matches_rust_bitcoin`; regression seed in `tests/property.proptest-regressions`. |
| BIP34 coinbase prefix at heights 1..=16 (`CScript() << nHeight` vs raw push) | `OP_1..OP_16` (this crate, after fix) | — | First-run catch of `tools/check_blocks_core.py`: `push_int` previously emitted `01 01` for height 1 where Core's `push_int64` emits `0x51`; the daemon returned `bad-cb-height` on our generated coinbase. Fixed in `script.rs` with `push_int(-1..=16)` mapping to `OP_1NEGATE`/`OP_0`/`OP_N`. |

Both findings are the class the differential adapters exist to catch
systematically — one against rust-bitcoin (documented divergence in the
dev-only reference), one caught against the live daemon.

## Not yet implemented (explicit gaps)

Not defects — scope boundaries for later gates:

- **Reorg handling**: `chainstate.rs` drives disconnect-to-fork /
  connect-forward reorgs plus Core's failed-block bookkeeping
  (`BLOCK_FAILED_*`, `bad-prevblk`, `duplicate-invalid`, activation pruning);
  exercised by the 80-fork corpus case and cases 82–85. Block bodies persist
  via `store.rs` (`with_store` resumes by re-validation); remaining G2
  storage work: durable coins view, persisted undo records, atomic
  block+coins commit ordering.
- **Header-chain rules not in Core's `ContextualCheckBlockHeader`**:
  checkpoints, `nMinimumChainWork` as a *header*-acceptance gate (it is wired
  for the `fScriptChecks` decision), BIP9 versionbits deployment state
  (Core treats unexpected versions as warnings, not rejections).
- **Infrastructure**: the scorecard measurement harness. The reference
  adapters exist: `tools/check_headers_core.py` (+ `examples/check_headers.rs`)
  launches an isolated `bitcoind` per network, replays every header fixture and
  a generated regtest invalid-case corpus through `submitheader`, and compares
  per-header verdicts against `HeaderTree` — first full run: **10,404 compared
  headers, zero verdict mismatches** (mainnet 4031, testnet4 4031 including
  real BIP94-enforced headers, signet 2047, regtest 295 incl. bad-diffbits /
  high-hash / time-too-old / time-too-new / orphan / duplicate agreement).
  `tools/check_blocks_core.py` (+ `examples/check_blocks.rs`) does the same at
  block level: it generates a stateful regtest corpus (valid controls plus one
  violation per implemented rule, replayed through the library `Chainstate` —
  header index plus `UtxoSet` — so tip-extending blocks run through
  `connect_block` exactly as the daemon connects them), submits each block
  through `submitblock`, replays the committed real block fixtures on
  per-network daemons, and runs a `segment-*` suite that feeds a contiguous
  real `blk.dat`-framed chain through `Chainstate::accept_block` in order —
  **1200 submissions, zero unexplained mismatches** (259 regtest + 9 fixtures +
  501-block mainnet segment, heights 0..=500 + 301-block signet segment,
  heights 0..=300 + the 130-body assumevalid suite),
  covering every `CheckBlock`/`ContextualCheckBlock` rule plus the
  `ConnectBlock` cases 61–72 (missingorspent, premature coinbase, in-belowout,
  cb-amount, BIP30, BIP68 height/time locks, P2SH/witness sigops), the
  signed-spend cases 73–79 and 81–82 (real ECDSA/schnorr spends of every
  standard output type — P2PKH, P2WPKH, P2WSH, taproot key- and script-path,
  P2SH-P2WPKH — accepted by the daemon's `CheckInputScripts` and by ours, plus
  a corrupted-signature spend both reject with the same reason string and a
  historical high-S P2PKH spend both accept), the
  failed-block bookkeeping cases 82–85 (`duplicate-invalid`, `bad-prevblk`,
  and `prev-blk-not-found` orphans), and the 80-fork reorg (104-block branch
  disconnects and replaces the connected 110-block chain identically on both
  sides). It caught the `push_int`/`OP_N` divergence described above on its
  first run, and the segment replay caught the block-183 high-S normalization
  gap described there too. Both artifacts record the reference binary's
  version and sha256.
  Coverage-guided fuzzing exists (`fuzz/`, libFuzzer via cargo-fuzz): six
  targets over header/transaction/block decoding, CompactSize canonicality,
  compact-target arithmetic and merkle roots; ~14M executions across a
  15 s/target smoke run with zero crashes. Run with
  `cargo +nightly fuzz run <target>` from `fuzz/`.

### Historical and activation cases to carry into G2

Rules the connect-block engine must reproduce, including non-obvious historical
exceptions (activation heights are mainnet):

- Genesis block outputs are not in the UTXO set (Core never indexes them) —
  **implemented**: `UtxoSet::new` starts empty.
- BIP30 duplicate-txid ban with its two grandfathered exceptions (heights
  91842 and 91880) — **implemented**: `enforce_bip30`/`is_bip30_repeat`,
  including the post-`BIP34_IMPLIES_BIP30_LIMIT` unconditional scan and the
  `bip34_hash` known-chain skip. Mainnet sync coverage of the actual repeat
  blocks remains a G2 sync task.
- Value-overflow checks: per-output and per-transaction caps at 21M
  (CVE-2010-5139 era) — **implemented** in `check_transaction`, plus the
  input-side ranges in `check_tx_inputs`.
- P2SH activation is **timestamp-based** (BIP16, April 2012), not height- or
  versionbits-based — the timestamp form lives in Core's flag plumbing; ours
  is subsumed by `block_script_flags`' always-on base + exception blocks,
  matching v29 behavior exactly.
- BIP34 coinbase height (supermajority-gated at height 227931) —
  **implemented** in `contextual_check_block`; BIP66 strict DER (height
  363725) and BIP65 CLTV (height 388381) — activation heights carried and
  flag-gated in `block_script_flags`, script enforcement **implemented** in
  `interpreter.rs`/`sigchecker.rs` (DER checks, `OP_CHECKLOCKTIMEVERIFY`).
- BIP9 versionbits deployments: CSV/BIP68-112-113 (height 419328 — the
  BIP113 locktime cutoff **implemented**, BIP68 sequence locks
  **implemented** in `connect.rs`, `OP_CHECKSEQUENCEVERIFY` **implemented**
  in `interpreter.rs`), segwit BIP141/143/147 (height 481824 — commitment
  rules, witness sigops, BIP143 sighashes, NULLDUMMY **implemented**),
  taproot BIP340-342 (height 709632 — key/script-path spends, schnorr
  verification, control-block commitment, tapscript **implemented**).
- BIP141 enforcement quirks — **implemented**: no witness commitment in the
  coinbase ⇒ all non-coinbase witnesses must be empty; commitment counted
  in the coinbase's own witness.
- Subsidy halving schedule (height % 210000, regtest % 150) and coinbase
  maturity (100 blocks) — **implemented** (`block_subsidy`, `check_tx_inputs`).
- `nLockTime`/`nSequence` semantics across the pre-/post-BIP68 boundary —
  `IsFinalTx` **implemented** in `check.rs`, `SequenceLocks` **implemented**
  in `connect.rs`.


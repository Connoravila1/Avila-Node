# Consensus rule and fixture inventory

**Status: header-chain rules implemented and tested; transaction/block contextual
rules, script, and UTXO validation are not yet implemented.** This inventory is the
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
`bad-diffbits` → `time-too-old` → BIP94 timewarp → `time-too-new`.

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
| Cumulative chainwork; best tip = strictly greatest work | `CBlockIndex::nChainWork`, `ActivateBestChain` tip comparison | `arith.rs` `Work`, `chain.rs` | Fixture chains reproduce real cumulative work; differential per-block work vs rust-bitcoin | `ChainWorkOverflow` guard; equal-work fork does not displace tip |
| Height accumulation | `CBlockIndex::nHeight` | `chain.rs` | Fixture heights | `HeightOverflow` guard (`u32::MAX` parent) |

## Network parameters (`params.rs`)

| Parameter | mainnet | testnet4 | signet | regtest |
| --- | --- | --- | --- | --- |
| `pow_limit` | 2²²⁴ − 1 (raw) | 2²²⁴ − 1 (raw) | `0x1d00ffff` target | `0x7fffff…` target |
| `pow_target_timespan` / spacing / interval | 14 d / 600 s / 2016 | 14 d / 600 s / 2016 | 14 d / 600 s / 2016 | 1 d / 600 s / 144 |
| `allow_min_difficulty_blocks` | false | true | false | true |
| `enforce_bip94` | false | true | false | false (Core default; Core exposes it as a regtest option) |
| `no_retargeting` | false | false | false | true |
| Genesis header | ✓ fixture-pinned | ✓ fixture-pinned | ✓ fixture-pinned | ✓ canonical hash |

Mainnet/testnet4 `pow_limit` is Core's raw `uint256S` value; its canonical compact
`0x1d00ffff` is slightly smaller. The gap is unobservable on built-in networks
(every `nBits` expansion has ≤ 23 significant bits) and documented in `params.rs`.

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

This is the class of finding the pinned-Core reference adapter (remaining G1
work) exists to catch systematically.

## Not yet implemented (explicit gaps)

Not defects — scope boundaries for later gates:

- **Block-level acceptance**: signet block-signature validation, BIP34 coinbase
  height, BIP30 duplicate-txid, weight limit (`MAX_BLOCK_WEIGHT`), sigop counting.
- **Transaction-level rules**: standardless-input checks, coinbase maturity,
  subsidy schedule, fee accounting, BIP68/112 sequence locks, BIP65 CLTV.
- **Script**: entire script interpreter (legacy, P2SH, segwit v0, taproot) — G2.
- **UTXO/connect**: `ConnectBlock` equivalents, undo data, reorg handling beyond
  header-tip selection — G2.
- **Header-chain rules not in Core's `ContextualCheckBlockHeader`**:
  checkpoints, `nMinimumChainWork`, BIP9 versionbits deployment state
  (Core treats unexpected versions as warnings, not rejections).
- **Infrastructure**: pinned-Core reference adapter with disagreement artifacts
  and the scorecard measurement harness. Coverage-guided fuzzing exists
  (`fuzz/`, libFuzzer via cargo-fuzz): six targets over header/transaction/
  block decoding, CompactSize canonicality, compact-target arithmetic and
  merkle roots; ~14M executions across a 15 s/target smoke run with zero
  crashes. Run with `cargo +nightly fuzz run <target>` from `fuzz/`.

### Historical and activation cases to carry into G2

Rules the connect-block engine must reproduce, including non-obvious historical
exceptions (activation heights are mainnet):

- Genesis block outputs are not in the UTXO set (Core never indexes them).
- BIP30 duplicate-txid ban with its two grandfathered exceptions (heights
  91842 and 91880).
- Value-overflow checks: per-output and per-transaction caps at 21M
  (CVE-2010-5139 era); the pre-fix chain contains none, but the check is
  consensus-critical.
- P2SH activation is **timestamp-based** (BIP16, April 2012), not height- or
  versionbits-based.
- BIP34 coinbase height (supermajority-gated at height 227931), BIP66 strict
  DER (height 363725), BIP65 CLTV (height 388381).
- BIP9 versionbits deployments: CSV/BIP68-112-113 (height 419328), segwit
  BIP141/143/147 (height 481824), taproot BIP340-342 (height 709632).
- BIP141 enforcement quirks: no witness commitment in the coinbase ⇒ all
  non-coinbase witnesses must be empty; commitment counted in the coinbase's
  own witness.
- Subsidy halving schedule (height % 210000) and coinbase maturity (100 blocks).
- `nLockTime`/`nSequence` semantics across the pre-/post-BIP68 boundary.


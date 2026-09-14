//! Proof of work: target validation against the network limit and the block hash, and the
//! difficulty-adjustment schedule (`nBits`) every new header must satisfy.
//!
//! Mirrors `CheckProofOfWork`, `GetNextWorkRequired` and `CalculateNextWorkRequired` from
//! Bitcoin Core's `pow.cpp`, including the testnet-style minimum-difficulty rules, the 4×
//! timespan clamp, and testnet4's BIP94 retarget base (the first block of the period, not
//! the last). The BIP94 timewarp bound on period-start blocks is a timestamp rule and lives
//! in [`crate::rules`]. Per-block work (`GetBlockProof`/`GetBitsProof`) lives on
//! [`crate::arith::Work::from_compact`].

use thiserror::Error;

use crate::arith::{CompactTarget, U256};
use crate::hash::BlockHash;
use crate::header::BlockHeader;
use crate::params::Params;

/// Read-only access to the accepted ancestors of a header, used to walk a chain backwards
/// during retarget and minimum-difficulty calculations.
///
/// This is the slice of Core's `CBlockIndex` chain navigation (`pprev`) that `pow.cpp`
/// needs. Implementations must return the header stored under `hash` — i.e. follow the
/// chain's own `prev_block_hash` links — or `None` when the hash is not in the chain
/// (which terminates a walk exactly like Core hitting `pindex == nullptr`).
/// [`crate::chain::HeaderTree`] implements it.
pub trait Ancestry {
    /// Returns the header stored under `hash`, or `None` if it is not in the chain.
    fn ancestor(&self, hash: &BlockHash) -> Option<BlockHeader>;
}

/// Reasons a header can fail proof-of-work validation or a retarget calculation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum PowError {
    /// The `nBits` field decodes to a negative target (Core's `SetCompact` `fNegative`).
    /// [`CompactTarget::expand`] flags this.
    #[error("nBits {0} decodes to a negative target")]
    NegativeTarget(CompactTarget),
    /// The `nBits` field encodes a value too large for 256 bits (Core's `fOverflow`).
    #[error("nBits {0} encodes a target that overflows 256 bits")]
    OverflowTarget(CompactTarget),
    /// The `nBits` field decodes to a zero target.
    #[error("nBits {0} decodes to a zero target")]
    ZeroTarget(CompactTarget),
    /// The expanded target exceeds the network's `powLimit` (Core's `bnTarget > bnPowLimit`
    /// in `CheckProofOfWork`).
    #[error("nBits {0} expands to a target above the network's proof-of-work limit")]
    TargetAboveLimit(CompactTarget),
    /// The block's own hash is numerically greater than its claimed target (Core's
    /// `UintToArith256(hash) > bnTarget`).
    #[error("block hash {hash} does not meet the target encoded by nBits {bits}")]
    InsufficientWork {
        hash: BlockHash,
        bits: CompactTarget,
    },
    /// The retarget/minimum-difficulty calculation needed a header that is not in the
    /// provided [`Ancestry`] (Core dereferences `pindex` unconditionally; we surface the
    /// missing ancestor instead).
    #[error("ancestor {0} needed for the difficulty calculation is not in the chain")]
    UnknownAncestor(BlockHash),
    /// The parameters' difficulty-adjustment interval is zero
    /// (`pow_target_timespan <= pow_target_spacing`, or a zero `pow_target_spacing`), making
    /// the retarget schedule meaningless. No built-in network's parameters trigger this.
    #[error("difficulty parameters are degenerate (adjustment interval is zero)")]
    DegenerateDifficultyParams,
}

/// Core's `CheckProofOfWork` (`pow.cpp`): a header's claimed work is valid iff its `nBits`
/// decodes to a positive, non-overflowing target at or below the network `powLimit`, and the
/// block's own hash does not exceed that target.
///
/// `hash` must be the hash of the header `bits` was taken from — the two are independent
/// inputs in Core (`hash` of the `uint256` being checked, `nBits` separately), and passing a
/// mismatched pair misapplies the rule. [`crate::chain::HeaderTree::insert`] always pairs
/// them correctly.
///
/// # Errors
///
/// Returns the specific [`PowError`] for the first failing condition. Core reports all four
/// `nBits` problems as one "bad-diffbits"-style rejection; the split here is diagnostic only.
pub fn check_proof_of_work(
    hash: &BlockHash,
    bits: CompactTarget,
    params: &Params,
) -> Result<(), PowError> {
    let expanded = bits.expand();
    // Flag checks first: an overflowing encoding can produce a zero `value` (the mantissa
    // is shifted entirely out of 256 bits), and reporting the flag is the better diagnosis.
    if expanded.negative {
        return Err(PowError::NegativeTarget(bits));
    }
    if expanded.overflow {
        return Err(PowError::OverflowTarget(bits));
    }
    if expanded.value.is_zero() {
        return Err(PowError::ZeroTarget(bits));
    }
    if expanded.value > params.pow_limit.0 {
        return Err(PowError::TargetAboveLimit(bits));
    }
    // A block hash's 32 wire bytes are its `uint256` in little-endian order — the same
    // interpretation as Core's `UintToArith256(hash)`.
    if U256::from_le_bytes(hash.to_bytes()) > expanded.value {
        return Err(PowError::InsufficientWork { hash: *hash, bits });
    }
    Ok(())
}

/// Core's `GetNextWorkRequired` (`pow.cpp`): the `nBits` a block extending the header at
/// `last_height`/`last` must carry, given its own timestamp `new_time`.
///
/// The schedule, in Core's order:
///
/// 1. If `last_height + 1` is not a retarget boundary, then on networks with
///    [`Params::allow_min_difficulty_blocks`] the new block may use the `powLimit` compact
///    when its timestamp is more than twice the target spacing past its parent's; otherwise
///    it must carry the bits of the most recent ancestor that did not itself use the
///    minimum-difficulty rule (the walk-back in Core's `pindex->nBits == nProofOfWorkLimit`
///    loop). On other networks it must repeat `last.bits` unchanged.
/// 2. At a retarget boundary (`(last_height + 1) % interval == 0`), the bits come from
///    `retarget` over the window ending at `last` — from the first block of the period
///    just ended under BIP94, or from `last` otherwise.
///
/// There is no "required bits" for a genesis block (Core asserts `pindexLast != nullptr`);
/// a chain's genesis is an anchor supplied by [`Params::genesis_header`], not a validated
/// child.
///
/// # Errors
///
/// Returns [`PowError::UnknownAncestor`] if the walk to an ancestor required by the
/// schedule hits a hash not present in `ancestry`, and
/// [`PowError::DegenerateDifficultyParams`] if `params`'s adjustment interval is zero.
pub fn required_bits(
    last_height: u32,
    last: &BlockHeader,
    new_time: u32,
    params: &Params,
    ancestry: &dyn Ancestry,
) -> Result<CompactTarget, PowError> {
    let interval = params.difficulty_adjustment_interval();
    if interval == 0 || params.pow_target_timespan == 0 {
        return Err(PowError::DegenerateDifficultyParams);
    }
    let pow_limit_bits = params.pow_limit_compact();
    let next_height = u64::from(last_height) + 1;
    if next_height % interval != 0 {
        if params.allow_min_difficulty_blocks {
            // Core: `pblock->GetBlockTime() > pindexLast->GetBlockTime() +
            // params.nPowTargetSpacing * 2`. The u64 compare is identical for sane
            // parameters; `saturating_mul` keeps a pathological custom `pow_target_spacing`
            // (> u64::MAX/2) from wrapping into an enabled exemption.
            if u64::from(new_time)
                > u64::from(last.time).saturating_add(params.pow_target_spacing.saturating_mul(2))
            {
                return Ok(pow_limit_bits);
            }
            // Otherwise the new block carries the difficulty of the last ancestor that was
            // not itself a minimum-difficulty block (Core's walk over
            // `pindex->nBits == nProofOfWorkLimit`, stopping at interval boundaries and at
            // the chain's start). A boundary block's height is `0 mod interval`, so the
            // height check below is Core's `nHeight % nInterval != 0` exactly.
            let mut height = last_height;
            let mut header = *last;
            while u64::from(height) % interval != 0 && header.bits == pow_limit_bits {
                header = ancestry
                    .ancestor(&header.prev_block_hash)
                    .ok_or(PowError::UnknownAncestor(header.prev_block_hash))?;
                // `ancestor` follows the chain's own `prev` links, so each step descends
                // exactly one height; tracking it locally keeps the boundary test honest
                // even if an implementation stores heights inconsistently.
                height = height.wrapping_sub(1);
            }
            return Ok(header.bits);
        }
        return Ok(last.bits);
    }

    // Retarget boundary: the window runs from the ancestor `interval - 1` below `last`
    // through `last` itself (Core's `pindexLast->GetAncestor(nHeight - (interval-1))`).
    // `next_height % interval == 0` implies `last_height + 1 >= interval`, so the target
    // ancestor always exists on a complete chain; a partial `ancestry` surfaces as
    // `UnknownAncestor` when the walk reaches its end first. The `.min()` below only
    // truncates walks a non-chain-faithful `Ancestry` could otherwise extend past the
    // chain's own length.
    let mut window_first = *last;
    for _ in 0..(interval - 1).min(u64::from(last_height) + 1) {
        window_first = ancestry
            .ancestor(&window_first.prev_block_hash)
            .ok_or(PowError::UnknownAncestor(window_first.prev_block_hash))?;
    }
    // BIP94 (testnet4): the retarget base is the *first* block of the period just ended —
    // that block is never allowed the minimum-difficulty exemption, so the real difficulty
    // survives the transition (Core's `bnNew.SetCompact(pindexFirst->nBits)`).
    let base_bits = if params.enforce_bip94 {
        window_first.bits
    } else {
        last.bits
    };
    Ok(retarget(base_bits, last, window_first.time, params))
}

/// Core's `CalculateNextWorkRequired` (`pow.cpp`): the retargeted `nBits` for the block
/// following `last`, given the timestamp of the first header in the adjustment window.
///
/// `base_bits` is the difficulty the adjustment scales: `last.bits` normally, or the
/// window-first block's `bits` under BIP94 (testnet4 — Core's
/// `bnNew.SetCompact(pindexFirst->nBits)` branch).
///
/// The window's actual timespan is clamped to `[timespan/4, timespan*4]` and the new target
/// is `base_target * actual_timespan / pow_target_timespan`, clamped to `powLimit`. The
/// multiply wraps modulo `2^256` exactly like Core's fixed-width `bnNew *= nActualTimespan`
/// (reachable in principle when the base target is close to `powLimit` on networks with a
/// large limit, e.g. signet).
fn retarget(
    base_bits: CompactTarget,
    last: &BlockHeader,
    window_first_time: u32,
    params: &Params,
) -> CompactTarget {
    if params.no_retargeting {
        return last.bits;
    }
    let timespan = i64::try_from(params.pow_target_timespan).unwrap_or(i64::MAX);
    let actual = i64::from(last.time) - i64::from(window_first_time);
    let clamped = actual.clamp(timespan / 4, timespan.saturating_mul(4));
    // `clamped >= timespan/4 > 0` whenever `timespan > 0`; the degenerate case was rejected
    // in `required_bits`, and `u64::try_from` below additionally tolerates a hypothetical
    // negative by saturating to 0 (which makes the product 0, a harmless degenerate target).
    let mut new_target = base_bits
        .expand()
        .value
        .wrapping_mul_u64(u64::try_from(clamped).unwrap_or(0));
    // `pow_target_timespan` is nonzero here (guarded by `required_bits`); the `None` arm is
    // unreachable for parameters that pass that check.
    if let Some((quotient, _remainder)) =
        new_target.div_rem(U256::from_u64(params.pow_target_timespan))
    {
        new_target = quotient;
    }
    if new_target > params.pow_limit.0 {
        new_target = params.pow_limit.0;
    }
    crate::arith::Target(new_target).to_compact()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arith::Work;
    use crate::params::Network;
    use std::collections::HashMap;

    const MAINNET_HEADERS: &[u8] =
        include_bytes!("../../../fixtures/mainnet-headers-000000-004031.bin");
    const MAINNET_RETARGET_WINDOW: &[u8] =
        include_bytes!("../../../fixtures/mainnet-headers-030229-032257.bin");
    const TESTNET4_HEADERS: &[u8] =
        include_bytes!("../../../fixtures/testnet4-headers-000000-004031.bin");
    const SIGNET_HEADERS: &[u8] =
        include_bytes!("../../../fixtures/signet-headers-000000-002047.bin");

    fn decode_headers(bytes: &[u8]) -> Vec<BlockHeader> {
        bytes
            .as_chunks::<{ BlockHeader::SIZE }>()
            .0
            .iter()
            .map(|chunk| BlockHeader::decode(chunk))
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// A `HashMap`-backed [`Ancestry`] over a decoded fixture run.
    struct MapAncestry<'a> {
        headers: &'a HashMap<BlockHash, BlockHeader>,
    }

    impl Ancestry for MapAncestry<'_> {
        fn ancestor(&self, hash: &BlockHash) -> Option<BlockHeader> {
            self.headers.get(hash).copied()
        }
    }

    fn ancestry_of(headers: &[BlockHeader]) -> HashMap<BlockHash, BlockHeader> {
        headers.iter().map(|h| (h.hash(), *h)).collect()
    }

    /// Asserts `required_bits` reproduces every header's actual `bits` across a fixture run
    /// whose first element sits at `first_height`.
    fn assert_required_bits_match(headers: &[BlockHeader], first_height: u32, network: Network) {
        let params = network.params();
        let map = ancestry_of(headers);
        let ancestry = MapAncestry { headers: &map };
        for i in 1..headers.len() {
            let height = u64::from(first_height) + i as u64;
            // A retarget boundary whose window starts before the fixture cannot be checked
            // (its first-window header isn't available).
            if height.is_multiple_of(params.difficulty_adjustment_interval())
                && height < u64::from(first_height) + params.difficulty_adjustment_interval()
            {
                continue;
            }
            let required = required_bits(
                (height - 1) as u32,
                &headers[i - 1],
                headers[i].time,
                &params,
                &ancestry,
            )
            .unwrap_or_else(|e| panic!("required_bits failed at height {height}: {e}"));
            assert_eq!(
                required, headers[i].bits,
                "required_bits mismatch at height {height}"
            );
        }
    }

    // ---- check_proof_of_work ----

    #[test]
    fn every_fixture_header_passes_proof_of_work() {
        for (bytes, network) in [
            (MAINNET_HEADERS, Network::Mainnet),
            (MAINNET_RETARGET_WINDOW, Network::Mainnet),
            (TESTNET4_HEADERS, Network::Testnet4),
            (SIGNET_HEADERS, Network::Signet),
        ] {
            let params = network.params();
            for header in decode_headers(bytes) {
                check_proof_of_work(&header.hash(), header.bits, &params).unwrap();
            }
        }
    }

    #[test]
    fn hash_above_target_is_rejected() {
        // Height 4031's hash (≈ 2^224.7) does not meet height 32256's retargeted target
        // (0x1d00d86a → ≈ 2^223.8). Both inputs are real; only `InsufficientWork` can fire.
        let headers = decode_headers(MAINNET_HEADERS);
        let window = decode_headers(MAINNET_RETARGET_WINDOW);
        let hash = headers[4031].hash();
        let tighter_bits = window.last().unwrap().bits;
        assert_eq!(tighter_bits, CompactTarget(0x1d00_d86a));
        assert_eq!(
            check_proof_of_work(&hash, tighter_bits, &Network::Mainnet.params()),
            Err(PowError::InsufficientWork {
                hash,
                bits: tighter_bits,
            })
        );
    }

    #[test]
    fn bad_bits_forms_are_rejected_with_the_right_reason() {
        let params = Network::Mainnet.params();
        let hash = BlockHash::ZERO;
        // Negative: sign bit set on a non-zero mantissa.
        assert_eq!(
            check_proof_of_work(&hash, CompactTarget(0x1d80_ffff), &params),
            Err(PowError::NegativeTarget(CompactTarget(0x1d80_ffff)))
        );
        // Overflow: exponent 0x23 > 34.
        assert_eq!(
            check_proof_of_work(&hash, CompactTarget(0x2300_ffff), &params),
            Err(PowError::OverflowTarget(CompactTarget(0x2300_ffff)))
        );
        // Zero target.
        assert_eq!(
            check_proof_of_work(&hash, CompactTarget(0), &params),
            Err(PowError::ZeroTarget(CompactTarget(0)))
        );
        // Above powLimit: 0x1d01ffff expands to 0x01ffff << 208, above 2^224 - 1.
        // (The check happens before the hash comparison, so any hash works.)
        assert_eq!(
            check_proof_of_work(&hash, CompactTarget(0x1d01_ffff), &params),
            Err(PowError::TargetAboveLimit(CompactTarget(0x1d01_ffff)))
        );
    }

    /// `nBits` is not required to be in canonical form: `0x02000100` is a non-canonical
    /// encoding of the target `1` (canonical would be `0x01010000`-style), and Core accepts
    /// it — `CheckProofOfWork` looks only at the expanded value.
    #[test]
    fn noncanonical_encoding_of_a_valid_target_is_accepted() {
        let params = Network::Mainnet.params();
        // Expands to the target `1`; a zero block hash meets every positive target.
        let expanded = CompactTarget(0x0200_0100).expand();
        assert!(!expanded.negative && !expanded.overflow);
        assert_eq!(expanded.value, U256::ONE);
        check_proof_of_work(&BlockHash::ZERO, CompactTarget(0x0200_0100), &params).unwrap();
        // While a mantissa with the sign bit set is negative, not merely non-canonical.
        assert_eq!(
            check_proof_of_work(&BlockHash::ZERO, CompactTarget(0x1cff_ffff), &params),
            Err(PowError::NegativeTarget(CompactTarget(0x1cff_ffff)))
        );
    }

    // ---- required_bits ----

    #[test]
    fn mainnet_required_bits_match_real_chain_through_two_periods() {
        assert_required_bits_match(&decode_headers(MAINNET_HEADERS), 0, Network::Mainnet);
    }

    #[test]
    fn mainnet_retarget_window_reproduces_the_first_real_retarget() {
        // Heights 30229..=32257 include height 32256, mainnet's first retarget that
        // actually changed nBits (0x1d00ffff → 0x1d00d86a).
        let headers = decode_headers(MAINNET_RETARGET_WINDOW);
        assert_eq!(
            headers[0].hash().to_string(),
            "00000000a3e008fc688b82c7513b5870909fbd86cf43026130a569043d737756"
        );
        assert_required_bits_match(&headers, 30_229, Network::Mainnet);
        let at_32256 = &headers[32256 - 30229];
        assert_eq!(at_32256.bits, CompactTarget(0x1d00_d86a));
    }

    #[test]
    fn testnet4_required_bits_match_real_chain() {
        // Early testnet4 blocks lean heavily on the minimum-difficulty rule, so this run
        // exercises both the 20-minute exemption and the non-min-difficulty walk-back.
        let headers = decode_headers(TESTNET4_HEADERS);
        assert_required_bits_match(&headers, 0, Network::Testnet4);
        // Confirm the fixture really did exercise the min-difficulty path.
        let params = Network::Testnet4.params();
        let min_diff_count = headers
            .iter()
            .filter(|h| h.bits == params.pow_limit_compact())
            .count();
        assert!(
            min_diff_count > 0,
            "expected the testnet4 fixture to contain minimum-difficulty blocks"
        );
    }

    #[test]
    fn signet_required_bits_match_real_chain() {
        assert_required_bits_match(&decode_headers(SIGNET_HEADERS), 0, Network::Signet);
    }

    #[test]
    fn regtest_required_bits_never_retargets() {
        let params = Network::Regtest.params();
        // Regtest headers: with `no_retargeting`, every non-min-difficulty answer is
        // `last.bits`, and min-difficulty is allowed by the 20-minute rule.
        let last = params.genesis_header;
        let map = ancestry_of(&[last]);
        let ancestry = MapAncestry { headers: &map };
        // New block 20+ minutes after genesis → min-difficulty (powLimit) bits.
        assert_eq!(
            required_bits(0, &last, last.time + 1201, &params, &ancestry).unwrap(),
            params.pow_limit_compact()
        );
        // Within 20 minutes → repeat last bits.
        assert_eq!(
            required_bits(0, &last, last.time + 600, &params, &ancestry).unwrap(),
            last.bits
        );
    }

    /// BIP94 (testnet4): at a retarget boundary the base difficulty is the *first* block
    /// of the period just ended, not the last. The real testnet4 fixture cannot separate
    /// the two rules — every early period is uniformly minimum-difficulty — so this test
    /// builds a synthetic 4-block-interval chain whose period ends on a minimum-difficulty
    /// block but began on a harder one.
    #[test]
    fn bip94_retarget_uses_first_block_of_period_as_base() {
        let mut params = Network::Testnet4.params();
        params.pow_target_spacing = 60;
        params.pow_target_timespan = 240; // interval = 4
        // A genesis with tighter-than-limit bits (testnet4 powLimit is the mainnet one,
        // so `0x1c00ffff` is admissible); genesis is anchored, never PoW-checked.
        let genesis = BlockHeader {
            version: 1,
            prev_block_hash: BlockHash::ZERO,
            merkle_root: params.genesis_header.merkle_root,
            time: 1_000_000,
            bits: CompactTarget(0x1c00_ffff),
            nonce: 0,
        };
        // Heights 1..=3 are minimum-difficulty blocks: each is >2*spacing after its parent.
        let mut chain = vec![genesis];
        for i in 1..=3u32 {
            let prev = chain.last().unwrap();
            chain.push(BlockHeader {
                version: 1,
                prev_block_hash: prev.hash(),
                merkle_root: genesis.merkle_root,
                time: genesis.time + i * (2 * 60 + 1),
                bits: params.pow_limit_compact(),
                nonce: 0,
            });
        }
        let map = ancestry_of(&chain);
        let ancestry = MapAncestry { headers: &map };
        let last = chain.last().unwrap();
        let new_time = last.time + 60;
        // actual = 3 * 121 = 363, within [240/4, 240*4], so the new target is
        // min(base * 363 / 240, powLimit). Under BIP94 the base is the genesis block's
        // tighter target; without it the base is the last block's minimum difficulty,
        // whose scaled target exceeds powLimit and clamps back to it — the "block storm"
        // floor BIP94 exists to prevent.
        let scale = |bits: CompactTarget| {
            let scaled = bits
                .expand()
                .value
                .wrapping_mul_u64(363)
                .div_rem(U256::from_u64(240))
                .unwrap()
                .0;
            crate::arith::Target(scaled.min(params.pow_limit.0)).to_compact()
        };
        let bip94 = required_bits(3, last, new_time, &params, &ancestry).unwrap();
        assert_eq!(bip94, scale(genesis.bits));
        let mut plain = params;
        plain.enforce_bip94 = false;
        let naive = required_bits(3, last, new_time, &plain, &ancestry).unwrap();
        assert_eq!(naive, scale(last.bits));
        assert_ne!(bip94, naive);
    }

    #[test]
    fn required_bits_errors_on_missing_ancestor() {
        // A retarget boundary with an ancestry that stops short of the window's first
        // header must surface `UnknownAncestor`, not panic or miscompute.
        let headers = decode_headers(MAINNET_HEADERS);
        let params = Network::Mainnet.params();
        // Give the ancestry only the last 10 headers of the first window; the walk to
        // height 0 for the height-2016 retarget runs out of chain.
        let map = ancestry_of(&headers[2006..]);
        let ancestry = MapAncestry { headers: &map };
        assert_eq!(
            required_bits(2015, &headers[2015], headers[2016].time, &params, &ancestry),
            Err(PowError::UnknownAncestor(headers[2006].prev_block_hash))
        );
    }

    #[test]
    fn required_bits_rejects_degenerate_params() {
        let params = {
            let mut p = Network::Mainnet.params();
            p.pow_target_spacing = 0;
            p
        };
        let last = Network::Mainnet.params().genesis_header;
        let map = ancestry_of(&[last]);
        let ancestry = MapAncestry { headers: &map };
        assert_eq!(
            required_bits(0, &last, last.time + 600, &params, &ancestry),
            Err(PowError::DegenerateDifficultyParams)
        );
    }

    // ---- Differential checks against rust-bitcoin ----

    #[test]
    fn retarget_matches_rust_bitcoin_on_every_fixture_boundary() {
        use bitcoin::blockdata::block::Header as BitcoinHeader;
        use bitcoin::hashes::Hash as _;
        use bitcoin::pow::CompactTarget as BitcoinCompact;

        let to_bitcoin = |h: &BlockHeader| BitcoinHeader {
            version: bitcoin::blockdata::block::Version::from_consensus(h.version),
            prev_blockhash: bitcoin::BlockHash::from_byte_array(h.prev_block_hash.to_bytes()),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array(h.merkle_root.to_bytes()),
            time: h.time,
            bits: BitcoinCompact::from_consensus(h.bits.0),
            nonce: h.nonce,
        };

        for (bytes, first_height, bitcoin_params, params) in [
            (
                MAINNET_HEADERS,
                0u32,
                &bitcoin::consensus::params::MAINNET,
                Network::Mainnet.params(),
            ),
            (
                MAINNET_RETARGET_WINDOW,
                30_229,
                &bitcoin::consensus::params::MAINNET,
                Network::Mainnet.params(),
            ),
            (
                TESTNET4_HEADERS,
                0,
                &bitcoin::consensus::params::TESTNET4,
                Network::Testnet4.params(),
            ),
            (
                SIGNET_HEADERS,
                0,
                &bitcoin::consensus::params::SIGNET,
                Network::Signet.params(),
            ),
        ] {
            let headers = decode_headers(bytes);
            let map = ancestry_of(&headers);
            let ancestry = MapAncestry { headers: &map };
            let interval = params.difficulty_adjustment_interval();
            for (i, header) in headers.iter().enumerate() {
                let height = u64::from(first_height) + i as u64;
                // Skip non-boundary heights and boundaries whose full retarget window is
                // not inside the fixture (the window's first header must be present for
                // `required_bits` to walk to it).
                if !height.is_multiple_of(interval)
                    || height < u64::from(first_height) + interval - 1
                {
                    continue;
                }
                // `required_bits` for the block at `height` consults the window ending at
                // `height - 1`; rust-bitcoin's `from_header_difficulty_adjustment` takes
                // the same two endpoints (window-first and window-last headers).
                let last = &headers[i - 1];
                let ours =
                    required_bits((height - 1) as u32, last, header.time, &params, &ancestry)
                        .unwrap();
                let window_first_index = (height - interval - u64::from(first_height)) as usize;
                if params.network == Network::Testnet4 {
                    // rust-bitcoin 0.32 does not implement BIP94's first-block-of-period
                    // retarget base. Parity is expected here only because every boundary
                    // in this early-fixture range has identical bits at both window ends;
                    // pin that precondition so a longer fixture can't silently weaken the
                    // comparison.
                    assert_eq!(
                        headers[window_first_index].bits, last.bits,
                        "testnet4 boundary {height} no longer exercises identical window ends"
                    );
                }
                let theirs = BitcoinCompact::from_header_difficulty_adjustment(
                    to_bitcoin(&headers[window_first_index]),
                    to_bitcoin(last),
                    bitcoin_params,
                );
                assert_eq!(
                    ours.0,
                    theirs.to_consensus(),
                    "retarget mismatch at height {height}"
                );
            }
        }
    }

    #[test]
    fn per_block_work_matches_rust_bitcoin() {
        for bytes in [
            MAINNET_HEADERS,
            MAINNET_RETARGET_WINDOW,
            TESTNET4_HEADERS,
            SIGNET_HEADERS,
        ] {
            for header in decode_headers(bytes) {
                let ours = Work::from_compact(header.bits);
                let theirs = bitcoin::pow::Target::from_compact(
                    bitcoin::pow::CompactTarget::from_consensus(header.bits.0),
                )
                .to_work();
                assert_eq!(
                    ours.0.to_be_bytes(),
                    theirs.to_be_bytes(),
                    "work mismatch for nBits {}",
                    header.bits
                );
            }
        }
    }

    #[test]
    fn hash_target_comparison_matches_rust_bitcoin() {
        use bitcoin::hashes::Hash as _;
        use bitcoin::pow::CompactTarget as BitcoinCompact;
        for bytes in [MAINNET_HEADERS, TESTNET4_HEADERS] {
            for header in decode_headers(bytes) {
                let target = bitcoin::pow::Target::from_compact(BitcoinCompact::from_consensus(
                    header.bits.0,
                ));
                let hash = bitcoin::BlockHash::from_byte_array(header.hash().to_bytes());
                let meets = target.is_met_by(hash);
                let ours =
                    check_proof_of_work(&header.hash(), header.bits, &Network::Mainnet.params());
                assert_eq!(meets, ours.is_ok(), "PoW mismatch on {}", header.hash());
            }
        }
    }
}

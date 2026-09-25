//! Anti-DoS presync for low-work header chains — a P2P-layer port of
//! Core's `headerssync.cpp` plus the `net_processing.cpp` glue
//! (`TryLowWorkHeadersSync` / `IsContinuationOfLowWorkHeadersSync` /
//! `GetAntiDoSWorkThreshold`).
//!
//! [`avila_consensus::chain::HeaderTree::insert`] stores any header whose
//! own proof-of-work is valid, with no floor on the chain's total work —
//! by design, that floor belongs above the consensus crate (Core's
//! anti-DoS presync isn't a consensus rule either; a chain either side of
//! the threshold is equally consensus-valid, the threshold only bounds
//! what we're willing to *store* while unproven). Left unguarded, a peer
//! can hand us an unbounded low-difficulty chain rooted at genesis and
//! grow our header tree without limit. This module is the guard: it sits
//! in front of [`crate::sync::PeerSync::on_headers`] and decides whether
//! a batch is even worth handing to [`avila_consensus::chainstate::Chainstate::accept_header`].
//!
//! The mechanism (identical to Core's, see `headerssync.h`'s module
//! comment for the full rationale): a headers batch whose *claimed*
//! total work (fork point plus the batch, taken at face value) is below
//! [`anti_dos_work_threshold`] is never stored directly. If the batch is
//! a full page, a per-peer [`HeadersSyncState`] starts a two-pass
//! download instead:
//!
//! * **PRESYNC** — validate continuity and the difficulty schedule
//!   (`permitted_difficulty_transition`, the ancestry-free proxy for
//!   the real retarget check) and accumulate claimed work, without
//!   storing headers. Every `commitment_period`th header gets a salted
//!   1-bit commitment; only the latest header itself is kept.
//! * **REDOWNLOAD** — once accumulated work reaches the threshold,
//!   re-request the same range from `chain_start`, verify each
//!   commitment as its header comes back, and buffer headers until
//!   either the buffer holds `redownload_buffer_size` headers or the
//!   redownloaded chain's own work reaches the threshold — at which
//!   point buffered headers are released to the caller for real
//!   acceptance.
//!
//! A short (non-full) low-work batch is simply ignored: the peer has
//! nothing more to give and never proved suficient work.

use std::collections::VecDeque;

use avila_consensus::arith::{CompactTarget, U256, Work};
use avila_consensus::chain::HeaderNode;
use avila_consensus::chainstate::Chainstate;
use avila_consensus::hash::BlockHash;
use avila_consensus::header::BlockHeader;
use avila_consensus::params::{Network, Params};
use avila_consensus::rules;

use crate::message::{GetHeaders, Message};

/// Core `kernel/chainparams.cpp`'s `HeadersSyncParams` — the per-network
/// memory/DoS tuning for a presync (v31.1, `headerssync-params.py`).
/// `avila_consensus::params::Params` has no equivalent field (it isn't a
/// consensus rule), so these live here, at the layer that owns the
/// presync mechanism.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HeadersSyncParams {
    /// Distance in headers between salted 1-bit commitments.
    pub commitment_period: u32,
    /// Minimum number of verified headers to accumulate in the
    /// redownload buffer before releasing them for real acceptance.
    pub redownload_buffer_size: u32,
}

impl HeadersSyncParams {
    /// Core's per-network constant (`kernel/chainparams.cpp`, v31.1).
    /// Every built-in [`Network`] has a nonzero `commitment_period` —
    /// callers may divide by it without a zero-check.
    #[must_use]
    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => Self {
                commitment_period: 641,
                redownload_buffer_size: 15_218,
            },
            Network::Testnet4 => Self {
                commitment_period: 606,
                redownload_buffer_size: 16_092,
            },
            Network::Signet => Self {
                commitment_period: 620,
                redownload_buffer_size: 15_724,
            },
            // Core's `CRegTestParams` comment: "Copied from Testnet4" —
            // regtest ships its own (smaller) numbers, not testnet4's.
            Network::Regtest => Self {
                commitment_period: 275,
                redownload_buffer_size: 7_017,
            },
        }
    }
}

/// Core's `GetAntiDoSWorkThreshold`: never trust a headers batch
/// claiming less work than this. `144` blocks is Core's fork-tolerance
/// buffer near our own tip — a legitimate reorg competing with our
/// last day or so of blocks is never penalized; only chains that would
/// need to be *both* low-work *and* deep are gated. `minimum_chain_work`
/// is the network-wide floor beneath which nothing is trusted at all
/// (zero on regtest, so a fresh chain's threshold is zero too).
#[must_use]
pub fn anti_dos_work_threshold(cs: &Chainstate, params: &Params) -> Work {
    let near_tip = cs
        .chain()
        .last()
        .and_then(|hash| cs.tree().get(hash))
        .map_or(U256::ZERO, |tip| {
            // Core: `144*GetBlockProof(tip)` via `arith_uint256`'s
            // truncating multiply — unreachable in practice (a real
            // tip's per-block proof is astronomically below 2^256/144),
            // ported faithfully rather than saturated.
            let buffer = Work::from_compact(tip.header.bits).0.wrapping_mul_u64(144);
            tip.chainwork.0.checked_sub(buffer).unwrap_or(U256::ZERO)
        });
    Work(near_tip.max(params.minimum_chain_work.0))
}

/// Core's `PermittedDifficultyTransition` (`pow.cpp`): whether `new_bits`
/// at `height` is reachable from `old_bits` within the retarget bounds,
/// without needing the intervening headers — presync's ancestry-free
/// stand-in for the real, ancestry-walking retarget check
/// ([`avila_consensus::pow::required_bits`]). Always permissive on
/// networks that allow minimum-difficulty blocks (nothing meaningful to
/// bound there).
fn permitted_difficulty_transition(
    params: &Params,
    height: u64,
    old_bits: CompactTarget,
    new_bits: CompactTarget,
) -> bool {
    if params.allow_min_difficulty_blocks {
        return true;
    }
    let interval = params.difficulty_adjustment_interval();
    if interval == 0 || !height.is_multiple_of(interval) {
        return old_bits == new_bits;
    }
    let pow_limit = params.pow_limit.0;
    // Core's SetCompact(new_nbits): the raw decoded magnitude, ignoring
    // the negative/overflow flags exactly as `arith_uint256::SetCompact`
    // does when only the value (not the flags) is consumed.
    let observed_new_target = new_bits.expand().value;
    let old_target = old_bits.expand().value;
    // Clamp `old_target` scaled by `timespan/pow_target_timespan` to
    // `pow_limit`, then round through the lossy compact encoding —
    // Core does the same `SetCompact(x.GetCompact())` round-trip before
    // comparing.
    let clamp = |timespan: u64| -> U256 {
        let scaled = old_target.wrapping_mul_u64(timespan);
        let (quotient, _) = scaled
            .div_rem(U256::from_u64(params.pow_target_timespan))
            .unwrap_or((U256::ZERO, U256::ZERO));
        CompactTarget::from_target(quotient.min(pow_limit), false)
            .expand()
            .value
    };
    let maximum_new_target = clamp(params.pow_target_timespan * 4);
    if maximum_new_target < observed_new_target {
        return false;
    }
    let minimum_new_target = clamp(params.pow_target_timespan / 4);
    if minimum_new_target > observed_new_target {
        return false;
    }
    true
}

/// A salted, keyed 1-bit commitment for `hash` — Core's
/// `SaltedUint256Hasher` output `& 1`. `salt` is drawn once per
/// [`HeadersSyncState`] (never sent on the wire), so a peer cannot
/// predict which bit a given header will commit to and therefore cannot
/// forge a low-difficulty chain that also passes the commitments it
/// never saw checked.
fn commitment_bit(salt: &[u8; 32], hash: &BlockHash) -> bool {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(salt);
    buf.extend_from_slice(hash.as_bytes());
    avila_consensus::hash::sha256d(&buf)[0] & 1 == 1
}

/// A fresh 32-byte secret for [`commitment_bit`] (and, split off its
/// first 8 bytes, the commitment-period offset) — Core's
/// `FastRandomContext`. Falls back to a wall-clock-derived value on the
/// (essentially unreachable, since BIP324 key generation depends on the
/// same source) chance the OS RNG is unavailable, so a presync can still
/// proceed rather than panicking; the only cost of the fallback is
/// weaker commitment secrecy, never a correctness gap.
fn random_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    if getrandom::fill(&mut salt).is_err() {
        let seed = crate::session::wall_epoch().to_le_bytes();
        for (i, b) in salt.iter_mut().enumerate() {
            *b = seed[i % 8];
        }
    }
    salt
}

/// Core's `LocatorEntries`, generalized to start anywhere rather than
/// always at the tip — the presync/redownload continuation locator
/// starts at `chain_start`, not our current best header.
fn locator_from(cs: &Chainstate, start_hash: BlockHash, start_height: u32) -> Vec<BlockHash> {
    let mut have = Vec::with_capacity(32);
    let mut hash = start_hash;
    let mut height = start_height;
    let mut step = 1u32;
    loop {
        have.push(hash);
        if height == 0 {
            break;
        }
        let next_height = height.saturating_sub(step);
        let Some(node) = cs.tree().get_ancestor(&hash, next_height) else {
            break;
        };
        height = next_height;
        hash = node.hash();
        if have.len() > 10 {
            step = step.saturating_mul(2);
        }
    }
    have
}

/// Where a per-peer presync is at — Core's `HeadersSyncState::State`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// Building commitments, chasing the work threshold.
    Presync,
    /// Re-downloading the same range, checking commitments, buffering.
    Redownload,
    /// Nothing left to do; the holder should drop this state.
    Final,
}

/// What one [`HeadersSyncState::process_next_headers`] call produced —
/// Core's `HeadersSyncState::ProcessingResult`.
#[derive(Default)]
pub struct ProcessingResult {
    /// Headers verified enough to hand to
    /// [`avila_consensus::chainstate::Chainstate::accept_header`] for
    /// real (only ever nonempty during REDOWNLOAD).
    pub pow_validated_headers: Vec<BlockHeader>,
    /// `false` means the sync hit an internal inconsistency (bad
    /// continuity, an impossible difficulty transition, a commitment
    /// mismatch, or a peer-length bound) and has been abandoned — not
    /// misbehavior on its own, since an honest peer can simply reorg
    /// mid-sync; the caller just stops trying with this peer for now.
    pub success: bool,
    /// The caller should request another page — via
    /// [`HeadersSyncState::next_headers_request`], not the ordinary
    /// best-header locator.
    pub request_more: bool,
}

/// Core's `HeadersSyncState`: one peer's in-progress low-work-chain
/// presync/redownload. Bounded memory throughout — PRESYNC keeps only
/// the latest header plus a bitstream of commitments, and REDOWNLOAD's
/// buffer is capped at `redownload_buffer_size` headers except in the
/// final release.
pub struct HeadersSyncState {
    params: Params,
    sync_params: HeadersSyncParams,
    minimum_required_work: Work,
    salt: [u8; 32],
    /// The offset (into `0..commitment_period`) at which a header's
    /// height earns a commitment — Core's `m_commit_offset`, drawn once
    /// per sync so a peer can't predict which heights are checked.
    commit_offset: u64,

    chain_start_hash: BlockHash,
    chain_start_height: u32,
    chain_start_bits: CompactTarget,
    chain_start_work: Work,

    // PRESYNC state.
    current_chain_work: Work,
    header_commitments: VecDeque<bool>,
    max_commitments: u64,
    last_header_received: BlockHeader,
    current_height: u64,

    // REDOWNLOAD state.
    redownloaded_headers: VecDeque<BlockHeader>,
    redownload_last_height: u64,
    redownload_last_hash: BlockHash,
    redownload_chain_work: Work,
    process_all_remaining: bool,

    phase: Phase,
}

impl HeadersSyncState {
    /// Starts a presync rooted at `chain_start` (the header `headers[0]`
    /// of the triggering batch extends) — Core's constructor plus its
    /// `m_max_commitments` estimate: the most headers a real chain could
    /// possibly have grown to since `chain_start`'s median time past, at
    /// the fastest rate the median-time-past rule allows (6 blocks/sec).
    /// Exceeding it can only mean the peer is feeding a fabricated
    /// chain, so the sync aborts rather than growing commitments
    /// forever.
    #[must_use]
    pub fn new(
        cs: &Chainstate,
        chain_start: &HeaderNode,
        params: Params,
        sync_params: HeadersSyncParams,
        minimum_required_work: Work,
        now: u32,
    ) -> Self {
        let salt = random_salt();
        let commit_offset = u64::from_le_bytes(salt[..8].try_into().unwrap_or([0; 8]))
            % u64::from(sync_params.commitment_period);
        let mtp = cs
            .tree()
            .median_time_past(&chain_start.hash())
            .unwrap_or(chain_start.header.time);
        let max_seconds_since_start = u64::from(now)
            .saturating_sub(u64::from(mtp))
            .saturating_add(u64::from(rules::MAX_FUTURE_BLOCK_TIME));
        let max_commitments =
            max_seconds_since_start.saturating_mul(6) / u64::from(sync_params.commitment_period);
        Self {
            params,
            sync_params,
            minimum_required_work,
            salt,
            commit_offset,
            chain_start_hash: chain_start.hash(),
            chain_start_height: chain_start.height,
            chain_start_bits: chain_start.header.bits,
            chain_start_work: chain_start.chainwork,
            current_chain_work: chain_start.chainwork,
            header_commitments: VecDeque::new(),
            max_commitments,
            last_header_received: chain_start.header,
            current_height: u64::from(chain_start.height),
            redownloaded_headers: VecDeque::new(),
            redownload_last_height: u64::from(chain_start.height),
            redownload_last_hash: chain_start.hash(),
            redownload_chain_work: chain_start.chainwork,
            process_all_remaining: false,
            phase: Phase::Presync,
        }
    }

    /// `true` once this state has nothing left to do — the caller should
    /// drop it (Core's `HeadersSyncState::State::FINAL`).
    #[must_use]
    /// How far the buffered candidate chain has grown — the presync's
    /// own progress counter while nothing is committed to the tree.
    pub fn buffered_height(&self) -> u64 {
        self.current_height
    }

    pub fn is_final(&self) -> bool {
        self.phase == Phase::Final
    }

    /// Frees the buffered state and marks this sync over — Core's
    /// `Finalize`. `mem::take` (not `clear`) drops the backing
    /// allocations, matching `ClearShrink`.
    fn finalize(&mut self) {
        let _ = std::mem::take(&mut self.header_commitments);
        let _ = std::mem::take(&mut self.redownloaded_headers);
        self.phase = Phase::Final;
    }

    /// Core's `ProcessNextHeaders`: feed one wire batch through whichever
    /// phase this sync is in. `received` must already have passed the
    /// caller's own PoW-self-consistency and internal-continuity checks
    /// (this mirrors headerssync.h's own documented precondition).
    pub fn process_next_headers(
        &mut self,
        received: &[BlockHeader],
        full_headers_message: bool,
    ) -> ProcessingResult {
        let mut ret = ProcessingResult::default();
        if received.is_empty() || self.phase == Phase::Final {
            return ret;
        }
        match self.phase {
            Phase::Presync => {
                ret.success = self.validate_and_store_headers_commitments(received);
                if ret.success && (full_headers_message || self.phase == Phase::Redownload) {
                    ret.request_more = true;
                }
                // A non-full page while still in PRESYNC means the
                // peer's chain ended without ever reaching the
                // threshold — nothing more to request.
            }
            Phase::Redownload => {
                ret.success = true;
                for header in received {
                    if !self.validate_and_store_redownloaded_header(header) {
                        ret.success = false;
                        break;
                    }
                }
                if ret.success {
                    ret.pow_validated_headers = self.pop_headers_ready_for_acceptance();
                    if !(self.redownloaded_headers.is_empty() && self.process_all_remaining) {
                        ret.request_more = full_headers_message;
                    }
                }
            }
            Phase::Final => unreachable!("checked above"),
        }
        if !(ret.success && ret.request_more) {
            self.finalize();
        }
        ret
    }

    /// PRESYNC only: validates continuity from `last_header_received`
    /// and each header's difficulty transition, accumulating claimed
    /// work; switches to REDOWNLOAD once the threshold is met. Core's
    /// `ValidateAndStoreHeadersCommitments`.
    fn validate_and_store_headers_commitments(&mut self, headers: &[BlockHeader]) -> bool {
        if headers[0].prev_block_hash != self.last_header_received.hash() {
            return false;
        }
        for header in headers {
            if !self.validate_and_process_single_header(header) {
                return false;
            }
        }
        if self.current_chain_work >= self.minimum_required_work {
            self.redownloaded_headers.clear();
            self.redownload_last_height = u64::from(self.chain_start_height);
            self.redownload_last_hash = self.chain_start_hash;
            self.redownload_chain_work = self.chain_start_work;
            self.phase = Phase::Redownload;
        }
        true
    }

    /// One PRESYNC header: Core's `ValidateAndProcessSingleHeader`.
    fn validate_and_process_single_header(&mut self, current: &BlockHeader) -> bool {
        let next_height = self.current_height + 1;
        if !permitted_difficulty_transition(
            &self.params,
            next_height,
            self.last_header_received.bits,
            current.bits,
        ) {
            return false;
        }
        if next_height % u64::from(self.sync_params.commitment_period) == self.commit_offset {
            self.header_commitments
                .push_back(commitment_bit(&self.salt, &current.hash()));
            if self.header_commitments.len() as u64 > self.max_commitments {
                return false;
            }
        }
        let Some(work) = self
            .current_chain_work
            .checked_add(Work::from_compact(current.bits))
        else {
            return false; // unreachable on any real chain; defended per this crate's style
        };
        self.current_chain_work = work;
        self.last_header_received = *current;
        self.current_height = next_height;
        true
    }

    /// One REDOWNLOAD header: continuity, difficulty transition, then
    /// the commitment check (skipped once `process_all_remaining` is
    /// set — Core's comment: a peer may have extended its chain between
    /// our two passes, and running out of commitments after the target
    /// work is already proven isn't a failure). Core's
    /// `ValidateAndStoreRedownloadedHeader`.
    fn validate_and_store_redownloaded_header(&mut self, header: &BlockHeader) -> bool {
        let next_height = self.redownload_last_height + 1;
        if header.prev_block_hash != self.redownload_last_hash {
            return false;
        }
        let previous_bits = self
            .redownloaded_headers
            .back()
            .map_or(self.chain_start_bits, |h| h.bits);
        if !permitted_difficulty_transition(&self.params, next_height, previous_bits, header.bits) {
            return false;
        }
        let Some(work) = self
            .redownload_chain_work
            .checked_add(Work::from_compact(header.bits))
        else {
            return false;
        };
        self.redownload_chain_work = work;
        if self.redownload_chain_work >= self.minimum_required_work {
            self.process_all_remaining = true;
        }
        if !self.process_all_remaining
            && next_height % u64::from(self.sync_params.commitment_period) == self.commit_offset
        {
            let Some(expected) = self.header_commitments.pop_front() else {
                return false; // commitment overrun — the peer's chain diverged
            };
            if commitment_bit(&self.salt, &header.hash()) != expected {
                return false;
            }
        }
        self.redownloaded_headers.push_back(*header);
        self.redownload_last_height = next_height;
        self.redownload_last_hash = header.hash();
        true
    }

    /// Drains headers ready for real acceptance — Core's
    /// `PopHeadersReadyForAcceptance`: past the buffer cap, or
    /// everything once `process_all_remaining` is set.
    fn pop_headers_ready_for_acceptance(&mut self) -> Vec<BlockHeader> {
        let mut ret = Vec::new();
        while self.redownloaded_headers.len() as u64
            > u64::from(self.sync_params.redownload_buffer_size)
            || (!self.redownloaded_headers.is_empty() && self.process_all_remaining)
        {
            let Some(header) = self.redownloaded_headers.pop_front() else {
                break;
            };
            ret.push(header);
        }
        ret
    }

    /// The next `getheaders` to send — Core's
    /// `NextHeadersRequestLocator`: the point we last reached in this
    /// sync, then `chain_start`'s own exponential locator as a reorg
    /// fallback.
    #[must_use]
    pub fn next_headers_request(&self, cs: &Chainstate) -> Message {
        let mut locator = Vec::with_capacity(2);
        match self.phase {
            Phase::Presync => locator.push(self.last_header_received.hash()),
            Phase::Redownload => locator.push(self.redownload_last_hash),
            Phase::Final => {}
        }
        locator.extend(locator_from(
            cs,
            self.chain_start_hash,
            self.chain_start_height,
        ));
        Message::GetHeaders(GetHeaders {
            locator,
            stop: BlockHash::ZERO,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::testchain::{chain_blocks, regtest};

    const NOW: u32 = 1_800_000_000;

    /// `easy_params` with an artificially high `minimum_chain_work` so a
    /// short test-scale chain can be made to sit below the anti-DoS
    /// threshold without mining real difficulty. Every regtest header
    /// here has bits `0x207fffff`, whose `Work::from_compact` is `2`
    /// (`arith.rs`'s own `work_from_compact_vectors` pins this).
    fn params_with_floor(min_work: u64) -> Params {
        let mut params = Network::Regtest.params();
        params.minimum_chain_work = Work(U256::from_u64(min_work));
        params
    }

    #[test]
    fn threshold_is_zero_on_a_fresh_regtest_chain() {
        // Regtest's own `minimum_chain_work` is zero and a fresh chain's
        // tip is genesis, so `near_tip_work` is also zero — the anti-DoS
        // gate must never fire for any of the existing regtest-based
        // tests.
        let cs = regtest();
        let params = *cs.tree().params();
        assert_eq!(anti_dos_work_threshold(&cs, &params), Work::ZERO);
    }

    #[test]
    fn permitted_difficulty_transition_allows_unchanged_bits_off_boundary() {
        let params = Network::Mainnet.params();
        // Height 1 is not a retarget boundary on mainnet (interval 2016)
        // — bits must repeat exactly.
        assert!(permitted_difficulty_transition(
            &params,
            1,
            CompactTarget(0x1d00_ffff),
            CompactTarget(0x1d00_ffff)
        ));
        assert!(!permitted_difficulty_transition(
            &params,
            1,
            CompactTarget(0x1d00_ffff),
            CompactTarget(0x1d00_d86a)
        ));
    }

    #[test]
    fn permitted_difficulty_transition_bounds_a_boundary_jump() {
        let params = Network::Mainnet.params();
        // At a boundary (height 2016) the target may move by at most a
        // factor of 4 either way; a claimed 5x-easier target is rejected.
        // `old` must sit far enough below `pow_limit` (2^224-ish on
        // mainnet) that scaling by 4-5x doesn't itself run into the
        // limit and get clamped there — a tiny, unmistakably-far-from-
        // limit value sidesteps that entirely.
        let old = CompactTarget::from_target(U256::from_u64(1_000_000), false);
        let target = old.expand().value;
        let five_x_easier = CompactTarget::from_target(target.wrapping_mul_u64(5), false);
        assert!(!permitted_difficulty_transition(
            &params,
            2016,
            old,
            five_x_easier
        ));
        // Exactly 4x easier is the boundary itself and must be allowed.
        let four_x_easier = CompactTarget::from_target(target.wrapping_mul_u64(4), false);
        assert!(permitted_difficulty_transition(
            &params,
            2016,
            old,
            four_x_easier
        ));
    }

    #[test]
    fn allow_min_difficulty_networks_accept_any_transition() {
        // Regtest allows minimum-difficulty blocks — any transition, at
        // any height, is permitted.
        let params = Network::Regtest.params();
        assert!(permitted_difficulty_transition(
            &params,
            0,
            CompactTarget(0x207f_ffff),
            CompactTarget(0x1d00_ffff)
        ));
    }

    /// Builds `n` headers with the given network's `chain_blocks`, then
    /// re-derives every header from `divergence_height` onward with
    /// different coinbase content — same prev-linkage, time and bits
    /// schedule (so it's just as continuous and individually PoW-valid),
    /// but a different hash at and after that point. Used to simulate a
    /// peer whose redownload no longer matches what it served in
    /// presync.
    fn diverge_after(
        cs: &Chainstate,
        chain: &[BlockHeader],
        divergence_height: usize,
    ) -> Vec<BlockHeader> {
        use avila_consensus::block::Block;
        use avila_consensus::script;
        use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};
        let params = *cs.tree().params();
        let mut out = chain[..divergence_height].to_vec();
        let mut prev = *out.last().unwrap_or(&params.genesis_header);
        for i in divergence_height..chain.len() {
            let mut script_sig = script::push_int(i as i64 + 1_000_000); // differs from testchain's coinbase_tx(height)
            script_sig.push(script::OP_1);
            let coinbase = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::NULL,
                    script_sig: Script::new(script_sig),
                    sequence: 0xffff_ffff,
                    witness: Witness::default(),
                }],
                outputs: vec![TxOut {
                    value: 5_000_000_000,
                    script_pubkey: Script::new(vec![script::OP_1]),
                }],
                lock_time: 0,
            };
            let mut block = Block {
                header: BlockHeader {
                    version: 4,
                    prev_block_hash: prev.hash(),
                    merkle_root: prev.merkle_root,
                    time: prev.time + 1,
                    bits: prev.bits,
                    nonce: 0,
                },
                transactions: vec![coinbase],
            };
            let (root, _) = block.merkle_root();
            block.header.merkle_root = root;
            while avila_consensus::pow::check_proof_of_work(
                &block.block_hash(),
                block.header.bits,
                &params,
            )
            .is_err()
            {
                block.header.nonce += 1;
            }
            out.push(block.header);
            prev = block.header;
        }
        out
    }

    /// The headline regression: a low-work chain long enough to fill a
    /// full page must never land in the header tree, however many
    /// headers the peer offers.
    #[test]
    fn full_low_work_page_starts_presync_without_storing_anything() {
        let params = params_with_floor(3_000); // 2000 headers * work(2) each clears this, but no short batch would
        let cs = Chainstate::new(&params);
        let blocks = chain_blocks(&cs, crate::message::MAX_HEADERS_RESULTS as u32);
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();

        let chain_start = *cs.tree().tip();
        let threshold = anti_dos_work_threshold(&cs, &params);
        assert_eq!(threshold, Work(U256::from_u64(3_000)));

        let sync_params = HeadersSyncParams::for_network(params.network);
        let mut state =
            HeadersSyncState::new(&cs, &chain_start, params, sync_params, threshold, NOW);
        let result = state.process_next_headers(&headers, true);

        assert!(result.success);
        assert!(result.request_more);
        assert!(result.pow_validated_headers.is_empty());
        // Nothing was ever handed to accept_header — the tree still
        // holds only genesis.
        assert_eq!(cs.tree().len(), 1);
        // 2000 headers * work(2) each comfortably clears a 3000 floor,
        // so this first full page already promoted presync to redownload.
        assert!(!state.is_final());
    }

    /// A short (non-full) low-work batch is ignored outright — Core logs
    /// "Ignoring low-work chain" and never starts a sync object.
    #[test]
    fn short_low_work_batch_is_ignored() {
        let params = params_with_floor(50_000); // unreachable within a handful of headers
        let cs = Chainstate::new(&params);
        let blocks = chain_blocks(&cs, 10);
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        let chain_start = *cs.tree().tip();
        let threshold = anti_dos_work_threshold(&cs, &params);
        let sync_params = HeadersSyncParams::for_network(params.network);
        let mut state =
            HeadersSyncState::new(&cs, &chain_start, params, sync_params, threshold, NOW);
        // A non-full page in PRESYNC: work never reaches the threshold,
        // so nothing more should be requested and the state finalizes.
        let result = state.process_next_headers(&headers, false);
        assert!(result.success);
        assert!(!result.request_more);
        assert!(state.is_final());
    }

    /// End-to-end: once the redownloaded chain's own work reaches the
    /// threshold, every buffered header (the whole chain, since regtest's
    /// `redownload_buffer_size` is 7017 — comfortably above the 2000
    /// headers used here) is released for real acceptance in one shot.
    #[test]
    fn redownload_releases_the_whole_chain_once_proven() {
        let params = params_with_floor(3_000);
        let cs = Chainstate::new(&params);
        let blocks = chain_blocks(&cs, crate::message::MAX_HEADERS_RESULTS as u32);
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        let chain_start = *cs.tree().tip();
        let threshold = anti_dos_work_threshold(&cs, &params);

        let sync_params = HeadersSyncParams::for_network(params.network);
        let mut state =
            HeadersSyncState::new(&cs, &chain_start, params, sync_params, threshold, NOW);
        let first = state.process_next_headers(&headers, true);
        assert!(first.success && first.request_more);

        // Redownload re-requests the identical range from chain_start.
        let second = state.process_next_headers(&headers, true);
        assert!(second.success);
        assert_eq!(second.pow_validated_headers.len(), headers.len());
        assert_eq!(second.pow_validated_headers, headers);
        assert!(
            state.is_final(),
            "work cleared the floor mid-batch, so the sync should be complete"
        );
        assert!(!second.request_more);
    }

    /// A peer that served one chain during PRESYNC but a differently
    /// -hashed (though still internally valid) chain during REDOWNLOAD
    /// fails a commitment check partway through and the sync is
    /// abandoned — not treated as misbehavior on its own, just given up.
    #[test]
    fn redownload_detects_commitment_mismatch() {
        let params = params_with_floor(3_000);
        let cs = Chainstate::new(&params);
        let blocks = chain_blocks(&cs, crate::message::MAX_HEADERS_RESULTS as u32);
        let headers: Vec<BlockHeader> = blocks.iter().map(|b| b.header).collect();
        let chain_start = *cs.tree().tip();
        let threshold = anti_dos_work_threshold(&cs, &params);
        let sync_params = HeadersSyncParams::for_network(params.network);

        // Diverge right after the shared starting point: every commit
        // height (period 275 on regtest, ~5 of them fall before the
        // ~1500th header crosses the work threshold here) now hashes
        // differently from what presync committed to. Each commitment
        // is an independently salted coin flip, so a single draw has a
        // small (~3%) chance of every check coincidentally agreeing
        // anyway; retrying with a fresh salt each time (`new` draws one
        // every call) makes that astronomically unlikely rather than
        // leaving the suite flaky.
        let forged = diverge_after(&cs, &headers, 1);
        let detected = (0..20).any(|_| {
            let mut state =
                HeadersSyncState::new(&cs, &chain_start, params, sync_params, threshold, NOW);
            let first = state.process_next_headers(&headers, true);
            assert!(first.success && first.request_more);
            let second = state.process_next_headers(&forged, true);
            !second.success && state.is_final()
        });
        assert!(
            detected,
            "a divergent redownload should fail a commitment check well within 20 attempts"
        );
    }
}

//! Opt-in full-check Swift IBD driver primitives.
//!
//! This driver keeps block validation provisional until every block through the
//! pinned checkpoint has passed ordinary full validation and the local audit has
//! matched. The caller owns peer scheduling and ordinary-sync fallback.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use avila_consensus::block::Block;
use avila_consensus::chain::{HeaderTree, InsertStatus};
use avila_consensus::chainstate::Chainstate;
use avila_consensus::hash::BlockHash;
use avila_consensus::params::Params;
use avila_consensus::swift_audit::AuditVerdict;
use avila_consensus::swift_engine::{
    AuditedSwiftSnapshot, InputCoinClaim, SwiftEngineError, SwiftValidationEngine,
};
use avila_consensus::swift_hints::{Bip456HintsError, Bip456HintsReader};
use avila_consensus::swift_live::{
    DEFAULT_REORG_DEPTH, MAX_BLOCK_EVENTS, SwiftLiveBinding, SwiftLiveError, SwiftLiveIndex,
    SwiftLiveLimits,
};
use avila_consensus::swift_stump::{SwiftCheckpoint, SwiftStumpBuilder, SwiftStumpLimits};
use avila_consensus::transaction::OutPoint;
use avila_p2p::swift_spent::{GetSpentCoins, SpentCoins, SpentCoinsBatchPlan, SpentCoinsError};

/// File and durable workspace for one explicitly pinned Swift checkpoint.
#[derive(Clone, Debug)]
pub struct SwiftIbdOptions {
    /// User-selected checkpoint height.
    pub checkpoint_height: u32,
    /// User-selected checkpoint hash; the full validator checks its header ancestry.
    pub checkpoint_hash: BlockHash,
    /// Draft BIP456 v0 hintfile, bound here to height and later to the full audit.
    pub hints_path: PathBuf,
    /// Fresh or resumable private Swift staging directory. Never the node datadir.
    pub workspace: PathBuf,
}

/// Per-block result, still provisional until [`SwiftIbdDriver::into_snapshot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwiftBlockProgress {
    /// Fully script-checked height.
    pub height: u32,
    /// Locally computed block identifier.
    pub hash: BlockHash,
    /// Whether this reached the configured checkpoint.
    pub checkpoint_reached: bool,
}

/// Result of starting a body: either it can be checked immediately or requires
/// one exact provider response before processing.
#[derive(Clone, Debug)]
pub enum SwiftBlockStart {
    /// This block has no inputs sourced from earlier blocks and was processed.
    Processed(SwiftBlockProgress),
    /// Request this exact index set from this plan's provider.
    NeedsSpentCoins {
        /// Draft BIP455 request.
        request: GetSpentCoins,
        /// Exact sorted non-coinbase input ordinals expected in the response.
        input_indices: Vec<u32>,
    },
    /// Body retained in the bounded ordered queue while an earlier block waits
    /// for its spent-coin response.
    Queued,
}

const MAX_QUEUED_SWIFT_BODIES: usize = 4;
// One body may be pending a claim response; four manager reservations in all
// therefore remain within the protocol's 4,000,000-byte serialized body limit.
const MAX_QUEUED_SWIFT_BODY_BYTES: usize = 16 * 1024 * 1024;
// Conservatively mirrors the block decoder's 64x wire reservation plus its
// per-block overhead. This is a retained decoded-memory budget, not a claim
// that encoded bytes equal heap usage.
const MAX_RETAINED_SWIFT_DECODED_BYTES: usize = 256 * 1024 * 1024;

fn swift_body_queue_capacity(has_pending: bool) -> (usize, usize) {
    if has_pending {
        (
            MAX_QUEUED_SWIFT_BODIES - 1,
            MAX_QUEUED_SWIFT_BODY_BYTES - avila_consensus::block::MAX_BLOCK_SERIALIZED_SIZE,
        )
    } else {
        (MAX_QUEUED_SWIFT_BODIES, MAX_QUEUED_SWIFT_BODY_BYTES)
    }
}

fn swift_body_fits_queue(
    queued_count: usize,
    queued_bytes: usize,
    retained_decoded_bytes: usize,
    has_pending: bool,
    encoded_bytes: usize,
) -> bool {
    let (max_count, max_bytes) = swift_body_queue_capacity(has_pending);
    let decoded_reservation = encoded_bytes.saturating_mul(64).saturating_add(4096);
    queued_count < max_count
        && queued_bytes
            .checked_add(encoded_bytes)
            .is_some_and(|total| total <= max_bytes)
        && retained_decoded_bytes
            .checked_add(decoded_reservation)
            .is_some_and(|total| total <= MAX_RETAINED_SWIFT_DECODED_BYTES)
}

fn next_swift_body_index(queued: &VecDeque<QueuedBody>, parent: BlockHash) -> Option<usize> {
    queued
        .iter()
        .position(|body| body.block.header.prev_block_hash == parent)
}

struct QueuedBody {
    peer_id: u64,
    block: Block,
    encoded_bytes: usize,
}

struct PendingBlock {
    peer_id: u64,
    block: Block,
    plan: SpentCoinsBatchPlan,
}

/// Sequential full-script Swift IBD attempt. Its state is durable and resumable;
/// ordinary Chainstate remains the only publication path.
pub struct SwiftIbdDriver {
    target_height: u32,
    target_hash: BlockHash,
    engine: Option<SwiftValidationEngine>,
    completed: Option<AuditedSwiftSnapshot>,
    hints: Option<Bip456HintsReader<BufReader<File>>>,
    pending: Option<PendingBlock>,
    queued: VecDeque<QueuedBody>,
    queued_bytes: usize,
    retained_decoded_bytes: usize,
}

/// Resource, protocol, or consensus failure that requires ordinary-sync fallback.
#[derive(Debug, thiserror::Error)]
pub enum SwiftIbdError {
    /// Local file or database failure.
    #[error("Swift IBD local storage: {0}")]
    Io(#[from] std::io::Error),
    /// BIP456 file framing, bound, or ordering failure.
    #[error("Swift IBD hints: {0}")]
    Hints(#[from] Bip456HintsError),
    /// BIP455 request/response binding failure.
    #[error("Swift IBD spent coins: {0}")]
    SpentCoins(#[from] SpentCoinsError),
    /// Swift engine found a consensus or local-index inconsistency.
    #[error("Swift IBD validation: {0}")]
    Engine(#[from] SwiftEngineError),
    /// Local durable live-index error.
    #[error("Swift IBD live index: {0}")]
    Live(#[from] SwiftLiveError),
    /// Provisional Utreexo forest error.
    #[error("Swift IBD stump: {0}")]
    Stump(String),
    /// Attempt must be abandoned and ordinary validation used.
    #[error("Swift IBD requires ordinary fallback: {0}")]
    Fallback(&'static str),
}

impl SwiftIbdDriver {
    /// Opens a new or resumable attempt bound to the supplied checkpoint and rules.
    /// `header_source` is the node's isolated header-only staging chainstate.
    pub fn open(
        options: &SwiftIbdOptions,
        mut params: Params,
        header_source: &Chainstate,
        now: u32,
    ) -> Result<Self, SwiftIbdError> {
        const MAX_HINTFILE_BYTES: u64 = 128 * 1024 * 1024 * 1024;
        // These are persistent redb working-state ceilings, not RAM estimates.
        // The live index separately caps its redb cache at 64 MiB; block decode,
        // stump batching, and the ordinary chainstate cache have independent
        // bounded budgets. Exceeding either disk ceiling falls back to ordinary
        // validation and never classifies a block as consensus-invalid.
        const MAX_LIVE_COINS: u64 = 180_000_000;
        const MAX_LIVE_INDEX_BYTES: u64 = 7 * 1024 * 1024 * 1024;

        if options.checkpoint_height == 0
            || options.checkpoint_hash == BlockHash::ZERO
            || header_source.chain().len() != 1
        {
            return Err(SwiftIbdError::Fallback(
                "invalid checkpoint or nonempty source state",
            ));
        }
        let hints_metadata = std::fs::metadata(&options.hints_path)?;
        if hints_metadata.len() < 9 || hints_metadata.len() > MAX_HINTFILE_BYTES {
            return Err(SwiftIbdError::Fallback(
                "hintfile size is outside local bounds",
            ));
        }
        std::fs::create_dir_all(&options.workspace)?;
        #[cfg(unix)]
        std::fs::set_permissions(
            &options.workspace,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;

        params.assume_valid = None;
        let binding = SwiftLiveBinding {
            network: params.network,
            start_height: 0,
            start_hash: params.genesis_header.hash(),
            target_height: options.checkpoint_height,
            target_hash: options.checkpoint_hash,
            params_commitment: params.swift_validation_commitment(),
        };
        let limits = live_limits(MAX_LIVE_COINS, MAX_LIVE_INDEX_BYTES);
        let live_path = options.workspace.join("swift-live.redb");
        let exists = live_path.exists();
        let live = if exists {
            SwiftLiveIndex::open(&live_path, binding, limits)?
        } else {
            SwiftLiveIndex::create(&live_path, binding, limits)?
        };
        let (height, hash) = live.tip();
        let header_tree = tree_through(header_source.tree(), height, hash, params, now)?;

        if live.is_complete() {
            let snapshot =
                SwiftValidationEngine::recover_completed_snapshot(params, header_tree, live)?;
            return Ok(Self {
                target_height: binding.target_height,
                target_hash: binding.target_hash,
                engine: None,
                completed: Some(snapshot),
                hints: None,
                pending: None,
                queued: VecDeque::new(),
                queued_bytes: 0,
                retained_decoded_bytes: 0,
            });
        }

        let mut engine = if exists {
            SwiftValidationEngine::resume(params, header_tree, live)?
        } else {
            let audit = avila_consensus::swift_audit::SwiftAudit::new(
                params.network,
                binding.target_height,
                binding.target_hash,
            )
            .map_err(SwiftEngineError::from)?;
            SwiftValidationEngine::new(params, header_tree, live, audit)?
        };
        if !engine.has_provisional_stump() {
            let stump = SwiftStumpBuilder::new(
                SwiftCheckpoint {
                    first_height: 1,
                    last_height: binding.target_height,
                    checkpoint_hash: *binding.target_hash.as_bytes(),
                },
                stump_limits(),
            )
            .map_err(|error| SwiftIbdError::Stump(format!("{error:?}")))?;
            engine
                .enable_provisional_stump(stump)
                .map_err(|error| SwiftIbdError::Stump(format!("{error:?}")))?;
        }
        engine.sync_active_headers(header_source.tree(), now)?;

        let file = File::open(&options.hints_path)?;
        let mut hints = Bip456HintsReader::new(
            BufReader::new(file),
            binding.target_height,
            hints_metadata.len(),
        )?;
        for prior_height in 0..=height {
            // Earlier records are only consumed to restore the sequential parser cursor.
            // Their untrusted indices were already bound by the persisted keyed audit.
            let _ = hints.next_indices(prior_height, u32::MAX as usize)?;
        }

        Ok(Self {
            target_height: binding.target_height,
            target_hash: binding.target_hash,
            engine: Some(engine),
            completed: None,
            hints: Some(hints),
            pending: None,
            queued: VecDeque::new(),
            queued_bytes: 0,
            retained_decoded_bytes: 0,
        })
    }

    /// Incorporates newly received active headers under the engine's own rules.
    pub fn sync_headers(&mut self, source: &HeaderTree, now: u32) -> Result<(), SwiftIbdError> {
        if let Some(engine) = &mut self.engine {
            engine.sync_active_headers(source, now)?;
        }
        Ok(())
    }

    /// Current durable full-check frontier. It is provisional, not the node's checked tip.
    #[must_use]
    pub fn tip(&self) -> (u32, BlockHash) {
        self.engine.as_ref().map_or(
            (self.target_height, self.target_hash),
            SwiftValidationEngine::tip,
        )
    }

    /// Prepares one body. The caller sends the returned BIP455 request to this exact peer;
    /// an empty input list is processed immediately without network acquisition.
    pub fn begin_block(
        &mut self,
        peer_id: u64,
        block: Block,
        now: u32,
    ) -> Result<SwiftBlockStart, SwiftIbdError> {
        if self.completed.is_some() {
            return Err(SwiftIbdError::Fallback(
                "driver already completed the checkpoint",
            ));
        }
        let expected_parent = self
            .engine
            .as_ref()
            .ok_or(SwiftIbdError::Fallback("driver is closed"))?
            .tip()
            .1;
        if self.pending.is_some() || block.header.prev_block_hash != expected_parent {
            let block_hash = block.block_hash();
            if self
                .pending
                .as_ref()
                .is_some_and(|pending| pending.block.block_hash() == block_hash)
                || self
                    .queued
                    .iter()
                    .any(|queued| queued.block.block_hash() == block_hash)
            {
                return Ok(SwiftBlockStart::Queued);
            }
            let encoded_bytes = block.size_with_witness();
            let decoded_reservation = encoded_bytes.saturating_mul(64).saturating_add(4096);
            if !swift_body_fits_queue(
                self.queued.len(),
                self.queued_bytes,
                self.retained_decoded_bytes,
                self.pending.is_some(),
                encoded_bytes,
            ) {
                return Err(SwiftIbdError::Fallback(
                    "ordered captured-body queue reached its bound",
                ));
            }
            self.queued_bytes += encoded_bytes;
            self.retained_decoded_bytes += decoded_reservation;
            self.queued.push_back(QueuedBody {
                peer_id,
                block,
                encoded_bytes,
            });
            return Ok(SwiftBlockStart::Queued);
        }
        let encoded_bytes = block.size_with_witness();
        let decoded_reservation = encoded_bytes.saturating_mul(64).saturating_add(4096);
        if decoded_reservation > MAX_RETAINED_SWIFT_DECODED_BYTES {
            return Err(SwiftIbdError::Fallback(
                "captured body exceeds the retained decode budget",
            ));
        }
        self.retained_decoded_bytes = self
            .retained_decoded_bytes
            .checked_add(decoded_reservation)
            .filter(|total| *total <= MAX_RETAINED_SWIFT_DECODED_BYTES)
            .ok_or(SwiftIbdError::Fallback(
                "captured bodies exceed the retained decode budget",
            ))?;
        let engine = self
            .engine
            .as_mut()
            .ok_or(SwiftIbdError::Fallback("driver is closed"))?;
        let height = engine
            .tip()
            .0
            .checked_add(1)
            .ok_or(SwiftIbdError::Fallback("height overflow"))?;
        let plan = SpentCoinsBatchPlan::for_block(
            peer_id,
            &block,
            height,
            self.target_height,
            self.target_hash,
        )?;
        let (request, indices) = plan.request();
        self.pending = Some(PendingBlock {
            peer_id,
            block,
            plan,
        });
        if indices.is_empty() {
            let pending = self
                .pending
                .take()
                .ok_or(SwiftIbdError::Fallback("pending block disappeared"))?;
            let pending_bytes = pending
                .block
                .size_with_witness()
                .saturating_mul(64)
                .saturating_add(4096);
            let result = self.process_block(pending.block, Vec::new(), now);
            self.retained_decoded_bytes = self.retained_decoded_bytes.saturating_sub(pending_bytes);
            Ok(SwiftBlockStart::Processed(result?))
        } else {
            Ok(SwiftBlockStart::NeedsSpentCoins {
                request,
                input_indices: indices,
            })
        }
    }

    /// Starts the next retained body after the preceding body was checked.
    /// The caller owns peer scheduling and must send any returned request.
    pub fn start_queued_block(
        &mut self,
        now: u32,
    ) -> Result<Option<(u64, SwiftBlockStart)>, SwiftIbdError> {
        if self.pending.is_some() || self.completed.is_some() {
            return Ok(None);
        }
        let expected_parent = self
            .engine
            .as_ref()
            .ok_or(SwiftIbdError::Fallback("driver is closed"))?
            .tip()
            .1;
        let Some(index) = next_swift_body_index(&self.queued, expected_parent) else {
            return Ok(None);
        };
        let queued = self
            .queued
            .remove(index)
            .ok_or(SwiftIbdError::Fallback("queued body disappeared"))?;
        self.queued_bytes = self.queued_bytes.saturating_sub(queued.encoded_bytes);
        let peer_id = queued.peer_id;
        let decoded_reservation = queued.encoded_bytes.saturating_mul(64).saturating_add(4096);
        self.retained_decoded_bytes = self
            .retained_decoded_bytes
            .saturating_sub(decoded_reservation);
        self.begin_block(peer_id, queued.block, now)
            .map(|start| Some((peer_id, start)))
    }

    /// Binds the peer's response to the one pending locally parsed block and validates it.
    pub fn accept_spent_coins(
        &mut self,
        peer_id: u64,
        response: SpentCoins,
        now: u32,
    ) -> Result<SwiftBlockProgress, SwiftIbdError> {
        let pending = self
            .pending
            .take()
            .ok_or(SwiftIbdError::Fallback("unsolicited spent-coin response"))?;
        let pending_bytes = pending
            .block
            .size_with_witness()
            .saturating_mul(64)
            .saturating_add(4096);
        if pending.peer_id != peer_id {
            return Err(SwiftIbdError::Fallback("spent-coin provider changed"));
        }
        let claims = pending.plan.bind_response(peer_id, response)?;
        let result = self.process_block(pending.block, claims, now);
        self.retained_decoded_bytes = self.retained_decoded_bytes.saturating_sub(pending_bytes);
        result
    }

    fn process_block(
        &mut self,
        block: Block,
        claims: Vec<InputCoinClaim>,
        now: u32,
    ) -> Result<SwiftBlockProgress, SwiftIbdError> {
        let engine = self
            .engine
            .as_mut()
            .ok_or(SwiftIbdError::Fallback("driver is closed"))?;
        let height = engine
            .tip()
            .0
            .checked_add(1)
            .ok_or(SwiftIbdError::Fallback("height overflow"))?;
        let spendable = spendable_output_ordinals(&block)?;
        let hints = self
            .hints
            .as_mut()
            .ok_or(SwiftIbdError::Fallback("hint reader is closed"))?;
        let survivors = hints.next_indices(height, spendable.len())?;
        let overwrite_claims = engine.required_bip30_overwrites(&block)?;
        engine.connect_block(
            &block,
            now,
            &claims,
            &overwrite_claims,
            |outpoint, _coin| {
                let Some(index) = spendable.get(&outpoint) else {
                    return Err(SwiftEngineError::ClaimsMismatch);
                };
                Ok(survivors.binary_search(index).is_ok())
            },
        )?;
        let hash = block.block_hash();
        Ok(SwiftBlockProgress {
            height,
            hash,
            checkpoint_reached: height == self.target_height && hash == self.target_hash,
        })
    }

    /// Finishes the keyed audit and returns the only token accepted by the ordinary
    /// chainstate promotion path. A mismatch never produces a token.
    pub fn into_snapshot(mut self) -> Result<AuditedSwiftSnapshot, SwiftIbdError> {
        if let Some(snapshot) = self.completed.take() {
            return Ok(snapshot);
        }
        if self.pending.is_some() {
            return Err(SwiftIbdError::Fallback("a block response is still pending"));
        }
        let engine = self
            .engine
            .as_mut()
            .ok_or(SwiftIbdError::Fallback("driver is closed"))?;
        if engine.tip() != (self.target_height, self.target_hash) {
            return Err(SwiftIbdError::Fallback(
                "pinned target has not been fully checked",
            ));
        }
        let report = engine.finish_audit()?;
        if report.audit.verdict != AuditVerdict::Match || report.stump.is_none() {
            return Err(SwiftIbdError::Fallback(
                "full-coin audit or stump did not match",
            ));
        }
        self.engine
            .take()
            .ok_or(SwiftIbdError::Fallback("driver is closed"))?
            .into_audited_snapshot()
            .map_err(SwiftIbdError::from)
    }
}

fn tree_through(
    source: &HeaderTree,
    height: u32,
    expected_hash: BlockHash,
    params: Params,
    now: u32,
) -> Result<HeaderTree, SwiftIbdError> {
    let active = source.best_chain();
    if active.get(height as usize) != Some(&expected_hash) {
        return Err(SwiftIbdError::Fallback(
            "staged headers do not contain the durable Swift tip",
        ));
    }
    let mut tree = HeaderTree::new(params);
    for hash in active.iter().take(height as usize + 1).skip(1) {
        let header = source
            .get(hash)
            .ok_or(SwiftIbdError::Fallback("active header disappeared"))?
            .header;
        match tree
            .insert(&header, now)
            .map_err(|_| SwiftIbdError::Fallback("header path failed independent replay"))?
        {
            InsertStatus::Added { .. } | InsertStatus::AlreadyKnown { .. } => {}
        }
    }
    Ok(tree)
}

fn spendable_output_ordinals(block: &Block) -> Result<HashMap<OutPoint, u32>, SwiftIbdError> {
    let count = block
        .transactions
        .iter()
        .flat_map(|tx| tx.outputs.iter())
        .filter(|output| output.value >= 0 && !output.script_pubkey.is_unspendable())
        .count();
    let mut map = HashMap::with_capacity(count);
    let mut ordinal = 0u32;
    for tx in &block.transactions {
        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            if output.value < 0 || output.script_pubkey.is_unspendable() {
                continue;
            }
            let outpoint = OutPoint {
                txid,
                vout: u32::try_from(vout)
                    .map_err(|_| SwiftIbdError::Fallback("output index overflow"))?,
            };
            if map.insert(outpoint, ordinal).is_some() {
                return Err(SwiftIbdError::Fallback(
                    "duplicate spendable outpoint in one block",
                ));
            }
            ordinal = ordinal
                .checked_add(1)
                .ok_or(SwiftIbdError::Fallback("output ordinal overflow"))?;
        }
    }
    Ok(map)
}

fn live_limits(max_entries: u64, max_live_bytes: u64) -> SwiftLiveLimits {
    SwiftLiveLimits {
        max_live_entries: max_entries,
        max_live_encoded_bytes: max_live_bytes,
        max_undo_encoded_bytes: 2 * 1024 * 1024 * 1024,
        max_survivor_entries: max_entries,
        max_survivor_encoded_bytes: 1024 * 1024 * 1024 * 1024,
        max_reorg_depth: DEFAULT_REORG_DEPTH,
        max_block_events: MAX_BLOCK_EVENTS,
        cache_bytes: 64 * 1024 * 1024,
    }
}

fn stump_limits() -> SwiftStumpLimits {
    SwiftStumpLimits {
        max_pending_blocks: 1,
        max_pending_leaves: 4_000_000,
        max_pending_bytes: 256 * 1024 * 1024,
        max_batch_leaves: 4_000_000,
        max_batch_bytes: 256 * 1024 * 1024,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use avila_consensus::arith::CompactTarget;
    use avila_consensus::hash::MerkleRoot;
    use avila_consensus::header::BlockHeader;

    fn queued_body(parent: u8) -> QueuedBody {
        QueuedBody {
            peer_id: u64::from(parent),
            block: Block {
                header: BlockHeader {
                    version: 1,
                    prev_block_hash: BlockHash::from_bytes([parent; 32]),
                    merkle_root: MerkleRoot::from_bytes([0; 32]),
                    time: 0,
                    bits: CompactTarget(0),
                    nonce: 0,
                },
                transactions: Vec::new(),
            },
            encoded_bytes: 80,
        }
    }

    fn insert_queued(
        queued: &mut VecDeque<QueuedBody>,
        queued_bytes: &mut usize,
        retained_decoded_bytes: &mut usize,
        has_pending: bool,
        body: QueuedBody,
    ) -> bool {
        let encoded = body.encoded_bytes;
        let decoded = encoded * 64 + 4096;
        if !swift_body_fits_queue(
            queued.len(),
            *queued_bytes,
            *retained_decoded_bytes,
            has_pending,
            encoded,
        ) {
            return false;
        }
        *queued_bytes += encoded;
        *retained_decoded_bytes += decoded;
        queued.push_back(body);
        true
    }

    #[test]
    fn four_body_window_accepts_expected_parent_as_fourth_out_of_order_arrival() {
        let mut queued = VecDeque::new();
        let (mut bytes, mut decoded) = (0, 0);
        for parent in [1, 2, 3] {
            assert!(insert_queued(
                &mut queued,
                &mut bytes,
                &mut decoded,
                false,
                queued_body(parent),
            ));
        }
        // The three future bodies do not advance the provisional tip. The matching
        // body may still arrive fourth and is selected once its parent is expected.
        let provisional_tip = BlockHash::from_bytes([9; 32]);
        assert!(insert_queued(
            &mut queued,
            &mut bytes,
            &mut decoded,
            false,
            queued_body(9),
        ));
        assert_eq!(provisional_tip, BlockHash::from_bytes([9; 32]));
        let expected_parent = provisional_tip;
        assert_eq!(next_swift_body_index(&queued, expected_parent), Some(3));
        let before_fifth = (queued.len(), bytes, decoded, provisional_tip);
        assert!(!insert_queued(
            &mut queued,
            &mut bytes,
            &mut decoded,
            false,
            queued_body(10),
        ));
        assert_eq!(
            (queued.len(), bytes, decoded, provisional_tip),
            before_fifth,
            "a fifth body must fail without changing queue/accounting/tip"
        );
        queued.remove(3);
        assert_eq!(queued.len(), 3);
        assert_eq!(next_swift_body_index(&queued, expected_parent), None);
    }

    #[test]
    fn pending_body_plus_three_queued_bodies_is_the_four_body_limit() {
        let mut queued = VecDeque::new();
        let (mut bytes, mut decoded) = (0, 80 * 64 + 4096); // active claim body
        for parent in [1, 2, 3] {
            assert!(insert_queued(
                &mut queued,
                &mut bytes,
                &mut decoded,
                true,
                queued_body(parent),
            ));
        }
        assert_eq!(queued.len(), 3);
        let before_fifth = (queued.len(), bytes, decoded);
        assert!(!insert_queued(
            &mut queued,
            &mut bytes,
            &mut decoded,
            true,
            queued_body(4),
        ));
        assert_eq!((queued.len(), bytes, decoded), before_fifth);
    }
}

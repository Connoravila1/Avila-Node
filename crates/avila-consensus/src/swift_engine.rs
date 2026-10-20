//! Sequential full-check SwiftSync fixture engine.
//!
//! Spent coins arrive as untrusted per-block claims. The engine checks their exact
//! outpoint and creation metadata against a compact live-status index, then supplies
//! only the current block's input coins to ordinary full validation. A keyed transcript
//! audit binds the claimed coin bodies to locally parsed outputs at the checkpoint.
//! This is an experimental offline stage: transcript state and provisional survivor coins
//! are durably checkpointed, but no conventional node UTXO database is promoted.

use std::collections::HashMap;

use crate::block::Block;
use crate::chain::{HeaderTree, InsertStatus};
use crate::check::{self, BlockContext};
use crate::connect::{self, Coin, ConnectContext, UtxoSet};
use crate::hash::BlockHash;
use crate::params::Params;
use crate::swift_audit::{AuditError, AuditVerdict, SwiftAudit};
use crate::swift_live::MAX_BLOCK_EVENTS;
use crate::swift_live::{LiveCoinMeta, LiveEvent, SwiftLiveError, SwiftLiveIndex};
use crate::swift_stump::{
    ExternalAuditPassed, ProvisionalStump, SwiftCheckpoint, SwiftStumpBuilder, SwiftStumpError,
};
use crate::transaction::OutPoint;

/// Hard ceiling on externally supplied per-block coin records.
pub const MAX_BLOCK_COIN_CLAIMS: usize = 100_000;
/// Encoded script/value/metadata budget for all supplied coin claims in one block.
/// Decoders must also enforce this before allocating the claims themselves.
pub const MAX_BLOCK_CLAIM_BYTES: usize = 64 * 1024 * 1024;

/// One untrusted coin supplied for a prior-block input.
pub type InputCoinClaim = (OutPoint, Coin);

/// One untrusted prior coin replaced by an exact historical BIP30 repeat block.
pub type OverwriteCoinClaim = (OutPoint, Coin);

/// Audit outcome and, only after a matching audit, an explicitly provisional stump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwiftFinishReport {
    /// Full-coin checkpoint audit counters and verdict.
    pub audit: crate::swift_audit::AuditReport,
    /// Provisional root set built with rustreexo 0.7 and implicit empty leaves.
    /// This is never itself a consensus acceptance or node promotion result.
    pub stump: Option<ProvisionalStump>,
}

/// Opaque proof that a local full-check transcript, survivor set, and stump
/// all matched the configured checkpoint. Only this module can construct it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwiftCheckpointSeal {
    network: crate::params::Network,
    height: u32,
    hash: BlockHash,
    leaf_count: u64,
    survivor_count: u64,
}

impl SwiftCheckpointSeal {
    /// Network bound to the successful full-check transcript.
    #[must_use]
    pub const fn network(self) -> crate::params::Network {
        self.network
    }
    /// Audited checkpoint height.
    #[must_use]
    pub const fn height(self) -> u32 {
        self.height
    }
    /// Audited checkpoint hash.
    #[must_use]
    pub const fn hash(self) -> BlockHash {
        self.hash
    }
    /// Provisional accumulator leaf count at the checkpoint.
    #[must_use]
    pub const fn leaf_count(self) -> u64 {
        self.leaf_count
    }
    /// Survivor count authenticated by the matching full-coin audit.
    #[must_use]
    pub const fn survivor_count(self) -> u64 {
        self.survivor_count
    }
}

/// Finalized source for ordinary-chainstate promotion. It keeps the private
/// completed database and validated header tree alive while the owner streams
/// survivors, active headers, block bodies, and full connector undo records.
pub struct AuditedSwiftSnapshot {
    seal: SwiftCheckpointSeal,
    stump: ProvisionalStump,
    /// Exact normalized consensus rules used by the engine (assume-valid disabled).
    params: Params,
    live: SwiftLiveIndex,
    tree: HeaderTree,
    undo_floor_height: u32,
    undo_floor_hash: BlockHash,
}

impl AuditedSwiftSnapshot {
    /// The unforgeable, exact checkpoint/audit seal fields.
    #[must_use]
    pub const fn seal(&self) -> SwiftCheckpointSeal {
        self.seal
    }

    /// Bitcoin network whose parameters validated the transcript.
    #[must_use]
    pub const fn network(&self) -> crate::params::Network {
        self.seal.network
    }

    /// Exact normalized consensus parameters used for full validation.
    ///
    /// `assume_valid` is always `None`: the Swift engine never accepts a
    /// snapshot on the basis of an assume-valid policy.
    #[must_use]
    pub const fn params(&self) -> &Params {
        &self.params
    }

    /// Fully validated checkpoint height.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.seal.height
    }

    /// Fully validated checkpoint hash.
    #[must_use]
    pub const fn hash(&self) -> BlockHash {
        self.seal.hash
    }

    /// Leaf count committed by the audited rustreexo stump.
    #[must_use]
    pub const fn leaf_count(&self) -> u64 {
        self.seal.leaf_count
    }

    /// Number of ordered survivor coins authenticated by the checkpoint audit.
    #[must_use]
    pub const fn survivor_count(&self) -> u64 {
        self.seal.survivor_count
    }

    /// The rustreexo 0.7 roots and exact leaf count at the audited target.
    #[must_use]
    pub fn stump(&self) -> &ProvisionalStump {
        &self.stump
    }

    /// Parent height/hash below which ordinary disconnect is unavailable.
    #[must_use]
    pub const fn undo_floor(&self) -> (u32, BlockHash) {
        (self.undo_floor_height, self.undo_floor_hash)
    }

    /// Streams every full survivor coin in exact outpoint-key order.
    pub fn for_each_survivor(
        &self,
        visit: impl FnMut(OutPoint, LiveCoinMeta, Coin) -> Result<(), SwiftLiveError>,
    ) -> Result<(), SwiftLiveError> {
        self.live.for_each_audited_survivor(visit)
    }

    /// Streams the active header path from genesis through the checkpoint.
    pub fn for_each_active_header(
        &self,
        mut visit: impl FnMut(u32, crate::header::BlockHeader) -> Result<(), SwiftLiveError>,
    ) -> Result<(), SwiftLiveError> {
        for height in 0..=self.seal.height {
            let node = self
                .tree
                .get_ancestor(&self.seal.hash, height)
                .filter(|node| node.height == height)
                .ok_or(SwiftLiveError::Corrupt)?;
            visit(height, node.header)?;
        }
        Ok(())
    }

    /// Streams per-height transaction and cumulative transaction counts for
    /// connected active-chain blocks. Genesis is represented by `(1, 1)`.
    pub fn for_each_active_tx_meta(
        &self,
        mut visit: impl FnMut(u32, BlockHash, u32, u64) -> Result<(), SwiftLiveError>,
    ) -> Result<(), SwiftLiveError> {
        for height in 0..=self.seal.height {
            let node = self
                .tree
                .get_ancestor(&self.seal.hash, height)
                .filter(|node| node.height == height)
                .ok_or(SwiftLiveError::Corrupt)?;
            visit(height, node.header.hash(), node.n_tx, node.n_chain_tx)?;
        }
        Ok(())
    }

    /// Streams the retained final full block bodies and connector undos.
    pub(crate) fn for_each_block_undo(
        &self,
        visit: impl FnMut(
            u32,
            BlockHash,
            BlockHash,
            Block,
            connect::BlockUndo,
        ) -> Result<(), SwiftLiveError>,
    ) -> Result<usize, SwiftLiveError> {
        let (_, _, count) = self.live.for_each_audited_undo(visit)?;
        Ok(count)
    }
}

/// Failures from standalone full-check block processing.
#[derive(Debug, thiserror::Error)]
pub enum SwiftEngineError {
    /// The configured components do not share one Bitcoin window and tip.
    #[error("swift engine component binding mismatch")]
    BindingMismatch,
    /// Candidate block does not extend the durable live-index tip.
    #[error("candidate block does not extend current swift tip")]
    WrongParent,
    /// Header insertion or contextual difficulty/time validation failed.
    #[error("header validation failed: {0}")]
    Header(String),
    /// Context-free block validation failed.
    #[error("context-free block validation failed: {0}")]
    Block(String),
    /// Contextual block validation failed.
    #[error("contextual block validation failed: {0}")]
    Context(String),
    /// BIP30 found an unspent collision in the exact compact status index.
    #[error("BIP30 duplicate live output at {0:?}")]
    Bip30(OutPoint),
    /// Input claims did not exactly match the block's external inputs.
    #[error("input coin claims are missing, duplicated, or unused")]
    ClaimsMismatch,
    /// The candidate exceeds a local Swift resource budget; the caller should use
    /// ordinary validation instead of treating this as a consensus-invalid block.
    #[error("swift per-block resource budget exceeded; use ordinary validation")]
    ResourceLimit,
    /// Claims failed exact live metadata or BIP30 overwrite checks.
    #[error("untrusted coin claim differs from local history metadata")]
    CoinMismatch,
    /// An input did not exist in the expected prior-block or earlier-same-block set.
    #[error("input is unknown, future-created, or already spent")]
    InputUnavailable,
    /// Ordinary UTXO and script checks rejected the candidate block.
    #[error("ordinary block connection failed: {0}")]
    Connect(String),
    /// A prior cross-store commit failed; this provisional session cannot continue.
    #[error("swift validation session is poisoned and must be discarded")]
    SessionPoisoned,
    /// The provisional Utreexo transcript rejected a height batch or checkpoint.
    #[error("provisional utreexo transcript failed: {0:?}")]
    Stump(SwiftStumpError),
    /// Audit transcript exceeded bounds or does not match its checkpoint.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// Durable live-index update failed after validation.
    #[error(transparent)]
    Live(#[from] SwiftLiveError),
}

/// Sequential engine that uses ordinary connect and script validation with per-block coins.
pub struct SwiftValidationEngine {
    params: Params,
    tree: HeaderTree,
    live: SwiftLiveIndex,
    audit: SwiftAudit,
    stump: Option<SwiftStumpBuilder>,
    poisoned: bool,
}

impl SwiftValidationEngine {
    /// Creates an engine from a prevalidated header tree and matching durable stores.
    ///
    /// The header tree must contain history back to genesis, matching the empty live index,
    /// so no pre-window outputs are mistaken for absent outpoints. At the start tip, the
    /// audit must be fresh; at a later tip its serialized state must exactly match the
    /// atomically persisted transcript.
    pub fn new(
        mut params: Params,
        mut tree: HeaderTree,
        live: SwiftLiveIndex,
        audit: SwiftAudit,
    ) -> Result<Self, SwiftEngineError> {
        params.assume_valid = None;
        let binding = live.binding();
        let (height, hash) = live.tip();
        live.restore_active_tx_meta(&mut tree)?;
        let stored_audit = live.audit_snapshot()?;
        let expected_audit = if height == binding.start_height {
            None
        } else {
            Some(audit.persisted_state()?)
        };
        let mut tree_params = *tree.params();
        tree_params.assume_valid = None;
        if params.network != binding.network
            || binding.params_commitment != params.swift_validation_commitment()
            || tree_params != params
            || tree.tip_hash() != hash
            || binding.start_height != 0
            || !audit.matches_checkpoint(params.network, binding.target_height, binding.target_hash)
            || height < binding.start_height
            || stored_audit.as_deref() != expected_audit.as_deref()
            || live.is_complete()
        {
            return Err(SwiftEngineError::BindingMismatch);
        }
        Ok(Self {
            params,
            tree,
            live,
            audit,
            stump: None,
            poisoned: false,
        })
    }

    /// Restores the secret-keyed transcript from the private live-index database.
    pub fn resume(
        params: Params,
        tree: HeaderTree,
        live: SwiftLiveIndex,
    ) -> Result<Self, SwiftEngineError> {
        let binding = live.binding();
        let audit = match live.audit_snapshot()? {
            Some(snapshot) => SwiftAudit::from_persisted_state(
                &snapshot,
                binding.network,
                binding.target_height,
                binding.target_hash,
            )?,
            None if live.tip().0 == binding.start_height => {
                SwiftAudit::new(binding.network, binding.target_height, binding.target_hash)?
            }
            None => return Err(SwiftEngineError::BindingMismatch),
        };
        let mut engine = Self::new(params, tree, live, audit)?;
        if let Some(snapshot) = engine.live.stump_snapshot()? {
            let binding = engine.live.binding();
            let checkpoint = SwiftCheckpoint {
                first_height: 1,
                last_height: binding.target_height,
                checkpoint_hash: *binding.target_hash.as_bytes(),
            };
            let builder = SwiftStumpBuilder::from_persisted_state(&snapshot, checkpoint)
                .map_err(SwiftEngineError::Stump)?;
            if builder.next_height() != u64::from(engine.live.tip().0) + 1 {
                return Err(SwiftEngineError::BindingMismatch);
            }
            engine.stump = Some(builder);
        }
        Ok(engine)
    }

    /// Recovers the promotion token after a crash between durable audit
    /// completion and handoff to ordinary chainstate. The completed flag,
    /// transcript, live survivors, stump, header path, and exact parameter
    /// commitment are all rechecked before an opaque token can be minted.
    pub fn recover_completed_snapshot(
        mut params: Params,
        mut tree: HeaderTree,
        live: SwiftLiveIndex,
    ) -> Result<AuditedSwiftSnapshot, SwiftEngineError> {
        params.assume_valid = None;
        let binding = live.binding();
        let (height, hash) = live.tip();
        live.restore_active_tx_meta(&mut tree)?;
        let mut tree_params = *tree.params();
        tree_params.assume_valid = None;
        if !live.is_complete()
            || binding.params_commitment != params.swift_validation_commitment()
            || tree_params != params
            || height != binding.target_height
            || hash != binding.target_hash
            || tree.tip_hash() != binding.target_hash
            || tree.tip().height != binding.target_height
            || binding.network != params.network
        {
            return Err(SwiftEngineError::BindingMismatch);
        }
        let audit_state = live
            .audit_snapshot()?
            .ok_or(SwiftEngineError::BindingMismatch)?;
        let audit = SwiftAudit::from_persisted_state(
            &audit_state,
            binding.network,
            binding.target_height,
            binding.target_hash,
        )?;
        let checkpoint = SwiftCheckpoint {
            first_height: 1,
            last_height: binding.target_height,
            checkpoint_hash: *binding.target_hash.as_bytes(),
        };
        let stump_state = live
            .stump_snapshot()?
            .ok_or(SwiftEngineError::BindingMismatch)?;
        let builder = SwiftStumpBuilder::from_persisted_state(&stump_state, checkpoint)
            .map_err(SwiftEngineError::Stump)?;
        if builder.next_height() != u64::from(binding.target_height) + 1 {
            return Err(SwiftEngineError::BindingMismatch);
        }
        Self {
            params,
            tree,
            live,
            audit,
            stump: Some(builder),
            poisoned: false,
        }
        .into_audited_snapshot()
    }

    /// Enables a shadow-only Utreexo transcript before processing height 1.
    ///
    /// The builder must cover every post-genesis block through this engine's exact target.
    /// Each output's survivor hint remains untrusted and is checked only by the final keyed
    /// audit. The resulting stump is always provisional; this adapter does not install it
    /// into `UtxoAccumulator` or a node's accepted chainstate.
    pub fn enable_provisional_stump(
        &mut self,
        builder: SwiftStumpBuilder,
    ) -> Result<(), SwiftEngineError> {
        let binding = self.live.binding();
        let checkpoint = builder.checkpoint();
        if self.poisoned
            || self.stump.is_some()
            || self.live.tip().0 != 0
            || checkpoint.first_height != 1
            || checkpoint.last_height != binding.target_height
            || checkpoint.checkpoint_hash != *binding.target_hash.as_bytes()
        {
            return Err(SwiftEngineError::BindingMismatch);
        }
        let snapshot = builder.persisted_state().map_err(SwiftEngineError::Stump)?;
        self.live.initialize_stump_snapshot(&snapshot)?;
        self.stump = Some(builder);
        Ok(())
    }

    /// Validates one sequential block with full scripts and commits exact status events.
    ///
    /// `input_claims` must contain each prior-block input coin exactly once. Same-block
    /// inputs are resolved only from earlier transactions. `overwrite_claims` contains the
    /// exact old live coins for outputs replaced in one of the two BIP30 repeat blocks.
    ///
    /// Neither claim slice is trusted: outpoint existence, liveness, creation height, and
    /// coinbase status are checked locally; the checkpoint-bound audit later binds the
    /// complete value and script bytes to the historical output transcript.
    pub fn connect_block(
        &mut self,
        block: &Block,
        now: u32,
        input_claims: &[InputCoinClaim],
        overwrite_claims: &[OverwriteCoinClaim],
        survivor_hint: impl FnMut(OutPoint, &Coin) -> Result<bool, SwiftEngineError>,
    ) -> Result<connect::BlockUndo, SwiftEngineError> {
        if self.poisoned {
            return Err(SwiftEngineError::SessionPoisoned);
        }
        let candidate_hash = block.block_hash();
        let result =
            self.connect_block_inner(block, now, input_claims, overwrite_claims, survivor_hint);
        if result.is_err() && self.tree.contains(&candidate_hash) {
            // HeaderTree insertion precedes contextual body checks. Once a candidate
            // header has entered the in-memory tree, any later failure invalidates this
            // session until the caller reopens/rebuilds its exact durable tip.
            self.poisoned = true;
        }
        result
    }

    fn connect_block_inner(
        &mut self,
        block: &Block,
        now: u32,
        input_claims: &[InputCoinClaim],
        overwrite_claims: &[OverwriteCoinClaim],
        mut survivor_hint: impl FnMut(OutPoint, &Coin) -> Result<bool, SwiftEngineError>,
    ) -> Result<connect::BlockUndo, SwiftEngineError> {
        if self.poisoned {
            return Err(SwiftEngineError::SessionPoisoned);
        }
        if input_claims.len() > MAX_BLOCK_COIN_CLAIMS
            || overwrite_claims.len() > MAX_BLOCK_COIN_CLAIMS
            || claim_payload_bytes(input_claims, overwrite_claims)? > MAX_BLOCK_CLAIM_BYTES
        {
            return Err(SwiftEngineError::ResourceLimit);
        }
        let (parent_height, parent_hash) = self.live.tip();
        if block.header.prev_block_hash != parent_hash {
            return Err(SwiftEngineError::WrongParent);
        }
        let height = parent_height
            .checked_add(1)
            .ok_or(SwiftEngineError::BindingMismatch)?;
        let binding = self.live.binding();
        if height > binding.target_height {
            return Err(SwiftEngineError::BindingMismatch);
        }
        let block_hash = block.block_hash();
        let inserted = self
            .tree
            .insert(&block.header, now)
            .map_err(|error| SwiftEngineError::Header(error.to_string()))?;
        match inserted {
            InsertStatus::Added { height: actual }
            | InsertStatus::AlreadyKnown { height: actual }
                if actual == height => {}
            other => {
                return Err(SwiftEngineError::Header(format!(
                    "height mismatch: {other:?}"
                )));
            }
        }
        check::check_block(block, &self.params)
            .map_err(|error| SwiftEngineError::Block(error.to_string()))?;
        if block_work_bytes(block)? > MAX_BLOCK_CLAIM_BYTES {
            return Err(SwiftEngineError::ResourceLimit);
        }
        let parent_mtp = self.tree.median_time_past(&parent_hash);
        check::contextual_check_block(
            block,
            &BlockContext {
                params: &self.params,
                height,
                parent_median_time_past: parent_mtp,
            },
        )
        .map_err(|error| SwiftEngineError::Context(error.to_string()))?;

        let context = ConnectContext {
            params: &self.params,
            tree: &self.tree,
            block_hash,
            script_checks: true,
            script_pool: None,
            advice: None,
            advice_collect: None,
        };
        let enforce_bip30 = connect::enforce_bip30(height, &block_hash, &context);
        let repeat_exception = connect::is_bip30_repeat(height, &block_hash);
        let mut overwrite_map = HashMap::<OutPoint, &Coin>::with_capacity(overwrite_claims.len());
        for (outpoint, coin) in overwrite_claims {
            if overwrite_map.insert(*outpoint, coin).is_some() {
                return Err(SwiftEngineError::ClaimsMismatch);
            }
        }
        let mut required_overwrites = Vec::new();
        for tx in &block.transactions {
            let txid = tx.txid();
            for (vout, output) in tx.outputs.iter().enumerate() {
                if output.value < 0 || output.script_pubkey.is_unspendable() {
                    continue;
                }
                let outpoint = OutPoint {
                    txid,
                    vout: u32::try_from(vout).map_err(|_| SwiftEngineError::BindingMismatch)?,
                };
                if self.live.get(&outpoint)?.is_some_and(|meta| meta.live) {
                    if enforce_bip30 {
                        return Err(SwiftEngineError::Bip30(outpoint));
                    }
                    if !repeat_exception {
                        return Err(SwiftEngineError::Bip30(outpoint));
                    }
                    let coin = overwrite_map
                        .remove(&outpoint)
                        .ok_or(SwiftEngineError::CoinMismatch)?;
                    let meta = self
                        .live
                        .get(&outpoint)?
                        .ok_or(SwiftEngineError::CoinMismatch)?;
                    check_claim_meta(coin, meta.height, meta.coinbase)?;
                    required_overwrites.push((outpoint, coin));
                }
            }
        }
        if !overwrite_map.is_empty() {
            return Err(SwiftEngineError::ClaimsMismatch);
        }

        let mut claim_map = HashMap::<OutPoint, &Coin>::with_capacity(input_claims.len());
        for (outpoint, coin) in input_claims {
            if claim_map.insert(*outpoint, coin).is_some() {
                return Err(SwiftEngineError::ClaimsMismatch);
            }
        }
        let mut local = HashMap::<OutPoint, Coin>::new();
        let mut events = Vec::new();
        let mut outputs = Vec::new();
        let mut input_records = Vec::new();
        let mut utxo = UtxoSet::new();
        for (outpoint, old_coin) in &required_overwrites {
            utxo.insert_synthetic(*outpoint, (*old_coin).clone());
        }

        for tx in &block.transactions {
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    let outpoint = input.previous_output;
                    let coin = if let Some(same_block) = local.remove(&outpoint) {
                        same_block
                    } else {
                        let claimed = claim_map
                            .remove(&outpoint)
                            .ok_or(SwiftEngineError::InputUnavailable)?;
                        let metadata = self
                            .live
                            .get(&outpoint)?
                            .filter(|metadata| metadata.live)
                            .ok_or(SwiftEngineError::InputUnavailable)?;
                        check_claim_meta(claimed, metadata.height, metadata.coinbase)?;
                        utxo.insert_synthetic(outpoint, (*claimed).clone());
                        (*claimed).clone()
                    };
                    input_records.push((outpoint, coin.clone()));
                    events.push(LiveEvent::Spend {
                        outpoint,
                        height: coin.height,
                        coinbase: coin.coinbase,
                    });
                }
            }
            let txid = tx.txid();
            for (vout, output) in tx.outputs.iter().enumerate() {
                if output.value < 0 || output.script_pubkey.is_unspendable() {
                    continue;
                }
                let outpoint = OutPoint {
                    txid,
                    vout: u32::try_from(vout).map_err(|_| SwiftEngineError::BindingMismatch)?,
                };
                let coin = Coin {
                    out: output.clone(),
                    height,
                    coinbase: tx.is_coinbase(),
                };
                if local.insert(outpoint, coin.clone()).is_some() {
                    return Err(SwiftEngineError::InputUnavailable);
                }
                let allow_live_overwrite =
                    repeat_exception && required_overwrites.iter().any(|(old, _)| *old == outpoint);
                events.push(LiveEvent::Create {
                    outpoint,
                    height,
                    coinbase: tx.is_coinbase(),
                    allow_live_overwrite,
                });
                outputs.push((outpoint, coin));
            }
        }
        if !claim_map.is_empty() {
            return Err(SwiftEngineError::ClaimsMismatch);
        }

        let undo = connect::connect_block(block, &mut utxo, &context)
            .map_err(|error| SwiftEngineError::Connect(format!("{error:?}")))?;
        for (outpoint, old_coin) in &required_overwrites {
            let reported = undo
                .txs
                .iter()
                .flat_map(|tx_undo| tx_undo.overwritten.iter())
                .any(|(undo_outpoint, coin)| undo_outpoint == outpoint && coin == *old_coin);
            if !reported {
                return Err(SwiftEngineError::CoinMismatch);
            }
        }

        let mut output_hints = Vec::with_capacity(outputs.len());
        let mut stump_batch = Vec::new();
        if self.stump.is_some() {
            stump_batch.reserve(outputs.len());
        }
        for (outpoint, coin) in &outputs {
            let survives = survivor_hint(*outpoint, coin)?;
            output_hints.push(survives);
            // The canonical forest appends only outputs still live after this
            // block's transaction sequence. A same-block create-and-spend has
            // no leaf position at all; `None` is reserved for a coin that
            // survives this block but is spent later before the checkpoint.
            if self.stump.is_some() {
                add_stump_position(
                    &mut stump_batch,
                    *outpoint,
                    coin,
                    local.contains_key(outpoint),
                    survives,
                );
            }
        }

        let output_records: Vec<_> = outputs.into_iter().zip(output_hints).collect();
        let audit_result = (|| {
            for ((outpoint, coin), claims_survivor) in &output_records {
                self.audit
                    .record_output_with_hint(outpoint, coin, *claims_survivor)?;
            }
            for (outpoint, coin) in input_records {
                self.audit.record_input_coin(&outpoint, &coin)?;
            }
            for (outpoint, coin) in required_overwrites {
                self.audit.record_overwritten_output(&outpoint, coin)?;
            }
            Ok::<(), AuditError>(())
        })();
        if let Err(error) = audit_result {
            self.poisoned = true;
            return Err(map_audit_error(error));
        }
        let mut survivor_updates = Vec::with_capacity(events.len());
        let mut output_index = 0usize;
        for event in &events {
            match *event {
                LiveEvent::Spend { outpoint, .. } => survivor_updates.push((outpoint, None)),
                LiveEvent::Create { outpoint, .. } => {
                    let ((recorded_outpoint, coin), is_survivor) = output_records
                        .get(output_index)
                        .ok_or(SwiftEngineError::ClaimsMismatch)?;
                    if *recorded_outpoint != outpoint {
                        self.poisoned = true;
                        return Err(SwiftEngineError::ClaimsMismatch);
                    }
                    survivor_updates.push((outpoint, if *is_survivor { Some(coin) } else { None }));
                    output_index += 1;
                }
            }
        }
        if output_index != output_records.len() {
            self.poisoned = true;
            return Err(SwiftEngineError::ClaimsMismatch);
        }
        let stump_snapshot = if let Some(stump) = &mut self.stump {
            if let Err(error) = stump.push(height, stump_batch) {
                self.poisoned = true;
                return Err(SwiftEngineError::Stump(error));
            }
            match stump.persisted_state() {
                Ok(snapshot) => Some(snapshot),
                Err(error) => {
                    self.poisoned = true;
                    return Err(SwiftEngineError::Stump(error));
                }
            }
        } else {
            None
        };
        let audit_snapshot = match self.audit.persisted_state() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.poisoned = true;
                return Err(map_audit_error(error));
            }
        };
        let n_tx =
            u32::try_from(block.transactions.len()).map_err(|_| SwiftEngineError::ResourceLimit)?;
        let parent_chain_tx = self
            .tree
            .get(&parent_hash)
            .ok_or(SwiftEngineError::BindingMismatch)?
            .n_chain_tx;
        let n_chain_tx = parent_chain_tx
            .checked_add(u64::from(n_tx))
            .ok_or(SwiftEngineError::ResourceLimit)?;
        self.tree.note_body(&block_hash, n_tx);
        self.tree.note_connected(&block_hash);
        if let Err(error) = self.live.apply_full_validated_block(
            height,
            parent_hash,
            block,
            &undo,
            n_chain_tx,
            &events,
            &audit_snapshot,
            stump_snapshot.as_deref(),
            &survivor_updates,
        ) {
            self.poisoned = true;
            return Err(map_live_error(error));
        }
        Ok(undo)
    }

    /// Audit the bounded disk-backed survivor table against the exact live index.
    /// A matching checkpoint is marked complete atomically, but is not promoted into
    /// ordinary node chainstate by this module.
    pub fn finish_audit(&mut self) -> Result<SwiftFinishReport, SwiftEngineError> {
        if self.poisoned {
            return Err(SwiftEngineError::SessionPoisoned);
        }
        if self.live.is_complete() {
            return Err(SwiftEngineError::BindingMismatch);
        }
        if self.live.tip().0 != self.live.binding().target_height
            || self.live.tip().1 != self.live.binding().target_hash
        {
            return Err(SwiftEngineError::BindingMismatch);
        }
        let Self {
            live,
            audit,
            params,
            stump,
            ..
        } = self;
        let mut callback_error = None;
        live.for_each_live_survivor(|outpoint, metadata, coin| {
            if callback_error.is_some() {
                return Ok(());
            }
            if let Err(error) = check_claim_meta(&coin, metadata.height, metadata.coinbase)
                .and_then(|()| {
                    audit
                        .record_survivor(&outpoint, &coin)
                        .map_err(map_audit_error)
                })
            {
                callback_error = Some(error);
            }
            Ok(())
        })?;
        if let Some(error) = callback_error {
            return Err(error);
        }
        let report = audit
            .finish(
                params.network,
                live.binding().target_height,
                live.binding().target_hash,
            )
            .map_err(SwiftEngineError::from)?;
        let stump = match (report.verdict, stump.take()) {
            (AuditVerdict::Match, Some(builder)) => {
                let checkpoint = SwiftCheckpoint {
                    first_height: 1,
                    last_height: live.binding().target_height,
                    checkpoint_hash: *live.binding().target_hash.as_bytes(),
                };
                Some(
                    builder
                        .finish(ExternalAuditPassed::after_external_audit(checkpoint))
                        .map_err(SwiftEngineError::Stump)?,
                )
            }
            _ => None,
        };
        if report.verdict == AuditVerdict::Match {
            let snapshot = audit.persisted_state()?;
            live.mark_complete(&snapshot)?;
        }
        Ok(SwiftFinishReport {
            audit: report,
            stump,
        })
    }

    /// Current validated height/hash, as committed in the compact index.
    #[must_use]
    pub const fn tip(&self) -> (u32, BlockHash) {
        self.live.tip()
    }

    /// Whether this engine has the persisted rustreexo 0.7 transition state required
    /// for a promotable full-check checkpoint.
    #[must_use]
    pub const fn has_provisional_stump(&self) -> bool {
        self.stump.is_some()
    }

    /// Imports a source header tree's active path through this engine's pinned
    /// checkpoint. Headers are reinserted and validated under this engine's
    /// exact normalized parameters. A reorganization that changes any already
    /// full-checked ancestor or the pinned checkpoint is rejected so the node
    /// can fall back to ordinary validation.
    pub fn sync_active_headers(
        &mut self,
        source: &HeaderTree,
        now: u32,
    ) -> Result<(), SwiftEngineError> {
        let mut source_params = *source.params();
        source_params.assume_valid = None;
        if source_params != self.params {
            return Err(SwiftEngineError::BindingMismatch);
        }
        let active = source.best_chain();
        let binding = self.live.binding();
        let (validated_height, validated_hash) = self.live.tip();
        let genesis_hash = self.params.genesis_header.hash();
        if active.first() != Some(&genesis_hash)
            || active
                .get(validated_height as usize)
                .is_none_or(|hash| *hash != validated_hash)
        {
            return Err(SwiftEngineError::BindingMismatch);
        }
        if active.len() > binding.target_height as usize
            && active[binding.target_height as usize] != binding.target_hash
        {
            return Err(SwiftEngineError::BindingMismatch);
        }
        let last = active
            .len()
            .saturating_sub(1)
            .min(binding.target_height as usize);
        for hash in active
            .iter()
            .take(last + 1)
            .skip(validated_height as usize + 1)
        {
            let header = source
                .get(hash)
                .ok_or(SwiftEngineError::BindingMismatch)?
                .header;
            match self
                .tree
                .insert(&header, now)
                .map_err(|error| SwiftEngineError::Header(error.to_string()))?
            {
                InsertStatus::Added { .. } | InsertStatus::AlreadyKnown { .. } => {}
            }
        }
        Ok(())
    }

    /// Reconstructs old coin bodies for the two consensus-defined BIP30 repeat
    /// blocks from the repeated transaction outputs plus locally indexed
    /// creation metadata. BIP30 identifies the collision by exact txid/vout;
    /// equal txids commit to the same transaction outputs under Bitcoin's
    /// consensus identifier. No peer-provided overwrite coin is needed.
    pub fn required_bip30_overwrites(
        &self,
        block: &Block,
    ) -> Result<Vec<OverwriteCoinClaim>, SwiftEngineError> {
        let height = self
            .live
            .tip()
            .0
            .checked_add(1)
            .ok_or(SwiftEngineError::BindingMismatch)?;
        let block_hash = block.block_hash();
        if !connect::is_bip30_repeat(height, &block_hash) {
            return Ok(Vec::new());
        }
        let mut claims = Vec::new();
        for tx in &block.transactions {
            let txid = tx.txid();
            for (vout, output) in tx.outputs.iter().enumerate() {
                if output.value < 0 || output.script_pubkey.is_unspendable() {
                    continue;
                }
                let outpoint = OutPoint {
                    txid,
                    vout: u32::try_from(vout).map_err(|_| SwiftEngineError::ResourceLimit)?,
                };
                let Some(meta) = self.live.get(&outpoint)?.filter(|meta| meta.live) else {
                    continue;
                };
                claims.push((
                    outpoint,
                    Coin {
                        out: output.clone(),
                        height: meta.height,
                        coinbase: meta.coinbase,
                    },
                ));
            }
        }
        Ok(claims)
    }

    /// Streams final full coins only after the checkpoint aggregate matched.
    pub fn for_each_audited_survivor(
        &self,
        visit: impl FnMut(OutPoint, LiveCoinMeta, Coin) -> Result<(), SwiftLiveError>,
    ) -> Result<(), SwiftLiveError> {
        self.live.for_each_audited_survivor(visit)
    }

    /// Consumes a fully audited engine into an opaque promotion source. This
    /// requires a persisted matching audit, rustreexo stump, exact target tip,
    /// complete header path, and the retained full-block rollback window.
    pub fn into_audited_snapshot(self) -> Result<AuditedSwiftSnapshot, SwiftEngineError> {
        if self.poisoned || !self.live.is_complete() {
            return Err(SwiftEngineError::BindingMismatch);
        }
        let binding = self.live.binding();
        if self.live.tip() != (binding.target_height, binding.target_hash)
            || self.tree.tip_hash() != binding.target_hash
            || self.tree.tip().height != binding.target_height
            || self.tree.params().network != binding.network
        {
            return Err(SwiftEngineError::BindingMismatch);
        }
        let mut expected_chain_tx = 1u64;
        for height in 0..=binding.target_height {
            let node = self
                .tree
                .get_ancestor(&binding.target_hash, height)
                .filter(|node| node.height == height)
                .ok_or(SwiftEngineError::BindingMismatch)?;
            if (height == 0 && (node.n_tx != 1 || node.n_chain_tx != 1))
                || (height > 0
                    && (node.n_tx == 0
                        || node.n_chain_tx
                            != expected_chain_tx
                                .checked_add(u64::from(node.n_tx))
                                .ok_or(SwiftEngineError::BindingMismatch)?))
            {
                return Err(SwiftEngineError::BindingMismatch);
            }
            if height > 0 {
                expected_chain_tx = node.n_chain_tx;
            }
        }
        if binding.start_height != 0 {
            // Promotion currently requires a full genesis-to-checkpoint active
            // header and transaction-metadata path, not an assumeutxo-style base.
            return Err(SwiftEngineError::BindingMismatch);
        }
        let audit_snapshot = self
            .live
            .audit_snapshot()?
            .ok_or(SwiftEngineError::BindingMismatch)?;
        let audit = SwiftAudit::from_persisted_state(
            &audit_snapshot,
            binding.network,
            binding.target_height,
            binding.target_hash,
        )?;
        let report = audit.finish(binding.network, binding.target_height, binding.target_hash)?;
        if report.verdict != AuditVerdict::Match {
            return Err(SwiftEngineError::BindingMismatch);
        }
        let checkpoint = SwiftCheckpoint {
            first_height: 1,
            last_height: binding.target_height,
            checkpoint_hash: *binding.target_hash.as_bytes(),
        };
        let stump_snapshot = self
            .live
            .stump_snapshot()?
            .ok_or(SwiftEngineError::BindingMismatch)?;
        let stump_builder = SwiftStumpBuilder::from_persisted_state(&stump_snapshot, checkpoint)
            .map_err(SwiftEngineError::Stump)?;
        if stump_builder.next_height() != u64::from(binding.target_height) + 1 {
            return Err(SwiftEngineError::BindingMismatch);
        }
        let stump = stump_builder
            .finish(ExternalAuditPassed::after_external_audit(checkpoint))
            .map_err(SwiftEngineError::Stump)?;
        let (first_undo, floor_hash, undo_count) =
            self.live.for_each_audited_undo(|_, _, _, _, _| Ok(()))?;
        let expected_undos = usize::try_from(
            binding
                .target_height
                .min(crate::swift_live::DEFAULT_REORG_DEPTH),
        )
        .map_err(|_| SwiftEngineError::BindingMismatch)?;
        if undo_count != expected_undos
            || first_undo == 0
            || first_undo - 1 != self.live.undo_floor_height()
        {
            return Err(SwiftEngineError::BindingMismatch);
        }
        let seal = SwiftCheckpointSeal {
            network: binding.network,
            height: binding.target_height,
            hash: binding.target_hash,
            leaf_count: stump.leaves,
            survivor_count: report.survivors,
        };
        Ok(AuditedSwiftSnapshot {
            seal,
            stump,
            params: self.params,
            live: self.live,
            tree: self.tree,
            undo_floor_height: first_undo - 1,
            undo_floor_hash: floor_hash,
        })
    }
}

fn check_claim_meta(
    coin: &Coin,
    expected_height: u32,
    expected_coinbase: bool,
) -> Result<(), SwiftEngineError> {
    if coin.height != expected_height || coin.coinbase != expected_coinbase {
        return Err(SwiftEngineError::CoinMismatch);
    }
    Ok(())
}

fn claim_payload_bytes(
    inputs: &[InputCoinClaim],
    overwrites: &[OverwriteCoinClaim],
) -> Result<usize, SwiftEngineError> {
    inputs
        .iter()
        .chain(overwrites)
        .try_fold(0usize, |total, (_, coin)| {
            total
                .checked_add(128)
                .and_then(|bytes| bytes.checked_add(coin.out.script_pubkey.len()))
                .ok_or(SwiftEngineError::ResourceLimit)
        })
}

fn block_work_bytes(block: &Block) -> Result<usize, SwiftEngineError> {
    let mut events = 0usize;
    let mut bytes = 0usize;
    for tx in &block.transactions {
        if !tx.is_coinbase() {
            events = events
                .checked_add(tx.inputs.len())
                .ok_or(SwiftEngineError::ResourceLimit)?;
            bytes = bytes
                .checked_add(
                    tx.inputs
                        .len()
                        .checked_mul(64)
                        .ok_or(SwiftEngineError::ResourceLimit)?,
                )
                .ok_or(SwiftEngineError::ResourceLimit)?;
        }
        for output in &tx.outputs {
            if output.value < 0 || output.script_pubkey.is_unspendable() {
                continue;
            }
            events = events
                .checked_add(1)
                .ok_or(SwiftEngineError::ResourceLimit)?;
            bytes = bytes
                .checked_add(128)
                .and_then(|total| total.checked_add(output.script_pubkey.len()))
                .ok_or(SwiftEngineError::ResourceLimit)?;
        }
        if events > MAX_BLOCK_EVENTS || bytes > MAX_BLOCK_CLAIM_BYTES {
            return Err(SwiftEngineError::ResourceLimit);
        }
    }
    Ok(bytes)
}

fn add_stump_position(
    batch: &mut Vec<Option<rustreexo::node_hash::BitcoinNodeHash>>,
    outpoint: OutPoint,
    coin: &Coin,
    live_after_block: bool,
    survives_checkpoint: bool,
) {
    if live_after_block {
        batch.push(survives_checkpoint.then(|| crate::utreexo::leaf_for(&outpoint, coin)));
    }
}

fn map_audit_error(error: AuditError) -> SwiftEngineError {
    match error {
        AuditError::ScriptTooLarge
        | AuditError::RecordLimitExceeded
        | AuditError::CounterOverflow => SwiftEngineError::ResourceLimit,
        other => SwiftEngineError::Audit(other),
    }
}

fn map_live_error(error: SwiftLiveError) -> SwiftEngineError {
    match error {
        SwiftLiveError::EventLimit | SwiftLiveError::EntryLimit | SwiftLiveError::ByteLimit => {
            SwiftEngineError::ResourceLimit
        }
        other => SwiftEngineError::Live(other),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::add_stump_position;
    use crate::connect::Coin;
    use crate::hash::Txid;
    use crate::transaction::{OutPoint, Script, TxOut};

    #[test]
    fn implicit_positions_omit_same_block_spends() {
        let outpoint = OutPoint {
            txid: Txid::from_bytes([0x31; 32]),
            vout: 2,
        };
        let coin = Coin {
            out: TxOut {
                value: 7,
                script_pubkey: Script::new(vec![0x51]),
            },
            height: 10,
            coinbase: false,
        };
        let mut batch = Vec::new();
        add_stump_position(&mut batch, outpoint, &coin, false, false);
        add_stump_position(&mut batch, outpoint, &coin, true, false);
        add_stump_position(&mut batch, outpoint, &coin, true, true);
        assert_eq!(batch.len(), 2);
        assert!(batch[0].is_none());
        assert_eq!(batch[1], Some(crate::utreexo::leaf_for(&outpoint, &coin)));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod modern_regtest_tests {
    use super::*;
    use crate::arith::CompactTarget;
    use crate::chainstate::{Acceptance, BlockRejection, Chainstate};
    use crate::hash::{BlockHash, hash160, tagged_hash};
    use crate::header::BlockHeader;
    use crate::interpreter::{ExecutionData, SigVersion};
    use crate::params::{Network, Params};
    use crate::pow;
    use crate::script;
    use crate::sigchecker::{
        PrecomputedTransactionData, SIGHASH_ALL, SIGHASH_DEFAULT, check_input_scripts,
        signature_hash, signature_hash_schnorr,
    };
    use crate::swift_audit::AuditVerdict;
    use crate::swift_live::{SwiftLiveBinding, SwiftLiveIndex, SwiftLiveLimits};
    use crate::swift_stump::{SwiftCheckpoint, SwiftStumpBuilder, SwiftStumpLimits};
    use crate::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicU64, Ordering};

    const COIN: i64 = 100_000_000;
    const NOW: u32 = 2_000_000_000;
    const REGTEST_BITS: u32 = 0x207f_ffff;
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new() -> Self {
            loop {
                let id = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("avila-swift-modern-{}-{id}", std::process::id()));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create temporary directory: {error}"),
                }
            }
        }
        fn db(&self) -> std::path::PathBuf {
            self.0.join("swift.redb")
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn txout(value: i64, script: Vec<u8>) -> TxOut {
        TxOut {
            value,
            script_pubkey: Script::new(script),
        }
    }

    fn coinbase(height: u32, outputs: Vec<TxOut>) -> Transaction {
        let mut script_sig = script::push_int(i64::from(height));
        script_sig.push(script::OP_1);
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(script_sig),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs,
            lock_time: 0,
        }
    }

    fn mine_block(prev: &BlockHeader, height: u32, mut txs: Vec<Transaction>, p: &Params) -> Block {
        let has_witness = txs.iter().any(Transaction::has_witness);
        if has_witness {
            txs[0].inputs[0].witness = Witness::new(vec![vec![0; 32]]);
        }
        let mut block = Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: prev.hash(),
                merkle_root: prev.merkle_root,
                time: prev.time + 1,
                bits: CompactTarget(REGTEST_BITS),
                nonce: 0,
            },
            transactions: txs,
        };
        if has_witness {
            let commitment = block.expected_witness_commitment().unwrap();
            let mut script_pubkey = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            script_pubkey.extend_from_slice(&commitment);
            block.transactions[0].outputs.push(txout(0, script_pubkey));
        }
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, p).is_err() {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        assert!(height > 0);
        block
    }

    fn sign_modern_spend(
        mut tx: Transaction,
        wpkh_input: usize,
        taproot_input: usize,
        spent: &[TxOut],
        wpkh_secret: &secp256k1::SecretKey,
        taproot_secret: &secp256k1::SecretKey,
    ) -> Transaction {
        let secp = secp256k1::Secp256k1::new();
        let wpkh_public = secp256k1::PublicKey::from_secret_key(&secp, wpkh_secret);
        let wpkh_hash = hash160(&wpkh_public.serialize());
        let script_code =
            Script::new([&[0x76, 0xa9, 0x14][..], &wpkh_hash, &[0x88, 0xac]].concat());
        let cache = PrecomputedTransactionData::new(&tx, Some(spent.to_vec()), true);
        let sighash = signature_hash(
            &script_code,
            &tx,
            wpkh_input,
            i32::from(SIGHASH_ALL),
            spent[wpkh_input].value,
            SigVersion::WitnessV0,
            Some(&cache),
        );
        let msg = secp256k1::Message::from_digest_slice(&sighash).unwrap();
        let mut der = secp.sign_ecdsa(&msg, wpkh_secret).serialize_der().to_vec();
        der.push(SIGHASH_ALL);
        tx.inputs[wpkh_input].witness = Witness::new(vec![der, wpkh_public.serialize().to_vec()]);

        let internal_pair = secp256k1::Keypair::from_secret_key(&secp, taproot_secret);
        let (internal, _) = internal_pair.x_only_public_key();
        let tweak =
            secp256k1::Scalar::from_be_bytes(tagged_hash(b"TapTweak", &internal.serialize()))
                .unwrap();
        let tweaked = internal_pair.add_xonly_tweak(&secp, &tweak).unwrap();
        let cache = PrecomputedTransactionData::new(&tx, Some(spent.to_vec()), true);
        let mut execdata = ExecutionData {
            annex_init: true,
            ..ExecutionData::default()
        };
        let sighash = signature_hash_schnorr(
            &tx,
            taproot_input,
            SIGHASH_DEFAULT,
            SigVersion::Taproot,
            &cache,
            &mut execdata,
        )
        .unwrap();
        let msg = secp256k1::Message::from_digest_slice(&sighash).unwrap();
        let signature = secp.sign_schnorr_no_aux_rand(&msg, &tweaked);
        tx.inputs[taproot_input].witness = Witness::new(vec![signature.serialize().to_vec()]);
        tx
    }

    fn modern_blocks() -> Vec<Block> {
        let mut params = Network::Regtest.params();
        params.assume_valid = None;
        let wpkh_secret = secp256k1::SecretKey::from_slice(&[5; 32]).unwrap();
        let wpkh_public =
            secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &wpkh_secret);
        let wpkh_hash = hash160(&wpkh_public.serialize());
        let wpkh_script = [&[0x00, 0x14][..], &wpkh_hash].concat();

        let taproot_secret = secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
        let secp = secp256k1::Secp256k1::new();
        let internal = secp256k1::Keypair::from_secret_key(&secp, &taproot_secret)
            .x_only_public_key()
            .0;
        let tweak =
            secp256k1::Scalar::from_be_bytes(tagged_hash(b"TapTweak", &internal.serialize()))
                .unwrap();
        let taproot_key = secp256k1::Keypair::from_secret_key(&secp, &taproot_secret)
            .add_xonly_tweak(&secp, &tweak)
            .unwrap()
            .x_only_public_key()
            .0;
        let taproot_script = [&[0x51, 0x20][..], &taproot_key.serialize()].concat();

        let mut csv_script = script::push_int(1);
        csv_script.extend_from_slice(&[script::OP_CSV, 0x75, script::OP_1]);
        let mut cltv_script = script::push_int(102);
        cltv_script.extend_from_slice(&[script::OP_CLTV, 0x75, script::OP_1]);
        let mut prev = params.genesis_header;
        let mut blocks = Vec::with_capacity(290);
        let genesis_coinbase = coinbase(
            1,
            vec![
                txout(47 * COIN, vec![script::OP_1]),
                txout(COIN, wpkh_script),
                txout(COIN, taproot_script),
                txout(COIN / 2, csv_script),
                txout(COIN / 2, cltv_script),
            ],
        );
        let first = mine_block(&prev, 1, vec![genesis_coinbase], &params);
        prev = first.header;
        blocks.push(first);

        for height in 2..=100 {
            let block = mine_block(
                &prev,
                height,
                vec![coinbase(height, vec![txout(50 * COIN, vec![script::OP_1])])],
                &params,
            );
            prev = block.header;
            blocks.push(block);
        }

        let first_coinbase = &blocks[0].transactions[0];
        let wpkh_point = OutPoint {
            txid: first_coinbase.txid(),
            vout: 1,
        };
        let taproot_point = OutPoint {
            txid: first_coinbase.txid(),
            vout: 2,
        };
        let spent = vec![
            first_coinbase.outputs[1].clone(),
            first_coinbase.outputs[2].clone(),
        ];
        let unsigned = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: wpkh_point,
                    script_sig: Script::new(vec![]),
                    sequence: u32::MAX,
                    witness: Witness::default(),
                },
                TxIn {
                    previous_output: taproot_point,
                    script_sig: Script::new(vec![]),
                    sequence: u32::MAX,
                    witness: Witness::default(),
                },
            ],
            outputs: vec![
                txout(COIN / 2, {
                    let mut v = script::push_int(1);
                    v.extend_from_slice(&[script::OP_CSV, 0x75, script::OP_1]);
                    v
                }),
                txout(COIN / 2, {
                    let mut v = script::push_int(102);
                    v.extend_from_slice(&[script::OP_CLTV, 0x75, script::OP_1]);
                    v
                }),
                txout(80_000_000, vec![script::OP_1]),
            ],
            lock_time: 0,
        };
        let signed = sign_modern_spend(unsigned, 0, 1, &spent, &wpkh_secret, &taproot_secret);
        let block101 = mine_block(
            &prev,
            101,
            vec![
                coinbase(101, vec![txout(50 * COIN, vec![script::OP_1])]),
                signed,
            ],
            &params,
        );
        prev = block101.header;
        blocks.push(block101);

        let txid101 = blocks[100].transactions[1].txid();
        let tx102 = Transaction {
            version: 2,
            inputs: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: txid101,
                        vout: 0,
                    },
                    script_sig: Script::new(vec![]),
                    sequence: 1,
                    witness: Witness::default(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: txid101,
                        vout: 1,
                    },
                    script_sig: Script::new(vec![]),
                    sequence: 1,
                    witness: Witness::default(),
                },
            ],
            outputs: vec![txout(90_000_000, vec![script::OP_1])],
            lock_time: 102,
        };
        let block102 = mine_block(
            &prev,
            102,
            vec![coinbase(102, vec![txout(50 * COIN, vec![script::OP_1])])],
            &params,
        );
        prev = block102.header;
        blocks.push(block102);
        let block103 = mine_block(
            &prev,
            103,
            vec![
                coinbase(103, vec![txout(50 * COIN, vec![script::OP_1])]),
                tx102,
            ],
            &params,
        );
        prev = block103.header;
        blocks.push(block103);
        for height in 104..=290 {
            let subsidy = if height < 150 { 50 } else { 25 };
            let block = mine_block(
                &prev,
                height,
                vec![coinbase(
                    height,
                    vec![txout(subsidy * COIN, vec![script::OP_1])],
                )],
                &params,
            );
            prev = block.header;
            blocks.push(block);
        }
        blocks
    }

    fn helper_claims(blocks: &[Block]) -> (Vec<Vec<InputCoinClaim>>, HashSet<OutPoint>) {
        let mut live = HashMap::<OutPoint, Coin>::new();
        let mut all_claims = vec![Vec::new(); blocks.len() + 1];
        for (index, block) in blocks.iter().enumerate() {
            let height = index as u32 + 1;
            for tx in &block.transactions {
                if !tx.is_coinbase() {
                    for input in &tx.inputs {
                        let coin = live.remove(&input.previous_output).unwrap();
                        if coin.height < height {
                            all_claims[height as usize].push((input.previous_output, coin));
                        }
                    }
                }
                for (vout, output) in tx.outputs.iter().enumerate() {
                    if output.value < 0 || output.script_pubkey.is_unspendable() {
                        continue;
                    }
                    let outpoint = OutPoint {
                        txid: tx.txid(),
                        vout: vout as u32,
                    };
                    assert!(
                        live.insert(
                            outpoint,
                            Coin {
                                out: output.clone(),
                                height,
                                coinbase: tx.is_coinbase(),
                            },
                        )
                        .is_none()
                    );
                }
            }
        }
        (all_claims, live.into_keys().collect())
    }

    fn limits() -> SwiftLiveLimits {
        SwiftLiveLimits {
            max_live_entries: 100_000,
            max_live_encoded_bytes: 100_000 * 41,
            max_undo_encoded_bytes: 64 * 1024 * 1024,
            max_survivor_entries: 100_000,
            max_survivor_encoded_bytes: 64 * 1024 * 1024,
            max_reorg_depth: crate::swift_live::DEFAULT_REORG_DEPTH,
            max_block_events: crate::swift_live::MAX_BLOCK_EVENTS,
            cache_bytes: 16 * 1024 * 1024,
        }
    }

    #[test]
    fn modern_signed_regtest_fullcheck_matches_conventional_oracle() {
        let blocks = modern_blocks();
        let mut params = Network::Regtest.params();
        params.assume_valid = None;
        let target = blocks.last().unwrap().block_hash();
        let (claims, survivors) = helper_claims(&blocks);
        let temp = TempDir::new();
        let binding = SwiftLiveBinding {
            network: Network::Regtest,
            start_height: 0,
            start_hash: params.genesis_header.hash(),
            target_height: blocks.len() as u32,
            target_hash: target,
            params_commitment: params.swift_validation_commitment(),
        };
        let live = SwiftLiveIndex::create(&temp.db(), binding, limits()).unwrap();
        let audit = crate::swift_audit::SwiftAudit::new(
            Network::Regtest,
            binding.target_height,
            binding.target_hash,
        )
        .unwrap();
        let tree = HeaderTree::new(params);
        let mut engine = SwiftValidationEngine::new(params, tree, live, audit).unwrap();
        let stump = SwiftStumpBuilder::new(
            SwiftCheckpoint {
                first_height: 1,
                last_height: binding.target_height,
                checkpoint_hash: *binding.target_hash.as_bytes(),
            },
            SwiftStumpLimits {
                max_pending_blocks: 1,
                max_pending_leaves: 100_000,
                max_pending_bytes: 8 * 1024 * 1024,
                max_batch_leaves: 100_000,
                max_batch_bytes: 8 * 1024 * 1024,
            },
        )
        .unwrap();
        engine.enable_provisional_stump(stump).unwrap();

        let mut oracle_params = params;
        oracle_params.assume_valid = None;
        let mut oracle = Chainstate::new(&oracle_params);
        for (index, block) in blocks.iter().enumerate() {
            assert_eq!(
                oracle
                    .accept_block(block, NOW)
                    .unwrap_or_else(|error| panic!("oracle block {}: {error:?}", index + 1)),
                Acceptance::Connected {
                    height: (index + 1) as u32,
                    reorged: false,
                }
            );
            engine
                .connect_block(block, NOW, &claims[index + 1], &[], |outpoint, _| {
                    Ok(survivors.contains(&outpoint))
                })
                .unwrap();
            if index == 39 {
                drop(engine);
                let mut resumed_tree = HeaderTree::new(params);
                for accepted in &blocks[..=index] {
                    assert!(matches!(
                        resumed_tree.insert(&accepted.header, NOW).unwrap(),
                        InsertStatus::Added { .. }
                    ));
                }
                let mut changed_rules = params;
                changed_rules.subsidy_halving_interval += 1;
                let mut changed_tree = HeaderTree::new(changed_rules);
                for accepted in &blocks[..=index] {
                    assert!(matches!(
                        changed_tree.insert(&accepted.header, NOW).unwrap(),
                        InsertStatus::Added { .. }
                    ));
                }
                let changed_live = SwiftLiveIndex::open(&temp.db(), binding, limits()).unwrap();
                assert!(matches!(
                    SwiftValidationEngine::resume(changed_rules, changed_tree, changed_live),
                    Err(SwiftEngineError::BindingMismatch)
                ));
                let reopened = SwiftLiveIndex::open(&temp.db(), binding, limits()).unwrap();
                engine = SwiftValidationEngine::resume(params, resumed_tree, reopened).unwrap();
            }
        }
        let finish = engine.finish_audit().unwrap();
        assert_eq!(finish.audit.verdict, AuditVerdict::Match);
        drop(engine);
        let mut completed_tree = HeaderTree::new(params);
        for accepted in &blocks {
            assert!(matches!(
                completed_tree.insert(&accepted.header, NOW).unwrap(),
                InsertStatus::Added { .. }
            ));
        }
        let completed_live = SwiftLiveIndex::open(&temp.db(), binding, limits()).unwrap();
        let token = SwiftValidationEngine::recover_completed_snapshot(
            params,
            completed_tree,
            completed_live,
        )
        .unwrap();
        assert_eq!(token.network(), Network::Regtest);
        assert_eq!(token.height(), 290);
        assert_eq!(token.hash(), target);
        assert_eq!(token.survivor_count(), oracle.utxo().len() as u64);
        assert_eq!(token.undo_floor().0, 2);

        let expected: HashMap<_, _> = oracle.utxo().iter().into_iter().collect();
        let mut actual = HashMap::new();
        token
            .for_each_survivor(|outpoint, _, coin| {
                assert!(actual.insert(outpoint, coin).is_none());
                Ok(())
            })
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(oracle.tip_hash(), target);

        // Consume the opaque token through the ordinary node path, then prove
        // the imported state survives ordinary connection, reorg, prune
        // checkpointing, and a later reopen.
        let promoted_dir = temp.0.join("promoted-node");
        let mut different_rules = params;
        different_rules.subsidy_halving_interval += 1;
        assert!(
            Chainstate::promote_audited_swift_snapshot(
                &promoted_dir,
                &different_rules,
                NOW,
                16 * 1024 * 1024,
                &token,
            )
            .is_err(),
            "same-network consensus-rule changes cannot consume the token"
        );
        assert!(!promoted_dir.exists());

        let mut wrong_params = params;
        wrong_params.assume_valid = Some(BlockHash::from_bytes([0x44; 32]));
        assert!(
            Chainstate::promote_audited_swift_snapshot(
                &promoted_dir,
                &wrong_params,
                NOW,
                16 * 1024 * 1024,
                &token,
            )
            .is_err()
        );
        assert!(!promoted_dir.exists());

        Chainstate::promote_audited_swift_snapshot_with_file_limit_for_test(
            &promoted_dir,
            &params,
            NOW,
            16 * 1024 * 1024,
            &token,
            1,
        )
        .unwrap();
        let mut promoted =
            Chainstate::with_store_coinsdb(&promoted_dir, &params, NOW, 16 * 1024 * 1024).unwrap();
        assert_eq!(promoted.tip_hash(), target);
        assert_eq!(
            promoted
                .utxo()
                .iter()
                .into_iter()
                .collect::<HashMap<_, _>>(),
            expected
        );
        let before_floor_rewind = promoted.tip_hash();
        let below_promotion_floor = promoted.chain()[2];
        assert!(promoted.invalidate_block(&below_promotion_floor).is_err());
        assert_eq!(promoted.tip_hash(), before_floor_rewind);

        let block103 = mine_block(
            &blocks[289].header,
            291,
            vec![coinbase(291, vec![txout(25 * COIN, vec![script::OP_1])])],
            &params,
        );
        assert_eq!(
            promoted.accept_block(&block103, NOW).unwrap(),
            Acceptance::Connected {
                height: 291,
                reorged: false,
            }
        );

        let mut fork_parent = blocks[279].header;
        let mut fork = Vec::new();
        for height in 281..=294 {
            let block = mine_block(
                &fork_parent,
                height,
                vec![coinbase(
                    height,
                    vec![txout(25 * COIN, script::push_int(2))],
                )],
                &params,
            );
            fork_parent = block.header;
            fork.push(block);
        }
        for block in &fork {
            promoted.accept_block(block, NOW).unwrap();
        }
        assert_eq!(promoted.tip_hash(), fork_parent.hash());
        promoted.flush().unwrap();
        assert!(promoted.prune(0).unwrap() > 0);
        drop(promoted);

        let mut reopened =
            Chainstate::with_store_coinsdb(&promoted_dir, &params, NOW, 16 * 1024 * 1024).unwrap();
        assert_eq!(reopened.tip_hash(), fork_parent.hash());
        assert_eq!(reopened.chain().len(), 295);
        let before_pruned_floor_rewind = reopened.tip_hash();
        let below_pruned_floor = reopened.chain()[6];
        assert!(reopened.invalidate_block(&below_pruned_floor).is_err());
        assert_eq!(reopened.tip_hash(), before_pruned_floor_rewind);
        drop(reopened);
    }

    #[test]
    fn modern_signature_and_timelock_mutations_fail_direct_script_checks() {
        let blocks = modern_blocks();
        let spend = &blocks[100].transactions[1];
        let coinbase = &blocks[0].transactions[0];
        let spent = vec![coinbase.outputs[1].clone(), coinbase.outputs[2].clone()];
        let mut bad = spend.clone();
        let mut witness = bad.inputs[0].witness.items().to_vec();
        witness[0][0] ^= 1;
        bad.inputs[0].witness = Witness::new(witness);
        assert!(
            check_input_scripts(
                &bad,
                &spent,
                crate::script::ScriptFlags::P2SH
                    .union(crate::script::ScriptFlags::WITNESS)
                    .union(crate::script::ScriptFlags::TAPROOT)
                    .union(crate::script::ScriptFlags::DERSIG)
                    .union(crate::script::ScriptFlags::CHECKLOCKTIMEVERIFY)
                    .union(crate::script::ScriptFlags::CHECKSEQUENCEVERIFY)
                    .union(crate::script::ScriptFlags::NULLDUMMY)
            )
            .is_err()
        );
        let mut bad_taproot = spend.clone();
        let mut witness = bad_taproot.inputs[1].witness.items().to_vec();
        witness[0][0] ^= 1;
        bad_taproot.inputs[1].witness = Witness::new(witness);
        assert!(
            check_input_scripts(
                &bad_taproot,
                &spent,
                crate::script::ScriptFlags::P2SH
                    .union(crate::script::ScriptFlags::WITNESS)
                    .union(crate::script::ScriptFlags::TAPROOT)
                    .union(crate::script::ScriptFlags::DERSIG)
                    .union(crate::script::ScriptFlags::CHECKLOCKTIMEVERIFY)
                    .union(crate::script::ScriptFlags::CHECKSEQUENCEVERIFY)
                    .union(crate::script::ScriptFlags::NULLDUMMY)
            )
            .is_err()
        );
        let mut bad_commitment = blocks[100].clone();
        let commitment_output = bad_commitment.transactions[0].outputs.last_mut().unwrap();
        let mut commitment_script = commitment_output.script_pubkey.as_bytes().to_vec();
        *commitment_script.last_mut().unwrap() ^= 1;
        commitment_output.script_pubkey = Script::new(commitment_script);
        let (root, _) = bad_commitment.merkle_root();
        bad_commitment.header.merkle_root = root;
        let mut params = Network::Regtest.params();
        params.assume_valid = None;
        assert!(check::check_block(&bad_commitment, &params).is_err());
        assert_eq!(blocks[102].transactions[1].lock_time, 102);
        assert_eq!(blocks[102].transactions[1].inputs[0].sequence, 1);

        let lock_spend = &blocks[102].transactions[1];
        let lock_coins = blocks[100].transactions[1].outputs[..2].to_vec();
        let flags = crate::script::ScriptFlags::P2SH
            .union(crate::script::ScriptFlags::WITNESS)
            .union(crate::script::ScriptFlags::TAPROOT)
            .union(crate::script::ScriptFlags::DERSIG)
            .union(crate::script::ScriptFlags::CHECKLOCKTIMEVERIFY)
            .union(crate::script::ScriptFlags::CHECKSEQUENCEVERIFY)
            .union(crate::script::ScriptFlags::NULLDUMMY);
        assert!(check_input_scripts(lock_spend, &lock_coins, flags).is_ok());
        let mut early_cltv = lock_spend.clone();
        early_cltv.lock_time = 101;
        assert!(check_input_scripts(&early_cltv, &lock_coins, flags).is_err());
        let mut failed_csv = lock_spend.clone();
        failed_csv.inputs[0].sequence = 0;
        assert!(check_input_scripts(&failed_csv, &lock_coins, flags).is_err());
    }

    #[test]
    fn premature_coinbase_spend_is_rejected_by_engine_and_oracle() {
        let blocks = modern_blocks();
        let mut params = Network::Regtest.params();
        params.assume_valid = None;
        let first_coinbase = &blocks[0].transactions[0];
        let premature_spend = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: first_coinbase.txid(),
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![txout(4_690_000_000, vec![script::OP_1])],
            lock_time: 0,
        };
        let bad = mine_block(
            &blocks[98].header,
            100,
            vec![
                coinbase(100, vec![txout(50 * COIN, vec![script::OP_1])]),
                premature_spend,
            ],
            &params,
        );
        let mut oracle = Chainstate::new(&params);
        for block in &blocks[..99] {
            oracle.accept_block(block, NOW).unwrap();
        }
        assert!(matches!(
            oracle.accept_block(&bad, NOW),
            Err(BlockRejection::Connect(
                crate::connect::ConnectError::PrematureCoinbaseSpend { depth: 99 }
            ))
        ));

        let (claims, _) = helper_claims(&blocks[..99]);
        let binding = SwiftLiveBinding {
            network: Network::Regtest,
            start_height: 0,
            start_hash: params.genesis_header.hash(),
            target_height: 100,
            target_hash: bad.block_hash(),
            params_commitment: params.swift_validation_commitment(),
        };
        let temp = TempDir::new();
        let live = SwiftLiveIndex::create(&temp.db(), binding, limits()).unwrap();
        let audit = crate::swift_audit::SwiftAudit::new(
            Network::Regtest,
            binding.target_height,
            binding.target_hash,
        )
        .unwrap();
        let mut engine =
            SwiftValidationEngine::new(params, HeaderTree::new(params), live, audit).unwrap();
        for (index, block) in blocks[..99].iter().enumerate() {
            engine
                .connect_block(block, NOW, &claims[index + 1], &[], |_, _| Ok(true))
                .unwrap();
        }
        let coin = Coin {
            out: first_coinbase.outputs[0].clone(),
            height: 1,
            coinbase: true,
        };
        assert!(matches!(
            engine.connect_block(
                &bad,
                NOW,
                &[(premature_spend_outpoint(&bad), coin)],
                &[],
                |_, _| Ok(true),
            ),
            Err(SwiftEngineError::Connect(_))
        ));
    }

    fn premature_spend_outpoint(block: &Block) -> OutPoint {
        block.transactions[1].inputs[0].previous_output
    }
}

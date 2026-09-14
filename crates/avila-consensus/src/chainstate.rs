//! Block acceptance and the active chain — the crate-level equivalent of Core's
//! `ProcessNewBlock` → `AcceptBlock` → `ActivateBestChain` pipeline.
//!
//! [`Chainstate`] composes the implemented layers into one stateful driver:
//! [`HeaderTree`] is the block index, [`UtxoSet`] the coins view, and the
//! connected tip the active chain. [`Chainstate::accept_block`] runs the same
//! gates in the same order the daemon does for `submitblock` with a stored
//! body: header insertion (`AcceptBlockHeader`/`ContextualCheckBlockHeader`),
//! `CheckBlock`, `ContextualCheckBlock`, body retention, then
//! `ActivateBestChain` — connecting a block that extends the tip, or a real
//! disconnect/reconnect reorg when a stored side branch overtakes it.
//!
//! Failed-block bookkeeping matches `mapBlockIndex`: a block that fails
//! `ContextualCheckBlock` or `ConnectBlock` is marked invalid
//! (`BLOCK_FAILED_VALID`), descendants of invalid blocks are rejected at header
//! insertion (`bad-prevblk`), and resubmitting a failed block reports
//! `duplicate-invalid`. `CheckBlock` failures are deliberately never marked —
//! `ProcessNewBlock` runs `CheckBlock` before the header enters the index, as
//! protection against undiscovered block malleability (CVE-2012-2459), and
//! `BLOCK_MUTATED`-class rejections are never marked either. A heavier branch
//! that fails to connect leaves the active chain untouched — as does Core when
//! `ActivateBestChainStep` hits an invalid block.
//!
//! Two simplifications relative to the daemon, both in-memory rather than
//! consensus-relevant: block bodies live in a [`HashMap`] instead of blk*.dat
//! files, and a reorg's disconnect/connect runs against a cloned [`UtxoSet`]
//! committed on success instead of `CCoinsViewCache` layers over a database.
//! Neither changes any verdict.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use thiserror::Error;

use crate::block::Block;
use crate::chain::{ChainError, HeaderTree, InsertStatus};
use crate::check::{self, BlockContext, BlockRuleError, ContextualBlockError, RuleError};
use crate::connect::{self, BlockUndo, ConnectContext, ConnectError, UtxoSet};
use crate::hash::BlockHash;
use crate::header::BlockHeader;
use crate::params::Params;
use crate::store::{self, BlockStore, StateData};

/// The outcome of a successful [`Chainstate::accept_block`] call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Acceptance {
    /// The block connected as the new active tip. `reorged` is `true` when a
    /// previously connected branch was disconnected to make room for it.
    Connected {
        /// The block's height.
        height: u32,
        /// Whether connecting this block displaced a previously active branch.
        reorged: bool,
    },
    /// The block is valid and stored, but its branch does not outwork the
    /// connected tip (Core: the pindex is parked, `submitblock` reports
    /// `inconclusive`) — or descends from a failed block.
    Parked {
        /// The block's height.
        height: u32,
    },
    /// The block's header was already in the index (Core's `AcceptBlockHeader`
    /// returning the existing `CBlockIndex`; `submitblock` reports
    /// `duplicate`).
    AlreadyKnown {
        /// The existing node's height.
        height: u32,
    },
}

/// Why [`Chainstate::accept_block`] rejected a block, in the order the gates
/// run inside Core's `ProcessNewBlock`.
#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum BlockRejection {
    /// `AcceptBlockHeader`/`ContextualCheckBlockHeader` failed — including
    /// `bad-prevblk` for children of failed blocks.
    #[error("{0}")]
    Header(ChainError),
    /// The block was already known and carries the failed flag (Core's
    /// `BLOCK_CACHED_INVALID`, reported as `duplicate-invalid`).
    #[error("block was previously marked invalid")]
    CachedInvalid,
    /// `CheckBlock` failed — before header insertion, so the index is
    /// untouched and nothing is marked invalid.
    #[error("{0}")]
    Check(BlockRuleError),
    /// `ContextualCheckBlock` failed.
    #[error("{0}")]
    Contextual(ContextualBlockError),
    /// `ConnectBlock` failed — on the tip-extension path or inside a reorg
    /// attempt. The failing block is marked invalid; the active chain and UTXO
    /// set are left as they were before the call.
    #[error("{0}")]
    Connect(ConnectError),
    /// Writing the accepted body to the [`BlockStore`] failed (Core's
    /// `WriteBlockToDisk` failure path — a `FatalError`, not a rule
    /// rejection). Carries the `io::ErrorKind` so the error type stays
    /// comparable.
    #[error("block store write failed: {0:?}")]
    Store(std::io::ErrorKind),
}

impl BlockRejection {
    /// The reject reason `submitblock` reports for the equivalent failure.
    #[must_use]
    pub fn reason(&self) -> Cow<'static, str> {
        match self {
            BlockRejection::Header(err) => err.reason(),
            BlockRejection::CachedInvalid => "duplicate-invalid".into(),
            BlockRejection::Check(err) => err.reason().into(),
            BlockRejection::Contextual(err) => err.reason().into(),
            BlockRejection::Connect(err) => err.reason(),
            BlockRejection::Store(_) => "store-error".into(),
        }
    }
}

/// Stateful block acceptance: the block index, the coins view, the active
/// chain, and the undo records needed to reorganize it.
///
/// With [`Chainstate::new`] all state is resident in memory — this is the
/// validation driver. [`Chainstate::with_store`] adds durability: accepted
/// blocks append to `blkNNNNN.dat` files at `AcceptBlock`'s
/// `WriteBlockToDisk` point, [`Chainstate::flush`] writes a `state.dat`
/// snapshot (header index, connected chain, undo records, coins view, failed
/// set) atomically behind them, and reopening restores the snapshot then
/// replays only the bodies it does not cover — resumable import without
/// re-downloading *or* re-validating.
pub struct Chainstate {
    tree: HeaderTree,
    utxo: UtxoSet,
    /// Block hash of the connected tip — the genesis at start, whose coinbase
    /// is never in the UTXO set on any network.
    connected: BlockHash,
    /// Bodies accepted this session, by hash — populated only when no store
    /// is attached. With a store, bodies live in the blk files and
    /// `have_body`/`body` serve them from disk, so memory stays bounded no
    /// matter how many blocks arrive. Core keeps bodies in blk*.dat for
    /// reorgs and rescan; this map plus the store play the same role.
    blocks: HashMap<BlockHash, Block>,
    /// The connected chain's block hashes, genesis at index 0.
    chain: Vec<BlockHash>,
    /// Per-block undo for `chain[1..]` (the genesis is never connected):
    /// `undos[k]` reverses the block at height `k + 1`.
    undos: Vec<BlockUndo>,
    /// The durable body store when this chainstate was opened with
    /// [`Chainstate::with_store`]; `None` keeps everything in memory.
    store: Option<BlockStore>,
}

impl Chainstate {
    /// A chainstate at genesis on `params`' network — the state Core reaches at
    /// startup with an empty datadir (the genesis is in the block index and is
    /// the active tip, but its coinbase is unspendable and absent from the
    /// coins view).
    #[must_use]
    pub fn new(params: &Params) -> Self {
        let genesis = params.genesis_header.hash();
        Self {
            tree: HeaderTree::new(*params),
            utxo: UtxoSet::new(),
            connected: genesis,
            blocks: HashMap::new(),
            chain: vec![genesis],
            undos: Vec::new(),
            store: None,
        }
    }

    /// A chainstate backed by a durable [`BlockStore`] in `dir`, resumed from
    /// whatever the store already holds. `BlockStore::open` rebuilds the
    /// hash→position index by scanning the blk files (truncating a partial
    /// tail left by an interrupted write). Resume then takes one of two paths:
    ///
    /// * A valid `state.dat` snapshot restores the validated state directly —
    ///   the header index, failed set, connected chain, undo records and coins
    ///   view — and only bodies the snapshot does not cover (accepted after
    ///   the last flush) are replayed through the normal pipeline.
    /// * Otherwise — no snapshot, or a corrupt/unsupported one — every stored
    ///   body replays in file order, exactly as the original run left them.
    ///
    /// Stored blocks that were rejected still replay to the same rejection, so
    /// per-block verdicts are not errors here. A corrupt snapshot is likewise
    /// non-fatal: the blk files remain the record of what arrived, and replay
    /// rebuilds everything the snapshot claimed.
    ///
    /// `now` is the caller's adjusted local time for the header future-drift
    /// check during replay.
    ///
    /// # Errors
    ///
    /// `io::Error` on store-open/read failures — including a payload that no
    /// longer decodes, which is store corruption, not a rule verdict.
    pub fn with_store(dir: &Path, params: &Params, now: u32) -> std::io::Result<Self> {
        let store = BlockStore::open(dir, params.message_start)?;
        let mut cs = Self::new(params);
        // Attach before replay: `append` is idempotent on indexed hashes, so
        // replaying a stored body writes nothing back — and `have_body`/`body`
        // see the store, so a post-snapshot side branch can reorg against
        // snapshotted (memory-absent) connected blocks.
        cs.store = Some(store);
        // A snapshot that fails to load or restore falls back to full replay —
        // the blk files are the record of what arrived; state.dat only ever
        // re-derives it faster.
        let mut pending = match store::read_state(dir, params.message_start) {
            Ok(Some(state)) => match cs.restore(state, now) {
                Ok(pending) => pending,
                Err(_) => {
                    let store = cs.store.take();
                    cs = Self::new(params);
                    cs.store = store;
                    cs.stored_bodies(&HashSet::new())?
                }
            },
            _ => cs.stored_bodies(&HashSet::new())?,
        };
        // Bodies stored out of order are orphans until their parent lands —
        // loop until a pass makes no progress. A body that keeps failing a
        // non-orphan gate is a permanently-invalid stored block (it was
        // written before its connect attempt), not a reason to keep retrying.
        while !pending.is_empty() {
            let mut progress = false;
            pending.retain(|block| match cs.accept_block(block, now) {
                Ok(_) => {
                    progress = true;
                    false
                }
                Err(BlockRejection::Header(ChainError::UnknownParent(_))) => true,
                Err(_) => false,
            });
            if !progress {
                break;
            }
        }
        Ok(cs)
    }

    /// Every stored body in file order except hashes in `skip` — the replay
    /// set for both the no-snapshot path (`skip` empty) and the snapshot path
    /// (`skip` = connected ∪ failed).
    fn stored_bodies(&self, skip: &HashSet<BlockHash>) -> std::io::Result<Vec<Block>> {
        let Some(store) = &self.store else {
            return Ok(Vec::new());
        };
        store
            .positions()
            .into_iter()
            .filter(|(hash, _)| !skip.contains(hash))
            .map(|(_, pos)| store.read(pos))
            .collect()
    }

    /// Restores validated state from a snapshot: reinserts every indexed
    /// header (validation is deterministic, so the index comes back exactly),
    /// re-applies the failed marks and the best-header tip, then installs the
    /// connected chain, undo records and coins view. Returns the stored bodies
    /// the snapshot does not cover, still to be replayed.
    ///
    /// # Errors
    ///
    /// `io::Error` when the snapshot is internally inconsistent or disagrees
    /// with the header rules or the store — the caller falls back to replay.
    fn restore(&mut self, state: StateData, now: u32) -> std::io::Result<Vec<Block>> {
        let corrupt = |msg: &str| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("state.dat: {msg}"))
        };
        // Headers first, while `invalid` is still empty: a FAILED_CHILD mark
        // cannot turn a stored header's insert into `InvalidParent`. Insert
        // order is by height, so parents always precede children.
        for header in &state.headers {
            self.tree
                .insert(header, now)
                .map_err(|e| corrupt(&format!("header reinsert: {e}")))?;
        }
        for hash in &state.failed {
            if !self.tree.contains(hash) {
                return Err(corrupt("failed mark on unindexed header"));
            }
            self.tree.mark_invalid(*hash);
        }
        if !self.tree.restore_tip(state.best_header) {
            return Err(corrupt("best header not a max-work tip"));
        }
        let store = self.store.as_ref().ok_or_else(|| corrupt("no store"))?;
        for (index, hash) in state.chain.iter().enumerate() {
            if !self.tree.contains(hash) {
                return Err(corrupt("connected block unindexed"));
            }
            // The genesis (index 0) is never accepted through `accept_block`,
            // so its body is legitimately absent from the store.
            if index > 0 && store.position(hash).is_none() {
                return Err(corrupt("connected block body not stored"));
            }
        }
        self.connected = state.tip;
        self.chain = state.chain;
        self.undos = state.undos;
        self.utxo = UtxoSet::new();
        for (outpoint, coin) in state.utxo {
            self.utxo.insert_synthetic(outpoint, coin);
        }
        let mut covered: HashSet<BlockHash> = state.failed.into_iter().collect();
        covered.extend(self.chain.iter().copied());
        self.stored_bodies(&covered)
    }

    /// `true` if `hash`'s body is available — in memory or in the store.
    /// Core's `HaveTxsDownloaded` equivalent under a durable body store.
    /// The sync layer needs it to decide which announced blocks to fetch.
    pub fn have_body(&self, hash: &BlockHash) -> bool {
        self.blocks.contains_key(hash)
            || self
                .store
                .as_ref()
                .is_some_and(|store| store.position(hash).is_some())
    }

    /// `hash`'s body, from memory or the store.
    fn body(&self, hash: &BlockHash) -> Option<Block> {
        if let Some(block) = self.blocks.get(hash) {
            return Some(block.clone());
        }
        let store = self.store.as_ref()?;
        store.read(store.position(hash)?).ok()
    }

    /// The snapshot of the current validation state for `state.dat`.
    fn snapshot(&self) -> StateData {
        let mut failed = self.tree.failed_hashes();
        failed.sort_unstable();
        StateData {
            tip: self.connected,
            height: self.chain.len() as u32 - 1,
            headers: self.tree.headers_by_height(),
            best_header: self.tree.tip_hash(),
            chain: self.chain.clone(),
            undos: self.undos.clone(),
            utxo: self
                .utxo
                .iter()
                .map(|(outpoint, coin)| (*outpoint, coin.clone()))
                .collect(),
            failed,
        }
    }

    /// Flushes the durable state, when present: the blk files first, then the
    /// `state.dat` snapshot atomically over the old one. The ordering keeps the
    /// invariant that every body the snapshot covers is already durable —
    /// a crash between the two leaves the older snapshot plus the bodies the
    /// replay path re-validates.
    ///
    /// # Errors
    ///
    /// `io::Error` on flush or snapshot-write failure.
    pub fn flush(&mut self) -> std::io::Result<()> {
        let Some(store) = &mut self.store else {
            return Ok(());
        };
        store.flush()?;
        let (dir, magic) = (store.dir().to_path_buf(), store.magic());
        store::write_state(&dir, magic, &self.snapshot())
    }

    /// The block index (Core's `mapBlockIndex` + best-tip bookkeeping).
    #[must_use]
    pub fn tree(&self) -> &HeaderTree {
        &self.tree
    }

    /// The coins view of the active chain tip.
    #[must_use]
    pub fn utxo(&self) -> &UtxoSet {
        &self.utxo
    }

    /// Mutable access to the coins view — for tests seeding synthetic coins.
    pub fn utxo_mut(&mut self) -> &mut UtxoSet {
        &mut self.utxo
    }

    /// The block hash of the active chain's tip.
    #[must_use]
    pub fn tip_hash(&self) -> BlockHash {
        self.connected
    }

    /// The active chain's block hashes, genesis at index 0 — so
    /// `chain().len() - 1` is the tip height.
    #[must_use]
    pub fn chain(&self) -> &[BlockHash] {
        &self.chain
    }

    /// A stored block body by hash, if it passed `CheckBlock` +
    /// `ContextualCheckBlock` — from memory only. Bodies a snapshot restore
    /// left on disk (everything at or below the snapshot tip) are reachable
    /// through the store, not here.
    #[must_use]
    pub fn block(&self, hash: &BlockHash) -> Option<&Block> {
        self.blocks.get(hash)
    }

    /// Indexes a header without a body — Core's `ProcessNewBlockHeaders` →
    /// `AcceptBlockHeader`. Headers-first intake matters for `assume_valid`:
    /// `ConnectBlock` only skips script checks when the best *header* sits far
    /// enough above the block being connected, so exercising that path requires
    /// headers in the tree before their blocks arrive.
    ///
    /// # Errors
    ///
    /// [`BlockRejection::Header`] on any header-validation failure (orphan,
    /// PoW, contextual, failed ancestry).
    pub fn accept_header(&mut self, header: &BlockHeader, now: u32) -> Result<u32, BlockRejection> {
        match self.tree.insert(header, now) {
            Ok(InsertStatus::Added { height } | InsertStatus::AlreadyKnown { height }) => {
                Ok(height)
            }
            Err(err) => Err(BlockRejection::Header(err)),
        }
    }

    /// `ConnectBlock`'s `fScriptChecks` decision for the block at `hash`
    /// (validation.cpp): `true` = run `CheckInputScripts`. Script checks may be
    /// skipped only when every condition holds:
    ///
    /// * `assume_valid` is configured (`AssumedValidBlock` non-null);
    /// * the assumevalid hash is in the block index;
    /// * this block is the assumevalid block's ancestor-or-self;
    /// * this block is the best *header*'s ancestor-or-self;
    /// * the best header's chainwork meets `minimum_chain_work`;
    /// * the block is more than two weeks of proof-equivalent time below the
    ///   best header (the "block too recent" extortion guard).
    fn script_checks(&self, hash: &BlockHash, params: &Params) -> bool {
        const TWO_WEEKS: i64 = 60 * 60 * 24 * 7 * 2;
        let Some(assume) = params.assume_valid else {
            return true; // assumevalid=0 (always verify)
        };
        let Some(av) = self.tree.get(&assume) else {
            return true; // assumevalid hash not in headers
        };
        let Some(pindex) = self.tree.get(hash) else {
            return true;
        };
        let best = self.tree.tip();
        if !self.tree.is_ancestor(pindex, av)
            || !self.tree.is_ancestor(pindex, best)
            || best.chainwork < params.minimum_chain_work
            || HeaderTree::block_proof_equivalent_time(best, pindex, best, params) <= TWO_WEEKS
        {
            return true;
        }
        false
    }

    /// Runs `block` through the full acceptance pipeline — Core's
    /// `ProcessNewBlock` for a block with its body present, i.e.
    /// `AcceptBlock` (header insert, `CheckBlock`, `ContextualCheckBlock`,
    /// body retention) followed by `ActivateBestChain` (tip-extension connect
    /// or a heavier-branch reorg).
    ///
    /// `now` is the caller's adjusted local time for the header future-drift
    /// check.
    ///
    /// # Errors
    ///
    /// [`BlockRejection`] names the gate that failed. A `CheckBlock` failure
    /// leaves no trace — `ProcessNewBlock` runs `CheckBlock` before
    /// `AcceptBlock` and skips the rest entirely, so the header never enters
    /// the index and the block is never marked invalid (Core's CVE-2012-2459
    /// caution). `ContextualCheckBlock` and `ConnectBlock` failures do mark the
    /// index entry — except `BLOCK_MUTATED`-class rejections, which never mark
    /// — so descendants of a marked block can never activate.
    pub fn accept_block(&mut self, block: &Block, now: u32) -> Result<Acceptance, BlockRejection> {
        let params = *self.tree.params();
        // `ProcessNewBlock` runs `CheckBlock` before `AcceptBlock`: on failure
        // the block index is never touched and the block is never marked —
        // Core deliberately does not cache CheckBlock failures (CVE-2012-2459
        // malleability caution).
        check::check_block(block, &params).map_err(BlockRejection::Check)?;

        // `AcceptBlock` → `AcceptBlockHeader` (duplicate check, PoW, parent
        // linkage, the `bad-prevblk` gates, contextual header checks).
        let hash = block.block_hash();
        let height = match self.tree.insert(&block.header, now) {
            Ok(InsertStatus::Added { height }) => height,
            Ok(InsertStatus::AlreadyKnown { height }) => {
                // `AcceptBlockHeader`: a resubmitted header carrying
                // `BLOCK_FAILED_MASK` is `BLOCK_CACHED_INVALID`.
                if self.tree.is_failed(&hash) {
                    return Err(BlockRejection::CachedInvalid);
                }
                if self.have_body(&hash) {
                    // Body stored from the first submission: `AcceptBlock`
                    // short-circuits at `fAlreadyHave`, but `ActivateBestChain`
                    // still runs — a resubmitted side block whose branch now
                    // outworks the tip does reorg.
                    return match self.maybe_reorg(hash, &params) {
                        Ok(Some(disconnected)) => Ok(Acceptance::Connected {
                            height,
                            reorged: disconnected,
                        }),
                        Ok(None) => Ok(Acceptance::AlreadyKnown { height }),
                        Err(err) => Err(BlockRejection::Connect(err)),
                    };
                }
                // Header known but body never stored — a `BLOCK_MUTATED`-class
                // `ContextualCheckBlock` rejection leaves the index entry
                // unmarked and unbodied. `AcceptBlock` re-runs the body checks
                // on resubmission, so fall through to them.
                height
            }
            Err(err) => return Err(BlockRejection::Header(err)),
        };
        // `AcceptBlock` re-runs `CheckBlock` at this point, but it is
        // deterministic and just passed — the only remaining gate before the
        // body is stored is `ContextualCheckBlock`.
        let parent_mtp = self.tree.median_time_past(&block.header.prev_block_hash);
        let ctx = BlockContext {
            params: &params,
            height,
            parent_median_time_past: parent_mtp,
        };
        if let Err(err) = check::contextual_check_block(block, &ctx) {
            // `AcceptBlock`: `pindex->nStatus |= BLOCK_FAILED_VALID` when the
            // rejection is `IsInvalid()` and not `BLOCK_MUTATED`. The
            // witness-commitment failures are the MUTATED results;
            // `MissingMedianTimePast` is missing context, not an invalid
            // block.
            if !matches!(
                err,
                ContextualBlockError::BadWitnessNonceSize
                    | ContextualBlockError::BadWitnessMerkleMatch
                    | ContextualBlockError::UnexpectedWitness
                    | ContextualBlockError::MissingMedianTimePast
            ) {
                self.tree.mark_invalid(hash);
            }
            return Err(BlockRejection::Contextual(err));
        }
        // Structurally valid: retain the body — a later-arriving sibling may
        // outwork the tip and need it for a reorg (Core writes every accepted
        // block to a blk*.dat file for the same reason: `WriteBlockToDisk`
        // inside `AcceptBlock`, before `ActivateBestChain` decides anything —
        // so even a body that later fails to connect is stored). With a store
        // attached the file is the retention point — `have_body`/`body` serve
        // it from disk and the in-memory map stays empty; without one the map
        // is the retention point.
        if let Some(store) = &mut self.store {
            store
                .append(block)
                .map_err(|err| BlockRejection::Store(err.kind()))?;
        } else {
            self.blocks.insert(hash, block.clone());
        }
        if block.header.prev_block_hash == self.connected {
            let ctx = ConnectContext {
                params: &params,
                tree: &self.tree,
                block_hash: hash,
                script_checks: self.script_checks(&hash, &params),
            };
            match connect::connect_block(block, &mut self.utxo, &ctx) {
                Ok(undo) => {
                    self.chain.push(hash);
                    self.undos.push(undo);
                    self.connected = hash;
                    Ok(Acceptance::Connected {
                        height,
                        reorged: false,
                    })
                }
                Err(err) => {
                    // `InvalidChainFound`: the block is marked failed; its
                    // descendants can never connect. `connect_block` rolls
                    // back its partial UTXO application before returning.
                    self.tree.mark_invalid(hash);
                    Err(BlockRejection::Connect(err))
                }
            }
        } else {
            match self.maybe_reorg(hash, &params) {
                Ok(Some(disconnected)) => Ok(Acceptance::Connected {
                    height,
                    reorged: disconnected,
                }),
                Ok(None) => Ok(Acceptance::Parked { height }),
                Err(err) => Err(BlockRejection::Connect(err)),
            }
        }
    }

    /// If `hash`'s branch has more chainwork than the connected tip, reorg:
    /// disconnect `chain[fork+1..]` then connect the branch `fork+1..=hash`.
    ///
    /// The whole branch switch is simulated on a cloned UTXO set and committed
    /// only on success — `ActivateBestChain` likewise keeps the old chain when
    /// a heavier branch fails to connect. A branch block that fails
    /// `connect_block` is marked invalid (`BLOCK_FAILED_VALID`), so its
    /// descendants stop being reorg candidates.
    ///
    /// Returns `Ok(Some(disconnected))` when the branch activated —
    /// `disconnected` is `true` when connected blocks were rolled back (a real
    /// reorg) and `false` when the branch merely extended the tip —
    /// `Ok(None)` when the branch does not outwork the tip, and `Err` when the
    /// branch won the work race but failed to connect.
    fn maybe_reorg(
        &mut self,
        hash: BlockHash,
        params: &Params,
    ) -> Result<Option<bool>, ConnectError> {
        let Some(new_node) = self.tree.get(&hash) else {
            return Err(ConnectError::Internal("reorg on unknown header"));
        };
        let Some(conn_node) = self.tree.get(&self.connected) else {
            return Err(ConnectError::Internal("connected tip not in tree"));
        };
        if new_node.chainwork <= conn_node.chainwork {
            return Ok(None);
        }
        // Activation pruning: `FindMostWorkChain` skips a candidate whose
        // branch contains a failed block, marking the walked nodes
        // `BLOCK_FAILED_CHILD`. `ancestor_is_invalid` is the same walk with the
        // same marks — a failed-branch block parks rather than reconnecting.
        if self.tree.ancestor_is_invalid(hash) {
            return Ok(None);
        }
        // Collect the branch back to its fork point with the connected chain.
        let chain_set: HashSet<BlockHash> = self.chain.iter().copied().collect();
        let mut branch_hashes = Vec::new();
        let mut cursor = hash;
        while !chain_set.contains(&cursor) {
            branch_hashes.push(cursor);
            let Some(node) = self.tree.get(&cursor) else {
                return Err(ConnectError::Internal("branch walk left the tree"));
            };
            cursor = node.header.prev_block_hash;
        }
        let fork = cursor;
        let fork_height = self.tree.get(&fork).map(|n| n.height).unwrap_or(0);
        branch_hashes.reverse();

        // A candidate whose branch lacks a stored body can never activate
        // (Core: `!HaveTxsDownloaded` keeps it out of `setBlockIndexCandidates`)
        // — the only way a header enters the index without a body is a
        // `BLOCK_MUTATED`-class `CheckBlock` rejection, which is not marked
        // failed, so its descendants park rather than report a verdict.
        if branch_hashes.iter().any(|h| !self.have_body(h)) {
            return Ok(None);
        }

        // Simulate on a clone: disconnect the old branch, connect the new one.
        let mut utxo = self.utxo.clone();
        for height in (fork_height + 1..=self.undos.len() as u32).rev() {
            let block_hash = self.chain[height as usize];
            let Some(block) = self.body(&block_hash) else {
                return Err(ConnectError::Internal("missing connected block body"));
            };
            let undo = &self.undos[(height - 1) as usize];
            connect::disconnect_block(&block, &mut utxo, undo)
                .map_err(|_| ConnectError::Internal("disconnect undo inconsistent"))?;
        }
        let mut new_undos = Vec::with_capacity(branch_hashes.len());
        for branch_hash in &branch_hashes {
            let Some(block) = self.body(branch_hash) else {
                return Err(ConnectError::Internal("missing branch block body"));
            };
            let ctx = ConnectContext {
                params,
                tree: &self.tree,
                block_hash: *branch_hash,
                script_checks: self.script_checks(branch_hash, params),
            };
            match connect::connect_block(&block, &mut utxo, &ctx) {
                Ok(undo) => new_undos.push(undo),
                Err(err) => {
                    // The branch wins on work but this block is invalid: mark
                    // it (and thereby every later descendant) and keep the old
                    // active chain — `InvalidChainFound`'s exact behavior.
                    self.tree.mark_invalid(*branch_hash);
                    return Err(err);
                }
            }
        }

        // Commit. `disconnected` records whether any connected block was rolled
        // back — false when the branch merely extended the tip (a stored-body
        // resubmission landing here is `ActivateBestChain` connecting it, not
        // a reorg).
        let disconnected = (fork_height as usize) < self.chain.len() - 1;
        self.utxo = utxo;
        self.chain.truncate(fork_height as usize + 1);
        self.undos.truncate(fork_height as usize);
        self.chain.extend(branch_hashes);
        self.undos.extend(new_undos);
        self.connected = hash;
        Ok(Some(disconnected))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arith::CompactTarget;
    use crate::check::SEQUENCE_FINAL;
    use crate::header::BlockHeader;
    use crate::params::Network;
    use crate::pow;
    use crate::script;
    use crate::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

    const REGTEST_BITS: u32 = 0x207f_ffff;
    const NOW: u32 = 1_800_000_000;

    fn params() -> Params {
        Network::Regtest.params()
    }

    /// A valid regtest coinbase paying exactly the 50 BTC subsidy to `OP_1`,
    /// its scriptSig carrying the BIP34 height push (active at height 1).
    fn coinbase_tx(height: u32, subsidy: i64) -> Transaction {
        let mut script_sig = script::push_int(i64::from(height));
        script_sig.push(script::OP_1);
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(script_sig),
                sequence: SEQUENCE_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: subsidy,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        }
    }

    /// A regtest block on `parent` over `txs`, with a correct merkle root and
    /// ground PoW.
    fn block_on(parent: &BlockHeader, txs: Vec<Transaction>, params: &Params) -> Block {
        let mut block = Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: parent.hash(),
                merkle_root: parent.merkle_root,
                time: parent.time + 1,
                bits: CompactTarget(REGTEST_BITS),
                nonce: 0,
            },
            transactions: txs,
        };
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
            block.header.nonce += 1;
        }
        block
    }

    fn subsidy(height: u32) -> i64 {
        connect::block_subsidy(height, &params())
    }

    /// Like [`coinbase_tx`], but with an extra tag opcode in the scriptSig so a
    /// side branch's coinbases (and headers) differ from the main chain's.
    fn tagged_coinbase(height: u32, subsidy: i64, tag: u8) -> Transaction {
        let mut script_sig = script::push_int(i64::from(height));
        script_sig.push(script::OP_1);
        script_sig.push(tag);
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(script_sig),
                sequence: SEQUENCE_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: subsidy,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        }
    }

    fn genesis_header() -> BlockHeader {
        params().genesis_header
    }

    #[test]
    fn linear_connect_advances_tip() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        let mut parent = genesis_header();
        for height in 1..=3u32 {
            let block = block_on(&parent, vec![coinbase_tx(height, subsidy(height))], &params);
            parent = block.header;
            assert_eq!(
                cs.accept_block(&block, NOW),
                Ok(Acceptance::Connected {
                    height,
                    reorged: false
                }),
            );
        }
        assert_eq!(cs.chain().len(), 4);
        assert_eq!(cs.tip_hash(), parent.hash());
        assert_eq!(cs.utxo().len(), 3);
    }

    #[test]
    fn equal_work_side_block_parks() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        let a = block_on(&genesis_header(), vec![coinbase_tx(1, subsidy(1))], &params);
        assert_eq!(
            cs.accept_block(&a, NOW),
            Ok(Acceptance::Connected {
                height: 1,
                reorged: false
            })
        );
        // A second child of genesis — different coinbase content, same work.
        let b = block_on(
            &genesis_header(),
            vec![tagged_coinbase(1, subsidy(1), script::OP_RETURN)],
            &params,
        );
        assert_eq!(
            cs.accept_block(&b, NOW),
            Ok(Acceptance::Parked { height: 1 })
        );
        assert_eq!(cs.tip_hash(), a.block_hash());
    }

    #[test]
    fn heavier_branch_reorgs() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        // Main chain: two blocks on genesis.
        let a1 = block_on(&genesis_header(), vec![coinbase_tx(1, subsidy(1))], &params);
        let a2 = block_on(&a1.header, vec![coinbase_tx(2, subsidy(2))], &params);
        cs.accept_block(&a1, NOW).unwrap();
        cs.accept_block(&a2, NOW).unwrap();
        // Side branch: three blocks on genesis (distinct coinbases).
        let b1 = block_on(
            &genesis_header(),
            vec![tagged_coinbase(1, subsidy(1), script::OP_EQUAL)],
            &params,
        );
        let b2 = block_on(
            &b1.header,
            vec![tagged_coinbase(2, subsidy(2), script::OP_EQUAL)],
            &params,
        );
        let b3 = block_on(
            &b2.header,
            vec![tagged_coinbase(3, subsidy(3), script::OP_EQUAL)],
            &params,
        );
        assert_eq!(
            cs.accept_block(&b1, NOW),
            Ok(Acceptance::Parked { height: 1 })
        );
        assert_eq!(
            cs.accept_block(&b2, NOW),
            Ok(Acceptance::Parked { height: 2 })
        );
        // b3 outworks the h2 tip: disconnect a1+a2, connect b1+b2+b3.
        assert_eq!(
            cs.accept_block(&b3, NOW),
            Ok(Acceptance::Connected {
                height: 3,
                reorged: true
            })
        );
        assert_eq!(cs.tip_hash(), b3.block_hash());
        assert_eq!(cs.chain().len(), 4);
        assert_eq!(cs.chain()[1], b1.block_hash());
        // The UTXO set now holds the branch's three coinbases, not the old
        // chain's two.
        assert_eq!(cs.utxo().len(), 3);
        let a2_txid = a2.transactions[0].txid();
        assert!(!cs.utxo().have(&OutPoint {
            txid: a2_txid,
            vout: 0
        }));
    }

    #[test]
    fn connect_failure_marks_invalid_and_descendants_rejected() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        // A block whose coinbase overpays: passes CheckBlock, fails
        // ConnectBlock's `bad-cb-amount`.
        let bad = block_on(
            &genesis_header(),
            vec![coinbase_tx(1, subsidy(1) + 1)],
            &params,
        );
        let bad_hash = bad.block_hash();
        match cs.accept_block(&bad, NOW) {
            Err(BlockRejection::Connect(err)) => {
                assert_eq!(&*err.reason(), "bad-cb-amount");
            }
            other => panic!("expected connect rejection, got {other:?}"),
        }
        assert!(cs.tree().is_failed(&bad_hash));
        // Resubmitting the failed block: `duplicate-invalid`.
        match cs.accept_block(&bad, NOW) {
            Err(BlockRejection::CachedInvalid) => {}
            other => panic!("expected cached-invalid, got {other:?}"),
        }
        // A child of the failed block: `bad-prevblk` at header insertion.
        let child = block_on(&bad.header, vec![coinbase_tx(2, subsidy(2))], &params);
        match cs.accept_block(&child, NOW) {
            Err(BlockRejection::Header(ChainError::InvalidParent)) => {}
            other => panic!("expected bad-prevblk, got {other:?}"),
        }
        // A valid block still connects on genesis.
        let good = block_on(&genesis_header(), vec![coinbase_tx(1, subsidy(1))], &params);
        assert_eq!(
            cs.accept_block(&good, NOW),
            Ok(Acceptance::Connected {
                height: 1,
                reorged: false
            })
        );
    }

    #[test]
    fn failed_heavier_branch_keeps_old_tip() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        let a1 = block_on(&genesis_header(), vec![coinbase_tx(1, subsidy(1))], &params);
        let a2 = block_on(&a1.header, vec![coinbase_tx(2, subsidy(2))], &params);
        cs.accept_block(&a1, NOW).unwrap();
        cs.accept_block(&a2, NOW).unwrap();
        // Side branch: b1 valid, b2 pays too much (fails only at connect),
        // b3 valid — the branch outworks the h2 tip.
        let b1 = block_on(
            &genesis_header(),
            vec![tagged_coinbase(1, subsidy(1), script::OP_HASH160)],
            &params,
        );
        let b2 = block_on(
            &b1.header,
            vec![tagged_coinbase(2, subsidy(2) + 1, script::OP_HASH160)],
            &params,
        );
        let b3 = block_on(
            &b2.header,
            vec![tagged_coinbase(3, subsidy(3), script::OP_HASH160)],
            &params,
        );
        assert_eq!(
            cs.accept_block(&b1, NOW),
            Ok(Acceptance::Parked { height: 1 })
        );
        assert_eq!(
            cs.accept_block(&b2, NOW),
            Ok(Acceptance::Parked { height: 2 })
        );
        // b3 triggers the reorg attempt; it fails at b2's `bad-cb-amount`.
        match cs.accept_block(&b3, NOW) {
            Err(BlockRejection::Connect(err)) => {
                assert_eq!(&*err.reason(), "bad-cb-amount");
            }
            other => panic!("expected connect rejection, got {other:?}"),
        }
        // The old tip stands; b2 is marked; b3's children get bad-prevblk.
        assert_eq!(cs.tip_hash(), a2.block_hash());
        assert_eq!(cs.chain().len(), 3);
        assert!(cs.tree().is_failed(&b2.block_hash()));
        let b4 = block_on(
            &b3.header,
            vec![tagged_coinbase(4, subsidy(4), script::OP_HASH160)],
            &params,
        );
        match cs.accept_block(&b4, NOW) {
            Err(BlockRejection::Header(ChainError::InvalidParent)) => {}
            other => panic!("expected bad-prevblk, got {other:?}"),
        }
        // The `b4` insertion's ancestor walk marked `b3` failed between it and
        // `b2` — resubmitting `b3` is now `duplicate-invalid`, and the tip is
        // still `a2`.
        match cs.accept_block(&b3, NOW) {
            Err(BlockRejection::CachedInvalid) => {}
            other => panic!("expected cached-invalid, got {other:?}"),
        }
        assert!(cs.tree().is_failed(&b3.block_hash()));
        assert_eq!(cs.tip_hash(), a2.block_hash());
    }

    #[test]
    fn resubmissions() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        let a = block_on(&genesis_header(), vec![coinbase_tx(1, subsidy(1))], &params);
        cs.accept_block(&a, NOW).unwrap();
        // Resubmitted connected block.
        assert_eq!(
            cs.accept_block(&a, NOW),
            Ok(Acceptance::AlreadyKnown { height: 1 })
        );
        // Resubmitted parked block.
        let b = block_on(
            &genesis_header(),
            vec![tagged_coinbase(1, subsidy(1), script::OP_CHECKSIG)],
            &params,
        );
        cs.accept_block(&b, NOW).unwrap();
        assert_eq!(
            cs.accept_block(&b, NOW),
            Ok(Acceptance::AlreadyKnown { height: 1 })
        );
    }

    /// Builds a same-difficulty header chain 1..=`tip_height` over the regtest
    /// genesis. Height 1's coinbase pays two zero-value `OP_0` (always-false)
    /// outputs at v1/v2; `probe_heights` blocks additionally spend one of
    /// them — a spend that can only connect while script checks are skipped.
    fn probe_chain(tip_height: u32, probe_heights: &[(u32, u32)], params: &Params) -> Vec<Block> {
        let mut blocks: Vec<Block> = Vec::new();
        let mut parent = params.genesis_header;
        for height in 1..=tip_height {
            let mut coinbase = coinbase_tx(height, subsidy(height));
            if height == 1 {
                coinbase.outputs.push(TxOut {
                    value: 0,
                    script_pubkey: Script::new(vec![script::OP_0]),
                });
                coinbase.outputs.push(TxOut {
                    value: 0,
                    script_pubkey: Script::new(vec![script::OP_0]),
                });
            }
            let mut txs = vec![coinbase];
            if let Some((_, vout)) = probe_heights.iter().find(|(h, _)| *h == height) {
                txs.push(Transaction {
                    version: 1,
                    inputs: vec![TxIn {
                        previous_output: OutPoint {
                            txid: blocks[0].transactions[0].txid(),
                            vout: *vout,
                        },
                        script_sig: Script::new(vec![]),
                        sequence: SEQUENCE_FINAL,
                        witness: Witness::default(),
                    }],
                    outputs: vec![TxOut {
                        value: 0,
                        script_pubkey: Script::new(vec![script::OP_1]),
                    }],
                    lock_time: 0,
                });
            }
            let block = block_on(&parent, txs, params);
            parent = block.header;
            blocks.push(block);
        }
        blocks
    }

    #[test]
    fn assumevalid_skips_script_checks_below_the_assumed_block() {
        let mut params = params();
        // Bodies to height 135; headers to 2130 so the best header sits
        // >2017 blocks (two weeks of proof-equivalent time at 10-minute
        // spacing) above every connected block. assumevalid = block@120.
        // Block 105 spends an always-false output (below av -> checks
        // skipped -> connects); block 135 spends the second (above av ->
        // verified -> rejected).
        let blocks = probe_chain(2130, &[(105, 1), (135, 2)], &params);
        params.assume_valid = Some(blocks[119].block_hash());
        let mut cs = Chainstate::new(&params);
        for block in &blocks {
            cs.accept_header(&block.header, NOW).unwrap();
        }
        for block in &blocks[..134] {
            assert!(
                cs.accept_block(block, NOW).is_ok(),
                "body {} should connect",
                cs.tree().get(&block.block_hash()).map_or(0, |n| n.height)
            );
        }
        assert!(matches!(
            cs.accept_block(&blocks[134], NOW),
            Err(BlockRejection::Connect(ConnectError::ScriptVerify(_)))
        ));
    }

    #[test]
    fn assumevalid_unindexed_or_unset_still_verifies() {
        // `assumevalid hash not in headers` — a configured hash that never
        // entered the index keeps script checks on (Core's first gate).
        let mut unindexed = params();
        unindexed.assume_valid = Some(BlockHash::from_bytes([7; 32]));
        let blocks = probe_chain(105, &[(105, 1)], &unindexed);
        for params in [unindexed, params()] {
            let mut cs = Chainstate::new(&params);
            for block in &blocks[..104] {
                cs.accept_block(block, NOW).unwrap();
            }
            assert!(matches!(
                cs.accept_block(&blocks[104], NOW),
                Err(BlockRejection::Connect(ConnectError::ScriptVerify(_)))
            ));
        }
    }

    /// A unique store dir — same pattern as the store tests.
    fn store_dir(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        let dir = base.join(format!(
            "avila-chainstate-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// The coins view as a sorted vec — `UtxoSet` iteration order is
    /// unspecified, so equality checks go through this.
    fn sorted_utxo(cs: &Chainstate) -> Vec<(OutPoint, crate::connect::Coin)> {
        let mut v: Vec<_> = cs.utxo().iter().map(|(op, c)| (*op, c.clone())).collect();
        v.sort_by_key(|(op, _)| (op.txid.to_bytes(), op.vout));
        v
    }

    #[test]
    fn with_store_persists_and_resumes() {
        let params = params();
        let dir = store_dir("resume");

        let blocks = probe_chain(20, &[], &params);
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        for block in &blocks[..10] {
            cs.accept_block(block, NOW).unwrap();
        }
        cs.flush().unwrap();
        let tip10 = cs.tip_hash();
        drop(cs);

        // Resume: the snapshot restores the same tip and coins view, and new
        // bodies connect on top.
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        assert_eq!(cs.tip_hash(), tip10);
        for block in &blocks[10..] {
            assert!(cs.accept_block(block, NOW).is_ok());
        }
        assert_eq!(cs.tip_hash(), blocks[19].block_hash());
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn snapshot_resume_skips_covered_bodies() {
        let params = params();
        let dir = store_dir("snapshot-resume");
        let blocks = probe_chain(20, &[], &params);
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        for block in &blocks[..10] {
            cs.accept_block(block, NOW).unwrap();
        }
        cs.flush().unwrap();
        assert!(dir.join("state.dat").exists());
        let tip = cs.tip_hash();
        let utxo = sorted_utxo(&cs);
        drop(cs);

        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        assert_eq!(cs.tip_hash(), tip);
        assert_eq!(cs.chain().len(), 11);
        assert_eq!(sorted_utxo(&cs), utxo);
        // Covered bodies came from the snapshot — never re-validated, so they
        // never entered the in-memory body map (the store still serves them).
        for block in &blocks[..10] {
            assert!(cs.block(&block.block_hash()).is_none());
        }
        // A resubmitted snapshotted body reports already-known, not parked.
        assert_eq!(
            cs.accept_block(&blocks[5], NOW),
            Ok(Acceptance::AlreadyKnown { height: 6 })
        );
        // Post-snapshot bodies connect normally.
        for block in &blocks[10..] {
            assert!(cs.accept_block(block, NOW).is_ok());
        }
        assert_eq!(cs.tip_hash(), blocks[19].block_hash());
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn snapshot_gap_bodies_replay() {
        let params = params();
        let dir = store_dir("snapshot-gap");
        let blocks = probe_chain(15, &[], &params);
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        for block in &blocks[..10] {
            cs.accept_block(block, NOW).unwrap();
        }
        cs.flush().unwrap();
        // Bodies appended after the flush are not in the snapshot — the tail
        // file is unbuffered, so they are already on disk.
        for block in &blocks[10..] {
            cs.accept_block(block, NOW).unwrap();
        }
        let tip = cs.tip_hash();
        drop(cs);

        let cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        assert_eq!(cs.tip_hash(), tip);
        assert_eq!(cs.chain().len(), 16);
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn snapshot_corruption_falls_back_to_replay() {
        let params = params();
        let dir = store_dir("snapshot-corrupt");
        let blocks = probe_chain(10, &[], &params);
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        for block in &blocks {
            cs.accept_block(block, NOW).unwrap();
        }
        cs.flush().unwrap();
        let tip = cs.tip_hash();
        drop(cs);

        // Corrupt the snapshot payload — resume must still reach the same
        // state by replaying every stored body.
        let path = dir.join("state.dat");
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();

        let cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        assert_eq!(cs.tip_hash(), tip);
        assert_eq!(cs.chain().len(), 11);
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn snapshot_failed_marks_persist() {
        let params = params();
        let dir = store_dir("snapshot-failed");
        let a1 = block_on(&genesis_header(), vec![coinbase_tx(1, subsidy(1))], &params);
        let bad = block_on(
            &a1.header,
            vec![tagged_coinbase(2, subsidy(2) + 1, script::OP_EQUAL)],
            &params,
        );
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        cs.accept_block(&a1, NOW).unwrap();
        assert!(matches!(
            cs.accept_block(&bad, NOW),
            Err(BlockRejection::Connect(_))
        ));
        cs.flush().unwrap();
        drop(cs);

        // The failed mark survives the restart: the resubmission is
        // `duplicate-invalid`, and a child of it is `bad-prevblk`.
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        assert!(cs.tree().is_failed(&bad.block_hash()));
        match cs.accept_block(&bad, NOW) {
            Err(BlockRejection::CachedInvalid) => {}
            other => panic!("expected cached-invalid, got {other:?}"),
        }
        let child = block_on(
            &bad.header,
            vec![tagged_coinbase(3, subsidy(3), script::OP_EQUAL)],
            &params,
        );
        match cs.accept_block(&child, NOW) {
            Err(BlockRejection::Header(ChainError::InvalidParent)) => {}
            other => panic!("expected bad-prevblk, got {other:?}"),
        }
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reorg_after_snapshot_restore() {
        let params = params();
        let dir = store_dir("snapshot-reorg");
        let mut parent = genesis_header();
        let mut a_chain = Vec::new();
        for height in 1..=3u32 {
            let block = block_on(&parent, vec![coinbase_tx(height, subsidy(height))], &params);
            parent = block.header;
            a_chain.push(block);
        }
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        for block in &a_chain {
            cs.accept_block(block, NOW).unwrap();
        }
        cs.flush().unwrap();
        drop(cs);

        // A heavier side branch post-restore must disconnect the snapshotted
        // connected blocks — their bodies exist only in the store.
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        assert!(cs.block(&a_chain[2].block_hash()).is_none());
        let mut b_parent = genesis_header();
        let mut b_chain = Vec::new();
        for height in 1..=4u32 {
            let block = block_on(
                &b_parent,
                vec![tagged_coinbase(height, subsidy(height), script::OP_HASH160)],
                &params,
            );
            b_parent = block.header;
            b_chain.push(block);
        }
        for block in &b_chain[..3] {
            assert!(matches!(
                cs.accept_block(block, NOW),
                Ok(Acceptance::Parked { .. })
            ));
        }
        // b4 outworks the a3 tip: the reorg disconnects a1..a3, whose bodies
        // the store serves because they were never re-read into memory.
        assert_eq!(
            cs.accept_block(&b_chain[3], NOW),
            Ok(Acceptance::Connected {
                height: 4,
                reorged: true
            })
        );
        assert_eq!(cs.tip_hash(), b_chain[3].block_hash());
        assert_eq!(cs.chain().len(), 5);
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn snapshot_write_failure_keeps_previous_snapshot() {
        let params = params();
        let dir = store_dir("snapshot-writefail");
        let blocks = probe_chain(10, &[], &params);
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        for block in &blocks[..5] {
            cs.accept_block(block, NOW).unwrap();
        }
        cs.flush().unwrap();
        let committed = std::fs::read(dir.join("state.dat")).unwrap();
        drop(cs);

        // Connect five more bodies, then make `state.dat.tmp` a directory so
        // the snapshot write fails after the blk flush succeeded.
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        for block in &blocks[5..] {
            cs.accept_block(block, NOW).unwrap();
        }
        std::fs::create_dir(dir.join("state.dat.tmp")).unwrap();
        assert!(cs.flush().is_err());
        drop(cs);
        std::fs::remove_dir(dir.join("state.dat.tmp")).unwrap();

        // The committed snapshot is byte-identical; resume restores it and
        // replays the five post-snapshot bodies to the same tip.
        assert_eq!(std::fs::read(dir.join("state.dat")).unwrap(), committed);
        let cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        assert_eq!(cs.tip_hash(), blocks[9].block_hash());
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

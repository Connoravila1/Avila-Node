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

use thiserror::Error;

use crate::block::Block;
use crate::chain::{ChainError, HeaderTree, InsertStatus};
use crate::check::{self, BlockContext, BlockRuleError, ContextualBlockError, RuleError};
use crate::connect::{self, BlockUndo, ConnectContext, ConnectError, UtxoSet};
use crate::hash::BlockHash;
use crate::params::Params;

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
        }
    }
}

/// Stateful block acceptance: the block index, the coins view, the active
/// chain, and the undo records needed to reorganize it.
///
/// All state is resident in memory — this is the validation driver, not the
/// storage layer. A durable backend (blk/rev files, a coins database,
/// resumable replay) slots in behind the same pipeline in a later milestone.
pub struct Chainstate {
    tree: HeaderTree,
    utxo: UtxoSet,
    /// Block hash of the connected tip — the genesis at start, whose coinbase
    /// is never in the UTXO set on any network.
    connected: BlockHash,
    /// Accepted block bodies by hash — Core keeps them in blk*.dat; a real
    /// node needs them for reorgs and rescan, this driver needs them for
    /// reorgs.
    blocks: HashMap<BlockHash, Block>,
    /// The connected chain's block hashes, genesis at index 0.
    chain: Vec<BlockHash>,
    /// Per-block undo for `chain[1..]` (the genesis is never connected):
    /// `undos[k]` reverses the block at height `k + 1`.
    undos: Vec<BlockUndo>,
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
        }
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
    /// `ContextualCheckBlock`.
    #[must_use]
    pub fn block(&self, hash: &BlockHash) -> Option<&Block> {
        self.blocks.get(hash)
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
                if self.blocks.contains_key(&hash) {
                    // Body stored from the first submission: `AcceptBlock`
                    // short-circuits at `fAlreadyHave`, but `ActivateBestChain`
                    // still runs — a resubmitted side block whose branch now
                    // outworks the tip does reorg.
                    return match self.maybe_reorg(hash, &params) {
                        Ok(true) => Ok(Acceptance::Connected {
                            height,
                            reorged: true,
                        }),
                        Ok(false) => Ok(Acceptance::AlreadyKnown { height }),
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
        // block to a blk*.dat file for the same reason).
        self.blocks.insert(hash, block.clone());
        if block.header.prev_block_hash == self.connected {
            let ctx = ConnectContext {
                params: &params,
                tree: &self.tree,
                block_hash: hash,
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
                Ok(true) => Ok(Acceptance::Connected {
                    height,
                    reorged: true,
                }),
                Ok(false) => Ok(Acceptance::Parked { height }),
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
    /// Returns `Ok(true)` when a reorg was performed, `Ok(false)` when the
    /// branch does not outwork the tip, `Err` when the branch won the work
    /// race but failed to connect.
    fn maybe_reorg(&mut self, hash: BlockHash, params: &Params) -> Result<bool, ConnectError> {
        let Some(new_node) = self.tree.get(&hash) else {
            return Err(ConnectError::Internal("reorg on unknown header"));
        };
        let Some(conn_node) = self.tree.get(&self.connected) else {
            return Err(ConnectError::Internal("connected tip not in tree"));
        };
        if new_node.chainwork <= conn_node.chainwork {
            return Ok(false);
        }
        // Activation pruning: `FindMostWorkChain` skips a candidate whose
        // branch contains a failed block, marking the walked nodes
        // `BLOCK_FAILED_CHILD`. `ancestor_is_invalid` is the same walk with the
        // same marks — a failed-branch block parks rather than reconnecting.
        if self.tree.ancestor_is_invalid(hash) {
            return Ok(false);
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
        if branch_hashes.iter().any(|h| !self.blocks.contains_key(h)) {
            return Ok(false);
        }

        // Simulate on a clone: disconnect the old branch, connect the new one.
        let mut utxo = self.utxo.clone();
        for height in (fork_height + 1..=self.undos.len() as u32).rev() {
            let block_hash = self.chain[height as usize];
            let Some(block) = self.blocks.get(&block_hash) else {
                return Err(ConnectError::Internal("missing connected block body"));
            };
            let undo = &self.undos[(height - 1) as usize];
            connect::disconnect_block(block, &mut utxo, undo)
                .map_err(|_| ConnectError::Internal("disconnect undo inconsistent"))?;
        }
        let mut new_undos = Vec::with_capacity(branch_hashes.len());
        for branch_hash in &branch_hashes {
            let Some(block) = self.blocks.get(branch_hash) else {
                return Err(ConnectError::Internal("missing branch block body"));
            };
            let ctx = ConnectContext {
                params,
                tree: &self.tree,
                block_hash: *branch_hash,
            };
            match connect::connect_block(block, &mut utxo, &ctx) {
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

        // Commit.
        self.utxo = utxo;
        self.chain.truncate(fork_height as usize + 1);
        self.undos.truncate(fork_height as usize);
        self.chain.extend(branch_hashes);
        self.undos.extend(new_undos);
        self.connected = hash;
        Ok(true)
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
}

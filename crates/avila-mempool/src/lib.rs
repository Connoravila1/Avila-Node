//! The transaction memory pool — **policy**, not consensus. Everything
//! here is a node-local relay/storage decision layered on top of
//! `avila-consensus` primitives: consensus rules (`check_transaction`,
//! `check_tx_inputs`, `bip68_locks_satisfied`, `check_input_scripts`)
//! run unchanged; the pool adds Core's standardness and economic gates
//! (`AcceptToMemoryPool` shape: weight cap, min-relay fee, RBF
//! conflicts, size-bounded eviction).
//!
//! Nothing in this crate can make a block invalid — it only decides
//! which unconfirmed transactions we keep and relay.

use std::collections::HashMap;

use avila_consensus::check::{TxRuleError, check_transaction};
use avila_consensus::connect::{
    Coin, ConnectError, UtxoSet, bip68_locks_satisfied, check_tx_inputs,
};
use avila_consensus::hash::Txid;
use avila_consensus::interpreter::ScriptError;
use avila_consensus::script::{ScriptFlags, block_script_flags};
use avila_consensus::sigchecker::check_input_scripts;
use avila_consensus::transaction::{OutPoint, Transaction};

/// Core's `DEFAULT_MIN_RELAY_TX_FEE`: 1000 sat/kvB (1 sat/vB).
pub const DEFAULT_MIN_RELAY_FEE: i64 = 1000;

/// Core's `MAX_STANDARD_TX_WEIGHT` — 400,000 weight units (~100 kvB).
/// Policy only; consensus has no per-tx weight cap beyond the block's.
pub const MAX_STANDARD_TX_WEIGHT: usize = 400_000;

/// Core's `DEFAULT_INCREMENTAL_RELAY_FEE` — a replacement must cover its
/// own relay at this rate on top of the conflicting tx's fee.
pub const INCREMENTAL_RELAY_FEE: i64 = 1000; // sat/kvB

/// Bound on pool entries — Core bounds by bytes (300 MB default); ours
/// is an entry count, which is simpler and strictly bounded either way.
pub const DEFAULT_MAX_ENTRIES: usize = 25_000;

/// Core's `nSequence` threshold for BIP125 replaceability signaling:
/// any input below `0xfffffffe` opts the tx into replacement.
const RBF_SEQUENCE_THRESHOLD: u32 = 0xffff_fffe;

/// A pooled transaction with the policy facts admission computed.
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    /// The transaction.
    pub tx: Transaction,
    /// `value_in - value_out` in satoshis.
    pub fee: i64,
    /// Virtual size (weight/4) used for fee-rate and eviction scoring.
    pub vsize: usize,
    /// Arrival time (caller-supplied).
    pub time: u32,
}

/// Why a transaction was refused — the vocabulary Core's
/// `AcceptToMemoryPool` reports via `state.Invalid()`/`Reject`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MempoolReject {
    /// A context-free consensus failure (`check_transaction`) — the tx
    /// is invalid everywhere, not just unpooled.
    #[error("{0}")]
    Consensus(#[from] TxRuleError),
    /// Coinbase transactions never enter the mempool.
    #[error("coinbase")]
    Coinbase,
    /// The txid is already pooled.
    #[error("txn-already-in-mempool")]
    AlreadyKnown,
    /// Weight exceeds [`MAX_STANDARD_TX_WEIGHT`].
    #[error("tx-size")]
    TooHeavy,
    /// An input resolves nowhere — not in the UTXO set, not a mempool
    /// parent's output. (Core parks such txs in the orphan pool.)
    #[error("bad-txns-inputs-missingorspent")]
    InputsMissingOrSpent,
    /// Consensus input checks failed (maturity, ranges, fee ≥ 0).
    #[error("{0}")]
    Inputs(ConnectError),
    /// BIP68 sequence locks are not satisfied for the next block.
    #[error("non-BIP68-final")]
    NotFinal,
    /// A mandatory script-verify flag failed.
    #[error("mandatory-script-verify-flag-failed ({0})")]
    ScriptVerify(#[from] ScriptError),
    /// `fee / vsize` is below the min-relay rate.
    #[error("min relay fee not met")]
    MinRelayFee,
    /// Spends an outpoint a pooled tx already spends and the replacement
    /// fails BIP125 (conflicts don't signal RBF, or the bump is too
    /// small to cover incremental relay).
    #[error("txn-mempool-conflict")]
    Conflict,
    /// The pool is at capacity and this tx's fee rate doesn't beat the
    /// lowest-fee-rate entry.
    #[error("mempool full")]
    Full,
}

/// Core's `MAX_ORPHAN_TRANSACTIONS` — orphan entries bound separately
/// from the pool so orphan flooding can't crowd out confirmed-parent
/// txs or blow memory.
pub const MAX_ORPHANS: usize = 100;

/// Core's `ORPHAN_TX_EXPIRE_TIME` — orphans live at most 20 minutes.
pub const ORPHAN_EXPIRE_SECS: u32 = 20 * 60;

/// A parked orphan — a tx with unresolved inputs, kept for when its
/// parents arrive.
#[derive(Clone, Debug)]
struct OrphanEntry {
    tx: Transaction,
    time: u32,
}

/// A bounded policy pool over the live UTXO set.
pub struct Mempool {
    /// txid → entry.
    map: HashMap<Txid, MempoolEntry>,
    /// outpoint → txid of the pooled tx spending it (conflict index).
    spends: HashMap<OutPoint, Txid>,
    /// txid → parked tx with missing parents (Core's orphan pool).
    orphans: HashMap<Txid, OrphanEntry>,
    /// Entry cap.
    max_entries: usize,
    /// Min relay fee rate in sat/kvB.
    min_relay_fee: i64,
}

impl Mempool {
    /// An empty pool with Core's default relay fee and the entry cap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            spends: HashMap::new(),
            orphans: HashMap::new(),
            max_entries: DEFAULT_MAX_ENTRIES,
            min_relay_fee: DEFAULT_MIN_RELAY_FEE,
        }
    }

    /// Pool size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Lookup by txid.
    #[must_use]
    pub fn get(&self, txid: &Txid) -> Option<&Transaction> {
        self.map.get(txid).map(|e| &e.tx)
    }

    /// Overrides the min-relay fee rate (sat/kvB) — an operator knob.
    pub fn set_min_relay_fee(&mut self, sat_per_kvb: i64) {
        self.min_relay_fee = sat_per_kvb;
    }

    /// Overrides the entry cap — an operator knob.
    pub fn set_max_entries(&mut self, n: usize) {
        self.max_entries = n;
    }

    /// Does `tx` signal BIP125 replaceability (any input sequence below
    /// `0xfffffffe`)?
    fn signals_rbf(tx: &Transaction) -> bool {
        tx.inputs
            .iter()
            .any(|i| i.sequence < RBF_SEQUENCE_THRESHOLD)
    }

    /// Resolves an input's coin: the confirmed UTXO first, else a pooled
    /// parent's output — Core's `view` layered over `pool.cs`/`mapTx`.
    fn resolve(&self, cs: &avila_consensus::chainstate::Chainstate, op: &OutPoint) -> Option<Coin> {
        if let Some(coin) = cs.utxo().get(op) {
            return Some(coin.clone());
        }
        // Unconfirmed parent: the pooled tx's output at `op.vout`.
        let parent = self.map.get(&op.txid)?;
        let out = parent.tx.outputs.get(op.vout as usize)?.clone();
        Some(Coin {
            out,
            // In-pool coins are unconfirmed — maturity can't apply
            // (coinbase txs never pool) and BIP68 measures from the
            // parent's height, which for admission purposes is the tip.
            height: cs.tree().tip().height,
            coinbase: false,
        })
    }

    /// `AcceptToMemoryPool` for a single transaction (no package
    /// admission yet — parents must resolve individually). On success
    /// the txid is returned; conflicts replaced under BIP125 are
    /// dropped from the pool.
    ///
    /// `now` is the caller's clock for entry bookkeeping.
    pub fn accept_tx(
        &mut self,
        tx: Transaction,
        cs: &avila_consensus::chainstate::Chainstate,
        now: u32,
    ) -> Result<Txid, MempoolReject> {
        // 1. Context-free consensus (Core's CheckTransaction).
        check_transaction(&tx)?;
        if tx.is_coinbase() {
            return Err(MempoolReject::Coinbase);
        }
        let txid = tx.txid();
        if self.map.contains_key(&txid) {
            return Err(MempoolReject::AlreadyKnown);
        }
        if tx.weight() > MAX_STANDARD_TX_WEIGHT {
            return Err(MempoolReject::TooHeavy);
        }

        // 2. Resolve inputs; index outpoint conflicts for BIP125.
        let mut spent = Vec::with_capacity(tx.inputs.len());
        let mut conflicts: Vec<Txid> = Vec::new();
        for input in &tx.inputs {
            let Some(coin) = self.resolve(cs, &input.previous_output) else {
                self.park_orphan(tx, now);
                return Err(MempoolReject::InputsMissingOrSpent);
            };
            spent.push(coin);
            if let Some(&conflict) = self.spends.get(&input.previous_output)
                && !conflicts.contains(&conflict)
            {
                conflicts.push(conflict);
            }
        }

        // 3. BIP125: a conflicted spend may only proceed if every
        //    conflict signals replaceability and the bump is large
        //    enough — checked after the fee is known (step 5).
        if !conflicts.is_empty() {
            let all_signal = conflicts
                .iter()
                .all(|id| self.map.get(id).is_some_and(|e| Self::signals_rbf(&e.tx)));
            if !all_signal || !Self::signals_rbf(&tx) {
                return Err(MempoolReject::Conflict);
            }
        }

        // 4. Consensus input checks against an overlay containing exactly
        //    this tx's resolved coins — identical logic to block connect.
        let tip = cs.tip_hash();
        let next_height = cs.tree().tip().height + 1;
        let mut overlay = UtxoSet::new();
        for (input, coin) in tx.inputs.iter().zip(spent.iter()) {
            overlay.insert_synthetic(input.previous_output, coin.clone());
        }
        let (_, fee) =
            check_tx_inputs(&tx, &overlay, next_height).map_err(MempoolReject::Inputs)?;

        // 5. BIP125 fee rule: replacement must pay the conflicts' fees
        //    plus incremental relay for its own size.
        let vsize = tx.weight().div_ceil(4);
        if !conflicts.is_empty() {
            let conflict_fees: i64 = conflicts
                .iter()
                .filter_map(|id| self.map.get(id))
                .map(|e| e.fee)
                .sum();
            let required = conflict_fees + INCREMENTAL_RELAY_FEE * vsize as i64 / 1000;
            if fee < required {
                return Err(MempoolReject::Conflict);
            }
        }

        // 6. BIP68 sequence locks vs the tip (Core evaluates mempool
        //    locks against the active chain's tip context).
        if cs.tree().params().csv_height <= next_height {
            let parent_mtp = cs
                .tree()
                .median_time_past(&tip)
                .ok_or(MempoolReject::NotFinal)?;
            if !bip68_locks_satisfied(&tx, &spent, next_height, parent_mtp, cs.tree(), &tip) {
                return Err(MempoolReject::NotFinal);
            }
        }

        // 7. Script checks: consensus flags at the next height plus
        //    Core's standardness set (policy — a tx failing only these
        //    is still block-valid, just not relayed).
        let flags = standard_script_flags(cs, next_height, &tip);
        let spent_outs: Vec<_> = spent.iter().map(|c| c.out.clone()).collect();
        check_input_scripts(&tx, &spent_outs, flags).map_err(MempoolReject::ScriptVerify)?;

        // 8. Min relay fee (Core: fee >= GetVirtualTransactionSize *
        //    minRelayTxFee / 1000).
        if fee * 1000 < self.min_relay_fee * vsize as i64 {
            return Err(MempoolReject::MinRelayFee);
        }

        // 9. Capacity: evict the lowest fee-rate entry if this one
        //    outbids it; refuse otherwise.
        if self.map.len() >= self.max_entries {
            let my_rate = fee * 1000 / vsize as i64;
            let Some((&worst_id, worst)) = self
                .map
                .iter()
                .min_by_key(|(_, e)| e.fee * 1000 / e.vsize.max(1) as i64)
            else {
                return Err(MempoolReject::Full);
            };
            if my_rate <= worst.fee * 1000 / worst.vsize.max(1) as i64 {
                return Err(MempoolReject::Full);
            }
            self.remove(&worst_id);
        }

        // 10. BIP125 replacement: drop the conflicts (their descendants
        //     go too — a child can't outlive its parent in the pool).
        for id in conflicts {
            self.remove_recursive(&id);
        }

        for input in &tx.inputs {
            self.spends.insert(input.previous_output, txid);
        }
        self.map.insert(
            txid,
            MempoolEntry {
                tx,
                fee,
                vsize,
                time: now,
            },
        );
        // Newly pooled outputs may un-orphan parked children — Core's
        // ProcessOrphanTx recursion. Repeat until no orphan resolves:
        // each accepted orphan can itself be a parent.
        loop {
            let ready: Vec<Transaction> = self
                .orphans
                .values()
                .filter(|e| {
                    e.tx.inputs
                        .iter()
                        .all(|i| self.resolve(cs, &i.previous_output).is_some())
                })
                .map(|e| e.tx.clone())
                .collect();
            if ready.is_empty() {
                break;
            }
            for orphan in ready {
                let oid = orphan.txid();
                self.orphans.remove(&oid);
                // Re-admit through the full path; failures just stay out
                // (they may fail policy even once resolvable).
                let _ = self.accept_tx(orphan, cs, now);
            }
        }
        Ok(txid)
    }

    /// Parks a tx whose inputs don't resolve, bounded and expiring —
    /// Core's `AddToOrphanage`. Evicts a random orphan at capacity
    /// (deterministic here: the oldest).
    fn park_orphan(&mut self, tx: Transaction, now: u32) {
        self.expire_orphans(now);
        let txid = tx.txid();
        if self.orphans.contains_key(&txid) {
            return;
        }
        if self.orphans.len() >= MAX_ORPHANS
            && let Some((&oldest, _)) = self.orphans.iter().min_by_key(|(_, e)| e.time)
        {
            self.orphans.remove(&oldest);
        }
        self.orphans.insert(txid, OrphanEntry { tx, time: now });
    }

    /// Drops orphans older than [`ORPHAN_EXPIRE_SECS`].
    fn expire_orphans(&mut self, now: u32) {
        self.orphans
            .retain(|_, e| now.saturating_sub(e.time) < ORPHAN_EXPIRE_SECS);
    }

    /// Orphan-pool size — observability for the sync layer.
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    /// Drops `txid` and unindexes its input spends.
    pub fn remove(&mut self, txid: &Txid) -> Option<MempoolEntry> {
        let entry = self.map.remove(txid)?;
        for input in &entry.tx.inputs {
            self.spends.remove(&input.previous_output);
        }
        Some(entry)
    }

    /// Drops `txid` and every pooled descendant (depth-first).
    pub fn remove_recursive(&mut self, txid: &Txid) {
        // Children spend this tx's outputs — find them via the spends
        // index before removing.
        if let Some(entry) = self.map.get(txid) {
            let children: Vec<Txid> = (0..entry.tx.outputs.len())
                .filter_map(|vout| {
                    self.spends
                        .get(&OutPoint {
                            txid: *txid,
                            vout: vout as u32,
                        })
                        .copied()
                })
                .collect();
            for child in children {
                self.remove_recursive(&child);
            }
        }
        self.remove(txid);
    }

    /// Drops every tx that spends a block's *newly spent* outpoints or
    /// whose txid the block now confirms — Core's
    /// `removeForBlock`-lite: confirmed txs leave the pool, and so do
    /// conflicts that can no longer confirm.
    pub fn on_block_connected(&mut self, block: &avila_consensus::block::Block) {
        let mut dead: Vec<Txid> = Vec::new();
        for tx in &block.transactions {
            let txid = tx.txid();
            if self.map.contains_key(&txid) {
                dead.push(txid);
            }
            if tx.is_coinbase() {
                continue;
            }
            // Anything spending the same outpoint is now a double-spend.
            for input in &tx.inputs {
                if let Some(&conflict) = self.spends.get(&input.previous_output) {
                    dead.push(conflict);
                }
            }
        }
        for id in dead {
            self.remove_recursive(&id);
        }
    }

    /// Re-admits the non-coinbase transactions of a *disconnected* block
    /// — Core's `DisconnectedBlockTransactions` queue: after a reorg the
    /// old branch's txs are valid unconfirmed again. Each goes through
    /// full admission (a tx may now conflict with the new chain).
    pub fn reinsert_disconnected(
        &mut self,
        block: &avila_consensus::block::Block,
        cs: &avila_consensus::chainstate::Chainstate,
        now: u32,
    ) -> usize {
        let mut readmitted = 0usize;
        for tx in &block.transactions {
            if tx.is_coinbase() {
                continue;
            }
            if self.accept_tx(tx.clone(), cs, now).is_ok() {
                readmitted += 1;
            }
        }
        readmitted
    }

    /// Every pooled txid — relay bookkeeping.
    #[must_use]
    pub fn txids(&self) -> Vec<Txid> {
        self.map.keys().copied().collect()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

/// Core's `STANDARD_SCRIPT_VERIFY_FLAGS`: the mandatory consensus set at
/// `next_height` plus the standardness flags — policy-only tightenings a
/// block may still violate without being invalid.
fn standard_script_flags(
    cs: &avila_consensus::chainstate::Chainstate,
    next_height: u32,
    tip: &avila_consensus::hash::BlockHash,
) -> ScriptFlags {
    // MANDATORY half: the flags the next block will enforce.
    let consensus = block_script_flags(cs.tree().params(), next_height, tip);
    // STANDARD extras (policy): strict encoding, low-S, clean stack,
    // minimal encodings, and the discourage-upgradable family.
    consensus
        .union(ScriptFlags::STRICTENC)
        .union(ScriptFlags::LOW_S)
        .union(ScriptFlags::MINIMALDATA)
        .union(ScriptFlags::NULLDUMMY)
        .union(ScriptFlags::CLEANSTACK)
        .union(ScriptFlags::MINIMALIF)
        .union(ScriptFlags::NULLFAIL)
        .union(ScriptFlags::CONST_SCRIPTCODE)
        .union(ScriptFlags::WITNESS_PUBKEYTYPE)
        .union(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS)
        .union(ScriptFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
        .union(ScriptFlags::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]
mod tests {
    use super::*;
    use avila_consensus::arith::CompactTarget;
    use avila_consensus::block::Block;
    use avila_consensus::chainstate::Chainstate;
    use avila_consensus::header::BlockHeader;
    use avila_consensus::params::{Network, Params};
    use avila_consensus::pow;
    use avila_consensus::script;
    use avila_consensus::transaction::{Script, TxIn, TxOut, Witness};

    const REGTEST_BITS: u32 = 0x207f_ffff;
    const SEQ_FINAL: u32 = 0xffff_ffff;
    const SEQ_RBF: u32 = 0xffff_fffd;
    const NOW: u32 = 1_700_000_000;

    fn coinbase_tx(height: u32) -> Transaction {
        let mut script_sig = script::push_int(i64::from(height));
        script_sig.push(script::OP_1);
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(script_sig),
                sequence: SEQ_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 5_000_000_000,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        }
    }

    fn block_on(prev: &BlockHeader, height: u32, params: &Params) -> Block {
        let mut block = Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: prev.hash(),
                merkle_root: prev.merkle_root,
                time: prev.time + 1,
                bits: CompactTarget(REGTEST_BITS),
                nonce: 0,
            },
            transactions: vec![coinbase_tx(height)],
        };
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
            block.header.nonce += 1;
        }
        block
    }

    /// A regtest chainstate at height `n` — mature coinbases from
    /// h1..=n-100 are spendable.
    fn chainstate_at(n: u32) -> (Chainstate, Vec<Block>) {
        let mut cs = Chainstate::new(&Network::Regtest.params());
        let params = Network::Regtest.params();
        let mut blocks = Vec::new();
        let mut prev = params.genesis_header;
        for h in 1..=n {
            let b = block_on(&prev, h, &params);
            cs.accept_block(&b, NOW + h).unwrap();
            prev = b.header;
            blocks.push(b);
        }
        (cs, blocks)
    }

    /// A tx spending `op` (must be an OP_1 anyone-can-spend output) with
    /// `value` out and `sequence`.
    fn spend_tx(op: OutPoint, value: i64, sequence: u32) -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: op,
                script_sig: Script::new(vec![]),
                sequence,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        }
    }

    fn mature_outpoint(blocks: &[Block], h: usize) -> OutPoint {
        OutPoint {
            txid: blocks[h - 1].transactions[0].txid(),
            vout: 0,
        }
    }

    #[test]
    fn valid_spend_is_accepted() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let txid = tx.txid();
        assert_eq!(pool.accept_tx(tx, &cs, NOW).unwrap(), txid);
        assert!(pool.get(&txid).is_some());
    }

    #[test]
    fn missing_input_is_rejected() {
        let (cs, _b) = chainstate_at(5);
        let mut pool = Mempool::new();
        let fake = OutPoint {
            txid: Txid::ZERO,
            vout: 0,
        };
        let tx = spend_tx(fake, 1_000, SEQ_FINAL);
        assert_eq!(
            pool.accept_tx(tx, &cs, NOW),
            Err(MempoolReject::InputsMissingOrSpent)
        );
    }

    #[test]
    fn immature_coinbase_is_rejected() {
        let (cs, blocks) = chainstate_at(50);
        let mut pool = Mempool::new();
        // h1 coinbase at tip h50 → depth 49 < 100.
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        assert!(matches!(
            pool.accept_tx(tx, &cs, NOW),
            Err(MempoolReject::Inputs(
                ConnectError::PrematureCoinbaseSpend { .. }
            ))
        ));
    }

    #[test]
    fn dust_fee_fails_min_relay() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        // fee = 1 sat over ~250 vB → below 1 sat/vB.
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_999_999, SEQ_FINAL);
        assert_eq!(
            pool.accept_tx(tx, &cs, NOW),
            Err(MempoolReject::MinRelayFee)
        );
    }

    #[test]
    fn double_spend_without_rbf_is_rejected() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let op = mature_outpoint(&blocks, 1);
        let tx1 = spend_tx(op, 4_999_000_000, SEQ_FINAL);
        let tx2 = spend_tx(op, 4_998_000_000, SEQ_FINAL);
        pool.accept_tx(tx1, &cs, NOW).unwrap();
        assert_eq!(pool.accept_tx(tx2, &cs, NOW), Err(MempoolReject::Conflict));
    }

    #[test]
    fn rbf_replacement_with_adequate_bump() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let op = mature_outpoint(&blocks, 1);
        let tx1 = spend_tx(op, 4_999_000_000, SEQ_RBF); // 1M sat fee
        let tx2 = spend_tx(op, 4_998_000_000, SEQ_RBF); // 2M sat fee — covers bump
        let id1 = tx1.txid();
        let id2 = tx2.txid();
        pool.accept_tx(tx1, &cs, NOW).unwrap();
        assert_eq!(pool.accept_tx(tx2, &cs, NOW), Ok(id2));
        assert!(pool.get(&id1).is_none(), "conflict evicted");
        assert!(pool.get(&id2).is_some());
    }

    #[test]
    fn unconfirmed_parent_chain_is_accepted() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let parent_id = parent.txid();
        pool.accept_tx(parent, &cs, NOW).unwrap();
        let child = spend_tx(
            OutPoint {
                txid: parent_id,
                vout: 0,
            },
            4_998_000_000,
            SEQ_FINAL,
        );
        assert!(pool.accept_tx(child, &cs, NOW).is_ok());
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn orphan_parks_then_joins_when_parent_arrives() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        // Child arrives before its parent → parks as orphan.
        let parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let parent_id = parent.txid();
        let child = spend_tx(
            OutPoint {
                txid: parent_id,
                vout: 0,
            },
            4_998_000_000,
            SEQ_FINAL,
        );
        assert_eq!(
            pool.accept_tx(child, &cs, NOW),
            Err(MempoolReject::InputsMissingOrSpent)
        );
        assert_eq!(pool.orphan_count(), 1);
        assert_eq!(pool.len(), 0);
        // Parent's arrival un-orphans the child automatically.
        pool.accept_tx(parent, &cs, NOW).unwrap();
        assert_eq!(pool.len(), 2, "parent + adopted orphan");
        assert_eq!(pool.orphan_count(), 0);
    }

    #[test]
    fn orphan_pool_is_bounded() {
        let (cs, _b) = chainstate_at(5);
        let mut pool = Mempool::new();
        // MAX_ORPHANS + 5 distinct missing-input txs — the cap binds.
        for i in 0..(MAX_ORPHANS + 5) {
            let tx = spend_tx(
                OutPoint {
                    txid: Txid::from_bytes([i as u8; 32].map(|b| b.wrapping_add(1))),
                    vout: i as u32,
                },
                1_000,
                SEQ_FINAL,
            );
            let _ = pool.accept_tx(tx, &cs, NOW);
        }
        assert_eq!(pool.orphan_count(), MAX_ORPHANS);
    }

    #[test]
    fn block_connected_purges_confirmed_and_conflicts() {
        let (mut cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let params = Network::Regtest.params();
        let confirmed = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        pool.accept_tx(confirmed.clone(), &cs, NOW).unwrap();
        // A conflicting (unconfirmed) tx on the same outpoint.
        let conflict_op = mature_outpoint(&blocks, 2);
        let conflict = spend_tx(conflict_op, 4_999_000_000, SEQ_FINAL);
        pool.accept_tx(conflict, &cs, NOW).unwrap();

        // A block containing `confirmed` and spending `conflict_op`
        // differently → conflict must leave too.
        let mut block = block_on(&cs.tree().tip().header, 102, &params);
        block.transactions = vec![
            coinbase_tx(102),
            confirmed,
            spend_tx(conflict_op, 4_999_500_000, SEQ_FINAL),
        ];
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, &params).is_err() {
            block.header.nonce += 1;
        }
        cs.accept_block(&block, NOW + 200).unwrap();
        pool.on_block_connected(&block);
        assert!(pool.is_empty());
    }
}

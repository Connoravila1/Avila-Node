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

use std::collections::{HashMap, HashSet};

use avila_consensus::check::{TxRuleError, check_transaction};
use avila_consensus::connect::{
    Coin, ConnectError, UtxoSet, bip68_locks_satisfied, check_tx_inputs,
};
use avila_consensus::hash::{Txid, Wtxid};
use avila_consensus::interpreter::ScriptError;
use avila_consensus::script::{ScriptFlags, block_script_flags};
use avila_consensus::sigchecker::check_input_scripts;
use avila_consensus::transaction::{OutPoint, Transaction};

/// Deployed Core's `DEFAULT_MIN_RELAY_TX_FEE`: 100 sat/kvB
/// (0.1 sat/vB — lowered in the 29.x policy relaxation).
pub const DEFAULT_MIN_RELAY_FEE: i64 = 100;

/// Core's `MAX_STANDARD_TX_WEIGHT` — 400,000 weight units (~100 kvB).
/// Policy only; consensus has no per-tx weight cap beyond the block's.
pub const MAX_STANDARD_TX_WEIGHT: usize = 400_000;

/// Deployed Core's `DEFAULT_INCREMENTAL_RELAY_FEE` — a replacement must
/// cover its own relay at this rate on top of the conflicting tx's fee.
pub const INCREMENTAL_RELAY_FEE: i64 = 100; // sat/kvB

/// Bound on pool entries — a belt alongside the `DEFAULT_MAX_BYTES`
/// suspenders; either cap trips the evict-lowest-feerate path.
pub const DEFAULT_MAX_ENTRIES: usize = 25_000;

/// Core's `DEFAULT_MAX_MEMPOOL_SIZE` — 300 MB in bytes.
pub const DEFAULT_MAX_BYTES: usize = 300_000_000;

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
    /// The chain height when first pooled — the estimator's clock for
    /// "blocks to confirm" (Core's `nHeight` at acceptance).
    pub first_seen_height: u32,
    /// `prioritisetransaction`'s accumulated adjustment (Core's
    /// `nFeeDelta`) — `fee + fee_delta` is the modified fee template
    /// ordering and `fees.modified` report.
    pub fee_delta: i64,
}

impl MempoolEntry {
    /// `fee + fee_delta` — Core's `GetModifiedFee`.
    #[must_use]
    pub fn modified_fee(&self) -> i64 {
        self.fee.saturating_add(self.fee_delta)
    }
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
    /// Ancestor or descendant package limits exceeded — Core reports
    /// both as `too-long-mempool-chain`.
    #[error("too-long-mempool-chain")]
    PackageLimits,
}

/// Core's `DEFAULT_ANCESTOR_LIMIT` — a candidate may not bring its
/// in-pool ancestor set (parents, grandparents, …) past 25 entries.
pub const ANCESTOR_LIMIT: usize = 25;
/// Core's `DEFAULT_ANCESTOR_SIZE_LIMIT_KVB` — candidate + ancestors.
pub const ANCESTOR_SIZE_LIMIT_KVB: usize = 101;
/// Core's `DEFAULT_DESCENDANT_LIMIT` — adding the candidate must not
/// push any in-pool ancestor's descendant set past 25.
pub const DESCENDANT_LIMIT: usize = 25;
/// Core's `DEFAULT_DESCENDANT_SIZE_LIMIT_KVB`.
pub const DESCENDANT_SIZE_LIMIT_KVB: usize = 101;

/// Core's `MAX_ORPHAN_TRANSACTIONS` — orphan entries bound separately
/// from the pool so orphan flooding can't crowd out confirmed-parent
/// txs or blow memory.
pub const MAX_ORPHANS: usize = 100;

/// Core's `ORPHAN_TX_EXPIRE_TIME` — orphans live at most 20 minutes.
pub const ORPHAN_EXPIRE_SECS: u32 = 20 * 60;

/// One admission gate's outcome in a policy explanation.
#[derive(Clone, Debug)]
pub struct PolicyStep {
    /// Which gate (`"input-resolution"`, `"bip125-fee"`, …).
    pub gate: &'static str,
    /// Whether the tx passed this gate.
    pub passed: bool,
    /// What the gate observed — source of each input, fee computed,
    /// or the reject reason.
    pub detail: String,
}

/// A parked orphan — a tx with unresolved inputs, kept for when its
/// parents arrive.
#[derive(Clone, Debug)]
struct OrphanEntry {
    tx: Transaction,
    time: u32,
}

/// Recent confirmation observations for fee estimation — Core's
/// `CBlockPolicyEstimator` reduced to a bounded sample ring: each
/// confirmed tx contributes `(fee rate in sat/kvB, blocks waited)`.
/// `estimate` returns the median rate among samples that confirmed
/// within the target — honest "recent blocks at this rate confirmed
/// that fast" rather than a model.
pub struct FeeEstimator {
    /// `(rate sat/kvB, blocks from pool-entry to confirm)`.
    samples: std::collections::VecDeque<(i64, u32)>,
    /// Ring capacity — Core's `MAX_BLOCK_HISTORY` analog.
    capacity: usize,
}

impl FeeEstimator {
    /// An empty estimator with a 4096-sample ring.
    #[must_use]
    pub fn new() -> Self {
        Self {
            samples: std::collections::VecDeque::new(),
            capacity: 4096,
        }
    }

    /// Records one confirmation observation.
    pub fn observe(&mut self, rate_sat_per_kvb: i64, blocks_to_confirm: u32) {
        if self.samples.len() >= self.capacity {
            self.samples.pop_front();
        }
        self.samples
            .push_back((rate_sat_per_kvb, blocks_to_confirm));
    }

    /// The median fee rate of samples confirmed within `target` blocks,
    /// or `None` with fewer than 5 qualifying samples — an honest
    /// "insufficient data" rather than a fabricated rate.
    #[must_use]
    pub fn estimate(&self, target_blocks: u32) -> Option<i64> {
        let mut rates: Vec<i64> = self
            .samples
            .iter()
            .filter(|(_, waited)| *waited <= target_blocks)
            .map(|(rate, _)| *rate)
            .collect();
        if rates.len() < 5 {
            return None;
        }
        rates.sort_unstable();
        Some(rates[rates.len() / 2])
    }

    /// Samples held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// No observations yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// A bounded policy pool over the live UTXO set.
pub struct Mempool {
    /// txid → entry.
    map: HashMap<Txid, MempoolEntry>,
    /// outpoint → txid of the pooled tx spending it (conflict index).
    spends: HashMap<OutPoint, Txid>,
    /// wtxid → txid — BIP339 announcements arrive by wtxid; dedup must
    /// answer "do we have this" for either hash without a full scan.
    wtxids: HashMap<Wtxid, Txid>,
    /// txid → parked tx with missing parents (Core's orphan pool).
    orphans: HashMap<Txid, OrphanEntry>,
    /// Entry cap.
    max_entries: usize,
    /// Serialized-bytes cap — Core's `-maxmempool` (300 MB default).
    /// Enforced alongside the entry cap: either limit trips the
    /// evict-lowest-feerate path.
    max_bytes: usize,
    /// Live serialized bytes in the pool — the `max_bytes` accounting.
    pool_bytes: usize,
    /// Min relay fee rate in sat/kvB.
    min_relay_fee: i64,
    /// Full-RBF: deployed Core accepts replacements regardless of
    /// BIP125 signaling (`-mempoolfullrbf` default-on). When false,
    /// the signaling requirement is enforced.
    full_rbf: bool,
    /// Confirmation observations from connected blocks.
    estimator: FeeEstimator,
    /// `prioritisetransaction` accumulations by txid — Core's
    /// `mapDeltas`. Entries for not-yet-pooled txids apply at
    /// admission; mined txids are cleared at block connect.
    deltas: HashMap<Txid, i64>,
    /// Locally submitted txids no peer has requested yet — Core's
    /// `m_unbroadcast_txids`, cleared when a peer's getdata asks for
    /// the tx or the entry leaves the pool.
    unbroadcast: HashSet<Txid>,
}

impl Mempool {
    /// An empty pool with Core's default relay fee and the entry cap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            spends: HashMap::new(),
            wtxids: HashMap::new(),
            orphans: HashMap::new(),
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
            pool_bytes: 0,
            min_relay_fee: DEFAULT_MIN_RELAY_FEE,
            full_rbf: true,
            estimator: FeeEstimator::new(),
            deltas: HashMap::new(),
            unbroadcast: HashSet::new(),
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

    /// Lookup by wtxid (BIP339 announcements and `MSG_WTX` requests).
    #[must_use]
    pub fn get_wtxid(&self, wtxid: &Wtxid) -> Option<&Transaction> {
        self.wtxids.get(wtxid).and_then(|id| self.get(id))
    }

    /// The pooled tx spending `outpoint`, if any — Core's
    /// `gettxspendingprevout` lookup (`mempool.NextTransactionsIter`).
    #[must_use]
    pub fn spent_by(&self, outpoint: &OutPoint) -> Option<&Transaction> {
        self.spends.get(outpoint).and_then(|id| self.get(id))
    }

    /// Does the pool hold a tx under either hash form? Used to dedup
    /// `inv` announcements before issuing `getdata`.
    #[must_use]
    pub fn contains_hash(&self, hash: &avila_consensus::hash::BlockHash) -> bool {
        let txid = Txid::from_bytes(*hash.as_bytes());
        if self.map.contains_key(&txid) {
            return true;
        }
        self.wtxids
            .contains_key(&Wtxid::from_bytes(*hash.as_bytes()))
    }

    /// Total serialized size of pooled transactions in bytes —
    /// getmempoolinfo's `bytes`/`usage` basis (Core's `DynamicUsage`
    /// is allocator-dependent; encoded size is the honest floor).
    #[must_use]
    pub fn total_tx_bytes(&self) -> usize {
        self.pool_bytes
    }

    /// Sum of pooled entry fees in satoshis — getmempoolinfo's
    /// `total_fee` (Core reports BTC; callers convert).
    #[must_use]
    pub fn total_fees(&self) -> i64 {
        self.map.values().map(|e| e.fee).sum()
    }

    /// The pool's current minimum relay fee rate in sat/kvB.
    #[must_use]
    pub fn min_relay_fee(&self) -> i64 {
        self.min_relay_fee
    }

    /// Overrides the min-relay fee rate (sat/kvB) — an operator knob.
    pub fn set_min_relay_fee(&mut self, sat_per_kvb: i64) {
        self.min_relay_fee = sat_per_kvb;
    }

    /// Overrides the entry cap — an operator knob.
    pub fn set_max_entries(&mut self, n: usize) {
        self.max_entries = n;
    }

    /// The serialized-bytes cap — `getmempoolinfo`'s `maxmempool`.
    #[must_use]
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Overrides the serialized-bytes cap — `-maxmempool`'s analog.
    pub fn set_max_bytes(&mut self, n: usize) {
        self.max_bytes = n;
    }

    /// Whether full-RBF is on (deployed Core's `-mempoolfullrbf`
    /// default). With it on, replacements skip the BIP125 signaling
    /// requirement; the fee-bump rules always apply.
    #[must_use]
    pub fn full_rbf(&self) -> bool {
        self.full_rbf
    }

    /// Overrides the full-RBF policy — `-mempoolfullrbf`'s analog.
    pub fn set_full_rbf(&mut self, on: bool) {
        self.full_rbf = on;
    }

    /// Does `tx` signal BIP125 replaceability (any input sequence below
    /// `0xfffffffe`)?
    fn signals_rbf(tx: &Transaction) -> bool {
        tx.inputs
            .iter()
            .any(|i| i.sequence < RBF_SEQUENCE_THRESHOLD)
    }

    /// Core's `IsRBFOptIn` for `getmempoolentry`'s `bip125-replaceable`:
    /// the tx's own signal, or — with no signal of its own — every
    /// direct in-pool parent signaling. A non-signaling tx with no
    /// pooled parents is `FINAL` → false.
    #[must_use]
    pub fn bip125_replaceable(&self, txid: &Txid) -> bool {
        let Some(e) = self.map.get(txid) else {
            return false;
        };
        if Self::signals_rbf(&e.tx) {
            return true;
        }
        let mut has_parent = false;
        for input in &e.tx.inputs {
            if let Some(parent) = self.map.get(&input.previous_output.txid) {
                has_parent = true;
                if !Self::signals_rbf(&parent.tx) {
                    return false;
                }
            }
        }
        has_parent
    }

    /// Resolves an input's coin: the confirmed UTXO first, else a pooled
    /// parent's output — Core's `view` layered over `pool.cs`/`mapTx`.
    /// Public so query surfaces (`gettxout`, `testmempoolaccept`) can
    /// answer "what would admission see" without duplicating the rules.
    #[must_use]
    pub fn resolve(
        &self,
        cs: &avila_consensus::chainstate::Chainstate,
        op: &OutPoint,
    ) -> Option<Coin> {
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

    /// Dry-runs every admission gate and reports each outcome — the
    /// replayable policy explanation. Never mutates the pool: a
    /// missing-input tx is *reported* as unresolvable, not parked.
    pub fn explain_tx(
        &self,
        tx: &Transaction,
        cs: &avila_consensus::chainstate::Chainstate,
        _now: u32,
    ) -> Vec<PolicyStep> {
        fn push(
            steps: &mut Vec<PolicyStep>,
            gate: &'static str,
            r: Result<String, String>,
        ) -> bool {
            let (passed, detail) = match r {
                Ok(d) => (true, d),
                Err(d) => (false, d),
            };
            steps.push(PolicyStep {
                gate,
                passed,
                detail,
            });
            passed
        }
        let mut steps = Vec::new();

        if !push(
            &mut steps,
            "context-free",
            check_transaction(tx)
                .map(|()| format!("{} in, {} out", tx.inputs.len(), tx.outputs.len()))
                .map_err(|e: TxRuleError| e.to_string()),
        ) {
            return steps;
        }
        if tx.is_coinbase() {
            push(&mut steps, "coinbase", Err("coinbase".into()));
            return steps;
        }
        if !push(
            &mut steps,
            "already-known",
            if self.map.contains_key(&tx.txid()) {
                Err("txn-already-in-mempool".into())
            } else {
                Ok("new".into())
            },
        ) {
            return steps;
        }
        if !push(
            &mut steps,
            "weight-cap",
            if tx.weight() > MAX_STANDARD_TX_WEIGHT {
                Err(format!(
                    "tx-size: {} > {MAX_STANDARD_TX_WEIGHT}",
                    tx.weight()
                ))
            } else {
                Ok(format!("weight {}", tx.weight()))
            },
        ) {
            return steps;
        }

        let mut spent = Vec::with_capacity(tx.inputs.len());
        let mut missing = 0usize;
        let mut from_pool = 0usize;
        let mut conflicts: Vec<Txid> = Vec::new();
        for input in &tx.inputs {
            if let Some(coin) = cs.utxo().get(&input.previous_output) {
                spent.push(coin.clone());
            } else if self
                .map
                .get(&input.previous_output.txid)
                .and_then(|parent| parent.tx.outputs.get(input.previous_output.vout as usize))
                .is_some_and(|out| {
                    spent.push(Coin {
                        out: out.clone(),
                        height: cs.tree().tip().height,
                        coinbase: false,
                    });
                    true
                })
            {
                from_pool += 1;
            } else {
                missing += 1;
            }
            if let Some(&conflict) = self.spends.get(&input.previous_output)
                && !conflicts.contains(&conflict)
            {
                conflicts.push(conflict);
            }
        }
        if !push(
            &mut steps,
            "input-resolution",
            if missing > 0 {
                Err(format!(
                    "bad-txns-inputs-missingorspent: {missing} of {} unresolved",
                    tx.inputs.len()
                ))
            } else {
                Ok(format!(
                    "{} resolved ({} via pool parents)",
                    spent.len(),
                    from_pool
                ))
            },
        ) {
            return steps;
        }

        if !push(
            &mut steps,
            "bip125-signal",
            if conflicts.is_empty() {
                Ok("no conflicts".into())
            } else if self.full_rbf
                || (conflicts
                    .iter()
                    .all(|id| self.map.get(id).is_some_and(|e| Self::signals_rbf(&e.tx)))
                    && Self::signals_rbf(tx))
            {
                Ok(format!("replaces {} conflict(s)", conflicts.len()))
            } else {
                Err("txn-mempool-conflict: insufficient RBF signaling".into())
            },
        ) {
            return steps;
        }

        let vsize = tx.weight().div_ceil(4);
        let ancestors = self.ancestors_of(tx);
        let ancestor_vsize: usize = ancestors
            .iter()
            .filter_map(|id| self.map.get(id))
            .map(|e| e.vsize)
            .sum();
        let mut limit_violation = if ancestors.len() + 1 > ANCESTOR_LIMIT {
            Some(format!(
                "{} ancestors > {ANCESTOR_LIMIT}",
                ancestors.len() + 1
            ))
        } else if ancestor_vsize + vsize > ANCESTOR_SIZE_LIMIT_KVB * 1000 {
            Some(format!(
                "ancestor size {} > {} vB",
                ancestor_vsize + vsize,
                ANCESTOR_SIZE_LIMIT_KVB * 1000
            ))
        } else {
            None
        };
        if limit_violation.is_none() {
            for ancestor in &ancestors {
                let (count, size) = self.descendants_of(ancestor);
                if count + 1 > DESCENDANT_LIMIT {
                    limit_violation =
                        Some(format!("descendants {} > {DESCENDANT_LIMIT}", count + 1));
                    break;
                }
                if size + vsize > DESCENDANT_SIZE_LIMIT_KVB * 1000 {
                    limit_violation = Some(format!(
                        "descendant size {} > {} vB",
                        size + vsize,
                        DESCENDANT_SIZE_LIMIT_KVB * 1000
                    ));
                    break;
                }
            }
        }
        if !push(
            &mut steps,
            "package-limits",
            match limit_violation {
                None => Ok(format!(
                    "{} ancestors, {} vB package",
                    ancestors.len(),
                    ancestor_vsize + vsize
                )),
                Some(w) => Err(format!("too-long-mempool-chain: {w}")),
            },
        ) {
            return steps;
        }

        let tip = cs.tip_hash();
        let next_height = cs.tree().tip().height + 1;
        let mut overlay = UtxoSet::new();
        for (input, coin) in tx.inputs.iter().zip(spent.iter()) {
            overlay.insert_synthetic(input.previous_output, coin.clone());
        }
        let fee = match check_tx_inputs(tx, &overlay, next_height) {
            Ok((_, fee)) => {
                push(&mut steps, "consensus-inputs", Ok(format!("fee {fee} sat")));
                fee
            }
            Err(e) => {
                push(&mut steps, "consensus-inputs", Err(e.to_string()));
                return steps;
            }
        };

        if !conflicts.is_empty() {
            let conflict_fees: i64 = conflicts
                .iter()
                .filter_map(|id| self.map.get(id))
                .map(|e| e.fee)
                .sum();
            let required = conflict_fees + INCREMENTAL_RELAY_FEE * vsize as i64 / 1000;
            if !push(
                &mut steps,
                "bip125-fee",
                if fee < required {
                    Err(format!("txn-mempool-conflict: {fee} < required {required}"))
                } else {
                    Ok(format!("{fee} >= required {required}"))
                },
            ) {
                return steps;
            }
        }

        if cs.tree().params().csv_height <= next_height {
            let mtp = cs.tree().median_time_past(&tip);
            let ok = mtp.is_some_and(|m| {
                bip68_locks_satisfied(tx, &spent, next_height, m, cs.tree(), &tip)
            });
            if !push(
                &mut steps,
                "bip68",
                if ok {
                    Ok(format!("locks satisfied (mtp {})", mtp.unwrap_or(0)))
                } else {
                    Err("non-BIP68-final".into())
                },
            ) {
                return steps;
            }
        }

        let flags = standard_script_flags(cs, next_height, &tip);
        let spent_outs: Vec<_> = spent.iter().map(|c| c.out.clone()).collect();
        if !push(
            &mut steps,
            "scripts",
            check_input_scripts(tx, &spent_outs, flags)
                .map(|()| "all inputs verified".to_string())
                .map_err(|e| format!("mandatory-script-verify-flag-failed ({e})")),
        ) {
            return steps;
        }

        if !push(
            &mut steps,
            "min-relay-fee",
            if fee * 1000 < self.min_relay_fee * vsize as i64 {
                Err(format!("min relay fee not met: {fee} sat for {vsize} vB"))
            } else {
                Ok(format!("{fee} sat for {vsize} vB"))
            },
        ) {
            return steps;
        }

        push(
            &mut steps,
            "capacity",
            if self.map.len() < self.max_entries
                && self.pool_bytes + tx.encode().len() <= self.max_bytes
            {
                Ok(format!(
                    "{}/{} entries, {}/{} bytes",
                    self.map.len(),
                    self.max_entries,
                    self.pool_bytes,
                    self.max_bytes
                ))
            } else {
                let my_rate = fee * 1000 / vsize as i64;
                match self
                    .map
                    .iter()
                    .min_by_key(|(_, e)| e.fee * 1000 / e.vsize.max(1) as i64)
                {
                    Some((_, worst)) if my_rate > worst.fee * 1000 / worst.vsize.max(1) as i64 => {
                        Ok(format!(
                            "full; would evict rate {}",
                            worst.fee * 1000 / worst.vsize.max(1) as i64
                        ))
                    }
                    _ => Err("mempool full".into()),
                }
            },
        );
        steps
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

        // 3. BIP125: with full-RBF off, a conflicted spend may only
        //    proceed if every conflict signals replaceability and the
        //    bump is large enough — checked after the fee is known
        //    (step 5).
        if !conflicts.is_empty() && !self.full_rbf {
            let all_signal = conflicts
                .iter()
                .all(|id| self.map.get(id).is_some_and(|e| Self::signals_rbf(&e.tx)));
            if !all_signal || !Self::signals_rbf(&tx) {
                return Err(MempoolReject::Conflict);
            }
        }

        // 3.5 Package limits — Core's CalculateMemPoolAncestors. The
        //    candidate's in-pool ancestor set (count and total vsize)
        //    is bounded, and no ancestor's descendant set may overflow
        //    by accepting it.
        let vsize = tx.weight().div_ceil(4);
        let ancestors = self.ancestors_of(&tx);
        if ancestors.len() + 1 > ANCESTOR_LIMIT {
            return Err(MempoolReject::PackageLimits);
        }
        let ancestor_vsize: usize = ancestors
            .iter()
            .filter_map(|id| self.map.get(id))
            .map(|e| e.vsize)
            .sum();
        if ancestor_vsize + vsize > ANCESTOR_SIZE_LIMIT_KVB * 1000 {
            return Err(MempoolReject::PackageLimits);
        }
        for ancestor in &ancestors {
            let (count, size) = self.descendants_of(ancestor);
            if count + 1 > DESCENDANT_LIMIT || size + vsize > DESCENDANT_SIZE_LIMIT_KVB * 1000 {
                return Err(MempoolReject::PackageLimits);
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

        // 9. Capacity: either cap (entries or serialized bytes — Core's
        //    `-maxmempool` analog) trips the evict-the-worst path; the
        //    candidate must outbid the victim to displace it.
        let tx_size = tx.encode().len();
        if self.map.len() >= self.max_entries || self.pool_bytes + tx_size > self.max_bytes {
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
        self.wtxids.insert(tx.wtxid(), txid);
        self.pool_bytes += tx.encode().len();
        self.map.insert(
            txid,
            MempoolEntry {
                tx,
                fee,
                vsize,
                time: now,
                first_seen_height: cs.tree().tip().height,
                // A prioritisetransaction delta recorded before the tx
                // arrived applies now (Core reads mapDeltas at
                // admission into the entry's nFeeDelta).
                fee_delta: self.deltas.get(&txid).copied().unwrap_or(0),
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

    /// All in-pool ancestors of a candidate — the transitive closure of
    /// its pooled parents (parents of parents of …).
    fn ancestors_of(&self, tx: &Transaction) -> HashSet<Txid> {
        let mut ancestors = HashSet::new();
        let mut stack: Vec<Txid> = tx
            .inputs
            .iter()
            .map(|i| i.previous_output.txid)
            .filter(|id| self.map.contains_key(id))
            .collect();
        while let Some(id) = stack.pop() {
            if !ancestors.insert(id) {
                continue;
            }
            if let Some(parent) = self.map.get(&id) {
                stack.extend(
                    parent
                        .tx
                        .inputs
                        .iter()
                        .map(|i| i.previous_output.txid)
                        .filter(|pid| self.map.contains_key(pid)),
                );
            }
        }
        ancestors
    }

    /// All in-pool ancestors of a candidate tx — Core's
    /// `CalculateMemPoolAncestors` set, exposed for query surfaces.
    #[must_use]
    pub fn ancestor_txids(&self, tx: &Transaction) -> HashSet<Txid> {
        self.ancestors_of(tx)
    }

    /// All in-pool descendants of a pooled txid — the set behind
    /// `getmempooldescendants`.
    #[must_use]
    pub fn descendant_txids(&self, txid: &Txid) -> HashSet<Txid> {
        let mut descendants = HashSet::new();
        let mut stack = vec![*txid];
        while let Some(id) = stack.pop() {
            let Some(entry) = self.map.get(&id) else {
                continue;
            };
            for vout in 0..entry.tx.outputs.len() as u32 {
                if let Some(child) = self.spends.get(&OutPoint { txid: id, vout })
                    && descendants.insert(*child)
                {
                    stack.push(*child);
                }
            }
        }
        descendants
    }

    /// The pooled entry for `txid`, with its admission-computed fee,
    /// vsize, and arrival facts (Core's `mapTx` lookup behind
    /// `getmempoolentry`).
    #[must_use]
    pub fn entry(&self, txid: &Txid) -> Option<&MempoolEntry> {
        self.map.get(txid)
    }

    /// The parked orphans' txids — Core's orphan pool contents behind
    /// `getorphantxs`-style queries.
    #[must_use]
    pub fn orphan_txids(&self) -> Vec<Txid> {
        self.orphans.keys().copied().collect()
    }

    /// All in-pool descendants of a pooled tx, as `(count, total vsize)`.
    fn descendants_of(&self, txid: &Txid) -> (usize, usize) {
        let mut descendants = HashSet::new();
        let mut stack = vec![*txid];
        while let Some(id) = stack.pop() {
            let Some(entry) = self.map.get(&id) else {
                continue;
            };
            for vout in 0..entry.tx.outputs.len() as u32 {
                if let Some(child) = self.spends.get(&OutPoint { txid: id, vout })
                    && descendants.insert(*child)
                {
                    stack.push(*child);
                }
            }
        }
        let vsize: usize = descendants
            .iter()
            .filter_map(|id| self.map.get(id))
            .map(|e| e.vsize)
            .sum();
        (descendants.len(), vsize)
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

    /// `mempool.dat` file magic + version byte.
    const MEMPOOL_FILE_MAGIC: &'static [u8; 8] = b"avmpool\x01";

    /// The largest raw transaction `load` will read — consensus's
    /// `MAX_BLOCK_WEIGHT` bounds any single tx's serialized length;
    /// a bigger recorded length is file corruption, not a real entry.
    const MAX_TX_BYTES: usize = 4_000_000;

    /// Writes every pooled entry to `path` — Core's `DumpMempool` /
    /// `mempool.dat`. Each record is `tx || time || first_seen_height`
    /// (fees recompute at re-admission, so they needn't be stored).
    /// Returns the number of entries written.
    ///
    /// # Errors
    ///
    /// `io::Error` on write failure — the file is replaced, not
    /// merged, so a partial write leaves a truncated file `load`
    /// reports as fewer entries, never a corrupt state.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<usize> {
        use std::io::Write;
        let entries: Vec<&MempoolEntry> = self.map.values().collect();
        let mut f = std::fs::File::create(path)?;
        f.write_all(Self::MEMPOOL_FILE_MAGIC)?;
        f.write_all(&(entries.len() as u32).to_le_bytes())?;
        for e in &entries {
            let bytes = e.tx.encode();
            f.write_all(&(bytes.len() as u32).to_le_bytes())?;
            f.write_all(&bytes)?;
            f.write_all(&e.time.to_le_bytes())?;
            f.write_all(&e.first_seen_height.to_le_bytes())?;
        }
        // Trailing prioritisetransaction deltas — Core persists
        // `mapDeltas` in mempool.dat the same way; a file without the
        // section just leaves `deltas` empty at load.
        f.write_all(&(self.deltas.len() as u32).to_le_bytes())?;
        for (txid, delta) in &self.deltas {
            f.write_all(txid.as_bytes())?;
            f.write_all(&delta.to_le_bytes())?;
        }
        Ok(entries.len())
    }

    /// Reads `path` and re-runs every entry through [`Self::accept_tx`]
    /// — Core's `LoadMempool`: a tx that fails admission (inputs spent
    /// by a newer tip, aged policy, decode failure) is skipped, not an
    /// error. Entries re-enter in passes until one adds nothing, so a
    /// file listing a child before its parent still resolves. Original
    /// `time`/`first_seen_height` are restored onto accepted entries so
    /// the fee estimator keeps its samples.
    ///
    /// Returns `(imported, skipped)`.
    ///
    /// # Errors
    ///
    /// `io::Error` on read failure or a malformed header — a missing
    /// file is `Ok((0, 0))`, matching Core's first-run behavior.
    pub fn load(
        &mut self,
        path: &std::path::Path,
        cs: &avila_consensus::chainstate::Chainstate,
        now: u32,
    ) -> std::io::Result<(usize, usize)> {
        use std::io::Read;
        let mut buf = Vec::new();
        match std::fs::File::open(path).and_then(|mut f| f.read_to_end(&mut buf)) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(e),
        }
        if buf.len() < Self::MEMPOOL_FILE_MAGIC.len() + 4 || buf[..8] != *Self::MEMPOOL_FILE_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mempool.dat: bad magic",
            ));
        }
        let count = u32::from_le_bytes(buf[8..12].try_into().unwrap_or_default()) as usize;
        let mut cursor = 12usize;
        let mut pending: Vec<(Transaction, u32, u32)> = Vec::with_capacity(count.min(65_536));
        for _ in 0..count {
            if cursor + 4 > buf.len() {
                break; // truncated tail — import what decoded
            }
            let tx_len =
                u32::from_le_bytes(buf[cursor..cursor + 4].try_into().unwrap_or_default()) as usize;
            cursor += 4;
            if tx_len > Self::MAX_TX_BYTES || cursor + tx_len + 8 > buf.len() {
                break;
            }
            let raw = &buf[cursor..cursor + tx_len];
            cursor += tx_len;
            let time = u32::from_le_bytes(buf[cursor..cursor + 4].try_into().unwrap_or_default());
            let height =
                u32::from_le_bytes(buf[cursor + 4..cursor + 8].try_into().unwrap_or_default());
            cursor += 8;
            if let Ok(tx) = Transaction::decode(raw) {
                pending.push((tx, time, height));
            }
        }
        // Optional trailing `mapDeltas` section — absent in files written
        // before deltas were persisted; a short/corrupt tail is ignored.
        if cursor + 4 <= buf.len() {
            let dcount =
                u32::from_le_bytes(buf[cursor..cursor + 4].try_into().unwrap_or_default()) as usize;
            cursor += 4;
            for _ in 0..dcount.min((buf.len() - cursor) / 40) {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&buf[cursor..cursor + 32]);
                let delta = i64::from_le_bytes(
                    buf[cursor + 32..cursor + 40].try_into().unwrap_or_default(),
                );
                self.deltas.insert(Txid::from_bytes(bytes), delta);
                cursor += 40;
            }
        }
        let decoded = pending.len();
        // Admission re-runs until a pass accepts nothing new. A child
        // listed before its parent parks as an orphan on its first pass,
        // then the parent's own accept_tx recursion un-parks it — so
        // "imported" is everything that left the pending queue, whether
        // this loop accepted it or the parent's orphan sweep did.
        loop {
            let mut progress = false;
            pending.retain(|(tx, time, height)| {
                match self.accept_tx(tx.clone(), cs, now) {
                    Ok(txid) => {
                        if let Some(e) = self.map.get_mut(&txid) {
                            e.time = *time;
                            e.first_seen_height = *height;
                        }
                        progress = true;
                        false
                    }
                    // Already pooled — possibly just orphan-swept by a
                    // parent's accept; restore its stored timestamps.
                    Err(MempoolReject::AlreadyKnown) => {
                        if let Some(e) = self.map.get_mut(&tx.txid()) {
                            e.time = *time;
                            e.first_seen_height = *height;
                        }
                        false
                    }
                    // Inputs may resolve once a later-file parent lands.
                    Err(MempoolReject::InputsMissingOrSpent) => true,
                    Err(_) => false,
                }
            });
            if !progress {
                break;
            }
        }
        Ok((decoded - pending.len(), pending.len()))
    }

    /// Every pooled entry — template.rs iterates these.
    pub(crate) fn entries(&self) -> impl Iterator<Item = &MempoolEntry> {
        self.map.values()
    }

    /// `txid` is pooled — template.rs's dependency test.
    pub(crate) fn has_entry(&self, txid: &Txid) -> bool {
        self.map.contains_key(txid)
    }

    /// Orphan-pool size — observability for the sync layer.
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.orphans.len()
    }

    /// Drops `txid` and unindexes its input spends.
    pub fn remove(&mut self, txid: &Txid) -> Option<MempoolEntry> {
        let entry = self.map.remove(txid)?;
        self.unbroadcast.remove(txid);
        self.wtxids.remove(&entry.tx.wtxid());
        self.pool_bytes = self.pool_bytes.saturating_sub(entry.tx.encode().len());
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

    /// Marks `txid` as locally submitted but not yet requested by any
    /// peer — Core's `AddToUnbroadcastTxSet`.
    pub fn mark_unbroadcast(&mut self, txid: &Txid) {
        self.unbroadcast.insert(*txid);
    }

    /// A peer's getdata asked for `txid` — Core's `RemoveUnbroadcastTx`.
    pub fn clear_unbroadcast(&mut self, txid: &Txid) {
        self.unbroadcast.remove(txid);
    }

    /// Whether `txid` is still waiting for its first peer request.
    #[must_use]
    pub fn is_unbroadcast(&self, txid: &Txid) -> bool {
        self.unbroadcast.contains(txid)
    }

    /// `getmempoolinfo`'s `unbroadcastcount`.
    #[must_use]
    pub fn unbroadcast_count(&self) -> usize {
        self.unbroadcast.len()
    }

    /// `prioritisetransaction` — accumulates `delta` onto the txid's
    /// `mapDeltas` slot and stores the accumulated value on the entry
    /// (Core's `UpdateFeeDelta` sets, doesn't add). Unknown txids are
    /// remembered for admission; the RPC reports success either way.
    /// Ancestor/descendant fee stats pick the delta up automatically —
    /// they're summed from each entry's `modified_fee()` at query time.
    pub fn prioritise(&mut self, txid: &Txid, delta: i64) {
        let slot = self.deltas.entry(*txid).or_insert(0);
        *slot = slot.saturating_add(delta);
        if let Some(e) = self.map.get_mut(txid) {
            e.fee_delta = *slot;
        }
    }

    /// Drops every tx that spends a block's *newly spent* outpoints or
    /// whose txid the block now confirms — Core's
    /// `removeForBlock`-lite: confirmed txs leave the pool, and so do
    /// conflicts that can no longer confirm.
    pub fn on_block_connected(&mut self, block: &avila_consensus::block::Block, conf_height: u32) {
        let mut dead: Vec<Txid> = Vec::new();
        for tx in &block.transactions {
            let txid = tx.txid();
            // Core's ClearPrioritisation — confirmation retires the
            // txid's delta slot.
            self.deltas.remove(&txid);
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
        for id in &dead {
            // Feed the estimator before removal: (entry rate, wait).
            if let Some(entry) = self.map.get(id) {
                let waited = conf_height.saturating_sub(entry.first_seen_height).max(1);
                self.estimator
                    .observe(entry.fee * 1000 / entry.vsize.max(1) as i64, waited);
            }
        }
        for id in dead {
            self.remove_recursive(&id);
        }
    }

    /// A fee rate (sat/kvB) that recently confirmed within
    /// `target_blocks` — `None` means insufficient observations.
    #[must_use]
    pub fn estimate_fee(&self, target_blocks: u32) -> Option<i64> {
        self.estimator.estimate(target_blocks)
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

pub mod template;

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
        // BIP125 signaling is still enforced when full-RBF is off —
        // deployed Core's -mempoolfullrbf=0 path.
        pool.set_full_rbf(false);
        let op = mature_outpoint(&blocks, 1);
        let tx1 = spend_tx(op, 4_999_000_000, SEQ_FINAL);
        let tx2 = spend_tx(op, 4_998_000_000, SEQ_FINAL);
        pool.accept_tx(tx1, &cs, NOW).unwrap();
        assert_eq!(pool.accept_tx(tx2, &cs, NOW), Err(MempoolReject::Conflict));
    }

    #[test]
    fn full_rbf_accepts_unsignaled_replacement() {
        // Deployed Core default (-mempoolfullrbf=1): neither side needs
        // BIP125 signaling — only the fee-bump rules bind.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        assert!(pool.full_rbf());
        let op = mature_outpoint(&blocks, 1);
        let tx1 = spend_tx(op, 4_999_000_000, SEQ_FINAL); // 1M sat fee
        let tx2 = spend_tx(op, 4_998_000_000, SEQ_FINAL); // 2M sat — covers bump
        let id1 = tx1.txid();
        let id2 = tx2.txid();
        pool.accept_tx(tx1, &cs, NOW).unwrap();
        assert_eq!(pool.accept_tx(tx2, &cs, NOW), Ok(id2));
        assert!(pool.get(&id1).is_none(), "conflict evicted");
        assert!(pool.get(&id2).is_some());
    }

    #[test]
    fn full_rbf_still_requires_adequate_bump() {
        // Full-RBF waives signaling, not economics: an underpaying
        // replacement still fails.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let op = mature_outpoint(&blocks, 1);
        let tx1 = spend_tx(op, 4_999_000_000, SEQ_FINAL); // 1M sat fee
        // Same inputs, barely more output — fee shrinks below bump.
        let tx2 = spend_tx(op, 4_999_999_000, SEQ_FINAL);
        pool.accept_tx(tx1, &cs, NOW).unwrap();
        assert_eq!(pool.accept_tx(tx2, &cs, NOW), Err(MempoolReject::Conflict));
    }

    #[test]
    fn byte_cap_evicts_lowest_feerate() {
        // `-maxmempool`'s analog: a candidate that outbids the pool's
        // worst feerate displaces it when the byte cap binds.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let small = spend_tx(mature_outpoint(&blocks, 1), 4_999_999_000, SEQ_FINAL);
        let cap = small.encode().len() + 8;
        pool.set_max_bytes(cap);
        // Low feerate occupies the only byte-slot.
        let weak = spend_tx(mature_outpoint(&blocks, 1), 4_999_999_000, SEQ_FINAL);
        let weak_id = weak.txid();
        pool.accept_tx(weak, &cs, NOW).unwrap();
        // A richer spend of a different outpoint outbids → evicts.
        let rich = spend_tx(mature_outpoint(&blocks, 2), 4_000_000_000, SEQ_FINAL);
        let rich_id = rich.txid();
        assert_eq!(pool.accept_tx(rich, &cs, NOW), Ok(rich_id));
        assert!(pool.get(&weak_id).is_none());
        assert!(pool.get(&rich_id).is_some());
        // …but an equal-or-lower feerate bounces off the full pool.
        // (h1's outpoint freed when `weak` was evicted.)
        let poor = spend_tx(mature_outpoint(&blocks, 1), 4_999_999_500, SEQ_FINAL);
        assert_eq!(pool.accept_tx(poor, &cs, NOW), Err(MempoolReject::Full));
        assert!(pool.pool_bytes + 8 <= cap);
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
        pool.on_block_connected(&block, 102);
        assert!(pool.is_empty());
    }

    /// A tx spending `op` and fanning out to `n` outputs (descendant
    /// tests need one parent with many children).
    fn fan_tx(op: OutPoint, n: u32, value_each: i64) -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: op,
                script_sig: Script::new(vec![]),
                sequence: SEQ_FINAL,
                witness: Witness::default(),
            }],
            outputs: (0..n)
                .map(|_| TxOut {
                    value: value_each,
                    script_pubkey: Script::new(vec![script::OP_1]),
                })
                .collect(),
            lock_time: 0,
        }
    }

    #[test]
    fn ancestor_chain_is_capped_at_25() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let mut op = mature_outpoint(&blocks, 1);
        let mut value = 4_999_000_000i64;
        // 25 chained accepts — the 25th has 24 ancestors (within limit).
        for _ in 0..25 {
            let tx = spend_tx(op, value, SEQ_FINAL);
            op = OutPoint {
                txid: tx.txid(),
                vout: 0,
            };
            value -= 10_000;
            pool.accept_tx(tx, &cs, NOW).unwrap();
        }
        // The 26th would have 25 ancestors + itself → over the limit.
        let over = spend_tx(op, value, SEQ_FINAL);
        assert_eq!(
            pool.accept_tx(over, &cs, NOW),
            Err(MempoolReject::PackageLimits)
        );
    }

    #[test]
    fn descendant_fanout_is_capped_at_25() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        // One parent with 30 outputs, each child spends a distinct one.
        let parent = fan_tx(mature_outpoint(&blocks, 1), 30, 10_000_000);
        let pid = parent.txid();
        pool.accept_tx(parent, &cs, NOW).unwrap();
        for vout in 0..25 {
            let child = spend_tx(OutPoint { txid: pid, vout }, 9_000_000, SEQ_FINAL);
            pool.accept_tx(child, &cs, NOW).unwrap();
        }
        // Child 26 pushes the parent's descendant set to 26.
        let over = spend_tx(
            OutPoint {
                txid: pid,
                vout: 25,
            },
            9_000_000,
            SEQ_FINAL,
        );
        assert_eq!(
            pool.accept_tx(over, &cs, NOW),
            Err(MempoolReject::PackageLimits)
        );
    }

    #[test]
    fn explain_traces_every_gate() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let steps = pool.explain_tx(&tx, &cs, NOW);
        // Every gate passed, in order, and nothing was pooled.
        assert!(steps.iter().all(|s| s.passed), "{steps:?}");
        assert_eq!(steps.first().unwrap().gate, "context-free");
        assert_eq!(steps.last().unwrap().gate, "capacity");
        assert!(pool.is_empty());
        pool.accept_tx(tx.clone(), &cs, NOW).unwrap();

        // The same tx explained again reports the duplicate.
        let steps = pool.explain_tx(&tx, &cs, NOW);
        let dup = steps.iter().find(|s| s.gate == "already-known").unwrap();
        assert!(!dup.passed);
        assert!(dup.detail.contains("already-in-mempool"));
    }

    #[test]
    fn explain_reports_the_failing_gate() {
        let (cs, _b) = chainstate_at(5);
        let pool = Mempool::new();
        let tx = spend_tx(
            OutPoint {
                txid: Txid::ZERO,
                vout: 0,
            },
            1_000,
            SEQ_FINAL,
        );
        let steps = pool.explain_tx(&tx, &cs, NOW);
        let last = steps.last().unwrap();
        assert_eq!(last.gate, "input-resolution");
        assert!(!last.passed);
        assert!(last.detail.contains("missingorspent"));
        // Orphan parking must not happen in explain mode.
        assert_eq!(pool.orphan_count(), 0);
    }

    #[test]
    fn template_connects_as_a_real_block() {
        let (mut cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let t1 = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let t2 = spend_tx(mature_outpoint(&blocks, 2), 4_999_500_000, SEQ_FINAL);
        pool.accept_tx(t1, &cs, NOW).unwrap();
        pool.accept_tx(t2, &cs, NOW).unwrap();

        let miner_script = Script::new(vec![script::OP_1]);
        let template = pool.build_template(&cs, miner_script, NOW + 120).unwrap();
        assert_eq!(template.height, 102);
        assert_eq!(template.tx_count, 2);
        let params = Network::Regtest.params();
        let mut block = template.block;
        // The coinbase pays subsidy + both fees.
        let subsidy = avila_consensus::connect::block_subsidy(102, &params);
        assert_eq!(
            block.transactions[0].outputs[0].value,
            subsidy + template.fees
        );
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, &params).is_err() {
            block.header.nonce += 1;
        }
        // The decisive check: full accept path connects our template.
        match cs.accept_block(&block, NOW + 130).unwrap() {
            avila_consensus::chainstate::Acceptance::Connected { height, .. } => {
                assert_eq!(height, 102)
            }
            other => panic!("template did not connect: {other:?}"),
        }
        pool.on_block_connected(&block, 102);
        assert!(pool.is_empty());
    }

    #[test]
    fn template_orders_parents_before_children() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let pid = parent.txid();
        let child = spend_tx(OutPoint { txid: pid, vout: 0 }, 4_998_000_000, SEQ_FINAL);
        pool.accept_tx(parent, &cs, NOW).unwrap();
        pool.accept_tx(child, &cs, NOW).unwrap();

        let template = pool
            .build_template(&cs, Script::new(vec![script::OP_1]), NOW + 120)
            .unwrap();
        let order: Vec<Txid> = template
            .block
            .transactions
            .iter()
            .skip(1)
            .map(|t| t.txid())
            .collect();
        assert_eq!(order.len(), 2);
        assert_eq!(order[0], pid, "parent must precede its child");
    }

    #[test]
    fn mempool_persists_round_trip() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let pid = parent.txid();
        let child = spend_tx(OutPoint { txid: pid, vout: 0 }, 4_998_000_000, SEQ_FINAL);
        pool.accept_tx(parent, &cs, NOW).unwrap();
        pool.accept_tx(child, &cs, NOW).unwrap();

        let dir = std::env::temp_dir().join(format!("avila-mp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mempool.dat");
        assert_eq!(pool.save(&path).unwrap(), 2);

        let mut fresh = Mempool::new();
        let (imported, skipped) = fresh.load(&path, &cs, NOW + 60).unwrap();
        assert_eq!((imported, skipped), (2, 0));
        assert!(fresh.has_entry(&pid));
        // Original acceptance time is restored, not the load time.
        assert_eq!(fresh.entry(&pid).unwrap().time, NOW);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn mempool_load_resolves_parent_after_child() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let pid = parent.txid();
        let child = spend_tx(OutPoint { txid: pid, vout: 0 }, 4_998_000_000, SEQ_FINAL);
        pool.accept_tx(parent.clone(), &cs, NOW).unwrap();
        pool.accept_tx(child.clone(), &cs, NOW).unwrap();

        // Hand-write the file child-first so the parent's record trails.
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("avila-mpr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mempool.dat");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"avmpool\x01").unwrap();
        f.write_all(&2u32.to_le_bytes()).unwrap();
        for tx in [&child, &parent] {
            let b = tx.encode();
            f.write_all(&(b.len() as u32).to_le_bytes()).unwrap();
            f.write_all(&b).unwrap();
            f.write_all(&NOW.to_le_bytes()).unwrap();
            f.write_all(&1u32.to_le_bytes()).unwrap();
        }
        drop(f);

        let mut fresh = Mempool::new();
        let (imported, skipped) = fresh.load(&path, &cs, NOW).unwrap();
        assert_eq!((imported, skipped), (2, 0), "passes resolve ordering");
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn mempool_load_skips_spent_and_truncated() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        pool.accept_tx(tx.clone(), &cs, NOW).unwrap();
        let dir = std::env::temp_dir().join(format!("avila-mps-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mempool.dat");
        pool.save(&path).unwrap();

        // The spend confirms — the persisted tx's input is now spent.
        let mut block = block_on(&blocks[100].header, 102, &Network::Regtest.params());
        block.transactions.push(tx);
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, cs.tree().params())
            .is_err()
        {
            block.header.nonce += 1;
        }
        let mut cs2 = cs;
        cs2.accept_block(&block, NOW + 200).unwrap();

        let mut fresh = Mempool::new();
        let (imported, skipped) = fresh.load(&path, &cs2, NOW + 300).unwrap();
        assert_eq!((imported, skipped), (0, 1), "spent input → skipped");

        // A truncated file imports what decoded without erroring — cut
        // through the 4-byte delta tail into the last entry's data.
        let raw = std::fs::read(&path).unwrap();
        std::fs::write(&path, &raw[..raw.len() - 7]).unwrap();
        let (imported, skipped) = fresh.load(&path, &cs2, NOW + 300).unwrap();
        assert_eq!((imported, skipped), (0, 0));
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn fee_estimate_needs_enough_samples() {
        let mut est = FeeEstimator::new();
        assert_eq!(est.estimate(6), None, "no samples → no estimate");
        for _ in 0..6 {
            est.observe(5_000, 2);
        }
        assert_eq!(est.estimate(6), Some(5_000));
        // A tighter target than any observation → still enough samples
        // only if they waited ≤ target.
        assert_eq!(est.estimate(1), None);
        for _ in 0..6 {
            est.observe(2_000, 1);
        }
        assert_eq!(est.estimate(1), Some(2_000));
    }

    #[test]
    fn prioritise_unknown_txid_applies_at_admission() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let txid = tx.txid();
        // Core: deltas land in mapDeltas before the tx is known and
        // attach when it enters.
        pool.prioritise(&txid, 5_000);
        pool.prioritise(&txid, -2_000);
        pool.accept_tx(tx, &cs, NOW).unwrap();
        let e = pool.entry(&txid).unwrap();
        assert_eq!(e.fee_delta, 3_000);
        assert_eq!(e.modified_fee(), e.fee + 3_000);
        // A further prioritise on the pooled entry accumulates.
        pool.prioritise(&txid, 500);
        assert_eq!(pool.entry(&txid).unwrap().fee_delta, 3_500);
    }

    #[test]
    fn prioritise_pooled_tx_sets_accumulated_delta() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let txid = tx.txid();
        pool.accept_tx(tx, &cs, NOW).unwrap();
        pool.prioritise(&txid, 10_000);
        pool.prioritise(&txid, -4_000);
        let e = pool.entry(&txid).unwrap();
        assert_eq!(e.fee_delta, 6_000);
        assert_eq!(e.modified_fee(), e.fee + 6_000);
        // Saturating accumulation — no overflow panic at the i64 edge.
        pool.prioritise(&txid, i64::MAX);
        assert_eq!(pool.entry(&txid).unwrap().fee_delta, i64::MAX);
    }

    #[test]
    fn confirmation_clears_the_delta() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let txid = tx.txid();
        pool.accept_tx(tx.clone(), &cs, NOW).unwrap();
        pool.prioritise(&txid, 10_000);
        let mut block = block_on(&blocks[100].header, 102, &Network::Regtest.params());
        block.transactions.push(tx);
        pool.on_block_connected(&block, 102);
        assert!(pool.get(&txid).is_none());
        // Core's ClearPrioritisation — the txid's slot is gone, so a
        // re-prioritise starts from zero rather than accumulating.
        assert!(!pool.deltas.contains_key(&txid));
        pool.prioritise(&txid, 7);
        assert_eq!(pool.deltas.get(&txid), Some(&7));
    }

    #[test]
    fn deltas_persist_through_save_load() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = Mempool::new();
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let txid = tx.txid();
        pool.prioritise(&txid, 42_000);
        pool.accept_tx(tx, &cs, NOW).unwrap();
        // A delta for a tx that never arrived persists too.
        let ghost = Txid::from_bytes([9u8; 32]);
        pool.prioritise(&ghost, 1_000);
        let dir = std::env::temp_dir().join(format!("avila-mpd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mempool.dat");
        pool.save(&path).unwrap();

        let mut fresh = Mempool::new();
        let (imported, skipped) = fresh.load(&path, &cs, NOW).unwrap();
        assert_eq!((imported, skipped), (1, 0));
        assert_eq!(fresh.entry(&txid).unwrap().fee_delta, 42_000);
        assert_eq!(fresh.deltas.get(&ghost), Some(&1_000));
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}

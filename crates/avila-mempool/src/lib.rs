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

/// Core's `MAX_STANDARD_TX_SIGOPS_COST` (`policy/policy.h`) —
/// `MAX_BLOCK_SIGOPS_COST / 5`: the most a single relayed tx may cost
/// in sigops, independent of its byte size.
pub const MAX_STANDARD_TX_SIGOPS_COST: u64 = avila_consensus::check::MAX_BLOCK_SIGOPS_COST / 5;

/// Deployed Core's `DEFAULT_INCREMENTAL_RELAY_FEE` — a replacement must
/// cover its own relay at this rate on top of the conflicting tx's fee.
pub const INCREMENTAL_RELAY_FEE: i64 = 100; // sat/kvB

/// Core's `ROLLING_FEE_HALFLIFE` — the time (12 hours) for the rolling
/// minimum fee to decay by half; the pool halves that halflife again
/// under half its byte cap, and again under a quarter.
pub const ROLLING_FEE_HALFLIFE_SECS: f64 = 12.0 * 60.0 * 60.0;

/// Bound on pool entries — a belt alongside the `DEFAULT_MAX_BYTES`
/// suspenders; either cap trips the evict-lowest-feerate path.
pub const DEFAULT_MAX_ENTRIES: usize = 25_000;

/// Core's `DEFAULT_MAX_MEMPOOL_SIZE` — 300 MB in bytes.
pub const DEFAULT_MAX_BYTES: usize = 300_000_000;

/// Core's `nSequence` threshold for BIP125 replaceability signaling:
/// any input below `0xfffffffe` opts the tx into replacement.
const RBF_SEQUENCE_THRESHOLD: u32 = 0xffff_fffe;

/// BIP125 rule 5's `MAX_REPLACEMENT_CANDIDATES` (Core's
/// `policy/rbf.h`) — a replacement may not evict more than this many
/// entries in total, counting every conflict's in-pool descendants.
pub const MAX_REPLACEMENT_CANDIDATES: usize = 100;

/// A pooled transaction with the policy facts admission computed.
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    /// The transaction.
    pub tx: Transaction,
    /// `value_in - value_out` in satoshis.
    pub fee: i64,
    /// Core's `GetVirtualTransactionSize(weight, sigops, 20)` —
    /// `max(weight, sigops * 20).div_ceil(4)` — computed once at
    /// admission and used everywhere a size is needed: fee-rate and
    /// eviction scoring, ancestor/descendant package totals, the
    /// min-relay-fee and capacity checks.
    pub vsize: usize,
    /// Sigop cost — Core's `GetTransactionSigOpCost` (legacy × 4, plus
    /// P2SH and witness sigops resolved against this entry's inputs).
    /// The basis for `vsize` above and the per-tx sigop cap.
    pub sigops: u64,
    /// Arrival time (caller-supplied).
    pub time: u32,
    /// The chain height when first pooled — the estimator's clock for
    /// "blocks to confirm" (Core's `nHeight` at acceptance).
    pub first_seen_height: u32,
    /// `prioritisetransaction`'s accumulated adjustment (Core's
    /// `nFeeDelta`) — `fee + fee_delta` is the modified fee template
    /// ordering and `fees.modified` report.
    pub fee_delta: i64,
    /// Serialized size — computed once at admission; `pool_bytes`
    /// accounting and eviction reuse it instead of re-encoding.
    pub size: usize,
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
    /// The candidate's own in-pool ancestor set overlaps the set of
    /// entries it would evict (conflicts plus their descendants) — Core's
    /// `EntriesAndTxidsDisjoint`. Left unchecked, admitting the tx and
    /// then evicting its conflicts leaves a dangling reference to a coin
    /// that never confirmed.
    #[error("bad-txns-spends-conflicting-tx")]
    SpendsConflict,
    /// BIP125 rule 5: replacing this tx's conflicts would evict more
    /// than [`MAX_REPLACEMENT_CANDIDATES`] entries (conflicts plus
    /// their descendants) — Core's `GetEntriesForConflicts`.
    #[error("too many potential replacements")]
    TooManyReplacements,
    /// Sigop cost exceeds [`MAX_STANDARD_TX_SIGOPS_COST`] — Core's
    /// `PreChecks`: a handful of expensive scripts can burn CPU wildly
    /// out of proportion to a tx's byte size.
    #[error("bad-txns-too-many-sigops")]
    TooManySigops,
    /// A `require_standard`-gated policy failure — Core's `IsStandardTx`,
    /// `AreInputsStandard`, `IsWitnessStandard`, or the ephemeral-dust
    /// zero-fee rule. Carries Core's own short reject reason (`"version"`,
    /// `"scriptpubkey"`, `"dust"`, `"bad-txns-nonstandard-inputs"`, …).
    /// With `require_standard` off, every check that can produce this is
    /// skipped entirely.
    #[error("{0}")]
    NotStandard(&'static str),
    /// Below Core's rolling `CTxMemPool::GetMinFee` floor — a second,
    /// independent gate from [`Self::MinRelayFee`] that only ever binds
    /// once a size-based trim has evicted something, decaying back
    /// toward zero afterward.
    #[error("mempool min fee not met")]
    MempoolMinFeeNotMet,
    /// BIP431 TRUC (`nVersion = 3`) topology rule failed — Core's
    /// `SingleTRUCChecks`. Core's own wire-level reject reason is the
    /// bare `"TRUC-violation"`; the detail carries the specific rule.
    #[error("TRUC-violation: {0}")]
    TrucViolation(&'static str),
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

/// Core's `MAX_DISCONNECTED_TX_POOL_BYTES` — 20 × `MAX_BLOCK_WEIGHT`:
/// the byte bound on the `DisconnectedBlockTransactions` queue during a
/// reorg; excess evicts the oldest-queued (fork-side) transactions.
pub const MAX_DISCONNECTED_TX_POOL_BYTES: usize = 20 * 4_000_000;

/// Core's `ORPHAN_TX_EXPIRE_TIME` — orphans live at most 20 minutes.
pub const ORPHAN_EXPIRE_SECS: u32 = 20 * 60;

/// Core's `DEFAULT_MEMPOOL_EXPIRY_HOURS` (336h = 14 days) in seconds —
/// a pooled entry older than this is swept regardless of fee, taking
/// its descendants with it.
pub const DEFAULT_MEMPOOL_EXPIRY_SECS: u32 = 336 * 60 * 60;

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
    /// Weight budgeted for the coinbase (and witness commitment) when
    /// selecting a block template — Core's `-blockreservedweight`
    /// (`DEFAULT_BLOCK_RESERVED_WEIGHT`).
    block_reserved_weight: usize,
    /// Sigop cost budgeted for the coinbase's own outputs when selecting
    /// a template — Core's `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS`.
    coinbase_max_additional_sigops: u64,
    /// Core's `require_standard` (`kernel::MemPoolOptions`): gates
    /// `IsStandardTx`/`AreInputsStandard`/`IsWitnessStandard` and the
    /// ephemeral-dust zero-fee rule. Core defaults this to `true` on
    /// every network — `-acceptnonstdtxn` (default off) is the only way
    /// to relax it, and mainnet refuses to relax it at all.
    require_standard: bool,
    /// Datacarrier (`OP_RETURN`) budget for `IsStandardTx` — Core's
    /// `-datacarriersize`; `None` mirrors `-datacarrier=0` (no nulldata
    /// outputs at all, matching Core's `datacarrier_bytes_left` default
    /// of zero when disabled).
    max_datacarrier_bytes: Option<usize>,
    /// Core's `-permitbaremultisig` (default on).
    permit_bare_multisig: bool,
    /// Core's `-dustrelayfee` in sat/kvB.
    dust_relay_fee: i64,
    /// Core's `rollingMinimumFeeRate` (sat/kvB) — the extra floor
    /// `min_mempool_fee` enforces on top of `min_relay_fee`, raised
    /// whenever a size-based trim evicts something and decaying back
    /// toward zero afterward. Zero until the pool has ever trimmed.
    rolling_min_fee: f64,
    /// Core's `lastRollingFeeUpdate` — the `now` at which
    /// `rolling_min_fee` was last set; decay is computed as elapsed
    /// time since this point.
    last_rolling_fee_update: u32,
    /// Core's `blockSinceLastRollingFeeBump` — decay is paused (the raw
    /// `rolling_min_fee` applies unchanged) until a block connects.
    block_since_rolling_fee_bump: bool,
    /// Core's `-mempoolexpiry` in seconds — a pooled entry older than
    /// this is swept regardless of fee.
    mempool_expiry_secs: u32,
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
    /// Bumps on every membership change — subscription checks compare
    /// it to skip recomputing when the pool hasn't moved.
    epoch: u64,
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
            block_reserved_weight: template::DEFAULT_BLOCK_RESERVED_WEIGHT,
            coinbase_max_additional_sigops: template::DEFAULT_COINBASE_MAX_ADDITIONAL_SIGOPS,
            require_standard: true,
            max_datacarrier_bytes: Some(policy::MAX_OP_RETURN_RELAY),
            permit_bare_multisig: policy::DEFAULT_PERMIT_BAREMULTISIG,
            dust_relay_fee: policy::DUST_RELAY_TX_FEE,
            rolling_min_fee: 0.0,
            last_rolling_fee_update: 0,
            block_since_rolling_fee_bump: false,
            mempool_expiry_secs: DEFAULT_MEMPOOL_EXPIRY_SECS,
            estimator: FeeEstimator::new(),
            deltas: HashMap::new(),
            unbroadcast: HashSet::new(),
            epoch: 0,
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

    /// Core's `rollingMinimumFeeRate` decayed to `now` — the raw
    /// internal rate a lazy `CTxMemPool::GetMinFee` call would have left
    /// the field holding, before the final `max` with the incremental
    /// relay fee and before its "already decayed away" hard zero.
    /// Recomputed fresh from [`Self::last_rolling_fee_update`] each call
    /// rather than cached in place (Core mutates the field on every
    /// `GetMinFee`; a pure recompute observes identically at any given
    /// `now` since exponential decay composes across sub-intervals).
    fn rolling_rate_now(&self, now: u32) -> f64 {
        if !self.block_since_rolling_fee_bump || self.rolling_min_fee <= 0.0 {
            return self.rolling_min_fee;
        }
        let elapsed = f64::from(now.saturating_sub(self.last_rolling_fee_update));
        let mut halflife = ROLLING_FEE_HALFLIFE_SECS;
        if self.pool_bytes < self.max_bytes / 4 {
            halflife /= 4.0;
        } else if self.pool_bytes < self.max_bytes / 2 {
            halflife /= 2.0;
        }
        let decayed = self.rolling_min_fee / 2f64.powf(elapsed / halflife);
        if decayed < INCREMENTAL_RELAY_FEE as f64 / 2.0 {
            0.0
        } else {
            decayed
        }
    }

    /// The rolling minimum feerate (sat/kvB) a transaction's fee must
    /// clear on top of [`Self::min_relay_fee`] — Core's `CTxMemPool::
    /// GetMinFee`. Zero until a size-based trim has ever evicted
    /// something; then decays back toward zero over
    /// [`ROLLING_FEE_HALFLIFE_SECS`] (faster while the pool is well
    /// under its byte cap), floored at [`INCREMENTAL_RELAY_FEE`] while
    /// it hasn't fully decayed away.
    #[must_use]
    pub fn min_mempool_fee(&self, now: u32) -> i64 {
        if !self.block_since_rolling_fee_bump || self.rolling_min_fee <= 0.0 {
            return self.rolling_min_fee.round() as i64;
        }
        let rate = self.rolling_rate_now(now);
        if rate <= 0.0 {
            0
        } else {
            (rate.round() as i64).max(INCREMENTAL_RELAY_FEE)
        }
    }

    /// The pooled-entry expiry age in seconds — Core's `-mempoolexpiry`.
    #[must_use]
    pub fn mempool_expiry_secs(&self) -> u32 {
        self.mempool_expiry_secs
    }

    /// Overrides the expiry age — an operator knob.
    pub fn set_mempool_expiry_secs(&mut self, secs: u32) {
        self.mempool_expiry_secs = secs;
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

    /// Weight budgeted for the coinbase when building a template —
    /// `-blockreservedweight`'s analog.
    #[must_use]
    pub fn block_reserved_weight(&self) -> usize {
        self.block_reserved_weight
    }

    /// Overrides the block-reserved-weight budget, clamped to
    /// [`template::MINIMUM_BLOCK_RESERVED_WEIGHT`]`..=MAX_BLOCK_WEIGHT` —
    /// Core refuses a smaller reserve outright at startup; clamping up
    /// is the conservative analog for a runtime setter.
    pub fn set_block_reserved_weight(&mut self, weight: usize) {
        self.block_reserved_weight = weight.clamp(
            template::MINIMUM_BLOCK_RESERVED_WEIGHT,
            avila_consensus::block::MAX_BLOCK_WEIGHT,
        );
    }

    /// Sigop cost budgeted for the coinbase's own outputs when building
    /// a template — Core's `-blockmaxsigopscost`-adjacent
    /// `coinbase_output_max_additional_sigops` option.
    #[must_use]
    pub fn coinbase_max_additional_sigops(&self) -> u64 {
        self.coinbase_max_additional_sigops
    }

    /// Overrides the coinbase sigop-cost budget, clamped to
    /// `0..=MAX_BLOCK_SIGOPS_COST` (Core's `std::clamp` in
    /// `ApplyArgsManOptions`).
    pub fn set_coinbase_max_additional_sigops(&mut self, sigops: u64) {
        self.coinbase_max_additional_sigops =
            sigops.min(avila_consensus::check::MAX_BLOCK_SIGOPS_COST);
    }

    /// Whether standardness (`IsStandardTx`/`AreInputsStandard`/
    /// `IsWitnessStandard`/ephemeral-dust) is enforced — Core's
    /// `require_standard`, on by default for every network.
    #[must_use]
    pub fn require_standard(&self) -> bool {
        self.require_standard
    }

    /// Overrides `require_standard` — Core's `-acceptnonstdtxn` (negated).
    /// Existing callers that build deliberately nonstandard test
    /// transactions should flip this to `false` rather than reshaping
    /// their fixtures; deployed Core itself refuses to relax this on
    /// mainnet, so callers wiring this up per-network should keep that
    /// restriction rather than exposing it as a mainnet knob.
    pub fn set_require_standard(&mut self, on: bool) {
        self.require_standard = on;
    }

    /// The `-datacarriersize` budget: `Some(n)` standard `OP_RETURN`
    /// outputs may total at most `n` scriptPubKey bytes; `None` mirrors
    /// `-datacarrier=0` (no nulldata outputs at all).
    #[must_use]
    pub fn max_datacarrier_bytes(&self) -> Option<usize> {
        self.max_datacarrier_bytes
    }

    /// Overrides the datacarrier budget.
    pub fn set_max_datacarrier_bytes(&mut self, bytes: Option<usize>) {
        self.max_datacarrier_bytes = bytes;
    }

    /// Whether bare (non-P2SH) multisig outputs are standard — Core's
    /// `-permitbaremultisig`.
    #[must_use]
    pub fn permit_bare_multisig(&self) -> bool {
        self.permit_bare_multisig
    }

    /// Overrides `-permitbaremultisig`.
    pub fn set_permit_bare_multisig(&mut self, on: bool) {
        self.permit_bare_multisig = on;
    }

    /// The dust-relay feerate in sat/kvB — Core's `-dustrelayfee`.
    #[must_use]
    pub fn dust_relay_fee(&self) -> i64 {
        self.dust_relay_fee
    }

    /// Overrides the dust-relay feerate.
    pub fn set_dust_relay_fee(&mut self, sat_per_kvb: i64) {
        self.dust_relay_fee = sat_per_kvb;
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
            return Some(coin);
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
        now: u32,
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
        if self.require_standard {
            if !push(
                &mut steps,
                "standard-tx",
                policy::is_standard_tx(
                    tx,
                    self.max_datacarrier_bytes,
                    self.permit_bare_multisig,
                    self.dust_relay_fee,
                )
                .map(|()| "standard".to_string())
                .map_err(str::to_string),
            ) {
                return steps;
            }
            if !push(
                &mut steps,
                "standard-tx-size",
                if tx.size_without_witness() < policy::MIN_STANDARD_TX_NONWITNESS_SIZE {
                    Err("tx-size-small".into())
                } else {
                    Ok(format!("{} non-witness bytes", tx.size_without_witness()))
                },
            ) {
                return steps;
            }
        }

        let mut spent = Vec::with_capacity(tx.inputs.len());
        let mut missing = 0usize;
        let mut from_pool = 0usize;
        let mut conflicts: Vec<Txid> = Vec::new();
        for input in &tx.inputs {
            if let Some(coin) = cs.utxo().get(&input.previous_output) {
                spent.push(coin);
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
        let spent_outs: Vec<_> = spent.iter().map(|c| c.out.clone()).collect();
        if self.require_standard {
            if !push(
                &mut steps,
                "standard-inputs",
                policy::are_inputs_standard(tx, &spent_outs)
                    .map(|()| "standard".to_string())
                    .map_err(str::to_string),
            ) {
                return steps;
            }
            if tx.has_witness()
                && !push(
                    &mut steps,
                    "standard-witness",
                    policy::is_witness_standard(tx, &spent_outs)
                        .map(|()| "standard".to_string())
                        .map_err(str::to_string),
                )
            {
                return steps;
            }
        }

        // Sigop cost and the one true vsize — same computation and
        // ordering as `accept_tx`'s step 2.5; every later size-based
        // gate below reads this `vsize` back rather than `tx.weight()`.
        let tip = cs.tip_hash();
        let next_height = cs.tree().tip().height + 1;
        let flags = standard_script_flags(cs, next_height, &tip);
        let sigop_cost = self.real_sigop_cost(cs, tx, flags);
        if !push(
            &mut steps,
            "sigop-cap",
            if sigop_cost > MAX_STANDARD_TX_SIGOPS_COST {
                Err(format!(
                    "bad-txns-too-many-sigops: {sigop_cost} > {MAX_STANDARD_TX_SIGOPS_COST}"
                ))
            } else {
                Ok(format!("{sigop_cost} <= {MAX_STANDARD_TX_SIGOPS_COST}"))
            },
        ) {
            return steps;
        }
        let vsize = virtual_size(tx.weight(), sigop_cost);

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

        let ancestors = self.ancestors_of(tx);

        // TRUC/BIP431 (Core's `SingleTRUCChecks`) — mirrors accept_tx's
        // step 3.6, including folding an offered sibling eviction into
        // `conflicts` before the disjointness/rule-5 gates below so this
        // dry run reports the same outcome `accept_tx` would reach.
        {
            let mut direct_parent_ids: Vec<Txid> = Vec::new();
            for input in &tx.inputs {
                let pid = input.previous_output.txid;
                if self.map.contains_key(&pid) && !direct_parent_ids.contains(&pid) {
                    direct_parent_ids.push(pid);
                }
            }
            let truc_parents: Vec<truc::ParentFacts> = direct_parent_ids
                .iter()
                .filter_map(|pid| {
                    let parent = self.map.get(pid)?;
                    let ancestor_count = self.ancestors_of(&parent.tx).len() + 1;
                    let descendants = self
                        .descendant_txids(pid)
                        .iter()
                        .filter_map(|did| {
                            let d = self.map.get(did)?;
                            Some((*did, self.ancestors_of(&d.tx).len() + 1))
                        })
                        .collect();
                    Some(truc::ParentFacts {
                        version: parent.tx.version,
                        ancestor_count,
                        descendants,
                    })
                })
                .collect();
            let direct_conflicts: HashSet<Txid> = conflicts.iter().copied().collect();
            let outcome =
                match truc::single_truc_checks(tx.version, vsize, &truc_parents, &direct_conflicts)
                {
                    truc::TrucOutcome::Ok => Ok("no TRUC violation".to_string()),
                    truc::TrucOutcome::Reject(reason) => Err(format!("TRUC-violation: {reason}")),
                    truc::TrucOutcome::ConsiderSiblingEviction { sibling, .. } => {
                        if !conflicts.contains(&sibling) {
                            conflicts.push(sibling);
                        }
                        Ok(format!("would evict sibling {sibling}"))
                    }
                };
            if !push(&mut steps, "truc", outcome) {
                return steps;
            }
        }

        if !conflicts.is_empty() {
            let replaced = self.set_being_replaced(&conflicts);
            if !push(
                &mut steps,
                "spends-conflict",
                if ancestors.iter().any(|a| replaced.contains(a)) {
                    Err("bad-txns-spends-conflicting-tx".into())
                } else {
                    Ok("ancestors disjoint from replaced set".into())
                },
            ) {
                return steps;
            }
            if !push(
                &mut steps,
                "replacement-candidates",
                if replaced.len() > MAX_REPLACEMENT_CANDIDATES {
                    Err(format!(
                        "too many potential replacements: {} > {MAX_REPLACEMENT_CANDIDATES}",
                        replaced.len()
                    ))
                } else {
                    Ok(format!("{} entries would be evicted", replaced.len()))
                },
            ) {
                return steps;
            }
        }

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

        // `tip`/`next_height` were already computed above (sigop-cap).
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

        if self.require_standard {
            let modified_fee =
                fee.saturating_add(self.deltas.get(&tx.txid()).copied().unwrap_or(0));
            if !push(
                &mut steps,
                "ephemeral-dust",
                policy::precheck_ephemeral(tx, self.dust_relay_fee, fee, modified_fee)
                    .map(|()| "ok".to_string())
                    .map_err(str::to_string),
            ) {
                return steps;
            }
        }

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

        let modified_fee = fee.saturating_add(self.deltas.get(&tx.txid()).copied().unwrap_or(0));
        let mempool_min_fee = self.min_mempool_fee(now);
        if !push(
            &mut steps,
            "mempool-min-fee",
            if modified_fee * 1000 < mempool_min_fee * vsize as i64 {
                Err(format!(
                    "mempool min fee not met: {modified_fee} sat for {vsize} vB (floor {mempool_min_fee} sat/kvB)"
                ))
            } else {
                Ok(format!("{modified_fee} sat for {vsize} vB"))
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
                match self.worst_by_descendant_score() {
                    Some(worst_id) => {
                        let (worst_fee, worst_size) = self.descendant_score(&worst_id);
                        if (fee as i128) * (worst_size as i128)
                            > (worst_fee as i128) * (vsize as i128)
                        {
                            Ok(format!(
                                "full; would evict {worst_id} (descendant-score rate {})",
                                worst_fee * 1000 / worst_size.max(1) as i64
                            ))
                        } else {
                            Err("mempool full".into())
                        }
                    }
                    None => Err("mempool full".into()),
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
        // 0. Sweep anything that's aged out (Core's `CTxMemPool::Expire`,
        //    normally run from a periodic scheduled task or a reorg;
        //    driven off admission here instead since this crate has no
        //    scheduler of its own). Cheap relative to admission itself
        //    and bounded by the entry cap.
        self.expire(now);

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

        // 1.5 Standardness on the tx alone (Core's `IsStandardTx`, gated
        //    by `require_standard`): version range, scriptSig size and
        //    push-only-ness, output template and datacarrier/bare-multisig
        //    limits, and the dust cap. Off by default only via
        //    `set_require_standard(false)` — deployed Core defaults this
        //    on for every network.
        if self.require_standard {
            policy::is_standard_tx(
                &tx,
                self.max_datacarrier_bytes,
                self.permit_bare_multisig,
                self.dust_relay_fee,
            )
            .map_err(MempoolReject::NotStandard)?;
            // Core's CVE-2017-12842 mitigation (`tx-size-small`) is
            // unconditional upstream; bundled under `require_standard`
            // here so the existing sub-65-byte test fixtures keep
            // working via the permissive setting instead of being
            // padded out.
            if tx.size_without_witness() < policy::MIN_STANDARD_TX_NONWITNESS_SIZE {
                return Err(MempoolReject::NotStandard("tx-size-small"));
            }
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
        let spent_outs: Vec<_> = spent.iter().map(|c| c.out.clone()).collect();

        // 2.4 Standardness on the resolved inputs (Core's
        //    `AreInputsStandard`/`IsWitnessStandard`, `require_standard`
        //    -gated): non-standard or unknown-witness prevouts, oversized
        //    P2SH redeem-script sigops, BIP54's legacy-sigop cap, and
        //    non-standard witness shapes (P2WSH/tapscript stack limits,
        //    annexes).
        if self.require_standard {
            policy::are_inputs_standard(&tx, &spent_outs).map_err(MempoolReject::NotStandard)?;
            if tx.has_witness() {
                policy::is_witness_standard(&tx, &spent_outs)
                    .map_err(MempoolReject::NotStandard)?;
            }
        }

        // 2.5 Sigop cost and the one true vsize for this entry — Core's
        //    `GetTransactionSigOpCost` and `GetVirtualTransactionSize`
        //    (`max(weight, sigops * bytes_per_sigop) / 4`). Computed once
        //    and used for every size-based decision below, the stored
        //    entry, and every later ancestor/descendant/eviction
        //    calculation that reads it back off the entry. Also enforces
        //    the per-tx sigop cap (Core's PreChecks,
        //    `MAX_STANDARD_TX_SIGOPS_COST`) independent of byte size.
        let tip = cs.tip_hash();
        let next_height = cs.tree().tip().height + 1;
        let flags = standard_script_flags(cs, next_height, &tip);
        let sigop_cost = self.real_sigop_cost(cs, &tx, flags);
        if sigop_cost > MAX_STANDARD_TX_SIGOPS_COST {
            return Err(MempoolReject::TooManySigops);
        }
        let vsize = virtual_size(tx.weight(), sigop_cost);

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
        let ancestors = self.ancestors_of(&tx);

        // 3.6 TRUC/BIP431 (Core's `SingleTRUCChecks`): v3 transactions
        //    never mix unconfirmed ancestry with non-v3 txs, are capped
        //    at one unconfirmed ancestor and one descendant, and size
        //    limits tighten once either side of that relationship is in
        //    play. A parent's sole existing child in the plain,
        //    non-reorg shape may be evicted instead of rejecting the new
        //    tx outright — Core's opportunistic sibling eviction, which
        //    applies to ordinary single-tx submission (not just
        //    packages). The evicted sibling joins `conflicts` *before*
        //    the disjointness/rule-5/fee checks below, so it's bound by
        //    the same replacement economics as any other conflict —
        //    Core gives it no free pass on BIP125 signaling or fees.
        {
            let mut direct_parent_ids: Vec<Txid> = Vec::new();
            for input in &tx.inputs {
                let pid = input.previous_output.txid;
                if self.map.contains_key(&pid) && !direct_parent_ids.contains(&pid) {
                    direct_parent_ids.push(pid);
                }
            }
            let truc_parents: Vec<truc::ParentFacts> = direct_parent_ids
                .iter()
                .filter_map(|pid| {
                    let parent = self.map.get(pid)?;
                    let ancestor_count = self.ancestors_of(&parent.tx).len() + 1;
                    let descendants = self
                        .descendant_txids(pid)
                        .iter()
                        .filter_map(|did| {
                            let d = self.map.get(did)?;
                            Some((*did, self.ancestors_of(&d.tx).len() + 1))
                        })
                        .collect();
                    Some(truc::ParentFacts {
                        version: parent.tx.version,
                        ancestor_count,
                        descendants,
                    })
                })
                .collect();
            let direct_conflicts: HashSet<Txid> = conflicts.iter().copied().collect();
            match truc::single_truc_checks(tx.version, vsize, &truc_parents, &direct_conflicts) {
                truc::TrucOutcome::Ok => {}
                truc::TrucOutcome::Reject(reason) => {
                    return Err(MempoolReject::TrucViolation(reason));
                }
                truc::TrucOutcome::ConsiderSiblingEviction { sibling, .. } => {
                    if !conflicts.contains(&sibling) {
                        conflicts.push(sibling);
                    }
                }
            }
        }

        if !conflicts.is_empty() {
            let replaced = self.set_being_replaced(&conflicts);

            // Core's `EntriesAndTxidsDisjoint`: a tx that both conflicts
            // with a pooled entry and descends from it (directly, or
            // through one of that entry's own in-pool descendants) is
            // invalid — step 10 below evicts the whole replaced set out
            // from under it, leaving an ancestor reference that can
            // never resolve.
            if ancestors.iter().any(|a| replaced.contains(a)) {
                return Err(MempoolReject::SpendsConflict);
            }

            // BIP125 rule 5 (Core's `GetEntriesForConflicts`,
            // `MAX_REPLACEMENT_CANDIDATES`): cap how many entries a
            // single replacement may evict, counting descendants —
            // otherwise one low-fee input could force evicting an
            // unbounded cluster.
            if replaced.len() > MAX_REPLACEMENT_CANDIDATES {
                return Err(MempoolReject::TooManyReplacements);
            }
        }

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
        //    `tip`/`next_height` were already computed at step 2.5.
        let mut overlay = UtxoSet::new();
        for (input, coin) in tx.inputs.iter().zip(spent.iter()) {
            overlay.insert_synthetic(input.previous_output, coin.clone());
        }
        let (_, fee) =
            check_tx_inputs(&tx, &overlay, next_height).map_err(MempoolReject::Inputs)?;
        // Core's `GetModifiedFee` for a not-yet-pooled tx: a
        // `prioritisetransaction` delta recorded before the tx arrived
        // applies immediately (mirrors the same lookup at entry
        // construction, step 11 below).
        let modified_fee = fee.saturating_add(self.deltas.get(&txid).copied().unwrap_or(0));

        // 4.5 Ephemeral dust (Core's `PreCheckEphemeralTx`,
        //    `require_standard`-gated): a tx creating dust must be
        //    exactly 0-fee — Core's `AreInputsStandard`/dust cap above
        //    already limit it to at most one dust output.
        if self.require_standard {
            policy::precheck_ephemeral(&tx, self.dust_relay_fee, fee, modified_fee)
                .map_err(MempoolReject::NotStandard)?;
        }

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
        //    is still block-valid, just not relayed). `flags` and
        //    `spent_outs` were already computed above (2.4/2.5).
        check_input_scripts(&tx, &spent_outs, flags).map_err(MempoolReject::ScriptVerify)?;
        avila_consensus::sigchecker::mark_scripts_verified(tx.wtxid(), flags);

        // 8. Min relay fee (Core: fee >= GetVirtualTransactionSize *
        //    minRelayTxFee / 1000).
        if fee * 1000 < self.min_relay_fee * vsize as i64 {
            return Err(MempoolReject::MinRelayFee);
        }

        // 8.5 Rolling mempool-min-fee floor (Core's `CTxMemPool::
        //    GetMinFee`) — a *second*, independent floor from the static
        //    min-relay-fee above: it's zero until a size-based trim ever
        //    evicts something, then decays back toward zero over
        //    `ROLLING_FEE_HALFLIFE_SECS`.
        let mempool_min_fee = self.min_mempool_fee(now);
        if modified_fee * 1000 < mempool_min_fee * vsize as i64 {
            return Err(MempoolReject::MempoolMinFeeNotMet);
        }

        // 9. Capacity: either cap (entries or serialized bytes — Core's
        //    `-maxmempool` analog) trips the evict-the-worst path. The
        //    victim is picked by descendant score (Core's `TrimToSize`/
        //    `CompareTxMemPoolEntryByDescendantScore`), not its own bare
        //    feerate: a low-fee parent scores at its richest descendant
        //    package's rate, so a merely-mediocre standalone tx is
        //    evicted first instead of dragging a valuable child down
        //    with its low-fee parent. The candidate isn't pooled yet, so
        //    its own (fee, vsize) is its whole score for this
        //    comparison — it has no descendants to fold in.
        let tx_size = tx.encode().len();
        // The highest-rate cluster removed during this trim, tracked so
        // the rolling-fee bump below uses the whole pass's high-water
        // mark — Core's `maxFeeRateRemoved`, not each individual removal.
        let mut removed_high: Option<(i64, usize)> = None;
        while self.map.len() >= self.max_entries || self.pool_bytes + tx_size > self.max_bytes {
            let Some(worst_id) = self.worst_by_descendant_score() else {
                return Err(MempoolReject::Full);
            };
            let (worst_fee, worst_size) = self.descendant_score(&worst_id);
            if (fee as i128) * (worst_size as i128) <= (worst_fee as i128) * (vsize as i128) {
                return Err(MempoolReject::Full);
            }
            let removed = self.cluster_totals(&worst_id);
            let better = removed_high.is_none_or(|(rf, rs)| {
                (removed.0 as i128) * (rs as i128) > (rf as i128) * (removed.1 as i128)
            });
            if better {
                removed_high = Some(removed);
            }
            // The evicted entry's descendants leave with it — Core's
            // TrimToSize drops clusters, not lone txs.
            self.remove_recursive(&worst_id);
        }
        // Core's `TrackPackageRemoved`: the rolling floor only ever
        // rises here, to the priciest thing this trim gave up plus one
        // incremental relay fee — never lowered except by time decay.
        // Compared against the *decayed-to-now* rate, not the raw stored
        // field, since nothing else keeps that field's decay current.
        if let Some((removed_fee, removed_size)) = removed_high {
            let removed_rate = removed_fee * 1000 / removed_size.max(1) as i64;
            let bumped = removed_rate.saturating_add(INCREMENTAL_RELAY_FEE);
            if bumped as f64 > self.rolling_rate_now(now) {
                self.rolling_min_fee = bumped as f64;
                self.last_rolling_fee_update = now;
                self.block_since_rolling_fee_bump = false;
            }
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
        self.pool_bytes += tx_size;
        self.epoch += 1;
        self.map.insert(
            txid,
            MempoolEntry {
                size: tx_size,
                tx,
                fee,
                vsize,
                sigops: sigop_cost,
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

    /// The full set of entries a replacement would tear out of the pool:
    /// each direct conflict plus every one of its in-pool descendants —
    /// exactly what [`Self::remove_recursive`] removes per conflict in
    /// step 10 of [`Self::accept_tx`]. Core's `EntriesAndTxidsDisjoint`
    /// checks the candidate's ancestors against direct conflicts alone;
    /// we check against this wider set because it's what our own
    /// eviction actually tears out from under the candidate's ancestry.
    fn set_being_replaced(&self, conflicts: &[Txid]) -> HashSet<Txid> {
        let mut replaced: HashSet<Txid> = HashSet::new();
        for &conflict in conflicts {
            replaced.insert(conflict);
            replaced.extend(self.descendant_txids(&conflict));
        }
        replaced
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

    /// `(fee, vsize)` of `txid` together with every one of its current
    /// in-pool descendants — Core's `GetModFeesWithDescendants`/
    /// `GetSizeWithDescendants`. Missing/unpooled `txid` reports as
    /// `(0, 1)` (a harmless, never-winning score; `1` avoids a zero
    /// denominator in rate comparisons).
    fn cluster_totals(&self, txid: &Txid) -> (i64, usize) {
        let Some(entry) = self.map.get(txid) else {
            return (0, 1);
        };
        let mut totals = (entry.modified_fee(), entry.vsize);
        for id in self.descendant_txids(txid) {
            if let Some(e) = self.map.get(&id) {
                totals.0 = totals.0.saturating_add(e.modified_fee());
                totals.1 = totals.1.saturating_add(e.vsize);
            }
        }
        totals
    }

    /// Core's `CompareTxMemPoolEntryByDescendantScore`'s per-entry score
    /// (its `GetModFeeAndSize`): whichever is the higher feerate of the
    /// entry's own `(fee, vsize)` and its [`Self::cluster_totals`] (self
    /// plus every current in-pool descendant). A low-fee parent with a
    /// rich descendant is scored at the descendants' rate rather than
    /// its own, so trimming can't take the rich descendant down just to
    /// evict a merely-mediocre parent. Returns a `(fee, size)` pair
    /// rather than a ratio — callers compare two scores by cross-
    /// multiplication instead of floating point.
    fn descendant_score(&self, txid: &Txid) -> (i64, usize) {
        let Some(entry) = self.map.get(txid) else {
            return (0, 1);
        };
        let own = (entry.modified_fee(), entry.vsize);
        let with_descendants = self.cluster_totals(txid);
        // `with_descendants` rate > `own` rate, cross-multiplied to
        // avoid floating point (Core's `f1`/`f2` comparison in doubles).
        if (with_descendants.0 as i128) * (own.1 as i128)
            > (own.0 as i128) * (with_descendants.1 as i128)
        {
            with_descendants
        } else {
            own
        }
    }

    /// The lowest-scoring pooled entry by [`Self::descendant_score`] —
    /// the eviction cursor for the capacity trim (Core's `TrimToSize`,
    /// driven off its `descendant_score_index`). Ties break on txid so
    /// the choice is deterministic. `O(n)` over the pool: only walked
    /// when a candidate is admitted at capacity, not on every lookup —
    /// Core's own index is `O(log n)` per removal, but a plain scan
    /// avoids keeping a relationship-dependent score continuously
    /// up to date as unrelated entries come and go.
    fn worst_by_descendant_score(&self) -> Option<Txid> {
        self.map.keys().copied().min_by(|&a, &b| {
            let (fa, sa) = self.descendant_score(&a);
            let (fb, sb) = self.descendant_score(&b);
            ((fa as i128) * (sb as i128))
                .cmp(&((fb as i128) * (sa as i128)))
                .then_with(|| a.cmp(&b))
        })
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

    /// `txid` is pooled.
    #[cfg(test)]
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
        self.epoch += 1;
        self.unbroadcast.remove(txid);
        self.wtxids.remove(&entry.tx.wtxid());
        self.pool_bytes = self.pool_bytes.saturating_sub(entry.size);
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

    /// Core's `CTxMemPool::Expire`: drops every entry that has sat
    /// unconfirmed for at least [`Self::mempool_expiry_secs`], taking
    /// its descendants with it — Core walks its time-sorted index only
    /// to the first not-yet-expired entry and expands each expired root
    /// to its descendants; the effect (and, since a descendant can't be
    /// older than its parent, the exact set) is the same whether or not
    /// an expired descendant is reached again once its own ancestor's
    /// removal has already swept it. Returns the number of entries
    /// removed.
    pub fn expire(&mut self, now: u32) -> usize {
        let cutoff = now.saturating_sub(self.mempool_expiry_secs);
        let stale: Vec<Txid> = self
            .map
            .iter()
            .filter(|(_, e)| e.time < cutoff)
            .map(|(id, _)| *id)
            .collect();
        let before = self.map.len();
        for id in &stale {
            if self.map.contains_key(id) {
                self.remove_recursive(id);
            }
        }
        before - self.map.len()
    }

    /// `remove_recursive` for a transaction that is not itself pooled —
    /// Core's `removeRecursive(tx)` on a failed resurrected tx, whose
    /// in-pool dependents must drop even though `tx` never made it in.
    /// The tx's outpoints are enumerable from the object, so its
    /// children are found via the spends index directly.
    fn remove_dependents(&mut self, tx: &Transaction) {
        let txid = tx.txid();
        let children: Vec<Txid> = (0..tx.outputs.len())
            .filter_map(|vout| {
                self.spends
                    .get(&OutPoint {
                        txid,
                        vout: vout as u32,
                    })
                    .copied()
            })
            .collect();
        for child in children {
            self.remove_recursive(&child);
        }
        self.remove(&txid);
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

    /// The `mapDeltas` map itself, for `getprioritisedtransactions` —
    /// Core iterates `std::map<Txid,...>` (txid raw-byte order), so
    /// callers sort `Txid`'s raw bytes to match.
    pub fn deltas(&self) -> &HashMap<Txid, i64> {
        &self.deltas
    }

    /// Drops every tx that spends a block's *newly spent* outpoints or
    /// whose txid the block now confirms — Core's
    /// `removeForBlock`-lite: confirmed txs leave the pool, and so do
    /// conflicts that can no longer confirm.
    pub fn on_block_connected(&mut self, block: &avila_consensus::block::Block, conf_height: u32) {
        // Core's `blockSinceLastRollingFeeBump = true`: a connected
        // block un-pauses the rolling-fee decay.
        self.block_since_rolling_fee_bump = true;
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
    /// full admission (a tx may now conflict with the new chain); a tx
    /// that fails admission takes its in-pool descendants down with it
    /// (Core's `removeRecursive` on the failed re-add) and never parks
    /// as an orphan.
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
            match self.accept_tx(tx.clone(), cs, now) {
                Ok(_) => readmitted += 1,
                Err(_) => {
                    // Core runs the resurrected tx through
                    // `AcceptToMemoryPool` — no orphanage — and
                    // `removeRecursive`s it on failure so in-pool
                    // dependents don't outlive a lost parent.
                    self.orphans.remove(&tx.txid());
                    self.remove_dependents(tx);
                }
            }
        }
        readmitted
    }

    /// Core's `MaybeUpdateMempoolForReorg` over a batch of disconnected
    /// blocks. `disconnected` carries block hashes in disconnect order
    /// (most-recent tip first — [`Chainstate::take_disconnected`]).
    ///
    /// `fork_first` picks the feed order: `true` iterates fork-adjacent
    /// block first (the batched `ActivateBestChain` reorg — Core's
    /// reverse-order drain); `false` keeps disconnect order
    /// (`invalidateblock`'s per-`DisconnectTip` feed, where children
    /// whose parents are still connected fail and drop).
    ///
    /// `max_blocks` caps how many disconnect-order blocks contribute —
    /// Core's `(++disconnected <= 10)` gate on `invalidateblock`; pass
    /// `usize::MAX` for the uncapped reorg path. Queued bytes are capped
    /// at [`MAX_DISCONNECTED_TX_POOL_BYTES`], evicting from the fork
    /// side, matching Core's queue bound.
    ///
    /// Returns the number of transactions re-admitted.
    pub fn refill_from_disconnected(
        &mut self,
        disconnected: &[avila_consensus::hash::BlockHash],
        cs: &avila_consensus::chainstate::Chainstate,
        now: u32,
        fork_first: bool,
        max_blocks: usize,
    ) -> usize {
        // Queue in disconnect order, bounded by serialized bytes — over
        // the cap, the fork-side (oldest-queued) blocks lose their txs.
        let mut queued: Vec<avila_consensus::block::Block> = Vec::new();
        let mut bytes = 0usize;
        for hash in disconnected.iter().take(max_blocks) {
            let Some(block) = cs.body(hash) else {
                continue;
            };
            let size: usize = block.transactions.iter().map(|tx| tx.encode().len()).sum();
            if bytes + size > MAX_DISCONNECTED_TX_POOL_BYTES {
                break;
            }
            bytes += size;
            queued.push(block);
        }
        if fork_first {
            queued.reverse();
        }
        let mut readmitted = 0usize;
        for block in &queued {
            readmitted += self.reinsert_disconnected(block, cs, now);
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

/// Core's `GetVirtualTransactionSize(weight, sigop_cost, bytes_per_sigop)`
/// with Core's default `bytes_per_sigop` (`DEFAULT_BYTES_PER_SIGOP`, 20):
/// `max(weight, sigops * 20)` rounded up to vbytes. A sigop-heavy tx is
/// billed as if it were as big as its sigop cost demands, even when its
/// byte weight is small — the one vsize every size-based mempool and
/// template decision should read back off the entry rather than
/// recomputing from `tx.weight()` alone.
pub(crate) fn virtual_size(weight: usize, sigop_cost: u64) -> usize {
    /// Core's `DEFAULT_BYTES_PER_SIGOP`.
    const BYTES_PER_SIGOP: u64 = 20;
    let sigop_weight =
        usize::try_from(sigop_cost.saturating_mul(BYTES_PER_SIGOP)).unwrap_or(usize::MAX);
    weight.max(sigop_weight).div_ceil(4)
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

pub mod policy;
pub mod template;
pub mod truc;

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

    /// A pool with `require_standard` off. Every test in this module
    /// predates fix 6 (standardness) and spends/creates the trivial
    /// `OP_1` "anyone can spend" script for convenience — not a
    /// standard output template — so they opt out of standardness
    /// wholesale here rather than being rewritten to sign real standard
    /// scripts. Tests that specifically exercise standardness construct
    /// `Mempool::new()` directly (standard by default, matching
    /// deployed Core) instead of calling this helper.
    fn permissive_pool() -> Mempool {
        let mut pool = Mempool::new();
        pool.set_require_standard(false);
        pool
    }

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

    /// A tx spending every outpoint in `ops` into one output — covers the
    /// `spend_tx`-can't-build cases (multi-input conflict/ancestor tests).
    fn spend_many(ops: &[OutPoint], value: i64, sequence: u32) -> Transaction {
        Transaction {
            version: 2,
            inputs: ops
                .iter()
                .map(|&previous_output| TxIn {
                    previous_output,
                    script_sig: Script::new(vec![]),
                    sequence,
                    witness: Witness::default(),
                })
                .collect(),
            outputs: vec![TxOut {
                value,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        }
    }

    /// Builds and pools a linear chain rooted at `op`: one root spending
    /// `op`, then `extra` further txs each spending the previous one's
    /// sole output — `1 + extra` pooled entries in total. Returns the
    /// root's txid.
    fn accept_chain(
        pool: &mut Mempool,
        cs: &Chainstate,
        op: OutPoint,
        extra: usize,
        base_value: i64,
    ) -> Txid {
        let root = spend_tx(op, base_value, SEQ_RBF);
        let root_id = root.txid();
        pool.accept_tx(root, cs, NOW).unwrap();
        let mut prev = OutPoint {
            txid: root_id,
            vout: 0,
        };
        let mut value = base_value;
        for _ in 0..extra {
            value -= 1_000;
            let tx = spend_tx(prev, value, SEQ_FINAL);
            prev = OutPoint {
                txid: tx.txid(),
                vout: 0,
            };
            pool.accept_tx(tx, cs, NOW).unwrap();
        }
        root_id
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let txid = tx.txid();
        assert_eq!(pool.accept_tx(tx, &cs, NOW).unwrap(), txid);
        assert!(pool.get(&txid).is_some());
    }

    #[test]
    fn missing_input_is_rejected() {
        let (cs, _b) = chainstate_at(5);
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        // fee = 1 sat over ~250 vB → below 1 sat/vB.
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_999_999, SEQ_FINAL);
        assert_eq!(
            pool.accept_tx(tx, &cs, NOW),
            Err(MempoolReject::MinRelayFee)
        );
    }

    #[test]
    fn tx_with_excessive_sigop_cost_is_rejected() {
        // Core's PreChecks: GetTransactionSigOpCost vs
        // MAX_STANDARD_TX_SIGOPS_COST (16,000), independent of tx size.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        let op = mature_outpoint(&blocks, 1);
        // 250 bare OP_CHECKMULTISIG opcodes in the sole output: legacy
        // sigop count (non-accurate, 20 each) * WITNESS_SCALE_FACTOR(4)
        // = 250*20*4 = 20,000 > 16,000, while the tx itself is tiny.
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: op,
                script_sig: Script::new(vec![]),
                sequence: SEQ_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 4_999_000_000,
                script_pubkey: Script::new(vec![script::OP_CHECKMULTISIG; 250]),
            }],
            lock_time: 0,
        };
        assert_eq!(
            pool.accept_tx(tx, &cs, NOW),
            Err(MempoolReject::TooManySigops)
        );
    }

    #[test]
    fn vsize_is_sigop_adjusted_not_just_weight() {
        // Core's `GetVirtualTransactionSize`: a sigop-heavy but
        // byte-light tx is billed at `sigops * 20` bytes-equivalent
        // once that exceeds its real weight, not `weight / 4` alone —
        // and every gate (here, min-relay-fee) must read that adjusted
        // size, not re-derive its own from `tx.weight()`. 100 bare
        // OP_CHECKMULTISIG opcodes cost 100*20*4 = 8,000 sigop cost
        // (safely under the 16,000 per-tx cap) — 8,000*20 = 160,000
        // weight-equivalent bytes, vastly more than this ~640 WU tx's
        // real weight (~40,000 vB vs. ~160 vB). A 2,000 sat fee clears
        // min-relay under the old, weight-only vsize but not the
        // correct, sigop-adjusted one.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        let mut tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_998_000, SEQ_FINAL);
        tx.outputs[0].script_pubkey = Script::new(vec![script::OP_CHECKMULTISIG; 100]);
        let txid = tx.txid();
        assert_eq!(
            pool.accept_tx(tx, &cs, NOW),
            Err(MempoolReject::MinRelayFee)
        );
        assert!(pool.get(&txid).is_none());
    }

    #[test]
    fn accept_tx_enforces_standardness_by_default() {
        // Core defaults `require_standard` to true on every network
        // (v31.1 moved it out of `CChainParams`; there's no per-chain
        // default split any more). This suite's trivial bare-`OP_1`
        // "anyone can spend" script is not a standard output template,
        // so a real (non-permissive) pool rejects it — and the same tx
        // is admitted once the permissive option is set, exactly as the
        // rest of this module already relies on via `permissive_pool`.
        let (cs, blocks) = chainstate_at(101);
        let mut strict = Mempool::new();
        assert!(strict.require_standard());
        let tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        assert_eq!(
            strict.accept_tx(tx.clone(), &cs, NOW),
            Err(MempoolReject::NotStandard("scriptpubkey"))
        );

        let mut permissive = permissive_pool();
        assert!(!permissive.require_standard());
        assert!(permissive.accept_tx(tx, &cs, NOW).is_ok());
    }

    #[test]
    fn is_standard_tx_rejects_out_of_range_version() {
        let tx = Transaction {
            version: 4,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(vec![]),
                sequence: SEQ_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 900,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        assert_eq!(
            policy::is_standard_tx(
                &tx,
                Some(policy::MAX_OP_RETURN_RELAY),
                true,
                policy::DUST_RELAY_TX_FEE
            ),
            Err("version")
        );
    }

    #[test]
    fn is_standard_tx_caps_bare_multisig_at_three_keys() {
        // Solver accepts up to `MAX_PUBKEYS_PER_MULTISIG` (20) keys, but
        // `IsStandard` additionally caps a *standard-shaped* bare
        // multisig at 3 — a 1-of-4 is Solver-valid but policy-nonstandard
        // regardless of `permit_bare_multisig`.
        let mut spk = vec![script::OP_1];
        for i in 0u8..4 {
            let mut key = vec![0x02, i.wrapping_add(1)];
            key.extend_from_slice(&[0u8; 31]);
            spk.extend_from_slice(&script::push_slice(&key));
        }
        spk.push(script::OP_1 + 3); // OP_4: four keys follow.
        spk.push(script::OP_CHECKMULTISIG);
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(vec![]),
                sequence: SEQ_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 900,
                script_pubkey: Script::new(spk),
            }],
            lock_time: 0,
        };
        assert_eq!(
            policy::is_standard_tx(
                &tx,
                Some(policy::MAX_OP_RETURN_RELAY),
                true,
                policy::DUST_RELAY_TX_FEE
            ),
            Err("scriptpubkey")
        );
    }

    #[test]
    fn is_standard_tx_rejects_more_than_one_dust_output() {
        // Core's ephemeral-dust allowance tolerates a single below-dust
        // output; a second one is always rejected regardless of fee.
        let p2wpkh = |value: i64| TxOut {
            value,
            script_pubkey: Script::new({
                let mut s = vec![script::OP_0, 0x14];
                s.extend_from_slice(&[0u8; 20]);
                s
            }),
        };
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(vec![]),
                sequence: SEQ_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![p2wpkh(100), p2wpkh(100)],
            lock_time: 0,
        };
        assert_eq!(
            policy::is_standard_tx(
                &tx,
                Some(policy::MAX_OP_RETURN_RELAY),
                true,
                policy::DUST_RELAY_TX_FEE
            ),
            Err("dust")
        );
    }

    #[test]
    fn are_inputs_standard_caps_p2sh_redeem_sigops() {
        // A redeem script's sigops are counted accurately, but a bare
        // (unconditioned) OP_CHECKMULTISIG still costs the flat 20 —
        // over MAX_P2SH_SIGOPS(15) on its own.
        let redeem = Script::new(vec![script::OP_CHECKMULTISIG]);
        let script_sig = Script::new(script::push_slice(redeem.as_bytes()));
        let prevout = TxOut {
            value: 1_000,
            script_pubkey: Script::new({
                let mut s = vec![script::OP_HASH160, 0x14];
                s.extend_from_slice(&[0u8; 20]);
                s.push(script::OP_EQUAL);
                s
            }),
        };
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig,
                sequence: SEQ_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 900,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        assert_eq!(
            policy::are_inputs_standard(&tx, &[prevout]),
            Err("bad-txns-nonstandard-inputs")
        );
    }

    #[test]
    fn is_witness_standard_caps_p2wsh_stack_item_size() {
        let prevout = TxOut {
            value: 1_000,
            script_pubkey: Script::new({
                let mut s = vec![script::OP_0, 0x20];
                s.extend_from_slice(&[0u8; 32]);
                s
            }),
        };
        let big_item = vec![0u8; 81]; // > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(vec![]),
                sequence: SEQ_FINAL,
                witness: Witness::new(vec![big_item, vec![script::OP_1]]),
            }],
            outputs: vec![TxOut {
                value: 900,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        assert_eq!(
            policy::is_witness_standard(&tx, &[prevout]),
            Err("bad-witness-nonstandard")
        );
    }

    #[test]
    fn double_spend_without_rbf_is_rejected() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        let op = mature_outpoint(&blocks, 1);
        let tx1 = spend_tx(op, 4_999_000_000, SEQ_FINAL); // 1M sat fee
        // Same inputs, barely more output — fee shrinks below bump.
        let tx2 = spend_tx(op, 4_999_999_000, SEQ_FINAL);
        pool.accept_tx(tx1, &cs, NOW).unwrap();
        assert_eq!(pool.accept_tx(tx2, &cs, NOW), Err(MempoolReject::Conflict));
    }

    #[test]
    fn rbf_cannot_spend_its_own_conflict() {
        // Core's EntriesAndTxidsDisjoint (policy/rbf.cpp): `x` double-spends
        // `p`'s input (conflicts with `p`) *and* spends `p`'s output (`p` is
        // one of `x`'s ancestors). Without the check, `p` gets evicted as a
        // replaced conflict while `x` is admitted still pointing at `p`'s
        // now-gone output — a dangling in-pool parent that can never confirm.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        let op = mature_outpoint(&blocks, 1);
        let p = spend_tx(op, 4_999_000_000, SEQ_RBF);
        let p_id = p.txid();
        pool.accept_tx(p, &cs, NOW).unwrap();

        let x = spend_many(
            &[
                OutPoint {
                    txid: p_id,
                    vout: 0,
                },
                op,
            ],
            4_000_000_000,
            SEQ_RBF,
        );
        assert_eq!(
            pool.accept_tx(x, &cs, NOW),
            Err(MempoolReject::SpendsConflict)
        );
        // The rejected replacement must not have taken its conflict with it.
        assert!(pool.get(&p_id).is_some());
    }

    #[test]
    fn rbf_rejects_past_max_replacement_candidates() {
        // BIP125 rule 5 (Core's GetEntriesForConflicts,
        // MAX_REPLACEMENT_CANDIDATES = 100): five independent 25-entry
        // chains (each at the ANCESTOR_LIMIT/DESCENDANT_LIMIT boundary)
        // give 125 entries a single tx could evict by double-spending
        // each chain's root input — past the rule-5 cap.
        let (cs, blocks) = chainstate_at(105);
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        let mut roots_ops = Vec::new();
        for h in 1..=5 {
            let op = mature_outpoint(&blocks, h);
            accept_chain(&mut pool, &cs, op, 24, 4_999_000_000);
            roots_ops.push(op);
        }
        assert_eq!(pool.len(), 125, "5 chains of 25 entries each");

        // `x` double-spends every chain root's input (a direct conflict
        // with each root) without spending any pooled output itself.
        let x = spend_many(&roots_ops, 20_000_000_000, SEQ_RBF);
        assert_eq!(
            pool.accept_tx(x, &cs, NOW),
            Err(MempoolReject::TooManyReplacements)
        );
        assert_eq!(pool.len(), 125, "rejected replacement evicts nothing");
    }

    #[test]
    fn byte_cap_evicts_lowest_feerate() {
        // `-maxmempool`'s analog: a candidate that outbids the pool's
        // worst feerate displaces it when the byte cap binds.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        // …but an equal-or-lower feerate bounces off the full pool —
        // now via the rolling min-fee floor fix 8 raised when `weak` was
        // trimmed (Core's `TrackPackageRemoved`: evicted rate +
        // incremental relay fee), which binds before capacity is even
        // reconsidered for a rate this far under `rich`'s.
        // (h1's outpoint freed when `weak` was evicted.)
        let poor = spend_tx(mature_outpoint(&blocks, 1), 4_999_999_500, SEQ_FINAL);
        assert_eq!(
            pool.accept_tx(poor, &cs, NOW),
            Err(MempoolReject::MempoolMinFeeNotMet)
        );
        assert!(pool.pool_bytes + 8 <= cap);
    }

    #[test]
    fn capacity_eviction_uses_descendant_score_not_own_rate() {
        // Core's `TrimToSize`/`CompareTxMemPoolEntryByDescendantScore`:
        // a low-fee parent `b` with a huge-fee child `c` scores at `c`'s
        // rate, not its own — so at capacity, the worse *standalone* `a`
        // is evicted instead, and `b`+`c` survive together. Ranking by
        // each entry's own bare feerate alone (the bug) would instead
        // pick `b` (lowest raw rate) and its eviction would drag the
        // valuable `c` down with it, leaving the worse `a` untouched.
        let (cs, blocks) = chainstate_at(102);
        let mut pool = permissive_pool();
        pool.set_max_entries(3);

        let a = spend_tx(mature_outpoint(&blocks, 1), 4_999_995_000, SEQ_FINAL); // fee 5,000
        let a_id = a.txid();
        let b = spend_tx(mature_outpoint(&blocks, 2), 4_999_999_900, SEQ_FINAL); // fee 100
        let b_id = b.txid();
        let c = spend_tx(
            OutPoint {
                txid: b_id,
                vout: 0,
            },
            4_989_999_900, // fee 10,000,000 off b's output
            SEQ_FINAL,
        );
        let c_id = c.txid();
        pool.accept_tx(a, &cs, NOW).unwrap();
        pool.accept_tx(b, &cs, NOW).unwrap();
        pool.accept_tx(c, &cs, NOW).unwrap();
        assert_eq!(pool.len(), 3, "pool at capacity");

        // `d`'s own rate clears `a`'s but is nowhere near `b`+`c`'s
        // combined package rate — it should only ever need to beat `a`.
        let d = spend_tx(mature_outpoint(&blocks, 3), 4_999_950_000, SEQ_FINAL); // fee 50,000
        let d_id = d.txid();
        assert_eq!(pool.accept_tx(d, &cs, NOW), Ok(d_id));

        assert!(pool.get(&a_id).is_none(), "worse standalone tx evicted");
        assert!(
            pool.get(&b_id).is_some(),
            "low-fee parent survives via its child's package rate"
        );
        assert!(pool.get(&c_id).is_some(), "rich child untouched");
        assert!(pool.get(&d_id).is_some());
    }

    #[test]
    fn rolling_min_fee_rejects_until_it_decays() {
        // Core's `CTxMemPool::GetMinFee`: a size-based trim raises the
        // rolling floor to the evicted entry's rate plus the
        // incremental relay fee; a later, otherwise-fine tx below that
        // floor is rejected until decay (paced by connected blocks, not
        // wall-clock alone) brings the floor back down.
        let (cs, blocks) = chainstate_at(102);
        let mut pool = permissive_pool();
        let sized = spend_tx(mature_outpoint(&blocks, 1), 4_999_999_000, SEQ_FINAL);
        pool.set_max_bytes(sized.encode().len() + 8);

        let weak = spend_tx(mature_outpoint(&blocks, 1), 4_999_999_000, SEQ_FINAL); // fee 1,000
        pool.accept_tx(weak, &cs, NOW).unwrap();
        assert_eq!(pool.min_mempool_fee(NOW), 0, "no trim yet — no extra floor");

        // A huge-fee tx of a different outpoint forces the byte cap and
        // evicts `weak`, raising the rolling floor.
        let rich = spend_tx(mature_outpoint(&blocks, 2), 1_000, SEQ_FINAL);
        pool.accept_tx(rich, &cs, NOW).unwrap();
        let floor = pool.min_mempool_fee(NOW);
        assert!(floor > 0, "trim must raise the rolling floor");

        // `mid` clears the (0.1 sat/vB) min-relay-fee comfortably but
        // not the new rolling floor.
        let mid = spend_tx(mature_outpoint(&blocks, 3), 4_999_999_500, SEQ_FINAL); // fee 500
        assert_eq!(
            pool.accept_tx(mid.clone(), &cs, NOW),
            Err(MempoolReject::MempoolMinFeeNotMet)
        );

        // Decay is paused until a block connects (Core's
        // `blockSinceLastRollingFeeBump`) — a wall-clock jump alone
        // doesn't move the floor.
        assert_eq!(pool.min_mempool_fee(NOW + 30 * 24 * 60 * 60), floor);
        let params = Network::Regtest.params();
        let tip = cs.tree().tip();
        let fake_block = block_on(&tip.header, tip.height + 1, &params);
        pool.on_block_connected(&fake_block, tip.height + 1);

        // Many halflives after that, the floor has decayed away and the
        // same tx is admitted — lift the byte cap first so only the
        // rolling-fee recovery is under test, not capacity (the pool is
        // still pinned to one entry's worth of bytes from the setup
        // above, and `mid`'s fee alone could never outbid `rich`'s).
        pool.set_max_bytes(DEFAULT_MAX_BYTES);
        let much_later = NOW + 30 * 24 * 60 * 60;
        assert_eq!(pool.min_mempool_fee(much_later), 0);
        assert!(pool.accept_tx(mid, &cs, much_later).is_ok());
    }

    #[test]
    fn expire_sweeps_stale_entries_and_their_descendants() {
        // Core's `CTxMemPool::Expire`: an entry older than
        // `DEFAULT_MEMPOOL_EXPIRY_SECS` (14 days) is dropped regardless
        // of fee, taking its descendants — even a *fresh* one — with it.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        let parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let parent_id = parent.txid();
        pool.accept_tx(parent, &cs, NOW).unwrap(); // pooled at time NOW

        let child = spend_tx(
            OutPoint {
                txid: parent_id,
                vout: 0,
            },
            4_998_000_000,
            SEQ_FINAL,
        );
        let child_id = child.txid();
        let later = NOW + 60; // the child arrives a minute after its parent
        pool.accept_tx(child, &cs, later).unwrap();
        assert_eq!(pool.len(), 2);

        // Neither has aged out yet.
        assert_eq!(pool.expire(later), 0);
        assert_eq!(pool.len(), 2);

        // Past the *parent's* 14-day expiry — the child alone is still
        // under the limit (pooled 60s later), but leaves anyway via the
        // parent's removal cascade.
        let expired_at = NOW + DEFAULT_MEMPOOL_EXPIRY_SECS + 1;
        assert_eq!(pool.expire(expired_at), 2);
        assert!(pool.get(&parent_id).is_none());
        assert!(pool.get(&child_id).is_none());
    }

    #[test]
    fn truc_tx_over_max_vsize_is_rejected() {
        // BIP431/Core's SingleTRUCChecks: TRUC_MAX_VSIZE = 10,000 vB for
        // any v3 tx, standalone or not.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        let mut tx = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        tx.version = 3;
        tx.outputs[0].script_pubkey = Script::new(vec![0u8; 10_300]); // pushes ~vsize > 10,000
        assert_eq!(
            pool.accept_tx(tx, &cs, NOW),
            Err(MempoolReject::TrucViolation("version=3 tx is too big"))
        );
    }

    #[test]
    fn truc_child_over_child_max_vsize_is_rejected() {
        // TRUC_CHILD_MAX_VSIZE = 1,000 vB — tighter than the 10,000
        // standalone cap once the tx has an unconfirmed (TRUC) parent.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        let mut parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        parent.version = 3;
        let parent_id = parent.txid();
        pool.accept_tx(parent, &cs, NOW).unwrap();

        let mut child = spend_tx(
            OutPoint {
                txid: parent_id,
                vout: 0,
            },
            4_998_000_000,
            SEQ_FINAL,
        );
        child.version = 3;
        child.outputs[0].script_pubkey = Script::new(vec![0u8; 1_200]); // > 1,000 vB, < 10,000
        assert_eq!(
            pool.accept_tx(child, &cs, NOW),
            Err(MempoolReject::TrucViolation(
                "version=3 child tx is too big"
            ))
        );
    }

    #[test]
    fn truc_non_v3_cannot_spend_v3_parent() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        let mut parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        parent.version = 3;
        let parent_id = parent.txid();
        pool.accept_tx(parent, &cs, NOW).unwrap();

        // Ordinary v2 child of a v3 (TRUC) parent.
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
            Err(MempoolReject::TrucViolation(
                "non-version=3 tx cannot spend from version=3 tx"
            ))
        );
    }

    #[test]
    fn truc_v3_cannot_spend_non_v3_parent() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        let parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL); // v2
        let parent_id = parent.txid();
        pool.accept_tx(parent, &cs, NOW).unwrap();

        let mut child = spend_tx(
            OutPoint {
                txid: parent_id,
                vout: 0,
            },
            4_998_000_000,
            SEQ_FINAL,
        );
        child.version = 3;
        assert_eq!(
            pool.accept_tx(child, &cs, NOW),
            Err(MempoolReject::TrucViolation(
                "version=3 tx cannot spend from non-version=3 tx"
            ))
        );
    }

    #[test]
    fn truc_second_child_evicts_sibling_when_it_outpays_it() {
        // A TRUC parent may have only one unconfirmed descendant; a
        // second, unrelated child (not a direct double-spend of the
        // first) may still land by evicting the sole existing sibling —
        // Core's opportunistic sibling eviction — provided it clears the
        // ordinary replacement fee rule against it.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        let mut parent = fan_tx(mature_outpoint(&blocks, 1), 2, 2_000_000_000);
        parent.version = 3;
        let parent_id = parent.txid();
        pool.accept_tx(parent, &cs, NOW).unwrap();

        let mut child1 = spend_tx(
            OutPoint {
                txid: parent_id,
                vout: 0,
            },
            1_999_999_000, // fee 1,000
            SEQ_FINAL,
        );
        child1.version = 3;
        let child1_id = child1.txid();
        pool.accept_tx(child1, &cs, NOW).unwrap();

        let mut child2 = spend_tx(
            OutPoint {
                txid: parent_id,
                vout: 1,
            },
            1_900_000_000, // fee 100,000,000 — comfortably outpays child1
            SEQ_FINAL,
        );
        child2.version = 3;
        let child2_id = child2.txid();
        assert_eq!(pool.accept_tx(child2, &cs, NOW), Ok(child2_id));
        assert!(pool.get(&child1_id).is_none(), "sibling evicted");
        assert!(pool.get(&child2_id).is_some());
        assert!(pool.get(&parent_id).is_some());
    }

    #[test]
    fn truc_ancestor_limit_rejects_third_generation() {
        // TRUC_ANCESTOR_LIMIT = 2 (the tx plus at most one unconfirmed
        // ancestor) — a v3 grandchild of a v3 grandparent (both already
        // pooled) has 2 unconfirmed ancestors, one too many.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        let mut grandparent = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        grandparent.version = 3;
        let gp_id = grandparent.txid();
        pool.accept_tx(grandparent, &cs, NOW).unwrap();

        let mut parent = spend_tx(
            OutPoint {
                txid: gp_id,
                vout: 0,
            },
            4_998_000_000,
            SEQ_FINAL,
        );
        parent.version = 3;
        let parent_id = parent.txid();
        pool.accept_tx(parent, &cs, NOW).unwrap();

        let mut child = spend_tx(
            OutPoint {
                txid: parent_id,
                vout: 0,
            },
            4_997_000_000,
            SEQ_FINAL,
        );
        child.version = 3;
        assert_eq!(
            pool.accept_tx(child, &cs, NOW),
            Err(MempoolReject::TrucViolation(
                "tx would have too many ancestors"
            ))
        );
    }

    #[test]
    fn rbf_replacement_with_adequate_bump() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
    fn template_mines_by_ancestor_feerate() {
        // Core's addPackageTxs: a low-fee parent rides its high-fee
        // child's package rate — the whole package lands ahead of a
        // standalone tx whose own rate sits between the two.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        // parent: 1 sat/vB-ish (tiny fee); child: enormous fee.
        let parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_900_000, SEQ_FINAL);
        let pid = parent.txid();
        let child = spend_tx(OutPoint { txid: pid, vout: 0 }, 1_000_000_000, SEQ_FINAL);
        let cid = child.txid();
        // standalone: mid-range fee — higher than parent alone, far
        // below the (parent+child) package rate.
        let solo = spend_tx(mature_outpoint(&blocks, 2), 4_000_000_000, SEQ_FINAL);
        let sid = solo.txid();
        pool.accept_tx(parent, &cs, NOW).unwrap();
        pool.accept_tx(child, &cs, NOW).unwrap();
        pool.accept_tx(solo, &cs, NOW).unwrap();

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
        assert_eq!(
            order,
            vec![pid, cid, sid],
            "package rate (~2B/220vB) beats the standalone's own rate"
        );
    }

    #[test]
    fn template_prioritise_lifts_the_whole_package() {
        // `prioritisetransaction`'s delta lands in the *modified* fee,
        // which the ancestor-feerate score uses — a prioritized child
        // pulls its parent forward too.
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        let parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_990_000, SEQ_FINAL);
        let pid = parent.txid();
        let child = spend_tx(OutPoint { txid: pid, vout: 0 }, 4_999_000_000, SEQ_FINAL);
        let cid = child.txid();
        let solo = spend_tx(mature_outpoint(&blocks, 2), 4_000_000_000, SEQ_FINAL);
        let sid = solo.txid();
        pool.accept_tx(parent, &cs, NOW).unwrap();
        pool.accept_tx(child, &cs, NOW).unwrap();
        pool.accept_tx(solo, &cs, NOW).unwrap();
        // Solo outranks both alone; lift the package via the child.
        pool.prioritise(&cid, 5_000_000_000);

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
        assert_eq!(order, vec![pid, cid, sid]);
    }

    #[test]
    fn template_rejects_oversized_coinbase_weight() {
        // node/miner.cpp's BlockAssembler budgets a fixed weight for the
        // coinbase during selection, but a caller-supplied
        // `miner_script_pubkey` isn't bounded by that budget — the real,
        // assembled block must still be checked before it's handed out
        // as a template.
        let (cs, _blocks) = chainstate_at(101);
        let pool = permissive_pool();
        let huge_script = Script::new(vec![0u8; 1_100_000]);
        let err = pool
            .build_template(&cs, huge_script, NOW + 120)
            .unwrap_err();
        assert!(matches!(
            err,
            template::TemplateError::WeightExceeded { .. }
        ));
    }

    #[test]
    fn template_rejects_oversized_coinbase_sigops() {
        // A script that is tiny by weight but stuffed with
        // non-accurate-counted OP_CHECKMULTISIG (20 sigops each, Core's
        // GetSigOpCount default) — the coinbase's own sigop cost alone
        // can blow MAX_BLOCK_SIGOPS_COST even though its weight is
        // negligible and the pool is empty.
        let (cs, _blocks) = chainstate_at(101);
        let pool = permissive_pool();
        let sigop_script = Script::new(vec![script::OP_CHECKMULTISIG; 2_000]);
        let err = pool
            .build_template(&cs, sigop_script, NOW + 120)
            .unwrap_err();
        assert!(matches!(
            err,
            template::TemplateError::SigOpsExceeded { .. }
        ));
    }

    #[test]
    fn mempool_persists_round_trip() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        let parent = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let pid = parent.txid();
        let child = spend_tx(OutPoint { txid: pid, vout: 0 }, 4_998_000_000, SEQ_FINAL);
        pool.accept_tx(parent, &cs, NOW).unwrap();
        pool.accept_tx(child, &cs, NOW).unwrap();

        let dir = std::env::temp_dir().join(format!("avila-mp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mempool.dat");
        assert_eq!(pool.save(&path).unwrap(), 2);

        let mut fresh = permissive_pool();
        fresh.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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

        let mut fresh = permissive_pool();
        fresh.set_require_standard(false);
        let (imported, skipped) = fresh.load(&path, &cs, NOW).unwrap();
        assert_eq!((imported, skipped), (2, 0), "passes resolve ordering");
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn mempool_load_skips_spent_and_truncated() {
        let (cs, blocks) = chainstate_at(101);
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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

        let mut fresh = permissive_pool();
        fresh.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
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

        let mut fresh = permissive_pool();
        fresh.set_require_standard(false);
        let (imported, skipped) = fresh.load(&path, &cs, NOW).unwrap();
        assert_eq!((imported, skipped), (1, 0));
        assert_eq!(fresh.entry(&txid).unwrap().fee_delta, 42_000);
        assert_eq!(fresh.deltas.get(&ghost), Some(&1_000));
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }

    /// A block carrying `coinbase + extra` txs — `block_on` variant for
    /// refill tests that need non-coinbase transactions on-chain.
    fn block_with(prev: &BlockHeader, height: u32, extra: Transaction, params: &Params) -> Block {
        let mut block = block_on(prev, height, params);
        block.transactions.push(extra);
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
            block.header.nonce += 1;
        }
        block
    }

    /// Reorg refill: the evicted block's non-coinbase txs re-enter the
    /// pool — Core's `DisconnectedBlockTransactions` drain.
    #[test]
    fn refill_readmits_disconnected_spends() {
        let (mut cs, blocks) = chainstate_at(101);
        let params = Network::Regtest.params();
        let spend = spend_tx(mature_outpoint(&blocks, 1), 4_999_000_000, SEQ_FINAL);
        let spend_txid = spend.txid();
        let b102 = block_with(&blocks[100].header, 102, spend, &params);
        cs.accept_block(&b102, NOW).unwrap();

        // A heavier rival evicts b102 — its spend is unconfirmed again.
        let c102 = block_on(&blocks[100].header, 102, &params);
        let c103 = block_on(&c102.header, 103, &params);
        cs.accept_block(&c102, NOW).unwrap();
        cs.accept_block(&c103, NOW).unwrap();
        let gone = cs.take_disconnected();
        assert_eq!(gone, vec![b102.block_hash()]);

        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        assert_eq!(
            pool.refill_from_disconnected(&gone, &cs, NOW, true, usize::MAX),
            1
        );
        assert!(pool.get(&spend_txid).is_some());
    }

    /// A resurrected tx whose input the new chain spent drops — and
    /// takes its in-pool descendants with it (Core's `removeRecursive`
    /// on a failed re-add), even though the failed tx was never pooled.
    #[test]
    fn refill_drops_conflicts_and_dependents() {
        let (mut cs, blocks) = chainstate_at(101);
        let params = Network::Regtest.params();
        let op = mature_outpoint(&blocks, 1);
        let losing = spend_tx(op, 4_999_000_000, SEQ_FINAL);
        let losing_txid = losing.txid();
        let b102 = block_with(&blocks[100].header, 102, losing, &params);
        cs.accept_block(&b102, NOW).unwrap();

        // While b102 is connected its outputs are UTXOs — a child
        // spending one is admissible to the pool.
        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        let child = spend_tx(
            OutPoint {
                txid: losing_txid,
                vout: 0,
            },
            4_998_000_000,
            SEQ_FINAL,
        );
        let child_txid = child.txid();
        pool.accept_tx(child, &cs, NOW).unwrap();

        // The winning branch double-spends the coinbase: the losing
        // spend can never come back and the pooled child is dangling.
        let winner = spend_tx(op, 4_999_500_000, SEQ_FINAL);
        let c102 = block_with(&blocks[100].header, 102, winner, &params);
        let c103 = block_on(&c102.header, 103, &params);
        cs.accept_block(&c102, NOW).unwrap();
        cs.accept_block(&c103, NOW).unwrap();
        let gone = cs.take_disconnected();
        assert_eq!(gone, vec![b102.block_hash()]);

        assert_eq!(
            pool.refill_from_disconnected(&gone, &cs, NOW, true, usize::MAX),
            0
        );
        assert!(pool.get(&losing_txid).is_none());
        assert!(pool.get(&child_txid).is_none());
        assert!(pool.is_empty());
    }

    /// `invalidateblock` semantics: only the first `max_blocks`
    /// disconnect-order blocks feed the pool — Core's
    /// `(++disconnected <= 10)` gate on deep invalidations.
    #[test]
    fn refill_caps_invalidation_depth() {
        let (mut cs, blocks) = chainstate_at(101);
        let params = Network::Regtest.params();
        // Blocks h102..h113 each carry one spend of a distinct mature
        // coinbase (h1..h12) so none conflict.
        let mut txs = Vec::new();
        let mut prev = blocks[100].header;
        for i in 0..12usize {
            let h = 102 + i as u32;
            let spend = spend_tx(mature_outpoint(&blocks, i + 1), 4_999_000_000, SEQ_FINAL);
            txs.push(spend.txid());
            let b = block_with(&prev, h, spend, &params);
            cs.accept_block(&b, NOW).unwrap();
            prev = b.header;
        }
        // Invalidate h102 — twelve blocks disconnect, but the refill cap
        // keeps the deepest two out of the pool.
        let target = cs.chain()[102];
        assert_eq!(cs.invalidate_block(&target), Ok(Some(12)));
        let gone = cs.take_disconnected();
        assert_eq!(gone.len(), 12);

        let mut pool = permissive_pool();
        pool.set_require_standard(false);
        let n = pool.refill_from_disconnected(&gone, &cs, NOW, false, 10);
        // Disconnect order is tip-first: h113's spend feeds first,
        // h103/h102's are past the cap.
        assert_eq!(n, 10);
        assert_eq!(pool.len(), 10);
        assert!(pool.get(&txs[11]).is_some());
        assert!(pool.get(&txs[0]).is_none());
    }
}

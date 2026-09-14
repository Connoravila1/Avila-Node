//! The UTXO set and stateful block connection — Core's `ConnectBlock` /
//! `DisconnectBlock` and the `CCoinsView` layer beneath them.
//!
//! [`connect_block`] applies a block whose header is already in the
//! [`HeaderTree`], whose context-free checks ([`crate::check::check_block`]) and
//! contextual checks ([`crate::check::contextual_check_block`]) have passed, and
//! whose parent is the UTXO set's tip. It enforces the UTXO-dependent consensus
//! rules in Core's `ConnectBlock` order:
//!
//! 1. BIP30 duplicate-output protection,
//! 2. per-transaction input availability, coinbase maturity, value ranges, and
//!    fees (`Consensus::CheckTxInputs`),
//! 3. BIP68 sequence locks (`SequenceLocks`, only when CSV is active at the
//!    block's height),
//! 4. UTXO-dependent sigop cost (`GetTransactionSigOpCost`: legacy always,
//!    P2SH/witness under their flags) against `MAX_BLOCK_SIGOPS_COST`,
//! 5. the coinbase's total value against `subsidy + fees` (`bad-cb-amount`),
//!
//! and records the state transition as a [`BlockUndo`] so
//! [`disconnect_block`] can reverse it exactly.
//!
//! Two deliberate departures from Core's mechanism (identical verdicts, cleaner
//! machinery):
//!
//! * **Atomicity without a cache layer.** Core applies updates to a
//!   `CCoinsViewCache` mid-loop and discards the cache on failure. This
//!   implementation applies directly to the [`UtxoSet`] but records undo data
//!   as it goes; on any failure it un-applies the partial work, so callers can
//!   never observe a half-connected block.
//! * **No script execution.** `CheckInputScripts` is the one `ConnectBlock`
//!   step this module does not implement — it requires the script interpreter.
//!   A block that passes [`connect_block`] is *provisionally* connected: every
//!   non-script consensus rule held, but script validity is a separate gate
//!   that must still pass before the block is truly accepted.
//!
//! [`HeaderTree`]: crate::chain::HeaderTree

use std::collections::HashMap;

use crate::block::{Block, WITNESS_SCALE_FACTOR};
use crate::chain::HeaderTree;
use crate::check::{MAX_BLOCK_SIGOPS_COST, MAX_MONEY};
use crate::hash::{BlockHash, Txid};
use crate::params::Params;
use crate::script::{ScriptFlags, block_script_flags, count_witness_sig_ops};
use crate::transaction::{OutPoint, Transaction, TxOut};

/// `consensus/coinbase.h`'s `COINBASE_MATURITY`: a coinbase output is spendable
/// only once `spend_height - coin_height >= 100`.
pub const COINBASE_MATURITY: u32 = 100;

/// Core `validation.cpp`'s `BIP34_IMPLIES_BIP30_LIMIT`: at this height and
/// above the BIP30 scan runs unconditionally — the "BIP34 implies BIP30"
/// optimization is unsound beyond it (coinbases exist whose *indicated* height
/// exceeds their real one, enabling future duplicate coinbases; see the
/// exhaustive comment in Core's `ConnectBlock`).
const BIP34_IMPLIES_BIP30_LIMIT: u32 = 1_983_702;

/// The two mainnet blocks whose coinbase transactions duplicate earlier
/// coinbases — Core's `IsBIP30Repeat`. BIP30 enforcement is skipped for them.
/// Display-order hashes: `00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec`
/// (91842) and `00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721`
/// (91880).
const BIP30_REPEAT_BLOCKS: [(u32, BlockHash); 2] = [
    (
        91_842,
        BlockHash::from_bytes([
            0xec, 0xca, 0xe0, 0x00, 0xe3, 0xc8, 0xe4, 0xe0, 0x93, 0x93, 0x63, 0x60, 0x43, 0x1f,
            0x3b, 0x76, 0x03, 0xc5, 0x63, 0xc1, 0xff, 0x61, 0x81, 0x39, 0x0a, 0x4d, 0x0a, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]),
    ),
    (
        91_880,
        BlockHash::from_bytes([
            0x21, 0xd7, 0x7c, 0xcb, 0x4c, 0x08, 0x38, 0x6a, 0x04, 0xac, 0x01, 0x96, 0xae, 0x10,
            0xf6, 0xa1, 0xd2, 0xc2, 0xa3, 0x77, 0x55, 0x8c, 0xa1, 0x90, 0xf1, 0x43, 0x07, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]),
    ),
];

/// BIP68's `nSequence` disable flag — a sequence with bit 31 set is not a
/// relative lock (`CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG`).
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;
/// BIP68's `nSequence` type flag — set means the masked value counts 512-second
/// units (`CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG`).
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
/// BIP68's `nSequence` value mask (`CTxIn::SEQUENCE_LOCKTIME_MASK`).
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000_ffff;
/// BIP68's time-lock granularity shift (`CTxIn::SEQUENCE_LOCKTIME_GRANULARITY`
/// = 9): masked time-lock values are shifted left by 9 to get seconds.
pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;
/// The minimum transaction `version` for which BIP68 relative locks are
/// enforced.
pub const SEQUENCE_LOCKS_MIN_VERSION: u32 = 2;

/// `true` if `value` is inside Core's `MoneyRange` (`0 <= value <= MAX_MONEY`).
fn money_range(value: i64) -> bool {
    (0..=MAX_MONEY).contains(&value)
}

/// One spendable output tracked in the [`UtxoSet`] — Core's `Coin`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Coin {
    /// The output's value and locking script.
    pub out: TxOut,
    /// The height of the block that created this coin — coinbase maturity and
    /// BIP68 relative-lock evaluation need it.
    pub height: u32,
    /// `true` when the creating transaction was a coinbase — maturity applies.
    pub coinbase: bool,
}

/// The set of unspent transaction outputs — a flat `OutPoint → Coin` map with
/// Core's `CCoinsView` semantics but no cache layering.
///
/// Invariants, matching `AddCoin`/`SpendCoin`:
///
/// * unspendable outputs ([`Script::is_unspendable`]) are never stored;
/// * a spent coin is removed entirely — Core's spent-tombstone/`FRESH`
///   bookkeeping exists for cache flushing, which this type doesn't do.
///
/// [`Script::is_unspendable`]: crate::script::Script::is_unspendable
#[derive(Clone, Default, Debug)]
pub struct UtxoSet {
    map: HashMap<OutPoint, Coin>,
}

impl UtxoSet {
    /// An empty UTXO set — the state at genesis. The genesis block is never
    /// connected (Core's chainstate starts empty and never applies it), so its
    /// outputs are unspendable.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of tracked coins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if no coins are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The coin at `outpoint`, if present (Core's `AccessCoin` for an unspent
    /// entry — there are no spent tombstones to distinguish).
    #[must_use]
    pub fn get(&self, outpoint: &OutPoint) -> Option<&Coin> {
        self.map.get(outpoint)
    }

    /// `true` if `outpoint` holds a coin (Core's `HaveCoin`).
    #[must_use]
    pub fn have(&self, outpoint: &OutPoint) -> bool {
        self.map.contains_key(outpoint)
    }

    /// Inserts a coin directly — the staging hook for tests and future
    /// chainstate seeding. Bypasses the unspendable check; the caller is
    /// responsible for the invariant.
    pub fn insert_synthetic(&mut self, outpoint: OutPoint, coin: Coin) {
        self.map.insert(outpoint, coin);
    }

    /// Adds `tx`'s outputs at `height`, recording undo into `undo` — Core's
    /// `AddCoins`. Unspendable outputs are skipped (Core's `AddCoin` early
    /// return). A coinbase output may overwrite an existing entry (the BIP30
    /// repeat blocks require it — Core passes `possible_overwrite = fCoinbase`);
    /// overwritten coins land in `undo.overwritten`. A *non-coinbase* overwrite
    /// of an unspent coin is a BIP30 violation the caller's scan should already
    /// have rejected — it surfaces as [`ConnectError::Internal`], not Core's
    /// `logic_error` abort.
    fn add_tx_outputs(
        &mut self,
        tx: &Transaction,
        height: u32,
        undo: &mut TxUndo,
    ) -> Result<(), ConnectError> {
        let txid = tx.txid();
        let coinbase = tx.is_coinbase();
        for (vout, out) in tx.outputs.iter().enumerate() {
            if out.script_pubkey.is_unspendable() {
                continue;
            }
            let outpoint = OutPoint {
                txid,
                vout: vout as u32,
            };
            let coin = Coin {
                out: out.clone(),
                height,
                coinbase,
            };
            if let Some(previous) = self.map.insert(outpoint, coin) {
                if !coinbase {
                    // Restore the entry so rollback sees pre-tx state.
                    self.map.insert(outpoint, previous);
                    return Err(ConnectError::Internal(
                        "non-coinbase tx overwrote an unspent coin past the BIP30 scan",
                    ));
                }
                undo.overwritten.push((outpoint, previous));
            }
        }
        Ok(())
    }

    /// Removes the coin at `outpoint`, returning it (Core's `SpendCoin` with
    /// `moveout`). `None` when absent.
    fn spend(&mut self, outpoint: &OutPoint) -> Option<Coin> {
        self.map.remove(outpoint)
    }
}

/// The undo data for one transaction — everything needed to reverse its UTXO
/// effects (Core's `CTxUndo`).
#[derive(Clone, Default, Debug)]
pub struct TxUndo {
    /// The coins this transaction spent, in input order (Core's `vprevout`).
    /// Empty for the coinbase.
    pub spent: Vec<Coin>,
    /// Pre-existing coins this transaction's outputs overwrote — only possible
    /// for the BIP30-repeat coinbases; empty in normal operation. Restored on
    /// disconnect after this tx's outputs are removed.
    pub overwritten: Vec<(OutPoint, Coin)>,
}

/// The undo data for a whole block: one [`TxUndo`] per transaction —
/// `undo.txs[i]` belongs to `block.transactions[i]`, the coinbase included.
///
/// Core's on-disk `CBlockUndo` has `vtx.size() - 1` entries (the coinbase
/// spends nothing, so nothing needs restoring) — which is *why* its
/// `DisconnectBlock` needs the `IsBIP30Unspendable` exceptions at heights
/// 91722/91812: a repeat-block coinbase overwrite can't be undone without a
/// record of the overwritten coin. This in-memory layout keeps the coinbase's
/// entry instead, so [`disconnect_block`] restores even those blocks exactly.
/// Mapping to Core's n−1 layout is a serialization concern for the storage
/// layer, not a state-correctness one.
#[derive(Clone, Default, Debug)]
pub struct BlockUndo {
    /// Undo records for `block.transactions`, in block order.
    pub txs: Vec<TxUndo>,
}

/// Everything [`connect_block`] needs from outside the UTXO set — the
/// candidate's already-inserted header context. Because the block's header
/// must be in `tree` to construct a usable context, height and ancestry are
/// always consistent with the header the caller validated.
#[derive(Clone, Copy)]
pub struct ConnectContext<'a> {
    /// The network's consensus parameters.
    pub params: &'a Params,
    /// The header tree containing the candidate's header (inserted, and thereby
    /// header-validated, before connect runs).
    pub tree: &'a HeaderTree,
    /// The candidate block's hash — locates its `HeaderNode`, from which the
    /// block's height and ancestor chain derive.
    pub block_hash: BlockHash,
}

/// A consensus or internal failure while connecting a block. Every
/// consensus-visible variant maps to the reject reason Core's
/// `ConnectBlock`/`CheckTxInputs` reports via [`ConnectError::reason`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ConnectError {
    /// `ctx.tree` does not contain `ctx.block_hash` — a caller bug; the header
    /// must be inserted (and thereby header-validated) before connecting.
    UnknownBlock,
    /// The candidate's parent is not in `ctx.tree` — the block must extend a
    /// known header.
    OrphanBlock,
    /// A transaction spends an outpoint not present in the UTXO set
    /// (`bad-txns-inputs-missingorspent`).
    InputsMissingOrSpent,
    /// A transaction spends a coinbase output before [`COINBASE_MATURITY`]
    /// (`bad-txns-premature-spend-of-coinbase`). `depth` is
    /// `spend_height - coin_height`.
    PrematureCoinbaseSpend { depth: u32 },
    /// An input's value, or the running sum of input values, is outside
    /// `MoneyRange` (`bad-txns-inputvalues-outofrange`).
    InputValuesOutOfRange,
    /// A transaction's outputs exceed its inputs (`bad-txns-in-belowout`).
    InBelowOut,
    /// A transaction's fee is outside `MoneyRange` (`bad-txns-fee-outofrange`).
    /// Unreachable for a tx whose inputs and outputs each passed range checks
    /// — kept for parity with `CheckTxInputs`.
    FeeOutOfRange,
    /// The block's accumulated fees left `MoneyRange`
    /// (`bad-txns-accumulated-fee-outofrange`).
    AccumulatedFeeOutOfRange,
    /// The block creates an output at an outpoint already unspent in the UTXO
    /// set — a BIP30 violation (`bad-txns-BIP30`).
    Bip30(OutPoint),
    /// The block's transaction sigop cost exceeds `MAX_BLOCK_SIGOPS_COST`
    /// (`bad-blk-sigops`).
    SigopsExceeded,
    /// A transaction's BIP68 sequence locks are not satisfied at this block's
    /// position (`bad-txns-nonfinal`).
    NotFinal,
    /// The coinbase pays more than `subsidy + fees` (`bad-cb-amount`).
    CoinbaseAmount { actual: i64, limit: i64 },
    /// An internal inconsistency Core reaches via `assert`/`logic_error` (e.g.
    /// a non-coinbase output overwrite that the BIP30 scan should have
    /// rejected). Not producible through a correctly-ordered pipeline.
    Internal(&'static str),
}

impl ConnectError {
    /// The Core `state.Invalid(...)` reason string for this error — the same
    /// vocabulary the reference daemon returns over `submitblock`. Internal
    /// variants report `"internal"`: they have no Core reject reason because
    /// Core never surfaces them as validation failures.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::UnknownBlock | Self::OrphanBlock | Self::Internal(_) => "internal",
            Self::InputsMissingOrSpent => "bad-txns-inputs-missingorspent",
            Self::PrematureCoinbaseSpend { .. } => "bad-txns-premature-spend-of-coinbase",
            Self::InputValuesOutOfRange => "bad-txns-inputvalues-outofrange",
            Self::InBelowOut => "bad-txns-in-belowout",
            Self::FeeOutOfRange => "bad-txns-fee-outofrange",
            Self::AccumulatedFeeOutOfRange => "bad-txns-accumulated-fee-outofrange",
            Self::Bip30(_) => "bad-txns-BIP30",
            Self::SigopsExceeded => "bad-blk-sigops",
            Self::NotFinal => "bad-txns-nonfinal",
            Self::CoinbaseAmount { .. } => "bad-cb-amount",
        }
    }
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownBlock => write!(f, "connect called on a header not in the tree"),
            Self::OrphanBlock => write!(f, "block's parent is not in the tree"),
            Self::InputsMissingOrSpent => write!(f, "inputs missing or already spent"),
            Self::PrematureCoinbaseSpend { depth } => {
                write!(f, "tried to spend coinbase at depth {depth}")
            }
            Self::InputValuesOutOfRange => write!(f, "input value out of range"),
            Self::InBelowOut => write!(f, "value in < value out"),
            Self::FeeOutOfRange => write!(f, "fee out of range"),
            Self::AccumulatedFeeOutOfRange => write!(f, "accumulated fee out of range"),
            Self::Bip30(out) => write!(f, "tried to overwrite unspent output {out:?}"),
            Self::SigopsExceeded => write!(f, "too many sigops"),
            Self::NotFinal => write!(f, "contains a non-BIP68-final transaction"),
            Self::CoinbaseAmount { actual, limit } => {
                write!(
                    f,
                    "coinbase pays too much (actual={actual} vs limit={limit})"
                )
            }
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// `consensus/tx_verify.h`'s `GetBlockSubsidy`: `50 BTC >> (height /
/// halving_interval)`, `0` once the shift count would be 64 or more. A
/// `subsidy_halving_interval` of `0` (never produced by the built-in networks)
/// yields the unhalved subsidy rather than panicking.
#[must_use]
pub fn block_subsidy(height: u32, params: &Params) -> i64 {
    let halvings = height
        .checked_div(params.subsidy_halving_interval)
        .unwrap_or(0);
    if halvings >= 64 {
        return 0;
    }
    (50 * 100_000_000i64) >> halvings
}

/// Core's `IsBIP30Repeat`: `true` for the two historical blocks whose coinbases
/// legitimately duplicated earlier ones.
fn is_bip30_repeat(height: u32, hash: &BlockHash) -> bool {
    BIP30_REPEAT_BLOCKS
        .iter()
        .any(|(h, repeat_hash)| *h == height && repeat_hash == hash)
}

/// Whether the BIP30 duplicate-output scan runs for this block — Core's
/// `fEnforceBIP30 || height >= BIP34_IMPLIES_BIP30_LIMIT`:
///
/// * always above the limit;
/// * never for the two repeat blocks;
/// * otherwise, skipped only when the chain has passed `bip34_height` *and* the
///   ancestor of the candidate's parent at that height is the real chain's
///   block (`consensus.BIP34Hash`) — i.e. we're on the known chain where BIP34
///   already prevents future duplicate coinbases. A missing ancestor (chain
///   not yet that tall) or a missing configured hash (non-mainnet networks use
///   the null `uint256`, which matches nothing) keeps the scan on.
fn enforce_bip30(height: u32, hash: &BlockHash, ctx: &ConnectContext<'_>) -> bool {
    if height >= BIP34_IMPLIES_BIP30_LIMIT {
        return true;
    }
    if is_bip30_repeat(height, hash) {
        return false;
    }
    let Some(bip34_hash) = ctx.params.bip34_hash else {
        return true;
    };
    let Some(node) = ctx.tree.get(&ctx.block_hash) else {
        return true;
    };
    match ctx
        .tree
        .get_ancestor(&node.header.prev_block_hash, ctx.params.bip34_height)
    {
        Some(ancestor) => ancestor.hash() != bip34_hash,
        None => true,
    }
}

/// Core's `Consensus::CheckTxInputs` plus the per-input coin lookup it
/// presumes: every input's outpoint must name an unspent coin
/// (`inputs.HaveInputs` — checked across *all* inputs first, so a missing
/// input anywhere beats a maturity failure on an earlier one), coinbase coins
/// must have matured, each coin's value and the running input total must stay
/// inside `MoneyRange`, and `value_in >= value_out`. Returns the spent coins
/// (in input order — sequence locks and sigop counting consume them) and the
/// tx's fee.
///
/// Read-only against `utxo`; the caller applies the spends after all checks.
fn check_tx_inputs(
    tx: &Transaction,
    utxo: &UtxoSet,
    spend_height: u32,
) -> Result<(Vec<Coin>, i64), ConnectError> {
    let mut spent = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        match utxo.get(&input.previous_output) {
            Some(coin) => spent.push(coin.clone()),
            None => return Err(ConnectError::InputsMissingOrSpent),
        }
    }
    let mut value_in: i64 = 0;
    for coin in &spent {
        // A coin's height never exceeds the spend height for a set built by
        // connect_block; saturating_sub keeps a synthetic caller-supplied set
        // from panicking instead of erroring.
        let depth = spend_height.saturating_sub(coin.height);
        if coin.coinbase && depth < COINBASE_MATURITY {
            return Err(ConnectError::PrematureCoinbaseSpend { depth });
        }
        // Core accumulates then MoneyRange-checks; each coin's value is itself
        // range-checked, so the checked add only trips on i64 overflow — past
        // MAX_MONEY either way.
        value_in = match value_in.checked_add(coin.out.value) {
            Some(total) => total,
            None => return Err(ConnectError::InputValuesOutOfRange),
        };
        if !money_range(coin.out.value) || !money_range(value_in) {
            return Err(ConnectError::InputValuesOutOfRange);
        }
    }
    // GetValueOut's range is guaranteed by CheckTransaction's
    // bad-txns-vout-* / -txouttotal checks upstream of connect.
    let mut value_out: i64 = 0;
    for out in &tx.outputs {
        value_out = match value_out.checked_add(out.value) {
            Some(total) => total,
            None => {
                return Err(ConnectError::Internal(
                    "output total overflowed i64 past CheckTransaction",
                ));
            }
        };
    }
    if value_in < value_out {
        return Err(ConnectError::InBelowOut);
    }
    let fee = value_in - value_out;
    if !money_range(fee) {
        return Err(ConnectError::FeeOutOfRange);
    }
    Ok((spent, fee))
}

/// Core's `CalculateSequenceLocks` + `EvaluateSequenceLocks`: whether `tx`'s
/// BIP68 relative locks are satisfied at the candidate's position. `spent`
/// holds each input's coin in input order (their `height` is Core's
/// `prevHeights`); `parent_mtp` is the candidate's parent's median-time-past
/// (Core's `block.pprev->GetMedianTimePast()`). The caller gates this on CSV
/// being active at the block's height — inside, version < 2 short-circuits as
/// unlocked.
fn bip68_locks_satisfied(
    tx: &Transaction,
    spent: &[Coin],
    height: u32,
    parent_mtp: u32,
    ctx: &ConnectContext<'_>,
) -> bool {
    if tx.version < SEQUENCE_LOCKS_MIN_VERSION {
        return true;
    }
    // nLockTime semantics: the computed values are the last *invalid*
    // height/time, so -1 means "always valid".
    let mut min_height: i64 = -1;
    let mut min_time: i64 = -1;
    for (input, coin) in tx.inputs.iter().zip(spent.iter()) {
        if input.sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
            continue;
        }
        if input.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 {
            // MTP of the ancestor at coin_height - 1 (the genesis itself for a
            // height-0 coin), then the masked value in 512-second units, minus
            // one to keep nLockTime's last-invalid semantics.
            let ancestor_height = coin.height.saturating_sub(1);
            let coin_time = ctx
                .tree
                .get_ancestor(&ctx.block_hash, ancestor_height)
                .and_then(|node| ctx.tree.median_time_past(&node.hash()))
                .map(i64::from);
            let Some(coin_time) = coin_time else {
                return false;
            };
            let lock =
                i64::from(input.sequence & SEQUENCE_LOCKTIME_MASK) << SEQUENCE_LOCKTIME_GRANULARITY;
            min_time = min_time.max(coin_time + lock - 1);
        } else {
            let lock = i64::from(input.sequence & SEQUENCE_LOCKTIME_MASK);
            min_height = min_height.max(i64::from(coin.height) + lock - 1);
        }
    }
    // EvaluateSequenceLocks: fails when min_height >= block height, or
    // min_time >= the parent's median time past.
    if min_height >= i64::from(height) {
        return false;
    }
    min_time < i64::from(parent_mtp)
}

/// Core's `GetTransactionSigOpCost`: `legacy * WITNESS_SCALE_FACTOR`, plus
/// `p2sh * WSF` when the P2SH flag is set, plus per-input
/// `CountWitnessSigOps`. `spent` must be this tx's consumed coins in input
/// order — pass an empty slice for the coinbase (it returns after the legacy
/// term).
fn tx_sigop_cost(tx: &Transaction, spent: &[Coin], flags: ScriptFlags) -> u64 {
    let mut sigops = tx
        .inputs
        .iter()
        .map(|input| input.script_sig.sig_ops(false))
        .sum::<u64>()
        + tx.outputs
            .iter()
            .map(|out| out.script_pubkey.sig_ops(false))
            .sum::<u64>();
    sigops *= u64::from(WITNESS_SCALE_FACTOR as u32);
    if tx.is_coinbase() {
        return sigops;
    }
    if flags.contains(ScriptFlags::P2SH) {
        sigops += spent
            .iter()
            .zip(tx.inputs.iter())
            .filter(|(coin, _)| coin.out.script_pubkey.is_p2sh())
            .map(|(coin, input)| coin.out.script_pubkey.p2sh_sig_ops(&input.script_sig))
            .sum::<u64>()
            * u64::from(WITNESS_SCALE_FACTOR as u32);
    }
    for (input, coin) in tx.inputs.iter().zip(spent.iter()) {
        sigops += count_witness_sig_ops(
            &input.script_sig,
            &coin.out.script_pubkey,
            &input.witness,
            flags,
        );
    }
    sigops
}

/// One transaction applied mid-`connect_block`, with enough context to reverse
/// it if a later transaction fails.
struct AppliedTx {
    /// The index into `block.transactions`.
    index: usize,
    /// The undo record built while applying.
    undo: TxUndo,
}

/// Applies `block`'s UTXO effects and enforces the UTXO-dependent consensus
/// rules — Core's `ConnectBlock` minus `CheckInputScripts` (see the module
/// docs for the script boundary).
///
/// # Preconditions
///
/// * `block`'s header is already in `ctx.tree` — header checks,
///   [`crate::check::check_block`], and
///   [`crate::check::contextual_check_block`] have run (so the tx list is
///   non-empty, txid-unique, and individually valid);
/// * `utxo` is the state at the block's parent.
///
/// # Atomicity
///
/// On `Err`, `utxo` is restored to its pre-call state: applied work is rolled
/// back in place from the undo records — same net effect as Core's
/// discard-the-layered-cache approach without a cache layer.
///
/// # Errors
///
/// The first failing [`ConnectError`]; reject reasons match Core's
/// `ConnectBlock` vocabulary.
pub fn connect_block(
    block: &Block,
    utxo: &mut UtxoSet,
    ctx: &ConnectContext<'_>,
) -> Result<BlockUndo, ConnectError> {
    let Some(node) = ctx.tree.get(&ctx.block_hash) else {
        return Err(ConnectError::UnknownBlock);
    };
    let height = node.height;
    if ctx.tree.get(&node.header.prev_block_hash).is_none() {
        return Err(ConnectError::OrphanBlock);
    }
    // The parent's MTP is the BIP68 time-lock evaluation point (Core's
    // `block.pprev->GetMedianTimePast()`); the parent is in the tree, so this
    // cannot be missing.
    let Some(parent_mtp) = ctx.tree.median_time_past(&node.header.prev_block_hash) else {
        return Err(ConnectError::Internal("parent in tree without an MTP"));
    };

    let flags = block_script_flags(ctx.params, height, &ctx.block_hash);
    let csv_active = height >= ctx.params.csv_height;

    // BIP30 duplicate-output scan — against the pre-block view, before any
    // transaction is applied (Core's ConnectBlock ordering).
    if enforce_bip30(height, &ctx.block_hash, ctx) {
        for tx in &block.transactions {
            let txid = tx.txid();
            for vout in 0..tx.outputs.len() {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                if utxo.have(&outpoint) {
                    return Err(ConnectError::Bip30(outpoint));
                }
            }
        }
    }

    let mut applied: Vec<AppliedTx> = Vec::with_capacity(block.transactions.len());
    let mut fees: i64 = 0;
    let mut sigops_cost: u64 = 0;

    let result = (|| -> Result<(), ConnectError> {
        for (i, tx) in block.transactions.iter().enumerate() {
            let mut tx_undo = TxUndo::default();
            let mut spent = Vec::new();
            if !tx.is_coinbase() {
                let (spent_coins, fee) = check_tx_inputs(tx, utxo, height)?;
                spent = spent_coins;
                fees = match fees.checked_add(fee) {
                    Some(total) => total,
                    None => return Err(ConnectError::AccumulatedFeeOutOfRange),
                };
                if !money_range(fees) {
                    return Err(ConnectError::AccumulatedFeeOutOfRange);
                }
                if csv_active && !bip68_locks_satisfied(tx, &spent, height, parent_mtp, ctx) {
                    return Err(ConnectError::NotFinal);
                }
            }
            sigops_cost = sigops_cost.saturating_add(tx_sigop_cost(tx, &spent, flags));
            if sigops_cost > MAX_BLOCK_SIGOPS_COST {
                return Err(ConnectError::SigopsExceeded);
            }
            // Apply (Core's UpdateCoins): spend inputs, then add outputs.
            for (input, coin) in tx.inputs.iter().zip(spent.iter()) {
                let removed = utxo.spend(&input.previous_output);
                debug_assert!(
                    removed.is_some(),
                    "check_tx_inputs verified this coin exists"
                );
                tx_undo.spent.push(coin.clone());
            }
            utxo.add_tx_outputs(tx, height, &mut tx_undo)?;
            applied.push(AppliedTx {
                index: i,
                undo: tx_undo,
            });
        }
        let Some(coinbase) = block.transactions.first() else {
            return Err(ConnectError::Internal("empty block reached connect_block"));
        };
        let coinbase_out: i64 = coinbase.outputs.iter().map(|out| out.value).sum();
        let reward = fees.saturating_add(block_subsidy(height, ctx.params));
        if coinbase_out > reward {
            return Err(ConnectError::CoinbaseAmount {
                actual: coinbase_out,
                limit: reward,
            });
        }
        Ok(())
    })();

    match result {
        Ok(()) => Ok(BlockUndo {
            txs: applied.into_iter().map(|a| a.undo).collect(),
        }),
        Err(error) => {
            rollback(block, utxo, applied);
            Err(error)
        }
    }
}

/// Reverses the applied prefix of a failed `connect_block`, restoring `utxo`
/// to its pre-call state: each applied tx's outputs are removed, overwritten
/// coins restored, and spent inputs re-added — newest transaction first.
fn rollback(block: &Block, utxo: &mut UtxoSet, applied: Vec<AppliedTx>) {
    for applied_tx in applied.into_iter().rev() {
        let tx = &block.transactions[applied_tx.index];
        let txid: Txid = tx.txid();
        for (vout, out) in tx.outputs.iter().enumerate() {
            if out.script_pubkey.is_unspendable() {
                continue;
            }
            utxo.map.remove(&OutPoint {
                txid,
                vout: vout as u32,
            });
        }
        for (outpoint, coin) in applied_tx.undo.overwritten {
            utxo.map.insert(outpoint, coin);
        }
        for (input, coin) in tx.inputs.iter().zip(applied_tx.undo.spent.iter()) {
            utxo.map.insert(input.previous_output, coin.clone());
        }
    }
}

/// Reverses a connected block (Core's `DisconnectBlock` minus the on-disk undo
/// read and the "unclean" diagnostics): transactions undo in reverse order —
/// each tx's created outputs are removed, any overwritten coins restored, then
/// the tx's spent inputs re-added from `undo`.
///
/// `undo` must be the value [`connect_block`] returned for `block`.
///
/// # Errors
///
/// [`DisconnectError::Inconsistent`] if `undo` doesn't line up with the block.
pub fn disconnect_block(
    block: &Block,
    utxo: &mut UtxoSet,
    undo: &BlockUndo,
) -> Result<(), DisconnectError> {
    if undo.txs.len() != block.transactions.len() {
        return Err(DisconnectError::Inconsistent);
    }
    for i in (0..block.transactions.len()).rev() {
        let tx = &block.transactions[i];
        let txid = tx.txid();
        for (vout, out) in tx.outputs.iter().enumerate() {
            if out.script_pubkey.is_unspendable() {
                continue;
            }
            utxo.map.remove(&OutPoint {
                txid,
                vout: vout as u32,
            });
        }
        let tx_undo = &undo.txs[i];
        for (outpoint, coin) in &tx_undo.overwritten {
            utxo.map.insert(*outpoint, coin.clone());
        }
        for (input, coin) in tx.inputs.iter().zip(tx_undo.spent.iter()) {
            utxo.map.insert(input.previous_output, coin.clone());
        }
    }
    Ok(())
}

/// A `disconnect_block` failure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DisconnectError {
    /// The undo records don't line up with the block's transaction count.
    Inconsistent,
}

impl std::fmt::Display for DisconnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inconsistent => write!(f, "undo data inconsistent with block"),
        }
    }
}

impl std::error::Error for DisconnectError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::block::Block;
    use crate::header::BlockHeader;
    use crate::params::Network;
    use crate::pow;
    use crate::script;
    use crate::transaction::{Script, TxIn, Witness};

    /// Regtest with a trivially-easy PoW limit (chain.rs's `easy_params`).
    fn easy_params() -> Params {
        let mut params = Network::Regtest.params();
        params.pow_limit = crate::arith::Target(crate::arith::U256::MAX);
        params.allow_min_difficulty_blocks = false;
        params
    }

    fn txin(prev: OutPoint, script_sig: Vec<u8>, sequence: u32) -> TxIn {
        TxIn {
            previous_output: prev,
            script_sig: Script::new(script_sig),
            sequence,
            witness: Witness::default(),
        }
    }

    fn txout(value: i64, script_pubkey: Vec<u8>) -> TxOut {
        TxOut {
            value,
            script_pubkey: Script::new(script_pubkey),
        }
    }

    const SEQUENCE_FINAL: u32 = 0xffff_ffff;
    const SUBSIDY: i64 = 50 * 100_000_000;
    /// Anyone-can-spend output script: a single `OP_TRUE`.
    const ANYONE: &[u8] = &[script::OP_1];

    /// A coinbase paying `value` to an anyone-can-spend output, with the BIP34
    /// height prefix and a second push so the scriptSig reaches the 2-byte
    /// minimum.
    fn coinbase(height: u32, value: i64) -> Transaction {
        let mut script_sig = script::push_int(i64::from(height));
        script_sig.push(script::OP_1);
        Transaction {
            version: 1,
            inputs: vec![txin(OutPoint::NULL, script_sig, SEQUENCE_FINAL)],
            outputs: vec![txout(value, ANYONE.to_vec())],
            lock_time: 0,
        }
    }

    /// Drafts a block over `txs` extending `parent` with `parent.time + 1`,
    /// the parent's bits, and a correct merkle root, then grinds the nonce
    /// until the header passes its own claimed target.
    fn block_on(parent: &BlockHeader, txs: Vec<Transaction>, params: &Params) -> Block {
        let mut block = Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: parent.hash(),
                merkle_root: parent.merkle_root,
                time: parent.time + 1,
                bits: parent.bits,
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

    /// A connected chain scaffold: the header tree plus the UTXO set and
    /// connected tip. `insert_and_connect` runs the whole pipeline each test
    /// also exercises.
    struct Chain {
        params: Params,
        tree: HeaderTree,
        utxo: UtxoSet,
        tip: BlockHash,
        tip_header: BlockHeader,
        now: u32,
    }

    impl Chain {
        fn new(params: Params) -> Self {
            let tree = HeaderTree::new(params);
            let tip = params.genesis_header.hash();
            let tip_header = params.genesis_header;
            // `now` far past genesis so the future-drift check never trips.
            Self {
                params,
                tree,
                utxo: UtxoSet::new(),
                tip,
                tip_header,
                now: u32::MAX / 2,
            }
        }

        /// The txid of the coinbase in `block` (the only output these test
        /// blocks' coinbases create).
        fn coinbase_outpoint(block: &Block) -> OutPoint {
            OutPoint {
                txid: block.transactions[0].txid(),
                vout: 0,
            }
        }

        /// Builds, inserts, and connects a block over `txs` extending the
        /// connected tip; returns the block (which the caller may inspect or
        /// disconnect).
        fn extend(&mut self, txs: Vec<Transaction>) -> Result<Block, ConnectError> {
            self.extend_on(self.tip_header, txs)
        }

        /// [`extend`] on an arbitrary parent — for forks and failure cases.
        fn extend_on(
            &mut self,
            parent: BlockHeader,
            txs: Vec<Transaction>,
        ) -> Result<Block, ConnectError> {
            let block = block_on(&parent, txs, &self.params);
            self.tree
                .insert(&block.header, self.now)
                .map_err(|_| ConnectError::Internal("header insert failed"))?;
            let ctx = ConnectContext {
                params: &self.params,
                tree: &self.tree,
                block_hash: block.block_hash(),
            };
            connect_block(&block, &mut self.utxo, &ctx)?;
            self.tip = block.block_hash();
            self.tip_header = block.header;
            Ok(block)
        }

        /// Grows the chain to `height` with coinbase-only blocks, returning
        /// their outpoints (index = block height).
        fn grow_to(&mut self, height: u32) -> Vec<OutPoint> {
            let mut coinbase_outs = Vec::with_capacity(height as usize);
            for h in 1..=height {
                let block = self
                    .extend(vec![coinbase(h, SUBSIDY)])
                    .unwrap_or_else(|e| panic!("connect h{h}: {e}"));
                coinbase_outs.push(Self::coinbase_outpoint(&block));
            }
            coinbase_outs
        }
    }

    // -- subsidy -------------------------------------------------------------

    #[test]
    fn subsidy_halving_schedule() {
        let params = Network::Mainnet.params();
        assert_eq!(block_subsidy(0, &params), SUBSIDY);
        assert_eq!(block_subsidy(209_999, &params), SUBSIDY);
        assert_eq!(block_subsidy(210_000, &params), SUBSIDY / 2);
        assert_eq!(block_subsidy(420_000, &params), SUBSIDY / 4);
        assert_eq!(block_subsidy(630_000, &params), SUBSIDY / 8);
        // 64 halvings: the shift would be UB in C++, so Core returns zero.
        assert_eq!(block_subsidy(210_000 * 64, &params), 0);
        let regtest = Network::Regtest.params();
        assert_eq!(block_subsidy(149, &regtest), SUBSIDY);
        assert_eq!(block_subsidy(150, &regtest), SUBSIDY / 2);
    }

    // -- basic connect / maturity --------------------------------------------

    #[test]
    fn connect_adds_coinbase_output() {
        let mut chain = Chain::new(easy_params());
        let block = chain.extend(vec![coinbase(1, SUBSIDY)]).unwrap();
        let outpoint = Chain::coinbase_outpoint(&block);
        let coin = chain.utxo.get(&outpoint).unwrap();
        assert!(coin.coinbase);
        assert_eq!(coin.height, 1);
        assert_eq!(coin.out.value, SUBSIDY);
        assert_eq!(chain.utxo.len(), 1);
    }

    #[test]
    fn premature_coinbase_spend_rejected() {
        let mut chain = Chain::new(easy_params());
        let block1 = chain.extend(vec![coinbase(1, SUBSIDY)]).unwrap();
        let cb1 = Chain::coinbase_outpoint(&block1);
        // Spend the height-1 coinbase at height 50: depth 49 < 100.
        for _h in 2..=49 {
            chain.extend(vec![coinbase(_h, SUBSIDY)]).unwrap();
        }
        let spend = Transaction {
            version: 1,
            inputs: vec![txin(cb1, vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(SUBSIDY - 1, ANYONE.to_vec())],
            lock_time: 0,
        };
        let err = chain
            .extend(vec![coinbase(50, SUBSIDY), spend])
            .unwrap_err();
        assert_eq!(
            err,
            ConnectError::PrematureCoinbaseSpend { depth: 49 },
            "reason: {}",
            err.reason()
        );
        assert_eq!(err.reason(), "bad-txns-premature-spend-of-coinbase");
    }

    #[test]
    fn mature_coinbase_spend_connects_and_counts_fee() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        // Spend the height-1 coinbase at height 101: depth exactly 100.
        let spend = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(SUBSIDY - 1000, ANYONE.to_vec())],
            lock_time: 0,
        };
        // The fee (1000) can go to the coinbase: pays subsidy + fees.
        let block = chain
            .extend(vec![coinbase(102, SUBSIDY + 1000), spend])
            .unwrap();
        assert!(!chain.utxo.have(&cb_outs[0]));
        let spend_txid = block.transactions[1].txid();
        let coin = chain
            .utxo
            .get(&OutPoint {
                txid: spend_txid,
                vout: 0,
            })
            .unwrap();
        assert_eq!(coin.out.value, SUBSIDY - 1000);
        assert!(!coin.coinbase);
    }

    // -- value rules ----------------------------------------------------------

    #[test]
    fn missing_and_spent_inputs_rejected() {
        let mut chain = Chain::new(easy_params());
        chain.grow_to(2);
        let phantom = Transaction {
            version: 1,
            inputs: vec![txin(
                OutPoint {
                    txid: Txid::from_bytes([0x99; 32]),
                    vout: 0,
                },
                vec![],
                SEQUENCE_FINAL,
            )],
            outputs: vec![txout(1, ANYONE.to_vec())],
            lock_time: 0,
        };
        let err = chain
            .extend(vec![coinbase(3, SUBSIDY), phantom])
            .unwrap_err();
        assert_eq!(err, ConnectError::InputsMissingOrSpent);
        assert_eq!(err.reason(), "bad-txns-inputs-missingorspent");
    }

    #[test]
    fn in_belowout_rejected() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        let spend = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(SUBSIDY + 1, ANYONE.to_vec())],
            lock_time: 0,
        };
        let err = chain
            .extend(vec![coinbase(102, SUBSIDY), spend])
            .unwrap_err();
        assert_eq!(err, ConnectError::InBelowOut);
        assert_eq!(err.reason(), "bad-txns-in-belowout");
    }

    #[test]
    fn coinbase_amount_above_subsidy_plus_fees_rejected() {
        let mut chain = Chain::new(easy_params());
        chain.grow_to(3);
        // No fees in the block: the coinbase may pay at most the subsidy.
        let err = chain.extend(vec![coinbase(4, SUBSIDY + 1)]).unwrap_err();
        assert_eq!(
            err,
            ConnectError::CoinbaseAmount {
                actual: SUBSIDY + 1,
                limit: SUBSIDY,
            }
        );
        assert_eq!(err.reason(), "bad-cb-amount");
    }

    // -- BIP30 ----------------------------------------------------------------

    #[test]
    fn duplicate_txid_with_unspent_outputs_rejected() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        // Block 102 carries tx T spending the height-1 coinbase; T's output is
        // left unspent.
        let t = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(SUBSIDY - 1, ANYONE.to_vec())],
            lock_time: 0,
        };
        chain
            .extend(vec![coinbase(102, SUBSIDY), t.clone()])
            .unwrap();
        // Block 103 carries T again: its outputs are still unspent in the set.
        let err = chain.extend(vec![coinbase(103, SUBSIDY), t]).unwrap_err();
        match err {
            ConnectError::Bip30(_) => assert_eq!(err.reason(), "bad-txns-BIP30"),
            other => panic!("expected Bip30, got {other:?}"),
        }
    }

    // -- BIP68 sequence locks --------------------------------------------------

    fn bip68_tx(outpoint: OutPoint, sequence: u32) -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![txin(outpoint, vec![], sequence)],
            outputs: vec![txout(1, ANYONE.to_vec())],
            lock_time: 0,
        }
    }

    #[test]
    fn bip68_height_lock_enforced() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        // Height-1 coin, spent at height 102 with sequence=200 (height type):
        // min height = 1 + 200 - 1 = 200 >= 102 -> not final.
        let spend = bip68_tx(cb_outs[0], 200);
        let err = chain
            .extend(vec![coinbase(102, SUBSIDY), spend])
            .unwrap_err();
        assert_eq!(err, ConnectError::NotFinal);
        assert_eq!(err.reason(), "bad-txns-nonfinal");
    }

    #[test]
    fn bip68_height_lock_satisfied() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        // sequence=50: 1 + 50 - 1 = 50 < 102 -> final.
        let spend = bip68_tx(cb_outs[0], 50);
        chain.extend(vec![coinbase(102, SUBSIDY), spend]).unwrap();
    }

    #[test]
    fn bip68_disable_flag_and_version_escape() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        // Disable flag set: the sequence is not a lock at all.
        let spend = bip68_tx(cb_outs[0], 0xffff_ffff);
        chain.extend(vec![coinbase(102, SUBSIDY), spend]).unwrap();
        chain.extend(vec![coinbase(103, SUBSIDY)]).unwrap();
        // A mature coin (height 4) spent at height 104 with an unsatisfied
        // height lock — but version < 2 opts the transaction out of BIP68.
        let mut old = bip68_tx(cb_outs[3], 200);
        old.version = 1;
        chain.extend(vec![coinbase(104, SUBSIDY), old]).unwrap();
    }

    // -- UTXO-dependent sigops ------------------------------------------------

    /// A P2SH locking script: `OP_HASH160 <20-byte hash> OP_EQUAL`.
    fn p2sh_script() -> Vec<u8> {
        let mut s = vec![script::OP_HASH160, 0x14];
        s.extend_from_slice(&[0x33; 20]);
        s.push(script::OP_EQUAL);
        s
    }

    #[test]
    fn p2sh_sigops_counted_against_block_limit() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        // At 102, create the P2SH coin (its own cost is just the 3-op spk).
        let setup = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(1_000, p2sh_script())],
            lock_time: 0,
        };
        let block102 = chain.extend(vec![coinbase(102, SUBSIDY), setup]).unwrap();
        let p2sh_out = OutPoint {
            txid: block102.transactions[1].txid(),
            vout: 0,
        };
        // Spend it at 103 with a redeem script holding 20_001 OP_CHECKSIGs:
        // sigop cost 20_001 * 4 > MAX_BLOCK_SIGOPS_COST.
        let redeem = vec![script::OP_CHECKSIG; 20_001];
        let spend = Transaction {
            version: 1,
            inputs: vec![txin(p2sh_out, script::push_slice(&redeem), SEQUENCE_FINAL)],
            outputs: vec![txout(999, ANYONE.to_vec())],
            lock_time: 0,
        };
        let err = chain
            .extend(vec![coinbase(103, SUBSIDY), spend])
            .unwrap_err();
        assert_eq!(err, ConnectError::SigopsExceeded);
        assert_eq!(err.reason(), "bad-blk-sigops");
    }

    #[test]
    fn witness_sigops_counted_under_witness_flag() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        // A v0-P2WPKH-looking coin (witness program, 20 bytes).
        let mut wpkh = vec![script::OP_0, 0x14];
        wpkh.extend_from_slice(&[0x44; 20]);
        let setup = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(1_000, wpkh)],
            lock_time: 0,
        };
        let block102 = chain.extend(vec![coinbase(102, SUBSIDY), setup]).unwrap();
        let wpkh_out = OutPoint {
            txid: block102.transactions[1].txid(),
            vout: 0,
        };
        // Spending it counts 1 witness sigop; the block stays under the cap.
        let mut spend = Transaction {
            version: 1,
            inputs: vec![txin(wpkh_out, vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(999, ANYONE.to_vec())],
            lock_time: 0,
        };
        spend.inputs[0].witness = Witness::new(vec![vec![1u8; 72], vec![2u8; 33]]);
        chain.extend(vec![coinbase(103, SUBSIDY), spend]).unwrap();
    }

    // -- disconnect / rollback -------------------------------------------------

    #[test]
    fn disconnect_restores_utxo_exactly() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        let spend = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(SUBSIDY - 7, ANYONE.to_vec())],
            lock_time: 0,
        };
        let before = chain.utxo.clone();
        let block = chain
            .extend(vec![coinbase(102, SUBSIDY + 7), spend])
            .unwrap();
        let ctx = ConnectContext {
            params: &chain.params,
            tree: &chain.tree,
            block_hash: block.block_hash(),
        };
        // Re-run connect on a clone to capture the undo (extend already applied
        // it); disconnect must restore `before` exactly.
        let mut utxo2 = before.clone();
        let undo = connect_block(&block, &mut utxo2, &ctx).unwrap();
        disconnect_block(&block, &mut utxo2, &undo).unwrap();
        assert_eq!(utxo2.map, before.map);
    }

    #[test]
    fn failed_connect_leaves_utxo_untouched() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        let before = chain.utxo.clone();
        // First tx is fine (spends a mature coinbase); the second tx is a
        // double-spend of the same outpoint — the connect must roll back the
        // first tx's applied effects too.
        let spend_a = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(SUBSIDY - 1, ANYONE.to_vec())],
            lock_time: 0,
        };
        let spend_b = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[1], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(SUBSIDY + 1, ANYONE.to_vec())],
            lock_time: 0,
        };
        let parent = chain.tip_header;
        let block = block_on(
            &parent,
            vec![coinbase(102, SUBSIDY), spend_a, spend_b],
            &chain.params,
        );
        chain.tree.insert(&block.header, chain.now).unwrap();
        let ctx = ConnectContext {
            params: &chain.params,
            tree: &chain.tree,
            block_hash: block.block_hash(),
        };
        assert_eq!(
            connect_block(&block, &mut chain.utxo, &ctx).unwrap_err(),
            ConnectError::InBelowOut
        );
        assert_eq!(chain.utxo.map, before.map);
    }

    // -- unspendable outputs / money-range / reconnect ------------------------

    #[test]
    fn unspendable_outputs_never_enter_the_set() {
        let mut chain = Chain::new(easy_params());
        let mut cb = coinbase(1, SUBSIDY);
        cb.outputs = vec![
            txout(SUBSIDY - 1, ANYONE.to_vec()),
            txout(1, vec![script::OP_RETURN, 0x02, 0xaa, 0xbb]),
        ];
        let block = chain.extend(vec![cb]).unwrap();
        // Only the OP_1 output landed in the set.
        assert_eq!(chain.utxo.len(), 1);
        let txid = block.transactions[0].txid();
        assert!(chain.utxo.have(&OutPoint { txid, vout: 0 }));
        assert!(!chain.utxo.have(&OutPoint { txid, vout: 1 }));
    }

    #[test]
    fn input_values_out_of_range_rejected() {
        let mut chain = Chain::new(easy_params());
        chain.extend(vec![coinbase(1, SUBSIDY)]).unwrap();
        // A synthetic coin above MAX_MONEY: per-coin range check fires.
        let bad = OutPoint {
            txid: Txid::from_bytes([0xaa; 32]),
            vout: 0,
        };
        chain.utxo.insert_synthetic(
            bad,
            Coin {
                out: txout(MAX_MONEY + 1, ANYONE.to_vec()),
                height: 0,
                coinbase: false,
            },
        );
        let spend = Transaction {
            version: 1,
            inputs: vec![txin(bad, vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(1, ANYONE.to_vec())],
            lock_time: 0,
        };
        let err = chain.extend(vec![coinbase(2, SUBSIDY), spend]).unwrap_err();
        assert_eq!(err, ConnectError::InputValuesOutOfRange);
        assert_eq!(err.reason(), "bad-txns-inputvalues-outofrange");

        // Two in-range coins whose sum exceeds MAX_MONEY: running-total check.
        let a = OutPoint {
            txid: Txid::from_bytes([0xbb; 32]),
            vout: 0,
        };
        let b = OutPoint {
            txid: Txid::from_bytes([0xcc; 32]),
            vout: 0,
        };
        for op in [a, b] {
            chain.utxo.insert_synthetic(
                op,
                Coin {
                    out: txout(MAX_MONEY, ANYONE.to_vec()),
                    height: 0,
                    coinbase: false,
                },
            );
        }
        let spend2 = Transaction {
            version: 1,
            inputs: vec![
                txin(a, vec![], SEQUENCE_FINAL),
                txin(b, vec![], SEQUENCE_FINAL),
            ],
            outputs: vec![txout(1, ANYONE.to_vec())],
            lock_time: 0,
        };
        let err = chain
            .extend(vec![coinbase(3, SUBSIDY), spend2])
            .unwrap_err();
        assert_eq!(err, ConnectError::InputValuesOutOfRange);
    }

    #[test]
    fn reconnect_after_disconnect_is_exact() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        let spend = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(SUBSIDY - 7, ANYONE.to_vec())],
            lock_time: 0,
        };
        let block = block_on(
            &chain.tip_header,
            vec![coinbase(102, SUBSIDY + 7), spend],
            &chain.params,
        );
        chain.tree.insert(&block.header, chain.now).unwrap();
        let ctx = ConnectContext {
            params: &chain.params,
            tree: &chain.tree,
            block_hash: block.block_hash(),
        };
        let base = chain.utxo.clone();
        let undo = connect_block(&block, &mut chain.utxo, &ctx).unwrap();
        let connected = chain.utxo.clone();
        disconnect_block(&block, &mut chain.utxo, &undo).unwrap();
        assert_eq!(chain.utxo.map, base.map);
        // Reconnecting yields the same state.
        connect_block(&block, &mut chain.utxo, &ctx).unwrap();
        assert_eq!(chain.utxo.map, connected.map);
    }

    // -- BIP30 skip on the known chain ----------------------------------------

    #[test]
    fn coinbase_overwrite_allowed_when_bip30_skipped() {
        // Custom params: bip34_height = 1 and bip34_hash = the height-1 block's
        // hash, so `enforce_bip30` skips once the known chain passes height 1.
        let mut params = easy_params();
        params.bip34_height = 1;
        let mut chain = Chain::new(params);
        let block1 = chain.extend(vec![coinbase(1, SUBSIDY)]).unwrap();
        params.bip34_hash = Some(block1.block_hash());
        chain.params = params;
        let cb1_txid = block1.transactions[0].txid();
        // A coinbase at height 2 with *identical bytes* to height 1's — same
        // txid — exercises the overwrite path. (Contextual BIP34 checks are
        // out of connect's scope; Core's AddCoin permits the overwrite here.)
        let same = coinbase(1, SUBSIDY);
        assert_eq!(same.txid(), cb1_txid);
        chain.extend(vec![same]).unwrap();
    }
}

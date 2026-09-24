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
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};

use crate::block::{Block, WITNESS_SCALE_FACTOR};
use crate::chain::HeaderTree;
use crate::check::{MAX_BLOCK_SIGOPS_COST, MAX_MONEY};
use crate::hash::{BlockHash, Hash256, Txid};
use crate::params::Params;
use crate::script::{ScriptFlags, block_script_flags, count_witness_sig_ops};
use crate::sigchecker::check_input_scripts;
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

/// One cache entry in [`UtxoSet::map`]: `Some` a live coin, `None` a
/// tombstone over a coin that exists in a lower layer and was spent
/// since the last flush.
type CacheMap = HashMap<OutPoint, Option<Coin>>;

/// Rough in-memory size of one cache entry — key + `Coin` + map
/// overhead. Used for the `-dbcache` budget signal only; precision to
/// the byte isn't required, the order of magnitude is.
fn entry_bytes(coin: Option<&Coin>) -> usize {
    36 + 8 + coin.map_or(32, |c| c.out.script_pubkey.as_bytes().len()) + 64
}

/// The set of unspent transaction outputs — Core's `CCoinsViewCache`
/// shape: a small write-back cache of pending changes layered over a
/// disk backend (`coinsdb.redb`) and/or a moved-in parent view.
///
/// Layered lookup order for `get`/`have`:
///   1. `map` — dirty writes (`Some`) and tombstones (`None`)
///   2. `base` — a moved-in parent view (reorg simulation overlay)
///   3. `backend` — the persisted `redb` coins table
///
/// The cache is *write-back only*: reads that miss `map` go straight
/// to the backend's mmap index rather than being cached, so `map`
/// holds only state that must eventually flush. When `map` exceeds
/// `budget` bytes the caller flushes it — commits are atomic
/// coins+undo+tip transactions, so they may only happen at block
/// boundaries; a single block's dirty set may transiently exceed the
/// budget (Core's cache behaves the same way during `ConnectBlock`).
///
/// With no backend attached (`backend == None`) every entry lives in
/// `map` as `Some` and behavior is exactly the old flat-map set —
/// that's the mode tests and the mempool overlay use.
#[derive(Debug)]
pub struct UtxoSet {
    /// Pending writes: `Some` = live coin, `None` = tombstone.
    map: CacheMap,
    /// Moved-in lower view — `Some` only inside reorg simulation.
    base: Option<Box<UtxoSet>>,
    /// The persisted coins store — `Some` only on the real leaf set.
    backend: Option<std::sync::Arc<crate::coinsdb::CoinsBackend>>,
    /// The immutable snapshot base — the lowest layer. Reads fall
    /// through after map/base/backend all miss. Writes never touch it:
    /// a spent snapshot coin leaves a tombstone in `map` that shadows
    /// the base (and commits a harmless no-op delete to the backend).
    snapshot: Option<std::sync::Arc<crate::sortedrun::SnapshotRun>>,
    /// Approximate bytes held by `map` — the flush-pressure signal.
    map_bytes: usize,
    /// Soft cap on `map_bytes` — Core's `-dbcache` for the coins view.
    budget: usize,
    /// Coins live in `map` minus tombstones over lower-layer coins —
    /// tracks the map's net contribution so `len()` stays O(1).
    live_delta: i64,
    /// Outpoints created since the last flush with no lower-layer
    /// presence — "born in memory". A tombstone on a born key is a
    /// delete of a key the backend never saw: pure waste, elided at
    /// commit. Cleared on flush.
    born: std::collections::HashSet<OutPoint>,
}

impl Default for UtxoSet {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            base: None,
            backend: None,
            snapshot: None,
            map_bytes: 0,
            budget: DEFAULT_CACHE_BUDGET,
            live_delta: 0,
            born: std::collections::HashSet::new(),
        }
    }
}

/// Default coins-cache budget: 450 MiB — Core's `-dbcache` default,
/// covering both the UTXO cache and block/filter indexes in Core's
/// accounting. Here it bounds only the coins write-back cache.
pub const DEFAULT_CACHE_BUDGET: usize = 450 * 1024 * 1024;

impl UtxoSet {
    /// An empty UTXO set — the state at genesis. The genesis block is never
    /// connected (Core's chainstate starts empty and never applies it), so its
    /// outputs are unspendable.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches the disk backend — `Some` turns this set into a
    /// write-back cache over `coinsdb.redb`; `None` leaves it the
    /// in-memory map.
    pub fn attach_backend(&mut self, backend: crate::coinsdb::CoinsBackend) {
        self.backend = Some(std::sync::Arc::new(backend));
    }

    /// Attaches an already-shared backend handle — the chainstate
    /// holds the `Arc` (for undo reads during overlay sims) and hands
    /// the same one here.
    pub fn attach_shared(&mut self, backend: std::sync::Arc<crate::coinsdb::CoinsBackend>) {
        self.backend = Some(backend);
    }

    /// Attaches an immutable snapshot run as the lowest read layer —
    /// the delta-overlay base for a SnapshotRun-loaded chainstate.
    pub fn attach_snapshot(&mut self, run: crate::sortedrun::SnapshotRun) {
        self.snapshot = Some(std::sync::Arc::new(run));
    }

    /// Attaches an already-shared snapshot run — the chainstate holds
    /// the `Arc` and hands the same one here (mirrors `attach_shared`).
    pub fn attach_shared_snapshot(&mut self, run: std::sync::Arc<crate::sortedrun::SnapshotRun>) {
        self.snapshot = Some(run);
    }

    /// `true` when a disk backend is attached.
    #[must_use]
    pub fn has_backend(&self) -> bool {
        self.backend.is_some()
    }

    /// The backend handle — `None` in memory-only mode.
    #[must_use]
    pub fn backend(&self) -> Option<&crate::coinsdb::CoinsBackend> {
        self.backend.as_deref()
    }

    /// Sets the write-back cache budget in bytes (`-dbcache`).
    pub fn set_budget(&mut self, bytes: usize) {
        self.budget = bytes;
    }

    /// `true` when the dirty map exceeds the budget — the caller
    /// should flush at the next block boundary.
    #[must_use]
    pub fn over_budget(&self) -> bool {
        self.backend.is_some() && self.map_bytes > self.budget
    }

    /// The number of tracked coins — lower layers plus the map's net
    /// `live_delta` (new coins minus tombstones over lower-layer ones).
    /// O(1): the delta is maintained at write time.
    #[must_use]
    pub fn len(&self) -> usize {
        let lower = self
            .base
            .as_deref()
            .map_or(0, UtxoSet::len)
            .saturating_add(
                self.backend
                    .as_deref()
                    .map_or(0, |b| b.coins_len() as usize),
            )
            .saturating_add(self.snapshot.as_ref().map_or(0, |s| s.len()) as usize);
        lower.saturating_add_signed(self.live_delta as isize)
    }

    /// `true` if no coins are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The coin at `outpoint` — layered lookup: dirty map, then the
    /// simulation base, then the disk backend. Backend reads are not
    /// cached in `map` (the cache is write-back only); `redb`'s mmap
    /// lookups are cheap enough that read-caching buys little.
    #[must_use]
    pub fn get(&self, outpoint: &OutPoint) -> Option<Coin> {
        if let Some(entry) = self.map.get(outpoint) {
            return entry.clone();
        }
        if let Some(base) = &self.base {
            return base.get(outpoint);
        }
        if let Some(be) = &self.backend {
            return be.get(outpoint);
        }
        if let Some(snap) = &self.snapshot {
            return snap.get(outpoint);
        }
        None
    }

    /// Borrowing view of `get` — returns the cached coin by reference
    /// when it lives in `map`, else `None` (backend hits can't return
    /// a reference). Callers that only need presence should use
    /// [`UtxoSet::have`]; those needing the coin itself use `get`.
    #[must_use]
    pub fn get_cached(&self, outpoint: &OutPoint) -> Option<&Coin> {
        self.map.get(outpoint).and_then(|e| e.as_ref())
    }

    /// `true` if `outpoint` holds a coin (Core's `HaveCoin`).
    #[must_use]
    pub fn have(&self, outpoint: &OutPoint) -> bool {
        if let Some(entry) = self.map.get(outpoint) {
            return entry.is_some();
        }
        if let Some(base) = &self.base {
            return base.have(outpoint);
        }
        if self.backend.as_ref().is_some_and(|be| be.have(outpoint)) {
            return true;
        }
        self.snapshot
            .as_ref()
            .is_some_and(|s| s.get(outpoint).is_some())
    }

    /// Every live `OutPoint → Coin`, materialized — merges the dirty
    /// map over the backend table (tombstones remove, `Some` override
    /// or add). Snapshot/`gettxoutsetinfo`/`dumptxoutset` path; the
    /// callers all collect anyway.
    #[must_use]
    pub fn iter(&self) -> Vec<(OutPoint, Coin)> {
        let mut all: HashMap<OutPoint, Coin> = match &self.backend {
            Some(be) => be.iter_coins().into_iter().collect(),
            None => HashMap::new(),
        };
        // The snapshot file is the lowest layer — everything above
        // shadows it.
        if let Some(snap) = &self.snapshot {
            for (op, c) in snap.iter().unwrap_or_default() {
                all.insert(op, c);
            }
        }
        if let Some(base) = &self.base {
            for (op, c) in base.iter() {
                all.insert(op, c);
            }
        }
        for (op, entry) in &self.map {
            match entry {
                Some(c) => {
                    all.insert(*op, c.clone());
                }
                None => {
                    all.remove(op);
                }
            }
        }
        all.into_iter().collect()
    }

    /// [`Self::iter`] without the snapshot layer — the mutable delta
    /// alone. `state.dat` persists this view: the snapshot file is the
    /// base and must not be serialized into it.
    #[must_use]
    pub fn iter_delta(&self) -> Vec<(OutPoint, Coin)> {
        let mut all: HashMap<OutPoint, Coin> = match &self.backend {
            Some(be) => be.iter_coins().into_iter().collect(),
            None => HashMap::new(),
        };
        if let Some(base) = &self.base {
            for (op, c) in base.iter() {
                all.insert(op, c);
            }
        }
        for (op, entry) in &self.map {
            match entry {
                Some(c) => {
                    all.insert(*op, c.clone());
                }
                None => {
                    all.remove(op);
                }
            }
        }
        all.into_iter().collect()
    }

    /// Inserts a coin directly — the staging hook for tests, mempool
    /// overlays, and migration seeding. Bypasses the unspendable
    /// check; the caller is responsible for the invariant.
    pub fn insert_synthetic(&mut self, outpoint: OutPoint, coin: Coin) {
        self.put(outpoint, Some(coin));
    }

    /// Spends `outpoint` — Core's `SpendCoin`. Returns the consumed
    /// coin; a tombstone is recorded so the deletion survives flush.
    pub fn spend_coin(&mut self, outpoint: &OutPoint) -> Option<Coin> {
        self.spend(outpoint)
    }

    /// Read-through to the layers below `map`.
    fn lower_get(&self, outpoint: &OutPoint) -> Option<Coin> {
        self.base
            .as_deref()
            .and_then(|b| b.get(outpoint))
            .or_else(|| self.backend.as_deref().and_then(|be| be.get(outpoint)))
            .or_else(|| self.snapshot.as_ref().and_then(|s| s.get(outpoint)))
    }

    /// `true` if any layer below `map` holds `outpoint`.
    fn lower_live(&self, outpoint: &OutPoint) -> bool {
        self.base.as_deref().is_some_and(|b| b.have(outpoint))
            || self.backend.as_deref().is_some_and(|be| be.have(outpoint))
            || self
                .snapshot
                .as_ref()
                .is_some_and(|s| s.get(outpoint).is_some())
    }

    /// Writes `entry` into `map`, keeping `live_delta` exact: the map's
    /// net contribution is `is_live − was_live`, where "was live" counts
    /// both an existing live map entry and a coin in a lower layer that
    /// this entry now shadows.
    fn put(&mut self, outpoint: OutPoint, entry: Option<Coin>) {
        let was_live = match self.map.get(&outpoint) {
            Some(old) => old.is_some(),
            None => self.lower_live(&outpoint),
        };
        if let Some(old) = self.map.get(&outpoint) {
            self.map_bytes = self.map_bytes.saturating_sub(entry_bytes(old.as_ref()));
        }
        self.map_bytes += entry_bytes(entry.as_ref());
        self.live_delta += i64::from(entry.is_some()) - i64::from(was_live);
        // "Born this epoch" tracking: a `Some` insert whose key has no
        // lower-layer presence and no live map entry. Tombstones on
        // born keys are elided at commit — the backend never saw them.
        // `Some`→`Some` overwrites leave `born` untouched (status
        // already correct); tombstone→`Some` re-checks `lower_live` —
        // a backend-resident key must NOT be born (its tombstone is
        // real work).
        if entry.is_some() {
            let born_now = match self.map.get(&outpoint) {
                Some(Some(_)) => false,
                _ => !self.lower_live(&outpoint),
            };
            if born_now {
                self.born.insert(outpoint);
            }
        }
        self.map.insert(outpoint, entry);
    }

    /// `spend` exposed to sibling-module tests (coinsdb's suite drives
    /// the tombstone path without building a whole block).
    #[cfg(test)]
    pub(crate) fn test_spend(&mut self, outpoint: &OutPoint) -> Option<Coin> {
        self.spend(outpoint)
    }

    /// Removes the coin at `outpoint`, returning it (Core's `SpendCoin`
    /// with `moveout`). Misses `map` fall through to base/backend and
    /// leave a tombstone.
    fn spend(&mut self, outpoint: &OutPoint) -> Option<Coin> {
        if let Some(entry) = self.map.get_mut(outpoint) {
            self.map_bytes = self.map_bytes.saturating_sub(entry_bytes(entry.as_ref()));
            let taken = entry.take();
            if taken.is_some() {
                self.live_delta -= 1;
            }
            return taken;
        }
        let coin = self.lower_get(outpoint)?;
        self.live_delta -= 1;
        self.map_bytes += entry_bytes(None);
        self.map.insert(*outpoint, None);
        Some(coin)
    }

    /// Drops `outpoint`'s entry — the disconnect path's "remove created
    /// outputs" step. Two cases:
    /// * the created coin is only in `map` (this block created it since
    ///   the last commit) — drop it; if it shadowed a live lower coin
    ///   (BIP30 overwrite) the lower coin resurfaces, and the
    ///   overwritten-undo record rewrites it explicitly.
    /// * the created coin lives in a lower layer (a committed block
    ///   being disconnected during rewind) — shadow it with a
    ///   tombstone so the removal reaches the backend on commit.
    fn remove_entry(&mut self, outpoint: &OutPoint) {
        if let Some(old) = self.map.remove(outpoint) {
            self.map_bytes = self.map_bytes.saturating_sub(entry_bytes(old.as_ref()));
            self.live_delta -= i64::from(old.is_some()) - i64::from(self.lower_live(outpoint));
        }
        if self.lower_live(outpoint) {
            self.put(*outpoint, None);
        }
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
            // The overwrite check must see through the cache: a coin
            // living only in the backend still counts as unspent.
            let previous = self.get(&outpoint);
            self.put(outpoint, Some(coin));
            if let Some(previous) = previous {
                if !coinbase {
                    // Restore the entry so rollback sees pre-tx state.
                    self.put(outpoint, Some(previous));
                    return Err(ConnectError::Internal(
                        "non-coinbase tx overwrote an unspent coin past the BIP30 scan",
                    ));
                }
                undo.overwritten.push((outpoint, previous));
            }
        }
        Ok(())
    }

    /// Produces a simulation overlay: this set's state is *moved* into
    /// the overlay's `base` layer (an O(1) `mem::take`, not the old
    /// O(utxo) clone), leaving `self` empty. The overlay's reads see
    /// the full state; its writes land in its own `map`.
    ///
    /// The caller must hand the overlay back via [`UtxoSet::unoverlay`]
    /// (success or failure) to restore `self` — see `chainstate`'s
    /// `maybe_reorg` for the pattern.
    #[must_use]
    pub fn overlay(&mut self) -> UtxoSet {
        UtxoSet {
            map: HashMap::new(),
            base: Some(Box::new(std::mem::take(self))),
            backend: None,
            snapshot: None,
            map_bytes: 0,
            budget: usize::MAX, // simulation never flushes
            live_delta: 0,
            born: std::collections::HashSet::new(),
        }
    }

    /// Restores a set emptied by [`UtxoSet::overlay`]: folds the
    /// overlay's `base` back into `self` when the simulation is
    /// discarded, or applies the overlay's committed view when it
    /// passed (the caller picks). `overlay` must be this set's child —
    /// i.e. produced by `self.overlay()`.
    ///
    /// `commit == false`: discard the overlay — `self` gets its base
    /// back untouched. `commit == true`: adopt the overlay — `self`
    /// becomes `overlay` flattened (its base restored, its pending
    /// writes merged on top).
    pub fn unoverlay(&mut self, overlay: UtxoSet, commit: bool) {
        let Some(base) = overlay.base else {
            return;
        };
        if !commit {
            *self = *base;
            return;
        }
        // Adopt: restore the base into self, then replay the overlay's
        // pending writes on top — same layering the backend gives.
        *self = *base;
        for (op, entry) in overlay.map {
            self.put(op, entry);
        }
    }

    /// Flushes the pending writes to the backend atomically together
    /// with `new_undos` and the connected `tip` — Core's
    /// `CCoinsViewCache::Sync` + `BatchWrite`. No-op without a backend.
    ///
    /// # Errors
    /// `io::Error` on backend transaction failure.
    pub fn flush_to_backend(
        &mut self,
        new_undos: &[(u32, crate::hash::BlockHash, BlockUndo)],
        tip: u32,
    ) -> std::io::Result<()> {
        let Some(be) = &self.backend else {
            return Ok(());
        };
        // Tombstone elision: a `None` entry over a born key deletes a
        // coin the backend never saw — drop it before commit instead
        // of issuing a useless backend delete.
        if !self.born.is_empty() {
            let born = &self.born;
            self.map.retain(|op, e| e.is_some() || !born.contains(op));
        }
        be.commit(&self.map, new_undos, tip)?;
        self.map.clear();
        self.map_bytes = 0;
        self.live_delta = 0;
        self.born.clear();
        Ok(())
    }

    /// Coins-only flush that does NOT advance the backend tip — the
    /// bounded-batch drain inside snapshot import. A crash between
    /// batches leaves the backend at its old committed tip with extra
    /// coins orphaned (re-import overwrites them), never a false tip.
    pub fn flush_partial_to_backend(&mut self) -> std::io::Result<()> {
        let Some(be) = &self.backend else {
            return Ok(());
        };
        if !self.born.is_empty() {
            let born = &self.born;
            self.map.retain(|op, e| e.is_some() || !born.contains(op));
        }
        be.commit_partial(&self.map)?;
        self.map.clear();
        self.map_bytes = 0;
        self.live_delta = 0;
        self.born.clear();
        Ok(())
    }
}

impl Clone for UtxoSet {
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
            base: self.base.clone(),
            backend: self.backend.clone(),
            snapshot: self.snapshot.clone(),
            map_bytes: self.map_bytes,
            budget: self.budget,
            live_delta: self.live_delta,
            born: self.born.clone(),
        }
    }
}

impl PartialEq for UtxoSet {
    /// Content equality — normalizes layering away by comparing the
    /// merged view. O(n); test-only use.
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let mine: HashMap<OutPoint, Coin> = self.iter().into_iter().collect();
        let theirs: HashMap<OutPoint, Coin> = other.iter().into_iter().collect();
        mine == theirs
    }
}
impl Eq for UtxoSet {}

/// The undo data for one transaction — everything needed to reverse its UTXO
/// effects (Core's `CTxUndo`).
#[derive(Clone, Default, Debug, PartialEq, Eq)]
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
#[derive(Clone, Default, Debug, PartialEq, Eq)]
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
    /// Core's `fScriptChecks` (`ConnectBlock`): when `false`, `CheckInputScripts`
    /// is skipped — the assumevalid optimization for blocks already known to be
    /// valid through external verification. Every other check (inputs, maturity,
    /// values, sigops, locks, coinbase amount) still runs.
    pub script_checks: bool,
    /// When set, `connect_block` enqueues script checks and returns a
    /// [`BlockCheck`] handle instead of draining inline — the caller
    /// decides when to wait (`Chainstate`'s speculative pipeline waits
    /// a bounded window of blocks back, overlapping serial passes).
    pub script_pool: Option<&'a ScriptPool>,
}

/// A machine-checkable record of one block's connect — the
/// verification-transparency ledger's per-block grain (queue #5).
///
/// The receipt states what connect *did*: which flags were enforced,
/// how many input-script checks were performed (or queued), how many
/// were skipped through the verified-script cache, and the exact UTXO
/// transition applied, committed into [`BlockReceipt::delta_commitment`].
/// Replaying the same block against the same parent state recomputes
/// that commitment — the receipt is independently reproducible, never
/// a claim the node asks anyone to take on faith.
///
/// `delta_commitment` is **not** a UTXO-set hash: it commits to the
/// block's *delta* — per transaction, in block order, the txid, then
/// each spent `(outpoint, coin)` in input order, then each created
/// `(vout, output)` in output order — not to the resulting set. The
/// stream is SHA-256 over fixed-width fields plus length-prefixed
/// scripts, so framing is unambiguous.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockReceipt {
    /// Connected height.
    pub height: u32,
    /// The block's hash.
    pub hash: BlockHash,
    /// The script flag word enforced (`ScriptFlags::bits()`).
    pub script_flags: u32,
    /// Transactions in the block, coinbase included.
    pub txs: usize,
    /// Sigop cost accounted against `MAX_BLOCK_SIGOPS_COST`.
    pub sigops: u64,
    /// Total transaction fees, satoshis.
    pub fees: i64,
    /// Whether input-script checking was requested at all
    /// (`ConnectContext::script_checks` — `false` under assumevalid).
    pub checks_enabled: bool,
    /// Input-script checks queued for this block — already run when no
    /// script pool is configured, possibly still pending when it is.
    pub script_checks: usize,
    /// Non-coinbase transactions skipped because the verified-script
    /// cache already covered them under a superset flag set. Zero when
    /// `checks_enabled` is false.
    pub verified_hits: usize,
    /// Coins consumed (non-coinbase inputs resolved and spent).
    pub spent_coins: usize,
    /// Coins created (spendable outputs added; `is_unspendable`
    /// outputs excluded, matching `add_tx_outputs`).
    pub created_coins: usize,
    /// SHA-256 over the applied UTXO delta (see type docs).
    pub delta_commitment: Hash256,
    /// Wall time of the serial connect pass, nanoseconds — under a
    /// script pool this excludes the deferred check wait.
    pub wall_ns: u64,
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
    /// An input's script evaluation failed (`mandatory-script-verify-flag-failed (...)`);
    /// the payload is Core's `ScriptError` — its `Display` is `ScriptErrorString`.
    ScriptVerify(crate::interpreter::ScriptError),
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
    pub fn reason(&self) -> std::borrow::Cow<'static, str> {
        match self {
            Self::UnknownBlock | Self::OrphanBlock | Self::Internal(_) => "internal".into(),
            Self::InputsMissingOrSpent => "bad-txns-inputs-missingorspent".into(),
            Self::PrematureCoinbaseSpend { .. } => "bad-txns-premature-spend-of-coinbase".into(),
            Self::InputValuesOutOfRange => "bad-txns-inputvalues-outofrange".into(),
            Self::InBelowOut => "bad-txns-in-belowout".into(),
            Self::FeeOutOfRange => "bad-txns-fee-outofrange".into(),
            Self::AccumulatedFeeOutOfRange => "bad-txns-accumulated-fee-outofrange".into(),
            Self::Bip30(_) => "bad-txns-BIP30".into(),
            Self::SigopsExceeded => "bad-blk-sigops".into(),
            Self::NotFinal => "bad-txns-nonfinal".into(),
            Self::CoinbaseAmount { .. } => "bad-cb-amount".into(),
            Self::ScriptVerify(e) => format!("mandatory-script-verify-flag-failed ({e})").into(),
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
            Self::ScriptVerify(e) => write!(f, "script verification failed: {e}"),
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
/// Core's `Consensus::CheckTxInputs` — input resolution, maturity, value
/// range, and the non-negative fee for `tx` spending `utxo` at
/// `spend_height`. Returns the spent coins (input order) and the fee.
///
/// Public for the mempool's admission path — these are consensus rules,
/// and mempool admission must apply them identically. Callers outside a
/// block context supply their own resolved-coin view (e.g. a UTXO overlay
/// including unconfirmed parents).
pub fn check_tx_inputs(
    tx: &Transaction,
    utxo: &UtxoSet,
    spend_height: u32,
) -> Result<(Vec<Coin>, i64), ConnectError> {
    let mut spent = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        match utxo.get(&input.previous_output) {
            Some(coin) => spent.push(coin),
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
/// Core's `EvaluateSequenceLocks` result — whether `tx`'s BIP68 relative
/// locks are satisfied for inclusion at `height` under `parent_mtp`, with
/// coin-age ancestor lookups resolved against `tree` from `tip` (the block
/// being extended — for mempool admission, the current tip).
///
/// `spent` is `tx`'s consumed coins in input order.
#[must_use]
pub fn bip68_locks_satisfied(
    tx: &Transaction,
    spent: &[Coin],
    height: u32,
    parent_mtp: u32,
    tree: &HeaderTree,
    tip: &BlockHash,
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
            let coin_time = tree
                .get_ancestor(tip, ancestor_height)
                .and_then(|node| tree.median_time_past(&node.hash()))
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
/// Coarse phase timers for `connect_block` — relaxed atomics, a few
/// nanoseconds per bucket bump. Buckets: total wall, `check_tx_inputs`
/// (input fetches + value math — the UTXO read cost), spend+output
/// application (map writes), the parallel script-check drain, and
/// the BIP30 pre-scan.
pub struct ConnectTiming {
    pub blocks: u64,
    pub total_ns: u64,
    pub read_ns: u64,
    pub apply_ns: u64,
    pub script_ns: u64,
    pub bip30_ns: u64,
    /// Speculative-drain waits inside `accept_block` — the script
    /// pipeline's true cost under `enable_speculative_connect`
    /// (connect_block returns before the wait; the wait lands here).
    pub drain_ns: u64,
}

static TIMING: [AtomicU64; 7] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

fn tick(i: usize, start: std::time::Instant) {
    TIMING[i].fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
}

/// Speculative-drain timing — `chainstate::drain_pending_to` waits on
/// script jobs that `connect_block` already returned past; its wait
/// time lives in TIMING[6], not in `total_ns`.
pub(crate) fn drain_tick(start: std::time::Instant) {
    tick(6, start);
}

/// The mutable state behind a [`BlockCheck`] — `remaining` and `error`
/// live under the same mutex `wait` holds while checking them, so a
/// worker's update and notify can never land in the gap between the
/// waiter's predicate check and its `Condvar::wait` call.
struct CheckState {
    remaining: u64,
    error: Option<crate::interpreter::ScriptError>,
}

/// A block's outstanding script checks: workers decrement
/// `remaining` as each tx verifies; `wait` returns when all pass or
/// the first failure lands. The block's UTXO effects are already
/// applied — this only tracks verification, which mutates nothing.
pub struct BlockCheck {
    state: std::sync::Mutex<CheckState>,
    done: std::sync::Condvar,
}

impl BlockCheck {
    fn new(jobs: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(CheckState {
                remaining: jobs as u64,
                error: None,
            }),
            done: std::sync::Condvar::new(),
        }
    }

    /// Blocks until the block's script queue drains; returns the first
    /// verification failure, if any.
    pub fn wait(&self) -> Result<(), crate::interpreter::ScriptError> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while guard.remaining != 0 {
            guard = self.done.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
        match guard.error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

/// One queued script verification — owned so the worker never borrows
/// block memory (the block may be disconnected before the job runs).
struct ScriptJob {
    tx: Transaction,
    outs: Vec<TxOut>,
    flags: crate::script::ScriptFlags,
    check: std::sync::Arc<BlockCheck>,
}

/// A persistent script-check pool — Core's `scriptcheckqueue` with the
/// per-block barrier relaxed into a handle the caller waits on when it
/// chooses. Lets a block's serial connect overlap the previous block's
/// drain; verification results are consensus-exact either way.
pub struct ScriptPool {
    queue: std::sync::Mutex<std::collections::VecDeque<ScriptJob>>,
    avail: std::sync::Condvar,
}

impl ScriptPool {
    /// Spawns `workers` detached worker threads (same count rule as
    /// [`run_script_checks`]: `available_parallelism`, capped by the
    /// caller's queue depth).
    #[must_use]
    pub fn new(workers: usize) -> std::sync::Arc<Self> {
        let pool = std::sync::Arc::new(Self {
            queue: std::sync::Mutex::new(std::collections::VecDeque::new()),
            avail: std::sync::Condvar::new(),
        });
        for _ in 0..workers.max(1) {
            let pool = std::sync::Arc::clone(&pool);
            std::thread::spawn(move || pool.worker());
        }
        pool
    }

    fn worker(&self) {
        loop {
            let job = {
                let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    if let Some(job) = q.pop_front() {
                        break job;
                    }
                    q = self.avail.wait(q).unwrap_or_else(|e| e.into_inner());
                }
            };
            let result = check_input_scripts(&job.tx, &job.outs, job.flags);
            // The predicate `wait` loops on (`remaining`) and the error
            // slot are updated under the same mutex `wait` holds while
            // checking them, and the notify happens before it's
            // dropped — a concurrent `wait` either observes the
            // decremented count before blocking, or is already
            // registered on the condvar to receive this notify. Either
            // way the wakeup can't be missed.
            let mut guard = job.check.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(err) = result
                && guard.error.is_none()
            {
                guard.error = Some(err);
            }
            guard.remaining -= 1;
            if guard.remaining == 0 {
                job.check.done.notify_all();
            }
            drop(guard);
        }
    }

    fn submit(&self, job: ScriptJob) {
        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(job);
        self.avail.notify_one();
    }
}

/// Reads the cumulative `connect_block` phase timers — benchmark
/// instrumentation, not consensus state.
#[must_use]
pub fn connect_timing() -> ConnectTiming {
    ConnectTiming {
        blocks: TIMING[0].load(Ordering::Relaxed),
        total_ns: TIMING[1].load(Ordering::Relaxed),
        read_ns: TIMING[2].load(Ordering::Relaxed),
        apply_ns: TIMING[3].load(Ordering::Relaxed),
        script_ns: TIMING[4].load(Ordering::Relaxed),
        bip30_ns: TIMING[5].load(Ordering::Relaxed),
        drain_ns: TIMING[6].load(Ordering::Relaxed),
    }
}

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
    let (undo, pending, _receipt) = connect_block_inner(block, utxo, ctx)?;
    if let Some(check) = pending {
        if let Err(err) = check.wait() {
            // Deferred check failed: undo the application, exactly as
            // the inline drain's rollback does.
            let _ = disconnect_block(block, utxo, &undo);
            return Err(ConnectError::ScriptVerify(err));
        }
    }
    Ok(undo)
}

/// [`connect_block`] that additionally reports the per-block
/// [`BlockReceipt`] — the verification-transparency ledger's
/// per-block grain (queue #5).
///
/// Like [`connect_block_deferred`], a configured script pool means
/// the returned checks may still be outstanding: the caller MUST
/// `wait()` the [`BlockCheck`] before treating the block as validated,
/// and the receipt's `script_checks` field reports how many checks
/// were queued. When no pool is configured, checks ran inline and the
/// returned `Option` is `None`.
///
/// # Errors
///
/// Same contract as [`connect_block`] — on failure the UTXO set is
/// rolled back and no receipt is produced.
pub fn connect_block_full(
    block: &Block,
    utxo: &mut UtxoSet,
    ctx: &ConnectContext<'_>,
) -> Result<(BlockUndo, Option<std::sync::Arc<BlockCheck>>, BlockReceipt), ConnectError> {
    connect_block_inner(block, utxo, ctx)
}

/// `connect_block` through a [`ScriptPool`]: applies the block and
/// returns its undo plus a handle for the outstanding script checks.
/// The caller MUST `wait()` the handle before treating the block as
/// validated — the UTXO mutations are final either way; a `wait`
/// failure means the block (and anything applied on top) must roll
/// back, exactly as if the drain had failed inline.
pub fn connect_block_deferred(
    block: &Block,
    utxo: &mut UtxoSet,
    ctx: &ConnectContext<'_>,
) -> Result<(BlockUndo, std::sync::Arc<BlockCheck>), ConnectError> {
    let (undo, pending, _receipt) = connect_block_inner(block, utxo, ctx)?;
    let Some(check) = pending else {
        // Pool was absent — nothing outstanding; report an
        // already-complete handle so callers don't branch.
        let done = std::sync::Arc::new(BlockCheck::new(0));
        return Ok((undo, done));
    };
    Ok((undo, check))
}

fn connect_block_inner(
    block: &Block,
    utxo: &mut UtxoSet,
    ctx: &ConnectContext<'_>,
) -> Result<(BlockUndo, Option<std::sync::Arc<BlockCheck>>, BlockReceipt), ConnectError> {
    let t_total = std::time::Instant::now();
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
    let t_bip30 = std::time::Instant::now();
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
    tick(5, t_bip30);

    let mut applied: Vec<AppliedTx> = Vec::with_capacity(block.transactions.len());
    let mut fees: i64 = 0;
    let mut sigops_cost: u64 = 0;
    // Script checks are collected during the serial pass and run in
    // parallel after — Core's `scriptcheckqueue` shape. A tx's check
    // only needs its resolved prevouts, so it carries no dependence
    // on the UTXO mutations happening around it.
    let mut script_jobs: Vec<(&Transaction, Vec<TxOut>)> = Vec::new();
    let mut owned_jobs: Vec<(Transaction, Vec<TxOut>)> = Vec::new();

    // Receipt accumulation (queue #5): the delta stream commits, per
    // transaction in block order — txid, spend count, each spent
    // (outpoint, coin), create count, each created (vout, output) —
    // exactly the transition applied. Only used when the connect
    // succeeds; a failed block rolls back and produces no receipt.
    let mut delta_hasher = Sha256::new();
    let mut spent_coins = 0usize;
    let mut created_coins = 0usize;
    let mut scripts_queued = 0usize;

    let result = (|| -> Result<Option<std::sync::Arc<BlockCheck>>, ConnectError> {
        for (i, tx) in block.transactions.iter().enumerate() {
            let mut tx_undo = TxUndo::default();
            let mut spent = Vec::new();
            if !tx.is_coinbase() {
                let t_read = std::time::Instant::now();
                let (spent_coins, fee) = check_tx_inputs(tx, utxo, height)?;
                tick(2, t_read);
                spent = spent_coins;
                fees = match fees.checked_add(fee) {
                    Some(total) => total,
                    None => return Err(ConnectError::AccumulatedFeeOutOfRange),
                };
                if !money_range(fees) {
                    return Err(ConnectError::AccumulatedFeeOutOfRange);
                }
                if csv_active
                    && !bip68_locks_satisfied(
                        tx,
                        &spent,
                        height,
                        parent_mtp,
                        ctx.tree,
                        &ctx.block_hash,
                    )
                {
                    return Err(ConnectError::NotFinal);
                }
            }
            sigops_cost = sigops_cost.saturating_add(tx_sigop_cost(tx, &spent, flags));
            if sigops_cost > MAX_BLOCK_SIGOPS_COST {
                return Err(ConnectError::SigopsExceeded);
            }
            // Queue the script check — Core's CheckInputScripts posts
            // to the validation queue rather than verifying inline.
            // Txs whose scripts already passed (mempool acceptance)
            // under a superset flag-set are skipped — the cache hit
            // avoids a second full signature-verification pass.
            if !tx.is_coinbase()
                && ctx.script_checks
                && !crate::sigchecker::scripts_verified(&tx.wtxid(), flags)
            {
                let spent_outs: Vec<TxOut> = spent.iter().map(|c| c.out.clone()).collect();
                scripts_queued += 1;
                if ctx.script_pool.is_some() {
                    owned_jobs.push((tx.clone(), spent_outs));
                } else {
                    script_jobs.push((tx, spent_outs));
                }
            }
            // Apply (Core's UpdateCoins): spend inputs, then add outputs.
            let t_apply = std::time::Instant::now();
            for (input, coin) in tx.inputs.iter().zip(spent.iter()) {
                let removed = utxo.spend(&input.previous_output);
                debug_assert!(
                    removed.is_some(),
                    "check_tx_inputs verified this coin exists"
                );
                tx_undo.spent.push(coin.clone());
            }
            utxo.add_tx_outputs(tx, height, &mut tx_undo)?;
            tick(3, t_apply);
            applied.push(AppliedTx {
                index: i,
                undo: tx_undo,
            });
            // Receipt delta stream — fixed-width fields plus
            // length-prefixed scripts; see `BlockReceipt`'s docs for
            // the exact framing.
            delta_hasher.update(tx.txid().as_bytes());
            delta_hasher.update((spent.len() as u32).to_le_bytes());
            for (input, coin) in tx.inputs.iter().zip(spent.iter()) {
                delta_hasher.update(input.previous_output.txid.as_bytes());
                delta_hasher.update(input.previous_output.vout.to_le_bytes());
                delta_hasher.update(coin.out.value.to_le_bytes());
                delta_hasher.update(coin.height.to_le_bytes());
                delta_hasher.update([u8::from(coin.coinbase)]);
                let script = coin.out.script_pubkey.as_bytes();
                delta_hasher.update((script.len() as u32).to_le_bytes());
                delta_hasher.update(script);
            }
            spent_coins += spent.len();
            let created = tx
                .outputs
                .iter()
                .filter(|o| !o.script_pubkey.is_unspendable())
                .count() as u32;
            delta_hasher.update(created.to_le_bytes());
            for (vout, out) in tx.outputs.iter().enumerate() {
                if out.script_pubkey.is_unspendable() {
                    continue;
                }
                delta_hasher.update((vout as u32).to_le_bytes());
                delta_hasher.update(out.value.to_le_bytes());
                delta_hasher.update(height.to_le_bytes());
                delta_hasher.update([u8::from(tx.is_coinbase())]);
                let script = out.script_pubkey.as_bytes();
                delta_hasher.update((script.len() as u32).to_le_bytes());
                delta_hasher.update(script);
            }
            created_coins += created as usize;
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
        // Drain the queued script checks — or hand them to the
        // caller's pool for deferred waiting. Ordering within the
        // block is irrelevant either way: every check reads only its
        // own tx + prevouts.
        let t_script = std::time::Instant::now();
        if let Some(pool) = ctx.script_pool {
            let check = std::sync::Arc::new(BlockCheck::new(owned_jobs.len()));
            for (tx, outs) in owned_jobs {
                pool.submit(ScriptJob {
                    tx,
                    outs,
                    flags,
                    check: check.clone(),
                });
            }
            tick(4, t_script);
            return Ok(Some(check));
        }
        if !script_jobs.is_empty() {
            run_script_checks(&script_jobs, flags).map_err(ConnectError::ScriptVerify)?;
        }
        tick(4, t_script);
        Ok(None)
    })();

    TIMING[0].fetch_add(1, Ordering::Relaxed);
    tick(1, t_total);
    match result {
        Ok(pending) => {
            let non_coinbase = block.transactions.len().saturating_sub(1);
            let receipt = BlockReceipt {
                height,
                hash: ctx.block_hash,
                script_flags: flags.bits(),
                txs: block.transactions.len(),
                sigops: sigops_cost,
                fees,
                checks_enabled: ctx.script_checks,
                script_checks: scripts_queued,
                verified_hits: if ctx.script_checks {
                    non_coinbase.saturating_sub(scripts_queued)
                } else {
                    0
                },
                spent_coins,
                created_coins,
                delta_commitment: Hash256::from_bytes(delta_hasher.finalize().into()),
                wall_ns: u64::try_from(t_total.elapsed().as_nanos()).unwrap_or(u64::MAX),
            };
            Ok((
                BlockUndo {
                    txs: applied.into_iter().map(|a| a.undo).collect(),
                },
                pending,
                receipt,
            ))
        }
        Err(error) => {
            rollback(block, utxo, applied);
            Err(error)
        }
    }
}

/// Reverses the applied prefix of a failed `connect_block`, restoring `utxo`
/// to its pre-call state: each applied tx's outputs are removed, overwritten
/// Verifies every queued (tx, prevouts) script check, spreading the
/// work over `available_parallelism` scoped threads — the role of
/// Core's `scriptcheckqueue` workers. A single-thread fallback keeps
/// tiny blocks (and machines reporting one core) off the spawn path.
fn run_script_checks(
    jobs: &[(&Transaction, Vec<TxOut>)],
    flags: crate::script::ScriptFlags,
) -> Result<(), crate::interpreter::ScriptError> {
    let workers = std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1)
        .min(jobs.len());
    if workers <= 1 {
        for (tx, outs) in jobs {
            check_input_scripts(tx, outs, flags)?;
        }
        return Ok(());
    }
    // Static slicing beats a work queue here: jobs are uniform enough
    // (one verify per tx) that contention outweighs imbalance.
    let chunk = jobs.len().div_ceil(workers);
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(workers);
        for part in jobs.chunks(chunk) {
            handles.push(s.spawn(move || {
                for (tx, outs) in part {
                    check_input_scripts(tx, outs, flags)?;
                }
                Ok::<_, crate::interpreter::ScriptError>(())
            }));
        }
        handles.into_iter().try_fold((), |(), h| {
            h.join()
                .map_err(|_| crate::interpreter::ScriptError::EvalFalse)?
        })
    })
}

/// coins restored, and spent inputs re-added — newest transaction first.
fn rollback(block: &Block, utxo: &mut UtxoSet, applied: Vec<AppliedTx>) {
    for applied_tx in applied.into_iter().rev() {
        let tx = &block.transactions[applied_tx.index];
        let txid: Txid = tx.txid();
        for (vout, out) in tx.outputs.iter().enumerate() {
            if out.script_pubkey.is_unspendable() {
                continue;
            }
            utxo.remove_entry(&OutPoint {
                txid,
                vout: vout as u32,
            });
        }
        for (outpoint, coin) in applied_tx.undo.overwritten {
            utxo.put(outpoint, Some(coin));
        }
        for (input, coin) in tx.inputs.iter().zip(applied_tx.undo.spent.iter()) {
            utxo.put(input.previous_output, Some(coin.clone()));
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
            utxo.remove_entry(&OutPoint {
                txid,
                vout: vout as u32,
            });
        }
        let tx_undo = &undo.txs[i];
        for (outpoint, coin) in &tx_undo.overwritten {
            utxo.put(*outpoint, Some(coin.clone()));
        }
        for (input, coin) in tx.inputs.iter().zip(tx_undo.spent.iter()) {
            utxo.put(input.previous_output, Some(coin.clone()));
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
                script_checks: true,
                script_pool: None,
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

    // -- ScriptPool / BlockCheck concurrency -----------------------------------

    #[test]
    fn block_check_wait_has_no_lost_wakeup() {
        // Stress the exact race the old implementation had: `wait`
        // looped on `remaining != 0` under one mutex while the worker
        // decremented `remaining` (a separate atomic) and called
        // `notify_all` outside any mutex. A notify landing between the
        // waiter's check and its `Condvar::wait` call was lost
        // forever — `wait` then blocked forever, since `remaining` was
        // already 0 and nothing would ever notify again. The fix
        // (`CheckState` behind one mutex) makes that gap impossible.
        //
        // The whole stress loop runs on its own thread with a bounded
        // receive, so a reintroduced race fails this test instead of
        // hanging the suite.
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let pool = ScriptPool::new(4);
            let tx = coinbase(1, SUBSIDY);
            for _ in 0..20_000 {
                let check = std::sync::Arc::new(BlockCheck::new(1));
                pool.submit(ScriptJob {
                    tx: tx.clone(),
                    outs: Vec::new(),
                    flags: ScriptFlags::NONE,
                    check: check.clone(),
                });
                check.wait().unwrap();
            }
            let _ = done_tx.send(());
        });
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(15))
                .is_ok(),
            "BlockCheck::wait hung — lost wakeup"
        );
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

    /// The snapshot run sits below the backend: reads fall through,
    /// spends shadow with tombstones, `len` counts the base.
    #[test]
    fn snapshot_run_is_lowest_overlay_layer() {
        let dir = std::env::temp_dir().join(format!("avila-overlay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snap.dat");

        // Two coins in distinct txid groups, sorted by key (the format's
        // grouped order) — the index's binary search relies on it.
        let mk = |b: u8, vout: u32| OutPoint {
            txid: Txid::from_bytes([b; 32]),
            vout,
        };
        let coin = |v: i64, h: u32| Coin {
            out: TxOut {
                value: v,
                script_pubkey: Script::new(vec![0x51]),
            },
            height: h,
            coinbase: false,
        };
        let op1 = mk(0x10, 0);
        let op2 = mk(0x20, 1);
        let c1 = coin(50_000, 7);
        let c2 = coin(75_000, 8);
        let coins = vec![(op1, c1.clone()), (op2, c2.clone())];
        {
            let f = std::fs::File::create(&path).unwrap();
            crate::utxo_snapshot::write_snapshot(
                f,
                [0xfa, 0xbf, 0xb5, 0xda],
                &BlockHash::from_bytes([0; 32]),
                2,
                &coins,
            )
            .unwrap();
        }

        let run = crate::sortedrun::SnapshotRun::index(&path, 1).unwrap();
        assert_eq!(run.len(), 2);
        // Direct probe: both coins resolve through the index.
        assert_eq!(run.get(&op1).unwrap().out.value, 50_000);
        assert_eq!(run.get(&op2).unwrap().out.value, 75_000);

        let mut set = UtxoSet::new();
        set.attach_snapshot(run);
        assert_eq!(set.len(), 2);
        assert!(set.have(&op1));
        let got = set.get(&op1).unwrap();
        assert_eq!(got.out.value, 50_000);
        assert_eq!(got.height, 7);

        // Spending a snapshot coin leaves a tombstone — the base stays
        // immutable, `have`/`len` reflect the spend.
        assert!(set.spend_coin(&op1).is_some());
        assert!(!set.have(&op1));
        assert!(set.get(&op1).is_none());
        assert_eq!(set.len(), 1);

        // Recreating the same outpoint shadows the tombstone — the
        // delta behaves exactly like a backend-backed set.
        let c1b = coin(60_000, 9);
        set.insert_synthetic(op1, c1b.clone());
        assert_eq!(set.get(&op1).unwrap().out.value, 60_000);
        assert_eq!(set.len(), 2);

        // A coin absent from every layer stays absent.
        assert!(!set.have(&mk(0x99, 0)));
        assert_eq!(set.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
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
        // A P2WSH coin whose witness script is `OP_0 OP_IF <33B> OP_CHECKSIG
        // OP_ENDIF OP_1` — 1 counted witness sigop (GetSigOpCount is static),
        // trivially satisfiable without a signature.
        let witness_script = {
            let mut s = vec![script::OP_0, 0x63, 0x21];
            s.extend_from_slice(&[0x44; 33]);
            s.extend_from_slice(&[0xac, 0x68, script::OP_1]);
            s
        };
        let program = crate::hash::sha256(&witness_script);
        let mut wsh = vec![script::OP_0, 0x20];
        wsh.extend_from_slice(&program);
        let setup = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(1_000, wsh)],
            lock_time: 0,
        };
        let block102 = chain.extend(vec![coinbase(102, SUBSIDY), setup]).unwrap();
        let wsh_out = OutPoint {
            txid: block102.transactions[1].txid(),
            vout: 0,
        };
        // Spending it counts 1 witness sigop; the block stays under the cap.
        let mut spend = Transaction {
            version: 1,
            inputs: vec![txin(wsh_out, vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(999, ANYONE.to_vec())],
            lock_time: 0,
        };
        spend.inputs[0].witness = Witness::new(vec![witness_script]);
        chain.extend(vec![coinbase(103, SUBSIDY), spend]).unwrap();
    }

    #[test]
    fn verified_cache_keyed_by_wtxid_rejects_witness_swap() {
        // Regression: the script-verified cache used to be keyed by txid.
        // The txid only commits to the non-witness serialization, so a tx
        // "verified" (e.g. at mempool acceptance) and then rebroadcast in a
        // block with the *same txid* but a swapped, hash-mismatching witness
        // used to skip re-verification entirely and connect. The cache must
        // be keyed by wtxid, which does commit to the witness.
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        // A P2WSH coin whose witness script is a lone OP_1.
        let witness_script = vec![script::OP_1];
        let program = crate::hash::sha256(&witness_script);
        let mut wsh = vec![script::OP_0, 0x20];
        wsh.extend_from_slice(&program);
        let setup = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(1_000, wsh.clone())],
            lock_time: 0,
        };
        let block102 = chain.extend(vec![coinbase(102, SUBSIDY), setup]).unwrap();
        let wsh_out = OutPoint {
            txid: block102.transactions[1].txid(),
            vout: 0,
        };

        // The "mempool" tx: a correct witness satisfying the P2WSH program.
        let mut good = Transaction {
            version: 1,
            inputs: vec![txin(wsh_out, vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(999, ANYONE.to_vec())],
            lock_time: 0,
        };
        good.inputs[0].witness = Witness::new(vec![witness_script]);
        let spent_outs = vec![txout(1_000, wsh)];
        let flags = block_script_flags(&chain.params, 103, &BlockHash::ZERO);
        check_input_scripts(&good, &spent_outs, flags).unwrap();
        // Simulate mempool acceptance caching the pass (under a superset of
        // any block's consensus flags, as Core's standardness flags are).
        crate::sigchecker::mark_scripts_verified(good.wtxid(), ScriptFlags::from_bits(u32::MAX));

        // Same txid (identical non-witness fields), but a different witness
        // whose hash doesn't match the committed program.
        let mut evil = good.clone();
        evil.inputs[0].witness = Witness::new(vec![vec![script::OP_1, script::OP_1]]);
        assert_eq!(evil.txid(), good.txid());
        assert_ne!(evil.wtxid(), good.wtxid());

        let before = chain.utxo.clone();
        let err = chain
            .extend(vec![coinbase(103, SUBSIDY), evil])
            .unwrap_err();
        assert!(
            matches!(err, ConnectError::ScriptVerify(_)),
            "expected a script-verify rejection, got {err:?}"
        );
        assert_eq!(chain.utxo, before, "failed connect must roll back cleanly");
    }

    #[test]
    fn failing_script_rejects_block_and_rolls_back() {
        let mut chain = Chain::new(easy_params());
        let cb_outs = chain.grow_to(101);
        // An always-false script (OP_0): lands in the UTXO set (it isn't
        // provably-unspendable like OP_RETURN) but fails evaluation.
        let setup = Transaction {
            version: 1,
            inputs: vec![txin(cb_outs[0], vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(1_000, vec![script::OP_0])],
            lock_time: 0,
        };
        let block102 = chain.extend(vec![coinbase(102, SUBSIDY), setup]).unwrap();
        let false_out = OutPoint {
            txid: block102.transactions[1].txid(),
            vout: 0,
        };
        let spend = Transaction {
            version: 1,
            inputs: vec![txin(false_out, vec![], SEQUENCE_FINAL)],
            outputs: vec![txout(999, ANYONE.to_vec())],
            lock_time: 0,
        };
        let before = chain.utxo.clone();
        let err = chain
            .extend(vec![coinbase(103, SUBSIDY), spend])
            .unwrap_err();
        assert_eq!(
            err,
            ConnectError::ScriptVerify(crate::interpreter::ScriptError::EvalFalse)
        );
        assert!(
            err.reason()
                .starts_with("mandatory-script-verify-flag-failed (")
        );
        // The failed block left the UTXO set untouched.
        assert_eq!(chain.utxo, before);
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
            script_checks: true,
            script_pool: None,
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
            script_checks: true,
            script_pool: None,
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
            script_checks: true,
            script_pool: None,
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

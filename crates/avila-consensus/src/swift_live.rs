//! Compact disk-backed live-outpoint status index for experimental full-check SwiftSync.
//!
//! The index retains only currently live exact 36-byte outpoint keys with 5-byte
//! creation metadata. Spends physically remove rows; spent outpoints are absent.
//! A bounded reorg journal retains the last configured number of blocks. This
//! remains a full live-outpoint index, not a stateless accumulator.

use crate::coinsdb::CoinFormat;
use crate::connect::Coin;
use crate::hash::{BlockHash, Txid};
use crate::params::Network;
use crate::transaction::OutPoint;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

const COINS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("swift_live_outpoints");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("swift_live_meta");
const UNDO: TableDefinition<&[u8], &[u8]> = TableDefinition::new("swift_live_undo");
const AUDIT: TableDefinition<&str, &[u8]> = TableDefinition::new("swift_live_audit");
const STUMP: TableDefinition<&str, &[u8]> = TableDefinition::new("swift_live_stump");
const BLOCK_UNDO: TableDefinition<&[u8], &[u8]> = TableDefinition::new("swift_full_block_undo");
const TX_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("swift_active_tx_meta");
const SURVIVORS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("swift_live_provisional_survivors");
const META_KEY: &str = "state";
const AUDIT_KEY: &str = "secret-checkpoint-state";
const STUMP_KEY: &str = "provisional-rustreexo-stump";
const MAGIC: &[u8; 8] = b"AVLIVE03";
const FULL_UNDO_MAGIC: &[u8; 8] = b"AVUNDO01";
const TX_META_MAGIC: &[u8; 8] = b"AVTXMETA";
const VERSION: u32 = 3;
const ROW_LEN: usize = 5;
const META_DOMAIN: &[u8] = b"Avila SwiftLive metadata v1\0";
const UNDO_DOMAIN: &[u8] = b"Avila SwiftLive undo v1\0";
const MAX_CACHE_BYTES: usize = 256 * 1024 * 1024;
/// Hard ceiling for block events accepted by this implementation.
pub const MAX_BLOCK_EVENTS: usize = 1_000_000;
/// Default retained reorg depth for a provisional live index.
pub const DEFAULT_REORG_DEPTH: u32 = 288;
const MAX_REORG_DEPTH: u32 = 10_000;

/// Immutable network and checkpoint binding for a resumable window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwiftLiveBinding {
    /// Bitcoin network.
    pub network: Network,
    /// Height immediately before this window.
    pub start_height: u32,
    /// Hash immediately before this window.
    pub start_hash: BlockHash,
    /// Inclusive checkpoint height.
    pub target_height: u32,
    /// Required hash at the checkpoint.
    pub target_hash: BlockHash,
    /// Stable commitment to the exact normalized consensus parameters used by the engine.
    pub params_commitment: [u8; 32],
}

/// Persistent resource ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwiftLiveLimits {
    /// Maximum currently live outpoints in the index.
    pub max_live_entries: u64,
    /// Maximum encoded 36-byte key plus 5-byte metadata value bytes.
    pub max_live_encoded_bytes: u64,
    /// Maximum encoded bytes retained by the bounded reorg journal.
    pub max_undo_encoded_bytes: u64,
    /// Maximum provisional survivor rows persisted for final audit/promotion.
    pub max_survivor_entries: u64,
    /// Maximum encoded provisional survivor key/coin bytes.
    pub max_survivor_encoded_bytes: u64,
    /// Number of most recent block transitions that can be rewound. Use 288 for
    /// the default policy; a deeper reorg requires discarding this provisional index.
    pub max_reorg_depth: u32,
    /// Maximum spend plus create events in one block.
    pub max_block_events: usize,
    /// redb page-cache ceiling.
    pub cache_bytes: usize,
}

/// Creation metadata and current liveness for one outpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveCoinMeta {
    /// Creation block height.
    pub height: u32,
    /// Whether the creating transaction was coinbase.
    pub coinbase: bool,
    /// Whether the outpoint is currently unspent.
    pub live: bool,
}

/// One ordered event from a locally parsed block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveEvent {
    /// Spend a live coin with matching locally indexed creation metadata.
    Spend {
        outpoint: OutPoint,
        height: u32,
        coinbase: bool,
    },
    /// Create a spendable output from this block.
    Create {
        outpoint: OutPoint,
        height: u32,
        coinbase: bool,
        /// Caller sets this only for the exact consensus BIP30 repeat blocks.
        allow_live_overwrite: bool,
    },
}

/// Bounded failures from the compact live index.
#[derive(Debug, thiserror::Error)]
pub enum SwiftLiveError {
    /// Filesystem operation failed.
    #[error("swift live-index I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// redb operation failed.
    #[error("swift live-index database {operation}: {message}")]
    Database {
        operation: &'static str,
        message: String,
    },
    /// Invalid limits or checkpoint interval.
    #[error("invalid swift live-index binding or limits")]
    InvalidConfig,
    /// Creation path already exists.
    #[error("swift live-index path already exists")]
    AlreadyExists,
    /// Binding or persisted limits differ from the database.
    #[error("swift live-index binding or limits do not match")]
    BindingMismatch,
    /// The database is accessible to group/other users; audit key secrecy requires mode 0600.
    #[error("swift live-index database permissions must be owner-only (0600)")]
    InsecurePermissions,
    /// Malformed row, journal, metadata, or counters.
    #[error("swift live-index database is corrupt")]
    Corrupt,
    /// Per-block event ceiling was reached.
    #[error("swift live-index block event limit exceeded")]
    EventLimit,
    /// Block height/hash does not extend the durable tip.
    #[error("swift live-index block does not extend the durable tip")]
    TipMismatch,
    /// Input is unknown or has already been spent.
    #[error("swift live-index input is missing or spent")]
    MissingOrSpent,
    /// Input claim creation metadata differs from local history.
    #[error("swift live-index input claim metadata mismatch")]
    ClaimMismatch,
    /// Output would overwrite a currently live outpoint.
    #[error("swift live-index output collides with a live outpoint")]
    DuplicateLiveOutput,
    /// Final block hash differs from the configured checkpoint.
    #[error("swift live-index checkpoint hash mismatch")]
    CheckpointMismatch,
    /// The checkpoint audit has not completed successfully.
    #[error("swift survivor export requires a matching completed checkpoint audit")]
    NotComplete,
    /// Distinct outpoint limit exceeded.
    #[error("swift live-index entry limit exceeded")]
    EntryLimit,
    /// Live-row or bounded-journal encoded-byte limit exceeded.
    #[error("swift live-index byte limit exceeded")]
    ByteLimit,
    /// Arithmetic overflow or counter underflow.
    #[error("swift live-index counter overflow or underflow")]
    Overflow,
    /// Rewind does not match the durable tip.
    #[error("swift live-index rewind does not match current tip")]
    RewindMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    live_entries: u64,
    live_bytes: u64,
    undo_bytes: u64,
    undo_floor: u32,
    survivor_entries: u64,
    survivor_bytes: u64,
    complete: bool,
    height: u32,
    hash: BlockHash,
}

#[derive(Clone, Debug)]
struct BeforeImage {
    live: Option<[u8; ROW_LEN]>,
    survivor: Option<Vec<u8>>,
}

type DecodedJournal = (
    BlockHash,
    BlockHash,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<([u8; 36], BeforeImage)>,
);

/// Checkpoint-bound exact live-outpoint map with atomic block updates and bounded rewind.
pub struct SwiftLiveIndex {
    db: redb::Database,
    binding: SwiftLiveBinding,
    limits: SwiftLiveLimits,
    state: State,
}

impl SwiftLiveIndex {
    /// Create a new index without replacing an existing file.
    pub fn create(
        path: &Path,
        binding: SwiftLiveBinding,
        limits: SwiftLiveLimits,
    ) -> Result<Self, SwiftLiveError> {
        validate(binding, limits)?;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    SwiftLiveError::AlreadyExists
                } else {
                    SwiftLiveError::Io(e)
                }
            })?;
        drop(file);
        let db = builder(limits)
            .create(path)
            .map_err(|e| db_error("create", e))?;
        let state = State {
            live_entries: 0,
            live_bytes: 0,
            undo_bytes: 0,
            undo_floor: binding.start_height,
            survivor_entries: 0,
            survivor_bytes: 0,
            complete: false,
            height: binding.start_height,
            hash: binding.start_hash,
        };
        let write = db.begin_write().map_err(|e| db_error("begin create", e))?;
        {
            let _coins = write
                .open_table(COINS)
                .map_err(|e| db_error("create coin table", e))?;
            let _undo = write
                .open_table(UNDO)
                .map_err(|e| db_error("create undo table", e))?;
            let _audit = write
                .open_table(AUDIT)
                .map_err(|e| db_error("create audit table", e))?;
            let _stump = write
                .open_table(STUMP)
                .map_err(|e| db_error("create stump table", e))?;
            let _block_undo = write
                .open_table(BLOCK_UNDO)
                .map_err(|e| db_error("create full block undo table", e))?;
            let _tx_meta = write
                .open_table(TX_META)
                .map_err(|e| db_error("create active tx metadata table", e))?;
            let _survivors = write
                .open_table(SURVIVORS)
                .map_err(|e| db_error("create survivor table", e))?;
            let mut meta = write
                .open_table(META)
                .map_err(|e| db_error("create metadata", e))?;
            meta.insert(META_KEY, encode_state(binding, limits, state).as_slice())
                .map_err(|e| db_error("initialize metadata", e))?;
        }
        write.commit().map_err(|e| db_error("commit create", e))?;
        Ok(Self {
            db,
            binding,
            limits,
            state,
        })
    }

    /// Open a prior index only with its exact chain binding and limits.
    pub fn open(
        path: &Path,
        binding: SwiftLiveBinding,
        limits: SwiftLiveLimits,
    ) -> Result<Self, SwiftLiveError> {
        validate(binding, limits)?;
        if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err(SwiftLiveError::InsecurePermissions);
        }
        let db = builder(limits)
            .open(path)
            .map_err(|e| db_error("open", e))?;
        let read = db.begin_read().map_err(|e| db_error("begin open", e))?;
        let bytes = {
            let meta = read.open_table(META).map_err(|_| SwiftLiveError::Corrupt)?;
            meta.get(META_KEY)
                .map_err(|e| db_error("read metadata", e))?
                .ok_or(SwiftLiveError::Corrupt)?
                .value()
                .to_vec()
        };
        let (stored_binding, stored_limits, state) = decode_state(&bytes)?;
        if stored_binding != binding || stored_limits != limits {
            return Err(SwiftLiveError::BindingMismatch);
        }
        if state.live_entries > limits.max_live_entries
            || state.live_bytes > limits.max_live_encoded_bytes
            || state.live_bytes
                != state
                    .live_entries
                    .checked_mul((36 + ROW_LEN) as u64)
                    .ok_or(SwiftLiveError::Corrupt)?
            || state.undo_bytes > limits.max_undo_encoded_bytes
            || state.survivor_entries > limits.max_survivor_entries
            || state.survivor_bytes > limits.max_survivor_encoded_bytes
            || state.height < binding.start_height
            || state.height > binding.target_height
            || state.undo_floor < binding.start_height
            || state.undo_floor > state.height
            || state.height - state.undo_floor > limits.max_reorg_depth
            || (state.complete
                && (state.height != binding.target_height || state.hash != binding.target_hash))
        {
            return Err(SwiftLiveError::Corrupt);
        }
        let coins = read
            .open_table(COINS)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        if coins.len().map_err(|e| db_error("count rows", e))? != state.live_entries {
            return Err(SwiftLiveError::Corrupt);
        }
        drop(coins);
        let stump = read
            .open_table(STUMP)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        if stump
            .get(STUMP_KEY)
            .map_err(|e| db_error("read persisted stump", e))?
            .is_some_and(|row| row.value().len() > 4096)
        {
            return Err(SwiftLiveError::Corrupt);
        }
        let undo = read.open_table(UNDO).map_err(|_| SwiftLiveError::Corrupt)?;
        let block_undo = read
            .open_table(BLOCK_UNDO)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        let tx_meta = read
            .open_table(TX_META)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        let expected_journals = state.height - state.undo_floor;
        if u32::try_from(undo.len().map_err(|e| db_error("count undo records", e))?)
            .map_err(|_| SwiftLiveError::Corrupt)?
            != expected_journals
        {
            return Err(SwiftLiveError::Corrupt);
        }
        let mut undo_bytes = 0u64;
        if expected_journals > 0 {
            let first_height = state
                .undo_floor
                .checked_add(1)
                .ok_or(SwiftLiveError::Corrupt)?;
            let mut prior_hash = None;
            for expected_height in first_height..=state.height {
                let key = expected_height.to_be_bytes();
                let journal = undo
                    .get(&key[..])
                    .map_err(|e| db_error("read retained journal", e))?
                    .ok_or(SwiftLiveError::Corrupt)?;
                let record_bytes = 4u64
                    .checked_add(
                        u64::try_from(journal.value().len())
                            .map_err(|_| SwiftLiveError::Corrupt)?,
                    )
                    .ok_or(SwiftLiveError::Corrupt)?;
                if undo_bytes
                    .checked_add(record_bytes)
                    .is_none_or(|bytes| bytes > limits.max_undo_encoded_bytes)
                {
                    return Err(SwiftLiveError::Corrupt);
                }
                let decoded = decode_journal(journal.value())?;
                if prior_hash.is_some_and(|hash| hash != decoded.0)
                    || (expected_height == binding.start_height + 1
                        && decoded.0 != binding.start_hash)
                {
                    return Err(SwiftLiveError::Corrupt);
                }
                prior_hash = Some(decoded.1);
                undo_bytes = undo_bytes
                    .checked_add(record_bytes)
                    .ok_or(SwiftLiveError::Corrupt)?;
            }
            if prior_hash != Some(state.hash) {
                return Err(SwiftLiveError::Corrupt);
            }
        }
        let expected_full_count = state
            .height
            .saturating_sub(binding.start_height)
            .min(DEFAULT_REORG_DEPTH);
        let stored_full_count = u32::try_from(
            block_undo
                .len()
                .map_err(|e| db_error("count full block undo", e))?,
        )
        .map_err(|_| SwiftLiveError::Corrupt)?;
        if stored_full_count != 0 && stored_full_count != expected_full_count {
            return Err(SwiftLiveError::Corrupt);
        }
        if stored_full_count != 0 {
            let first = state
                .height
                .saturating_sub(DEFAULT_REORG_DEPTH - 1)
                .max(binding.start_height + 1);
            let mut prior = None;
            for height in first..=state.height {
                let key = height.to_be_bytes();
                let value = block_undo
                    .get(&key[..])
                    .map_err(|e| db_error("read retained full block undo", e))?
                    .ok_or(SwiftLiveError::Corrupt)?;
                let (previous, current, _, _) = decode_full_undo(value.value())?;
                if prior.is_some_and(|hash| hash != previous)
                    || (height == first
                        && first == binding.start_height + 1
                        && previous != binding.start_hash)
                {
                    return Err(SwiftLiveError::Corrupt);
                }
                prior = Some(current);
                undo_bytes = undo_bytes
                    .checked_add(
                        4 + u64::try_from(value.value().len())
                            .map_err(|_| SwiftLiveError::Corrupt)?,
                    )
                    .ok_or(SwiftLiveError::Corrupt)?;
                if undo_bytes > limits.max_undo_encoded_bytes {
                    return Err(SwiftLiveError::Corrupt);
                }
            }
            if prior != Some(state.hash) {
                return Err(SwiftLiveError::Corrupt);
            }
        }
        let stored_tx_meta = u32::try_from(
            tx_meta
                .len()
                .map_err(|e| db_error("count active tx metadata", e))?,
        )
        .map_err(|_| SwiftLiveError::Corrupt)?;
        let expected_tx_meta = state.height - binding.start_height;
        if stored_tx_meta != 0 && stored_tx_meta != expected_tx_meta {
            return Err(SwiftLiveError::Corrupt);
        }
        if stored_tx_meta != 0 {
            let mut expected_chain_tx = 1u64;
            for height in binding.start_height + 1..=state.height {
                let key = height.to_be_bytes();
                let row = tx_meta
                    .get(&key[..])
                    .map_err(|e| db_error("read active tx metadata", e))?
                    .ok_or(SwiftLiveError::Corrupt)?;
                let (_hash, n_tx, n_chain_tx) = decode_tx_meta(row.value())?;
                if n_tx == 0
                    || n_chain_tx
                        != expected_chain_tx
                            .checked_add(u64::from(n_tx))
                            .ok_or(SwiftLiveError::Corrupt)?
                {
                    return Err(SwiftLiveError::Corrupt);
                }
                expected_chain_tx = n_chain_tx;
            }
        }
        if undo_bytes != state.undo_bytes {
            return Err(SwiftLiveError::Corrupt);
        }
        drop(undo);
        drop(block_undo);
        drop(tx_meta);
        let survivors = read
            .open_table(SURVIVORS)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        if survivors
            .len()
            .map_err(|e| db_error("count survivor rows", e))?
            != state.survivor_entries
        {
            return Err(SwiftLiveError::Corrupt);
        }
        let live = read
            .open_table(COINS)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        let mut survivor_bytes = 0u64;
        for item in survivors
            .iter()
            .map_err(|e| db_error("iterate survivor rows", e))?
        {
            let (key, value) = item.map_err(|e| db_error("read survivor row", e))?;
            let key_bytes: [u8; 36] = key
                .value()
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?;
            let live_row = live
                .get(&key_bytes[..])
                .map_err(|e| db_error("check survivor liveness", e))?
                .ok_or(SwiftLiveError::Corrupt)?;
            let meta = decode_row(&key_bytes, live_row.value())?;
            let mut encoded = value.value();
            let coin =
                crate::coinsdb::decode_coin_compact(&mut encoded).ok_or(SwiftLiveError::Corrupt)?;
            if !encoded.is_empty()
                || coin.height != meta.height
                || coin.coinbase != meta.coinbase
                || !(0..=crate::check::MAX_MONEY).contains(&coin.out.value)
                || coin.out.script_pubkey.len() > crate::swift_audit::MAX_AUDIT_SCRIPT_BYTES
            {
                return Err(SwiftLiveError::Corrupt);
            }
            survivor_bytes = survivor_bytes
                .checked_add(36)
                .and_then(|bytes| {
                    u64::try_from(value.value().len())
                        .ok()
                        .and_then(|len| bytes.checked_add(len))
                })
                .ok_or(SwiftLiveError::Corrupt)?;
            if survivor_bytes > limits.max_survivor_encoded_bytes {
                return Err(SwiftLiveError::Corrupt);
            }
        }
        if survivor_bytes != state.survivor_bytes {
            return Err(SwiftLiveError::Corrupt);
        }
        drop(survivors);
        drop(read);
        Ok(Self {
            db,
            binding,
            limits,
            state,
        })
    }

    /// Immutable network and checkpoint binding.
    #[must_use]
    pub const fn binding(&self) -> SwiftLiveBinding {
        self.binding
    }

    /// Current durable tip height and hash.
    #[must_use]
    pub const fn tip(&self) -> (u32, BlockHash) {
        (self.state.height, self.state.hash)
    }

    /// Lowest height whose per-block live/audit state can still be rewound from
    /// this database. Promotion must not advertise a deeper full-body floor.
    #[must_use]
    pub const fn undo_floor_height(&self) -> u32 {
        self.state.undo_floor
    }

    /// Restores connected transaction counts onto a caller-rebuilt active header
    /// tree, rejecting any persisted height/hash mismatch before resume.
    pub(crate) fn restore_active_tx_meta(
        &self,
        tree: &mut crate::chain::HeaderTree,
    ) -> Result<(), SwiftLiveError> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| db_error("begin tx metadata restore", e))?;
        let table = read
            .open_table(TX_META)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        let expected = self.state.height - self.binding.start_height;
        if table
            .len()
            .map_err(|e| db_error("count tx metadata restore", e))?
            != u64::from(expected)
        {
            return Err(SwiftLiveError::Corrupt);
        }
        for height in self.binding.start_height + 1..=self.state.height {
            let key = height.to_be_bytes();
            let row = table
                .get(&key[..])
                .map_err(|e| db_error("read tx metadata restore", e))?
                .ok_or(SwiftLiveError::Corrupt)?;
            let (hash, n_tx, n_chain_tx) = decode_tx_meta(row.value())?;
            let node = tree
                .get_ancestor(&self.state.hash, height)
                .filter(|node| node.height == height)
                .ok_or(SwiftLiveError::BindingMismatch)?;
            if node.hash() != hash || n_tx == 0 {
                return Err(SwiftLiveError::BindingMismatch);
            }
            tree.apply_tx_meta(&hash, n_tx, n_chain_tx);
        }
        Ok(())
    }

    /// Number of currently live outpoints.
    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.state.live_entries
    }

    /// Encoded live-key/value bytes charged against the configured ceiling.
    #[must_use]
    pub const fn encoded_bytes(&self) -> u64 {
        self.state.live_bytes
    }

    /// Encoded rollback-journal bytes charged against their separate ceiling.
    #[must_use]
    pub const fn undo_encoded_bytes(&self) -> u64 {
        self.state.undo_bytes
    }

    /// Lowest height to which the retained reorg journal can rewind.
    #[must_use]
    pub const fn rewind_floor(&self) -> u32 {
        self.state.undo_floor
    }

    /// Whether the checkpoint audit completed and this store may be streamed as
    /// a provisional full UTXO snapshot for separate promotion.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.state.complete
    }

    /// Streams the audited survivor UTXO after reopening or finishing the checkpoint.
    /// This does not install it into node chainstate or create target-height undo.
    pub fn for_each_audited_survivor(
        &self,
        visit: impl FnMut(OutPoint, LiveCoinMeta, Coin) -> Result<(), SwiftLiveError>,
    ) -> Result<(), SwiftLiveError> {
        if !self.state.complete {
            return Err(SwiftLiveError::NotComplete);
        }
        self.for_each_live_survivor(visit)
    }

    /// Streams the exact last-288-or-available full connector undo records after
    /// checkpoint completion. The first returned parent hash is the rollback-floor
    /// anchor; every subsequent row is hash-linked through the audited target tip.
    pub(crate) fn for_each_audited_undo(
        &self,
        mut visit: impl FnMut(
            u32,
            BlockHash,
            BlockHash,
            crate::block::Block,
            crate::connect::BlockUndo,
        ) -> Result<(), SwiftLiveError>,
    ) -> Result<(u32, BlockHash, usize), SwiftLiveError> {
        if !self.state.complete || self.state.height != self.binding.target_height {
            return Err(SwiftLiveError::NotComplete);
        }
        let first = self
            .state
            .height
            .saturating_sub(DEFAULT_REORG_DEPTH - 1)
            .max(self.binding.start_height + 1);
        let expected =
            usize::try_from(self.state.height - first + 1).map_err(|_| SwiftLiveError::Corrupt)?;
        let read = self
            .db
            .begin_read()
            .map_err(|e| db_error("begin undo scan", e))?;
        let table = read
            .open_table(BLOCK_UNDO)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        if table
            .len()
            .map_err(|e| db_error("count completed undo", e))?
            != expected as u64
        {
            return Err(SwiftLiveError::NotComplete);
        }
        let mut anchor = None;
        let mut prior = None;
        for height in first..=self.state.height {
            let key = height.to_be_bytes();
            let value = table
                .get(&key[..])
                .map_err(|e| db_error("read completed undo", e))?
                .ok_or(SwiftLiveError::Corrupt)?;
            let (previous, current, block, undo) = decode_full_undo(value.value())?;
            if prior.is_some_and(|hash| hash != previous) {
                return Err(SwiftLiveError::Corrupt);
            }
            if anchor.is_none() {
                anchor = Some(previous);
            }
            prior = Some(current);
            visit(height, previous, current, block, undo)?;
        }
        if prior != Some(self.binding.target_hash) {
            return Err(SwiftLiveError::Corrupt);
        }
        Ok((first, anchor.ok_or(SwiftLiveError::Corrupt)?, expected))
    }

    /// Stream exact live coins from the provisional survivor table. The final audit
    /// must succeed before these records can be promoted to ordinary chainstate.
    pub(crate) fn for_each_live_survivor(
        &self,
        mut visit: impl FnMut(OutPoint, LiveCoinMeta, Coin) -> Result<(), SwiftLiveError>,
    ) -> Result<(), SwiftLiveError> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| db_error("begin survivor scan", e))?;
        let live = read
            .open_table(COINS)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        let survivors = read
            .open_table(SURVIVORS)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        for item in live
            .iter()
            .map_err(|e| db_error("iterate survivor live set", e))?
        {
            let (key, value) = item.map_err(|e| db_error("read survivor live set", e))?;
            let key_bytes: [u8; 36] = key
                .value()
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?;
            let meta = decode_row(&key_bytes, value.value())?;
            let Some(encoded) = survivors
                .get(&key_bytes[..])
                .map_err(|e| db_error("lookup provisional survivor", e))?
            else {
                // Missing helper payload is untrusted classification data. Leave the
                // survivor aggregate short so finalization returns AuditVerdict::Mismatch.
                continue;
            };
            let mut bytes = encoded.value();
            let coin =
                crate::coinsdb::decode_coin_compact(&mut bytes).ok_or(SwiftLiveError::Corrupt)?;
            if !bytes.is_empty()
                || coin.height != meta.height
                || coin.coinbase != meta.coinbase
                || !(0..=crate::check::MAX_MONEY).contains(&coin.out.value)
                || coin.out.script_pubkey.len() > crate::swift_audit::MAX_AUDIT_SCRIPT_BYTES
            {
                return Err(SwiftLiveError::Corrupt);
            }
            visit(decode_outpoint(&key_bytes)?, meta, coin)?;
        }
        Ok(())
    }

    /// Reads the secret-bearing aggregate state from this private local database.
    pub(crate) fn audit_snapshot(&self) -> Result<Option<Vec<u8>>, SwiftLiveError> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| db_error("begin audit read", e))?;
        let audit = read
            .open_table(AUDIT)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        let snapshot = audit
            .get(AUDIT_KEY)
            .map_err(|e| db_error("read audit snapshot", e))?
            .map(|row| row.value().to_vec());
        if snapshot.as_ref().is_some_and(|bytes| bytes.len() != 321) {
            return Err(SwiftLiveError::Corrupt);
        }
        Ok(snapshot)
    }

    /// Reads the provisional rustreexo snapshot coupled to the same atomic tip.
    pub(crate) fn stump_snapshot(&self) -> Result<Option<Vec<u8>>, SwiftLiveError> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| db_error("begin stump read", e))?;
        let stump = read
            .open_table(STUMP)
            .map_err(|_| SwiftLiveError::Corrupt)?;
        let snapshot = stump
            .get(STUMP_KEY)
            .map_err(|e| db_error("read stump snapshot", e))?
            .map(|row| row.value().to_vec());
        if snapshot.as_ref().is_some_and(|bytes| bytes.len() > 4096) {
            return Err(SwiftLiveError::Corrupt);
        }
        Ok(snapshot)
    }

    /// Stores the empty, checkpoint-bound stump before the first block transition.
    pub(crate) fn initialize_stump_snapshot(
        &mut self,
        snapshot: &[u8],
    ) -> Result<(), SwiftLiveError> {
        if self.state.height != self.binding.start_height || snapshot.len() > 4096 {
            return Err(SwiftLiveError::BindingMismatch);
        }
        let write = self
            .db
            .begin_write()
            .map_err(|e| db_error("begin stump initialization", e))?;
        {
            let mut stump = write
                .open_table(STUMP)
                .map_err(|_| SwiftLiveError::Corrupt)?;
            if stump
                .get(STUMP_KEY)
                .map_err(|e| db_error("check initial stump", e))?
                .is_some()
            {
                return Err(SwiftLiveError::BindingMismatch);
            }
            stump
                .insert(STUMP_KEY, snapshot)
                .map_err(|e| db_error("write initial stump", e))?;
        }
        write
            .commit()
            .map_err(|e| db_error("commit initial stump", e))?;
        Ok(())
    }

    /// Marks a successfully audited target complete, atomically retaining its final secret state.
    pub(crate) fn mark_complete(&mut self, audit_snapshot: &[u8]) -> Result<(), SwiftLiveError> {
        if self.state.height != self.binding.target_height
            || self.state.hash != self.binding.target_hash
            || audit_snapshot.len() != 321
        {
            return Err(SwiftLiveError::CheckpointMismatch);
        }
        let write = self
            .db
            .begin_write()
            .map_err(|e| db_error("begin completion", e))?;
        let mut next = self.state;
        next.complete = true;
        {
            let mut audit = write
                .open_table(AUDIT)
                .map_err(|_| SwiftLiveError::Corrupt)?;
            audit
                .insert(AUDIT_KEY, audit_snapshot)
                .map_err(|e| db_error("persist final audit", e))?;
        }
        {
            let mut meta = write
                .open_table(META)
                .map_err(|_| SwiftLiveError::Corrupt)?;
            meta.insert(
                META_KEY,
                encode_state(self.binding, self.limits, next).as_slice(),
            )
            .map_err(|e| db_error("mark complete", e))?;
        }
        write
            .commit()
            .map_err(|e| db_error("commit completion", e))?;
        self.state = next;
        Ok(())
    }

    /// Exact current-live outpoint metadata. Spent outpoints have no row.
    pub fn get(&self, outpoint: &OutPoint) -> Result<Option<LiveCoinMeta>, SwiftLiveError> {
        let key = crate::utxo_snapshot::outpoint_key(outpoint);
        let read = self
            .db
            .begin_read()
            .map_err(|e| db_error("begin lookup", e))?;
        let table = read
            .open_table(COINS)
            .map_err(|e| db_error("open lookup table", e))?;
        let row = table
            .get(&key[..])
            .map_err(|e| db_error("lookup row", e))?
            .map(|r| decode_row(&key, r.value()))
            .transpose()?;
        if row.is_some_and(|meta| meta.height == 0 || meta.height > self.state.height) {
            return Err(SwiftLiveError::Corrupt);
        }
        Ok(row)
    }

    /// True only when an exact row exists in the live-only table.
    pub fn is_live(&self, outpoint: &OutPoint) -> Result<bool, SwiftLiveError> {
        Ok(self.get(outpoint)?.is_some_and(|row| row.live))
    }

    /// Commit one validated block's ordered input/output events and advance its tip atomically.
    pub fn apply_block(
        &mut self,
        height: u32,
        previous_hash: BlockHash,
        block_hash: BlockHash,
        events: &[LiveEvent],
    ) -> Result<(), SwiftLiveError> {
        self.apply_block_inner(
            height,
            previous_hash,
            block_hash,
            events,
            None,
            None,
            None,
            None,
            &[],
        )
    }

    /// Atomically commits a validated block, its private audit snapshot, and ordered
    /// provisional-survivor updates in this same redb transaction.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_validated_block(
        &mut self,
        height: u32,
        previous_hash: BlockHash,
        block_hash: BlockHash,
        events: &[LiveEvent],
        audit_snapshot: &[u8],
        stump_snapshot: Option<&[u8]>,
        survivor_updates: &[(OutPoint, Option<&Coin>)],
    ) -> Result<(), SwiftLiveError> {
        self.apply_block_inner(
            height,
            previous_hash,
            block_hash,
            events,
            Some(audit_snapshot),
            stump_snapshot,
            None,
            None,
            survivor_updates,
        )
    }

    /// Full-validation variant that durably retains block bytes and ordinary
    /// connector undo alongside the checkpoint audit material.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_full_validated_block(
        &mut self,
        height: u32,
        previous_hash: BlockHash,
        block: &crate::block::Block,
        undo: &crate::connect::BlockUndo,
        n_chain_tx: u64,
        events: &[LiveEvent],
        audit_snapshot: &[u8],
        stump_snapshot: Option<&[u8]>,
        survivor_updates: &[(OutPoint, Option<&Coin>)],
    ) -> Result<(), SwiftLiveError> {
        let block_hash = block.block_hash();
        self.apply_block_inner(
            height,
            previous_hash,
            block_hash,
            events,
            Some(audit_snapshot),
            stump_snapshot,
            Some((block, undo)),
            Some((
                u32::try_from(block.transactions.len()).map_err(|_| SwiftLiveError::Overflow)?,
                n_chain_tx,
            )),
            survivor_updates,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_block_inner(
        &mut self,
        height: u32,
        previous_hash: BlockHash,
        block_hash: BlockHash,
        events: &[LiveEvent],
        audit_snapshot: Option<&[u8]>,
        stump_snapshot: Option<&[u8]>,
        full_block: Option<(&crate::block::Block, &crate::connect::BlockUndo)>,
        tx_meta: Option<(u32, u64)>,
        survivor_updates: &[(OutPoint, Option<&Coin>)],
    ) -> Result<(), SwiftLiveError> {
        if height
            != self
                .state
                .height
                .checked_add(1)
                .ok_or(SwiftLiveError::Overflow)?
            || previous_hash != self.state.hash
            || height > self.binding.target_height
        {
            return Err(SwiftLiveError::TipMismatch);
        }
        if self.state.complete {
            return Err(SwiftLiveError::TipMismatch);
        }
        if events.len() > self.limits.max_block_events {
            return Err(SwiftLiveError::EventLimit);
        }
        if height == self.binding.target_height && block_hash != self.binding.target_hash {
            return Err(SwiftLiveError::CheckpointMismatch);
        }
        let encoded_full_undo = full_block
            .map(|(block, undo)| encode_full_undo(previous_hash, block, undo))
            .transpose()?;
        let encoded_tx_meta =
            tx_meta.map(|(n_tx, n_chain_tx)| encode_tx_meta(block_hash, n_tx, n_chain_tx));
        if full_block.is_some() != tx_meta.is_some() {
            return Err(SwiftLiveError::BindingMismatch);
        }
        let write = self
            .db
            .begin_write()
            .map_err(|e| db_error("begin block", e))?;
        let mut next = self.state;
        let mut before = std::collections::BTreeMap::<[u8; 36], BeforeImage>::new();
        {
            let mut coins = write
                .open_table(COINS)
                .map_err(|e| db_error("open rows for block", e))?;
            let mut meta = write
                .open_table(META)
                .map_err(|e| db_error("open metadata for block", e))?;
            let mut audit = write
                .open_table(AUDIT)
                .map_err(|e| db_error("open audit state", e))?;
            let mut stump = write
                .open_table(STUMP)
                .map_err(|e| db_error("open stump state", e))?;
            let mut full_undo = write
                .open_table(BLOCK_UNDO)
                .map_err(|e| db_error("open full block undo", e))?;
            let mut active_tx_meta = write
                .open_table(TX_META)
                .map_err(|e| db_error("open active tx metadata", e))?;
            let mut survivors = write
                .open_table(SURVIVORS)
                .map_err(|e| db_error("open provisional survivors", e))?;
            let prior_audit_state = audit
                .get(AUDIT_KEY)
                .map_err(|e| db_error("read prior audit state", e))?
                .map(|row| row.value().to_vec());
            let prior_stump_state = stump
                .get(STUMP_KEY)
                .map_err(|e| db_error("read prior stump state", e))?
                .map(|row| row.value().to_vec());
            if stump_snapshot.is_some_and(|snapshot| snapshot.len() > 4096)
                || (stump_snapshot.is_some() != prior_stump_state.is_some())
                || (full_block.is_none()
                    && full_undo
                        .len()
                        .map_err(|e| db_error("count full undo", e))?
                        != 0)
                || (tx_meta.is_none()
                    && active_tx_meta
                        .len()
                        .map_err(|e| db_error("count active tx metadata", e))?
                        != 0)
            {
                return Err(SwiftLiveError::BindingMismatch);
            }
            // Preflight journal growth before cloning any old survivor script into
            // the in-memory before-image map. The 108-byte base includes count,
            // hashes, both state lengths, and checksum; each unique key adds 46 bytes
            // plus its old provisional coin encoding.
            let mut journal_value_bytes = 108usize
                .checked_add(prior_audit_state.as_ref().map_or(0, Vec::len))
                .and_then(|n| n.checked_add(prior_stump_state.as_ref().map_or(0, Vec::len)))
                .ok_or(SwiftLiveError::Overflow)?;
            if next
                .undo_bytes
                .checked_add(
                    4u64.checked_add(
                        u64::try_from(journal_value_bytes).map_err(|_| SwiftLiveError::Overflow)?,
                    )
                    .ok_or(SwiftLiveError::Overflow)?,
                )
                .is_none_or(|bytes| bytes > self.limits.max_undo_encoded_bytes)
            {
                return Err(SwiftLiveError::ByteLimit);
            }
            let stored = meta
                .get(META_KEY)
                .map_err(|e| db_error("read state before block", e))?
                .ok_or(SwiftLiveError::Corrupt)?;
            let (binding, limits, state) = decode_state(stored.value())?;
            if binding != self.binding || limits != self.limits || state != self.state {
                return Err(SwiftLiveError::Corrupt);
            }
            drop(stored);
            for event in events {
                let (key, action) = match *event {
                    LiveEvent::Spend {
                        outpoint,
                        height: claim_height,
                        coinbase: claim_coinbase,
                    } => {
                        let key = crate::utxo_snapshot::outpoint_key(&outpoint);
                        let current = coins
                            .get(&key[..])
                            .map_err(|e| db_error("read spend", e))?
                            .map(|r| decode_row(&key, r.value()))
                            .transpose()?
                            .ok_or(SwiftLiveError::MissingOrSpent)?;
                        if current.height != claim_height || current.coinbase != claim_coinbase {
                            return Err(SwiftLiveError::ClaimMismatch);
                        }
                        (key, None)
                    }
                    LiveEvent::Create {
                        outpoint,
                        height: creation_height,
                        coinbase,
                        allow_live_overwrite,
                    } => {
                        if creation_height != height {
                            return Err(SwiftLiveError::ClaimMismatch);
                        }
                        let key = crate::utxo_snapshot::outpoint_key(&outpoint);
                        let current = coins
                            .get(&key[..])
                            .map_err(|e| db_error("read create", e))?
                            .map(|r| decode_row(&key, r.value()))
                            .transpose()?;
                        if current.is_some() && !allow_live_overwrite {
                            return Err(SwiftLiveError::DuplicateLiveOutput);
                        }
                        (
                            key,
                            Some(LiveCoinMeta {
                                height: creation_height,
                                coinbase,
                                live: true,
                            }),
                        )
                    }
                };
                let current = coins
                    .get(&key[..])
                    .map_err(|e| db_error("read event row", e))?
                    .map(|row| decode_row(&key, row.value()))
                    .transpose()?;
                if let std::collections::btree_map::Entry::Vacant(entry) = before.entry(key) {
                    let survivor_row = survivors
                        .get(&key[..])
                        .map_err(|e| db_error("read survivor preimage", e))?;
                    let survivor_len = survivor_row.as_ref().map_or(0, |row| row.value().len());
                    journal_value_bytes = journal_value_bytes
                        .checked_add(46)
                        .and_then(|n| n.checked_add(survivor_len))
                        .ok_or(SwiftLiveError::Overflow)?;
                    if next
                        .undo_bytes
                        .checked_add(
                            4u64.checked_add(
                                u64::try_from(journal_value_bytes)
                                    .map_err(|_| SwiftLiveError::Overflow)?,
                            )
                            .ok_or(SwiftLiveError::Overflow)?,
                        )
                        .is_none_or(|bytes| bytes > self.limits.max_undo_encoded_bytes)
                    {
                        return Err(SwiftLiveError::ByteLimit);
                    }
                    let survivor = survivor_row.map(|row| row.value().to_vec());
                    entry.insert(BeforeImage {
                        live: current.map(encode_row),
                        survivor,
                    });
                }
                match action {
                    None => {
                        current.ok_or(SwiftLiveError::MissingOrSpent)?;
                        coins
                            .remove(&key[..])
                            .map_err(|e| db_error("remove spent row", e))?;
                        next.live_entries = next
                            .live_entries
                            .checked_sub(1)
                            .ok_or(SwiftLiveError::Corrupt)?;
                        next.live_bytes = next
                            .live_bytes
                            .checked_sub((36 + ROW_LEN) as u64)
                            .ok_or(SwiftLiveError::Corrupt)?;
                    }
                    Some(value) => {
                        if current.is_none() {
                            next.live_entries = next
                                .live_entries
                                .checked_add(1)
                                .ok_or(SwiftLiveError::Overflow)?;
                            next.live_bytes = next
                                .live_bytes
                                .checked_add((36 + ROW_LEN) as u64)
                                .ok_or(SwiftLiveError::Overflow)?;
                        }
                        if next.live_entries > self.limits.max_live_entries {
                            return Err(SwiftLiveError::EntryLimit);
                        }
                        if next.live_bytes > self.limits.max_live_encoded_bytes {
                            return Err(SwiftLiveError::ByteLimit);
                        }
                        let row = encode_row(value);
                        coins
                            .insert(&key[..], row.as_slice())
                            .map_err(|e| db_error("write live row", e))?;
                    }
                }
            }
            for (outpoint, replacement) in survivor_updates {
                let key = crate::utxo_snapshot::outpoint_key(outpoint);
                if let std::collections::btree_map::Entry::Vacant(entry) = before.entry(key) {
                    let live = coins
                        .get(&key[..])
                        .map_err(|e| db_error("read survivor update live preimage", e))?
                        .map(|row| decode_row(&key, row.value()).map(encode_row))
                        .transpose()?;
                    let survivor = survivors
                        .get(&key[..])
                        .map_err(|e| db_error("read survivor update preimage", e))?;
                    let survivor_len = survivor.as_ref().map_or(0, |row| row.value().len());
                    journal_value_bytes = journal_value_bytes
                        .checked_add(46)
                        .and_then(|n| n.checked_add(survivor_len))
                        .ok_or(SwiftLiveError::Overflow)?;
                    if next
                        .undo_bytes
                        .checked_add(
                            4u64.checked_add(
                                u64::try_from(journal_value_bytes)
                                    .map_err(|_| SwiftLiveError::Overflow)?,
                            )
                            .ok_or(SwiftLiveError::Overflow)?,
                        )
                        .is_none_or(|bytes| bytes > self.limits.max_undo_encoded_bytes)
                    {
                        return Err(SwiftLiveError::ByteLimit);
                    }
                    let survivor = survivor.map(|row| row.value().to_vec());
                    entry.insert(BeforeImage { live, survivor });
                }
                let existing = survivors
                    .get(&key[..])
                    .map_err(|e| db_error("read provisional coin", e))?
                    .map(|row| row.value().to_vec());
                match replacement {
                    Some(coin) => {
                        if coin.height != height
                            || !(0..=crate::check::MAX_MONEY).contains(&coin.out.value)
                            || coin.out.script_pubkey.len()
                                > crate::swift_audit::MAX_AUDIT_SCRIPT_BYTES
                        {
                            return Err(SwiftLiveError::ClaimMismatch);
                        }
                        let encoded = crate::coinsdb::encode_coin(coin, CoinFormat::Compact);
                        let old_size = existing.as_ref().map_or(0, |old| (36 + old.len()) as u64);
                        let new_size = (36 + encoded.len()) as u64;
                        next.survivor_bytes = next
                            .survivor_bytes
                            .checked_sub(old_size)
                            .and_then(|bytes| bytes.checked_add(new_size))
                            .ok_or(SwiftLiveError::Overflow)?;
                        if existing.is_none() {
                            next.survivor_entries = next
                                .survivor_entries
                                .checked_add(1)
                                .ok_or(SwiftLiveError::Overflow)?;
                        }
                        survivors
                            .insert(&key[..], encoded.as_slice())
                            .map_err(|e| db_error("write provisional coin", e))?;
                    }
                    None => {
                        if let Some(old) = existing {
                            next.survivor_entries = next
                                .survivor_entries
                                .checked_sub(1)
                                .ok_or(SwiftLiveError::Corrupt)?;
                            next.survivor_bytes = next
                                .survivor_bytes
                                .checked_sub((36 + old.len()) as u64)
                                .ok_or(SwiftLiveError::Corrupt)?;
                            survivors
                                .remove(&key[..])
                                .map_err(|e| db_error("remove provisional coin", e))?;
                        }
                    }
                }
                if next.survivor_entries > self.limits.max_survivor_entries
                    || next.survivor_bytes > self.limits.max_survivor_encoded_bytes
                {
                    return Err(SwiftLiveError::ByteLimit);
                }
            }
            if let Some(snapshot) = audit_snapshot {
                if snapshot.len() != 321 {
                    return Err(SwiftLiveError::Corrupt);
                }
                audit
                    .insert(AUDIT_KEY, snapshot)
                    .map_err(|e| db_error("write private audit state", e))?;
            }
            if let Some(snapshot) = stump_snapshot {
                stump
                    .insert(STUMP_KEY, snapshot)
                    .map_err(|e| db_error("write stump snapshot", e))?;
            }
            let journal = encode_journal(
                self.state.hash,
                block_hash,
                &before,
                prior_audit_state.as_deref(),
                prior_stump_state.as_deref(),
            )?;
            next.undo_bytes = next
                .undo_bytes
                .checked_add(
                    4 + u64::try_from(journal.len()).map_err(|_| SwiftLiveError::Overflow)?,
                )
                .ok_or(SwiftLiveError::Overflow)?;
            let key = height.to_be_bytes();
            let mut undo = write
                .open_table(UNDO)
                .map_err(|e| db_error("open journal", e))?;
            if undo
                .get(&key[..])
                .map_err(|e| db_error("check journal", e))?
                .is_some()
            {
                return Err(SwiftLiveError::Corrupt);
            }
            undo.insert(&key[..], journal.as_slice())
                .map_err(|e| db_error("write journal", e))?;
            if let Some(encoded) = &encoded_tx_meta {
                if active_tx_meta
                    .get(&key[..])
                    .map_err(|e| db_error("check active tx metadata height", e))?
                    .is_some()
                {
                    return Err(SwiftLiveError::Corrupt);
                }
                active_tx_meta
                    .insert(&key[..], encoded.as_slice())
                    .map_err(|e| db_error("write active tx metadata", e))?;
            }
            if let Some(encoded) = &encoded_full_undo {
                if full_undo
                    .get(&key[..])
                    .map_err(|e| db_error("check full undo height", e))?
                    .is_some()
                {
                    return Err(SwiftLiveError::Corrupt);
                }
                full_undo
                    .insert(&key[..], encoded.as_slice())
                    .map_err(|e| db_error("write full block undo", e))?;
                next.undo_bytes = next
                    .undo_bytes
                    .checked_add(
                        4 + u64::try_from(encoded.len()).map_err(|_| SwiftLiveError::Overflow)?,
                    )
                    .ok_or(SwiftLiveError::Overflow)?;
            }
            let prune_height = height.saturating_sub(DEFAULT_REORG_DEPTH);
            if prune_height > self.binding.start_height {
                let prune_key = prune_height.to_be_bytes();
                if let Some(old) = full_undo
                    .remove(&prune_key[..])
                    .map_err(|e| db_error("prune full block undo", e))?
                {
                    next.undo_bytes = next
                        .undo_bytes
                        .checked_sub(
                            4 + u64::try_from(old.value().len())
                                .map_err(|_| SwiftLiveError::Overflow)?,
                        )
                        .ok_or(SwiftLiveError::Corrupt)?;
                }
            }
            while height - next.undo_floor > self.limits.max_reorg_depth {
                let prune_height = next
                    .undo_floor
                    .checked_add(1)
                    .ok_or(SwiftLiveError::Overflow)?;
                let prune_key = prune_height.to_be_bytes();
                let old_journal = undo
                    .get(&prune_key[..])
                    .map_err(|e| db_error("read expired journal", e))?
                    .ok_or(SwiftLiveError::Corrupt)?;
                let old_size = 4u64
                    .checked_add(
                        u64::try_from(old_journal.value().len())
                            .map_err(|_| SwiftLiveError::Overflow)?,
                    )
                    .ok_or(SwiftLiveError::Overflow)?;
                drop(old_journal);
                undo.remove(&prune_key[..])
                    .map_err(|e| db_error("prune expired journal", e))?;
                next.undo_bytes = next
                    .undo_bytes
                    .checked_sub(old_size)
                    .ok_or(SwiftLiveError::Corrupt)?;
                next.undo_floor = prune_height;
            }
            if next.undo_bytes > self.limits.max_undo_encoded_bytes {
                return Err(SwiftLiveError::ByteLimit);
            }
            drop(undo);
            next.height = height;
            next.hash = block_hash;
            meta.insert(
                META_KEY,
                encode_state(self.binding, self.limits, next).as_slice(),
            )
            .map_err(|e| db_error("advance tip", e))?;
        }
        write.commit().map_err(|e| db_error("commit block", e))?;
        self.state = next;
        Ok(())
    }

    /// Rewind exactly the current block, restoring its prior rows and previous tip.
    pub fn rewind_one(&mut self, expected_tip: BlockHash) -> Result<BlockHash, SwiftLiveError> {
        if self.state.height <= self.state.undo_floor || self.state.hash != expected_tip {
            return Err(SwiftLiveError::RewindMismatch);
        }
        let height_key = self.state.height.to_be_bytes();
        let read = self
            .db
            .begin_read()
            .map_err(|e| db_error("begin rewind read", e))?;
        let bytes = {
            let undo = read.open_table(UNDO).map_err(|_| SwiftLiveError::Corrupt)?;
            undo.get(&height_key[..])
                .map_err(|e| db_error("read rewind journal", e))?
                .ok_or(SwiftLiveError::Corrupt)?
                .value()
                .to_vec()
        };
        drop(read);
        let (previous_hash, block_hash, audit_before, stump_before, before) =
            decode_journal(&bytes)?;
        if block_hash != self.state.hash {
            return Err(SwiftLiveError::RewindMismatch);
        }
        let write = self
            .db
            .begin_write()
            .map_err(|e| db_error("begin rewind", e))?;
        let mut next = self.state;
        next.undo_bytes = next
            .undo_bytes
            .checked_sub(4 + u64::try_from(bytes.len()).map_err(|_| SwiftLiveError::Overflow)?)
            .ok_or(SwiftLiveError::Corrupt)?;
        {
            let mut coins = write
                .open_table(COINS)
                .map_err(|e| db_error("open rows for rewind", e))?;
            let mut survivors = write
                .open_table(SURVIVORS)
                .map_err(|e| db_error("open survivors for rewind", e))?;
            for (key, old) in before {
                let current = coins
                    .get(&key[..])
                    .map_err(|e| db_error("read reverted row", e))?
                    .map(|row| decode_row(&key, row.value()))
                    .transpose()?;
                match (current, old.live) {
                    (None, None) => {}
                    (Some(_), None) => {
                        coins
                            .remove(&key[..])
                            .map_err(|e| db_error("remove reverted row", e))?;
                        next.live_entries = next
                            .live_entries
                            .checked_sub(1)
                            .ok_or(SwiftLiveError::Corrupt)?;
                        next.live_bytes = next
                            .live_bytes
                            .checked_sub((36 + ROW_LEN) as u64)
                            .ok_or(SwiftLiveError::Corrupt)?;
                    }
                    (None, Some(old)) => {
                        decode_row(&key, &old)?;
                        coins
                            .insert(&key[..], old.as_slice())
                            .map_err(|e| db_error("restore row", e))?;
                        next.live_entries = next
                            .live_entries
                            .checked_add(1)
                            .ok_or(SwiftLiveError::Overflow)?;
                        next.live_bytes = next
                            .live_bytes
                            .checked_add((36 + ROW_LEN) as u64)
                            .ok_or(SwiftLiveError::Overflow)?;
                    }
                    (Some(_), Some(old)) => {
                        decode_row(&key, &old)?;
                        coins
                            .insert(&key[..], old.as_slice())
                            .map_err(|e| db_error("restore row metadata", e))?;
                    }
                }
                let current_survivor = survivors
                    .get(&key[..])
                    .map_err(|e| db_error("read survivor for rewind", e))?
                    .map(|row| row.value().to_vec());
                match (current_survivor, old.survivor) {
                    (None, None) => {}
                    (Some(_), None) => {
                        let row = survivors
                            .remove(&key[..])
                            .map_err(|e| db_error("remove reverted survivor", e))?
                            .ok_or(SwiftLiveError::Corrupt)?;
                        next.survivor_entries = next
                            .survivor_entries
                            .checked_sub(1)
                            .ok_or(SwiftLiveError::Corrupt)?;
                        next.survivor_bytes = next
                            .survivor_bytes
                            .checked_sub((36 + row.value().len()) as u64)
                            .ok_or(SwiftLiveError::Corrupt)?;
                    }
                    (None, Some(old)) => {
                        survivors
                            .insert(&key[..], old.as_slice())
                            .map_err(|e| db_error("restore survivor", e))?;
                        next.survivor_entries = next
                            .survivor_entries
                            .checked_add(1)
                            .ok_or(SwiftLiveError::Overflow)?;
                        next.survivor_bytes = next
                            .survivor_bytes
                            .checked_add((36 + old.len()) as u64)
                            .ok_or(SwiftLiveError::Overflow)?;
                    }
                    (Some(current), Some(old)) => {
                        survivors
                            .insert(&key[..], old.as_slice())
                            .map_err(|e| db_error("restore survivor record", e))?;
                        next.survivor_bytes = next
                            .survivor_bytes
                            .checked_sub((36 + current.len()) as u64)
                            .and_then(|bytes| bytes.checked_add((36 + old.len()) as u64))
                            .ok_or(SwiftLiveError::Overflow)?;
                    }
                }
            }
        }
        {
            let mut audit = write
                .open_table(AUDIT)
                .map_err(|e| db_error("open audit for rewind", e))?;
            match audit_before {
                Some(state) => {
                    audit
                        .insert(AUDIT_KEY, state.as_slice())
                        .map_err(|e| db_error("restore audit state", e))?;
                }
                None => {
                    audit
                        .remove(AUDIT_KEY)
                        .map_err(|e| db_error("remove audit state", e))?;
                }
            }
        }
        {
            let mut stump = write
                .open_table(STUMP)
                .map_err(|_| SwiftLiveError::Corrupt)?;
            match stump_before {
                Some(state) => {
                    stump
                        .insert(STUMP_KEY, state.as_slice())
                        .map_err(|e| db_error("restore stump state", e))?;
                }
                None => {
                    stump
                        .remove(STUMP_KEY)
                        .map_err(|e| db_error("remove stump state", e))?;
                }
            }
        }
        {
            let mut undo = write
                .open_table(UNDO)
                .map_err(|e| db_error("open journal for rewind", e))?;
            undo.remove(&height_key[..])
                .map_err(|e| db_error("remove journal", e))?;
        }
        {
            let mut full_undo = write
                .open_table(BLOCK_UNDO)
                .map_err(|_| SwiftLiveError::Corrupt)?;
            if let Some(removed) = full_undo
                .remove(&height_key[..])
                .map_err(|e| db_error("remove full block undo", e))?
            {
                next.undo_bytes = next
                    .undo_bytes
                    .checked_sub(
                        4 + u64::try_from(removed.value().len())
                            .map_err(|_| SwiftLiveError::Overflow)?,
                    )
                    .ok_or(SwiftLiveError::Corrupt)?;
            }
        }
        {
            let mut tx_meta = write
                .open_table(TX_META)
                .map_err(|_| SwiftLiveError::Corrupt)?;
            tx_meta
                .remove(&height_key[..])
                .map_err(|e| db_error("remove active tx metadata", e))?;
        }
        next.height -= 1;
        next.hash = previous_hash;
        next.complete = false;
        {
            let mut meta = write
                .open_table(META)
                .map_err(|e| db_error("open metadata for rewind", e))?;
            meta.insert(
                META_KEY,
                encode_state(self.binding, self.limits, next).as_slice(),
            )
            .map_err(|e| db_error("restore tip", e))?;
        }
        write.commit().map_err(|e| db_error("commit rewind", e))?;
        self.state = next;
        Ok(previous_hash)
    }

    /// Stream all currently live outpoints in key order without collecting them in memory.
    pub fn for_each_live(
        &self,
        mut visit: impl FnMut(OutPoint, LiveCoinMeta) -> Result<(), SwiftLiveError>,
    ) -> Result<(), SwiftLiveError> {
        let read = self
            .db
            .begin_read()
            .map_err(|e| db_error("begin live scan", e))?;
        let table = read
            .open_table(COINS)
            .map_err(|e| db_error("open live scan", e))?;
        let rows = table.iter().map_err(|e| db_error("iterate rows", e))?;
        for row in rows {
            let (key, value) = row.map_err(|e| db_error("read live row", e))?;
            if key.value().len() != 36 {
                return Err(SwiftLiveError::Corrupt);
            }
            let mut key_bytes = [0u8; 36];
            key_bytes.copy_from_slice(key.value());
            let meta = decode_row(&key_bytes, value.value())?;
            if meta.height == 0 || meta.height > self.state.height {
                return Err(SwiftLiveError::Corrupt);
            }
            let outpoint = OutPoint {
                txid: Txid::from_bytes(
                    key_bytes[..32]
                        .try_into()
                        .map_err(|_| SwiftLiveError::Corrupt)?,
                ),
                vout: u32::from_be_bytes(
                    key_bytes[32..]
                        .try_into()
                        .map_err(|_| SwiftLiveError::Corrupt)?,
                ),
            };
            visit(outpoint, meta)?;
        }
        Ok(())
    }
}

fn validate(binding: SwiftLiveBinding, limits: SwiftLiveLimits) -> Result<(), SwiftLiveError> {
    if binding.start_height >= binding.target_height
        || limits.max_live_entries == 0
        || limits.max_live_encoded_bytes < (36 + ROW_LEN) as u64
        || limits.max_undo_encoded_bytes < (4 + 68 + 32) as u64
        || limits.max_survivor_entries == 0
        || limits.max_survivor_encoded_bytes < 41
        || limits.max_reorg_depth == 0
        || limits.max_reorg_depth > MAX_REORG_DEPTH
        || limits.max_block_events == 0
        || limits.max_block_events > MAX_BLOCK_EVENTS
        || limits.cache_bytes == 0
        || limits.cache_bytes > MAX_CACHE_BYTES
    {
        return Err(SwiftLiveError::InvalidConfig);
    }
    Ok(())
}
fn builder(limits: SwiftLiveLimits) -> redb::Builder {
    let mut b = redb::Database::builder();
    b.set_cache_size(limits.cache_bytes);
    b
}
fn db_error(operation: &'static str, error: impl std::fmt::Display) -> SwiftLiveError {
    SwiftLiveError::Database {
        operation,
        message: error.to_string(),
    }
}
fn checksum(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}
fn ct_eq(a: &[u8; 32], b: &[u8]) -> bool {
    if b.len() != 32 {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}
fn encode_row(meta: LiveCoinMeta) -> [u8; ROW_LEN] {
    let mut out = [0; ROW_LEN];
    out[..4].copy_from_slice(&meta.height.to_le_bytes());
    out[4] = u8::from(meta.coinbase);
    out
}
fn decode_row(key: &[u8; 36], bytes: &[u8]) -> Result<LiveCoinMeta, SwiftLiveError> {
    let _ = key;
    if bytes.len() != ROW_LEN || bytes[4] > 1 {
        return Err(SwiftLiveError::Corrupt);
    }
    Ok(LiveCoinMeta {
        height: u32::from_le_bytes(bytes[..4].try_into().map_err(|_| SwiftLiveError::Corrupt)?),
        coinbase: bytes[4] != 0,
        live: true,
    })
}
fn decode_outpoint(key: &[u8; 36]) -> Result<OutPoint, SwiftLiveError> {
    Ok(OutPoint {
        txid: Txid::from_bytes(key[..32].try_into().map_err(|_| SwiftLiveError::Corrupt)?),
        vout: u32::from_be_bytes(key[32..].try_into().map_err(|_| SwiftLiveError::Corrupt)?),
    })
}
fn encode_journal(
    previous: BlockHash,
    current: BlockHash,
    rows: &std::collections::BTreeMap<[u8; 36], BeforeImage>,
    audit_before: Option<&[u8]>,
    stump_before: Option<&[u8]>,
) -> Result<Vec<u8>, SwiftLiveError> {
    let count = u32::try_from(rows.len()).map_err(|_| SwiftLiveError::Overflow)?;
    let audit_len = u32::try_from(audit_before.map_or(0, |state| state.len()))
        .map_err(|_| SwiftLiveError::Overflow)?;
    if audit_len != 0 && audit_len != 321 {
        return Err(SwiftLiveError::Corrupt);
    }
    let stump_len = u32::try_from(stump_before.map_or(0, |state| state.len()))
        .map_err(|_| SwiftLiveError::Overflow)?;
    if stump_len > 4096 {
        return Err(SwiftLiveError::Corrupt);
    }
    let survivor_bytes = rows.values().try_fold(0usize, |total, before| {
        total
            .checked_add(before.survivor.as_ref().map_or(0, Vec::len))
            .ok_or(SwiftLiveError::Overflow)
    })?;
    let capacity = 76usize
        .checked_add(audit_len as usize)
        .and_then(|n| n.checked_add(stump_len as usize))
        .and_then(|n| n.checked_add(rows.len().checked_mul(46)?))
        .and_then(|n| n.checked_add(survivor_bytes))
        .and_then(|n| n.checked_add(32))
        .ok_or(SwiftLiveError::Overflow)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(previous.as_bytes());
    out.extend_from_slice(current.as_bytes());
    out.extend_from_slice(&audit_len.to_le_bytes());
    out.extend_from_slice(&stump_len.to_le_bytes());
    if let Some(audit) = audit_before {
        out.extend_from_slice(audit);
    }
    if let Some(stump) = stump_before {
        out.extend_from_slice(stump);
    }
    for (key, before) in rows {
        out.extend_from_slice(key);
        match before.live {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&v);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0; ROW_LEN]);
            }
        }
        match &before.survivor {
            Some(value) => {
                out.extend_from_slice(
                    &u32::try_from(value.len())
                        .map_err(|_| SwiftLiveError::Overflow)?
                        .to_le_bytes(),
                );
                out.extend_from_slice(value);
            }
            None => out.extend_from_slice(&u32::MAX.to_le_bytes()),
        }
    }
    let sum = checksum(UNDO_DOMAIN, &out);
    out.extend_from_slice(&sum);
    Ok(out)
}

fn encode_full_undo(
    previous: BlockHash,
    block: &crate::block::Block,
    undo: &crate::connect::BlockUndo,
) -> Result<Vec<u8>, SwiftLiveError> {
    if undo.txs.len() > MAX_BLOCK_EVENTS
        || block.header.prev_block_hash != previous
        || block.size_with_witness() > crate::block::MAX_BLOCK_SERIALIZED_SIZE
    {
        return Err(SwiftLiveError::EventLimit);
    }
    let body = block.encode();
    let mut out = Vec::new();
    out.extend_from_slice(FULL_UNDO_MAGIC);
    out.extend_from_slice(previous.as_bytes());
    out.extend_from_slice(block.block_hash().as_bytes());
    out.extend_from_slice(
        &u32::try_from(body.len())
            .map_err(|_| SwiftLiveError::Overflow)?
            .to_le_bytes(),
    );
    out.extend_from_slice(&body);
    out.extend_from_slice(
        &u32::try_from(undo.txs.len())
            .map_err(|_| SwiftLiveError::Overflow)?
            .to_le_bytes(),
    );
    let mut event_count = 0usize;
    for tx in &undo.txs {
        event_count = event_count
            .checked_add(tx.spent.len())
            .and_then(|n| n.checked_add(tx.overwritten.len()))
            .ok_or(SwiftLiveError::Overflow)?;
        if event_count > MAX_BLOCK_EVENTS {
            return Err(SwiftLiveError::EventLimit);
        }
        out.extend_from_slice(
            &u32::try_from(tx.spent.len())
                .map_err(|_| SwiftLiveError::Overflow)?
                .to_le_bytes(),
        );
        for coin in &tx.spent {
            push_undo_coin(&mut out, coin)?;
        }
        out.extend_from_slice(
            &u32::try_from(tx.overwritten.len())
                .map_err(|_| SwiftLiveError::Overflow)?
                .to_le_bytes(),
        );
        for (outpoint, coin) in &tx.overwritten {
            out.extend_from_slice(&crate::utxo_snapshot::outpoint_key(outpoint));
            push_undo_coin(&mut out, coin)?;
        }
        if out.len() > 64 * 1024 * 1024 {
            return Err(SwiftLiveError::ByteLimit);
        }
    }
    let sum = checksum(FULL_UNDO_MAGIC, &out);
    out.extend_from_slice(&sum);
    Ok(out)
}

fn encode_tx_meta(hash: BlockHash, n_tx: u32, n_chain_tx: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(84);
    out.extend_from_slice(TX_META_MAGIC);
    out.extend_from_slice(hash.as_bytes());
    out.extend_from_slice(&n_tx.to_le_bytes());
    out.extend_from_slice(&n_chain_tx.to_le_bytes());
    let sum = checksum(TX_META_MAGIC, &out);
    out.extend_from_slice(&sum);
    out
}

fn decode_tx_meta(bytes: &[u8]) -> Result<(BlockHash, u32, u64), SwiftLiveError> {
    if bytes.len() != 84 || &bytes[..8] != TX_META_MAGIC {
        return Err(SwiftLiveError::Corrupt);
    }
    let sum = checksum(TX_META_MAGIC, &bytes[..52]);
    if !ct_eq(&sum, &bytes[52..]) {
        return Err(SwiftLiveError::Corrupt);
    }
    let hash = BlockHash::from_bytes(
        bytes[8..40]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    );
    let n_tx = u32::from_le_bytes(
        bytes[40..44]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    );
    let n_chain_tx = u64::from_le_bytes(
        bytes[44..52]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    );
    Ok((hash, n_tx, n_chain_tx))
}

fn push_undo_coin(out: &mut Vec<u8>, coin: &Coin) -> Result<(), SwiftLiveError> {
    if !(0..=crate::check::MAX_MONEY).contains(&coin.out.value)
        || coin.out.script_pubkey.len() > crate::swift_audit::MAX_AUDIT_SCRIPT_BYTES
    {
        return Err(SwiftLiveError::ByteLimit);
    }
    let encoded = crate::coinsdb::encode_coin(coin, CoinFormat::Compact);
    out.extend_from_slice(
        &u32::try_from(encoded.len())
            .map_err(|_| SwiftLiveError::Overflow)?
            .to_le_bytes(),
    );
    out.extend_from_slice(&encoded);
    Ok(())
}

fn decode_full_undo(
    bytes: &[u8],
) -> Result<
    (
        BlockHash,
        BlockHash,
        crate::block::Block,
        crate::connect::BlockUndo,
    ),
    SwiftLiveError,
> {
    if bytes.len() < 8 + 64 + 4 + 4 + 32 || &bytes[..8] != FULL_UNDO_MAGIC {
        return Err(SwiftLiveError::Corrupt);
    }
    let checksum_end = bytes.len() - 32;
    let sum = checksum(FULL_UNDO_MAGIC, &bytes[..checksum_end]);
    if !ct_eq(&sum, &bytes[checksum_end..]) {
        return Err(SwiftLiveError::Corrupt);
    }
    let previous = BlockHash::from_bytes(
        bytes[8..40]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    );
    let current = BlockHash::from_bytes(
        bytes[40..72]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    );
    let body_len = u32::from_le_bytes(
        bytes[72..76]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    ) as usize;
    if body_len > crate::block::MAX_BLOCK_SERIALIZED_SIZE {
        return Err(SwiftLiveError::Corrupt);
    }
    let block_end = 76usize
        .checked_add(body_len)
        .ok_or(SwiftLiveError::Corrupt)?;
    let body_bytes = bytes.get(76..block_end).ok_or(SwiftLiveError::Corrupt)?;
    let block = crate::block::Block::decode(body_bytes).map_err(|_| SwiftLiveError::Corrupt)?;
    if block.block_hash() != current || block.header.prev_block_hash != previous {
        return Err(SwiftLiveError::Corrupt);
    }
    let tx_count = u32::from_le_bytes(
        bytes
            .get(block_end..block_end + 4)
            .ok_or(SwiftLiveError::Corrupt)?
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    ) as usize;
    if tx_count > MAX_BLOCK_EVENTS {
        return Err(SwiftLiveError::Corrupt);
    }
    let mut cursor = block_end + 4;
    let mut event_count = 0usize;
    let mut txs = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        let spent_count = read_undo_count(bytes, &mut cursor, checksum_end)?;
        event_count = event_count
            .checked_add(spent_count)
            .ok_or(SwiftLiveError::Corrupt)?;
        if event_count > MAX_BLOCK_EVENTS {
            return Err(SwiftLiveError::Corrupt);
        }
        let mut spent = Vec::with_capacity(spent_count);
        for _ in 0..spent_count {
            spent.push(read_undo_coin(bytes, &mut cursor, checksum_end)?);
        }
        let overwritten_count = read_undo_count(bytes, &mut cursor, checksum_end)?;
        event_count = event_count
            .checked_add(overwritten_count)
            .ok_or(SwiftLiveError::Corrupt)?;
        if event_count > MAX_BLOCK_EVENTS {
            return Err(SwiftLiveError::Corrupt);
        }
        let mut overwritten = Vec::with_capacity(overwritten_count);
        for _ in 0..overwritten_count {
            let key: [u8; 36] = take_undo_bytes(bytes, &mut cursor, checksum_end, 36)?
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?;
            overwritten.push((
                decode_outpoint(&key)?,
                read_undo_coin(bytes, &mut cursor, checksum_end)?,
            ));
        }
        txs.push(crate::connect::TxUndo { spent, overwritten });
    }
    if cursor != checksum_end {
        return Err(SwiftLiveError::Corrupt);
    }
    if tx_count != block.transactions.len() {
        return Err(SwiftLiveError::Corrupt);
    }
    Ok((previous, current, block, crate::connect::BlockUndo { txs }))
}

fn read_undo_count(bytes: &[u8], cursor: &mut usize, end: usize) -> Result<usize, SwiftLiveError> {
    let raw: [u8; 4] = take_undo_bytes(bytes, cursor, end, 4)?
        .try_into()
        .map_err(|_| SwiftLiveError::Corrupt)?;
    let count = u32::from_le_bytes(raw) as usize;
    if count > MAX_BLOCK_EVENTS {
        return Err(SwiftLiveError::Corrupt);
    }
    Ok(count)
}

fn read_undo_coin(bytes: &[u8], cursor: &mut usize, end: usize) -> Result<Coin, SwiftLiveError> {
    let raw: [u8; 4] = take_undo_bytes(bytes, cursor, end, 4)?
        .try_into()
        .map_err(|_| SwiftLiveError::Corrupt)?;
    let len = u32::from_le_bytes(raw) as usize;
    let encoded = take_undo_bytes(bytes, cursor, end, len)?;
    let mut rest = encoded;
    let coin = crate::coinsdb::decode_coin_compact(&mut rest).ok_or(SwiftLiveError::Corrupt)?;
    if !rest.is_empty()
        || !(0..=crate::check::MAX_MONEY).contains(&coin.out.value)
        || coin.out.script_pubkey.len() > crate::swift_audit::MAX_AUDIT_SCRIPT_BYTES
    {
        return Err(SwiftLiveError::Corrupt);
    }
    Ok(coin)
}

fn take_undo_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    end: usize,
    len: usize,
) -> Result<&'a [u8], SwiftLiveError> {
    let next = cursor.checked_add(len).ok_or(SwiftLiveError::Corrupt)?;
    if next > end {
        return Err(SwiftLiveError::Corrupt);
    }
    let slice = bytes.get(*cursor..next).ok_or(SwiftLiveError::Corrupt)?;
    *cursor = next;
    Ok(slice)
}
fn decode_journal(bytes: &[u8]) -> Result<DecodedJournal, SwiftLiveError> {
    if bytes.len() < 4 + 64 + 8 + 32 {
        return Err(SwiftLiveError::Corrupt);
    }
    let count =
        u32::from_le_bytes(bytes[..4].try_into().map_err(|_| SwiftLiveError::Corrupt)?) as usize;
    if count > MAX_BLOCK_EVENTS {
        return Err(SwiftLiveError::Corrupt);
    }
    let body_end = bytes.len() - 32;
    let sum = checksum(UNDO_DOMAIN, &bytes[..body_end]);
    if !ct_eq(&sum, &bytes[body_end..]) {
        return Err(SwiftLiveError::Corrupt);
    }
    let previous = BlockHash::from_bytes(
        bytes[4..36]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    );
    let current = BlockHash::from_bytes(
        bytes[36..68]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    );
    let audit_len = u32::from_le_bytes(
        bytes[68..72]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    ) as usize;
    if audit_len != 0 && audit_len != 321 {
        return Err(SwiftLiveError::Corrupt);
    }
    let stump_len = u32::from_le_bytes(
        bytes[72..76]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    ) as usize;
    if stump_len > 4096 {
        return Err(SwiftLiveError::Corrupt);
    }
    let audit_start = 76usize;
    let stump_start = audit_start
        .checked_add(audit_len)
        .ok_or(SwiftLiveError::Corrupt)?;
    let mut cursor = stump_start
        .checked_add(stump_len)
        .ok_or(SwiftLiveError::Corrupt)?;
    if cursor > body_end || count > (body_end - cursor) / 46 {
        return Err(SwiftLiveError::Corrupt);
    }
    let audit_before = (audit_len != 0).then(|| bytes[audit_start..stump_start].to_vec());
    let stump_before = (stump_len != 0).then(|| bytes[stump_start..cursor].to_vec());
    let mut result = Vec::with_capacity(count);
    let mut last = None;
    for _ in 0..count {
        let key: [u8; 36] = bytes
            .get(cursor..cursor + 36)
            .ok_or(SwiftLiveError::Corrupt)?
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?;
        cursor += 36;
        if last.is_some_and(|prior| key <= prior) {
            return Err(SwiftLiveError::Corrupt);
        }
        last = Some(key);
        let present = *bytes.get(cursor).ok_or(SwiftLiveError::Corrupt)?;
        cursor += 1;
        let raw: [u8; ROW_LEN] = bytes
            .get(cursor..cursor + ROW_LEN)
            .ok_or(SwiftLiveError::Corrupt)?
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?;
        cursor += ROW_LEN;
        let value = match present {
            0 if raw.iter().all(|b| *b == 0) => None,
            1 => {
                decode_row(&key, &raw)?;
                Some(raw)
            }
            _ => return Err(SwiftLiveError::Corrupt),
        };
        let survivor_len = u32::from_le_bytes(
            bytes
                .get(cursor..cursor + 4)
                .ok_or(SwiftLiveError::Corrupt)?
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        );
        cursor += 4;
        let survivor = if survivor_len == u32::MAX {
            None
        } else {
            let len = survivor_len as usize;
            let value = bytes
                .get(cursor..cursor.checked_add(len).ok_or(SwiftLiveError::Corrupt)?)
                .ok_or(SwiftLiveError::Corrupt)?
                .to_vec();
            cursor += len;
            Some(value)
        };
        if let Some(value) = &survivor {
            let mut cursor = value.as_slice();
            let coin =
                crate::coinsdb::decode_coin_compact(&mut cursor).ok_or(SwiftLiveError::Corrupt)?;
            if !cursor.is_empty() || !(0..=crate::check::MAX_MONEY).contains(&coin.out.value) {
                return Err(SwiftLiveError::Corrupt);
            }
        }
        result.push((
            key,
            BeforeImage {
                live: value,
                survivor,
            },
        ));
    }
    if cursor != body_end {
        return Err(SwiftLiveError::Corrupt);
    }
    Ok((previous, current, audit_before, stump_before, result))
}

fn encode_state(binding: SwiftLiveBinding, limits: SwiftLiveLimits, state: State) -> Vec<u8> {
    let mut out = Vec::with_capacity(250 + 32);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.push(network_byte(binding.network));
    out.extend_from_slice(&binding.start_height.to_le_bytes());
    out.extend_from_slice(binding.start_hash.as_bytes());
    out.extend_from_slice(&binding.target_height.to_le_bytes());
    out.extend_from_slice(binding.target_hash.as_bytes());
    out.extend_from_slice(&binding.params_commitment);
    out.extend_from_slice(&state.height.to_le_bytes());
    out.extend_from_slice(state.hash.as_bytes());
    out.extend_from_slice(&limits.max_live_entries.to_le_bytes());
    out.extend_from_slice(&limits.max_live_encoded_bytes.to_le_bytes());
    out.extend_from_slice(&limits.max_undo_encoded_bytes.to_le_bytes());
    out.extend_from_slice(&limits.max_survivor_entries.to_le_bytes());
    out.extend_from_slice(&limits.max_survivor_encoded_bytes.to_le_bytes());
    out.extend_from_slice(&limits.max_reorg_depth.to_le_bytes());
    out.extend_from_slice(&(limits.max_block_events as u32).to_le_bytes());
    out.extend_from_slice(&(limits.cache_bytes as u32).to_le_bytes());
    out.extend_from_slice(&state.live_entries.to_le_bytes());
    out.extend_from_slice(&state.live_bytes.to_le_bytes());
    out.extend_from_slice(&state.undo_bytes.to_le_bytes());
    out.extend_from_slice(&state.undo_floor.to_le_bytes());
    out.extend_from_slice(&state.survivor_entries.to_le_bytes());
    out.extend_from_slice(&state.survivor_bytes.to_le_bytes());
    out.push(u8::from(state.complete));
    let sum = checksum(META_DOMAIN, &out);
    out.extend_from_slice(&sum);
    out
}
fn decode_state(
    bytes: &[u8],
) -> Result<(SwiftLiveBinding, SwiftLiveLimits, State), SwiftLiveError> {
    const BODY: usize = 250;
    if bytes.len() != BODY + 32 || &bytes[..8] != MAGIC {
        return Err(SwiftLiveError::Corrupt);
    }
    let sum = checksum(META_DOMAIN, &bytes[..BODY]);
    if !ct_eq(&sum, &bytes[BODY..])
        || u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ) != VERSION
    {
        return Err(SwiftLiveError::Corrupt);
    }
    let network = network_from_byte(bytes[12]).ok_or(SwiftLiveError::Corrupt)?;
    let binding = SwiftLiveBinding {
        network,
        start_height: u32::from_le_bytes(
            bytes[13..17]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        start_hash: BlockHash::from_bytes(
            bytes[17..49]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        target_height: u32::from_le_bytes(
            bytes[49..53]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        target_hash: BlockHash::from_bytes(
            bytes[53..85]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        params_commitment: bytes[85..117]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    };
    let height = u32::from_le_bytes(
        bytes[117..121]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    );
    let hash = BlockHash::from_bytes(
        bytes[121..153]
            .try_into()
            .map_err(|_| SwiftLiveError::Corrupt)?,
    );
    let limits = SwiftLiveLimits {
        max_live_entries: u64::from_le_bytes(
            bytes[153..161]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        max_live_encoded_bytes: u64::from_le_bytes(
            bytes[161..169]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        max_undo_encoded_bytes: u64::from_le_bytes(
            bytes[169..177]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        max_survivor_entries: u64::from_le_bytes(
            bytes[177..185]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        max_survivor_encoded_bytes: u64::from_le_bytes(
            bytes[185..193]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        max_reorg_depth: u32::from_le_bytes(
            bytes[193..197]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        max_block_events: u32::from_le_bytes(
            bytes[197..201]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ) as usize,
        cache_bytes: u32::from_le_bytes(
            bytes[201..205]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ) as usize,
    };
    let state = State {
        live_entries: u64::from_le_bytes(
            bytes[205..213]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        live_bytes: u64::from_le_bytes(
            bytes[213..221]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        undo_bytes: u64::from_le_bytes(
            bytes[221..229]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        undo_floor: u32::from_le_bytes(
            bytes[229..233]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        survivor_entries: u64::from_le_bytes(
            bytes[233..241]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        survivor_bytes: u64::from_le_bytes(
            bytes[241..249]
                .try_into()
                .map_err(|_| SwiftLiveError::Corrupt)?,
        ),
        complete: match bytes[249] {
            0 => false,
            1 => true,
            _ => return Err(SwiftLiveError::Corrupt),
        },
        height,
        hash,
    };
    Ok((binding, limits, state))
}
fn network_byte(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Testnet4 => 1,
        Network::Signet => 2,
        Network::Regtest => 3,
    }
}
fn network_from_byte(byte: u8) -> Option<Network> {
    match byte {
        0 => Some(Network::Mainnet),
        1 => Some(Network::Testnet4),
        2 => Some(Network::Signet),
        3 => Some(Network::Regtest),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new() -> Self {
            loop {
                let id = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("avila-swift-live-{}-{id}", std::process::id()));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("create temporary directory: {e}"),
                }
            }
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("live.redb")
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn binding() -> SwiftLiveBinding {
        SwiftLiveBinding {
            network: Network::Regtest,
            start_height: 0,
            start_hash: BlockHash::from_bytes([0; 32]),
            target_height: 2,
            target_hash: BlockHash::from_bytes([2; 32]),
            params_commitment: Network::Regtest.params().swift_validation_commitment(),
        }
    }
    fn limits() -> SwiftLiveLimits {
        SwiftLiveLimits {
            max_live_entries: 32,
            max_live_encoded_bytes: 32 * 41,
            max_undo_encoded_bytes: 1024 * 1024,
            max_survivor_entries: 32,
            max_survivor_encoded_bytes: 32 * 4096,
            max_reorg_depth: 288,
            max_block_events: 16,
            cache_bytes: 4 * 1024 * 1024,
        }
    }
    fn outpoint(seed: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_bytes([seed; 32]),
            vout: u32::from(seed),
        }
    }

    #[test]
    fn retained_full_block_undo_roundtrips_and_rejects_tampering() {
        let block = crate::block::Block::decode(include_bytes!(
            "../../../fixtures/mainnet-block-000000.bin"
        ))
        .unwrap();
        let undo = crate::connect::BlockUndo {
            txs: vec![crate::connect::TxUndo::default(); block.transactions.len()],
        };
        let encoded = encode_full_undo(block.header.prev_block_hash, &block, &undo).unwrap();
        let (previous, current, decoded_block, decoded_undo) = decode_full_undo(&encoded).unwrap();
        assert_eq!(previous, block.header.prev_block_hash);
        assert_eq!(current, block.block_hash());
        assert_eq!(decoded_block, block);
        assert_eq!(decoded_undo, undo);

        let mut tampered = encoded;
        tampered[80] ^= 1;
        assert!(matches!(
            decode_full_undo(&tampered),
            Err(SwiftLiveError::Corrupt)
        ));
    }

    #[test]
    fn exact_live_status_resume_and_rewind() {
        let temp = TempDir::new();
        let mut index = SwiftLiveIndex::create(&temp.path(), binding(), limits()).unwrap();
        let point = outpoint(1);
        let block_one = BlockHash::from_bytes([1; 32]);
        index
            .apply_block(
                1,
                BlockHash::from_bytes([0; 32]),
                block_one,
                &[LiveEvent::Create {
                    outpoint: point,
                    height: 1,
                    coinbase: true,
                    allow_live_overwrite: false,
                }],
            )
            .unwrap();
        assert_eq!(
            index.get(&point).unwrap(),
            Some(LiveCoinMeta {
                height: 1,
                coinbase: true,
                live: true
            })
        );
        drop(index);

        let mut index = SwiftLiveIndex::open(&temp.path(), binding(), limits()).unwrap();
        let block_two = binding().target_hash;
        index
            .apply_block(
                2,
                block_one,
                block_two,
                &[LiveEvent::Spend {
                    outpoint: point,
                    height: 1,
                    coinbase: true,
                }],
            )
            .unwrap();
        assert_eq!(index.get(&point).unwrap(), None);
        index.rewind_one(block_two).unwrap();
        assert_eq!(index.tip(), (1, block_one));
        assert_eq!(
            index.get(&point).unwrap(),
            Some(LiveCoinMeta {
                height: 1,
                coinbase: true,
                live: true
            })
        );
    }

    #[test]
    fn rejects_missing_spends_claim_mismatch_live_collision_and_wrong_checkpoint() {
        let temp = TempDir::new();
        let mut index = SwiftLiveIndex::create(&temp.path(), binding(), limits()).unwrap();
        let point = outpoint(3);
        let block_one = BlockHash::from_bytes([4; 32]);
        index
            .apply_block(
                1,
                binding().start_hash,
                block_one,
                &[LiveEvent::Create {
                    outpoint: point,
                    height: 1,
                    coinbase: false,
                    allow_live_overwrite: false,
                }],
            )
            .unwrap();
        assert!(matches!(
            index.apply_block(
                2,
                block_one,
                binding().target_hash,
                &[LiveEvent::Spend {
                    outpoint: point,
                    height: 0,
                    coinbase: false
                }]
            ),
            Err(SwiftLiveError::ClaimMismatch)
        ));
        assert!(matches!(
            index.apply_block(
                2,
                block_one,
                binding().target_hash,
                &[LiveEvent::Create {
                    outpoint: point,
                    height: 2,
                    coinbase: false,
                    allow_live_overwrite: false,
                }]
            ),
            Err(SwiftLiveError::DuplicateLiveOutput)
        ));
        assert!(matches!(
            index.apply_block(2, block_one, BlockHash::from_bytes([9; 32]), &[]),
            Err(SwiftLiveError::CheckpointMismatch)
        ));
        assert!(matches!(
            index.apply_block(
                2,
                block_one,
                binding().target_hash,
                &[LiveEvent::Spend {
                    outpoint: outpoint(8),
                    height: 0,
                    coinbase: false
                }]
            ),
            Err(SwiftLiveError::MissingOrSpent)
        ));
        assert_eq!(index.tip(), (1, block_one));
    }

    #[test]
    fn spent_rows_are_removed_and_reorg_window_floor_is_enforced() {
        let temp = TempDir::new();
        let mut bounded = limits();
        bounded.max_reorg_depth = 1;
        let mut index = SwiftLiveIndex::create(&temp.path(), binding(), bounded).unwrap();
        let point = outpoint(11);
        let one = BlockHash::from_bytes([1; 32]);
        index
            .apply_block(
                1,
                binding().start_hash,
                one,
                &[LiveEvent::Create {
                    outpoint: point,
                    height: 1,
                    coinbase: false,
                    allow_live_overwrite: false,
                }],
            )
            .unwrap();
        let two = BlockHash::from_bytes([2; 32]);
        index
            .apply_block(
                2,
                one,
                two,
                &[LiveEvent::Spend {
                    outpoint: point,
                    height: 1,
                    coinbase: false,
                }],
            )
            .unwrap();
        assert_eq!(index.get(&point).unwrap(), None);
        assert_eq!(index.entries(), 0);
        // The height-1 journal was pruned, so rewinding height 2 succeeds but
        // the index cannot continue to genesis.
        assert_eq!(index.rewind_floor(), 1);
        assert_eq!(index.rewind_one(two).unwrap(), one);
        assert!(matches!(
            index.rewind_one(one),
            Err(SwiftLiveError::RewindMismatch)
        ));
    }

    #[test]
    fn validated_transition_persists_survivor_and_audit_atomically_and_rewinds_them() {
        use crate::transaction::Script;

        let temp = TempDir::new();
        let mut index = SwiftLiveIndex::create(&temp.path(), binding(), limits()).unwrap();
        let point = outpoint(12);
        let block_one = BlockHash::from_bytes([1; 32]);
        let coin = Coin {
            out: crate::transaction::TxOut {
                value: 50,
                script_pubkey: Script::new(vec![0x51]),
            },
            height: 1,
            coinbase: true,
        };
        let audit = crate::swift_audit::SwiftAudit::new(
            Network::Regtest,
            binding().target_height,
            binding().target_hash,
        )
        .unwrap();
        let snapshot = audit.persisted_state().unwrap();
        index.initialize_stump_snapshot(b"stump0").unwrap();
        index
            .apply_validated_block(
                1,
                binding().start_hash,
                block_one,
                &[LiveEvent::Create {
                    outpoint: point,
                    height: 1,
                    coinbase: true,
                    allow_live_overwrite: false,
                }],
                &snapshot,
                Some(b"stump1"),
                &[(point, Some(&coin))],
            )
            .unwrap();
        assert_eq!(index.audit_snapshot().unwrap(), Some(snapshot.clone()));
        assert_eq!(index.stump_snapshot().unwrap(), Some(b"stump1".to_vec()));
        let mut visited = None;
        index
            .for_each_live_survivor(|seen, meta, coin| {
                visited = Some((seen, meta, coin));
                Ok(())
            })
            .unwrap();
        assert_eq!(visited.unwrap().0, point);
        drop(index);

        let mut reopened = SwiftLiveIndex::open(&temp.path(), binding(), limits()).unwrap();
        reopened.rewind_one(block_one).unwrap();
        assert_eq!(reopened.audit_snapshot().unwrap(), None);
        assert_eq!(reopened.stump_snapshot().unwrap(), Some(b"stump0".to_vec()));
        assert_eq!(reopened.get(&point).unwrap(), None);
        let mut survivor_count = 0;
        reopened
            .for_each_live_survivor(|_, _, _| {
                survivor_count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(survivor_count, 0);

        reopened
            .apply_validated_block(
                1,
                binding().start_hash,
                block_one,
                &[LiveEvent::Create {
                    outpoint: point,
                    height: 1,
                    coinbase: true,
                    allow_live_overwrite: false,
                }],
                &snapshot,
                Some(b"stump1"),
                &[(point, Some(&coin))],
            )
            .unwrap();
        reopened
            .apply_validated_block(
                2,
                block_one,
                binding().target_hash,
                &[],
                &snapshot,
                Some(b"stump2"),
                &[],
            )
            .unwrap();
        reopened.mark_complete(&snapshot).unwrap();
        assert!(reopened.is_complete());
        drop(reopened);

        let completed = SwiftLiveIndex::open(&temp.path(), binding(), limits()).unwrap();
        assert!(completed.is_complete());
        let mut exported = 0;
        completed
            .for_each_audited_survivor(|seen, _, seen_coin| {
                assert_eq!(seen, point);
                assert_eq!(seen_coin, coin);
                exported += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(exported, 1);
    }
}

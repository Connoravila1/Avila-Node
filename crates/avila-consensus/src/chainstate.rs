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
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use thiserror::Error;

use crate::arith::Work;
use crate::block::Block;
use crate::chain::{ChainError, HeaderTree, InsertStatus};
use crate::check::{self, BlockContext, BlockRuleError, ContextualBlockError, RuleError};
use crate::coinstats::{self, CoinStats, CoinStatsHashType};
use crate::connect::{self, BlockUndo, Coin, ConnectContext, ConnectError, UtxoSet};
use crate::hash::{BlockHash, Txid};
use crate::header::BlockHeader;
use crate::params::Params;
use crate::store::{self, BlockStore, StateData};
use crate::transaction::OutPoint;

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

/// The result of [`Chainstate::chain_tx_stats`] — Core's
/// `getchaintxstats` response, with `Option` fields marking the slots
/// Core omits from the JSON object.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ChainTxStats {
    /// The window-final block's timestamp (UNIX epoch).
    pub time: u32,
    /// Cumulative transaction count up to the final block — `None`
    /// when that block was never connected (Core: `nChainTx` unknown,
    /// as with assumeutxo).
    pub tx_count: Option<u64>,
    /// The window-final block's hash.
    pub final_hash: BlockHash,
    /// The window-final block's height.
    pub final_height: u32,
    /// Blocks between the window start and final block.
    pub window_block_count: u32,
    /// Seconds between the window start's and final block's timestamps
    /// — `Some` only when `window_block_count > 0`.
    pub window_interval: Option<i64>,
    /// Transactions inside the window — `Some` only when both
    /// endpoints' cumulative counts are known.
    pub window_tx_count: Option<u64>,
    /// `window_tx_count / window_interval` — `Some` only when the
    /// interval is positive and the count is known.
    pub tx_rate: Option<f64>,
}

/// Why [`Chainstate::chain_tx_stats`] failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum TxStatsError {
    /// The named block is not in the block index (Core's `-5`).
    #[error("block not in index")]
    UnknownBlock,
    /// `nblocks` is negative or exceeds `height - 1` (Core's `-8`).
    #[error("window out of range")]
    BadWindow,
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
    /// Per-block undo *tail* — `undos[i]` reverses the block at height
    /// `undo_base + 1 + i`. Older undos live in the coinsdb backend's
    /// `undo` table once flushed (Core's `rev*.dat` role); in memory-only
    /// mode `undo_base` is 0 and this Vec covers the whole chain.
    undos: Vec<BlockUndo>,
    /// The shared coinsdb handle — the same `Arc` the `utxo` view
    /// carries, mirrored here so undo reads work while `utxo` is
    /// emptied mid-overlay (reorg simulation).
    coins_backend: Option<std::sync::Arc<crate::coinsdb::CoinsBackend>>,
    /// The durable body store when this chainstate was opened with
    /// [`Chainstate::with_store`]; `None` keeps everything in memory.
    store: Option<BlockStore>,
    /// txid → containing block index, Core's `-txindex`. `None` unless
    /// [`Chainstate::enable_txindex`] ran; when present every body
    /// retained by `accept_block` records its transactions here.
    txindex: Option<TxIndex>,
    /// BIP 158 basic filter index, Core's `-blockfilterindex`. `None`
    /// unless [`Chainstate::enable_blockfilterindex`] ran; indexed at
    /// connect time so spent-prevout scripts come from the undo data.
    filterindex: Option<FilterIndex>,
    /// Electrum-style scripthash index — scriptPubKey-hash →
    /// `(height, position, txid)` history. `None` unless
    /// [`Chainstate::enable_scripthashindex`] ran.
    scripthashindex: Option<ScripthashIndex>,
    /// `preciousblock` — the block that wins equal-work tie-breaks.
    /// Core implements it as the lowest `nSequenceId` (reception order
    /// settles work ties); a later call overrides the earlier one, and
    /// nothing persists it across restarts — hence a plain in-memory
    /// slot here.
    precious: Option<BlockHash>,
    /// `m_from_snapshot_blockhash` — the `loadtxoutset` base height,
    /// when this chainstate was built from a snapshot. Heights at or
    /// below it are assume-valid: their `undos` slots are empty
    /// placeholders and no reorg may fork below it.
    snapshot_base: Option<u32>,
    /// Core's ibd chainstate while a snapshot is active — replays the
    /// stored bodies of heights `1..=snapshot_base` into an independent
    /// UTXO set; on reaching the base, its recomputed content hash must
    /// equal the chainparams value or the snapshot was dishonest.
    /// `None` when no snapshot is loaded, when pre-base bodies have
    /// never been retained, or after verification completes (Core frees
    /// the ibd chainstate at merge).
    background: Option<BackgroundValidation>,
    /// `true` once the background replay reached the base and its
    /// hash matched — the moment Core merges the snapshot chainstate
    /// into the fully validated one and `getchainstates` reports a
    /// single `validated: true` entry.
    snapshot_verified: bool,
    /// Hashes of blocks disconnected since the last
    /// [`Self::take_disconnected`] drain, in disconnect order — the
    /// most-recent tip first. Core's `DisconnectedBlockTransactions`
    /// queue; the node layer feeds their non-coinbase transactions back
    /// to the mempool after each disconnecting operation.
    disconnected: Vec<BlockHash>,
    /// Speculative script-check pool — `None` until
    /// [`Self::enable_speculative_connect`]; when set, block connects
    /// return with verification still in flight.
    script_pool: Option<std::sync::Arc<connect::ScriptPool>>,
    /// Blocks applied to `utxo` whose script checks have not yet
    /// drained — a strictly-increasing tail of the connected chain.
    /// Bounded by the pipeline depth in `accept_block`; emptied by
    /// [`Self::drain_scripts`] before flushes, snapshots, reorgs.
    pending_scripts:
        std::collections::VecDeque<(BlockHash, u32, std::sync::Arc<connect::BlockCheck>)>,
}

/// The background validation replay beneath an active snapshot — a
/// second UTXO set built block-by-block from stored bodies, purely to
/// prove the loaded set. Core carries this as a whole second
/// `Chainstate`; here it is the coin set plus a height cursor — the
/// header index, body store and chain path are already shared.
struct BackgroundValidation {
    /// The replayed set — coin-for-coin with what honest validation
    /// produces at the base, before the hash check confirms it.
    utxo: UtxoSet,
    /// The next height to replay (`1` at start; `> base` when done).
    next: u32,
}

/// Where [`Chainstate::background_step`] left the snapshot replay —
/// the progress Core's `getchainstates` reports as the second
/// chainstate's `blocks`/`bestblockhash`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackgroundStatus {
    /// No snapshot is active — nothing to replay.
    NoSnapshot,
    /// The replay is waiting for a block body that has never been
    /// stored (Core stalls background validation until the block
    /// downloads).
    WaitingForBody {
        /// The height whose body is missing.
        height: u32,
    },
    /// Replayed up to `done` of `base`; still running.
    InProgress {
        /// Heights `1..=done` are replayed.
        done: u32,
        /// The snapshot base height the replay must reach.
        base: u32,
    },
    /// The replay reached the base and its content hash matched the
    /// chainparams value — the snapshot is now proven, not assumed.
    Verified,
}

/// The transaction index behind `-txindex`: every retained block's
/// txids mapped to its hash, plus an append log (`txindex.dat`) that
/// makes the index resumable — records are `blockhash || count ||
/// txids`, so a restart loads the map and backfills only blocks the
/// log never covered. Entries are never removed: Core's txindex
/// keeps a transaction findable through its block even after a reorg
/// disconnected that block.
pub struct TxIndex {
    map: HashMap<Txid, BlockHash>,
    /// Block hashes already logged — restart backfill scans only the
    /// store blocks missing from this set.
    indexed: HashSet<BlockHash>,
    /// The open append handle for `txindex.dat`, when persistence is on.
    log: Option<std::fs::File>,
}

impl TxIndex {
    const MAGIC: &'static [u8; 8] = b"txidx\x01\x00\x00";

    fn empty() -> Self {
        Self {
            map: HashMap::new(),
            indexed: HashSet::new(),
            log: None,
        }
    }

    /// Loads `dir/txindex.dat` and opens it for append. A missing file
    /// starts empty; a corrupt or truncated tail is cut back to the
    /// last whole record, the same recovery the blk store applies.
    fn open(dir: &Path) -> std::io::Result<Self> {
        use std::io::{Read, Write};
        let path = dir.join("txindex.dat");
        let mut idx = Self::empty();
        let mut committed = Self::MAGIC.len() as u64;
        let mut ok = false;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            if buf.len() >= Self::MAGIC.len() && buf[..8] == *Self::MAGIC {
                let mut cursor = Self::MAGIC.len();
                while cursor + 36 <= buf.len() {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&buf[cursor..cursor + 32]);
                    let count = u32::from_le_bytes(
                        buf[cursor + 32..cursor + 36].try_into().unwrap_or_default(),
                    ) as usize;
                    let rec_len = 36 + count * 32;
                    if cursor + rec_len > buf.len() {
                        break; // partial tail — truncate below
                    }
                    let block = BlockHash::from_bytes(hash);
                    idx.indexed.insert(block);
                    for i in 0..count {
                        let mut t = [0u8; 32];
                        let at = cursor + 36 + i * 32;
                        t.copy_from_slice(&buf[at..at + 32]);
                        idx.map.insert(Txid::from_bytes(t), block);
                    }
                    cursor += rec_len;
                }
                committed = cursor as u64;
                ok = true;
            }
            // Cut back any partial tail; a missing or foreign magic
            // means the file is not ours — start it over.
            f.set_len(if ok { committed } else { 0 })?;
        }
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        if !ok {
            log.write_all(Self::MAGIC)?;
        }
        idx.log = Some(log);
        Ok(idx)
    }

    /// Records one block's transactions; appends the log record when a
    /// persistence handle is attached.
    fn index_block(&mut self, hash: BlockHash, block: &Block) {
        if !self.indexed.insert(hash) {
            return; // already logged — reorg re-store or replay pass
        }
        let txids: Vec<Txid> = block.transactions.iter().map(|t| t.txid()).collect();
        for txid in &txids {
            self.map.insert(*txid, hash);
        }
        if let Some(log) = &mut self.log {
            use std::io::Write;
            let mut rec = Vec::with_capacity(36 + txids.len() * 32);
            rec.extend_from_slice(hash.as_bytes());
            rec.extend_from_slice(&(txids.len() as u32).to_le_bytes());
            for txid in &txids {
                rec.extend_from_slice(txid.as_bytes());
            }
            // A failed log write degrades the index to in-memory only —
            // the map stays correct; the next restart backfills.
            let _ = log.write_all(&rec);
        }
    }
}

/// The BIP 158 `basic` block-filter index behind `-blockfilterindex`.
/// Active-chain entries are keyed by height; a reorg moves the evicted
/// block's filter to the hash index, matching Core's
/// `CopyHeightIndexToHashIndex` rewind — so a filter stays retrievable
/// for a stale-branch block. `last_header` chains filter headers in the
/// index's append order (Core's `m_last_header`).
pub struct FilterIndex {
    /// height → (block hash, encoded filter, filter header).
    by_height: BTreeMap<u32, (BlockHash, Vec<u8>, [u8; 32])>,
    /// Reorged-out blocks: block hash → (encoded filter, header).
    by_hash: HashMap<BlockHash, (Vec<u8>, [u8; 32])>,
    /// Filter-header chain tip — the indexed block that connected last.
    last_header: [u8; 32],
    /// The open append handle for `cfilters.dat`, when persistence is on.
    log: Option<std::fs::File>,
}

impl FilterIndex {
    const MAGIC: &'static [u8; 8] = b"cflt\x01\x00\x00\x00";

    fn empty() -> Self {
        Self {
            by_height: BTreeMap::new(),
            by_hash: HashMap::new(),
            last_header: [0; 32],
            log: None,
        }
    }

    /// Loads `dir/cfilters.dat` and opens it for append. Records are
    /// `height || block_hash || filter_len || filter || header`; replay
    /// demotes an overwritten height to the hash index, so a reorg's
    /// disconnect records never need logging. A partial tail is cut back
    /// like the blk store's.
    fn open(dir: &Path) -> std::io::Result<Self> {
        use std::io::{Read, Write};
        let path = dir.join("cfilters.dat");
        let mut idx = Self::empty();
        let mut committed = Self::MAGIC.len() as u64;
        let mut ok = false;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            if buf.len() >= 8 && buf[..8] == *Self::MAGIC {
                let mut cursor = Self::MAGIC.len();
                while cursor + 72 <= buf.len() {
                    let height =
                        u32::from_le_bytes(buf[cursor..cursor + 4].try_into().unwrap_or_default());
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&buf[cursor + 4..cursor + 36]);
                    let flen = u32::from_le_bytes(
                        buf[cursor + 36..cursor + 40].try_into().unwrap_or_default(),
                    ) as usize;
                    let rec_len = 72 + flen;
                    if cursor + rec_len > buf.len() {
                        break; // partial tail — truncate below
                    }
                    let filter = buf[cursor + 40..cursor + 40 + flen].to_vec();
                    let mut header = [0u8; 32];
                    header.copy_from_slice(&buf[cursor + 40 + flen..cursor + rec_len]);
                    idx.insert(height, BlockHash::from_bytes(hash), filter, header);
                    cursor += rec_len;
                }
                committed = cursor as u64;
                ok = true;
            }
            f.set_len(if ok { committed } else { 0 })?;
        }
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        if !ok {
            log.write_all(Self::MAGIC)?;
        }
        idx.log = Some(log);
        Ok(idx)
    }

    /// Indexes `filter` for the block at `height` — the `Write` half of
    /// Core's `CustomAppend`. The header chains off `last_header`, then
    /// becomes it. A same-height replacement demotes the old entry to
    /// the hash index.
    fn insert(&mut self, height: u32, hash: BlockHash, filter: Vec<u8>, header: [u8; 32]) {
        if let Some((old_hash, old_filter, old_header)) = self.by_height.remove(&height) {
            self.by_hash.insert(old_hash, (old_filter, old_header));
        }
        self.by_height.insert(height, (hash, filter, header));
        self.last_header = header;
    }

    /// Builds and indexes `block`'s basic filter — Core's
    /// `CustomAppend`: `filter` from block + undo, header chained off
    /// `last_header`. `undo` is empty for the genesis block.
    fn append(&mut self, height: u32, block: &Block, undo: &BlockUndo) {
        let hash = block.block_hash();
        let filter = crate::gcs::build_basic(block, undo);
        let header =
            crate::gcs::compute_header(&crate::gcs::filter_hash(&filter), &self.last_header);
        self.insert(height, hash, filter.clone(), header);
        if let Some(log) = &mut self.log {
            use std::io::Write;
            let mut rec = Vec::with_capacity(72 + filter.len());
            rec.extend_from_slice(&height.to_le_bytes());
            rec.extend_from_slice(hash.as_bytes());
            rec.extend_from_slice(&(filter.len() as u32).to_le_bytes());
            rec.extend_from_slice(&filter);
            rec.extend_from_slice(&header);
            let _ = log.write_all(&rec);
        }
    }

    /// The rewind half of a reorg — moves the active-chain entry at
    /// `height` to the hash index and rewinds `last_header` to the
    /// parent's (`CustomRewind` + `ReadFilterHeader(new_tip)`).
    fn disconnect(&mut self, height: u32) {
        if let Some((hash, filter, header)) = self.by_height.remove(&height) {
            self.by_hash.insert(hash, (filter, header));
        }
        self.last_header = height
            .checked_sub(1)
            .and_then(|h| self.by_height.get(&h))
            .map(|(_, _, h)| *h)
            .unwrap_or([0; 32]);
    }

    /// Core's `LookupOne`: the height-index entry serves the block only
    /// when its hash matches; a reorged-out block falls to the hash
    /// index.
    fn lookup(&self, height: u32, hash: &BlockHash) -> Option<(&[u8], &[u8; 32])> {
        if let Some((h, filter, header)) = self.by_height.get(&height)
            && h == hash
        {
            return Some((filter, header));
        }
        self.by_hash.get(hash).map(|(f, h)| (f.as_slice(), h))
    }

    /// `loadtxoutset` rewinds: every active-chain entry below the
    /// snapshot base belongs to the abandoned prefix (those heights
    /// have no bodies to filter), so the height index empties into the
    /// hash index and the header chain restarts — Core's snapshot
    /// chainstate begins with an empty index the same way.
    fn reset_to_snapshot(&mut self) {
        for (_, (hash, filter, header)) in std::mem::take(&mut self.by_height) {
            self.by_hash.insert(hash, (filter, header));
        }
        self.last_header = [0; 32];
    }
}

/// The scripthash index behind `--electrum`: for every connected
/// block, every scriptPubKey each transaction creates *or* spends is
/// hashed (Electrum's `SHA256(scriptPubKey)`) and mapped to
/// `(height, tx position, txid)` — the history list `get_history`,
/// `get_balance` and `listunspent` serve. Spent-script hashes come
/// from the block's undo record, like the filter index.
///
/// Entries for a disconnected block are unwound through `by_height`
/// (per-height tx → touched-scripts records). Persistence is an
/// append log: connect records replay, `D` records apply rewinds, and
/// a partial tail is cut back like the blk store's.
pub struct ScripthashIndex {
    /// script hash → history entries, append-ordered by connect.
    by_script: HashMap<[u8; 32], Vec<(u32, u16, Txid)>>,
    /// height → every tx and the script hashes it touched (for
    /// disconnect rewinds).
    /// One connected block's record: per tx, the touched script
    /// hashes — the disconnect rewind list.
    by_height: BTreeMap<u32, BlockScripts>,
    /// The open append handle for `scindex.dat`, when persistence is on.
    log: Option<std::fs::File>,
}

/// Per-block touched-script records for the scripthash index:
/// `(txid, script hashes)` pairs in block order.
type BlockScripts = Vec<(Txid, Vec<[u8; 32]>)>;

impl ScripthashIndex {
    const MAGIC: &'static [u8; 8] = b"scidx\x01\x00\x00";

    fn empty() -> Self {
        Self {
            by_script: HashMap::new(),
            by_height: BTreeMap::new(),
            log: None,
        }
    }

    /// Loads `dir/scindex.dat` and opens it for append. `C` records
    /// replay connects (an overwritten height is first rewound), `D`
    /// records replay disconnects, and a partial tail is cut back.
    fn open(dir: &Path) -> std::io::Result<Self> {
        use std::io::{Read, Write};
        let path = dir.join("scindex.dat");
        let mut idx = Self::empty();
        let mut committed = Self::MAGIC.len() as u64;
        let mut ok = false;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            if buf.len() >= 8 && buf[..8] == *Self::MAGIC {
                let mut cursor = Self::MAGIC.len();
                while cursor + 7 <= buf.len() {
                    let height =
                        u32::from_le_bytes(buf[cursor..cursor + 4].try_into().unwrap_or_default());
                    match buf[cursor + 4] {
                        b'D' => {
                            idx.disconnect(height);
                            cursor += 5;
                        }
                        b'C' => {
                            let ntx = u16::from_le_bytes(
                                buf[cursor + 5..cursor + 7].try_into().unwrap_or_default(),
                            ) as usize;
                            let mut recs = Vec::with_capacity(ntx);
                            let mut p = cursor + 7;
                            let mut whole = true;
                            for _ in 0..ntx {
                                if p + 34 > buf.len() {
                                    whole = false;
                                    break;
                                }
                                let mut txid = [0u8; 32];
                                txid.copy_from_slice(&buf[p..p + 32]);
                                let nsh = u16::from_le_bytes(
                                    buf[p + 32..p + 34].try_into().unwrap_or_default(),
                                ) as usize;
                                p += 34;
                                if p + 32 * nsh > buf.len() {
                                    whole = false;
                                    break;
                                }
                                let mut scripts = Vec::with_capacity(nsh);
                                for _ in 0..nsh {
                                    let mut sh = [0u8; 32];
                                    sh.copy_from_slice(&buf[p..p + 32]);
                                    scripts.push(sh);
                                    p += 32;
                                }
                                recs.push((Txid::from_bytes(txid), scripts));
                            }
                            if !whole {
                                break;
                            }
                            idx.apply_connect(height, &recs);
                            cursor = p;
                        }
                        _ => break, // unknown record — treat as torn
                    }
                }
                committed = cursor as u64;
                ok = true;
            }
            // A partial tail is torn write — cut it.
            if f.metadata()?.len() != committed {
                f.set_len(committed)?;
            }
            idx.log = Some(f);
            let _ = ok;
        } else {
            idx.log = Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(&path)?,
            );
            if let Some(log) = &mut idx.log {
                log.write_all(Self::MAGIC)?;
            }
        }
        Ok(idx)
    }

    /// Applies one block's touched-script records — shared by log
    /// replay and the live connect path.
    fn apply_connect(&mut self, height: u32, recs: &BlockScripts) {
        if let Some(old) = self.by_height.remove(&height) {
            for (_txid, scripts) in old {
                for sh in scripts {
                    Self::unwind(&mut self.by_script, &sh, height);
                }
            }
        }
        for (pos, (txid, scripts)) in recs.iter().enumerate() {
            for sh in scripts {
                self.by_script
                    .entry(*sh)
                    .or_default()
                    .push((height, pos as u16, *txid));
            }
        }
        self.by_height.insert(height, recs.to_vec());
    }

    /// Indexes `block`'s touched scriptPubKeys at `height` — created
    /// outputs from the block, spent prevouts' scripts from `undo`.
    fn append(&mut self, height: u32, block: &Block, undo: &BlockUndo) {
        // `apply_connect` already unwinds prior entries at this height.
        let mut recs: BlockScripts = Vec::with_capacity(block.transactions.len());
        for (i, tx) in block.transactions.iter().enumerate() {
            let mut scripts: Vec<[u8; 32]> = Vec::new();
            for out in &tx.outputs {
                scripts.push(crate::hash::sha256(out.script_pubkey.as_bytes()));
            }
            if let Some(u) = undo.txs.get(i) {
                for coin in &u.spent {
                    scripts.push(crate::hash::sha256(coin.out.script_pubkey.as_bytes()));
                }
                for (_, coin) in &u.overwritten {
                    scripts.push(crate::hash::sha256(coin.out.script_pubkey.as_bytes()));
                }
            }
            scripts.sort_unstable();
            scripts.dedup();
            recs.push((tx.txid(), scripts));
        }
        self.apply_connect(height, &recs);
        if let Some(log) = &mut self.log {
            use std::io::Write;
            let mut rec = Vec::new();
            rec.extend_from_slice(&height.to_le_bytes());
            rec.push(b'C');
            rec.extend_from_slice(&(recs.len() as u16).to_le_bytes());
            for (txid, scripts) in &recs {
                rec.extend_from_slice(txid.as_bytes());
                rec.extend_from_slice(&(scripts.len() as u16).to_le_bytes());
                for sh in scripts {
                    rec.extend_from_slice(sh);
                }
            }
            let _ = log.write_all(&rec);
        }
    }

    /// Removes the tail entries a disconnect orphaned — history
    /// vectors are append-ordered by connect, so every entry at
    /// `height` is a suffix pop.
    fn unwind(
        by_script: &mut HashMap<[u8; 32], Vec<(u32, u16, Txid)>>,
        sh: &[u8; 32],
        height: u32,
    ) {
        if let Some(entries) = by_script.get_mut(sh) {
            while entries.last().is_some_and(|(h, _, _)| *h == height) {
                entries.pop();
            }
            if entries.is_empty() {
                by_script.remove(sh);
            }
        }
    }

    /// The disconnect half of a reorg — drops every entry recorded at
    /// `height`.
    fn disconnect(&mut self, height: u32) {
        if let Some(recs) = self.by_height.remove(&height) {
            for (_txid, scripts) in recs {
                for sh in scripts {
                    Self::unwind(&mut self.by_script, &sh, height);
                }
            }
        }
        if let Some(log) = &mut self.log {
            use std::io::Write;
            let mut rec = Vec::with_capacity(5);
            rec.extend_from_slice(&height.to_le_bytes());
            rec.push(b'D');
            let _ = log.write_all(&rec);
        }
    }

    /// `loadtxoutset` rewinds: heights below the snapshot base have no
    /// bodies and no history to serve — the snapshot chainstate begins
    /// with an empty index, like Core's.
    fn reset_to_snapshot(&mut self) {
        // A rewind record per abandoned height keeps replays
        // consistent; the log is small and this path is rare.
        let heights: Vec<u32> = self.by_height.keys().copied().collect();
        self.by_script.clear();
        self.by_height.clear();
        if let Some(log) = &mut self.log {
            use std::io::Write;
            for h in heights {
                let mut rec = Vec::with_capacity(5);
                rec.extend_from_slice(&h.to_le_bytes());
                rec.push(b'D');
                let _ = log.write_all(&rec);
            }
        }
    }
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
            coins_backend: None,
            store: None,
            txindex: None,
            scripthashindex: None,
            filterindex: None,
            precious: None,
            snapshot_base: None,
            background: None,
            snapshot_verified: false,
            disconnected: Vec::new(),
            script_pool: None,
            pending_scripts: std::collections::VecDeque::new(),
        }
    }

    /// Turns on speculative connect: script checks run on a persistent
    /// worker pool and `accept_block` returns once the pipeline window
    /// is full rather than once every queued check has drained. A
    /// block reported `Connected` under the pool may still have
    /// outstanding script jobs — callers needing the verified tip must
    /// `drain_scripts` first (flushes do so automatically). The
    /// consensus verdict is unchanged; only the wait boundary moved.
    pub fn enable_speculative_connect(&mut self) {
        let workers = std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(1);
        self.script_pool = Some(connect::ScriptPool::new(workers));
    }

    /// Waits out every speculatively-applied block — verifies any
    /// outstanding script jobs and surfaces the first failure. Called
    /// before any point that needs a fully-verified tip (flushes,
    /// snapshots, restore) or that observes `self.connected` as
    /// authoritative.
    ///
    /// # Errors
    ///
    /// The first script failure in pending order: that block and the
    /// pending suffix on top of it are rolled back and the failed
    /// block marked invalid — identical consensus state to an inline
    /// drain failing.
    pub fn drain_scripts(&mut self) -> Result<(), ConnectError> {
        self.drain_pending_to(0)
    }

    /// Waits until at most `depth` speculatively-applied blocks remain
    /// unverified — the pipeline's steady-state boundary inside
    /// `accept_block`.
    fn drain_pending_to(&mut self, depth: usize) -> Result<(), ConnectError> {
        let _dt = std::time::Instant::now();
        let r = self.drain_pending_inner(depth);
        crate::connect::drain_tick(_dt);
        r
    }

    fn drain_pending_inner(&mut self, depth: usize) -> Result<(), ConnectError> {
        while self.pending_scripts.len() > depth {
            let Some((hash, height, check)) = self.pending_scripts.pop_front() else {
                break;
            };
            if let Err(err) = check.wait() {
                // The failed block and everything pending above it can
                // never connect — drop their pending entries, mark the
                // block invalid, rewind to its parent.
                self.pending_scripts.retain(|(_, h, _)| *h < height);
                self.tree.mark_invalid(hash);
                self.rewind_connected(height.saturating_sub(1))?;
                return Err(ConnectError::ScriptVerify(err));
            }
        }
        Ok(())
    }

    /// Turns on the transaction index — Core's `-txindex`. With `dir`
    /// the index persists as `txindex.dat` (append log; a restart
    /// resumes from it and backfills only blocks never logged).
    /// Without a directory the index is in-memory only and the
    /// backfill scans whatever bodies this chainstate already holds.
    ///
    /// Like Core, enabling late does not erase history: every body
    /// already retained is indexed, and entries survive reorgs — a
    /// transaction stays findable through the block that carried it.
    ///
    /// # Errors
    ///
    /// `io::Error` when `dir` is given but `txindex.dat` cannot be
    /// read or opened for append.
    pub fn enable_txindex(&mut self, dir: Option<&Path>) -> std::io::Result<()> {
        let mut index = match dir {
            Some(dir) => TxIndex::open(dir)?,
            None => TxIndex::empty(),
        };
        // Backfill: every retained body the log never covered. The
        // store path scans blk files; the in-memory path the map.
        if let Some(store) = &self.store {
            for (hash, pos) in store.positions() {
                if !index.indexed.contains(&hash) {
                    index.index_block(hash, &store.read(pos)?);
                }
            }
        }
        for (hash, block) in &self.blocks {
            index.index_block(*hash, block);
        }
        self.txindex = Some(index);
        Ok(())
    }

    /// Turns on the basic block-filter index — Core's `-blockfilterindex`.
    /// With `dir` the index persists as `cfilters.dat` (append log; a
    /// restart resumes from it and backfills only blocks never logged).
    ///
    /// Backfill walks the connected chain: the genesis filter is
    /// outputs-only (Core appends it with an empty `CBlockUndo`), and
    /// every later height uses its stored undo records for the
    /// spent-script half of the element set.
    ///
    /// # Errors
    ///
    /// `io::Error` when `dir` is given but `cfilters.dat` cannot be
    /// read or opened for append.
    pub fn enable_blockfilterindex(&mut self, dir: Option<&Path>) -> std::io::Result<()> {
        let mut index = match dir {
            Some(dir) => FilterIndex::open(dir)?,
            None => FilterIndex::empty(),
        };
        // Backfill connected heights the log never covered — side
        // branches are never indexed, matching Core's active-chain index.
        for h in 0..self.chain.len() as u32 {
            let hash = self.chain[h as usize];
            if index
                .by_height
                .get(&h)
                .is_some_and(|(bh, _, _)| *bh == hash)
            {
                continue;
            }
            let Some(block) = self.body(&hash) else {
                continue; // retained-map gap — unreachable on a stored chain
            };
            let undo = self.undo(h).unwrap_or_default();
            index.append(h, &block, &undo);
        }
        self.filterindex = Some(index);
        Ok(())
    }

    /// Turns on the Electrum scripthash index (`--electrum`). With
    /// `dir` the index persists as `scindex.dat` — an append log of
    /// connect/disconnect records a restart replays, backfilling only
    /// blocks never logged.
    ///
    /// # Errors
    ///
    /// `io::Error` when `dir` is given but `scindex.dat` cannot be
    /// read or opened for append.
    pub fn enable_scripthashindex(&mut self, dir: Option<&Path>) -> std::io::Result<()> {
        let mut index = match dir {
            Some(dir) => ScripthashIndex::open(dir)?,
            None => ScripthashIndex::empty(),
        };
        for h in 0..self.chain.len() as u32 {
            if index.by_height.contains_key(&h) {
                continue;
            }
            let hash = self.chain[h as usize];
            let Some(block) = self.body(&hash) else {
                continue;
            };
            let undo = self.undo(h).unwrap_or_default();
            index.append(h, &block, &undo);
        }
        self.scripthashindex = Some(index);
        Ok(())
    }

    /// The Electrum history list for `script_hash`
    /// (`SHA256(scriptPubKey)`): `(height, tx position, txid)`
    /// entries in connect order. `None` when the index is disabled.
    pub fn scripthash_history(&self, script_hash: &[u8; 32]) -> Option<&[(u32, u16, Txid)]> {
        self.scripthashindex
            .as_ref()?
            .by_script
            .get(script_hash)
            .map(Vec::as_slice)
    }

    /// Whether the scripthash index is enabled.
    pub fn scripthash_index_enabled(&self) -> bool {
        self.scripthashindex.is_some()
    }

    /// Whether `-blockfilterindex` is active — `getindexinfo` reports
    /// `basic block filter index` under it.
    #[must_use]
    pub fn blockfilterindex_enabled(&self) -> bool {
        self.filterindex.is_some()
    }

    /// The basic filter and its header for a block — Core's
    /// `LookupFilter` + `LookupFilterHeader`. `height`/`hash` name the
    /// block index entry; a stale-branch hash resolves through the
    /// reorg hash index.
    #[must_use]
    pub fn block_filter(&self, height: u32, hash: &BlockHash) -> Option<(Vec<u8>, [u8; 32])> {
        self.filterindex
            .as_ref()?
            .lookup(height, hash)
            .map(|(f, h)| (f.to_vec(), *h))
    }

    /// The stored filter *header* for an active-chain height — the
    /// `cfheaders`/`cfcheckpt` half of BIP157 serving.
    #[must_use]
    pub fn filter_header_at(&self, height: u32) -> Option<[u8; 32]> {
        self.filterindex
            .as_ref()?
            .by_height
            .get(&height)
            .map(|e| e.2)
    }

    /// All active-chain filters in `start..=stop` — Core's
    /// `LookupFilterRange` for `scanblocks`. Heights the index never
    /// covered (shouldn't happen on a stored chain) skip silently —
    /// Core treats the same gap as an index error, but the maps here
    /// can't distinguish corruption from lag, so skipping is the safe
    /// degradation.
    #[must_use]
    pub fn block_filters_range(
        &self,
        start: u32,
        stop: u32,
    ) -> Vec<(BlockHash, Vec<u8>, [u8; 32])> {
        let Some(index) = &self.filterindex else {
            return Vec::new();
        };
        (start..=stop)
            .filter_map(|h| {
                index
                    .by_height
                    .get(&h)
                    .map(|(hash, f, hdr)| (*hash, f.clone(), *hdr))
            })
            .collect()
    }

    /// The assumeutxo base height when this chainstate was built from a
    /// `loadtxoutset` snapshot — Core's `m_from_snapshot_blockhash`.
    /// Heights at or below it are assume-valid: their undo slots are
    /// empty placeholders, their bodies were never required, and no
    /// reorg may fork below it.
    #[must_use]
    pub fn snapshot_base(&self) -> Option<u32> {
        self.snapshot_base
    }

    /// `ChainstateManager::ActivateSnapshot` + `PopulateAndValidateSnapshot`
    /// folded onto this single chainstate: the snapshot becomes the
    /// connected state (assume-valid through the base), and later
    /// blocks connect on top of it. Core additionally keeps a
    /// background-validation chainstate that re-validates up to the
    /// base; this port loads the set directly — the chainparams hash
    /// check is what makes that safe, and `snapshot_base` records the
    /// unvalidated prefix so reorgs never fork below it.
    ///
    /// Gate order and error strings are `ActivateSnapshot`'s, then
    /// `PopulateAndValidateSnapshot`'s.
    ///
    /// # Errors
    ///
    /// `SnapshotError` with Core's exact messages.
    pub fn activate_snapshot<R: std::io::Read>(
        &mut self,
        r: &mut R,
        meta: &crate::utxo_snapshot::SnapshotMetadata,
        mempool_nonempty: bool,
    ) -> Result<u32, crate::utxo_snapshot::SnapshotError> {
        use crate::utxo_snapshot::SnapshotError;
        let params = *self.tree.params();
        let base = meta.base_blockhash;
        let base_display = base.to_string();

        // ActivateSnapshot's checks, in order.
        if self.snapshot_base.is_some() {
            return Err(SnapshotError(
                "Can't activate a snapshot-based chainstate more than once".to_string(),
            ));
        }
        let Some(au_data) = params.assumeutxo_data.iter().find(|d| {
            std::str::FromStr::from_str(d.blockhash)
                .ok()
                .as_ref()
                .map(|h: &BlockHash| h.as_bytes() == base.as_bytes())
                .unwrap_or(false)
        }) else {
            let heights = params
                .assumeutxo_data
                .iter()
                .map(|d| d.height.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(SnapshotError(format!(
                "assumeutxo block hash in snapshot metadata not recognized (hash: {base_display}). The following snapshot heights are available: {heights}"
            )));
        };
        let Some(start) = self.tree.get(&base) else {
            return Err(SnapshotError(format!(
                "The base block header ({base_display}) must appear in the headers chain. Make sure all headers are syncing, and call loadtxoutset again"
            )));
        };
        if self.tree.is_failed(&base) {
            return Err(SnapshotError(format!(
                "The base block header ({base_display}) is part of an invalid chain"
            )));
        }
        let base_height = start.height;
        let best_header = self.tree.tip_hash();
        if self
            .tree
            .get_ancestor(&best_header, base_height)
            .map(|n| n.hash())
            != Some(base)
        {
            return Err(SnapshotError(
                "A forked headers-chain with more work than the chain with the snapshot base block header exists. Please proceed to sync without AssumeUtxo."
                    .to_string(),
            ));
        }
        if mempool_nonempty {
            return Err(SnapshotError(
                "Can't activate a snapshot when mempool not empty".to_string(),
            ));
        }

        // PopulateAndValidateSnapshot: the height-keyed table lookup is
        // a duplicate of the blockhash one here (the table is keyed on
        // both consistently), then the work comparison Core repeats.
        let Some(au_by_height) = params
            .assumeutxo_data
            .iter()
            .find(|d| d.height == base_height)
        else {
            return Err(SnapshotError(format!(
                "Assumeutxo height in snapshot metadata not recognized ({base_height}) - refusing to load snapshot"
            )));
        };
        let tip_work = self
            .tree
            .get(&self.connected)
            .map(|n| n.chainwork)
            .unwrap_or_default();
        if start.chainwork <= tip_work {
            return Err(SnapshotError(
                "Work does not exceed active chainstate".to_string(),
            ));
        }

        let mut loaded = UtxoSet::new();
        if let Some(be) = &self.coins_backend {
            loaded.attach_shared(be.clone());
        }
        // Backend mode: stream the coins through the dirty map in
        // bounded batches — a single commit of a full mainnet snapshot
        // (~166M entries) would balloon the write transaction.
        let mut since_flush = 0u32;
        let mut flush_err: Option<std::io::Error> = None;
        crate::utxo_snapshot::read_coins(r, meta.coins_count, base_height, |outpoint, coin| {
            if flush_err.is_some() {
                return;
            }
            loaded.insert_synthetic(outpoint, coin);
            since_flush += 1;
            if since_flush >= 2_000_000 && loaded.has_backend() {
                if let Err(e) = loaded.flush_partial_to_backend() {
                    flush_err = Some(e);
                }
                since_flush = 0;
            }
        })?;
        if let Some(e) = flush_err {
            return Err(SnapshotError(format!("coinsdb import: {e}")));
        }
        if loaded.has_backend() {
            loaded
                .flush_to_backend(&[], base_height)
                .map_err(|e| SnapshotError(format!("coinsdb import: {e}")))?;
        }

        // `AssumeutxoHash` — hash_serialized_3 of the loaded set must
        // match the chainparams value.
        let stats = crate::coinstats::compute(
            &loaded,
            i64::from(base_height),
            base,
            crate::coinstats::CoinStatsHashType::HashSerialized,
        );
        let got = stats
            .hash_serialized
            .map(|h| crate::hash::format_display_hex(h.as_bytes()))
            .unwrap_or_default();
        if got != au_by_height.hash_serialized {
            return Err(SnapshotError(format!(
                "Bad snapshot content hash: expected {}, got {got}",
                au_by_height.hash_serialized
            )));
        }

        // Commit: the connected chain becomes the header chain through
        // the base. Undo slots below it are empty placeholders — those
        // blocks were never connected here, and the reorg guard keeps
        // them from ever being "disconnected".
        let mut chain = Vec::with_capacity(base_height as usize + 1);
        let mut cursor = base;
        loop {
            chain.push(cursor);
            if cursor == params.genesis_header.hash() {
                break;
            }
            cursor = self
                .tree
                .get(&cursor)
                .map(|n| n.header.prev_block_hash)
                .ok_or_else(|| {
                    SnapshotError("snapshot base header chain is incomplete".to_string())
                })?;
        }
        chain.reverse();
        self.utxo = loaded;
        self.chain = chain;
        // Below the base no undo exists anywhere. Memory mode keeps the
        // `chain.len() - 1` invariant with empty placeholders; backend
        // mode leaves the tail empty — committed undos live in coinsdb.
        self.undos = if self.coins_backend.is_some() {
            Vec::new()
        } else {
            vec![BlockUndo::default(); base_height as usize]
        };
        self.connected = base;
        self.snapshot_base = Some(base_height);
        // Core creates the ibd chainstate at activation — background
        // validation replays `1..=base` from stored bodies and checks
        // the recomputed hash before the assumed prefix is trusted.
        self.background = Some(BackgroundValidation {
            utxo: UtxoSet::new(),
            next: 1,
        });
        self.snapshot_verified = false;
        self.precious = None;
        self.tree.apply_tx_meta(&base, 0, au_data.n_chain_tx);
        // The filter index belongs to the connected chain — every
        // pre-base height entry is now stale, and the first post-base
        // append chains its header off nothing (Core's snapshot
        // chainstate starts with an empty index).
        if let Some(index) = &mut self.filterindex {
            index.reset_to_snapshot();
        }
        if let Some(index) = &mut self.scripthashindex {
            index.reset_to_snapshot();
        }
        // The assumed state must be durable before the call returns —
        // a crash otherwise resumes the pre-snapshot `state.dat` while
        // blk files may already hold post-base bodies (Core flushes
        // the snapshot chainstate on activation).
        if self.store.is_some() {
            self.flush()
                .map_err(|e| SnapshotError(format!("snapshot flush: {e}")))?;
        }
        Ok(base_height)
    }

    /// The block a transaction was retained in, when the index is on —
    /// the `getrawtransaction` lookup for a txid with no named block.
    /// Entries survive disconnects (Core's txindex never removes), so
    /// the answer may name a side-branch block.
    #[must_use]
    pub fn find_transaction(&self, txid: &Txid) -> Option<BlockHash> {
        self.txindex.as_ref()?.map.get(txid).copied()
    }

    /// Whether `-txindex` is active — `getindexinfo` reports `txindex`
    /// only then, like Core's index list.
    #[must_use]
    pub fn txindex_enabled(&self) -> bool {
        self.txindex.is_some()
    }

    /// Whether `hash` is on the connected chain — Core's
    /// `in_active_chain` check for indexed lookups.
    #[must_use]
    pub fn on_active_chain(&self, hash: &BlockHash) -> bool {
        self.tree
            .get(hash)
            .is_some_and(|n| self.chain.get(n.height as usize) == Some(hash))
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
        cs.resume(dir, now)
    }

    /// `with_store` plus the disk-backed coins view — the default for
    /// a real datadir (`-dbcache` tunes `cache_bytes`). The backend is
    /// attached *before* `state.dat` loads so restore can migrate an
    /// inline-UTXO snapshot or rewind a crash-ahead backend.
    ///
    /// # Errors
    /// `io::Error` on store/backend open or resume failure.
    pub fn with_store_coinsdb(
        dir: &Path,
        params: &Params,
        now: u32,
        cache_bytes: usize,
    ) -> std::io::Result<Self> {
        let store = BlockStore::open(dir, params.message_start)?;
        let mut cs = Self::new(params);
        cs.store = Some(store);
        cs.enable_coinsdb(dir, cache_bytes)?;
        cs.resume(dir, now)
    }

    /// The resume half of `with_store*`: read `state.dat` if present,
    /// then replay any stored bodies it doesn't cover.
    fn resume(self, dir: &Path, now: u32) -> std::io::Result<Self> {
        let mut cs = self;
        // A snapshot that fails to load or restore falls back to full replay —
        // the blk files are the record of what arrived; state.dat only ever
        // re-derives it faster.
        let mut pending = match store::read_state(dir, cs.tree.params().message_start) {
            Ok(Some(state)) => match cs.restore(state, now) {
                Ok(pending) => pending,
                Err(_) => {
                    // Restore failed — rebuild a clean in-memory
                    // chainstate; the backend keeps its data (a fresh
                    // UtxoSet over it replays from blk files anyway).
                    let store = cs.store.take();
                    let backend = cs.coins_backend.take();
                    cs = Self::new(cs.tree.params());
                    cs.store = store;
                    cs.coins_backend = backend;
                    if let Some(be) = &cs.coins_backend {
                        cs.utxo.attach_shared(be.clone());
                    }
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
        for (hash, n_tx, n_chain_tx) in &state.tx_meta {
            if !self.tree.contains(hash) {
                return Err(corrupt("tx_meta on unindexed header"));
            }
            self.tree.apply_tx_meta(hash, *n_tx, *n_chain_tx);
        }
        if !self.tree.restore_tip(state.best_header) {
            return Err(corrupt("best header not a max-work tip"));
        }
        let store = self.store.as_ref().ok_or_else(|| corrupt("no store"))?;
        let snapshot_base = (state.snapshot_base > 0).then_some(state.snapshot_base);
        for (index, hash) in state.chain.iter().enumerate() {
            if !self.tree.contains(hash) {
                return Err(corrupt("connected block unindexed"));
            }
            // The genesis (index 0) is never accepted through
            // `accept_block`, and heights at or below an assumeutxo
            // base were never connected — both legitimately absent
            // from the store.
            let assumed = snapshot_base.is_some_and(|b| index <= b as usize);
            if index > 0 && !assumed && store.position(hash).is_none() {
                return Err(corrupt("connected block body not stored"));
            }
        }
        self.connected = state.tip;
        self.chain = state.chain;
        self.snapshot_base = snapshot_base;
        self.snapshot_verified = state.snapshot_verified;
        // A resumed snapshot that never finished its background
        // validation re-replays it — the ibd chainstate is rebuilt at
        // height 1 (Core persists its progress; replay from scratch is
        // the honest equivalent).
        if snapshot_base.is_some() && !state.snapshot_verified {
            self.background = Some(BackgroundValidation {
                utxo: UtxoSet::new(),
                next: 1,
            });
        }
        // Coins view: `externalized` (v4) states keep coins+undos in
        // coinsdb — reconcile it against this snapshot's tip. Inline
        // states (v3, or v4 written without a backend) carry the data
        // in `state.utxo`/`state.undos` — under a backend they migrate
        // in; without one they load as the live set.
        if state.externalized {
            if self.coins_backend.is_none() {
                return Err(corrupt(
                    "state externalizes coins to coinsdb but no backend is attached",
                ));
            }
            self.undos = Vec::new();
            // Crash window: the backend may have committed past this
            // snapshot's tip — rewind via the stored undos + bodies.
            self.reconcile_backend(state.height)?;
        } else if let Some(be) = &self.coins_backend {
            // Inline-format state under a backend: stream the coins in
            // bounded chunks, then the undos — one migration commit at
            // the snapshot's own height.
            let mut batch: HashMap<OutPoint, Option<Coin>> = HashMap::with_capacity(100_000);
            for (op, coin) in state.utxo {
                batch.insert(op, Some(coin));
                if batch.len() >= 100_000 {
                    be.commit(&batch, &[], state.height)?;
                    batch.clear();
                }
            }
            let undos: Vec<(u32, crate::hash::BlockHash, BlockUndo)> = state
                .undos
                .into_iter()
                .enumerate()
                .map(|(i, u)| (i as u32 + 1, self.chain[i + 1], u))
                .collect();
            be.commit(&batch, &undos, state.height)?;
            self.undos = Vec::new();
        } else {
            self.undos = state.undos;
            self.utxo = UtxoSet::new();
            for (outpoint, coin) in state.utxo {
                self.utxo.insert_synthetic(outpoint, coin);
            }
        }
        let mut covered: HashSet<BlockHash> = state.failed.into_iter().collect();
        covered.extend(self.chain.iter().copied());
        self.stored_bodies(&covered)
    }

    /// `true` if `hash`'s body is available — in memory or in the store.
    /// Core's `HaveTxsDownloaded` equivalent under a durable body store.
    /// The sync layer needs it to decide which announced blocks to fetch.
    pub fn have_body(&self, hash: &BlockHash) -> bool {
        // The genesis body is implicit in the chain anchor — Core marks it
        // BLOCK_HAVE_DATA without ever downloading it.
        *hash == self.tree.params().genesis_header.hash()
            || self.blocks.contains_key(hash)
            || self.store.as_ref().is_some_and(|store| {
                // A pruned body is genuinely unavailable — report false so
                // sync refetches it and `accept_block` re-stores it on
                // resubmission (Core's `fAlreadyHave` loses BLOCK_HAVE_DATA
                // under pruning the same way).
                store
                    .position(hash)
                    .is_some_and(|pos| !store.is_pruned(pos))
            })
    }

    /// `hash`'s body, from memory or the store. Public for the P2P serving
    /// path (`getdata` → block bytes). The genesis body is synthesized
    /// from params when nothing stored it — Core's blk files always
    /// carry it, and `getblock 0` must not report "not found".
    pub fn body(&self, hash: &BlockHash) -> Option<Block> {
        if let Some(block) = self.blocks.get(hash) {
            return Some(block.clone());
        }
        if let Some(store) = self.store.as_ref()
            && let Some(pos) = store.position(hash)
            && let Ok(block) = store.read(pos)
        {
            return Some(block);
        }
        if *hash == self.tree.params().genesis_header.hash() {
            return self.tree.params().genesis_block();
        }
        None
    }

    /// The snapshot of the current validation state for `state.dat`.
    fn snapshot(&self) -> StateData {
        let mut failed = self.tree.failed_hashes();
        failed.sort_unstable();
        // With a coinsdb backend the coins set and flushed undos live
        // in `coinsdb.redb` — `state.dat` carries only the unflushed
        // tail (still needed, since `flush_coins` runs before
        // `write_state` the tail is empty anyway, but write it for
        // correctness when called on a mid-flight state).
        let externalized = self.coins_backend.is_some();
        let (utxo, undos) = if externalized {
            (Vec::new(), Vec::new())
        } else {
            (self.utxo.iter(), self.undos.clone())
        };
        StateData {
            tip: self.connected,
            height: self.chain.len() as u32 - 1,
            headers: self.tree.headers_by_height(),
            best_header: self.tree.tip_hash(),
            chain: self.chain.clone(),
            undos,
            utxo,
            failed,
            tx_meta: {
                let mut meta: Vec<(BlockHash, u32, u64)> = self
                    .tree
                    .nodes()
                    // `n_chain_tx` alone is meaningful — the assumeutxo
                    // base carries the table's count with `n_tx` = 0.
                    .filter(|(_, n)| n.n_tx > 0 || n.n_chain_tx > 0)
                    .map(|(h, n)| (*h, n.n_tx, n.n_chain_tx))
                    .collect();
                meta.sort_unstable();
                meta
            },
            snapshot_base: self.snapshot_base.unwrap_or(0),
            snapshot_verified: self.snapshot_verified,
            externalized,
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
        // Bodies first — the crash-rewind path disconnects blocks via
        // their blk-file bodies, so they must be durable before the
        // coins commit that could need them.
        let (dir, magic) = {
            let Some(store) = &mut self.store else {
                return Ok(());
            };
            store.flush()?;
            (store.dir().to_path_buf(), store.magic())
        };
        // Coins second: a crash here leaves the backend ahead of
        // `state.dat`, which `reconcile_backend` rewinds via the
        // committed undo records. The reverse order would leave the
        // backend *behind* — unrecoverable without a full replay.
        self.flush_coins()?;
        store::write_state(&dir, magic, &self.snapshot())
    }

    /// Deletes the oldest `blk*.dat` files while their total exceeds
    /// `keep` bytes — Core's `-prune` analog. A reorg reaching a pruned
    /// body fails loudly at disconnect rather than silently skipping
    /// (Core halts with a fatal error past the prune depth); a
    /// resubmitted pruned block re-validates and re-stores.
    ///
    /// # Errors
    ///
    /// `io::Error` on listing/removal failure. No-op without a store.
    pub fn prune(&mut self, keep_bytes: u64) -> std::io::Result<u32> {
        match &mut self.store {
            Some(store) => store.prune_to_bytes(keep_bytes),
            None => Ok(0),
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

    /// The backing block store when this chainstate persists bodies —
    /// `None` for the in-memory configuration. Read-only access for
    /// reporting (getblockchaininfo's `pruned`/`size_on_disk`).
    #[must_use]
    pub fn store(&self) -> Option<&BlockStore> {
        self.store.as_ref()
    }

    /// A stored block body by hash, if it passed `CheckBlock` +
    /// `ContextualCheckBlock` — from memory only. Bodies a snapshot restore
    /// left on disk (everything at or below the snapshot tip) are reachable
    /// through the store, not here.
    #[must_use]
    pub fn block(&self, hash: &BlockHash) -> Option<&Block> {
        self.blocks.get(hash)
    }

    /// Heights `1..=undo_base` have their undo in the coinsdb backend
    /// (or none, below the assumeutxo base); the in-memory tail covers
    /// everything above.
    /// First height NOT covered by `self.undos` — the undo tail starts
    /// at `undo_base + 1`. With a backend it tracks the committed
    /// watermark (flushed undos live in coinsdb); in memory mode the
    /// vec holds one entry per height (empty placeholders below the
    /// assumeutxo base) so the tail starts at 0.
    fn undo_base(&self) -> u32 {
        self.coins_backend.as_ref().map_or(0, |b| b.tip_height())
    }

    /// The undo data for the *active-chain* block at `height` — Core's
    /// `ReadBlockUndo`. Reads the backend's `undo` table for flushed
    /// heights and the in-memory tail for the rest; genesis and heights
    /// above the connected tip have none, and side-branch blocks never
    /// get undo entries, matching Core's rev*.dat semantics.
    #[must_use]
    pub fn undo(&self, height: u32) -> Option<BlockUndo> {
        if height == 0 {
            return None;
        }
        let base = self.undo_base();
        if height <= base {
            return self
                .coins_backend
                .as_deref()
                .and_then(|b| b.undo_at(height));
        }
        self.undos.get((height - base - 1) as usize).cloned()
    }

    /// Attaches the disk coins backend — Core's `CCoinsViewDB` under
    /// the cache. Call before load/replay so every connect streams
    /// through the write-back cache.
    ///
    /// # Errors
    /// `io::Error` when `coinsdb.redb` cannot be opened or created.
    pub fn enable_coinsdb(
        &mut self,
        dir: &std::path::Path,
        cache_bytes: usize,
    ) -> std::io::Result<()> {
        let backend = std::sync::Arc::new(crate::coinsdb::CoinsBackend::open(dir)?);
        self.utxo.attach_shared(backend.clone());
        self.utxo.set_budget(cache_bytes);
        self.coins_backend = Some(backend);
        Ok(())
    }

    /// Commits the dirty coins cache plus the in-memory undo tail to
    /// the backend in one atomic transaction — Core's
    /// `FlushStateToDisk` coins layer. No-op in memory-only mode.
    ///
    /// # Errors
    /// `io::Error` on backend commit failure.
    fn flush_coins(&mut self) -> std::io::Result<()> {
        // A flush persists the tip + undo tail — every pending block
        // must be verified first. Empty unless speculative connect is
        // on; on failure the rewind path re-enters here with the
        // queue already cleared.
        self.drain_scripts()
            .map_err(|_| std::io::Error::other("pending script check failed"))?;
        self.flush_coins_with(&[], self.chain.len() as u32 - 1)
    }

    /// `flush_coins` with `extra` undo records for heights at/below the
    /// current backend watermark — used when a reorg replaces blocks
    /// whose undos were already flushed. The commit stays atomic:
    /// coins + every pending undo + the new `tip` land together.
    fn flush_coins_with(
        &mut self,
        extra: &[(u32, crate::hash::BlockHash, BlockUndo)],
        tip: u32,
    ) -> std::io::Result<()> {
        if self.coins_backend.is_none() {
            // Memory mode: `extra` is unreachable — a fork below
            // `undo_base` requires a backend watermark (memory mode's
            // `undo_base` is `snapshot_base`, and the reorg guard
            // forbids forking at or below it).
            return Ok(());
        }
        let base = self.undo_base();
        let mut pending: Vec<(u32, crate::hash::BlockHash, BlockUndo)> = extra.to_vec();
        pending.extend(self.undos.iter().enumerate().map(|(i, u)| {
            let h = base + 1 + i as u32;
            (h, self.chain[h as usize], u.clone())
        }));
        self.utxo.flush_to_backend(&pending, tip)?;
        self.undos.clear();
        Ok(())
    }

    /// Rewinds the coins backend down to `state_tip` — the
    /// crash-window repair when a coins commit landed but its
    /// `state.dat` never did. Each height disconnects through a
    /// scratch view sharing the backend, then commits — so progress
    /// survives another crash mid-rewind.
    fn reconcile_backend(&mut self, state_tip: u32) -> std::io::Result<()> {
        let Some(be) = self.coins_backend.clone() else {
            return Ok(());
        };
        let db_tip = be.tip_height();
        if db_tip < state_tip {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "coinsdb tip {db_tip} behind state.dat tip {state_tip} —                      commit order makes this impossible; the database is corrupt"
                ),
            ));
        }
        for h in (state_tip + 1..=db_tip).rev() {
            let Some((hash, undo)) = be.undo_entry(h) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("coinsdb rewind: no undo for height {h}"),
                ));
            };
            let Some(block) = self.body(&hash) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("coinsdb rewind: no body for {hash} at {h}"),
                ));
            };
            let mut scratch = UtxoSet::new();
            scratch.attach_shared(be.clone());
            connect::disconnect_block(&block, &mut scratch, &undo).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("coinsdb rewind: undo inconsistent at {h}"),
                )
            })?;
            scratch.flush_to_backend(&[], h - 1)?;
        }
        Ok(())
    }

    /// Core's `GetChainTxStats` — transaction-count statistics for the
    /// `nblocks`-sized window ending at `hash` (`None` = the connected
    /// tip; `nblocks` `None` = one month of blocks at the network's
    /// target spacing).
    ///
    /// `window_block_count` clamps the requested window to
    /// `height - 1` — the walk never crosses the genesis (Core's bound:
    /// `nblocks > height - 1` is a `-8`). Optional fields drop out
    /// exactly where Core omits them: `tx_count` when the end block was
    /// never connected (its `n_chain_tx` is unknown — assumeutxo or a
    /// side-branch tip), `window_tx_count` when either endpoint's count
    /// is unknown, `tx_rate` when the interval isn't positive.
    ///
    /// # Errors
    ///
    /// [`TxStatsError::UnknownBlock`] when `hash` isn't in the block
    /// index; [`TxStatsError::BadWindow`] when `nblocks` is negative or
    /// exceeds `height - 1` — on a genesis-only chain every `nblocks`
    /// fails, matching Core.
    pub fn chain_tx_stats(
        &self,
        hash: Option<&BlockHash>,
        nblocks: Option<i64>,
    ) -> Result<ChainTxStats, TxStatsError> {
        let node = match hash {
            Some(h) => self.tree.get(h).ok_or(TxStatsError::UnknownBlock)?,
            None => self
                .tree
                .get(&self.connected)
                .ok_or(TxStatsError::UnknownBlock)?,
        };
        let params = self.tree.params();
        // Core's bound is `max(0, height - 1)` — at genesis a zero
        // window is still legal. An absent `nblocks` clamps to the
        // available history; an explicit one out of range errors.
        let bound = i64::from(node.height).saturating_sub(1).max(0);
        let wanted = match nblocks {
            Some(n) => n,
            None => ((30 * 24 * 60 * 60 / params.pow_target_spacing) as i64).min(bound),
        };
        if wanted < 0 || wanted > bound {
            return Err(TxStatsError::BadWindow);
        }
        let count = wanted as u32;
        let start = self
            .tree
            .get_ancestor(&node.hash(), node.height - count)
            .ok_or(TxStatsError::UnknownBlock)?;
        let have_counts = node.n_chain_tx > 0 && start.n_chain_tx > 0;
        // Core's `window_interval` is `GetMedianTimePast(end) -
        // GetMedianTimePast(start)` — median-of-11, not the header
        // timestamps themselves.
        let end_mtp = self
            .tree
            .median_time_past(&node.hash())
            .unwrap_or(node.header.time);
        let start_mtp = self
            .tree
            .median_time_past(&start.hash())
            .unwrap_or(start.header.time);
        let interval = i64::from(end_mtp) - i64::from(start_mtp);
        let window_tx = if have_counts {
            Some(node.n_chain_tx - start.n_chain_tx)
        } else {
            None
        };
        Ok(ChainTxStats {
            time: node.header.time,
            tx_count: (node.n_chain_tx > 0).then_some(node.n_chain_tx),
            final_hash: node.hash(),
            final_height: node.height,
            window_block_count: count,
            window_interval: (count > 0).then_some(interval),
            window_tx_count: if count > 0 { window_tx } else { None },
            tx_rate: match (count > 0 && interval > 0, window_tx) {
                (true, Some(n)) => Some(n as f64 / interval as f64),
                _ => None,
            },
        })
    }

    /// `CVerifyDB::VerifyDB` — re-validates the last `depth` connected
    /// blocks, walking backwards through their undo records on a cloned
    /// UTXO set (level ≥ 3) then forwards again through `CheckBlock`,
    /// `ContextualCheckBlock`, and a full `ConnectBlock` with the same
    /// per-block script-check decision the live connect used (level 4).
    /// Level 0 checks body presence, ≥ 1 adds `CheckBlock`, ≥ 2 undo
    /// records, ≥ 3 the disconnect pass. The live UTXO set is never
    /// touched, so a `false` verdict leaves the chainstate consistent.
    /// `depth <= 0` or a depth past the tip means the whole chain
    /// (VerifyDB's `check_depth` clamp); `check_level < 0` runs no
    /// checks and returns `true`, like Core.
    #[must_use]
    pub fn verify_tip(&mut self, check_level: i32, depth: i64) -> bool {
        let tip = self.chain.len() as u32 - 1; // chain[0] is genesis
        if check_level < 0 {
            return true;
        }
        let depth = if depth <= 0 || depth > i64::from(tip) {
            i64::from(tip)
        } else {
            depth
        };
        let start = (u64::from(tip) + 1 - depth as u64) as u32;
        let params = *self.tree.params();
        // Overlay, not clone: VerifyDB's scratch view must not pay an
        // O(utxo) copy — it reads through to the live set and is
        // discarded at the end either way.
        let mut utxo = self.utxo.overlay();
        let verdict = (|utxo: &mut UtxoSet| {
            // VerifyDB's backward pass: bodies present (level 0),
            // CheckBlock (≥ 1), undo present (≥ 2), DisconnectBlock
            // applies (≥ 3).
            for height in (start..=tip).rev() {
                let hash = self.chain[height as usize];
                let Some(block) = self.body(&hash) else {
                    return false;
                };
                if check_level >= 1 && check::check_block(&block, &params).is_err() {
                    return false;
                }
                let Some(undo) = self.undo(height) else {
                    return check_level < 2;
                };
                if check_level >= 3 && connect::disconnect_block(&block, utxo, &undo).is_err() {
                    return false;
                }
            }
            if check_level < 4 {
                return true;
            }
            // Forward pass: full reconnect — contextual checks plus
            // ConnectBlock under the live assumevalid script decision.
            for height in start..=tip {
                let hash = self.chain[height as usize];
                let Some(block) = self.body(&hash) else {
                    return false;
                };
                let ctx = BlockContext {
                    params: &params,
                    height,
                    parent_median_time_past: self
                        .tree
                        .median_time_past(&block.header.prev_block_hash),
                };
                if check::contextual_check_block(&block, &ctx).is_err() {
                    return false;
                }
                let cctx = ConnectContext {
                    params: &params,
                    tree: &self.tree,
                    block_hash: hash,
                    script_checks: self.script_checks(&hash, &params),
                    script_pool: None,
                };
                if connect::connect_block(&block, utxo, &cctx).is_err() {
                    return false;
                }
            }
            true
        })(&mut utxo);
        self.utxo.unoverlay(utxo, false);
        verdict
    }

    /// UTXO-set statistics over the active tip — `gettxoutsetinfo`'s
    /// non-index path (Core's `GetUTXOStats` with no coinstatsindex and
    /// no target pindex: the view's own best block is reported).
    #[must_use]
    pub fn coin_stats(&self, hash_type: CoinStatsHashType) -> CoinStats {
        coinstats::compute(
            &self.utxo,
            i64::from(self.chain.len() as u32 - 1),
            self.connected,
            hash_type,
        )
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
        self.tree.note_body(&hash, block.transactions.len() as u32);
        if let Some(index) = &mut self.txindex {
            index.index_block(hash, block);
        }
        if block.header.prev_block_hash == self.connected {
            let ctx = ConnectContext {
                params: &params,
                tree: &self.tree,
                block_hash: hash,
                script_checks: self.script_checks(&hash, &params),
                script_pool: self.script_pool.as_deref(),
            };
            let connected = if ctx.script_pool.is_some() {
                connect::connect_block_deferred(block, &mut self.utxo, &ctx)
                    .map(|(undo, check)| (undo, Some(check)))
            } else {
                connect::connect_block(block, &mut self.utxo, &ctx).map(|undo| (undo, None))
            };
            match connected {
                Ok((undo, check)) => {
                    if let Some(index) = &mut self.filterindex {
                        index.append(height, block, &undo);
                    }
                    if let Some(index) = &mut self.scripthashindex {
                        index.append(height, block, &undo);
                    }
                    self.chain.push(hash);
                    self.undos.push(undo);
                    self.connected = hash;
                    self.tree.note_connected(&hash);
                    if let Some(check) = check {
                        // Pipeline window: leave this block's checks
                        // outstanding while the next block's serial
                        // phase overlaps them; only the oldest pending
                        // block waits here.
                        const SPEC_DEPTH: usize = 8;
                        self.pending_scripts.push_back((hash, height, check));
                        self.drain_pending_to(SPEC_DEPTH)
                            .map_err(BlockRejection::Connect)?;
                    }
                    // The write-back cache is flushed at block
                    // boundaries — a full map commits coins + undo tail
                    // + tip atomically (Core's `FlushStateToDisk` under
                    // cache pressure).
                    if self.utxo.over_budget() {
                        self.flush_coins().map_err(|_| {
                            BlockRejection::Connect(ConnectError::Internal("coinsdb flush failed"))
                        })?;
                    }
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
        // `ActivateBestChain` stops when the most-work candidate is
        // already the tip — resubmitting a precious-marked tip must
        // stay `AlreadyKnown`, not run an empty reorg.
        if hash == self.connected {
            return Ok(None);
        }
        // Equal work only activates when the candidate tip is the
        // `preciousblock` — Core's nSequenceId tie-break where the
        // precious block counts as received earliest.
        let wins_tie = new_node.chainwork == conn_node.chainwork && self.precious == Some(hash);
        if new_node.chainwork < conn_node.chainwork
            || (new_node.chainwork == conn_node.chainwork && !wins_tie)
        {
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

        // `assumeutxo` floors the chain: a branch forking below the
        // snapshot base can never activate — there is no state or undo
        // below it to disconnect into (Core's snapshot chainstate
        // simply has no view of the pre-base chain).
        if self.snapshot_base.is_some_and(|b| fork_height < b) {
            return Ok(None);
        }

        // A candidate whose branch lacks a stored body can never activate
        // (Core: `!HaveTxsDownloaded` keeps it out of `setBlockIndexCandidates`)
        // — the only way a header enters the index without a body is a
        // `BLOCK_MUTATED`-class `CheckBlock` rejection, which is not marked
        // failed, so its descendants park rather than report a verdict.
        if branch_hashes.iter().any(|h| !self.have_body(h)) {
            return Ok(None);
        }

        // Simulate on an overlay: the live set moves into the overlay's
        // base layer (an O(1) `mem::take`, not the old O(utxo) clone) —
        // every disconnect/connect writes only to the overlay's dirty
        // map. Any failure path restores `self.utxo` via `unoverlay`.
        let mut sim = self.utxo.overlay();
        let new_undos = match self.simulate_branch(&mut sim, fork_height, &branch_hashes, params) {
            Ok(undos) => undos,
            Err(err) => {
                self.utxo.unoverlay(sim, false);
                return Err(err);
            }
        };
        self.utxo.unoverlay(sim, true);

        // Commit. `disconnected` records whether any connected block was rolled
        // back — false when the branch merely extended the tip (a stored-body
        // resubmission landing here is `ActivateBestChain` connecting it, not
        // a reorg).
        let disconnected = (fork_height as usize) < self.chain.len() - 1;
        let old_tip_height = self.chain.len() as u32 - 1;
        // The filter index follows the chain's own rewind/append: evicted
        // heights move to the hash index, then each reconnected block
        // chains its header off the fork point's.
        if let Some(index) = &mut self.filterindex {
            for h in (fork_height + 1..=old_tip_height).rev() {
                index.disconnect(h);
            }
        }
        if let Some(index) = &mut self.scripthashindex {
            for h in (fork_height + 1..=old_tip_height).rev() {
                index.disconnect(h);
            }
        }
        // Core's `disconnectpool`: every rolled-back block's non-coinbase
        // txs are mempool candidates again, in disconnect order
        // (tip → fork).
        for h in (fork_height + 1..=old_tip_height).rev() {
            self.disconnected.push(self.chain[h as usize]);
        }
        self.chain.truncate(fork_height as usize + 1);
        // `undos` is the tail above `undo_base` — the backend holds the
        // rest. A fork below the watermark leaves flushed undo records
        // in place; the new branch's undos for those heights are
        // committed through `flush_coins` below (its overwrite keeps
        // backend undo = active chain).
        let base = self.undo_base();
        if fork_height >= base {
            self.undos
                .truncate(fork_height.saturating_sub(base) as usize);
        } else {
            self.undos.clear();
        }
        let bodies: Vec<Option<Block>> = branch_hashes.iter().map(|bh| self.body(bh)).collect();
        if let Some(index) = &mut self.filterindex {
            for (i, (b, u)) in bodies.iter().zip(new_undos.iter()).enumerate() {
                if let Some(b) = b {
                    index.append(fork_height + 1 + i as u32, b, u);
                }
            }
        }
        if let Some(index) = &mut self.scripthashindex {
            for (i, (b, u)) in bodies.iter().zip(new_undos.iter()).enumerate() {
                if let Some(b) = b {
                    index.append(fork_height + 1 + i as u32, b, u);
                }
            }
        }
        self.chain.extend(branch_hashes);
        // Undos for heights at/below the backend watermark can't sit in
        // the tail — they're committed now, atomically with the coin
        // delta, so backend undo records always describe the committed
        // coin state (the crash-rewind invariant).
        let base = self.undo_base();
        let split = (base.saturating_sub(fork_height) as usize).min(new_undos.len());
        if split > 0 {
            let low: Vec<(u32, crate::hash::BlockHash, BlockUndo)> = new_undos[..split]
                .iter()
                .enumerate()
                .map(|(i, u)| {
                    let h = fork_height + 1 + i as u32;
                    (h, self.chain[h as usize], u.clone())
                })
                .collect();
            self.flush_coins_with(&low, self.chain.len() as u32 - 1)
                .map_err(|_| ConnectError::Internal("coinsdb reorg flush"))?;
        }
        self.undos.extend(new_undos.into_iter().skip(split));
        self.connected = hash;
        Ok(Some(disconnected))
    }

    /// Runs a candidate branch against an overlay UTXO set: disconnect
    /// the active chain to `fork_height`, then connect `branch_hashes`.
    /// Returns the new branch's undo records. `sim` must be the overlay
    /// produced by `self.utxo.overlay()` — the caller restores it via
    /// `unoverlay` on both outcomes.
    fn simulate_branch(
        &mut self,
        sim: &mut UtxoSet,
        fork_height: u32,
        branch_hashes: &[BlockHash],
        params: &Params,
    ) -> Result<Vec<BlockUndo>, ConnectError> {
        for height in (fork_height + 1..self.chain.len() as u32).rev() {
            let block_hash = self.chain[height as usize];
            let Some(block) = self.body(&block_hash) else {
                return Err(ConnectError::Internal("missing connected block body"));
            };
            let Some(undo) = self.undo(height) else {
                return Err(ConnectError::Internal("missing connected undo"));
            };
            connect::disconnect_block(&block, sim, &undo)
                .map_err(|_| ConnectError::Internal("disconnect undo inconsistent"))?;
        }
        let mut new_undos = Vec::with_capacity(branch_hashes.len());
        for branch_hash in branch_hashes {
            let Some(block) = self.body(branch_hash) else {
                return Err(ConnectError::Internal("missing branch block body"));
            };
            let ctx = ConnectContext {
                params,
                tree: &self.tree,
                block_hash: *branch_hash,
                script_checks: self.script_checks(branch_hash, params),
                script_pool: None,
            };
            match connect::connect_block(&block, sim, &ctx) {
                Ok(undo) => {
                    // `ConnectTip` stamps nChainTx as each block lands —
                    // kept even if a later branch block fails the whole
                    // activation (those blocks genuinely connected).
                    self.tree.note_connected(branch_hash);
                    new_undos.push(undo);
                }
                Err(err) => {
                    // The branch wins on work but this block is invalid: mark
                    // it (and thereby every later descendant) and keep the old
                    // active chain — `InvalidChainFound`'s exact behavior.
                    self.tree.mark_invalid(*branch_hash);
                    return Err(err);
                }
            }
        }
        Ok(new_undos)
    }

    /// `preciousblock` — marks `hash` as the equal-work tie winner and
    /// re-runs tip selection, like Core's `PreciousBlock` bumping the
    /// block's `nSequenceId` then calling `ActivateBestChain`. Returns
    /// `Ok(false)` when `hash` isn't in the block index (the caller
    /// maps that to "Block not found"); `Ok(true)` after the mark —
    /// a less-work or header-only candidate simply stays parked, which
    /// is still a Core success. The mark is in-memory only: Core's
    /// sequence ids don't persist either, so a restart forgets it.
    ///
    /// # Errors
    ///
    /// `ConnectError` when the marked block wins its tie but fails to
    /// connect during the reorg.
    pub fn precious_block(&mut self, hash: &BlockHash) -> Result<bool, ConnectError> {
        if !self.tree.contains(hash) {
            return Ok(false);
        }
        self.precious = Some(*hash);
        // Immediate re-evaluation — a precious side-branch tip with
        // equal work activates on the spot (Core: ActivateBestChain).
        let params = *self.tree.params();
        self.maybe_reorg(*hash, &params)?;
        Ok(true)
    }

    /// `invalidateblock` — permanently marks `hash` failed along with every
    /// descendant (Core's `BLOCK_FAILED_VALID`/`BLOCK_FAILED_CHILD` sweep),
    /// disconnecting the chain down to its parent when it sits on the active
    /// tip path, then re-runs tip selection over what remains.
    ///
    /// Returns `Ok(None)` when `hash` is not in the block index (the RPC maps
    /// that to `-5` "Block not found"); `Ok(Some(rewound))` otherwise —
    /// `rewound` is the number of leading entries in the next
    /// [`Self::take_disconnected`] drain that came from the rewind loop,
    /// the phase Core feeds to the mempool tip-first and only for the
    /// first 10 `DisconnectTip`s. Entries after it are the follow-up
    /// `ActivateBestChain` reorg, fed fork-first like any other reorg.
    /// Genesis's invalidation is a silent no-op (`rewound == 0`).
    ///
    /// # Errors
    ///
    /// `ConnectError` when a disconnect or the follow-up activation hits an
    /// internal inconsistency (missing body/undo, undo mismatch, coinsdb
    /// commit failure).
    pub fn invalidate_block(&mut self, hash: &BlockHash) -> Result<Option<u32>, ConnectError> {
        let Some(node) = self.tree.get(hash) else {
            return Ok(None);
        };
        if node.height == 0 {
            return Ok(Some(0));
        }
        let height = node.height;
        self.tree.mark_invalid_subtree(hash);
        let rewind_start = self.disconnected.len();
        if self.chain.get(height as usize) == Some(hash) {
            self.rewind_connected(height - 1)?;
        }
        let rewound = (self.disconnected.len() - rewind_start) as u32;
        self.activate_best()?;
        Ok(Some(rewound))
    }

    /// `reconsiderblock` — clears the failed flag on `hash`, its ancestors and
    /// descendants (Core's `ResetBlockFailureFlags`), then re-runs tip
    /// selection: a previously disconnected branch that still carries the most
    /// work re-activates through the normal connect path.
    ///
    /// Returns `Ok(false)` when `hash` is not in the block index.
    ///
    /// # Errors
    ///
    /// `ConnectError` on the same internal failures as `invalidate_block`.
    pub fn reconsider_block(&mut self, hash: &BlockHash) -> Result<bool, ConnectError> {
        if !self.tree.contains(hash) {
            return Ok(false);
        }
        self.tree.clear_invalid_subtree(hash);
        self.activate_best()?;
        Ok(true)
    }

    /// Disconnects the connected chain down to `target` — the `DisconnectTip`
    /// loop inside Core's `InvalidateBlock`. Each popped block's undo reverses
    /// its UTXO application and the height drops out of the filter/scripthash
    /// indexes; the coin delta and new tip then commit in one transaction via
    /// `flush_coins`.
    fn rewind_connected(&mut self, target: u32) -> Result<(), ConnectError> {
        while self.chain.len() as u32 - 1 > target {
            let height = self.chain.len() as u32 - 1;
            let block_hash = self.chain[height as usize];
            let block = self
                .body(&block_hash)
                .ok_or(ConnectError::Internal("missing connected block body"))?;
            let undo = self
                .undo(height)
                .ok_or(ConnectError::Internal("missing connected undo"))?;
            connect::disconnect_block(&block, &mut self.utxo, &undo)
                .map_err(|_| ConnectError::Internal("disconnect undo inconsistent"))?;
            if let Some(index) = &mut self.filterindex {
                index.disconnect(height);
            }
            if let Some(index) = &mut self.scripthashindex {
                index.disconnect(height);
            }
            self.chain.pop();
            // Core's `DisconnectTip` → `disconnectpool`: the block's
            // non-coinbase txs are mempool candidates again. Disconnect
            // order is tip-first.
            self.disconnected.push(block_hash);
            let base = self.undo_base();
            self.undos
                .truncate((height - 1).saturating_sub(base) as usize);
        }
        if let Some(tip) = self.chain.last() {
            self.connected = *tip;
        }
        self.flush_coins()
            .map_err(|_| ConnectError::Internal("coinsdb flush failed"))?;
        Ok(())
    }

    /// Drains the disconnected-block queue — the hashes of every block
    /// unwound since the last drain, in disconnect order (most-recent
    /// tip first). The node layer re-admits their non-coinbase
    /// transactions to the mempool: Core's `MaybeUpdateMempoolForReorg`
    /// feed order is this list reversed (fork-adjacent block first,
    /// txs in block order) for a batched reorg, or in-order for
    /// `invalidateblock`'s per-tip loop.
    pub fn take_disconnected(&mut self) -> Vec<BlockHash> {
        std::mem::take(&mut self.disconnected)
    }

    /// Steps the snapshot's background validation: replays up to
    /// `max_blocks` stored bodies into the independent UTXO set, then —
    /// once the base is reached — compares its recomputed content hash
    /// to the chainparams `hash_serialized`. A match flips
    /// [`Self::snapshot_verified`]; a mismatch is fatal-by-design (Core
    /// aborts the node) and surfaces as `ConnectError::Internal`.
    ///
    /// Drives like Core's background validation thread: callers invoke
    /// it on a cadence (the sync tick does) and it stalls, reporting
    /// [`BackgroundStatus::WaitingForBody`], while a pre-base body has
    /// not been stored yet.
    ///
    /// # Errors
    ///
    /// `ConnectError` when a stored body fails replay — impossible under
    /// honest construction (these headers were validated and the bodies
    /// once connected) — or when the recomputed hash disagrees with the
    /// chainparams snapshot hash.
    pub fn background_step(&mut self, max_blocks: u32) -> Result<BackgroundStatus, ConnectError> {
        let Some(base) = self.snapshot_base else {
            return Ok(BackgroundStatus::NoSnapshot);
        };
        if self.snapshot_verified {
            return Ok(BackgroundStatus::Verified);
        }
        let Some(mut bg) = self.background.take() else {
            return Ok(BackgroundStatus::Verified);
        };
        let params = *self.tree.params();
        let mut waiting: Option<u32> = None;
        for _ in 0..max_blocks {
            if bg.next > base {
                break;
            }
            let h = bg.next;
            let Some(block) = self.body(&self.chain[h as usize]) else {
                waiting = Some(h);
                break;
            };
            let hash = block.block_hash();
            let ctx = ConnectContext {
                params: &params,
                tree: &self.tree,
                block_hash: hash,
                script_checks: self.script_checks(&hash, &params),
                script_pool: None,
            };
            match connect::connect_block(&block, &mut bg.utxo, &ctx) {
                Ok(_undo) => bg.next += 1,
                Err(e) => {
                    self.background = Some(bg);
                    return Err(e);
                }
            }
        }
        if bg.next <= base {
            let done = bg.next - 1;
            self.background = Some(bg);
            return Ok(match waiting {
                Some(height) => BackgroundStatus::WaitingForBody { height },
                None => BackgroundStatus::InProgress { done, base },
            });
        }
        // Replay reached the base — recompute the content hash exactly
        // as `activate_snapshot` verified the file's.
        let base_hash = self.chain[base as usize];
        let au = params
            .assumeutxo_data
            .iter()
            .find(|d| d.height == base)
            .ok_or(ConnectError::Internal(
                "snapshot base not in assumeutxo table",
            ))?;
        let stats = crate::coinstats::compute(
            &bg.utxo,
            i64::from(base),
            base_hash,
            crate::coinstats::CoinStatsHashType::HashSerialized,
        );
        let got = stats
            .hash_serialized
            .map(|h| crate::hash::format_display_hex(h.as_bytes()))
            .unwrap_or_default();
        if got != au.hash_serialized {
            return Err(ConnectError::Internal("snapshot content hash mismatch"));
        }
        self.snapshot_verified = true;
        Ok(BackgroundStatus::Verified)
    }

    /// `true` when no snapshot is active or the snapshot's assumed
    /// prefix has been proven by background validation — the
    /// `validated` flag Core's `getchainstates` reports.
    #[must_use]
    pub fn snapshot_verified(&self) -> bool {
        self.snapshot_base.is_none() || self.snapshot_verified
    }

    /// The background replay's tip height — the second entry's
    /// `blocks` in `getchainstates`. `None` when no snapshot is active
    /// or verification already freed the replay set.
    #[must_use]
    pub fn background_height(&self) -> Option<u32> {
        self.background.as_ref().map(|bg| bg.next - 1)
    }

    /// `ActivateBestChain` — while a stored-body, non-failed branch outworks
    /// the connected tip (or ties it as the `preciousblock`), reorg to the
    /// heaviest such candidate and rescan. A candidate that fails to connect
    /// is marked inside `maybe_reorg` and drops out of the next scan; one that
    /// merely cannot activate (header-only ancestors, the snapshot floor) is
    /// tried once per call and skipped.
    fn activate_best(&mut self) -> Result<(), ConnectError> {
        let params = *self.tree.params();
        let mut tried: HashSet<BlockHash> = HashSet::new();
        loop {
            let conn_work = self
                .tree
                .get(&self.connected)
                .map_or(Work::ZERO, |n| n.chainwork);
            let mut best: Option<(Work, BlockHash)> = None;
            for (h, node) in self.tree.nodes() {
                if *h == self.connected
                    || tried.contains(h)
                    || self.tree.is_failed(h)
                    || !self.have_body(h)
                {
                    continue;
                }
                let eligible = node.chainwork > conn_work
                    || (node.chainwork == conn_work && self.precious == Some(*h));
                if eligible && best.as_ref().is_none_or(|(w, _)| node.chainwork > *w) {
                    best = Some((node.chainwork, *h));
                }
            }
            let Some((_, candidate)) = best else {
                break;
            };
            match self.maybe_reorg(candidate, &params) {
                // The tip moved — rescan for deeper candidates.
                Ok(Some(_)) => tried.clear(),
                Ok(None) | Err(_) => {
                    tried.insert(candidate);
                }
            }
        }
        Ok(())
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
    fn verify_tip_revalidates_at_each_level() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        let mut parent = genesis_header();
        for height in 1..=5u32 {
            let block = block_on(&parent, vec![coinbase_tx(height, subsidy(height))], &params);
            parent = block.header;
            assert!(cs.accept_block(&block, NOW).is_ok());
        }
        // Honest chain: every level and depth verifies. 0 means "all"
        // and a depth past the tip clamps to it — Core's VerifyDB.
        for level in 0..=4 {
            assert!(cs.verify_tip(level, 5), "level {level}");
            assert!(cs.verify_tip(level, 3), "level {level} partial");
        }
        assert!(cs.verify_tip(4, 0));
        assert!(cs.verify_tip(4, 100));
        assert!(cs.verify_tip(-1, 5)); // level < 0 checks nothing
        assert!(cs.verify_tip(4, -7)); // depth < 0: whole chain
        assert!(Chainstate::new(&params).verify_tip(4, 10));
    }

    #[test]
    fn verify_tip_fails_when_bodies_are_gone() {
        let params = params();
        let dir = store_dir("verify-pruned");
        let blocks = probe_chain(6, &[], &params);
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        for block in &blocks {
            cs.accept_block(block, NOW).unwrap();
        }
        assert!(cs.verify_tip(4, 0)); // whole chain verifies
        // Drop the blk file under the live store — the index still
        // names positions but reads fail, so `body` reports None and
        // verification fails at every level like Core's
        // `ReadBlockFromDisk` failure does.
        std::fs::remove_file(dir.join("blk00000.dat")).unwrap();
        assert!(!cs.verify_tip(4, 0));
        assert!(!cs.verify_tip(0, 6));
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
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

    /// `getchaintxstats` — cumulative counts come from connect-time
    /// nChainTx bookkeeping; a parked side tip reports the count as
    /// unknown, and the window bound is `height - 1` like Core.
    #[test]
    fn chain_tx_stats_contract() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        // h1..h4 on the active chain, one coinbase each; block times
        // step +1s so windows have nonzero intervals.
        let mut parent = genesis_header();
        for h in 1..=4u32 {
            let b = block_on(&parent, vec![coinbase_tx(h, subsidy(h))], &params);
            cs.accept_block(&b, NOW).unwrap();
            parent = b.header;
        }
        let h3 = cs.chain()[3];
        let tip = cs.chain()[4];

        // Tip, default window → clamped to height-1 = 3 blocks back.
        // The interval is median-time-past based, matching Core:
        // MTP(h4) = t0+2, MTP(h1) = t0+1 → 1s for a 3-tx window.
        let s = cs.chain_tx_stats(None, None).unwrap();
        assert_eq!(s.final_height, 4);
        assert_eq!(s.tx_count, Some(5)); // genesis + h1..h4
        assert_eq!(s.window_block_count, 3);
        assert_eq!(s.window_tx_count, Some(3));
        assert_eq!(s.window_interval, Some(1));
        assert_eq!(s.tx_rate, Some(3.0));

        // Explicit window ending at h3, size 2: MTP(h3) = t0+2,
        // MTP(h1) = t0+1 → interval 1, rate 2.
        let s = cs.chain_tx_stats(Some(&h3), Some(2)).unwrap();
        assert_eq!(s.final_height, 3);
        assert_eq!(s.tx_count, Some(4));
        assert_eq!(s.window_block_count, 2);
        assert_eq!(s.window_tx_count, Some(2));
        assert_eq!(s.tx_rate, Some(2.0));

        // count=0: no interval/count/rate fields at all.
        let s = cs.chain_tx_stats(Some(&tip), Some(0)).unwrap();
        assert_eq!(s.window_block_count, 0);
        assert_eq!(s.window_interval, None);
        assert_eq!(s.window_tx_count, None);
        assert_eq!(s.tx_rate, None);

        // Bounds: `max(0, height - 1)` max, no negatives. At genesis
        // the bound is 0 — a zero window still answers (Core's h0
        // behavior) with count fields omitted.
        assert_eq!(
            cs.chain_tx_stats(Some(&tip), Some(4)),
            Err(TxStatsError::BadWindow)
        );
        assert_eq!(
            cs.chain_tx_stats(Some(&tip), Some(-1)),
            Err(TxStatsError::BadWindow)
        );
        let s = cs.chain_tx_stats(Some(&cs.chain()[0]), Some(0)).unwrap();
        assert_eq!(s.window_block_count, 0);
        assert_eq!(s.tx_count, Some(1));
        assert_eq!(s.window_interval, None);
        assert_eq!(
            cs.chain_tx_stats(Some(&cs.chain()[0]), Some(1)),
            Err(TxStatsError::BadWindow)
        );
        assert_eq!(
            cs.chain_tx_stats(Some(&BlockHash::from_bytes([7; 32])), None),
            Err(TxStatsError::UnknownBlock)
        );

        // A parked equal-work sibling at h4 — never connected, so its
        // cumulative count stays unknown and the count fields vanish.
        let h3_header = cs.tree().get(&h3).unwrap().header;
        let side = block_on(
            &h3_header,
            vec![tagged_coinbase(4, subsidy(4), script::OP_EQUAL)],
            &params,
        );
        cs.accept_block(&side, NOW).unwrap();
        let s = cs
            .chain_tx_stats(Some(&side.block_hash()), Some(1))
            .unwrap();
        assert_eq!(s.tx_count, None);
        assert_eq!(s.window_tx_count, None);
        assert_eq!(s.tx_rate, None);
        // MTP(side) and MTP(h3) are both t0+2 → a zero interval.
        assert_eq!(s.window_interval, Some(0));
    }

    /// `preciousblock` flips an equal-work parked tip onto the active
    /// chain and a later call overrides it — Core's nSequenceId
    /// tie-break. An unknown hash reports not-found; a shorter-work
    /// branch stays parked.
    #[test]
    fn precious_block_wins_equal_work_ties() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        let a = block_on(&genesis_header(), vec![coinbase_tx(1, subsidy(1))], &params);
        cs.accept_block(&a, NOW).unwrap();
        let b = block_on(
            &genesis_header(),
            vec![tagged_coinbase(1, subsidy(1), script::OP_RETURN)],
            &params,
        );
        let c = block_on(
            &genesis_header(),
            vec![tagged_coinbase(1, subsidy(1), script::OP_EQUAL)],
            &params,
        );
        cs.accept_block(&b, NOW).unwrap();
        cs.accept_block(&c, NOW).unwrap();
        assert_eq!(cs.tip_hash(), a.block_hash());

        // Unknown hash → not found; the tip is unchanged.
        assert_eq!(
            cs.precious_block(&BlockHash::from_bytes([0xee; 32])),
            Ok(false)
        );
        assert_eq!(cs.tip_hash(), a.block_hash());

        // Precious b activates its equal-work branch immediately.
        assert_eq!(cs.precious_block(&b.block_hash()), Ok(true));
        assert_eq!(cs.tip_hash(), b.block_hash());
        assert_eq!(cs.chain()[1], b.block_hash());

        // A later call overrides: precious c re-flips the tie.
        assert_eq!(cs.precious_block(&c.block_hash()), Ok(true));
        assert_eq!(cs.tip_hash(), c.block_hash());

        // Precious on the active tip is a harmless no-op.
        assert_eq!(cs.precious_block(&c.block_hash()), Ok(true));
        assert_eq!(cs.tip_hash(), c.block_hash());
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

    /// A chain of `tip` blocks; from height 102 each block also spends
    /// the coinbase from 101 blocks back (always-mature `OP_1`
    /// outputs — trivially valid scripts, real spend traffic).
    fn spend_chain(tip_height: u32, params: &Params) -> Vec<Block> {
        let mut blocks: Vec<Block> = Vec::new();
        let mut parent = params.genesis_header;
        for height in 1..=tip_height {
            let mut txs = vec![coinbase_tx(height, subsidy(height))];
            if height > 101 {
                txs.push(Transaction {
                    version: 1,
                    inputs: vec![TxIn {
                        previous_output: OutPoint {
                            txid: blocks[(height - 102) as usize].transactions[0].txid(),
                            vout: 0,
                        },
                        script_sig: Script::new(vec![]),
                        sequence: SEQUENCE_FINAL,
                        witness: Witness::default(),
                    }],
                    outputs: vec![TxOut {
                        value: subsidy(height - 101) - 1000,
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
    fn speculative_connect_matches_sequential() {
        let params = params();
        let blocks = spend_chain(140, &params);

        let mut plain = Chainstate::new(&params);
        for block in &blocks {
            assert!(plain.accept_block(block, NOW).is_ok());
        }

        let mut spec = Chainstate::new(&params);
        spec.enable_speculative_connect();
        for block in &blocks {
            assert!(spec.accept_block(block, NOW).is_ok());
        }
        spec.drain_scripts().unwrap();

        assert_eq!(plain.chain(), spec.chain());
        assert_eq!(plain.utxo().len(), spec.utxo().len());
        for block in blocks.iter().step_by(17) {
            let txid = block.transactions[0].txid();
            assert_eq!(
                plain.utxo().have(&OutPoint { txid, vout: 0 }),
                spec.utxo().have(&OutPoint { txid, vout: 0 })
            );
        }
    }

    #[test]
    fn speculative_failure_rewinds_pending_blocks() {
        // Block 110 spends an always-false OP_0 output — the script
        // check fails. With the pool, blocks 111.. enter the pending
        // window before 110's drain surfaces the error; the drain must
        // roll them all back and leave the tip at 109.
        let params = params();
        let blocks = probe_chain(130, &[(110, 1)], &params);
        let mut cs = Chainstate::new(&params);
        cs.enable_speculative_connect();
        let mut failed_at = None;
        for (i, block) in blocks.iter().enumerate() {
            match cs.accept_block(block, NOW) {
                Ok(_) => {}
                Err(BlockRejection::Connect(ConnectError::ScriptVerify(_))) => {
                    failed_at = Some(i);
                    break;
                }
                Err(e) => panic!("unexpected rejection {e:?}"),
            }
        }
        // The failure may surface a few blocks late (pending window);
        // the assert is about the resulting state, not the exact index.
        assert!(failed_at.is_some());
        cs.drain_scripts().ok();
        // Tip is back at the last good block and the bad one is marked.
        assert_eq!(cs.chain().len() as u32, 110); // genesis + 109
        assert!(cs.tree().is_failed(&blocks[109].block_hash()));
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

    /// The txindex answers `find_transaction` for every retained body —
    /// in-memory or store-backed — and the append log resumes the map
    /// across a reopen without re-scanning.
    #[test]
    fn txindex_finds_and_persists() {
        let params = params();
        let dir = store_dir("txindex");
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b, side) = {
            let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
            cs.enable_txindex(Some(&dir)).unwrap();
            let a = block_on(&genesis_header(), vec![coinbase_tx(1, subsidy(1))], &params);
            let b = block_on(&a.header, vec![coinbase_tx(2, subsidy(2))], &params);
            let side = block_on(
                &genesis_header(),
                vec![tagged_coinbase(1, subsidy(1), script::OP_RETURN)],
                &params,
            );
            cs.accept_block(&a, NOW).unwrap();
            cs.accept_block(&b, NOW).unwrap();
            cs.accept_block(&side, NOW).unwrap(); // parked side branch
            let atx = a.transactions[0].txid();
            let btx = b.transactions[0].txid();
            let stx = side.transactions[0].txid();
            assert_eq!(cs.find_transaction(&atx), Some(a.block_hash()));
            assert_eq!(cs.find_transaction(&btx), Some(b.block_hash()));
            // Side-branch bodies index too — Core keeps them findable.
            assert_eq!(cs.find_transaction(&stx), Some(side.block_hash()));
            assert!(cs.on_active_chain(&a.block_hash()));
            assert!(!cs.on_active_chain(&side.block_hash()));
            assert_eq!(cs.find_transaction(&Txid::ZERO), None);
            (a, b, side)
        };
        // Reopen: the log must carry the whole index — the backfill
        // scans nothing because every block was already recorded.
        let cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        let mut cs = cs;
        cs.enable_txindex(Some(&dir)).unwrap();
        assert_eq!(
            cs.find_transaction(&b.transactions[0].txid()),
            Some(b.block_hash())
        );
        assert_eq!(
            cs.find_transaction(&side.transactions[0].txid()),
            Some(side.block_hash())
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = a;
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
        let mut v: Vec<_> = cs.utxo().iter();
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

    /// The filter index follows the active chain: reorged-out heights
    /// keep serving their filter by block hash (Core retains stale
    /// filters), the new branch chains its headers off the fork, and
    /// the regtest genesis filter matches Core's `014756c0` / header
    /// `485e301e…`.
    #[test]
    fn filterindex_indexes_connects_and_survives_reorgs() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        cs.enable_blockfilterindex(None).unwrap();
        assert!(cs.blockfilterindex_enabled());

        // Genesis: outputs-only filter (Core appends it with an empty undo).
        let genesis = cs.chain()[0];
        let (gf, gh) = cs.block_filter(0, &genesis).unwrap();
        assert_eq!(crate::hex::encode(&gf), "014756c0");
        assert_eq!(
            crate::hash::format_display_hex(&gh),
            "485e301e4509d7f0d954bf5b529f3ecef68c5191fd0e635f775c1d0266dc5a2b"
        );

        let a1 = block_on(&genesis_header(), vec![coinbase_tx(1, subsidy(1))], &params);
        let a2 = block_on(&a1.header, vec![coinbase_tx(2, subsidy(2))], &params);
        cs.accept_block(&a1, NOW).unwrap();
        cs.accept_block(&a2, NOW).unwrap();
        let (a1f, a1h) = cs.block_filter(1, &a1.block_hash()).unwrap();
        assert_eq!(
            a1h,
            crate::gcs::compute_header(&crate::gcs::filter_hash(&a1f), &gh)
        );

        // Heavier side branch on genesis disconnects a1+a2.
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
        cs.accept_block(&b1, NOW).unwrap();
        cs.accept_block(&b2, NOW).unwrap();
        assert_eq!(
            cs.accept_block(&b3, NOW),
            Ok(Acceptance::Connected {
                height: 3,
                reorged: true
            })
        );

        // New branch owns heights 1..=3 and its headers chain off the
        // genesis header; the evicted filters still answer by hash.
        let (b1f, b1h) = cs.block_filter(1, &b1.block_hash()).unwrap();
        assert_eq!(
            b1h,
            crate::gcs::compute_header(&crate::gcs::filter_hash(&b1f), &gh)
        );
        assert_eq!(
            cs.block_filter(1, &a1.block_hash()).unwrap().0,
            a1f,
            "reorged-out a1 filter still resolvable by hash"
        );
        // Height keys point at the new branch — a stale hash at the
        // wrong height isn't confused for the active entry.
        assert_eq!(cs.block_filter(1, &b1.block_hash()).unwrap().0, b1f);
        assert_eq!(cs.chain()[1], b1.block_hash());
    }

    /// `cfilters.dat` reloads across restarts and tolerates a torn tail:
    /// records end mid-append after a crash and the log replays to the
    /// last complete record.
    #[test]
    fn filterindex_persists_and_recovers_partial_tail() {
        let params = params();
        let dir = store_dir("filterindex-restart");
        let blocks = probe_chain(3, &[], &params);

        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        cs.enable_blockfilterindex(Some(&dir)).unwrap();
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        let expected_h1 = cs.block_filter(1, &blocks[0].block_hash()).unwrap().0;
        drop(cs);
        let logged = std::fs::read(dir.join("cfilters.dat")).unwrap();

        // A fresh enable over the same dir answers h1 from the log —
        // an in-memory chainstate has no bodies to backfill from.
        let mut cs2 = Chainstate::new(&params);
        cs2.enable_blockfilterindex(Some(&dir)).unwrap();
        assert_eq!(
            cs2.block_filter(1, &blocks[0].block_hash()).unwrap().0,
            expected_h1
        );
        drop(cs2);

        // Torn tail: truncate the last record mid-write and the reload
        // still yields a consistent index through the previous record.
        let mut torn = logged.clone();
        torn.truncate(torn.len() - 5);
        std::fs::write(dir.join("cfilters.dat"), &torn).unwrap();
        let cs = Chainstate::new(&params);
        let mut cs = cs;
        cs.enable_blockfilterindex(Some(&dir)).unwrap();
        // Heights 0..=2 read back; the torn h3 record is dropped.
        assert!(cs.block_filter(0, &cs.chain()[0]).is_some());
        assert!(cs.block_filter(1, &blocks[0].block_hash()).is_some());
        assert!(cs.block_filter(2, &blocks[1].block_hash()).is_some());
        assert!(cs.block_filter(3, &blocks[2].block_hash()).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The scripthash index records every touched scriptPubKey —
    /// outputs from the block, spent scripts from the undo — and a
    /// reorg rewinds the disconnected heights' entries.
    #[test]
    fn scripthashindex_records_spends_and_survives_reorgs() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        cs.enable_scripthashindex(None).unwrap();
        assert!(cs.scripthash_index_enabled());

        // Blocks 1..=100 (coinbase maturity), then h101 spends h1's
        // coinbase to a fresh script.
        let a1 = block_on(&genesis_header(), vec![coinbase_tx(1, subsidy(1))], &params);
        let a1_spk = a1.transactions[0].outputs[0].script_pubkey.as_bytes();
        let a1_sh = crate::hash::sha256(a1_spk);
        cs.accept_block(&a1, NOW).unwrap();
        assert_eq!(cs.scripthash_history(&a1_sh).unwrap().len(), 1);

        let mut parent = a1.header;
        for h in 2..=100u32 {
            let b = block_on(&parent, vec![coinbase_tx(h, subsidy(h))], &params);
            cs.accept_block(&b, NOW).unwrap();
            parent = b.header;
        }
        let spend = Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: a1.transactions[0].txid(),
                    vout: 0,
                },
                script_sig: Script::new(vec![script::OP_1]),
                sequence: SEQUENCE_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: subsidy(1) - 1000,
                script_pubkey: Script::new(vec![script::OP_0, script::OP_1]),
            }],
            lock_time: 0,
        };
        let spend_spk = spend.outputs[0].script_pubkey.as_bytes();
        let spend_sh = crate::hash::sha256(spend_spk);
        let a101 = block_on(
            &parent,
            vec![coinbase_tx(101, subsidy(101)), spend],
            &params,
        );
        cs.accept_block(&a101, NOW).unwrap();
        // The spend touched BOTH scripts: the spent prevout's (from
        // undo) and the new output's. (`coinbase_tx` pays one fixed
        // script, so a1's script also carries every coinbase.)
        let h1_hist = cs.scripthash_history(&a1_sh).unwrap();
        let spend_tx = a101.transactions[1].txid();
        assert!(h1_hist.iter().any(|(h, _p, t)| *h == 101 && *t == spend_tx));
        assert_eq!(cs.scripthash_history(&spend_sh).unwrap().len(), 1);

        // A heavier branch on h100 orphans h101 — both entries unwind.
        let mut fork_parent = parent;
        for h in 101..=102u32 {
            let b = block_on(
                &fork_parent,
                vec![tagged_coinbase(h, subsidy(h), script::OP_EQUAL)],
                &params,
            );
            cs.accept_block(&b, NOW).unwrap();
            fork_parent = b.header;
        }
        assert!(
            !cs.scripthash_history(&a1_sh)
                .unwrap()
                .iter()
                .any(|(h, _p, t)| *h == 101 && *t == spend_tx)
        );
        assert!(cs.scripthash_history(&spend_sh).is_none());
    }

    /// `scindex.dat` replays connects and disconnects across restarts
    /// and cuts a torn tail like the other index logs.
    #[test]
    fn scripthashindex_persists_and_recovers() {
        let params = params();
        let dir = store_dir("scindex-restart");
        let blocks = probe_chain(4, &[], &params);
        let spk = blocks[0].transactions[0].outputs[0]
            .script_pubkey
            .as_bytes();
        let sh = crate::hash::sha256(spk);

        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        cs.enable_scripthashindex(Some(&dir)).unwrap();
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        drop(cs);

        // Reload: h1's coinbase script replays its history entry.
        let mut cs2 = Chainstate::with_store(&dir, &params, NOW).unwrap();
        cs2.enable_scripthashindex(Some(&dir)).unwrap();
        let hist = cs2.scripthash_history(&sh).unwrap();
        assert_eq!(hist.len(), 4);
        assert_eq!(hist[0].0, 1);
        assert_eq!(hist[3].0, 4);
        drop(cs2);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// `loadtxoutset` end to end on regtest: a snapshot written by
    /// `write_snapshot` loads into a headers-only chainstate, becomes
    /// the tip, accepts the next block, and refuses a reorg below the
    /// base. The assumeutxo table is injected like Core's test-only
    /// params do (its built-in regtest entries describe Core's own
    /// deterministic chain, not this one).
    #[test]
    fn assumeutxo_load_round_trip() {
        use crate::params::AssumeutxoData;
        use crate::utxo_snapshot::{read_metadata, sorted_coins, write_snapshot};

        let mut p = params();
        // The source node validates h1..h3 honestly.
        let mut src = Chainstate::new(&p);
        let mut blocks = Vec::new();
        let mut parent = genesis_header();
        for h in 1..=3u32 {
            let b = block_on(&parent, vec![coinbase_tx(h, subsidy(h))], &p);
            src.accept_block(&b, NOW).unwrap();
            parent = b.header;
            blocks.push(b);
        }
        // Snapshot at h2 — roll back on a clone like dumptxoutset does.
        let base_hash = blocks[1].block_hash();
        let mut utxo = src.utxo().clone();
        let undo3 = src.undo(3).unwrap();
        connect::disconnect_block(&blocks[2], &mut utxo, &undo3).unwrap();
        let stats = crate::coinstats::compute(
            &utxo,
            2,
            base_hash,
            crate::coinstats::CoinStatsHashType::HashSerialized,
        );
        let coins = sorted_coins(&utxo);
        let mut snap = Vec::new();
        write_snapshot(
            &mut snap,
            p.message_start,
            &base_hash,
            coins.len() as u64,
            &coins,
        )
        .unwrap();

        // The loading node gets a params copy whose assumeutxo table
        // describes this chain's h2.
        p.assumeutxo_data = Box::leak(Box::new([AssumeutxoData {
            height: 2,
            hash_serialized: Box::leak(stats.hash_serialized.unwrap().to_string().into_boxed_str()),
            n_chain_tx: 3,
            blockhash: Box::leak(base_hash.to_string().into_boxed_str()),
        }]));
        let dir = store_dir("assumeutxo");
        let mut cs = Chainstate::with_store(&dir, &p, NOW).unwrap();
        // Headers through h3 arrive (the base must be in the headers
        // chain and under the best header) — no bodies connected.
        for b in &blocks {
            cs.tree.insert(&b.header, NOW).unwrap();
        }

        let mut cursor = std::io::Cursor::new(&snap);
        let meta = read_metadata(&mut cursor, p.message_start).unwrap();
        assert_eq!(meta.base_blockhash, base_hash);
        assert_eq!(meta.coins_count, coins.len() as u64);
        let base_height = cs.activate_snapshot(&mut cursor, &meta, false).unwrap();
        assert_eq!(base_height, 2);
        assert_eq!(cs.tip_hash(), base_hash);
        assert_eq!(cs.snapshot_base(), Some(2));
        assert_eq!(cs.chain().len(), 3);
        // The loaded view equals the source's h2 view, coin for coin.
        assert_eq!(cs.utxo().len(), utxo.len());
        for (op, coin) in &coins {
            let got = cs.utxo().iter().into_iter().find(|(o, _)| *o == *op);
            assert_eq!(got, Some((*op, coin.clone())));
        }

        // A second load is refused exactly like Core's double activate.
        let mut cursor = std::io::Cursor::new(&snap);
        let meta = read_metadata(&mut cursor, p.message_start).unwrap();
        let err = cs.activate_snapshot(&mut cursor, &meta, false).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Can't activate a snapshot-based chainstate more than once"
        );

        // h3's body now connects on top of the assumed state.
        match cs.accept_block(&blocks[2], NOW) {
            Ok(Acceptance::Connected { height, .. }) => assert_eq!(height, 3),
            other => panic!("expected connect, got {other:?}"),
        }
        assert_eq!(cs.tip_hash(), blocks[2].block_hash());

        // A heavier branch forking below the base can never activate:
        // h2' h3' h4' on h1 outwork h3 but fork at 1 < base 2.
        let h1 = &blocks[0];
        let mut fork_parent = h1.header;
        let mut last = h1.block_hash();
        for h in 2..=4u32 {
            let b = block_on(&fork_parent, vec![tagged_coinbase(h, subsidy(h), 0xaa)], &p);
            last = b.block_hash();
            fork_parent = b.header;
            let accepted = cs.accept_block(&b, NOW).unwrap();
            assert!(matches!(accepted, Acceptance::Parked { .. }));
        }
        assert_eq!(cs.tip_hash(), blocks[2].block_hash());
        assert_ne!(cs.tip_hash(), last);

        // Restart: activation flushed state.dat at the base and h3's
        // body is on disk, so the resumed chainstate is tip h3 with
        // the snapshot floor intact — no sub-base bodies required.
        drop(cs);
        let cs = Chainstate::with_store(&dir, &p, NOW).unwrap();
        assert_eq!(cs.tip_hash(), blocks[2].block_hash());
        assert_eq!(cs.snapshot_base(), Some(2));
        assert_eq!(sorted_utxo(&cs).len(), utxo.len() + 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Background validation: a snapshot starts unverified, the replay
    /// stalls on missing bodies, then proves the assumed set once every
    /// pre-base body has been retained and replayed.
    #[test]
    fn assumeutxo_background_validation_verifies() {
        use crate::params::AssumeutxoData;
        use crate::utxo_snapshot::{read_metadata, sorted_coins, write_snapshot};
        let mut p = params();
        let mut src = Chainstate::new(&p);
        let mut blocks = Vec::new();
        let mut parent = genesis_header();
        for h in 1..=3u32 {
            let b = block_on(&parent, vec![coinbase_tx(h, subsidy(h))], &p);
            src.accept_block(&b, NOW).unwrap();
            parent = b.header;
            blocks.push(b);
        }
        let base_hash = blocks[1].block_hash();
        let mut utxo = src.utxo().clone();
        let undo3 = src.undo(3).unwrap();
        connect::disconnect_block(&blocks[2], &mut utxo, &undo3).unwrap();
        let stats = crate::coinstats::compute(
            &utxo,
            2,
            base_hash,
            crate::coinstats::CoinStatsHashType::HashSerialized,
        );
        let coins = sorted_coins(&utxo);
        let mut snap = Vec::new();
        write_snapshot(
            &mut snap,
            p.message_start,
            &base_hash,
            coins.len() as u64,
            &coins,
        )
        .unwrap();
        p.assumeutxo_data = Box::leak(Box::new([AssumeutxoData {
            height: 2,
            hash_serialized: Box::leak(stats.hash_serialized.unwrap().to_string().into_boxed_str()),
            n_chain_tx: 3,
            blockhash: Box::leak(base_hash.to_string().into_boxed_str()),
        }]));
        let dir = store_dir("assumeutxo-bg");
        let mut cs = Chainstate::with_store(&dir, &p, NOW).unwrap();
        for b in &blocks {
            cs.tree.insert(&b.header, NOW).unwrap();
        }
        let mut cursor = std::io::Cursor::new(&snap);
        let meta = read_metadata(&mut cursor, p.message_start).unwrap();
        cs.activate_snapshot(&mut cursor, &meta, false).unwrap();

        // Freshly activated: unverified, replay stalled at height 1 —
        // the loading node never had pre-base bodies.
        assert!(!cs.snapshot_verified());
        assert_eq!(cs.background_height(), Some(0));
        assert_eq!(
            cs.background_step(10),
            Ok(BackgroundStatus::WaitingForBody { height: 1 })
        );

        // Bodies for h1/h2 arrive (sub-base bodies store but never
        // connect); the replay then reaches the base and the hash
        // matches — the assumed prefix is now proven.
        for b in [&blocks[0], &blocks[1]] {
            cs.accept_block(b, NOW).unwrap();
        }
        assert_eq!(cs.background_step(10), Ok(BackgroundStatus::Verified));
        assert!(cs.snapshot_verified());
        assert_eq!(cs.background_height(), None);
        assert_eq!(cs.tip_hash(), base_hash);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A dishonest snapshot — valid serialization, wrong content hash —
    /// fails the replay's final check once the real bodies arrive.
    #[test]
    fn assumeutxo_background_validation_rejects_lie() {
        use crate::params::AssumeutxoData;
        use crate::utxo_snapshot::{read_metadata, sorted_coins, write_snapshot};
        let mut p = params();
        let mut src = Chainstate::new(&p);
        let mut blocks = Vec::new();
        let mut parent = genesis_header();
        for h in 1..=3u32 {
            let b = block_on(&parent, vec![coinbase_tx(h, subsidy(h))], &p);
            src.accept_block(&b, NOW).unwrap();
            parent = b.header;
            blocks.push(b);
        }
        let base_hash = blocks[1].block_hash();
        // The snapshot claims the h1-only UTXO set at base h2 — a
        // coin is missing. The chainparams entry is computed over
        // that same lie, so the file-hash gate passes; only honest
        // replay of the real bodies can catch it.
        let mut utxo = src.utxo().clone();
        let undo3 = src.undo(3).unwrap();
        connect::disconnect_block(&blocks[2], &mut utxo, &undo3).unwrap();
        let undo2 = src.undo(2).unwrap();
        connect::disconnect_block(&blocks[1], &mut utxo, &undo2).unwrap();
        let stats = crate::coinstats::compute(
            &utxo,
            2,
            base_hash,
            crate::coinstats::CoinStatsHashType::HashSerialized,
        );
        let coins = sorted_coins(&utxo);
        let mut snap = Vec::new();
        write_snapshot(
            &mut snap,
            p.message_start,
            &base_hash,
            coins.len() as u64,
            &coins,
        )
        .unwrap();
        p.assumeutxo_data = Box::leak(Box::new([AssumeutxoData {
            height: 2,
            hash_serialized: Box::leak(stats.hash_serialized.unwrap().to_string().into_boxed_str()),
            n_chain_tx: 3,
            blockhash: Box::leak(base_hash.to_string().into_boxed_str()),
        }]));
        let dir = store_dir("assumeutxo-bg-lie");
        let mut cs = Chainstate::with_store(&dir, &p, NOW).unwrap();
        for b in &blocks {
            cs.tree.insert(&b.header, NOW).unwrap();
        }
        let mut cursor = std::io::Cursor::new(&snap);
        let meta = read_metadata(&mut cursor, p.message_start).unwrap();
        cs.activate_snapshot(&mut cursor, &meta, false).unwrap();
        for b in [&blocks[0], &blocks[1]] {
            cs.accept_block(b, NOW).unwrap();
        }
        // Honest replay produces the true h2 set — which the (lying)
        // chainparams hash no longer matches. Hard error, no verified.
        assert!(cs.background_step(10).is_err());
        assert!(!cs.snapshot_verified());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The metadata + activation gate error strings, verbatim.
    #[test]
    fn assumeutxo_gate_errors() {
        use crate::utxo_snapshot::{read_metadata, write_snapshot};
        let p = params();
        let genesis = genesis_header().hash();
        let mut snap = Vec::new();
        write_snapshot(&mut snap, p.message_start, &genesis, 0, &[]).unwrap();

        // Wrong network magic → -22 surface text.
        let mut bad_magic = snap.clone();
        bad_magic[7] ^= 0xff; // network magic byte
        let mut c = std::io::Cursor::new(&bad_magic);
        let err = read_metadata(&mut c, p.message_start).unwrap_err();
        assert_eq!(
            err.to_string(),
            "This snapshot has been created for an unrecognized network. This could be a custom signet, a new testnet or possibly caused by data corruption.: iostream error"
        );

        // Known-but-different network names it.
        let mut signet_magic = snap.clone();
        signet_magic[7..11].copy_from_slice(&Network::Signet.params().message_start);
        let mut c = std::io::Cursor::new(&signet_magic);
        let err = read_metadata(&mut c, p.message_start).unwrap_err();
        assert_eq!(
            err.to_string(),
            "The network of the snapshot (signet) does not match the network of this node (regtest).: iostream error"
        );

        // Bad magic prefix.
        let mut wrong = snap.clone();
        wrong[0] = b'x';
        let mut c = std::io::Cursor::new(&wrong);
        assert_eq!(
            read_metadata(&mut c, p.message_start)
                .unwrap_err()
                .to_string(),
            "Invalid UTXO set snapshot magic bytes. Please check if this is indeed a snapshot file or if you are using an outdated snapshot format.: iostream error"
        );

        // Unsupported version.
        let mut v = snap.clone();
        v[5] = 1;
        v[6] = 0;
        let mut c = std::io::Cursor::new(&v);
        assert_eq!(
            read_metadata(&mut c, p.message_start)
                .unwrap_err()
                .to_string(),
            "Version of snapshot 1 does not match any of the supported versions.: iostream error"
        );

        // A hash the table doesn't know → "not recognized" + heights.
        let mut cs = Chainstate::new(&p);
        let mut cursor = std::io::Cursor::new(&snap);
        let meta = read_metadata(&mut cursor, p.message_start).unwrap();
        let err = cs.activate_snapshot(&mut cursor, &meta, false).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "assumeutxo block hash in snapshot metadata not recognized (hash: {genesis}). The following snapshot heights are available: 110, 200, 299"
            )
        );

        // A non-empty mempool is refused before any loading.
        let mut p2 = params();
        p2.assumeutxo_data = Box::leak(Box::new([crate::params::AssumeutxoData {
            height: 0,
            hash_serialized: "",
            n_chain_tx: 0,
            blockhash: Box::leak(genesis.to_string().into_boxed_str()),
        }]));
        let mut cs2 = Chainstate::new(&p2);
        let mut cursor = std::io::Cursor::new(&snap);
        let meta = read_metadata(&mut cursor, p2.message_start).unwrap();
        // genesis is in the headers chain and under the best header;
        // its chainwork does not exceed the connected tip (also
        // genesis) — so the mempool gate must come first to be
        // observable; run it with a non-empty mempool.
        let err = cs2.activate_snapshot(&mut cursor, &meta, true).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Can't activate a snapshot when mempool not empty"
        );
    }

    // ---- coinsdb backend integration ----

    #[test]
    fn coinsdb_restart_resumes() {
        let params = params();
        let dir = store_dir("coinsdb-resume");
        let blocks = probe_chain(20, &[], &params);
        let mut cs = Chainstate::with_store_coinsdb(&dir, &params, NOW, 1 << 20).unwrap();
        for block in &blocks[..10] {
            cs.accept_block(block, NOW).unwrap();
        }
        cs.flush().unwrap();
        let tip10 = cs.tip_hash();
        let utxo10: Vec<_> = cs.utxo().iter();
        drop(cs);

        let mut cs = Chainstate::with_store_coinsdb(&dir, &params, NOW, 1 << 20).unwrap();
        assert_eq!(cs.tip_hash(), tip10);
        // Coins come back from the backend, not the (empty) snapshot.
        let mut resumed = cs.utxo().iter();
        resumed.sort_by_key(|(o, _)| (o.txid, o.vout));
        let mut expected = utxo10;
        expected.sort_by_key(|(o, _)| (o.txid, o.vout));
        assert_eq!(resumed, expected);
        for block in &blocks[10..] {
            assert!(cs.accept_block(block, NOW).is_ok());
        }
        assert_eq!(cs.tip_hash(), blocks[19].block_hash());
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn coinsdb_crash_ahead_rewinds() {
        let params = params();
        let dir = store_dir("coinsdb-rewind");
        let blocks = probe_chain(15, &[], &params);
        let mut cs = Chainstate::with_store_coinsdb(&dir, &params, NOW, 1 << 20).unwrap();
        for block in &blocks[..8] {
            cs.accept_block(block, NOW).unwrap();
        }
        cs.flush().unwrap();

        // Connect 3 more and commit coins WITHOUT writing state.dat —
        // the backend-ahead crash window.
        for block in &blocks[8..11] {
            cs.accept_block(block, NOW).unwrap();
        }
        cs.flush_coins().unwrap();
        let utxo11: Vec<_> = cs.utxo().iter();
        drop(cs);

        // Restart: state.dat says tip=8, coinsdb says 11 — the backend
        // rewinds to 8, then the post-snapshot bodies (still in the blk
        // files) replay forward, converging both to tip 11.
        let cs = Chainstate::with_store_coinsdb(&dir, &params, NOW, 1 << 20).unwrap();
        assert_eq!(cs.tip_hash(), blocks[10].block_hash());
        let mut resumed = cs.utxo().iter();
        resumed.sort_by_key(|(o, _)| (o.txid, o.vout));
        let mut expected = utxo11;
        expected.sort_by_key(|(o, _)| (o.txid, o.vout));
        assert_eq!(resumed, expected, "replayed coins != pre-crash coins");
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn coinsdb_tiny_budget_flushes_and_reorgs() {
        let params = params();
        let dir = store_dir("coinsdb-budget");
        // ~1 KiB budget — every block's coinbase output (~100B map
        // entry) trips it quickly, forcing mid-sync commits.
        let mut cs = Chainstate::with_store_coinsdb(&dir, &params, NOW, 1 << 10).unwrap();
        let blocks = probe_chain(30, &[], &params);
        for block in &blocks[..20] {
            cs.accept_block(block, NOW).unwrap();
        }
        assert_eq!(cs.tip_hash(), blocks[19].block_hash());
        // Backend holds committed coins even without flush().
        assert!(cs.coins_backend.as_ref().unwrap().tip_height() > 0);
        cs.flush().unwrap();
        let tip20 = cs.tip_hash();
        drop(cs);

        // Reorg across the flushed watermark: a side branch off
        // height 5 (below the backend tip) that outgrows the tip.
        let mut cs = Chainstate::with_store_coinsdb(&dir, &params, NOW, 1 << 10).unwrap();
        assert_eq!(cs.tip_hash(), tip20);
        let mut parent = blocks[4].header;
        let mut branch = Vec::new();
        for i in 0..18u32 {
            let h = 6 + i;
            let b = block_on(
                &parent,
                vec![tagged_coinbase(h, subsidy(h), script::OP_EQUAL)],
                &params,
            );
            parent = b.header;
            branch.push(b);
        }
        for block in &branch {
            assert!(cs.accept_block(block, NOW).is_ok());
        }
        // 23-work branch tip vs 20-work active tip — reorged.
        assert_eq!(cs.tip_hash(), branch.last().unwrap().block_hash());
        // Undo for a below-watermark height describes the new branch.
        let undo7 = cs.undo(7).unwrap();
        assert!(!undo7.txs.is_empty());
        // And the old branch's coin is gone.
        assert!(!cs.utxo().have(&OutPoint {
            txid: blocks[7].transactions[0].txid(),
            vout: 0,
        }));
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn coinsdb_v3_state_migrates() {
        let params = params();
        let dir = store_dir("coinsdb-migrate");
        let blocks = probe_chain(10, &[], &params);
        // Write a v3-format state: inline utxo/undos (memory-mode
        // snapshot), then downgrade the version field.
        let mut cs = Chainstate::with_store(&dir, &params, NOW).unwrap();
        for block in &blocks[..6] {
            cs.accept_block(block, NOW).unwrap();
        }
        cs.flush().unwrap();
        let utxo6: Vec<_> = cs.utxo().iter();
        let tip6 = cs.tip_hash();
        drop(cs);

        // Downgrade state.dat to v3: drop the trailing flags byte
        // (v3's payload ends at snapshot_base), patch the version
        // field, and re-cover the payload with a fresh checksum.
        let state_path = dir.join("state.dat");
        let mut bytes = std::fs::read(&state_path).unwrap();
        let payload_end = bytes.len() - 1; // strip the v4 flags byte
        bytes.truncate(payload_end);
        bytes[4..8].copy_from_slice(&3u32.to_le_bytes());
        let digest = crate::hash::sha256d(&bytes[40..]);
        bytes[8..40].copy_from_slice(&digest);
        std::fs::write(&state_path, bytes).unwrap();

        // Reopen with the backend: inline coins migrate into coinsdb.
        let cs = Chainstate::with_store_coinsdb(&dir, &params, NOW, 1 << 20).unwrap();
        assert_eq!(cs.tip_hash(), tip6);
        let be = cs.coins_backend.clone().unwrap();
        assert_eq!(be.tip_height(), 6);
        assert_eq!(be.coins_len() as usize, utxo6.len());
        let mut resumed = cs.utxo().iter();
        resumed.sort_by_key(|(o, _)| (o.txid, o.vout));
        let mut expected = utxo6;
        expected.sort_by_key(|(o, _)| (o.txid, o.vout));
        assert_eq!(resumed, expected);
        drop(cs);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `invalidateblock`/`reconsiderblock`: invalidating a mid-chain block
    /// rewinds the connected chain and activates a heavier competitor;
    /// reconsidering clears the marks and reconnects the branch back to
    /// its original tip.
    #[test]
    fn invalidate_and_reconsider_rewind_and_restore() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        let genesis = genesis_header();

        // Main chain g→b1→b2→b3.
        let b1 = block_on(&genesis, vec![coinbase_tx(1, subsidy(1))], &params);
        let b2 = block_on(&b1.header, vec![coinbase_tx(2, subsidy(2))], &params);
        let b3 = block_on(&b2.header, vec![coinbase_tx(3, subsidy(3))], &params);
        for b in [&b1, &b2, &b3] {
            assert!(matches!(
                cs.accept_block(b, NOW),
                Ok(Acceptance::Connected { .. })
            ));
        }

        // Equal-work side branch g→b1→c2→c3, parked on arrival.
        let c2 = block_on(
            &b1.header,
            vec![tagged_coinbase(2, subsidy(2), 0xC2)],
            &params,
        );
        let c3 = block_on(
            &c2.header,
            vec![tagged_coinbase(3, subsidy(3), 0xC3)],
            &params,
        );
        for b in [&c2, &c3] {
            assert!(matches!(
                cs.accept_block(b, NOW),
                Ok(Acceptance::Parked { .. })
            ));
        }
        assert_eq!(cs.chain().len(), 4);
        assert_eq!(cs.tip_hash(), b3.block_hash());

        // Unknown hash → None; genesis → Some(0) no-op.
        assert_eq!(cs.invalidate_block(&BlockHash::from([0xAB; 32])), Ok(None));
        assert_eq!(cs.invalidate_block(&genesis.hash()), Ok(Some(0)));
        assert_eq!(cs.chain().len(), 4);

        // Invalidate b2: b2 and b3 are marked, the chain rewinds to b1
        // (2 blocks rewound), and the surviving c-branch out-works the
        // stub — it activates.
        assert_eq!(cs.invalidate_block(&b2.block_hash()), Ok(Some(2)));
        assert!(cs.tree().is_failed(&b2.block_hash()));
        assert!(cs.tree().is_failed(&b3.block_hash()));
        assert_eq!(cs.tip_hash(), c3.block_hash());
        assert_eq!(cs.chain()[2], c2.block_hash());
        assert_eq!(cs.chain()[3], c3.block_hash());

        // Reconsider b2: clears b2/b3 and any flagged ancestors. b3 and
        // c3 tie on work and c3 is already the tip, so the b-branch
        // stays parked until preciousblock breaks the tie.
        assert!(cs.reconsider_block(&b2.block_hash()).unwrap());
        assert!(!cs.tree().is_failed(&b2.block_hash()));
        assert!(!cs.tree().is_failed(&b3.block_hash()));
        assert_eq!(cs.tip_hash(), c3.block_hash());

        // Precious b3 breaks the tie — the b-branch reactivates.
        assert!(cs.precious_block(&b3.block_hash()).unwrap());
        assert_eq!(cs.tip_hash(), b3.block_hash());
    }

    /// Invalidating the tip with no surviving competitor simply rewinds.
    #[test]
    fn invalidate_tip_rewinds_one_block() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        let genesis = genesis_header();
        let b1 = block_on(&genesis, vec![coinbase_tx(1, subsidy(1))], &params);
        let b2 = block_on(&b1.header, vec![coinbase_tx(2, subsidy(2))], &params);
        for b in [&b1, &b2] {
            cs.accept_block(b, NOW).unwrap();
        }
        assert_eq!(cs.invalidate_block(&b2.block_hash()), Ok(Some(1)));
        assert_eq!(cs.tip_hash(), b1.block_hash());
        assert_eq!(cs.chain().len(), 2);
        assert!(cs.tree().is_failed(&b2.block_hash()));

        // Reconsider reconnects it — the body is still stored and the
        // branch out-works b1.
        assert!(cs.reconsider_block(&b2.block_hash()).unwrap());
        assert_eq!(cs.tip_hash(), b2.block_hash());
        assert_eq!(cs.chain().len(), 3);
    }

    /// `take_disconnected` drains evicted blocks in disconnect order
    /// (tip → fork) — Core's `DisconnectedBlockTransactions` queue — and
    /// `invalidate_block` reports the rewind count separately from the
    /// follow-up `ActivateBestChain` disconnects, because Core feeds the
    /// two phases to the mempool in opposite orders.
    #[test]
    fn disconnected_queue_orders_reorg_and_rewind() {
        let params = params();
        let mut cs = Chainstate::new(&params);
        let genesis = genesis_header();
        let b1 = block_on(&genesis, vec![coinbase_tx(1, subsidy(1))], &params);
        let b2 = block_on(&b1.header, vec![coinbase_tx(2, subsidy(2))], &params);
        let b3 = block_on(&b2.header, vec![coinbase_tx(3, subsidy(3))], &params);
        for b in [&b1, &b2, &b3] {
            cs.accept_block(b, NOW).unwrap();
        }

        // A heavier rival from genesis evicts the whole b-branch — the
        // drain lists the evictions tip-first.
        let mut c_blocks = Vec::new();
        let mut parent = genesis;
        for h in 1..=4u32 {
            let c = block_on(
                &parent,
                vec![tagged_coinbase(h, subsidy(h), 0xC0 + h as u8)],
                &params,
            );
            cs.accept_block(&c, NOW).unwrap();
            parent = c.header;
            c_blocks.push(c);
        }
        assert_eq!(cs.chain().len(), 5);
        assert_eq!(
            cs.take_disconnected(),
            vec![b3.block_hash(), b2.block_hash(), b1.block_hash()]
        );
        assert!(cs.take_disconnected().is_empty());

        // Invalidate c2: the rewind pops c4→c3→c2 (rewound == 3), then
        // activation evicts c1 to switch onto the surviving b-branch —
        // the drain's tail is that reorg's disconnect, tip-first too.
        assert_eq!(cs.invalidate_block(&c_blocks[1].block_hash()), Ok(Some(3)));
        assert_eq!(
            cs.take_disconnected(),
            vec![
                c_blocks[3].block_hash(),
                c_blocks[2].block_hash(),
                c_blocks[1].block_hash(),
                c_blocks[0].block_hash(),
            ]
        );
        assert_eq!(cs.tip_hash(), b3.block_hash());
    }
}

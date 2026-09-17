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

use crate::block::Block;
use crate::chain::{ChainError, HeaderTree, InsertStatus};
use crate::check::{self, BlockContext, BlockRuleError, ContextualBlockError, RuleError};
use crate::coinstats::{self, CoinStats, CoinStatsHashType};
use crate::connect::{self, BlockUndo, ConnectContext, ConnectError, UtxoSet};
use crate::hash::{BlockHash, Txid};
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
    /// Per-block undo for `chain[1..]` (the genesis is never connected):
    /// `undos[k]` reverses the block at height `k + 1`.
    undos: Vec<BlockUndo>,
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
            store: None,
            txindex: None,
            scripthashindex: None,
            filterindex: None,
            precious: None,
            snapshot_base: None,
        }
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
            let empty = BlockUndo::default();
            let undo = self.undo(h).unwrap_or(&empty);
            index.append(h, &block, undo);
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
            let empty = BlockUndo::default();
            let undo = self.undo(h).unwrap_or(&empty);
            index.append(h, &block, undo);
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
        crate::utxo_snapshot::read_coins(r, meta.coins_count, base_height, |outpoint, coin| {
            loaded.insert_synthetic(outpoint, coin)
        })?;

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
        self.undos = vec![BlockUndo::default(); base_height as usize];
        self.connected = base;
        self.snapshot_base = Some(base_height);
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
        self.undos = state.undos;
        self.snapshot_base = snapshot_base;
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

    /// The undo data for the *active-chain* block at `height` — Core's
    /// `ReadBlockUndo`. `undos[h-1]` reverses `chain[h]`; genesis and
    /// heights above the connected tip have none, and side-branch
    /// blocks never get undo entries, matching Core's rev*.dat
    /// semantics where undo exists only for the active chain.
    #[must_use]
    pub fn undo(&self, height: u32) -> Option<&BlockUndo> {
        if height == 0 {
            return None;
        }
        self.undos.get(height as usize - 1)
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
    pub fn verify_tip(&self, check_level: i32, depth: i64) -> bool {
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
        let mut utxo = self.utxo.clone();
        // VerifyDB's backward pass: bodies present (level 0), CheckBlock
        // (≥ 1), undo present (≥ 2), DisconnectBlock applies (≥ 3).
        for height in (start..=tip).rev() {
            let hash = self.chain[height as usize];
            let Some(block) = self.body(&hash) else {
                return false;
            };
            if check_level >= 1 && check::check_block(&block, &params).is_err() {
                return false;
            }
            let Some(undo) = self.undos.get(height as usize - 1) else {
                return check_level < 2;
            };
            if check_level >= 3 && connect::disconnect_block(&block, &mut utxo, undo).is_err() {
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
                parent_median_time_past: self.tree.median_time_past(&block.header.prev_block_hash),
            };
            if check::contextual_check_block(&block, &ctx).is_err() {
                return false;
            }
            let cctx = ConnectContext {
                params: &params,
                tree: &self.tree,
                block_hash: hash,
                script_checks: self.script_checks(&hash, &params),
            };
            if connect::connect_block(&block, &mut utxo, &cctx).is_err() {
                return false;
            }
        }
        true
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
            };
            match connect::connect_block(block, &mut self.utxo, &ctx) {
                Ok(undo) => {
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

        // Commit. `disconnected` records whether any connected block was rolled
        // back — false when the branch merely extended the tip (a stored-body
        // resubmission landing here is `ActivateBestChain` connecting it, not
        // a reorg).
        let disconnected = (fork_height as usize) < self.chain.len() - 1;
        let old_tip_height = self.chain.len() as u32 - 1;
        self.utxo = utxo;
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
        self.chain.truncate(fork_height as usize + 1);
        self.undos.truncate(fork_height as usize);
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
        self.undos.extend(new_undos);
        self.connected = hash;
        Ok(Some(disconnected))
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
        connect::disconnect_block(&blocks[2], &mut utxo, undo3).unwrap();
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
            let got = cs
                .utxo()
                .iter()
                .find(|(o, _)| *o == op)
                .map(|(_, c)| c)
                .unwrap();
            assert_eq!(got, coin);
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
}

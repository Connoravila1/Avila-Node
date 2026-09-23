//! The disk-backed coins store — Core's `CCoinsViewDB` analogue backed
//! by `redb` instead of LevelDB.
//!
//! Three tables, all written in a single atomic commit:
//!
//! * `coins`: outpoint (36B) → coin record — the full UTXO set for
//!   entries that have left the in-memory write-back cache.
//! * `undo`: height → serialized `BlockUndo` — the durable equivalent
//!   of Core's `rev*.dat` files; disconnects read it, and it is what
//!   makes a crash between a coins commit and the `state.dat` rename
//!   recoverable (the backend rewinds to the last flushed tip).
//! * `meta`: `tip_height`, `coins_len` — self-describing consistency
//!   markers committed in the same transaction as the coins.
//!
//! Consistency model: a commit is atomic, so `tip_height` never
//! describes more than the coin state on disk. `state.dat` is written
//! *after* the commit lands, so on load the backend may be ahead of
//! the snapshot (rewind via stored undos + blk-file bodies) but never
//! behind — a behind-state is declared corrupt, not silently patched.
//! `commit_partial` (snapshot import batches) deliberately commits
//! coins without advancing `tip_height`: a torn import leaves the old
//! tip with extra orphaned coins, which re-import overwrites — never
//! a tip claiming uncommitted state.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::connect::{BlockUndo, Coin};
use crate::encode::Decoder;
use crate::transaction::OutPoint;

/// outpoint bytes (txid 32 || vout LE 4) → coin record.
const COINS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("coins");
/// height → block hash (32B) || serialized `BlockUndo` — the hash tag
/// lets crash-recovery find the body to disconnect without the chain
/// vec (which only reaches the last snapshot tip).
const UNDO: TableDefinition<u32, &[u8]> = TableDefinition::new("undo");
/// ASCII key → value: `tip_height` (u32 LE), `coins_len` (u64 LE).
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

const K_TIP: &str = "tip_height";
const K_LEN: &str = "coins_len";
/// The record-encoding marker — absent means [`CoinFormat::Legacy`].
const K_FORMAT: &str = "format";
/// The coins-table engine marker — absent means [`Engine::Redb`].
const K_ENGINE: &str = "engine";

/// The coin-record encoding a `coinsdb.redb` carries, stamped into
/// `meta` at creation and read back on open. A database keeps its
/// creation format for life — undo records embed the same coin
/// encoding, so mid-life switches would misdecode stored undos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinFormat {
    /// Original layout: `i64 value | varbytes(script) | u32 height |
    /// u8 coinbase` (~39 bytes for a 25-byte script).
    Legacy,
    /// Core's `Coin` layout: `VARINT(height<<1|coinbase) |
    /// VARINT(CompressAmount) | VARINT(size_id) | payload` — reuses
    /// the snapshot codec (~26 bytes for the same P2PKH coin).
    Compact,
}

impl CoinFormat {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Legacy),
            1 => Some(Self::Compact),
            _ => None,
        }
    }
    fn byte(self) -> u8 {
        match self {
            Self::Legacy => 0,
            Self::Compact => 1,
        }
    }
}

/// Which data structure owns the coins table. Stamped into `meta` at
/// creation; an absent marker means the B-tree engine (every database
/// written before engines existed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// redb B-tree `coins` table inside `coinsdb.redb` — ordered, so
    /// canonical dumps iterate directly.
    Redb,
    /// [`crate::hashstore::HashStore`] — unordered hash index +
    /// append log (`coins.idx`/`coins.dat` beside `coinsdb.redb`,
    /// which still carries undo+meta). Canonical-order consumers sort
    /// externally.
    Hash,
}

impl Engine {
    fn byte(self) -> u8 {
        match self {
            Self::Redb => 0,
            Self::Hash => 1,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Redb),
            1 => Some(Self::Hash),
            _ => None,
        }
    }
}

/// outpoint → 36-byte key (wire byte order: txid || vout LE).
pub(crate) fn key_of(op: &OutPoint) -> [u8; 36] {
    let mut k = [0u8; 36];
    k[..32].copy_from_slice(op.txid.as_bytes());
    k[32..].copy_from_slice(&op.vout.to_le_bytes());
    k
}

/// Coin codec — `Legacy` is the original field order (same as
/// `store::put_coin`/`get_coin`); `Compact` is Core's `Coin`
/// serialization (the snapshot dump's wire codec, byte for byte).
pub(crate) fn encode_coin(c: &Coin, fmt: CoinFormat) -> Vec<u8> {
    match fmt {
        CoinFormat::Legacy => {
            let mut v = Vec::new();
            v.extend_from_slice(&c.out.value.to_le_bytes());
            crate::encode::write_var_bytes(&mut v, c.out.script_pubkey.as_bytes());
            v.extend_from_slice(&c.height.to_le_bytes());
            v.push(u8::from(c.coinbase));
            v
        }
        CoinFormat::Compact => {
            let mut v = Vec::new();
            crate::utxo_snapshot::write_varint(
                &mut v,
                u64::from(c.height) * 2 + u64::from(c.coinbase),
            );
            debug_assert!(c.out.value >= 0, "UTXO coins are never negative");
            crate::utxo_snapshot::write_varint(
                &mut v,
                crate::utxo_snapshot::compress_amount(c.out.value.max(0) as u64),
            );
            let (size_id, payload) = crate::utxo_snapshot::compress_script(&c.out.script_pubkey);
            crate::utxo_snapshot::write_varint(&mut v, size_id);
            v.extend_from_slice(&payload);
            v
        }
    }
}

pub(crate) fn decode_coin(b: &[u8], fmt: CoinFormat) -> Option<Coin> {
    match fmt {
        CoinFormat::Legacy => decode_coin_from(&mut Decoder::new(b)),
        CoinFormat::Compact => decode_coin_compact(&mut &b[..]),
    }
}

/// `Compact` records decode through a byte-slice reader — the varints
/// are Core's `VARINT` (MSB-first base-128), not CompactSize.
fn decode_coin_compact(r: &mut &[u8]) -> Option<Coin> {
    let code = crate::utxo_snapshot::read_varint(r).ok()?;
    let amount = crate::utxo_snapshot::read_varint(r).ok()?;
    let size_id = crate::utxo_snapshot::read_varint(r).ok()?;
    let script = crate::utxo_snapshot::decompress_script(r, size_id).ok()?;
    Some(Coin {
        out: crate::transaction::TxOut {
            value: crate::utxo_snapshot::decompress_amount(amount) as i64,
            script_pubkey: script,
        },
        height: (code / 2) as u32,
        coinbase: code % 2 == 1,
    })
}

/// A coin record is self-delimiting (the script is length-prefixed),
/// so undo entries decode straight from the stream without an outer
/// length.
fn decode_coin_from(d: &mut Decoder<'_>) -> Option<Coin> {
    let value = d.read_i64_le().ok()?;
    let spk = d.read_var_bytes().ok()?;
    let height = d.read_u32_le().ok()?;
    let coinbase = d.read_u8().ok()? != 0;
    Some(Coin {
        out: crate::transaction::TxOut {
            value,
            script_pubkey: crate::transaction::Script::new(spk),
        },
        height,
        coinbase,
    })
}

/// Undo record codec — the connecting block's hash followed by the
/// `BlockUndo` in `store::put_undo` layout. Coins inside carry the
/// database's [`CoinFormat`].
fn encode_undo(hash: &crate::hash::BlockHash, u: &BlockUndo, fmt: CoinFormat) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(hash.as_bytes());
    crate::encode::write_compact_size(&mut v, u.txs.len() as u64);
    for tx in &u.txs {
        crate::encode::write_compact_size(&mut v, tx.spent.len() as u64);
        for coin in &tx.spent {
            v.extend_from_slice(&encode_coin(coin, fmt));
        }
        crate::encode::write_compact_size(&mut v, tx.overwritten.len() as u64);
        for (op, coin) in &tx.overwritten {
            v.extend_from_slice(op.txid.as_bytes());
            v.extend_from_slice(&op.vout.to_le_bytes());
            v.extend_from_slice(&encode_coin(coin, fmt));
        }
    }
    v
}

/// `(block hash, undo)` — `None` on malformed records. Legacy coins
/// decode through `Decoder`; compact coins through a slice cursor —
/// the two varint schemes differ, so each branch keeps one cursor.
fn decode_undo(b: &[u8], fmt: CoinFormat) -> Option<(crate::hash::BlockHash, BlockUndo)> {
    match fmt {
        CoinFormat::Legacy => decode_undo_legacy(b),
        CoinFormat::Compact => decode_undo_compact(b),
    }
}

fn decode_undo_legacy(b: &[u8]) -> Option<(crate::hash::BlockHash, BlockUndo)> {
    let mut d = Decoder::new(b);
    let hash = crate::hash::BlockHash::from_bytes(d.read_array::<32>().ok()?);
    let tx_count = d.read_compact_size().ok()?;
    let mut txs = Vec::with_capacity(d.bounded_capacity(tx_count, 2));
    for _ in 0..tx_count {
        let spent_count = d.read_compact_size().ok()?;
        let mut spent = Vec::with_capacity(d.bounded_capacity(spent_count, 45));
        for _ in 0..spent_count {
            spent.push(decode_coin_from(&mut d)?);
        }
        let over_count = d.read_compact_size().ok()?;
        let mut overwritten = Vec::with_capacity(d.bounded_capacity(over_count, 81));
        for _ in 0..over_count {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(d.read_bytes(32).ok()?);
            let vout = d.read_u32_le().ok()?;
            let coin = decode_coin_from(&mut d)?;
            overwritten.push((
                OutPoint {
                    txid: crate::hash::Txid::from_bytes(txid),
                    vout,
                },
                coin,
            ));
        }
        txs.push(crate::connect::TxUndo { spent, overwritten });
    }
    Some((hash, BlockUndo { txs }))
}

/// The compact-format undo — same container layout (CompactSize
/// counts), but each coin is a `decode_coin_compact` record.
fn decode_undo_compact(b: &[u8]) -> Option<(crate::hash::BlockHash, BlockUndo)> {
    let (head, mut r) = b.split_at_checked(32)?;
    let hash = crate::hash::BlockHash::from_bytes(head.try_into().ok()?);
    let cs_u64 = |r: &mut &[u8]| -> Option<u64> {
        let b0 = *r.first()?;
        let (n, len) = match b0 {
            0..=0xfc => (u64::from(b0), 1),
            0xfd => (
                u64::from(u16::from_le_bytes(r.get(1..3)?.try_into().ok()?)),
                3,
            ),
            0xfe => (
                u64::from(u32::from_le_bytes(r.get(1..5)?.try_into().ok()?)),
                5,
            ),
            0xff => (u64::from_le_bytes(r.get(1..9)?.try_into().ok()?), 9),
        };
        *r = r.get(len..)?;
        Some(n)
    };
    let tx_count = cs_u64(&mut r)?;
    let mut txs = Vec::with_capacity((tx_count.min(10_000)) as usize);
    for _ in 0..tx_count {
        let spent_count = cs_u64(&mut r)?;
        let mut spent = Vec::with_capacity((spent_count.min(1_000_000)) as usize);
        for _ in 0..spent_count {
            spent.push(decode_coin_compact(&mut r)?);
        }
        let over_count = cs_u64(&mut r)?;
        let mut overwritten = Vec::with_capacity((over_count.min(1_000_000)) as usize);
        for _ in 0..over_count {
            let (head, tail) = r.split_at_checked(36)?;
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&head[..32]);
            let vout = u32::from_le_bytes(head[32..].try_into().ok()?);
            r = tail;
            let coin = decode_coin_compact(&mut r)?;
            overwritten.push((
                OutPoint {
                    txid: crate::hash::Txid::from_bytes(txid),
                    vout,
                },
                coin,
            ));
        }
        txs.push(crate::connect::TxUndo { spent, overwritten });
    }
    Some((hash, BlockUndo { txs }))
}

/// The on-disk coins store. Commits are whole-cache-delta
/// transactions — Core's `BatchWrite` where coins, undo and meta land
/// together or not at all.
#[derive(Debug)]
pub struct CoinsBackend {
    /// redb file — under [`Engine::Redb`] it owns the coins table too;
    /// under [`Engine::Hash`] it carries only undo+meta and the coins
    /// live in `hash` (`coins.idx`/`coins.dat`).
    db: redb::Database,
    /// Which data structure owns the coins table — fixed at creation.
    engine: Engine,
    /// The coin encoding every record in this database carries —
    /// fixed at creation, read from `meta` on open.
    format: CoinFormat,
    /// The hash store when `engine == Engine::Hash`.
    hash: Option<crate::hashstore::HashStore>,
    /// Cached `coins_len` — avoids a meta read per `len()` call.
    /// Atomic so commits stay `&self` (the backend lives behind `Arc`
    /// inside `UtxoSet`; the sync loop is still the only writer).
    coins_len: AtomicU64,
    /// Experiment counters — `(commits, coin puts, coin deletes)`
    /// actually executed. Lets benchmarks measure how much churn the
    /// write-back cache absorbs vs what reaches disk.
    stats: std::sync::Mutex<(u64, u64, u64)>,
}

impl CoinsBackend {
    /// Opens (creating) the database at `dir/coinsdb.redb`. An
    /// existing database decodes under its stored format/engine
    /// (absent markers → Legacy + Redb); a fresh one defaults to
    /// Compact + Redb — `AVILA_COINS_ENGINE=hash` selects the
    /// hash-indexed store for a fresh database (the experiment knob).
    ///
    /// # Errors
    /// `io::Error` on open/create or initial metadata read failure.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        let eng = match std::env::var("AVILA_COINS_ENGINE").as_deref() {
            Ok("hash") => Some(Engine::Hash),
            Ok("redb") => Some(Engine::Redb),
            _ => None,
        };
        Self::open_inner(dir, None, None, eng)
    }

    /// Opens with an explicit record format. A fresh database is
    /// stamped with `format`; an existing database must already carry
    /// that format — a mismatch is an error rather than a silent mix.
    ///
    /// # Errors
    /// `io::Error` on open/create or metadata failure, or when the
    /// database's stored format differs from `format`.
    pub fn open_with_format(dir: &Path, format: CoinFormat) -> std::io::Result<Self> {
        Self::open_inner(dir, Some(format), None, None)
    }

    /// `open_with_format` plus a redb cache budget — the memory-side
    /// knob for the profile experiment (`None` = redb's 1 GiB default).
    ///
    /// # Errors
    /// As [`Self::open_with_format`].
    pub fn open_tuned(dir: &Path, format: CoinFormat, cache_bytes: usize) -> std::io::Result<Self> {
        Self::open_inner(dir, Some(format), Some(cache_bytes), None)
    }

    /// Opens demanding a specific coins-table engine — the storage
    /// experiment's A/B path. Fresh databases are stamped with it;
    /// existing databases must already carry it.
    ///
    /// # Errors
    /// As [`Self::open_with_format`], or on engine mismatch.
    pub fn open_with_engine(dir: &Path, engine: Engine) -> std::io::Result<Self> {
        Self::open_inner(dir, None, None, Some(engine))
    }

    /// `requested = None` accepts whatever the database stores
    /// (fresh → Compact/Redb defaults); `Some` demands an exact match.
    fn open_inner(
        dir: &Path,
        requested: Option<CoinFormat>,
        cache_bytes: Option<usize>,
        requested_engine: Option<Engine>,
    ) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let db = {
            let mut b = redb::Database::builder();
            if let Some(cache) = cache_bytes {
                b.set_cache_size(cache);
            }
            b.create(dir.join("coinsdb.redb"))
        }
        .map_err(|e| std::io::Error::other(format!("coinsdb open: {e}")))?;
        // `(coins_len, has_tables, stored_format, stored_engine)` —
        // `has_tables` distinguishes a truly fresh database (stamp the
        // requested markers) from a pre-format one (absent → Legacy,
        // and absent engine → Redb: every pre-engine database is).
        let (coins_len, has_tables, stored_format, stored_engine) = {
            let r = db
                .begin_read()
                .map_err(|e| std::io::Error::other(format!("coinsdb read tx: {e}")))?;
            match r.open_table(META) {
                Ok(m) => {
                    let len = m
                        .get(K_LEN)
                        .map_err(|e| std::io::Error::other(format!("coinsdb meta: {e}")))?
                        .map(|g| u64::from_le_bytes(g.value().try_into().unwrap_or_default()))
                        .unwrap_or(0);
                    let fmt = m
                        .get(K_FORMAT)
                        .map_err(|e| std::io::Error::other(format!("coinsdb meta: {e}")))?
                        .and_then(|g| g.value().first().copied())
                        .and_then(CoinFormat::from_byte);
                    let eng = m
                        .get(K_ENGINE)
                        .map_err(|e| std::io::Error::other(format!("coinsdb meta: {e}")))?
                        .and_then(|g| g.value().first().copied())
                        .and_then(Engine::from_byte);
                    (len, true, fmt, eng)
                }
                Err(_) => (0, false, None, None), // fresh database — no tables yet
            }
        };
        // No markers on an existing database = written before formats/
        // engines existed = Legacy + Redb. Only a table-less database
        // is fresh.
        let stored_format = match (has_tables, stored_format) {
            (true, None) => Some(CoinFormat::Legacy),
            (true, f) => f,
            (false, _) => None,
        };
        let stored_engine = match (has_tables, stored_engine) {
            (true, None) => Some(Engine::Redb),
            (true, e) => e,
            (false, _) => None,
        };
        if let (Some(stored), Some(req)) = (stored_engine, requested_engine)
            && stored != req
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("coinsdb engine mismatch: stored {stored:?}, requested {req:?}"),
            ));
        }
        let engine = stored_engine.or(requested_engine).unwrap_or(Engine::Redb);
        let format = match stored_format {
            Some(f) => {
                if let Some(req) = requested
                    && req != f
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("coinsdb format mismatch: stored {f:?}, requested {req:?}"),
                    ));
                }
                f
            }
            None => {
                // Fresh database — stamp the requested format and
                // engine (or the Compact/Redb defaults when the
                // caller doesn't care).
                let fmt = requested.unwrap_or(CoinFormat::Compact);
                let w = db
                    .begin_write()
                    .map_err(|e| std::io::Error::other(format!("coinsdb write tx: {e}")))?;
                {
                    let mut m = w
                        .open_table(META)
                        .map_err(|e| std::io::Error::other(format!("coinsdb meta fmt: {e}")))?;
                    m.insert(K_FORMAT, &[fmt.byte()][..])
                        .map_err(|e| std::io::Error::other(format!("coinsdb meta fmt: {e}")))?;
                    m.insert(K_ENGINE, &[engine.byte()][..])
                        .map_err(|e| std::io::Error::other(format!("coinsdb meta eng: {e}")))?;
                }
                w.commit()
                    .map_err(|e| std::io::Error::other(format!("coinsdb commit: {e}")))?;
                fmt
            }
        };
        // Under the hash engine the meta byte records the redb-side
        // codec; hash log records are always Compact-encoded.
        let hash = if engine == Engine::Hash {
            let h = crate::hashstore::HashStore::open(dir)?;
            // Ordering tear: the index-header watermark commits with
            // the coins (phase 1), before this database's meta tx
            // (phase 3). Watermark > meta tip means a crash landed
            // between them — the coins are ahead of the tip and the
            // undo needed to rewind them was never written. Loud
            // error, not a MissingInput wedge downstream.
            let wm = h.tip_watermark();
            let meta_tip = {
                let r = db
                    .begin_read()
                    .map_err(|e| std::io::Error::other(format!("coinsdb read: {e}")))?;
                r.open_table(META)
                    .ok()
                    .and_then(|m| m.get(K_TIP).ok().flatten())
                    .and_then(|g| g.value().try_into().ok().map(u32::from_le_bytes))
                    .unwrap_or(0) as u64
            };
            if wm != u64::MAX && wm > meta_tip {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "coinsdb: hash coins at height {wm} but meta tip is {meta_tip} —                          torn commit, resync or restore required"
                    ),
                ));
            }
            Some(h)
        } else {
            None
        };
        Ok(Self {
            db,
            engine,
            format,
            hash,
            coins_len: AtomicU64::new(coins_len),
            stats: std::sync::Mutex::new((0, 0, 0)),
        })
    }

    /// `(commits, coin puts, coin deletes)` executed since open —
    /// experiment instrumentation.
    #[must_use]
    pub fn write_stats(&self) -> (u64, u64, u64) {
        *self.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn count_commit(&self, dirty: &HashMap<OutPoint, Option<Coin>>) {
        let mut puts = 0u64;
        let mut dels = 0u64;
        for e in dirty.values() {
            if e.is_some() {
                puts += 1;
            } else {
                dels += 1;
            }
        }
        if let Ok(mut s) = self.stats.lock() {
            s.0 += 1;
            s.1 += puts;
            s.2 += dels;
        }
    }

    /// The coins-table engine this database was created with.
    #[must_use]
    pub fn engine(&self) -> Engine {
        self.engine
    }

    /// The tip height the coins+undo tables describe — `0` on a fresh
    /// backend (genesis never connects, so height 0 is the empty set).
    #[must_use]
    pub fn tip_height(&self) -> u32 {
        self.db
            .begin_read()
            .ok()
            .and_then(|r| r.open_table(META).ok())
            .and_then(|m| m.get(K_TIP).ok().flatten())
            .and_then(|g| g.value().try_into().ok().map(u32::from_le_bytes))
            .unwrap_or(0)
    }

    /// The number of persisted coins.
    #[must_use]
    pub fn coins_len(&self) -> u64 {
        self.coins_len.load(Ordering::Relaxed)
    }

    /// `true` when nothing has ever been committed.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        self.tip_height() == 0 && self.coins_len() == 0
    }

    /// Hash-engine maintenance: rewrite `coins.dat` in slot order —
    /// restores read locality and reclaims dead-append space. No-op on
    /// the redb engine. Not crash-safe yet; hold the store quiescent.
    ///
    /// # Errors
    /// `io::Error` on compaction failure (hash engine only).
    pub fn compact_coins(&self) -> std::io::Result<()> {
        if let Some(h) = &self.hash {
            h.compact()
        } else {
            Ok(())
        }
    }

    /// The persisted coin at `outpoint` — a direct lookup; the
    /// in-memory layer above owns caching.
    #[must_use]
    pub fn get(&self, outpoint: &OutPoint) -> Option<Coin> {
        if let Some(h) = &self.hash {
            return h.get(&key_of(outpoint));
        }
        let r = self.db.begin_read().ok()?;
        let t = r.open_table(COINS).ok()?;
        let g = t.get(&key_of(outpoint)[..]).ok()??;
        decode_coin(g.value(), self.format)
    }

    /// `true` if the backend holds `outpoint` — cheaper than `get`
    /// when the coin itself isn't needed.
    #[must_use]
    pub fn have(&self, outpoint: &OutPoint) -> bool {
        if let Some(h) = &self.hash {
            return h.have(&key_of(outpoint));
        }
        self.db
            .begin_read()
            .ok()
            .and_then(|r| r.open_table(COINS).ok())
            .is_some_and(|t| matches!(t.get(&key_of(outpoint)[..]), Ok(Some(_))))
    }

    /// The stored undo for `height`, decoded — `None` if absent.
    #[must_use]
    pub fn undo_at(&self, height: u32) -> Option<BlockUndo> {
        self.undo_entry(height).map(|(_, u)| u)
    }

    /// The stored `(block hash, undo)` pair for `height` — the crash
    /// rewind path needs the hash to fetch the body to disconnect.
    #[must_use]
    pub fn undo_entry(&self, height: u32) -> Option<(crate::hash::BlockHash, BlockUndo)> {
        let r = self.db.begin_read().ok()?;
        let t = r.open_table(UNDO).ok()?;
        let g = t.get(height).ok()??;
        decode_undo(g.value(), self.format)
    }

    /// Atomically commits a cache delta: `dirty` entries (`Some` =
    /// put/overwrite, `None` = delete), `new_undos` the per-height undo
    /// records landing this commit, `tip` the connected height this
    /// state describes. All-or-nothing.
    ///
    /// # Errors
    /// `io::Error` on redb transaction failure.
    pub fn commit(
        &self,
        dirty: &HashMap<OutPoint, Option<Coin>>,
        new_undos: &[(u32, crate::hash::BlockHash, BlockUndo)],
        tip: u32,
    ) -> std::io::Result<()> {
        self.commit_inner(dirty, new_undos, Some(tip))
    }

    /// Like `commit` but leaves the meta tip untouched — mid-import
    /// batches in snapshot loading. A torn import then still reads
    /// tip=old (an unfinished activation never looks committed).
    pub fn commit_partial(&self, dirty: &HashMap<OutPoint, Option<Coin>>) -> std::io::Result<()> {
        self.commit_inner(dirty, &[], None)
    }

    fn commit_inner(
        &self,
        dirty: &HashMap<OutPoint, Option<Coin>>,
        new_undos: &[(u32, crate::hash::BlockHash, BlockUndo)],
        tip: Option<u32>,
    ) -> std::io::Result<()> {
        self.count_commit(dirty);
        // Hash engine: coins land in the log+index first (fsynced),
        // then the bookkeeping tx — torn state always replays as
        // "commit the same delta again", which is idempotent.
        if let Some(h) = &self.hash {
            let delta = h.commit_coins(dirty, tip)?;
            h.sync()?;
            let w = self
                .db
                .begin_write()
                .map_err(|e| std::io::Error::other(format!("coinsdb write tx: {e}")))?;
            {
                let mut undo = w
                    .open_table(UNDO)
                    .map_err(|e| std::io::Error::other(format!("coinsdb undo: {e}")))?;
                for (hgt, hash, u) in new_undos {
                    undo.insert(*hgt, encode_undo(hash, u, self.format).as_slice())
                        .map_err(|e| std::io::Error::other(format!("coinsdb undo put: {e}")))?;
                }
                let new_len = (self.coins_len() as i64 + delta).max(0) as u64;
                let mut meta = w
                    .open_table(META)
                    .map_err(|e| std::io::Error::other(format!("coinsdb meta: {e}")))?;
                meta.insert(K_LEN, new_len.to_le_bytes().as_slice())
                    .map_err(|e| std::io::Error::other(format!("coinsdb meta len: {e}")))?;
                if let Some(tip) = tip {
                    meta.insert(K_TIP, tip.to_le_bytes().as_slice())
                        .map_err(|e| std::io::Error::other(format!("coinsdb meta tip: {e}")))?;
                }
            }
            w.commit()
                .map_err(|e| std::io::Error::other(format!("coinsdb commit: {e}")))?;
            self.coins_len.store(
                (self.coins_len() as i64 + delta).max(0) as u64,
                Ordering::Relaxed,
            );
            return Ok(());
        }
        let w = self
            .db
            .begin_write()
            .map_err(|e| std::io::Error::other(format!("coinsdb write tx: {e}")))?;
        let mut delta: i64 = 0;
        {
            let mut coins = w
                .open_table(COINS)
                .map_err(|e| std::io::Error::other(format!("coinsdb coins: {e}")))?;
            // Insert in key order — sequential B-tree leaf fills beat
            // the HashMap's random walk, especially on large deltas
            // where random inserts thrash pages.
            let mut ordered: Vec<_> = dirty.iter().collect();
            ordered.sort_by_key(|(op, _)| key_of(op));
            for (op, entry) in ordered {
                match entry {
                    Some(c) => {
                        let had = coins
                            .insert(&key_of(op)[..], encode_coin(c, self.format).as_slice())
                            .map_err(|e| std::io::Error::other(format!("coinsdb insert: {e}")))?
                            .is_some();
                        if !had {
                            delta += 1;
                        }
                    }
                    None => {
                        if coins
                            .remove(&key_of(op)[..])
                            .map_err(|e| std::io::Error::other(format!("coinsdb remove: {e}")))?
                            .is_some()
                        {
                            delta -= 1;
                        }
                    }
                }
            }
            let mut undo = w
                .open_table(UNDO)
                .map_err(|e| std::io::Error::other(format!("coinsdb undo: {e}")))?;
            for (h, hash, u) in new_undos {
                undo.insert(*h, encode_undo(hash, u, self.format).as_slice())
                    .map_err(|e| std::io::Error::other(format!("coinsdb undo put: {e}")))?;
            }
            let new_len = (self.coins_len() as i64 + delta).max(0) as u64;
            let mut meta = w
                .open_table(META)
                .map_err(|e| std::io::Error::other(format!("coinsdb meta: {e}")))?;
            meta.insert(K_LEN, new_len.to_le_bytes().as_slice())
                .map_err(|e| std::io::Error::other(format!("coinsdb meta len: {e}")))?;
            if let Some(tip) = tip {
                meta.insert(K_TIP, tip.to_le_bytes().as_slice())
                    .map_err(|e| std::io::Error::other(format!("coinsdb meta tip: {e}")))?;
            }
        }
        w.commit()
            .map_err(|e| std::io::Error::other(format!("coinsdb commit: {e}")))?;
        self.coins_len.store(
            (self.coins_len() as i64 + delta).max(0) as u64,
            Ordering::Relaxed,
        );
        Ok(())
    }

    /// Every persisted `OutPoint → Coin` — migration and
    /// `gettxoutsetinfo`/`dumptxoutset` only; callers materialize the
    /// full set anyway (a streaming iterator can't outlive the read
    /// transaction that produced it under redb's ownership rules).
    #[must_use]
    pub fn iter_coins(&self) -> Vec<(OutPoint, Coin)> {
        if let Some(h) = &self.hash {
            return h.iter_coins();
        }
        let Ok(r) = self.db.begin_read() else {
            return Vec::new();
        };
        let Ok(t) = r.open_table(COINS) else {
            return Vec::new();
        };
        let Ok(iter) = t.iter() else {
            return Vec::new();
        };
        iter.filter_map(|row| {
            let (k, v) = row.ok()?;
            let kb = k.value();
            if kb.len() != 36 {
                return None;
            }
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&kb[..32]);
            let vout = u32::from_le_bytes(kb[32..].try_into().ok()?);
            Some((
                OutPoint {
                    txid: crate::hash::Txid::from_bytes(txid),
                    vout,
                },
                decode_coin(v.value(), self.format)?,
            ))
        })
        .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::connect::{BlockUndo, TxUndo};
    use crate::hash::{BlockHash, Txid};
    use crate::transaction::{OutPoint, Script, TxOut};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn test_dir(name: &str) -> PathBuf {
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        let dir = base.join(format!("avila-coinsdb-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn op(seed: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_bytes([seed; 32]),
            vout,
        }
    }

    fn coin(value: i64, height: u32) -> Coin {
        Coin {
            out: TxOut {
                value,
                script_pubkey: Script::new(vec![0x51]),
            },
            height,
            coinbase: false,
        }
    }

    fn undo(seed: u8) -> BlockUndo {
        BlockUndo {
            txs: vec![
                TxUndo::default(),
                TxUndo {
                    spent: vec![coin(50_000, seed as u32)],
                    overwritten: vec![(op(seed ^ 0xaa, 0), coin(1, 1))],
                },
            ],
        }
    }

    fn hash(seed: u8) -> BlockHash {
        BlockHash::from_bytes([seed; 32])
    }

    #[test]
    fn open_fresh_and_meta() {
        let dir = test_dir("fresh");
        let be = CoinsBackend::open(&dir).unwrap();
        assert!(be.is_fresh());
        assert_eq!(be.tip_height(), 0);
        assert_eq!(be.coins_len(), 0);
        assert!(be.get(&op(1, 0)).is_none());
        assert!(!be.have(&op(1, 0)));
    }

    #[test]
    fn commit_coins_undo_meta_roundtrip() {
        let dir = test_dir("roundtrip");
        let be = CoinsBackend::open(&dir).unwrap();
        let mut dirty = HashMap::new();
        dirty.insert(op(1, 0), Some(coin(100, 5)));
        dirty.insert(op(2, 1), Some(coin(200, 5)));
        be.commit(&dirty, &[(5, hash(9), undo(3))], 5).unwrap();
        assert_eq!(be.tip_height(), 5);
        assert_eq!(be.coins_len(), 2);
        assert_eq!(be.get(&op(1, 0)).unwrap().out.value, 100);
        assert!(be.have(&op(2, 1)));

        // Reopen: the same db is durable.
        drop(be);
        let be = CoinsBackend::open(&dir).unwrap();
        assert_eq!(be.tip_height(), 5);
        assert_eq!(be.coins_len(), 2);
        assert_eq!(be.get(&op(1, 0)).unwrap().out.value, 100);

        // Undo carries the block-hash tag for crash rewind.
        let (h, u) = be.undo_entry(5).unwrap();
        assert_eq!(h, hash(9));
        assert_eq!(u.txs.len(), 2);
        assert_eq!(u.txs[1].spent[0].out.value, 50_000);
        assert_eq!(u.txs[1].overwritten[0].1.out.value, 1);
    }

    #[test]
    fn commit_spend_deletes_and_replaces() {
        let dir = test_dir("spend");
        let be = CoinsBackend::open(&dir).unwrap();
        let mut dirty = HashMap::new();
        dirty.insert(op(1, 0), Some(coin(100, 1)));
        dirty.insert(op(2, 0), Some(coin(200, 1)));
        be.commit(&dirty, &[], 1).unwrap();
        assert_eq!(be.coins_len(), 2);

        // Spend one (tombstone), overwrite the other.
        let mut dirty = HashMap::new();
        dirty.insert(op(1, 0), None);
        dirty.insert(op(2, 0), Some(coin(999, 2)));
        dirty.insert(op(3, 0), Some(coin(50, 2)));
        be.commit(&dirty, &[], 2).unwrap();
        assert!(!be.have(&op(1, 0)));
        assert_eq!(be.get(&op(2, 0)).unwrap().out.value, 999);
        assert_eq!(be.get(&op(3, 0)).unwrap().out.value, 50);
        // 2 originals − 1 tombstone + 1 new = 2 (the overwrite nets 0).
        assert_eq!(be.coins_len(), 2);
        assert_eq!(be.tip_height(), 2);
    }

    #[test]
    fn iter_coins_covers_all() {
        let dir = test_dir("iter");
        let be = CoinsBackend::open(&dir).unwrap();
        let mut dirty = HashMap::new();
        for i in 0..10u8 {
            dirty.insert(op(i, 0), Some(coin(i64::from(i), 1)));
        }
        be.commit(&dirty, &[], 1).unwrap();
        let all = be.iter_coins();
        assert_eq!(all.len(), 10);
        assert!(
            all.iter()
                .any(|(o, c)| o.txid == Txid::from_bytes([7; 32]) && c.out.value == 7)
        );
    }

    #[test]
    fn utxo_set_backend_roundtrip() {
        let dir = test_dir("view");
        let be = CoinsBackend::open(&dir).unwrap();
        let mut set = crate::connect::UtxoSet::new();
        set.attach_backend(be);
        set.insert_synthetic(op(1, 0), coin(42, 1));
        set.insert_synthetic(op(2, 0), coin(43, 1));
        assert_eq!(set.len(), 2);
        assert!(set.have(&op(1, 0)));
        set.flush_to_backend(&[], 1).unwrap();
        // After flush the dirty map is empty — reads hit the backend.
        assert_eq!(set.len(), 2);
        assert_eq!(set.get(&op(1, 0)).unwrap().out.value, 42);
        assert!(set.have(&op(2, 0)));

        // Spend via the set's spend path — tombstone over backend.
        let spent = set.test_spend(&op(1, 0));
        assert_eq!(spent.unwrap().out.value, 42);
        assert_eq!(set.len(), 1);
        assert!(!set.have(&op(1, 0)));
        assert!(set.get(&op(1, 0)).is_none());
        set.flush_to_backend(&[], 2).unwrap();
        assert_eq!(set.len(), 1);
        assert!(!set.have(&op(1, 0)));
    }

    #[test]
    fn overlay_sim_reads_base_writes_dirty() {
        let dir = test_dir("overlay");
        let be = CoinsBackend::open(&dir).unwrap();
        let mut set = crate::connect::UtxoSet::new();
        set.attach_backend(be);
        set.insert_synthetic(op(1, 0), coin(42, 1));
        set.flush_to_backend(&[], 1).unwrap();

        // Overlay sees through to backend state.
        let mut sim = set.overlay();
        assert_eq!(sim.get(&op(1, 0)).unwrap().out.value, 42);
        sim.insert_synthetic(op(9, 0), coin(7, 9));
        assert_eq!(sim.len(), 2);
        // Discarded: live set unchanged.
        set.unoverlay(sim, false);
        assert_eq!(set.len(), 1);
        assert!(!set.have(&op(9, 0)));

        // Committed: adopt the overlay's writes.
        let mut sim = set.overlay();
        sim.insert_synthetic(op(9, 0), coin(7, 9));
        set.unoverlay(sim, true);
        assert_eq!(set.len(), 2);
        assert!(set.have(&op(9, 0)));
        // And it's still only in the dirty map until flushed.
        set.flush_to_backend(&[], 2).unwrap();
        assert!(set.have(&op(9, 0)));
    }

    /// Every standard script shape must survive the compact codec —
    /// P2PKH/P2SH take the type-id path, compressed/uncompressed P2PK
    /// the key path, and witness/OP_RETURN the raw fallback.
    #[test]
    fn compact_codec_roundtrips_all_script_types() {
        let p2pkh = {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend_from_slice(&[0x42; 20]);
            s.extend_from_slice(&[0x88, 0xac]);
            Script::new(s)
        };
        let p2sh = {
            let mut s = vec![0xa9, 0x14];
            s.extend_from_slice(&[0x43; 20]);
            s.push(0x87);
            Script::new(s)
        };
        let p2pk_c = {
            let mut s = vec![0x21, 0x02];
            s.extend_from_slice(&[0x44; 32]);
            s.push(0xac);
            Script::new(s)
        };
        let p2wpkh = {
            let mut s = vec![0x00, 0x14];
            s.extend_from_slice(&[0x45; 20]);
            Script::new(s)
        };
        let p2tr = {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&[0x46; 32]);
            Script::new(s)
        };
        let opret = {
            let mut s = vec![0x6a, 0x08];
            s.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3]);
            Script::new(s)
        };
        for (i, script) in [p2pkh, p2sh, p2pk_c, p2wpkh, p2tr, opret]
            .into_iter()
            .enumerate()
        {
            for (value, height, cb) in [
                (50_000i64, 1u32, false),
                (5_000_000_000, 500, true), // 50 BTC coinbase — the 229-compression case
                (1, 0, false),
                (2_100_000_000_000_000, 900_000, false),
            ] {
                let c = Coin {
                    out: TxOut {
                        value,
                        script_pubkey: script.clone(),
                    },
                    height,
                    coinbase: cb,
                };
                for fmt in [CoinFormat::Legacy, CoinFormat::Compact] {
                    let enc = encode_coin(&c, fmt);
                    let dec = decode_coin(&enc, fmt)
                        .unwrap_or_else(|| panic!("decode failed: script {i} fmt {fmt:?}"));
                    assert_eq!(dec.out.value, c.out.value, "value: script {i} fmt {fmt:?}");
                    assert_eq!(
                        dec.out.script_pubkey.as_bytes(),
                        c.out.script_pubkey.as_bytes(),
                        "script: {i} fmt {fmt:?}"
                    );
                    assert_eq!(dec.height, c.height, "height: {i} fmt {fmt:?}");
                    assert_eq!(dec.coinbase, c.coinbase, "coinbase: {i} fmt {fmt:?}");
                }
            }
        }
    }

    /// A compact record is smaller than the legacy one on a standard
    /// output — the whole point of the encoding.
    #[test]
    fn compact_is_smaller_on_standard_outputs() {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&[0x42; 20]);
        s.extend_from_slice(&[0x88, 0xac]);
        let c = Coin {
            out: TxOut {
                value: 50_000,
                script_pubkey: Script::new(s),
            },
            height: 500,
            coinbase: false,
        };
        let legacy = encode_coin(&c, CoinFormat::Legacy).len();
        let compact = encode_coin(&c, CoinFormat::Compact).len();
        assert!(
            compact < legacy,
            "compact {compact} should beat legacy {legacy}"
        );
    }

    /// The format marker persists: a Compact db reopens as Compact and
    /// rejects a conflicting request; a Legacy db (no marker or 0)
    /// stays Legacy.
    #[test]
    fn format_marker_persists_and_rejects_mismatch() {
        let dir = test_dir("format-marker");
        {
            let be = CoinsBackend::open_with_format(&dir, CoinFormat::Compact).unwrap();
            let mut dirty = HashMap::new();
            dirty.insert(op(1, 0), Some(coin(42, 1)));
            be.commit(&dirty, &[], 1).unwrap();
        }
        // Reopen with the matching format — reads decode.
        {
            let be = CoinsBackend::open_with_format(&dir, CoinFormat::Compact).unwrap();
            assert_eq!(be.get(&op(1, 0)).unwrap().out.value, 42);
        }
        // A conflicting open must fail, not silently mix encodings.
        assert!(CoinsBackend::open_with_format(&dir, CoinFormat::Legacy).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Undo records round-trip under the compact codec too — coins
    /// inside undo entries use the database's format.
    #[test]
    fn undo_roundtrips_under_compact() {
        let dir = test_dir("undo-compact");
        let be = CoinsBackend::open_with_format(&dir, CoinFormat::Compact).unwrap();
        let mut dirty = HashMap::new();
        dirty.insert(op(1, 0), Some(coin(42, 1)));
        be.commit(&dirty, &[(1, hash(7), undo(7))], 1).unwrap();
        let (h, u) = be.undo_entry(1).unwrap();
        assert_eq!(h, hash(7));
        assert_eq!(u.txs.len(), 2);
        assert_eq!(u.txs[1].spent[0].out.value, 50_000);
        assert_eq!(u.txs[1].overwritten[0].1.out.value, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

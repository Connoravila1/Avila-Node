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
//! Consistency model: a commit is atomic, so `tip_height` always
//! describes exactly the coin state on disk. `state.dat` is written
//! *after* the commit lands, so on load the backend may be ahead of
//! the snapshot (rewind via stored undos + blk-file bodies) but never
//! behind — a behind-state is declared corrupt, not silently patched.

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

/// outpoint → 36-byte key (wire byte order: txid || vout LE).
fn key_of(op: &OutPoint) -> [u8; 36] {
    let mut k = [0u8; 36];
    k[..32].copy_from_slice(op.txid.as_bytes());
    k[32..].copy_from_slice(&op.vout.to_le_bytes());
    k
}

/// Coin codec — same field order as `store::put_coin`/`get_coin`.
fn encode_coin(c: &Coin) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&c.out.value.to_le_bytes());
    crate::encode::write_var_bytes(&mut v, c.out.script_pubkey.as_bytes());
    v.extend_from_slice(&c.height.to_le_bytes());
    v.push(u8::from(c.coinbase));
    v
}

fn decode_coin(b: &[u8]) -> Option<Coin> {
    decode_coin_from(&mut Decoder::new(b))
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
/// `BlockUndo` in `store::put_undo` layout.
fn encode_undo(hash: &crate::hash::BlockHash, u: &BlockUndo) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(hash.as_bytes());
    crate::encode::write_compact_size(&mut v, u.txs.len() as u64);
    for tx in &u.txs {
        crate::encode::write_compact_size(&mut v, tx.spent.len() as u64);
        for coin in &tx.spent {
            v.extend_from_slice(&encode_coin(coin));
        }
        crate::encode::write_compact_size(&mut v, tx.overwritten.len() as u64);
        for (op, coin) in &tx.overwritten {
            v.extend_from_slice(op.txid.as_bytes());
            v.extend_from_slice(&op.vout.to_le_bytes());
            v.extend_from_slice(&encode_coin(coin));
        }
    }
    v
}

/// `(block hash, undo)` — `None` on malformed records.
fn decode_undo(b: &[u8]) -> Option<(crate::hash::BlockHash, BlockUndo)> {
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

/// The on-disk coins store. Commits are whole-cache-delta
/// transactions — Core's `BatchWrite` where coins, undo and meta land
/// together or not at all.
#[derive(Debug)]
pub struct CoinsBackend {
    db: redb::Database,
    /// Cached `coins_len` — avoids a meta read per `len()` call.
    /// Atomic so commits stay `&self` (the backend lives behind `Arc`
    /// inside `UtxoSet`; the sync loop is still the only writer).
    coins_len: AtomicU64,
}

impl CoinsBackend {
    /// Opens (creating) the database at `dir/coinsdb.redb`.
    ///
    /// # Errors
    /// `io::Error` on open/create or initial metadata read failure.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let db = redb::Database::create(dir.join("coinsdb.redb"))
            .map_err(|e| std::io::Error::other(format!("coinsdb open: {e}")))?;
        let coins_len = {
            let r = db
                .begin_read()
                .map_err(|e| std::io::Error::other(format!("coinsdb read tx: {e}")))?;
            match r.open_table(META) {
                Ok(m) => m
                    .get(K_LEN)
                    .map_err(|e| std::io::Error::other(format!("coinsdb meta: {e}")))?
                    .map(|g| u64::from_le_bytes(g.value().try_into().unwrap_or_default()))
                    .unwrap_or(0),
                Err(_) => 0, // fresh database — no tables yet
            }
        };
        Ok(Self {
            db,
            coins_len: AtomicU64::new(coins_len),
        })
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

    /// The persisted coin at `outpoint` — a direct mmap lookup; the
    /// in-memory layer above owns caching.
    #[must_use]
    pub fn get(&self, outpoint: &OutPoint) -> Option<Coin> {
        let r = self.db.begin_read().ok()?;
        let t = r.open_table(COINS).ok()?;
        let g = t.get(&key_of(outpoint)[..]).ok()??;
        decode_coin(g.value())
    }

    /// `true` if the backend holds `outpoint` — cheaper than `get`
    /// when the coin itself isn't needed.
    #[must_use]
    pub fn have(&self, outpoint: &OutPoint) -> bool {
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
        decode_undo(g.value())
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
        let w = self
            .db
            .begin_write()
            .map_err(|e| std::io::Error::other(format!("coinsdb write tx: {e}")))?;
        let mut delta: i64 = 0;
        {
            let mut coins = w
                .open_table(COINS)
                .map_err(|e| std::io::Error::other(format!("coinsdb coins: {e}")))?;
            for (op, entry) in dirty {
                match entry {
                    Some(c) => {
                        let had = coins
                            .insert(&key_of(op)[..], encode_coin(c).as_slice())
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
                undo.insert(*h, encode_undo(hash, u).as_slice())
                    .map_err(|e| std::io::Error::other(format!("coinsdb undo put: {e}")))?;
            }
            let new_len = (self.coins_len() as i64 + delta).max(0) as u64;
            let mut meta = w
                .open_table(META)
                .map_err(|e| std::io::Error::other(format!("coinsdb meta: {e}")))?;
            meta.insert(K_LEN, new_len.to_le_bytes().as_slice())
                .map_err(|e| std::io::Error::other(format!("coinsdb meta len: {e}")))?;
            meta.insert(K_TIP, tip.to_le_bytes().as_slice())
                .map_err(|e| std::io::Error::other(format!("coinsdb meta tip: {e}")))?;
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
                decode_coin(v.value())?,
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
}

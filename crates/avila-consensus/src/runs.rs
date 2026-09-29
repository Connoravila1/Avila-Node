//! Sorted-run flush storage — the LSM-style alternative to per-epoch
//! `redb` commits. Each flush epoch becomes a triple of files under
//! `coinsdb/runs/`:
//!
//! ```text
//!   e-<seq>-<tip>.sr    sorted run of live coins (sortedrun format)
//!   e-<seq>-<tip>.del   sorted 36-byte keys spent this epoch —
//!                        tombstones shadowing every older layer
//!   e-<seq>-<tip>.und   undo records: [height u32][hash 32][len u32][bytes]
//!   e-<seq>-<tip>.ok    zero-byte marker written LAST — restore only
//!                        attaches epochs carrying it, so a crash
//!                        mid-write abandons a partial epoch for the
//!                        ordinary replay path.
//! ```
//!
//! Writes are all sequential — sort (~100ms per ~1M keys) then bulk
//! file write — instead of ~1.4M random B-tree inserts. Read order
//! stays total by covered height: probing newest→oldest, a del-hit or
//! run-hit is definitive for that layer.
//!
//! The backend's meta tip stops advancing per-epoch — it moves only on
//! compaction (merging run stack → backend or run→run). Chainstate's
//! `committed_coins_tip` watermark covers attached runs.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::coinsdb::{self, CoinFormat};
use crate::connect::BlockUndo;
use crate::connect::Coin;
use crate::hash::BlockHash;
use crate::sortedrun::{RunBuilder, SortedRun};
use crate::transaction::OutPoint;

/// Filename pieces for one flush epoch. `seq` orders epochs within a
/// process; `tip` is the highest connected height the files cover —
/// it alone orders epochs across restarts.
#[derive(Debug, Clone)]
pub struct EpochPaths {
    pub run: PathBuf,
    pub del: PathBuf,
    pub und: PathBuf,
    pub ok: PathBuf,
}

impl EpochPaths {
    fn for_epoch(dir: &Path, seq: u64, tip: u32) -> Self {
        let stem = format!("e-{seq:06}-{tip}");
        Self {
            run: dir.join(format!("{stem}.sr")),
            del: dir.join(format!("{stem}.del")),
            und: dir.join(format!("{stem}.und")),
            ok: dir.join(format!("{stem}.ok")),
        }
    }
}

/// The durable product of one flush epoch — returned by the worker,
/// opened on join.
pub struct EpochWrite {
    pub seq: u64,
    pub tip: u32,
    pub delta: i64,
    pub paths: EpochPaths,
}

/// Writes one flush epoch: sorted live coins, sorted tombstones, the
/// epoch's undo records, and the `.ok` marker last. `dirty` entries
/// carry `None` tombstones (spends of older-layer coins) and `Some`
/// (created/updated coins); both collapse into the layer.
///
/// `undos` are `(height, block_hash, undo)` — they leave the backend
/// undo table alone so a flush needs no `redb` write at all.
pub fn write_epoch(
    dir: &Path,
    seq: u64,
    tip: u32,
    delta: i64,
    dirty: &std::collections::HashMap<OutPoint, Option<Coin>>,
    undos: &[(u32, BlockHash, BlockUndo)],
) -> io::Result<EpochWrite> {
    let paths = EpochPaths::for_epoch(dir, seq, tip);
    // Runs order by `outpoint_key` (big-endian vout — byte order is
    // numeric order); `coinsdb::key_of`'s little-endian vout would
    // violate RunBuilder's ascending invariant once vout >= 256.
    let mut ordered: Vec<([u8; 36], &Option<Coin>)> = dirty
        .iter()
        .map(|(op, e)| (crate::utxo_snapshot::outpoint_key(op), e))
        .collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));

    // Live coins → .sr; tombstone keys → .del (same ascending order,
    // so one pass writes both).
    {
        let mut run = RunBuilder::create(&paths.run)?;
        let mut del = BufWriter::with_capacity(1 << 22, File::create(&paths.del)?);
        let mut dels: u64 = 0;
        for (key, entry) in &ordered {
            match entry {
                Some(c) => {
                    let rec = coinsdb::encode_coin(c, CoinFormat::Compact);
                    run.push_wire(key, &rec)?;
                }
                None => {
                    del.write_all(key)?;
                    dels += 1;
                }
            }
        }
        run.finish()?;
        del.flush()?;
        del.into_inner()?.sync_all()?;
        let _ = dels;
    }

    // Undo sidecar — one record per block, in-connect order.
    {
        let mut w = BufWriter::with_capacity(1 << 20, File::create(&paths.und)?);
        for (h, hash, u) in undos {
            let body = coinsdb::encode_undo(hash, u, CoinFormat::Compact);
            w.write_all(&h.to_le_bytes())?;
            w.write_all(&(body.len() as u32).to_le_bytes())?;
            w.write_all(&body)?;
        }
        w.flush()?;
        w.into_inner()?.sync_all()?;
    }

    // Marker LAST — restore attaches only epochs that carry it.
    File::create(&paths.ok)?.sync_all()?;
    // Fsync the directory so the names themselves are durable.
    File::open(dir)?.sync_all()?;
    Ok(EpochWrite {
        seq,
        tip,
        delta,
        paths,
    })
}

/// One attached epoch layer: the run file's sparse-index reader plus
/// the deletion key list in memory (a del-list is ~36B/spend — a
/// 200k-spend epoch is ~7MB, acceptable per attached epoch).
pub struct EpochLayer {
    pub tip: u32,
    pub delta: i64,
    pub seq: u64,
    run: SortedRun,
    /// Sorted keys deleted by this epoch — shadows older layers.
    del: Vec<[u8; 36]>,
    /// Undo records loaded at attach — reorgs read them without a
    /// backend hit. `(height, hash, undo)` in connect order.
    pub undos: Vec<(u32, BlockHash, BlockUndo)>,
    pub paths: EpochPaths,
}

impl EpochLayer {
    /// Attaches a finished epoch — `get`/`del`/`undo` readable, files
    /// kept open lazily. `delta` is the write-time net live-coin
    /// change; pass `None` on restore and it approximates to
    /// `run − del` (telemetry-only).
    pub fn open(dir: &Path, seq: u64, tip: u32, delta: Option<i64>) -> io::Result<Self> {
        let paths = EpochPaths::for_epoch(dir, seq, tip);
        let run = SortedRun::open(&paths.run)?;
        let mut del = Vec::new();
        {
            let mut f = File::open(&paths.del)?;
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut f, &mut buf)?;
            for chunk in buf.chunks_exact(36) {
                del.push(<[u8; 36]>::try_from(chunk).unwrap_or([0u8; 36]));
            }
        }
        let undos = load_undos(&paths.und)?;
        let delta = delta.unwrap_or(run.len() as i64 - del.len() as i64);
        Ok(Self {
            tip,
            delta,
            seq,
            run,
            del,
            undos,
            paths,
        })
    }

    /// `Some(Some(coin))` coin hit, `Some(None)` deleted by this
    /// epoch, `None` untouched — probe the next-older layer.
    pub fn probe(&self, key: &[u8; 36]) -> Option<Option<Coin>> {
        if !self.del.is_empty() && self.del.binary_search(key).is_ok() {
            return Some(None);
        }
        if let Some(c) = self.run.get_key(key) {
            return Some(Some(c));
        }
        None
    }

    /// Every record in the run — sequential; iter paths only.
    pub fn iter_records(&self) -> io::Result<Vec<(OutPoint, Coin)>> {
        self.run.iter()
    }

    /// Raw del-list keys — [`key_to_outpoint`] maps them back.
    pub fn del_keys(&self) -> &[[u8; 36]] {
        &self.del
    }

    /// Undo for `height` if this epoch covers it.
    pub fn undo(&self, height: u32) -> Option<&BlockUndo> {
        self.undos
            .iter()
            .find(|(h, _, _)| *h == height)
            .map(|(_, _, u)| u)
    }

    pub fn len(&self) -> u64 {
        self.run.len() + self.del.len() as u64
    }
}

/// `outpoint_key` bytes → `OutPoint` — the iter/del-merge inverse.
/// `key[..32]` is raw txid bytes, `key[32..]` is big-endian `vout`.
pub fn key_to_outpoint(key: &[u8; 36]) -> OutPoint {
    let mut tx = [0u8; 32];
    tx.copy_from_slice(&key[..32]);
    OutPoint {
        txid: crate::hash::Txid::from_bytes(tx),
        vout: u32::from_be_bytes(key[32..].try_into().unwrap_or([0; 4])),
    }
}

/// `[height][len][encode_undo bytes]` — order preserved.
fn load_undos(path: &Path) -> io::Result<Vec<(u32, BlockHash, BlockUndo)>> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut f, &mut buf)?;
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= buf.len() {
        let h = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap_or([0; 4]));
        let len = u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap_or([0; 4])) as usize;
        pos += 8;
        if pos + len > buf.len() {
            break;
        }
        if let Some((hash, u)) = coinsdb::decode_undo(&buf[pos..pos + len], CoinFormat::Compact) {
            out.push((h, hash, u));
        }
        pos += len;
    }
    Ok(out)
}

/// What restore finds on disk: epochs that wrote their `.ok` marker,
/// ordered by covered tip. Partial epochs (no marker) are removed —
/// replay covers them.
pub fn scan_epochs(dir: &Path) -> io::Result<Vec<(u64, u32)>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if !name.ends_with(".ok") {
            continue;
        }
        // e-<seq>-<tip>.ok
        let stem = &name[..name.len() - 3];
        let mut parts = stem.split('-');
        let _e = parts.next();
        let seq: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let tip: u32 = match parts.next().and_then(|s| s.parse().ok()) {
            Some(t) => t,
            None => continue,
        };
        out.push((seq, tip));
    }
    out.sort_by_key(|(_, tip)| *tip);
    Ok(out)
}

/// Removes every file of a partial/stale epoch (marker absent or the
/// epoch's tip is below the restored watermark — already covered).
pub fn remove_epoch(dir: &Path, seq: u64, tip: u32) {
    let p = EpochPaths::for_epoch(dir, seq, tip);
    for f in [p.run, p.del, p.und, p.ok] {
        let _ = std::fs::remove_file(f);
    }
}

/// Drops everything under `dir` — used when a compact/repair wants a
/// clean runs directory.
pub fn purge(dir: &Path) -> io::Result<()> {
    if dir.exists() {
        for ent in std::fs::read_dir(dir)? {
            let _ = std::fs::remove_file(ent?.path());
        }
    }
    Ok(())
}

impl std::fmt::Debug for EpochLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochLayer")
            .field("tip", &self.tip)
            .field("seq", &self.seq)
            .field("len", &self.len())
            .finish()
    }
}

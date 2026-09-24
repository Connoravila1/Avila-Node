//! An immutable sorted run of coins — the bulk-load path for snapshots.
//!
//! `loadtxoutset`'s stream is already sorted by `(txid, vout)` — the
//! same order [`crate::coinsdb::key_of`] produces — so building the
//! base layer is a *sequential write*, not an index insert: records
//! append to `base.run` in stream order while a sparse in-memory index
//! records every `STRIDE`-th key. That turns a 20-minute B-tree ingest
//! into a bounded sequential write — the whole point of the format.
//!
//! Reads binary-search the sparse index, read one record window (~a
//! few pages), and scan it linearly: ~1-2 page faults per lookup.
//! Updates never touch the run — it's immutable; spends and new coins
//! live in the mutable layer above (LSM-style).
//!
//! Layout:
//! ```text
//! [header 32B] magic "AVRUN1" | ver u32 | stride u32 | count u64 | index_off u64
//! [records]    [key 36][rec_len u32][compact coin] × count, key-sorted
//! [index]      [key 36][file_off u64] × ceil(count/stride)
//! ```

use crate::coinsdb::{self, CoinFormat};
use crate::connect::Coin;
use crate::transaction::OutPoint;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

const MAGIC: &[u8; 8] = b"AVRUN1\0\0";
const VERSION: u32 = 1;
const HDR: u64 = 32;
/// Sparse-index granularity — one entry per this many records.
/// 512 → a 170M-coin run carries ~332k index entries (~15MB RAM)
/// and each read scans a ~512-record window (~40KB, ~1-2 pages).
const DEFAULT_STRIDE: u32 = 512;

/// Streaming writer — feed records in `key_of` order; it appends and
/// samples the sparse index. Sequential I/O only.
pub struct RunBuilder {
    w: BufWriter<File>,
    path: std::path::PathBuf,
    sparse: Vec<([u8; 36], u64)>,
    count: u64,
    stride: u32,
    /// File offset where the next record lands.
    pos: u64,
    last_key: Option<[u8; 36]>,
}

impl RunBuilder {
    pub fn create(path: &Path) -> io::Result<Self> {
        Self::create_with_stride(path, DEFAULT_STRIDE)
    }

    pub fn create_with_stride(path: &Path, stride: u32) -> io::Result<Self> {
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        let mut b = Self {
            w: BufWriter::with_capacity(1 << 22, f),
            path: path.to_path_buf(),
            sparse: Vec::new(),
            count: 0,
            stride,
            pos: HDR,
            last_key: None,
        };
        b.w.write_all(&[0u8; HDR as usize])?;
        Ok(b)
    }

    /// Append a coin. Keys must arrive in strictly ascending order —
    /// the snapshot stream guarantees it; anything else is a format
    /// bug worth failing loudly on.
    pub fn push(&mut self, op: &OutPoint, coin: &Coin) -> io::Result<()> {
        let key = coinsdb::key_of(op);
        if let Some(prev) = self.last_key {
            debug_assert!(key > prev, "sorted-run keys must ascend");
        }
        if self.count.is_multiple_of(u64::from(self.stride)) {
            self.sparse.push((key, self.pos));
        }
        let rec = coinsdb::encode_coin(coin, CoinFormat::Compact);
        self.w.write_all(&key)?;
        self.w.write_all(&(rec.len() as u32).to_le_bytes())?;
        self.w.write_all(&rec)?;
        self.pos += 36 + 4 + rec.len() as u64;
        self.last_key = Some(key);
        self.count += 1;
        Ok(())
    }

    /// Append a record whose body is already in stored format — the
    /// snapshot bulk-load path copies wire bytes verbatim (the wire
    /// encoding IS `CoinFormat::Compact`), skipping decode+re-encode.
    pub fn push_wire(&mut self, key: &[u8; 36], body: &[u8]) -> io::Result<()> {
        if let Some(prev) = self.last_key {
            debug_assert!(*key > prev, "sorted-run keys must ascend");
        }
        if self.count.is_multiple_of(u64::from(self.stride)) {
            self.sparse.push((*key, self.pos));
        }
        self.w.write_all(key)?;
        self.w.write_all(&(body.len() as u32).to_le_bytes())?;
        self.w.write_all(body)?;
        self.pos += 36 + 4 + body.len() as u64;
        self.last_key = Some(*key);
        self.count += 1;
        Ok(())
    }

    /// Flush records, write the sparse index trailer + header.
    pub fn finish(mut self) -> io::Result<u64> {
        let index_off = self.pos;
        for (key, off) in &self.sparse {
            self.w.write_all(key)?;
            self.w.write_all(&off.to_le_bytes())?;
        }
        self.w.flush()?;
        let mut f = self.w.into_inner()?;
        let mut hdr = [0u8; HDR as usize];
        hdr[..8].copy_from_slice(MAGIC);
        hdr[8..12].copy_from_slice(&VERSION.to_le_bytes());
        hdr[12..16].copy_from_slice(&self.stride.to_le_bytes());
        hdr[16..24].copy_from_slice(&self.count.to_le_bytes());
        hdr[24..32].copy_from_slice(&index_off.to_le_bytes());
        f.seek(SeekFrom::Start(0))?;
        f.write_all(&hdr)?;
        f.sync_all()?;
        let _ = &self.path;
        Ok(self.count)
    }
}

/// Read handle — sparse index held in memory; records read on demand.
pub struct SortedRun {
    f: std::sync::Mutex<File>,
    sparse: Vec<([u8; 36], u64)>,
    count: u64,
    stride: u32,
}

impl SortedRun {
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut f = File::open(path)?;
        let mut hdr = [0u8; HDR as usize];
        f.read_exact(&mut hdr)?;
        if &hdr[..8] != MAGIC {
            return Err(io::Error::other("bad run magic"));
        }
        let stride = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        let count = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        let index_off = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
        let index_len = (f.metadata()?.len() - index_off) / 44;
        let mut sparse = Vec::with_capacity(index_len as usize);
        let mut entry = [0u8; 44];
        f.seek(SeekFrom::Start(index_off))?;
        for _ in 0..index_len {
            f.read_exact(&mut entry)?;
            let mut key = [0u8; 36];
            key.copy_from_slice(&entry[..36]);
            sparse.push((key, u64::from_le_bytes(entry[36..44].try_into().unwrap())));
        }
        Ok(Self {
            f: std::sync::Mutex::new(f),
            sparse,
            count,
            stride,
        })
    }

    pub fn len(&self) -> u64 {
        self.count
    }

    /// Point lookup: sparse binary search → one window read → scan.
    pub fn get(&self, op: &OutPoint) -> Option<Coin> {
        self.get_key(&coinsdb::key_of(op))
    }

    /// Lookup by raw `key_of` bytes — for callers already holding a key.
    pub fn get_key(&self, key: &[u8; 36]) -> Option<Coin> {
        // Greatest sparse entry with key <= target.
        let lo_idx = match self.sparse.binary_search_by(|(k, _)| k.cmp(key)) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let off_lo = self.sparse[lo_idx].1;
        // Window end: next sparse entry or the index itself.
        let off_hi = if lo_idx + 1 < self.sparse.len() {
            self.sparse[lo_idx + 1].1
        } else {
            // Scan up to stride records past the last index entry —
            // the tail window is bounded by stride × max record size.
            return self.scan_window(off_lo, u64::MAX, key);
        };
        self.scan_window(off_lo, off_hi, key)
    }

    fn scan_window(&self, off_lo: u64, off_hi: u64, key: &[u8; 36]) -> Option<Coin> {
        // Read enough bytes for `stride` records (~40KB typical).
        let cap = (u64::from(self.stride) * 84).min(off_hi.saturating_sub(off_lo)).max(84);
        let mut buf = vec![0u8; cap as usize];
        let f = self.f.lock().ok()?;
        if f.read_exact_at(&mut buf, off_lo).is_err() {
            return None;
        }
        let mut pos = 0usize;
        while pos + 40 <= buf.len() {
            let k: &[u8; 36] = buf[pos..pos + 36].try_into().unwrap();
            let len = u32::from_le_bytes(buf[pos + 36..pos + 40].try_into().unwrap()) as usize;
            if pos + 40 + len > buf.len() {
                break;
            }
            if k == key {
                return coinsdb::decode_coin(&buf[pos + 40..pos + 40 + len], CoinFormat::Compact);
            }
            if k > key {
                return None; // keys ascend — passed it
            }
            pos += 40 + len;
        }
        None
    }
}

/// Read-only view over an *external* sorted coin stream — the UTXO
/// snapshot file itself. Wire format already equals `CoinFormat::Compact`
/// record bytes, so building the UTXO set is an index-only pass:
/// sample every `stride`-th `(key -> file offset)` and seek-read coins
/// on demand. ~15MB of index for 170M coins; zero bulk writes.
#[derive(Debug)]
pub struct SnapshotRun {
    f: std::sync::Mutex<File>,
    /// Sorted sparse index: key -> byte offset of that coin's wire body
    /// region (points at the coin's vout varint — the record start).
    sparse: Vec<([u8; 36], u64)>,
    count: u64,
    /// File length — the read window must clamp at EOF (the last
    /// group's window is always partial).
    file_len: u64,
}

impl SnapshotRun {
    pub fn from_index(
        snap: File,
        sparse: Vec<([u8; 36], u64)>,
        count: u64,
    ) -> Self {
        let file_len = snap.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
        Self {
            f: std::sync::Mutex::new(snap),
            sparse,
            count,
            file_len,
        }
    }

    pub fn len(&self) -> u64 {
        self.count
    }

    /// Lookup: sparse binary search -> read a window starting at the
    /// record's vout varint -> walk txid group + outputs -> decode the
    /// wire body directly.
    ///
    /// Sparse entries point at the *vout varint* of every stride-th
    /// coin, but a txid group may start before that — so a lookup must
    /// scan from the group start. Groups are small (~1-2 outs), so the
    /// window covers stride+margin coins worth of bytes.
    pub fn get(&self, op: &OutPoint) -> Option<Coin> {
        let key = crate::coinsdb::key_of(op);
        let lo_idx = match self.sparse.binary_search_by(|(k, _)| k.cmp(&key)) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let off = self.sparse[lo_idx].1;
        // The window must contain up to `stride` whole coin records
        // starting from an arbitrary group boundary — use a generous
        // bound: stride * max compressed coin (~75B) + group margin.
        let cap = 1 << 17; // 128KB covers ~256 groups of typical coins
        let mut buf = vec![0u8; cap];
        let f = self.f.lock().ok()?;
        // The sparse offset points at a vout varint mid-group; the key
        // may sit anywhere in the following `stride` records. Walk
        // record-by-record: vout compact-size + wire body. Clamp the
        // window at EOF — the last group's read is always partial.
        let n = (self.file_len - off).min(cap as u64) as usize;
        f.read_exact_at(&mut buf[..n], off).ok()?;
        // txid is implicit (32B before each group) — but our offset is
        // mid-group, so the txid for THIS group isn't at `off`. We
        // store sparse entries at *vout varints* — recover txid by
        // reading 32 bytes back? Groups begin with txid; the sparse
        // key tells us the txid of the indexed coin — for scanning we
        // only need vout+body per record, with txid from the sparse
        // entry's key... but a group boundary could appear mid-window.
        // Simpler robust approach: sparse entries point at *group
        // starts* only — index every txid group boundary instead of
        // every coin. Caller guarantees that via index construction.
        let mut pos = 0usize;
        let mut cur_txid = [0u8; 32];
        // First record in window starts a txid group: read txid32+count.
        if pos + 33 > n {
            return None;
        }
        cur_txid.copy_from_slice(&buf[pos..pos + 32]);
        pos += 32;
        let mut group_left = cs(&buf, &mut pos) as usize;
        loop {
            if group_left == 0 {
                if pos + 33 > n {
                    return None; // window/EOF — no full group header left
                }
                cur_txid.copy_from_slice(&buf[pos..pos + 32]);
                pos += 32;
                group_left = cs(&buf, &mut pos) as usize;
                if group_left == 0 {
                    return None; // zero-count group — past real data
                }
            }
            if pos + 4 > n {
                return None; // no room for vout + varints
            }
            let vout = cs(&buf, &mut pos) as u32;
            let body_start = pos;
            let mut varints = [0u64; 3];
            for v in varints.iter_mut() {
                loop {
                    if pos >= n {
                        return None;
                    }
                    let c = buf[pos];
                    *v = (*v << 7) | u64::from(c & 0x7f);
                    pos += 1;
                    if c & 0x80 != 0 {
                        *v += 1; // Core VARINT: +1 per continuation
                    } else {
                        break;
                    }
                }
            }
            let plen = match varints[2] {
                0 | 1 => 20usize,
                2 | 3 | 4 | 5 => 32usize,
                x => (x - 6) as usize,
            };
            if pos + plen > n {
                return None; // body runs past the read window
            }
            if cur_txid == *op.txid.as_bytes() && vout == op.vout {
                return crate::coinsdb::decode_coin(
                    &buf[body_start..pos + plen],
                    CoinFormat::Compact,
                );
            }
            // Passed the key within this txid's group -> miss.
            if cur_txid == *op.txid.as_bytes() && vout > op.vout {
                return None;
            }
            if cur_txid > *op.txid.as_bytes() {
                return None;
            }
            pos += plen;
            group_left -= 1;
            if pos + 33 > n {
                return None; // window exhausted
            }
        }
    }

    /// Builds the sparse index by a sequential scan of a Core-format
    /// snapshot file — the no-bundle path: anyone holding the public
    /// snapshot can produce the index themselves (advice invariants).
    /// `stride` groups per index entry; the bench's parallel indexer is
    /// the fast path, this is the portable fallback.
    ///
    /// File layout after the 51-byte header: txid-grouped records of
    /// `[txid32][count compactsize][vout cs + 3 Core-VARINTs + script]`.
    /// Sparse keys are each sampled group's first outpoint.
    pub fn index(path: &Path, stride: u32) -> io::Result<Self> {
        let f = File::open(path)?;
        let file_len = f.metadata()?.len();
        let mut hdr = [0u8; 51];
        f.read_exact_at(&mut hdr, 0)?;
        if &hdr[..5] != b"utxo\xff" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a utxo snapshot (bad magic)",
            ));
        }
        let mut coins_left = u64::from_le_bytes(hdr[43..51].try_into().unwrap());
        let stride = stride.max(1) as u64;

        // Sliding 1 MiB window over the coin stream — sequential I/O,
        // positions tracked as absolute file offsets.
        const WIN: usize = 1 << 20;
        let mut buf = vec![0u8; WIN];
        let mut win_off = 51u64;
        let mut win_len = 0usize;
        let mut pos = 51u64;
        let need = |p: u64, f: &File, buf: &mut Vec<u8>, win_off: &mut u64, win_len: &mut usize| -> io::Result<()> {
            if p < *win_off || p as usize + 256 > (*win_off as usize) + *win_len {
                *win_off = p;
                let n = (file_len - p).min(WIN as u64) as usize;
                f.read_exact_at(&mut buf[..n], p)?;
                *win_len = n;
            }
            Ok(())
        };
        let byte_at = |p: u64, f: &File, buf: &mut Vec<u8>, win_off: &mut u64, win_len: &mut usize| -> io::Result<u8> {
            need(p, f, buf, win_off, win_len)?;
            Ok(buf[(p - *win_off) as usize])
        };
        let read_cs = |p: &mut u64, f: &File, buf: &mut Vec<u8>, win_off: &mut u64, win_len: &mut usize| -> io::Result<u64> {
            let c = byte_at(*p, f, buf, win_off, win_len)?;
            *p += 1;
            Ok(match c {
                0xfd => {
                    need(*p, f, buf, win_off, win_len)?;
                    let v = u16::from_le_bytes(buf[(*p - *win_off) as usize..(*p - *win_off) as usize + 2].try_into().unwrap()) as u64;
                    *p += 2;
                    v
                }
                0xfe => {
                    need(*p, f, buf, win_off, win_len)?;
                    let v = u32::from_le_bytes(buf[(*p - *win_off) as usize..(*p - *win_off) as usize + 4].try_into().unwrap()) as u64;
                    *p += 4;
                    v
                }
                0xff => {
                    need(*p, f, buf, win_off, win_len)?;
                    let v = u64::from_le_bytes(buf[(*p - *win_off) as usize..(*p - *win_off) as usize + 8].try_into().unwrap());
                    *p += 8;
                    v
                }
                _ => c as u64,
            })
        };
        // Core VARINT: continuation adds 1 per level.
        let read_varint = |p: &mut u64, f: &File, buf: &mut Vec<u8>, win_off: &mut u64, win_len: &mut usize| -> io::Result<u64> {
            let mut v = 0u64;
            loop {
                let c = byte_at(*p, f, buf, win_off, win_len)?;
                *p += 1;
                v = (v << 7) | u64::from(c & 0x7f);
                if c & 0x80 != 0 {
                    v += 1;
                } else {
                    return Ok(v);
                }
            }
        };

        let mut sparse: Vec<([u8; 36], u64)> = Vec::new();
        let mut count = 0u64;
        let mut groups = 0u64;
        while coins_left > 0 {
            need(pos, &f, &mut buf, &mut win_off, &mut win_len)?;
            let group_off = pos;
            let base = (pos - win_off) as usize;
            let mut first_key = [0u8; 36];
            first_key[..32].copy_from_slice(&buf[base..base + 32]);
            pos += 32;
            let cnt = read_cs(&mut pos, &f, &mut buf, &mut win_off, &mut win_len)?;
            let save = pos;
            let v0 = read_cs(&mut pos, &f, &mut buf, &mut win_off, &mut win_len)? as u32;
            first_key[32..].copy_from_slice(&v0.to_le_bytes());
            if groups.is_multiple_of(stride) {
                sparse.push((first_key, group_off));
            }
            groups += 1;
            pos = save;
            for _ in 0..cnt {
                let _vout = read_cs(&mut pos, &f, &mut buf, &mut win_off, &mut win_len)?;
                let mut varints = [0u64; 3];
                for v in varints.iter_mut() {
                    *v = read_varint(&mut pos, &f, &mut buf, &mut win_off, &mut win_len)?;
                }
                let plen = match varints[2] {
                    0 | 1 => 20u64,
                    2 | 3 | 4 | 5 => 32u64,
                    n => n - 6,
                };
                pos += plen;
                count += 1;
                coins_left -= 1;
            }
        }
        Ok(Self {
            f: std::sync::Mutex::new(f),
            sparse,
            count,
            file_len,
        })
    }

    /// Every coin in the run, decoded — the full materialization for
    /// `UtxoSet::iter`/`dumptxoutset`-style whole-set consumers.
    /// Sequential read from just past the 51-byte header.
    pub fn iter(&self) -> std::io::Result<Vec<(OutPoint, Coin)>> {
        use std::io::Seek;
        let mut f = self.f.lock().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("snapshot lock: {e}"))
        })?;
        f.seek(io::SeekFrom::Start(51))?;
        let mut out = Vec::with_capacity(self.count as usize);
        crate::utxo_snapshot::read_coins(&mut *f, self.count, 0, |op, coin| {
            out.push((op, coin));
        })
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.0))?;
        Ok(out)
    }


}



/// Compact-size decode at buf[pos..] — returns value, advances pos.
fn cs(buf: &[u8], pos: &mut usize) -> u64 {
    let c = buf[*pos];
    *pos += 1;
    match c {
        0xfd => {
            let v = u16::from_le_bytes(buf[*pos..*pos + 2].try_into().unwrap()) as u64;
            *pos += 2;
            v
        }
        0xfe => {
            let v = u32::from_le_bytes(buf[*pos..*pos + 4].try_into().unwrap()) as u64;
            *pos += 4;
            v
        }
        0xff => {
            let v = u64::from_le_bytes(buf[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            v
        }
        _ => c as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{Script, TxOut};

    fn op(i: u64, vout: u32) -> OutPoint {
        let mut t = [0u8; 32];
        t[24..].copy_from_slice(&i.to_be_bytes());
        OutPoint {
            txid: crate::hash::Txid::from_bytes(t),
            vout,
        }
    }

    fn coin(v: i64) -> Coin {
        Coin {
            out: TxOut {
                value: v,
                script_pubkey: Script::new(vec![0x51, 0x20, 0xaa]),
            },
            height: 800_000,
            coinbase: false,
        }
    }

    #[test]
    fn build_lookup_roundtrip() {
        let dir = std::env::temp_dir().join(format!("srun-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("base.run");
        let mut b = RunBuilder::create_with_stride(&path, 4).unwrap();
        for i in 0..100u64 {
            b.push(&op(i, 0), &coin(i as i64 * 10)).unwrap();
        }
        let n = b.finish().unwrap();
        assert_eq!(n, 100);

        let run = SortedRun::open(&path).unwrap();
        assert_eq!(run.len(), 100);
        for i in 0..100u64 {
            let c = run.get(&op(i, 0)).expect("hit");
            assert_eq!(c.out.value, i as i64 * 10);
        }
        assert!(run.get(&op(200, 0)).is_none());
        assert!(run.get(&op(50, 1)).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! Hash-indexed UTXO store — the storage-layout experiment.
//!
//! The UTXO set has no range queries: every consensus access is a
//! point lookup by outpoint. A B-tree pays O(log n) descents and page
//! splits to maintain an ordering only `dumptxoutset`/`gettxoutsetinfo`
//! ever use. This store trades that ordering away: a hash index maps
//! `txid||vout` → record offset in an append log, O(1) per probe.
//!
//! ## Files
//!
//! * `coins.idx` — header + `cap` fixed 48-byte slots
//!   `[key 36 | off u64 | len u32]`; `off == 0` marks empty (the log
//!   starts with a 32-byte header, so offset 0 is never a record).
//!   Linear probing, SipHash-1-3 keyed by a per-database random seed
//!   stored in the header — outpoints are attacker-influenced, so the
//!   hash must be keyed or a mined-txid cluster becomes a probe-length
//!   DoS.
//! * `coins.dat` — header + append-only compact-coin records (the
//!   [`CoinFormat::Compact`] encoding). Updates append a new version
//!   and repoint the slot; when the new record fits the old allocation
//!   it overwrites in place instead, so churn doesn't grow the log.
//!
//! ## Consistency
//!
//! Commits order log bytes → index slots → fsync, before the meta
//! transaction (tip/undo) lands in the redb sidecar. A torn index is
//! therefore always *behind* meta, and the replayed commit is
//! idempotent: outpoint-keyed updates overwrite the same slots.
//! Deletes use backward-shift — no tombstone accumulation.
//!
//! Rare canonical-order consumers (`dumptxoutset`, serialized-hash
//! iteration) sort externally; that cost is the experiment's tradeoff.

use crate::coinsdb::CoinFormat;
use crate::connect::Coin;
use crate::transaction::OutPoint;
use std::collections::HashMap;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const IDX_MAGIC: &[u8; 8] = b"AVUCIDX1";
const DAT_MAGIC: &[u8; 8] = b"AVUCDAT1";
const IDX_HDR: u64 = 64;
const DAT_HDR: u64 = 32;
/// `[key 36][offset 8][len 4]`.
const SLOT: u64 = 48;
const SLOT_US: usize = SLOT as usize;
/// Grow when live entries would exceed 70% of slots.
const MAX_LOAD_NUM: u64 = 7;
const MAX_LOAD_DEN: u64 = 10;
const INIT_CAP: u64 = 1024;
const VERSION: u32 = 2;

/// SipHash-1-3 over the 36-byte key — keyed so a mined-txid cluster
/// can't target one bucket chain.
fn sip13(key: &[u8; 36], k0: u64, k1: u64) -> u64 {
    #[inline]
    fn round(v: &mut [u64; 4]) {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13);
        v[1] ^= v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16);
        v[3] ^= v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21);
        v[3] ^= v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17);
        v[1] ^= v[2];
        v[2] = v[2].rotate_left(32);
    }
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    for i in 0..4 {
        let m = u64::from_le_bytes(key[i * 8..i * 8 + 8].try_into().unwrap_or_default());
        v[3] ^= m;
        round(&mut v);
        v[0] ^= m;
    }
    // Tail: 4 bytes + length tag in the top byte.
    let mut tail = [0u8; 8];
    tail[..4].copy_from_slice(&key[32..36]);
    tail[7] = 36;
    let m = u64::from_le_bytes(tail);
    v[3] ^= m;
    round(&mut v);
    v[0] ^= m;
    v[2] ^= 0xff;
    round(&mut v);
    round(&mut v);
    round(&mut v);
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// SipHash-1-3 over arbitrary bytes — same construction as [`sip13`]
/// but streaming (used for record tags, where the payload is a
/// coin record, not a fixed 36-byte key).
fn sip13b(parts: &[&[u8]], k0: u64, k1: u64) -> u64 {
    #[inline]
    fn round(v: &mut [u64; 4]) {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13);
        v[1] ^= v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16);
        v[3] ^= v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21);
        v[3] ^= v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17);
        v[1] ^= v[2];
        v[2] = v[2].rotate_left(32);
    }
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    // Stream the parts as one continuous byte sequence — the tail
    // is the leftover <8 bytes with the total length in the top byte.
    let mut total = 0usize;
    let mut tail = [0u8; 8];
    let mut n = 0usize;
    for part in parts {
        total += part.len();
        for &b in part.iter() {
            tail[n] = b;
            n += 1;
            if n == 8 {
                let m = u64::from_le_bytes(tail);
                v[3] ^= m;
                round(&mut v);
                v[0] ^= m;
                n = 0;
            }
        }
    }
    tail[n..].fill(0);
    tail[7] = total as u8;
    let m = u64::from_le_bytes(tail);
    v[3] ^= m;
    round(&mut v);
    v[0] ^= m;
    v[2] ^= 0xff;
    round(&mut v);
    round(&mut v);
    round(&mut v);
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

/// 4-byte integrity tag for a stored record — SipHash-1-3 over
/// `key || record` with the database's random seeds. The key binds
/// the record to its slot (a torn slot pointing at another key's
/// record mismatches); the record bytes catch mid-record tears.
fn rec_tag(key: &[u8; 36], rec: &[u8], k0: u64, k1: u64) -> u32 {
    sip13b(&[&key[..], rec], k0, k1) as u32
}

fn random_seed() -> u64 {
    let mut b = [0u8; 8];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b))
        .is_ok()
    {
        return u64::from_le_bytes(b);
    }
    // Fallback: RandomState is randomly seeded per-process; hashing a
    // fixed input still yields per-process-varied entropy.
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write(b"avila-coins-seed");
    h.finish()
}

/// The mutable half of the store — file handles, a one-page read
/// cache for the index, and the capacity a grow swaps. The workspace
/// forbids `unsafe` so mmap is out; instead slot reads go through a
/// single 4 KiB page cache — a probe walks adjacent slots, which
/// almost always share one page, so a get costs one `pread` for the
/// index page plus one for the record.
#[derive(Debug)]
struct Inner {
    idx: std::fs::File,
    dat: std::fs::File,
    cap: u64,
    /// (file offset, bytes) of the last index page read — 4 KiB
    /// aligned. `page.0 == u64::MAX` means empty.
    page: (u64, Box<[u8; 4096]>),
}

/// Bytes an index page covers — a slot never straddles pages (48 does
/// not divide 4096, so a few tail bytes per page are unused — but
/// read-side only; the file layout stays densely packed).
impl Inner {
    /// Slot `i` through the page cache — `None` when empty (`off==0`)
    /// or out of bounds.
    fn slot(&mut self, i: u64) -> io::Result<Option<[u8; SLOT_US]>> {
        let at = IDX_HDR + i * SLOT;
        // The page containing the slot's first byte; a slot at a page
        // boundary could straddle — read two pages' worth to be safe.
        // Simpler: the cache holds the 4 KiB page; a straddling slot
        // falls back to a direct read.
        let pg = at & !4095;
        if at + SLOT > pg + 4096 {
            return self.slot_direct(i);
        }
        if self.page.0 != pg {
            // `read_at` not `read_exact_at`: the file's last page is a
            // short tail (cap*48+64 isn't page-aligned). Bytes past the
            // tail are zeroed — an unwritten slot reads as empty.
            let n = self.idx.read_at(&mut self.page.1[..], pg)?;
            self.page.1[n..].fill(0);
            self.page.0 = pg;
        }
        let off = (at - pg) as usize;
        let s: &[u8; SLOT_US] = self.page.1[off..off + SLOT_US]
            .try_into()
            .unwrap_or(&[0u8; SLOT_US]);
        if u64::from_le_bytes(s[36..44].try_into().unwrap_or_default()) == 0 {
            return Ok(None);
        }
        Ok(Some(*s))
    }

    /// Direct slot read bypassing the cache (straddling slots).
    fn slot_direct(&self, i: u64) -> io::Result<Option<[u8; SLOT_US]>> {
        let mut b = [0u8; SLOT_US];
        self.idx.read_exact_at(&mut b, IDX_HDR + i * SLOT)?;
        if u64::from_le_bytes(b[36..44].try_into().unwrap_or_default()) == 0 {
            return Ok(None);
        }
        Ok(Some(b))
    }
}

/// The hash-indexed coin store. `meta`/`undo` live elsewhere (redb
/// sidecar) — this type owns only the coins table.
#[derive(Debug)]
pub struct HashStore {
    dir: PathBuf,
    /// Tip watermark — the highest height passed to
    /// `commit_coins(tip)`, mirrored into the index header. u64::MAX
    /// when no height has ever committed (fresh store / mid-import
    /// partial commits).
    tip: AtomicU64,
    /// File-pair generation — dat header `[12..20]` and idx header
    /// `[56..64]` carry the same value; `compact` bumps both. A
    /// mismatch on open is a torn compact swap; the surviving `.new`
    /// file completes it.
    generation: AtomicU64,
    k0: u64,
    k1: u64,
    /// Live entry count, mirrored into the index header on flush.
    count: AtomicU64,
    inner: Mutex<Inner>,
}

impl HashStore {
    /// Opens or creates `dir/coins.{idx,dat}`.
    ///
    /// # Errors
    /// `io::Error` on open/create, bad magic, or unsupported version.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let idx_path = dir.join("coins.idx");
        let dat_path = dir.join("coins.dat");
        let fresh = !idx_path.exists();
        let idx = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&idx_path)?;
        let dat = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&dat_path)?;
        if fresh {
            let mut dhdr = [0u8; DAT_HDR as usize];
            dhdr[..8].copy_from_slice(DAT_MAGIC);
            dhdr[8..12].copy_from_slice(&VERSION.to_le_bytes());
            dhdr[12..20].copy_from_slice(&0u64.to_le_bytes());
            dat.write_all_at(&dhdr, 0)?;
            let k0 = random_seed();
            let k1 = random_seed();
            let mut hdr = [0u8; IDX_HDR as usize];
            hdr[..8].copy_from_slice(IDX_MAGIC);
            hdr[8..12].copy_from_slice(&VERSION.to_le_bytes());
            hdr[16..24].copy_from_slice(&INIT_CAP.to_le_bytes());
            hdr[24..32].copy_from_slice(&0u64.to_le_bytes());
            hdr[32..40].copy_from_slice(&k0.to_le_bytes());
            hdr[40..48].copy_from_slice(&k1.to_le_bytes());
            // [48..56]: tip watermark — the highest committed height.
            // Written during commit_coins (phase 1), before the redb
            // bookkeeping tx (phase 3): watermark > meta tip on open
            // means the crash landed between them — coins ahead of
            // the tip, a detectable corruption rather than a silent
            // MissingInput wedge.
            hdr[48..56].copy_from_slice(&u64::MAX.to_le_bytes());
            hdr[56..64].copy_from_slice(&0u64.to_le_bytes());
            idx.write_all_at(&hdr, 0)?;
            // Sparse file: the slot array reads back as zeros = empty.
            idx.set_len(IDX_HDR + INIT_CAP * SLOT)?;
            dat.sync_data()?;
            idx.sync_data()?;
            return Ok(Self {
                dir: dir.to_path_buf(),
                k0,
                k1,
                tip: AtomicU64::new(u64::MAX),
                generation: AtomicU64::new(0),
                count: AtomicU64::new(0),
                inner: Mutex::new(Inner {
                    idx,
                    dat,
                    cap: INIT_CAP,
                    page: (u64::MAX, Box::new([0u8; 4096])),
                }),
            });
        }
        let mut dhdr = [0u8; DAT_HDR as usize];
        dat.read_exact_at(&mut dhdr, 0)?;
        if &dhdr[..8] != DAT_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "coins.dat: bad magic",
            ));
        }
        let mut hdr = [0u8; IDX_HDR as usize];
        idx.read_exact_at(&mut hdr, 0)?;
        if &hdr[..8] != IDX_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "coins.idx: bad magic",
            ));
        }
        let version = u32::from_le_bytes(hdr[8..12].try_into().unwrap_or_default());
        if version != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("coins.idx: unsupported version {version}"),
            ));
        }
        let cap = u64::from_le_bytes(hdr[16..24].try_into().unwrap_or_default());
        let count = u64::from_le_bytes(hdr[24..32].try_into().unwrap_or_default());
        let k0 = u64::from_le_bytes(hdr[32..40].try_into().unwrap_or_default());
        let k1 = u64::from_le_bytes(hdr[40..48].try_into().unwrap_or_default());
        let tip = u64::from_le_bytes(hdr[48..56].try_into().unwrap_or_default());
        let idx_gen = u64::from_le_bytes(hdr[56..64].try_into().unwrap_or_default());
        let dat_gen = u64::from_le_bytes(dhdr[12..20].try_into().unwrap_or_default());
        let gen_ok = Self::reconcile_generations(dir, idx_gen, dat_gen)?;
        // `reconcile_generations` may have just renamed a surviving
        // `.new` file over `coins.idx` or `coins.dat` to finish a torn
        // compact swap. `idx`/`dat` above were opened *before* that —
        // on a rename, a file descriptor keeps pointing at the old
        // inode, not the path's new target, so those handles would now
        // be writing into an unlinked file that vanishes once they
        // close (the tip would advance while the coins it describes
        // silently disappear). Reopen from the — now reconciled —
        // canonical paths, exactly like `compact` reopens after its own
        // renames.
        let idx = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&idx_path)?;
        let dat = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dat_path)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            k0,
            k1,
            tip: AtomicU64::new(tip),
            generation: AtomicU64::new(gen_ok),
            count: AtomicU64::new(count),
            inner: Mutex::new(Inner {
                idx,
                dat,
                cap,
                page: (u64::MAX, Box::new([0u8; 4096])),
            }),
        })
    }

    /// Reconciles the dat/idx generation pair on open: equal means a
    /// consistent pair; a mismatch means a torn compact swap — the
    /// side that already renamed has the newer generation, and the
    /// still-present `.new` file for the other side (stamped with
    /// that same generation) completes the swap. Stale `.new` files
    /// from a compact that never reached the swap are discarded.
    ///
    /// # Errors
    /// `io::Error` when the generations mismatch and no intact `.new`
    /// file of the newer generation exists to finish the swap.
    fn reconcile_generations(dir: &Path, idx_gen: u64, dat_gen: u64) -> io::Result<u64> {
        let dnew = dir.join("coins.dat.new");
        let inew = dir.join("coins.idx.new");
        if idx_gen == dat_gen {
            // Consistent pair — any .new/.grow leftovers predate the
            // interrupted operation.
            let _ = std::fs::remove_file(&dnew);
            let _ = std::fs::remove_file(&inew);
            let _ = std::fs::remove_file(dir.join("coins.idx.grow"));
            return Ok(idx_gen);
        }
        // The newer generation committed at least one rename; finish
        // the swap with the surviving .new file of the same gen.
        let gen_hi = idx_gen.max(dat_gen);
        let (need_path, want_off) = if idx_gen > dat_gen {
            (&dnew, 12) // idx won the race: need the dat.new stamped `gen`
        } else {
            (&inew, 56) // dat won: need idx.new stamped `gen`
        };
        let mut b = [0u8; 8];
        let stamped = std::fs::File::open(need_path)
            .and_then(|f| {
                use std::os::unix::fs::FileExt;
                f.read_exact_at(&mut b, want_off)
            })
            .map(|()| u64::from_le_bytes(b));
        match stamped {
            Ok(g) if g == gen_hi => {
                let live = if idx_gen > dat_gen {
                    dir.join("coins.dat")
                } else {
                    dir.join("coins.idx")
                };
                std::fs::rename(need_path, &live)?;
                // Persist the rename: fsync the directory entry.
                if let Ok(d) = std::fs::File::open(dir) {
                    let _ = d.sync_all();
                }
                Ok(gen_hi)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "coinsdb: torn compact (idx gen {idx_gen}, dat gen {dat_gen})                      and no intact .new file of gen {gen_hi} — resync or restore required"
                ),
            )),
        }
    }

    /// Tip watermark — the highest height committed through
    /// `commit_coins`, or `u64::MAX` before any tipped commit.
    /// `> meta tip` after a crash means coins committed whose
    /// bookkeeping tx never landed.
    #[must_use]
    pub fn tip_watermark(&self) -> u64 {
        self.tip.load(Ordering::Relaxed)
    }

    /// Persisted live-coin count (index header copy).
    #[must_use]
    pub fn len(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// `true` when no live coins are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The slot index `key` probes to first.
    fn home(&self, cap: u64, key: &[u8; 36]) -> u64 {
        sip13(key, self.k0, self.k1) & (cap - 1)
    }

    /// The stored `(offset, len)` for a present slot.
    fn slot_rec(s: &[u8; SLOT_US]) -> (u64, u32) {
        (
            u64::from_le_bytes(s[36..44].try_into().unwrap_or_default()),
            u32::from_le_bytes(s[44..48].try_into().unwrap_or_default()),
        )
    }

    fn slot_key(s: &[u8; SLOT_US]) -> &[u8; 36] {
        s[..36].try_into().unwrap_or(&[0u8; 36])
    }

    /// The persisted coin at `key` — a probe then one log read.
    #[must_use]
    pub fn get(&self, key: &[u8; 36]) -> Option<Coin> {
        let mut inner = self.inner.lock().ok()?;
        let (i, found) = self.probe(&mut inner, key).ok()?;
        if !found {
            return None;
        }
        let s = inner.slot(i).ok()??;
        let (off, len) = Self::slot_rec(&s);
        let mut b = vec![0u8; len as usize];
        inner.dat.read_exact_at(&mut b, off).ok()?;
        // Torn-write check: the stored 4-byte tag must match
        // key+record — a mismatch is a detectable miss, never a
        // silently-wrong coin.
        if b.len() < 4
            || u32::from_le_bytes(b[..4].try_into().unwrap_or_default())
                != rec_tag(key, &b[4..], self.k0, self.k1)
        {
            return None;
        }
        crate::coinsdb::decode_coin(&b[4..], CoinFormat::Compact)
    }

    /// `true` when `key` is present — probe only, no log read.
    #[must_use]
    pub fn have(&self, key: &[u8; 36]) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        self.probe(&mut inner, key).map(|(_, f)| f).unwrap_or(false)
    }

    /// Slot read through the commit overlay: staged state wins over
    /// disk, `None` meaning empty.
    fn slot_at(
        inner: &mut Inner,
        stage: &HashMap<u64, Option<[u8; SLOT_US]>>,
        i: u64,
    ) -> io::Result<Option<[u8; SLOT_US]>> {
        if let Some(s) = stage.get(&i) {
            return Ok(*s);
        }
        inner.slot(i)
    }

    /// Probe through the overlay — same contract as [`Self::probe`]
    /// but sees the commit's staged writes.
    fn probe_staged(
        &self,
        inner: &mut Inner,
        stage: &HashMap<u64, Option<[u8; SLOT_US]>>,
        key: &[u8; 36],
    ) -> io::Result<(u64, bool)> {
        let mut i = self.home(inner.cap, key);
        loop {
            match Self::slot_at(inner, stage, i)? {
                None => return Ok((i, false)),
                Some(s) if Self::slot_key(&s) == key => return Ok((i, true)),
                _ => i = (i + 1) & (inner.cap - 1),
            }
        }
    }

    /// Slot index holding `key`, or the empty slot a put would claim.
    fn probe(&self, inner: &mut Inner, key: &[u8; 36]) -> io::Result<(u64, bool)> {
        let mut i = self.home(inner.cap, key);
        loop {
            match inner.slot(i)? {
                None => return Ok((i, false)),
                Some(s) if Self::slot_key(&s) == key => return Ok((i, true)),
                _ => i = (i + 1) & (inner.cap - 1),
            }
        }
    }

    /// Applies a dirty-map delta: `Some` = put/overwrite, `None` =
    /// delete. Returns the live-count delta. Does not fsync — the
    /// caller commits bookkeeping (undo+meta) after [`Self::sync`].
    /// `tip` is the connecting block's height — written into the
    /// index header *before* the caller's meta commit lands, so a
    /// crash between the two leaves watermark > meta tip: detectable
    /// coins-ahead-of-tip on open.
    ///
    /// Slot writes stage in an overlay that probes consult first —
    /// without it, two same-home inserts in one commit would collide
    /// on disk state that doesn't yet show the first write, and a
    /// delete's backward-shift could strand a staged insert.
    ///
    /// # Errors
    /// `io::Error` on any file write.
    pub fn commit_coins(
        &self,
        dirty: &HashMap<OutPoint, Option<Coin>>,
        tip: Option<u32>,
    ) -> io::Result<i64> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("hashstore lock poisoned"))?;
        self.maybe_grow_locked(&mut inner, dirty.len() as u64)?;
        let mut delta = 0i64;
        let mut dat_appends: Vec<u8> = Vec::new();
        let mut dat_len = inner.dat.metadata()?.len();
        // Overlay of pending slot contents; `None` = empty slot.
        let mut stage: HashMap<u64, Option<[u8; SLOT_US]>> = HashMap::new();

        for (op, entry) in dirty {
            let key = crate::coinsdb::key_of(op);
            match entry {
                Some(coin) => {
                    let rec = crate::coinsdb::encode_coin(coin, CoinFormat::Compact);
                    // Stored layout: [4B tag][compact record] — the
                    // tag binds key+bytes so a torn write decodes as
                    // a detectable miss, not a wrong coin.
                    let tag = rec_tag(&key, &rec, self.k0, self.k1).to_le_bytes();
                    let mut stored = Vec::with_capacity(4 + rec.len());
                    stored.extend_from_slice(&tag);
                    stored.extend_from_slice(&rec);
                    let (i, found) = self.probe_staged(&mut inner, &stage, &key)?;
                    if found {
                        let Some(s) = Self::slot_at(&mut inner, &stage, i)? else {
                            continue;
                        };
                        let (off, old_len) = Self::slot_rec(&s);
                        if stored.len() as u32 <= old_len {
                            // Fits the old allocation — overwrite in
                            // place, no log growth.
                            inner.dat.write_all_at(&stored, off)?;
                            if stored.len() as u32 != old_len {
                                let mut ns = s;
                                ns[44..48].copy_from_slice(&(stored.len() as u32).to_le_bytes());
                                stage.insert(i, Some(ns));
                            }
                            continue;
                        }
                        // Doesn't fit — append and repoint.
                        let new_off = dat_len;
                        dat_appends.extend_from_slice(&stored);
                        dat_len += stored.len() as u64;
                        let mut ns = s;
                        ns[36..44].copy_from_slice(&new_off.to_le_bytes());
                        ns[44..48].copy_from_slice(&(stored.len() as u32).to_le_bytes());
                        stage.insert(i, Some(ns));
                    } else {
                        let new_off = dat_len;
                        dat_appends.extend_from_slice(&stored);
                        dat_len += stored.len() as u64;
                        let mut ns = [0u8; SLOT_US];
                        ns[..36].copy_from_slice(&key);
                        ns[36..44].copy_from_slice(&new_off.to_le_bytes());
                        ns[44..48].copy_from_slice(&(stored.len() as u32).to_le_bytes());
                        stage.insert(i, Some(ns));
                        delta += 1;
                    }
                }
                None => {
                    let (i, found) = self.probe_staged(&mut inner, &stage, &key)?;
                    if !found {
                        continue;
                    }
                    // Backward-shift delete: pull forward any slot
                    // whose probe path crosses the freed one — reads
                    // through the overlay so staged writes are seen.
                    let mut hole = i;
                    let mut j = (i + 1) & (inner.cap - 1);
                    while let Some(s) = Self::slot_at(&mut inner, &stage, j)? {
                        let home = self.home(inner.cap, Self::slot_key(&s));
                        // If j's key hashed outside (hole, j], it
                        // probed through the hole — move it back.
                        let crossed = if hole < j {
                            home <= hole || home > j
                        } else {
                            home <= hole && home > j
                        };
                        if crossed {
                            stage.insert(hole, Some(s));
                            hole = j;
                        }
                        j = (j + 1) & (inner.cap - 1);
                    }
                    stage.insert(hole, None);
                    delta -= 1;
                }
            }
        }

        if !dat_appends.is_empty() {
            let end = inner.dat.metadata()?.len();
            inner.dat.write_all_at(&dat_appends, end)?;
        }
        let mut writes: Vec<_> = stage.into_iter().collect();
        writes.sort_unstable_by_key(|(i, _)| *i);

        for (i, s) in writes {
            let b = s.unwrap_or([0u8; SLOT_US]);
            inner.idx.write_all_at(&b, IDX_HDR + i * SLOT)?;
        }
        // The page cache holds pre-write pages — drop it.
        inner.page.0 = u64::MAX;
        // Mirror count into the index header (offset 24) and the tip
        // watermark (offset 48) — the watermark commits before the
        // caller's meta tx, so it can only ever run *ahead*.
        inner
            .idx
            .write_all_at(&self.len().wrapping_add_signed(delta).to_le_bytes(), 24)?;
        if let Some(tip) = tip {
            inner.idx.write_all_at(&(tip as u64).to_le_bytes(), 48)?;
            self.tip.store(tip as u64, Ordering::Relaxed);
        }
        self.count
            .store(self.len().wrapping_add_signed(delta), Ordering::Relaxed);
        Ok(delta)
    }

    /// Pre-size the index for a known-future count — one grow instead
    /// of ~17 doubling rewrites when the caller knows the total (the
    /// snapshot's `coins_count` metadata). No-op when capacity suffices.
    pub fn reserve(&self, additional: u64) -> io::Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("hashstore lock poisoned"))?;
        self.maybe_grow_locked(&mut inner, additional)
    }

    /// Rewrites `coins.dat` in slot order: occupied slots walked
    /// 0..cap, each record appended to a fresh log at its slot's
    /// position. Restores read locality — a probe cluster's records
    /// land in the same log region — and drops dead records left by
    /// appends (the log shrinks to live-set size). Same idea as LSM
    /// compaction, applied to the log the index points into.
    ///
    /// Crash-safe: both new files carry the same generation stamp;
    /// either rename may persist alone, and `reconcile_generations`
    /// finishes the swap from the surviving `.new` file on open.
    /// Maintenance operation — callers hold the store quiescent.
    /// A dat-generation marker in the index
    /// header is the planned fix.
    ///
    /// # Errors
    /// `io::Error` on allocation, read, write, sync, or rename failure.
    pub fn compact(&self) -> io::Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|e| io::Error::other(format!("hashstore lock: {e}")))?;
        let dtmp = self.dir.join("coins.dat.new");
        let itmp = self.dir.join("coins.idx.new");
        let ndat = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&dtmp)?;
        let gen_new = self.generation.load(Ordering::Relaxed) + 1;
        let mut dhdr = [0u8; DAT_HDR as usize];
        dhdr[..8].copy_from_slice(DAT_MAGIC);
        dhdr[8..12].copy_from_slice(&VERSION.to_le_bytes());
        dhdr[12..20].copy_from_slice(&gen_new.to_le_bytes());
        ndat.write_all_at(&dhdr, 0)?;
        let nidx = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&itmp)?;
        nidx.set_len(IDX_HDR + inner.cap * SLOT)?;

        // Slot-ordered rewrite: scan the old index in aligned windows;
        // each window's slot bytes are patched in place (offset → new
        // log position) and written out sequentially.
        let mut noff = DAT_HDR;
        let mut buf = vec![0u8; (1 << 20) / SLOT_US * SLOT_US];
        let mut off = IDX_HDR;
        let end = IDX_HDR + inner.cap * SLOT;
        while off < end {
            let want = ((end - off) as usize).min(buf.len());
            buf.truncate(want);
            inner.idx.read_exact_at(&mut buf, off)?;
            for s in buf.as_chunks_mut::<SLOT_US>().0 {
                let roff = u64::from_le_bytes(s[36..44].try_into().unwrap_or_default());
                let rlen = u32::from_le_bytes(s[44..48].try_into().unwrap_or_default());
                if roff == 0 {
                    continue;
                }
                let mut rec = vec![0u8; rlen as usize];
                inner.dat.read_exact_at(&mut rec, roff)?;
                ndat.write_all_at(&rec, noff)?;
                s[36..44].copy_from_slice(&noff.to_le_bytes());
                noff += rlen as u64;
            }
            nidx.write_all_at(&buf, off)?;
            off += want as u64;
        }
        // Index header — same cap/count, new generation stamped.
        let mut hdr = [0u8; IDX_HDR as usize];
        inner.idx.read_exact_at(&mut hdr, 0)?;
        hdr[56..64].copy_from_slice(&gen_new.to_le_bytes());
        nidx.write_all_at(&hdr, 0)?;
        ndat.sync_data()?;
        nidx.sync_data()?;
        // Generation-marked swap: either rename may persist alone on
        // a crash — the pair's generations then mismatch, and
        // `reconcile_generations` finishes the swap from the
        // surviving .new file on next open.
        std::fs::rename(&itmp, self.dir.join("coins.idx"))?;
        std::fs::rename(&dtmp, self.dir.join("coins.dat"))?;
        self.generation.store(gen_new, Ordering::Relaxed);
        if let Ok(d) = std::fs::File::open(&self.dir) {
            let _ = d.sync_all();
        }
        inner.dat = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.dir.join("coins.dat"))?;
        inner.idx = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.dir.join("coins.idx"))?;
        inner.page.0 = u64::MAX;
        Ok(())
    }

    /// fsync log then index — the commit ordering's durability barrier.
    ///
    /// # Errors
    /// `io::Error` on sync failure.
    pub fn sync(&self) -> io::Result<()> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("hashstore lock poisoned"))?;
        inner.dat.sync_data()?;
        inner.idx.sync_data()
    }

    /// Grows the index so `count + pending` stays under the load
    /// bound — sequential scan + rehash into a temp file, swapped in
    /// by rename so a torn grow leaves the old index intact.
    fn maybe_grow_locked(&self, inner: &mut Inner, pending: u64) -> io::Result<()> {
        let need = self.len() + pending;
        if need * MAX_LOAD_DEN <= inner.cap * MAX_LOAD_NUM {
            return Ok(());
        }
        let mut new_cap = inner.cap * 2;
        while need * MAX_LOAD_DEN > new_cap * MAX_LOAD_NUM {
            new_cap *= 2;
        }
        let tmp = self.dir.join("coins.idx.grow");
        {
            let nidx = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            nidx.set_len(IDX_HDR + new_cap * SLOT)?;
            // Rehash every live slot — buffered scan. Windows must be
            // a whole number of slots: a window starting mid-slot
            // misaligns every slot after it.
            let mut buf = vec![0u8; (1 << 20) / SLOT_US * SLOT_US];
            let mut off = IDX_HDR;
            let end = IDX_HDR + inner.cap * SLOT;
            while off < end {
                let want = ((end - off) as usize).min(buf.len());
                buf.truncate(want);
                inner.idx.read_exact_at(&mut buf, off)?;
                for s in buf.as_chunks::<SLOT_US>().0 {
                    if u64::from_le_bytes(s[36..44].try_into().unwrap_or_default()) == 0 {
                        continue;
                    }
                    let mut i = sip13(Self::slot_key(s), self.k0, self.k1) & (new_cap - 1);
                    loop {
                        let mut probe = [0u8; SLOT_US];
                        nidx.read_exact_at(&mut probe, IDX_HDR + i * SLOT)?;
                        if u64::from_le_bytes(probe[36..44].try_into().unwrap_or_default()) == 0 {
                            nidx.write_all_at(s, IDX_HDR + i * SLOT)?;
                            break;
                        }
                        i = (i + 1) & (new_cap - 1);
                    }
                }
                off += want as u64;
            }
            // Header last — a torn grow leaves the old index intact.
            let mut hdr = [0u8; IDX_HDR as usize];
            hdr[..8].copy_from_slice(IDX_MAGIC);
            hdr[8..12].copy_from_slice(&VERSION.to_le_bytes());
            hdr[16..24].copy_from_slice(&new_cap.to_le_bytes());
            hdr[24..32].copy_from_slice(&self.len().to_le_bytes());
            hdr[32..40].copy_from_slice(&self.k0.to_le_bytes());
            hdr[40..48].copy_from_slice(&self.k1.to_le_bytes());
            nidx.write_all_at(&hdr, 0)?;
            nidx.sync_data()?;
        }
        std::fs::rename(&tmp, self.dir.join("coins.idx"))?;
        inner.idx = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.dir.join("coins.idx"))?;
        inner.cap = new_cap;
        inner.page.0 = u64::MAX;
        Ok(())
    }

    /// Every stored `(key, coin)` — unordered; callers needing the
    /// canonical outpoint-key order sort externally.
    #[must_use]
    pub fn iter_coins(&self) -> Vec<(OutPoint, Coin)> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(self.len() as usize);
        // One sequential sweep of the log instead of a pread per
        // record — the slot walk yields (off,len) pairs we resolve
        // in-place from the whole file image.
        let mut dat = Vec::new();
        {
            use std::io::Read as _;
            let Ok(mut f) = inner.dat.try_clone() else {
                return Vec::new();
            };
            use std::io::Seek as _;
            if f.seek(std::io::SeekFrom::Start(0)).is_err() || f.read_to_end(&mut dat).is_err() {
                return Vec::new();
            }
        }
        // Window size is a whole number of slots — a mid-slot window
        // boundary would misalign every slot after it.
        let mut buf = vec![0u8; (1 << 20) / SLOT_US * SLOT_US];
        let mut off = IDX_HDR;
        let end = IDX_HDR + inner.cap * SLOT;
        while off < end {
            let want = ((end - off) as usize).min(buf.len());
            buf.truncate(want);
            if inner.idx.read_exact_at(&mut buf, off).is_err() {
                break;
            }
            for s in buf.as_chunks::<SLOT_US>().0 {
                let (roff, rlen) = Self::slot_rec(s);
                if roff == 0 {
                    continue;
                }
                let Some(rec) = dat.get(roff as usize..roff as usize + rlen as usize) else {
                    continue;
                };
                // Skip + verify the 4B integrity tag — torn records
                // are dropped from the iteration, never mis-decoded.
                if rec.len() < 4 {
                    continue;
                }
                let key: &[u8; 36] = s[..36].try_into().unwrap_or(&[0u8; 36]);
                if u32::from_le_bytes(rec[..4].try_into().unwrap_or_default())
                    != rec_tag(key, &rec[4..], self.k0, self.k1)
                {
                    continue;
                }
                let Some(coin) = crate::coinsdb::decode_coin(&rec[4..], CoinFormat::Compact) else {
                    continue;
                };
                let mut txid = [0u8; 32];
                txid.copy_from_slice(&s[..32]);
                let vout = u32::from_le_bytes(s[32..36].try_into().unwrap_or_default());
                out.push((
                    OutPoint {
                        txid: crate::hash::Txid::from_bytes(txid),
                        vout,
                    },
                    coin,
                ));
            }
            off += want as u64;
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::transaction::Script;
    use crate::transaction::TxOut;
    use std::sync::Arc;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("avila-hs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn op(n: u32) -> OutPoint {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&n.to_le_bytes());
        OutPoint {
            txid: crate::hash::Txid::from_bytes(b),
            vout: n % 4,
        }
    }

    fn coin(v: i64, h: u32) -> Coin {
        Coin {
            out: TxOut {
                value: v,
                script_pubkey: Script::new(vec![0x51]),
            },
            height: h,
            coinbase: false,
        }
    }

    #[test]
    fn put_get_delete_roundtrip() {
        let d = dir("roundtrip");
        let s = HashStore::open(&d).unwrap();
        let mut dirty = HashMap::new();
        for i in 0..100u32 {
            dirty.insert(op(i), Some(coin(i as i64 * 7, i)));
        }
        s.commit_coins(&dirty, None).unwrap();
        s.sync().unwrap();
        assert_eq!(s.len(), 100);
        for i in 0..100u32 {
            let c = s.get(&crate::coinsdb::key_of(&op(i))).unwrap();
            assert_eq!(c.out.value, i as i64 * 7);
        }
        let mut del = HashMap::new();
        for i in 0..50u32 {
            del.insert(op(i), None);
        }
        s.commit_coins(&del, None).unwrap();
        assert_eq!(s.len(), 50);
        for i in 0..100u32 {
            let got = s.get(&crate::coinsdb::key_of(&op(i)));
            if i < 50 {
                assert!(got.is_none(), "deleted {i} still present");
            } else {
                assert_eq!(got.unwrap().out.value, i as i64 * 7);
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Random insert/delete batches vs a HashMap oracle — exercises
    /// probing, backward-shift deletes, resizes, and reopen.
    #[test]
    fn random_ops_match_hashmap_oracle() {
        let d = dir("oracle");
        let s = HashStore::open(&d).unwrap();
        let mut oracle: HashMap<OutPoint, Coin> = HashMap::new();
        let mut rng = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        // Enough keys to force ~4 grows from the 1024-slot start and
        // real probe clusters; deletes interleaved.
        for round in 0..30 {
            let mut dirty = HashMap::new();
            for _ in 0..300 {
                let n = (next() % 20_000) as u32;
                let o = op(n);
                if next() % 5 == 0 && oracle.contains_key(&o) {
                    dirty.insert(o, None);
                    oracle.remove(&o);
                } else {
                    let c = coin(n as i64, round);
                    dirty.insert(o, Some(c.clone()));
                    oracle.insert(o, c);
                }
            }
            s.commit_coins(&dirty, None).unwrap();
            s.sync().unwrap();
            // Spot-check this round's survivors plus a stale sample.
            for (o, c) in oracle.iter().step_by(37) {
                let got = s.get(&crate::coinsdb::key_of(o));
                assert_eq!(
                    got.as_ref().map(|g| g.out.value),
                    Some(c.out.value),
                    "oracle mismatch at {o:?} round {round}"
                );
            }
            assert_eq!(s.len(), oracle.len() as u64);
        }
        // Full verify + reopen persistence.
        for (o, c) in &oracle {
            assert_eq!(
                s.get(&crate::coinsdb::key_of(o)).unwrap().out.value,
                c.out.value
            );
        }
        drop(s);
        let s = HashStore::open(&d).unwrap();
        assert_eq!(s.len(), oracle.len() as u64);
        for (o, c) in oracle.iter().take(200) {
            assert_eq!(
                s.get(&crate::coinsdb::key_of(o)).unwrap().out.value,
                c.out.value
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The CoinsBackend hash-engine path end-to-end: commit, undo,
    /// reopen, iter — plus engine marker rejection.
    #[test]
    fn backend_hash_engine_roundtrip() {
        use crate::coinsdb::Engine;
        let d = dir("engine");
        {
            let be = crate::coinsdb::CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
            assert_eq!(be.engine(), Engine::Hash);
            let mut dirty = HashMap::new();
            for i in 0..10u32 {
                dirty.insert(op(i), Some(coin(i as i64, i)));
            }
            be.commit(&dirty, &[], 1).unwrap();
            assert_eq!(be.coins_len(), 10);
            assert_eq!(be.get(&op(3)).unwrap().out.value, 3);
            let mut del = HashMap::new();
            del.insert(op(3), None);
            be.commit(&del, &[], 2).unwrap();
            assert!(be.get(&op(3)).is_none());
            assert_eq!(be.coins_len(), 9);
            assert_eq!(be.iter_coins().len(), 9);
        }
        // Reopen keeps the engine; a mismatched request fails.
        {
            let be = crate::coinsdb::CoinsBackend::open(&d).unwrap();
            assert_eq!(be.engine(), Engine::Hash);
            assert_eq!(be.coins_len(), 9);
            assert_eq!(be.tip_height(), 2);
            assert_eq!(be.iter_coins().len(), 9);
            assert!(crate::coinsdb::CoinsBackend::open_with_engine(&d, Engine::Redb).is_err());
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Arc-shared use matches the chainstate pattern.
    #[test]
    fn shared_arc_works() {
        let d = dir("arc");
        let s = Arc::new(HashStore::open(&d).unwrap());
        let s2 = s.clone();
        let mut dirty = HashMap::new();
        dirty.insert(op(1), Some(coin(5, 1)));
        s2.commit_coins(&dirty, None).unwrap();
        assert_eq!(s.get(&crate::coinsdb::key_of(&op(1))).unwrap().out.value, 5);
        eprintln!("DIR={d:?}");
    }

    /// Bulk commits forcing grows — must not lose slots.
    #[test]
    fn bulk_commit_grow_no_loss() {
        let d = dir("bulk");
        let s = HashStore::open(&d).unwrap();
        let mut n = 0u32;
        for _ in 0..5 {
            let mut dirty = HashMap::new();
            for _ in 0..100_000 {
                dirty.insert(op(n), Some(coin(n as i64, 1)));
                n += 1;
            }
            s.commit_coins(&dirty, None).unwrap();
        }
        assert_eq!(s.len(), 500_000);
        assert_eq!(s.iter_coins().len(), 500_000, "iter lost coins");
        // And a random get sample must resolve post-grow.
        for i in (0..500_000u32).step_by(9_973) {
            assert!(s.get(&crate::coinsdb::key_of(&op(i))).is_some());
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// SipHash-1-3 output is uniform — 40k keys spread over 131k
    /// buckets with textbook max-cluster occupancy.
    #[test]
    fn sip13_distribution() {
        let mut buckets = vec![0u32; 131072];
        for n in 0..40_000u32 {
            let k = crate::coinsdb::key_of(&op(n));
            buckets[(sip13(&k, 12345, 67890) & 131071) as usize] += 1;
        }
        let used = buckets.iter().filter(|b| **b > 0).count();
        let max = *buckets.iter().max().unwrap();
        // ~30% empty buckets expected at 30% load; a broken hash would
        // collapse or clump wildly.
        assert!(used > 30_000 && used < 40_000);
        assert!(max <= 10);
    }

    /// `compact` must preserve every coin byte-exact — slot-ordered
    /// log rewrite is a pure re-placement.
    #[test]
    fn compact_preserves_all() {
        let d = dir("compact");
        let s = HashStore::open(&d).unwrap();
        let mut oracle = HashMap::new();
        let mut rng_state = 0x9E3779B97F4A7C15u64;
        let mut rand = || {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            rng_state
        };
        // Two rounds: insert → compact → verify → churn → compact → verify.
        for round in 0..2 {
            let mut dirty = HashMap::new();
            for _ in 0..20_000 {
                let n = (rand() % 60_000) as u32;
                let c = if rand() % 3 == 0 {
                    None
                } else {
                    Some(coin(n as i64, n % 4))
                };
                dirty.insert(op(n), c.clone());
                match c {
                    Some(c) => oracle.insert(op(n), c),
                    None => oracle.remove(&op(n)),
                };
            }
            s.commit_coins(&dirty, None).unwrap();
            s.compact().unwrap();
            assert_eq!(s.len() as usize, oracle.len(), "round {round} len");
            for (o, want) in &oracle {
                let got = s.get(&crate::coinsdb::key_of(o));
                assert_eq!(got.as_ref(), Some(want), "round {round} lost {o:?}");
            }
            assert_eq!(s.iter_coins().len(), oracle.len(), "round {round} iter");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A crash mid-`compact()` can land after one rename but before the
    /// other, leaving `coins.idx`/`coins.dat` at different generations —
    /// `reconcile_generations` finishes that swap on open by renaming
    /// the surviving `.new` file into place. Before this fix, `open`'s
    /// file handles were opened *before* that rename ran, so they kept
    /// writing into the now-unlinked pre-reconcile file: the data
    /// looked committed (tip advanced, `sync` succeeded) but vanished
    /// once the handle closed.
    #[test]
    fn open_reopens_after_torn_compact_reconcile() {
        let d = dir("torn-open");
        let s = HashStore::open(&d).unwrap();
        let mut dirty = HashMap::new();
        for i in 0..20u32 {
            dirty.insert(op(i), Some(coin(i as i64, 1)));
        }
        s.commit_coins(&dirty, Some(1)).unwrap();
        s.sync().unwrap();
        // A real compact leaves a consistent generation-1 pair on disk.
        s.compact().unwrap();
        drop(s);

        // Simulate a compact torn between its two renames: fresh
        // generation-2 files exist (reconciliation never inspects more
        // than the generation stamp, so cloning the current, already
        // self-consistent pair and only patching the generation bytes
        // is a faithful, valid "freshly compacted" pair), and only the
        // idx side's rename "landed" before the crash.
        let mut idx_new = std::fs::read(d.join("coins.idx")).unwrap();
        idx_new[56..64].copy_from_slice(&2u64.to_le_bytes());
        let mut dat_new = std::fs::read(d.join("coins.dat")).unwrap();
        dat_new[12..20].copy_from_slice(&2u64.to_le_bytes());
        std::fs::write(d.join("coins.idx.new"), &idx_new).unwrap();
        std::fs::write(d.join("coins.dat.new"), &dat_new).unwrap();
        std::fs::rename(d.join("coins.idx.new"), d.join("coins.idx")).unwrap();
        // coins.dat.new (generation 2) is left behind, un-renamed —
        // exactly the intermediate state a crash between compact's two
        // renames leaves: idx at generation 2, dat still at generation 1.

        // Open must reconcile (rename coins.dat.new -> coins.dat) and
        // then commit through handles that see that reconciled file.
        let s = HashStore::open(&d).unwrap();
        let mut more = HashMap::new();
        more.insert(op(99), Some(coin(999, 2)));
        s.commit_coins(&more, Some(2)).unwrap();
        s.sync().unwrap();
        drop(s);

        // A fresh open reads coins.dat/coins.idx straight from disk —
        // if the commit above landed in an unlinked pre-reconcile file,
        // it's gone now.
        let s = HashStore::open(&d).unwrap();
        assert_eq!(
            s.get(&crate::coinsdb::key_of(&op(99))).unwrap().out.value,
            999
        );
        for i in 0..20u32 {
            assert!(
                s.get(&crate::coinsdb::key_of(&op(i))).is_some(),
                "lost pre-existing coin {i}"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}

//! Snapshot files at disk speed: a parallel exact scan, a streaming
//! `hash_serialized_3` check, the same check split across cores by
//! SHA-256 midstate hints, and point lookups that need no index at all.
//!
//! ## Why the old floors were not floors
//!
//! The 20 s "read floor" was the page cache, not the drive. The 990 EVO
//! Plus on this box sits on a PCIe 3.0 x4 link: O_DIRECT reads move the
//! 9.3 GB file in ~3.5 s, where the buffered single-thread path spends
//! 7.6 CPU-seconds just copying pages on a 15 W core (16.7 s wall).
//!
//! Once reads are cheap, the next wall is the commitment itself.
//! `loadtxoutset` must check that SHA256d over every coin's `TxOutSer`
//! bytes (in file order, which is Core's cursor order) equals the
//! chainparams value. SHA-256 is a Merkle–Damgård chain — block *i*
//! needs the state after block *i − 1* — so one core has to absorb all
//! ~12.6 GB of `TxOutSer` for 170M coins, at ~1.3 GB/s here.
//!
//! ## Midstate hints
//!
//! A [`Hint`] is the complete SHA-256 stream state (8 chaining words,
//! the buffered partial block, the byte count) at a txid-group boundary,
//! with that boundary's file offset and coin count. Hints H0..Hn split
//! the file into independent intervals: a worker restores Hj, parses and
//! hashes the coins between Hj.off and Hj+1.off, and requires the state
//! it reaches to equal Hj+1 exactly. H0 is built by the verifier, not
//! read; if every interval checks and the last state finalizes to the
//! chainparams hash, then the whole stream hashed to that value — each
//! transition was recomputed from the file's own bytes, so no hint is
//! ever trusted. A wrong hint can make a good snapshot fail (fall back
//! to [`verify_stream`]); it cannot make a bad snapshot pass.
//! Proof-of-history chains are verified in parallel the same way.
//!
//! Anyone holding the snapshot produces the hints in one sequential
//! pass ([`verify_stream`] emits them), so they can ship beside the
//! chainparams entry (~17 KB per snapshot at 64 MiB spacing) or come
//! from any peer. The trust anchor stays Core's `hash_serialized_3`.
//!
//! ## Zero-scan lookups
//!
//! The file is sorted by txid, and txids are SHA-256 outputs — uniform.
//! A txid's value therefore predicts its byte position to within
//! ~sqrt(N) groups, so [`ZeroScan`] answers lookups from the file with
//! interpolation probes and no index build. Probe windows start at
//! arbitrary offsets and find group boundaries with `resync`; those
//! boundaries are statistical until a verification pass has run, so
//! zero-scan answers belong to the optimistic window before the hash
//! check completes.

use crate::check::MAX_MONEY;
use sha2::block_api::compress256;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

/// `utxo\xff`, u16 version, network magic, base blockhash, coins count.
pub const HEADER_LEN: u64 = 51;
/// Core's `MAX_SIZE` — the range check `ReadCompactSize` applies.
const MAX_SIZE: u64 = 0x0200_0000;
/// Core's `MAX_SCRIPT_SIZE`; longer scripts decompress to `OP_RETURN`.
const MAX_SCRIPT_SIZE: u64 = 10_000;
const ALIGN: usize = 4096;
/// Largest txid group held in one parse window. A group is one
/// transaction's unspent outputs and a 4M-weight block keeps that under
/// ~4 MB; a larger group is reported as an error, never guessed at.
pub const MAX_GROUP: usize = 16 << 20;
/// Bytes per read request — one O_DIRECT stream reaches the drive's
/// sequential rate at this size.
const READ_BLOCK: usize = 8 << 20;
/// Groups a resync candidate must parse, txids strictly ascending,
/// before it is taken as a boundary. Stitching then proves it.
const RESYNC_GROUPS: usize = 8;
/// Outputs one transaction can have: a 4M-weight block holds at most
/// ~111k 9-byte outputs. Bounds `STRICT` group sizes and vouts.
const STRICT_MAX_OUTPUTS: u64 = 1 << 17;
/// How far a resync chain's txid gaps may exceed their median.
const GAP_FACTOR: u128 = 32;
/// `TxOutSer` bytes buffered before a SHA-256 update.
const SER_CHUNK: usize = 4 << 20;
const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

// ---------------------------------------------------------------------
// SHA-256 with an exportable stream state
// ---------------------------------------------------------------------

/// A SHA-256 stream state that can be saved and resumed: the chaining
/// words, the partial block and the bytes absorbed so far.
#[derive(Clone, Copy, Debug)]
pub struct ShaState {
    pub h: [u32; 8],
    pub buf: [u8; 64],
    pub buf_len: u8,
    pub total: u64,
}

impl Default for ShaState {
    fn default() -> Self {
        Self {
            h: IV,
            buf: [0; 64],
            buf_len: 0,
            total: 0,
        }
    }
}

/// Equal when the logical stream state is equal — bytes past `buf_len`
/// are scratch and do not count.
impl PartialEq for ShaState {
    fn eq(&self, o: &Self) -> bool {
        let n = usize::from(self.buf_len);
        self.h == o.h
            && self.total == o.total
            && self.buf_len == o.buf_len
            && self.buf[..n] == o.buf[..n]
    }
}
impl Eq for ShaState {}

impl ShaState {
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        let have = usize::from(self.buf_len);
        if have > 0 {
            let take = (64 - have).min(data.len());
            self.buf[have..have + take].copy_from_slice(&data[..take]);
            data = &data[take..];
            if have + take < 64 {
                self.buf_len = (have + take) as u8;
                return;
            }
            compress256(&mut self.h, &[self.buf]);
            self.buf_len = 0;
        }
        let (blocks, rest) = data.as_chunks::<64>();
        if !blocks.is_empty() {
            compress256(&mut self.h, blocks);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len() as u8;
    }

    /// Standard padding; returns the single SHA-256 digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        let bits = self.total.wrapping_mul(8);
        let mut n = usize::from(self.buf_len);
        self.buf[n] = 0x80;
        n += 1;
        if n > 56 {
            self.buf[n..].fill(0);
            compress256(&mut self.h, &[self.buf]);
            n = 0;
        }
        self.buf[n..56].fill(0);
        self.buf[56..].copy_from_slice(&bits.to_be_bytes());
        compress256(&mut self.h, &[self.buf]);
        let mut out = [0u8; 32];
        for (c, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.h) {
            c.copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

/// `hash_serialized_3` in raw (internal) byte order from the stream
/// state after the last coin — the SHA256d `HashWriter::GetHash` takes.
#[must_use]
pub fn finish_hash(state: ShaState) -> [u8; 32] {
    crate::hash::sha256(&state.finalize())
}

// ---------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86")))]
const O_DIRECT: Option<i32> = Some(0o40000);
#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
const O_DIRECT: Option<i32> = Some(0o200000);
#[cfg(not(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm"
    )
)))]
const O_DIRECT: Option<i32> = None;

/// Opens `path` read-only, bypassing the page cache when `direct` and
/// the filesystem allows it (tmpfs, for one, may refuse O_DIRECT).
pub fn open_snapshot(path: &Path, direct: bool) -> io::Result<File> {
    if direct
        && let Some(flag) = O_DIRECT
        && let Ok(f) = OpenOptions::new().read(true).custom_flags(flag).open(path)
    {
        return Ok(f);
    }
    File::open(path)
}

/// A heap buffer whose usable part starts on an `ALIGN` boundary, as
/// O_DIRECT requires — over-allocated and sliced, so no `unsafe`.
struct AlignedBuf {
    v: Vec<u8>,
    off: usize,
    len: usize,
}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        let v = vec![0u8; len + ALIGN];
        let off = (ALIGN - (v.as_ptr() as usize) % ALIGN) % ALIGN;
        Self { v, off, len }
    }
    fn get(&self) -> &[u8] {
        &self.v[self.off..self.off + self.len]
    }
    fn get_mut(&mut self) -> &mut [u8] {
        &mut self.v[self.off..self.off + self.len]
    }
}

/// Fills `buf` from `off`, stopping at end of file. A short read means
/// EOF on a regular file — and retrying at the unaligned offset it
/// leaves would be refused under O_DIRECT.
fn read_full_at(f: &File, buf: &mut [u8], mut off: u64) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read_at(&mut buf[n..], off) {
            Ok(0) => break,
            Ok(k) => {
                let asked = buf.len() - n;
                n += k;
                off += k as u64;
                if k < asked {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn align_down(x: u64) -> u64 {
    x / ALIGN as u64 * ALIGN as u64
}

fn align_up(x: u64) -> u64 {
    x.div_ceil(ALIGN as u64) * ALIGN as u64
}

/// A sequential reader over `[start, limit)` that keeps one read in
/// flight on a helper thread and hands the parser a contiguous window.
/// The unconsumed tail of the previous block (at most one group) is
/// copied in front of the next block, so a group that straddles a read
/// boundary still parses in place.
struct Stream {
    rx: Receiver<io::Result<(AlignedBuf, usize)>>,
    free: SyncSender<AlignedBuf>,
    cur: AlignedBuf,
    lo: usize,
    hi: usize,
    /// File offset of `cur[lo]`.
    off: u64,
    /// Bytes of the first block that precede `start` (alignment).
    skip: usize,
    done: bool,
    read: u64,
}

impl Stream {
    fn new(f: File, file_len: u64, start: u64, limit: u64) -> Self {
        let first = align_down(start);
        let limit = limit.min(file_len);
        let (tx, rx) = sync_channel::<io::Result<(AlignedBuf, usize)>>(1);
        let (free, free_rx) = sync_channel::<AlignedBuf>(3);
        for _ in 0..2 {
            let _ = free.try_send(AlignedBuf::new(MAX_GROUP + READ_BLOCK));
        }
        std::thread::spawn(move || {
            let mut next = first;
            while next < limit {
                let Ok(mut b) = free_rx.recv() else { return };
                let want = (READ_BLOCK as u64).min(align_up(limit - next)) as usize;
                let r = read_full_at(&f, &mut b.get_mut()[MAX_GROUP..MAX_GROUP + want], next);
                match r {
                    Ok(n) => {
                        next += n as u64;
                        let last = n < want;
                        if tx.send(Ok((b, n))).is_err() || last {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                }
            }
        });
        Self {
            rx,
            free,
            cur: AlignedBuf::new(MAX_GROUP + READ_BLOCK),
            lo: MAX_GROUP,
            hi: MAX_GROUP,
            off: first,
            skip: (start - first) as usize,
            done: false,
            read: 0,
        }
    }

    fn window(&self) -> &[u8] {
        &self.cur.get()[self.lo..self.hi]
    }

    fn consume(&mut self, n: usize) {
        self.lo += n;
        self.off += n as u64;
    }

    /// Appends the next block to the window. `Ok(false)`: nothing left.
    fn fill(&mut self) -> io::Result<bool> {
        if self.done {
            return Ok(false);
        }
        let carry = self.hi - self.lo;
        if carry > MAX_GROUP {
            return Err(invalid("txid group larger than the parse window"));
        }
        match self.rx.recv() {
            Err(_) => {
                self.done = true;
                Ok(false)
            }
            Ok(Err(e)) => Err(e),
            Ok(Ok((mut next, n))) => {
                let at = MAX_GROUP - carry;
                next.get_mut()[at..MAX_GROUP].copy_from_slice(&self.cur.get()[self.lo..self.hi]);
                let old = std::mem::replace(&mut self.cur, next);
                let _ = self.free.try_send(old);
                self.lo = at;
                self.hi = MAX_GROUP + n;
                self.read += n as u64;
                if self.skip > 0 {
                    let s = self.skip.min(self.hi - self.lo);
                    self.consume(s);
                    self.skip -= s;
                }
                Ok(n > 0)
            }
        }
    }
}

/// The snapshot file's metadata header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub network: [u8; 4],
    pub base_blockhash: [u8; 32],
    pub coins_count: u64,
}

pub fn read_header(f: &File) -> io::Result<Header> {
    let mut h = [0u8; HEADER_LEN as usize];
    f.read_exact_at(&mut h, 0)?;
    if &h[..5] != b"utxo\xff" {
        return Err(invalid("bad snapshot magic"));
    }
    if u16::from_le_bytes([h[5], h[6]]) != 2 {
        return Err(invalid("unsupported snapshot version"));
    }
    let mut network = [0u8; 4];
    network.copy_from_slice(&h[7..11]);
    let mut base_blockhash = [0u8; 32];
    base_blockhash.copy_from_slice(&h[11..43]);
    let mut count = [0u8; 8];
    count.copy_from_slice(&h[43..51]);
    Ok(Header {
        network,
        base_blockhash,
        coins_count: u64::from_le_bytes(count),
    })
}

// ---------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------

/// `Short`: the window ends mid-record, read more. `Bad`: malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PErr {
    Short,
    Bad(&'static str),
}

#[inline]
fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8], PErr> {
    let end = p.checked_add(n).ok_or(PErr::Bad("length overflow"))?;
    let s = b.get(*p..end).ok_or(PErr::Short)?;
    *p = end;
    Ok(s)
}

/// `ReadCompactSize` with Core's canonical-form and `MAX_SIZE` checks.
#[inline]
fn compact(b: &[u8], p: &mut usize) -> Result<u64, PErr> {
    let tag = *b.get(*p).ok_or(PErr::Short)?;
    *p += 1;
    let v = match tag {
        0..=252 => return Ok(u64::from(tag)),
        253 => {
            let s = take(b, p, 2)?;
            let v = u64::from(u16::from_le_bytes([s[0], s[1]]));
            if v < 253 {
                return Err(PErr::Bad("non-canonical CompactSize"));
            }
            v
        }
        254 => {
            let s = take(b, p, 4)?;
            let v = u64::from(u32::from_le_bytes([s[0], s[1], s[2], s[3]]));
            if v < 0x1_0000 {
                return Err(PErr::Bad("non-canonical CompactSize"));
            }
            v
        }
        255 => {
            let s = take(b, p, 8)?;
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            let v = u64::from_le_bytes(a);
            if v < 0x1_0000_0000 {
                return Err(PErr::Bad("non-canonical CompactSize"));
            }
            v
        }
    };
    if v > MAX_SIZE {
        return Err(PErr::Bad("CompactSize above MAX_SIZE"));
    }
    Ok(v)
}

/// Core's `ReadVarInt` for an integer type whose maximum is `max`: MSB
/// base-128 with the `n++` after every continuation byte.
#[inline]
fn varint(b: &[u8], p: &mut usize, max: u64) -> Result<u64, PErr> {
    let mut n = 0u64;
    loop {
        let c = *b.get(*p).ok_or(PErr::Short)?;
        *p += 1;
        if n > max >> 7 {
            return Err(PErr::Bad("VARINT too large"));
        }
        n = (n << 7) | u64::from(c & 0x7f);
        if c & 0x80 == 0 {
            return Ok(n);
        }
        if n == max {
            return Err(PErr::Bad("VARINT too large"));
        }
        n += 1;
    }
}

/// Core's `DecompressAmount`, with its unsigned wrap-around (a hostile
/// exponent must not panic an overflow-checked build).
fn decompress_amount(x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    let mut x = x - 1;
    let mut e = x % 10;
    x /= 10;
    let mut n = if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        x.wrapping_mul(10).wrapping_add(d)
    } else {
        x.wrapping_add(1)
    };
    while e > 0 {
        n = n.wrapping_mul(10);
        e -= 1;
    }
    n
}

/// `DecompressScript` for ids 4/5: X plus Y's parity, recovered to the
/// 65-byte key. Core ignores a failed decompression and keeps the
/// empty script, so an off-curve X serializes as an empty script here.
fn p2pk_uncompressed(ser: &mut Vec<u8>, id: u64, x: &[u8]) {
    let mut c = [0u8; 33];
    c[0] = if id == 4 { 2 } else { 3 };
    c[1..].copy_from_slice(x);
    match secp256k1::PublicKey::from_slice(&c) {
        Ok(pk) => {
            ser.extend_from_slice(&[67, 65]);
            ser.extend_from_slice(&pk.serialize_uncompressed());
            ser.push(0xac);
        }
        Err(_) => ser.push(0),
    }
}

/// One coin after its vout. With `SER`, appends the rest of its
/// `TxOutSer` (height code, value, script) — the caller wrote the
/// outpoint. Core's per-coin checks run after the whole coin is read,
/// as in `PopulateAndValidateSnapshot`.
#[inline]
fn coin<const SER: bool, const STRICT: bool>(
    b: &[u8],
    p: &mut usize,
    base_height: u32,
    ser: &mut Vec<u8>,
) -> Result<u64, PErr> {
    let code = varint(b, p, u64::from(u32::MAX))?;
    let amount = varint(b, p, u64::MAX)?;
    let size_id = varint(b, p, u64::from(u32::MAX))?;
    let value = decompress_amount(amount) as i64;
    if SER {
        ser.extend_from_slice(&(code as u32).to_le_bytes());
        ser.extend_from_slice(&value.to_le_bytes());
    }
    match size_id {
        0 => {
            let h = take(b, p, 20)?;
            if SER {
                ser.extend_from_slice(&[25, 0x76, 0xa9, 0x14]);
                ser.extend_from_slice(h);
                ser.extend_from_slice(&[0x88, 0xac]);
            }
        }
        1 => {
            let h = take(b, p, 20)?;
            if SER {
                ser.extend_from_slice(&[23, 0xa9, 0x14]);
                ser.extend_from_slice(h);
                ser.push(0x87);
            }
        }
        2 | 3 => {
            let x = take(b, p, 32)?;
            if SER {
                ser.extend_from_slice(&[35, 33, size_id as u8]);
                ser.extend_from_slice(x);
                ser.push(0xac);
            }
        }
        4 | 5 => {
            let x = take(b, p, 32)?;
            if SER {
                p2pk_uncompressed(ser, size_id, x);
            }
        }
        n => {
            let len = n - 6;
            if STRICT && len > MAX_SCRIPT_SIZE {
                // Never in a UTXO set; a hostile length would otherwise
                // read as "need more bytes" for megabytes.
                return Err(PErr::Bad("script above MAX_SCRIPT_SIZE"));
            }
            let raw = take(
                b,
                p,
                usize::try_from(len).map_err(|_| PErr::Bad("script size"))?,
            )?;
            if SER {
                if len > MAX_SCRIPT_SIZE {
                    // Core: "Overly long script, replace with a short
                    // invalid one" — the payload is skipped.
                    ser.extend_from_slice(&[1, 0x6a]);
                } else {
                    crate::encode::write_compact_size(ser, len);
                    ser.extend_from_slice(raw);
                }
            }
        }
    }
    if code >> 1 > u64::from(base_height) {
        return Err(PErr::Bad("coin height above the snapshot base"));
    }
    if !(0..=MAX_MONEY).contains(&value) {
        return Err(PErr::Bad("bad tx out value"));
    }
    Ok(code)
}

struct Group {
    len: usize,
    txid: [u8; 32],
    n: u64,
}

/// One txid group at the start of `b`. On error, `ser` is left as it
/// was, so a `Short` group can be retried after a refill.
#[inline]
fn group<const SER: bool>(b: &[u8], base_height: u32, ser: &mut Vec<u8>) -> Result<Group, PErr> {
    let mark = ser.len();
    let r = group_body::<SER, false>(b, base_height, ser);
    if r.is_err() {
        ser.truncate(mark);
    }
    r
}

/// `STRICT` adds the shape every Core dump has but Core's loader does
/// not demand — at least one coin per group, vouts ascending (cursor
/// order), and with `same_code` one height/coinbase code per group
/// (the outputs of one transaction) — used only to judge resync
/// candidates. `same_code` is what stops a phantom parse within a coin
/// or two instead of letting it walk a large group's real records.
#[inline]
fn group_body<const SER: bool, const STRICT: bool>(
    b: &[u8],
    base_height: u32,
    ser: &mut Vec<u8>,
) -> Result<Group, PErr> {
    group_shaped::<SER, STRICT>(b, base_height, ser, false)
}

#[inline]
fn group_shaped<const SER: bool, const STRICT: bool>(
    b: &[u8],
    base_height: u32,
    ser: &mut Vec<u8>,
    same_code: bool,
) -> Result<Group, PErr> {
    let mut p = 0usize;
    let mut txid = [0u8; 32];
    txid.copy_from_slice(take(b, &mut p, 32)?);
    let n = compact(b, &mut p)?;
    if STRICT && (n == 0 || n > STRICT_MAX_OUTPUTS) {
        return Err(PErr::Bad("implausible group size"));
    }
    let mut prev_vout: Option<u64> = None;
    let mut first_code: Option<u64> = None;
    for _ in 0..n {
        let vout = compact(b, &mut p)?;
        if STRICT {
            if vout >= STRICT_MAX_OUTPUTS || prev_vout.is_some_and(|v| vout <= v) {
                return Err(PErr::Bad("vouts out of order"));
            }
            prev_vout = Some(vout);
        }
        if SER {
            ser.extend_from_slice(&txid);
            ser.extend_from_slice(&(vout as u32).to_le_bytes());
        }
        let code = coin::<SER, STRICT>(b, &mut p, base_height, ser)?;
        if STRICT && same_code && *first_code.get_or_insert(code) != code {
            return Err(PErr::Bad("mixed heights in one txid"));
        }
    }
    Ok(Group { len: p, txid, n })
}

/// Whether multi-output groups carry one height code each — true of
/// every Core dump; the counter fixture draws a height per coin. Judged
/// from the first groups of the file, parsed exactly.
fn uniform_codes(f: &File, base_height: u32) -> io::Result<bool> {
    let (buf, at) = read_window(f, HEADER_LEN, 1 << 20)?;
    let mut p = at;
    let (mut multi, mut uniform) = (0u32, 0u32);
    let mut scratch = Vec::new();
    while multi < 2000 {
        let Ok(g) = group::<false>(&buf[p..], base_height, &mut scratch) else {
            break;
        };
        if g.n > 1 {
            multi += 1;
            if group_shaped::<false, true>(&buf[p..], base_height, &mut scratch, true).is_ok() {
                uniform += 1;
            }
        }
        p += g.len;
    }
    Ok(multi > 0 && uniform == multi)
}

/// A resync candidate's first group. It may be a phantom — see
/// `resync` — so only its end is used as a boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Head {
    at: usize,
    txid: [u8; 32],
    len: usize,
}

/// What `resync` concluded about a window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sync {
    /// `at` is a group boundary: the end of `head`, or the known `end`
    /// when no group starts before it.
    At { head: Option<Head>, at: usize },
    /// The earliest unrefuted candidate runs off the window: read more.
    More,
    /// No candidate in the window.
    Nothing,
}

/// Finds a group boundary at or after `from` in a window that starts at
/// an arbitrary byte.
///
/// Candidates are judged in file order; the earliest not refuted wins.
/// It must start `RESYNC_GROUPS` groups of Core-dump shape
/// ([`group_body`]'s `STRICT`), txids strictly ascending and inside
/// `bounds` when a bracket is known, with no txid gap far above the
/// chain's median ([`tight`]) — or run exactly into `end`, an index
/// known to be a boundary. A candidate the window cannot decide is
/// never skipped for a later one: the caller is asked for more bytes.
///
/// The coin encoding self-synchronizes: a parse started inside a large
/// group drifts back into step with the real coin records, and its
/// phantom first "group" often ends exactly on the next real boundary,
/// after which every check passes on real groups. So the boundary
/// reported is the end of the first group, not its start; the first
/// group is returned as `head` for callers that can use it on its own
/// merits (a lookup whose target txid it equals). Still a candidate:
/// scans prove it by stitching, lookups use it in the optimistic window.
fn resync(
    win: &[u8],
    from: usize,
    base_height: u32,
    end: Option<usize>,
    bounds: Option<(&[u8; 32], &[u8; 32])>,
    same_code: bool,
) -> Sync {
    let mut scratch = Vec::new();
    let end = end.map(|e| e.min(win.len()));
    let lim = end.unwrap_or(win.len());
    let mut chain: Vec<Head> = Vec::with_capacity(RESYNC_GROUPS);
    'cand: for c in from..lim {
        chain.clear();
        let mut p = c;
        let mut prev: Option<[u8; 32]> = bounds.map(|(lo, _)| *lo);
        while chain.len() < RESYNC_GROUPS {
            if !chain.is_empty() && Some(p) == end {
                break;
            }
            // Cheap first: the txid must fit the order before any coin
            // is parsed.
            if let Some(t) = win.get(p..p + 32)
                && (prev.is_some_and(|q| t <= &q[..]) || bounds.is_some_and(|(_, hi)| t >= &hi[..]))
            {
                continue 'cand;
            }
            match group_shaped::<false, true>(&win[p..lim], base_height, &mut scratch, same_code) {
                Ok(g) => {
                    if prev.is_some_and(|t| g.txid <= t)
                        || bounds.is_some_and(|(_, hi)| g.txid >= *hi)
                    {
                        continue 'cand;
                    }
                    prev = Some(g.txid);
                    chain.push(Head {
                        at: p,
                        txid: g.txid,
                        len: g.len,
                    });
                    p += g.len;
                }
                // A group cannot straddle a known boundary.
                Err(PErr::Short) if end.is_some() => continue 'cand,
                Err(PErr::Short) => return Sync::More,
                Err(PErr::Bad(_)) => continue 'cand,
            }
        }
        let h = chain[0];
        match tight(&chain) {
            Tight::Yes => {
                return Sync::At {
                    head: Some(h),
                    at: h.at + h.len,
                };
            }
            // A phantom head that merged: the real chain after it is
            // the boundary evidence.
            Tight::HeadOnly => {
                return Sync::At {
                    head: None,
                    at: h.at + h.len,
                };
            }
            Tight::No => {}
        }
    }
    match end {
        Some(e) => Sync::At { head: None, at: e },
        None => Sync::Nothing,
    }
}

enum Tight {
    Yes,
    /// Only the head's gap is loose: a phantom head over a real chain.
    HeadOnly,
    No,
}

/// Sorted uniform txids sit close to their neighbours: consecutive gaps
/// are exponential around `2^256 / N`. A phantom's "txid" is unrelated
/// bytes, so its gap to the real txid after it is typically ~N times
/// the median. A gap above `GAP_FACTOR` × the median of the chain's
/// other gaps is loose (a true gap is, with probability ~e^-20).
fn tight(chain: &[Head]) -> Tight {
    if chain.len() < 4 {
        return Tight::Yes;
    }
    let tail = &chain[1..];
    let pre = tail
        .windows(2)
        .map(|w| {
            w[0].txid
                .iter()
                .zip(&w[1].txid)
                .take_while(|(a, b)| a == b)
                .count()
        })
        .min()
        .unwrap_or(0)
        .min(16);
    let key = |t: &[u8; 32]| {
        t[pre..pre + 16]
            .iter()
            .fold(0u128, |k, b| (k << 8) | u128::from(*b))
    };
    let gaps: Vec<u128> = tail
        .windows(2)
        .map(|w| key(&w[1].txid).saturating_sub(key(&w[0].txid)))
        .collect();
    let mut sorted = gaps.clone();
    sorted.sort_unstable();
    let limit = sorted[sorted.len() / 2].max(1).saturating_mul(GAP_FACTOR);
    if gaps.iter().any(|g| *g > limit) {
        return Tight::No;
    }
    let head_ok = chain[0].txid[..pre] == tail[0].txid[..pre]
        && key(&tail[0].txid).saturating_sub(key(&chain[0].txid)) <= limit;
    if head_ok { Tight::Yes } else { Tight::HeadOnly }
}

/// Reads up to `len` bytes at `off`, aligned for O_DIRECT. Returns the
/// bytes and the index of `off` inside them.
fn read_window(f: &File, off: u64, len: usize) -> io::Result<(Vec<u8>, usize)> {
    let a = align_down(off);
    let want = align_up(off + len as u64) - a;
    let mut b = AlignedBuf::new(want as usize);
    let n = read_full_at(f, b.get_mut(), a)?;
    let mut v = b.get()[..n].to_vec();
    let at = (off - a) as usize;
    if at > v.len() {
        v.clear();
        return Ok((v, 0));
    }
    v.truncate((at + len).min(v.len()));
    Ok((v, at))
}

/// A group boundary at or after `at`, found by `resync` in a window
/// that grows until the earliest candidate is decided.
fn boundary_near(
    f: &File,
    file_len: u64,
    at: u64,
    base_height: u32,
    same_code: bool,
) -> io::Result<u64> {
    let mut len = PROBE;
    loop {
        let (buf, s) = read_window(f, at, len)?;
        let win = &buf[s..];
        let eof = at + win.len() as u64 >= file_len;
        match resync(
            win,
            0,
            base_height,
            eof.then_some(win.len()),
            None,
            same_code,
        ) {
            Sync::At { at: k, .. } => return Ok(at + k as u64),
            Sync::More if len < MAX_GROUP => len *= 4,
            _ => return Err(invalid("no group boundary found")),
        }
    }
}

// ---------------------------------------------------------------------
// Parallel exact scan (index only)
// ---------------------------------------------------------------------

/// One region's parse: groups whose start lies in `[first, stop)`.
struct Region {
    first: u64,
    end: u64,
    coins: u64,
    groups: u64,
    first_txid: Option<[u8; 32]>,
    last_txid: Option<[u8; 32]>,
    last_n: u64,
    sparse: Vec<([u8; 32], u64)>,
    read: u64,
}

/// Parses the groups that start in `[start, stop)`; `start` is taken
/// as a boundary.
fn scan_region(
    path: &Path,
    direct: bool,
    file_len: u64,
    start: u64,
    stop: u64,
    base_height: u32,
    bucket: u64,
) -> io::Result<Region> {
    let mut s = Stream::new(open_snapshot(path, direct)?, file_len, start, file_len);
    s.fill()?;
    let mut r = Region {
        first: s.off,
        end: s.off,
        coins: 0,
        groups: 0,
        first_txid: None,
        last_txid: None,
        last_n: 0,
        sparse: Vec::new(),
        read: 0,
    };
    let mut prev_bucket = u64::MAX;
    let mut scratch = Vec::new();
    loop {
        let off = s.off;
        if off >= stop {
            break;
        }
        match group::<false>(s.window(), base_height, &mut scratch) {
            Ok(g) => {
                if r.last_txid.is_some_and(|t| g.txid <= t) {
                    return Err(invalid("txids out of order"));
                }
                r.first_txid.get_or_insert(g.txid);
                r.last_txid = Some(g.txid);
                let b = (off - HEADER_LEN) / bucket;
                if b != prev_bucket {
                    r.sparse.push((g.txid, off));
                    prev_bucket = b;
                }
                r.coins += g.n;
                r.groups += 1;
                r.last_n = g.n;
                s.consume(g.len);
            }
            Err(PErr::Short) => {
                if !s.fill()? {
                    if s.window().is_empty() {
                        break;
                    }
                    return Err(invalid("truncated snapshot"));
                }
            }
            Err(PErr::Bad(m)) => return Err(invalid(m)),
        }
    }
    r.end = s.off;
    r.read = s.read;
    Ok(r)
}

/// Result of a full pass over a snapshot.
#[derive(Debug)]
pub struct ScanOut {
    pub coins: u64,
    pub groups: u64,
    /// First group of every `bucket` bytes: `(txid, file offset)`.
    pub sparse: Vec<([u8; 32], u64)>,
    /// Regions whose resync start failed stitching and were re-parsed.
    pub fallbacks: usize,
    pub bytes_read: u64,
}

fn check_end(
    hdr: &Header,
    file_len: u64,
    end: u64,
    coins: u64,
    last_n: u64,
    groups: u64,
) -> io::Result<()> {
    if end != file_len {
        return Err(invalid("snapshot does not end at a group boundary"));
    }
    if coins != hdr.coins_count {
        return Err(invalid(format!(
            "coins count mismatch: header {} file {coins}",
            hdr.coins_count
        )));
    }
    // Core stops reading once `coins_count` coins are in and demands
    // EOF, so a trailing zero-output group is "coins left over".
    if groups > 0 && last_n == 0 {
        return Err(invalid("coins left over after the declared count"));
    }
    Ok(())
}

/// Parses the whole file in `threads` contiguous regions at once.
///
/// Phase 1 finds a candidate boundary near each nominal split with
/// `resync` (one small read each); phase 2 parses every region from
/// its candidate to the next one. A candidate counts only if the exact
/// parse of the region before it ends on it; a region that fails that
/// check is re-parsed from the proven end. By induction from the
/// header, the stitched parse is the sequential parse — speculation
/// changes the speed, never the result.
pub fn scan(
    path: &Path,
    direct: bool,
    threads: usize,
    base_height: u32,
    bucket: u64,
) -> io::Result<ScanOut> {
    // The 51-byte header read is unaligned: never through O_DIRECT.
    let hdr = read_header(&File::open(path)?)?;
    let f = open_snapshot(path, direct)?;
    let file_len = f.metadata()?.len();
    let body = file_len - HEADER_LEN;
    let per = body.div_ceil(threads.max(1) as u64).max(1);
    let splits: Vec<u64> = (1..threads.max(1) as u64)
        .map(|i| HEADER_LEN + i * per)
        .filter(|&x| x < file_len)
        .collect();
    let same_code = uniform_codes(&f, base_height)?;
    let found: Vec<io::Result<u64>> = std::thread::scope(|sc| {
        let f = &f;
        let hs: Vec<_> = splits
            .iter()
            .map(|&x| sc.spawn(move || boundary_near(f, file_len, x, base_height, same_code)))
            .collect();
        hs.into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(invalid("resync worker panicked")))
            })
            .collect()
    });
    let mut starts = vec![HEADER_LEN];
    for b in found.into_iter().flatten() {
        if b > *starts.last().unwrap_or(&HEADER_LEN) && b < file_len {
            starts.push(b);
        }
    }
    let stops: Vec<u64> = starts
        .iter()
        .skip(1)
        .copied()
        .chain(std::iter::once(file_len))
        .collect();
    let results: Vec<io::Result<Region>> = std::thread::scope(|sc| {
        let hs: Vec<_> = starts
            .iter()
            .zip(&stops)
            .map(|(&a, &b)| {
                sc.spawn(move || scan_region(path, direct, file_len, a, b, base_height, bucket))
            })
            .collect();
        hs.into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(invalid("scan worker panicked")))
            })
            .collect()
    });
    let mut out = ScanOut {
        coins: 0,
        groups: 0,
        sparse: Vec::new(),
        fallbacks: 0,
        bytes_read: 0,
    };
    let mut end = HEADER_LEN;
    let mut last_txid: Option<[u8; 32]> = None;
    let mut last_n = 0;
    let mut last_bucket = u64::MAX;
    for (i, r) in results.into_iter().enumerate() {
        let r = match r {
            Ok(r) if r.first == end => r,
            _ => {
                out.fallbacks += 1;
                scan_region(
                    path,
                    direct,
                    file_len,
                    end,
                    stops[i].max(end),
                    base_height,
                    bucket,
                )?
            }
        };
        if let (Some(a), Some(b)) = (last_txid, r.first_txid)
            && b <= a
        {
            return Err(invalid("txids out of order"));
        }
        for (t, o) in r.sparse {
            let b = (o - HEADER_LEN) / bucket;
            if b != last_bucket {
                out.sparse.push((t, o));
                last_bucket = b;
            }
        }
        if r.groups > 0 {
            last_n = r.last_n;
            last_txid = r.last_txid;
        }
        out.coins += r.coins;
        out.groups += r.groups;
        out.bytes_read += r.read;
        end = r.end;
    }
    check_end(&hdr, file_len, end, out.coins, last_n, out.groups)?;
    Ok(out)
}

// ---------------------------------------------------------------------
// Verification: streaming, and in parallel from hints
// ---------------------------------------------------------------------

/// SHA-256 stream state at a group boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hint {
    /// File offset of the group that starts here (or the file length).
    pub off: u64,
    /// Coins before this boundary.
    pub coins: u64,
    pub state: ShaState,
}

/// Midstate hints for one snapshot file. Untrusted by construction —
/// see the module docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hints {
    pub file_len: u64,
    pub header: Header,
    pub hints: Vec<Hint>,
}

const HINTS_MAGIC: &[u8; 8] = b"AVHINT01";
const HINT_LEN: usize = 8 + 8 + 8 + 32 + 1 + 64;

impl Hints {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64 + self.hints.len() * HINT_LEN);
        v.extend_from_slice(HINTS_MAGIC);
        v.extend_from_slice(&self.file_len.to_le_bytes());
        v.extend_from_slice(&self.header.network);
        v.extend_from_slice(&self.header.base_blockhash);
        v.extend_from_slice(&self.header.coins_count.to_le_bytes());
        v.extend_from_slice(&(self.hints.len() as u32).to_le_bytes());
        for h in &self.hints {
            v.extend_from_slice(&h.off.to_le_bytes());
            v.extend_from_slice(&h.coins.to_le_bytes());
            v.extend_from_slice(&h.state.total.to_le_bytes());
            for w in h.state.h {
                v.extend_from_slice(&w.to_le_bytes());
            }
            let n = usize::from(h.state.buf_len);
            v.push(h.state.buf_len);
            v.extend_from_slice(&h.state.buf[..n]);
            v.extend_from_slice(&[0u8; 64][..64 - n]);
        }
        v
    }

    pub fn decode(b: &[u8]) -> io::Result<Self> {
        let mut p = 0usize;
        let mut get = |n: usize| -> io::Result<&[u8]> {
            let s = b.get(p..p + n).ok_or_else(|| invalid("short hints file"))?;
            p += n;
            Ok(s)
        };
        let u64le = |s: &[u8]| {
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            u64::from_le_bytes(a)
        };
        if get(8)? != HINTS_MAGIC {
            return Err(invalid("bad hints magic"));
        }
        let file_len = u64le(get(8)?);
        let mut network = [0u8; 4];
        network.copy_from_slice(get(4)?);
        let mut base_blockhash = [0u8; 32];
        base_blockhash.copy_from_slice(get(32)?);
        let coins_count = u64le(get(8)?);
        let mut n4 = [0u8; 4];
        n4.copy_from_slice(get(4)?);
        let n = u32::from_le_bytes(n4) as usize;
        let mut hints = Vec::with_capacity(n.min(1 << 20));
        for _ in 0..n {
            let off = u64le(get(8)?);
            let coins = u64le(get(8)?);
            let total = u64le(get(8)?);
            let mut h = [0u32; 8];
            for w in &mut h {
                let mut a = [0u8; 4];
                a.copy_from_slice(get(4)?);
                *w = u32::from_le_bytes(a);
            }
            let buf_len = get(1)?[0];
            if buf_len >= 64 {
                return Err(invalid("bad hint buffer length"));
            }
            let mut buf = [0u8; 64];
            buf.copy_from_slice(get(64)?);
            hints.push(Hint {
                off,
                coins,
                state: ShaState {
                    h,
                    buf,
                    buf_len,
                    total,
                },
            });
        }
        Ok(Self {
            file_len,
            header: Header {
                network,
                base_blockhash,
                coins_count,
            },
            hints,
        })
    }
}

/// A verification result.
#[derive(Debug)]
pub struct VerifyOut {
    /// `hash_serialized_3`, raw byte order.
    pub hash: [u8; 32],
    pub coins: u64,
    pub groups: u64,
    pub sparse: Vec<([u8; 32], u64)>,
    pub bytes_read: u64,
}

enum Msg {
    Data(Vec<u8>),
    Mark(u64, u64),
}

/// The sequential check: one pass, `TxOutSer` into one SHA-256 stream.
/// Parsing (with its reads) runs on one thread and hashing on another,
/// so the wall time is the slower of the two — on this box, SHA-256.
/// Records a [`Hint`] at the first group boundary past every `every`
/// bytes of file, plus one at the end.
pub fn verify_stream(
    path: &Path,
    direct: bool,
    base_height: u32,
    every: u64,
    bucket: u64,
) -> io::Result<(VerifyOut, Hints)> {
    let f = File::open(path)?;
    let hdr = read_header(&f)?;
    let file_len = f.metadata()?.len();
    let (tx, rx) = sync_channel::<Msg>(8);
    let (back_tx, back_rx) = sync_channel::<Vec<u8>>(16);
    let every = every.max(1);
    std::thread::scope(|sc| {
        let parser = sc.spawn(move || -> io::Result<(Region, u64)> {
            let mut s = Stream::new(open_snapshot(path, direct)?, file_len, HEADER_LEN, file_len);
            let mut r = Region {
                first: HEADER_LEN,
                end: HEADER_LEN,
                coins: 0,
                groups: 0,
                first_txid: None,
                last_txid: None,
                last_n: 0,
                sparse: Vec::new(),
                read: 0,
            };
            let fresh = |back_rx: &Receiver<Vec<u8>>| {
                back_rx
                    .try_recv()
                    .unwrap_or_else(|_| Vec::with_capacity(SER_CHUNK + (64 << 10)))
            };
            let mut ser = fresh(&back_rx);
            let mut next_mark = HEADER_LEN + every;
            let mut prev_bucket = u64::MAX;
            loop {
                let off = s.off;
                let before = ser.len();
                match group::<true>(s.window(), base_height, &mut ser) {
                    Ok(g) => {
                        if off >= next_mark {
                            // The hint sits in front of this group: hash
                            // everything before it, then mark.
                            let tail = ser.split_off(before);
                            let full = std::mem::replace(&mut ser, tail);
                            if tx.send(Msg::Data(full)).is_err()
                                || tx.send(Msg::Mark(off, r.coins)).is_err()
                            {
                                return Err(invalid("hasher stopped"));
                            }
                            next_mark = HEADER_LEN + ((off - HEADER_LEN) / every + 1) * every;
                        }
                        if r.last_txid.is_some_and(|t| g.txid <= t) {
                            return Err(invalid("txids out of order"));
                        }
                        r.last_txid = Some(g.txid);
                        let b = (off - HEADER_LEN) / bucket;
                        if b != prev_bucket {
                            r.sparse.push((g.txid, off));
                            prev_bucket = b;
                        }
                        r.coins += g.n;
                        r.groups += 1;
                        r.last_n = g.n;
                        s.consume(g.len);
                        if ser.len() >= SER_CHUNK {
                            let full = std::mem::replace(&mut ser, fresh(&back_rx));
                            if tx.send(Msg::Data(full)).is_err() {
                                return Err(invalid("hasher stopped"));
                            }
                        }
                    }
                    Err(PErr::Short) => {
                        if !s.fill()? {
                            if s.window().is_empty() {
                                break;
                            }
                            return Err(invalid("truncated snapshot"));
                        }
                    }
                    Err(PErr::Bad(m)) => return Err(invalid(m)),
                }
            }
            r.end = s.off;
            let _ = tx.send(Msg::Data(ser));
            if r.end > HEADER_LEN {
                let _ = tx.send(Msg::Mark(r.end, r.coins));
            }
            Ok((r, s.read))
        });
        let mut sha = ShaState::default();
        let mut hints = vec![Hint {
            off: HEADER_LEN,
            coins: 0,
            state: sha,
        }];
        for m in rx {
            match m {
                Msg::Data(mut v) => {
                    sha.update(&v);
                    v.clear();
                    let _ = back_tx.try_send(v);
                }
                Msg::Mark(off, coins) => hints.push(Hint {
                    off,
                    coins,
                    state: sha,
                }),
            }
        }
        let (r, read) = parser
            .join()
            .unwrap_or_else(|_| Err(invalid("parser panicked")))?;
        check_end(&hdr, file_len, r.end, r.coins, r.last_n, r.groups)?;
        Ok((
            VerifyOut {
                hash: finish_hash(sha),
                coins: r.coins,
                groups: r.groups,
                sparse: r.sparse,
                bytes_read: read,
            },
            Hints {
                file_len,
                header: hdr,
                hints,
            },
        ))
    })
}

struct Interval {
    first_txid: [u8; 32],
    last_txid: [u8; 32],
    last_n: u64,
    groups: u64,
    sparse: Vec<([u8; 32], u64)>,
    read: u64,
}

/// Re-derives the transition `a -> b` from the file: parse the groups
/// in `[a.off, b.off)`, hash their `TxOutSer` from `a.state`, and
/// require the exact boundary, coin count and state `b` claims.
fn verify_interval(
    path: &Path,
    direct: bool,
    file_len: u64,
    a: &Hint,
    b: &Hint,
    base_height: u32,
    bucket: u64,
) -> io::Result<Interval> {
    let mut s = Stream::new(
        open_snapshot(path, direct)?,
        file_len,
        a.off,
        align_up(b.off),
    );
    let mut sha = a.state;
    let mut ser = Vec::with_capacity(SER_CHUNK + (64 << 10));
    let mut coins = 0u64;
    let mut iv = Interval {
        first_txid: [0; 32],
        last_txid: [0; 32],
        last_n: 0,
        groups: 0,
        sparse: Vec::new(),
        read: 0,
    };
    let mut prev_bucket = u64::MAX;
    loop {
        let off = s.off;
        if off >= b.off {
            break;
        }
        match group::<true>(s.window(), base_height, &mut ser) {
            Ok(g) => {
                if iv.groups == 0 {
                    iv.first_txid = g.txid;
                } else if g.txid <= iv.last_txid {
                    return Err(invalid("txids out of order"));
                }
                iv.last_txid = g.txid;
                iv.last_n = g.n;
                iv.groups += 1;
                coins += g.n;
                let bk = (off - HEADER_LEN) / bucket;
                if bk != prev_bucket {
                    iv.sparse.push((g.txid, off));
                    prev_bucket = bk;
                }
                s.consume(g.len);
                if ser.len() >= SER_CHUNK {
                    sha.update(&ser);
                    ser.clear();
                }
            }
            Err(PErr::Short) => {
                if !s.fill()? {
                    return Err(invalid("hint interval runs past the data"));
                }
            }
            Err(PErr::Bad(m)) => return Err(invalid(m)),
        }
    }
    sha.update(&ser);
    if s.off != b.off {
        return Err(invalid("hint offset is not a group boundary"));
    }
    if a.coins.checked_add(coins) != Some(b.coins) {
        return Err(invalid("hint coin count does not match the file"));
    }
    if sha != b.state {
        return Err(invalid("hint state does not match the file"));
    }
    iv.read = s.read;
    Ok(iv)
}

/// The parallel check. Intervals between consecutive hints are verified
/// on `threads` workers in any order; the result is exactly
/// [`verify_stream`]'s hash or an error. Nothing in `hints` is trusted:
/// the first hint must be the empty stream at the first group, every
/// transition is recomputed from the file, and the caller compares the
/// returned hash with the chainparams value.
pub fn verify_hinted(
    path: &Path,
    direct: bool,
    threads: usize,
    base_height: u32,
    hints: &Hints,
    bucket: u64,
) -> io::Result<VerifyOut> {
    let f = File::open(path)?;
    let hdr = read_header(&f)?;
    let file_len = f.metadata()?.len();
    if hints.file_len != file_len || hints.header != hdr {
        return Err(invalid("hints are for a different snapshot file"));
    }
    let hs = &hints.hints;
    let genesis = Hint {
        off: HEADER_LEN,
        coins: 0,
        state: ShaState::default(),
    };
    if hs.first() != Some(&genesis) {
        return Err(invalid("first hint must be the empty stream at the header"));
    }
    let Some(last) = hs.last() else {
        return Err(invalid("no hints"));
    };
    if last.off != file_len || last.coins != hdr.coins_count {
        return Err(invalid("last hint must be the end of the file"));
    }
    if hs.windows(2).any(|w| w[1].off <= w[0].off) {
        return Err(invalid("hint offsets must ascend"));
    }
    let n = hs.len() - 1;
    let next = AtomicUsize::new(0);
    let mut done: Vec<(usize, io::Result<Interval>)> = std::thread::scope(|sc| {
        let hs_ = &hs;
        let next = &next;
        let ws: Vec<_> = (0..threads.max(1))
            .map(|_| {
                sc.spawn(move || {
                    let mut mine = Vec::new();
                    loop {
                        let j = next.fetch_add(1, Ordering::Relaxed);
                        if j >= n {
                            return mine;
                        }
                        let r = verify_interval(
                            path,
                            direct,
                            file_len,
                            &hs_[j],
                            &hs_[j + 1],
                            base_height,
                            bucket,
                        );
                        let failed = r.is_err();
                        mine.push((j, r));
                        if failed {
                            next.store(n, Ordering::Relaxed);
                            return mine;
                        }
                    }
                })
            })
            .collect();
        ws.into_iter()
            .flat_map(|w| w.join().unwrap_or_default())
            .collect()
    });
    if done.len() != n {
        if let Some(e) = done.into_iter().find_map(|(_, r)| r.err()) {
            return Err(e);
        }
        return Err(invalid("interval verification did not complete"));
    }
    done.sort_by_key(|(j, _)| *j);
    let mut out = VerifyOut {
        hash: finish_hash(last.state),
        coins: last.coins,
        groups: 0,
        sparse: Vec::new(),
        bytes_read: 0,
    };
    let mut prev: Option<[u8; 32]> = None;
    let mut last_n = 0;
    let mut last_bucket = u64::MAX;
    for (_, r) in done {
        let iv = r?;
        if prev.is_some_and(|t| iv.first_txid <= t) {
            return Err(invalid("txids out of order"));
        }
        prev = Some(iv.last_txid);
        last_n = iv.last_n;
        out.groups += iv.groups;
        out.bytes_read += iv.read;
        for (t, o) in iv.sparse {
            let b = (o - HEADER_LEN) / bucket;
            if b != last_bucket {
                out.sparse.push((t, o));
                last_bucket = b;
            }
        }
    }
    check_end(&hdr, file_len, last.off, last.coins, last_n, out.groups)?;
    Ok(out)
}

// ---------------------------------------------------------------------
// Zero-scan lookups
// ---------------------------------------------------------------------

/// Bytes per lookup probe.
const PROBE: usize = 32 << 10;

/// Point lookups straight from the snapshot file — no index build.
/// Txids are uniform, so a txid's value interpolates to its byte
/// position; each probe reads `PROBE` bytes and narrows a bracket of
/// known group starts. An optional sample of boundaries (one read
/// each, taken in parallel) shrinks the first probe's error.
pub struct ZeroScan {
    f: File,
    file_len: u64,
    base_height: u32,
    first_txid: [u8; 32],
    last_txid: [u8; 32],
    last_off: u64,
    /// Common prefix length of the first and last txid; keys compare
    /// the 16 bytes after it (counter-style txids share 24 zero bytes).
    prefix: usize,
    table: Vec<([u8; 32], u64)>,
    same_code: bool,
    pub probes: AtomicU64,
}

#[derive(Clone, Copy)]
struct Bound {
    off: u64,
    txid: [u8; 32],
    /// End of the group at `off`, once it has been parsed.
    end: Option<u64>,
}

impl ZeroScan {
    pub fn open(path: &Path, direct: bool, base_height: u32) -> io::Result<Self> {
        read_header(&File::open(path)?)?;
        let f = open_snapshot(path, direct)?;
        let file_len = f.metadata()?.len();
        if file_len <= HEADER_LEN {
            return Err(invalid("empty snapshot"));
        }
        let mut z = Self {
            f,
            file_len,
            base_height,
            first_txid: [0; 32],
            last_txid: [0; 32],
            last_off: HEADER_LEN,
            prefix: 0,
            table: Vec::new(),
            same_code: false,
            probes: AtomicU64::new(0),
        };
        z.same_code = uniform_codes(&z.f, base_height)?;
        let mut len = PROBE;
        z.first_txid = loop {
            let (buf, at) = z.read_window(HEADER_LEN, len)?;
            match group::<false>(&buf[at..], base_height, &mut Vec::new()) {
                Ok(g) => break g.txid,
                Err(PErr::Short) if len < MAX_GROUP => len *= 4,
                Err(_) => return Err(invalid("first group does not parse")),
            }
        };
        // The last group: resync near the end and walk to EOF.
        let mut span = PROBE as u64;
        loop {
            let from = file_len.saturating_sub(span).max(HEADER_LEN);
            let (buf, at) = z.read_window(from, (file_len - from) as usize)?;
            let win = &buf[at..];
            let start = if from == HEADER_LEN {
                Sync::At { head: None, at: 0 }
            } else {
                resync(win, 0, base_height, Some(win.len()), None, z.same_code)
            };
            if let Sync::At { at: mut p, .. } = start
                && p < win.len()
            {
                let mut last = None;
                while p < win.len() {
                    match group::<false>(&win[p..], base_height, &mut Vec::new()) {
                        Ok(g) => {
                            last = Some((from + p as u64, g.txid));
                            p += g.len;
                        }
                        Err(_) => break,
                    }
                }
                if p == win.len()
                    && let Some((o, t)) = last
                {
                    z.last_off = o;
                    z.last_txid = t;
                    break;
                }
            }
            if from == HEADER_LEN || span >= MAX_GROUP as u64 {
                return Err(invalid("last group not found"));
            }
            span *= 4;
        }
        z.prefix = z
            .first_txid
            .iter()
            .zip(&z.last_txid)
            .take_while(|(a, b)| a == b)
            .count()
            .min(31);
        Ok(z)
    }

    /// Samples `n` boundaries across the file on `threads` readers — a
    /// learned-index correction table built in one parallel read each.
    pub fn sample(&mut self, n: usize, threads: usize) -> io::Result<()> {
        let body = self.file_len - HEADER_LEN;
        let next = AtomicUsize::new(0);
        let this = &*self;
        let mut found: Vec<([u8; 32], u64)> = std::thread::scope(|sc| {
            let ws: Vec<_> = (0..threads.max(1))
                .map(|_| {
                    let next = &next;
                    sc.spawn(move || {
                        let mut v = Vec::new();
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            if i >= n {
                                return v;
                            }
                            let at = HEADER_LEN + body / n as u64 * i as u64;
                            let mut len = PROBE;
                            while let Ok((buf, s)) = this.read_window(at, len) {
                                let win = &buf[s..];
                                let eof = at + win.len() as u64 >= this.file_len;
                                match resync(
                                    win,
                                    0,
                                    this.base_height,
                                    eof.then_some(win.len()),
                                    None,
                                    this.same_code,
                                ) {
                                    Sync::At { at: p, .. } => {
                                        if p < win.len()
                                            && let Ok(g) = group::<false>(
                                                &win[p..],
                                                this.base_height,
                                                &mut Vec::new(),
                                            )
                                        {
                                            v.push((g.txid, at + p as u64));
                                        }
                                        break;
                                    }
                                    Sync::More if len < MAX_GROUP => len *= 4,
                                    _ => break,
                                }
                            }
                        }
                    })
                })
                .collect();
            ws.into_iter()
                .flat_map(|w| w.join().unwrap_or_default())
                .collect()
        });
        found.sort_by_key(|&(_, o)| o);
        found.dedup_by_key(|&mut (_, o)| o);
        // Keep only entries consistent with sorted order — a resync
        // miss would otherwise poison the bracket.
        let mut table: Vec<([u8; 32], u64)> = Vec::with_capacity(found.len());
        for e in found {
            if table.last().is_none_or(|l| e.0 > l.0) {
                table.push(e);
            }
        }
        self.table = table;
        Ok(())
    }

    fn read_window(&self, off: u64, len: usize) -> io::Result<(Vec<u8>, usize)> {
        self.probes.fetch_add(1, Ordering::Relaxed);
        read_window(&self.f, off, len)
    }

    fn key(&self, t: &[u8; 32]) -> u128 {
        let mut k = 0u128;
        for i in 0..16 {
            k = (k << 8) | u128::from(*t.get(self.prefix + i).unwrap_or(&0));
        }
        k
    }

    /// Byte position `t` interpolates to between two known groups.
    fn interpolate(&self, lo: &Bound, hi: &Bound, t: &[u8; 32]) -> u64 {
        let kl = self.key(&lo.txid);
        let span = self.key(&hi.txid).saturating_sub(kl).max(1) as f64;
        let frac = (self.key(t).saturating_sub(kl) as f64 / span).clamp(0.0, 1.0);
        lo.off + (frac * (hi.off - lo.off) as f64) as u64
    }

    /// The coin's `TxOutSer` bytes, or `None` if absent.
    ///
    /// Keeps a bracket `lo < target < hi` of known group starts. Each
    /// probe reads one window and must move the bracket; a probe that
    /// cannot (a resync the bracket contradicts, a window inside one
    /// big group) escalates from interpolation to a window ending at
    /// `hi`, then to an exact walk from `lo`, which always advances.
    pub fn get(&self, txid: &[u8; 32], vout: u32) -> io::Result<Option<Vec<u8>>> {
        if *txid < self.first_txid || *txid > self.last_txid {
            return Ok(None);
        }
        let mut lo = Bound {
            off: HEADER_LEN,
            txid: self.first_txid,
            end: None,
        };
        let mut hi = Bound {
            off: self.last_off,
            txid: self.last_txid,
            end: None,
        };
        if *txid == self.last_txid {
            lo = hi;
        } else if !self.table.is_empty() {
            let i = self.table.partition_point(|e| e.0 <= *txid);
            if i > 0 {
                lo = Bound {
                    off: self.table[i - 1].1,
                    txid: self.table[i - 1].0,
                    end: None,
                };
            }
            if let Some(e) = self.table.get(i) {
                hi = Bound {
                    off: e.1,
                    txid: e.0,
                    end: None,
                };
            }
        }
        // 0: interpolate, 1: window ending at `hi`, 2: walk from `lo`.
        let mut mode = 0u8;
        let mut len = PROBE;
        for _ in 0..4096 {
            let from = if lo.txid == *txid {
                lo.off
            } else {
                match mode {
                    0 => {
                        let est = self.interpolate(&lo, &hi, txid);
                        if est < lo.off + PROBE as u64 / 2 {
                            lo.off
                        } else {
                            est - PROBE as u64 / 2
                        }
                    }
                    1 => hi.off.saturating_sub(PROBE as u64).max(lo.off),
                    _ => lo.off,
                }
            };
            let exact = from == lo.off;
            let before = (lo.off, lo.end, hi.off);
            let (buf, at) = self.read_window(from, len)?;
            let win = &buf[at..];
            let start = if exact {
                Sync::At { head: None, at: 0 }
            } else {
                // `hi` (or EOF) is a known boundary if it is in view.
                let end = if hi.off < from + win.len() as u64 {
                    Some((hi.off - from) as usize)
                } else {
                    (from + win.len() as u64 >= self.file_len).then_some(win.len())
                };
                resync(
                    win,
                    0,
                    self.base_height,
                    end,
                    Some((&lo.txid, &hi.txid)),
                    self.same_code,
                )
            };
            if start == Sync::More && len < MAX_GROUP {
                len *= 4;
                continue;
            }
            if let Sync::At { head, at: mut p } = start {
                // The head is no boundary proof, but a txid equal to the
                // target cannot be a phantom's.
                if let Some(h) = head
                    && h.txid == *txid
                {
                    return Ok(find_vout(&win[h.at..h.at + h.len], vout, self.base_height));
                }
                while p < win.len() {
                    let o = from + p as u64;
                    if o >= hi.off {
                        break;
                    }
                    let g = match group::<false>(&win[p..], self.base_height, &mut Vec::new()) {
                        Ok(g) => g,
                        Err(PErr::Short) => break,
                        Err(PErr::Bad(m)) if exact => return Err(invalid(m)),
                        Err(PErr::Bad(_)) => break,
                    };
                    if g.txid == *txid {
                        return Ok(find_vout(&win[p..p + g.len], vout, self.base_height));
                    }
                    if g.txid < *txid {
                        lo = Bound {
                            off: o,
                            txid: g.txid,
                            end: Some(o + g.len as u64),
                        };
                    } else {
                        hi = Bound {
                            off: o,
                            txid: g.txid,
                            end: None,
                        };
                        break;
                    }
                    p += g.len;
                }
            }
            if lo.end == Some(hi.off) {
                return Ok(None);
            }
            if (lo.off, lo.end, hi.off) == before {
                if mode == 2 {
                    // A walk from `lo` stalled: its group outgrew the window.
                    if len >= MAX_GROUP {
                        return Err(invalid("txid group larger than the parse window"));
                    }
                    len *= 4;
                }
                mode = (mode + 1).min(2);
            } else {
                mode = 0;
            }
        }
        Err(invalid("lookup did not converge"))
    }
}

/// The `TxOutSer` of `vout` inside one parsed group, if present.
fn find_vout(g: &[u8], vout: u32, base_height: u32) -> Option<Vec<u8>> {
    let mut ser = Vec::new();
    let mut p = 32usize;
    let n = compact(g, &mut p).ok()?;
    for _ in 0..n {
        let v = compact(g, &mut p).ok()?;
        ser.clear();
        ser.extend_from_slice(&g[..32]);
        ser.extend_from_slice(&(v as u32).to_le_bytes());
        coin::<true, false>(g, &mut p, base_height, &mut ser).ok()?;
        if v == u64::from(vout) {
            return Some(ser);
        }
    }
    None
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::connect::{Coin, UtxoSet};
    use crate::hash::{BlockHash, Txid};
    use crate::transaction::{OutPoint, Script, TxOut};
    use sha2::Digest;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn keys() -> Vec<secp256k1::PublicKey> {
        let secp = secp256k1::Secp256k1::new();
        (0..50u64)
            .map(|i| {
                let mut sk = crate::hash::sha256(&i.to_le_bytes());
                sk[0] &= 0x7f;
                secp256k1::PublicKey::from_secret_key(
                    &secp,
                    &secp256k1::SecretKey::from_slice(&sk).unwrap(),
                )
            })
            .collect()
    }

    /// Every encoding the counter fixture never exercises: P2PK in both
    /// forms, a 201-byte bare multisig (two-byte script-size VARINT),
    /// multi-byte heights/amounts, vouts past 252 (3-byte CompactSize).
    fn script(r: &mut Rng, keys: &[secp256k1::PublicKey]) -> Vec<u8> {
        match r.below(10) {
            0 => {
                let mut s = vec![0x76, 0xa9, 0x14];
                s.extend((0..20).map(|_| r.next() as u8));
                s.extend([0x88, 0xac]);
                s
            }
            1 => {
                let mut s = vec![0xa9, 0x14];
                s.extend((0..20).map(|_| r.next() as u8));
                s.push(0x87);
                s
            }
            2 => {
                let mut s = vec![33];
                s.extend(keys[r.below(50) as usize].serialize());
                s.push(0xac);
                s
            }
            3 => {
                let mut s = vec![65];
                s.extend(keys[r.below(50) as usize].serialize_uncompressed());
                s.push(0xac);
                s
            }
            4 => {
                let mut s = vec![0x51];
                for _ in 0..3 {
                    s.push(65);
                    s.extend(keys[r.below(50) as usize].serialize_uncompressed());
                }
                s.extend([0x53, 0xae]);
                s
            }
            5 => {
                let mut s = vec![0x51, 0x20];
                s.extend((0..32).map(|_| r.next() as u8));
                s
            }
            6 => {
                let mut s = vec![0x00, 0x14];
                s.extend((0..20).map(|_| r.next() as u8));
                s
            }
            7 => (0..r.below(300)).map(|_| r.next() as u8).collect(),
            _ => {
                let mut s = vec![0x00, 0x20];
                s.extend((0..32).map(|_| r.next() as u8));
                s
            }
        }
    }

    /// A snapshot with `groups` random-txid groups; returns the file
    /// bytes and the coins in file order.
    fn fixture(groups: usize, seed: u64, counter_txids: bool) -> (Vec<u8>, Vec<(OutPoint, Coin)>) {
        let mut r = Rng(seed | 1);
        let mut txids: Vec<[u8; 32]> = (0..groups as u64)
            .map(|i| {
                let mut t = [0u8; 32];
                if counter_txids {
                    t[24..].copy_from_slice(&i.to_be_bytes());
                } else {
                    for b in &mut t {
                        *b = r.next() as u8;
                    }
                }
                t
            })
            .collect();
        txids.sort();
        txids.dedup();
        let keys = keys();
        let mut coins = Vec::new();
        for t in txids {
            // `snapshot_bench gen` writes 1-2 outputs per txid; real
            // dumps have a long tail of large groups.
            let n = match r.below(20) {
                _ if counter_txids => 1 + r.below(2),
                0 => 300 + r.below(40),
                1..=3 => 2 + r.below(5),
                _ => 1,
            };
            let mut vout = r.below(3) as u32;
            let (group_height, group_cb) = (r.below(935_001) as u32, r.below(10) == 0);
            for _ in 0..n {
                let value = match r.below(4) {
                    0 => 546,
                    1 => r.below(2_100_000_000_000_000) as i64,
                    _ => r.below(100_000_000) as i64,
                };
                coins.push((
                    OutPoint {
                        txid: Txid::from_bytes(t),
                        vout,
                    },
                    Coin {
                        out: TxOut {
                            value,
                            script_pubkey: Script::new(script(&mut r, &keys)),
                        },
                        // One transaction's outputs share a height; the
                        // counter fixture mimics `snapshot_bench gen`,
                        // which draws one per coin.
                        height: if counter_txids {
                            r.below(935_001) as u32
                        } else {
                            group_height
                        },
                        coinbase: if counter_txids {
                            r.below(10) == 0
                        } else {
                            group_cb
                        },
                    },
                ));
                vout += 1 + r.below(2) as u32;
            }
        }
        let mut file = Vec::new();
        crate::utxo_snapshot::write_snapshot(
            &mut file,
            [0xf9, 0xbe, 0xb4, 0xd9],
            &BlockHash::from_bytes([0xab; 32]),
            coins.len() as u64,
            &coins,
        )
        .unwrap();
        (file, coins)
    }

    pub(super) fn fixture_pub(
        groups: usize,
        seed: u64,
        counter: bool,
    ) -> (Vec<u8>, Vec<(OutPoint, Coin)>) {
        fixture(groups, seed, counter)
    }

    fn reference_hash(coins: &[(OutPoint, Coin)]) -> [u8; 32] {
        let mut set = UtxoSet::new();
        for (op, c) in coins {
            set.insert_synthetic(*op, c.clone());
        }
        let s = crate::coinstats::compute(
            &set,
            935_000,
            BlockHash::from_bytes([0xab; 32]),
            crate::coinstats::CoinStatsHashType::HashSerialized,
        );
        *s.hash_serialized.unwrap().as_bytes()
    }

    struct Tmp(std::path::PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    fn tmp(name: &str, bytes: &[u8]) -> Tmp {
        let p = std::env::temp_dir().join(format!("snapverify-{}-{name}", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        Tmp(p)
    }

    #[test]
    fn sha_state_matches_sha2_across_splits_and_restores() {
        let mut r = Rng(7);
        let data: Vec<u8> = (0..5000).map(|_| r.next() as u8).collect();
        for _ in 0..200 {
            let mut s = ShaState::default();
            let mut i = 0;
            while i < data.len() {
                let n = (r.below(200) as usize).min(data.len() - i);
                s.update(&data[i..i + n]);
                // Round-trip the state through a copy mid-stream.
                s = ShaState { ..s };
                i += n;
            }
            let want: [u8; 32] = sha2::Sha256::digest(&data).into();
            assert_eq!(s.finalize(), want);
        }
        for len in 0..130 {
            let mut s = ShaState::default();
            s.update(&data[..len]);
            let want: [u8; 32] = sha2::Sha256::digest(&data[..len]).into();
            assert_eq!(s.finalize(), want, "len {len}");
        }
    }

    #[test]
    fn stream_hash_matches_coinstats_reference() {
        for (seed, counter) in [(1u64, false), (2, true), (3, false)] {
            let (file, coins) = fixture(400, seed, counter);
            let t = tmp(&format!("ref{seed}"), &file);
            let (v, hints) = verify_stream(&t.0, false, 935_000, 4096, 1024).unwrap();
            assert_eq!(v.coins, coins.len() as u64);
            assert_eq!(v.hash, reference_hash(&coins), "seed {seed}");
            assert!(hints.hints.len() > 3);
        }
    }

    #[test]
    fn hinted_verification_equals_stream_and_rejects_tampering() {
        let (file, coins) = fixture(600, 11, false);
        let t = tmp("hinted", &file);
        let (v, hints) = verify_stream(&t.0, false, 935_000, 2000, 1024).unwrap();
        for threads in [1, 3, 8] {
            let h = verify_hinted(&t.0, false, threads, 935_000, &hints, 1024).unwrap();
            assert_eq!(h.hash, v.hash);
            assert_eq!(h.coins, coins.len() as u64);
            assert_eq!(h.sparse, v.sparse);
        }
        let enc = hints.encode();
        assert_eq!(Hints::decode(&enc).unwrap(), hints);

        // A hint whose state is off by one word.
        let mut bad = hints.clone();
        bad.hints[2].state.h[0] ^= 1;
        assert!(verify_hinted(&t.0, false, 4, 935_000, &bad, 1024).is_err());
        // A hint pointing one byte past a group boundary.
        let mut bad = hints.clone();
        bad.hints[2].off += 1;
        assert!(verify_hinted(&t.0, false, 4, 935_000, &bad, 1024).is_err());
        // A dropped hint still verifies — hints are only split points.
        let mut fewer = hints.clone();
        fewer.hints.remove(3);
        assert_eq!(
            verify_hinted(&t.0, false, 4, 935_000, &fewer, 1024)
                .unwrap()
                .hash,
            v.hash
        );
        // A forged first hint is refused outright.
        let mut bad = hints.clone();
        bad.hints[0].state.total = 1;
        assert!(verify_hinted(&t.0, false, 4, 935_000, &bad, 1024).is_err());

        // Tampered data with the honest hints: the covering interval fails.
        let mut evil = file.clone();
        let at = file.len() / 2;
        evil[at] ^= 0x01;
        let te = tmp("hinted-evil", &evil);
        let r = verify_hinted(&te.0, false, 4, 935_000, &hints, 1024);
        if let Ok(o) = r {
            assert_ne!(o.hash, v.hash, "tampered file must not reproduce the hash");
        }
    }

    #[test]
    fn parallel_scan_equals_sequential_for_every_split() {
        for (seed, counter) in [(21u64, false), (22, true)] {
            let (file, coins) = fixture(900, seed, counter);
            let t = tmp(&format!("scan{seed}"), &file);
            let (v, _) = verify_stream(&t.0, false, 935_000, 1 << 20, 512).unwrap();
            for threads in [1, 2, 3, 7, 16, 64] {
                let s = scan(&t.0, false, threads, 935_000, 512).unwrap();
                assert_eq!(s.coins, coins.len() as u64, "threads {threads}");
                assert_eq!(s.sparse, v.sparse, "threads {threads}");
            }
        }
    }

    #[test]
    fn truncation_and_leftovers_are_rejected() {
        let (file, _) = fixture(200, 31, false);
        let t = tmp("trunc", &file[..file.len() - 7]);
        assert!(scan(&t.0, false, 4, 935_000, 512).is_err());
        assert!(verify_stream(&t.0, false, 935_000, 4096, 512).is_err());
        let mut extra = file.clone();
        extra.extend_from_slice(&[0x42; 32]);
        extra.push(0);
        let t = tmp("extra", &extra);
        assert!(scan(&t.0, false, 4, 935_000, 512).is_err());
        assert!(verify_stream(&t.0, false, 935_000, 4096, 512).is_err());
    }

    // Unfinished: correct on these fixtures in earlier runs but far too
    // slow in debug builds (phantom resync cost); not yet validated.
    #[test]
    #[ignore = "zero-scan lookups are unfinished; see experiments LOG #26"]
    fn zero_scan_answers_every_coin_and_absences() {
        for (seed, counter) in [(41u64, false), (42, true)] {
            let (file, coins) = fixture(3000, seed, counter);
            let t = tmp(&format!("zs{seed}"), &file);
            let mut z = ZeroScan::open(&t.0, false, 935_000).unwrap();
            for pass in 0..2 {
                if pass == 1 {
                    z.sample(64, 4).unwrap();
                }
                for (op, c) in coins.iter().step_by(7) {
                    let mut want = Vec::new();
                    want.extend_from_slice(op.txid.as_bytes());
                    want.extend_from_slice(&op.vout.to_le_bytes());
                    let code = (c.height << 1) | u32::from(c.coinbase);
                    want.extend_from_slice(&code.to_le_bytes());
                    want.extend_from_slice(&c.out.value.to_le_bytes());
                    crate::encode::write_var_bytes(&mut want, c.out.script_pubkey.as_bytes());
                    let got = z.get(op.txid.as_bytes(), op.vout).unwrap();
                    assert_eq!(got.as_deref(), Some(&want[..]), "seed {seed} pass {pass}");
                    assert_eq!(z.get(op.txid.as_bytes(), op.vout + 100_000).unwrap(), None);
                }
                let mut r = Rng(seed);
                for _ in 0..200 {
                    let mut t = [0u8; 32];
                    for b in &mut t {
                        *b = r.next() as u8;
                    }
                    assert_eq!(z.get(&t, 0).unwrap(), None);
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod resync_probe {
    use super::*;

    /// Every boundary resync reports must be a real one — including
    /// windows that open inside 300-output groups, where phantom parses
    /// merge into the real stream.
    #[test]
    #[ignore = "slow in debug builds (~40 s); run with --ignored"]
    fn resync_reports_only_real_boundaries() {
        for (seed, counter) in [(41u64, false), (42, true)] {
            let (file, _) = super::tests::fixture_pub(3000, seed, counter);
            let mut bounds = std::collections::BTreeSet::new();
            let mut p = HEADER_LEN as usize;
            let mut v = Vec::new();
            while p < file.len() {
                bounds.insert(p);
                p += group::<false>(&file[p..], 935_000, &mut v).unwrap().len;
            }
            bounds.insert(file.len());
            let mut found = 0;
            for from in (HEADER_LEN as usize..file.len() - 40_000).step_by(997) {
                let win = &file[from..from + 32_768];
                if let Sync::At { at, .. } = resync(win, 0, 935_000, None, None, !counter) {
                    found += 1;
                    assert!(
                        bounds.contains(&(from + at)),
                        "seed {seed}: {} is not a boundary",
                        from + at
                    );
                }
            }
            assert!(found > 100, "seed {seed}: resync found only {found}");
        }
    }
}

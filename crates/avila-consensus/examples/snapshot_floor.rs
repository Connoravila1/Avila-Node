//! Experimental snapshot startup: overlap parsing with reads, or prepare a
//! persisted, authenticated sparse index and verify only the chunks accessed.
//!
//! This is NOT a chainstate backend or a consensus validator. `pack` checks
//! framing/order/counts, not AssumeUTXO's semantic content hash. A root printed
//! by an untrusted producer is not a trusted checkpoint. See the experiment doc.
//!
//! scan SNAPSHOT [serial|pipeline]
//! pack SNAPSHOT INDEX [serial|pipeline] [groups_per_chunk]
//! bench SNAPSHOT INDEX TRUSTED_ROOT QUERY_FILE
//!
//! pack also writes INDEX.queries: deterministic sampled outpoints + coin hashes.
//! All output files use create_new. Existing snapshots are opened read-only.

use avila_consensus::{hash::sha256, hex, utxo_snapshot::read_metadata};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::mpsc::{Receiver, sync_channel};
use std::time::Instant;

const HEADER: usize = 51;
const MAGIC: &[u8; 8] = b"AVSIDX01";
const ENTRY: usize = 88; // first txid | offset | length | coin count | sha256
const INDEX_HEADER: usize = 8 + HEADER + 8 + 8;
const READ_SIZE: usize = 8 << 20;
const MAX_CHUNK: usize = 64 << 20;
const MAX_INDEX: u64 = 128 << 20;
const SAMPLE_STRIDE: u64 = 65_536;

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn take<'a>(b: &'a [u8], p: &mut usize, n: usize) -> io::Result<&'a [u8]> {
    let end = p.checked_add(n).ok_or_else(|| bad("length overflow"))?;
    let result = b
        .get(*p..end)
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    *p = end;
    Ok(result)
}

fn fixed<const N: usize>(b: &[u8], p: &mut usize) -> io::Result<[u8; N]> {
    take(b, p, N)?
        .try_into()
        .map_err(|_| bad("fixed-width field"))
}

fn compact(b: &[u8], p: &mut usize) -> io::Result<u64> {
    let tag = take(b, p, 1)?[0];
    let (v, min) = match tag {
        253 => (u64::from(u16::from_le_bytes(fixed(b, p)?)), 253),
        254 => (u64::from(u32::from_le_bytes(fixed(b, p)?)), 65_536),
        255 => (u64::from_le_bytes(fixed(b, p)?), 1 << 32),
        _ => return Ok(u64::from(tag)),
    };
    if v < min {
        return Err(bad("noncanonical CompactSize"));
    }
    Ok(v)
}

fn varint(b: &[u8], p: &mut usize) -> io::Result<u64> {
    let mut n = 0u64;
    loop {
        let c = take(b, p, 1)?[0];
        if n > u64::MAX >> 7 {
            return Err(bad("VARINT overflow"));
        }
        n = (n << 7) | u64::from(c & 127);
        if c & 128 == 0 {
            return Ok(n);
        }
        // Core's VARINT is not ordinary base-128: continuation adds one.
        n = n.checked_add(1).ok_or_else(|| bad("VARINT overflow"))?;
    }
}

fn coin_span(b: &[u8], p: &mut usize) -> io::Result<(u32, std::ops::Range<usize>)> {
    let vout = compact(b, p)?;
    if vout >= u64::from(u32::MAX) {
        return Err(bad("outpoint index out of range"));
    }
    let start = *p;
    varint(b, p)?; // height/coinbase; semantic validation belongs to the importer
    varint(b, p)?; // amount
    let size = varint(b, p)?;
    let payload = match size {
        0 | 1 => 20,
        2..=5 => 32,
        n => n - 6,
    };
    if payload > MAX_CHUNK as u64 {
        return Err(bad("script exceeds experiment's 64 MiB chunk limit"));
    }
    take(b, p, payload as usize)?;
    Ok((vout as u32, start..*p))
}

struct Group {
    txid: [u8; 32],
    coins: u64,
    end: usize,
}

fn group(b: &[u8], mut p: usize) -> io::Result<Group> {
    let txid = fixed(b, &mut p)?;
    let coins = compact(b, &mut p)?;
    if coins == 0 || coins > MAX_CHUNK as u64 / 4 {
        return Err(bad("empty or oversized txid group"));
    }
    for _ in 0..coins {
        coin_span(b, &mut p)?;
    }
    Ok(Group {
        txid,
        coins,
        end: p,
    })
}

// A bounded reader thread: at most two queued 8 MiB buffers. Parsing can run
// while the next read blocks. No unsafe code, mmap, new dependency, or key guess.
struct Pipeline {
    rx: Receiver<io::Result<Vec<u8>>>,
    buffer: Vec<u8>,
    pos: usize,
}

impl Pipeline {
    fn new(mut source: File) -> Self {
        let (tx, rx) = sync_channel(2);
        std::thread::spawn(move || {
            loop {
                let mut b = vec![0; READ_SIZE];
                match source.read(&mut b) {
                    Ok(0) => break,
                    Ok(n) => {
                        b.truncate(n);
                        if tx.send(Ok(b)).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        break;
                    }
                }
            }
        });
        Self {
            rx,
            buffer: Vec::new(),
            pos: 0,
        }
    }
}

impl Read for Pipeline {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.pos == self.buffer.len() {
            self.buffer = match self.rx.recv() {
                Ok(b) => b?,
                Err(_) => return Ok(0),
            };
            self.pos = 0;
        }
        let n = out.len().min(self.buffer.len() - self.pos);
        out[..n].copy_from_slice(&self.buffer[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[derive(Clone)]
struct Entry {
    first: [u8; 32],
    offset: u64,
    length: u64,
    coins: u64,
    hash: [u8; 32],
}

struct Prepared {
    header: [u8; HEADER],
    file_len: u64,
    entries: Vec<Entry>,
    queries: Vec<u8>,
    coins: u64,
    groups: u64,
}

fn scan(
    mut source: impl Read,
    header: [u8; HEADER],
    file_len: u64,
    stride: usize,
    authenticate: bool,
) -> io::Result<Prepared> {
    if stride == 0 {
        return Err(bad("groups_per_chunk must be positive"));
    }
    let meta = read_metadata(
        &mut &header[..],
        header[7..11].try_into().map_err(|_| bad("network"))?,
    )
    .map_err(|e| bad(&e.to_string()))?;
    let mut result = Prepared {
        header,
        file_len,
        entries: Vec::new(),
        queries: Vec::new(),
        coins: 0,
        groups: 0,
    };
    let mut data = Vec::new();
    let mut pos = 0;
    let mut offset = HEADER as u64;
    let mut previous = None;
    while result.coins < meta.coins_count {
        let mut start = pos;
        let mut first = [0; 32];
        let mut chunk_coins = 0;
        for g in 0..stride {
            if result.coins == meta.coins_count {
                break;
            }
            let parsed = loop {
                match group(&data, pos) {
                    Ok(parsed) => break parsed,
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                        data.copy_within(start.., 0);
                        data.truncate(data.len() - start);
                        offset += start as u64;
                        pos -= start;
                        start = 0;
                        if data.len() >= MAX_CHUNK {
                            return Err(bad("chunk exceeds experiment's 64 MiB limit"));
                        }
                        let old = data.len();
                        data.resize((old + READ_SIZE).min(MAX_CHUNK), 0);
                        let n = loop {
                            match source.read(&mut data[old..]) {
                                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                                other => break other?,
                            }
                        };
                        data.truncate(old + n);
                        if n == 0 {
                            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                        }
                    }
                    Err(e) => return Err(e),
                }
            };
            if previous.is_some_and(|p| p >= parsed.txid) {
                return Err(bad("txid groups must strictly ascend"));
            }
            if parsed.coins > meta.coins_count - result.coins {
                return Err(bad("coin count exceeds snapshot header"));
            }
            if parsed.end - start > MAX_CHUNK {
                return Err(bad("chunk exceeds experiment's 64 MiB limit"));
            }
            if g == 0 {
                first = parsed.txid;
            }
            // Rare second walk generates an independent lookup corpus while
            // packing. Query timers never pre-read the source to find targets.
            if authenticate {
                let mut sample = result.coins.div_ceil(SAMPLE_STRIDE) * SAMPLE_STRIDE;
                if sample < result.coins + parsed.coins {
                    let mut p = pos + 32;
                    compact(&data, &mut p)?;
                    for i in result.coins..result.coins + parsed.coins {
                        let (vout, body) = coin_span(&data, &mut p)?;
                        if i == sample {
                            result.queries.extend_from_slice(&parsed.txid);
                            result.queries.extend_from_slice(&vout.to_le_bytes());
                            result.queries.extend_from_slice(&sha256(&data[body]));
                            sample += SAMPLE_STRIDE;
                        }
                    }
                }
            }
            previous = Some(parsed.txid);
            pos = parsed.end;
            result.coins += parsed.coins;
            chunk_coins += parsed.coins;
            result.groups += 1;
        }
        result.entries.push(Entry {
            first,
            offset: offset + start as u64,
            length: (pos - start) as u64,
            coins: chunk_coins,
            hash: if authenticate {
                sha256(&data[start..pos])
            } else {
                [0; 32]
            },
        });
        if result.entries.len() > (MAX_INDEX as usize - INDEX_HEADER) / ENTRY {
            return Err(bad("index exceeds experiment's 128 MiB limit"));
        }
    }
    if pos != data.len() || offset + pos as u64 != file_len || source.read(&mut [0])? != 0 {
        return Err(bad("trailing bytes or source length changed"));
    }
    Ok(result)
}

impl Prepared {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INDEX_HEADER + self.entries.len() * ENTRY);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.file_len.to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.first);
            out.extend_from_slice(&e.offset.to_le_bytes());
            out.extend_from_slice(&e.length.to_le_bytes());
            out.extend_from_slice(&e.coins.to_le_bytes());
            out.extend_from_slice(&e.hash);
        }
        out
    }
}

struct Indexed {
    source: File,
    entries: Vec<Entry>,
    bytes_read: u64,
}

impl Indexed {
    fn open(source: &Path, index: &Path, trusted_root: [u8; 32]) -> io::Result<Self> {
        let file = File::open(index)?;
        if file.metadata()?.len() > MAX_INDEX {
            return Err(bad("index too large"));
        }
        let mut b = Vec::new();
        file.take(MAX_INDEX + 1).read_to_end(&mut b)?;
        if b.len() as u64 > MAX_INDEX || sha256(&b) != trusted_root {
            return Err(bad("index does not match trusted root"));
        }
        let mut p = 0;
        if take(&b, &mut p, 8)? != MAGIC {
            return Err(bad("index magic/version"));
        }
        let header: [u8; HEADER] = fixed(&b, &mut p)?;
        let file_len = u64::from_le_bytes(fixed(&b, &mut p)?);
        let n = u64::from_le_bytes(fixed(&b, &mut p)?);
        if n > MAX_INDEX / ENTRY as u64 || b.len() != INDEX_HEADER + n as usize * ENTRY {
            return Err(bad("index length"));
        }
        let meta = read_metadata(
            &mut &header[..],
            header[7..11].try_into().map_err(|_| bad("network"))?,
        )
        .map_err(|e| bad(&e.to_string()))?;
        let mut source = File::open(source)?;
        let mut actual_header = [0; HEADER];
        source.read_exact(&mut actual_header)?;
        if source.metadata()?.len() != file_len || actual_header != header {
            return Err(bad("snapshot header/length does not match index"));
        }
        let mut entries: Vec<Entry> = Vec::with_capacity(n as usize);
        let mut offset = HEADER as u64;
        let mut coins = 0u64;
        for _ in 0..n {
            let e = Entry {
                first: fixed(&b, &mut p)?,
                offset: u64::from_le_bytes(fixed(&b, &mut p)?),
                length: u64::from_le_bytes(fixed(&b, &mut p)?),
                coins: u64::from_le_bytes(fixed(&b, &mut p)?),
                hash: fixed(&b, &mut p)?,
            };
            if e.offset != offset
                || e.length == 0
                || e.length > MAX_CHUNK as u64
                || e.coins == 0
                || entries.last().is_some_and(|last| last.first >= e.first)
            {
                return Err(bad("invalid chunk bounds/order"));
            }
            offset = offset
                .checked_add(e.length)
                .ok_or_else(|| bad("offset overflow"))?;
            coins = coins
                .checked_add(e.coins)
                .ok_or_else(|| bad("count overflow"))?;
            entries.push(e);
        }
        if offset != file_len || coins != meta.coins_count {
            return Err(bad("index does not cover snapshot"));
        }
        Ok(Self {
            source,
            entries,
            bytes_read: b.len() as u64 + HEADER as u64,
        })
    }

    fn get(&mut self, txid: &[u8; 32], vout: u32) -> io::Result<Option<Vec<u8>>> {
        let upper = self.entries.partition_point(|e| e.first <= *txid);
        if upper == 0 {
            return Ok(None); // authenticated directory proves this range empty
        }
        let e = &self.entries[upper - 1];
        let mut b = vec![0; e.length as usize];
        self.source.read_exact_at(&mut b, e.offset)?;
        self.bytes_read += e.length;
        if sha256(&b) != e.hash {
            return Err(bad("snapshot chunk hash mismatch")); // never an absent coin
        }
        let mut p = 0;
        while p < b.len() {
            let current: [u8; 32] = fixed(&b, &mut p)?;
            let n = compact(&b, &mut p)?;
            if current > *txid {
                return Ok(None);
            }
            for _ in 0..n {
                let (v, body) = coin_span(&b, &mut p)?;
                if current == *txid && v == vout {
                    return Ok(Some(b[body].to_vec()));
                }
            }
        }
        Ok(None)
    }
}

fn save(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn physical_reads() -> io::Result<u64> {
    std::fs::read_to_string("/proc/self/io")?
        .lines()
        .find_map(|line| line.strip_prefix("read_bytes: ").map(str::trim))
        .ok_or_else(|| bad("Linux read_bytes counter missing"))?
        .parse()
        .map_err(|_| bad("Linux read_bytes counter invalid"))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<_> = std::env::args().skip(1).collect();
    let usage = "scan SNAP [serial|pipeline] | pack SNAP INDEX [serial|pipeline] [groups] | bench SNAP INDEX TRUSTED_ROOT QUERIES";
    match a.first().map(String::as_str) {
        Some(mode @ ("scan" | "pack")) if a.len() >= 2 => {
            let pack = mode == "pack";
            if pack && a.len() < 3 {
                return Err(usage.into());
            }
            let pipeline = match a.get(if pack { 3 } else { 2 }).map(String::as_str) {
                None | Some("pipeline") => true,
                Some("serial") => false,
                _ => return Err(usage.into()),
            };
            let stride = if pack {
                a.get(4).map(|s| s.parse()).transpose()?.unwrap_or(256)
            } else {
                256
            };
            let t = Instant::now();
            let mut source = File::open(&a[1])?;
            let file_len = source.metadata()?.len();
            let mut header = [0; HEADER];
            source.read_exact(&mut header)?;
            let reader: Box<dyn Read> = if pipeline {
                Box::new(Pipeline::new(source))
            } else {
                Box::new(source)
            };
            let prepared = scan(reader, header, file_len, stride, pack)?;
            let scan_seconds = t.elapsed().as_secs_f64();
            if pack {
                let bytes = prepared.encode();
                let root = hex::encode(&sha256(&bytes));
                save(Path::new(&a[2]), &bytes)?;
                save(Path::new(&format!("{}.queries", a[2])), &prepared.queries)?;
                println!(
                    "mode=pack pipeline={pipeline} scan_seconds={scan_seconds:.6} durable_seconds={:.6} coins={} groups={} entries={} index_bytes={} queries={} root={root}",
                    t.elapsed().as_secs_f64(),
                    prepared.coins,
                    prepared.groups,
                    prepared.entries.len(),
                    bytes.len(),
                    prepared.queries.len() / 68
                );
            } else {
                println!(
                    "mode=scan pipeline={pipeline} seconds={scan_seconds:.6} coins={} groups={} entries={} logical_bytes={file_len}",
                    prepared.coins,
                    prepared.groups,
                    prepared.entries.len()
                );
            }
        }
        Some("bench") if a.len() == 5 => {
            let root = hex::decode(&a[3])?
                .try_into()
                .map_err(|_| bad("root must be 32 bytes"))?;
            let before_open = physical_reads()?;
            let t = Instant::now();
            let mut view = Indexed::open(Path::new(&a[1]), Path::new(&a[2]), root)?;
            let open_seconds = t.elapsed().as_secs_f64();
            let open_bytes = view.bytes_read;
            let open_physical_bytes = physical_reads()? - before_open;
            // Deterministic shuffle to avoid sequential read locality.
            let bytes = std::fs::read(&a[4])?;
            if !bytes.len().is_multiple_of(68) || bytes.is_empty() {
                return Err(bad("empty/invalid query corpus").into());
            }
            let mut queries: Vec<_> = bytes.as_chunks::<68>().0.iter().collect();
            let mut rng = 0x243f_6a88_85a3_08d3u64;
            for i in (1..queries.len()).rev() {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                queries.swap(i, rng as usize % (i + 1));
            }
            let before_queries = physical_reads()?;
            let t = Instant::now();
            let mut latency = Vec::with_capacity(queries.len());
            for q in &queries {
                let start = Instant::now();
                let txid: [u8; 32] = q[..32].try_into()?;
                let vout = u32::from_le_bytes(q[32..36].try_into()?);
                let body = view
                    .get(&txid, vout)?
                    .ok_or_else(|| bad("expected coin missing"))?;
                if sha256(&body) != q[36..68] {
                    return Err(bad("wrong coin contents").into());
                }
                latency.push(start.elapsed().as_nanos());
            }
            let query_seconds = t.elapsed().as_secs_f64();
            let query_physical_bytes = physical_reads()? - before_queries;
            latency.sort_unstable();
            let p = |percent| latency[(latency.len() - 1) * percent / 100] as f64 / 1e3;
            println!(
                "mode=bench open_seconds={open_seconds:.6} open_logical_bytes={open_bytes} open_physical_bytes={open_physical_bytes} queries={} query_seconds={query_seconds:.6} query_logical_bytes={} query_physical_bytes={query_physical_bytes} p50_us={:.3} p95_us={:.3} p99_us={:.3} checked_hits={}",
                queries.len(),
                view.bytes_read - open_bytes,
                p(50),
                p(95),
                p(99),
                queries.len()
            );
        }
        _ => return Err(usage.into()),
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("snapshot_floor: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use avila_consensus::{
        connect::Coin,
        hash::{BlockHash, Txid},
        transaction::{OutPoint, Script, TxOut},
        utxo_snapshot::{read_coins, write_coin, write_snapshot},
    };

    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            static ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("snapshot-floor-{}-{id}", std::process::id()));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> Vec<u8> {
        let mut coins = Vec::new();
        for i in 1..=20u8 {
            let mut txid = [0; 32];
            txid[0] = i;
            // Deliberately not numeric order; lookup must not stop at vout>target.
            for vout in [0, 256, 1, 65_536] {
                let coin = Coin {
                    out: TxOut {
                        value: 123_456_789,
                        script_pubkey: Script::new(vec![0x61; if i == 20 { 200_000 } else { 200 }]),
                    },
                    height: 935_000,
                    coinbase: false,
                };
                coins.push((
                    OutPoint {
                        txid: Txid::from_bytes(txid),
                        vout,
                    },
                    coin,
                ));
            }
        }
        let mut bytes = Vec::new();
        write_snapshot(
            &mut bytes,
            [0xf9, 0xbe, 0xb4, 0xd9],
            &BlockHash::from_bytes([42; 32]),
            coins.len() as u64,
            &coins,
        )
        .unwrap();
        bytes
    }

    fn prepare(bytes: &[u8], stride: usize) -> io::Result<Prepared> {
        scan(
            &bytes[HEADER..],
            bytes[..HEADER].try_into().unwrap(),
            bytes.len() as u64,
            stride,
            true,
        )
    }

    #[test]
    fn all_coins_match_reference_decoder_including_large_scripts_and_tail() {
        let bytes = fixture();
        let prepared = prepare(&bytes, 3).unwrap();
        let temp = Temp::new();
        let source = temp.0.join("snap");
        let index = temp.0.join("idx");
        std::fs::write(&source, &bytes).unwrap();
        let encoded = prepared.encode();
        std::fs::write(&index, &encoded).unwrap();
        let mut view = Indexed::open(&source, &index, sha256(&encoded)).unwrap();
        let mut count = 0;
        read_coins(&mut &bytes[HEADER..], 80, 935_000, |op, coin| {
            let mut expected = Vec::new();
            write_coin(&mut expected, &coin);
            assert_eq!(
                view.get(op.txid.as_bytes(), op.vout).unwrap(),
                Some(expected)
            );
            count += 1;
        })
        .unwrap();
        assert_eq!(count, 80);
        assert_eq!(view.get(&[0; 32], 0).unwrap(), None);
        assert_eq!(view.get(&[255; 32], 0).unwrap(), None);
        let mut middle = [0; 32];
        middle[0] = 10;
        assert_eq!(view.get(&middle, 5).unwrap(), None);
        middle[1] = 1;
        assert_eq!(view.get(&middle, 0).unwrap(), None);
    }

    #[test]
    fn corruption_is_an_error_and_never_a_missing_coin() {
        let mut bytes = fixture();
        let prepared = prepare(&bytes, 3).unwrap();
        let temp = Temp::new();
        let source = temp.0.join("snap");
        let index = temp.0.join("idx");
        let mut encoded = prepared.encode();
        let root = sha256(&encoded);
        std::fs::write(&source, &bytes).unwrap();
        std::fs::write(&index, &encoded).unwrap();
        let mut view = Indexed::open(&source, &index, root).unwrap();
        bytes[HEADER + 40] ^= 1;
        std::fs::write(&source, &bytes).unwrap();
        assert!(view.get(&prepared.entries[0].first, 0).is_err());
        // An untouched chunk remains readable: verification is explicitly lazy.
        assert!(view.get(&prepared.entries[1].first, 0).unwrap().is_some());
        encoded[INDEX_HEADER] ^= 1;
        std::fs::write(&index, &encoded).unwrap();
        assert!(Indexed::open(&source, &index, root).is_err());
    }

    #[test]
    fn malformed_framing_and_lengths_are_rejected() {
        let bytes = fixture();
        assert!(prepare(&bytes, 0).is_err());
        for n in [HEADER, HEADER + 33, bytes.len() - 1] {
            assert!(prepare(&bytes[..n], 3).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(prepare(&extra, 3).is_err());
        let mut empty = bytes.clone();
        empty[HEADER + 32] = 0;
        assert!(prepare(&empty, 3).is_err());
        let mut oversized = bytes;
        oversized[HEADER + 32] = 252;
        assert!(prepare(&oversized, 3).is_err());
        assert!(varint(&[255; 11], &mut 0).is_err());
        assert!(compact(&[253, 1, 0], &mut 0).is_err());
    }

    #[test]
    fn short_reads_preserve_offsets_and_chunk_hashes() {
        struct Fragmented<'a>(&'a [u8]);
        impl Read for Fragmented<'_> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let n = out.len().min(self.0.len()).min(65_537);
                out[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let bytes = fixture();
        let expected = prepare(&bytes, 3).unwrap();
        let actual = scan(
            Fragmented(&bytes[HEADER..]),
            bytes[..HEADER].try_into().unwrap(),
            bytes.len() as u64,
            3,
            true,
        )
        .unwrap();
        assert_eq!(actual.encode(), expected.encode());
        assert_eq!(actual.queries, expected.queries);
    }

    #[test]
    fn wrong_source_and_reordered_index_are_rejected() {
        let mut bytes = fixture();
        let prepared = prepare(&bytes, 3).unwrap();
        let temp = Temp::new();
        let source = temp.0.join("snap");
        let index = temp.0.join("idx");
        let mut encoded = prepared.encode();
        let root = sha256(&encoded);
        std::fs::write(&index, &encoded).unwrap();
        std::fs::write(&source, &bytes[..bytes.len() - 1]).unwrap();
        assert!(Indexed::open(&source, &index, root).is_err());
        bytes[11] ^= 1;
        std::fs::write(&source, &bytes).unwrap();
        assert!(Indexed::open(&source, &index, root).is_err());
        bytes[11] ^= 1;
        std::fs::write(&source, &bytes).unwrap();
        // Even a matching root cannot bypass directory structural checks.
        encoded[INDEX_HEADER + ENTRY..INDEX_HEADER + ENTRY + 32].fill(0);
        std::fs::write(&index, &encoded).unwrap();
        assert!(Indexed::open(&source, &index, sha256(&encoded)).is_err());
    }

    #[test]
    fn empty_snapshot_and_pipeline_match_serial() {
        let temp = Temp::new();
        for bytes in [fixture(), {
            let mut b = Vec::new();
            write_snapshot(
                &mut b,
                [0xf9, 0xbe, 0xb4, 0xd9],
                &BlockHash::from_bytes([0; 32]),
                0,
                &[],
            )
            .unwrap();
            b
        }] {
            let source = temp.0.join("snap");
            std::fs::write(&source, &bytes).unwrap();
            let serial = prepare(&bytes, 3).unwrap();
            let mut f = File::open(&source).unwrap();
            let mut header = [0; HEADER];
            f.read_exact(&mut header).unwrap();
            let piped = scan(Pipeline::new(f), header, bytes.len() as u64, 3, true).unwrap();
            assert_eq!(serial.encode(), piped.encode());
            assert_eq!(serial.queries, piped.queries);
            let encoded = serial.encode();
            let index = temp.0.join("idx");
            std::fs::write(&index, &encoded).unwrap();
            let mut view = Indexed::open(&source, &index, sha256(&encoded)).unwrap();
            assert_eq!(view.get(&[255; 32], 0).unwrap(), None);
        }
    }
}

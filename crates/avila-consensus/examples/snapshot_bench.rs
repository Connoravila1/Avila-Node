//! Real-scale coinsdb measurement.
//!
//! `file <path> <base_height>` — stream a Core dumptxoutset file into a
//! backend-backed UtxoSet: the exact code path `loadtxoutset` drives.
//!
//! `synthetic <count> [base_height]` — generate <count> coins with a
//! realistic mainnet script mix and stream them through the same
//! insert_synthetic/flush_partial_to_backend path. Used when no synced
//! Core datadir is available to produce a real dump; measures the
//! storage-ingest path only (no wire decompression).
//!
//! Both modes then measure point reads, a mixed spend+insert commit,
//! and report the resulting coinsdb.redb size.

use avila_consensus::connect::{Coin, UtxoSet};
use avila_consensus::hash::Txid;
use avila_consensus::transaction::{OutPoint, Script, TxOut};
use avila_consensus::utxo_snapshot::{read_coins, read_metadata};
use std::io::Read as _;
use std::time::Instant;

/// xorshift64* — deterministic, dependency-free key material.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Approximate mainnet UTXO script-type mix: ~35% P2PKH, ~18% P2SH,
/// ~25% P2WPKH, ~7% P2WSH, ~13% P2TR, ~2% bare/other.
fn synth_script(r: &mut Rng) -> Script {
    let roll = r.below(100);
    let mut s = Vec::new();
    if roll < 35 {
        s.extend_from_slice(&[0x76, 0xa9, 0x14]);
        s.extend((0..20).map(|_| r.next() as u8));
        s.extend_from_slice(&[0x88, 0xac]);
    } else if roll < 53 {
        s.extend_from_slice(&[0xa9, 0x14]);
        s.extend((0..20).map(|_| r.next() as u8));
        s.push(0x87);
    } else if roll < 78 {
        s.extend_from_slice(&[0x00, 0x14]);
        s.extend((0..20).map(|_| r.next() as u8));
    } else if roll < 85 {
        s.extend_from_slice(&[0x00, 0x20]);
        s.extend((0..32).map(|_| r.next() as u8));
    } else if roll < 98 {
        s.extend_from_slice(&[0x51, 0x20]);
        s.extend((0..32).map(|_| r.next() as u8));
    } else {
        s.push(0x51);
    }
    Script::new(s)
}

fn synth_coin(r: &mut Rng, base_height: u32) -> (OutPoint, Coin) {
    let mut txid = [0u8; 32];
    for b in txid.chunks_mut(8) {
        b.copy_from_slice(&r.next().to_le_bytes());
    }
    let op = OutPoint {
        txid: Txid::from_bytes(txid),
        vout: r.below(4) as u32,
    };
    let coin = Coin {
        out: TxOut {
            value: 546 + r.below(500_000_000) as i64,
            script_pubkey: synth_script(r),
        },
        height: 1 + r.below(u64::from(base_height)) as u32,
        coinbase: r.below(100) == 0,
    };
    (op, coin)
}

/// Point reads + a mixed spend/insert commit against the loaded set.
fn measure(
    set: &mut UtxoSet,
    be: &avila_consensus::coinsdb::CoinsBackend,
    ops: &[OutPoint],
    tip: u32,
) {
    let t = Instant::now();
    let mut hits = 0u64;
    for op in ops {
        if set.get(op).is_some() {
            hits += 1;
        }
    }
    let el = t.elapsed();
    println!(
        "point reads: {} in {:.0?} — {:.0}/s ({hits} hits)",
        ops.len(),
        el,
        ops.len() as f64 / el.as_secs_f64()
    );

    let t = Instant::now();
    for (i, op) in ops.iter().take(1000).enumerate() {
        let _ = set.spend_coin(op);
        set.insert_synthetic(
            OutPoint {
                txid: Txid::from_bytes([(i & 0xff) as u8; 32]),
                vout: 9,
            },
            Coin {
                out: TxOut {
                    value: 1,
                    script_pubkey: Script::new(vec![0x51]),
                },
                height: tip + 1,
                coinbase: false,
            },
        );
    }
    set.flush_to_backend(&[], tip + 1)
        .unwrap_or_else(|e| panic!("mixed flush: {e}"));
    println!(
        "mixed spend+insert commit (2k entries): {:.0?}",
        t.elapsed()
    );
    println!(
        "final: backend coins_len={} tip={}",
        be.coins_len(),
        be.tip_height()
    );
}

const FLUSH_EVERY: u64 = 16_000_000; // knob: batch granularity
fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "synthetic".into());
    // On real disk, not tmpfs — a full-scale coinsdb is GiB-scale.
    let dir = std::env::var("SNAP_BENCH_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from("target").join(format!("snap-bench-{}", std::process::id()))
        });
    let _ = std::fs::remove_dir_all(&dir);

    let mut set = UtxoSet::new();
    // SNAP_BENCH_FORMAT=legacy|compact selects the record encoding
    // (default: compact) — the layout experiment's knob.
    let fmt = match std::env::var("SNAP_BENCH_FORMAT").as_deref() {
        Ok("legacy") => avila_consensus::coinsdb::CoinFormat::Legacy,
        _ => avila_consensus::coinsdb::CoinFormat::Compact,
    };
    // SNAP_BENCH_ENGINE=hash swaps the coins table for the
    // hash-indexed store (undo/meta stay in the redb sidecar).
    let be = std::sync::Arc::new(
        if std::env::var("SNAP_BENCH_ENGINE").as_deref() == Ok("hash") {
            avila_consensus::coinsdb::CoinsBackend::open_with_engine(
                &dir,
                avila_consensus::coinsdb::Engine::Hash,
            )
        } else {
            avila_consensus::coinsdb::CoinsBackend::open_with_format(&dir, fmt)
        }
        .unwrap_or_else(|e| panic!("be: {e}")),
    );
    set.attach_shared(be.clone());
    set.set_budget(512 << 20);

    let base_height;
    let mut sample_ops: Vec<OutPoint> = Vec::new();
    let t = Instant::now();
    match mode.as_str() {
        // `gen <path> <count>` — stream a Core-format snapshot file:
        // sorted txids (big-endian counter suffix), 1-2 vouts each,
        // realistic script mix. RAM-bounded — writes groups as it goes.
        "gen" => {
            let path = args.next().expect("gen <path> <count>");
            let count: u64 = args.next().expect("count").parse().unwrap();
            let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
            let mut w = std::io::BufWriter::with_capacity(
                1 << 24,
                std::fs::File::create(&path).expect("create"),
            );
            use std::io::Write;
            w.write_all(b"utxo\xff").unwrap();
            w.write_all(&2u16.to_le_bytes()).unwrap();
            w.write_all(&[0xf9, 0xbe, 0xb4, 0xd9]).unwrap(); // mainnet magic
            w.write_all(&[0xabu8; 32]).unwrap(); // base blockhash
            w.write_all(&count.to_le_bytes()).unwrap();
            let mut written = 0u64;
            let mut tx_i = 0u64;
            let mut buf = Vec::with_capacity(512);
            while written < count {
                // txid: ascending — byte-sorted by construction.
                let mut txid = [0u8; 32];
                txid[24..].copy_from_slice(&tx_i.to_be_bytes());
                tx_i += 1;
                let n_out = 1 + rng.below(2); // 1-2 outputs
                let group = (count - written).min(n_out);
                buf.clear();
                buf.extend_from_slice(&txid);
                avila_consensus::encode::write_compact_size(&mut buf, group);
                for v in 0..group {
                    avila_consensus::encode::write_compact_size(&mut buf, v);
                    let (_, coin) = synth_coin(&mut rng, 935_000);
                    avila_consensus::utxo_snapshot::write_coin(&mut buf, &coin);
                    written += 1;
                }
                w.write_all(&buf).unwrap();
            }
            w.flush().unwrap();
            println!("gen: {written} coins -> {path}");
            return;
        }
        // `decode <path>` — stream-decode only: isolates wire format +
        // decompression cost from backend insert cost.
        "decode" => {
            let path = args
                .next()
                .unwrap_or_else(|| "/tmp/mainnet-utxo.dat".into());
            base_height = args.next().map(|x| x.parse().unwrap()).unwrap_or(935_000);
            let f = std::fs::File::open(&path).unwrap();
            let mut r = std::io::BufReader::with_capacity(1 << 24, f);
            let meta = read_metadata(&mut r, [0xf9, 0xbe, 0xb4, 0xd9])
                .unwrap_or_else(|e| panic!("meta: {e}"));
            let mut count = 0u64;
            let mut bytes = 0u64;
            read_coins(&mut r, meta.coins_count, base_height, |_, coin| {
                bytes += coin.out.script_pubkey.as_bytes().len() as u64;
                count += 1;
            })
            .unwrap_or_else(|e| panic!("read: {e}"));
            let el = t.elapsed();
            println!(
                "decode-only: {count} coins ({bytes} script bytes) in {:.0?} — {:.0} coins/s",
                el,
                count as f64 / el.as_secs_f64()
            );
            return;
        }
        // `sharded <path> <base> <n>` — one decode thread routes each
        // coin to one of N independent backends (txid top-byte shard);
        // each shard has its own dirty map + redb file, so writes
        // parallelize. Tests whether insert is writer-bound.
        "sharded" => {
            let path = args.next().unwrap();
            let bh: u32 = args.next().map(|x| x.parse().unwrap()).unwrap_or(935_000);
            base_height = bh;
            let nshards: usize = args.next().map(|x| x.parse().unwrap()).unwrap_or(4);
            let f = std::fs::File::open(&path).unwrap();
            let mut r = std::io::BufReader::with_capacity(1 << 24, f);
            let meta = read_metadata(&mut r, [0xf9, 0xbe, 0xb4, 0xd9])
                .unwrap_or_else(|e| panic!("meta: {e}"));
            let mut senders = Vec::new();
            let mut workers = Vec::new();
            for si in 0..nshards {
                let (tx, rx) = std::sync::mpsc::sync_channel::<(OutPoint, Coin)>(65_536);
                senders.push(tx);
                let sdir = dir.join(format!("shard{si}"));
                workers.push(std::thread::spawn(move || {
                    let be = std::sync::Arc::new(
                        avila_consensus::coinsdb::CoinsBackend::open(&sdir).unwrap(),
                    );
                    let mut set = UtxoSet::new();
                    set.attach_shared(be.clone());
                    set.set_budget(256 << 20);
                    let mut since = 0u64;
                    let mut cnt = 0u64;
                    while let Ok((op, coin)) = rx.recv() {
                        set.insert_synthetic(op, coin);
                        since += 1;
                        cnt += 1;
                        if since >= 8_000_000 {
                            set.flush_partial_to_backend().unwrap();
                            since = 0;
                        }
                    }
                    set.flush_to_backend(&[], bh).unwrap();
                    cnt
                }));
            }
            let mut ferr: Option<String> = None;
            read_coins(&mut r, meta.coins_count, bh, |op, coin| {
                if ferr.is_some() {
                    return;
                }
                let shard = (op.txid.as_bytes()[0] as usize) % nshards;
                if senders[shard].send((op, coin)).is_err() {
                    ferr = Some(format!("shard{shard} died"));
                }
            })
            .unwrap_or_else(|e| panic!("read: {e}"));
            drop(senders);
            if let Some(e) = ferr {
                panic!("{e}");
            }
            let total: u64 = workers.into_iter().map(|w| w.join().unwrap()).sum();
            let el = t.elapsed();
            println!(
                "sharded({nshards}): {total} coins in {:.0?} — {:.0} coins/s",
                el,
                total as f64 / el.as_secs_f64()
            );
            return;
        }
        // `run <path> <base>` — bulk-load via SortedRun: sequential
        // append of the already-sorted stream + sparse index. The
        // ~5min path: no B-tree, no incremental hashing.
        "run" => {
            let path = args.next().unwrap();
            let bh: u32 = args.next().map(|x| x.parse().unwrap()).unwrap_or(935_000);
            base_height = bh;
            let run_path = dir.join("base.run");
            let f = std::fs::File::open(&path).unwrap();
            let mut r = std::io::BufReader::with_capacity(1 << 24, f);
            let meta = read_metadata(&mut r, [0xf9, 0xbe, 0xb4, 0xd9])
                .unwrap_or_else(|e| panic!("meta: {e}"));
            let mut b = avila_consensus::sortedrun::RunBuilder::create(&run_path)
                .unwrap_or_else(|e| panic!("create: {e}"));
            let mut count = 0u64;
            let mut sample: Vec<OutPoint> = Vec::new();
            read_coins(&mut r, meta.coins_count, bh, |op, coin| {
                b.push(&op, &coin).unwrap_or_else(|e| panic!("push: {e}"));
                if count.is_multiple_of(65536) {
                    sample.push(op);
                }
                count += 1;
            })
            .unwrap_or_else(|e| panic!("read: {e}"));
            let n = b.finish().unwrap_or_else(|e| panic!("finish: {e}"));
            let el = t.elapsed();
            println!(
                "run-build: {n} coins in {:.0?} — {:.0} coins/s",
                el,
                n as f64 / el.as_secs_f64()
            );
            let run = avila_consensus::sortedrun::SortedRun::open(&run_path).unwrap();
            let tr = Instant::now();
            let mut hits = 0u64;
            for op in &sample {
                if run.get(op).is_some() {
                    hits += 1;
                }
            }
            let el = tr.elapsed();
            println!(
                "point reads: {} in {:.0?} — {:.0}/s ({hits} hits)",
                sample.len(),
                el,
                sample.len() as f64 / el.as_secs_f64()
            );
            let sz = std::fs::metadata(&run_path).unwrap().len() as f64 / (1 << 30) as f64;
            println!("run file = {sz:.2} GiB");
            return;
        }
        // `runfast <path> <base>` — byte-level snapshot walk: parse
        // group headers + index varints, copy each coin's wire body
        // verbatim into the run (wire format == stored format). No
        // Coin objects ever materialize — the ~I/O-bound floor.
        "runfast" => {
            let path = args.next().unwrap();
            let bh: u32 = args.next().map(|x| x.parse().unwrap()).unwrap_or(935_000);
            base_height = bh;
            let run_path = dir.join("base.run");
            let f = std::fs::File::open(&path).unwrap();
            let mut r = std::io::BufReader::with_capacity(1 << 24, f);
            let meta = read_metadata(&mut r, [0xf9, 0xbe, 0xb4, 0xd9])
                .unwrap_or_else(|e| panic!("meta: {e}"));
            let mut b = avila_consensus::sortedrun::RunBuilder::create(&run_path)
                .unwrap_or_else(|e| panic!("create: {e}"));
            let mut buf = vec![0u8; 1 << 24]; // 16MB stream window
            let mut pos = 0usize;
            let mut len = 0usize;
            // Compact [pos..len] to the front and refill. Only called
            // between coins — a coin's parse never straddles once we
            // guarantee a min margin up front.
            let mut refill =
                |buf: &mut Vec<u8>,
                 pos: &mut usize,
                 len: &mut usize,
                 r: &mut std::io::BufReader<std::fs::File>| {
                    buf.copy_within(*pos..*len, 0);
                    *len -= *pos;
                    *pos = 0;
                    while *len < buf.len() {
                        let n = r.read(&mut buf[*len..]).unwrap();
                        if n == 0 {
                            break;
                        }
                        *len += n;
                    }
                };
            let margin = 1 << 18; // 256KB — max sane coin body margin
            refill(&mut buf, &mut pos, &mut len, &mut r);
            let mut coins_left = meta.coins_count;
            let mut sample: Vec<OutPoint> = Vec::new();
            let mut count = 0u64;
            // compact-size value at buf[pos..]
            macro_rules! cs {
                () => {{
                    let c = buf[pos];
                    pos += 1;
                    match c {
                        0xfd => {
                            let v =
                                u16::from_le_bytes(buf[pos..pos + 2].try_into().unwrap()) as u64;
                            pos += 2;
                            v
                        }
                        0xfe => {
                            let v =
                                u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as u64;
                            pos += 4;
                            v
                        }
                        0xff => {
                            let v = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                            pos += 8;
                            v
                        }
                        _ => c as u64,
                    }
                }};
            }
            while coins_left > 0 {
                if len - pos < margin {
                    refill(&mut buf, &mut pos, &mut len, &mut r);
                }
                let mut key = [0u8; 36];
                key[..32].copy_from_slice(&buf[pos..pos + 32]);
                pos += 32;
                let cnt = cs!();
                for _ in 0..cnt {
                    if len - pos < margin {
                        refill(&mut buf, &mut pos, &mut len, &mut r);
                    }
                    let vout = cs!() as u32;
                    // Big-endian: this key feeds RunBuilder::push_wire,
                    // whose ordering (and binary search on read back)
                    // needs byte order == numeric vout order.
                    key[32..].copy_from_slice(&vout.to_be_bytes());
                    let body_start = pos;
                    // Scan 3 MSB-chained varints; only size_id's value is needed.
                    let mut varints = [0u64; 3];
                    for v in varints.iter_mut() {
                        loop {
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
                        n => (n - 6) as usize,
                    };
                    if pos + plen <= len {
                        b.push_wire(&key, &buf[body_start..pos + plen]).unwrap();
                        pos += plen;
                    } else {
                        // Rare: huge bare-script payload — assemble it.
                        let mut body = Vec::with_capacity(pos - body_start + plen);
                        body.extend_from_slice(&buf[body_start..len]);
                        let want = plen - (len - pos);
                        let mut tail = vec![0u8; want];
                        r.read_exact(&mut tail).unwrap();
                        body.extend_from_slice(&tail);
                        b.push_wire(&key, &body).unwrap();
                        pos = 0;
                        len = 0;
                        refill(&mut buf, &mut pos, &mut len, &mut r);
                    }
                    if count.is_multiple_of(65536) {
                        let mut t = [0u8; 32];
                        t.copy_from_slice(&key[..32]);
                        sample.push(OutPoint {
                            txid: Txid::from_bytes(t),
                            vout,
                        });
                    }
                    count += 1;
                    coins_left -= 1;
                }
            }
            let n = b.finish().unwrap_or_else(|e| panic!("finish: {e}"));
            let el = t.elapsed();
            println!(
                "runfast-build: {n} coins in {:.0?} — {:.0} coins/s",
                el,
                n as f64 / el.as_secs_f64()
            );
            let run = avila_consensus::sortedrun::SortedRun::open(&run_path).unwrap();
            let tr = Instant::now();
            let mut hits = 0u64;
            for op in &sample {
                if run.get(op).is_some() {
                    hits += 1;
                }
            }
            let el = tr.elapsed();
            println!(
                "point reads: {} in {:.0?} — {:.0}/s ({hits} hits)",
                sample.len(),
                el,
                sample.len() as f64 / el.as_secs_f64()
            );
            return;
        }
        // `runpipe <path> <base>` — runfast parse on this thread,
        // record writes on another: batches of pre-formatted
        // [key36][len4][body] records flow through a bounded channel
        // so scan CPU overlaps sequential I/O.
        "runpipe" => {
            let path = args.next().unwrap();
            let bh: u32 = args.next().map(|x| x.parse().unwrap()).unwrap_or(935_000);
            base_height = bh;
            let run_path = dir.join("base.run");
            let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(4);
            let wr = std::thread::spawn({
                let run_path = run_path.clone();
                move || {
                    let mut b = avila_consensus::sortedrun::RunBuilder::create(&run_path)
                        .unwrap_or_else(|e| panic!("create: {e}"));
                    while let Ok(blob) = rx.recv() {
                        let mut off = 0usize;
                        while off + 40 <= blob.len() {
                            let l = u32::from_le_bytes(blob[off + 36..off + 40].try_into().unwrap())
                                as usize;
                            let key: &[u8; 36] = blob[off..off + 36].try_into().unwrap();
                            b.push_wire(key, &blob[off + 40..off + 40 + l]).unwrap();
                            off += 40 + l;
                        }
                    }
                    b.finish().unwrap_or_else(|e| panic!("finish: {e}"))
                }
            });
            let f = std::fs::File::open(&path).unwrap();
            let mut r = std::io::BufReader::with_capacity(1 << 24, f);
            let meta = read_metadata(&mut r, [0xf9, 0xbe, 0xb4, 0xd9])
                .unwrap_or_else(|e| panic!("meta: {e}"));
            let mut buf = vec![0u8; 1 << 24];
            let mut pos = 0usize;
            let mut len = 0usize;
            let mut refill =
                |buf: &mut Vec<u8>,
                 pos: &mut usize,
                 len: &mut usize,
                 r: &mut std::io::BufReader<std::fs::File>| {
                    buf.copy_within(*pos..*len, 0);
                    *len -= *pos;
                    *pos = 0;
                    while *len < buf.len() {
                        let n = r.read(&mut buf[*len..]).unwrap();
                        if n == 0 {
                            break;
                        }
                        *len += n;
                    }
                };
            let margin = 1 << 18;
            refill(&mut buf, &mut pos, &mut len, &mut r);
            let mut coins_left = meta.coins_count;
            let mut batch = Vec::with_capacity(1 << 22);
            let mut count = 0u64;
            macro_rules! cs {
                () => {{
                    let c = buf[pos];
                    pos += 1;
                    match c {
                        0xfd => {
                            let v =
                                u16::from_le_bytes(buf[pos..pos + 2].try_into().unwrap()) as u64;
                            pos += 2;
                            v
                        }
                        0xfe => {
                            let v =
                                u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as u64;
                            pos += 4;
                            v
                        }
                        0xff => {
                            let v = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                            pos += 8;
                            v
                        }
                        _ => c as u64,
                    }
                }};
            }
            while coins_left > 0 {
                if len - pos < margin {
                    refill(&mut buf, &mut pos, &mut len, &mut r);
                }
                let mut key = [0u8; 36];
                key[..32].copy_from_slice(&buf[pos..pos + 32]);
                pos += 32;
                let cnt = cs!();
                for _ in 0..cnt {
                    if len - pos < margin {
                        refill(&mut buf, &mut pos, &mut len, &mut r);
                    }
                    let vout = cs!() as u32;
                    // Big-endian: this key feeds RunBuilder::push_wire,
                    // whose ordering (and binary search on read back)
                    // needs byte order == numeric vout order.
                    key[32..].copy_from_slice(&vout.to_be_bytes());
                    let body_start = pos;
                    let mut varints = [0u64; 3];
                    for v in varints.iter_mut() {
                        loop {
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
                        n => (n - 6) as usize,
                    };
                    if pos + plen > len {
                        // rare giant payload — assemble via tail read
                        let mut body = Vec::with_capacity(pos - body_start + plen);
                        body.extend_from_slice(&buf[body_start..len]);
                        let want = plen - (len - pos);
                        let mut tail = vec![0u8; want];
                        r.read_exact(&mut tail).unwrap();
                        body.extend_from_slice(&tail);
                        batch.extend_from_slice(&key);
                        batch.extend_from_slice(&(body.len() as u32).to_le_bytes());
                        batch.extend_from_slice(&body);
                        pos = 0;
                        len = 0;
                        refill(&mut buf, &mut pos, &mut len, &mut r);
                    } else {
                        batch.extend_from_slice(&key);
                        batch.extend_from_slice(
                            &(plen as u32 + (pos - body_start) as u32).to_le_bytes(),
                        );
                        batch.extend_from_slice(&buf[body_start..pos + plen]);
                        pos += plen;
                    }
                    count += 1;
                    coins_left -= 1;
                    if batch.len() >= 1 << 22 {
                        if tx.send(std::mem::take(&mut batch)).is_err() {
                            panic!("writer died");
                        }
                        batch = Vec::with_capacity(1 << 22);
                    }
                }
            }
            if !batch.is_empty() {
                tx.send(batch).unwrap();
            }
            drop(tx);
            let n = wr.join().unwrap();
            let el = t.elapsed();
            println!(
                "runpipe-build: {n} coins ({count} seen) in {:.0?} — {:.0} coins/s",
                el,
                n as f64 / el.as_secs_f64()
            );
            return;
        }
        // `runindex <path> <base>` — the zero-write load: index every
        // Nth txid-group start in the snapshot file, then answer reads
        // by seeking into the file directly. The snapshot IS the UTXO
        // set; ~15MB of index, no bulk data writes at all.
        "runindex" => {
            let path = args.next().unwrap();
            let bh: u32 = args.next().map(|x| x.parse().unwrap()).unwrap_or(935_000);
            base_height = bh;
            let f = std::fs::File::open(&path).unwrap();
            let mut r = std::io::BufReader::with_capacity(1 << 24, f.try_clone().unwrap());
            let meta = read_metadata(&mut r, [0xf9, 0xbe, 0xb4, 0xd9])
                .unwrap_or_else(|e| panic!("meta: {e}"));
            let mut buf = vec![0u8; 1 << 24];
            let mut pos = 0usize;
            let mut len = 0usize;
            let mut file_off = 0u64; // absolute offset of buf[0]
            let hdr_off = 51u64; // magic4+ver2+net4+base32+count8+? — measured below
            let _ = hdr_off;
            // Track absolute file position: base = bytes consumed by header.
            // BufReader consumed the header already; its inner position:
            // read_metadata read exactly the header bytes.
            let mut abs = 51u64;
            let mut refill =
                |buf: &mut Vec<u8>,
                 pos: &mut usize,
                 len: &mut usize,
                 abs: &mut u64,
                 r: &mut std::io::BufReader<std::fs::File>| {
                    *abs += *pos as u64;
                    buf.copy_within(*pos..*len, 0);
                    *len -= *pos;
                    *pos = 0;
                    while *len < buf.len() {
                        let n = r.read(&mut buf[*len..]).unwrap();
                        if n == 0 {
                            break;
                        }
                        *len += n;
                    }
                };
            // Measure true header size: read_metadata consumed magic4+ver2
            // +net4+base32+count8 = 50 bytes? verify: utxoÿ(4) + u16(2)
            // + magic(4) + hash(32) + count(8) = 50.
            abs = 51; // "utxo\\xff"(5) + ver(2) + magic(4) + base(32) + count(8)
            let margin = 1 << 18;
            refill(&mut buf, &mut pos, &mut len, &mut abs, &mut r);
            let mut coins_left = meta.coins_count;
            let mut sparse: Vec<([u8; 36], u64)> = Vec::new();
            let mut groups = 0u64;
            let mut count = 0u64;
            let mut sample: Vec<OutPoint> = Vec::new();
            macro_rules! cs {
                () => {{
                    let c = buf[pos];
                    pos += 1;
                    match c {
                        0xfd => {
                            let v =
                                u16::from_le_bytes(buf[pos..pos + 2].try_into().unwrap()) as u64;
                            pos += 2;
                            v
                        }
                        0xfe => {
                            let v =
                                u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as u64;
                            pos += 4;
                            v
                        }
                        0xff => {
                            let v = u64::from_le_bytes(buf[pos..pos + 8].try_into().unwrap());
                            pos += 8;
                            v
                        }
                        _ => c as u64,
                    }
                }};
            }
            while coins_left > 0 {
                if len - pos < margin {
                    refill(&mut buf, &mut pos, &mut len, &mut abs, &mut r);
                }
                let group_off = abs + pos as u64;
                let mut first_key = [0u8; 36];
                first_key[..32].copy_from_slice(&buf[pos..pos + 32]);
                let mut cur_txid = [0u8; 32];
                cur_txid.copy_from_slice(&buf[pos..pos + 32]);
                pos += 32;
                let cnt = cs!();
                // Peek the group's first vout to complete its first key.
                let save = pos;
                let v0 = cs!() as u32;
                // Big-endian to match SnapshotRun::get's query key —
                // see the RunBuilder/SortedRun key fix above.
                first_key[32..].copy_from_slice(&v0.to_be_bytes());
                if groups.is_multiple_of(256) {
                    sparse.push((first_key, group_off));
                }
                groups += 1;
                pos = save;
                for _ in 0..cnt {
                    if len - pos < margin {
                        refill(&mut buf, &mut pos, &mut len, &mut abs, &mut r);
                    }
                    let vout = cs!() as u32;
                    let mut varints = [0u64; 3];
                    for v in varints.iter_mut() {
                        loop {
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
                        n => (n - 6) as usize,
                    };
                    if pos + plen > len {
                        // giant payload — skip by seeking
                        let skip = plen - (len - pos);
                        use std::io::Seek;
                        r.seek_relative(skip as i64).unwrap();
                        abs = abs + len as u64 + skip as u64;
                        pos = 0;
                        len = 0;
                        refill(&mut buf, &mut pos, &mut len, &mut abs, &mut r);
                    } else {
                        pos += plen;
                    }
                    if count.is_multiple_of(65536) {
                        sample.push(OutPoint {
                            txid: Txid::from_bytes(cur_txid),
                            vout,
                        });
                    }
                    count += 1;
                    coins_left -= 1;
                }
            }
            let el = t.elapsed();
            println!(
                "index-build: {count} coins {groups} groups in {:.0?} — {:.0} coins/s ({} index entries)",
                el,
                count as f64 / el.as_secs_f64(),
                sparse.len()
            );
            let run = avila_consensus::sortedrun::SnapshotRun::from_index(f, sparse, count);
            let tr = Instant::now();
            let mut hits = 0u64;
            for op in &sample {
                if run.get(op).is_some() {
                    hits += 1;
                }
            }
            let el = tr.elapsed();
            println!(
                "point reads: {} in {:.0?} — {:.0}/s ({hits} hits)",
                sample.len(),
                el,
                sample.len() as f64 / el.as_secs_f64()
            );
            return;
        }
        "file" => {
            // Push-based path — mirrors `Chainstate::load_snapshot`.
            let path = args
                .next()
                .unwrap_or_else(|| "/tmp/mainnet-utxo.dat".into());
            base_height = args
                .next()
                .map(|s| s.parse().unwrap_or_else(|e| panic!("base_height: {e}")))
                .unwrap_or(935_000);
            let f = std::fs::File::open(&path).unwrap_or_else(|e| panic!("open {path}: {e}"));
            let mut r = std::io::BufReader::with_capacity(1 << 24, f);
            let meta = read_metadata(&mut r, [0xf9, 0xbe, 0xb4, 0xd9])
                .unwrap_or_else(|e| panic!("meta: {e}"));
            println!(
                "snapshot: base={} coins={}",
                meta.base_blockhash, meta.coins_count
            );
            // Pre-size: the metadata declares the count — one index
            // grow now instead of ~17 doubling rewrites mid-stream.
            let t_rs = Instant::now();
            be.reserve_coins(meta.coins_count)
                .unwrap_or_else(|e| panic!("reserve: {e}"));
            println!("reserve({}) took {:.0?}", meta.coins_count, t_rs.elapsed());
            let mut count = 0u64;
            let mut since_flush = 0u64;
            let mut ferr: Option<String> = None;
            read_coins(&mut r, meta.coins_count, base_height, |op, coin| {
                if ferr.is_some() {
                    return;
                }
                if count.is_multiple_of(65536) {
                    sample_ops.push(op);
                }
                set.insert_synthetic(op, coin);
                since_flush += 1;
                count += 1;
                if since_flush >= FLUSH_EVERY {
                    if let Err(e) = set.flush_partial_to_backend() {
                        ferr = Some(e.to_string());
                    }
                    since_flush = 0;
                }
            })
            .unwrap_or_else(|e| panic!("read: {e}"));
            if let Some(e) = ferr {
                panic!("mid flush: {e}");
            }
            set.flush_to_backend(&[], base_height)
                .unwrap_or_else(|e| panic!("final flush: {e}"));
            let el = t.elapsed();
            println!(
                "import: {count} coins in {:.0?} — {:.0} coins/s",
                el,
                count as f64 / el.as_secs_f64()
            );
        }
        "synthetic" => {
            let count: u64 = args
                .next()
                .map(|s| s.parse().unwrap_or_else(|e| panic!("count: {e}")))
                .unwrap_or(100_000_000);
            base_height = args
                .next()
                .map(|s| s.parse().unwrap_or_else(|e| panic!("base_height: {e}")))
                .unwrap_or(935_000);
            let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
            let mut since_flush = 0u64;
            for i in 0..count {
                let (op, coin) = synth_coin(&mut rng, base_height);
                if i.is_multiple_of(65536) {
                    sample_ops.push(op);
                }
                set.insert_synthetic(op, coin);
                since_flush += 1;
                if since_flush >= FLUSH_EVERY {
                    set.flush_partial_to_backend()
                        .unwrap_or_else(|e| panic!("mid flush: {e}"));
                    since_flush = 0;
                }
            }
            set.flush_to_backend(&[], base_height)
                .unwrap_or_else(|e| panic!("final flush: {e}"));
            let el = t.elapsed();
            println!(
                "import: {count} synthetic coins in {:.0?} — {:.0} coins/s",
                el,
                count as f64 / el.as_secs_f64()
            );
        }
        "synthetic-sorted" => {
            // Same generator, but keys arrive in coinsdb order — the
            // real-dump case: dumptxoutset iterates the chainstate in
            // key order, so a real snapshot is already sorted.
            // Random-order `synthetic` is the adversarial bound.
            let count: u64 = args
                .next()
                .map(|s| s.parse().unwrap_or_else(|e| panic!("count: {e}")))
                .unwrap_or(100_000_000);
            base_height = args
                .next()
                .map(|s| s.parse().unwrap_or_else(|e| panic!("base_height: {e}")))
                .unwrap_or(935_000);
            let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
            let mut all: Vec<(OutPoint, Coin)> = (0..count)
                .map(|_| synth_coin(&mut rng, base_height))
                .collect();
            // Same byte order as coinsdb::key_of: txid || vout LE.
            all.sort_unstable_by(|a, b| {
                let mut ka = [0u8; 36];
                ka[..32].copy_from_slice(a.0.txid.as_bytes());
                ka[32..].copy_from_slice(&a.0.vout.to_le_bytes());
                let mut kb = [0u8; 36];
                kb[..32].copy_from_slice(b.0.txid.as_bytes());
                kb[32..].copy_from_slice(&b.0.vout.to_le_bytes());
                ka.cmp(&kb)
            });
            let mut since_flush = 0u64;
            for (i, (op, coin)) in all.into_iter().enumerate() {
                if i.is_multiple_of(65536) {
                    sample_ops.push(op);
                }
                set.insert_synthetic(op, coin);
                since_flush += 1;
                if since_flush >= FLUSH_EVERY {
                    set.flush_partial_to_backend()
                        .unwrap_or_else(|e| panic!("mid flush: {e}"));
                    since_flush = 0;
                }
            }
            set.flush_to_backend(&[], base_height)
                .unwrap_or_else(|e| panic!("final flush: {e}"));
            let el = t.elapsed();
            println!(
                "import: {count} sorted synthetic coins in {:.0?} — {:.0} coins/s",
                el,
                count as f64 / el.as_secs_f64()
            );
        }
        _ => panic!(
            "usage: snapshot_bench [file <path> <base_height> | synthetic[-sorted] <count> [base_height]]"
        ),
    }

    measure(&mut set, &be, &sample_ops, base_height);
    // SNAP_BENCH_COMPACT=1: hash-engine log-locality experiment —
    // rewrite coins.dat in slot order, then re-measure reads.
    if std::env::var("SNAP_BENCH_COMPACT").as_deref() == Ok("1") {
        let t = Instant::now();
        be.compact_coins()
            .unwrap_or_else(|e| panic!("compact: {e}"));
        println!("compact: {:.0?}", t.elapsed());
        // sample_ops were spent by measure()'s mixed commit — draw
        // fresh probes from the backend's live set instead.
        let live: Vec<_> = be
            .iter_coins()
            .iter()
            .step_by(65536)
            .map(|(o, _)| *o)
            .collect();
        let t = Instant::now();
        let mut hits = 0u64;
        for op in &live {
            if be.get(op).is_some() {
                hits += 1;
            }
        }
        let el = t.elapsed();
        println!(
            "post-compact backend reads: {} in {:.0?} — {:.0}/s ({hits} hits)",
            live.len(),
            el,
            live.len() as f64 / el.as_secs_f64()
        );
    }
    // Whole-dir allocated size — under the hash engine the coins live
    // in coins.idx/coins.dat, not coinsdb.redb.
    let dir_bytes: u64 = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| {
                    std::os::unix::fs::MetadataExt::blocks(
                        &e.metadata().unwrap_or_else(|e| panic!("meta: {e}")),
                    ) * 512
                })
                .sum()
        })
        .unwrap_or(0);
    println!("datadir = {:.1} GiB", dir_bytes as f64 / (1 << 30) as f64);
    let _ = std::fs::remove_dir_all(&dir);
}

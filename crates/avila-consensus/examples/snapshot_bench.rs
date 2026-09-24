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
            let path = args.next().unwrap_or_else(|| "/tmp/mainnet-utxo.dat".into());
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
                el, count as f64 / el.as_secs_f64()
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

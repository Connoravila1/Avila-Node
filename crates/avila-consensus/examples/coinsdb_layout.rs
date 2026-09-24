// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! coinsdb_layout — the UTXO record-encoding experiment. Runs the
//! same workload through `CoinsBackend` under each `CoinFormat` and
//! prints a comparison table: commit throughput, point reads,
//! full-set iteration, and on-disk size.
//!
//!   cargo run --release -p avila-consensus --example coinsdb_layout

use avila_consensus::coinsdb::{CoinFormat, CoinsBackend, Engine};
use avila_consensus::connect::Coin;
use avila_consensus::hash::Txid;
use avila_consensus::transaction::{OutPoint, Script, TxOut};
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

const COINS_TOTAL: u32 = 500_000;
const BULK_CHUNK: u32 = 100_000;
const BLOCK_COMMITS: u32 = 50;
const COINS_PER_BLOCK_COMMIT: u32 = 2_000;
const POINT_READS: u32 = 60_000;

/// A realistic mainnet-ish script mix: P2PKH 45%, P2WPKH 25%,
/// P2SH 12%, P2TR 12%, bare P2PK 4%, OP_RETURN/other 2%.
fn sample_script(i: u32) -> Script {
    let b = i.to_le_bytes();
    match i % 50 {
        // P2PKH: 76 a9 14 <20> 88 ac  (25B)
        0..=21 => {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend_from_slice(&[b[0]; 20]);
            s.extend_from_slice(&[0x88, 0xac]);
            Script::new(s)
        }
        // P2WPKH: 00 14 <20>  (22B)
        22..=33 => {
            let mut s = vec![0x00, 0x14];
            s.extend_from_slice(&[b[1]; 20]);
            Script::new(s)
        }
        // P2SH: a9 14 <20> 87  (23B)
        34..=39 => {
            let mut s = vec![0xa9, 0x14];
            s.extend_from_slice(&[b[2]; 20]);
            s.push(0x87);
            Script::new(s)
        }
        // P2TR: 51 20 <32>  (34B)
        40..=45 => {
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&[b[3]; 32]);
            Script::new(s)
        }
        // bare compressed P2PK: 21 02 <32> ac  (35B)
        46 | 47 => {
            let mut s = vec![0x21, 0x02 | (b[0] & 1)];
            s.extend_from_slice(&[b[1]; 32]);
            s.push(0xac);
            Script::new(s)
        }
        // OP_RETURN-ish nonstandard (30B)
        _ => {
            let mut s = vec![0x6a, 0x1c];
            s.extend_from_slice(&[b[0]; 28]);
            Script::new(s)
        }
    }
}

/// Realistic amounts: mostly small outputs with a few round ones.
fn sample_amount(i: u32) -> i64 {
    match i % 7 {
        0 => 50_000,             // 0.0005 BTC
        1 => 1_000_000,          // 0.01
        2 => 5_000_000_000,      // 50 BTC (coinbase-era)
        3 => 123_456,            // non-round
        4 => 21_000_000_000_000, // large
        5 => 546,                // dust
        _ => 100_000_000,        // 1 BTC
    }
}

fn mk(i: u32, height: u32) -> (OutPoint, Coin) {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&i.to_le_bytes());
    b[4..8].copy_from_slice(&i.to_be_bytes());
    (
        OutPoint {
            txid: Txid::from_bytes(b),
            vout: i % 5,
        },
        Coin {
            out: TxOut {
                value: sample_amount(i),
                script_pubkey: sample_script(i),
            },
            height,
            coinbase: i.is_multiple_of(97),
        },
    )
}

/// Allocated bytes (st_blocks·512) — the honest figure: the hash
/// index file is sparse, so logical length would overstate it.
fn dir_size(dir: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.metadata().map(|m| m.blocks() * 512).unwrap_or(0))
                .sum()
        })
        .unwrap_or(0)
}

fn run_format(fmt: CoinFormat, name: &str, cache: Option<usize>) {
    let dir = std::env::temp_dir().join(format!("avila-layout-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let be = match cache {
        Some(b) => CoinsBackend::open_tuned(&dir, fmt, b).unwrap_or_else(|e| panic!("open: {e}")),
        None => CoinsBackend::open_with_format(&dir, fmt).unwrap_or_else(|e| panic!("open: {e}")),
    };
    run_bench(be, name, &dir);
}

/// The hash-indexed engine — same workloads through `CoinsBackend`.
fn run_hash(name: &str) {
    let dir = std::env::temp_dir().join(format!("avila-layout-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let be =
        CoinsBackend::open_with_engine(&dir, Engine::Hash).unwrap_or_else(|e| panic!("open: {e}"));
    run_bench(be, name, &dir);
}

fn run_bench(be: CoinsBackend, name: &str, dir: &std::path::Path) {
    let t = Instant::now();
    let mut n = 0u32;
    for chunk in 0..(COINS_TOTAL / BULK_CHUNK) {
        let mut dirty = HashMap::with_capacity(BULK_CHUNK as usize);
        for _ in 0..BULK_CHUNK {
            let (op, c) = mk(n, chunk);
            dirty.insert(op, Some(c));
            n += 1;
        }
        be.commit(&dirty, &[], (chunk + 1) * BULK_CHUNK)
            .unwrap_or_else(|e| panic!("bulk commit: {e}"));
    }
    let bulk_el = t.elapsed();

    // Point reads — the per-input lookup path.
    let t = Instant::now();
    let mut hits = 0u64;
    for i in (0..COINS_TOTAL).step_by((COINS_TOTAL / POINT_READS) as usize) {
        if be.get(&mk(i, i / BULK_CHUNK).0).is_some() {
            hits += 1;
        }
    }
    let read_el = t.elapsed();

    // Full-set iteration — dumptxoutset/gettxoutsetinfo shape.
    let t = Instant::now();
    let all = be.iter_coins();
    let iter_el = t.elapsed();
    assert_eq!(all.len(), COINS_TOTAL as usize);

    // Block-shaped commits — steady-state connect shape (~2k delta).
    let t = Instant::now();
    for h in 6..(6 + BLOCK_COMMITS) {
        let mut dirty = HashMap::with_capacity(COINS_PER_BLOCK_COMMIT as usize);
        for j in 0..COINS_PER_BLOCK_COMMIT {
            let (op, c) = mk(h * 100_000 + j, h);
            dirty.insert(op, Some(c));
        }
        be.commit(&dirty, &[], h)
            .unwrap_or_else(|e| panic!("block commit: {e}"));
    }
    let block_el = t.elapsed();

    let bytes = dir_size(dir);
    println!(
        "{name:>10} | bulk {:>7.0}/s | reads {:>7.0}/s ({hits} hits) | iter {:>6.2?} | blocks {:>5.1}/s | file {:>5.1} MiB",
        COINS_TOTAL as f64 / bulk_el.as_secs_f64(),
        POINT_READS as f64 / read_el.as_secs_f64(),
        iter_el,
        BLOCK_COMMITS as f64 / block_el.as_secs_f64(),
        bytes as f64 / (1024.0 * 1024.0),
    );
    println!(
        "{name:>10} | detail: bulk {bulk_el:.2?}  reads {read_el:.2?}  iter {iter_el:.2?}  blocks {block_el:.2?}"
    );

    drop(be);
    let _ = std::fs::remove_dir_all(dir);
}

fn main() {
    println!("coinsdb layout experiment — {COINS_TOTAL} coins, realistic script/amount mix");
    println!("{}", "-".repeat(100));
    run_format(CoinFormat::Legacy, "legacy", None);
    run_format(CoinFormat::Compact, "compact", None);
    // Cache dimension: same compact layout, tight vs generous redb cache.
    run_format(CoinFormat::Compact, "compact-32M", Some(32 << 20));
    run_format(CoinFormat::Compact, "compact-4G", Some(4 << 30));
    // Engine dimension: unordered hash index + append log.
    run_hash("hash");
}

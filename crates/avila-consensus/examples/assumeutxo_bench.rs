//! assumeutxo end-to-end: time-to-usable-node vs full sync.
//!
//! Phase A: full validation of the fixture (baseline).
//! Phase B: dump a snapshot at the tip.
//! Phase C: fresh node — headers only, activate_snapshot -> usable NOW.
//! Phase D: background_step validates the pre-snapshot history -> verified.
//!
//! usage: assumeutxo_bench <fixture.dat>

use avila_consensus::block::Block;
use avila_consensus::chainstate::{BackgroundStatus, Chainstate};
use avila_consensus::coinstats::{self, CoinStatsHashType};
use avila_consensus::params::{AssumeutxoData, Network};
use avila_consensus::utxo_snapshot::{read_metadata, sorted_coins, write_snapshot};
use std::time::Instant;

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn main() {
    let fixture = std::env::args()
        .nth(1)
        .expect("usage: assumeutxo_bench <fixture.dat>");
    let raw = std::fs::read(&fixture).unwrap();
    let params = match &raw[..4] {
        [0xf9, 0xbe, 0xb4, 0xd9] => Network::Mainnet.params(),
        [0xfa, 0xbf, 0xb5, 0xda] => Network::Regtest.params(),
        m => panic!("unknown magic {m:02x?}"),
    };
    let mut blocks = Vec::new();
    let mut off = 0usize;
    while off + 8 <= raw.len() {
        let len = u32::from_le_bytes(raw[off + 4..off + 8].try_into().unwrap()) as usize;
        blocks.push(Block::decode(&raw[off + 8..off + 8 + len]).unwrap());
        off += 8 + len;
    }
    let n = blocks.len();
    println!("fixture: {n} blocks");

    // ---- A: honest full sync (sequential) -------------------------
    let t0 = Instant::now();
    let mut src = Chainstate::new(&params);
    for b in &blocks {
        src.accept_block(b, now()).unwrap();
    }
    let full_sync = t0.elapsed();
    println!(
        "A. full sync: {:.1}s ({:.0} blk/s)",
        full_sync.as_secs_f64(),
        n as f64 / full_sync.as_secs_f64()
    );

    // ---- B: dumptxoutset at tip -----------------------------------
    let tip = src.tip_hash();
    let tip_h = src.chain().len() as u32 - 1;
    let t0 = Instant::now();
    let coins = sorted_coins(src.utxo());
    let stats = coinstats::compute(
        src.utxo(),
        tip_h as i64,
        tip,
        CoinStatsHashType::HashSerialized,
    );
    let snap_path = std::env::temp_dir().join("avila-assumeutxo-snap.dat");
    let mut out = std::io::BufWriter::new(std::fs::File::create(&snap_path).unwrap());
    write_snapshot(
        &mut out,
        params.message_start,
        &tip,
        coins.len() as u64,
        &coins,
    )
    .unwrap();
    use std::io::Write;
    out.flush().unwrap();
    drop(out);
    let dump_t = t0.elapsed();
    let snap_mb = std::fs::metadata(&snap_path).unwrap().len() as f64 / 1e6;
    println!(
        "B. dumptxoutset: {} coins, {snap_mb:.1} MB, {:.1}s",
        coins.len(),
        dump_t.as_secs_f64()
    );

    // ---- C: fresh node — usable immediately -----------------------
    let mut p2 = params.clone();
    p2.assumeutxo_data = Box::leak(Box::new([AssumeutxoData {
        height: tip_h,
        hash_serialized: Box::leak(stats.hash_serialized.unwrap().to_string().into_boxed_str()),
        n_chain_tx: src.chain().len() as u64,
        blockhash: Box::leak(tip.to_string().into_boxed_str()),
    }]));
    let mut dst = Chainstate::new(&p2);
    // Headers only — cheap (the "sync to tip" the user waits on).
    let t0 = Instant::now();
    for b in &blocks {
        dst.accept_header(&b.header, now()).unwrap();
    }
    let headers_t = t0.elapsed();
    let t0 = Instant::now();
    let mut r = std::io::BufReader::new(std::fs::File::open(&snap_path).unwrap());
    let meta = read_metadata(&mut r, p2.message_start).unwrap();
    let base_h = dst.activate_snapshot(&mut r, &meta, false).unwrap();
    let load_t = t0.elapsed();
    let usable_t = headers_t + load_t;
    println!(
        "C. usable: headers {:.2}s + snapshot load {:.2}s = {:.2}s to tip {}",
        headers_t.as_secs_f64(),
        load_t.as_secs_f64(),
        usable_t.as_secs_f64(),
        base_h
    );
    // Bodies for the background pass — accept_block stores pre-base
    // blocks for validation rather than connecting them.
    let t0 = Instant::now();
    for b in &blocks {
        dst.accept_block(b, now()).unwrap();
    }
    println!(
        "    stored {} bodies in {:.2}s",
        n,
        t0.elapsed().as_secs_f64()
    );

    // ---- D: background validation -> fully verified ---------------
    let t0 = Instant::now();
    loop {
        match dst.background_step(10_000) {
            Ok(BackgroundStatus::Verified) | Ok(BackgroundStatus::NoSnapshot) => break,
            Ok(_) => continue,
            Err(e) => panic!("background validation failed: {e:?}"),
        }
    }
    let bg_t = t0.elapsed();
    assert!(dst.snapshot_verified());
    println!(
        "D. background validation of 0..{base_h}: {:.1}s",
        bg_t.as_secs_f64()
    );

    println!(
        "\ntime-to-usable: {:.2}s vs full sync {:.1}s  ({:.0}x)",
        usable_t.as_secs_f64(),
        full_sync.as_secs_f64(),
        full_sync.as_secs_f64() / usable_t.as_secs_f64().max(1e-3)
    );
    println!(
        "time-to-fully-validated: {:.1}s (snapshot path) vs {:.1}s (classic)",
        usable_t.as_secs_f64() + bg_t.as_secs_f64(),
        full_sync.as_secs_f64()
    );
}

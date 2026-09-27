// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Measures `get_ancestor` descent cost — the skip list should make a
//! tip→deep-ancestor probe O(log n) (~tens of hops), not O(n).
use avila_consensus::chainstate::Chainstate;
use std::time::Instant;

fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).expect("datadir"));
    let params = avila_consensus::params::Network::Mainnet.params();
    let cs = Chainstate::with_store_coinsdb(&dir, &params, 0, 512 << 20).expect("open");
    let best = cs.tree().tip();
    let n150k = cs
        .tree()
        .get_ancestor(&best.hash(), 150_000)
        .expect("ancestor");
    eprintln!("tip={} n150k.height={}", best.height, n150k.height);
    // Manual hop count of the script_checks-style descent — follow
    // `skip` whenever the target survives it, else step to prev.
    let mut hops = 0u64;
    let mut node = best;
    while node.height > n150k.height {
        hops += 1;
        node = match node.skip.and_then(|h| cs.tree().get(&h)) {
            Some(s) if s.height >= n150k.height => s,
            _ => cs.tree().get(&node.header.prev_block_hash).unwrap(),
        };
    }
    eprintln!("greedy descent tip→150k: {hops} hops");
    // And how many nodes carry a skip pointer at all?
    let (mut with_skip, mut total) = (0u64, 0u64);
    let mut cursor = best;
    loop {
        total += 1;
        if cursor.skip.is_some() {
            with_skip += 1;
        }
        if cursor.height == 0 {
            break;
        }
        cursor = cs.tree().get(&cursor.header.prev_block_hash).unwrap();
        if total > 20_000 {
            break;
        }
    }
    eprintln!("skip coverage on main chain (last 20k): {with_skip}/{total}");
    let t = Instant::now();
    let n = 1000;
    for _ in 0..n {
        std::hint::black_box(cs.tree().get_ancestor(&best.hash(), 150_000));
    }
    eprintln!(
        "get_ancestor(tip→150k): {} calls in {:?} = {:.2}us/call",
        n,
        t.elapsed(),
        t.elapsed().as_micros() as f64 / n as f64
    );
}

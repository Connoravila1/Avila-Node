//! Profile the `accept_block` path on a real datadir copy: after
//! `with_store_coinsdb` restores, stored tip-children are offered one
//! at a time and the connect-timing buckets are diffed every 100 —
//! splits the per-block cost into connect vs reorg vs total-accept.
//!
//! Usage: accept_probe <datadir-copy> [--start HEIGHT] [--count N]
//! The copy is opened like the live node — `state.dat`'s tip is the
//! floor; stored bodies above it are re-offered in chain order.
//!
//! Read-only w.r.t. the live node: run against a `cp -r` copy, never
//! the live dir (the store truncates partial tails on open).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use avila_consensus::chainstate::Chainstate;
use avila_consensus::connect::connect_timing;
use avila_consensus::store::read_state;
use std::path::PathBuf;

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().expect("usage: accept_probe <dir>"));
    let mut start = 0usize;
    let mut count = 2000usize;
    let mut a = args.peekable();
    while let Some(flag) = a.next() {
        match flag.as_str() {
            "--start" => start = a.next().unwrap().parse().unwrap(),
            "--count" => count = a.next().unwrap().parse().unwrap(),
            other => panic!("unknown flag {other}"),
        }
    }

    // Chain order comes from state.dat (connected hashes); bodies are
    // read back from the store at their recorded positions.
    let params = avila_consensus::params::Network::Mainnet.params();
    let state = read_state(&dir, params.message_start)
        .expect("read_state")
        .expect("state.dat present");
    let mut cs =
        Chainstate::with_store_coinsdb(&dir, &params, now(), 512 << 20).expect("chainstate open");

    // Stored bodies waiting above the restored tip — the parked set
    // isn't in state.chain (it never connected), so enumerate the store
    // index and keep entries whose recorded parent is the live tip.
    let tip_h = cs.chain().len() as u32 - 1;
    let mut by_height: Vec<(u32, avila_consensus::hash::BlockHash)> = Vec::new();
    if let Some(store) = cs.store() {
        for (hash, _) in store.positions() {
            if let Some(n) = cs.tree().get(&hash)
                && n.height > tip_h
            {
                by_height.push((n.height, hash));
            }
        }
    }
    by_height.sort_unstable();
    let queue: Vec<_> = by_height.into_iter().map(|(_, h)| h).collect();
    let queue = queue[start.min(queue.len())..(start + count).min(queue.len())].to_vec();
    let _ = state;
    eprintln!(
        "probe: tip={tip_h} queued={} (state.height={})",
        queue.len(),
        state.height
    );

    let ms = |ns: u64| ns / 1_000_000;
    let mut last = connect_timing();
    let wall = std::time::Instant::now();
    let mut body_ns = 0u64;
    let mut last_hops = 0u64;
    for (i, hash) in queue.iter().enumerate() {
        let t0 = std::time::Instant::now();
        let Some(block) = cs.body(hash) else { continue };
        body_ns += t0.elapsed().as_nanos() as u64;
        let _ = cs.accept_block(&block, now());
        if (i + 1) % 100 == 0 {
            let t = connect_timing();
            eprintln!(
                "probe: {i} tip={} dAccept={}ms dReorg={}ms dConnect={}ms dBody={}ms dSimBody={}ms dSimChecks={}ms seg=[{} {} {} {} {} {}]ms checks=[av={} best={} proof={}]ms hops={} (blk={})",
                cs.chain().len() - 1,
                ms(t.accept_ns - last.accept_ns),
                ms(t.reorg_ns - last.reorg_ns),
                ms(t.total_ns - last.total_ns),
                ms(body_ns),
                ms(t.sim_body_ns - last.sim_body_ns),
                ms(t.sim_checks_ns - last.sim_checks_ns),
                ms(t.seg_ns[0] - last.seg_ns[0]),
                ms(t.seg_ns[1] - last.seg_ns[1]),
                ms(t.seg_ns[2] - last.seg_ns[2]),
                ms(t.seg_ns[3] - last.seg_ns[3]),
                ms(t.seg_ns[4] - last.seg_ns[4]),
                ms(t.seg_ns[5] - last.seg_ns[5]),
                ms(t.checks_parts_ns[0] - last.checks_parts_ns[0]),
                ms(t.checks_parts_ns[1] - last.checks_parts_ns[1]),
                ms(t.checks_parts_ns[2] - last.checks_parts_ns[2]),
                avila_consensus::chain::ancestor_steps() - last_hops,
                t.blocks - last.blocks,
            );
            body_ns = 0;
            last_hops = avila_consensus::chain::ancestor_steps();
            last = t;
        }
    }
    eprintln!("probe done in {:?}", wall.elapsed());
}

//! End-to-end sync timing: blocks -> decode -> headers -> connect ->
//! flush, wall-clock by pipeline phase. `connect_bench` breaks down
//! inside `connect_block`; this reports the whole accept path —
//! where a real sync actually spends time.
//!
//! The flush share lands inside `accept_block` (it flushes on
//! `over_budget`), so: accept_total - connect_total ~= headers +
//! contextual + flush. A small `AVILA_DBCACHE_MB` forces real
//! backend commits into the measurement.
//!
//! usage: sync_bench <fixture.dat> [--spec]
//! env:   AVILA_DBCACHE_MB (default 512), AVILA_COINS_ENGINE (redb|hash)

use avila_consensus::chainstate::Chainstate;
use avila_consensus::connect::connect_timing;
use avila_consensus::params::Network;
use std::time::Instant;

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn main() {
    let mut args = std::env::args().skip(1);
    let fixture = args.next().unwrap_or_else(|| {
        eprintln!("usage: sync_bench <fixture.dat> [--spec]");
        std::process::exit(2);
    });
    let raw = std::fs::read(&fixture).unwrap_or_else(|e| panic!("read {fixture}: {e}"));
    let magic = &raw[..4];
    let params = match magic {
        [0xf9, 0xbe, 0xb4, 0xd9] => Network::Mainnet.params(),
        [0xfa, 0xbf, 0xb5, 0xda] => Network::Regtest.params(),
        other => panic!("unknown magic {other:02x?}"),
    };

    let dir = std::env::temp_dir().join(format!("avila-sync-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let budget: usize = std::env::var("AVILA_DBCACHE_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(|mb: usize| mb << 20)
        .unwrap_or(512 << 20);
    let engine = std::env::var("AVILA_COINS_ENGINE").unwrap_or_else(|_| "redb".into());
    let mut cs = Chainstate::with_store_coinsdb(&dir, &params, now(), budget)
        .unwrap_or_else(|e| panic!("chainstate: {e}"));
    let spec = args.any(|a| a == "--spec");
    if spec {
        cs.enable_speculative_connect();
    }

    let mut t_decode = 0u128;
    let mut t_header = 0u128;
    let mut t_accept = 0u128;
    let mut n = 0u64;
    let mut ntx = 0u64;
    let mut off = 0usize;
    let t_wall = Instant::now();
    while off + 8 <= raw.len() {
        let len = u32::from_le_bytes(raw[off + 4..off + 8].try_into().unwrap()) as usize;
        let t0 = Instant::now();
        let block = avila_consensus::block::Block::decode(&raw[off + 8..off + 8 + len])
            .unwrap_or_else(|e| panic!("decode block {n}: {e:?}"));
        t_decode += t0.elapsed().as_nanos();
        ntx += block.transactions.len() as u64;

        let t0 = Instant::now();
        cs.accept_header(&block.header, now())
            .unwrap_or_else(|e| panic!("header {n}: {e:?}"));
        t_header += t0.elapsed().as_nanos();

        let t0 = Instant::now();
        cs.accept_block(&block, now())
            .unwrap_or_else(|e| panic!("accept block {n}: {e:?}"));
        t_accept += t0.elapsed().as_nanos();
        n += 1;
        off += 8 + len;
    }
    let t0 = Instant::now();
    cs.drain_scripts().expect("drain");
    let t_drain = t0.elapsed().as_nanos();
    let wall = t_wall.elapsed();

    let t = connect_timing();
    let ms = |ns: u128| ns as f64 / 1e6;
    let connect_total = t.total_ns as u128;
    // accept_block also runs headers-contextual checks, over_budget
    // flushes, and (under --spec) drain_pending_to waits — the drain
    // is timed separately so the residual is really flush+contextual.
    let drain_ns = t.drain_ns as u128;
    let flush_resid = t_accept.saturating_sub(connect_total + drain_ns);
    println!(
        "blocks: {n} ({ntx} tx) in {:.1?} — {:.0} blk/s, {:.0} tx/s \
         (engine={engine}, cache {} MiB, spec={spec})",
        wall,
        n as f64 / wall.as_secs_f64(),
        ntx as f64 / wall.as_secs_f64(),
        budget >> 20,
    );
    println!("end-to-end pipeline (cum over {n} blocks):");
    let row = |name: &str, ns: u128| {
        println!(
            "  {name:<10} {:>9.0} ms  {:>5.1}%",
            ms(ns),
            ns as f64 / wall.as_nanos() as f64 * 100.0
        );
    };
    row("decode", t_decode);
    row("headers", t_header);
    row("connect", connect_total);
    row("spec-drain", drain_ns);
    row("flush*", flush_resid);
    row("drain", t_drain);
    let acct = t_decode + t_header + t_accept + t_drain;
    println!(
        "  (accounted {:.0} ms of {:.0} ms wall)",
        ms(acct),
        wall.as_secs_f64() * 1000.0
    );
    println!("  inside connect:");
    println!("    read   {:>8.0} ms", ms(t.read_ns as u128));
    println!("    apply  {:>8.0} ms", ms(t.apply_ns as u128));
    println!("    scripts{:>8.0} ms", ms(t.script_ns as u128));
    println!("    bip30  {:>8.0} ms", ms(t.bip30_ns as u128));
    let _ = std::fs::remove_dir_all(&dir);
}

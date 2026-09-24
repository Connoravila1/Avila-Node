// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Speculative block pre-validation probe.
//!
//! Connect-time script work for mempool-seen txs is already skipped via
//! the verified-tx cache (experiment #20). What remains unmeasured is the
//! *residual*: once scripts are covered by a correct mempool-template
//! prediction, what does connect still cost — and does prefetching the
//! predicted inputs' coins squeeze the remaining read+apply share?
//!
//! Modes:
//!   baseline            — plain connect, cold everything
//!   verified            — mark each block's txs verified right before
//!                         connect (models a perfectly predicted template:
//!                         mempool accept already did the script work)
//!   verified+prefetch   — verified + touch every input's prevout through
//!                         utxo().get() before connect (models the full
//!                         speculative path: template → prefetch coins)
//!
//! Usage: predict_bench <fixture.dat> <mode> [--spec]

use avila_consensus::chainstate::Chainstate;
use avila_consensus::connect::connect_timing;
use avila_consensus::params::Network;
use avila_consensus::script::{ScriptFlags, block_script_flags};
use avila_consensus::sigchecker::mark_scripts_verified;

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn main() {
    let mut args = std::env::args().skip(1);
    let fixture = args.next().unwrap_or_else(|| {
        eprintln!(
            "usage: predict_bench <fixture.dat> <baseline|verified|verified+prefetch> [--spec]"
        );
        std::process::exit(2);
    });
    let mode = args.next().unwrap_or_else(|| "baseline".into());
    let raw = std::fs::read(&fixture).unwrap_or_else(|e| panic!("read {fixture}: {e}"));

    let magic = &raw[..4];
    let params = match magic {
        [0xf9, 0xbe, 0xb4, 0xd9] => Network::Mainnet.params(),
        [0xfa, 0xbf, 0xb5, 0xda] => Network::Regtest.params(),
        other => panic!("unknown magic {other:02x?}"),
    };

    let dir = std::env::temp_dir().join(format!("avila-predict-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let budget: usize = std::env::var("AVILA_DBCACHE_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(|mb: usize| mb << 20)
        .unwrap_or(512 << 20);
    let mut cs = Chainstate::with_store_coinsdb(&dir, &params, now(), budget)
        .unwrap_or_else(|e| panic!("chainstate: {e}"));
    let spec = std::env::args().any(|a| a == "--spec");
    if spec {
        cs.enable_speculative_connect();
    }

    // Decode all blocks up front (as connect_bench does).
    let mut blocks = Vec::new();
    let mut off = 0usize;
    while off + 8 <= raw.len() {
        let len = u32::from_le_bytes(raw[off + 4..off + 8].try_into().unwrap()) as usize;
        blocks.push(
            avila_consensus::block::Block::decode(&raw[off + 8..off + 8 + len])
                .unwrap_or_else(|e| panic!("decode: {e:?}")),
        );
        off += 8 + len;
    }

    let n = blocks.len() as u64;
    let t_wall = std::time::Instant::now();
    for block in &blocks {
        cs.accept_header(&block.header, now())
            .unwrap_or_else(|e| panic!("header: {e:?}"));

        // Pre-connect prediction pass: mark verified and/or prefetch.
        if mode != "baseline" {
            let next_height = cs.chain().len() as u32;
            let tip = cs.tip_hash();
            let flags = block_script_flags(cs.tree().params(), next_height, &tip)
                .union(ScriptFlags::STRICTENC)
                .union(ScriptFlags::LOW_S)
                .union(ScriptFlags::MINIMALDATA)
                .union(ScriptFlags::NULLDUMMY)
                .union(ScriptFlags::CLEANSTACK)
                .union(ScriptFlags::MINIMALIF)
                .union(ScriptFlags::NULLFAIL)
                .union(ScriptFlags::WITNESS_PUBKEYTYPE);

            for tx in &block.transactions {
                if !tx.is_coinbase() {
                    mark_scripts_verified(tx.wtxid(), flags);
                    if mode == "verified+prefetch" {
                        for input in &tx.inputs {
                            let _ = cs.utxo().get(&input.previous_output);
                        }
                    }
                }
            }
        }

        match cs.accept_block(block, now()) {
            Ok(_) => {}
            Err(e) => panic!("accept: {e:?}"),
        }
    }
    cs.drain_scripts().expect("drain");
    let wall = t_wall.elapsed();

    let t = connect_timing();
    let ms = |ns: u64| ns as f64 / 1e6;
    let other = t
        .total_ns
        .saturating_sub(t.read_ns + t.apply_ns + t.script_ns + t.bip30_ns);
    println!(
        "blocks: {n} in {:.1?} — {:.0} blocks/s (mode={mode}, cache {} MiB, spec={})",
        wall,
        n as f64 / wall.as_secs_f64(),
        budget >> 20,
        spec
    );
    println!(
        "  read {:>8.0}ms  apply {:>8.0}ms  script {:>8.0}ms  bip30 {:>8.0}ms  other {:>8.0}ms",
        ms(t.read_ns),
        ms(t.apply_ns),
        ms(t.script_ns),
        ms(t.bip30_ns),
        ms(other)
    );
}

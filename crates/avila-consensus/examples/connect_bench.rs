// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end connect timing: replay a wire-format block fixture
//! through a real persistent chainstate and report where the time
//! goes — UTXO input fetches, map application, script checks, and
//! everything else (headers, hashing, undo, bookkeeping).
//!
//! This is the experiment that prices the UTXO layer: if read/apply
//! dominate, storage work is the right target; if scripts or "other"
//! dominate, the storage wins matter proportionally less.
//!
//! Usage: connect_bench <fixture.dat> [--engine redb|hash]
//! Fixture: `[magic4][len u32][block]…` — same layout as the diff
//! tools (`diff_segment.py` mainnet fixtures, `make_spend_fixture.py`
//! regtest fixtures).

use avila_consensus::chainstate::Chainstate;
use avila_consensus::connect::connect_timing;
use avila_consensus::params::Network;

/// Wall clock now — block mtimes must sit under the header window.
fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn main() {
    let mut args = std::env::args().skip(1);
    let fixture = args.next().unwrap_or_else(|| {
        eprintln!("usage: connect_bench <fixture.dat>");
        std::process::exit(2);
    });
    let raw = std::fs::read(&fixture).unwrap_or_else(|e| panic!("read {fixture}: {e}"));

    // Detect network from the fixture's magic.
    let magic = &raw[..4];
    let params = match magic {
        [0xf9, 0xbe, 0xb4, 0xd9] => Network::Mainnet.params(),
        [0xfa, 0xbf, 0xb5, 0xda] => Network::Regtest.params(),
        other => panic!("unknown magic {other:02x?}"),
    };

    let dir = std::env::temp_dir().join(format!("avila-connect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let budget: usize = std::env::var("AVILA_DBCACHE_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .map(|mb: usize| mb << 20)
        .unwrap_or(512 << 20);
    let mut cs = Chainstate::with_store_coinsdb(&dir, &params, now(), budget)
        .unwrap_or_else(|e| panic!("chainstate: {e}"));
    let spec = args.any(|a| a == "--spec");
    if spec {
        cs.enable_speculative_connect();
    }

    let mut off = 0usize;
    let mut n = 0u64;
    let t_wall = std::time::Instant::now();
    while off + 8 <= raw.len() {
        let len = u32::from_le_bytes(raw[off + 4..off + 8].try_into().unwrap()) as usize;
        let block = avila_consensus::block::Block::decode(&raw[off + 8..off + 8 + len])
            .unwrap_or_else(|e| {
                panic!("decode block {n}: {e:?}");
            });
        cs.accept_header(&block.header, now())
            .unwrap_or_else(|e| panic!("header {n}: {e:?}"));
        match cs.accept_block(&block, now()) {
            Ok(_) => {}
            Err(e) => panic!("accept block {n}: {e:?}"),
        }
        n += 1;
        off += 8 + len;
    }
    cs.drain_scripts().expect("drain");
    let wall = t_wall.elapsed();

    let t = connect_timing();
    let ms = |ns: u64| ns as f64 / 1e6;
    let other = t
        .total_ns
        .saturating_sub(t.read_ns + t.apply_ns + t.script_ns + t.bip30_ns);
    println!(
        "blocks: {n} in {:.1?} — {:.0} blocks/s (cache {} MiB, spec={})",
        wall,
        n as f64 / wall.as_secs_f64(),
        budget >> 20,
        spec
    );
    println!("connect_block breakdown (cum over {n} blocks):");
    println!("  total   {:>9.0} ms", ms(t.total_ns));
    println!(
        "  read    {:>9.0} ms  (utxo.get inside check_tx_inputs)",
        ms(t.read_ns)
    );
    println!(
        "  apply   {:>9.0} ms  (spend + add_tx_outputs)",
        ms(t.apply_ns)
    );
    println!(
        "  scripts {:>9.0} ms  (parallel sig checks)",
        ms(t.script_ns)
    );
    println!("  bip30   {:>9.0} ms", ms(t.bip30_ns));
    println!(
        "  other   {:>9.0} ms  (headers/tree/undo/hashing/misc)",
        ms(other)
    );
    let pct = |x: u64| 100.0 * x as f64 / t.total_ns as f64;
    println!(
        "storage share (read+apply): {:.1}% of connect time",
        pct(t.read_ns + t.apply_ns)
    );

    // Backend write stats — how much churn reached disk.
    if let Some(be) = cs.utxo().backend() {
        let (commits, puts, dels) = be.write_stats();
        println!("backend: {commits} commits, {puts} puts, {dels} dels");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

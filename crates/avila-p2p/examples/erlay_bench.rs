// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Erlay (BIP-330) set-reconciliation spike on the pure-Rust sketch:
//! one sketch exchange reconciles D differing tx short-ids — measure
//! real bytes/D, decode success rates, and decode cost vs full-inv.
//!
//! Run: cargo run --release -p avila-p2p --example erlay_bench

use avila_p2p::sketch::Sketch;
use std::time::Instant;

fn main() {
    const SET: u32 = 40_000; // ~mempool size in short-ids
    println!("set={SET} 32-bit ids — one sketch exchange, one decode round\n");
    println!(
        "{:>6} {:>9} {:>9} {:>12} {:>6}",
        "D", "cap", "sketch B", "decode", "ok"
    );

    for &d in &[0u32, 1, 4, 16, 64, 128, 256] {
        let cap = ((2 * d).max(8)) as usize;
        let (mut a, mut b) = (Sketch::new(cap), Sketch::new(cap));
        for i in 0..SET {
            a.add(i);
            b.add(i);
        }
        for i in 0..d {
            a.add(SET + i);
            b.add(SET + 100_000 + i);
        }
        let wire = a.serialize().len();
        a.merge(&b);
        let t = Instant::now();
        let got = a.decode();
        let dt = t.elapsed();
        let ok = got.map(|v| v.len() == (2 * d) as usize).unwrap_or(false);
        println!("{d:>6} {cap:>9} {wire:>9} {dt:>12.1?} {ok:>6}");
    }

    // Capacity-tightness: exact-capacity sketches at small D.
    println!("\ncapacity = D exactly (tightest wire):");
    for &d in &[1u32, 4, 16, 64] {
        let (mut a, mut b) = (Sketch::new(d as usize), Sketch::new(d as usize));
        for i in 0..SET {
            a.add(i);
            b.add(i);
        }
        for i in 0..d {
            a.add(SET + i);
            b.add(SET + 100_000 + i);
        }
        a.merge(&b);
        let t = Instant::now();
        let got = a.decode();
        println!(
            "  D={d}: {}B sketch -> decode {:?} ({} found)",
            4 * d,
            t.elapsed(),
            got.map(|v| v.len()).unwrap_or(0)
        );
    }

    println!("\nvs full-inv of the same 40k mempool:");
    let inv_bytes = 40_000usize * 32;
    for &d in &[4u32, 16, 64, 128] {
        let sketch_bytes = 4 * 2 * d;
        println!(
            "  D={d}: sketch {sketch_bytes}B vs inv {inv_bytes}B — {:.0}x smaller",
            inv_bytes / sketch_bytes as usize
        );
    }
}

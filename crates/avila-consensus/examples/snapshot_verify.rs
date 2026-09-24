// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Snapshot load at disk speed — see `avila_consensus::snapverify`.
//!
//! `scan <snapshot> <threads>` — parallel exact parse + sparse index.
//! `verify <snapshot> <base_height> <hints_out>` — sequential
//!   `hash_serialized_3` (one SHA-256 stream); writes midstate hints.
//! `hinted <snapshot> <base_height> <hints> <threads>` — the same hash,
//!   verified in parallel from untrusted hints.
//!
//! All reads use O_DIRECT, so no page-cache eviction is needed between
//! runs. Prints one `key=value` line.

use avila_consensus::snapverify::{self, Hints};
use std::path::Path;
use std::time::Instant;

const BUCKET: u64 = 16 << 10;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| a.get(i).map(String::as_str).ok_or("missing argument");
    let t = Instant::now();
    match arg(0)? {
        "scan" => {
            let threads: usize = arg(2)?.parse()?;
            let o = snapverify::scan(Path::new(arg(1)?), true, threads, u32::MAX >> 1, BUCKET)?;
            println!(
                "mode=scan threads={threads} seconds={:.3} coins={} groups={} sparse={} fallbacks={} read={}",
                t.elapsed().as_secs_f64(),
                o.coins,
                o.groups,
                o.sparse.len(),
                o.fallbacks,
                o.bytes_read
            );
        }
        "verify" => {
            let (o, hints) = snapverify::verify_stream(
                Path::new(arg(1)?),
                true,
                arg(2)?.parse()?,
                64 << 20,
                BUCKET,
            )?;
            let secs = t.elapsed().as_secs_f64();
            std::fs::write(arg(3)?, hints.encode())?;
            println!(
                "mode=verify seconds={secs:.3} coins={} hash={} hints={} hint_bytes={}",
                o.coins,
                avila_consensus::hash::format_display_hex(&o.hash),
                hints.hints.len(),
                hints.encode().len()
            );
        }
        "hinted" => {
            let hints = Hints::decode(&std::fs::read(arg(3)?)?)?;
            let threads: usize = arg(4)?.parse()?;
            let o = snapverify::verify_hinted(
                Path::new(arg(1)?),
                true,
                threads,
                arg(2)?.parse()?,
                &hints,
                BUCKET,
            )?;
            println!(
                "mode=hinted threads={threads} seconds={:.3} coins={} hash={} read={}",
                t.elapsed().as_secs_f64(),
                o.coins,
                avila_consensus::hash::format_display_hex(&o.hash),
                o.bytes_read
            );
        }
        m => return Err(format!("unknown mode {m}").into()),
    }
    Ok(())
}

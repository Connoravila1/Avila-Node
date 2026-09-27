// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Re-encode a `dumptxoutset` snapshot in `window_join`'s canonical
//! export order/bytes, so the node's incremental chainstate at a height
//! can be byte-compared against the join engine's materialized state.
//!
//! `snap_to_canonical <snapshot.utxo> <out.canonical>`
//!
//! Prints `coins=<n> bytes=<n> sha256=<hex>` — the same digest a
//! `window_join --export` run reports, so equality is a one-line check.

use avila_consensus::snapverify::{self, ShaState, for_each_coin};
use std::io::{Read, Write};
use std::path::Path;

#[path = "shared/join_engine.rs"]
mod join_engine;
use join_engine::{FlatBoundary, FlatBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let snap = Path::new(a.first().ok_or("snapshot path")?);
    let out = Path::new(a.get(1).ok_or("out path")?);
    // Flat sorted table — a HashMap of ~46M coins needs ~10+ GB; this
    // needs ~4 GB and iterates in canonical order for free.
    let expected = snapverify::read_header(&std::fs::File::open(snap)?)
        .map(|h| h.coins_count as usize)
        .unwrap_or(0);
    let mut fb = FlatBuilder::new(expected);
    let loaded = for_each_coin(snap, None, |txid, vout, code, value, script| {
        fb.push(txid, vout, value, code, script);
        Ok(())
    })?;
    let (flat, dups): (FlatBoundary, usize) = fb.finish();
    if dups > 0 {
        return Err(format!("snapshot contains {dups} duplicate outpoints").into());
    }
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    for i in 0..flat.txids_len() {
        let (txid, vout, value, code, spk) = flat.record_raw(i);
        f.write_all(&txid)?;
        f.write_all(&vout.to_le_bytes())?;
        f.write_all(&value.to_le_bytes())?;
        f.write_all(&(spk.len() as u32).to_le_bytes())?;
        f.write_all(spk)?;
        f.write_all(&(code >> 1).to_le_bytes())?;
        f.write_all(&[(code & 1) as u8])?;
    }
    f.flush()?;
    // Streamed digest — no 3.6 GB whole-file read.
    let mut st = ShaState::default();
    let mut bytes = 0u64;
    let mut r = std::io::BufReader::with_capacity(1 << 22, std::fs::File::open(out)?);
    let mut buf = vec![0u8; 1 << 22];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        st.update(&buf[..n]);
        bytes += n as u64;
    }
    let digest = st.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "coins={} declared={} bytes={} sha256={}",
        flat.txids_len(),
        loaded.header.coins_count,
        bytes,
        hex
    );
    Ok(())
}

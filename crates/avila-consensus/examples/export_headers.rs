// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Export the full header index stored in `state.dat` as a compact
//! manifest for `window_join --headers`.
//!
//! `export_headers <datadir> <network> <out>`
//!
//! Layout: `b"HCHAIN01"` | u32 count | count × 80-byte headers in the
//! stored (parent-before-child) order. Heights are not repeated — the
//! receiving `HeaderTree` derives them from linkage.
//!
//! `state.dat` also records which of those headers sit on the connected
//! best chain (`chain` hash list); the second section emits that list so
//! the driver can distinguish connected headers from headers-first-only
//! index entries: `b"CHAIN"` | u32 count | count × 32-byte hashes.

use std::io::Write;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let dir = Path::new(a.first().ok_or("datadir")?);
    let net = a.get(1).map(String::as_str).unwrap_or("mainnet");
    let out = Path::new(a.get(2).ok_or("out")?);
    let magic = match net {
        "mainnet" => *b"\xf9\xbe\xb4\xd9",
        "regtest" => *b"\xfa\xbf\xb5\xda",
        "signet" => *b"\x0a\x03\xcf\x40",
        "testnet" | "testnet4" => *b"\x0b\x11\x09\x08",
        other => return Err(format!("unknown network {other}").into()),
    };
    let state = avila_consensus::store::read_state(dir, magic)?
        .ok_or("no state.dat snapshot — run the node once first")?;
    let mut f = std::io::BufWriter::new(std::fs::File::create(out)?);
    f.write_all(b"HCHAIN01")?;
    f.write_all(&(state.headers.len() as u32).to_le_bytes())?;
    for h in &state.headers {
        f.write_all(&h.encode())?;
    }
    f.write_all(b"CHAIN")?;
    f.write_all(&(state.chain.len() as u32).to_le_bytes())?;
    for hash in &state.chain {
        f.write_all(hash.as_bytes())?;
    }
    f.flush()?;
    eprintln!(
        "headers={} chain={} tip={} height={}",
        state.headers.len(),
        state.chain.len(),
        state.tip,
        state.height
    );
    Ok(())
}

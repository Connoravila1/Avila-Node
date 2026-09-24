//! Scripthash-index cost model: replay a fixture with the Electrum
//! index on vs off and report the connect-time delta, on-disk log
//! size, and in-memory index size — the inputs to "is an opt-in
//! address-index profile practical?".
//!
//! Usage: scindex_bench <fixture.dat>

use avila_consensus::chainstate::Chainstate;
use avila_consensus::params::Network;

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn run(fixture: &[u8], params: &avila_consensus::params::Params, index: bool) -> (f64, u64, usize, usize) {
    let dir = std::env::temp_dir().join(format!(
        "avila-scindex-{}-{}",
        std::process::id(),
        if index { "on" } else { "off" }
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let mut cs = Chainstate::with_store_coinsdb(&dir, params, now(), 512 << 20)
        .unwrap_or_else(|e| panic!("chainstate: {e}"));
    if index {
        cs.enable_scripthashindex(Some(&dir)).expect("scindex");
    }
    let mut off = 0usize;
    let mut n = 0u64;
    let t = std::time::Instant::now();
    while off + 8 <= fixture.len() {
        let len = u32::from_le_bytes(fixture[off + 4..off + 8].try_into().unwrap()) as usize;
        let block = avila_consensus::block::Block::decode(&fixture[off + 8..off + 8 + len])
            .unwrap_or_else(|e| panic!("decode: {e:?}"));
        cs.accept_header(&block.header, now()).unwrap();
        cs.accept_block(&block, now()).unwrap();
        n += 1;
        off += 8 + len;
    }
    cs.drain_scripts().expect("drain");
    let wall = t.elapsed().as_secs_f64();
    let log_bytes = std::fs::metadata(dir.join("scindex.dat"))
        .map(|m| m.len())
        .unwrap_or(0);
    let (scripts, entries) = cs.scripthash_index_stats().unwrap_or((0, 0));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = n;
    (wall, log_bytes, scripts, entries)
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: scindex_bench <fixture.dat>");
        std::process::exit(2);
    });
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let params = match &raw[..4] {
        [0xf9, 0xbe, 0xb4, 0xd9] => Network::Mainnet.params(),
        [0xfa, 0xbf, 0xb5, 0xda] => Network::Regtest.params(),
        other => panic!("unknown magic {other:02x?}"),
    };
    let (w0, _, _, _) = run(&raw, &params, false);
    let (w1, log_bytes, scripts, entries) = run(&raw, &params, true);
    println!("index off: {w0:.2}s   on: {w1:.2}s   (+{:.1}%)", (w1 / w0 - 1.0) * 100.0);
    println!("scindex.dat: {log_bytes} bytes  | {scripts} unique scripts, {entries} history entries");
    if entries > 0 {
        println!("~{:.0} bytes/log-entry, ~{:.0} in-mem bytes/entry est.", log_bytes as f64 / entries as f64, 42.0);
    }
}

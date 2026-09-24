// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! #31 — SwiftSync-style write elision, proven on real chain data.
//!
//! Replays the node's own signet `blk*.dat` files maintaining only a
//! 256-bit tag aggregate plus a transient tag map — no coin writes —
//! then proves `created − spent == Σ survivor tags`, the equality an
//! aggregate-verified no-write sync depends on. Reports the coin
//! writes a hinted path eliminates, the transient map's peak memory
//! (the technique's real cost), and runs the fraud check a consumer
//! needs: a corrupted survivor claim must fail the equality.
//!
//! blk files are written in arrival order and carry orphan blocks, so
//! pass 1 indexes headers and builds the best chain; pass 2 replays
//! the main chain only — a spend that misses is then a real anomaly.
//!
//! `BLKDIR` env selects the block directory (default
//! `/tmp/avila-data/signet`); `MAXBLOCKS` caps the replay height.

use avila_consensus::block::Block;
use avila_consensus::hash::{BlockHash, tagged_hash};
use avila_consensus::header::BlockHeader;
use avila_consensus::transaction::{OutPoint, Script};
use std::collections::HashMap;

/// 256-bit wrapping-sum accumulator — the order-free multiset hash a
/// hinted sync maintains over created/spent coin tags. Wrapping
/// arithmetic makes subtraction the exact inverse of addition, so the
/// running value always equals Σ(live tags) regardless of order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Agg([u64; 4]);

impl Agg {
    fn add(&mut self, t: &[u8; 32]) {
        for (i, w) in self.0.iter_mut().enumerate() {
            let v = u64::from_le_bytes(t[i * 8..i * 8 + 8].try_into().unwrap_or_default());
            *w = w.wrapping_add(v);
        }
    }
    fn sub(&mut self, t: &[u8; 32]) {
        for (i, w) in self.0.iter_mut().enumerate() {
            let v = u64::from_le_bytes(t[i * 8..i * 8 + 8].try_into().unwrap_or_default());
            *w = w.wrapping_sub(v);
        }
    }
}

/// Commitment to one created coin — binds the outpoint to the coin
/// contents (value, script, height, coinbase flag) so a hinted
/// consumer recomputes the identical tag from the coin it must
/// already fetch to validate the spend.
fn coin_tag(op: OutPoint, value: i64, height: u32, coinbase: bool, script: &Script) -> [u8; 32] {
    let mut b = Vec::with_capacity(49 + script.as_bytes().len());
    b.extend_from_slice(op.txid.as_bytes());
    b.extend_from_slice(&op.vout.to_le_bytes());
    b.extend_from_slice(&value.to_le_bytes());
    b.extend_from_slice(&height.to_le_bytes());
    b.push(u8::from(coinbase));
    b.extend_from_slice(script.as_bytes());
    tagged_hash(b"avila/swiftsync-coin", &b)
}

const MAGIC: [u8; 4] = [0x0a, 0x03, 0xcf, 0x40]; // signet

/// Frame location of one block inside the blk file set.
#[derive(Clone, Copy)]
struct Loc {
    file: usize,
    offset: usize,
    len: usize,
}

fn main() {
    let dir = std::env::var("BLKDIR").unwrap_or_else(|_| "/tmp/avila-data/signet".into());
    let max: u64 = std::env::var("MAXBLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(u64::MAX);
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("blkdir {dir}: {e}"))
        .filter_map(|e| {
            let e = e.ok()?;
            let n = e.file_name().into_string().ok()?;
            n.starts_with("blk").then(|| e.path())
        })
        .collect();
    files.sort();

    // Pass 1: index every frame by header hash; remember each block's
    // parent so the best chain can be rebuilt.
    let mut data: Vec<Vec<u8>> = Vec::with_capacity(files.len());
    let mut locs: HashMap<BlockHash, Loc> = HashMap::new();
    let mut prev_of: HashMap<BlockHash, BlockHash> = HashMap::new();
    for (fi, path) in files.iter().enumerate() {
        let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
        let mut pos = 0usize;
        while pos + 88 <= bytes.len() {
            if bytes[pos..pos + 4] != MAGIC {
                break; // torn tail
            }
            let len = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap()) as usize;
            pos += 8;
            if pos + len > bytes.len() || len < 80 {
                break;
            }
            let hdr = BlockHeader::decode(&bytes[pos..pos + 80])
                .unwrap_or_else(|e| panic!("header decode: {e}"));
            let h = hdr.hash();
            locs.entry(h).or_insert(Loc {
                file: fi,
                offset: pos,
                len,
            });
            prev_of.entry(h).or_insert(hdr.prev_block_hash);
            pos += len;
        }
        data.push(bytes);
    }

    // Deepest tip wins the header race — walk every candidate back
    // and keep the longest chain (the one our node connected).
    let is_parent: std::collections::HashSet<BlockHash> = prev_of.values().copied().collect();
    let genesis_h = *prev_of
        .iter()
        .find(|(_, p)| !locs.contains_key(*p))
        .map(|(h, _)| h)
        .unwrap_or_else(|| panic!("no genesis-rooted block in set"));
    let mut best_tip = genesis_h;
    let mut best_depth = 0u64;
    for (&h, _) in locs.iter().filter(|(h, _)| !is_parent.contains(*h)) {
        let mut depth = 0u64;
        let mut cur = h;
        while let Some(&p) = prev_of.get(&cur) {
            depth += 1;
            if !locs.contains_key(&p) {
                break;
            }
            cur = p;
        }
        if depth > best_depth {
            best_depth = depth;
            best_tip = h;
        }
    }

    // Rebuild the main chain genesis→tip.
    let mut chain = Vec::new();
    let mut cur = best_tip;
    while let Some(&p) = prev_of.get(&cur) {
        chain.push(cur);
        if !locs.contains_key(&p) {
            break;
        }
        cur = p;
    }
    chain.reverse();
    let indexed = locs.len();
    let side = indexed - chain.len();
    println!(
        "indexed {indexed} blocks ({side} side-branch) — main chain {} blocks, replaying {}",
        chain.len() + 1,
        chain.len().min(max as usize) + 1
    );

    // Pass 2: replay the main chain only.
    let mut live: HashMap<OutPoint, [u8; 32]> = HashMap::new();
    let mut agg = Agg::default();
    let (mut created, mut spent, mut misses) = (0u64, 0u64, 0u64);
    let mut peak_live = 0usize;
    for (h_idx, &bh) in chain.iter().enumerate() {
        let height = (h_idx + 1) as u32;
        if u64::from(height) > max {
            break;
        }
        let loc = locs[&bh];
        let block = Block::decode(&data[loc.file][loc.offset..loc.offset + loc.len])
            .unwrap_or_else(|e| panic!("decode {bh:?}: {e}"));
        for (txi, tx) in block.transactions.iter().enumerate() {
            let coinbase = txi == 0;
            if !coinbase {
                for i in &tx.inputs {
                    match live.remove(&i.previous_output) {
                        Some(t) => {
                            agg.sub(&t);
                            spent += 1;
                        }
                        None => misses += 1,
                    }
                }
            }
            let txid = tx.txid();
            for (vout, out) in tx.outputs.iter().enumerate() {
                let op = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                let tag = coin_tag(op, out.value, height, coinbase, &out.script_pubkey);
                agg.add(&tag);
                live.insert(op, tag);
                created += 1;
            }
        }
        peak_live = peak_live.max(live.len());
    }
    let tip_height = chain.len().min(max as usize) as u32;

    // The verification a hinted consumer runs at window end: the
    // aggregate must equal the sum over the surviving set.
    let mut survivor_sum = Agg::default();
    for t in live.values() {
        survivor_sum.add(t);
    }
    let elided = created - live.len() as u64;
    println!(
        "blocks {tip_height} | created {created} | spent {spent} | survivors {}",
        live.len()
    );
    println!(
        "write elision: {elided} of {created} creates never need disk ({:.1}%) — \
         plus {spent} deletes",
        100.0 * elided as f64 / created as f64
    );
    println!(
        "transient map: peak {peak_live} entries (~{:.0} MiB at ~96B/entry)",
        peak_live as f64 * 96.0 / (1 << 20) as f64
    );
    println!(
        "aggregate check: created−spent {} Σ survivors",
        if agg == survivor_sum {
            "=="
        } else {
            "!= (FAIL)"
        }
    );
    assert_eq!(agg, survivor_sum, "aggregate must equal survivor sum");

    // Fraud check: drop one survivor from the hinted claim — the
    // equality must break, which is the consumer's fraud detection.
    if let Some((&op, _)) = live.iter().next() {
        let mut corrupted: HashMap<OutPoint, [u8; 32]> = live.clone();
        corrupted.remove(&op);
        let mut csum = Agg::default();
        for t in corrupted.values() {
            csum.add(t);
        }
        assert_ne!(agg, csum, "dropped survivor must break the aggregate");
        println!("fraud check: omitted survivor detected — equality fails as required");
    }
    if misses > 0 {
        println!("ANOMALY: {misses} spends hit outpoints not in the live map");
    }

    // The hints artifact a producer ships: sorted survivor outpoints
    // + the aggregate commitment + the block hash it describes. A
    // consumer verifies `Σ tag(hinted coins) == committed aggregate`
    // before trusting a single entry — the file is untrusted input,
    // never needed until the checkpoint.
    let mut hint_bytes = Vec::with_capacity(32 + 4 + live.len() * 36);
    hint_bytes.extend_from_slice(&agg.0.map(|w| w.to_le_bytes()).concat());
    hint_bytes.extend_from_slice(&tip_height.to_le_bytes());
    for op in {
        let mut v: Vec<_> = live.keys().collect();
        v.sort_by(|a, b| {
            a.txid
                .as_bytes()
                .cmp(b.txid.as_bytes())
                .then(a.vout.cmp(&b.vout))
        });
        v
    } {
        hint_bytes.extend_from_slice(op.txid.as_bytes());
        hint_bytes.extend_from_slice(&op.vout.to_le_bytes());
    }
    let hint_path = std::env::temp_dir().join("avila-swiftsync.hints");
    std::fs::write(&hint_path, &hint_bytes).unwrap_or_else(|e| panic!("hints write: {e}"));
    println!(
        "hints file: {} bytes ({:.1}B/survivor — outpoint-only) -> {}",
        hint_bytes.len(),
        hint_bytes.len() as f64 / live.len().max(1) as f64,
        hint_path.display()
    );
}

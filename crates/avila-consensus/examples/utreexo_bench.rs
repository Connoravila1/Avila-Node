//! Utreexo spike on a synthetic UTXO set: build the accumulator as a
//! bridge node (MemForest), then validate spends as a light node
//! (Stump = roots only) — measures proof size, verify cost, and the
//! state-size difference that is the whole point.
//!
//! Model: leaf hash = SHA-256d of the coin's compact serialization
//! (outpoint key + coin body) — the same bytes the snapshot commits
//! to, so the leaf is derivable by anyone holding the set.
//!
//! Run: cargo run --release -p avila-consensus --example utreexo_bench [N]

use rustreexo::mem_forest::MemForest;
use rustreexo::node_hash::BitcoinNodeHash;
use rustreexo::stump::Stump;
use std::time::Instant;

fn leaf_of(op_key: &[u8; 36], coin_body: &[u8]) -> BitcoinNodeHash {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(op_key);
    h.update(coin_body);
    let d = sha2::Sha256::digest(h.finalize());
    BitcoinNodeHash::from(d.as_slice())
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    println!("building {n}-leaf utreexo accumulator\n");

    // Synthetic coin set: deterministic keys + plausible bodies.
    let mut forest = MemForest::<BitcoinNodeHash>::new();
    let t = Instant::now();
    let mut leaves = Vec::with_capacity(n);
    for i in 0..n {
        let mut key = [0u8; 36];
        key[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let body = [0x51u8; 25]; // P2WSH-ish size body
        leaves.push(leaf_of(&key, &body));
    }
    forest.modify(&leaves, &[]).expect("forest build");
    println!(
        "forest build: {n} leaves in {:?} ({:.0}/s)",
        t.elapsed(),
        n as f64 / t.elapsed().as_secs_f64()
    );
    let _forest_bytes = 0usize;

    // Light node: Stump = roots only — the entire state it stores.
    let mut stump = Stump::<BitcoinNodeHash>::new();
    let (new_stump, _ud) = stump
        .modify(&leaves, &[], &Default::default())
        .expect("stump build");
    stump = new_stump;
    let mut stump_bytes = Vec::new();
    let _ = stump.serialize(&mut stump_bytes);
    println!(
        "stump state: {} bytes for {n} leaves ({:.0}x smaller than ~{}MB utxo set)",
        stump_bytes.len(),
        (n * 50) as f64 / stump_bytes.len() as f64,
        n * 50 / 1_000_000
    );

    // Proof: a spend of k coins = proof of their leaves — disjoint
    // ranges per k since spent leaves can't be proven again.
    let mut cursor = 0usize;
    for &k in &[1usize, 8, 64] {
        let targets: Vec<BitcoinNodeHash> = leaves[cursor..cursor + k].to_vec();
        cursor += k;
        let t = Instant::now();
        let proof = forest.prove(&targets).expect("prove");
        let prove_t = t.elapsed();
        let mut pbytes = Vec::new();
        let _ = proof.serialize(&mut pbytes);

        let t = Instant::now();
        let ok = stump.verify(&proof, &targets).unwrap_or(false);
        let verify_t = t.elapsed();
        // Apply the spend on both sides: the bridge forest deletes the
        // proven leaves + adds the new output too — the accumulator is
        // shared state, both sides advance together.
        let new_leaf = leaf_of(&[9u8; 36], &[0x51; 25]);
        forest.modify(&[new_leaf], &targets).expect("forest spend");
        let (s2, _ud2) = stump.modify(&[new_leaf], &targets, &proof).expect("spend");
        stump = s2;
        println!(
            "spend k={k}: proof {}B in {:?} | verify {:?} ok={ok}",
            pbytes.len(),
            prove_t,
            verify_t
        );
    }

    // Throughput: a block-ish batch of 2000 spends.
    let k = 2000usize.min((n - cursor) / 2);
    let targets: Vec<BitcoinNodeHash> = leaves[cursor..cursor + k].to_vec();
    let t = Instant::now();
    let proof = forest.prove(&targets).expect("batch prove");
    let mut pbytes = Vec::new();
    let _ = proof.serialize(&mut pbytes);
    let prove_t = t.elapsed();
    let t = Instant::now();
    let (s2, _ud) = stump.modify(&[], &targets, &proof).expect("batch apply");
    stump = s2;
    forest.modify(&[], &targets).expect("forest batch");
    println!(
        "\nblock-batch k={k}: proof {}B gen {:?} | verify+apply {:?} ({:.0} leaves/s)",
        pbytes.len(),
        prove_t,
        t.elapsed(),
        k as f64 / t.elapsed().as_secs_f64()
    );
}

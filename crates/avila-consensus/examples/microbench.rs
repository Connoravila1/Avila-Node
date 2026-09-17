//! G1 microbenchmarks for the consensus hot paths — plain `std::time`
//! timings, no harness deps. Run:
//!
//!   cargo run --release -p avila-consensus --example microbench
//!
//! Emits `name, ops/s, ns/op` lines for scorecard ingestion.

use std::time::Instant;

use avila_consensus::block::Block;
use avila_consensus::hash::{BlockHash, MerkleRoot};
use avila_consensus::header::BlockHeader;
use avila_consensus::transaction::{OutPoint, Transaction, TxIn, TxOut};

fn bench<F: FnMut() -> R, R>(name: &str, mut f: F, iters: usize) {
    // Warmup.
    for _ in 0..iters / 10 {
        std::hint::black_box(f());
    }
    let t0 = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(f());
    }
    let el = t0.elapsed();
    let ns = el.as_nanos() as f64 / iters as f64;
    let ops = 1e9 / ns;
    println!("{name:<40} {ops:>14.0} ops/s  {ns:>10.1} ns/op");
}

fn sample_tx(n: u32) -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: avila_consensus::hash::Txid::from_bytes([n as u8; 32]),
                vout: 0,
            },
            script_sig: avila_consensus::transaction::Script::new(vec![0x51; 40]),
            sequence: 0xffffffff,
            witness: avila_consensus::transaction::Witness::default(),
        }],
        outputs: vec![TxOut {
            value: 1000,
            script_pubkey: avila_consensus::transaction::Script::new(vec![0x51; 34]),
        }],
        lock_time: 0,
    }
}

fn sample_block(txs: usize) -> Block {
    Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: BlockHash::from_bytes([1; 32]),
            merkle_root: MerkleRoot::from_bytes([0; 32]),
            time: 1_700_000_000,
            bits: avila_consensus::arith::CompactTarget(0x207f_ffff),
            nonce: 0,
        },
        transactions: (0..txs).map(|i| sample_tx(i as u32)).collect(),
    }
}

fn main() {
    let tx = sample_tx(7);
    let raw = tx.encode();
    bench("tx encode", || tx.encode(), 200_000);
    bench("tx decode", || Transaction::decode(&raw).ok(), 200_000);
    bench("tx txid", || tx.txid(), 200_000);
    bench("tx wtxid", || tx.wtxid(), 200_000);

    let b10 = sample_block(10);
    let b500 = sample_block(500);
    bench("block merkle_root (10 tx)", || b10.merkle_root(), 20_000);
    bench("block merkle_root (500 tx)", || b500.merkle_root(), 2_000);
    bench("block encode (500 tx)", || b500.encode(), 2_000);
    let b500_raw = b500.encode();
    bench(
        "block decode (500 tx)",
        || Block::decode(&b500_raw).ok(),
        2_000,
    );

    // secp256k1 signature verification — the per-input hot path.
    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let msg = secp256k1::Message::from_digest([9; 32]);
    let sig = secp.sign_ecdsa(&msg, &sk);
    bench(
        "secp256k1 ecdsa verify",
        || secp.verify_ecdsa(&msg, &sig, &pk).is_ok(),
        10_000,
    );

    // UTXO-set insert/spend churn — the connect-side hot path.
    let mut utxos = avila_consensus::connect::UtxoSet::new();
    let mut n = 0u32;
    bench(
        "utxo insert+spend",
        || {
            n += 1;
            let op = OutPoint {
                txid: avila_consensus::hash::Txid::from_bytes(
                    n.to_le_bytes().repeat(8).try_into().unwrap_or([0; 32]),
                ),
                vout: 0,
            };
            utxos.insert_synthetic(
                op,
                avila_consensus::connect::Coin {
                    out: TxOut {
                        value: 1,
                        script_pubkey: avila_consensus::transaction::Script::new(vec![]),
                    },
                    height: 1,
                    coinbase: false,
                },
            );
            let _ = utxos.have(&op);
        },
        100_000,
    );
}

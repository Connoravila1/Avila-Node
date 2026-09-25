//! Generates a regtest chain into a datadir — coinbase-only blocks,
//! ground to the trivial regtest target. Used to stage datadirs for
//! live two-node tests (e.g. the utxproof bridge pair).
//!
//! Usage: `regtest_mine <datadir> <blocks>`

// Scratch tooling — panics on operator error are the right behavior.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use avila_consensus::arith::CompactTarget;
use avila_consensus::block::Block;
use avila_consensus::chainstate::Chainstate;
use avila_consensus::check::SEQUENCE_FINAL;
use avila_consensus::connect;
use avila_consensus::hash::BlockHash;
use avila_consensus::header::BlockHeader;
use avila_consensus::params::{Network, Params};
use avila_consensus::pow;
use avila_consensus::script;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

const REGTEST_BITS: u32 = 0x207f_ffff;

fn coinbase_tx(height: u32, subsidy: i64) -> Transaction {
    let mut script_sig = script::push_int(i64::from(height));
    script_sig.push(script::OP_1);
    Transaction {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::NULL,
            script_sig: Script::new(script_sig),
            sequence: SEQUENCE_FINAL,
            witness: Witness::default(),
        }],
        outputs: vec![TxOut {
            value: subsidy,
            script_pubkey: Script::new(vec![script::OP_1]),
        }],
        lock_time: 0,
    }
}

fn block_on(parent: &BlockHeader, txs: Vec<Transaction>, params: &Params) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: 4,
            prev_block_hash: parent.hash(),
            merkle_root: parent.merkle_root,
            time: parent.time + 1,
            bits: CompactTarget(REGTEST_BITS),
            nonce: 0,
        },
        transactions: txs,
    };
    let (root, _) = block.merkle_root();
    block.header.merkle_root = root;
    while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
        block.header.nonce += 1;
    }
    block
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = std::path::PathBuf::from(args.next().expect("datadir"));
    let n: u32 = args.next().expect("blocks").parse().unwrap();
    let params = Network::Regtest.params();
    let now = 1_800_000_000u32;
    let mut cs =
        Chainstate::with_store_coinsdb(&dir, &params, now, 16 * 1024 * 1024).expect("open datadir");
    let mut tip: BlockHash = *cs.chain().last().expect("genesis");
    // Track the h1 coinbase's outpoint so a later block can spend it —
    // exercises non-empty utreexo spend proofs on the wire.
    let mut h1_coinbase: Option<(OutPoint, i64)> = None;
    for _ in 0..n {
        let height = cs.chain().len() as u32;
        let subsidy = connect::block_subsidy(height, &params);
        let coinbase = coinbase_tx(height, subsidy);
        let mut txs = vec![coinbase];
        if height == 1 {
            h1_coinbase = Some((
                OutPoint {
                    txid: txs[0].txid(),
                    vout: 0,
                },
                subsidy,
            ));
        }
        if height == 120
            && let Some((prev, value)) = h1_coinbase
        {
            // h1's coinbase matured at h101 — spend it to a fresh OP_1.
            txs.push(Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: prev,
                    script_sig: Script::new(vec![]),
                    sequence: SEQUENCE_FINAL,
                    witness: Witness::default(),
                }],
                outputs: vec![TxOut {
                    value,
                    script_pubkey: Script::new(vec![script::OP_1]),
                }],
                lock_time: 0,
            });
        }
        let block = block_on(&cs.tree().get(&tip).expect("header").header, txs, &params);
        tip = block.block_hash();
        cs.accept_block(&block, now).expect("accept");
        if height.is_multiple_of(100) {
            eprintln!("mined h{height}");
        }
    }
    cs.flush().expect("flush");
    eprintln!("done: {} blocks, tip {tip}", n);
}

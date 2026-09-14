//! Regtest chain builders shared by the p2p test modules — real
//! PoW-valid blocks on the regtest genesis, same construction the
//! consensus tests use.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]
use avila_consensus::arith::CompactTarget;
use avila_consensus::block::Block;
use avila_consensus::chainstate::Chainstate;
use avila_consensus::header::BlockHeader;
use avila_consensus::params::{Network, Params};
use avila_consensus::pow;
use avila_consensus::script;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

const REGTEST_BITS: u32 = 0x207f_ffff;
const SEQUENCE_FINAL: u32 = 0xffff_ffff;

pub fn coinbase_tx(height: u32) -> Transaction {
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
            value: 5_000_000_000,
            script_pubkey: Script::new(vec![script::OP_1]),
        }],
        lock_time: 0,
    }
}

pub fn block_on(prev: &BlockHeader, height: u32, params: &Params) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: 4,
            prev_block_hash: prev.hash(),
            merkle_root: prev.merkle_root,
            time: prev.time + 1,
            bits: CompactTarget(REGTEST_BITS),
            nonce: 0,
        },
        transactions: vec![coinbase_tx(height)],
    };
    let (root, _) = block.merkle_root();
    block.header.merkle_root = root;
    while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
        block.header.nonce += 1;
    }
    block
}

pub fn regtest() -> Chainstate {
    Chainstate::new(&Network::Regtest.params())
}

/// A chain of `n` blocks on `cs`'s genesis (not yet submitted).
pub fn chain_blocks(cs: &Chainstate, n: u32) -> Vec<Block> {
    let params = *cs.tree().params();
    let mut out = Vec::new();
    let mut prev = params.genesis_header;
    for h in 1..=n {
        let block = block_on(&prev, h, &params);
        prev = block.header;
        out.push(block);
    }
    out
}

/// A branch of `n` blocks extending `prev` — a competing fork when `prev`
/// is behind the tip. `first_height` is the branch's first block height.
pub fn fork_blocks(cs: &Chainstate, prev: &BlockHeader, first_height: u32, n: u32) -> Vec<Block> {
    let params = *cs.tree().params();
    let mut out = Vec::new();
    let mut p = *prev;
    for i in 0..n {
        let block = block_on(&p, first_height + i, &params);
        p = block.header;
        out.push(block);
    }
    out
}

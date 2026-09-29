#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration-level A/B for the advice stack — through `connect_block`
//! itself (not the corpus harness). Builds a regtest chain of
//! P2PKH-spending blocks with real secp256k1 signatures, then measures:
//!
//!   ordinary : connect with neither advice nor capture
//!   produce  : connect with `advice_collect` (real verify + capture)
//!   consume  : connect a fresh chain consuming the produced sidecar
//!
//! Synthetic keys, real signatures, real script engine — the honest
//! measure of whether the batch survives the connect plumbing (pool,
//! deferred eval, sink resolution) that `advice_ab` bypasses.
//!
//! Usage: `advice_connect_bench [--blocks N] [--spends K]`

use std::collections::HashMap;
use std::time::Instant;

use avila_consensus::block::Block;
use avila_consensus::connect::{
    ConnectContext, ConnectError, ScriptPool, UtxoSet, block_subsidy, connect_block_full,
};
use avila_consensus::hash::{BlockHash, Txid};
use avila_consensus::header::BlockHeader;
use avila_consensus::chain::HeaderTree;
use avila_consensus::params::{Network, Params};
use avila_consensus::script;
use avila_consensus::sigchecker::signature_hash;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

const SEQ: u32 = 0xffff_ffff;
const SUBSIDY: i64 = 50 * 100_000_000;
const MATURITY: u32 = 100;

fn p2pkh(pk33: &[u8; 33]) -> Vec<u8> {
    let pkh = avila_consensus::hash::hash160(pk33);
    let mut v = vec![script::OP_DUP, script::OP_HASH160];
    v.extend_from_slice(&script::push_slice(&pkh));
    v.push(script::OP_EQUALVERIFY);
    v.push(script::OP_CHECKSIG);
    v
}

fn txin(prev: OutPoint, ss: Vec<u8>) -> TxIn {
    TxIn {
        previous_output: prev,
        script_sig: Script::new(ss),
        sequence: SEQ,
        witness: Witness::default(),
    }
}

fn txout(v: i64, spk: Vec<u8>) -> TxOut {
    TxOut {
        value: v,
        script_pubkey: Script::new(spk),
    }
}

fn coinbase(h: u32, spk: Vec<u8>) -> Transaction {
    coinbase_value(h, SUBSIDY, spk)
}

fn coinbase_value(h: u32, value: i64, spk: Vec<u8>) -> Transaction {
    let mut ss = script::push_int(i64::from(h));
    ss.push(script::OP_1);
    Transaction {
        version: 1,
        inputs: vec![txin(OutPoint::NULL, ss)],
        outputs: vec![txout(value, spk)],
        lock_time: 0,
    }
}

/// Sign `tx`'s input `i` spending a P2PKH coin — same byte path the
/// interpreter verifies.
fn sign_input(tx: &mut Transaction, i: usize, spk: &[u8], sk: &secp256k1::SecretKey) {
    let z = signature_hash(
        &Script::new(spk.to_vec()),
        tx,
        i,
        1,
        0,
        avila_consensus::interpreter::SigVersion::Base,
        None,
    );
    let msg = secp256k1::Message::from_digest_slice(&z).unwrap();
    let secp = secp256k1::Secp256k1::new();
    let mut der = secp.sign_ecdsa(&msg, sk).serialize_der().to_vec();
    der.push(1);
    let mut ss = script::push_slice(&der);
    ss.extend_from_slice(&script::push_slice(&sk.public_key(&secp).serialize()));
    tx.inputs[i].script_sig = Script::new(ss);
}

fn block_on(parent: &BlockHeader, txs: Vec<Transaction>, params: &Params) -> Block {
    let mut b = Block {
        header: BlockHeader {
            version: 4,
            prev_block_hash: parent.hash(),
            merkle_root: parent.merkle_root,
            time: parent.time + 1,
            bits: parent.bits,
            nonce: 0,
        },
        transactions: txs,
    };
    let (root, _) = b.merkle_root();
    b.header.merkle_root = root;
    while avila_consensus::pow::check_proof_of_work(&b.block_hash(), b.header.bits, params).is_err()
    {
        b.header.nonce += 1;
    }
    b
}

struct Harness {
    params: Params,
    tree: HeaderTree,
    utxo: UtxoSet,
    tip: BlockHash,
    tip_header: BlockHeader,
    pool: std::sync::Arc<ScriptPool>,
}

impl Harness {
    fn new() -> Self {
        let params = Network::Regtest.params();
        Self {
            tree: HeaderTree::new(params),
            utxo: UtxoSet::new(),
            params,
            tip: params.genesis_header.hash(),
            tip_header: params.genesis_header,
            pool: ScriptPool::new(4),
        }
    }

    /// Connect through the real pipeline; `advice`/`collect` mirror the
    /// two `ConnectContext` fields the node sets from `advice_dir`.
    /// Mirrors the node's pending queue: script checks stay outstanding
    /// until [`Self::drain`] — that's the overlap the barrier needs.
    fn submit(
        &mut self,
        block: &Block,
        advice: Option<&HashMap<Txid, Vec<u8>>>,
        collect: bool,
    ) -> Result<(BlockHash, Option<std::sync::Arc<avila_consensus::connect::BlockCheck>>), ConnectError>
    {
        self.tree
            .insert(&block.header, u32::MAX / 2)
            .map_err(|_| ConnectError::Internal("header insert"))?;
        let collect_map: std::sync::Arc<
            std::sync::Mutex<HashMap<Txid, Vec<u8>>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));
        let ctx = ConnectContext {
            params: &self.params,
            tree: &self.tree,
            block_hash: block.block_hash(),
            script_checks: true,
            script_pool: Some(&self.pool),
            advice,
            advice_collect: collect.then(|| &collect_map),
        };
        let (_undo, check, _r) = connect_block_full(block, &mut self.utxo, &ctx)?;
        self.tip = block.block_hash();
        self.tip_header = block.header;
        Ok((block.block_hash(), check))
    }
}

/// Wait on every outstanding check (the pending-scripts drain).
fn drain(
    pending: Vec<(BlockHash, Option<std::sync::Arc<avila_consensus::connect::BlockCheck>>)>,
) -> HashMap<BlockHash, HashMap<Txid, Vec<u8>>> {
    let mut out = HashMap::new();
    for (hash, check) in pending {
        if let Some(check) = check {
            check.wait().unwrap();
            let map = check.take_advice_map();
            if !map.is_empty() {
                out.insert(hash, map);
            }
        }
    }
    out
}

/// One spendable coin: `(mature_at_height, outpoint, value)`.
type Coin_ = (u32, OutPoint, i64);

/// Build the full block plan once: MATURITY growth coinbases, then
/// `n_spend` blocks each draining up to `max_spends` mature coins and
/// fanning each into 4 fresh P2PKH outputs (no maturity — non-coinbase).
/// Returns the blocks and the total signature count.
fn plan(params: &Params, spk: &[u8], sk: &secp256k1::SecretKey, n_spend: u32, max_spends: usize)
    -> (Vec<Block>, u64)
{
    let mut blocks = Vec::new();
    let mut tip = params.genesis_header;
    // A spendable coin needs no UTXO here — planning only needs txids.
    let mut pool: Vec<Coin_> = Vec::new();
    for h in 1..=MATURITY {
        let cb = coinbase(h, spk.to_vec());
        let op = OutPoint {
            txid: cb.txid(),
            vout: 0,
        };
        let b = block_on(&tip, vec![cb], params);
        tip = b.header;
        pool.push((h + MATURITY, op, SUBSIDY));
        blocks.push(b);
    }
    let mut sigs = 0u64;
    for s in 0..n_spend {
        let height = MATURITY + 1 + s;
        // Count mature coins first so the coinbase claims the fee total.
        let mature_n = pool
            .iter()
            .filter(|c| c.0 <= height)
            .count()
            .min(max_spends);
        let mut txs = vec![coinbase_value(
            height,
            block_subsidy(height, params) + 1000 * mature_n as i64,
            vec![script::OP_1],
        )];
        let mut drained = 0usize;
        let mut keep = Vec::new();
        for c in pool.drain(..) {
            if drained < max_spends && c.0 <= height {
                drained += 1;
                let (op, val) = (c.1, c.2);
                let mut tx = Transaction {
                    version: 1,
                    inputs: vec![txin(op, Vec::new())],
                    outputs: (0..4)
                        .map(|_| txout((val - 1000) / 4, spk.to_vec()))
                        .collect(),
                    lock_time: 0,
                };
                sign_input(&mut tx, 0, spk, sk);
                let id = tx.txid();
                let child = (val - 1000) / 4;
                for v in 0..4u32 {
                    if child > 10_000 {
                        keep.push((0, OutPoint { txid: id, vout: v }, child));
                    }
                }
                sigs += 1;
                txs.push(tx);
            } else {
                keep.push(c);
            }
        }
        pool = keep;
        let b = block_on(&tip, txs, params);
        tip = b.header;
        blocks.push(b);
    }
    (blocks, sigs)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opt = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let n_spend: u32 = opt("--blocks").map_or(24, |s| s.parse().unwrap());
    let max_spends: usize = opt("--spends").map_or(64, |s| s.parse().unwrap());

    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[0x42; 32]).unwrap();
    let pk33 = sk.public_key(&secp).serialize();
    let spk = p2pkh(&pk33);
    let params = Network::Regtest.params();

    let (blocks, sigs) = plan(&params, &spk, &sk, n_spend, max_spends);
    eprintln!("plan: {} blocks (incl. scaffold), {sigs} signed spends", blocks.len());

    let mut advice_store: HashMap<BlockHash, HashMap<Txid, Vec<u8>>> = HashMap::new();
    let mut results = HashMap::new();

    for mode in ["ordinary", "produce", "consume"] {
        let mut h = Harness::new();
        // A syncing node's verified cache starts empty — emulate that:
        // without the clear, later phases would silently skip every
        // check the earlier phase already proved.
        avila_consensus::sigchecker::clear_verified_scripts();
        let t0 = Instant::now();
        let mut pending = Vec::new();
        for b in &blocks {
            match mode {
                "produce" => {
                    pending.push(h.submit(b, None, true).unwrap());
                }
                "consume" => {
                    let map = advice_store.get(&b.block_hash());
                    pending.push(h.submit(b, map, false).unwrap());
                }
                _ => {
                    pending.push(h.submit(b, None, false).unwrap());
                }
            }
        }
        for (hash, map) in drain(pending) {
            advice_store.insert(hash, map);
        }
        let el = t0.elapsed().as_secs_f64();
        results.insert(mode, el);
        eprintln!("{mode}: {el:.3}s");
    }

    let (ord, pro, con) = (results["ordinary"], results["produce"], results["consume"]);
    println!(
        "{{\"type\":\"result\",\"blocks\":{},\"sigs\":{sigs},\"ordinary_s\":{ord:.3},\"produce_s\":{pro:.3},\"consume_s\":{con:.3},\"consume_speedup\":{:.3},\"produce_overhead\":{:.3}}}",
        blocks.len(),
        ord / con,
        pro / ord,
    );
}

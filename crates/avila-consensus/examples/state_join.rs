// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::type_complexity)]

//! Gate 3 (repaired) — exact-state equivalence between a batch
//! occurrence-record engine and the real incremental connect path.
//!
//! Two state implementations apply the same contiguous selected chain
//! from a declared starting state. Comparison oracle:
//!   1. per-block-boundary canonical digests must match at every height,
//!      and a rejected block must leave the prior state unchanged;
//!   2. each scenario has a DECLARED expected outcome (accept-all, or
//!      reject at a stated height) — agreement alone is not accepted;
//!   3. tip heights AND tip hashes must match each other, the declared
//!      expectation, and the selected chain.
//!
//! Canonical record: txid(32B)‖vout(u32le)‖value(i64le)‖scriptlen(u32le)
//! ‖script‖height(u32le)‖coinbase(u8), sorted by (txid, vout).
//! Database internals are never compared. Exports are preserved per
//! scenario under `experiments/results/gate3/` (set GATE3_OUT).
//!
//! The batch engine is occurrence-aware: every creation carries
//! (height, txidx, vout) and every spend (height, txidx, inidx);
//! resolution is an ordered merge over those records — a spend at
//! position p sees only creations with position < p plus the starting
//! set, minus earlier spends (multiplicity). Lock/sequence/finality and
//! the context-free/contextual rule layer reuse the shared helpers any
//! implementation of these rules must provide; availability,
//! multiplicity, ordering, maturity, conservation, subsidy bound, and
//! duplicate-creation are implemented independently here.
//!
//! The `bip30_*` fixtures run under a SYNTHETIC params value
//! (`bip34_height = u32::MAX` on the regtest network shape) — BIP34
//! activation makes duplicate coinbase txids unreachable-by-construction,
//! so an inactive-BIP34 fixture is the only way to exercise the
//! duplicate-creation predicate at all. It is labeled synthetic and is
//! not a statement about production parameterization.

use avila_consensus::block::Block;
use avila_consensus::chain::HeaderTree;
use avila_consensus::check::{
    BlockContext, MAX_MONEY, check_block, contextual_check_block, is_final_tx,
};
use avila_consensus::connect::{
    COINBASE_MATURITY, Coin, ConnectContext, UtxoSet, bip68_locks_satisfied, block_subsidy,
    connect_block,
};
use avila_consensus::hash::BlockHash;
use avila_consensus::header::BlockHeader;
use avila_consensus::params::{Network, Params};
use avila_consensus::pow;
use avila_consensus::script;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Write as _;

const SEQUENCE_FINAL: u32 = 0xffff_ffff;
const SUBSIDY: i64 = 50 * 100_000_000;
const ANYONE: &[u8] = &[script::OP_1];
const OP_RETURN: &[u8] = &[0x6a];
const BIP68_TYPE_TIME: u32 = 1 << 22;

fn txin(prev: OutPoint, script_sig: Vec<u8>, sequence: u32) -> TxIn {
    TxIn {
        previous_output: prev,
        script_sig: Script::new(script_sig),
        sequence,
        witness: Witness::default(),
    }
}

fn txout(value: i64, script_pubkey: Vec<u8>) -> TxOut {
    TxOut {
        value,
        script_pubkey: Script::new(script_pubkey),
    }
}

fn coinbase_tx(height: u32, value: i64) -> Transaction {
    let mut script_sig = script::push_int(i64::from(height));
    script_sig.push(script::OP_1);
    Transaction {
        version: 1,
        inputs: vec![txin(OutPoint::NULL, script_sig, SEQUENCE_FINAL)],
        outputs: vec![txout(value, ANYONE.to_vec())],
        lock_time: 0,
    }
}

/// Coinbase with a fixed script (no height push) — only valid where
/// BIP34 is inactive; used by the synthetic BIP30 fixture.
fn coinbase_flat(value: i64) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![txin(
            OutPoint::NULL,
            // [OP_16, OP_16]: 2-byte minimum, and unreachable by any
            // height-pushing coinbase (`[push(N), OP_1]`) — the fixture
            // must collide only with ITSELF across the two blocks.
            vec![script::OP_16, script::OP_16],
            SEQUENCE_FINAL,
        )],
        outputs: vec![txout(value, ANYONE.to_vec())],
        lock_time: 0,
    }
}

fn spend_tx(prev: OutPoint, value: i64, script_pubkey: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![txin(prev, ANYONE.to_vec(), SEQUENCE_FINAL)],
        outputs: vec![txout(value, script_pubkey)],
        lock_time: 0,
    }
}

fn block_on(parent: &BlockHeader, txs: Vec<Transaction>, params: &Params) -> Block {
    block_on_step(parent, txs, params, 1)
}

fn block_on_step(
    parent: &BlockHeader,
    txs: Vec<Transaction>,
    params: &Params,
    time_step: u32,
) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: 4,
            prev_block_hash: parent.hash(),
            merkle_root: parent.merkle_root,
            time: parent.time.wrapping_add(time_step),
            bits: parent.bits,
            nonce: 0,
        },
        transactions: txs,
    };
    let (root, _) = block.merkle_root();
    block.header.merkle_root = root;
    while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
    block
}

// ---------------------------------------------------------------------------
// Canonical export — sorted complete-coin records, byte-exact
// ---------------------------------------------------------------------------

fn canonical_bytes(map: &[(OutPoint, Coin)]) -> Vec<u8> {
    let mut recs: Vec<(&OutPoint, &Coin)> = map.iter().map(|(o, c)| (o, c)).collect();
    recs.sort_by_key(|a| (a.0.txid, a.0.vout));
    let mut out = Vec::new();
    for (op, c) in recs {
        out.extend_from_slice(op.txid.as_bytes());
        out.extend_from_slice(&op.vout.to_le_bytes());
        out.extend_from_slice(&c.out.value.to_le_bytes());
        let spk = c.out.script_pubkey.as_bytes();
        out.extend_from_slice(&(spk.len() as u32).to_le_bytes());
        out.extend_from_slice(spk);
        out.extend_from_slice(&c.height.to_le_bytes());
        out.push(u8::from(c.coinbase));
    }
    out
}

fn canonical_decode(bytes: &[u8]) -> Vec<(OutPoint, Coin)> {
    let mut out = Vec::new();
    let mut o = 0usize;
    while o < bytes.len() {
        let txid = avila_consensus::hash::Txid::from_bytes(bytes[o..o + 32].try_into().unwrap());
        o += 32;
        let vout = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        o += 4;
        let value = i64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
        o += 8;
        let sl = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()) as usize;
        o += 4;
        let spk = bytes[o..o + sl].to_vec();
        o += sl;
        let height = u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        o += 4;
        let coinbase = bytes[o] != 0;
        o += 1;
        out.push((
            OutPoint { txid, vout },
            Coin {
                out: TxOut {
                    value,
                    script_pubkey: Script::new(spk),
                },
                height,
                coinbase,
            },
        ));
    }
    out
}

fn digest_hex(bytes: &[u8]) -> String {
    let d = avila_consensus::hash::sha256(bytes);
    d.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn hexid(h: &BlockHash) -> String {
    h.as_bytes().iter().rev().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Minimal JSON string escaping — the harness emits diagnostics by hand.
fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn opt_json(o: Option<String>) -> String {
    o.map(|s| jstr(&s)).unwrap_or_else(|| "null".into())
}

fn money_range(v: i64) -> bool {
    (0..=MAX_MONEY).contains(&v)
}

// ---------------------------------------------------------------------------
// Incremental baseline — the real pipeline:
// header insert → check_block → contextual_check_block → connect_block
// ---------------------------------------------------------------------------

struct EngineResult {
    tip_height: u32,
    tip_hash: BlockHash,
    rejected: Option<(u32, String)>,
    /// canonical digest after EVERY attempted block boundary (position
    /// i corresponds to blocks[i]; on rejection the digest repeats the
    /// pre-block state — rejection must not corrupt state).
    boundary_digests: Vec<String>,
    canonical: Vec<u8>,
    elapsed: std::time::Duration,
}

fn run_incremental(
    params: &Params,
    blocks: &[Block],
    start: Option<Vec<(OutPoint, Coin)>>,
    pre_tree: Option<HeaderTree>,
    start_height: u32,
) -> EngineResult {
    let mut tree = pre_tree.unwrap_or_else(|| HeaderTree::new(*params));
    let t0 = std::time::Instant::now();
    let mut utxo = UtxoSet::new();
    utxo.set_budget(usize::MAX); // never flush mid-window
    if let Some(coins) = start {
        for (op, c) in coins {
            utxo.insert_synthetic(op, c);
        }
    }
    let mut tip_h = start_height;
    let mut tip_hh = tree.tip_hash();
    let mut rejected = None;
    let mut boundary_digests = Vec::new();
    for b in blocks {
        let hh = b.block_hash();
        // header insert is checked; missing linkage or an unexpected
        // height is a hard harness error, not a silent default.
        let h = match tree.insert(&b.header, u32::MAX / 2) {
            Ok(_) => match tree.get(&hh).map(|n| n.height) {
                Some(h) => h,
                None => {
                    rejected = Some((tip_h + 1, "header unindexed after insert".into()));
                    break;
                }
            },
            Err(e) => {
                rejected = Some((tip_h + 1, format!("header insert: {e}")));
                break;
            }
        };
        if h != tip_h + 1 {
            rejected = Some((tip_h + 1, format!("non-contiguous height {h}")));
            break;
        }
        let ctx = ConnectContext {
            params,
            tree: &tree,
            block_hash: hh,
            script_checks: true,
            script_pool: None,
            advice: None,
            advice_collect: None,
        };
        if let Err(e) = check_block(b, params) {
            rejected = Some((h, format!("check_block: {e}")));
        } else {
            let bctx = BlockContext {
                params,
                height: h,
                parent_median_time_past: Some(
                    tree.median_time_past(&b.header.prev_block_hash)
                        .expect("parent MTP must exist for inserted parent"),
                ),
            };
            if let Err(e) = contextual_check_block(b, &bctx) {
                rejected = Some((h, format!("contextual: {e}")));
            } else if let Err(e) = connect_block(b, &mut utxo, &ctx) {
                rejected = Some((h, format!("{e}")));
            }
        }
        // record the post-attempt state digest: rejection must leave the
        // prior state byte-identical.
        boundary_digests.push(digest_hex(&canonical_bytes(&utxo.iter())));
        if rejected.is_some() {
            break;
        }
        tip_h = h;
        tip_hh = hh;
    }
    EngineResult {
        tip_height: tip_h,
        tip_hash: tip_hh,
        rejected,
        boundary_digests,
        canonical: canonical_bytes(&utxo.iter()),
        elapsed: t0.elapsed(),
    }
}

// ---------------------------------------------------------------------------
// Occurrence-record batch engine.
//
// Records:
//   Creation { pos=(height,txidx,vout), op, coin }
//   Spend    { pos=(height,txidx,inidx), op }
// Resolution is an ordered merge: a spend at position p resolves a coin
// from the starting set or a creation with pos < p, not previously
// consumed (multiplicity: each outpoint consumed at most once).
// Application is a block-boundary delta: created_minus_spent inserts,
// spends remove.
// ---------------------------------------------------------------------------

#[path = "shared/join_engine.rs"]
mod join_engine;
use join_engine::{Creation, JoinRes, Occ, Spend, join_window};

fn run_occurrence(
    params: &Params,
    blocks: &[Block],
    start: Option<Vec<(OutPoint, Coin)>>,
    mut tree: HeaderTree,
    start_height: u32,
) -> EngineResult {
    let t0 = std::time::Instant::now();
    let mut live: HashMap<OutPoint, Coin> = start.unwrap_or_default().into_iter().collect();
    let mut tip_h = start_height;
    let mut tip_hh = tree.tip_hash();
    let mut rejected = None;
    let mut boundary_digests = Vec::new();

    for (bi, b) in blocks.iter().enumerate() {
        let height = start_height + bi as u32 + 1;
        // Grow + check header context; linkage errors are hard failures.
        let hh = b.block_hash();
        match tree.insert(&b.header, u32::MAX / 2) {
            Ok(_) => {
                let got = tree.get(&hh).map(|n| n.height);
                if got != Some(height) {
                    rejected = Some((height, format!("header linkage: got {got:?}")));
                    break;
                }
            }
            Err(e) => {
                rejected = Some((height, format!("header insert: {e}")));
                break;
            }
        }
        let parent_hash = b.header.prev_block_hash;
        let Some(mtp) = tree.median_time_past(&parent_hash) else {
            rejected = Some((height, "missing parent MTP context".into()));
            break;
        };
        // Shared rule layer (context-free + contextual).
        if let Err(e) = check_block(b, params) {
            rejected = Some((height, format!("check_block: {e}")));
        } else if let Err(e) = contextual_check_block(
            b,
            &BlockContext {
                params,
                height,
                parent_median_time_past: Some(mtp),
            },
        ) {
            rejected = Some((height, format!("contextual: {e}")));
        }

        // ---- occurrence records for this block ----------------------
        let mut creations: Vec<Creation> = Vec::new();
        let mut spends: Vec<Spend> = Vec::new();
        if rejected.is_none() {
            for (j, t) in b.transactions.iter().enumerate() {
                let txid = t.txid();
                for (i, inp) in t.inputs.iter().enumerate() {
                    if !inp.previous_output.is_null() {
                        spends.push(Spend {
                            pos: Occ {
                                h: height,
                                tx: j as u32,
                                idx: i as u32,
                            },
                            op: inp.previous_output,
                        });
                    }
                }
                let cb = j == 0;
                for (n, o) in t.outputs.iter().enumerate() {
                    if o.script_pubkey.is_unspendable() {
                        continue; // provably unspendable never enters the set
                    }
                    creations.push(Creation {
                        pos: Occ {
                            h: height,
                            tx: j as u32,
                            idx: n as u32,
                        },
                        op: OutPoint {
                            txid,
                            vout: n as u32,
                        },
                        coin: Coin {
                            out: o.clone(),
                            height,
                            coinbase: cb,
                        },
                    });
                }
            }
            // ---- multiplicity predicate over the spend records ------
            let mut seen: HashSet<OutPoint> = HashSet::new();
            for s in &spends {
                if !seen.insert(s.op) {
                    rejected = Some((height, format!("double spend pos {:?}", s.pos)));
                    break;
                }
            }
        }
        // ---- per-tx evaluation in occurrence order ------------------
        let mut fees: i64 = 0;
        let mut consumed: HashSet<OutPoint> = HashSet::new();
        if rejected.is_none() {
            // in-block availability: creations sorted by position
            let mut created_sorted: Vec<&Creation> = creations.iter().collect();
            created_sorted.sort_by_key(|a| a.pos);
            for (j, t) in b.transactions.iter().enumerate() {
                // duplicate-creation (BIP30) applies to EVERY tx's
                // outputs, including the coinbase — a recreated txid
                // whose outputs are unspent must be rejected. The
                // coinbase's inputs are null prevouts so its only
                // records are creations.
                let dt = t.txid();
                for (n, _o) in t.outputs.iter().enumerate() {
                    let op = OutPoint {
                        txid: dt,
                        vout: n as u32,
                    };
                    if live.contains_key(&op)
                        || creations.iter().any(|c| c.op == op && c.pos.tx < j as u32)
                    {
                        rejected = Some((height, format!("BIP30 duplicate creation tx{j} out{n}")));
                        break;
                    }
                }
                if rejected.is_some() {
                    break;
                }
                if j == 0 {
                    continue; // coinbase bound checked after fees
                }
                let mut vin: i64 = 0;
                let mut spent_coins: Vec<Coin> = Vec::new();
                for (i, inp) in t.inputs.iter().enumerate() {
                    let op = &inp.previous_output;
                    if consumed.contains(op) {
                        rejected = Some((height, format!("double spend tx{j} in{i}")));
                        break;
                    }
                    // resolution join: live set or an earlier creation
                    let coin = live.get(op).cloned().or_else(|| {
                        created_sorted
                            .iter()
                            .find(|c| c.op == *op && c.pos.tx < j as u32)
                            .map(|c| c.coin.clone())
                    });
                    let Some(coin) = coin else {
                        rejected = Some((height, format!("missing/unavailable input tx{j} in{i}")));
                        break;
                    };
                    consumed.insert(*op);
                    if coin.coinbase && height.saturating_sub(coin.height) < COINBASE_MATURITY {
                        rejected = Some((
                            height,
                            format!(
                                "immature coinbase tx{j} depth {}",
                                height.saturating_sub(coin.height)
                            ),
                        ));
                        break;
                    }
                    if !money_range(coin.out.value) {
                        rejected = Some((height, "input value out of range".into()));
                        break;
                    }
                    vin = match vin.checked_add(coin.out.value) {
                        Some(v) if money_range(v) => v,
                        _ => {
                            rejected = Some((height, "input total out of range".into()));
                            break;
                        }
                    };
                    spent_coins.push(coin);
                }
                if rejected.is_some() {
                    break;
                }
                let vout = match t
                    .outputs
                    .iter()
                    .try_fold(0i64, |a, o| a.checked_add(o.value))
                {
                    Some(v) => v,
                    None => {
                        rejected = Some((height, "output total overflow".into()));
                        break;
                    }
                };
                if vout > vin {
                    rejected = Some((height, format!("outputs exceed inputs tx{j}")));
                    break;
                }
                let fee = vin - vout;
                if !money_range(fee) {
                    rejected = Some((height, "fee out of range".into()));
                    break;
                }
                fees = match fees.checked_add(fee) {
                    Some(f) => f,
                    None => {
                        rejected = Some((height, "fee overflow".into()));
                        break;
                    }
                };
                if !is_final_tx(t, height, mtp) {
                    rejected = Some((height, format!("non-final tx{j}")));
                    break;
                }
                if height >= params.csv_height
                    && !bip68_locks_satisfied(t, &spent_coins, height, mtp, &tree, &parent_hash)
                {
                    rejected = Some((height, format!("BIP68 lock tx{j}")));
                    break;
                }
                if rejected.is_some() {
                    break;
                }
            }
        }
        // ---- coinbase bound after fee aggregation --------------------
        if rejected.is_none() {
            let cb_sum: i64 = b.transactions[0].outputs.iter().map(|o| o.value).sum();
            let bound = block_subsidy(height, params).saturating_add(fees);
            if cb_sum > bound {
                rejected = Some((height, format!("coinbase overpays {cb_sum}>{bound}")));
            }
        }
        // ---- commit or roll back -------------------------------------
        if rejected.is_none() {
            for s in &spends {
                live.remove(&s.op);
            }
            for c in creations {
                // anti-join: created ∧ not spent this block
                if !consumed.contains(&c.op) {
                    live.insert(c.op, c.coin);
                }
            }
            tip_h = height;
            tip_hh = hh;
        }
        let v: Vec<(OutPoint, Coin)> = live.iter().map(|(o, c)| (*o, c.clone())).collect();
        boundary_digests.push(digest_hex(&canonical_bytes(&v)));
        if rejected.is_some() {
            break;
        }
    }
    let v: Vec<(OutPoint, Coin)> = live.into_iter().collect();
    EngineResult {
        tip_height: tip_h,
        tip_hash: tip_hh,
        rejected,
        boundary_digests,
        canonical: canonical_bytes(&v),
        elapsed: t0.elapsed(),
    }
}

// ---------------------------------------------------------------------------
// Corpus-wide join engine — the architecture under test.
//
// Semantics are expressed as a WINDOW-WIDE join over occurrence records,
// not as a per-block cursor. The whole window is emitted into two ledgers
// first; resolution is a partitioned sort/merge keyed by outpoint; only
// then are predicates evaluated and the survivor set materialized.
// Per-block commit boundaries exist because block-boundary validity is a
// consensus requirement, not an implementation choice.
//
//   CREATED  = {(pos=(h,txidx,vout), op, coin)}        — all window outputs
//   SPENT    = {(pos=(h,txidx,inidx), op)}             — all window spends
//   for each outpoint group (partition → sort by pos → merge):
//     alive walks start-state ∪ creations ∖ spends in pos order
//     creation while alive          → BIP30 violation @ its pos
//     spend while !alive            → missing/unavailable  @ its pos
//     second spend in same group    → multiplicity violation @ its pos
//     otherwise spend resolves      → (coin, src_pos)
//   tx predicates (conservation, maturity, locks, finality, cb bound)
//   evaluate per tx in block order over the resolved coins.
//   Survivors = (start ∪ CREATED) ∖ SPENT over positions < boundary.
// ---------------------------------------------------------------------------

fn run_join(
    params: &Params,
    blocks: &[Block],
    start: Option<Vec<(OutPoint, Coin)>>,
    mut tree: HeaderTree,
    start_height: u32,
) -> EngineResult {
    let t0 = std::time::Instant::now();
    let mut live: HashMap<OutPoint, Coin> = start.unwrap_or_default().into_iter().collect();
    let mut tip_h = start_height;
    let mut tip_hh = tree.tip_hash();
    let mut rejected = None;
    let mut boundary_digests = Vec::new();

    // ---- Pass A: emit the whole window's occurrence ledgers ----------
    let mut created: Vec<Creation> = Vec::new();
    let mut spends: Vec<Spend> = Vec::new();
    // block-meta list: (height, block) for the evaluation pass
    for (bi, b) in blocks.iter().enumerate() {
        let height = start_height + bi as u32 + 1;
        for (j, t) in b.transactions.iter().enumerate() {
            let txid = t.txid();
            for (i, inp) in t.inputs.iter().enumerate() {
                if !inp.previous_output.is_null() {
                    spends.push(Spend {
                        pos: Occ {
                            h: height,
                            tx: j as u32,
                            idx: i as u32,
                        },
                        op: inp.previous_output,
                    });
                }
            }
            for (n, o) in t.outputs.iter().enumerate() {
                if o.script_pubkey.is_unspendable() {
                    continue;
                }
                created.push(Creation {
                    pos: Occ {
                        h: height,
                        tx: j as u32,
                        idx: n as u32,
                    },
                    op: OutPoint {
                        txid,
                        vout: n as u32,
                    },
                    coin: Coin {
                        out: o.clone(),
                        height,
                        coinbase: j == 0,
                    },
                });
            }
        }
    }

    // ---- Pass B: the SHARED corpus-wide join --------------------------
    // Identical code to the real-data `window_join` driver's resolution:
    // partition by outpoint → order events by occurrence pos → walk
    // alive = (boundary ∪ created) ∖ spent. The starting state seeds the
    // boundary once per outpoint; a second spend of the same boundary
    // coin is a DupSpend, never a second resolution.
    let boundary: HashMap<OutPoint, Coin> = live.clone();
    let report = join_window(
        &created,
        &spends,
        &boundary,
        &std::collections::HashSet::new(),
    );
    let resolved = report.resolved;
    let join_violations: std::collections::BTreeMap<Occ, String> = report
        .violations
        .iter()
        .map(|(p, v)| (*p, format!("BIP30 duplicate creation ({v:?}) @ {p:?}")))
        .collect();

    // ---- Pass C: per-block predicate evaluation ----------------------
    for (bi, b) in blocks.iter().enumerate() {
        let height = start_height + bi as u32 + 1;
        // grow + check header context
        let hh = b.block_hash();
        match tree.insert(&b.header, u32::MAX / 2) {
            Ok(_) => {
                let got = tree.get(&hh).map(|n| n.height);
                if got != Some(height) {
                    rejected = Some((height, format!("header linkage: got {got:?}")));
                    break;
                }
            }
            Err(e) => {
                rejected = Some((height, format!("header insert: {e}")));
                break;
            }
        }
        let parent_hash = b.header.prev_block_hash;
        let Some(mtp) = tree.median_time_past(&parent_hash) else {
            rejected = Some((height, "missing parent MTP context".into()));
            break;
        };
        if let Err(e) = check_block(b, params) {
            rejected = Some((height, format!("check_block: {e}")));
        } else if let Err(e) = contextual_check_block(
            b,
            &BlockContext {
                params,
                height,
                parent_median_time_past: Some(mtp),
            },
        ) {
            rejected = Some((height, format!("contextual: {e}")));
        }

        // any join violation inside THIS block rejects it (report first
        // by position; violations from later blocks are irrelevant —
        // the engine stops at the first bad block anyway)
        if rejected.is_none()
            && let Some((pos, msg)) = join_violations.iter().find(|(p, _)| p.h == height)
        {
            rejected = Some((pos.h, format!("join: {msg}")));
        }

        // per-tx predicates over resolved coins
        let mut fees: i64 = 0;
        if rejected.is_none() {
            for (j, t) in b.transactions.iter().enumerate() {
                if j == 0 {
                    continue;
                }
                let mut vin: i64 = 0;
                let mut spent_coins: Vec<Coin> = Vec::new();
                for (i, _inp) in t.inputs.iter().enumerate() {
                    let pos = Occ {
                        h: height,
                        tx: j as u32,
                        idx: i as u32,
                    };
                    let coin = match resolved.get(&pos) {
                        Some(JoinRes::Coin(c)) => c.clone(),
                        Some(JoinRes::DupSpend(_)) => {
                            rejected = Some((height, format!("double spend tx{j} in{i}")));
                            break;
                        }
                        Some(JoinRes::BoundaryConflict) => {
                            rejected =
                                Some((height, format!("conflicting boundary spec tx{j} in{i}")));
                            break;
                        }
                        Some(JoinRes::Missing) => {
                            rejected = Some((height, format!("missing input tx{j} in{i}")));
                            break;
                        }
                        None => {
                            rejected = Some((height, format!("unresolved input tx{j} in{i}")));
                            break;
                        }
                    };
                    if coin.coinbase && height.saturating_sub(coin.height) < COINBASE_MATURITY {
                        rejected = Some((
                            height,
                            format!(
                                "immature coinbase tx{j} depth {}",
                                height.saturating_sub(coin.height)
                            ),
                        ));
                        break;
                    }
                    if !money_range(coin.out.value) {
                        rejected = Some((height, "input value out of range".into()));
                        break;
                    }
                    vin = match vin.checked_add(coin.out.value) {
                        Some(v) if money_range(v) => v,
                        _ => {
                            rejected = Some((height, "input total out of range".into()));
                            break;
                        }
                    };
                    spent_coins.push(coin);
                }
                if rejected.is_some() {
                    break;
                }
                let vout = match t
                    .outputs
                    .iter()
                    .try_fold(0i64, |a, o| a.checked_add(o.value))
                {
                    Some(v) => v,
                    None => {
                        rejected = Some((height, "output total overflow".into()));
                        break;
                    }
                };
                if vout > vin {
                    rejected = Some((height, format!("outputs exceed inputs tx{j}")));
                    break;
                }
                let fee = vin - vout;
                if !money_range(fee) {
                    rejected = Some((height, "fee out of range".into()));
                    break;
                }
                fees = match fees.checked_add(fee) {
                    Some(f) if money_range(f) => f,
                    _ => {
                        rejected = Some((height, "fee range/overflow".into()));
                        break;
                    }
                };
                if !is_final_tx(t, height, mtp) {
                    rejected = Some((height, format!("non-final tx{j}")));
                    break;
                }
                if height >= params.csv_height
                    && !bip68_locks_satisfied(t, &spent_coins, height, mtp, &tree, &parent_hash)
                {
                    rejected = Some((height, format!("BIP68 lock tx{j}")));
                    break;
                }
            }
        }
        if rejected.is_none() {
            let cb_sum: i64 = b.transactions[0].outputs.iter().map(|o| o.value).sum();
            let bound = block_subsidy(height, params).saturating_add(fees);
            if cb_sum > bound {
                rejected = Some((height, format!("coinbase overpays {cb_sum}>{bound}")));
            }
        }
        // ---- boundary commit: apply this block's events ----------------
        if rejected.is_none() {
            for s in spends.iter().filter(|s| s.pos.h == height) {
                live.remove(&s.op);
            }
            for c in created.iter().filter(|c| c.pos.h == height) {
                if !spends.iter().any(|s| s.pos.h == height && s.op == c.op) {
                    live.insert(c.op, c.coin.clone());
                }
            }
            tip_h = height;
            tip_hh = hh;
        }
        let v: Vec<(OutPoint, Coin)> = live.iter().map(|(o, c)| (*o, c.clone())).collect();
        boundary_digests.push(digest_hex(&canonical_bytes(&v)));
        if rejected.is_some() {
            break;
        }
    }
    let v: Vec<(OutPoint, Coin)> = live.into_iter().collect();
    EngineResult {
        tip_height: tip_h,
        tip_hash: tip_hh,
        rejected,
        boundary_digests,
        canonical: canonical_bytes(&v),
        elapsed: t0.elapsed(),
    }
}

// ---------------------------------------------------------------------------
// Scenarios with DECLARED expectations
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Expected {
    Accept,
    RejectAt(u32),
}

struct Scenario {
    name: &'static str,
    /// build the block sequence; may use alternate params for the
    /// fixture (BIP30 synthetic case)
    params_override: Option<Box<dyn Fn(&Params) -> Params>>,
    build: Box<dyn Fn(&Params) -> Vec<Block>>,
    expected: Expected,
    /// declared last-valid tip height
    expect_tip: u32,
}

fn grow_chain(params: &Params, upto: u32) -> (Vec<Block>, Vec<OutPoint>) {
    let mut blocks = Vec::new();
    let mut outs = Vec::new();
    let mut parent = params.genesis_header;
    for h in 1..=upto {
        let b = block_on(&parent, vec![coinbase_tx(h, SUBSIDY)], params);
        outs.push(OutPoint {
            txid: b.transactions[0].txid(),
            vout: 0,
        });
        parent = b.header;
        blocks.push(b);
    }
    (blocks, outs)
}

fn grow_chain_step(params: &Params, upto: u32, step: u32) -> (Vec<Block>, Vec<OutPoint>) {
    let mut blocks = Vec::new();
    let mut outs = Vec::new();
    let mut parent = params.genesis_header;
    for h in 1..=upto {
        let b = block_on_step(&parent, vec![coinbase_tx(h, SUBSIDY)], params, step);
        outs.push(OutPoint {
            txid: b.transactions[0].txid(),
            vout: 0,
        });
        parent = b.header;
        blocks.push(b);
    }
    (blocks, outs)
}

fn scenarios() -> Vec<Scenario> {
    let mut v: Vec<Scenario> = Vec::new();
    macro_rules! sc {
        ($name:expr, $exp:expr, $tip:expr, $build:expr) => {
            v.push(Scenario {
                name: $name,
                params_override: None,
                build: Box::new($build),
                expected: $exp,
                expect_tip: $tip,
            })
        };
    }

    sc!("valid_window", Expected::Accept, 108, |params: &Params| {
        let (mut blocks, outs) = grow_chain(params, 105);
        let mut parent = blocks.last().unwrap().header;
        let t1 = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
        let t2 = spend_tx(
            OutPoint {
                txid: t1.txid(),
                vout: 0,
            },
            SUBSIDY - 2000,
            ANYONE.to_vec(),
        );
        let b = block_on(&parent, vec![coinbase_tx(106, SUBSIDY), t1, t2], params);
        parent = b.header;
        blocks.push(b);
        let mut t3 = spend_tx(outs[1], SUBSIDY - 3000, OP_RETURN.to_vec());
        t3.lock_time = 106;
        let b = block_on(&parent, vec![coinbase_tx(107, SUBSIDY), t3], params);
        parent = b.header;
        blocks.push(b);
        let t4 = spend_tx(outs[2], SUBSIDY - 500, ANYONE.to_vec());
        let t5 = spend_tx(
            OutPoint {
                txid: blocks[105].transactions[2].txid(),
                vout: 0,
            },
            SUBSIDY - 3000,
            ANYONE.to_vec(),
        );
        blocks.push(block_on(
            &parent,
            vec![coinbase_tx(108, SUBSIDY), t4, t5],
            params,
        ));
        blocks
    });

    sc!(
        "immature_coinbase",
        Expected::RejectAt(104),
        103,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 103);
            let parent = blocks.last().unwrap().header;
            let t = spend_tx(outs[4], SUBSIDY - 1000, ANYONE.to_vec());
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(104, SUBSIDY), t],
                params,
            ));
            blocks
        }
    );

    sc!(
        "double_spend_cross_block",
        Expected::RejectAt(106),
        105,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 104);
            let mut parent = blocks.last().unwrap().header;
            let t = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            let b = block_on(&parent, vec![coinbase_tx(105, SUBSIDY), t], params);
            parent = b.header;
            blocks.push(b);
            let t2 = spend_tx(outs[0], SUBSIDY - 2000, ANYONE.to_vec());
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(106, SUBSIDY), t2],
                params,
            ));
            blocks
        }
    );

    sc!(
        "double_spend_same_block",
        Expected::RejectAt(105),
        104,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 104);
            let parent = blocks.last().unwrap().header;
            let t1 = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            let t2 = spend_tx(outs[0], SUBSIDY - 2000, ANYONE.to_vec());
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(105, SUBSIDY), t1, t2],
                params,
            ));
            blocks
        }
    );

    sc!(
        "future_output",
        Expected::RejectAt(105),
        104,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 104);
            let mut parent = blocks.last().unwrap().header;
            let t1 = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            let t_bad = spend_tx(
                OutPoint {
                    txid: t1.txid(),
                    vout: 0,
                },
                SUBSIDY - 2000,
                ANYONE.to_vec(),
            );
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(105, SUBSIDY), t_bad],
                params,
            ));
            parent = blocks.last().unwrap().header;
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(106, SUBSIDY), t1],
                params,
            ));
            blocks
        }
    );

    sc!(
        "same_block_order_bad",
        Expected::RejectAt(105),
        104,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 104);
            let parent = blocks.last().unwrap().header;
            let creator = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            let spender = spend_tx(
                OutPoint {
                    txid: creator.txid(),
                    vout: 0,
                },
                SUBSIDY - 2000,
                ANYONE.to_vec(),
            );
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(105, SUBSIDY), spender, creator],
                params,
            ));
            blocks
        }
    );

    sc!(
        "wrong_amount",
        Expected::RejectAt(105),
        104,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 104);
            let parent = blocks.last().unwrap().header;
            let t = spend_tx(outs[0], SUBSIDY + 1, ANYONE.to_vec());
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(105, SUBSIDY), t],
                params,
            ));
            blocks
        }
    );

    sc!(
        "excess_reward",
        Expected::RejectAt(105),
        104,
        |params: &Params| {
            let (mut blocks, _o) = grow_chain(params, 104);
            let parent = blocks.last().unwrap().header;
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(105, SUBSIDY + 1)],
                params,
            ));
            blocks
        }
    );

    sc!(
        "unspendable_spend",
        Expected::RejectAt(106),
        105,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 104);
            let mut parent = blocks.last().unwrap().header;
            let t1 = spend_tx(outs[0], SUBSIDY - 1000, OP_RETURN.to_vec());
            let b = block_on(&parent, vec![coinbase_tx(105, SUBSIDY), t1.clone()], params);
            parent = b.header;
            blocks.push(b);
            let t2 = spend_tx(
                OutPoint {
                    txid: t1.txid(),
                    vout: 0,
                },
                SUBSIDY - 2000,
                ANYONE.to_vec(),
            );
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(106, SUBSIDY), t2],
                params,
            ));
            blocks
        }
    );

    // locktime: non-final seq, lock=105 at h105 → reject
    sc!(
        "locktime_early",
        Expected::RejectAt(105),
        104,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 104);
            let parent = blocks.last().unwrap().header;
            let mut t = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            t.lock_time = 105;
            t.inputs[0].sequence = SEQUENCE_FINAL - 1;
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(105, SUBSIDY), t],
                params,
            ));
            blocks
        }
    );

    // locktime satisfied: non-final seq, lock=105 at h106 → accept
    sc!(
        "locktime_satisfied",
        Expected::Accept,
        106,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 105);
            let parent = blocks.last().unwrap().header;
            let mut t = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            t.lock_time = 105;
            t.inputs[0].sequence = SEQUENCE_FINAL - 1;
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(106, SUBSIDY), t],
                params,
            ));
            blocks
        }
    );

    // locktime bypass: all-final seqs bypass lock entirely (lock far
    // in the future still accepts) — separate positive control.
    sc!(
        "locktime_bypass_final",
        Expected::Accept,
        106,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 105);
            let parent = blocks.last().unwrap().header;
            let mut t = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            t.lock_time = 9999; // way in the future; all-final inputs bypass
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(106, SUBSIDY), t],
                params,
            ));
            blocks
        }
    );

    // MTP-mode locktime (>=500M): lock=parent_mtp at h106, non-final → reject;
    // satisfied twin lock=parent_mtp-1 → accept. Block times step +1 so
    // MTP at h105 ≈ genesis+53.
    sc!(
        "locktime_mtp_early",
        Expected::RejectAt(106),
        105,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 105);
            let parent = blocks.last().unwrap().header;
            let mut t = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            // MTP at h105 ≈ genesis(1296688602)+52. A MTP-mode lock above
            // every block time is unreached → non-final seq rejects.
            t.lock_time = 2_000_000_000;
            t.inputs[0].sequence = SEQUENCE_FINAL - 1;
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(106, SUBSIDY), t],
                params,
            ));
            blocks
        }
    );
    sc!(
        "locktime_mtp_ok",
        Expected::Accept,
        106,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 105);
            let parent = blocks.last().unwrap().header;
            let mut t = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            // genesis regtest time ~1296688602 — MTP at h105 ≈ genesis+52.
            // A lock below that MTP is already past → accept.
            t.lock_time = 500_000_000;
            t.inputs[0].sequence = SEQUENCE_FINAL - 1;
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(106, SUBSIDY), t],
                params,
            ));
            blocks
        }
    );

    // BIP68 height locks
    sc!(
        "seq_lock_early",
        Expected::RejectAt(107),
        106,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 105);
            let mut parent = blocks.last().unwrap().header;
            let t1 = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            let t1id = t1.txid();
            let b = block_on(&parent, vec![coinbase_tx(106, SUBSIDY), t1], params);
            parent = b.header;
            blocks.push(b);
            let mut t2 = spend_tx(
                OutPoint {
                    txid: t1id,
                    vout: 0,
                },
                SUBSIDY - 2000,
                ANYONE.to_vec(),
            );
            t2.version = 2;
            t2.inputs[0].sequence = 5;
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(107, SUBSIDY), t2],
                params,
            ));
            blocks
        }
    );
    sc!(
        "seq_lock_satisfied",
        Expected::Accept,
        108,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 105);
            let mut parent = blocks.last().unwrap().header;
            let t1 = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            let t1id = t1.txid();
            let b = block_on(&parent, vec![coinbase_tx(106, SUBSIDY), t1], params);
            parent = b.header;
            blocks.push(b);
            let mut t2 = spend_tx(
                OutPoint {
                    txid: t1id,
                    vout: 0,
                },
                SUBSIDY - 2000,
                ANYONE.to_vec(),
            );
            t2.version = 2;
            t2.inputs[0].sequence = 1;
            let b = block_on(&parent, vec![coinbase_tx(107, SUBSIDY), t2], params);
            parent = b.header;
            blocks.push(b);
            blocks.push(block_on(&parent, vec![coinbase_tx(108, SUBSIDY)], params));
            blocks
        }
    );

    // BIP68 TIME-type locks (bit 22). Block times step +600s so parent
    // MTP advances ~600s/block. Coin created h106; spend at h107.
    // seq=(1<<22)|1 → needs ≥512s of coin-age-MTP growth: MTP(h105)→
    // MTP(h106) is one step =600s → satisfied.
    sc!(
        "seq_timelock_ok",
        Expected::Accept,
        107,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain_step(params, 105, 600);
            let mut parent = blocks.last().unwrap().header;
            let t1 = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            let t1id = t1.txid();
            let b = block_on_step(&parent, vec![coinbase_tx(106, SUBSIDY), t1], params, 600);
            parent = b.header;
            blocks.push(b);
            let mut t2 = spend_tx(
                OutPoint {
                    txid: t1id,
                    vout: 0,
                },
                SUBSIDY - 2000,
                ANYONE.to_vec(),
            );
            t2.version = 2;
            t2.inputs[0].sequence = BIP68_TYPE_TIME | 1; // 512s — satisfied
            blocks.push(block_on_step(
                &parent,
                vec![coinbase_tx(107, SUBSIDY), t2],
                params,
                600,
            ));
            blocks
        }
    );
    // Same layout but lock=10 units (5120s) → one 600s step insufficient.
    sc!(
        "seq_timelock_early",
        Expected::RejectAt(107),
        106,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain_step(params, 105, 600);
            let mut parent = blocks.last().unwrap().header;
            let t1 = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
            let t1id = t1.txid();
            let b = block_on_step(&parent, vec![coinbase_tx(106, SUBSIDY), t1], params, 600);
            parent = b.header;
            blocks.push(b);
            let mut t2 = spend_tx(
                OutPoint {
                    txid: t1id,
                    vout: 0,
                },
                SUBSIDY - 2000,
                ANYONE.to_vec(),
            );
            t2.version = 2;
            t2.inputs[0].sequence = BIP68_TYPE_TIME | 10; // 5120s — early
            blocks.push(block_on_step(
                &parent,
                vec![coinbase_tx(107, SUBSIDY), t2],
                params,
                600,
            ));
            blocks
        }
    );

    // fee-bearing coinbase: cb claims exactly subsidy+fees → accept;
    // +1 sat → reject. Exercises post-fee bound ordering.
    sc!(
        "fee_claim_exact",
        Expected::Accept,
        106,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 105);
            let parent = blocks.last().unwrap().header;
            let t = spend_tx(outs[0], SUBSIDY - 7000, ANYONE.to_vec()); // fee 7000
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(106, SUBSIDY + 7000), t],
                params,
            ));
            blocks
        }
    );
    sc!(
        "fee_claim_plus1",
        Expected::RejectAt(106),
        105,
        |params: &Params| {
            let (mut blocks, outs) = grow_chain(params, 105);
            let parent = blocks.last().unwrap().header;
            let t = spend_tx(outs[0], SUBSIDY - 7000, ANYONE.to_vec());
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(106, SUBSIDY + 7001), t],
                params,
            ));
            blocks
        }
    );

    // missing input — never-created outpoint
    sc!(
        "missing_input",
        Expected::RejectAt(105),
        104,
        |params: &Params| {
            let (mut blocks, _outs) = grow_chain(params, 104);
            let parent = blocks.last().unwrap().header;
            let bogus = OutPoint {
                txid: avila_consensus::hash::Txid::from_bytes([0x77; 32]),
                vout: 0,
            };
            let t = spend_tx(bogus, 1000, ANYONE.to_vec());
            blocks.push(block_on(
                &parent,
                vec![coinbase_tx(105, SUBSIDY), t],
                params,
            ));
            blocks
        }
    );

    // BIP30 isolated fixture: SYNTHETIC params with BIP34 inactive —
    // two byte-identical coinbase transactions (no height push) at
    // h105/h106 share one txid; the second block attempts creation
    // while the first's outputs are unspent → the duplicate-creation
    // predicate must fire on both engines. Params here are a fixture,
    // not a production setting; the fixture exercises pre-BIP34-era
    // semantics that full-IBD must still implement.
    v.push(Scenario {
        name: "bip30_dup_coinbase_synthetic",
        params_override: Some(Box::new(|p: &Params| {
            let mut q = *p;
            q.bip34_height = u32::MAX;
            q
        })),
        build: Box::new(|params: &Params| {
            let (mut blocks, _outs) = grow_chain(params, 104);
            let mut parent = blocks.last().unwrap().header;
            // identical coinbase txs → identical txid
            let cb = coinbase_flat(SUBSIDY);
            let b = block_on(&parent, vec![cb.clone()], params);
            parent = b.header;
            blocks.push(b);
            blocks.push(block_on(&parent, vec![cb], params));
            blocks
        }),
        expected: Expected::RejectAt(106),
        expect_tip: 105,
    });

    v
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn scenario_bounds(blocks: &[Block]) -> (String, String) {
    (
        hexid(&blocks.first().unwrap().header.prev_block_hash),
        hexid(&blocks.last().unwrap().block_hash()),
    )
}

fn first_diff(a: &[u8], b: &[u8]) -> (usize, usize, String, String, usize, usize) {
    let idx = a
        .iter()
        .zip(b.iter())
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()));
    let ra = canonical_decode(a);
    let rb = canonical_decode(b);
    let rec = ra
        .iter()
        .zip(rb.iter())
        .position(|(x, y)| x != y)
        .unwrap_or(ra.len().min(rb.len()));
    (
        idx,
        rec,
        format!("{:?}", ra.get(rec)),
        format!("{:?}", rb.get(rec)),
        ra.len(),
        rb.len(),
    )
}

fn main() {
    let base_params = Network::Regtest.params();
    let out_dir = std::env::var("GATE3_OUT").unwrap_or_else(|_| ".".into());
    std::fs::create_dir_all(&out_dir).ok();
    let mut all_ok = true;
    let mut manifest = String::new();
    manifest.push_str("{\"type\":\"manifest\",\"genesis_hash\":");
    manifest.push_str(&jstr(&hexid(&base_params.genesis_header.hash())));
    manifest.push_str("}\n");

    for sc in scenarios() {
        let params = sc
            .params_override
            .map(|f| f(&base_params))
            .unwrap_or_else(|| base_params);
        let blocks = (sc.build)(&params);
        let (first_parent, last_tip) = scenario_bounds(&blocks);
        let inc = run_incremental(&params, &blocks, None, None, 0);
        let batch_tree = HeaderTree::new(params);
        let bat = run_occurrence(&params, &blocks, None, batch_tree, 0);
        // the window-wide join engine — the architecture under test
        let join_tree = HeaderTree::new(params);
        let join = run_join(&params, &blocks, None, join_tree, 0);

        // -- oracle ----------------------------------------------------
        let expect_ok = match sc.expected {
            Expected::Accept => {
                inc.rejected.is_none()
                    && bat.rejected.is_none()
                    && join.rejected.is_none()
                    && inc.tip_height == sc.expect_tip
                    && bat.tip_height == sc.expect_tip
                    && join.tip_height == sc.expect_tip
            }
            Expected::RejectAt(h) => {
                inc.rejected.as_ref().map(|r| r.0) == Some(h)
                    && bat.rejected.as_ref().map(|r| r.0) == Some(h)
                    && join.rejected.as_ref().map(|r| r.0) == Some(h)
                    && inc.tip_height == sc.expect_tip
                    && bat.tip_height == sc.expect_tip
                    && join.tip_height == sc.expect_tip
            }
        };
        // ALL THREE must produce identical canonical state, digests, tips
        let state_equal = inc.canonical == bat.canonical && inc.canonical == join.canonical;
        let digests_equal = inc.boundary_digests == bat.boundary_digests
            && inc.boundary_digests == join.boundary_digests;
        let tip_hash_equal = inc.tip_hash == bat.tip_hash && inc.tip_hash == join.tip_hash;
        // expected tip hash = hash of the last accepted block
        let expect_tip_hash = if sc.expect_tip > 0 {
            blocks[sc.expect_tip as usize - 1].block_hash()
        } else {
            params.genesis_header.hash()
        };
        let tip_correct = inc.tip_hash == expect_tip_hash
            && bat.tip_hash == expect_tip_hash
            && join.tip_hash == expect_tip_hash;
        // rejection must preserve pre-block state: last boundary digest
        // equals the digest at the declared last-valid boundary
        let preserved = match (sc.expected, inc.boundary_digests.len()) {
            (Expected::RejectAt(_), n) if n > sc.expect_tip as usize => {
                inc.boundary_digests[sc.expect_tip as usize - 1]
                    == *inc.boundary_digests.last().unwrap()
                    && bat.boundary_digests[sc.expect_tip as usize - 1]
                        == *bat.boundary_digests.last().unwrap()
                    && join.boundary_digests[sc.expect_tip as usize - 1]
                        == *join.boundary_digests.last().unwrap()
            }
            _ => true,
        };
        let ok =
            expect_ok && state_equal && digests_equal && tip_hash_equal && tip_correct && preserved;
        all_ok &= ok;

        // persist exports
        let _ = std::fs::write(
            format!("{out_dir}/{}-inc.canonical", sc.name),
            &inc.canonical,
        );
        let _ = std::fs::write(
            format!("{out_dir}/{}-batch.canonical", sc.name),
            &bat.canonical,
        );
        let _ = std::fs::write(
            format!("{out_dir}/{}-join.canonical", sc.name),
            &join.canonical,
        );

        let (d_idx, d_rec, d_ra, d_rb, d_ral, d_rbl) = if !state_equal {
            let t = first_diff(&inc.canonical, &join.canonical);
            (
                t.0.to_string(),
                t.1.to_string(),
                jstr(&t.2),
                jstr(&t.3),
                t.4.to_string(),
                t.5.to_string(),
            )
        } else {
            (
                "null".into(),
                "null".into(),
                "null".into(),
                "null".into(),
                "null".into(),
                "null".into(),
            )
        };
        println!(
            "{{\"scenario\":{},\"blocks\":{},\
\"first_block_parent\":{},\"last_block_hash\":{},\
\"expected\":{},\"expect_tip\":{},\
\"inc_tip\":{},\"inc_tip_hash\":{},\"inc_reject\":{},\
\"batch_tip\":{},\"batch_tip_hash\":{},\"batch_reject\":{},\
\"state_bytes\":{},\"records\":{},\
\"inc_digest\":{},\"batch_digest\":{},\
\"inc_ms\":{:.2},\"batch_ms\":{:.2},\
\"state_equal\":{state_equal},\"boundary_digests_equal\":{digests_equal},\
\"tip_hash_equal\":{tip_hash_equal},\"tip_correct\":{tip_correct},\
\"rejection_preserves_state\":{preserved},\"expectations_met\":{expect_ok},\
\"first_diff_byte\":{d_idx},\"first_diff_record\":{d_rec},\
\"inc_rec\":{d_ra},\"batch_rec\":{d_rb},\
\"inc_records_n\":{d_ral},\"batch_records_n\":{d_rbl},\
\"ok\":{ok}}}",
            jstr(sc.name),
            blocks.len(),
            jstr(&first_parent),
            jstr(&last_tip),
            jstr(&match sc.expected {
                Expected::Accept => "accept".into(),
                Expected::RejectAt(h) => format!("reject@{h}"),
            }),
            sc.expect_tip,
            inc.tip_height,
            jstr(&hexid(&inc.tip_hash)),
            opt_json(inc.rejected.map(|(h, e)| format!("h{h}:{e}"))),
            bat.tip_height,
            jstr(&hexid(&bat.tip_hash)),
            opt_json(bat.rejected.map(|(h, e)| format!("h{h}:{e}"))),
            inc.canonical.len(),
            canonical_decode(&inc.canonical).len(),
            jstr(&digest_hex(&inc.canonical)),
            jstr(&digest_hex(&bat.canonical)),
            inc.elapsed.as_secs_f64() * 1e3,
            bat.elapsed.as_secs_f64() * 1e3,
        );
        // join-engine diagnostics on the same line set
        println!(
            "{{\"scenario\":{},\"engine\":\"join\",\"tip\":{},\
\"tip_hash\":{},\"reject\":{},\"digest\":{},\"ms\":{:.2}}}",
            jstr(sc.name),
            join.tip_height,
            jstr(&hexid(&join.tip_hash)),
            opt_json(join.rejected.map(|(h, e)| format!("h{h}:{e}"))),
            jstr(&digest_hex(&join.canonical)),
            join.elapsed.as_secs_f64() * 1e3,
        );
    }

    // -- supplied-state continuation ------------------------------------
    {
        let params = base_params;
        let s = scenarios();
        let sc = s
            .iter()
            .find(|s| s.name == "valid_window")
            .expect("valid_window scenario");
        let blocks = (sc.build)(&params);
        const SPLIT: usize = 105;
        let base = run_incremental(&params, &blocks[..SPLIT], None, None, 0);
        assert!(base.rejected.is_none());
        let fixture = canonical_decode(&base.canonical);
        let fixture_hash = digest_hex(&base.canonical);
        // header context for the suffix: checked tree extended INSIDE
        // run_occurrence/run_incremental as blocks evaluate.
        let mut pre = HeaderTree::new(params);
        for b in &blocks[..SPLIT] {
            assert!(pre.insert(&b.header, u32::MAX / 2).is_ok());
        }
        let mut pre2 = HeaderTree::new(params);
        for b in &blocks[..SPLIT] {
            assert!(pre2.insert(&b.header, u32::MAX / 2).is_ok());
        }
        let mut pre3 = HeaderTree::new(params);
        for b in &blocks[..SPLIT] {
            assert!(pre3.insert(&b.header, u32::MAX / 2).is_ok());
        }
        let inc = run_incremental(
            &params,
            &blocks[SPLIT..],
            Some(fixture.clone()),
            Some(pre2),
            SPLIT as u32,
        );
        let bat = run_occurrence(
            &params,
            &blocks[SPLIT..],
            Some(fixture.clone()),
            pre,
            SPLIT as u32,
        );
        let join = run_join(&params, &blocks[SPLIT..], Some(fixture), pre3, SPLIT as u32);
        // continuation must reproduce the uninterrupted run's terminal
        // state AND tip hash.
        let whole = run_incremental(&params, &blocks, None, None, 0);
        let state_equal = inc.canonical == bat.canonical
            && inc.canonical == join.canonical
            && inc.canonical == whole.canonical;
        let tip_equal = inc.tip_hash == bat.tip_hash
            && inc.tip_hash == join.tip_hash
            && inc.tip_hash == whole.tip_hash
            && inc.tip_height == whole.tip_height;
        let ok = state_equal
            && tip_equal
            && inc.rejected.is_none()
            && bat.rejected.is_none()
            && join.rejected.is_none();
        all_ok &= ok;
        println!(
            "{{\"scenario\":\"supplied_state_h105\",\"suffix_blocks\":{},\
\"fixture_bytes\":{},\"fixture_records\":{},\"fixture_sha256\":{},\
\"inc_tip\":{},\"inc_tip_hash\":{},\"batch_tip\":{},\"batch_tip_hash\":{},\
\"whole_tip_hash\":{},\"inc_digest\":{},\"batch_digest\":{},\"whole_digest\":{},\
\"state_equal\":{state_equal},\"tip_equal\":{tip_equal},\"ok\":{ok}}}",
            blocks.len() - SPLIT,
            base.canonical.len(),
            canonical_decode(&base.canonical).len(),
            jstr(&fixture_hash),
            inc.tip_height,
            jstr(&hexid(&inc.tip_hash)),
            bat.tip_height,
            jstr(&hexid(&bat.tip_hash)),
            jstr(&hexid(&whole.tip_hash)),
            jstr(&digest_hex(&inc.canonical)),
            jstr(&digest_hex(&bat.canonical)),
            jstr(&digest_hex(&whole.canonical)),
        );
    }

    // -- supplied-state continuation with time-type BIP68 post-split ----
    {
        let params = base_params;
        // chain with +600s steps; coin created INSIDE the suffix is
        // spent under a time-type relative lock later in the suffix —
        // exercises ancestor/MTP resolution past the supplied boundary.
        let (mut blocks, outs) = grow_chain_step(&params, 105, 600);
        let mut parent = blocks.last().unwrap().header;
        // suffix h106: create spendable coin from cb h1
        let t1 = spend_tx(outs[0], SUBSIDY - 1000, ANYONE.to_vec());
        let t1id = t1.txid();
        let b = block_on_step(&parent, vec![coinbase_tx(106, SUBSIDY), t1], &params, 600);
        parent = b.header;
        blocks.push(b);
        // h107: spend it with time-type lock 1 unit (512s) — satisfied
        // since ancestor MTP advanced ~600s across the boundary.
        let mut t2 = spend_tx(
            OutPoint {
                txid: t1id,
                vout: 0,
            },
            SUBSIDY - 2000,
            ANYONE.to_vec(),
        );
        t2.version = 2;
        t2.inputs[0].sequence = BIP68_TYPE_TIME | 1;
        let b = block_on_step(&parent, vec![coinbase_tx(107, SUBSIDY), t2], &params, 600);
        parent = b.header;
        blocks.push(b);
        // h108: a second time-locked spend, still satisfied (2 units).
        let mut t3 = spend_tx(outs[1], SUBSIDY - 500, ANYONE.to_vec());
        t3.version = 2;
        t3.inputs[0].sequence = BIP68_TYPE_TIME | 2;
        blocks.push(block_on_step(
            &parent,
            vec![coinbase_tx(108, SUBSIDY), t3],
            &params,
            600,
        ));

        const SPLIT: usize = 105;
        let base = run_incremental(&params, &blocks[..SPLIT], None, None, 0);
        let fixture = canonical_decode(&base.canonical);
        let mut pre = HeaderTree::new(params);
        for b in &blocks[..SPLIT] {
            assert!(pre.insert(&b.header, u32::MAX / 2).is_ok());
        }
        let mut pre2 = HeaderTree::new(params);
        for b in &blocks[..SPLIT] {
            assert!(pre2.insert(&b.header, u32::MAX / 2).is_ok());
        }
        let mut pre3 = HeaderTree::new(params);
        for b in &blocks[..SPLIT] {
            assert!(pre3.insert(&b.header, u32::MAX / 2).is_ok());
        }
        let inc = run_incremental(
            &params,
            &blocks[SPLIT..],
            Some(fixture.clone()),
            Some(pre2),
            SPLIT as u32,
        );
        let bat = run_occurrence(
            &params,
            &blocks[SPLIT..],
            Some(fixture.clone()),
            pre,
            SPLIT as u32,
        );
        let join = run_join(&params, &blocks[SPLIT..], Some(fixture), pre3, SPLIT as u32);
        let whole = run_incremental(&params, &blocks, None, None, 0);
        let state_equal = inc.canonical == bat.canonical
            && inc.canonical == join.canonical
            && inc.canonical == whole.canonical;
        let tip_equal = inc.tip_hash == bat.tip_hash
            && inc.tip_hash == join.tip_hash
            && inc.tip_hash == whole.tip_hash;
        let accepted = inc.rejected.is_none()
            && bat.rejected.is_none()
            && join.rejected.is_none()
            && inc.tip_height == 108
            && bat.tip_height == 108
            && join.tip_height == 108;
        let ok = state_equal && tip_equal && accepted;
        all_ok &= ok;
        println!(
            "{{\"scenario\":\"supplied_state_timelock\",\"suffix_blocks\":{},\
\"inc_tip\":{},\"inc_reject\":{},\"batch_tip\":{},\"batch_reject\":{},\
\"inc_digest\":{},\"batch_digest\":{},\"whole_digest\":{},\
\"state_equal\":{state_equal},\"tip_equal\":{tip_equal},\"accepted\":{accepted},\"ok\":{ok}}}",
            blocks.len() - SPLIT,
            inc.tip_height,
            opt_json(inc.rejected.map(|(h, e)| format!("h{h}:{e}"))),
            bat.tip_height,
            opt_json(bat.rejected.map(|(h, e)| format!("h{h}:{e}"))),
            jstr(&digest_hex(&inc.canonical)),
            jstr(&digest_hex(&bat.canonical)),
            jstr(&digest_hex(&whole.canonical)),
        );
    }

    println!(
        "{{\"type\":\"summary\",\"genesis_hash\":{},\"all_ok\":{all_ok}}}",
        jstr(&hexid(&base_params.genesis_header.hash())),
    );
    let _ = std::io::stdout().flush();
    if !all_ok {
        std::process::exit(1);
    }
}

//! Reference-adapter helper for block-level rules: run a raw serialized block
//! through the implemented validation pipeline and print one verdict, or emit a
//! generated regtest corpus for `tools/check_blocks_core.py` to replay through
//! the reference daemon's `submitblock` RPC.
//!
//! Usage:
//!   `check-blocks check <network> <block.bin> <now>`
//!   `check-blocks check-many <network> <now> <block.bin>...`
//!   `check-blocks replay <network> <blocks.dat> <now>`
//!   `check-blocks gen-corpus <outdir>`
//!
//! The pipeline mirrors Core's `ProcessNewBlock` order: header insertion
//! (`AcceptBlockHeader`/`ContextualCheckBlockHeader`) into a [`HeaderTree`]
//! seeded with the network genesis, then [`check::check_block`] (`CheckBlock`),
//! then [`check::contextual_check_block`] (`ContextualCheckBlock`). `check`
//! uses a fresh tree per invocation; `check-many` shares one tree across all
//! input blocks in order — like the daemon's block index — so later blocks may
//! build on earlier accepted ones and resubmissions report `accepted-known`.
//! Output lines are `<name>\t<verdict>\t<detail>` where `<verdict>` is
//! `accepted`, `accepted-known`, or `rejected:<reason>` with the reason token
//! matching the reject reason the reference daemon reports.
//!
//! `gen-corpus` writes `<name>.bin` files plus a `manifest.json` recording each
//! block's expected verdict — every entry is produced by `validate` against a
//! shared tree in manifest order, so the manifest reflects the
//! implementation's actual stateful behavior, not an assertion.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use avila_consensus::arith::CompactTarget;
use avila_consensus::block::{Block, MAX_BLOCK_SERIALIZED_SIZE};
use avila_consensus::chainstate::{Acceptance, BlockRejection, Chainstate};
use avila_consensus::check;
use avila_consensus::connect;
use avila_consensus::connect::ConnectError;
use avila_consensus::hash::{BlockHash, MerkleRoot, Txid};
use avila_consensus::header::BlockHeader;
use avila_consensus::params::{Network, Params};
use avila_consensus::pow;
use avila_consensus::script;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

fn network(name: &str) -> Option<Network> {
    Some(match name {
        "main" | "mainnet" => Network::Mainnet,
        "testnet4" => Network::Testnet4,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => return None,
    })
}

/// Runs [`Chainstate::accept_block`] against `state` (shared across calls, like
/// Core's block index + chainstate) and returns `(verdict, detail)` in the
/// shape the differential driver compares. A block that extends the connected
/// tip reports `accepted` after a real `connect_block`; a valid block on any
/// other branch reports `accepted` after the context-free and contextual
/// layers, like the daemon's `inconclusive` for side-chain blocks.
fn validate(block: &Block, state: &mut Chainstate, now: u32) -> (String, String) {
    match state.accept_block(block, now) {
        Ok(Acceptance::Connected { height, reorged }) => (
            "accepted".to_string(),
            if reorged {
                format!("height={height},connected,reorg")
            } else {
                format!("height={height},connected")
            },
        ),
        Ok(Acceptance::Parked { height }) => ("accepted".to_string(), format!("height={height}")),
        Ok(Acceptance::AlreadyKnown { height }) => {
            ("accepted-known".to_string(), format!("height={height}"))
        }
        Err(err) => (format!("rejected:{}", err.reason()), err.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Corpus generation (regtest only — every deployment is active from genesis or
// height 1, so a single height-1 block can exercise every implemented rule).
// ---------------------------------------------------------------------------

const REGTEST_BITS: u32 = 0x207f_ffff;

fn outpoint(byte: u8, vout: u32) -> OutPoint {
    OutPoint {
        txid: Txid::from_bytes([byte; 32]),
        vout,
    }
}

fn txin(prev: OutPoint, script_sig: Vec<u8>) -> TxIn {
    TxIn {
        previous_output: prev,
        script_sig: Script::new(script_sig),
        sequence: check::SEQUENCE_FINAL,
        witness: Witness::default(),
    }
}

fn txin_seq(prev: OutPoint, sequence: u32) -> TxIn {
    TxIn {
        previous_output: prev,
        script_sig: Script::new(Vec::new()),
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

fn spend_tx() -> Transaction {
    Transaction {
        version: 1,
        inputs: vec![txin(outpoint(1, 0), vec![])],
        outputs: vec![txout(1000, vec![script::OP_1])],
        lock_time: 0,
    }
}

/// A regtest height-`height` coinbase: the scriptSig starts with the BIP34
/// height push (active at height 1 on regtest) and stays within the 2–100 byte
/// bound; the output pays exactly the 50 BTC initial subsidy.
fn regtest_coinbase(height: u32) -> Transaction {
    let mut script_sig = script::push_int(i64::from(height));
    script_sig.push(script::OP_1);
    Transaction {
        version: 1,
        inputs: vec![txin(OutPoint::NULL, script_sig)],
        outputs: vec![txout(5_000_000_000, vec![script::OP_1])],
        lock_time: 0,
    }
}

/// Drafts a regtest block over `txs` building on `parent` with a correct
/// merkle root, `parent.time + 1`, and the regtest `nBits`. PoW is not ground —
/// callers pass the result through `finish` after any intended mutations.
fn draft_on(parent: &BlockHeader, txs: Vec<Transaction>) -> Block {
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
    block
}

/// Drafts a block on the network genesis — the usual corpus parent.
fn draft_block(params: &Params, txs: Vec<Transaction>) -> Block {
    draft_on(&params.genesis_header, txs)
}

/// Recomputes the merkle root after transaction-list mutations, then grinds the
/// nonce until the header satisfies its claimed target.
fn fixup(block: &mut Block, params: &Params) {
    let (root, _) = block.merkle_root();
    block.header.merkle_root = root;
    while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
        block.header.nonce += 1;
    }
}

fn finish(mut block: Block, params: &Params) -> Block {
    fixup(&mut block, params);
    block
}

/// Grinds the nonce without touching the merkle root — for cases whose whole
/// point is a committed root that doesn't match the transaction list.
fn grind(block: &mut Block, params: &Params) {
    while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
        block.header.nonce += 1;
    }
}

/// Appends a valid witness-commitment output (requires the coinbase to carry a
/// single 32-byte witness reserved value already).
fn add_witness_commitment(block: &mut Block, params: &Params) {
    let Some(commitment) = block.expected_witness_commitment() else {
        eprintln!("gen-corpus: coinbase witness stack is not a single 32-byte item");
        return;
    };
    let mut commit_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commit_script.extend_from_slice(&commitment);
    block.transactions[0].outputs.push(txout(0, commit_script));
    fixup(block, params);
}

/// Runs `validate` on `block` against the shared corpus `tree`, writes
/// `<name>.bin`, and records the verdict.
fn emit(
    manifest: &mut Vec<(String, String)>,
    outdir: &Path,
    name: &str,
    block: &Block,
    state: &mut Chainstate,
    now: u32,
) -> Result<(), String> {
    let (verdict, _detail) = validate(block, state, now);
    let path = outdir.join(format!("{name}.bin"));
    fs::write(&path, block.encode()).map_err(|e| format!("write {}: {e}", path.display()))?;
    manifest.push((name.to_string(), verdict));
    Ok(())
}

/// Builds `[regtest_coinbase(1), spend_tx() mutated by `mutate`]`, fixing the
/// merkle root and PoW, then emits it.
fn emit_tx_case(
    manifest: &mut Vec<(String, String)>,
    outdir: &Path,
    name: &str,
    params: &Params,
    state: &mut Chainstate,
    now: u32,
    mutate: impl FnOnce(&mut Transaction),
) -> Result<(), String> {
    let mut tx = spend_tx();
    mutate(&mut tx);
    let block = finish(draft_block(params, vec![regtest_coinbase(1), tx]), params);
    emit(manifest, outdir, name, &block, state, now)
}

fn gen_corpus(outdir: &Path, now: u32) -> Result<(), String> {
    let params = Network::Regtest.params();
    let mut manifest = Vec::new();
    // One chain state across the whole corpus: verdicts are stateful, matching
    // how the daemon accumulates headers in its block index and connects the
    // active chain tip between submissions.
    let mut state = Chainstate::new(&params);

    // -- valid baseline ------------------------------------------------------
    let valid = finish(draft_block(&params, vec![regtest_coinbase(1)]), &params);
    emit(&mut manifest, outdir, "00-valid", &valid, &mut state, now)?;

    // A valid child at height 2: exercises the pipeline past genesis+1 (the
    // daemon will connect both blocks). `child` is also the connect-phase
    // chain's h2 link below.
    let child = finish(draft_on(&valid.header, vec![regtest_coinbase(2)]), &params);
    emit(
        &mut manifest,
        outdir,
        "05-valid-height2",
        &child,
        &mut state,
        now,
    )?;

    // -- header rules (AcceptBlockHeader/ContextualCheckBlockHeader) ---------

    // high-hash: a valid compact encoding under the limit, but the hash fails
    // the claimed (~2^248) target.
    let high_hash_header;
    {
        let mut block = draft_block(&params, vec![regtest_coinbase(1)]);
        block.header.bits = CompactTarget(0x1f7f_ffff);
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, &params).is_ok() {
            block.header.nonce += 1;
        }
        high_hash_header = block.header;
        emit(
            &mut manifest,
            outdir,
            "10-high-hash",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-diffbits: PoW passes under the claimed bits, but required_bits at
    // regtest height 1 is the limit.
    {
        let mut block = draft_block(&params, vec![regtest_coinbase(1)]);
        block.header.bits = CompactTarget(0x1f7f_ffff);
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, &params).is_err() {
            block.header.nonce += 1;
        }
        emit(
            &mut manifest,
            outdir,
            "11-bad-diffbits",
            &block,
            &mut state,
            now,
        )?;
    }

    // time-too-old: nTime equal to the parent's median-time-past.
    {
        let mut block = draft_block(&params, vec![regtest_coinbase(1)]);
        block.header.time = params.genesis_header.time;
        let block = finish(block, &params);
        emit(
            &mut manifest,
            outdir,
            "12-time-too-old",
            &block,
            &mut state,
            now,
        )?;
    }

    // time-too-new: a far-future nTime (always beyond now + 2h).
    {
        let mut block = draft_block(&params, vec![regtest_coinbase(1)]);
        block.header.time = u32::MAX;
        let block = finish(block, &params);
        emit(
            &mut manifest,
            outdir,
            "13-time-too-new",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-version: nVersion below the BIP34 floor (regtest requires >= 2 at
    // height 1).
    {
        let mut block = draft_block(&params, vec![regtest_coinbase(1)]);
        block.header.version = 1;
        let block = finish(block, &params);
        emit(
            &mut manifest,
            outdir,
            "14-bad-version",
            &block,
            &mut state,
            now,
        )?;
    }

    // -- CheckBlock ----------------------------------------------------------

    // bad-txnmrklroot: the committed root doesn't match the transaction list.
    let mutated_header;
    {
        let mut block = draft_block(&params, vec![regtest_coinbase(1)]);
        let mut bytes = block.header.merkle_root.to_bytes();
        bytes[0] ^= 0xff;
        block.header.merkle_root = MerkleRoot::from_bytes(bytes);
        grind(&mut block, &params);
        mutated_header = block.header;
        emit(
            &mut manifest,
            outdir,
            "20-bad-txnmrklroot",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-txns-duplicate: an identical transaction pair at *natural* even leaf
    // positions (2,3) trips the CVE-2012-2459 merkle-mutation check. An odd-tail
    // pair like [cb, a, a] is only duplicated by the padding rule and is not
    // flagged — Core accepts it at CheckBlock (it would fail later, at
    // ConnectBlock, as a double-spend).
    {
        let mut other = spend_tx();
        other.inputs[0].previous_output = outpoint(2, 0);
        let block = draft_block(
            &params,
            vec![regtest_coinbase(1), other, spend_tx(), spend_tx()],
        );
        let block = finish(block, &params);
        emit(
            &mut manifest,
            outdir,
            "21-bad-txns-duplicate",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-blk-length: zero transactions. The committed root matches the
    // degenerate (all-zero) merkle result so the size rule is what fires.
    {
        let block = finish(draft_block(&params, Vec::new()), &params);
        emit(
            &mut manifest,
            outdir,
            "22-bad-blk-length",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-cb-missing: the first transaction is not a coinbase.
    {
        let block = finish(draft_block(&params, vec![spend_tx()]), &params);
        emit(
            &mut manifest,
            outdir,
            "23-bad-cb-missing",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-cb-multiple: a second, different coinbase later in the block.
    {
        let mut cb2 = regtest_coinbase(1);
        cb2.inputs[0].script_sig = Script::new(script::push_int(2));
        let block = finish(
            draft_block(&params, vec![regtest_coinbase(1), cb2]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "24-bad-cb-multiple",
            &block,
            &mut state,
            now,
        )?;
    }

    // -- CheckTransaction (per-transaction, non-coinbase position) ------------

    emit_tx_case(
        &mut manifest,
        outdir,
        "30-vin-empty",
        &params,
        &mut state,
        now,
        |tx| {
            tx.inputs.clear();
        },
    )?;
    emit_tx_case(
        &mut manifest,
        outdir,
        "31-vout-empty",
        &params,
        &mut state,
        now,
        |tx| {
            tx.outputs.clear();
        },
    )?;
    emit_tx_case(
        &mut manifest,
        outdir,
        "32-oversize",
        &params,
        &mut state,
        now,
        |tx| {
            tx.inputs[0].script_sig = Script::new(vec![0u8; 1_000_100]);
        },
    )?;
    emit_tx_case(
        &mut manifest,
        outdir,
        "33-vout-negative",
        &params,
        &mut state,
        now,
        |tx| {
            tx.outputs[0].value = -1;
        },
    )?;
    emit_tx_case(
        &mut manifest,
        outdir,
        "34-vout-toolarge",
        &params,
        &mut state,
        now,
        |tx| {
            tx.outputs[0].value = check::MAX_MONEY + 1;
        },
    )?;
    emit_tx_case(
        &mut manifest,
        outdir,
        "35-txouttotal-toolarge",
        &params,
        &mut state,
        now,
        |tx| {
            tx.outputs[0].value = check::MAX_MONEY;
            tx.outputs.push(txout(1, vec![script::OP_1]));
        },
    )?;
    emit_tx_case(
        &mut manifest,
        outdir,
        "36-inputs-duplicate",
        &params,
        &mut state,
        now,
        |tx| {
            tx.inputs.push(tx.inputs[0].clone());
        },
    )?;
    emit_tx_case(
        &mut manifest,
        outdir,
        "37-prevout-null",
        &params,
        &mut state,
        now,
        |tx| {
            tx.inputs.push(txin(outpoint(9, 1), vec![]));
            tx.inputs[1].previous_output = OutPoint::NULL;
        },
    )?;

    // bad-cb-length: the coinbase's scriptSig is under the 2-byte minimum.
    {
        let mut cb = regtest_coinbase(1);
        cb.inputs[0].script_sig = Script::new(vec![script::OP_1]);
        let block = finish(draft_block(&params, vec![cb]), &params);
        emit(
            &mut manifest,
            outdir,
            "39-cb-length",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-blk-sigops: legacy sigop cost above 80_000.
    {
        let mut tx = spend_tx();
        tx.outputs[0].script_pubkey = Script::new(vec![script::OP_CHECKSIG; 20_001]);
        let block = finish(draft_block(&params, vec![regtest_coinbase(1), tx]), &params);
        emit(
            &mut manifest,
            outdir,
            "40-bad-blk-sigops",
            &block,
            &mut state,
            now,
        )?;
    }

    // -- ContextualCheckBlock -------------------------------------------------

    // bad-txns-nonfinal: lock_time above the block height with a non-final
    // input sequence (height-based locktime needs no MTP).
    emit_tx_case(
        &mut manifest,
        outdir,
        "50-nonfinal",
        &params,
        &mut state,
        now,
        |tx| {
            tx.lock_time = 2;
            tx.inputs[0].sequence = 0;
        },
    )?;

    // bad-cb-height: the coinbase pushes height 2 at block height 1.
    {
        let mut cb = regtest_coinbase(1);
        let mut script_sig = script::push_int(2);
        script_sig.push(script::OP_1);
        cb.inputs[0].script_sig = Script::new(script_sig);
        let block = finish(draft_block(&params, vec![cb]), &params);
        emit(
            &mut manifest,
            outdir,
            "51-bad-cb-height",
            &block,
            &mut state,
            now,
        )?;
    }

    // unexpected-witness: witness data with no commitment (segwit active from
    // height 0 on regtest).
    {
        let mut tx = spend_tx();
        tx.inputs[0].witness = Witness::new(vec![vec![0xaa; 20], vec![0xbb; 33]]);
        let block = finish(draft_block(&params, vec![regtest_coinbase(1), tx]), &params);
        emit(
            &mut manifest,
            outdir,
            "52-unexpected-witness",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-witness-nonce-size: a commitment output exists but the coinbase's
    // witness stack isn't a single 32-byte item.
    {
        let mut cb = regtest_coinbase(1);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32], vec![0x00]]);
        let mut tx = spend_tx();
        tx.inputs[0].witness = Witness::new(vec![vec![0xaa; 20], vec![0xbb; 33]]);
        let mut block = draft_block(&params, vec![cb, tx]);
        let mut commit_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commit_script.extend_from_slice(&[0u8; 32]);
        block.transactions[0].outputs.push(txout(0, commit_script));
        fixup(&mut block, &params);
        emit(
            &mut manifest,
            outdir,
            "53-bad-witness-nonce-size",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-witness-merkle-match: valid nonce and commitment position, wrong hash.
    {
        let mut cb = regtest_coinbase(1);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let mut tx = spend_tx();
        tx.inputs[0].witness = Witness::new(vec![vec![0xaa; 20], vec![0xbb; 33]]);
        let mut block = draft_block(&params, vec![cb, tx]);
        let mut commit_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commit_script.extend_from_slice(&[0xee; 32]);
        block.transactions[0].outputs.push(txout(0, commit_script));
        fixup(&mut block, &params);
        emit(
            &mut manifest,
            outdir,
            "54-bad-witness-merkle-match",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-blk-weight: a ~4 MB witness item under a valid commitment — weight is
    // checked after witness-malleation verification in Core's order.
    {
        let mut cb = regtest_coinbase(1);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let mut tx = spend_tx();
        tx.inputs[0].witness = Witness::new(vec![vec![0u8; 4_000_100]]);
        let mut block = draft_block(&params, vec![cb, tx]);
        add_witness_commitment(&mut block, &params);
        emit(
            &mut manifest,
            outdir,
            "55-bad-blk-weight",
            &block,
            &mut state,
            now,
        )?;
    }

    // Positive control: witness data under a valid commitment is accepted.
    {
        let mut cb = regtest_coinbase(1);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let mut tx = spend_tx();
        tx.inputs[0].witness = Witness::new(vec![vec![0xaa; 20], vec![0xbb; 33]]);
        let mut block = draft_block(&params, vec![cb, tx]);
        add_witness_commitment(&mut block, &params);
        emit(
            &mut manifest,
            outdir,
            "56-valid-witness",
            &block,
            &mut state,
            now,
        )?;
    }

    // orphan: builds on an unknown parent — exercises the prev-blk-not-found /
    // inconclusive boundary between the two surfaces.
    {
        let mut block = draft_block(&params, vec![regtest_coinbase(1)]);
        block.header.prev_block_hash = BlockHash::from_bytes([0x77; 32]);
        let block = finish(block, &params);
        emit(&mut manifest, outdir, "57-orphan", &block, &mut state, now)?;
    }

    // duplicate: resubmitting 00-valid — our shared tree reports
    // `accepted-known`, the daemon's block index reports `duplicate`; both
    // normalize to `accepted`.
    {
        let (verdict, _detail) = validate(&valid, &mut state, now);
        manifest.push(("00-valid".to_string(), verdict));
    }

    // -- ConnectBlock (UTXO-dependent rules) ----------------------------------
    //
    // The daemon connects each of these blocks to its active chain, so
    // `ConnectBlock`'s verdict surfaces as the submitblock result. Our side
    // runs `connect_block` — including `check_input_scripts` — when the block
    // extends the connected tip; `state.connected` tracks it. The spends here
    // use anyone-can-spend (`OP_1`) prevouts with empty scriptSigs; the
    // signed-spend cases below cover the key-locked paths.
    //
    // Baseline: blocks h3..=h101 so the h1/h2 coinbases are mature (depth
    // >= 100) when the spend cases run at h102+.
    let mut coinbase_outs = vec![
        OutPoint {
            txid: valid.transactions[0].txid(),
            vout: 0,
        },
        OutPoint {
            txid: child.transactions[0].txid(),
            vout: 0,
        },
    ];
    let mut parent_header = child.header;
    for h in 3..=101u32 {
        let block = finish(draft_on(&parent_header, vec![regtest_coinbase(h)]), &params);
        coinbase_outs.push(OutPoint {
            txid: block.transactions[0].txid(),
            vout: 0,
        });
        parent_header = block.header;
        emit(
            &mut manifest,
            outdir,
            &format!("60-chain-{h:03}"),
            &block,
            &mut state,
            now,
        )?;
    }

    // Positive control at h102 (connects): spend the mature h1 coinbase for a
    // 1-sat fee, and a setup tx (h2 coinbase) creating one P2SH output plus
    // three anyone-can-spend outputs for the locktime/sigop cases below.
    let spend_h1 = Transaction {
        version: 1,
        inputs: vec![txin(coinbase_outs[0], vec![])],
        outputs: vec![txout(5_000_000_000 - 1, vec![script::OP_1])],
        lock_time: 0,
    };
    let mut p2sh_spk = vec![script::OP_HASH160, 0x14];
    p2sh_spk.extend_from_slice(&[0x33; 20]);
    p2sh_spk.push(script::OP_EQUAL);
    let setup = Transaction {
        version: 1,
        inputs: vec![txin(coinbase_outs[1], vec![])],
        outputs: vec![
            txout(1_000, p2sh_spk),
            txout(500, vec![script::OP_1]),
            txout(500, vec![script::OP_1]),
            txout(500, vec![script::OP_1]),
        ],
        lock_time: 0,
    };
    let block102 = finish(
        draft_on(&parent_header, vec![regtest_coinbase(102), spend_h1, setup]),
        &params,
    );
    emit(
        &mut manifest,
        outdir,
        "61-valid-spend",
        &block102,
        &mut state,
        now,
    )?;
    let setup_txid = block102.transactions[2].txid();
    let out = |vout: u32| OutPoint {
        txid: setup_txid,
        vout,
    };
    // After 61 connects, the daemon's tip is h102 — connect-failure cases must
    // extend it or they'd be side blocks judged "inconclusive".
    let case_parent = block102.header;

    // bad-txns-inputs-missingorspent: a never-created outpoint.
    {
        let tx = Transaction {
            version: 1,
            inputs: vec![txin(outpoint(0xde, 0), vec![])],
            outputs: vec![txout(1, vec![script::OP_1])],
            lock_time: 0,
        };
        let block = finish(
            draft_on(&case_parent, vec![regtest_coinbase(103), tx]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "62-missing-input",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-txns-inputs-missingorspent again: h1's coinbase was spent by 61.
    {
        let tx = Transaction {
            version: 1,
            inputs: vec![txin(coinbase_outs[0], vec![])],
            outputs: vec![txout(1, vec![script::OP_1])],
            lock_time: 0,
        };
        let block = finish(
            draft_on(&case_parent, vec![regtest_coinbase(103), tx]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "63-spent-input",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-txns-premature-spend-of-coinbase: h4's coinbase at h103 — depth 99.
    {
        let tx = Transaction {
            version: 1,
            inputs: vec![txin(coinbase_outs[3], vec![])],
            outputs: vec![txout(1, vec![script::OP_1])],
            lock_time: 0,
        };
        let block = finish(
            draft_on(&case_parent, vec![regtest_coinbase(103), tx]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "64-premature-coinbase",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-txns-in-belowout: spend the mature h3 coinbase creating more than its
    // input value.
    {
        let tx = Transaction {
            version: 1,
            inputs: vec![txin(coinbase_outs[2], vec![])],
            outputs: vec![txout(5_000_000_000 + 1, vec![script::OP_1])],
            lock_time: 0,
        };
        let block = finish(
            draft_on(&case_parent, vec![regtest_coinbase(103), tx]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "65-in-belowout",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-cb-amount: the coinbase pays subsidy + 1 with no fees in the block.
    let bad_cb;
    {
        let mut cb = regtest_coinbase(103);
        cb.outputs[0].value = 5_000_000_001;
        let block = finish(draft_on(&case_parent, vec![cb]), &params);
        bad_cb = block.clone();
        emit(
            &mut manifest,
            outdir,
            "66-cb-amount",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-txns-BIP30: block102's spend tx appears again; its output is still
    // unspent, so the pre-scan rejects before input checks.
    {
        let dup = block102.transactions[1].clone();
        let block = finish(
            draft_on(&case_parent, vec![regtest_coinbase(103), dup]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "67-bip30-duplicate",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-txns-nonfinal (BIP68 height lock): a h102 coin (created by 61),
    // sequence = 200 height units — min height 102 + 200 - 1 = 301 >= 103.
    {
        let tx = Transaction {
            version: 2,
            inputs: vec![txin_seq(out(1), 200)],
            outputs: vec![txout(1, vec![script::OP_1])],
            lock_time: 0,
        };
        let block = finish(
            draft_on(&case_parent, vec![regtest_coinbase(103), tx]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "68-bip68-nonfinal",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-txns-nonfinal (BIP68 time lock): a h102 coin, sequence = TYPE|1 —
    // min time = coin-MTP + 512 - 1, far beyond the parent MTP (corpus blocks
    // tick at +1 s).
    {
        let tx = Transaction {
            version: 2,
            inputs: vec![txin_seq(out(2), connect::SEQUENCE_LOCKTIME_TYPE_FLAG | 1)],
            outputs: vec![txout(1, vec![script::OP_1])],
            lock_time: 0,
        };
        let block = finish(
            draft_on(&case_parent, vec![regtest_coinbase(103), tx]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "69-bip68-time-nonfinal",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-blk-sigops (P2SH): spending `out(0)` — the P2SH coin — with a
    // 20_001-CHECKSIG redeem script costs 20_001 * 4 > 80_000. The daemon's
    // sigop check fires before script evaluation, so the redeem body never
    // runs there and our stubbed script layer is not divergent.
    {
        let redeem = vec![script::OP_CHECKSIG; 20_001];
        let tx = Transaction {
            version: 1,
            inputs: vec![txin(out(0), script::push_slice(&redeem))],
            outputs: vec![txout(999, vec![script::OP_1])],
            lock_time: 0,
        };
        let block = finish(
            draft_on(&case_parent, vec![regtest_coinbase(103), tx]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "70-p2sh-sigops",
            &block,
            &mut state,
            now,
        )?;
    }

    // bad-blk-sigops (witness): an in-block setup creates a P2WSH-looking coin
    // (h3 coinbase input — mature at h103), then a spend whose witness script
    // holds 80_001 CHECKSIGs costs 80_001 > 80_000 under WITNESS accounting.
    // The block carries a valid witness commitment so the sigop rule — not
    // unexpected-witness — is what fires.
    {
        let witness_script = vec![script::OP_CHECKSIG; 80_001];
        let mut wsh_spk = vec![script::OP_0, 0x20];
        wsh_spk.extend_from_slice(&[0x55; 32]);
        let setup_wsh = Transaction {
            version: 1,
            inputs: vec![txin(coinbase_outs[2], vec![])],
            outputs: vec![txout(1_000, wsh_spk)],
            lock_time: 0,
        };
        let wsh_out = OutPoint {
            txid: setup_wsh.txid(),
            vout: 0,
        };
        let mut spend = Transaction {
            version: 1,
            inputs: vec![txin(wsh_out, vec![])],
            outputs: vec![txout(999, vec![script::OP_1])],
            lock_time: 0,
        };
        spend.inputs[0].witness = Witness::new(vec![Vec::new(), witness_script]);
        let mut cb = regtest_coinbase(103);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let mut block = draft_on(&case_parent, vec![cb, setup_wsh, spend]);
        add_witness_commitment(&mut block, &params);
        emit(
            &mut manifest,
            outdir,
            "71-witness-sigops",
            &block,
            &mut state,
            now,
        )?;
    }

    // Positive controls at h103 (connects): a satisfied BIP68 height lock
    // (sequence 1 on a h102 coin — min height 102 < 103) and a sequence with
    // the disable flag set (not a lock at all).
    let signed_parent;
    {
        let tx_ok = Transaction {
            version: 2,
            inputs: vec![txin_seq(out(1), 1)],
            outputs: vec![txout(1, vec![script::OP_1])],
            lock_time: 0,
        };
        let tx_disabled = Transaction {
            version: 2,
            inputs: vec![txin_seq(
                out(2),
                connect::SEQUENCE_LOCKTIME_DISABLE_FLAG | 200,
            )],
            outputs: vec![txout(1, vec![script::OP_1])],
            lock_time: 0,
        };
        let block = finish(
            draft_on(
                &case_parent,
                vec![regtest_coinbase(103), tx_ok, tx_disabled],
            ),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "72-bip68-ok",
            &block,
            &mut state,
            now,
        )?;
        // 72 connects — the signed-spend chain below extends its tip.
        signed_parent = block.header;
    }

    // -- signed spends --------------------------------------------------------
    // Real signature-verification coverage (see `emit_signed_spends`): a
    // funding tx creates key-locked outputs of every standard type, then one
    // block per spend connects on top so the daemon runs CheckInputScripts.
    emit_signed_spends(
        &mut manifest,
        outdir,
        signed_parent,
        coinbase_outs[3],
        &params,
        &mut state,
        now,
    )?;

    // -- failed-block bookkeeping --------------------------------------------
    // Core marks a block that fails CheckBlock/ContextualCheckBlock/ConnectBlock
    // BLOCK_FAILED_VALID: resubmitting it is `duplicate-invalid`, and every
    // descendant is `bad-prevblk` at AcceptBlockHeader — including descendants
    // reached only through the failed-ancestor walk over unmarked parents.
    emit(
        &mut manifest,
        outdir,
        "82-invalid-resubmit",
        &bad_cb,
        &mut state,
        now,
    )?;

    // A child of the connect-failed `66-cb-amount`: header insertion meets a
    // failed direct parent.
    {
        let child = finish(
            draft_on(&bad_cb.header, vec![regtest_coinbase(104)]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "83-child-of-invalid",
            &child,
            &mut state,
            now,
        )?;
    }

    // A child of `10-high-hash`: that header never entered the index, so this
    // is an orphan — `prev-blk-not-found`, not `bad-prevblk`.
    {
        let child = finish(
            draft_on(&high_hash_header, vec![regtest_coinbase(2)]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "84-child-of-unknown-header",
            &child,
            &mut state,
            now,
        )?;
    }

    // A child of `20-bad-txnmrklroot`: `ProcessNewBlock` runs `CheckBlock`
    // before `AcceptBlock`, so a CheckBlock failure never enters the index at
    // all — the child is an orphan (`prev-blk-not-found`), same as a child of
    // a header-rejected block.
    {
        let child = finish(
            draft_on(&mutated_header, vec![regtest_coinbase(2)]),
            &params,
        );
        emit(
            &mut manifest,
            outdir,
            "85-child-of-mutated",
            &child,
            &mut state,
            now,
        )?;
    }

    // Reorg: a 104-block branch on genesis outworks the connected tip (h110) —
    // both sides disconnect the 103-block main chain and connect 104 fork
    // blocks. Fork coinbases carry a tag byte so their txids (and headers)
    // differ from the main chain's. Fork blocks f1..f103 arrive as
    // heavier-branch precursors and are judged side blocks; f104 triggers the
    // reorg.
    let mut fork_parent = params.genesis_header;
    for h in 1..=104u32 {
        let mut cb = regtest_coinbase(h);
        cb.inputs[0].script_sig = Script::new(
            [
                script::push_int(i64::from(h)).as_slice(),
                &[script::OP_1, 0x01, 0xf0],
            ]
            .concat(),
        );
        let block = finish(draft_on(&fork_parent, vec![cb]), &params);
        fork_parent = block.header;
        emit(
            &mut manifest,
            outdir,
            &format!("80-fork-{h:03}"),
            &block,
            &mut state,
            now,
        )?;
    }

    // Hand-rolled manifest: `[{"file": ..., "expected_verdict": ...}]` — no JSON
    // dependency in this example.
    let mut json = String::from("[\n");
    for (i, (name, verdict)) in manifest.iter().enumerate() {
        let sep = if i + 1 == manifest.len() { "" } else { "," };
        json.push_str(&format!(
            "  {{\"file\": \"{name}.bin\", \"expected_verdict\": \"{verdict}\"}}{sep}\n"
        ));
    }
    json.push_str("]\n");
    fs::write(outdir.join("manifest.json"), json).map_err(|e| format!("write manifest: {e}"))
}

/// `gen-assumevalid-corpus` — a headers-first scenario exercising
/// `Chainstate::script_checks` (Core's assumevalid `fScriptChecks` path in
/// `ConnectBlock`).
///
/// * `headers.bin` — the raw 80-byte headers of the full chain, heights
///   1..=2160 (genesis is already indexed on both sides).
/// * `blocks.dat` — blk.dat-framed bodies for heights 1..=130 only (the
///   genesis body is never connected on either side; the segment suites
///   already cover its resubmission verdict).
/// * `manifest.json` — the assumevalid hash (block 120) and case notes.
///
/// Block 1's coinbase pays two zero-value `OP_0` (always-false) outputs in
/// addition to its subsidy output. Block 110 — strictly below the assumevalid
/// height — spends `OP_0` output v1: script checks are skipped on both sides,
/// so the block connects despite the unsatisfiable spend. Block 130 — above
/// the assumevalid height — spends v2 and is rejected
/// `mandatory-script-verify-flag-failed` on both sides, pinning the gate's
/// threshold.
fn gen_assumevalid_corpus(outdir: &Path, now: u32) -> Result<(), String> {
    const LAST_BODY: u32 = 130;
    const ASSUMEVALID_HEIGHT: u32 = 120;
    const LAST_HEADER: u32 = 2160; // 2030 blocks above the last body — >2017 blocks of proof-equivalent time
    const REGTEST_MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];

    let mut params = Network::Regtest.params();
    let mut blocks: Vec<Block> = Vec::new();
    let mut parent = params.genesis_header;
    let mut assumevalid_hash = String::new();
    let mut funding_txid = Txid::from_bytes([0; 32]);
    let mut headers_bin = Vec::new();
    let mut blocks_dat = Vec::new();

    for height in 1..=LAST_HEADER {
        let block = {
            let mut coinbase = regtest_coinbase(height);
            if height == 1 {
                // v1/v2: zero-value always-false outputs spent by the two
                // probe blocks — spendable only while script checks skip.
                coinbase.outputs.push(txout(0, vec![script::OP_0]));
                coinbase.outputs.push(txout(0, vec![script::OP_0]));
            }
            let mut txs = vec![coinbase];
            if height == 110 || height == 130 {
                let vout = if height == 110 { 1 } else { 2 };
                txs.push(Transaction {
                    version: 1,
                    inputs: vec![txin(
                        OutPoint {
                            txid: funding_txid,
                            vout,
                        },
                        vec![],
                    )],
                    outputs: vec![txout(0, vec![script::OP_1])],
                    lock_time: 0,
                });
            }
            finish(draft_on(&parent, txs), &params)
        };
        if height == 1 {
            funding_txid = block.transactions[0].txid();
        }
        if height == ASSUMEVALID_HEIGHT {
            assumevalid_hash = block.block_hash().to_string();
        }
        headers_bin.extend_from_slice(&block.header.encode());
        if height <= LAST_BODY {
            let payload = block.encode();
            blocks_dat.extend_from_slice(&REGTEST_MAGIC);
            blocks_dat.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            blocks_dat.extend_from_slice(&payload);
            blocks.push(block.clone());
        }
        parent = block.header;
    }
    params.assume_valid = Some(
        assumevalid_hash
            .parse()
            .map_err(|_| "unparseable assumevalid hash".to_string())?,
    );

    // Self-check, mirroring the driver: headers first, then bodies.
    let mut state = Chainstate::new(&params);
    {
        let mut header_bytes = headers_bin.as_slice();
        let mut index = 1u32;
        while !header_bytes.is_empty() {
            let header = BlockHeader::decode(&header_bytes[..80])
                .map_err(|e| format!("corpus header {index} decode: {e}"))?;
            state
                .accept_header(&header, now)
                .map_err(|err| format!("corpus header {index} rejected: {}", err.reason()))?;
            header_bytes = &header_bytes[80..];
            index += 1;
        }
    }
    for block in &blocks {
        let height = state
            .tree()
            .get(&block.block_hash())
            .map(|n| n.height)
            .unwrap_or(0);
        match state.accept_block(block, now) {
            Ok(_) if height == 130 => {
                return Err("verify-case block unexpectedly connected".to_string());
            }
            Ok(_) => {}
            Err(err) if height == 130 => {
                if !matches!(err, BlockRejection::Connect(ConnectError::ScriptVerify(_))) {
                    return Err(format!(
                        "verify-case block failed with the wrong gate: {}",
                        err.reason()
                    ));
                }
            }
            Err(err) => {
                return Err(format!("corpus block {height} rejected: {}", err.reason()));
            }
        }
    }

    fs::write(outdir.join("headers.bin"), headers_bin)
        .map_err(|e| format!("write headers.bin: {e}"))?;
    fs::write(outdir.join("blocks.dat"), blocks_dat)
        .map_err(|e| format!("write blocks.dat: {e}"))?;
    let manifest = format!(
        "{{\n  \"network\": \"regtest\",\n  \"assumevalid\": \"{assumevalid_hash}\",\n  \"assumevalid_height\": {ASSUMEVALID_HEIGHT},\n  \"header_count\": {LAST_HEADER},\n  \"body_count\": {},\n  \"skip_case_height\": 110,\n  \"verify_case_height\": {LAST_BODY}\n}}\n",
        LAST_BODY
    );
    fs::write(outdir.join("manifest.json"), manifest).map_err(|e| format!("write manifest: {e}"))
}

/// Emits the signed-spend corpus cases (73–79 plus the 81 negative control)
/// extending `parent`. `fund_input` must name a mature, unspent coinbase
/// output.
///
/// Keys and signatures are produced with rust-bitcoin's `SighashCache` +
/// `secp256k1` — implementations independent of this crate's sighash code —
/// so a daemon-accepted spend proves end-to-end agreement, not
/// self-consistency.
#[allow(clippy::unwrap_used, clippy::expect_used)]
fn emit_signed_spends(
    manifest: &mut Vec<(String, String)>,
    outdir: &Path,
    parent: BlockHeader,
    fund_input: OutPoint,
    params: &Params,
    state: &mut Chainstate,
    now: u32,
) -> Result<(), String> {
    use bitcoin::hashes::Hash as _;
    let mut signed_parent = parent;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x77; 32]).unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let pk_bytes = pk.serialize();
    let pk_hash160 = {
        use bitcoin::hashes::Hash as _;
        bitcoin::hashes::hash160::Hash::hash(&pk_bytes).to_byte_array()
    };
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk);
    let (internal_key, _) = keypair.x_only_public_key();

    // `OP_DUP OP_HASH160 <h160(pk)> OP_EQUALVERIFY OP_CHECKSIG`.
    let p2pkh_spk =
        Script::new([[0x76, 0xa9, 0x14].as_slice(), &pk_hash160, &[0x88, 0xac]].concat());
    // P2WPKH program.
    let p2wpkh_spk = Script::new([[0x00, 0x14].as_slice(), &pk_hash160].concat());
    // P2WSH: witness script `<pk> OP_CHECKSIG`.
    let p2wsh_script = Script::new([[0x21].as_slice(), &pk_bytes, &[0xac]].concat());
    let p2wsh_spk = Script::new(
        [
            [0x00, 0x20].as_slice(),
            &avila_consensus::hash::sha256(p2wsh_script.as_bytes()),
        ]
        .concat(),
    );
    // P2TR key path: tweaked internal key, no script tree.
    let (p2tr_key_spk, tweaked_keypair) = {
        let tweak = {
            use sha2::Digest as _;
            let tag = avila_consensus::hash::sha256(b"TapTweak");
            let mut h = sha2::Sha256::new();
            h.update(tag);
            h.update(tag);
            h.update(internal_key.serialize());
            let r: [u8; 32] = h.finalize().into();
            r
        };
        let scalar = bitcoin::secp256k1::Scalar::from_be_bytes(tweak).unwrap();
        let tweaked = keypair.add_xonly_tweak(&secp, &scalar).unwrap();
        let (out_key, _) = tweaked.x_only_public_key();
        (
            Script::new([[0x51, 0x20].as_slice(), &out_key.serialize()].concat()),
            tweaked,
        )
    };
    // P2TR script path: single leaf `<xonly leaf pk> OP_CHECKSIG` — the leaf
    // key signs (untweaked); the output key is the internal key tweaked by
    // TapTweak(internal || leaf_hash). The control block is leaf_ver|parity +
    // internal key with no path nodes (single-leaf tree).
    let leaf_sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x88; 32]).unwrap();
    let leaf_keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &leaf_sk);
    let (leaf_key, _) = leaf_keypair.x_only_public_key();
    let tap_script = Script::new([[0x20].as_slice(), &leaf_key.serialize(), &[0xac]].concat());
    let leaf_hash = avila_consensus::interpreter::compute_tapleaf_hash(0xc0, tap_script.as_bytes());
    let (p2tr_script_spk, control_block) = {
        let tweak = {
            use sha2::Digest as _;
            let tag = avila_consensus::hash::sha256(b"TapTweak");
            let mut h = sha2::Sha256::new();
            h.update(tag);
            h.update(tag);
            h.update(internal_key.serialize());
            h.update(leaf_hash);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        let scalar = bitcoin::secp256k1::Scalar::from_be_bytes(tweak).unwrap();
        let (out_key, parity) = internal_key.add_tweak(&secp, &scalar).unwrap();
        let mut control = vec![0xc0 | parity.to_u8()];
        control.extend_from_slice(&internal_key.serialize());
        (
            Script::new([[0x51, 0x20].as_slice(), &out_key.serialize()].concat()),
            control,
        )
    };
    // P2SH-P2WPKH: redeem = the witness program; spk = HASH160 <h160(redeem)>.
    let p2sh_p2wpkh_redeem = p2wpkh_spk.as_bytes().to_vec();
    let p2sh_p2wpkh_spk = Script::new(
        [
            [0xa9, 0x14].as_slice(),
            &bitcoin::hashes::hash160::Hash::hash(&p2sh_p2wpkh_redeem).to_byte_array(),
            &[0x87],
        ]
        .concat(),
    );
    // Bare P2SH: redeem = `<pk> OP_CHECKSIG`.
    let p2sh_redeem = Script::new([[0x21].as_slice(), &pk_bytes, &[0xac]].concat());
    let p2sh_spk2 = Script::new(
        [
            [0xa9, 0x14].as_slice(),
            &bitcoin::hashes::hash160::Hash::hash(p2sh_redeem.as_bytes()).to_byte_array(),
            &[0x87],
        ]
        .concat(),
    );

    // 73-fund: spend the mature h4 coinbase into all the keyed outputs above.
    let fund = Transaction {
        version: 1,
        inputs: vec![txin(fund_input, vec![])],
        outputs: vec![
            txout(100_000, p2pkh_spk.as_bytes().to_vec()),    // v0
            txout(100_000, p2wpkh_spk.as_bytes().to_vec()),   // v1
            txout(100_000, p2wsh_spk.as_bytes().to_vec()),    // v2
            txout(100_000, p2tr_key_spk.as_bytes().to_vec()), // v3
            txout(100_000, p2tr_script_spk.as_bytes().to_vec()), // v4
            txout(100_000, p2sh_p2wpkh_spk.as_bytes().to_vec()), // v5
            txout(100_000, p2sh_spk2.as_bytes().to_vec()),    // v6
            txout(100_000, p2pkh_spk.as_bytes().to_vec()),    // v7
            txout(4_900_000_000, vec![script::OP_1]),         // change
        ],
        lock_time: 0,
    };
    let fund_txid = fund.txid();
    {
        let block = finish(
            draft_on(&signed_parent, vec![regtest_coinbase(104), fund]),
            params,
        );
        emit(manifest, outdir, "73-fund", &block, state, now)?;
        signed_parent = block.header;
    }
    let spent_outs = |vout: u32| OutPoint {
        txid: fund_txid,
        vout,
    };
    let fund_outs = [
        txout(100_000, p2pkh_spk.as_bytes().to_vec()),
        txout(100_000, p2wpkh_spk.as_bytes().to_vec()),
        txout(100_000, p2wsh_spk.as_bytes().to_vec()),
        txout(100_000, p2tr_key_spk.as_bytes().to_vec()),
        txout(100_000, p2tr_script_spk.as_bytes().to_vec()),
        txout(100_000, p2sh_p2wpkh_spk.as_bytes().to_vec()),
        txout(100_000, p2sh_spk2.as_bytes().to_vec()),
    ];

    // Signing helpers: sighashes come from rust-bitcoin's SighashCache —
    // independent of this crate's sighash code, so a daemon-accepted spend is
    // end-to-end agreement, not self-consistency.
    fn btc_tx(tx: &Transaction) -> bitcoin::Transaction {
        bitcoin::consensus::deserialize(&tx.encode()).expect("encoding parses")
    }
    fn btc_txout(o: &TxOut) -> bitcoin::TxOut {
        bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(o.value as u64),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(o.script_pubkey.as_bytes().to_vec()),
        }
    }
    fn sign_ecdsa(
        secp: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
        sk: &bitcoin::secp256k1::SecretKey,
        sighash: &[u8; 32],
        hash_byte: u8,
    ) -> Vec<u8> {
        let msg = bitcoin::secp256k1::Message::from_digest_slice(sighash).unwrap();
        let mut sig = secp.sign_ecdsa(&msg, sk).serialize_der().to_vec();
        sig.push(hash_byte);
        sig
    }

    // 74-spend-p2pkh (legacy sighash, scriptSig-signed).
    {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![txin(spent_outs(0), vec![])],
            outputs: vec![txout(99_000, vec![script::OP_1])],
            lock_time: 0,
        };
        let sighash = bitcoin::sighash::SighashCache::new(&btc_tx(&tx))
            .legacy_signature_hash(
                0,
                &bitcoin::ScriptBuf::from_bytes(p2pkh_spk.as_bytes().to_vec()),
                1,
            )
            .unwrap()
            .to_byte_array();
        let sig = sign_ecdsa(&secp, &sk, &sighash, 1);
        let mut script_sig = script::push_slice(&sig);
        script_sig.extend_from_slice(&script::push_slice(&pk_bytes));
        tx.inputs[0].script_sig = Script::new(script_sig);
        let block = finish(
            draft_on(&signed_parent, vec![regtest_coinbase(105), tx]),
            params,
        );
        emit(manifest, outdir, "74-spend-p2pkh", &block, state, now)?;
        signed_parent = block.header;
    }

    // 75-spend-p2wpkh (BIP143 sighash, witness-carried).
    {
        let mut tx = Transaction {
            version: 2,
            inputs: vec![txin(spent_outs(1), vec![])],
            outputs: vec![txout(99_000, vec![script::OP_1])],
            lock_time: 0,
        };
        let sighash = bitcoin::sighash::SighashCache::new(&btc_tx(&tx))
            .p2wpkh_signature_hash(
                0,
                &bitcoin::ScriptBuf::from_bytes(p2wpkh_spk.as_bytes().to_vec()),
                bitcoin::Amount::from_sat(100_000),
                bitcoin::sighash::EcdsaSighashType::All,
            )
            .unwrap()
            .to_byte_array();
        let sig = sign_ecdsa(&secp, &sk, &sighash, 1);
        tx.inputs[0].witness = Witness::new(vec![sig, pk_bytes.to_vec()]);
        let mut cb = regtest_coinbase(106);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let mut block = draft_on(&signed_parent, vec![cb, tx]);
        add_witness_commitment(&mut block, params);
        emit(manifest, outdir, "75-spend-p2wpkh", &block, state, now)?;
        signed_parent = block.header;
    }

    // 76-spend-p2wsh (witness script `<pk> CHECKSIG`).
    {
        let mut tx = Transaction {
            version: 2,
            inputs: vec![txin(spent_outs(2), vec![])],
            outputs: vec![txout(99_000, vec![script::OP_1])],
            lock_time: 0,
        };
        let sighash = bitcoin::sighash::SighashCache::new(&btc_tx(&tx))
            .p2wsh_signature_hash(
                0,
                &bitcoin::ScriptBuf::from_bytes(p2wsh_script.as_bytes().to_vec()),
                bitcoin::Amount::from_sat(100_000),
                bitcoin::sighash::EcdsaSighashType::All,
            )
            .unwrap()
            .to_byte_array();
        let sig = sign_ecdsa(&secp, &sk, &sighash, 1);
        tx.inputs[0].witness = Witness::new(vec![sig, p2wsh_script.as_bytes().to_vec()]);
        let mut cb = regtest_coinbase(107);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let mut block = draft_on(&signed_parent, vec![cb, tx]);
        add_witness_commitment(&mut block, params);
        emit(manifest, outdir, "76-spend-p2wsh", &block, state, now)?;
        signed_parent = block.header;
    }

    // 77-spend-p2tr-key (BIP341 key path — tweaked key signs).
    {
        let mut tx = Transaction {
            version: 2,
            inputs: vec![txin(spent_outs(3), vec![])],
            outputs: vec![txout(99_000, vec![script::OP_1])],
            lock_time: 0,
        };
        let prevouts: Vec<bitcoin::TxOut> = vec![btc_txout(&fund_outs[3])];
        let sighash = bitcoin::sighash::SighashCache::new(&btc_tx(&tx))
            .taproot_key_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                bitcoin::sighash::TapSighashType::Default,
            )
            .unwrap()
            .to_byte_array();
        let msg = bitcoin::secp256k1::Message::from_digest_slice(&sighash).unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked_keypair);
        tx.inputs[0].witness = Witness::new(vec![sig.serialize().to_vec()]);
        let mut cb = regtest_coinbase(108);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let mut block = draft_on(&signed_parent, vec![cb, tx]);
        add_witness_commitment(&mut block, params);
        emit(manifest, outdir, "77-spend-p2tr-key", &block, state, now)?;
        signed_parent = block.header;
    }

    // 78-spend-p2tr-script (BIP342 script path — leaf key signs).
    {
        let mut tx = Transaction {
            version: 2,
            inputs: vec![txin(spent_outs(4), vec![])],
            outputs: vec![txout(99_000, vec![script::OP_1])],
            lock_time: 0,
        };
        let prevouts: Vec<bitcoin::TxOut> = vec![btc_txout(&fund_outs[4])];
        let sighash = bitcoin::sighash::SighashCache::new(&btc_tx(&tx))
            .taproot_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                None,
                Some((
                    bitcoin::taproot::TapLeafHash::from_byte_array(leaf_hash),
                    0xffff_ffff,
                )),
                bitcoin::sighash::TapSighashType::Default,
            )
            .unwrap()
            .to_byte_array();
        let msg = bitcoin::secp256k1::Message::from_digest_slice(&sighash).unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &leaf_keypair);
        tx.inputs[0].witness = Witness::new(vec![
            sig.serialize().to_vec(),
            tap_script.as_bytes().to_vec(),
            control_block.clone(),
        ]);
        let mut cb = regtest_coinbase(109);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let mut block = draft_on(&signed_parent, vec![cb, tx]);
        add_witness_commitment(&mut block, params);
        emit(manifest, outdir, "78-spend-p2tr-script", &block, state, now)?;
        signed_parent = block.header;
    }

    // 79-spend-p2sh-p2wpkh (nested segwit: scriptSig = redeem push only).
    {
        let mut tx = Transaction {
            version: 2,
            inputs: vec![txin(spent_outs(5), vec![])],
            outputs: vec![txout(99_000, vec![script::OP_1])],
            lock_time: 0,
        };
        let sighash = bitcoin::sighash::SighashCache::new(&btc_tx(&tx))
            .p2wpkh_signature_hash(
                0,
                &bitcoin::ScriptBuf::from_bytes(p2wpkh_spk.as_bytes().to_vec()),
                bitcoin::Amount::from_sat(100_000),
                bitcoin::sighash::EcdsaSighashType::All,
            )
            .unwrap()
            .to_byte_array();
        let sig = sign_ecdsa(&secp, &sk, &sighash, 1);
        tx.inputs[0].script_sig = Script::new(script::push_slice(&p2sh_p2wpkh_redeem));
        tx.inputs[0].witness = Witness::new(vec![sig, pk_bytes.to_vec()]);
        let mut cb = regtest_coinbase(110);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let mut block = draft_on(&signed_parent, vec![cb, tx]);
        add_witness_commitment(&mut block, params);
        emit(manifest, outdir, "79-spend-p2sh-p2wpkh", &block, state, now)?;
        signed_parent = block.header;
    }

    // 81-p2sh-badsig: the bare-P2SH spend with a corrupted signature — the
    // daemon rejects with mandatory-script-verify-flag-failed; our side must
    // produce the same reason. (Not connected; parent stays the tip.)
    {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![txin(spent_outs(6), vec![])],
            outputs: vec![txout(99_000, vec![script::OP_1])],
            lock_time: 0,
        };
        let sighash = bitcoin::sighash::SighashCache::new(&btc_tx(&tx))
            .legacy_signature_hash(
                0,
                &bitcoin::ScriptBuf::from_bytes(p2sh_redeem.as_bytes().to_vec()),
                1,
            )
            .unwrap()
            .to_byte_array();
        let mut sig = sign_ecdsa(&secp, &sk, &sighash, 1);
        // Corrupt a middle byte of the DER payload — still DER-valid, wrong sig.
        sig[20] ^= 1;
        let mut script_sig = script::push_slice(&sig);
        script_sig.extend_from_slice(&script::push_slice(p2sh_redeem.as_bytes()));
        tx.inputs[0].script_sig = Script::new(script_sig);
        let block = finish(
            draft_on(&signed_parent, vec![regtest_coinbase(111), tx]),
            params,
        );
        emit(manifest, outdir, "81-p2sh-badsig", &block, state, now)?;
    }

    // 82-high-s-p2pkh: a valid P2PKH spend whose signature carries a *high* S
    // (s -> n - s). LOW_S is mempool policy, not a block flag, so Core's
    // CPubKey::Verify normalizes before verifying (pubkey.cpp:283) — both
    // sides must accept. This case exists because real mainnet history
    // contains high-S signatures (e.g. block 183's spend).
    {
        let mut tx = Transaction {
            version: 1,
            inputs: vec![txin(spent_outs(7), vec![])],
            outputs: vec![txout(99_000, vec![script::OP_1])],
            lock_time: 0,
        };
        let sighash = bitcoin::sighash::SighashCache::new(&btc_tx(&tx))
            .legacy_signature_hash(
                0,
                &bitcoin::ScriptBuf::from_bytes(p2pkh_spk.as_bytes().to_vec()),
                1,
            )
            .unwrap()
            .to_byte_array();
        let mut sig = sign_ecdsa(&secp, &sk, &sighash, 1);
        // Flip S to n - S: compact r||s, subtract s from the group order,
        // re-encode DER, re-append the sighash byte.
        let low = bitcoin::secp256k1::ecdsa::Signature::from_der(&sig[..sig.len() - 1]).unwrap();
        let compact = low.serialize_compact();
        const ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut high = [0u8; 64];
        high[..32].copy_from_slice(&compact[..32]);
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = ORDER[i] as i16 - compact[32 + i] as i16 - borrow;
            if d < 0 {
                high[32 + i] = (d + 256) as u8;
                borrow = 1;
            } else {
                high[32 + i] = d as u8;
                borrow = 0;
            }
        }
        let high_sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&high).unwrap();
        sig = high_sig.serialize_der().to_vec();
        sig.push(1);
        let mut script_sig = script::push_slice(&sig);
        script_sig.extend_from_slice(&script::push_slice(&pk_bytes));
        tx.inputs[0].script_sig = Script::new(script_sig);
        let block = finish(
            draft_on(&signed_parent, vec![regtest_coinbase(111), tx]),
            params,
        );
        emit(manifest, outdir, "82-high-s-p2pkh", &block, state, now)?;
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check") if args.len() == 4 => {
            let Some(net) = network(&args[1]) else {
                eprintln!("unknown network {:?}", args[1]);
                return ExitCode::FAILURE;
            };
            let Ok(now) = args[3].parse::<u32>() else {
                eprintln!("invalid <now> timestamp {:?}", args[3]);
                return ExitCode::FAILURE;
            };
            let bytes = match fs::read(&args[2]) {
                Ok(bytes) => bytes,
                Err(err) => {
                    eprintln!("cannot read {}: {err}", args[2]);
                    return ExitCode::FAILURE;
                }
            };
            let mut state = Chainstate::new(&net.params());
            match Block::decode(&bytes) {
                Ok(block) => {
                    let (verdict, detail) = validate(&block, &mut state, now);
                    println!("{verdict}\t{detail}");
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    println!("rejected:decode\t{err}");
                    ExitCode::SUCCESS
                }
            }
        }
        Some("check-many") if args.len() >= 4 => {
            let Some(net) = network(&args[1]) else {
                eprintln!("unknown network {:?}", args[1]);
                return ExitCode::FAILURE;
            };
            let Ok(now) = args[2].parse::<u32>() else {
                eprintln!("invalid <now> timestamp {:?}", args[2]);
                return ExitCode::FAILURE;
            };
            // One chain state across all inputs — stateful, like the daemon's
            // block index + chainstate — so duplicates are reported
            // `accepted-known` and later blocks may build on and connect
            // earlier accepted ones.
            let mut state = Chainstate::new(&net.params());
            for path in &args[3..] {
                let name = Path::new(path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                let verdict_line = match fs::read(path)
                    .map_err(|e| e.to_string())
                    .and_then(|bytes| Block::decode(&bytes).map_err(|e| format!("decode\t{e}")))
                {
                    Ok(block) => {
                        let (verdict, detail) = validate(&block, &mut state, now);
                        format!("{verdict}\t{detail}")
                    }
                    Err(err) => format!("rejected:{err}"),
                };
                println!("{name}\t{verdict_line}");
            }
            ExitCode::SUCCESS
        }
        Some("replay") if args.len() >= 4 => {
            let Some(net) = network(&args[1]) else {
                eprintln!("unknown network {:?}", args[1]);
                return ExitCode::FAILURE;
            };
            let Ok(now) = args[3].parse::<u32>() else {
                eprintln!("invalid <now> timestamp {:?}", args[3]);
                return ExitCode::FAILURE;
            };
            let data = match fs::read(&args[2]) {
                Ok(data) => data,
                Err(err) => {
                    eprintln!("cannot read {}: {err}", args[2]);
                    return ExitCode::FAILURE;
                }
            };
            // Optional headers-first intake and an assumevalid override —
            // `Chainstate::script_checks` only skips when the best header sits
            // far enough above the connected block, so exercising that path
            // needs headers indexed before bodies arrive (Core's real sync
            // order).
            let mut params = net.params();
            let mut header_bytes: Option<Vec<u8>> = None;
            let mut store_dir: Option<std::path::PathBuf> = None;
            let mut i = 4;
            while i < args.len() {
                match args[i].as_str() {
                    "--headers" if i + 1 < args.len() => {
                        match fs::read(&args[i + 1]) {
                            Ok(b) => header_bytes = Some(b),
                            Err(err) => {
                                eprintln!("cannot read {}: {err}", args[i + 1]);
                                return ExitCode::FAILURE;
                            }
                        }
                        i += 2;
                    }
                    "--assumevalid" if i + 1 < args.len() => {
                        match args[i + 1].parse::<BlockHash>() {
                            Ok(hash) => params.assume_valid = Some(hash),
                            Err(err) => {
                                eprintln!("invalid --assumevalid hash: {err}");
                                return ExitCode::FAILURE;
                            }
                        }
                        i += 2;
                    }
                    "--store" if i + 1 < args.len() => {
                        store_dir = Some(std::path::PathBuf::from(&args[i + 1]));
                        i += 2;
                    }
                    flag => {
                        eprintln!("unknown replay flag {flag:?}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            // blk.dat framing: 4-byte network magic + 4-byte LE length +
            // raw block, repeated. One Chainstate across the stream — this is
            // the offline-import/replay path: every block runs the full
            // accept pipeline (CheckBlock -> header insert -> contextual ->
            // connect/reorg) in file order.
            let expected_magic = params.message_start;
            let mut state = match store_dir {
                Some(dir) => match Chainstate::with_store(&dir, &params, now) {
                    Ok(state) => {
                        eprintln!(
                            "store {}: resumed at height {}",
                            dir.display(),
                            state.tree().get(&state.tip_hash()).map_or(0, |n| n.height)
                        );
                        state
                    }
                    Err(err) => {
                        eprintln!("cannot open store {}: {err}", dir.display());
                        return ExitCode::FAILURE;
                    }
                },
                None => Chainstate::new(&params),
            };
            if let Some(bytes) = header_bytes {
                // `ProcessNewBlockHeaders`: raw 80-byte headers, chain order.
                // A rejected header aborts the preload — a body whose header
                // was never indexed is an orphan to `accept_block`.
                for (index, chunk) in (1u64..).zip(bytes.chunks(80)) {
                    match BlockHeader::decode(chunk)
                        .map_err(|e| format!("decode\t{e}"))
                        .and_then(|h| {
                            state
                                .accept_header(&h, now)
                                .map_err(|e| e.reason().into_owned())
                        }) {
                        Ok(_) => {}
                        Err(err) => {
                            println!("#header\trejected:{err}\tindex={index}");
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }
            let mut cursor = 0usize;
            let mut index = 0u64;
            while cursor + 8 <= data.len() {
                let magic = [
                    data[cursor],
                    data[cursor + 1],
                    data[cursor + 2],
                    data[cursor + 3],
                ];
                let len = u32::from_le_bytes([
                    data[cursor + 4],
                    data[cursor + 5],
                    data[cursor + 6],
                    data[cursor + 7],
                ]) as usize;
                cursor += 8;
                if magic != expected_magic {
                    println!("#{index}\trejected:bad-frame-magic\t{magic:02x?}");
                    break;
                }
                if len > MAX_BLOCK_SERIALIZED_SIZE || cursor + len > data.len() {
                    println!("#{index}\trejected:bad-frame-length\t{len}");
                    break;
                }
                let payload = &data[cursor..cursor + len];
                cursor += len;
                let verdict_line = match Block::decode(payload) {
                    Ok(block) => {
                        let (verdict, detail) = validate(&block, &mut state, now);
                        format!("{verdict}\t{detail}")
                    }
                    Err(err) => format!("rejected:decode\t{err}"),
                };
                println!("#{index}\t{verdict_line}");
                index += 1;
            }
            if cursor != data.len() {
                eprintln!(
                    "warning: {} trailing byte(s) after last frame",
                    data.len() - cursor
                );
            }
            if let Err(err) = state.flush() {
                eprintln!("store flush failed: {err}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Some("gen-corpus") if args.len() == 2 => {
            let outdir = Path::new(&args[1]);
            if let Err(err) = fs::create_dir_all(outdir) {
                eprintln!("cannot create {}: {err}", outdir.display());
                return ExitCode::FAILURE;
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            match gen_corpus(outdir, now) {
                Ok(()) => {
                    for entry in fs::read_dir(outdir).into_iter().flatten().flatten() {
                        println!("{}", entry.file_name().to_string_lossy());
                    }
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("gen-corpus: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("gen-assumevalid-corpus") if args.len() == 2 => {
            let outdir = Path::new(&args[1]);
            if let Err(err) = fs::create_dir_all(outdir) {
                eprintln!("cannot create {}: {err}", outdir.display());
                return ExitCode::FAILURE;
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            match gen_assumevalid_corpus(outdir, now) {
                Ok(()) => {
                    for entry in fs::read_dir(outdir).into_iter().flatten().flatten() {
                        println!("{}", entry.file_name().to_string_lossy());
                    }
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("gen-assumevalid-corpus: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("usage:");
            eprintln!("  check-blocks check <network> <block.bin> <now>");
            eprintln!("  check-blocks check-many <network> <now> <block.bin>...");
            eprintln!(
                "  check-blocks replay <network> <blocks.dat> <now> \
                 [--headers <headers.bin>] [--assumevalid <hex>] [--store <dir>]"
            );
            eprintln!("  check-blocks gen-corpus <outdir>");
            eprintln!("  check-blocks gen-assumevalid-corpus <outdir>");
            ExitCode::FAILURE
        }
    }
}

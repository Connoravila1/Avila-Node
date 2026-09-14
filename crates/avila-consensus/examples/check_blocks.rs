//! Reference-adapter helper for block-level rules: run a raw serialized block
//! through the implemented validation pipeline and print one verdict, or emit a
//! generated regtest corpus for `tools/check_blocks_core.py` to replay through
//! the reference daemon's `submitblock` RPC.
//!
//! Usage:
//!   `check-blocks check <network> <block.bin> <now>`
//!   `check-blocks check-many <network> <now> <block.bin>...`
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
use avila_consensus::block::Block;
use avila_consensus::chain::{ChainError, HeaderTree, InsertStatus};
use avila_consensus::check::{self, BlockContext, RuleError};
use avila_consensus::connect::{self, ConnectContext, UtxoSet};
use avila_consensus::hash::{BlockHash, MerkleRoot, Txid};
use avila_consensus::header::BlockHeader;
use avila_consensus::params::{Network, Params};
use avila_consensus::pow::{self, PowError};
use avila_consensus::rules::TimeError;
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

/// The reject reason Core's `AcceptBlockHeader` reports for the equivalent
/// failure — the same mapping `check-headers` uses.
fn core_reason_header(err: &ChainError) -> String {
    match err {
        ChainError::UnknownParent(_) => "prev-blk-not-found".to_string(),
        ChainError::WrongBits { .. } => "bad-diffbits".to_string(),
        ChainError::Pow(
            PowError::NegativeTarget(_)
            | PowError::OverflowTarget(_)
            | PowError::ZeroTarget(_)
            | PowError::TargetAboveLimit(_)
            | PowError::InsufficientWork { .. },
        ) => "high-hash".to_string(),
        ChainError::Pow(PowError::UnknownAncestor(_) | PowError::DegenerateDifficultyParams) => {
            "internal".to_string()
        }
        ChainError::Time(TimeError::TooOld { .. }) => "time-too-old".to_string(),
        ChainError::Time(TimeError::Timewarp { .. }) => "time-timewarp-attack".to_string(),
        ChainError::Time(TimeError::TooNew { .. }) => "time-too-new".to_string(),
        ChainError::BadVersion { .. } => err.to_string(),
        ChainError::ChainWorkOverflow | ChainError::HeightOverflow => "internal".to_string(),
    }
}

/// Stateful validation chain — mirrors the daemon's block index plus active
/// chainstate. `tree` accumulates every inserted header; `utxo`/`connected`
/// track the active chain tip so a block that extends it is actually
/// connected, exactly as `submitblock` connecting a new tip on the daemon.
struct ChainState {
    tree: HeaderTree,
    utxo: UtxoSet,
    /// Block hash of the connected tip (`genesis` at start — the genesis
    /// block's coinbase is not in the UTXO set on any network).
    connected: BlockHash,
}

impl ChainState {
    fn new(params: &Params) -> Self {
        Self {
            tree: HeaderTree::new(*params),
            utxo: UtxoSet::new(),
            connected: params.genesis_header.hash(),
        }
    }
}

/// Runs the implemented pipeline against `state` (shared across calls, like
/// Core's block index + chainstate) and returns `(verdict, detail)`. A header
/// that passes insertion stays in the tree even when a later block-level rule
/// rejects the block — matching Core, where `AcceptBlockHeader` commits the
/// header to the block index before `CheckBlock` runs. A block that extends
/// the connected tip is run through [`connect::connect_block`]; a valid block
/// on any other branch reports `accepted` after the context-free and
/// contextual layers, like the daemon's `inconclusive` for side-chain blocks.
fn validate(block: &Block, params: &Params, state: &mut ChainState, now: u32) -> (String, String) {
    let height = match state.tree.insert(&block.header, now) {
        Ok(InsertStatus::Added { height }) => height,
        Ok(InsertStatus::AlreadyKnown { height }) => {
            return ("accepted-known".to_string(), format!("height={height}"));
        }
        Err(err) => {
            return (
                format!("rejected:{}", core_reason_header(&err)),
                err.to_string(),
            );
        }
    };
    if let Err(err) = check::check_block(block, params) {
        return (format!("rejected:{}", err.reason()), err.to_string());
    }
    // Corpus blocks build on the seeded genesis, so the parent is in the tree.
    let parent_mtp = state.tree.median_time_past(&block.header.prev_block_hash);
    let ctx = BlockContext {
        params,
        height,
        parent_median_time_past: parent_mtp,
    };
    if let Err(err) = check::contextual_check_block(block, &ctx) {
        return (format!("rejected:{}", err.reason()), err.to_string());
    }
    if block.header.prev_block_hash == state.connected {
        let ctx = ConnectContext {
            params,
            tree: &state.tree,
            block_hash: block.block_hash(),
        };
        if let Err(err) = connect::connect_block(block, &mut state.utxo, &ctx) {
            return (format!("rejected:{}", err.reason()), err.to_string());
        }
        state.connected = block.block_hash();
        return ("accepted".to_string(), format!("height={height},connected"));
    }
    ("accepted".to_string(), format!("height={height}"))
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
    params: &Params,
    state: &mut ChainState,
    now: u32,
) -> Result<(), String> {
    let (verdict, _detail) = validate(block, params, state, now);
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
    state: &mut ChainState,
    now: u32,
    mutate: impl FnOnce(&mut Transaction),
) -> Result<(), String> {
    let mut tx = spend_tx();
    mutate(&mut tx);
    let block = finish(draft_block(params, vec![regtest_coinbase(1), tx]), params);
    emit(manifest, outdir, name, &block, params, state, now)
}

fn gen_corpus(outdir: &Path, now: u32) -> Result<(), String> {
    let params = Network::Regtest.params();
    let mut manifest = Vec::new();
    // One chain state across the whole corpus: verdicts are stateful, matching
    // how the daemon accumulates headers in its block index and connects the
    // active chain tip between submissions.
    let mut state = ChainState::new(&params);

    // -- valid baseline ------------------------------------------------------
    let valid = finish(draft_block(&params, vec![regtest_coinbase(1)]), &params);
    emit(
        &mut manifest,
        outdir,
        "00-valid",
        &valid,
        &params,
        &mut state,
        now,
    )?;

    // A valid child at height 2: exercises the pipeline past genesis+1 (the
    // daemon will connect both blocks). `child` is also the connect-phase
    // chain's h2 link below.
    let child = finish(draft_on(&valid.header, vec![regtest_coinbase(2)]), &params);
    emit(
        &mut manifest,
        outdir,
        "05-valid-height2",
        &child,
        &params,
        &mut state,
        now,
    )?;

    // -- header rules (AcceptBlockHeader/ContextualCheckBlockHeader) ---------

    // high-hash: a valid compact encoding under the limit, but the hash fails
    // the claimed (~2^248) target.
    {
        let mut block = draft_block(&params, vec![regtest_coinbase(1)]);
        block.header.bits = CompactTarget(0x1f7f_ffff);
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, &params).is_ok() {
            block.header.nonce += 1;
        }
        emit(
            &mut manifest,
            outdir,
            "10-high-hash",
            &block,
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
            &mut state,
            now,
        )?;
    }

    // -- CheckBlock ----------------------------------------------------------

    // bad-txnmrklroot: the committed root doesn't match the transaction list.
    {
        let mut block = draft_block(&params, vec![regtest_coinbase(1)]);
        let mut bytes = block.header.merkle_root.to_bytes();
        bytes[0] ^= 0xff;
        block.header.merkle_root = MerkleRoot::from_bytes(bytes);
        grind(&mut block, &params);
        emit(
            &mut manifest,
            outdir,
            "20-bad-txnmrklroot",
            &block,
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
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
        emit(
            &mut manifest,
            outdir,
            "57-orphan",
            &block,
            &params,
            &mut state,
            now,
        )?;
    }

    // duplicate: resubmitting 00-valid — our shared tree reports
    // `accepted-known`, the daemon's block index reports `duplicate`; both
    // normalize to `accepted`.
    {
        let (verdict, _detail) = validate(&valid, &params, &mut state, now);
        manifest.push(("00-valid".to_string(), verdict));
    }

    // -- ConnectBlock (UTXO-dependent rules) ----------------------------------
    //
    // The daemon connects each of these blocks to its active chain, so
    // `ConnectBlock`'s verdict surfaces as the submitblock result. Our side
    // runs `connect_block` when the block extends the connected tip —
    // `state.connected` tracks it. Spends use anyone-can-spend (`OP_1`)
    // prevouts with empty scriptSigs, so the daemon's script checks pass; our
    // own script evaluation is intentionally not yet wired.
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
            &params,
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
        &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
            &mut state,
            now,
        )?;
    }

    // bad-cb-amount: the coinbase pays subsidy + 1 with no fees in the block.
    {
        let mut cb = regtest_coinbase(103);
        cb.outputs[0].value = 5_000_000_001;
        let block = finish(draft_on(&case_parent, vec![cb]), &params);
        emit(
            &mut manifest,
            outdir,
            "66-cb-amount",
            &block,
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
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
            &params,
            &mut state,
            now,
        )?;
    }

    // Positive controls at h103 (connects): a satisfied BIP68 height lock
    // (sequence 1 on a h102 coin — min height 102 < 103) and a sequence with
    // the disable flag set (not a lock at all).
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
            &params,
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
    fs::write(outdir.join("manifest.json"), json).map_err(|e| e.to_string())?;
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
            let mut state = ChainState::new(&net.params());
            match Block::decode(&bytes) {
                Ok(block) => {
                    let (verdict, detail) = validate(&block, &net.params(), &mut state, now);
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
            let mut state = ChainState::new(&net.params());
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
                        let (verdict, detail) = validate(&block, &net.params(), &mut state, now);
                        format!("{verdict}\t{detail}")
                    }
                    Err(err) => format!("rejected:{err}"),
                };
                println!("{name}\t{verdict_line}");
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
        _ => {
            eprintln!("usage:");
            eprintln!("  check-blocks check <network> <block.bin> <now>");
            eprintln!("  check-blocks check-many <network> <now> <block.bin>...");
            eprintln!("  check-blocks gen-corpus <outdir>");
            ExitCode::FAILURE
        }
    }
}

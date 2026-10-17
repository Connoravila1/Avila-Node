//! Offline shadow experiment over the committed mainnet heights 0..=500 fixture.
//!
//! It performs two ordinary full-validation replays with `assume_valid = None`, then
//! compares a secret-keyed SwiftAudit multiset and provisional SwiftStump roots against
//! local full-set oracles. This is a bounded fixture experiment, not an IBD path, a
//! membership proof, or a consensus acceptance mechanism.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;

use avila_consensus::block::{Block, MAX_BLOCK_SERIALIZED_SIZE};
use avila_consensus::chainstate::{Acceptance, Chainstate};
use avila_consensus::connect::Coin;
use avila_consensus::hash::sha256;
use avila_consensus::params::{Network, Params};
use avila_consensus::swift_audit::{AuditVerdict, OutputClass, SwiftAudit};
use avila_consensus::swift_stump::{
    ExternalAuditPassed, SwiftCheckpoint, SwiftStumpBuilder, SwiftStumpLimits,
};
use avila_consensus::transaction::OutPoint;
use avila_consensus::utreexo::leaf_for;
use rustreexo::mem_forest::MemForest;
use rustreexo::node_hash::BitcoinNodeHash;

const FIXTURE: &str = "mainnet-blocks-000000-000500.dat";
const FIXTURE_BYTES: usize = 114_278;
const FIXTURE_SHA256: &str = "ef9cb1e45eaaafa55d23016d7dfce3e8f64f56609573e18b9a8940b8b1ac3d73";
const MAX_FIXTURE_BYTES: usize = 1024 * 1024;
const MAX_BLOCKS: usize = 501;
const MAX_OUTPUTS: usize = 1_000_000;
const MAX_ORACLE_COINS: usize = 1_000_000;
const MAX_STUMP_BYTES: usize = 32 * 1024 * 1024;
const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
const ACCEPT_TIME: u32 = 2_000_000_000;

fn main() -> Result<(), Box<dyn Error>> {
    let tamper_input = parse_args()?;
    let fixture = fixture_path();
    let file = File::open(&fixture)?;
    let file_size = file.metadata()?.len();
    if file_size > MAX_FIXTURE_BYTES as u64 || file_size != FIXTURE_BYTES as u64 {
        return Err(invalid(format!(
            "fixture size {file_size} is outside the expected bounded size {FIXTURE_BYTES}"
        ))
        .into());
    }
    let mut bytes = Vec::with_capacity(FIXTURE_BYTES);
    file.take((MAX_FIXTURE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != FIXTURE_BYTES {
        return Err(invalid("fixture changed or was truncated while being read").into());
    }
    let digest = sha256(&bytes);
    let digest_hex = hex(&digest);
    if digest_hex != FIXTURE_SHA256 {
        return Err(invalid(format!("fixture SHA-256 mismatch: {digest_hex}")).into());
    }
    let blocks = decode_fixture(&bytes)?;
    let mut params = Network::Mainnet.params();
    params.assume_valid = None;

    // The first full-validation replay supplies the local final-live-set oracle.
    let mut oracle = Chainstate::new(&params);
    replay_full(&mut oracle, &blocks, &params)?;
    let checkpoint_hash = blocks
        .last()
        .ok_or_else(|| invalid("fixture contains no blocks"))?
        .block_hash();
    if oracle.tip_hash() != checkpoint_hash || oracle.chain().len() != MAX_BLOCKS {
        return Err(invalid("oracle replay did not connect exactly through height 500").into());
    }
    let oracle_checked_height = oracle.checked_height();
    if oracle_checked_height != 500 {
        return Err(invalid(format!(
            "oracle fully checked height {oracle_checked_height}, expected 500"
        ))
        .into());
    }
    if oracle.utxo().len() > MAX_ORACLE_COINS {
        return Err(invalid("oracle UTXO exceeds the experiment's coin bound").into());
    }
    let final_coins = oracle.utxo().iter();
    let oracle_live: HashSet<OutPoint> = final_coins.into_iter().map(|(op, _)| op).collect();

    // This is the independent full-coin audit and leaf-builder pass. Every block is
    // still accepted by Chainstate before any shadow result is recorded.
    let checkpoint = SwiftCheckpoint {
        first_height: 1,
        last_height: 500,
        checkpoint_hash: checkpoint_hash.as_bytes().to_owned(),
    };
    let mut audit = SwiftAudit::new(Network::Mainnet, 500, checkpoint_hash)
        .map_err(|e| invalid(format!("audit session initialization failed: {e:?}")))?;
    let stump_limits = SwiftStumpLimits {
        max_pending_blocks: 1,
        max_pending_leaves: MAX_OUTPUTS,
        max_pending_bytes: MAX_STUMP_BYTES,
        max_batch_leaves: MAX_OUTPUTS,
        max_batch_bytes: MAX_STUMP_BYTES,
    };
    let mut stump = SwiftStumpBuilder::new(checkpoint, stump_limits)
        .map_err(|e| invalid(format!("stump initialization failed: {e:?}")))?;
    let mut full = Chainstate::new(&params);
    let mut all_created = HashSet::new();
    let mut all_positions: Vec<BitcoinNodeHash> = Vec::new();
    let mut deleted_positions: Vec<BitcoinNodeHash> = Vec::new();
    let mut did_tamper = false;

    for (height, block) in blocks.iter().enumerate().skip(1) {
        let height = u32::try_from(height)?;
        let input_coins = resolve_input_coins(&full, block, height)?;
        let result = full
            .accept_block(block, ACCEPT_TIME)
            .map_err(|e| invalid(format!("full replay rejected height {height}: {e:?}")))?;
        match result {
            Acceptance::Connected {
                height: connected_height,
                reorged: false,
            } if connected_height == height => {}
            other => {
                return Err(invalid(format!(
                    "full replay did not connect expected height {height}: {other:?}"
                ))
                .into());
            }
        }

        for (outpoint, mut coin) in input_coins {
            if tamper_input && !did_tamper {
                coin.out.value = coin
                    .out
                    .value
                    .checked_add(1)
                    .ok_or_else(|| invalid("could not safely tamper with input value"))?;
                did_tamper = true;
            }
            audit
                .record_input_coin(&outpoint, &coin)
                .map_err(|e| invalid(format!("audit input record failed: {e:?}")))?;
        }

        let mut batch = Vec::new();
        for tx in &block.transactions {
            let txid = tx.txid();
            for (vout, output) in tx.outputs.iter().enumerate() {
                if output.value < 0 || output.script_pubkey.is_unspendable() {
                    continue;
                }
                let outpoint = OutPoint {
                    txid,
                    vout: u32::try_from(vout)?,
                };
                if !all_created.insert(outpoint) {
                    return Err(invalid(format!(
                        "duplicate spendable outpoint in fixture at height {height}"
                    ))
                    .into());
                }
                if all_created.len() > MAX_OUTPUTS {
                    return Err(invalid("fixture output count exceeds experiment bound").into());
                }
                let coin = Coin {
                    out: output.clone(),
                    height,
                    coinbase: tx.is_coinbase(),
                };
                let survives = oracle_live.contains(&outpoint);
                let class = if survives {
                    OutputClass::SurvivesCheckpoint
                } else {
                    OutputClass::SpentByCheckpoint
                };
                audit
                    .record_output(&outpoint, &coin, class)
                    .map_err(|e| invalid(format!("audit output record failed: {e:?}")))?;
                let leaf = leaf_for(&outpoint, &coin);
                if survives {
                    batch.push(Some(leaf));
                } else {
                    batch.push(None);
                    deleted_positions.push(leaf);
                }
                all_positions.push(leaf);
            }
        }
        stump
            .push(height, batch)
            .map_err(|e| invalid(format!("stump batch failed at height {height}: {e:?}")))?;
    }

    if tamper_input && !did_tamper {
        return Err(invalid("tamper mode found no input coin to alter").into());
    }
    if full.tip_hash() != checkpoint_hash || full.chain().len() != MAX_BLOCKS {
        return Err(invalid("shadow replay did not connect exactly through height 500").into());
    }
    let checked_height = full.checked_height();
    if checked_height != 500 {
        return Err(invalid(format!(
            "shadow replay fully checked height {checked_height}, expected 500"
        ))
        .into());
    }
    let report = audit
        .finish(Network::Mainnet, 500, checkpoint_hash)
        .map_err(|e| invalid(format!("audit finish failed: {e:?}")))?;
    let expected_verdict = if tamper_input {
        AuditVerdict::Mismatch
    } else {
        AuditVerdict::Match
    };
    if report.verdict != expected_verdict {
        return Err(invalid(format!(
            "audit verdict {:?}, expected {:?}",
            report.verdict, expected_verdict
        ))
        .into());
    }

    // Independent explicit-deletion oracle: add every spendable output position,
    // then explicitly delete those the local final UTXO set says are spent.
    let mut forest = MemForest::<BitcoinNodeHash>::new();
    forest
        .modify(&all_positions, &[])
        .map_err(|e| invalid(format!("explicit forest add failed: {e}")))?;
    forest
        .modify(&[], &deleted_positions)
        .map_err(|e| invalid(format!("explicit forest delete failed: {e}")))?;
    let explicit_roots: Vec<_> = forest
        .get_roots()
        .iter()
        .map(|root| root.get_data())
        .collect();
    let stump_finished = report.verdict == AuditVerdict::Match;
    let (stump_leaf_count, roots_match) = if stump_finished {
        let receipt = ExternalAuditPassed::after_external_audit(checkpoint);
        let provisional = stump
            .finish(receipt)
            .map_err(|e| invalid(format!("provisional stump finish failed: {e:?}")))?;
        (
            provisional.leaves,
            Some(provisional.roots == explicit_roots && provisional.leaves == forest.leaves),
        )
    } else {
        (stump.leaves(), None)
    };
    if roots_match == Some(false) {
        return Err(invalid("implicit stump roots differ from explicit MemForest oracle").into());
    }
    if !tamper_input && stump_leaf_count != forest.leaves {
        return Err(invalid("stump leaf count differs from explicit MemForest oracle").into());
    }

    println!(
        "{{\"experiment\":\"swift_checkpoint_shadow\",\"scope\":\"fixture_heights_0_500\",\
         \"fixture\":\"{FIXTURE}\",\"fixture_bytes\":{},\"fixture_sha256\":\"{}\",\
         \"network\":\"main\",\"assume_valid\":false,\"blocks\":{},\
         \"checked_height\":{},\"checkpoint_hash\":\"{}\",\"tamper_input\":{},\
         \"negative_test\":{},\
         \"audit_verdict\":\"{}\",\"spendable_audit_outputs\":{},\"audit_survivors\":{},\
         \"audit_input_coins\":{},\"stump_provisional\":{},\"stump_leaves\":{},\
         \"explicit_forest_leaves\":{},\"stump_roots_match_explicit_forest\":{} }}",
        bytes.len(),
        digest_hex,
        blocks.len(),
        checked_height,
        checkpoint_hash,
        tamper_input,
        if tamper_input {
            "\"tampered_audit_mismatch_detected\""
        } else {
            "null"
        },
        verdict_name(report.verdict),
        report.outputs,
        report.survivors,
        report.input_coins,
        stump_finished,
        stump_leaf_count,
        forest.leaves,
        roots_match.map_or("null".to_owned(), |matched| matched.to_string()),
    );
    Ok(())
}

fn parse_args() -> io::Result<bool> {
    let mut tamper = false;
    for arg in std::env::args_os().skip(1) {
        if arg == "--tamper-input" && !tamper {
            tamper = true;
        } else {
            return Err(invalid("expected at most one --tamper-input argument"));
        }
    }
    Ok(tamper)
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(FIXTURE)
}

fn decode_fixture(bytes: &[u8]) -> io::Result<Vec<Block>> {
    let mut blocks = Vec::with_capacity(MAX_BLOCKS);
    let mut offset = 0usize;
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(8)
            .ok_or_else(|| invalid("fixture frame offset overflow"))?;
        if header_end > bytes.len() {
            return Err(invalid("truncated fixture frame header"));
        }
        if bytes[offset..offset + 4] != MAINNET_MAGIC {
            return Err(invalid(format!("wrong mainnet magic at byte {offset}")));
        }
        let block_len = u32::from_le_bytes(
            bytes[offset + 4..header_end]
                .try_into()
                .map_err(|_| invalid("bad fixture frame length"))?,
        ) as usize;
        if block_len == 0 || block_len > MAX_BLOCK_SERIALIZED_SIZE {
            return Err(invalid(format!("invalid framed block size {block_len}")));
        }
        let end = header_end
            .checked_add(block_len)
            .ok_or_else(|| invalid("fixture frame length overflow"))?;
        if end > bytes.len() {
            return Err(invalid("truncated fixture block"));
        }
        if blocks.len() >= MAX_BLOCKS {
            return Err(invalid("fixture contains more than 501 blocks"));
        }
        blocks.push(
            Block::decode(&bytes[header_end..end])
                .map_err(|e| invalid(format!("block {} decode failed: {e}", blocks.len())))?,
        );
        offset = end;
    }
    if offset != bytes.len() || blocks.len() != MAX_BLOCKS {
        return Err(invalid(format!(
            "fixture had {} frames, expected exactly {MAX_BLOCKS}",
            blocks.len()
        )));
    }
    Ok(blocks)
}

fn replay_full(chain: &mut Chainstate, blocks: &[Block], params: &Params) -> io::Result<()> {
    let genesis = blocks
        .first()
        .ok_or_else(|| invalid("fixture has no genesis"))?;
    if genesis.block_hash() != params.genesis_header.hash()
        || !genesis.header.prev_block_hash.is_zero()
    {
        return Err(invalid("fixture genesis does not match mainnet parameters"));
    }
    let mut parent = genesis.block_hash();
    for (height, block) in blocks.iter().enumerate().skip(1) {
        if block.header.prev_block_hash != parent {
            return Err(invalid(format!("broken block linkage at height {height}")));
        }
        match chain
            .accept_block(block, ACCEPT_TIME)
            .map_err(|e| invalid(format!("full validation rejected height {height}: {e:?}")))?
        {
            Acceptance::Connected {
                height: accepted,
                reorged: false,
            } if accepted == height as u32 => {}
            other => {
                return Err(invalid(format!(
                    "block at height {height} did not become active: {other:?}"
                )));
            }
        }
        parent = block.block_hash();
    }
    Ok(())
}

fn resolve_input_coins(
    chain: &Chainstate,
    block: &Block,
    height: u32,
) -> io::Result<Vec<(OutPoint, Coin)>> {
    let mut earlier_outputs = HashMap::new();
    let mut inputs = Vec::new();
    for tx in &block.transactions {
        if !tx.is_coinbase() {
            for input in &tx.inputs {
                let outpoint = input.previous_output;
                let coin = earlier_outputs
                    .remove(&outpoint)
                    .or_else(|| chain.utxo().get(&outpoint))
                    .ok_or_else(|| {
                        invalid(format!(
                            "no pre-block or earlier-in-block coin for input {}:{} at height {height}",
                            outpoint.txid, outpoint.vout
                        ))
                    })?;
                inputs.push((outpoint, coin));
            }
        }
        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            if output.value < 0 || output.script_pubkey.is_unspendable() {
                continue;
            }
            let outpoint = OutPoint {
                txid,
                vout: u32::try_from(vout)
                    .map_err(|_| invalid("transaction output index overflow"))?,
            };
            earlier_outputs.insert(
                outpoint,
                Coin {
                    out: output.clone(),
                    height,
                    coinbase: tx.is_coinbase(),
                },
            );
        }
    }
    Ok(inputs)
}

fn verdict_name(verdict: AuditVerdict) -> &'static str {
    match verdict {
        AuditVerdict::Match => "match",
        AuditVerdict::Mismatch => "mismatch",
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

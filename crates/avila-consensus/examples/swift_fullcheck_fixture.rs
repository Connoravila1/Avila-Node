//! Standalone full-check SwiftSync fixture runner over bounded mainnet heights 0..=500.
//!
//! The runner reconstructs helper spent-coin records from the committed raw block fixture,
//! then gives those records to `SwiftValidationEngine` as untrusted claims. The engine itself
//! performs header, block, contextual, UTXO, fee/subsidy, maturity, locktime, BIP30 and script
//! validation with `assume_valid=None`; no `Chainstate` acceptance oracle is used. The fixture
//! predates SegWit and Taproot, so this is an integration smoke fixture, not modern coverage.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use avila_consensus::block::{Block, MAX_BLOCK_SERIALIZED_SIZE};
use avila_consensus::chain::HeaderTree;
use avila_consensus::connect::Coin;
use avila_consensus::hash::sha256;
use avila_consensus::params::Network;
use avila_consensus::swift_audit::AuditVerdict;
use avila_consensus::swift_engine::{
    InputCoinClaim, MAX_BLOCK_COIN_CLAIMS, SwiftEngineError, SwiftValidationEngine,
};
use avila_consensus::swift_live::{
    DEFAULT_REORG_DEPTH, MAX_BLOCK_EVENTS, SwiftLiveBinding, SwiftLiveIndex, SwiftLiveLimits,
};
use avila_consensus::swift_stump::{SwiftCheckpoint, SwiftStumpBuilder, SwiftStumpLimits};
use avila_consensus::transaction::OutPoint;

const FIXTURE: &str = "mainnet-blocks-000000-000500.dat";
const FIXTURE_BYTES: usize = 114_278;
const FIXTURE_SHA256: &str = "ef9cb1e45eaaafa55d23016d7dfce3e8f64f56609573e18b9a8940b8b1ac3d73";
const MAX_FIXTURE_BYTES: usize = 1024 * 1024;
const MAX_BLOCKS: usize = 501;
const MAX_OUTPUTS: u64 = 1_000_000;
const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
const ACCEPT_TIME: u32 = 2_000_000_000;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::args_os().len() != 1 {
        return Err(invalid("this bounded runner accepts no fixture path or options").into());
    }
    let bytes = read_fixture(&fixture_path())?;
    let blocks = decode_fixture(&bytes)?;
    let mut params = Network::Mainnet.params();
    params.assume_valid = None;
    let checkpoint_hash = blocks
        .last()
        .ok_or_else(|| invalid("fixture contains no blocks"))?
        .block_hash();
    if blocks[0].block_hash() != params.genesis_header.hash() {
        return Err(invalid("fixture genesis differs from mainnet parameters").into());
    }

    let survivors = checkpoint_survivors(&blocks)?;
    let temp = TempDir::new()?;
    let binding = SwiftLiveBinding {
        network: Network::Mainnet,
        start_height: 0,
        start_hash: params.genesis_header.hash(),
        target_height: 500,
        target_hash: checkpoint_hash,
        params_commitment: params.swift_validation_commitment(),
    };
    let limits = SwiftLiveLimits {
        max_live_entries: MAX_OUTPUTS,
        max_live_encoded_bytes: MAX_OUTPUTS * 41,
        max_undo_encoded_bytes: 256 * 1024 * 1024,
        max_survivor_entries: MAX_OUTPUTS,
        max_survivor_encoded_bytes: 512 * 1024 * 1024,
        max_reorg_depth: DEFAULT_REORG_DEPTH,
        max_block_events: MAX_BLOCK_EVENTS,
        cache_bytes: 32 * 1024 * 1024,
    };
    let live = SwiftLiveIndex::create(&temp.path().join("swift.redb"), binding, limits)?;
    let audit = avila_consensus::swift_audit::SwiftAudit::new(
        Network::Mainnet,
        binding.target_height,
        binding.target_hash,
    )?;
    let tree = HeaderTree::new(params);
    let mut engine = SwiftValidationEngine::new(params, tree, live, audit)?;
    let stump_builder = SwiftStumpBuilder::new(
        SwiftCheckpoint {
            first_height: 1,
            last_height: binding.target_height,
            checkpoint_hash: *binding.target_hash.as_bytes(),
        },
        SwiftStumpLimits {
            max_pending_blocks: 1,
            max_pending_leaves: 1_000_000,
            max_pending_bytes: 32 * 1024 * 1024,
            max_batch_leaves: 1_000_000,
            max_batch_bytes: 32 * 1024 * 1024,
        },
    )
    .map_err(|error| invalid(format!("stump builder creation failed: {error:?}")))?;
    engine
        .enable_provisional_stump(stump_builder)
        .map_err(|error| invalid(format!("stump setup failed: {error}")))?;

    // This bounded helper-side map models supplied full-coindata records. It is built only
    // from the raw fixture's prior outputs and transaction spends; it never calls or reads
    // the conventional chainstate implementation. The validation engine has its own compact
    // exact live-status table and independently checks every supplied coin's liveness/height.
    let mut helper_live = HashMap::<OutPoint, Coin>::new();
    let mut wrong_claim_rejected = false;
    for (height, block) in blocks.iter().enumerate().skip(1) {
        let height = u32::try_from(height)?;
        let mut claims = helper_records_for_block(&mut helper_live, block, height)?;
        if !wrong_claim_rejected && !claims.is_empty() {
            claims[0].1.height = claims[0]
                .1
                .height
                .checked_add(1)
                .ok_or_else(|| invalid("test claim height overflow"))?;
            match engine.connect_block(block, ACCEPT_TIME, &claims, &[], |outpoint, _coin| {
                Ok(survivors.contains(&outpoint))
            }) {
                Err(SwiftEngineError::CoinMismatch) => wrong_claim_rejected = true,
                other => {
                    return Err(invalid(format!(
                        "altered helper claim was not rejected before block commit: {other:?}"
                    ))
                    .into());
                }
            }
            claims[0].1.height -= 1;
        }
        engine
            .connect_block(block, ACCEPT_TIME, &claims, &[], |outpoint, _coin| {
                Ok(survivors.contains(&outpoint))
            })
            .map_err(|error| invalid(format!("Swift full-check failed at {height}: {error}")))?;
    }

    let finish = engine.finish_audit()?;
    if finish.audit.verdict != AuditVerdict::Match {
        return Err(invalid("checkpoint-bound full-coin audit did not match").into());
    }
    let stump = finish
        .stump
        .ok_or_else(|| invalid("validated fixture did not finish its provisional stump"))?;
    let mut exported = 0u64;
    engine.for_each_audited_survivor(|_, _, _| {
        exported += 1;
        Ok(())
    })?;
    if exported != helper_live.len() as u64 || exported != finish.audit.survivors {
        return Err(
            invalid("durable survivor export count differs from the audited live set").into(),
        );
    }

    println!(
        "{{\"experiment\":\"swift_fullcheck_fixture\",\"fixture\":\"{FIXTURE}\",\
         \"fixture_bytes\":{},\"fixture_sha256\":\"{}\",\"network\":\"main\",\
         \"assume_valid\":false,\"blocks\":{},\"checkpoint_hash\":\"{}\",\
         \"engine\":\"standalone_ordinary_connect\",\"audit_verdict\":\"match\",\
         \"wrong_claim_rejected\":{},\
         \"audited_survivors\":{},\"durable_exported_survivors\":{},\
         \"provisional_stump_leaves\":{},\"modern_witness_taproot_coverage\":false}}",
        bytes.len(),
        hex(&sha256(&bytes)),
        blocks.len(),
        checkpoint_hash,
        wrong_claim_rejected,
        finish.audit.survivors,
        exported,
        stump.leaves,
    );
    Ok(())
}

fn helper_records_for_block(
    live: &mut HashMap<OutPoint, Coin>,
    block: &Block,
    height: u32,
) -> io::Result<Vec<InputCoinClaim>> {
    let mut claims = Vec::new();
    for tx in &block.transactions {
        if !tx.is_coinbase() {
            for input in &tx.inputs {
                let outpoint = input.previous_output;
                let coin = live.remove(&outpoint).ok_or_else(|| {
                    invalid(format!(
                        "fixture helper has no prior output {}:{} at height {height}",
                        outpoint.txid, outpoint.vout
                    ))
                })?;
                if coin.height < height {
                    if claims.len() >= MAX_BLOCK_COIN_CLAIMS {
                        return Err(invalid(
                            "fixture input-claim count exceeds the engine bound",
                        ));
                    }
                    claims.push((outpoint, coin));
                }
            }
        }
        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            if output.value < 0 || output.script_pubkey.is_unspendable() {
                continue;
            }
            let outpoint = OutPoint {
                txid,
                vout: u32::try_from(vout).map_err(|_| invalid("output index overflow"))?,
            };
            let coin = Coin {
                out: output.clone(),
                height,
                coinbase: tx.is_coinbase(),
            };
            if live.insert(outpoint, coin).is_some() {
                return Err(invalid(format!(
                    "fixture helper found a live duplicate output at height {height}"
                )));
            }
            if live.len() as u64 > MAX_OUTPUTS {
                return Err(invalid(
                    "fixture helper live set exceeds its explicit bound",
                ));
            }
        }
    }
    Ok(claims)
}

fn checkpoint_survivors(blocks: &[Block]) -> io::Result<HashSet<OutPoint>> {
    let mut created = HashSet::new();
    let mut spent = HashSet::new();
    for block in blocks.iter().skip(1) {
        for tx in &block.transactions {
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    spent.insert(input.previous_output);
                }
            }
            let txid = tx.txid();
            for (vout, output) in tx.outputs.iter().enumerate() {
                if output.value < 0 || output.script_pubkey.is_unspendable() {
                    continue;
                }
                let outpoint = OutPoint {
                    txid,
                    vout: u32::try_from(vout).map_err(|_| invalid("output index overflow"))?,
                };
                if !created.insert(outpoint) {
                    return Err(invalid("fixture repeats a spendable outpoint"));
                }
                if created.len() as u64 > MAX_OUTPUTS {
                    return Err(invalid(
                        "fixture spendable output count exceeds its explicit bound",
                    ));
                }
            }
        }
    }
    Ok(created.difference(&spent).copied().collect())
}

fn read_fixture(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    if file.metadata()?.len() != FIXTURE_BYTES as u64 {
        return Err(invalid("unexpected fixture file length"));
    }
    let mut bytes = Vec::with_capacity(FIXTURE_BYTES);
    file.take((MAX_FIXTURE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != FIXTURE_BYTES || hex(&sha256(&bytes)) != FIXTURE_SHA256 {
        return Err(invalid("fixture length or SHA-256 mismatch"));
    }
    Ok(bytes)
}

fn decode_fixture(bytes: &[u8]) -> io::Result<Vec<Block>> {
    let mut blocks = Vec::with_capacity(MAX_BLOCKS);
    let mut offset = 0usize;
    while offset < bytes.len() {
        let frame_end = offset
            .checked_add(8)
            .ok_or_else(|| invalid("fixture frame offset overflow"))?;
        if frame_end > bytes.len() || bytes[offset..offset + 4] != MAINNET_MAGIC {
            return Err(invalid("truncated frame or wrong mainnet magic"));
        }
        let block_len = u32::from_le_bytes(
            bytes[offset + 4..frame_end]
                .try_into()
                .map_err(|_| invalid("invalid framed block length"))?,
        ) as usize;
        if block_len == 0 || block_len > MAX_BLOCK_SERIALIZED_SIZE {
            return Err(invalid("framed block length outside protocol bound"));
        }
        let end = frame_end
            .checked_add(block_len)
            .ok_or_else(|| invalid("fixture frame end overflow"))?;
        if end > bytes.len() || blocks.len() >= MAX_BLOCKS {
            return Err(invalid("truncated frame or too many blocks"));
        }
        blocks.push(
            Block::decode(&bytes[frame_end..end])
                .map_err(|error| invalid(format!("block decode failed: {error}")))?,
        );
        offset = end;
    }
    if offset != bytes.len() || blocks.len() != MAX_BLOCKS {
        return Err(invalid("fixture did not contain exactly 501 blocks"));
    }
    Ok(blocks)
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(FIXTURE)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[(byte >> 4) as usize]));
        out.push(char::from(DIGITS[(byte & 0x0f) as usize]));
    }
    out
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        loop {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("avila-swift-fullcheck-{}-{id}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

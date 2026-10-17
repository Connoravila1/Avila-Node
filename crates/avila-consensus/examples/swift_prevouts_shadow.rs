//! Bounded disk-prevout shadow experiment on the committed mainnet heights 0..=500.
//!
//! This performs conventional full validation with `assume_valid = None`; a separate
//! checkpoint-bound redb index supplies historical input coins to the audit sidecar.
//! Same-block inputs use only earlier transaction outputs from a bounded in-memory
//! overlay. The index is experimental coin-data storage, not a membership or unspent
//! proof and never supplies data to the consensus acceptance path. This early historical
//! fixture does not cover modern witness/taproot-era blocks or establish broad coverage.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use avila_consensus::block::{Block, MAX_BLOCK_SERIALIZED_SIZE};
use avila_consensus::chainstate::{Acceptance, Chainstate};
use avila_consensus::connect::Coin;
use avila_consensus::hash::{BlockHash, sha256};
use avila_consensus::params::{Network, Params};
use avila_consensus::swift_audit::{AuditVerdict, OutputClass, SwiftAudit};
use avila_consensus::swift_prevouts::{PrevoutCheckpoint, SwiftPrevoutLimits, SwiftPrevoutStore};
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
const MAX_STUMP_BYTES: usize = 32 * 1024 * 1024;
const MAX_PREVOUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PREVOUT_CACHE: usize = 64 * 1024 * 1024;
const MAX_PREVOUT_BATCH: usize = 100_000;
const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];
const ACCEPT_TIME: u32 = 2_000_000_000;

fn main() -> Result<(), Box<dyn Error>> {
    reject_args()?;
    let fixture = fixture_path();
    let bytes = read_fixture(&fixture)?;
    let blocks = decode_fixture(&bytes)?;
    let mut params = Network::Mainnet.params();
    params.assume_valid = None;
    let checkpoint_hash = blocks
        .last()
        .ok_or_else(|| invalid("fixture contains no blocks"))?
        .block_hash();

    // Conventional full validation establishes a local final-live-set oracle.
    let mut oracle = Chainstate::new(&params);
    replay_full(&mut oracle, &blocks, &params)?;
    check_tip(&oracle, checkpoint_hash)?;
    if oracle.utxo().len() > MAX_OUTPUTS {
        return Err(invalid("oracle UTXO exceeds the fixture experiment bound").into());
    }
    let oracle_coins: HashMap<OutPoint, Coin> = oracle.utxo().iter().into_iter().collect();
    let oracle_live: HashSet<OutPoint> = oracle_coins.keys().copied().collect();

    // The database is newly created under a unique temporary directory. Its metadata
    // binds it to the fixture's final checkpoint, and its input/byte/cache limits are
    // explicit. It is an append-only side index and has no role in Chainstate acceptance.
    let temp = TempDir::new()?;
    let db_path = temp.path().join("prevouts.redb");
    let checkpoint = PrevoutCheckpoint {
        network: Network::Mainnet,
        height: 500,
        hash: checkpoint_hash,
    };
    let limits = SwiftPrevoutLimits {
        max_entries: MAX_OUTPUTS as u64,
        max_total_encoded_bytes: MAX_PREVOUT_BYTES,
        max_batch_entries: MAX_PREVOUT_BATCH,
        max_record_bytes: 20_000,
        max_script_bytes: 10_000,
        cache_bytes: MAX_PREVOUT_CACHE,
    };
    let mut prevouts = SwiftPrevoutStore::create(&db_path, checkpoint, limits)
        .map_err(|e| invalid(format!("prevout store create failed: {e:?}")))?;
    let mut audit = SwiftAudit::new(Network::Mainnet, 500, checkpoint_hash)
        .map_err(|e| invalid(format!("audit initialization failed: {e:?}")))?;
    let swift_checkpoint = SwiftCheckpoint {
        first_height: 1,
        last_height: 500,
        checkpoint_hash: checkpoint_hash.as_bytes().to_owned(),
    };
    let stump_limits = SwiftStumpLimits {
        max_pending_blocks: 1,
        max_pending_leaves: MAX_OUTPUTS,
        max_pending_bytes: MAX_STUMP_BYTES,
        max_batch_leaves: MAX_OUTPUTS,
        max_batch_bytes: MAX_STUMP_BYTES,
    };
    let mut stump = SwiftStumpBuilder::new(swift_checkpoint, stump_limits)
        .map_err(|e| invalid(format!("stump initialization failed: {e:?}")))?;
    let mut full = Chainstate::new(&params);
    let mut all_created = HashSet::new();
    let mut all_positions: Vec<BitcoinNodeHash> = Vec::new();
    let mut deleted_positions: Vec<BitcoinNodeHash> = Vec::new();

    for (height, block) in blocks.iter().enumerate().skip(1) {
        let height = u32::try_from(height)?;
        let inputs = resolve_inputs_from_store(&full, &prevouts, block, height)?;
        accept_at_height(&mut full, block, height)?;

        for (outpoint, coin) in inputs {
            audit
                .record_input_coin(&outpoint, &coin)
                .map_err(|e| invalid(format!("audit input record failed: {e:?}")))?;
        }

        let mut batch = Vec::new();
        let mut new_rows = Vec::new();
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
                if !all_created.insert(outpoint) || all_created.len() > MAX_OUTPUTS {
                    return Err(invalid(format!(
                        "duplicate or excessive spendable outpoint at height {height}"
                    ))
                    .into());
                }
                let coin = Coin {
                    out: output.clone(),
                    height,
                    coinbase: tx.is_coinbase(),
                };
                let survives = oracle_live.contains(&outpoint);
                audit
                    .record_output(
                        &outpoint,
                        &coin,
                        if survives {
                            OutputClass::SurvivesCheckpoint
                        } else {
                            OutputClass::SpentByCheckpoint
                        },
                    )
                    .map_err(|e| invalid(format!("audit output record failed: {e:?}")))?;
                let leaf = leaf_for(&outpoint, &coin);
                if survives {
                    batch.push(Some(leaf));
                } else {
                    batch.push(None);
                    deleted_positions.push(leaf);
                }
                all_positions.push(leaf);
                new_rows.push((outpoint, coin));
            }
        }
        if new_rows.len() > MAX_PREVOUT_BATCH {
            return Err(invalid("one fixture block exceeds the prevout batch bound").into());
        }
        prevouts
            .insert_batch(&new_rows)
            .map_err(|e| invalid(format!("prevout insert failed at height {height}: {e:?}")))?;
        stump
            .push(height, batch)
            .map_err(|e| invalid(format!("stump batch failed at height {height}: {e:?}")))?;
    }

    check_tip(&full, checkpoint_hash)?;
    if full.checked_height() != 500 {
        return Err(invalid(format!(
            "full replay checked height {}, expected 500",
            full.checked_height()
        ))
        .into());
    }
    let final_coins: HashMap<OutPoint, Coin> = full.utxo().iter().into_iter().collect();
    if final_coins != oracle_coins {
        return Err(invalid("shadow full-validation final UTXO differs from oracle").into());
    }
    if prevouts.len() != all_created.len() as u64 {
        return Err(
            invalid("prevout index does not contain every fixture spendable output").into(),
        );
    }
    let report = audit
        .finish(Network::Mainnet, 500, checkpoint_hash)
        .map_err(|e| invalid(format!("audit finish failed: {e:?}")))?;
    if report.verdict != AuditVerdict::Match {
        return Err(invalid("prevout-backed audit did not match full-validation inputs").into());
    }

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
    let receipt = ExternalAuditPassed::after_external_audit(swift_checkpoint);
    let provisional = stump
        .finish(receipt)
        .map_err(|e| invalid(format!("provisional stump finish failed: {e:?}")))?;
    if provisional.roots != explicit_roots || provisional.leaves != forest.leaves {
        return Err(invalid("provisional stump differs from explicit MemForest oracle").into());
    }

    // Save bounded metadata and release the redb handle before reopening: redb
    // keeps an exclusive process-local lock while the live store owns the DB.
    let expected_prevout_entries = prevouts.len();
    let expected_prevout_encoded_bytes = prevouts.encoded_bytes();
    drop(prevouts);

    let reopened = SwiftPrevoutStore::open(&db_path, checkpoint, limits)
        .map_err(|e| invalid(format!("prevout reopen failed: {e:?}")))?;
    if reopened.checkpoint() != checkpoint
        || reopened.len() != expected_prevout_entries
        || reopened.encoded_bytes() != expected_prevout_encoded_bytes
    {
        return Err(
            invalid("reopened prevout metadata differs from saved pre-close metadata").into(),
        );
    }
    let checked_height = full.checked_height();
    let prevout_entries = reopened.len();
    let prevout_encoded_bytes = reopened.encoded_bytes();
    drop(reopened);
    drop(temp);

    println!(
        "{{\"experiment\":\"swift_prevouts_shadow\",\"scope\":\"fixture_heights_0_500\",\
         \"fixture\":\"{FIXTURE}\",\"fixture_bytes\":{},\"fixture_sha256\":\"{}\",\
         \"network\":\"main\",\"assume_valid\":false,\"blocks\":{},\"checked_height\":{},\
         \"checkpoint_hash\":\"{}\",\"audit_verdict\":\"match\",\
         \"prevout_entries\":{},\"prevout_encoded_bytes\":{},\
         \"utxo_matches_full_validation_oracle\":true,\"stump_provisional\":true,\
         \"stump_leaves\":{},\"stump_roots_match_explicit_forest\":true,\
         \"modern_witness_taproot_coverage\":false}}",
        bytes.len(),
        hex(&sha256(&bytes)),
        blocks.len(),
        checked_height,
        checkpoint_hash,
        prevout_entries,
        prevout_encoded_bytes,
        provisional.leaves,
    );
    Ok(())
}

fn reject_args() -> io::Result<()> {
    if std::env::args_os().nth(1).is_some() {
        return Err(invalid(
            "this bounded experiment takes no arguments or arbitrary fixture paths",
        ));
    }
    Ok(())
}

fn read_fixture(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    if size != FIXTURE_BYTES as u64 || size > MAX_FIXTURE_BYTES as u64 {
        return Err(invalid(format!("unexpected bounded fixture length {size}")));
    }
    let mut bytes = Vec::with_capacity(FIXTURE_BYTES);
    file.take((MAX_FIXTURE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != FIXTURE_BYTES || hex(&sha256(&bytes)) != FIXTURE_SHA256 {
        return Err(invalid(
            "fixture size or SHA-256 differs from the committed fixture",
        ));
    }
    Ok(bytes)
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
        let frame_end = offset
            .checked_add(8)
            .ok_or_else(|| invalid("frame offset overflow"))?;
        if frame_end > bytes.len() || bytes[offset..offset + 4] != MAINNET_MAGIC {
            return Err(invalid("truncated frame or wrong mainnet magic"));
        }
        let block_len = u32::from_le_bytes(
            bytes[offset + 4..frame_end]
                .try_into()
                .map_err(|_| invalid("invalid frame length"))?,
        ) as usize;
        if block_len == 0 || block_len > MAX_BLOCK_SERIALIZED_SIZE {
            return Err(invalid("framed block length outside protocol bound"));
        }
        let end = frame_end
            .checked_add(block_len)
            .ok_or_else(|| invalid("frame end overflow"))?;
        if end > bytes.len() || blocks.len() >= MAX_BLOCKS {
            return Err(invalid("truncated frame or more than 501 blocks"));
        }
        blocks.push(
            Block::decode(&bytes[frame_end..end])
                .map_err(|error| invalid(format!("block decode failed: {error}")))?,
        );
        offset = end;
    }
    if offset != bytes.len() || blocks.len() != MAX_BLOCKS {
        return Err(invalid(format!(
            "expected exactly {MAX_BLOCKS} framed blocks"
        )));
    }
    Ok(blocks)
}

fn replay_full(chain: &mut Chainstate, blocks: &[Block], params: &Params) -> io::Result<()> {
    let genesis = blocks
        .first()
        .ok_or_else(|| invalid("fixture has no genesis block"))?;
    if genesis.block_hash() != params.genesis_header.hash()
        || !genesis.header.prev_block_hash.is_zero()
    {
        return Err(invalid("fixture genesis differs from mainnet parameters"));
    }
    let mut parent = genesis.block_hash();
    for (height, block) in blocks.iter().enumerate().skip(1) {
        if block.header.prev_block_hash != parent {
            return Err(invalid(format!("broken parent link at height {height}")));
        }
        accept_at_height(
            chain,
            block,
            u32::try_from(height).map_err(|_| invalid("fixture height overflow"))?,
        )?;
        parent = block.block_hash();
    }
    Ok(())
}

fn accept_at_height(chain: &mut Chainstate, block: &Block, height: u32) -> io::Result<()> {
    match chain.accept_block(block, ACCEPT_TIME).map_err(|error| {
        invalid(format!(
            "full validation rejected height {height}: {error:?}"
        ))
    })? {
        Acceptance::Connected {
            height: connected,
            reorged: false,
        } if connected == height => Ok(()),
        other => Err(invalid(format!(
            "unexpected acceptance at height {height}: {other:?}"
        ))),
    }
}

fn check_tip(chain: &Chainstate, checkpoint_hash: BlockHash) -> io::Result<()> {
    if chain.tip_hash() != checkpoint_hash || chain.chain().len() != MAX_BLOCKS {
        return Err(invalid(
            "full validation did not connect exactly through height 500",
        ));
    }
    if chain.checked_height() != 500 {
        return Err(invalid(format!(
            "full validation checked height {}, expected 500",
            chain.checked_height()
        )));
    }
    Ok(())
}

fn resolve_inputs_from_store(
    chain: &Chainstate,
    store: &SwiftPrevoutStore,
    block: &Block,
    height: u32,
) -> io::Result<Vec<(OutPoint, Coin)>> {
    let mut earlier_outputs = HashMap::new();
    let mut inputs = Vec::new();
    for tx in &block.transactions {
        if !tx.is_coinbase() {
            for input in &tx.inputs {
                let outpoint = input.previous_output;
                let coin = if let Some(coin) = earlier_outputs.remove(&outpoint) {
                    coin
                } else {
                    let indexed = store
                        .get(&outpoint)
                        .map_err(|error| invalid(format!("prevout lookup failed: {error:?}")))?
                        .ok_or_else(|| {
                            invalid(format!(
                                "prevout store lacks {}:{} at height {height}",
                                outpoint.txid, outpoint.vout
                            ))
                        })?;
                    let chain_coin = chain.utxo().get(&outpoint).ok_or_else(|| {
                        invalid(format!(
                            "full chainstate lacks indexed input {}:{} at height {height}",
                            outpoint.txid, outpoint.vout
                        ))
                    })?;
                    if indexed != chain_coin {
                        return Err(invalid(format!(
                            "prevout store coin differs from full chainstate at height {height}"
                        )));
                    }
                    indexed
                };
                inputs.push((outpoint, coin));
            }
        }
        let txid = tx.txid();
        for (vout, output) in tx.outputs.iter().enumerate() {
            if output.value >= 0 && !output.script_pubkey.is_unspendable() {
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
    }
    Ok(inputs)
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "avila-swift-prevouts-shadow-{}-{sequence}",
                std::process::id()
            ));
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

//! Bounded offline comparison of borrowed and owned asynchronous undo flushes.
//!
//! Usage: undo_flush_probe <fresh-directory> <borrowed|owned>
//!
//! This synthetic storage probe is not a consensus fixture or an IBD benchmark.

use avila_consensus::coinsdb::CoinsBackend;
use avila_consensus::connect::{BlockUndo, Coin, TxUndo, UtxoSet};
use avila_consensus::hash::{BlockHash, Txid};
use avila_consensus::transaction::{OutPoint, Script, TxOut};
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const UNDO_RECORDS: u32 = 64;
const TXS_PER_RECORD: u32 = 32;
const SPENT_PER_TX: u32 = 32;
const SCRIPT_BYTES: usize = 1024;
const SEED_COINS: u32 = 8;

#[derive(Clone, Copy)]
enum Mode {
    Borrowed,
    Owned,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Borrowed => "borrowed",
            Self::Owned => "owned",
        }
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn parse_args() -> io::Result<(PathBuf, Mode)> {
    let mut args = std::env::args_os().skip(1);
    let directory = args.next().map(PathBuf::from).ok_or_else(|| {
        invalid_input("usage: undo_flush_probe <fresh-directory> <borrowed|owned>")
    })?;
    let mode = match args.next() {
        Some(arg) => match arg.into_string() {
            Ok(mode) if mode == "borrowed" => Mode::Borrowed,
            Ok(mode) if mode == "owned" => Mode::Owned,
            Ok(_) => return Err(invalid_input("mode must be borrowed or owned")),
            Err(_) => return Err(invalid_input("mode must be valid UTF-8")),
        },
        None => return Err(invalid_input("missing mode: expected borrowed or owned")),
    };
    if args.next().is_some() {
        return Err(invalid_input("too many arguments"));
    }
    Ok((directory, mode))
}

fn create_fresh_directory(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid_input("directory path must name a new final component"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = fs::canonicalize(parent)?.join(name);
    match fs::symlink_metadata(&directory) {
        Ok(_) => {
            return Err(invalid_input(
                "destination already exists (including symlinks); refusing reuse",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::create_dir(&directory)?;
    Ok(directory)
}

fn hash_for_height(height: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&height.to_le_bytes());
    BlockHash::from_bytes(bytes)
}

fn build_original_undos() -> Vec<(u32, BlockHash, BlockUndo)> {
    let mut records = Vec::with_capacity(UNDO_RECORDS as usize);
    for height in 1..=UNDO_RECORDS {
        let mut txs = Vec::with_capacity(TXS_PER_RECORD as usize);
        for tx_index in 0..TXS_PER_RECORD {
            let mut spent = Vec::with_capacity(SPENT_PER_TX as usize);
            for coin_index in 0..SPENT_PER_TX {
                let unique = ((height - 1) * TXS_PER_RECORD * SPENT_PER_TX
                    + tx_index * SPENT_PER_TX
                    + coin_index) as u64;
                let mut script = vec![unique as u8; SCRIPT_BYTES];
                script[..8].copy_from_slice(&unique.to_le_bytes());
                spent.push(Coin {
                    out: TxOut {
                        value: unique as i64 + 1,
                        script_pubkey: Script::new(script),
                    },
                    height,
                    coinbase: false,
                });
            }
            txs.push(TxUndo {
                spent,
                overwritten: Vec::new(),
            });
        }
        records.push((height, hash_for_height(height), BlockUndo { txs }));
    }
    records
}

fn seed_coins(set: &mut UtxoSet) -> Vec<(OutPoint, Coin)> {
    let mut coins = Vec::with_capacity(SEED_COINS as usize);
    for index in 0..SEED_COINS {
        let outpoint = OutPoint {
            txid: Txid::from_bytes([0xA0 + index as u8; 32]),
            vout: index,
        };
        let coin = Coin {
            out: TxOut {
                value: 100_000 + index as i64,
                script_pubkey: Script::new(vec![0x51, index as u8]),
            },
            height: 1,
            coinbase: false,
        };
        set.insert_synthetic(outpoint, coin.clone());
        coins.push((outpoint, coin));
    }
    coins
}

fn verify_backend(
    backend: &CoinsBackend,
    undos: &[(u32, BlockHash, BlockUndo)],
    coins: &[(OutPoint, Coin)],
) -> io::Result<()> {
    if backend.tip_height() != UNDO_RECORDS {
        return Err(io::Error::other("backend tip did not match fixture"));
    }
    for (height, expected_hash, expected_undo) in undos {
        let Some((actual_hash, actual_undo)) = backend.undo_entry(*height) else {
            return Err(io::Error::other(format!("missing undo at height {height}")));
        };
        if actual_hash != *expected_hash || actual_undo != *expected_undo {
            return Err(io::Error::other(format!(
                "undo mismatch at height {height}"
            )));
        }
    }
    for (outpoint, expected_coin) in coins {
        if backend.get(outpoint).as_ref() != Some(expected_coin) {
            return Err(io::Error::other("seed coin mismatch"));
        }
    }
    Ok(())
}

fn vm_hwm_kib() -> io::Result<Option<u64>> {
    let mut file = File::open("/proc/self/status")?.take(64 * 1024);
    let mut status = String::new();
    file.read_to_string(&mut status)?;
    Ok(status.lines().find_map(|line| {
        let value = line.strip_prefix("VmHWM:")?.split_whitespace().next()?;
        value.parse().ok()
    }))
}

fn run() -> Result<(), Box<dyn Error>> {
    let (path, mode) = parse_args()?;
    let started = Instant::now();
    let directory = create_fresh_directory(&path)?;

    // This retained vector models Chainstate::undos. `pending` is the same
    // bounded deep copy each mode would hand to its flush API.
    let original = build_original_undos();
    let pending = original.clone();
    let backend = Arc::new(CoinsBackend::open(&directory)?);
    let mut utxo = UtxoSet::new();
    utxo.attach_shared(Arc::clone(&backend));
    let coins = seed_coins(&mut utxo);

    match mode {
        Mode::Borrowed => {
            utxo.flush_to_backend(&pending, UNDO_RECORDS)?;
            // Chainstate drops this local after handoff; its original undo
            // vector remains alive while the worker owns the clone.
            drop(pending);
            utxo.join_flush()?;
        }
        Mode::Owned => {
            utxo.flush_to_backend_owned(pending, UNDO_RECORDS)?;
            utxo.join_flush()?;
        }
    }
    verify_backend(&backend, &original, &coins)?;
    drop(utxo);
    drop(backend);

    let reopened = CoinsBackend::open(&directory)?;
    verify_backend(&reopened, &original, &coins)?;
    drop(reopened);

    let hwm = vm_hwm_kib()?;
    let hwm_field = hwm.map_or_else(|| "unavailable".to_owned(), |value| value.to_string());
    let coin_count = UNDO_RECORDS as u64 * TXS_PER_RECORD as u64 * SPENT_PER_TX as u64;
    let script_bytes = coin_count * SCRIPT_BYTES as u64;
    println!(
        "mode={} undo_records={} txs_per_record={} spent_coins_per_tx={} undo_coins={} script_bytes={} seed_coins={} elapsed_ms={} vm_hwm_kib={} verification=true",
        mode.as_str(),
        UNDO_RECORDS,
        TXS_PER_RECORD,
        SPENT_PER_TX,
        coin_count,
        script_bytes,
        SEED_COINS,
        started.elapsed().as_millis(),
        hwm_field,
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("undo_flush_probe: {error}");
        std::process::exit(2);
    }
}

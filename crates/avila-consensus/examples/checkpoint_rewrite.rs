//! Offline byte-equivalence and peak-memory probe for the v4 state writer.
//!
//! Usage: checkpoint_rewrite <source-dir> <fresh-destination-dir>
//!        checkpoint_rewrite <source-dir> <fresh-destination-dir> --buffered-reference
//!
//! This deliberately accepts only a bounded, mainnet v4 state with externalized
//! coins and no inline UTXO/undo data. Keep the source offline and immutable.

use avila_consensus::connect::{BlockUndo, Coin};
use avila_consensus::encode::{write_compact_size, write_var_bytes};
use avila_consensus::hash::sha256d;
use avila_consensus::params::Network;
use avila_consensus::store::{STATE_VERSION, StateData, read_state, write_state};
use avila_consensus::transaction::OutPoint;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy)]
enum Mode {
    Streaming,
    BufferedReference,
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn parse_args() -> io::Result<(PathBuf, PathBuf, Mode)> {
    let mut args = std::env::args_os().skip(1);
    let source = args.next().map(PathBuf::from).ok_or_else(|| {
        invalid_input(
            "usage: checkpoint_rewrite <source-dir> <fresh-destination-dir> [--buffered-reference]",
        )
    })?;
    let destination = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| invalid_input("missing fresh destination directory"))?;
    let mode = match args.next() {
        None => Mode::Streaming,
        Some(arg) => match arg.into_string() {
            Ok(arg) if arg == "--buffered-reference" => Mode::BufferedReference,
            Ok(_) => return Err(invalid_input("unknown option")),
            Err(_) => return Err(invalid_input("option must be valid UTF-8")),
        },
    };
    if args.next().is_some() {
        return Err(invalid_input("too many arguments"));
    }
    Ok((source, destination, mode))
}

fn resolve_destination(path: &Path, source: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid_input("destination must name a new directory"))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let destination = fs::canonicalize(parent)?.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            return Err(invalid_input(
                "destination already exists; refusing overwrite",
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    if destination.starts_with(source) || source.starts_with(&destination) {
        return Err(invalid_input("source and destination paths overlap"));
    }
    Ok(destination)
}

fn validate_source(source: &Path, magic: [u8; 4]) -> io::Result<u64> {
    let source = fs::canonicalize(source)?;
    if !fs::metadata(&source)?.is_dir() {
        return Err(invalid_input("source must be a directory"));
    }
    let state_path = source.join("state.dat");
    if !fs::symlink_metadata(&state_path)?.file_type().is_file() {
        return Err(invalid_input(
            "state.dat must be a regular file, not a symlink",
        ));
    }
    let size = fs::metadata(&state_path)?.len();
    if size > MAX_INPUT_BYTES {
        return Err(invalid_input("state.dat exceeds the 256 MiB input limit"));
    }
    // read_state removes a leftover state.dat.tmp. Refuse it so this probe
    // never mutates its source directory, even during interrupted-write cleanup.
    match fs::symlink_metadata(source.join("state.dat.tmp")) {
        Ok(_) => {
            return Err(invalid_input(
                "source has state.dat.tmp; refusing a source-mutating read",
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let mut file = File::open(state_path)?;
    let mut header = [0u8; 8];
    file.read_exact(&mut header)?;
    if header[..4] != magic[..] {
        return Err(invalid_input("state.dat is not a mainnet state file"));
    }
    let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if version != STATE_VERSION {
        return Err(invalid_input("only state.dat v4 is supported"));
    }
    Ok(size)
}

fn buffered_reference_bytes(data: &StateData, magic: [u8; 4]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(data.tip.as_bytes());
    payload.extend_from_slice(&data.height.to_le_bytes());
    write_compact_size(&mut payload, data.headers.len() as u64);
    for header in &data.headers {
        payload.extend_from_slice(&header.encode());
    }
    payload.extend_from_slice(data.best_header.as_bytes());
    write_compact_size(&mut payload, data.chain.len() as u64);
    for hash in &data.chain {
        payload.extend_from_slice(hash.as_bytes());
    }
    write_compact_size(&mut payload, data.undos.len() as u64);
    for undo in &data.undos {
        let mut encoded = Vec::new();
        put_undo(&mut encoded, undo);
        write_var_bytes(&mut payload, &encoded);
    }
    write_compact_size(&mut payload, data.utxo.len() as u64);
    for (outpoint, coin) in &data.utxo {
        put_outpoint(&mut payload, outpoint);
        put_coin(&mut payload, coin);
    }
    write_compact_size(&mut payload, data.failed.len() as u64);
    for hash in &data.failed {
        payload.extend_from_slice(hash.as_bytes());
    }
    write_compact_size(&mut payload, data.tx_meta.len() as u64);
    for (hash, n_tx, n_chain_tx) in &data.tx_meta {
        payload.extend_from_slice(hash.as_bytes());
        payload.extend_from_slice(&n_tx.to_le_bytes());
        payload.extend_from_slice(&n_chain_tx.to_le_bytes());
    }
    payload.extend_from_slice(&data.snapshot_base.to_le_bytes());
    let flags = u8::from(data.externalized) | (u8::from(data.snapshot_verified) << 1);
    payload.push(flags);

    let mut framed = Vec::with_capacity(payload.len() + 40);
    framed.extend_from_slice(&magic);
    framed.extend_from_slice(&STATE_VERSION.to_le_bytes());
    framed.extend_from_slice(&sha256d(&payload));
    framed.extend_from_slice(&payload);
    framed
}

fn put_coin(out: &mut Vec<u8>, coin: &Coin) {
    out.extend_from_slice(&coin.out.value.to_le_bytes());
    write_var_bytes(out, coin.out.script_pubkey.as_bytes());
    out.extend_from_slice(&coin.height.to_le_bytes());
    out.push(u8::from(coin.coinbase));
}

fn put_outpoint(out: &mut Vec<u8>, outpoint: &OutPoint) {
    out.extend_from_slice(outpoint.txid.as_bytes());
    out.extend_from_slice(&outpoint.vout.to_le_bytes());
}

fn put_undo(out: &mut Vec<u8>, undo: &BlockUndo) {
    write_compact_size(out, undo.txs.len() as u64);
    for tx in &undo.txs {
        write_compact_size(out, tx.spent.len() as u64);
        for coin in &tx.spent {
            put_coin(out, coin);
        }
        write_compact_size(out, tx.overwritten.len() as u64);
        for (outpoint, coin) in &tx.overwritten {
            put_outpoint(out, outpoint);
            put_coin(out, coin);
        }
    }
}

fn write_buffered_reference(
    destination: &Path,
    data: &StateData,
    magic: [u8; 4],
) -> io::Result<()> {
    let bytes = buffered_reference_bytes(data, magic);
    let temporary = destination.join("state.dat.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, destination.join("state.dat"))?;
    File::open(destination)?.sync_all()
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
    let (source_arg, destination_arg, mode) = parse_args()?;
    let source = fs::canonicalize(source_arg)?;
    let destination = resolve_destination(&destination_arg, &source)?;
    let magic = Network::Mainnet.params().message_start;
    let source_bytes = validate_source(&source, magic)?;
    let started = Instant::now();
    let state =
        read_state(&source, magic)?.ok_or_else(|| invalid_input("source state.dat disappeared"))?;
    if !state.externalized || !state.utxo.is_empty() || !state.undos.is_empty() {
        return Err(invalid_input(
            "checkpoint_rewrite accepts only v4 externalized state with empty inline UTXO and undo sections",
        )
        .into());
    }

    fs::create_dir(&destination)?;
    match mode {
        Mode::Streaming => write_state(&destination, magic, &state)?,
        Mode::BufferedReference => write_buffered_reference(&destination, &state, magic)?,
    }
    let bytes = fs::metadata(destination.join("state.dat"))?.len();
    let elapsed = started.elapsed();
    let mode_name = match mode {
        Mode::Streaming => "streaming",
        Mode::BufferedReference => "buffered-reference",
    };
    let hwm = vm_hwm_kib()?.map_or_else(|| "unavailable".to_string(), |n| n.to_string());
    println!(
        "mode={mode_name} height={} headers={} input_bytes={source_bytes} output_bytes={bytes} elapsed_ms={} vmhwm_kib={hwm}",
        state.height,
        state.headers.len(),
        elapsed.as_millis(),
    );
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("checkpoint_rewrite: {err}");
        std::process::exit(1);
    }
}

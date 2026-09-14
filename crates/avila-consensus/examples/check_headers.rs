//! Reference-adapter helper: feed raw concatenated 80-byte headers through
//! [`HeaderTree`] and print one verdict per header for comparison against the
//! reference daemon's `submitheader` RPC (see `tools/check_headers_core.py`).
//!
//! Usage: `check-headers <network> <headers.bin> <now>`
//!
//! `<network>` is `main`, `testnet4`, `signet` or `regtest`; `<now>` is the
//! unix timestamp the `time-too-new` check compares against. Each output line
//! is `<index>\t<verdict>\t<detail>` where `<verdict>` is `accepted`,
//! `accepted-known`, or `rejected:<reason>` with the reason token matching the
//! reject reason Bitcoin Core would report for the equivalent failure.

use std::process::ExitCode;

use avila_consensus::chain::{ChainError, HeaderTree, InsertStatus};
use avila_consensus::header::BlockHeader;
use avila_consensus::params::Network;
use avila_consensus::pow::PowError;
use avila_consensus::rules::TimeError;

fn network(name: &str) -> Option<Network> {
    Some(match name {
        "main" | "mainnet" => Network::Mainnet,
        "testnet4" => Network::Testnet4,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => return None,
    })
}

/// The reject reason Core's `submitheader`/`AcceptBlockHeader` reports for the
/// equivalent failure. Internal-only errors have no RPC-visible analog.
fn core_reason(err: &ChainError) -> &'static str {
    match err {
        ChainError::UnknownParent(_) => "prev-blk-not-found",
        ChainError::WrongBits { .. } => "bad-diffbits",
        // CheckProofOfWork failures all surface as "high-hash"
        // (BLOCK_HEADER_LOW_WORK) through submitheader.
        ChainError::Pow(
            PowError::NegativeTarget(_)
            | PowError::OverflowTarget(_)
            | PowError::ZeroTarget(_)
            | PowError::TargetAboveLimit(_)
            | PowError::InsufficientWork { .. },
        ) => "high-hash",
        ChainError::Pow(PowError::UnknownAncestor(_) | PowError::DegenerateDifficultyParams) => {
            "internal"
        }
        ChainError::Time(TimeError::TooOld { .. }) => "time-too-old",
        ChainError::Time(TimeError::Timewarp { .. }) => "time-timewarp-attack",
        ChainError::Time(TimeError::TooNew { .. }) => "time-too-new",
        ChainError::ChainWorkOverflow | ChainError::HeightOverflow => "internal",
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: {} <network> <headers.bin> <now>", args[0]);
        return ExitCode::FAILURE;
    }
    let Some(network) = network(&args[1]) else {
        eprintln!("unknown network {:?}", args[1]);
        return ExitCode::FAILURE;
    };
    let Ok(now) = args[3].parse::<u32>() else {
        eprintln!("invalid --now timestamp {:?}", args[3]);
        return ExitCode::FAILURE;
    };
    let bytes = match std::fs::read(&args[2]) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("cannot read {}: {err}", args[2]);
            return ExitCode::FAILURE;
        }
    };
    if !bytes.len().is_multiple_of(BlockHeader::SIZE) {
        eprintln!(
            "{}: length {} is not a multiple of the {}-byte header size",
            args[2],
            bytes.len(),
            BlockHeader::SIZE
        );
        return ExitCode::FAILURE;
    }

    let mut tree = HeaderTree::new(network.params());
    for (index, chunk) in bytes
        .as_chunks::<{ BlockHeader::SIZE }>()
        .0
        .iter()
        .enumerate()
    {
        let header = match BlockHeader::decode(chunk) {
            Ok(header) => header,
            Err(err) => {
                // Unreachable in practice: every 80-byte slice decodes.
                println!("{index}\trejected:decode\t{err}");
                continue;
            }
        };
        match tree.insert(&header, now) {
            Ok(InsertStatus::Added { height }) => println!("{index}\taccepted\theight={height}"),
            Ok(InsertStatus::AlreadyKnown { height }) => {
                println!("{index}\taccepted-known\theight={height}");
            }
            Err(err) => println!("{index}\trejected:{}\t{err}", core_reason(&err)),
        }
    }
    ExitCode::SUCCESS
}

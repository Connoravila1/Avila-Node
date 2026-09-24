//! Isolated replay driver. See tools/ecdsa_replay_bench.py for staging.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use avila_consensus::{
    block::Block, chainstate::Chainstate, coinstats::CoinStatsHashType,
    experimental_advice as advice, hash::Sha256d, params::Network, sigchecker::check_input_scripts,
};
use std::path::Path;
use std::time::Instant;

mod ecdsa_replay_cases;

fn take<'a>(data: &mut &'a [u8], count: usize) -> Result<&'a [u8], String> {
    if count > data.len() {
        return Err("truncated corpus".into());
    }
    let (head, rest) = data.split_at(count);
    *data = rest;
    Ok(head)
}
fn u32le(data: &mut &[u8]) -> Result<u32, String> {
    Ok(u32::from_le_bytes(take(data, 4)?.try_into().unwrap()))
}

struct Outcome {
    blocks: u64,
    transactions: u64,
    hash: String,
    coins: u64,
}

fn chain_replay(mut raw: &[u8]) -> Result<Outcome, String> {
    let network = match raw.get(..4) {
        Some([0xfa, 0xbf, 0xb5, 0xda]) => Network::Regtest,
        Some([0xf9, 0xbe, 0xb4, 0xd9]) => Network::Mainnet,
        _ => return Err("unsupported fixture network".into()),
    };
    let params = network.params();
    let mut cs = Chainstate::new(&params);
    let now = 2_000_000_000;
    let mut blocks = 0;
    let mut transactions = 0;
    while !raw.is_empty() {
        take(&mut raw, 4)?;
        let size = u32le(&mut raw)? as usize;
        if size > 4_000_000 {
            return Err("block bound".into());
        }
        let block = Block::decode(take(&mut raw, size)?).map_err(|e| e.to_string())?;
        cs.accept_header(&block.header, now)
            .map_err(|e| format!("header {blocks}: {e:?}"))?;
        cs.accept_block(&block, now)
            .map_err(|e| format!("block {blocks}: {e:?}"))?;
        blocks += 1;
        transactions += block.transactions.len() as u64;
    }
    cs.drain_scripts().map_err(|e| e.to_string())?;
    let state = cs.coin_stats(CoinStatsHashType::HashSerialized);
    Ok(Outcome {
        blocks,
        transactions,
        hash: state.hash_serialized.unwrap().to_string(),
        coins: state.txouts,
    })
}

fn scripts_replay(mut raw: &[u8]) -> Result<Outcome, String> {
    if take(&mut raw, 8)? != b"AVREPLAY" {
        return Err("corpus magic".into());
    }
    let params = Network::Mainnet.params();
    let mut digest = Sha256d::new();
    let mut previous = None;
    let mut blocks = 0;
    let mut transactions = 0;
    while !raw.is_empty() {
        let height = u32le(&mut raw)?;
        let size = u32le(&mut raw)? as usize;
        let undo_size = u32le(&mut raw)? as usize;
        if size > 4_000_000 || undo_size > 16 << 20 {
            return Err("corpus size bound".into());
        }
        let block = Block::decode(take(&mut raw, size)?).map_err(|e| e.to_string())?;
        avila_consensus::check::check_block(&block, &params).map_err(|e| e.to_string())?;
        if let Some(hash) = previous {
            if block.header.prev_block_hash != hash {
                return Err("broken corpus chain".into());
            }
        }
        let hash = block.block_hash();
        previous = Some(hash);
        digest.update(hash.as_bytes());
        let outputs =
            advice::undo_outputs(take(&mut raw, undo_size)?, &block).map_err(|e| e.to_string())?;
        let flags = avila_consensus::script::block_script_flags(&params, height, &hash);
        for (tx, prevouts) in block.transactions[1..].iter().zip(outputs.iter()) {
            check_input_scripts(tx, prevouts, flags)
                .map_err(|e| format!("height {height}, tx {}: {e:?}", tx.txid()))?;
            digest.update(tx.wtxid().as_bytes());
            transactions += 1;
        }
        blocks += 1;
    }
    Ok(Outcome {
        blocks,
        transactions,
        hash: avila_consensus::hex::encode(&digest.finalize()),
        coins: 0,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        7,
        "usage: replay <chain|scripts> <corpus> <baseline|capture|candidate> <trace-or-hints> <worker> <batch-size>"
    );
    assert!(
        std::fs::metadata(&args[2]).unwrap().len() <= 256 << 20,
        "bounded experiment corpus"
    );
    let raw = std::fs::read(&args[2]).unwrap();
    let mode = &args[3];
    let batch: usize = args[6].parse().unwrap();
    let replay = |bytes: &[u8]| match args[1].as_str() {
        "chain" => chain_replay(bytes),
        "scripts" => scripts_replay(bytes),
        "cases" => ecdsa_replay_cases::run(),
        _ => panic!("workload mode"),
    };
    let start = Instant::now();
    advice::configure(mode, Path::new(&args[4]), Path::new(&args[5]), batch).unwrap();
    let first = replay(&raw);
    let stats = advice::finish().unwrap();
    let retry = mode == "candidate" && (first.is_err() || stats.failed);
    let mut retry_stats = advice::Stats::default();
    let outcome = if retry {
        advice::configure("baseline", Path::new(""), Path::new(""), batch).unwrap();
        let ordinary = replay(&raw);
        retry_stats = advice::finish().unwrap();
        ordinary
    } else {
        first
    };
    let wall = start.elapsed().as_secs_f64();
    let outcome = match outcome {
        Ok(v) => v,
        Err(e) => {
            eprintln!("replay rejected: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "{{\"workload\":\"{}\",\"mode\":\"{}\",\"batch_size\":{},\"wall_seconds\":{:.9},\"blocks\":{},\"transactions\":{},\"result_hash\":\"{}\",\"coins\":{},\"checks\":{},\"hinted\":{},\"ordinary\":{},\"false_checks\":{},\"uncompressed\":{},\"hybrid\":{},\"high_s\":{},\"batches\":{},\"worker_cpu_seconds\":{:.9},\"hints_bytes\":{},\"fallback\":{},\"fallback_checks\":{}}}",
        args[1],
        mode,
        batch,
        wall,
        outcome.blocks,
        outcome.transactions,
        outcome.hash,
        outcome.coins,
        stats.checks,
        stats.hinted,
        stats.ordinary,
        stats.false_checks,
        stats.uncompressed,
        stats.hybrid,
        stats.high_s,
        stats.batches,
        stats.worker_cpu_ns as f64 / 1e9,
        stats.hints_bytes,
        retry,
        retry_stats.checks
    );
}

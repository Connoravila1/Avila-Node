//! Isolated replay driver. See tools/ecdsa_economics_bench.py for staging.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use avila_consensus::{
    block::Block, chainstate::Chainstate, coinstats::CoinStatsHashType,
    experimental_advice as advice, hash::Sha256d, params::Network,
};
use std::path::Path;
use std::time::Instant;

mod ecdsa_parallel_rollback;
mod ecdsa_stream_cases;

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

fn chain_replay(mut raw: &[u8], storage: &str) -> Result<Outcome, String> {
    let network = match raw.get(..4) {
        Some([0xfa, 0xbf, 0xb5, 0xda]) => Network::Regtest,
        Some([0xf9, 0xbe, 0xb4, 0xd9]) => Network::Mainnet,
        _ => return Err("unsupported fixture network".into()),
    };
    let params = network.params();
    let now = 2_000_000_000;
    let mut cs = if storage == "ram" {
        Chainstate::new(&params)
    } else {
        if Path::new(storage).exists() {
            return Err("fresh disk directory required".into());
        }
        Chainstate::with_store_coinsdb(Path::new(storage), &params, now, 1 << 20)
            .map_err(|e| e.to_string())?
    };
    cs.enable_speculative_connect();
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
    cs.flush().map_err(|e| e.to_string())?;
    let state = cs.coin_stats(CoinStatsHashType::HashSerialized);
    if storage != "ram" {
        let expected = (state.hash_serialized, state.txouts, cs.tip_hash());
        drop(cs);
        let restored = Chainstate::with_store_coinsdb(Path::new(storage), &params, now, 1 << 20)
            .map_err(|e| e.to_string())?;
        let actual = restored.coin_stats(CoinStatsHashType::HashSerialized);
        if (actual.hash_serialized, actual.txouts, restored.tip_hash()) != expected {
            return Err("durable reopen mismatch".into());
        }
    }
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
    let pool = avila_consensus::connect::ScriptPool::new(
        std::thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(1),
    );
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
        let outputs = avila_consensus::experimental_replay_util::undo_outputs(
            take(&mut raw, undo_size)?,
            &block,
        )
        .map_err(|e| e.to_string())?;
        let flags = avila_consensus::script::block_script_flags(&params, height, &hash);
        let jobs = block.transactions[1..]
            .iter()
            .zip(outputs)
            .map(|(tx, outs)| {
                digest.update(tx.wtxid().as_bytes());
                transactions += 1;
                (tx.clone(), outs, flags)
            })
            .collect();
        pool.experimental_submit(&block, jobs)
            .wait()
            .map_err(|e| format!("height {height}: {e:?}"))?;
        blocks += 1;
    }
    Ok(Outcome {
        blocks,
        transactions,
        hash: avila_consensus::hex::encode(&digest.finalize()),
        coins: 0,
    })
}

fn pack_replay(mut raw: &[u8], kind: &str, output: &Path) -> Result<Outcome, String> {
    use std::io::{BufWriter, Write};
    let mut writer = BufWriter::new(std::fs::File::create(output).map_err(|e| e.to_string())?);
    writer
        .write_all(avila_consensus::experimental_advice_codec::MAGIC)
        .map_err(|e| e.to_string())?;
    let mut blocks = 0;
    let mut transactions = 0;
    if kind == "cases" {
        ecdsa_stream_cases::pack(&mut writer).map_err(|e| e.to_string())?;
    } else {
        if kind == "scripts" && take(&mut raw, 8)? != b"AVREPLAY" {
            return Err("corpus magic".into());
        }
        while !raw.is_empty() {
            take(&mut raw, 4)?; // height (scripts) or magic (chain)
            let size = u32le(&mut raw)? as usize;
            let undo = if kind == "scripts" {
                u32le(&mut raw)? as usize
            } else {
                0
            };
            if size > 4_000_000 || undo > 16 << 20 {
                return Err("corpus bound".into());
            }
            let block = Block::decode(take(&mut raw, size)?).map_err(|e| e.to_string())?;
            take(&mut raw, undo)?;
            advice::pack_transactions(
                &mut writer,
                block.block_hash().as_bytes(),
                &block.transactions[1..],
            )
            .map_err(|e| e.to_string())?;
            blocks += 1;
            transactions += block.transactions.len() as u64;
        }
    }
    writer.flush().map_err(|e| e.to_string())?;
    Ok(Outcome {
        blocks,
        transactions,
        hash: String::new(),
        coins: 0,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(
        args.len(),
        10,
        "usage: parallel <chain|scripts|cases> <corpus> <baseline|capture|candidate> <sidecar> <worker> <batch> <minimum> <group-jobs> <ram|fresh-directory>"
    );
    assert!(std::fs::metadata(&args[2]).unwrap().len() <= 256 << 20);
    let raw = std::fs::read(&args[2]).unwrap();
    let start = Instant::now();
    let sidecar = if args[1] == "rollback" && args[3] == "candidate" {
        ecdsa_parallel_rollback::advice_for_invalid(&raw, Path::new(&args[4])).unwrap()
    } else {
        std::path::PathBuf::from(&args[4])
    };
    advice::configure(
        &args[3],
        &sidecar,
        Path::new(&args[5]),
        args[6].parse().unwrap(),
        args[7].parse().unwrap(),
        args[8].parse().unwrap(),
    )
    .unwrap();
    let outcome = if args[3] == "pack" {
        pack_replay(&raw, &args[1], Path::new(&args[9]))
    } else {
        match args[1].as_str() {
            "chain" => chain_replay(&raw, &args[9]),
            "scripts" => scripts_replay(&raw),
            "cases" => ecdsa_stream_cases::run(),
            "rollback" => ecdsa_parallel_rollback::run(&raw),
            _ => panic!("workload"),
        }
    };
    let stats = advice::finish().unwrap();
    let wall = start.elapsed().as_secs_f64();
    let outcome = match outcome {
        Ok(value) => value,
        Err(e) => {
            eprintln!("replay rejected: {e}");
            std::process::exit(1);
        }
    };
    let mut json = format!(
        concat!(
            "{{\"workload\":\"{}\",\"mode\":\"{}\",\"wall_seconds\":{:.9},",
            "\"blocks\":{},\"transactions\":{},\"result_hash\":\"{}\",\"coins\":{},",
            "\"checks\":{},\"hinted\":{},\"ordinary\":{},\"false_checks\":{},",
            "\"batches\":{},\"direct\":{},\"failed_batches\":{},\"worker_errors\":{},",
            "\"retry_groups\":{},\"retry_checks\":{},\"max_retry_jobs\":{},\"groups\":{},",
            "\"max_pending\":{},\"worker_cpu_seconds\":{:.9},\"workers\":{},",
            "\"hints_bytes\":{},\"sidecar_rejected\":{},\"disabled\":{}}}"
        ),
        args[1],
        args[3],
        wall,
        outcome.blocks,
        outcome.transactions,
        outcome.hash,
        outcome.coins,
        stats.checks,
        stats.hinted,
        stats.ordinary,
        stats.false_checks,
        stats.batches,
        stats.direct,
        stats.failed_batches,
        stats.worker_errors,
        stats.retry_groups,
        stats.retry_checks,
        stats.max_retry_jobs,
        stats.groups,
        stats.max_pending,
        stats.worker_cpu_ns as f64 / 1e9,
        stats.workers,
        stats.hints_bytes,
        stats.sidecar_rejected,
        stats.disabled
    );
    assert_eq!(json.pop(), Some('}'));
    println!(
        "{json},\"produced\":{},\"stream_bytes\":{},\"stream_frames\":{},\"stream_missed\":{},\"stream_rejected\":{},\"peak_frames\":{},\"peak_hint_bytes\":{}}}",
        stats.produced,
        stats.stream_bytes,
        stats.stream_frames,
        stats.stream_missed,
        stats.stream_rejected,
        stats.peak_frames,
        stats.peak_hint_bytes
    );
}

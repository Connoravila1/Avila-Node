// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Corpus-parallel script-replay benchmark (candidate #41).
//!
//! Reads an `AVCORP02` corpus produced by `tools/ibd_corpus_window.py`:
//! window transactions in chain order, each with per-input resolved
//! `TxOut`s looked up from the raw block corpus (no UTXO database, no
//! chainstate). Every fully-resolved tx is checked with the ordinary
//! `check_input_scripts` interpreter under exact per-height
//! `block_script_flags`.
//!
//! Counter model (per the 72–75 audit): resolution and execution are
//! distinct sets. A tx is *executed* only when every non-coinbase input
//! has a resolved prevout; resolved inputs inside excluded txs are counted
//! separately — the executed-inputs denominator is never inflated.
//! Coinbase-source metadata (creation height) rides each resolved input so
//! maturity can be checked separately from availability.
//!
//! Output: one JSON line per stage — "prep" (corpus parse/decode/memory),
//! "counters" (denominator reconciliation), and one "run" line per worker
//! count. Exit status is nonzero if any executed tx fails.
//!
//! Usage: corpus_replay <corpus.bin|dir> [--workers 1,2,4,8] [--jsonl path]

use avila_consensus::hash::BlockHash;
use avila_consensus::params::Network;
use avila_consensus::script::block_script_flags;
use avila_consensus::sigchecker::check_input_scripts;
use avila_consensus::transaction::{Script, Transaction, TxOut};

struct Source {
    out: TxOut,
    creation_height: u32,
    coinbase: bool,
}

struct Rec {
    height: u32,
    hash: [u8; 32],
    txs: Vec<(Vec<u8>, Vec<Option<Source>>)>,
}

fn u32at(b: &[u8], o: &mut usize) -> u32 {
    let v = u32::from_le_bytes(b[*o..*o + 4].try_into().unwrap());
    *o += 4;
    v
}

fn parse_corpus(raw: &[u8]) -> Vec<Rec> {
    assert_eq!(&raw[..8], b"AVCORP02", "bad magic (expect AVCORP02)");
    let mut o = 8usize;
    let mut blocks = Vec::new();
    while o < raw.len() {
        let height = u32at(raw, &mut o);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&raw[o..o + 32]);
        o += 32;
        let n_tx = u32at(raw, &mut o) as usize;
        let mut txs = Vec::with_capacity(n_tx);
        for _ in 0..n_tx {
            let n = u32at(raw, &mut o) as usize;
            let rawtx = raw[o..o + n].to_vec();
            o += n;
            let n_in = u32at(raw, &mut o) as usize;
            let mut outs = Vec::with_capacity(n_in);
            for _ in 0..n_in {
                let resolved = raw[o];
                o += 1;
                if resolved == 0 {
                    outs.push(None);
                } else {
                    let value = i64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
                    o += 8;
                    let sl = u32at(raw, &mut o) as usize;
                    let spk = Script::new(raw[o..o + sl].to_vec());
                    o += sl;
                    let creation_height = u32at(raw, &mut o);
                    let coinbase = raw[o] & 1 != 0;
                    o += 1;
                    outs.push(Some(Source {
                        out: TxOut {
                            value,
                            script_pubkey: spk,
                        },
                        creation_height,
                        coinbase,
                    }));
                }
            }
            txs.push((rawtx, outs));
        }
        blocks.push(Rec { height, hash, txs });
    }
    blocks
}

fn rss_hwm_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .map(|kb: u64| kb * 1024)
        .unwrap_or(0)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: corpus_replay <corpus.bin> [--workers 1,2,4,8] [--jsonl path]");
        std::process::exit(2);
    });
    let rest: Vec<String> = args.collect();
    let opt = |name: &str| -> Option<String> {
        rest.iter()
            .position(|a| a == name)
            .and_then(|i| rest.get(i + 1).cloned())
    };
    let workers: Vec<usize> = opt("--workers")
        .unwrap_or_else(|| "1,2,4,8".into())
        .split(',')
        .map(|s| s.parse().unwrap())
        .collect();
    if workers.contains(&0) {
        eprintln!(
            "error: worker counts must be positive — a 0-worker run cannot do the declared work"
        );
        std::process::exit(2);
    }
    let jsonl_path = opt("--jsonl");
    let corpus_path = if std::path::Path::new(&path).is_dir() {
        format!("{path}/corpus.bin")
    } else {
        path
    };

    let t_prep = std::time::Instant::now();
    let raw = std::fs::read(&corpus_path).unwrap();
    let corpus_bytes = raw.len() as u64;
    let blocks = parse_corpus(&raw);
    let parse_s = t_prep.elapsed().as_secs_f64();
    drop(raw);

    let t_tasks = std::time::Instant::now();
    let params = Network::Mainnet.params();
    struct Task {
        tx: Transaction,
        outs: Vec<TxOut>,
        flags: avila_consensus::script::ScriptFlags,
        n_in: usize,
    }
    // Denominator reconciliation (audit §5): every non-coinbase input lands
    // in exactly one bucket.
    let mut total_txs = 0usize;
    let mut total_inputs_noncb = 0usize;
    let mut inputs_resolved = 0usize;
    let mut inputs_missing_source = 0usize;
    let mut excluded_unresolved_txs = 0usize;
    let mut resolved_inputs_in_excluded_txs = 0usize;
    let mut excluded_immature_txs = 0usize;
    let mut immature_source_inputs = 0usize;
    let mut inputs_excluded_by_immaturity = 0usize;
    let mut resolved_inputs_in_immature_txs = 0usize;
    let mut tasks: Vec<Task> = Vec::new();
    let mut sel_bytes: Vec<u8> = Vec::new();
    for b in &blocks {
        let flags = block_script_flags(&params, b.height, &BlockHash::from_bytes(b.hash));
        for (txs_in_block, (rawtx, outs)) in b.txs.iter().enumerate() {
            total_txs += 1;
            let tx = Transaction::decode(rawtx).unwrap();
            let n_in = tx.inputs.len();
            assert_eq!(
                outs.len(),
                n_in,
                "corpus input-source vector length {} != decoded tx input count {}",
                outs.len(),
                n_in
            );
            let is_cb = n_in == 1 && tx.inputs[0].previous_output.is_null();
            if is_cb {
                continue; // coinbase inputs are not spends; never replayed
            }
            total_inputs_noncb += n_in;
            let n_missing = outs.iter().filter(|o| o.is_none()).count();
            inputs_missing_source += n_missing;
            inputs_resolved += n_in - n_missing;
            let n_immature = outs
                .iter()
                .filter(|o| {
                    o.as_ref()
                        .map(|s| s.coinbase && b.height < s.creation_height + 100)
                        .unwrap_or(false)
                })
                .count();
            immature_source_inputs += n_immature;
            if n_immature > 0 {
                // Detected consensus invalidity — distinct from missing-
                // source incompleteness. ALL inputs of this tx are excluded
                // by the immaturity predicate (including missing ones).
                excluded_immature_txs += 1;
                inputs_excluded_by_immaturity += n_in;
                resolved_inputs_in_immature_txs += n_in - n_missing;
                continue;
            }
            if n_missing > 0 {
                excluded_unresolved_txs += 1;
                resolved_inputs_in_excluded_txs += n_in - n_missing;
                continue;
            }
            let owned: Vec<TxOut> = outs
                .iter()
                .map(|o| o.as_ref().unwrap().out.clone())
                .collect();
            // executed-set membership record: block hash || u32 tx index
            // — the Python calibration tool reconstructs the identical set
            // and must produce the identical digest.
            sel_bytes.extend_from_slice(&b.hash);
            sel_bytes.extend_from_slice(&(txs_in_block as u32).to_le_bytes());
            tasks.push(Task {
                tx,
                outs: owned,
                flags,
                n_in,
            });
        }
    }
    let tasks_s = t_tasks.elapsed().as_secs_f64();
    let executed_txs = tasks.len();
    let executed_inputs: usize = tasks.iter().map(|t| t.n_in).sum();
    // Exact reconciliation (audit §5): every input lands in exactly one
    // input-level bucket; missing+resolved sum to the window total.
    assert_eq!(
        inputs_missing_source + inputs_resolved,
        total_inputs_noncb,
        "input-level reconciliation failed"
    );
    assert_eq!(
        executed_inputs + resolved_inputs_in_excluded_txs + resolved_inputs_in_immature_txs,
        inputs_resolved,
        "resolved-input reconciliation failed"
    );
    let rss = rss_hwm_bytes();
    let digest = avila_consensus::hash::sha256(&sel_bytes);
    let digest_hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let counters = format!(
        "{{\"type\":\"counters\",\"total_txs\":{total_txs},\
\"total_inputs_noncb\":{total_inputs_noncb},\"inputs_resolved\":{inputs_resolved},\
\"inputs_missing_source\":{inputs_missing_source},\
\"excluded_unresolved_txs\":{excluded_unresolved_txs},\
\"resolved_inputs_in_excluded_txs\":{resolved_inputs_in_excluded_txs},\
\"excluded_immature_txs\":{excluded_immature_txs},\
\"immature_source_inputs\":{immature_source_inputs},\
\"inputs_excluded_by_immaturity\":{inputs_excluded_by_immaturity},\
\"resolved_inputs_in_immature_txs\":{resolved_inputs_in_immature_txs},\
\"executed_txs\":{executed_txs},\"executed_inputs\":{executed_inputs},\
\"executed_set_digest\":\"{digest_hex}\"}}"
    );
    let prep = format!(
        "{{\"type\":\"prep\",\"corpus_bytes\":{corpus_bytes},\"blocks\":{},\
\"parse_s\":{parse_s:.3},\"task_build_s\":{tasks_s:.3},\"rss_hwm_bytes\":{rss}}}",
        blocks.len()
    );
    println!("{prep}\n{counters}");
    let mut jsonl = String::new();
    jsonl.push_str(&prep);
    jsonl.push('\n');
    jsonl.push_str(&counters);
    jsonl.push('\n');

    let tasks = std::sync::Arc::new(tasks);
    let mut any_failed = false;
    let ord = std::sync::atomic::Ordering::Relaxed;
    for &nw in &workers {
        let cursor = std::sync::atomic::AtomicUsize::new(0);
        let done = std::sync::atomic::AtomicUsize::new(0);
        let failed_txs = std::sync::atomic::AtomicUsize::new(0);
        let failed_inputs = std::sync::atomic::AtomicUsize::new(0);
        use avila_consensus::sigchecker::{
            ECDSA_SIGHASH_CALLS, ECDSA_VERIFY_BACKEND_CALLS, ECDSA_VERIFY_CALLS,
            ECDSA_VERIFY_CALLS_DER, ECDSA_VERIFY_CALLS_NONDER, SCHNORR_VERIFY_BACKEND_CALLS,
            SCHNORR_VERIFY_CALLS, SIGHASH_NS, VERIFY_NS,
        };
        let g = |a: &std::sync::atomic::AtomicU64| a.load(ord);
        let before = (
            g(&SIGHASH_NS),
            g(&VERIFY_NS),
            g(&ECDSA_SIGHASH_CALLS),
            g(&ECDSA_VERIFY_CALLS),
            g(&SCHNORR_VERIFY_CALLS),
            g(&ECDSA_VERIFY_BACKEND_CALLS),
            g(&SCHNORR_VERIFY_BACKEND_CALLS),
            g(&ECDSA_VERIFY_CALLS_DER),
            g(&ECDSA_VERIFY_CALLS_NONDER),
        );
        let t0 = std::time::Instant::now();
        std::thread::scope(|s| {
            for _ in 0..nw {
                s.spawn(|| {
                    loop {
                        let i = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if i >= tasks.len() {
                            break;
                        }
                        let t = &tasks[i];
                        if check_input_scripts(&t.tx, &t.outs, t.flags).is_err() {
                            failed_txs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            failed_inputs.fetch_add(t.n_in, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            done.fetch_add(t.n_in, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                });
            }
        });
        let el = t0.elapsed();
        let after = (
            g(&SIGHASH_NS),
            g(&VERIFY_NS),
            g(&ECDSA_SIGHASH_CALLS),
            g(&ECDSA_VERIFY_CALLS),
            g(&SCHNORR_VERIFY_CALLS),
            g(&ECDSA_VERIFY_BACKEND_CALLS),
            g(&SCHNORR_VERIFY_BACKEND_CALLS),
            g(&ECDSA_VERIFY_CALLS_DER),
            g(&ECDSA_VERIFY_CALLS_NONDER),
        );
        let (d_shns, d_vns, d_shc, d_ec, d_sc, d_ecb, d_scb, d_der, d_nonder) = (
            after.0 - before.0,
            after.1 - before.1,
            after.2 - before.2,
            after.3 - before.3,
            after.4 - before.4,
            after.5 - before.5,
            after.6 - before.6,
            after.7 - before.7,
            after.8 - before.8,
        );
        let inputs = done.load(std::sync::atomic::Ordering::Relaxed);
        let bad_txs = failed_txs.load(std::sync::atomic::Ordering::Relaxed);
        let bad_inputs = failed_inputs.load(std::sync::atomic::Ordering::Relaxed);
        if bad_txs > 0 {
            any_failed = true;
        }
        let line = format!(
            "{{\"type\":\"run\",\"workers\":{nw},\"wall_s\":{:.3},\
\"executed_txs\":{executed_txs},\"executed_inputs_ok\":{inputs},\
\"failed_txs\":{bad_txs},\"failed_inputs_ub\":{bad_inputs},\
\"ecdsa_sighash_calls\":{d_shc},\"ecdsa_verify_attempts\":{d_ec},\
\"schnorr_verify_attempts\":{d_sc},\
\"ecdsa_backend_calls\":{d_ecb},\"schnorr_backend_calls\":{d_scb},\
\"ecdsa_attempts_der\":{d_der},\"ecdsa_attempts_nonder\":{d_nonder},\
\"sighash_ms\":{:.1},\"verify_ms\":{:.1},\
\"inputs_per_s\":{:.0},\"us_per_input\":{:.2}}}",
            el.as_secs_f64(),
            d_shns as f64 / 1e6,
            d_vns as f64 / 1e6,
            inputs as f64 / el.as_secs_f64(),
            el.as_secs_f64() * 1e6 / inputs.max(1) as f64
        );
        println!("{line}");
        jsonl.push_str(&line);
        jsonl.push('\n');
    }
    // Post-run resource high-water (per audit: RSS must be sampled after
    // the worker runs, not only during preparation).
    let rss_end = rss_hwm_bytes();
    let fin = format!("{{\"type\":\"final\",\"rss_hwm_bytes\":{rss_end}}}");
    println!("{fin}");
    jsonl.push_str(&fin);
    jsonl.push('\n');
    if let Some(p) = jsonl_path {
        std::fs::write(&p, jsonl).unwrap();
    }
    // Detected consensus invalidity fails the run even with zero script
    // failures — distinct from missing-source incompleteness.
    if any_failed || immature_source_inputs > 0 {
        std::process::exit(1);
    }
}

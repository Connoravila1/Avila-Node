// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Flat-mirror lockstep on the REAL corpus: stream AVCORP03, apply
//! each tx's actual spends and outputs to two UtxoSets — one plain
//! (disk cascade) and one flat-enabled — flushing periodically so the
//! flat mirror's commit-delta path is exercised. Any divergence in
//! `get`/`have`/`iter` is a flat-consistency failure.
//!
//! Inputs whose resolution is in-window arrive as committed state on
//! first sight (the corpus starts mid-chain; seeding stands in for
//! the missing history). Divergence oracle: identical `spend`/`get`
//! results per op, plus a final full-`iter` set equality.
//!
//! Usage: flat_lockstep_corpus <corpus.bin> [--max-tx N]
//! Run under tools/guard_run.sh --max 8192.

use avila_consensus::coinsdb::CoinsBackend;
use avila_consensus::connect::{Coin, UtxoSet};
use avila_consensus::hash::Txid;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxOut};
use std::collections::HashMap;
use std::time::Instant;

fn u32at(b: &[u8], o: &mut usize) -> u32 {
    let v = u32::from_le_bytes(b[*o..*o + 4].try_into().unwrap());
    *o += 4;
    v
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap();
    let max_tx = usize::MAX;
    let raw = std::fs::read(&path).unwrap();
    assert_eq!(&raw[..8], b"AVCORP03", "bad magic");
    let mut o = 8usize;

    let dir_a = std::env::temp_dir().join(format!("avila-corplock-a-{}", std::process::id()));
    let dir_b = std::env::temp_dir().join(format!("avila-corplock-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    let mut plain = UtxoSet::new();
    plain.attach_backend(CoinsBackend::open(&dir_a).unwrap());
    let mut flat = UtxoSet::new();
    flat.attach_backend(CoinsBackend::open(&dir_b).unwrap());
    assert!(flat.enable_flat(0));

    let (mut n_tx, mut n_spend, mut n_seed, mut n_create) = (0u64, 0u64, 0u64, 0u64);
    let (mut t_read, mut t_flatread) = (std::time::Duration::ZERO, std::time::Duration::ZERO);
    let mut tip = 0u32;
    let t_all = Instant::now();

    'blocks: while o < raw.len() {
        let height = u32at(&raw, &mut o);
        o += 32 + 80;
        let ntx = u32at(&raw, &mut o) as usize;
        for _ in 0..ntx {
            let n = u32at(&raw, &mut o) as usize;
            let tx = Transaction::decode(&raw[o..o + n]).expect("decode");
            o += n;
            let nin = u32at(&raw, &mut o) as usize;
            let is_cb = tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null();
            if !is_cb {
                for inp in &tx.inputs {
                    let resolved = raw[o];
                    o += 1;
                    if resolved == 0 {
                        continue;
                    }
                    let value = i64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
                    o += 8;
                    let sl = u32at(&raw, &mut o) as usize;
                    let spk = Script::new(raw[o..o + sl].to_vec());
                    o += sl;
                    let h = u32at(&raw, &mut o);
                    let cb = raw[o] != 0;
                    o += 1;
                    // Seed on first sight when the creator is outside
                    // the window — stands in for missing history.
                    if plain.get(&inp.previous_output).is_none() {
                        let seed = Coin {
                            out: TxOut {
                                value,
                                script_pubkey: spk.clone(),
                            },
                            height: h,
                            coinbase: cb,
                        };
                        plain.insert_synthetic(inp.previous_output, seed.clone());
                        flat.insert_synthetic(inp.previous_output, seed);
                        n_seed += 1;
                    }
                    let t = Instant::now();
                    let a = plain.spend_coin(&inp.previous_output);
                    t_read += t.elapsed();
                    let t = Instant::now();
                    let b = flat.spend_coin(&inp.previous_output);
                    t_flatread += t.elapsed();
                    assert_eq!(a, b, "spend diverged at height {height}");
                    assert!(a.is_some(), "seeded coin unspendable at {height}");
                    n_spend += 1;
                }
            } else {
                o += nin; // coinbase inputs carry no resolution
            }
            // Outputs land in both sets identically.
            let txid: Txid = tx.txid();
            for (vout, out) in tx.outputs.iter().enumerate() {
                if out.script_pubkey.is_unspendable() {
                    continue;
                }
                let c = Coin {
                    out: out.clone(),
                    height,
                    coinbase: is_cb,
                };
                let op = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                plain.insert_synthetic(op, c.clone());
                flat.insert_synthetic(op, c);
                n_create += 1;
            }
            n_tx += 1;
            if n_tx % 50_000 == 0 {
                tip += 1;
                plain.flush_to_backend(&[], tip).unwrap();
                flat.flush_to_backend(&[], tip).unwrap();
                eprintln!(
                    "  tx {n_tx}  spends {n_spend}  seeds {n_seed}  live plain={} flat={}",
                    plain.len(),
                    flat.len()
                );
            }
            if n_tx >= max_tx as u64 {
                break 'blocks;
            }
        }
    }
    tip += 1;
    plain.flush_to_backend(&[], tip).unwrap();
    flat.flush_to_backend(&[], tip).unwrap();

    // Final equivalence: identical committed views.
    let a: HashMap<OutPoint, Coin> = plain.iter().into_iter().collect();
    let b: HashMap<OutPoint, Coin> = flat.iter().into_iter().collect();
    assert_eq!(a, b, "iter diverged — flat mirror inconsistency");

    eprintln!(
        "DONE: txs {n_tx}  spends {n_spend}  seeds {n_seed}  creates {n_create}  live {}",
        a.len()
    );
    eprintln!(
        "spend-time: plain {:.0}ns/in   flat {:.0}ns/in   ({:.1}x)   wall {:.1?}",
        t_read.as_secs_f64() * 1e9 / n_spend.max(1) as f64,
        t_flatread.as_secs_f64() * 1e9 / n_spend.max(1) as f64,
        t_read.as_secs_f64() / t_flatread.as_secs_f64().max(1e-9),
        t_all.elapsed()
    );
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

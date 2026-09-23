//! Write-amplification measurement: how much coin churn does the
//! write-back cache absorb before it reaches the backend?
//!
//! Simulates `ROUNDS` blocks of `CREATES` outputs each, spending a
//! share of previously-created coins after `AGE_BLOCKS` (the modern-
//! chain pattern: most spends are young). Reports gross ops vs
//! backend puts/dels executed — the gap is churn that died in cache.
//!
//! `CHURN_BUDGET_MB` bounds the write-back map — small budgets force
//! mid-simulation flushes and show where naive flush-all wastes work.

use avila_consensus::coinsdb::{CoinsBackend, Engine};
use avila_consensus::connect::{Coin, UtxoSet};
use avila_consensus::hash::Txid;
use avila_consensus::transaction::{OutPoint, Script, TxOut};

const ROUNDS: u32 = 4_000;
const CREATES: u32 = 2_000;
const AGE_BLOCKS: usize = 40;
const SPEND_FRAC: usize = 4; // spend ~1/4 of each aged cohort

fn op(n: u64) -> OutPoint {
    let mut t = [0u8; 32];
    t[..8].copy_from_slice(&n.to_le_bytes());
    OutPoint {
        txid: Txid::from_bytes(t),
        vout: 0,
    }
}

fn coin(n: u64) -> Coin {
    Coin {
        out: TxOut {
            value: (n % 50_000 + 1) as i64,
            script_pubkey: Script::new(vec![0x51]),
        },
        height: 1,
        coinbase: false,
    }
}

fn run(name: &str, engine: Engine, budget_mb: usize) {
    let dir = std::env::temp_dir().join(format!("avila-churn-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let be = std::sync::Arc::new(
        CoinsBackend::open_with_engine(&dir, engine).unwrap_or_else(|e| panic!("open: {e}")),
    );
    let mut set = UtxoSet::new();
    set.attach_shared(be.clone());
    set.set_budget(budget_mb << 20);

    let mut gross: u64 = 0;
    let mut flushes: u64 = 0;
    let mut cohorts: Vec<Vec<OutPoint>> = Vec::new();
    let mut n = 0u64;
    for r in 0..ROUNDS {
        let mut cohort = Vec::with_capacity(CREATES as usize);
        for _ in 0..CREATES {
            let o = op(n);
            set.insert_synthetic(o, coin(n));
            cohort.push(o);
            n += 1;
            gross += 1;
        }
        cohorts.push(cohort);
        // Spend a share of the cohort that is AGE_BLOCKS old.
        if cohorts.len() > AGE_BLOCKS {
            let aged = &cohorts[cohorts.len() - 1 - AGE_BLOCKS];
            for o in aged.iter().step_by(SPEND_FRAC) {
                set.spend_coin(o);
                gross += 1;
            }
        }
        if set.over_budget() {
            set.flush_to_backend(&[], r)
                .unwrap_or_else(|e| panic!("flush: {e}"));
            flushes += 1;
        }
    }
    set.flush_to_backend(&[], ROUNDS)
        .unwrap_or_else(|e| panic!("final: {e}"));

    let (commits, puts, dels) = be.write_stats();
    let disk = puts + dels;
    println!(
        "{name:>8} | budget {budget_mb:>4}M | gross {gross:>9} | flushes {flushes} \
         | backend commits {commits:>3} puts {puts:>9} dels {dels:>9} \
         | disk/gross {:.2}",
        disk as f64 / gross as f64
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn main() {
    let budget: usize = std::env::var("CHURN_BUDGET_MB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    run("redb", Engine::Redb, budget);
    run("hash", Engine::Hash, budget);
}

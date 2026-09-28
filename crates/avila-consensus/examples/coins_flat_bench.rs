// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Join-plane measurement on the REAL spend path: price
//! `UtxoSet::get` per input as IBD actually calls it
//! (check_tx_inputs → get → map → backend), then compare the same
//! input stream against a flat open-addressed table holding the same
//! coins — the measured probe winner from join_probe2 (172ns).
//!
//! Layers measured:
//!   1. utxo.get()      — dirty-map miss → backend get (real cascade)
//!   2. backend.get()   — redb/hash engine probe + decode alone
//!   3. mem UtxoSet     — all coins in `map` (pure HashMap path)
//!   4. flat36          — one open-addr probe, 80B slots, everything
//!   5. map→flat        — dirty overlay over flat (the honest proposal:
//!      tombstones must still shadow committed coins)
//!
//! Usage: coins_flat_bench [--engine redb|hash]
//! Run under tools/guard_run.sh --max 4096.

use avila_consensus::coinsdb::{CoinsBackend, Engine};
use avila_consensus::connect::{Coin, UtxoSet};
use avila_consensus::hash::Txid;
use avila_consensus::transaction::{OutPoint, Script, TxOut};
use std::collections::HashMap;
use std::time::Instant;

const N_BACKEND: usize = 3_000_000;
const N_DIRTY: usize = 200_000;
const N_INPUTS: usize = 1_000_000;
const CHUNK: usize = 250_000;

fn xs64(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

fn mk_op(s: &mut u64) -> OutPoint {
    let mut t = [0u8; 32];
    for b in t.chunks_mut(8) {
        b.copy_from_slice(&xs64(s).to_be_bytes());
    }
    OutPoint {
        txid: Txid::from_bytes(t),
        vout: (xs64(s) % 5) as u32,
    }
}

fn mk_coin(s: &mut u64) -> Coin {
    Coin {
        out: TxOut {
            value: (xs64(s) % 21_000_000) as i64 * 1000,
            script_pubkey: Script::new(vec![0x76; 25]),
        },
        height: (xs64(s) % 800_000) as u32,
        coinbase: xs64(s).is_multiple_of(97),
    }
}

/// Flat open-addressed coins table — the join_probe2 winner. One slot
/// per coin: 36B key + fixed-width body (spk capped at 28B inline for
/// the probe; a real build would pool longer scripts).
#[repr(C)]
#[derive(Clone, Copy)]
struct Slot {
    key: [u8; 36],
    vout: u32, // shadow copy so key stays a pure txid prefix + vout tail
    value: i64,
    height: u32,
    coinbase: u32,
    spk: [u8; 24],
}
impl Default for Slot {
    fn default() -> Self {
        Slot {
            key: [0; 36],
            vout: 0,
            value: 0,
            height: 0,
            coinbase: 0,
            spk: [0; 24],
        }
    }
}

struct Flat {
    slots: Vec<Slot>,
    mask: usize,
}

#[inline]
fn key_of(op: &OutPoint) -> [u8; 36] {
    let mut k = [0u8; 36];
    k[..32].copy_from_slice(op.txid.as_bytes());
    k[32..].copy_from_slice(&op.vout.to_le_bytes());
    k
}

#[inline]
fn h64(k: &[u8; 36]) -> usize {
    let lo = u64::from_le_bytes(k[..8].try_into().unwrap());
    let v = u32::from_le_bytes(k[32..36].try_into().unwrap()) as u64;
    lo.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(v) as usize
}

impl Flat {
    fn new(cap: usize) -> Flat {
        let n = ((cap as f64) / 0.7) as usize;
        Flat {
            slots: vec![Slot::default(); n.next_power_of_two()],
            mask: n.next_power_of_two() - 1,
        }
    }
    fn insert(&mut self, op: &OutPoint, c: &Coin) {
        let k = key_of(op);
        let mut i = h64(&k) & self.mask;
        while self.slots[i].coinbase & 0x8000_0000 != 0 {
            i = (i + 1) & self.mask;
        }
        let mut spk = [0u8; 24];
        let n = c.out.script_pubkey.as_bytes().len().min(24);
        spk[..n].copy_from_slice(&c.out.script_pubkey.as_bytes()[..n]);
        self.slots[i] = Slot {
            key: k,
            vout: op.vout,
            value: c.out.value,
            height: c.height,
            coinbase: u32::from(c.coinbase) | 0x8000_0000, // used bit
            spk,
        };
    }
    #[inline]
    fn get(&self, op: &OutPoint) -> Option<Slot> {
        let k = key_of(op);
        let mut i = h64(&k) & self.mask;
        loop {
            let s = &self.slots[i];
            if s.coinbase & 0x8000_0000 == 0 {
                return None; // never-used slot ends the chain
            }
            if s.coinbase & 0x4000_0000 == 0 && s.key == k {
                return Some(*s); // 0x4000_0000 = tombstone: keep probing
            }
            i = (i + 1) & self.mask;
        }
    }
    fn remove(&mut self, op: &OutPoint) {
        let k = key_of(op);
        let mut i = h64(&k) & self.mask;
        loop {
            let s = &mut self.slots[i];
            if s.coinbase & 0x8000_0000 == 0 {
                return;
            }
            if s.coinbase & 0x4000_0000 == 0 && s.key == k {
                s.coinbase |= 0x4000_0000; // tombstone: chain stays intact
                return;
            }
            i = (i + 1) & self.mask;
        }
    }
}

fn main() {
    let engine = if std::env::args().any(|a| a == "--engine=hash") {
        Engine::Hash
    } else {
        Engine::Redb
    };
    let dir = std::env::temp_dir().join(format!("avila-flatbench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut s = 0x9E37_79B9_7F4A_7C15u64;

    // ---- populate: N_BACKEND committed coins + N_DIRTY dirty --------
    let mut backend_ops = Vec::with_capacity(N_BACKEND);
    let mut backend_coins = Vec::with_capacity(N_BACKEND);
    for _ in 0..N_BACKEND {
        backend_ops.push(mk_op(&mut s));
        backend_coins.push(mk_coin(&mut s));
    }
    let be = CoinsBackend::open_with_engine(&dir, engine).unwrap();
    let t = Instant::now();
    for c in (0..N_BACKEND).step_by(CHUNK) {
        let mut dirty: HashMap<OutPoint, Option<Coin>> = HashMap::with_capacity(CHUNK);
        for i in c..(c + CHUNK).min(N_BACKEND) {
            dirty.insert(backend_ops[i], Some(backend_coins[i].clone()));
        }
        be.commit_partial(&dirty).unwrap();
        eprintln!("  committed {} coins", (c + CHUNK).min(N_BACKEND));
    }
    eprintln!("backend populate: {:.1}s", t.elapsed().as_secs_f64());

    let mut utxo = UtxoSet::new();
    utxo.attach_shared(std::sync::Arc::new(be));
    // Dirty layer: fresh coins + tombstones over backend coins.
    let mut dirty_ops = Vec::with_capacity(N_DIRTY);
    for _ in 0..N_DIRTY / 2 {
        let op = mk_op(&mut s);
        dirty_ops.push(op);
        utxo.insert_synthetic(op, mk_coin(&mut s));
    }
    for _ in 0..N_DIRTY / 2 {
        let i = (xs64(&mut s) as usize) % N_BACKEND;
        dirty_ops.push(backend_ops[i]);
        utxo.spend_coin(&backend_ops[i]);
    }
    eprintln!("dirty map: {} entries", N_DIRTY);

    // ---- input stream: ~85% backend-resident, ~15% dirty -----------
    let mut inputs = Vec::with_capacity(N_INPUTS);
    for _ in 0..N_INPUTS {
        let op = if xs64(&mut s) % 100 < 85 {
            backend_ops[(xs64(&mut s) as usize) % N_BACKEND]
        } else {
            dirty_ops[(xs64(&mut s) as usize) % dirty_ops.len()]
        };
        inputs.push(op);
    }

    // ---- 1: utxo.get() — the real cascade --------------------------
    let t = Instant::now();
    let mut acc = 0u64;
    for op in &inputs {
        if let Some(c) = utxo.get(op) {
            acc = acc.wrapping_add(c.out.value as u64);
        }
    }
    let cascade = t.elapsed().as_secs_f64() / N_INPUTS as f64 * 1e9;
    eprintln!(
        "1 utxo.get cascade ({:?}): {:.0} ns/in  acc={}",
        engine, cascade, acc
    );

    // ---- 2: backend.get() alone ------------------------------------
    let be2 = utxo.backend().unwrap();
    let t = Instant::now();
    let mut acc2 = 0u64;
    for op in &inputs {
        if let Some(c) = be2.get(op) {
            acc2 = acc2.wrapping_add(c.out.value as u64);
        }
    }
    let be_ns = t.elapsed().as_secs_f64() / N_INPUTS as f64 * 1e9;
    eprintln!("2 backend.get alone          : {:.0} ns/in", be_ns);

    // ---- 3: memory-only UtxoSet (everything in map) -----------------
    let mut mem = UtxoSet::new();
    for i in 0..N_BACKEND.min(1_500_000) {
        mem.insert_synthetic(backend_ops[i], backend_coins[i].clone());
    }
    let t = Instant::now();
    let mut acc3 = 0u64;
    for op in &inputs {
        if let Some(c) = mem.get(op) {
            acc3 = acc3.wrapping_add(c.out.value as u64);
        }
    }
    let mem_ns = t.elapsed().as_secs_f64() / N_INPUTS as f64 * 1e9;
    eprintln!(
        "3 mem UtxoSet (HashMap map)  : {:.0} ns/in (partial hits)",
        mem_ns
    );

    // ---- 4: flat36 — every coin, one probe --------------------------
    let mut flat = Flat::new(N_BACKEND + N_DIRTY);
    for i in 0..N_BACKEND {
        flat.insert(&backend_ops[i], &backend_coins[i]);
    }
    // dirty layer replayed over flat: fresh coins insert, spends remove.
    for (j, op) in dirty_ops.iter().enumerate() {
        if j < N_DIRTY / 2 {
            if let Some(c) = utxo.get(op) {
                flat.insert(op, &c);
            }
        } else {
            flat.remove(op);
        }
    }
    let t = Instant::now();
    let mut acc4 = 0u64;
    for op in &inputs {
        if let Some(sl) = flat.get(op) {
            acc4 = acc4.wrapping_add(sl.value as u64);
        }
    }
    let flat_ns = t.elapsed().as_secs_f64() / N_INPUTS as f64 * 1e9;
    eprintln!("4 flat36 one-probe           : {:.0} ns/in", flat_ns);

    // ---- 5: map-overlay over flat (the deployable shape) ------------
    // Read order preserves tombstone semantics: dirty map first (a
    // tombstone must shadow a flat hit), then flat.
    let mut overlay: HashMap<OutPoint, Option<Coin>> = HashMap::new();
    for op in &dirty_ops {
        overlay.insert(*op, utxo.get(op));
    }
    let t = Instant::now();
    let mut acc5 = 0u64;
    for op in &inputs {
        let v = match overlay.get(op) {
            Some(e) => e.clone(),
            None => flat.get(op).map(|sl| Coin {
                out: TxOut {
                    value: sl.value,
                    script_pubkey: Script::new(sl.spk.to_vec()),
                },
                height: sl.height,
                coinbase: (sl.coinbase & 1) != 0,
            }),
        };
        if let Some(c) = v {
            acc5 = acc5.wrapping_add(c.out.value as u64);
        }
    }
    let ov_ns = t.elapsed().as_secs_f64() / N_INPUTS as f64 * 1e9;
    eprintln!("5 dirty-map + flat overlay   : {:.0} ns/in", ov_ns);

    eprintln!(
        "cascade/flat = {:.1}x   backend-alone = {:.1}x flat",
        cascade / flat_ns,
        be_ns / flat_ns
    );

    // ---- 6: REAL utxo.get() with the flat layer enabled -------------
    // Same set, same input stream — the flat mirror is populated by
    // streaming the committed backend, then stays exact via flush
    // deltas. This is the in-crate deployable path.
    let t = Instant::now();
    assert!(utxo.enable_flat(0));
    eprintln!(
        "enable_flat populate: {:.1?} over {} committed",
        t.elapsed(),
        N_BACKEND
    );
    let t = Instant::now();
    let mut acc6 = 0u64;
    for op in &inputs {
        if let Some(c) = utxo.get(op) {
            acc6 = acc6.wrapping_add(c.out.value as u64);
        }
    }
    let flatget_ns = t.elapsed().as_secs_f64() / N_INPUTS as f64 * 1e9;
    eprintln!(
        "6 utxo.get + flat layer    : {:.0} ns/in  acc={acc6}  ({:.1}x cascade)",
        flatget_ns,
        cascade / flatget_ns
    );
    // sanity: identical accumulators
    assert_eq!(acc6, acc);

    let _ = std::fs::remove_dir_all(&dir);
}

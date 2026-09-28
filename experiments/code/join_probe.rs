// MIT-licensed research harness, not linked into Avila Node.
//
// Join-plane probe: the capacity forecast prices the prevout anti-join at
// ~6us/input serial — the cost of layered HashMap<OutPoint,Coin> lookups.
// This probe compares, on a realistic-size synthetic stream:
//
//   A) baseline  : HashMap<[u8;36]-shaped OutPoint, Coin> — today's shape
//   B) positional: txid -> txpos probe on a partitioned index, then a
//      u64-key open-addressing probe on the live-UTXO table
//   C) same as B but probing the txid index by sorted binary search
//
// The point: whether the join is hash-map physics or a reorganizable
// data structure. Run under tools/guard_run.sh.
//
// Build: rustc -O -C target-cpu=native join_probe.rs -o join_probe

use std::collections::HashMap;
use std::time::Instant;

const N_TX: usize = 40_000_000;      // historical txs (scaled-down corpus)
const M_LIVE: usize = 12_000_000;    // live UTXO entries
const M_SPEND: usize = 2_000_000;    // inputs in the probe stream

fn xs64(s: &mut u64) -> u64 {
    *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; *s
}

fn now() -> f64 {
    static T0: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    T0.get_or_init(Instant::now).elapsed().as_secs_f64()
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct OutPoint { txid: [u8; 32], vout: u32 }

// Coin: scriptPubKey(~25B)+amount(8)+flags — modeled as 24B payload.
#[derive(Clone, Copy, Default)]
struct Coin { amount: u64, spk_lo: u64, spk_hi: u64 }

// ---------- A. baseline: HashMap<OutPoint, Coin> ----------
fn bench_hashmap(outpoints: &[OutPoint], coins: &[Coin]) -> f64 {
    let mut map: HashMap<OutPoint, Coin> = HashMap::with_capacity(M_LIVE);
    for i in 0..M_LIVE { map.insert(outpoints[i], coins[i]); }
    let t = now();
    let mut acc = 0u64;
    for i in 0..M_SPEND {
        if let Some(c) = map.get(&outpoints[i % M_LIVE]) { acc += c.amount; }
    }
    let d = now() - t;
    std::hint::black_box(acc);
    d / M_SPEND as f64 * 1e9
}

// ---------- B. positional: partition txid index + u64 live table -------

// txid index: 256 partitions by txid[0]; each a sorted Vec<(u64 prefix, u32 pos)>
// covering txid[1..9]; probe = partition + binary search (branchless-ish).
struct TxIndex {
    parts: Vec<Vec<(u64, u32)>>,
}
impl TxIndex {
    fn build(txids: &[[u8; 32]]) -> TxIndex {
        let mut parts: Vec<Vec<(u64, u32)>> = vec![Vec::new(); 256];
        for (pos, t) in txids.iter().enumerate() {
            let mut k = [0u8; 8];
            k.copy_from_slice(&t[1..9]);
            parts[t[0] as usize].push((u64::from_be_bytes(k), pos as u32));
        }
        for p in &mut parts { p.sort_unstable(); }
        TxIndex { parts }
    }
    #[inline]
    fn get(&self, txid: &[u8; 32]) -> Option<u32> {
        let p = &self.parts[txid[0] as usize];
        let mut k = [0u8; 8];
        k.copy_from_slice(&txid[1..9]);
        let k = u64::from_be_bytes(k);
        let lo = p.partition_point(|&(pk, _)| pk < k);
        (lo < p.len() && p[lo].0 == k).then(|| p[lo].1)
    }
}

// live UTXO: open-addressing u64 -> Coin, Fibonacci hash.
struct LiveSet {
    slots: Vec<u64>,   // 0 = empty (keys never 0: we use key|1 encoding)
    coins: Vec<Coin>,
    mask: usize,
}
impl LiveSet {
    fn new(cap: usize) -> LiveSet {
        let n = cap.next_power_of_two() * 2;
        LiveSet { slots: vec![0; n], coins: vec![Coin::default(); n], mask: n - 1 }
    }
    #[inline]
    fn hash(k: u64) -> usize { (k.wrapping_mul(0x9E3779B97F4A7C15) >> 24) as usize }
    fn insert(&mut self, k: u64, c: Coin) {
        let k = k | 1;
        let mut i = Self::hash(k) & self.mask;
        while self.slots[i] != 0 { i = (i + 1) & self.mask; }
        self.slots[i] = k; self.coins[i] = c;
    }
    #[inline]
    fn get(&self, k: u64) -> Option<Coin> {
        let k = k | 1;
        let mut i = Self::hash(k) & self.mask;
        while self.slots[i] != 0 {
            if self.slots[i] == k { return Some(self.coins[i]); }
            i = (i + 1) & self.mask;
        }
        None
    }
}

fn main() {
    // build txid table + the live-set outpoints and spend stream.
    let mut s = 0x9E3779B97F4A7C15u64;
    let mut txids = vec![[0u8; 32]; N_TX];
    for t in &mut txids {
        for b in t.chunks_mut(8) { b.copy_from_slice(&xs64(&mut s).to_be_bytes()); }
    }
    // live outpoints: each picks a random past tx and a vout.
    let mut outpoints = vec![OutPoint { txid: [0; 32], vout: 0 }; M_LIVE];
    for op in &mut outpoints {
        let t = (xs64(&mut s) as usize) % N_TX;
        op.txid = txids[t];
        op.vout = (xs64(&mut s) % 5) as u32;
    }
    let mut coins = vec![Coin::default(); M_LIVE];
    for c in &mut coins { c.amount = xs64(&mut s); }

    eprintln!("built inputs (untimed)");

    // ---- B: build positional structures ----
    let t = now();
    let index = TxIndex::build(&txids);
    let build_idx = now() - t;
    let t = now();
    let mut live = LiveSet::new(M_LIVE);
    // positional key: pos << 16 | vout  (probe models the *structure*, not
    // the true position — pos here is the index rank within its partition)
    for i in 0..M_LIVE {
        let pos = index.get(&outpoints[i].txid).unwrap() as u64;
        live.insert(pos << 16 | outpoints[i].vout as u64, coins[i]);
    }
    let build_live = now() - t;
    eprintln!("index build {build_idx:.2}s  live build {build_live:.2}s");

    // spend stream: random picks from the live set's outpoints
    let t = now();
    let mut acc = 0u64;
    for i in 0..M_SPEND {
        let op = &outpoints[(xs64(&mut s) as usize) % M_LIVE];
        if let Some(pos) = index.get(&op.txid) {
            let key = (pos as u64) << 16 | op.vout as u64;
            if let Some(c) = live.get(key) { acc += c.amount; }
        }
    }
    let pos_ns = (now() - t) / M_SPEND as f64 * 1e9;
    std::hint::black_box(acc);
    eprintln!("positional: {pos_ns:.1} ns/input");

    // spend-stream upper bound on the SAME data, HashMap baseline:
    let hm_ns = bench_hashmap(&outpoints, &coins);
    eprintln!("hashmap   : {hm_ns:.1} ns/input");

    // live-table probe only (isolates the txid-index share):
    let t = now();
    let mut acc = 0u64;
    for i in 0..M_SPEND {
        let op = &outpoints[(xs64(&mut s) as usize) % M_LIVE];
        let pos = index.get(&op.txid).unwrap_or(0) as u64;
        if let Some(c) = live.get(pos << 16 | op.vout as u64) { acc += c.amount; }
    }
    let both_ns = (now() - t) / M_SPEND as f64 * 1e9;
    std::hint::black_box(acc);
    eprintln!("positional (repeat, cache-warm): {both_ns:.1} ns/input");

    eprintln!("ratio hashmap/positional = {:.2}x", hm_ns / pos_ns);

    // ---- isolation probes ----
    // (a) u64-key HashMap: isolates the key-size effect
    {
        let mut m64: HashMap<u64, Coin> = HashMap::with_capacity(M_LIVE);
        for i in 0..M_LIVE {
            let pos = i as u64;
            m64.insert(pos << 16 | outpoints[i].vout as u64, coins[i]);
        }
        let t = now();
        let mut acc = 0u64;
        for i in 0..M_SPEND {
            let op = &outpoints[(xs64(&mut s) as usize) % M_LIVE];
            let pos = i as u64 % M_LIVE as u64; // stand-in: any present key
            if let Some(c) = m64.get(&(pos << 16 | op.vout as u64)) { acc += c.amount; }
        }
        let d = (now() - t) / M_SPEND as f64 * 1e9;
        std::hint::black_box(acc);
        eprintln!("hashmap u64-key       : {d:.1} ns/input");
    }
    // (b) u64 open-addr table probe alone (the live-set half of B)
    {
        let t = now();
        let mut acc = 0u64;
        for i in 0..M_SPEND {
            let op = &outpoints[(xs64(&mut s) as usize) % M_LIVE];
            let key = (i as u64 % M_LIVE as u64) << 16 | op.vout as u64;
            if let Some(c) = live.get(key) { acc += c.amount; }
        }
        let d = (now() - t) / M_SPEND as f64 * 1e9;
        std::hint::black_box(acc);
        eprintln!("u64 open-addr live tbl: {d:.1} ns/input");
    }
    // (b2) txid partition index probe alone (the expensive half)
    {
        let t = now();
        let mut acc = 0u64;
        for _ in 0..M_SPEND {
            let op = &outpoints[(xs64(&mut s) as usize) % M_LIVE];
            if let Some(pos) = index.get(&op.txid) { acc += pos as u64; }
        }
        let d = (now() - t) / M_SPEND as f64 * 1e9;
        std::hint::black_box(acc);
        eprintln!("txid partition probe  : {d:.1} ns/input");
    }
    // (c) sorted-merge floor: sequential scan of a sorted u64 array
    {
        let mut keys: Vec<u64> = (0..M_LIVE as u64)
            .map(|i| i << 16 | (xs64(&mut s) % 5)).collect();
        keys.sort_unstable();
        let t = now();
        let mut acc = 0u64;
        let mut j = 0usize;
        for _ in 0..M_SPEND {
            let k = keys[(xs64(&mut s) as usize) % M_LIVE];
            j = keys.partition_point(|&x| x < k);
            if j < keys.len() && keys[j] == k { acc += k; }
        }
        let d = (now() - t) / M_SPEND as f64 * 1e9;
        std::hint::black_box((acc, j));
        eprintln!("sorted u64 binsearch  : {d:.1} ns/input");
    }
}

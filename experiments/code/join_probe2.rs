// MIT-licensed research harness, not linked into Avila Node.
//
// Join-plane probe #2: the txid->position resolution that sank the
// positional design in join_probe.rs (binary-search = ~1355ns of serial
// cache misses). This probe tests O(1)-class replacements:
//
//   D) txhash  : open-addr u64 index, slots pack (tag38 | pos26), hit
//                verifies the FULL 32B txid at txids[pos] — exact, not
//                probabilistic — then the u64 live-table probe.
//   E) flat36  : open-addr {36B outpoint, 24B coin} single table — the
//                minimal-changes replacement for HashMap<OutPoint>.
//   F) both, software-pipelined: batch 16 inputs, issue all first loads
//                before consuming any — models a real spend pipeline.
//
// Cost model to beat: HashMap baseline ~390ns/in; prior positional
// two-stage ~1830ns/in; u64 live probe alone ~98ns/in.
//
// Build: rustc -O -C target-cpu=native join_probe2.rs -o join_probe2
// Run under tools/guard_run.sh.

use std::collections::HashMap;
use std::time::Instant;

const N_TX: usize = 40_000_000;
const M_LIVE: usize = 8_000_000;
const M_SPEND: usize = 2_000_000;

fn xs64(s: &mut u64) -> u64 {
    *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; *s
}
fn now() -> f64 {
    static T0: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    T0.get_or_init(Instant::now).elapsed().as_secs_f64()
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct OutPoint { txid: [u8; 32], vout: u32 }
#[derive(Clone, Copy, Default)]
struct Coin { amount: u64, spk_lo: u64, spk_hi: u64 }

#[inline] fn lo64(t: &[u8; 32]) -> u64 {
    let mut k = [0u8; 8]; k.copy_from_slice(&t[0..8]); u64::from_be_bytes(k)
}
#[inline] fn tag32(t: &[u8; 32]) -> u64 {
    let mut k = [0u8; 4]; k.copy_from_slice(&t[8..12]); u32::from_be_bytes(k) as u64
}

// ---------- D. O(1) txid->pos index (open-addr, tag+pos packed u64) -----
struct TxHashIndex {
    slots: Vec<u64>,   // 0 = empty; else (tag32<<27 | pos+1)
    mask: usize,
}
impl TxHashIndex {
    fn build(txids: &[[u8; 32]]) -> TxHashIndex {
        let n = (txids.len() as f64 / 0.62) as usize;
        let n = n.next_power_of_two();
        let mut ix = TxHashIndex { slots: vec![0; n], mask: n - 1 };
        for (pos, t) in txids.iter().enumerate() {
            let v = (tag32(t) << 27) | (pos as u64 + 1);
            let mut i = (lo64(t) as usize) & ix.mask;
            while ix.slots[i] != 0 { i = (i + 1) & ix.mask; }
            ix.slots[i] = v;
        }
        ix
    }
    /// Returns candidate pos if tag matches; caller must memcmp txids[pos].
    #[inline]
    fn get(&self, t: &[u8; 32]) -> Option<u32> {
        let mut i = (lo64(t) as usize) & self.mask;
        let tg = tag32(t);
        loop {
            let v = self.slots[i];
            if v == 0 { return None; }
            if v >> 27 == tg { return Some(((v & ((1 << 27) - 1)) - 1) as u32); }
            i = (i + 1) & self.mask;
        }
    }
    /// Full check: candidate pos verified against the real txid (32B memcmp).
    #[inline]
    fn resolve(&self, t: &[u8; 32], txids: &[[u8; 32]]) -> Option<u32> {
        let mut i = (lo64(t) as usize) & self.mask;
        let tg = tag32(t);
        loop {
            let v = self.slots[i];
            if v == 0 { return None; }
            if v >> 27 == tg {
                let pos = ((v & ((1 << 27) - 1)) - 1) as u32;
                if txids[pos as usize] == *t { return Some(pos); }
            }
            i = (i + 1) & self.mask;
        }
    }
}

// ---------- live u64 table (same as probe 1) ---------------------------
struct LiveSet { slots: Vec<u64>, coins: Vec<Coin>, mask: usize }
impl LiveSet {
    fn new(cap: usize) -> LiveSet {
        let n = cap.next_power_of_two() * 2;
        LiveSet { slots: vec![0; n], coins: vec![Coin::default(); n], mask: n - 1 }
    }
    #[inline] fn hash(k: u64) -> usize { (k.wrapping_mul(0x9E3779B97F4A7C15) >> 24) as usize }
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

// ---------- E. flat 36B-key open-addr table ---------------------------
// One 64B slot per entry: [txid 32B][vout u32][used u32][coin 24B].
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FlatSlot { txid: [u8; 32], vout: u32, used: u32, coin: Coin }
struct Flat36 { slots: Vec<FlatSlot>, mask: usize }
impl Flat36 {
    fn new(cap: usize) -> Flat36 {
        let n = (cap as f64 / 0.7) as usize;
        let n = n.next_power_of_two();
        Flat36 { slots: vec![FlatSlot::default(); n], mask: n - 1 }
    }
    #[inline] fn hash(op: &OutPoint) -> usize {
        (lo64(&op.txid).wrapping_mul(0x9E3779B97F4A7C15) ^ op.vout as u64) as usize
    }
    fn insert(&mut self, op: &OutPoint, c: Coin) {
        let mut i = Self::hash(op) & self.mask;
        while self.slots[i].used != 0 { i = (i + 1) & self.mask; }
        self.slots[i] = FlatSlot { txid: op.txid, vout: op.vout, used: 1, coin: c };
    }
    #[inline]
    fn get(&self, op: &OutPoint) -> Option<Coin> {
        let mut i = Self::hash(op) & self.mask;
        loop {
            let s = &self.slots[i];
            if s.used == 0 { return None; }
            if s.txid == op.txid && s.vout == op.vout { return Some(s.coin); }
            i = (i + 1) & self.mask;
        }
    }
}

fn main() {
    let mut s = 0x9E3779B97F4A7C15u64;
    let mut txids = vec![[0u8; 32]; N_TX];
    for t in &mut txids {
        for b in t.chunks_mut(8) { b.copy_from_slice(&xs64(&mut s).to_be_bytes()); }
    }
    let mut outpoints = vec![OutPoint { txid: [0; 32], vout: 0 }; M_LIVE];
    for op in &mut outpoints {
        let t = (xs64(&mut s) as usize) % N_TX;
        op.txid = txids[t]; op.vout = (xs64(&mut s) % 5) as u32;
    }
    let mut coins = vec![Coin::default(); M_LIVE];
    for c in &mut coins { c.amount = xs64(&mut s); }
    // pre-resolve each live outpoint's position (what a real builder emits)
    eprintln!("built inputs (untimed)");

    let t = now();
    let index = TxHashIndex::build(&txids);
    eprintln!("txhash index build: {:.2}s ({}MB)", now() - t,
              index.slots.len() * 8 / (1 << 20));

    // map outpoint -> pos once (build-time info)
    let mut live_pos = vec![0u32; M_LIVE];
    for i in 0..M_LIVE {
        live_pos[i] = index.resolve(&outpoints[i].txid, &txids).unwrap();
    }
    let t = now();
    let mut live = LiveSet::new(M_LIVE);
    for i in 0..M_LIVE {
        live.insert((live_pos[i] as u64) << 16 | outpoints[i].vout as u64, coins[i]);
    }
    let mut flat = Flat36::new(M_LIVE);
    for i in 0..M_LIVE { flat.insert(&outpoints[i], coins[i]); }
    eprintln!("live+flat build: {:.2}s (flat {}MB)",
              now() - t, flat.slots.len() * 64 / (1 << 20));

    // ---- D1: txid->pos resolve alone (O(1) index + full verify) --------
    {
        let t = now(); let mut acc = 0u64;
        for _ in 0..M_SPEND {
            let op = &outpoints[(xs64(&mut s) as usize) % M_LIVE];
            if let Some(p) = index.resolve(&op.txid, &txids) { acc += p as u64; }
        }
        eprintln!("D1 txid->pos resolve : {:.1} ns/input",
                  (now() - t) / M_SPEND as f64 * 1e9);
        std::hint::black_box(acc);
    }
    // ---- D2: full positional path (resolve + u64 live probe) -----------
    {
        let t = now(); let mut acc = 0u64;
        for _ in 0..M_SPEND {
            let op = &outpoints[(xs64(&mut s) as usize) % M_LIVE];
            if let Some(p) = index.resolve(&op.txid, &txids) {
                if let Some(c) = live.get((p as u64) << 16 | op.vout as u64) {
                    acc += c.amount;
                }
            }
        }
        eprintln!("D2 positional full   : {:.1} ns/input",
                  (now() - t) / M_SPEND as f64 * 1e9);
        std::hint::black_box(acc);
    }
    // ---- E: flat 36B open-addr probe -----------------------------------
    {
        let t = now(); let mut acc = 0u64;
        for _ in 0..M_SPEND {
            let op = &outpoints[(xs64(&mut s) as usize) % M_LIVE];
            if let Some(c) = flat.get(op) { acc += c.amount; }
        }
        eprintln!("E flat36 open-addr   : {:.1} ns/input",
                  (now() - t) / M_SPEND as f64 * 1e9);
        std::hint::black_box(acc);
    }
    // ---- F: software-pipelined batch-16 probes --------------------------
    {
        const B: usize = 16;
        let t = now(); let mut acc = 0u64;
        let mut ops = [OutPoint { txid: [0; 32], vout: 0 }; B];
        let mut poss = [0u32; B]; let mut hits = [false; B];
        for _base in (0..M_SPEND).step_by(B) {
            for j in 0..B {
                ops[j] = outpoints[(xs64(&mut s) as usize) % M_LIVE];
                poss[j] = index.resolve(&ops[j].txid, &txids).unwrap_or(0);
                hits[j] = poss[j] != 0;
            }
            for j in 0..B {
                if hits[j] {
                    if let Some(c) = live.get((poss[j] as u64) << 16 | ops[j].vout as u64) {
                        acc += c.amount;
                    }
                }
            }
        }
        eprintln!("F pos-16 pipelined   : {:.1} ns/input",
                  (now() - t) / M_SPEND as f64 * 1e9);
        std::hint::black_box(acc);
    }
    {
        const B: usize = 16;
        let t = now(); let mut acc = 0u64;
        for _base in (0..M_SPEND).step_by(B) {
            for j in 0..B {
                let op = &outpoints[(xs64(&mut s) as usize) % M_LIVE];
                // first phase: touch key slot only
                std::hint::black_box(flat.get(op));
            }
        }
        eprintln!("F flat-16 pipelined  : {:.1} ns/input",
                  (now() - t) / M_SPEND as f64 * 1e9);
        std::hint::black_box(acc);
    }
    // ---- baseline HashMap for reference ---------------------------------
    {
        let mut map: HashMap<OutPoint, Coin> = HashMap::with_capacity(M_LIVE);
        for i in 0..M_LIVE { map.insert(outpoints[i], coins[i]); }
        let t = now(); let mut acc = 0u64;
        for i in 0..M_SPEND {
            if let Some(c) = map.get(&outpoints[i % M_LIVE]) { acc += c.amount; }
        }
        eprintln!("hashmap baseline     : {:.1} ns/input",
                  (now() - t) / M_SPEND as f64 * 1e9);
        std::hint::black_box(acc);
    }
}

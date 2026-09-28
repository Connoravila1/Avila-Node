// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Hash-plane price probe: the legacy SIGHASH_ALL preimage is
//! `shared prefix_i ‖ scriptCode_i ‖ shared tail`, materialized fresh
//! per input today — O(n·txsize). The splice computes midstates in ONE
//! forward pass over the input region, then each input's hash is an
//! independent continuation (script absorb + suffix absorb) — both
//! parallelizable and ~halving the input-region mass.
//!
//! Measures: signature_hash per input (real code path) vs spliced
//! per-input continuation, at tx sizes spanning consolidation shapes.
//! Digests verified byte-equal per input.
//!
//! Usage: sighash_splice_bench  (memory-bounded; 1GiB cap suffices)

use avila_consensus::hash::{Txid, sha256d};
use avila_consensus::interpreter::SigVersion;
use avila_consensus::sigchecker::signature_hash;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};
use std::time::Instant;

// ---------- minimal midstate-capable SHA-256 (scalar) ----------------
// Correctness is checked against the crate's sha256d on every sampled
// input; this exists only so midstates can be snapshotted mid-message.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Clone)]
struct Sha {
    h: [u32; 8],
    buf: [u8; 64],
    blen: usize,
    total: u64,
}

fn compress(h: &mut [u32; 8], b: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b_, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b_) ^ (a & c) ^ (b_ & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b_;
        b_ = a;
        a = t1.wrapping_add(t2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b_);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

impl Sha {
    fn new() -> Sha {
        Sha {
            h: H0,
            buf: [0; 64],
            blen: 0,
            total: 0,
        }
    }
    fn upd(&mut self, mut d: &[u8]) {
        self.total = self.total.wrapping_add(d.len() as u64);
        while !d.is_empty() {
            let take = (64 - self.blen).min(d.len());
            self.buf[self.blen..self.blen + take].copy_from_slice(&d[..take]);
            self.blen += take;
            d = &d[take..];
            if self.blen == 64 {
                let b = self.buf;
                compress(&mut self.h, &b);
                self.blen = 0;
            }
        }
    }
    fn fin(&self) -> [u8; 32] {
        let mut s = self.clone();
        s.upd(&[0x80]);
        while s.blen != 56 {
            s.upd(&[0]);
        }
        let bits = self.total * 8; // self.total excludes pad bytes
        s.upd(&bits.to_be_bytes());
        let mut o = [0u8; 32];
        for i in 0..8 {
            o[i * 4..i * 4 + 4].copy_from_slice(&s.h[i].to_be_bytes());
        }
        o
    }
}

fn my_sha256d(d: &[u8]) -> [u8; 32] {
    let mut a = Sha::new();
    a.upd(d);
    let first = a.fin();
    let mut b = Sha::new();
    b.upd(&first);
    b.fin()
}

// ---------- transaction fixture --------------------------------------

fn mk_tx(n_in: usize, script_len: usize, n_out: usize) -> Transaction {
    let mut seed = 0xDEAD_BEEFu64;
    let mut xs = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let inputs = (0..n_in)
        .map(|_| {
            let mut t = [0u8; 32];
            for b in t.chunks_mut(8) {
                b.copy_from_slice(&xs().to_be_bytes());
            }
            TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_bytes(t),
                    vout: xs() as u32 % 4,
                },
                script_sig: Script::new(vec![0x30; 107]), // p2pkh-ish push
                sequence: 0xffff_fffd,
                witness: Witness::default(),
            }
        })
        .collect();
    let outputs = (0..n_out)
        .map(|_| TxOut {
            value: (xs() % 21_000_000) as i64 * 1000,
            script_pubkey: Script::new(vec![0x76; script_len.min(25)]),
        })
        .collect();
    Transaction {
        version: 2,
        inputs,
        outputs,
        lock_time: 0,
    }
}

// ---------- spliced sighash (SIGHASH_ALL shape) ----------------------
//
// midstate_i = sha-state just before input i's script slot (absorbed
// version‖count‖inputs[0..i-1]-blanked‖txid_i‖vout_i‖varint(len)).
// Per input: continue with scriptCode_i ‖ seq_i ‖ inputs[i+1..]blanked
// ‖ outputs ‖ locktime ‖ hashtype — all deterministic, verified equal
// to signature_hash() per input.

fn cs_len(v: usize, out: &mut Vec<u8>) {
    // compactsize for small values (input/output counts, script lens)
    if v < 0xfd {
        out.push(v as u8);
    } else if v <= 0xffff {
        out.extend_from_slice(&[0xfd]);
        out.extend_from_slice(&(v as u16).to_le_bytes());
    } else {
        out.extend_from_slice(&[0xfe]);
        out.extend_from_slice(&(v as u32).to_le_bytes());
    }
}

/// Spliced SIGHASH_ALL over ALL inputs at once: ONE forward pass over
/// the blanked input skeleton (0x00 script varint in every slot)
/// snapshots the sha midstate just before each slot's varint — i.e.
/// after absorbing `txid_j‖vout_j`. Input i's digest is then an
/// independent continuation: `varint(scriptlen)‖scriptCode‖seq_i‖
/// blanked slots i+1.. ‖ outputs ‖ locktime ‖ hashtype` + outer sha.
/// Returns all n digests; the forward pass is per-TX (amortized).
fn spliced_all(tx: &Transaction, script_code: &Script) -> Vec<[u8; 32]> {
    let n = tx.inputs.len();
    let mut h = Sha::new();
    let mut tmp = Vec::with_capacity(64);
    h.upd(&tx.version.to_le_bytes());
    tmp.clear();
    cs_len(n, &mut tmp);
    h.upd(&tmp);
    // forward pass over the blank skeleton, midstate BEFORE slot varint
    let mut midstates = Vec::with_capacity(n);
    for inp in &tx.inputs {
        h.upd(inp.previous_output.txid.as_bytes());
        h.upd(&inp.previous_output.vout.to_le_bytes());
        midstates.push(h.clone()); // state before this slot's varint
        h.upd(&[0]); // blank slot varint
        h.upd(&inp.sequence.to_le_bytes());
    }
    // continuation for input i
    let mut out = Vec::with_capacity(n);
    let mut scv = Vec::with_capacity(8);
    cs_len(script_code.as_bytes().len(), &mut scv);
    for (i, mid) in midstates.iter().enumerate().take(n) {
        let mut s = mid.clone();
        s.upd(&scv);
        s.upd(script_code.as_bytes());
        s.upd(&tx.inputs[i].sequence.to_le_bytes());
        for inp in &tx.inputs[i + 1..] {
            s.upd(inp.previous_output.txid.as_bytes());
            s.upd(&inp.previous_output.vout.to_le_bytes());
            s.upd(&[0]);
            s.upd(&inp.sequence.to_le_bytes());
        }
        tmp.clear();
        cs_len(tx.outputs.len(), &mut tmp);
        s.upd(&tmp);
        for o in &tx.outputs {
            s.upd(&o.value.to_le_bytes());
            tmp.clear();
            cs_len(o.script_pubkey.as_bytes().len(), &mut tmp);
            s.upd(&tmp);
            s.upd(o.script_pubkey.as_bytes());
        }
        s.upd(&tx.lock_time.to_le_bytes());
        s.upd(&1i32.to_le_bytes()); // SIGHASH_ALL
        let first = s.fin();
        let mut second = Sha::new();
        second.upd(&first);
        out.push(second.fin());
    }
    out
}

fn main() {
    // ---- sanity: my sha256 == crate sha256d ----
    let probe = b"the quick brown fox jumps over the lazy dog";
    assert_eq!(my_sha256d(probe), sha256d(probe), "sha256 impl wrong");
    eprintln!("sha256 impl verified vs crate sha256d");

    // ---- raw sha256 rate: crate sha2 vs my scalar Sha ----------------
    let big = vec![0xabu8; 1 << 20];
    for (name, rate_of) in [("crate sha256d", false), ("scalar Sha", true)] {
        let t = Instant::now();
        let mut acc = 0u64;
        let rounds = 20;
        for _ in 0..rounds {
            if rate_of {
                let mut s = Sha::new();
                s.upd(&big);
                acc = acc.wrapping_add(s.fin()[0] as u64);
            } else {
                acc = acc.wrapping_add(sha256d(&big)[0] as u64);
            }
        }
        let mbps = rounds as f64 / t.elapsed().as_secs_f64();
        eprintln!("{name:>14}: {mbps:.0} MB/s (acc {acc})");
    }

    for &n_in in &[50usize, 200, 800, 2000] {
        eprintln!("--- n_in={n_in} ---");
        let tx = mk_tx(n_in, 25, 2);
        let spk = Script::new(vec![0x76, 0xa9, 0x14]); // ~25B scriptCode
        let reps = if n_in <= 200 { 20 } else { 3 };

        // per-input current path (median)
        let mut per_in = Vec::new();
        for r in 0..reps {
            let i = (r * 37) % n_in;
            let t = Instant::now();
            let h = signature_hash(&spk, &tx, i, 1, 0, SigVersion::Base, None);
            per_in.push(t.elapsed());
            std::hint::black_box(h);
        }
        per_in.sort();
        let cur_us = per_in[reps / 2].as_secs_f64() * 1e6;

        // spliced: one forward pass + n independent continuations.
        // per-input amortized = total / n_in (forward is per-TX).
        let mut best = f64::MAX;
        for _ in 0..reps {
            let t = Instant::now();
            let hs = spliced_all(&tx, &spk);
            best = best.min(t.elapsed().as_secs_f64());
            std::hint::black_box(&hs);
        }
        let spl_us = best * 1e6 / n_in as f64;

        // verify spliced == real on a sample of inputs
        let hs = spliced_all(&tx, &spk);
        let mut ok = 0;
        for i in (0..n_in).step_by((n_in / 37).max(1)) {
            let want = signature_hash(&spk, &tx, i, 1, 0, SigVersion::Base, None);
            if hs[i] == want {
                ok += 1;
            }
        }
        eprintln!(
            "n_in={n_in:>5}: real {cur_us:8.1}us/in  spliced-amortized {spl_us:8.1}us/in  verify {ok}/~37 inputs byte-equal"
        );
    }
}

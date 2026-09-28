// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Transcript/positional wire-rep probe (#7): on a real AVCORP03 mainnet
//! window, measure where wire bytes actually live — prevout outpoints
//! (dictionary-compressible against the receiver's UTXO set), output
//! scripts (template-compressible), vs sig/pubkey entropy that cannot
//! compress. Then model the transcript-encoded byte cost.
//!
//! The verifier-local dictionary is legitimate only because every
//! prevout is *locally resolved and validated anyway* — a positional
//! reference replaces sending 36 redundant bytes, never a check.
//!
//! Usage: transcript_probe <corpus.bin>
//! Run under tools/guard_run.sh --max 6144.

use avila_consensus::transaction::Transaction;
use std::time::Instant;

fn u32at(b: &[u8], o: &mut usize) -> u32 {
    let v = u32::from_le_bytes(b[*o..*o + 4].try_into().unwrap());
    *o += 4;
    v
}

fn varint_len(v: usize) -> usize {
    match v {
        0..=252 => 1,
        253..=0xffff => 3,
        _ => 5,
    }
}

/// spk template classification: returns (tag_bytes_needed) if templated.
fn spk_template(spk: &[u8]) -> Option<usize> {
    match spk {
        [0x76, 0xa9, 0x14, .., 0x88, 0xac] if spk.len() == 25 => Some(1 + 20), // P2PKH
        [0xa9, 0x14, .., 0x87] if spk.len() == 23 => Some(1 + 20),             // P2SH
        [0x00, 0x14, ..] if spk.len() == 22 => Some(1 + 20),                   // P2WPKH
        [0x00, 0x20, ..] if spk.len() == 34 => Some(1 + 32),                   // P2WSH
        [0x51, 0x20, ..] if spk.len() == 34 => Some(1 + 32),                   // P2TR
        _ => None,
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: transcript_probe <corpus.bin>");
        std::process::exit(2);
    });
    let raw = std::fs::read(&path).unwrap();
    assert_eq!(&raw[..8], b"AVCORP03", "bad magic");
    let mut o = 8usize;

    let t0 = Instant::now();
    // ---- byte shares over decoded txs ----
    let mut wire_total = 0u64; // rawtx bytes on the wire
    let mut prevout_b = 0u64; // txid+vout per non-coinbase input
    let mut scriptsig_b = 0u64; // varint + script bytes
    let mut witness_b = 0u64; // count varint + item varints + items
    let mut seq_b = 0u64;
    let mut value_b = 0u64;
    let mut spk_b = 0u64; // varint + script bytes
    let mut fixed_b = 0u64; // version+locktime+counts+marker/flags
    let (mut n_tx, mut n_in, mut n_out) = (0u64, 0u64, 0u64);
    let (mut n_coinbase, mut n_witness_tx) = (0u64, 0u64);
    // entropy floor: signature-lookalike + pubkey-lookalike bytes
    let mut sig_bytes = 0u64;
    let mut spk_templatable = 0u64; // spk bytes that fit a template
    let mut spk_model = 0u64; // modeled bytes for those

    let mut n_blocks = 0u64;
    while o < raw.len() {
        let _height = u32at(&raw, &mut o);
        o += 32; // hash
        o += 80; // header
        let ntx = u32at(&raw, &mut o) as usize;
        for _ in 0..ntx {
            let n = u32at(&raw, &mut o) as usize;
            let tx = Transaction::decode(&raw[o..o + n]).expect("decode");
            o += n;
            wire_total += n as u64;
            n_tx += 1;
            let is_cb = tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null();
            if is_cb {
                n_coinbase += 1;
            }
            let mut wit = false;
            for inp in &tx.inputs {
                n_in += 1;
                seq_b += 4;
                if is_cb {
                    // coinbase prevout is all-zero — not compressible-eligible
                    prevout_b += 0;
                } else {
                    prevout_b += 36;
                }
                let sl = inp.script_sig.as_bytes().len();
                scriptsig_b += varint_len(sl) as u64 + sl as u64;
                // count sig+pubkey-looking entropy in scriptsig
                sig_bytes += sl as u64; // upper bound: all scriptsig is entropy-ish
                for item in inp.witness.items() {
                    wit = true;
                    witness_b += varint_len(item.len()) as u64 + item.len() as u64;
                    sig_bytes += item.len() as u64;
                }
                if !inp.witness.is_empty() {
                    witness_b += varint_len(inp.witness.len()) as u64;
                }
            }
            if wit {
                n_witness_tx += 1;
            }
            fixed_b += 4 + 4 // version + locktime
                + varint_len(tx.inputs.len()) as u64
                + varint_len(tx.outputs.len()) as u64
                + if wit { 2 } else { 0 }; // marker+flags
            for out in &tx.outputs {
                n_out += 1;
                value_b += 8;
                let spk = out.script_pubkey.as_bytes();
                spk_b += varint_len(spk.len()) as u64 + spk.len() as u64;
                if let Some(t) = spk_template(spk) {
                    spk_templatable += varint_len(spk.len()) as u64 + spk.len() as u64;
                    spk_model += t as u64;
                }
            }
            // skip the resolved-input sidecar — not wire data
            let nin = u32at(&raw, &mut o) as usize;
            for _ in 0..nin {
                let resolved = raw[o];
                o += 1;
                if resolved != 0 {
                    o += 8;
                    let sl = u32at(&raw, &mut o) as usize;
                    o += sl + 4 + 1;
                }
            }
        }
        n_blocks += 1;
    }

    let accounted = prevout_b + scriptsig_b + witness_b + seq_b + value_b + spk_b + fixed_b;
    eprintln!(
        "parsed {} blocks, {} txs in {:.1?}",
        n_blocks,
        n_tx,
        t0.elapsed()
    );
    eprintln!(
        "wire total {:>12.1} MB | accounted {:>12.1} MB ({:.1}%)",
        wire_total as f64 / 1e6,
        accounted as f64 / 1e6,
        100.0 * accounted as f64 / wire_total as f64
    );
    eprintln!("--- field shares ---");
    let pct = |b: u64| 100.0 * b as f64 / wire_total as f64;
    eprintln!(
        "prevout (txid+vout)  {:>10.1} MB  {:5.1}%   <- dict-compressible",
        prevout_b as f64 / 1e6,
        pct(prevout_b)
    );
    eprintln!(
        "scriptSig            {:>10.1} MB  {:5.1}%   <- entropy",
        scriptsig_b as f64 / 1e6,
        pct(scriptsig_b)
    );
    eprintln!(
        "witness              {:>10.1} MB  {:5.1}%   <- entropy",
        witness_b as f64 / 1e6,
        pct(witness_b)
    );
    eprintln!(
        "output spk           {:>10.1} MB  {:5.1}%   templatable {:.1}%",
        spk_b as f64 / 1e6,
        pct(spk_b),
        100.0 * spk_templatable as f64 / spk_b as f64
    );
    eprintln!(
        "seq                  {:>10.1} MB  {:5.1}%",
        seq_b as f64 / 1e6,
        pct(seq_b)
    );
    eprintln!(
        "value                {:>10.1} MB  {:5.1}%",
        value_b as f64 / 1e6,
        pct(value_b)
    );
    eprintln!(
        "fixed (ver/lt/cnts)  {:>10.1} MB  {:5.1}%",
        fixed_b as f64 / 1e6,
        pct(fixed_b)
    );
    eprintln!(
        "blocks {n_blocks}  txs {n_tx}  ins {n_in} (coinbase {n_coinbase})  outs {n_out}  wit-tx {n_witness_tx}"
    );

    // ---- transcript models ----
    // T0 = raw wire. T1 = prevouts as sorted-UTXO positions (varint,
    // ~4B avg at ~46-150M entries, delta-ish clustering). T2 = T1 +
    // output spk as template tags. T3 = T2 + sequences dropped to a
    // per-tx flags byte + entropy unchanged.
    let noncb_in = n_in - n_coinbase;
    for (name, per_prevout) in [("T1 pos@4B", 4u64), ("T1' pos@6B", 6), ("T1'' pos@8B", 8)] {
        let t1 = wire_total - prevout_b + noncb_in * per_prevout;
        let t2 = t1 - spk_templatable + spk_model;
        eprintln!(
            "{name}: {:>9.1} MB ({:4.1}% of wire)   +spk-tmpl: {:>9.1} MB ({:4.1}%)",
            t1 as f64 / 1e6,
            100.0 * t1 as f64 / wire_total as f64,
            t2 as f64 / 1e6,
            100.0 * t2 as f64 / wire_total as f64,
        );
    }
    // entropy floor: sig+pubkey-ish bytes alone
    eprintln!(
        "entropy floor (scriptsig+witness-ish): {:>9.1} MB ({:.1}% of wire)",
        sig_bytes as f64 / 1e6,
        100.0 * sig_bytes as f64 / wire_total as f64
    );
}

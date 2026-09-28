// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Composite extraction probe (#8 stage A): stream the real AVCORP03
//! corpus, decode every tx, and for each resolved non-coinbase input
//! whose scriptSig is a `sig ‖ pubkey` two-push pattern (legacy P2PKH
//! shape), emit a flat advice record `(z32 ‖ r‖s64 ‖ pub33)` — the
//! exact inputs the C batch harness consumes. Measures per-input
//! extraction cost incl. the REAL sighash, and reports coverage.
//!
//! Usage: corpus_extract <corpus.bin> <records.bin>
//! Run under tools/guard_run.sh --max 6144.

use avila_consensus::interpreter::SigVersion;
use avila_consensus::sigchecker::signature_hash;
use avila_consensus::transaction::{Script, Transaction};
use std::io::Write;
use std::time::Instant;

fn u32at(b: &[u8], o: &mut usize) -> u32 {
    let v = u32::from_le_bytes(b[*o..*o + 4].try_into().unwrap());
    *o += 4;
    v
}

/// Parse a script into pushed-data items (direct pushes + PUSHDATA1/2).
/// Returns None on malformed push framing — extraction just skips.
fn pushes(script: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            0 => {
                out.push(&script[0..0]);
                continue;
            }
            1..=75 => op as usize,
            0x4c => {
                if i >= script.len() {
                    return None;
                }
                let l = script[i] as usize;
                i += 1;
                l
            }
            0x4d => {
                if i + 2 > script.len() {
                    return None;
                }
                let l = u16::from_le_bytes(script[i..i + 2].try_into().unwrap()) as usize;
                i += 2;
                l
            }
            // non-push opcode — the pattern can't be [sig,pub]
            _ => return None,
        };
        if i + len > script.len() {
            return None;
        }
        out.push(&script[i..i + len]);
        i += len;
    }
    Some(out)
}

/// Lax DER→compact: sig = 0x30 len 0x02 rlen R 0x02 slen S [hashtype].
/// Returns (r32, s32, hashtype) or None. Mirrors libsecp lax parse:
/// tolerates missing leading-zero strip beyond strict-DER bounds.
fn der_to_compact(sig: &[u8]) -> Option<([u8; 32], [u8; 32], u8)> {
    if sig.len() < 9 || sig[0] != 0x30 || sig[2] != 0x02 {
        return None;
    }
    let rlen = sig[3] as usize;
    if rlen == 0 || rlen > 33 || 5 + rlen >= sig.len() {
        return None;
    }
    let r_off = 4;
    if sig[r_off + rlen] != 0x02 {
        return None;
    }
    let slen = sig[r_off + rlen + 1] as usize;
    let s_off = r_off + rlen + 2;
    if slen == 0 || slen > 33 || s_off + slen + 1 > sig.len() {
        return None;
    }
    let hashtype = sig[s_off + slen];
    let pad = |v: &[u8]| {
        let mut b = [0u8; 32];
        let k = v.len().min(32);
        b[32 - k..].copy_from_slice(&v[v.len() - k..]);
        b
    };
    Some((
        pad(&sig[r_off..r_off + rlen]),
        pad(&sig[s_off..s_off + slen]),
        hashtype,
    ))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (path, outpath) = (args.next().unwrap(), args.next().unwrap());
    let raw = std::fs::read(&path).unwrap();
    assert_eq!(&raw[..8], b"AVCORP03", "bad magic");
    let mut o = 8usize;
    let mut out = std::io::BufWriter::new(std::fs::File::create(&outpath).unwrap());

    let (mut n_tx, mut n_in, mut n_resolved, mut n_emit) = (0u64, 0u64, 0u64, 0u64);
    let (mut t_decode, mut t_sighash) = (std::time::Duration::ZERO, std::time::Duration::ZERO);
    let t_all = Instant::now();

    while o < raw.len() {
        let _height = u32at(&raw, &mut o);
        o += 32 + 80;
        let ntx = u32at(&raw, &mut o) as usize;
        for _ in 0..ntx {
            let n = u32at(&raw, &mut o) as usize;
            let t = Instant::now();
            let tx = Transaction::decode(&raw[o..o + n]).expect("decode");
            t_decode += t.elapsed();
            o += n;
            let nin = u32at(&raw, &mut o) as usize;
            // collect resolved spks for this tx's inputs
            let mut spks: Vec<Option<(Script, i64)>> = Vec::with_capacity(nin);
            for _ in 0..nin {
                let resolved = raw[o];
                o += 1;
                if resolved == 0 {
                    spks.push(None);
                } else {
                    let value = i64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
                    o += 8;
                    let sl = u32at(&raw, &mut o) as usize;
                    let spk = Script::new(raw[o..o + sl].to_vec());
                    o += sl + 4 + 1;
                    spks.push(Some((spk, value)));
                }
            }
            assert_eq!(spks.len(), tx.inputs.len());
            let is_cb = tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null();
            n_tx += 1;
            if is_cb {
                n_in += 1;
                continue;
            }
            for (i, inp) in tx.inputs.iter().enumerate() {
                n_in += 1;
                let Some((spk, _value)) = &spks[i] else {
                    continue;
                };
                n_resolved += 1;
                let Some(items) = pushes(inp.script_sig.as_bytes()) else {
                    continue;
                };
                if items.len() != 2 {
                    continue;
                }
                let (sig_b, pub_b) = (items[0], items[1]);
                if pub_b.len() != 33 || (pub_b[0] != 0x02 && pub_b[0] != 0x03) {
                    continue;
                }
                let Some((r, s, hashtype)) = der_to_compact(sig_b) else {
                    continue;
                };
                // REAL sighash over the spent coin's scriptPubKey
                let t = Instant::now();
                let z = signature_hash(spk, &tx, i, i32::from(hashtype), 0, SigVersion::Base, None);
                t_sighash += t.elapsed();
                out.write_all(&z).unwrap();
                out.write_all(&r).unwrap();
                out.write_all(&s).unwrap();
                out.write_all(pub_b).unwrap();
                n_emit += 1;
            }
        }
    }
    out.flush().unwrap();
    eprintln!(
        "txs {n_tx}  ins {n_in}  resolved {n_resolved}  emitted {n_emit} ({:.1}% of resolved)  in {:.1?}",
        100.0 * n_emit as f64 / n_resolved.max(1) as f64,
        t_all.elapsed()
    );
    eprintln!(
        "decode+extract {:>8.2}us/tx   sighash {:>8.3}us/input (of emitted-eligible pass)",
        t_decode.as_secs_f64() * 1e6 / n_tx as f64,
        t_sighash.as_secs_f64() * 1e6 / n_emit.max(1) as f64
    );
    eprintln!("record file: {outpath} ({} MB)", n_emit * 129 / 1_000_000);
}

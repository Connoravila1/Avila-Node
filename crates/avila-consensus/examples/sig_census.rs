// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Modern-era sig-plane census: stream local Core blk*.dat files
//! (XOR-deobfuscated via blocks/xor.dat), decode every tx, and classify
//! each input's signature type — legacy ECDSA (scriptSig pushes),
//! segwit-v0 ECDSA (witness DER sigs), or taproot schnorr (64/65B sig
//! items, keypath vs script-path). No coin resolution needed — this
//! prices sig-MIX on modern blocks, not validity.
//!
//! Usage: sig_census <blocks_dir>
//! Run under tools/guard_run.sh --max 4096.

use avila_consensus::block::Block;

use std::io::Read;
use std::time::Instant;

fn looks_der_sig(b: &[u8]) -> bool {
    // DER sig + sighash byte: 0x30 len 0x02 rlen .. 0x02 slen .. ht
    b.len() >= 9 && b.len() <= 73 && b[0] == 0x30 && b[1] as usize == b.len() - 3 && b[2] == 0x02
}

fn push_items(script: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            0 => 0,
            1..=75 => op as usize,
            0x4c => {
                if i >= script.len() {
                    break;
                }
                let l = script[i] as usize;
                i += 1;
                l
            }
            0x4d => {
                if i + 2 > script.len() {
                    break;
                }
                let l = u16::from_le_bytes(script[i..i + 2].try_into().unwrap()) as usize;
                i += 2;
                l
            }
            _ => break, // non-push opcode — not a pure-push script
        };
        if i + len > script.len() {
            break;
        }
        out.push(&script[i..i + len]);
        i += len;
    }
    out
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: sig_census <blocks_dir>");
        std::process::exit(2);
    });
    // xor key (Core >= v28 obfuscates blk/rev files)
    let mut xor = [0u8; 8];
    let mut xf = std::fs::File::open(format!("{dir}/xor.dat")).unwrap();
    xf.read_exact(&mut xor).unwrap();

    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let n = e.unwrap().file_name().into_string().unwrap();
            if n.starts_with("blk") && n.ends_with(".dat") {
                Some(format!("{dir}/{n}"))
            } else {
                None
            }
        })
        .collect();
    files.sort();

    let (mut n_blocks, mut n_tx, mut n_in) = (0u64, 0u64, 0u64);
    let (mut coinbase, mut legacy_1p, mut legacy_other) = (0u64, 0u64, 0u64);
    let (mut wpkh, mut wsh_other, mut tr_key, mut tr_script) = (0u64, 0u64, 0u64, 0u64);
    let (mut ecdsa_sigs, mut schnorr_sigs) = (0u64, 0u64);
    let (mut ecdsa_bytes, mut schnorr_bytes) = (0u64, 0u64);
    let mut wire_total = 0u64;
    let t0 = Instant::now();

    for f in &files {
        let enc = std::fs::read(f).unwrap();
        let mut raw = vec![0u8; enc.len()];
        for (i, b) in enc.iter().enumerate() {
            raw[i] = b ^ xor[i & 7];
        }
        let mut o = 0usize;
        while o + 8 <= raw.len() {
            if raw[o..o + 4] != [0xf9, 0xbe, 0xb4, 0xd9] {
                break; // end of records / padding
            }
            let len = u32::from_le_bytes(raw[o + 4..o + 8].try_into().unwrap()) as usize;
            if o + 8 + len > raw.len() {
                break;
            }
            let block = Block::decode(&raw[o + 8..o + 8 + len]).expect("block decodes");
            wire_total += len as u64;
            o += 8 + len;
            n_blocks += 1;
            for tx in &block.transactions {
                n_tx += 1;
                let is_cb = tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null();
                for inp in &tx.inputs {
                    n_in += 1;
                    if is_cb {
                        coinbase += 1;
                        continue;
                    }
                    let wit = inp.witness.items();
                    if !wit.is_empty() {
                        // witness spend — classify
                        let last = &wit[wit.len() - 1];
                        if wit.len() == 1 && (last.len() == 64 || last.len() == 65) {
                            tr_key += 1;
                            schnorr_sigs += 1;
                            schnorr_bytes += last.len() as u64;
                        } else if last.len() >= 33
                            && last.len() % 32 == 1
                            && (last[0] & 0xfe) == 0xc0
                        {
                            // taproot script path: control block last
                            tr_script += 1;
                            for it in &wit[..wit.len() - 1] {
                                if it.len() == 64 || it.len() == 65 {
                                    schnorr_sigs += 1;
                                    schnorr_bytes += it.len() as u64;
                                } else if looks_der_sig(it.as_slice()) {
                                    ecdsa_sigs += 1; // hybrid leaf scripts exist
                                    ecdsa_bytes += it.len() as u64;
                                }
                            }
                        } else if wit.len() == 2
                            && looks_der_sig(&wit[0])
                            && (wit[1].len() == 33 || wit[1].len() == 65)
                        {
                            wpkh += 1;
                            ecdsa_sigs += 1;
                            ecdsa_bytes += wit[0].len() as u64 + wit[1].len() as u64;
                        } else {
                            // P2WSH or other v0: count DER-sig items in the
                            // stack (excluding witnessScript last)
                            wsh_other += 1;
                            for it in &wit[..wit.len() - 1] {
                                if looks_der_sig(it.as_slice()) {
                                    ecdsa_sigs += 1;
                                    ecdsa_bytes += it.len() as u64;
                                }
                            }
                        }
                    } else {
                        // legacy scriptSig
                        let items = push_items(inp.script_sig.as_bytes());
                        let sig_like = items.iter().filter(|p| looks_der_sig(p)).count();
                        if items.len() == 2 && sig_like == 1 {
                            legacy_1p += 1;
                            ecdsa_sigs += 1;
                            ecdsa_bytes += items[0].len() as u64 + items[1].len() as u64;
                        } else {
                            legacy_other += 1;
                            ecdsa_sigs += sig_like as u64;
                            for p in &items {
                                if looks_der_sig(p) {
                                    ecdsa_bytes += p.len() as u64;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let spend_in = n_in - coinbase;
    eprintln!(
        "{} files, {} blocks, {} txs, {} inputs ({:.1?})",
        files.len(),
        n_blocks,
        n_tx,
        n_in,
        t0.elapsed()
    );
    eprintln!(
        "wire {:>8.1} MB | spend inputs {} (coinbase {})",
        wire_total as f64 / 1e6,
        spend_in,
        coinbase
    );
    eprintln!("--- input classes ---");
    let pin = |c: u64| 100.0 * c as f64 / spend_in as f64;
    eprintln!(
        "legacy 1-push sig+pub (P2PKH-ish)  {legacy_1p:>8}  {:5.1}%",
        pin(legacy_1p)
    );
    eprintln!(
        "legacy other (multisig/P2SH/P2PK){legacy_other:>8}  {:5.1}%",
        pin(legacy_other)
    );
    eprintln!(
        "P2WPKH (ecdsa, witness)          {wpkh:>8}  {:5.1}%",
        pin(wpkh)
    );
    eprintln!(
        "P2WSH/other v0                   {wsh_other:>8}  {:5.1}%",
        pin(wsh_other)
    );
    eprintln!(
        "taproot keypath (schnorr)        {tr_key:>8}  {:5.1}%",
        pin(tr_key)
    );
    eprintln!(
        "taproot script-path              {tr_script:>8}  {:5.1}%",
        pin(tr_script)
    );
    eprintln!("--- signature counts ---");
    eprintln!(
        "ECDSA sigs {:>8} ({:5.1}%, {:.1} MB) | schnorr sigs {:>8} ({:5.1}%, {:.1} MB)",
        ecdsa_sigs,
        100.0 * ecdsa_sigs as f64 / (ecdsa_sigs + schnorr_sigs) as f64,
        ecdsa_bytes as f64 / 1e6,
        schnorr_sigs,
        100.0 * schnorr_sigs as f64 / (ecdsa_sigs + schnorr_sigs) as f64,
        schnorr_bytes as f64 / 1e6
    );
}

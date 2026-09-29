// Rig/test helper — panics on misuse are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! regtest_advice_spend — helper for the two-node advice rig.
//!
//! `addr` — print the regtest P2PKH address for a fixed test key.
//! `spend <txid_hex> <vout> <value_sats>` — emit a signed P2PKH-spend
//! rawtx (SIGHASH_ALL, one key) that a `generateblock` can include.

use avila_consensus::hash::{Txid, hash160};
use avila_consensus::script;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

fn test_key() -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_slice(&[0x11; 32]).unwrap()
}

fn p2pkh_spk(pk33: &[u8; 33]) -> Vec<u8> {
    let h160 = hash160(pk33);
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&h160);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

fn base58check(payload: &[u8]) -> String {
    use avila_consensus::hash::sha256d;
    const ALPH: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut data = payload.to_vec();
    data.extend_from_slice(&sha256d(payload)[..4]);
    // plain base58 on the checksummed payload
    let mut digits = Vec::new();
    let mut num = data;
    while !num.is_empty() {
        let mut rem = 0u32;
        let mut next = Vec::new();
        for b in num {
            let acc = (rem << 8) | u32::from(b);
            next.push((acc / 58) as u8);
            rem = acc % 58;
        }
        while next.first() == Some(&0) {
            next.remove(0);
        }
        digits.push(ALPH[rem as usize]);
        num = next;
    }
    // leading zero bytes → '1'
    for b in payload {
        if *b == 0 {
            digits.push(b'1');
        } else {
            break;
        }
    }
    digits.reverse();
    String::from_utf8(digits).unwrap()
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let secp = secp256k1::Secp256k1::new();
    let sk = test_key();
    let pk33 = sk.public_key(&secp).serialize();
    match mode.as_str() {
        "addr" => {
            let mut payload = vec![0x6f]; // regtest pubkey prefix
            payload.extend_from_slice(&hash160(&pk33));
            println!("{}", base58check(&payload));
        }
        "spend" => {
            let args: Vec<String> = std::env::args().collect();
            let txid_bytes = avila_consensus::hex::decode(&args[2]).unwrap();
            let mut b = [0u8; 32];
            b.copy_from_slice(&txid_bytes);
            b.reverse(); // rpc hex is display-order; txid internal is little-endian
            let vout: u32 = args[3].parse().unwrap();
            let value: i64 = args[4].parse().unwrap();
            let mut spend = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_bytes(b),
                        vout,
                    },
                    script_sig: Script::new(vec![]),
                    sequence: 0xffff_ffff,
                    witness: Witness::default(),
                }],
                outputs: vec![TxOut {
                    value: value - 1000,
                    script_pubkey: Script::new(p2pkh_spk(&pk33)),
                }],
                lock_time: 0,
            };
            let spk = p2pkh_spk(&pk33);
            let z = avila_consensus::sigchecker::signature_hash(
                &Script::new(spk),
                &spend,
                0,
                1,
                0,
                avila_consensus::interpreter::SigVersion::Base,
                None,
            );
            let msg = secp256k1::Message::from_digest_slice(&z).unwrap();
            let sig = secp.sign_ecdsa(&msg, &sk);
            let mut der = sig.serialize_der().to_vec();
            der.push(1);
            let mut ss = script::push_slice(&der);
            ss.extend_from_slice(&script::push_slice(&pk33));
            spend.inputs[0].script_sig = Script::new(ss);
            println!("{}", avila_consensus::hex::encode(&spend.encode()));
        }
        "block" => {
            // block <prevhash_display_hex> <height> <prevtime> <rawtx_hex>
            // Mints a regtest block carrying the spend; prints block hex.
            use avila_consensus::arith::CompactTarget;
            use avila_consensus::block::Block;
            use avila_consensus::hash::BlockHash;
            use avila_consensus::header::BlockHeader;
            use avila_consensus::params::Network;
            use avila_consensus::pow;
            let args: Vec<String> = std::env::args().collect();
            let mut ph = [0u8; 32];
            let raw = avila_consensus::hex::decode(&args[2]).unwrap();
            ph.copy_from_slice(&raw);
            ph.reverse();
            let height: u32 = args[3].parse().unwrap();
            let time: u32 = args[4].parse::<u32>().unwrap() + 1;
            let spend =
                Transaction::decode(&avila_consensus::hex::decode(&args[5]).unwrap()).unwrap();
            let params = Network::Regtest.params();
            let fee: i64 = 1000;
            let mut cb_sig = script::push_int(i64::from(height));
            cb_sig.push(script::OP_1);
            let cb = Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::NULL,
                    script_sig: Script::new(cb_sig),
                    sequence: 0xffff_ffff,
                    witness: Witness::default(),
                }],
                outputs: vec![TxOut {
                    value: avila_consensus::connect::block_subsidy(height, &params) + fee,
                    script_pubkey: Script::new(vec![script::OP_1]),
                }],
                lock_time: 0,
            };
            let mut block = Block {
                header: BlockHeader {
                    version: 4,
                    prev_block_hash: BlockHash::from_bytes(ph),
                    merkle_root: avila_consensus::hash::MerkleRoot::from_bytes([0; 32]),
                    time,
                    bits: CompactTarget(0x207f_ffff),
                    nonce: 0,
                },
                transactions: vec![cb, spend],
            };
            let (root, _) = block.merkle_root();
            block.header.merkle_root = root;
            while pow::check_proof_of_work(&block.block_hash(), block.header.bits, &params).is_err()
            {
                block.header.nonce = block.header.nonce.wrapping_add(1);
                if block.header.nonce == 0 {
                    block.header.time += 1;
                }
            }
            println!("{}", avila_consensus::hex::encode(&block.encode()));
        }
        _ => eprintln!(
            "usage: regtest_advice_spend addr|spend <txid> <vout> <sats>|block <prevhash> <height> <prevtime> <rawtx>"
        ),
    }
}

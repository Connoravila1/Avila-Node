//! Construct the rare x(R) = n + 2 branch without searching for a nonce.
//! Legacy SIGHASH_SINGLE's out-of-range input fixes z independently of Q.
//! Choose s=1, r=2 and Q=(R-zG)/2; both parities must verify and serialize.
use super::*;
use avila_consensus::{
    hash::Txid,
    interpreter::SigVersion,
    script::ScriptFlags,
    sigchecker::{check_input_scripts, signature_hash},
    transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness},
};

fn fixtures() -> Vec<(Transaction, Vec<TxOut>)> {
    let secp = secp256k1::Secp256k1::new();
    let inverse_two: [u8; 32] = avila_consensus::hex::decode(
        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
    )
    .unwrap()
    .try_into()
    .unwrap();
    let inverse_two = secp256k1::Scalar::from_be_bytes(inverse_two).unwrap();
    (0..2)
        .map(|parity| {
            let mut tx = Transaction {
                version: 1,
                lock_time: 0,
                inputs: (0..2)
                    .map(|vout| TxIn {
                        previous_output: OutPoint {
                            txid: Txid::from_bytes([90 + parity; 32]),
                            vout,
                        },
                        script_sig: Script::default(),
                        sequence: u32::MAX,
                        witness: Witness::EMPTY,
                    })
                    .collect(),
                outputs: vec![TxOut {
                    value: 19_000,
                    script_pubkey: Script::new(vec![0x51]),
                }],
            };
            let z = signature_hash(
                &Script::default(),
                &tx,
                1,
                3,
                10_000,
                SigVersion::Base,
                None,
            );
            assert_eq!(z[0], 1);
            assert!(z[1..].iter().all(|b| *b == 0));
            let mut encoded = vec![2 + parity];
            encoded.extend_from_slice(
                &avila_consensus::hex::decode(
                    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364143",
                )
                .unwrap(),
            );
            let nonce = secp256k1::PublicKey::from_slice(&encoded).unwrap();
            let zg = secp256k1::PublicKey::from_secret_key(
                &secp,
                &secp256k1::SecretKey::from_slice(&z).unwrap(),
            );
            let key = nonce
                .combine(&zg.negate(&secp))
                .unwrap()
                .mul_tweak(&secp, &inverse_two)
                .unwrap();
            let mut locking = vec![33];
            locking.extend_from_slice(&key.serialize());
            locking.push(0xac);
            let mut compact = [0; 64];
            compact[31] = 2;
            compact[63] = 1;
            let signature = secp256k1::ecdsa::Signature::from_compact(&compact).unwrap();
            assert!(
                secp.verify_ecdsa(&secp256k1::Message::from_digest(z), &signature, &key)
                    .is_ok()
            );
            let mut signature = signature.serialize_der().to_vec();
            signature.push(3);
            let mut unlocking = vec![signature.len() as u8];
            unlocking.extend_from_slice(&signature);
            tx.inputs[1].script_sig = Script::new(unlocking);
            (
                tx,
                vec![
                    TxOut {
                        value: 10_000,
                        script_pubkey: Script::new(vec![0x51]),
                    },
                    TxOut {
                        value: 10_000,
                        script_pubkey: Script::new(locking),
                    },
                ],
            )
        })
        .collect()
}

pub(super) fn run() -> Result<Outcome, String> {
    let cases = fixtures();
    let frame = advice::begin_block(&[91; 32], cases.len());
    let verdicts: Vec<_> = cases
        .iter()
        .enumerate()
        .map(|(index, (tx, spent))| {
            u8::from(
                advice::with_token(&advice::token(&frame, index), || {
                    check_input_scripts(tx, spent, ScriptFlags::NONE)
                })
                .is_ok(),
            )
        })
        .collect();
    Ok(Outcome {
        blocks: 0,
        transactions: 2,
        coins: 0,
        hash: avila_consensus::hex::encode(&avila_consensus::hash::sha256d(&verdicts)),
    })
}

pub(super) fn pack(writer: &mut impl std::io::Write) -> std::io::Result<()> {
    advice::pack_transactions(
        writer,
        &[91; 32],
        &fixtures().into_iter().map(|(tx, _)| tx).collect::<Vec<_>>(),
    )
}

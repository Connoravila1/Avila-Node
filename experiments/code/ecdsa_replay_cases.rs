//! Script-level adversarial fixtures for the isolated replay boundary.
use avila_consensus::{
    hash::{Txid, sha256d},
    interpreter::SigVersion,
    script::ScriptFlags,
    sigchecker::{check_input_scripts, signature_hash},
    transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness},
};

fn push(script: &mut Vec<u8>, data: &[u8]) {
    assert!(data.len() < 76);
    script.push(data.len() as u8);
    script.extend_from_slice(data);
}

pub(super) fn run() -> Result<super::Outcome, String> {
    let secp = secp256k1::Secp256k1::new();
    let key = secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
    let wrong = secp256k1::SecretKey::from_slice(&[2; 32]).unwrap();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &key);
    let wrong_pk = secp256k1::PublicKey::from_secret_key(&secp, &wrong);
    let mut verdicts = Vec::new();
    for case in 0..9 {
        let mut public = if matches!(case, 4 | 5) {
            pk.serialize_uncompressed().to_vec()
        } else {
            pk.serialize().to_vec()
        };
        if case == 5 {
            public[0] = 6 | (public[64] & 1);
        }
        let mut script = Vec::new();
        if case == 3 {
            script.push(0x51); // 1-of-2; last key is tried first by this interpreter.
            push(&mut script, &public);
            push(&mut script, &wrong_pk.serialize());
            script.extend_from_slice(&[0x52, 0xae]);
        } else {
            push(&mut script, &public);
            script.push(0xac);
            if matches!(case, 1 | 7) {
                script.push(0x91);
            } // CHECKSIG NOT
        }
        let spent = TxOut {
            value: 10_000,
            script_pubkey: Script::new(script),
        };
        let mut tx = Transaction {
            version: 1,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_bytes([3; 32]),
                    vout: 0,
                },
                script_sig: Script::default(),
                sequence: u32::MAX,
                witness: Witness::EMPTY,
            }],
            outputs: vec![TxOut {
                value: 9_000,
                script_pubkey: Script::new(vec![0x51]),
            }],
        };
        let mut message = signature_hash(
            &spent.script_pubkey,
            &tx,
            0,
            1,
            spent.value,
            SigVersion::Base,
            None,
        );
        if matches!(case, 1 | 2) {
            message[0] ^= 1;
        }
        let signature = secp.sign_ecdsa(&secp256k1::Message::from_digest(message), &key);
        let mut signature = if case == 6 {
            let mut compact = signature.serialize_compact();
            let order = avila_consensus::hex::decode(
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            )
            .unwrap();
            let mut borrow = 0i16;
            for i in (0..32).rev() {
                let v = i16::from(order[i]) - i16::from(compact[i + 32]) - borrow;
                compact[i + 32] = v.rem_euclid(256) as u8;
                borrow = i16::from(v < 0);
            }
            secp256k1::ecdsa::Signature::from_compact(&compact)
                .unwrap()
                .serialize_der()
                .to_vec()
        } else {
            signature.serialize_der().to_vec()
        };
        if case == 7 {
            signature[0] = 0;
        } // malformed DER, legitimately false
        if case == 8 {
            signature.push(0);
        } // lax-DER trailing byte, flags NONE
        signature.push(1); // SIGHASH_ALL
        let mut unlocking = Vec::new();
        if case == 3 {
            unlocking.push(0);
        } // CHECKMULTISIG's historical dummy
        push(&mut unlocking, &signature);
        tx.inputs[0].script_sig = Script::new(unlocking);
        verdicts.push(u8::from(
            check_input_scripts(&tx, &[spent], ScriptFlags::NONE).is_ok(),
        ));
    }
    Ok(super::Outcome {
        blocks: 0,
        transactions: verdicts.len() as u64,
        hash: avila_consensus::hex::encode(&sha256d(&verdicts)),
        coins: 0,
    })
}

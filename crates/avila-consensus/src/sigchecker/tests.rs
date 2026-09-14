//! `sigchecker.rs` tests — Core's own `sighash.json` legacy vectors, a
//! rust-bitcoin `SighashCache` differential for BIP143/BIP341, and real
//! sign→verify spends through `check_input_scripts`.

use super::*;
use crate::hash::Txid;
use crate::interpreter::{ExecutionData, SigVersion};
use crate::script::ScriptFlags;
use crate::transaction::{OutPoint, TxIn, Witness};

use bitcoin::hashes::Hash as _;

fn txid(b: u8) -> Txid {
    Txid::from_bytes([b; 32])
}

fn txin(prev_txid: u8, vout: u32, script_sig: Vec<u8>, seq: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: txid(prev_txid),
            vout,
        },
        script_sig: Script::new(script_sig),
        sequence: seq,
        witness: Witness::EMPTY,
    }
}

fn txout(value: i64, spk: Vec<u8>) -> TxOut {
    TxOut {
        value,
        script_pubkey: Script::new(spk),
    }
}

fn sample_tx() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![
            txin(0x11, 0, vec![0x01, 0x33], 0xffff_fffe),
            txin(0x22, 1, vec![], 0xffff_fffd),
        ],
        outputs: vec![txout(50_000, vec![0x51]), txout(30_000, vec![0x52])],
        lock_time: 500_000,
    }
}

/// The flag set `block_script_flags` produces for a modern block:
/// `P2SH|WITNESS|TAPROOT` base plus the buried deployments.
fn consensus_flags() -> ScriptFlags {
    ScriptFlags::P2SH
        .union(ScriptFlags::WITNESS)
        .union(ScriptFlags::TAPROOT)
        .union(ScriptFlags::DERSIG)
        .union(ScriptFlags::CHECKLOCKTIMEVERIFY)
        .union(ScriptFlags::CHECKSEQUENCEVERIFY)
        .union(ScriptFlags::NULLDUMMY)
}

// ---------------------------------------------------------------------------
// Core's sighash.json — 500 legacy signature-hash vectors
// ---------------------------------------------------------------------------

#[test]
fn legacy_sighash_core_vectors() {
    // Flattened src/test/data/sighash.json from Core v29.0:
    // raw_tx | script_code | input_index | hashType | expected (display hex).
    for (line_no, line) in include_str!("sighash_legacy.txt").lines().enumerate() {
        if line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('|').collect();
        assert_eq!(fields.len(), 5, "line {line_no}: malformed vector");
        let tx = Transaction::decode(&crate::hex::decode(fields[0]).unwrap())
            .unwrap_or_else(|e| panic!("line {line_no}: tx decode: {e}"));
        let script = Script::new(crate::hex::decode(fields[1]).unwrap());
        let n_in: usize = fields[2].parse().unwrap();
        let hash_type: i32 = fields[3].parse::<i64>().unwrap() as i32;
        let expected = crate::hex::decode(fields[4]).unwrap();

        let got = signature_hash(&script, &tx, n_in, hash_type, 0, SigVersion::Base, None);
        // Core's test prints hash.ToString() — the internal bytes reversed.
        let mut got_display = got;
        got_display.reverse();
        assert_eq!(
            got_display[..],
            expected[..],
            "line {line_no}: sighash mismatch"
        );
    }
}

// ---------------------------------------------------------------------------
// rust-bitcoin differential — BIP143 (segwit v0) and BIP341/342 (taproot)
// ---------------------------------------------------------------------------

fn to_bitcoin_tx(tx: &Transaction) -> bitcoin::Transaction {
    bitcoin::consensus::deserialize(&tx.encode()).expect("our encoding must parse")
}

fn to_bitcoin_txouts(outs: &[TxOut]) -> Vec<bitcoin::TxOut> {
    outs.iter()
        .map(|o| bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(o.value as u64),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(o.script_pubkey.as_bytes().to_vec()),
        })
        .collect()
}

#[test]
fn segwit_v0_sighash_matches_rust_bitcoin() {
    let tx = sample_tx();
    let their_tx = to_bitcoin_tx(&tx);
    let script_code = bitcoin::ScriptBuf::from_bytes(vec![0x76, 0xa9, 0x14, 0xaa]);
    let our_script = Script::new(vec![0x76, 0xa9, 0x14, 0xaa]);
    let value = bitcoin::Amount::from_sat(12345);

    // Canonical hashtypes only — rust-bitcoin normalizes exotic values through
    // its enum (0x41 → All serializes as 0x01), while Core and this port hash
    // the raw byte. Exotic hashtypes are covered by the Core vectors above.
    for hash_byte in [0x01u8, 0x02, 0x03, 0x81, 0x82, 0x83] {
        for n_in in 0..tx.inputs.len() {
            let sighash_type = bitcoin::sighash::EcdsaSighashType::from_consensus(hash_byte as u32);
            let mut cache = bitcoin::sighash::SighashCache::new(&their_tx);
            let theirs = cache
                .p2wsh_signature_hash(n_in, &script_code, value, sighash_type)
                .unwrap();
            let ours = signature_hash(
                &our_script,
                &tx,
                n_in,
                i32::from(hash_byte),
                value.to_sat() as i64,
                SigVersion::WitnessV0,
                None,
            );
            assert_eq!(
                ours,
                theirs.to_byte_array(),
                "hashtype {hash_byte:#04x} input {n_in}"
            );
        }
    }
}

#[test]
fn taproot_sighash_matches_rust_bitcoin() {
    let mut tx = sample_tx();
    // Witness-bearing inputs are required for the taproot-ready feature scan.
    for input in &mut tx.inputs {
        input.witness = Witness::new(vec![vec![0xaa; 64]]);
    }
    // 34-byte v1 taproot programs.
    let spent = vec![
        TxOut {
            value: 100_000,
            script_pubkey: Script::new([&[OP_1, 0x20][..], &[0x33; 32]].concat()),
        },
        TxOut {
            value: 60_000,
            script_pubkey: Script::new([&[OP_1, 0x20][..], &[0x44; 32]].concat()),
        },
    ];
    let txdata = PrecomputedTransactionData::new(&tx, Some(spent.clone()), false);
    assert!(txdata.bip341_taproot_ready);

    let their_tx = to_bitcoin_tx(&tx);
    let their_prevouts = to_bitcoin_txouts(&spent);
    let leaf_hash = [0xabu8; 32];

    for hash_byte in [0x00u8, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83] {
        let sighash_type = bitcoin::sighash::TapSighashType::from_consensus_u8(hash_byte).unwrap();
        for n_in in 0..tx.inputs.len() {
            // Key path.
            let mut cache = bitcoin::sighash::SighashCache::new(&their_tx);
            let theirs = cache
                .taproot_key_spend_signature_hash(
                    n_in,
                    &bitcoin::sighash::Prevouts::All(&their_prevouts),
                    sighash_type,
                )
                .unwrap();
            let mut execdata = ExecutionData {
                annex_init: true,
                ..ExecutionData::default()
            };
            let ours = signature_hash_schnorr(
                &tx,
                n_in,
                hash_byte,
                SigVersion::Taproot,
                &txdata,
                &mut execdata,
            )
            .unwrap();
            assert_eq!(ours, theirs.to_byte_array(), "keypath {hash_byte:#04x}");

            // Script path (leaf hash + default codeseparator).
            let mut cache = bitcoin::sighash::SighashCache::new(&their_tx);
            let theirs = cache
                .taproot_signature_hash(
                    n_in,
                    &bitcoin::sighash::Prevouts::All(&their_prevouts),
                    None,
                    Some((
                        bitcoin::taproot::TapLeafHash::from_byte_array(leaf_hash),
                        0xffff_ffff,
                    )),
                    sighash_type,
                )
                .unwrap();
            let mut execdata = ExecutionData {
                annex_init: true,
                tapleaf_hash: Some(leaf_hash),
                tapleaf_hash_init: true,
                codeseparator_pos: 0xffff_ffff,
                codeseparator_pos_init: true,
                ..ExecutionData::default()
            };
            let ours = signature_hash_schnorr(
                &tx,
                n_in,
                hash_byte,
                SigVersion::Tapscript,
                &txdata,
                &mut execdata,
            )
            .unwrap();
            assert_eq!(ours, theirs.to_byte_array(), "scriptpath {hash_byte:#04x}");
        }
    }
}

#[test]
fn taproot_annex_and_anyonecanpay_match_rust_bitcoin() {
    let mut tx = sample_tx();
    tx.inputs[0].witness = Witness::new(vec![vec![0xaa; 64]]);
    // 34-byte v1 taproot programs.
    let spent = vec![
        TxOut {
            value: 100_000,
            script_pubkey: Script::new([&[OP_1, 0x20][..], &[0x33; 32]].concat()),
        },
        TxOut {
            value: 60_000,
            script_pubkey: Script::new([&[OP_1, 0x20][..], &[0x44; 32]].concat()),
        },
    ];
    let txdata = PrecomputedTransactionData::new(&tx, Some(spent.clone()), false);
    let their_tx = to_bitcoin_tx(&tx);
    let their_prevouts = to_bitcoin_txouts(&spent);
    let annex_bytes = [&[0x50u8][..], &[0x77; 40]].concat();

    // Annex present + ANYONECANPAY.
    let mut cache = bitcoin::sighash::SighashCache::new(&their_tx);
    let theirs = cache
        .taproot_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::One(0, their_prevouts[0].clone()),
            Some(bitcoin::sighash::Annex::new(&annex_bytes).unwrap()),
            None,
            bitcoin::sighash::TapSighashType::AllPlusAnyoneCanPay,
        )
        .unwrap();
    let annex_hash = {
        let mut buf = Vec::new();
        write_var_bytes(&mut buf, &annex_bytes);
        sha256(&buf)
    };
    let mut execdata = ExecutionData {
        annex_init: true,
        annex_present: true,
        annex_hash: Some(annex_hash),
        ..ExecutionData::default()
    };
    let ours =
        signature_hash_schnorr(&tx, 0, 0x81, SigVersion::Taproot, &txdata, &mut execdata).unwrap();
    assert_eq!(ours, theirs.to_byte_array());

    // SIGHASH_SINGLE with a valid input index past the outputs → Core
    // returns false (None). The tx has 2 inputs; drop to 1 output so n_in=1
    // is in-range but out-of-outputs.
    let mut tx_oor = tx.clone();
    tx_oor.outputs.truncate(1);
    let mut execdata = ExecutionData {
        annex_init: true,
        ..ExecutionData::default()
    };
    assert!(
        signature_hash_schnorr(
            &tx_oor,
            1,
            SIGHASH_SINGLE,
            SigVersion::Taproot,
            &txdata,
            &mut execdata,
        )
        .is_none()
    );
    // Bad hash types → None.
    for bad in [0x04u8, 0x84, 0x7f] {
        let mut execdata = ExecutionData {
            annex_init: true,
            ..ExecutionData::default()
        };
        assert!(
            signature_hash_schnorr(&tx, 0, bad, SigVersion::Taproot, &txdata, &mut execdata)
                .is_none(),
            "hash type {bad:#04x} must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// CheckLockTime / CheckSequence
// ---------------------------------------------------------------------------

#[test]
fn check_locktime_semantics() {
    let tx = sample_tx(); // lock_time = 500_000 < LOCKTIME_THRESHOLD
    let spent = vec![txout(1, vec![]), txout(1, vec![])];
    let txdata = PrecomputedTransactionData::new(&tx, Some(spent), false);
    let checker = TransactionSignatureChecker::new(&tx, 0, 50_000, &txdata);

    // Height-domain operand vs height-domain tx.
    assert!(checker.check_locktime(500_000));
    assert!(!checker.check_locktime(500_001));
    // Time-domain operand vs height-domain tx → type mismatch.
    assert!(!checker.check_locktime(i64::from(LOCKTIME_THRESHOLD)));
    // SEQUENCE_FINAL on the input disables locktime.
    let mut tx_final = sample_tx();
    tx_final.inputs[0].sequence = SEQUENCE_FINAL;
    let txdata = PrecomputedTransactionData::new(&tx_final, None, false);
    let checker = TransactionSignatureChecker::new(&tx_final, 0, 50_000, &txdata);
    assert!(!checker.check_locktime(500_000));
}

#[test]
fn check_sequence_semantics() {
    // version 2; input[0].sequence = 0x4000 — BIP68-active (disable bit clear)
    // height-locked.
    let mut tx = sample_tx();
    tx.inputs[0].sequence = 0x0000_4000;
    let spent = vec![txout(1, vec![]), txout(1, vec![])];
    let txdata = PrecomputedTransactionData::new(&tx, Some(spent), false);
    let checker = TransactionSignatureChecker::new(&tx, 0, 50_000, &txdata);

    assert!(checker.check_sequence(0x0000_4000));
    assert!(checker.check_sequence(0x0000_3fff));
    assert!(!checker.check_sequence(0x0000_4001)); // masked > masked
    // Type-flag mismatch (operand = time-locked, tx = height-locked).
    assert!(!checker.check_sequence(i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG)));
    // version < 2 → CSV fails.
    let mut tx_v1 = sample_tx();
    tx_v1.version = 1;
    let txdata = PrecomputedTransactionData::new(&tx_v1, None, false);
    let checker = TransactionSignatureChecker::new(&tx_v1, 0, 50_000, &txdata);
    assert!(!checker.check_sequence(1));
    // Disable flag on the tx sequence → CSV fails.
    let mut tx_dis = sample_tx();
    tx_dis.inputs[0].sequence |= SEQUENCE_LOCKTIME_DISABLE_FLAG;
    let txdata = PrecomputedTransactionData::new(&tx_dis, None, false);
    let checker = TransactionSignatureChecker::new(&tx_dis, 0, 50_000, &txdata);
    assert!(!checker.check_sequence(1));
}

// ---------------------------------------------------------------------------
// End-to-end: real signatures through check_input_scripts
// ---------------------------------------------------------------------------

/// `OP_DUP OP_HASH160 <20-byte hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG`.
fn p2pkh_script(pubkey: &[u8]) -> Vec<u8> {
    let h160 = ripemd::Ripemd160::digest(crate::hash::sha256(pubkey));
    [&[0x76, 0xa9, 0x14], h160.as_slice(), &[0x88, 0xac]].concat()
}

#[test]
fn p2pkh_signed_spend_verifies() {
    let secp = secp256k1::Secp256k1::signing_only();
    let sk = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let spent = txout(50_000, p2pkh_script(&pk.serialize()));
    let tx = Transaction {
        version: 2,
        inputs: vec![txin(0x11, 0, vec![], SEQUENCE_FINAL)],
        outputs: vec![txout(40_000, vec![0x51])],
        lock_time: 0,
    };

    // Sign the legacy sighash.
    let txdata = PrecomputedTransactionData::new(&tx, Some(vec![spent.clone()]), false);
    let sighash = signature_hash(
        &spent.script_pubkey,
        &tx,
        0,
        i32::from(SIGHASH_ALL),
        spent.value,
        SigVersion::Base,
        Some(&txdata),
    );
    let msg = secp256k1::Message::from_digest_slice(&sighash).unwrap();
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_der = sig.serialize_der().to_vec();
    sig_der.push(SIGHASH_ALL);

    // scriptSig: <sig> <pubkey>.
    let mut script_sig = vec![sig_der.len() as u8];
    script_sig.extend_from_slice(&sig_der);
    script_sig.push(33);
    script_sig.extend_from_slice(&pk.serialize());
    let mut tx_signed = tx.clone();
    tx_signed.inputs[0].script_sig = Script::new(script_sig);

    check_input_scripts(&tx_signed, std::slice::from_ref(&spent), consensus_flags()).unwrap();

    // A corrupted signature fails — EvalFalse under block flags (NULLFAIL is
    // policy, not consensus).
    let mut tx_bad = tx_signed.clone();
    let mut sig_bad = sig_der.clone();
    sig_bad[10] ^= 1;
    let mut script_sig = vec![sig_bad.len() as u8];
    script_sig.extend_from_slice(&sig_bad);
    script_sig.push(33);
    script_sig.extend_from_slice(&pk.serialize());
    tx_bad.inputs[0].script_sig = Script::new(script_sig);
    let err =
        check_input_scripts(&tx_bad, std::slice::from_ref(&spent), consensus_flags()).unwrap_err();
    // DER corruption may surface as SigDer (DERSIG is consensus) or EvalFalse.
    assert!(matches!(err, ScriptError::SigDer | ScriptError::EvalFalse));

    // Under the standard flag set, a DER-valid wrong signature is SigNullFail.
    let mut sig_wrong = secp
        .sign_ecdsa(
            &secp256k1::Message::from_digest_slice(&[0x42u8; 32]).unwrap(),
            &sk,
        )
        .serialize_der()
        .to_vec();
    sig_wrong.push(SIGHASH_ALL);
    let mut script_sig = vec![sig_wrong.len() as u8];
    script_sig.extend_from_slice(&sig_wrong);
    script_sig.push(33);
    script_sig.extend_from_slice(&pk.serialize());
    tx_bad.inputs[0].script_sig = Script::new(script_sig);
    let err = check_input_scripts(
        &tx_bad,
        &[spent],
        consensus_flags().union(ScriptFlags::NULLFAIL),
    )
    .unwrap_err();
    assert_eq!(err, ScriptError::SigNullFail);
}

#[test]
fn p2wpkh_signed_spend_verifies() {
    let secp = secp256k1::Secp256k1::signing_only();
    let sk = secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    // P2WPKH program: OP_0 <20-byte hash160>.
    let h160 = ripemd::Ripemd160::digest(crate::hash::sha256(&pk.serialize()));
    let program_spk = Script::new([&[0x00, 0x14], h160.as_slice()].concat());
    let spent = txout(50_000, program_spk.as_bytes().to_vec());
    let tx = Transaction {
        version: 2,
        inputs: vec![txin(0x11, 0, vec![], SEQUENCE_FINAL)],
        outputs: vec![txout(40_000, vec![0x51])],
        lock_time: 0,
    };

    // The BIP143 script_code for P2WPKH is the implied P2PKH body.
    let script_code = Script::new(p2pkh_script(&pk.serialize()));
    let txdata = PrecomputedTransactionData::new(&tx, Some(vec![spent.clone()]), true);
    let sighash = signature_hash(
        &script_code,
        &tx,
        0,
        i32::from(SIGHASH_ALL),
        spent.value,
        SigVersion::WitnessV0,
        Some(&txdata),
    );
    let msg = secp256k1::Message::from_digest_slice(&sighash).unwrap();
    let sig = secp.sign_ecdsa(&msg, &sk);
    let mut sig_der = sig.serialize_der().to_vec();
    sig_der.push(SIGHASH_ALL);

    let mut tx_signed = tx;
    tx_signed.inputs[0].witness = Witness::new(vec![sig_der, pk.serialize().to_vec()]);
    check_input_scripts(&tx_signed, &[spent], consensus_flags()).unwrap();
}

#[test]
fn taproot_keypath_signed_spend_verifies() {
    let secp_sign = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&[11u8; 32]).unwrap();
    let keypair = secp256k1::Keypair::from_secret_key(&secp_sign, &sk);
    let (internal, _parity) = keypair.x_only_public_key();

    // Key-path-only output: tweak = TapTweak(internal) with no merkle root.
    let mut h = tagged_hasher("TapTweak");
    h.update(internal.serialize());
    let tweak: [u8; 32] = h.finalize().into();
    let scalar = secp256k1::Scalar::from_be_bytes(tweak).unwrap();
    let tweaked_pair = keypair.add_xonly_tweak(&secp_sign, &scalar).unwrap();
    let (program, _) = tweaked_pair.x_only_public_key();

    let program_spk = Script::new([&[OP_1, 0x20][..], &program.serialize()].concat());
    let spent = txout(50_000, program_spk.as_bytes().to_vec());
    let tx = Transaction {
        version: 2,
        inputs: vec![txin(0x11, 0, vec![], SEQUENCE_FINAL)],
        outputs: vec![txout(40_000, vec![0x51])],
        lock_time: 0,
    };

    // force=true: the witness is attached after signing, like a wallet
    // computing the sighash before the signature exists.
    let txdata = PrecomputedTransactionData::new(&tx, Some(vec![spent.clone()]), true);
    assert!(txdata.bip341_taproot_ready);
    let mut execdata = ExecutionData {
        annex_init: true,
        ..ExecutionData::default()
    };
    let sighash = signature_hash_schnorr(
        &tx,
        0,
        SIGHASH_DEFAULT,
        SigVersion::Taproot,
        &txdata,
        &mut execdata,
    )
    .unwrap();
    let msg = secp256k1::Message::from_digest_slice(&sighash).unwrap();
    let sig = secp_sign.sign_schnorr_no_aux_rand(&msg, &tweaked_pair);

    let mut tx_signed = tx;
    tx_signed.inputs[0].witness = Witness::new(vec![sig.serialize().to_vec()]);
    check_input_scripts(&tx_signed, &[spent], consensus_flags()).unwrap();
}

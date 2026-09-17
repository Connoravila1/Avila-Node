//! BIP352 silent-payments detection — the recipient's scan half.
//!
//! A silent payment sends to `B_spend + hash(shared_secret || k)·G`
//! where `shared_secret = input_hash · A · d_scan`: `A` aggregates
//! every input's public key, `input_hash` commits to the smallest
//! outpoint, and `d_scan` is the recipient's scan key. Detection
//! needs only `(d_scan, B_spend)` — no spend-side private key.

#[cfg(test)]
use secp256k1::SecretKey;
use secp256k1::{PublicKey, Scalar, Secp256k1, XOnlyPublicKey};

use crate::hash::tagged_hash;
use crate::transaction::{OutPoint, Transaction};

/// A watched silent-payments address — the scan private key plus the
/// spend public key the sender tweaks per payment.
#[derive(Debug, Clone)]
pub struct SilentAddress {
    /// `d_scan` — the 32-byte scan private key.
    pub scan_priv: [u8; 32],
    /// `B_spend` — the x-only spend public key.
    pub spend_pub: [u8; 32],
}

/// The public key a BIP352 input contributes to `A`. `prevout` is the
/// spent output's scriptPubKey; `txin` carries the scriptSig/witness.
/// `None` when the script type carries no key — per BIP352 ineligible
/// inputs are simply ignored, not disqualifying.
fn input_pubkey(txin: &crate::transaction::TxIn, prevout: &[u8]) -> Option<PublicKey> {
    // p2tr key-path spend: the x-only key in the output script.
    if prevout.len() == 34 && prevout[0] == 0x51 && prevout[1] == 0x20 {
        let x = XOnlyPublicKey::from_slice(&prevout[2..34]).ok()?;
        return Some(x.public_key(secp256k1::Parity::Even));
    }
    // p2wpkh / p2sh-p2wpkh: the compressed key is witness[1].
    if (prevout.len() == 22 && prevout[0] == 0x00 && prevout[1] == 0x14)
        || (prevout.len() == 23 && prevout[0] == 0xa9 && prevout[1] == 0x14)
    {
        return txin
            .witness
            .items()
            .get(1)
            .and_then(|w| PublicKey::from_slice(w).ok());
    }
    // p2pkh: the pubkey is the last push of the scriptSig — the
    // trailing 33 bytes for compressed keys.
    if prevout.len() == 25 && prevout[..3] == [0x76, 0xa9, 0x14] {
        let ss = txin.script_sig.as_bytes();
        if ss.len() >= 33 {
            let tail = &ss[ss.len() - 33..];
            if tail[0] == 0x02 || tail[0] == 0x03 {
                return PublicKey::from_slice(tail).ok();
            }
        }
        return None;
    }
    // p2pk: the compressed key pushed in the output script itself.
    if prevout.len() == 35 && prevout[0] == 0x21 && prevout[34] == 0xac {
        return PublicKey::from_slice(&prevout[1..34]).ok();
    }
    None
}

/// Whether `tx` pays `addr` — BIP352's scanning routine. Returns the
/// matching output index when a silent payment lands.
///
/// `prevout_of` resolves an input's spent scriptPubKey — callers pass
/// the UTXO set plus same-block outputs (a later tx's input may spend
/// an earlier same-block tx's output).
///
/// # Scope
/// First slice: one output match per tx, no `label` tweak (change
/// outputs to self aren't detected), no `sp()` descriptor grammar.
#[must_use]
pub fn detect_silent_payment(
    tx: &Transaction,
    addr: &SilentAddress,
    prevout_of: impl Fn(&OutPoint) -> Option<Vec<u8>>,
) -> Option<u32> {
    if tx.is_coinbase() {
        return None;
    }
    // Sum every input's extractable key into `A` — inputs without
    // public keys (or unresolvable prevouts) are skipped per BIP352;
    // with zero contributors the tx isn't a silent payment.
    let mut agg: Option<PublicKey> = None;
    for txin in &tx.inputs {
        let Some(prevout) = prevout_of(&txin.previous_output) else {
            continue;
        };
        let Some(key) = input_pubkey(txin, &prevout) else {
            continue;
        };
        agg = Some(match agg {
            None => key,
            Some(a) => a.combine(&key).ok()?,
        });
    }
    let a = agg?;
    // input_hash = tagged BIP0352/Inputs over smallest-outpoint || A —
    // `A` serializes as the full compressed point (ser_P).
    let smallest = tx
        .inputs
        .iter()
        .map(|i| {
            let mut b = [0u8; 36];
            b[..32].copy_from_slice(i.previous_output.txid.as_bytes());
            b[32..].copy_from_slice(&i.previous_output.vout.to_le_bytes());
            b
        })
        .min()?;
    let mut ih_data = Vec::with_capacity(69);
    ih_data.extend_from_slice(&smallest);
    ih_data.extend_from_slice(&a.serialize());
    let input_hash = tagged_hash(b"BIP0352/Inputs", &ih_data);

    // shared_secret = input_hash · A · d_scan
    let secp = Secp256k1::new();
    let ecdh = a
        .mul_tweak(&secp, &Scalar::from_be_bytes(input_hash).ok()?)
        .ok()?
        .mul_tweak(&secp, &Scalar::from_be_bytes(addr.scan_priv).ok()?)
        .ok()?;

    // For each P2TR output index k: P_k = B_spend + t_k·G where
    // t_k = tagged BIP0352/SharedSecret(ser256(ecdh) || ser32(k)).
    let b_spend = XOnlyPublicKey::from_slice(&addr.spend_pub).ok()?;
    for (vout, out) in tx.outputs.iter().enumerate() {
        let spk = out.script_pubkey.as_bytes();
        if spk.len() != 34 || spk[0] != 0x51 || spk[1] != 0x20 {
            continue;
        }
        let mut td = Vec::with_capacity(37);
        td.extend_from_slice(&ecdh.serialize());
        td.extend_from_slice(&(vout as u32).to_le_bytes());
        let t_k = tagged_hash(b"BIP0352/SharedSecret", &td);
        let (p_k, _) = b_spend
            .add_tweak(&secp, &Scalar::from_be_bytes(t_k).ok()?)
            .ok()?;
        if p_k.serialize() == spk[2..34] {
            return Some(vout as u32);
        }
    }
    None
}

/// The recipient's side — compute the tweaked output key for
/// `(sender aggregate key, smallest outpoint, k)`. Exposed for tests:
/// a sending-side helper that produces what `detect_silent_payment`
/// must find.
#[cfg(test)]
pub fn silent_output_key(
    a: PublicKey,
    a_priv: &SecretKey,
    smallest_outpoint: &[u8; 36],
    b_spend: &XOnlyPublicKey,
    scan_pub: &PublicKey,
    k: u32,
) -> Option<[u8; 32]> {
    // The sender's view: shared_secret = input_hash · a · B_scan —
    // the same ECDH point the recipient computes as
    // input_hash · A · d_scan (a·G = A).
    let secp = Secp256k1::new();
    let mut ih = Vec::with_capacity(69);
    ih.extend_from_slice(smallest_outpoint);
    ih.extend_from_slice(&a.serialize());
    let input_hash = tagged_hash(b"BIP0352/Inputs", &ih);
    let ecdh = scan_pub
        .mul_tweak(&secp, &Scalar::from_be_bytes(a_priv.secret_bytes()).ok()?)
        .ok()?
        .mul_tweak(&secp, &Scalar::from_be_bytes(input_hash).ok()?)
        .ok()?;
    // ecdh here = input_hash · A · B_scan — the *public* form; the
    // tweak is hash(ecdh·d? no — BIP352: shared_secret =
    // input_hash·a·b_scan where a·b_scan = A·d_scan? The spec's
    // shared_secret is the ECDH point (a·B_scan) scaled by input_hash
    // — equal to input_hash·A·d_scan? a·B_scan·input_hash vs
    // input_hash·A·d_scan: a·(b_scan·G)·ih = (a·b_scan·ih)·G;
    // A·d_scan·ih = (a_sum·d_scan·ih)·G — equal when A = a·G. ✓
    let mut td = Vec::with_capacity(37);
    td.extend_from_slice(&ecdh.serialize());
    td.extend_from_slice(&k.to_le_bytes());
    let t_k = tagged_hash(b"BIP0352/SharedSecret", &td);
    let (p_k, _) = b_spend
        .add_tweak(&secp, &Scalar::from_be_bytes(t_k).ok()?)
        .ok()?;
    Some(p_k.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Txid;
    use crate::transaction::{OutPoint, Script, TxIn, TxOut, Witness};
    use secp256k1::Secp256k1;

    /// A p2wpkh-spending input pays a silent-payments output; the
    /// scan key must find it.
    #[test]
    fn detects_p2wpkh_funded_silent_payment() {
        let secp = Secp256k1::new();
        // Sender's input key — the prevout is p2wpkh, key in witness.
        let a_priv = SecretKey::from_slice(&[0x11; 32]).unwrap_or_else(|_| unreachable!());
        let a_pub = PublicKey::from_secret_key(&secp, &a_priv);
        // Recipient: scan priv + spend pub.
        let scan_priv = SecretKey::from_slice(&[0x22; 32]).unwrap_or_else(|_| unreachable!());
        let scan_pub = PublicKey::from_secret_key(&secp, &scan_priv);
        let spend_priv = SecretKey::from_slice(&[0x33; 32]).unwrap_or_else(|_| unreachable!());
        let _ = spend_priv;
        let (spend_xonly, _) =
            XOnlyPublicKey::from_keypair(&secp256k1::Keypair::from_secret_key(&secp, &spend_priv));

        let op = OutPoint {
            txid: Txid::from_bytes([0x44; 32]),
            vout: 0,
        };
        let mut smallest = [0u8; 36];
        smallest[..32].copy_from_slice(op.txid.as_bytes());
        smallest[32..].copy_from_slice(&0u32.to_le_bytes());

        // The sender's output key: B_spend + t_0·G.
        let out_xonly = silent_output_key(a_pub, &a_priv, &smallest, &spend_xonly, &scan_pub, 0)
            .unwrap_or([0u8; 32]);
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&out_xonly);

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: op,
                script_sig: Script::new(vec![]),
                sequence: 0xffff_ffff,
                witness: Witness::new(vec![vec![0x30; 72], a_pub.serialize().to_vec()]),
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: Script::new(spk),
            }],
            lock_time: 0,
        };

        // The prevout script is p2wpkh — hash160(a_pub) filler.
        let mut prev = vec![0x00, 0x14];
        prev.extend_from_slice(&[0xaa; 20]);
        let watch = SilentAddress {
            scan_priv: scan_priv.secret_bytes(),
            spend_pub: spend_xonly.serialize(),
        };
        let found = detect_silent_payment(&tx, &watch, |o| (o == &op).then(|| prev.clone()));
        assert_eq!(found, Some(0));

        // A different watch must not match.
        let other = SilentAddress {
            scan_priv: [0x99; 32],
            spend_pub: spend_xonly.serialize(),
        };
        assert_eq!(
            detect_silent_payment(&tx, &other, |o| (o == &op).then(|| prev.clone())),
            None
        );
    }
    /// The BIP352 spec's "Simple send: two inputs" receiving vector —
    /// two p2pkh inputs fund one p2tr silent-payment output; the
    /// recipient's scan must find index 0 with exactly the expected
    /// tweaked key.
    #[test]
    fn bip352_vector_two_p2pkh_inputs() {
        let hex = |s: &str| crate::hex::decode(s).unwrap_or_default();
        let secp = Secp256k1::new();

        let vins = [
            (
                "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
                "483046022100ad79e6801dd9a8727f342f31c71c4912866f59dc6e7981878e92c5844a0ce929022100fb0d2393e813968648b9753b7e9871d90ab3d815ebf91820d704b19f4ed224d621025a1e61f898173040e20616d43e9f496fba90338a39faa1ed98fcbaeee4dd9be5",
                "76a91419c2f3ae0ca3b642bd3e49598b8da89f50c1416188ac",
            ),
            (
                "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d",
                "48304602210086783ded73e961037e77d49d9deee4edc2b23136e9728d56e4491c80015c3a63022100fda4c0f21ea18de29edbce57f7134d613e044ee150a89e2e64700de2d4e83d4e2103bd85685d03d111699b15d046319febe77f8de5286e9e512703cdee1bf3be3792",
                "76a914d9317c66f54ff0a152ec50b1d19c25be50c8e15988ac",
            ),
        ];
        let mut inputs = Vec::new();
        let mut prevouts = std::collections::HashMap::new();
        for (txid_hex, sig_hex, prev_hex) in &vins {
            let mut raw = hex(txid_hex);
            raw.reverse(); // display → internal LE
            let op = OutPoint {
                txid: Txid::from_bytes(<[u8; 32]>::try_from(raw).unwrap_or_else(|_| unreachable!())),
                vout: 0,
            };
            prevouts.insert(op, hex(prev_hex));
            inputs.push(TxIn {
                previous_output: op,
                script_sig: Script::new(hex(sig_hex)),
                sequence: 0xffff_ffff,
                witness: Witness::EMPTY,
            });
        }
        // The silent output — the vector's tweaked key at index 0.
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&hex(
            "3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1",
        ));
        let tx = Transaction {
            version: 2,
            inputs,
            outputs: vec![TxOut {
                value: 42_000,
                script_pubkey: Script::new(spk),
            }],
            lock_time: 0,
        };
        let mut scan = [0u8; 32];
        scan.copy_from_slice(&hex(
            "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c",
        ));
        let spend_priv = SecretKey::from_slice(&hex(
            "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
        ))
        .unwrap_or_else(|_| unreachable!());
        let (spend_xonly, _) =
            XOnlyPublicKey::from_keypair(&secp256k1::Keypair::from_secret_key(&secp, &spend_priv));
        let watch = SilentAddress {
            scan_priv: scan,
            spend_pub: spend_xonly.serialize(),
        };
        let found = detect_silent_payment(&tx, &watch, |op| prevouts.get(op).cloned());
        assert_eq!(found, Some(0));
    }
}

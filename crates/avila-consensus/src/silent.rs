//! BIP352 silent-payments detection — the recipient's scan half.
//!
//! A silent payment sends to `B_spend + hash(shared_secret || k)·G`
//! where `shared_secret = input_hash · A · d_scan`: `A` aggregates
//! every input's public key, `input_hash` commits to the smallest
//! outpoint, and `d_scan` is the recipient's scan key. Detection
//! needs only `(d_scan, B_spend)` — no spend-side private key.

use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::hash::{hash160, tagged_hash};
use crate::transaction::{OutPoint, Transaction};

/// A watched silent-payments address — the scan private key plus the
/// spend public key the sender tweaks per payment. `spend_pub` is the
/// FULL compressed key (33 bytes): the `sp1q` address encodes it that
/// way and the label-subtract scan needs the true parity. `labels`
/// holds the BIP352 label integers this address scans for (`m = 0`
/// is the change label — every wallet checks it even when no other
/// labels are used).
#[derive(Clone)]
pub struct SilentAddress {
    /// `d_scan` — the 32-byte scan private key.
    pub scan_priv: [u8; 32],
    /// `B_spend` — the 33-byte compressed spend public key.
    pub spend_pub: [u8; 33],
    /// BIP352 label integers to detect (always includes 0 = change).
    pub labels: Vec<u32>,
}

/// Audit low: derived `Debug` would print `scan_priv` — redact it;
/// the spend pubkey and labels are public and stay visible.
impl std::fmt::Debug for SilentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SilentAddress")
            .field("scan_priv", &"[redacted]")
            .field("spend_pub", &self.spend_pub)
            .field("labels", &self.labels)
            .finish()
    }
}

/// Audit V-S3: a dropped silent watch erases its scan key — the key
/// is secret (it reveals every payment detected to it) and freed heap
/// retains it until reuse.
impl Drop for SilentAddress {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.scan_priv);
    }
}

/// `label_point = hash_BIP0352/Label(ser256(b_scan) || ser32(m))·G` —
/// the precomputed label a receiving wallet compares `output - P_k`
/// against. Returns the x-only encoding.
#[must_use]
fn label_point(scan_priv: &[u8; 32], m: u32) -> Option<PublicKey> {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(scan_priv);
    data.extend_from_slice(&m.to_be_bytes());
    let t = tagged_hash(b"BIP0352/Label", &data);
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&t).ok()?;
    Some(PublicKey::from_secret_key(&secp, &sk))
}

/// BIP341's NUMS point `H = lift_x(0x50929b74…)` — the provably
/// unspendable internal key a taproot output uses when it carries no
/// key-path spend. BIP352 skips an input whose script-path control
/// block names `H` as the internal key: such an output can never have
/// had a real signer key to aggregate into `A`.
const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// The public key a BIP352 input contributes to `A`. `prevout` is the
/// spent output's scriptPubKey; `txin` carries the scriptSig/witness.
/// `None` when the script type carries no key — per BIP352 ineligible
/// inputs are simply ignored, not disqualifying.
fn input_pubkey(txin: &crate::transaction::TxIn, prevout: &[u8]) -> Option<PublicKey> {
    // p2tr: a key-path spend and a script-path spend both contribute
    // the output's x-only key, *unless* it's a script-path spend whose
    // control block names the NUMS point `H` as the internal key —
    // BIP352 requires skipping that input outright.
    if prevout.len() == 34 && prevout[0] == 0x51 && prevout[1] == 0x20 {
        let mut stack = txin.witness.items();
        // BIP341: an annex is present iff there are >= 2 items and the
        // last one starts with 0x50 — strip it before looking for a
        // control block.
        if stack.len() >= 2 && stack.last().is_some_and(|last| last.first() == Some(&0x50)) {
            stack = &stack[..stack.len() - 1];
        }
        // >= 2 items left means a script-path spend; the control block
        // is the last one: `<byte> <32-byte internal key> …` (BIP341).
        if stack.len() >= 2 && stack[stack.len() - 1].get(1..33) == Some(&NUMS_H[..]) {
            return None;
        }
        let x = XOnlyPublicKey::from_slice(&prevout[2..34]).ok()?;
        return Some(x.public_key(secp256k1::Parity::Even));
    }
    // p2wpkh: the compressed key is witness[1].
    if prevout.len() == 22 && prevout[0] == 0x00 && prevout[1] == 0x14 {
        return txin
            .witness
            .items()
            .get(1)
            .and_then(|w| PublicKey::from_slice(w).ok());
    }
    // p2sh-p2wpkh: BIP352 requires the P2SH to actually wrap a P2WPKH
    // redeem script, not just look P2SH-shaped — the scriptSig must be
    // exactly one minimal push of `OP_0 <20-byte-hash>` whose hash160
    // matches the P2SH script hash (Core's own malleation check for
    // the segwit-in-P2SH substitution requires that same exact
    // minimal-push scriptSig, so every confirmed P2SH-P2WPKH spend has
    // this shape). Any other P2SH — multisig, P2SH-P2WSH, ... — is
    // ineligible and must be skipped, not guessed at.
    if prevout.len() == 23 && prevout[0] == 0xa9 && prevout[1] == 0x14 && prevout[22] == 0x87 {
        let ss = txin.script_sig.as_bytes();
        let is_p2wpkh_redeem = ss.len() == 23 && ss[0] == 0x16 && ss[1] == 0x00 && ss[2] == 0x14;
        if !is_p2wpkh_redeem || hash160(&ss[1..23]) != prevout[2..22] {
            return None;
        }
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

/// A detected silent payment — the output index plus the label
/// integer when a labeled (e.g. change-to-self, `m = 0`) output hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SilentHit {
    /// The tx output index carrying the payment.
    pub vout: u32,
    /// The matched label, `None` for the base (unlabeled) address.
    pub label: Option<u32>,
}

/// Whether `tx` pays `addr` — BIP352's scanning routine. Returns
/// every matching output (a tx can carry several payments to the
/// same recipient — the `k` counter advances per hit, not per
/// output).
///
/// `prevout_of` resolves an input's spent scriptPubKey — callers pass
/// the UTXO set plus same-block outputs (a later tx's input may spend
/// an earlier same-block tx's output).
///
/// # Scope
/// First slice: one output match per tx, BIP352 labels via the
/// `output - P_k` lookup (change label always checked), no
/// `sp()`-address serving for light clients.
#[must_use]
pub fn detect_silent_payment(
    tx: &Transaction,
    addr: &SilentAddress,
    prevout_of: impl Fn(&OutPoint) -> Option<Vec<u8>>,
) -> Vec<SilentHit> {
    if tx.is_coinbase() {
        return Vec::new();
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
            Some(a) => match a.combine(&key) {
                Ok(x) => x,
                Err(_) => return Vec::new(),
            },
        });
    }
    let Some(a) = agg else {
        return Vec::new();
    };
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
        .min()
        .unwrap_or([0u8; 36]);
    let mut ih_data = Vec::with_capacity(69);
    ih_data.extend_from_slice(&smallest);
    ih_data.extend_from_slice(&a.serialize());
    let input_hash = tagged_hash(b"BIP0352/Inputs", &ih_data);

    // shared_secret = input_hash · A · d_scan
    let secp = Secp256k1::new();
    let (Ok(ih_s), Ok(scan_s)) = (
        Scalar::from_be_bytes(input_hash),
        Scalar::from_be_bytes(addr.scan_priv),
    ) else {
        return Vec::new();
    };
    let Ok(ecdh) = a
        .mul_tweak(&secp, &ih_s)
        .and_then(|p| p.mul_tweak(&secp, &scan_s))
    else {
        return Vec::new();
    };

    // Precompute label points once — `m = 0` (change) is always in
    // the set per the BIP's cross-compat rule.
    let mut label_pts = std::collections::HashMap::new();
    for m in addr.labels.iter().copied().chain(std::iter::once(0)) {
        if let Some(p) = label_point(&addr.scan_priv, m) {
            label_pts.insert(p.serialize(), m);
        }
    }

    // `k` is a sequential payment counter, NOT the output index:
    // start at 0, compute P_k = B_spend + t_k·G, check every taproot
    // output; a match removes it and rescans with k++ (BIP352's
    // K_max bounds the loop at 2323).
    // `B_spend` keeps its address-encoded parity — the compressed
    // point directly, no x-only re-lift.
    let Ok(b_full) = PublicKey::from_slice(&addr.spend_pub) else {
        return Vec::new();
    };
    let mut remaining: Vec<usize> = tx
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, o)| {
            let b = o.script_pubkey.as_bytes();
            b.len() == 34 && b[0] == 0x51 && b[1] == 0x20
        })
        .map(|(i, _)| i)
        .collect();
    let mut hits = Vec::new();
    let mut k = 0u32;
    while k < 2323 && !remaining.is_empty() {
        let mut td = Vec::with_capacity(37);
        td.extend_from_slice(&ecdh.serialize());
        td.extend_from_slice(&k.to_be_bytes());
        let t_k = tagged_hash(b"BIP0352/SharedSecret", &td);
        let Ok(t_sk) = SecretKey::from_slice(&t_k) else {
            break;
        };
        let Ok(p_full) = b_full.combine(&PublicKey::from_secret_key(&secp, &t_sk)) else {
            break;
        };
        let (p_k, _par) = p_full.x_only_public_key();
        let p_neg = p_full.negate(&secp);
        let mut hit: Option<(usize, Option<u32>)> = None;
        for (pos, &i) in remaining.iter().enumerate() {
            let spk = tx.outputs[i].script_pubkey.as_bytes();
            if p_k.serialize() == spk[2..34] {
                hit = Some((pos, None));
                break;
            }
            // Label check: `output - P_k` should be a known label
            // point; retry with the negated output for the lost Y.
            let Ok(out_pt) = PublicKey::from_slice(&[&[0x02], &spk[2..34]].concat()) else {
                continue;
            };
            for cand in [out_pt, out_pt.negate(&secp)] {
                let Ok(diff) = cand.combine(&p_neg) else {
                    continue;
                };
                if let Some(&m) = label_pts.get(&diff.serialize()) {
                    hit = Some((pos, Some(m)));
                    break;
                }
            }
            if hit.is_some() {
                break;
            }
        }
        let Some((pos, m)) = hit else {
            break;
        };
        let vout = remaining.remove(pos) as u32;
        hits.push(SilentHit { vout, label: m });
        k += 1;
    }
    hits
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
    b_spend: &PublicKey,
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
    td.extend_from_slice(&k.to_be_bytes());
    let t_k = tagged_hash(b"BIP0352/SharedSecret", &td);
    let t_sk = SecretKey::from_slice(&t_k).ok()?;
    let p_k = b_spend
        .combine(&PublicKey::from_secret_key(&secp, &t_sk))
        .ok()?;
    Some(p_k.x_only_public_key().0.serialize())
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
        let spend_pub_full = PublicKey::from_secret_key(&secp, &spend_priv);
        let spend_ser: [u8; 33] = spend_pub_full.serialize();

        let op = OutPoint {
            txid: Txid::from_bytes([0x44; 32]),
            vout: 0,
        };
        let mut smallest = [0u8; 36];
        smallest[..32].copy_from_slice(op.txid.as_bytes());
        smallest[32..].copy_from_slice(&0u32.to_le_bytes());

        // The sender's output key: B_spend + t_0·G.
        let out_xonly = silent_output_key(a_pub, &a_priv, &smallest, &spend_pub_full, &scan_pub, 0)
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
            spend_pub: spend_ser,
            labels: vec![0],
        };
        let found = detect_silent_payment(&tx, &watch, |o| (o == &op).then(|| prev.clone()));
        assert_eq!(
            found,
            vec![SilentHit {
                vout: 0,
                label: None
            }]
        );

        // A different watch must not match.
        let other = SilentAddress {
            scan_priv: [0x99; 32],
            spend_pub: spend_ser,
            labels: vec![0],
        };
        assert!(
            detect_silent_payment(&tx, &other, |o| (o == &op).then(|| prev.clone())).is_empty()
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
                txid: Txid::from_bytes(
                    <[u8; 32]>::try_from(raw).unwrap_or_else(|_| unreachable!()),
                ),
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
        let spend_ser: [u8; 33] = PublicKey::from_secret_key(&secp, &spend_priv).serialize();
        let watch = SilentAddress {
            scan_priv: scan,
            spend_pub: spend_ser,
            labels: vec![0],
        };
        let found = detect_silent_payment(&tx, &watch, |op| prevouts.get(op).cloned());
        assert_eq!(
            found,
            vec![SilentHit {
                vout: 0,
                label: None
            }]
        );
    }
    /// BIP352 "Single recipient: use silent payments for sender
    /// change" — two p2pkh inputs, output 0 is the change labeled
    /// with `m = 0`, output 1 is a different recipient. The scan must
    /// hit vout 0 with `label = Some(0)`.
    #[test]
    fn bip352_vector_change_label() {
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
                "473045022100a8c61b2d470e393279d1ba54f254b7c237de299580b7fa01ffcc940442ecec4502201afba952f4e4661c40acde7acc0341589031ba103a307b886eb867b23b850b972103782eeb913431ca6e9b8c2fd80a5f72ed2024ef72a3c6fb10263c379937323338",
                "76a9147cdd63cc408564188e8e472640e921c7c90e651d88ac",
            ),
        ];
        let mut inputs = Vec::new();
        let mut prevouts = std::collections::HashMap::new();
        for (txid_hex, sig_hex, prev_hex) in &vins {
            let mut raw = hex(txid_hex);
            raw.reverse();
            let op = OutPoint {
                txid: Txid::from_bytes(
                    <[u8; 32]>::try_from(raw).unwrap_or_else(|_| unreachable!()),
                ),
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
        let outputs = [
            "be368e28979d950245d742891ae6064020ba548c1e2e65a639a8bb0675d95cff",
            "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
        ]
        .into_iter()
        .map(|k| {
            let mut spk = vec![0x51, 0x20];
            spk.extend_from_slice(&hex(k));
            TxOut {
                value: 10_000,
                script_pubkey: Script::new(spk),
            }
        })
        .collect();
        let tx = Transaction {
            version: 2,
            inputs,
            outputs,
            lock_time: 0,
        };
        let mut scan = [0u8; 32];
        scan.copy_from_slice(&hex(
            "11b7a82e06ca2648d5fded2366478078ec4fc9dc1d8ff487518226f229d768fd",
        ));
        let spend_priv = SecretKey::from_slice(&hex(
            "b8f87388cbb41934c50daca018901b00070a5ff6cc25a7e9e716a9d5b9e4d664",
        ))
        .unwrap_or_else(|_| unreachable!());
        let spend_ser: [u8; 33] = PublicKey::from_secret_key(&secp, &spend_priv).serialize();
        let watch = SilentAddress {
            scan_priv: scan,
            spend_pub: spend_ser,
            labels: vec![0],
        };
        let hits = detect_silent_payment(&tx, &watch, |op| prevouts.get(op).cloned());
        assert_eq!(
            hits,
            vec![SilentHit {
                vout: 0,
                label: Some(0),
            }]
        );
    }

    fn dummy_txin(script_sig: Vec<u8>, witness: Witness) -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: Txid::from_bytes([0u8; 32]),
                vout: 0,
            },
            script_sig: Script::new(script_sig),
            sequence: 0xffff_ffff,
            witness,
        }
    }

    /// BIP352: a P2TR script-path spend whose control block's internal
    /// key is the NUMS point `H` must be skipped outright — such an
    /// output can never have had a real signer key.
    #[test]
    fn input_pubkey_skips_p2tr_script_path_with_nums_internal_key() {
        let mut prevout = vec![0x51, 0x20];
        prevout.extend_from_slice(&[0xaa; 32]);
        let mut control_block = vec![0xc0];
        control_block.extend_from_slice(&NUMS_H);
        let txin = dummy_txin(vec![], Witness::new(vec![vec![0x51], control_block]));
        assert_eq!(input_pubkey(&txin, &prevout), None);
    }

    /// The annex (last witness item starting with 0x50, when >= 2
    /// items are present) must be stripped before the control block is
    /// found, or a NUMS-keyed script path hides behind it undetected.
    #[test]
    fn input_pubkey_strips_annex_before_finding_control_block() {
        let mut prevout = vec![0x51, 0x20];
        prevout.extend_from_slice(&[0xaa; 32]);
        let mut control_block = vec![0xc0];
        control_block.extend_from_slice(&NUMS_H);
        let annex = vec![0x50, 0x01];
        let witness = Witness::new(vec![vec![0x51], control_block, annex]);
        let txin = dummy_txin(vec![], witness);
        assert_eq!(input_pubkey(&txin, &prevout), None);
    }

    /// A script-path spend whose control block's internal key is *not*
    /// `H` still contributes the output's x-only key — BIP352 only
    /// special-cases the NUMS point, not script-path spends generally.
    #[test]
    fn input_pubkey_uses_output_key_for_non_nums_control_block() {
        let out_x =
            crate::hex::decode("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap_or_default();
        let mut prevout = vec![0x51, 0x20];
        prevout.extend_from_slice(&out_x);
        let mut control_block = vec![0xc0];
        control_block.extend_from_slice(&[0x11; 32]);
        let txin = dummy_txin(vec![], Witness::new(vec![vec![0x51], control_block]));
        let expect = XOnlyPublicKey::from_slice(&out_x)
            .unwrap_or_else(|_| unreachable!())
            .public_key(secp256k1::Parity::Even);
        assert_eq!(input_pubkey(&txin, &prevout), Some(expect));
    }

    /// A key-path spend (single witness item, or two once an annex is
    /// stripped) is never treated as a script path — no control block
    /// to inspect, so the output key always applies.
    #[test]
    fn input_pubkey_treats_single_item_witness_as_key_path() {
        let out_x =
            crate::hex::decode("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
                .unwrap_or_default();
        let mut prevout = vec![0x51, 0x20];
        prevout.extend_from_slice(&out_x);
        let txin = dummy_txin(vec![], Witness::new(vec![vec![0x30; 64]]));
        let expect = XOnlyPublicKey::from_slice(&out_x)
            .unwrap_or_else(|_| unreachable!())
            .public_key(secp256k1::Parity::Even);
        assert_eq!(input_pubkey(&txin, &prevout), Some(expect));
    }

    /// BIP352 requires the P2SH to actually wrap a P2WPKH redeem
    /// script: scriptSig must be exactly one minimal push of
    /// `OP_0 <20-byte-hash>` whose hash160 matches the P2SH script
    /// hash. A P2SH output that merely looks 23-byte P2SH-shaped —
    /// wrapping some other script — must be skipped, not guessed at.
    #[test]
    fn input_pubkey_rejects_non_p2wpkh_p2sh() {
        let redeem = vec![0x51]; // an arbitrary, non-P2WPKH redeem script
        let redeem_hash = hash160(&redeem);
        let mut prevout = vec![0xa9, 0x14];
        prevout.extend_from_slice(&redeem_hash);
        prevout.push(0x87);
        let mut script_sig = vec![redeem.len() as u8];
        script_sig.extend_from_slice(&redeem);
        let txin = dummy_txin(
            script_sig,
            Witness::new(vec![vec![0x30; 72], vec![0x02; 33]]),
        );
        assert_eq!(input_pubkey(&txin, &prevout), None);
    }

    /// Right shape (`OP_0 <20 bytes>`, minimally pushed) but the wrong
    /// hash — BIP352 requires the hash to actually match, not just the
    /// redeem script's form.
    #[test]
    fn input_pubkey_rejects_p2wpkh_shaped_redeem_with_wrong_hash() {
        let mut redeem = vec![0x00, 0x14];
        redeem.extend_from_slice(&[0x22; 20]);
        let mut prevout = vec![0xa9, 0x14];
        prevout.extend_from_slice(&[0x99; 20]); // unrelated hash
        prevout.push(0x87);
        let mut script_sig = vec![0x16];
        script_sig.extend_from_slice(&redeem);
        let txin = dummy_txin(
            script_sig,
            Witness::new(vec![vec![0x30; 72], vec![0x02; 33]]),
        );
        assert_eq!(input_pubkey(&txin, &prevout), None);
    }

    /// A genuine P2SH-P2WPKH spend is still detected: minimal push of
    /// `OP_0 <20-byte-hash>` whose hash160 matches the P2SH hash.
    #[test]
    fn input_pubkey_accepts_genuine_p2sh_p2wpkh() {
        let secp = Secp256k1::new();
        let a_priv = SecretKey::from_slice(&[0x11; 32]).unwrap_or_else(|_| unreachable!());
        let a_pub = PublicKey::from_secret_key(&secp, &a_priv);
        let pkh = hash160(&a_pub.serialize());
        let mut redeem = vec![0x00, 0x14];
        redeem.extend_from_slice(&pkh);
        let redeem_hash = hash160(&redeem);
        let mut prevout = vec![0xa9, 0x14];
        prevout.extend_from_slice(&redeem_hash);
        prevout.push(0x87);
        let mut script_sig = vec![0x16];
        script_sig.extend_from_slice(&redeem);
        let txin = dummy_txin(
            script_sig,
            Witness::new(vec![vec![0x30; 72], a_pub.serialize().to_vec()]),
        );
        assert_eq!(input_pubkey(&txin, &prevout), Some(a_pub));
    }
}

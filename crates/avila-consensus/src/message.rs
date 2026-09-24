//! Bitcoin signed messages — Core's `common/signmessage.cpp`.
//!
//! The wire format predates segwit: a base64-encoded 65-byte compact
//! signature whose header byte is `27 + recid + (compressed ? 4 : 0)`.
//! Verification recovers the public key from (r, s, recid) and compares
//! its `PKHash` — in the compressed or uncompressed encoding the header
//! bit selected — against the address payload. Only P2PKH destinations
//! carry a key; P2SH and witness addresses are rejected by the caller.
//!
//! `MessageSign` uses RFC6979 deterministic nonces (libsecp256k1's
//! default), so the same key+message always produces the identical
//! signature — matching Core byte-for-byte.

use crate::encode::write_compact_size;
use crate::hash::{Hash256, Sha256d, hash160};

/// `MESSAGE_MAGIC` — the literal already carries its CompactSize
/// length prefix (`0x18` = 24).
const MESSAGE_MAGIC: &[u8] = b"\x18Bitcoin Signed Message:\n";

/// `MessageHash` — sha256d of the magic string and the message, each
/// prefixed by its CompactSize length.
#[must_use]
pub fn message_hash(message: &str) -> Hash256 {
    let mut msg = Vec::with_capacity(message.len() + 9);
    write_compact_size(&mut msg, message.len() as u64);
    msg.extend_from_slice(message.as_bytes());
    let mut hasher = Sha256d::new();
    hasher.update(MESSAGE_MAGIC);
    hasher.update(&msg);
    Hash256::from_bytes(hasher.finalize())
}

/// `DecodeSecret` — WIF base58check: `prefix || 32-byte secret` plus an
/// optional trailing `0x01` marking the compressed pubkey form.
/// Returns the secret and its compressed flag, or `None` for a bad
/// checksum, wrong prefix, bad length, or invalid scalar.
#[must_use]
pub fn decode_secret(wif: &str, secret_prefix: u8) -> Option<(secp256k1::SecretKey, bool)> {
    // Core's `DecodeBase58Check(str, data, 34)` — 1 version + 32-byte
    // secret + an optional trailing compressed-flag byte.
    let (version, payload) = crate::address::base58check_decode(wif, 34)?;
    if version != secret_prefix {
        return None;
    }
    let (compressed, key_bytes) = match payload.len() {
        32 => (false, &payload[..]),
        33 if payload[32] == 1 => (true, &payload[..32]),
        _ => return None,
    };
    let key = secp256k1::SecretKey::from_slice(key_bytes).ok()?;
    Some((key, compressed))
}

/// `CKey::GetPubKey` — the secp256k1 public key for `secret` in the
/// encoding `compressed` selects (33-byte compressed or 65-byte
/// uncompressed). WIF's trailing `0x01` flag feeds `compressed`.
#[must_use]
pub fn pubkey_from_secret(secret: &secp256k1::SecretKey, compressed: bool) -> Vec<u8> {
    let secp = secp256k1::Secp256k1::new();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, secret);
    if compressed {
        pubkey.serialize().to_vec()
    } else {
        pubkey.serialize_uncompressed().to_vec()
    }
}

/// `CKey::SignCompact` — RFC6979 deterministic signature, header byte
/// `27 + recid (+4 when the key is compressed)`. `None` only when the
/// secret is invalid — `MessageSign`'s `Sign failed` path.
#[must_use]
pub fn sign_message(
    secret: &secp256k1::SecretKey,
    compressed: bool,
    message: &str,
) -> Option<[u8; 65]> {
    let secp = secp256k1::Secp256k1::signing_only();
    let hash = secp256k1::Message::from_digest(message_hash(message).to_bytes());
    let sig = secp.sign_ecdsa_recoverable(&hash, secret);
    let (recid, compact) = sig.serialize_compact();
    let mut out = [0u8; 65];
    out[0] = 27 + recid.to_i32() as u8 + u8::from(compressed) * 4;
    out[1..].copy_from_slice(&compact);
    Some(out)
}

/// `CPubKey::RecoverCompact` + the `PKHash` comparison from
/// `MessageVerify`: `signature` is the decoded 65-byte compact form.
/// `false` covers every signature-level failure — wrong length, bad
/// recovery, or a hash mismatch — exactly as Core maps them all to
/// `ERR_PUBKEY_NOT_RECOVERED`/`ERR_NOT_SIGNED` → `false`.
#[must_use]
pub fn verify_message(pk_hash: &[u8; 20], signature: &[u8], message: &str) -> bool {
    if signature.len() != 65 {
        return false;
    }
    let header = i32::from(signature[0]) - 27;
    let recid = header & 3;
    let compressed = header & 4 != 0;
    let Ok(recid) = secp256k1::ecdsa::RecoveryId::from_i32(recid) else {
        return false;
    };
    let Ok(sig) = secp256k1::ecdsa::RecoverableSignature::from_compact(&signature[1..], recid)
    else {
        return false;
    };
    let secp = secp256k1::Secp256k1::verification_only();
    let hash = secp256k1::Message::from_digest(message_hash(message).to_bytes());
    let Ok(pubkey) = secp.recover_ecdsa(&hash, &sig) else {
        return false;
    };
    let encoded = if compressed {
        pubkey.serialize().to_vec()
    } else {
        pubkey.serialize_uncompressed().to_vec()
    };
    hash160(&encoded) == *pk_hash
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::params::Network;

    const SK: [u8; 32] = [7u8; 32];

    // The WIF forms and signature produced by Core 29.4's
    // `signmessagewithprivkey` for secret 0x07…07, message "hi".
    const WIF_COMPRESSED: &str = "cMpMxK92W1DjqDvWV3pMn4xLwAuQJhNF3MFqkEHUQRPQofUJku8R";
    const WIF_UNCOMPRESSED: &str = "91e1fpA4xxnUq5jwFxvKkk37nMNPVw1HKf7zGES2gHrV3uSs7pU";

    #[test]
    fn message_hash_matches_core() {
        // sha256d("\x18Bitcoin Signed Message:\n" + "\x02hi") — the
        // digest Core's MessageHash produces for "hi".
        let got = message_hash("hi");
        let mut expect = Sha256d::new();
        expect.update(b"\x18Bitcoin Signed Message:\n\x02hi");
        assert_eq!(got.to_bytes(), expect.finalize());
    }

    #[test]
    fn decode_secret_round_trips_wif() {
        let params = Network::Regtest.params();
        let (key, compressed) = decode_secret(WIF_COMPRESSED, params.base58_secret_prefix).unwrap();
        assert!(compressed);
        assert_eq!(key.secret_bytes(), SK);
        let (_, compressed) = decode_secret(WIF_UNCOMPRESSED, params.base58_secret_prefix).unwrap();
        assert!(!compressed);
        // Wrong network prefix, bad checksum, bad payload all fail.
        assert!(decode_secret(WIF_COMPRESSED, 0x80).is_none());
        assert!(decode_secret("bogus", params.base58_secret_prefix).is_none());
        let zero_wif = crate::address::base58check(params.base58_secret_prefix, &[0u8; 32]);
        assert!(decode_secret(&zero_wif, params.base58_secret_prefix).is_none());
    }

    #[test]
    fn sign_message_matches_core_byte_for_byte() {
        let key = secp256k1::SecretKey::from_slice(&SK).unwrap();
        let sig = sign_message(&key, true, "hi").unwrap();
        // Core 29.4 returned this exact base64 for the same inputs —
        // RFC6979 makes the (r, s) pair deterministic.
        assert_eq!(
            crate::hex::encode(&sig[1..]),
            "2f77f8e65bb74309bab32f9b7347c635b798174719cad8e88942bb0d8b897f647ab51768c00c5f194ce2fbfa981b43fc6f35830a728ad010a79ded0b418c5f1f"
        );
        assert_eq!((sig[0] - 27) & 4, 4, "compressed flag set");
        assert!(matches!(sig[0], 31..=34));
        // Uncompressed form: same (r, s), header without +4.
        let sig_u = sign_message(&key, false, "hi").unwrap();
        assert_eq!(sig[1..], sig_u[1..]);
        assert_eq!(sig_u[0], sig[0] - 4);
    }

    #[test]
    fn verify_round_trip_and_mismatch() {
        let key = secp256k1::SecretKey::from_slice(&SK).unwrap();
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &key);
        for compressed in [true, false] {
            let encoded = if compressed {
                pk.serialize().to_vec()
            } else {
                pk.serialize_uncompressed().to_vec()
            };
            let hash = hash160(&encoded);
            let sig = sign_message(&key, compressed, "hi").unwrap();
            assert!(verify_message(&hash, &sig, "hi"));
            assert!(!verify_message(&hash, &sig, "bye"), "wrong message");
            assert!(!verify_message(&[0u8; 20], &sig, "hi"), "wrong hash");
        }
        // Every malformed form fails soft.
        assert!(!verify_message(&[0u8; 20], &[], "hi"));
        assert!(!verify_message(&[0u8; 20], &[0u8; 64], "hi"));
        assert!(!verify_message(&[0u8; 20], &[0u8; 65], "hi"));
        let mut bad = sign_message(&key, true, "hi").unwrap();
        bad[10] ^= 1;
        // A corrupted r/s either fails recovery or recovers a different
        // key — never verifies.
        assert!(!verify_message(&hash160(&pk.serialize()), &bad, "hi"));
    }

    /// `decode_secret` threads Core's 34-byte WIF cap into
    /// `base58check_decode`, so a hostile multi-KiB string is rejected
    /// almost immediately instead of costing O(n²) CPU.
    #[test]
    fn decode_secret_rejects_long_input_quickly() {
        let params = Network::Regtest.params();
        let long = "z".repeat(64 * 1024);
        let start = std::time::Instant::now();
        assert!(decode_secret(&long, params.base58_secret_prefix).is_none());
        assert!(
            start.elapsed().as_millis() < 50,
            "took {:?}, expected well under 50ms",
            start.elapsed()
        );
    }
}

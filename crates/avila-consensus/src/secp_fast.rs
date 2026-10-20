//! Narrow byte-oriented boundary around the newer libsecp256k1 binding.
//!
//! The workspace keeps its established binding for key handling, signing,
//! BIP324 and test fixtures. Only consensus ECDSA/Schnorr verification crosses
//! this module, so no secp256k1 Rust types from the two crate versions escape.

use secp256k1_fast as secp;

pub(crate) type PublicKey = secp::PublicKey;
pub(crate) type EcdsaSignature = secp::ecdsa::Signature;
pub(crate) type XOnlyPublicKey = secp::XOnlyPublicKey;
pub(crate) type SchnorrSignature = secp::schnorr::Signature;

pub(crate) fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, secp::Error> {
    match bytes.len() {
        33 => {
            let bytes: [u8; 33] = match bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => return Err(secp::Error::InvalidPublicKey),
            };
            secp::PublicKey::from_byte_array_compressed(bytes)
        }
        65 => {
            let bytes: [u8; 65] = match bytes.try_into() {
                Ok(bytes) => bytes,
                Err(_) => return Err(secp::Error::InvalidPublicKey),
            };
            secp::PublicKey::from_byte_array_uncompressed(bytes)
        }
        _ => Err(secp::Error::InvalidPublicKey),
    }
}

pub(crate) fn parse_ecdsa_der(bytes: &[u8]) -> Result<EcdsaSignature, secp::Error> {
    secp::ecdsa::Signature::from_der_lax(bytes)
}

pub(crate) fn parse_xonly_public_key(bytes: &[u8]) -> Result<XOnlyPublicKey, secp::Error> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| secp::Error::InvalidPublicKey)?;
    secp::XOnlyPublicKey::from_byte_array(bytes)
}

pub(crate) fn parse_schnorr_signature(bytes: &[u8]) -> Result<SchnorrSignature, secp::Error> {
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| secp::Error::InvalidSignature)?;
    Ok(secp::schnorr::Signature::from_byte_array(bytes))
}

/// Verify a lax-DER ECDSA signature, including Core's historical low-S
/// normalization before verification.
pub(crate) fn verify_ecdsa(pk: &PublicKey, signature: &EcdsaSignature, digest: &[u8; 32]) -> bool {
    secp::ecdsa::verify(signature, secp::Message::from_digest(*digest), pk).is_ok()
}

/// Verify an already-normalized compact ECDSA signature using only byte data
/// at the API boundary (used by the advice fallback path).
pub(crate) fn verify_ecdsa_compact(pubkey: &[u8], signature: &[u8; 64], digest: &[u8; 32]) -> bool {
    let Ok(pk) = parse_public_key(pubkey) else {
        return false;
    };
    let Ok(signature) = secp::ecdsa::Signature::from_compact(signature) else {
        return false;
    };
    secp::ecdsa::verify(&signature, secp::Message::from_digest(*digest), &pk).is_ok()
}

pub(crate) fn verify_schnorr_parsed(
    signature: &SchnorrSignature,
    pk: &XOnlyPublicKey,
    digest: &[u8; 32],
) -> bool {
    secp::schnorr::verify(signature, digest, pk).is_ok()
}

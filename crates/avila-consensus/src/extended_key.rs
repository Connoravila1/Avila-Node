//! BIP32 extended keys — the subset Bitcoin Core's descriptor parser
//! consumes (`key.cpp`/`util/bip32.cpp`): base58check 78-byte
//! serialization, `CKDpub`/`CKDpriv` child derivation, and the parent
//! fingerprint used in `[origin/path]` key expressions.

use crate::hash::hash160;

/// HMAC-SHA512 — BIP32's `CKD`/`Fingerprint` primitive. Implemented
/// over sha2 directly rather than pulling in an hmac crate: block size
/// 128, pads the key or hashes it down when oversized.
fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    use sha2::Digest;
    const BLOCK: usize = 128;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..64].copy_from_slice(&sha2::Sha512::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = sha2::Sha512::new();
    for b in &mut key_block {
        *b ^= 0x36;
    }
    inner.update(key_block);
    inner.update(data);
    let inner_out = inner.finalize();
    let mut outer = sha2::Sha512::new();
    for b in &mut key_block {
        *b ^= 0x36 ^ 0x5c;
    }
    outer.update(key_block);
    outer.update(inner_out);
    outer.finalize().into()
}

/// A decoded BIP32 extended key — Core's `CExtKey`/`CExtPubKey`
/// serialized form, 78 bytes:
/// `version(4) || depth(1) || parent_fp(4) || child_num(4, BE) ||
/// chain(32) || key(33)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtKey {
    /// The four version bytes as serialized (e.g. `xpub`/`tpub`/
    /// `xprv`/`tprv`); the network checks happen at decode time.
    pub version: [u8; 4],
    /// Derivation depth (0 for master).
    pub depth: u8,
    /// First 4 bytes of the parent's `hash160(pubkey)` — zero for the
    /// master.
    pub parent_fingerprint: [u8; 4],
    /// The BIP32 child index, hardened bit included.
    pub child: u32,
    /// The 32-byte chain code.
    pub chain_code: [u8; 32],
    /// The serialized key: 33-byte compressed pubkey, or `0x00 ||
    /// secret` for private keys.
    pub key: [u8; 33],
}

/// Extended-key decode failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtKeyError {
    /// Not valid base58check of exactly 78 bytes.
    Encoding,
    /// The version bytes match neither the public nor private prefix.
    Prefix,
    /// The key material itself is invalid (off-curve pubkey or
    /// out-of-range/zero secret).
    Key,
    /// Depth/fingerprint/child fields are inconsistent (a depth-0 key
    /// must carry zero fingerprint and child number).
    Structure,
}

impl ExtKey {
    /// `DecodeExtKey`/`DecodeExtPubKey` — parse the 78-byte base58check
    /// form, expecting `pub_prefix` for public keys and `priv_prefix`
    /// for private. Validates the embedded key material (pubkey on
    /// curve; secret in range).
    pub fn decode(
        text: &str,
        pub_prefix: [u8; 4],
        priv_prefix: [u8; 4],
    ) -> Result<Self, ExtKeyError> {
        // Core's `DecodeBase58Check(str, data, BIP32_EXTKEY_SIZE)` — 78
        // bytes caps the decode before the length check below ever runs.
        let raw = crate::address::base58check_decode_body(text, 78).ok_or(ExtKeyError::Encoding)?;
        if raw.len() != 78 {
            return Err(ExtKeyError::Encoding);
        }
        let version: [u8; 4] = raw[..4].try_into().map_err(|_| ExtKeyError::Encoding)?;
        let is_pub = version == pub_prefix;
        let is_priv = version == priv_prefix;
        if !is_pub && !is_priv {
            return Err(ExtKeyError::Prefix);
        }
        let key: [u8; 33] = raw[45..78].try_into().map_err(|_| ExtKeyError::Encoding)?;
        let parsed = Self {
            version,
            depth: raw[4],
            parent_fingerprint: raw[5..9].try_into().map_err(|_| ExtKeyError::Encoding)?,
            child: u32::from_be_bytes(raw[9..13].try_into().map_err(|_| ExtKeyError::Encoding)?),
            chain_code: raw[13..45].try_into().map_err(|_| ExtKeyError::Encoding)?,
            key,
        };
        if is_pub && !crate::descriptor::pubkey_is_valid(&key) {
            return Err(ExtKeyError::Key);
        }
        if is_priv && (key[0] != 0 || secp256k1::SecretKey::from_slice(&key[1..]).is_err()) {
            return Err(ExtKeyError::Key);
        }
        // A master key must carry a zero fingerprint and child number
        // (Core's DecodeExtKey structural check).
        if parsed.depth == 0 && (parsed.parent_fingerprint != [0; 4] || parsed.child != 0) {
            return Err(ExtKeyError::Structure);
        }
        Ok(parsed)
    }

    /// Whether the key material is private (`0x00 || secret`).
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.key[0] == 0 && secp256k1::SecretKey::from_slice(&self.key[1..]).is_ok()
    }

    /// The compressed public key — decoded directly for public keys,
    /// derived from the secret for private ones.
    #[must_use]
    pub fn public_key(&self) -> Option<secp256k1::PublicKey> {
        if self.is_private() {
            let sk = secp256k1::SecretKey::from_slice(&self.key[1..]).ok()?;
            let secp = secp256k1::Secp256k1::new();
            Some(secp256k1::PublicKey::from_secret_key(&secp, &sk))
        } else {
            secp256k1::PublicKey::from_slice(&self.key).ok()
        }
    }

    /// The `fingerprint` field of `CExtPubKey::key` — first 4 bytes of
    /// `hash160(compressed_pubkey)`, used as the `[fp/…]` origin id.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 4] {
        let pk = self
            .public_key()
            .map(|p| p.serialize())
            .unwrap_or([0u8; 33]);
        let h = hash160(&pk);
        [h[0], h[1], h[2], h[3]]
    }

    /// `CKDpriv`/`CKDpub` — derive child `index` (hardened bit
    /// included). Hardened derivation requires private key material.
    /// Returns `None` on the (cryptographically impossible)
    /// invalid-child cases, matching Core's `Derive` failure.
    #[must_use]
    pub fn derive(&self, index: u32) -> Option<Self> {
        let hardened = index & 0x8000_0000 != 0;
        let mut data = Vec::with_capacity(37);
        if hardened {
            if !self.is_private() {
                return None;
            }
            data.extend_from_slice(&self.key); // 0x00 || secret
        } else {
            data.extend_from_slice(&self.public_key()?.serialize());
        }
        data.extend_from_slice(&index.to_be_bytes());
        let out = hmac_sha512(&self.chain_code, &data);
        let (tweak, chain) = out.split_at(32);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(chain);
        let mut key = [0u8; 33];
        let secp = secp256k1::Secp256k1::new();
        if self.is_private() {
            let sk = secp256k1::SecretKey::from_slice(&self.key[1..]).ok()?;
            let tweak_sk = secp256k1::SecretKey::from_slice(tweak).ok()?;
            let child = sk.add_tweak(&tweak_sk.into()).ok()?;
            key[0] = 0;
            key[1..].copy_from_slice(&child.secret_bytes());
        } else {
            let tweak_sk = secp256k1::SecretKey::from_slice(tweak).ok()?;
            let pk = self.public_key()?;
            let child = pk.add_exp_tweak(&secp, &tweak_sk.into()).ok()?;
            key.copy_from_slice(&child.serialize());
        }
        Some(Self {
            version: self.version,
            depth: self.depth.checked_add(1)?,
            parent_fingerprint: self.fingerprint(),
            child: index,
            chain_code,
            key,
        })
    }

    /// The `Neuter`ed public form — same fields, public version bytes,
    /// compressed pubkey material.
    #[must_use]
    pub fn neuter(&self, pub_prefix: [u8; 4]) -> Option<Self> {
        let mut out = self.clone();
        out.version = pub_prefix;
        out.key.copy_from_slice(&self.public_key()?.serialize());
        Some(out)
    }

    /// The BIP32 master key for a seed — `HMAC-SHA512("Bitcoin seed",
    /// seed)`, split into secret and chain code.
    #[must_use]
    pub fn from_seed(seed: &[u8], priv_prefix: [u8; 4]) -> Option<Self> {
        let out = hmac_sha512(b"Bitcoin seed", seed);
        let (secret, chain) = out.split_at(32);
        secp256k1::SecretKey::from_slice(secret).ok()?;
        let mut key = [0u8; 33];
        key[1..].copy_from_slice(secret);
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(chain);
        Some(Self {
            version: priv_prefix,
            depth: 0,
            parent_fingerprint: [0; 4],
            child: 0,
            chain_code,
            key,
        })
    }

    /// The canonical base58check text form.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut body = Vec::with_capacity(78);
        body.extend_from_slice(&self.version);
        body.push(self.depth);
        body.extend_from_slice(&self.parent_fingerprint);
        body.extend_from_slice(&self.child.to_be_bytes());
        body.extend_from_slice(&self.chain_code);
        body.extend_from_slice(&self.key);
        crate::address::base58check_body(&body)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const XPUB: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
    const XPRV: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
    const HARDENED: u32 = 0x8000_0000;

    // BIP32 test vector 1 — seed 000102…0f, chain m/0'/1/2'/2/1000000000.
    #[test]
    fn bip32_vector1_derivation() {
        let seed = crate::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtKey::from_seed(&seed, XPRV).unwrap();
        assert_eq!(
            master.encode(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );
        let path = [HARDENED, 1, 2 | HARDENED, 2, 1_000_000_000];
        let mut node = master.clone();
        for &i in &path {
            node = node.derive(i).unwrap();
        }
        assert_eq!(
            node.encode(),
            "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
        );
        // Public derivation arrives at the same xpub: neuter at
        // m/0'/1/2' then walk the non-hardened steps 2/1000000000.
        let mut pub_expected = master.clone();
        for &i in &path[..3] {
            pub_expected = pub_expected.derive(i).unwrap();
        }
        let mut check = pub_expected.neuter(XPUB).unwrap();
        for &i in &[2u32, 1_000_000_000] {
            check = check.derive(i).unwrap();
        }
        assert_eq!(
            check.encode(),
            "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        );
        // Public keys agree: derived privately then neutered equals
        // derived publicly.
        assert_eq!(node.neuter(XPUB).unwrap().key, check.key);
    }

    #[test]
    fn decode_validates_version_and_structure() {
        let seed = crate::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtKey::from_seed(&seed, XPRV).unwrap();
        let xprv = master.encode();
        let xpub = master.neuter(XPUB).unwrap().encode();
        assert!(ExtKey::decode(&xprv, XPUB, XPRV).unwrap().is_private());
        assert!(!ExtKey::decode(&xpub, XPUB, XPRV).unwrap().is_private());
        // Wrong prefixes (e.g. testnet) rejected.
        assert_eq!(
            ExtKey::decode(&xprv, [0x04, 0x35, 0x87, 0xcf], [0x04, 0x35, 0x83, 0x94]),
            Err(ExtKeyError::Prefix)
        );
        // Corrupted checksum.
        assert_eq!(
            ExtKey::decode(&(xprv[..10].to_string() + "1" + &xprv[11..]), XPUB, XPRV),
            Err(ExtKeyError::Encoding)
        );
        // Hardened derivation off an xpub is impossible.
        let pub_key = ExtKey::decode(&xpub, XPUB, XPRV).unwrap();
        assert!(pub_key.derive(HARDENED).is_none());
        assert!(pub_key.derive(0).is_some());
    }

    /// `decode` threads Core's 78-byte (`BIP32_EXTKEY_SIZE`) cap into
    /// `base58check_decode_body`, so a hostile multi-KiB string is
    /// rejected almost immediately instead of costing O(n²) CPU.
    #[test]
    fn decode_rejects_long_input_quickly() {
        let long = "z".repeat(64 * 1024);
        let start = std::time::Instant::now();
        assert_eq!(
            ExtKey::decode(&long, XPUB, XPRV),
            Err(ExtKeyError::Encoding)
        );
        assert!(
            start.elapsed().as_millis() < 50,
            "took {:?}, expected well under 50ms",
            start.elapsed()
        );
    }
}

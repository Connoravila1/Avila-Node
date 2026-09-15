//! SHA-256 and double-SHA-256 (`sha256d`) hashing, and the hash newtypes built on top of it.
//!
//! Bitcoin identifies blocks and transactions by `sha256d`, i.e. `SHA256(SHA256(data))`. The
//! 32-byte digest is stored and compared in the byte order it is produced in ("internal" or
//! "raw" order); the conventional human-readable form reverses those bytes before hex-encoding
//! them (so the genesis block hash's raw bytes end `...c68d6190...`, but reversed for display
//! they print as `000000000019d668...`; see the `genesis_header_hashes_to_expected_display`
//! test below for the full values). This module stores raw bytes internally and reverses only
//! for [`core::fmt::Display`]/[`core::fmt::Debug`]/[`core::str::FromStr`], per Bitcoin
//! convention.

use std::fmt;
use std::str::FromStr;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::hex;

/// Computes the single SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes `SHA256(SHA256(data))`, Bitcoin's standard hashing operation.
#[must_use]
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Computes `RIPEMD160(SHA256(data))` — Bitcoin's `Hash160`, the
/// 20-byte key/script hash behind P2PKH, P2SH and P2WPKH.
#[must_use]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd::Ripemd160::digest(sha256(data)).into()
}

/// An incremental double-SHA-256 hasher.
///
/// Feed data with repeated calls to [`Sha256d::update`], then call [`Sha256d::finalize`] once
/// to obtain `SHA256(SHA256(all data fed))`. Produces the same result as [`sha256d`] applied to
/// the concatenation of every chunk passed to `update`.
#[derive(Clone)]
pub struct Sha256d {
    inner: Sha256,
}

impl Sha256d {
    /// Creates a new, empty incremental hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Feeds more data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consumes the hasher, returning `SHA256(SHA256(data))` of everything fed in.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        let first: [u8; 32] = self.inner.finalize().into();
        sha256(&first)
    }
}

impl Default for Sha256d {
    fn default() -> Self {
        Self::new()
    }
}

/// Error parsing a hash from its display-order hex string.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HashParseError {
    /// The string was not exactly 64 bytes long (UTF-8 byte length of the input string).
    #[error("invalid hash length: expected 64 hex bytes, found {0}")]
    InvalidLength(usize),
    /// A character in the string is not a valid hex digit.
    #[error("invalid hex character at index {index}")]
    InvalidCharacter {
        /// Byte index into the input string of the offending character.
        index: usize,
    },
}

/// Parses a 64-character display-order hex string into raw (internal-order) bytes.
fn parse_display_hex(s: &str) -> Result<[u8; 32], HashParseError> {
    if s.len() != 64 {
        return Err(HashParseError::InvalidLength(s.len()));
    }
    let decoded = hex::decode(s).map_err(|err| match err {
        hex::HexError::OddLength(len) => HashParseError::InvalidLength(len),
        hex::HexError::InvalidCharacter { index } => HashParseError::InvalidCharacter { index },
    })?;
    let mut display_order: [u8; 32] = decoded
        .try_into()
        .map_err(|v: Vec<u8>| HashParseError::InvalidLength(v.len()))?;
    display_order.reverse();
    Ok(display_order)
}

/// Formats raw (internal-order) bytes as a reversed-byte-order hex string.
fn format_display_hex(raw: &[u8; 32]) -> String {
    let mut reversed = *raw;
    reversed.reverse();
    hex::encode(&reversed)
}

/// Defines a 32-byte hash newtype with Bitcoin's raw-storage / reversed-display convention.
macro_rules! hash_newtype {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Stored as 32 raw bytes in the order produced by hashing (internal order). The
        /// [`Display`](fmt::Display), [`Debug`](fmt::Debug), and [`FromStr`] implementations
        /// use the conventional *reversed-byte-order* hex string instead; use
        /// [`Self::as_bytes`] / [`Self::from_bytes`] to work with raw bytes directly.
        ///
        /// [`Ord`] and [`PartialOrd`] compare the **raw** bytes lexicographically. This is
        /// *not* the numeric order of the hash interpreted as a display-order integer (nor is
        /// it a difficulty ordering) — it exists so the type can be used as a map/set key.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 32]);

        impl $name {
            /// The all-zero hash.
            pub const ZERO: Self = Self([0u8; 32]);

            /// Wraps raw (internal-order) bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns a reference to the raw (internal-order) bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Consumes `self`, returning the raw (internal-order) bytes.
            #[must_use]
            pub fn to_bytes(self) -> [u8; 32] {
                self.0
            }

            /// Returns `true` if every byte is zero.
            #[must_use]
            pub fn is_zero(&self) -> bool {
                self.0 == [0u8; 32]
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&format_display_hex(&self.0))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), format_display_hex(&self.0))
            }
        }

        impl FromStr for $name {
            type Err = HashParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_display_hex(s).map(Self)
            }
        }
    };
}

hash_newtype!(
    BlockHash,
    "The `sha256d` hash of a block header, identifying a block."
);
hash_newtype!(
    Txid,
    "The `sha256d` hash of a transaction's non-witness serialization."
);
hash_newtype!(
    Wtxid,
    "The `sha256d` hash of a transaction's witness serialization (BIP141)."
);
hash_newtype!(MerkleRoot, "The root of a block's transaction merkle tree.");
hash_newtype!(
    Hash256,
    "A generic 32-byte digest — e.g. the `hash_serialized_3`/`muhash` UTXO-set commitment."
);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_empty() {
        let digest = sha256d(b"");
        assert_eq!(
            hex::encode(&digest),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn sha256_matches_known_vector() {
        // SHA256("abc") is a well-known NIST test vector; sha256d builds on the same primitive.
        let digest = sha256(b"abc");
        assert_eq!(
            hex::encode(&digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256d_is_double_sha256() {
        let data = b"bitcoin";
        let once = sha256(data);
        let twice = sha256(&once);
        assert_eq!(sha256d(data), twice);
    }

    #[test]
    fn incremental_hasher_equals_one_shot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let mut hasher = Sha256d::new();
        hasher.update(&data[..10]);
        hasher.update(&data[10..20]);
        hasher.update(&data[20..]);
        assert_eq!(hasher.finalize(), sha256d(data));
    }

    #[test]
    fn incremental_hasher_empty_matches_default() {
        assert_eq!(Sha256d::default().finalize(), sha256d(b""));
        assert_eq!(Sha256d::new().finalize(), sha256d(b""));
    }

    #[test]
    fn genesis_header_hashes_to_expected_display() {
        let header_hex = "0100000000000000000000000000000000000000000000000000000000000000\
000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
        let header = hex::decode(header_hex).unwrap();
        assert_eq!(header.len(), 80);
        let raw = sha256d(&header);
        // Pins the *raw* (internal, non-reversed) byte order, as quoted in this module's
        // top-of-file doc comment: the raw digest ends `...c68d6190...`, distinct from (and the
        // byte-reverse of) the reversed display form asserted below.
        assert_eq!(
            hex::encode(&raw),
            "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
        );
        let hash = BlockHash::from_bytes(raw);
        assert_eq!(
            hash.to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn hash_zero_is_zero() {
        assert!(BlockHash::ZERO.is_zero());
        assert!(Txid::ZERO.is_zero());
        assert!(Wtxid::ZERO.is_zero());
        assert!(MerkleRoot::ZERO.is_zero());
        assert_eq!(BlockHash::ZERO.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn hash_from_bytes_round_trips_bytes() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let hash = BlockHash::from_bytes(bytes);
        assert_eq!(*hash.as_bytes(), bytes);
        assert_eq!(hash.to_bytes(), bytes);
        assert!(!hash.is_zero());
    }

    #[test]
    fn hash_from_array_conversion() {
        let bytes = [7u8; 32];
        let hash: BlockHash = bytes.into();
        assert_eq!(hash.to_bytes(), bytes);
    }

    #[test]
    fn display_reverses_byte_order() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xaa;
        bytes[31] = 0xbb;
        let hash = BlockHash::from_bytes(bytes);
        let text = hash.to_string();
        assert!(text.starts_with("bb"));
        assert!(text.ends_with("aa"));
    }

    #[test]
    fn debug_wraps_display_in_type_name() {
        let hash = Txid::from_bytes([0u8; 32]);
        let debug = format!("{hash:?}");
        assert!(debug.starts_with("Txid("));
        assert!(debug.ends_with(')'));
        assert!(debug.contains(&hash.to_string()));
    }

    #[test]
    fn from_str_round_trips_with_display() {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let hash = MerkleRoot::from_bytes(bytes);
        let text = hash.to_string();
        let parsed: MerkleRoot = text.parse().expect("round trip must parse");
        assert_eq!(parsed, hash);
        assert_eq!(
            MerkleRoot::from_str(&text).expect("round trip must parse"),
            hash
        );
    }

    #[test]
    fn from_str_genesis_hash() {
        let hash: BlockHash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
            .parse()
            .expect("valid 64-char hash must parse");
        let header_hex = "0100000000000000000000000000000000000000000000000000000000000000\
000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
        let header = hex::decode(header_hex).unwrap();
        assert_eq!(hash, BlockHash::from_bytes(sha256d(&header)));
    }

    #[test]
    fn from_str_rejects_short_and_long() {
        let short = "a".repeat(63);
        let long = "a".repeat(65);
        assert_eq!(
            BlockHash::from_str(&short),
            Err(HashParseError::InvalidLength(63))
        );
        assert_eq!(
            BlockHash::from_str(&long),
            Err(HashParseError::InvalidLength(65))
        );
    }

    #[test]
    fn from_str_rejects_non_hex() {
        let mut s = "a".repeat(64);
        s.replace_range(10..11, "z");
        assert_eq!(
            BlockHash::from_str(&s),
            Err(HashParseError::InvalidCharacter { index: 10 })
        );
    }

    #[test]
    fn from_str_length_check_counts_bytes_not_chars() {
        // 32 two-byte UTF-8 characters ('é') is 64 bytes but only 32 Unicode scalar values.
        // The length pre-check (and `InvalidLength`'s value) must be measuring the 64-byte
        // length, not the 32-character count, so this passes the length check and is only
        // rejected afterward by the hex-digit check.
        let s: String = std::iter::repeat_n('é', 32).collect();
        assert_eq!(s.len(), 64);
        assert_eq!(s.chars().count(), 32);
        assert_eq!(
            BlockHash::from_str(&s),
            Err(HashParseError::InvalidCharacter { index: 0 })
        );
    }

    #[test]
    fn from_str_rejects_empty() {
        assert_eq!(
            BlockHash::from_str(""),
            Err(HashParseError::InvalidLength(0))
        );
    }

    #[test]
    fn ord_compares_raw_bytes_not_numeric_display() {
        // Raw bytes [0x00, ...] < [0x01, ...] even though, numerically, a hash with a leading
        // zero *byte* in raw order has that byte as its *last* (most significant after
        // reversal) display digit - Ord here is intentionally not that numeric comparison.
        let mut low_raw = [0u8; 32];
        low_raw[0] = 0x00;
        let mut high_raw = [0u8; 32];
        high_raw[0] = 0x01;
        let low = BlockHash::from_bytes(low_raw);
        let high = BlockHash::from_bytes(high_raw);
        assert!(low < high);
    }

    #[test]
    fn distinct_hash_types_are_independent() {
        let bytes = [9u8; 32];
        let txid = Txid::from_bytes(bytes);
        let wtxid = Wtxid::from_bytes(bytes);
        // Same bytes, but the compiler enforces these are different types; equality of the
        // underlying bytes is exercised via as_bytes.
        assert_eq!(txid.as_bytes(), wtxid.as_bytes());
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            HashParseError::InvalidLength(10).to_string(),
            "invalid hash length: expected 64 hex bytes, found 10"
        );
        assert_eq!(
            HashParseError::InvalidCharacter { index: 4 }.to_string(),
            "invalid hex character at index 4"
        );
    }
}

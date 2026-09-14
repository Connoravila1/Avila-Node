//! Block headers: the fixed 80-byte structure that identifies a block, commits to its
//! transactions via a merkle root, and carries its proof of work.
//!
//! Matches Bitcoin Core's `CBlockHeader` (`primitives/block.h`): five little-endian integer
//! fields plus two 32-byte hashes, serialized in a fixed field order with no length prefixes.

use crate::arith::{CompactTarget, ExpandedTarget};
use crate::encode::{DecodeError, Decoder};
use crate::hash::{BlockHash, MerkleRoot, sha256d};

/// A Bitcoin block header.
///
/// Always exactly [`BlockHeader::SIZE`] (80) bytes when serialized: a 4-byte version, two
/// 32-byte hashes (previous block, merkle root), and three 4-byte fields (time, bits, nonce).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlockHeader {
    /// The block version, interpreted as a signed 32-bit integer (Core's `nVersion`). Since
    /// BIP9, the high bits of a positive version encode signaled soft-fork deployments.
    pub version: i32,
    /// The hash of this block's parent (Core's `hashPrevBlock`). All-zero for genesis blocks.
    pub prev_block_hash: BlockHash,
    /// The root of the merkle tree of this block's transaction ids (Core's `hashMerkleRoot`).
    pub merkle_root: MerkleRoot,
    /// The block's timestamp, seconds since the Unix epoch (Core's `nTime`).
    pub time: u32,
    /// The compact-encoded proof-of-work target this block's hash must not exceed (Core's
    /// `nBits`).
    pub bits: CompactTarget,
    /// The value miners vary to satisfy the proof-of-work requirement (Core's `nNonce`).
    pub nonce: u32,
}

impl BlockHeader {
    /// The exact serialized size of every block header, in bytes.
    pub const SIZE: usize = 80;

    /// Serializes this header to its fixed 80-byte on-wire form.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut out = Vec::with_capacity(Self::SIZE);
        self.write(&mut out);
        let mut array = [0u8; Self::SIZE];
        // `write` always appends exactly `Self::SIZE` bytes: 4 (version) + 32 + 32 + 4 + 4 + 4.
        array.copy_from_slice(&out);
        array
    }

    /// Appends this header's serialized form to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(self.prev_block_hash.as_bytes());
        out.extend_from_slice(self.merkle_root.as_bytes());
        out.extend_from_slice(&self.time.to_le_bytes());
        out.extend_from_slice(&self.bits.0.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
    }

    /// Decodes a header from exactly [`BlockHeader::SIZE`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::HeaderLength`] if `bytes` is not exactly 80 bytes long.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != Self::SIZE {
            return Err(DecodeError::HeaderLength(bytes.len()));
        }
        let mut decoder = Decoder::new(bytes);
        let header = Self::read(&mut decoder)?;
        // Exactly `Self::SIZE` bytes were checked above and `read` consumes exactly that many,
        // so the decoder is always finished here; `finish` is called anyway for defense in
        // depth against a future change to `read`'s field list.
        decoder.finish()?;
        Ok(header)
    }

    /// Reads a header from `decoder`, consuming exactly [`BlockHeader::SIZE`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] if fewer than [`BlockHeader::SIZE`] bytes remain.
    pub fn read(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let version = decoder.read_i32_le()?;
        let prev_block_hash = BlockHash::from_bytes(decoder.read_array::<32>()?);
        let merkle_root = MerkleRoot::from_bytes(decoder.read_array::<32>()?);
        let time = decoder.read_u32_le()?;
        let bits = CompactTarget(decoder.read_u32_le()?);
        let nonce = decoder.read_u32_le()?;
        Ok(Self {
            version,
            prev_block_hash,
            merkle_root,
            time,
            bits,
            nonce,
        })
    }

    /// Computes this header's block hash: `sha256d` of its 80-byte serialization.
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        BlockHash::from_bytes(sha256d(&self.encode()))
    }

    /// Decodes this header's `bits` field into an [`ExpandedTarget`].
    #[must_use]
    pub fn target(&self) -> ExpandedTarget {
        self.bits.expand()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::hex;

    const GENESIS_HEADER_HEX: &str = "0100000000000000000000000000000000000000000000000000000000\
000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d\
1dac2b7c";

    fn genesis_header() -> BlockHeader {
        BlockHeader::decode(&hex::decode(GENESIS_HEADER_HEX).unwrap()).unwrap()
    }

    #[test]
    fn size_constant_is_80() {
        assert_eq!(BlockHeader::SIZE, 80);
    }

    #[test]
    fn genesis_decodes_to_expected_fields() {
        let header = genesis_header();
        assert_eq!(header.version, 1);
        assert!(header.prev_block_hash.is_zero());
        assert_eq!(
            header.merkle_root,
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
                .parse()
                .unwrap()
        );
        assert_eq!(header.time, 1_231_006_505);
        assert_eq!(header.bits, CompactTarget(0x1d00_ffff));
        assert_eq!(header.nonce, 2_083_236_893);
    }

    #[test]
    fn genesis_hash_matches_expected() {
        let header = genesis_header();
        assert_eq!(
            header.hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn genesis_target_matches_pow_limit() {
        let header = genesis_header();
        let expanded = header.target();
        assert!(!expanded.negative);
        assert!(!expanded.overflow);
        assert_eq!(expanded.value, header.bits.expand().value);
    }

    #[test]
    fn encode_round_trips_through_decode() {
        let header = genesis_header();
        let encoded = header.encode();
        assert_eq!(encoded.len(), 80);
        assert_eq!(BlockHeader::decode(&encoded).unwrap(), header);
        assert_eq!(hex::encode(&encoded), GENESIS_HEADER_HEX);
    }

    #[test]
    fn write_matches_encode() {
        let header = genesis_header();
        let mut out = Vec::new();
        header.write(&mut out);
        assert_eq!(out, header.encode().to_vec());
    }

    #[test]
    fn decode_rejects_79_bytes() {
        let bytes = hex::decode(GENESIS_HEADER_HEX).unwrap();
        assert_eq!(
            BlockHeader::decode(&bytes[..79]),
            Err(DecodeError::HeaderLength(79))
        );
    }

    #[test]
    fn decode_rejects_81_bytes() {
        let mut bytes = hex::decode(GENESIS_HEADER_HEX).unwrap();
        bytes.push(0);
        assert_eq!(
            BlockHeader::decode(&bytes),
            Err(DecodeError::HeaderLength(81))
        );
    }

    #[test]
    fn decode_rejects_empty() {
        assert_eq!(BlockHeader::decode(&[]), Err(DecodeError::HeaderLength(0)));
    }

    #[test]
    fn read_propagates_truncated_error_without_length_precheck() {
        // `read` (unlike `decode`) has no upfront length check: it simply reads fields in
        // order and fails with `UnexpectedEnd` as soon as one runs out of input.
        let bytes = hex::decode(GENESIS_HEADER_HEX).unwrap();
        let mut decoder = Decoder::new(&bytes[..40]);
        assert_eq!(
            BlockHeader::read(&mut decoder),
            Err(DecodeError::UnexpectedEnd {
                needed: 32,
                remaining: 4
            })
        );
    }

    #[test]
    fn header_equality_and_hash_are_field_based() {
        let a = genesis_header();
        let mut b = a;
        assert_eq!(a, b);
        b.nonce = a.nonce.wrapping_add(1);
        assert_ne!(a, b);
        assert_ne!(a.hash(), b.hash());
    }
}

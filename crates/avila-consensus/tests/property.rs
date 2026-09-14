//! Property tests (parser/arithmetic fuzzing) for `avila-consensus`.
//!
//! Arbitrary inputs must never panic, must stay bounded by the input's size, and must
//! round-trip — or agree with the rust-bitcoin reference implementation where one exists.
//! These are deterministic-seeded, cheap stand-ins for the full fuzz harness; the pinned
//! Core reference adapter and coverage-guided fuzzing remain separate G1 work items.

// Property assertions intentionally unwrap/expect: a failed invariant should panic.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use avila_consensus::arith::{CompactTarget, ExpandedTarget, Target, U256, Work};
use avila_consensus::block::Block;
use avila_consensus::encode::{self, Decoder};
use avila_consensus::header::BlockHeader;
use avila_consensus::hex;
use avila_consensus::merkle;
use avila_consensus::transaction::Transaction;
use proptest::prelude::*;

/// An arbitrary 256-bit value from raw big-endian bytes.
fn arb_u256() -> impl Strategy<Value = U256> {
    any::<[u8; 32]>().prop_map(U256::from_be_bytes)
}

/// An arbitrary `U256` below `2^128`, for comparisons against `u128`.
fn arb_u256_128() -> impl Strategy<Value = (U256, u128)> {
    any::<u128>().prop_map(|v| {
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&v.to_be_bytes());
        (U256::from_be_bytes(bytes), v)
    })
}

proptest! {
    // ---- Decoding: never panic, never exceed the input bound ----

    #[test]
    fn transaction_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = Transaction::decode(&bytes);
    }

    /// A decoded transaction's canonical re-encoding is stable and never larger than the
    /// input it was decoded from (a superfluous-witness encoding only ever shrinks).
    #[test]
    fn decoded_transactions_reencode_stably_and_bounded(
        bytes in prop::collection::vec(any::<u8>(), 0..4096)
    ) {
        if let Ok(tx) = Transaction::decode(&bytes) {
            let encoded = tx.encode();
            prop_assert!(encoded.len() <= bytes.len());
            let reparsed = Transaction::decode(&encoded).expect("canonical form must decode");
            prop_assert_eq!(reparsed.txid(), tx.txid());
            prop_assert_eq!(reparsed.encode(), encoded);
        }
    }

    /// Decoding a block never panics; a decoded block re-encodes to a stable canonical
    /// form no larger than its input.
    #[test]
    fn block_decode_reencodes_stably_and_bounded(
        bytes in prop::collection::vec(any::<u8>(), 0..4096)
    ) {
        if let Ok(block) = Block::decode(&bytes) {
            // Merkle computation over the decoded transactions must also be total.
            let _ = block.merkle_root();
            let encoded = block.encode();
            prop_assert!(encoded.len() <= bytes.len());
            let reparsed = Block::decode(&encoded).expect("canonical form must decode");
            prop_assert_eq!(reparsed.encode(), encoded);
        }
    }

    #[test]
    fn header_decode_encode_roundtrips(bytes in any::<[u8; BlockHeader::SIZE]>()) {
        let header = BlockHeader::decode(&bytes).expect("any 80 bytes form a header");
        prop_assert_eq!(header.encode(), bytes);
    }

    #[test]
    fn header_hash_matches_rust_bitcoin(bytes in any::<[u8; BlockHeader::SIZE]>()) {
        use bitcoin::consensus::Decodable;
        use bitcoin::hashes::Hash as _;
        let header = BlockHeader::decode(&bytes).unwrap();
        let mut slice: &[u8] = &bytes;
        let theirs = bitcoin::blockdata::block::Header::consensus_decode(&mut slice).unwrap();
        prop_assert_eq!(
            header.hash().to_bytes(),
            theirs.block_hash().to_byte_array()
        );
    }

    // ---- CompactSize ----

    /// Encoding is canonical, round-trips, and is byte-identical to rust-bitcoin's `VarInt`
    /// for every value this crate accepts.
    #[test]
    fn compact_size_roundtrip_matches_rust_bitcoin(value in 0u64..=encode::MAX_SIZE) {
        use bitcoin::consensus::Encodable;
        let mut ours = Vec::new();
        encode::write_compact_size(&mut ours, value);
        let mut theirs = Vec::new();
        bitcoin::consensus::encode::VarInt(value)
            .consensus_encode(&mut theirs)
            .unwrap();
        prop_assert_eq!(&ours, &theirs);
        let mut decoder = Decoder::new(&ours);
        prop_assert_eq!(decoder.read_compact_size().unwrap(), value);
    }

    /// Decode agreement: identical results within `MAX_SIZE`; rust-bitcoin accepts larger
    /// values that this crate deliberately rejects with `CompactSizeTooLarge`.
    #[test]
    fn compact_size_decode_agrees_with_rust_bitcoin(
        bytes in prop::collection::vec(any::<u8>(), 0..9)
    ) {
        use bitcoin::consensus::Decodable;
        let ours = {
            let mut decoder = Decoder::new(&bytes);
            decoder.read_compact_size()
        };
        let mut slice: &[u8] = &bytes;
        let theirs = bitcoin::consensus::encode::VarInt::consensus_decode(&mut slice);
        match (ours, theirs) {
            (Ok(a), Ok(b)) if b.0 <= encode::MAX_SIZE => prop_assert_eq!(a, b.0),
            (Ok(_), Ok(b)) => panic!("accepted {} but reference decoded {}", 0u64, b.0),
            (Err(encode::DecodeError::CompactSizeTooLarge(v)), Ok(b)) => {
                prop_assert!(v > encode::MAX_SIZE && b.0 == v)
            }
            (Err(_), Ok(b)) if b.0 > encode::MAX_SIZE => {}
            (Err(_), Ok(b)) => panic!("rejected but reference decoded {}", b.0),
            (Ok(_), Err(_)) => panic!("accepted where reference rejected"),
            (Err(_), Err(_)) => {}
        }
    }

    /// Canonicality: whenever a CompactSize read succeeds, re-encoding the value must
    /// reproduce exactly the bytes consumed — non-minimal encodings are rejected.
    #[test]
    fn compact_size_decode_is_canonical(bytes in prop::collection::vec(any::<u8>(), 0..9)) {
        let mut decoder = Decoder::new(&bytes);
        if let Ok(value) = decoder.read_compact_size() {
            let mut reencoded = Vec::new();
            encode::write_compact_size(&mut reencoded, value);
            prop_assert_eq!(&reencoded[..], &bytes[..decoder.position()]);
        }
    }

    // ---- U256 arithmetic ----

    #[test]
    fn u256_be_bytes_roundtrip(v in arb_u256()) {
        prop_assert_eq!(U256::from_be_bytes(v.to_be_bytes()), v);
    }

    #[test]
    fn u256_ordering_matches_u128((a, av) in arb_u256_128(), (b, bv) in arb_u256_128()) {
        prop_assert_eq!(a.cmp(&b), av.cmp(&bv));
        prop_assert_eq!(a < b, av < bv);
    }

    /// Addition of two sub-2^128 values can overflow `u128` but always fits `U256`; compare
    /// against the full 256-bit expected sum. Subtraction stays inside the range, so the
    /// `u128` reference applies directly.
    #[test]
    fn u256_add_sub_match_u128((a, av) in arb_u256_128(), (b, bv) in arb_u256_128()) {
        let (lo, carry) = av.overflowing_add(bv);
        let mut expected = [0u8; 32];
        expected[16..].copy_from_slice(&lo.to_be_bytes());
        expected[15] = u8::from(carry); // carry occupies bit 128
        prop_assert_eq!(
            a.checked_add(b).map(|s| s.to_be_bytes()),
            Some(expected)
        );
        prop_assert_eq!(
            a.checked_sub(b).map(|s| s.to_be_bytes()),
            av.checked_sub(bv).map(|s| {
                let mut bytes = [0u8; 32];
                bytes[16..].copy_from_slice(&s.to_be_bytes());
                bytes
            })
        );
    }

    /// `q * d + r == v` whenever the product cannot wrap (v < 2^128, d < 2^64 nonzero).
    #[test]
    fn u256_div_rem_rebuilds_dividend((v, _vv) in arb_u256_128(), d in 1u64..) {
        let (q, r) = v.div_rem(U256::from_u64(d)).expect("nonzero divisor");
        prop_assert!(r < U256::from_u64(d));
        prop_assert_eq!(q.wrapping_mul_u64(d).wrapping_add(r), v);
    }

    #[test]
    fn u256_shift_roundtrips_when_bits_fit(v in arb_u256(), s in 0u32..256) {
        // Shifting left then right recovers v iff v's top s bits were clear.
        let dropped = v.shr(256u32.saturating_sub(s).min(256));
        let dropped_nonzero = s < 256 && !dropped.is_zero();
        prop_assert_eq!(v.shl(s).shr(s) == v, !dropped_nonzero);
        // Right-shift then left-shift drops exactly the low s bits.
        prop_assert_eq!(v.shr(s).shl(s).shr(s), v.shr(s));
    }

    // ---- Targets and work ----

    /// `expand` agrees with rust-bitcoin's `Target::from_compact` on the raw value for
    /// encodings with a clear sign bit. rust-bitcoin does not model Core's sign/overflow
    /// flags — and for `size <= 3` it diverges from Core outright: it keeps the sign bit
    /// in the shifted mantissa (folding it into the value, or tripping its own
    /// `mant > 0x7fffff` reject at `size == 3`), while Core (and this crate) mask it out
    /// with `0x7fffff` before shifting. With the sign bit clear both mask
    /// identically, so the values must match exactly.
    #[test]
    fn compact_expand_matches_rust_bitcoin(bits in any::<u32>()) {
        let ours = CompactTarget(bits).expand();
        let theirs = bitcoin::pow::Target::from_compact(
            bitcoin::pow::CompactTarget::from_consensus(bits),
        );
        if bits & 0x0080_0000 == 0 && !ours.overflow {
            prop_assert_eq!(ours.value.to_be_bytes(), theirs.to_be_bytes());
        }
    }

    /// Canonical compact encoding (`GetCompact`) agrees with rust-bitcoin's
    /// `to_compact_lossy` on arbitrary 256-bit targets.
    #[test]
    fn to_compact_matches_rust_bitcoin(v in arb_u256()) {
        let ours = Target(v).to_compact();
        let theirs = bitcoin::pow::Target::from_be_bytes(v.to_be_bytes()).to_compact_lossy();
        prop_assert_eq!(ours.0, theirs.to_consensus());
    }

    /// Work is antitone in the target: a strictly smaller sane target means at least as
    /// much work (`GetBitsProof` = `2^256 / (target + 1)` is non-increasing in target).
    #[test]
    fn work_is_antitone_in_target(a in any::<u32>(), b in any::<u32>()) {
        let (ea, eb) = (CompactTarget(a).expand(), CompactTarget(b).expand());
        let sane =
            |e: &ExpandedTarget| !e.negative && !e.overflow && !e.value.is_zero();
        if sane(&ea) && sane(&eb) && ea.value <= eb.value {
            prop_assert!(Work::from_compact(CompactTarget(a)) >= Work::from_compact(CompactTarget(b)));
        }
    }

    // ---- Merkle root (CVE-2012-2459 aware) ----

    /// The computed root agrees with rust-bitcoin's `merkle_tree::calculate_root` on every
    /// leaf set; the mutation flag changes acceptance, never the root value.
    #[test]
    fn merkle_root_matches_rust_bitcoin(
        leaves in prop::collection::vec(any::<[u8; 32]>(), 1..65)
    ) {
        use bitcoin::hashes::Hash as _;
        let (ours, _mutated) = merkle::merkle_root(&leaves);
        let theirs = bitcoin::merkle_tree::calculate_root(
            leaves
                .iter()
                .copied()
                .map(bitcoin::TxMerkleNode::from_byte_array),
        )
        .expect("non-empty leaf set");
        prop_assert_eq!(ours, theirs.to_byte_array());
    }

    // ---- Hex ----

    #[test]
    fn hex_encode_decode_roundtrips(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        prop_assert_eq!(hex::decode(&hex::encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn hex_decode_never_panics(text in any::<String>()) {
        let _ = hex::decode(&text);
    }
}

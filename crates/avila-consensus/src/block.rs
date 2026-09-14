//! Blocks: a header plus the list of transactions it commits to, with BIP141 witness commitment
//! helpers.
//!
//! Matches Bitcoin Core's `CBlock` (`primitives/block.h`, which serializes as its base
//! `CBlockHeader` followed by `vtx`) and the block-size/weight limits and witness-commitment
//! logic of `consensus/consensus.h` and `consensus/validation.h`.

use crate::encode::{DecodeError, Decoder, compact_size_len, write_compact_size};
use crate::hash::{BlockHash, MerkleRoot, Txid, sha256d};
use crate::header::BlockHeader;
use crate::merkle;
use crate::transaction::Transaction;

/// Core `consensus/consensus.h`'s `MAX_BLOCK_SERIALIZED_SIZE`: the largest allowed serialized
/// size of a block, in bytes (a buffer-size limit, not itself a proof-of-work or fee rule).
pub const MAX_BLOCK_SERIALIZED_SIZE: usize = 4_000_000;

/// Core `consensus/consensus.h`'s `MAX_BLOCK_WEIGHT`: the largest allowed block weight (BIP141).
pub const MAX_BLOCK_WEIGHT: usize = 4_000_000;

/// Core `consensus/consensus.h`'s `WITNESS_SCALE_FACTOR`: the factor by which non-witness bytes
/// count more than witness bytes when computing a block or transaction's weight (BIP141).
pub const WITNESS_SCALE_FACTOR: usize = 4;

/// The 6 fixed header bytes (`OP_RETURN`, push length, then a 4-byte magic) that identify a
/// BIP141 witness commitment output: `6a 24 aa 21 a9 ed`.
const WITNESS_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// Core `consensus/validation.h`'s `MINIMUM_WITNESS_COMMITMENT`: the minimum `scriptPubKey`
/// length (the 6-byte header plus a 32-byte commitment hash) for an output to be considered a
/// witness commitment.
const MINIMUM_WITNESS_COMMITMENT: usize = 38;

/// A Bitcoin block: a header and the transactions it commits to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    /// The block header.
    pub header: BlockHeader,
    /// The block's transactions, in the order they were serialized. By convention (though not
    /// checked by this module) the first is the coinbase transaction.
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Decodes a block from exactly `bytes`, requiring the whole input to be consumed.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::InputTooLarge`] if `bytes` is longer than
    /// [`MAX_BLOCK_SERIALIZED_SIZE`] (checked before any decoding is attempted), any error
    /// [`BlockHeader::read`] or [`Transaction::read`] can produce, or
    /// [`DecodeError::TrailingBytes`] if bytes remain after an otherwise-successful decode.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_BLOCK_SERIALIZED_SIZE {
            return Err(DecodeError::InputTooLarge {
                len: bytes.len(),
                limit: MAX_BLOCK_SERIALIZED_SIZE,
            });
        }
        let mut decoder = Decoder::new(bytes);
        let block = Self::read(&mut decoder)?;
        decoder.finish()?;
        Ok(block)
    }

    /// Reads a block from `decoder`: a header followed by a `CompactSize`-prefixed vector of
    /// transactions (each in BIP144 format when it carries witness data).
    ///
    /// # Errors
    ///
    /// Propagates any error from [`BlockHeader::read`], [`Decoder::read_compact_size`], or
    /// [`Transaction::read`].
    pub fn read(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let header = BlockHeader::read(decoder)?;
        let count = decoder.read_compact_size()?;
        // `Transaction::MIN_SERIALIZED_SIZE` is a wire-size minimum, but a decoded `Transaction`
        // also owns two heap-allocating `Vec`s (`inputs`, `outputs`), so its true in-memory size
        // can exceed that minimum. Reserve by whichever is larger so this eager
        // `Vec::with_capacity` can never allocate more bytes than the remaining input could
        // actually justify (see the identical reasoning in `transaction::Transaction::read_vin`).
        let reserve = Transaction::MIN_SERIALIZED_SIZE.max(std::mem::size_of::<Transaction>());
        let mut transactions = Vec::with_capacity(decoder.bounded_capacity(count, reserve));
        for _ in 0..count {
            transactions.push(Transaction::read(decoder)?);
        }
        Ok(Block {
            header,
            transactions,
        })
    }

    /// Serializes this block, with witness data included where present.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.size_with_witness());
        self.header.write(&mut out);
        write_compact_size(&mut out, self.transactions.len() as u64);
        for tx in &self.transactions {
            tx.write_with_witness(&mut out);
        }
        out
    }

    /// Computes the serialized size of the block's legacy (non-witness) form, without
    /// allocating.
    #[must_use]
    pub fn size_without_witness(&self) -> usize {
        let mut size = BlockHeader::SIZE + compact_size_len(self.transactions.len() as u64);
        for tx in &self.transactions {
            size += tx.size_without_witness();
        }
        size
    }

    /// Computes the serialized size of the block including witness data, without allocating.
    #[must_use]
    pub fn size_with_witness(&self) -> usize {
        let mut size = BlockHeader::SIZE + compact_size_len(self.transactions.len() as u64);
        for tx in &self.transactions {
            size += tx.size_with_witness();
        }
        size
    }

    /// Computes this block's weight: `3 * size_without_witness + size_with_witness` (BIP141).
    #[must_use]
    pub fn weight(&self) -> usize {
        3 * self.size_without_witness() + self.size_with_witness()
    }

    /// Computes this block's hash: its header's hash.
    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        self.header.hash()
    }

    /// Computes the transaction id of every transaction in the block, in order.
    #[must_use]
    pub fn txids(&self) -> Vec<Txid> {
        self.transactions.iter().map(Transaction::txid).collect()
    }

    /// Computes the merkle root of this block's transaction ids, and whether the computation
    /// detected a CVE-2012-2459 mutation (see [`crate::merkle::merkle_root`]). A block with
    /// `mutated == true` must be treated as invalid regardless of whether the root matches
    /// [`BlockHeader::merkle_root`].
    #[must_use]
    pub fn merkle_root(&self) -> (MerkleRoot, bool) {
        let leaves: Vec<[u8; 32]> = self
            .transactions
            .iter()
            .map(|tx| tx.txid().to_bytes())
            .collect();
        let (root, mutated) = merkle::merkle_root(&leaves);
        (MerkleRoot::from_bytes(root), mutated)
    }

    /// Computes this block's witness merkle root (BIP141): the merkle root of witness ids, with
    /// the coinbase transaction's leaf replaced by the all-zero hash (Core's
    /// `BlockWitnessMerkleRoot`).
    #[must_use]
    pub fn witness_merkle_root(&self) -> MerkleRoot {
        // Core unconditionally emplaces a zero leaf for "the coinbase's witness hash", then
        // appends every other transaction's witness id starting at index 1 -- even when the
        // block has no transactions at all, which still yields a single zero leaf.
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(self.transactions.len().max(1));
        leaves.push([0u8; 32]);
        for tx in self.transactions.iter().skip(1) {
            leaves.push(tx.wtxid().to_bytes());
        }
        let (root, _mutated) = merkle::merkle_root(&leaves);
        MerkleRoot::from_bytes(root)
    }

    /// Finds the position of the witness commitment output in the coinbase transaction (BIP141):
    /// the *last* output of the first transaction whose `scriptPubKey` is at least
    /// `MINIMUM_WITNESS_COMMITMENT` (38) bytes and begins with `6a 24 aa 21 a9 ed`. Returns
    /// `None` if the block has no transactions or no output matches (Core's
    /// `GetWitnessCommitmentIndex`).
    #[must_use]
    pub fn witness_commitment_output(&self) -> Option<usize> {
        let coinbase = self.transactions.first()?;
        let mut found = None;
        for (index, output) in coinbase.outputs.iter().enumerate() {
            let script = output.script_pubkey.as_bytes();
            if script.len() >= MINIMUM_WITNESS_COMMITMENT
                && script.starts_with(&WITNESS_COMMITMENT_HEADER)
            {
                found = Some(index);
            }
        }
        found
    }

    /// Computes the witness commitment hash BIP141 expects to be embedded in the coinbase, from
    /// the block's actual transactions: `sha256d(witness_merkle_root || witness_reserved_value)`,
    /// where the reserved value is the coinbase's first input's sole witness stack item (which
    /// must be exactly 32 bytes). Returns `None` if the block has no transactions, the coinbase
    /// has no inputs, its first input's witness stack does not contain *exactly one* item, or
    /// that item is not exactly 32 bytes -- matching Core's
    /// `witness_stack.size() != 1 || witness_stack[0].size() != 32` check in
    /// `CheckWitnessMalleation` (`validation.cpp`) exactly: a stack with two or more items is
    /// rejected regardless of what its first item contains.
    #[must_use]
    pub fn expected_witness_commitment(&self) -> Option<[u8; 32]> {
        let coinbase = self.transactions.first()?;
        let first_input = coinbase.inputs.first()?;
        if first_input.witness.len() != 1 {
            return None;
        }
        let reserved_value = first_input.witness.items().first()?;
        if reserved_value.len() != 32 {
            return None;
        }
        let root = self.witness_merkle_root();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(root.as_bytes());
        buf[32..].copy_from_slice(reserved_value);
        Some(sha256d(&buf))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::transaction::{OutPoint, Script, TxIn, Witness};

    const MAINNET_BLOCK_000000: &[u8] =
        include_bytes!("../../../fixtures/mainnet-block-000000.bin");
    const MAINNET_BLOCK_000001: &[u8] =
        include_bytes!("../../../fixtures/mainnet-block-000001.bin");
    const MAINNET_BLOCK_000170: &[u8] =
        include_bytes!("../../../fixtures/mainnet-block-000170.bin");
    const MAINNET_BLOCK_100000: &[u8] =
        include_bytes!("../../../fixtures/mainnet-block-100000.bin");
    const MAINNET_BLOCK_SEGWIT_SMALL: &[u8] =
        include_bytes!("../../../fixtures/mainnet-block-segwit-small.bin");
    const MAINNET_BLOCK_TAPROOT_ERA_SMALL: &[u8] =
        include_bytes!("../../../fixtures/mainnet-block-taproot-era-small.bin");
    const TESTNET4_BLOCK_000000: &[u8] =
        include_bytes!("../../../fixtures/testnet4-block-000000.bin");
    const SIGNET_BLOCK_000000: &[u8] = include_bytes!("../../../fixtures/signet-block-000000.bin");
    const SIGNET_BLOCK_000001: &[u8] = include_bytes!("../../../fixtures/signet-block-000001.bin");

    /// One fixture's manifest facts (see `fixtures/manifest.json`), copied as literals per the
    /// crate specification (no JSON parsing at test time).
    struct Fixture {
        bytes: &'static [u8],
        hash: &'static str,
        tx_count: usize,
        size: usize,
        weight: usize,
    }

    const FIXTURES: &[Fixture] = &[
        Fixture {
            bytes: MAINNET_BLOCK_000000,
            hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            tx_count: 1,
            size: 285,
            weight: 1140,
        },
        Fixture {
            bytes: MAINNET_BLOCK_000001,
            hash: "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
            tx_count: 1,
            size: 215,
            weight: 860,
        },
        Fixture {
            bytes: MAINNET_BLOCK_000170,
            hash: "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee",
            tx_count: 2,
            size: 490,
            weight: 1960,
        },
        Fixture {
            bytes: MAINNET_BLOCK_100000,
            hash: "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506",
            tx_count: 4,
            size: 957,
            weight: 3828,
        },
        Fixture {
            bytes: MAINNET_BLOCK_SEGWIT_SMALL,
            hash: "00000000000000000136ce1ea2813e3980c69ba6d1030e55910730edde2e43ea",
            tx_count: 31,
            size: 9246,
            weight: 36876,
        },
        Fixture {
            bytes: MAINNET_BLOCK_TAPROOT_ERA_SMALL,
            hash: "000000000000000000093c20b1a0cb944a26b22de731aa1be7cc6aa941d5122c",
            tx_count: 15,
            size: 9183,
            weight: 24576,
        },
        Fixture {
            bytes: TESTNET4_BLOCK_000000,
            hash: "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            tx_count: 1,
            size: 261,
            weight: 1044,
        },
        Fixture {
            bytes: SIGNET_BLOCK_000000,
            hash: "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            tx_count: 1,
            size: 285,
            weight: 1140,
        },
        Fixture {
            bytes: SIGNET_BLOCK_000001,
            hash: "00000086d6b2636cb2a392d45edc4ec544a10024d30141c9adf4bfd9de533b53",
            tx_count: 1,
            size: 329,
            weight: 1208,
        },
    ];

    #[test]
    fn every_fixture_decodes_and_matches_manifest_facts() {
        for fixture in FIXTURES {
            let block = Block::decode(fixture.bytes)
                .unwrap_or_else(|e| panic!("{} failed to decode: {e}", fixture.hash));
            assert_eq!(
                block.block_hash().to_string(),
                fixture.hash,
                "block_hash mismatch for {}",
                fixture.hash
            );
            assert_eq!(
                block.transactions.len(),
                fixture.tx_count,
                "tx_count mismatch for {}",
                fixture.hash
            );
            assert_eq!(
                block.size_with_witness(),
                fixture.size,
                "size mismatch for {}",
                fixture.hash
            );
            assert_eq!(
                block.weight(),
                fixture.weight,
                "weight mismatch for {}",
                fixture.hash
            );
            let (root, mutated) = block.merkle_root();
            assert!(!mutated, "unexpected mutation for {}", fixture.hash);
            assert_eq!(
                root, block.header.merkle_root,
                "merkle root mismatch for {}",
                fixture.hash
            );
            assert_eq!(
                block.encode(),
                fixture.bytes,
                "round-trip encoding mismatch for {}",
                fixture.hash
            );
        }
    }

    /// Asserts that `fixture`'s coinbase carries a witness commitment output whose embedded
    /// 32-byte hash (offset 6..38 of its `scriptPubKey`) equals
    /// [`Block::expected_witness_commitment`].
    fn assert_witness_commitment_matches(block: &Block) {
        let commit_index = block
            .witness_commitment_output()
            .expect("coinbase must carry a witness commitment output");
        let script = block.transactions[0].outputs[commit_index]
            .script_pubkey
            .as_bytes();
        assert!(script.len() >= 38);
        let embedded = &script[6..38];
        let expected = block
            .expected_witness_commitment()
            .expect("witness commitment must be computable");
        assert_eq!(embedded, expected);
    }

    #[test]
    fn taproot_era_fixture_has_a_non_coinbase_segwit_spend_and_valid_commitment() {
        // Unlike `mainnet-block-segwit-small` (see the note on the next test), this block
        // genuinely contains non-coinbase segwit spends: several inputs beyond the coinbase
        // carry non-empty witness stacks, so their `txid` differs from their `wtxid`.
        let block = Block::decode(MAINNET_BLOCK_TAPROOT_ERA_SMALL).unwrap();
        let has_segwit_spend = block.transactions[1..]
            .iter()
            .any(|tx| tx.txid().as_bytes() != tx.wtxid().as_bytes());
        assert!(
            has_segwit_spend,
            "expected at least one non-coinbase segwit spend"
        );
        assert_witness_commitment_matches(&block);
    }

    #[test]
    fn segwit_small_fixture_has_valid_commitment_from_coinbase_witness_alone() {
        // `mainnet-block-segwit-small` (height 482229, only 405 blocks after segwit's height
        // 481824 activation) was selected by the fixture generator's `weight < 4 * size` proxy
        // for "carries witness data", but empirically its *only* witness data is the coinbase's
        // own mandatory 32-byte reserved-value nonce (added by every post-activation block's
        // witness commitment, `GenerateCoinbaseCommitment` in `validation.cpp`, regardless of
        // whether any other transaction actually spends via segwit) -- none of its 30
        // non-coinbase transactions carry a witness. This is a real property of that historical
        // block, not a decoder bug: see this crate's implementation report for how it was
        // confirmed. The commitment computation is exercised here instead.
        let block = Block::decode(MAINNET_BLOCK_SEGWIT_SMALL).unwrap();
        assert!(block.transactions[0].has_witness());
        assert!(
            block.transactions[1..]
                .iter()
                .all(|tx| tx.txid().as_bytes() == tx.wtxid().as_bytes()),
            "expected no non-coinbase segwit spends in this specific fixture"
        );
        assert_witness_commitment_matches(&block);
    }

    #[test]
    fn signet_block_one_has_valid_commitment_from_coinbase_witness_alone() {
        // Signet activates segwit from height 1 (see `params.rs`'s table), so this single-
        // transaction block (just a coinbase, no other transactions to spend via segwit) still
        // carries a full witness commitment, exactly like the segwit-small case above.
        let block = Block::decode(SIGNET_BLOCK_000001).unwrap();
        assert_eq!(block.transactions.len(), 1);
        assert!(block.transactions[0].has_witness());
        assert_witness_commitment_matches(&block);
    }

    #[test]
    fn pre_segwit_fixtures_have_no_witness_commitment() {
        // Every fixture except the three exercised above predates segwit activation on its
        // network (or, for signet genesis, predates height 1): none has a witness commitment.
        const HAS_COMMITMENT: [&str; 3] = [
            "00000000000000000136ce1ea2813e3980c69ba6d1030e55910730edde2e43ea", // segwit-small
            "000000000000000000093c20b1a0cb944a26b22de731aa1be7cc6aa941d5122c", // taproot-era-small
            "00000086d6b2636cb2a392d45edc4ec544a10024d30141c9adf4bfd9de533b53", // signet height 1
        ];
        for fixture in FIXTURES {
            if HAS_COMMITMENT.contains(&fixture.hash) {
                continue;
            }
            let block = Block::decode(fixture.bytes).unwrap();
            assert_eq!(block.witness_commitment_output(), None, "{}", fixture.hash);
            assert_eq!(
                block.expected_witness_commitment(),
                None,
                "{}",
                fixture.hash
            );
        }
    }

    /// Builds a minimal coinbase-shaped transaction whose sole input carries the given witness
    /// stack, for exercising `expected_witness_commitment`'s witness-stack checks in isolation
    /// (outputs are irrelevant to that function, so left empty).
    fn coinbase_with_witness_items(items: Vec<Vec<u8>>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::default(),
                sequence: 0xffff_ffff,
                witness: Witness::new(items),
            }],
            outputs: vec![],
            lock_time: 0,
        }
    }

    #[test]
    fn expected_witness_commitment_none_when_witness_stack_has_extra_item() {
        // Core's `CheckWitnessMalleation` (`validation.cpp`) rejects a coinbase whose first
        // input's witness stack has anything other than exactly one item, even when the first
        // item is itself a well-formed 32-byte reserved value:
        // `witness_stack.size() != 1 || witness_stack[0].size() != 32`. A 2-item stack whose
        // first item happens to be 32 bytes must not be mistaken for a well-formed commitment.
        let header = Block::decode(MAINNET_BLOCK_000000).unwrap().header;
        let block = Block {
            header,
            transactions: vec![coinbase_with_witness_items(vec![vec![0u8; 32], vec![0xaa]])],
        };
        assert_eq!(block.expected_witness_commitment(), None);
    }

    #[test]
    fn expected_witness_commitment_none_when_reserved_value_wrong_length() {
        // Regression coverage for the `reserved_value.len() != 32` branch specifically: every
        // other test either short-circuits earlier (no transactions/inputs/witness items) or
        // uses real fixtures whose reserved value is always exactly 32 bytes, so a regression
        // flipping or off-by-oneing this comparison would previously have gone uncaught.
        let header = Block::decode(MAINNET_BLOCK_000000).unwrap().header;
        let block = Block {
            header,
            transactions: vec![coinbase_with_witness_items(vec![vec![0u8; 31]])],
        };
        assert_eq!(block.expected_witness_commitment(), None);
    }

    #[test]
    fn transaction_vector_reservation_never_implies_more_bytes_than_remain() {
        // Regression test: `Block::read` used to reserve its transaction vector's capacity using
        // only `Transaction::MIN_SERIALIZED_SIZE` (10 bytes), the smallest possible *wire* size
        // of a transaction. A decoded `Transaction` also owns two heap-allocating `Vec`s
        // (`inputs`, `outputs`), so its true in-memory size exceeds that wire minimum.
        //
        // This exercises the real `Block::read` directly (not a re-derived copy of its reserve
        // formula compared against itself): it decodes a declared transaction count, backed by
        // genuine minimal-wire-size (10-byte, empty-vin/flags-0) transactions, chosen large
        // enough that the correct (`size_of`-aware) reserve leaves `Vec::with_capacity` short of
        // the final length -- forcing at least one real reallocation -- while the buggy,
        // wire-minimum-only reserve happens to land on exactly the declared count for this
        // specific input (`remaining` here is exactly `COUNT * Transaction::MIN_SERIALIZED_SIZE`,
        // so `remaining / Transaction::MIN_SERIALIZED_SIZE == COUNT` exactly), needing no
        // reallocation at all. So the final vector's `capacity()` is `> COUNT` after the fix and
        // would be *exactly* `COUNT` if the reserve regressed back to the wire minimum alone.
        //
        // (Verified for these exact constants against Rust's amortized-doubling `Vec` growth:
        // with `size_of::<Transaction>() == 56` on this target, the correct reserve's initial
        // capacity is always strictly below `COUNT` and its post-growth capacity always lands
        // strictly above `COUNT` -- never coincidentally equal to it.)
        const COUNT: usize = 12_345;
        let element_size = std::mem::size_of::<Transaction>();
        assert!(
            element_size > Transaction::MIN_SERIALIZED_SIZE,
            "test premise violated: Transaction's in-memory size must exceed its wire minimum"
        );

        // An arbitrary (all-zero) 80-byte header, followed by `COUNT` minimal transactions: each
        // is exactly `Transaction::MIN_SERIALIZED_SIZE` (10) zero bytes -- a zero version, an
        // empty `vin` (CompactSize 0), a zero `flags` byte (so no `vout` is read; see
        // `Transaction::read`), and a zero lock time.
        let mut bytes = vec![0u8; BlockHeader::SIZE];
        write_compact_size(&mut bytes, COUNT as u64);
        bytes.extend(vec![0u8; COUNT * Transaction::MIN_SERIALIZED_SIZE]);
        let mut decoder = Decoder::new(&bytes);
        let block = Block::read(&mut decoder).unwrap();

        assert_eq!(block.transactions.len(), COUNT);
        assert!(
            block.transactions.capacity() > COUNT,
            "Block::read's returned capacity {} did not exceed COUNT ({COUNT}): its initial \
             reservation was not bounded by size_of::<Transaction>() (a wire-minimum-only \
             reserve would have sized the vector at exactly COUNT, needing no growth here)",
            block.transactions.capacity()
        );
    }

    #[test]
    fn oversized_declared_transaction_count_fails_fast() {
        // A `CompactSize` declaring ~33 million transactions, backed by almost no payload, must
        // fail with `UnexpectedEnd` on the very first transaction, not reserve
        // `Vec::with_capacity` space for tens of millions of `Transaction`s up front.
        let header = Block::decode(MAINNET_BLOCK_000000).unwrap().header;
        let mut bytes = Vec::new();
        header.write(&mut bytes);
        bytes.push(0xfe); // CompactSize u32 prefix
        bytes.extend_from_slice(&0x0200_0000u32.to_le_bytes()); // MAX_SIZE transactions declared
        bytes.extend_from_slice(&[0xaa, 0xbb]); // far too little payload
        let mut decoder = Decoder::new(&bytes);
        let start = std::time::Instant::now();
        let result = Block::read(&mut decoder);
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        assert!(matches!(result, Err(DecodeError::UnexpectedEnd { .. })));
    }

    #[test]
    fn truncated_block_errors() {
        let block = Block::decode(MAINNET_BLOCK_100000).unwrap();
        let bytes = block.encode();
        for len in [0, 1, 40, 79, 80, 81, bytes.len() - 1] {
            assert!(
                Block::decode(&bytes[..len]).is_err(),
                "expected truncation at {len} to error"
            );
        }
    }

    #[test]
    fn trailing_byte_errors() {
        let mut bytes = MAINNET_BLOCK_000000.to_vec();
        bytes.push(0x00);
        assert_eq!(Block::decode(&bytes), Err(DecodeError::TrailingBytes(1)));
    }

    #[test]
    fn oversized_input_rejected_before_decoding() {
        let bytes = vec![0u8; MAX_BLOCK_SERIALIZED_SIZE + 1];
        assert_eq!(
            Block::decode(&bytes),
            Err(DecodeError::InputTooLarge {
                len: MAX_BLOCK_SERIALIZED_SIZE + 1,
                limit: MAX_BLOCK_SERIALIZED_SIZE,
            })
        );
    }

    #[test]
    fn max_size_input_is_not_rejected_by_the_size_check() {
        // Exactly `MAX_BLOCK_SERIALIZED_SIZE` bytes of garbage passes the size check (and then
        // fails decoding for an unrelated reason), confirming the check is a strict `>`.
        let bytes = vec![0u8; MAX_BLOCK_SERIALIZED_SIZE];
        assert_ne!(
            Block::decode(&bytes),
            Err(DecodeError::InputTooLarge {
                len: MAX_BLOCK_SERIALIZED_SIZE,
                limit: MAX_BLOCK_SERIALIZED_SIZE,
            })
        );
    }

    #[test]
    fn empty_block_witness_merkle_root_is_zero() {
        let header = Block::decode(MAINNET_BLOCK_000000).unwrap().header;
        let block = Block {
            header,
            transactions: Vec::new(),
        };
        assert!(block.witness_commitment_output().is_none());
        assert!(block.expected_witness_commitment().is_none());
        assert!(block.witness_merkle_root().is_zero());
        let (root, mutated) = block.merkle_root();
        assert!(root.is_zero());
        assert!(!mutated);
        assert!(block.txids().is_empty());
    }

    #[test]
    fn constants_match_specification() {
        assert_eq!(MAX_BLOCK_SERIALIZED_SIZE, 4_000_000);
        assert_eq!(MAX_BLOCK_WEIGHT, 4_000_000);
        assert_eq!(WITNESS_SCALE_FACTOR, 4);
    }
}

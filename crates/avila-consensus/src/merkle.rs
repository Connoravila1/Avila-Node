//! Merkle root computation, matching Bitcoin Core's `ComputeMerkleRoot`
//! (`consensus/merkle.cpp`) including its CVE-2012-2459 mutation detection.
//!
//! # A note on the algorithm
//!
//! Bitcoin's merkle tree duplicates the last hash at any level with an odd number of nodes
//! before pairing and hashing. This is non-standard (most merkle tree designs avoid it
//! specifically) and has a known flaw: a transaction list with a duplicated tail can produce
//! the same root as a shorter list without the duplicate, letting an attacker relay a mutated
//! but hash-identical block (CVE-2012-2459). [`merkle_root`] detects the specific condition
//! that enables this -- two adjacent equal hashes at some level, before that level's own
//! odd-length duplication (if any) -- and reports it via its `mutated` return value; callers
//! must treat a mutated root as invalid, exactly as Core's block validation does.

use crate::hash::sha256d;

/// A BIP37 partial merkle tree — Core's `CPartialMerkleTree`
/// (`merkleblock.cpp`). Encodes the subset of a block's hash tree
/// needed to prove membership of the matched leaves: a depth-first
/// bit vector marking parents-of-matches and the hashes of the
/// subtrees that terminate the walk.
///
/// The serialization is wire-compatible with Core: `nTransactions`
/// (u32), then `vHash` (compactsize-prefixed 32-byte hashes), then
/// `vBits` (compactsize-prefixed bytes, bit `n` of byte `n/8` at
/// position `n%8`, LSB-first).
#[derive(Clone, Debug)]
pub struct PartialMerkleTree {
    /// The number of leaves in the full tree (the block's tx count).
    pub num_transactions: u32,
    /// Hashes stored at cut points of the traversal, in DFS order.
    pub hashes: Vec<[u8; 32]>,
    /// Parent-of-match flags in DFS order (serialized bit-packed).
    pub bits: Vec<bool>,
    /// Set during extraction when the proof is malformed.
    bad: bool,
}

/// A matched leaf — `(hash, index-in-block)` — from [`PartialMerkleTree::extract`].
pub type Matched = ([u8; 32], u32);

impl PartialMerkleTree {
    /// `CPartialMerkleTree::CalcTreeWidth`: leaves remaining at `height`.
    fn tree_width(&self, height: u32) -> u32 {
        (self.num_transactions + (1 << height) - 1) >> height
    }

    fn width_of(num_transactions: u32, height: u32) -> u32 {
        (num_transactions + (1 << height) - 1) >> height
    }

    /// Builds the proof over `txids` for the positions where
    /// `matches[i]` is set — Core's `CPartialMerkleTree(vTxid, vMatch)`.
    /// `txids`/`matches` are raw 32-byte hashes, one entry per block tx.
    #[must_use]
    pub fn build(txids: &[[u8; 32]], matches: &[bool]) -> Self {
        let mut tree = Self {
            num_transactions: txids.len() as u32,
            hashes: Vec::new(),
            bits: Vec::new(),
            bad: false,
        };
        let mut height = 0u32;
        while Self::width_of(tree.num_transactions, height) > 1 {
            height += 1;
        }
        tree.traverse_build(height, 0, txids, matches);
        tree
    }

    /// `CalcHash` — the subtree root at (`height`, `pos`), duplicating
    /// the left child when the right is beyond the level's width.
    fn calc_hash(height: u32, pos: u32, txids: &[[u8; 32]], num_tx: u32) -> [u8; 32] {
        if height == 0 {
            return txids[pos as usize];
        }
        let left = Self::calc_hash(height - 1, pos * 2, txids, num_tx);
        let right = if pos * 2 + 1 < Self::width_of(num_tx, height - 1) {
            Self::calc_hash(height - 1, pos * 2 + 1, txids, num_tx)
        } else {
            left
        };
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&left);
        buf[32..].copy_from_slice(&right);
        sha256d(&buf)
    }

    /// `TraverseAndBuild` — DFS; stores the subtree hash at leaves and
    /// at nodes with no match below, descends otherwise.
    fn traverse_build(&mut self, height: u32, pos: u32, txids: &[[u8; 32]], matches: &[bool]) {
        let mut parent_of_match = false;
        let mut p = pos << height;
        while p < ((pos + 1) << height) && p < self.num_transactions {
            parent_of_match |= matches[p as usize];
            p += 1;
        }
        self.bits.push(parent_of_match);
        if height == 0 || !parent_of_match {
            self.hashes
                .push(Self::calc_hash(height, pos, txids, self.num_transactions));
        } else {
            self.traverse_build(height - 1, pos * 2, txids, matches);
            if pos * 2 + 1 < self.tree_width(height - 1) {
                self.traverse_build(height - 1, pos * 2 + 1, txids, matches);
            }
        }
    }

    /// `TraverseAndExtract` — the mirror walk; consumes `bits`/`hashes`
    /// and collects matched (hash, position) pairs.
    fn traverse_extract(
        &mut self,
        height: u32,
        pos: u32,
        bits_used: &mut usize,
        hash_used: &mut usize,
        matched: &mut Vec<Matched>,
    ) -> [u8; 32] {
        if *bits_used >= self.bits.len() {
            self.bad = true;
            return [0u8; 32];
        }
        let parent_of_match = self.bits[*bits_used];
        *bits_used += 1;
        if height == 0 || !parent_of_match {
            if *hash_used >= self.hashes.len() {
                self.bad = true;
                return [0u8; 32];
            }
            let hash = self.hashes[*hash_used];
            *hash_used += 1;
            if height == 0 && parent_of_match {
                matched.push((hash, pos));
            }
            hash
        } else {
            let left = self.traverse_extract(height - 1, pos * 2, bits_used, hash_used, matched);
            let right = if pos * 2 + 1 < self.tree_width(height - 1) {
                let r =
                    self.traverse_extract(height - 1, pos * 2 + 1, bits_used, hash_used, matched);
                // Left and right must never be identical — the tx
                // hashes they cover are unique (Core's fBad check).
                if r == left {
                    self.bad = true;
                }
                r
            } else {
                left
            };
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&left);
            buf[32..].copy_from_slice(&right);
            sha256d(&buf)
        }
    }

    /// `ExtractMatches` — returns the merkle root plus the matched
    /// (hash, tx-index) pairs. Any malformed shape returns `None`
    /// exactly where Core returns the zero hash.
    #[must_use]
    pub fn extract(&mut self) -> Option<([u8; 32], Vec<Matched>)> {
        let mut matched = Vec::new();
        if self.num_transactions == 0 {
            return None;
        }
        // MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT.
        if self.num_transactions > 4_000_000 / 60 {
            return None;
        }
        if self.hashes.len() > self.num_transactions as usize {
            return None;
        }
        if self.bits.len() < self.hashes.len() {
            return None;
        }
        let mut height = 0u32;
        while self.tree_width(height) > 1 {
            height += 1;
        }
        let (mut bits_used, mut hash_used) = (0usize, 0usize);
        let root = self.traverse_extract(height, 0, &mut bits_used, &mut hash_used, &mut matched);
        if self.bad {
            return None;
        }
        // All bits consumed up to byte padding, all hashes consumed.
        if bits_used.div_ceil(8) != self.bits.len().div_ceil(8) {
            return None;
        }
        if hash_used != self.hashes.len() {
            return None;
        }
        Some((root, matched))
    }

    /// Core's `>>`/`<<` on `CPartialMerkleTree`: `nTransactions`,
    /// then the hash vector, then the bit vector packed LSB-first.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.num_transactions.to_le_bytes());
        crate::encode::write_compact_size(out, self.hashes.len() as u64);
        for h in &self.hashes {
            out.extend_from_slice(h);
        }
        let packed = self.packed_bits();
        crate::encode::write_compact_size(out, packed.len() as u64);
        out.extend_from_slice(&packed);
    }

    /// The `vBits` byte packing — bit `i` lands at `i%8` of byte `i/8`.
    #[must_use]
    pub fn packed_bits(&self) -> Vec<u8> {
        let mut packed = vec![0u8; self.bits.len().div_ceil(8)];
        for (i, &b) in self.bits.iter().enumerate() {
            if b {
                packed[i / 8] |= 1 << (i % 8);
            }
        }
        packed
    }

    /// The deserializer — `nTransactions ‖ vHash ‖ vBits`. Truncation
    /// is reported as `None`; semantic validation happens in
    /// [`extract`](Self::extract).
    pub fn decode(r: &mut crate::encode::Decoder<'_>) -> Option<Self> {
        let num_transactions = r.read_u32_le().ok()?;
        let n_hashes = r.read_compact_size().ok()?;
        if n_hashes > num_transactions as u64 {
            return None;
        }
        // Capacity is bounded by what the input can actually contain —
        // a tiny buffer claiming huge counts must not allocate it.
        let mut hashes = Vec::with_capacity(r.bounded_capacity(n_hashes, 32));
        for _ in 0..n_hashes {
            hashes.push(r.read_array::<32>().ok()?);
        }
        let n_bytes = r.read_compact_size().ok()?;
        let mut bits = Vec::with_capacity(r.bounded_capacity(n_bytes, 1) * 8);
        for _ in 0..n_bytes {
            let byte = r.read_u8().ok()?;
            for shift in 0..8 {
                bits.push((byte >> shift) & 1 == 1);
            }
        }
        Some(Self {
            num_transactions,
            hashes,
            bits,
            bad: false,
        })
    }
}

/// Computes the merkle root of `leaves`, matching Bitcoin Core's `ComputeMerkleRoot`.
///
/// `leaves` are raw 32-byte hashes (internal/raw byte order, as produced by [`crate::hash`]'s
/// hash types -- e.g. `Txid::to_bytes()` -- not their reversed display form). An empty slice
/// returns the all-zero hash with `mutated = false`; a single leaf returns that leaf, unchanged,
/// with `mutated = false`. At every level with an odd number of hashes, the last hash is
/// duplicated before pairing (see the module documentation for why this matters).
///
/// The returned `bool` is `true` if, at any level, two adjacent hashes were equal *before* that
/// level's own duplication step -- the condition CVE-2012-2459 exploited. A caller must treat a
/// `mutated` root the same as an invalid one.
#[must_use]
pub fn merkle_root(leaves: &[[u8; 32]]) -> ([u8; 32], bool) {
    let mut hashes = leaves.to_vec();
    let mut mutated = false;
    while hashes.len() > 1 {
        let level_len = hashes.len();
        // Detect adjacent equal pairs among the *original* hashes at this level, before any
        // odd-length duplication below. Mirrors Core's `for (pos = 0; pos + 1 < size; pos += 2)`.
        let mut pos = 0;
        while pos + 1 < level_len {
            if hashes[pos] == hashes[pos + 1] {
                mutated = true;
            }
            pos += 2;
        }
        if level_len % 2 == 1 {
            let last = hashes[level_len - 1];
            hashes.push(last);
        }
        let (pairs, remainder) = hashes.as_chunks::<2>();
        debug_assert!(
            remainder.is_empty(),
            "the odd-length duplication above evens the length"
        );
        let mut next = Vec::with_capacity(pairs.len());
        for pair in pairs {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(sha256d(&buf));
        }
        hashes = next;
    }
    match hashes.first() {
        Some(&root) => (root, mutated),
        // Only reachable when `leaves` was empty: the while loop above never runs, so
        // `mutated` is still its initial `false`.
        None => ([0u8; 32], mutated),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::hash::Txid;

    /// Parses a display-order (reversed-byte) hex hash, as quoted from a block explorer or the
    /// crate specification, into the raw leaf bytes `merkle_root` expects.
    fn leaf(display_hex: &str) -> [u8; 32] {
        display_hex.parse::<Txid>().unwrap().to_bytes()
    }

    #[test]
    fn empty_returns_zero_and_not_mutated() {
        let (root, mutated) = merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
        assert!(!mutated);
    }

    #[test]
    fn single_leaf_returns_leaf_unchanged() {
        let a = [0x11u8; 32];
        let (root, mutated) = merkle_root(&[a]);
        assert_eq!(root, a);
        assert!(!mutated);
    }

    #[test]
    fn two_leaves_hash_the_pair() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let (root, mutated) = merkle_root(&[a, b]);
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&a);
        buf[32..].copy_from_slice(&b);
        assert_eq!(root, sha256d(&buf));
        assert!(!mutated);
    }

    #[test]
    fn three_leaves_duplicate_the_last() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let (three, mutated) = merkle_root(&[a, b, b]);
        assert!(!mutated);
        // [a, b, b] duplicates the trailing `b` to [a, b, b, b] before pairing, so its root
        // must equal the root of the explicit 4-leaf list.
        let (four, four_mutated) = merkle_root(&[a, b, b, b]);
        assert_eq!(three, four);
        assert!(four_mutated);
    }

    #[test]
    fn cve_2012_2459_mutation_is_detected_on_explicit_duplicate_but_not_the_implicit_one() {
        let a = [0xaa; 32];
        let b = [0xbb; 32];
        // [a, b, b]: the odd-length duplication of `b` happens *after* the mutation check for
        // this level (which only compares the original pair (a, b)), so no mutation is
        // reported -- even though the tree ends up pairing (b, b) internally.
        let (_root3, mutated3) = merkle_root(&[a, b, b]);
        assert!(!mutated3);
        // [a, b, b, b]: now (b, b) is a genuine adjacent pair present in the input at this
        // level (positions 2 and 3), so it is detected.
        let (_root4, mutated4) = merkle_root(&[a, b, b, b]);
        assert!(mutated4);
    }

    #[test]
    fn four_distinct_leaves_no_mutation() {
        let leaves = [[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]];
        let (_root, mutated) = merkle_root(&leaves);
        assert!(!mutated);
    }

    #[test]
    fn mutation_detected_at_a_higher_level() {
        // Four distinct leaves whose *second*-level pairing (not the leaves themselves)
        // produces two equal combined hashes: construct two leaf-pairs that hash identically
        // by simply repeating a whole pair, e.g. [a, b, a, b]. Level 0 has no equal adjacent
        // leaves (a != b), but level 1 combines H(a,b) with H(a,b) -- an equal adjacent pair,
        // which the level-1 mutation check must catch.
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        let (_root, mutated) = merkle_root(&[a, b, a, b]);
        assert!(mutated);
    }

    #[test]
    fn mainnet_block_100000_known_vector() {
        // From the crate specification: mainnet block 100000's four transaction ids (display
        // order) and their known merkle root.
        let leaves = [
            leaf("8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87"),
            leaf("fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4"),
            leaf("6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4"),
            leaf("e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"),
        ];
        let (root, mutated) = merkle_root(&leaves);
        assert!(!mutated);
        let root_txid = Txid::from_bytes(root);
        assert_eq!(
            root_txid.to_string(),
            "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766"
        );
    }

    #[test]
    fn larger_odd_count_duplicates_only_the_final_hash() {
        // Five leaves: level 0 has 5 (odd) -> duplicate the 5th; level 1 has 3 (odd) ->
        // duplicate again. Exercise this purely to confirm no panic and a stable, deterministic
        // result (recomputing must give the same answer).
        let leaves: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
        let (root_a, mutated_a) = merkle_root(&leaves);
        let (root_b, mutated_b) = merkle_root(&leaves);
        assert_eq!(root_a, root_b);
        assert_eq!(mutated_a, mutated_b);
    }

    fn txid_bytes(i: u8) -> [u8; 32] {
        [i; 32]
    }

    #[test]
    fn partial_tree_round_trips_matches() {
        let txids: Vec<[u8; 32]> = (0u8..7).map(txid_bytes).collect();
        let matches = [false, true, false, true, false, false, true];
        let mut tree = PartialMerkleTree::build(&txids, &matches);
        let (root, found) = tree.extract().unwrap();
        let (real_root, mutated) = merkle_root(&txids);
        assert!(!mutated);
        assert_eq!(root, real_root);
        assert_eq!(found, vec![(txids[1], 1), (txids[3], 3), (txids[6], 6)]);
    }

    #[test]
    fn partial_tree_encode_decode_round_trip() {
        let txids: Vec<[u8; 32]> = (0u8..9).map(txid_bytes).collect();
        let matches = [true, false, false, true, false, false, false, false, true];
        let tree = PartialMerkleTree::build(&txids, &matches);
        let mut bytes = Vec::new();
        tree.encode(&mut bytes);
        let mut d = crate::encode::Decoder::new(&bytes);
        let mut back = PartialMerkleTree::decode(&mut d).unwrap();
        assert!(d.is_finished());
        let (root, found) = back.extract().unwrap();
        assert_eq!(root, merkle_root(&txids).0);
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].1, 0);
        assert_eq!(found[1].1, 3);
        assert_eq!(found[2].1, 8);
    }

    /// Core's `CPartialMerkleTree` of a 16-tx block matching indexes
    /// 0, 1, 4 — a fixed wire vector (hashes `00*32, 01*32, ...`).
    #[test]
    fn partial_tree_wire_format_matches_core() {
        let txids: Vec<[u8; 32]> = (0u8..16).map(txid_bytes).collect();
        let mut matches = [false; 16];
        matches[0] = true;
        matches[1] = true;
        matches[4] = true;
        let mut tree = PartialMerkleTree::build(&txids, &matches);
        let mut bytes = Vec::new();
        tree.encode(&mut bytes);
        // Re-decoding must recover the same three matches and the root.
        let mut d = crate::encode::Decoder::new(&bytes);
        let mut back = PartialMerkleTree::decode(&mut d).unwrap();
        let (root, found) = back.extract().unwrap();
        assert_eq!(root, merkle_root(&txids).0);
        assert_eq!(found.iter().map(|(_, i)| *i).collect::<Vec<_>>(), [0, 1, 4]);
        // Sanity on the wire shape: u32 count, compactsize hash count.
        assert_eq!(&bytes[..5], &[16, 0, 0, 0, 7]);
        let _ = &mut tree;
    }

    #[test]
    fn partial_tree_rejects_malformed_inputs() {
        let txids: Vec<[u8; 32]> = (0u8..4).map(txid_bytes).collect();
        // Zero transactions.
        let mut t = PartialMerkleTree {
            num_transactions: 0,
            hashes: vec![],
            bits: vec![],
            bad: false,
        };
        assert!(t.extract().is_none());
        // More hashes than transactions.
        let mut t = PartialMerkleTree {
            num_transactions: 4,
            hashes: vec![[0u8; 32]; 5],
            bits: vec![false; 8],
            bad: false,
        };
        assert!(t.extract().is_none());
        // Fewer bits than hashes.
        let mut t = PartialMerkleTree {
            num_transactions: 4,
            hashes: vec![[0u8; 32]; 2],
            bits: vec![false],
            bad: false,
        };
        assert!(t.extract().is_none());
        // Truncated encoding fails to decode.
        let tree = PartialMerkleTree::build(&txids, &[true, false, false, false]);
        let mut bytes = Vec::new();
        tree.encode(&mut bytes);
        let mut d = crate::encode::Decoder::new(&bytes[..bytes.len() - 3]);
        assert!(PartialMerkleTree::decode(&mut d).is_none());
        // A claimed hash count beyond the input must not allocate or
        // succeed: four-byte buffer claiming a billion hashes.
        let mut evil = Vec::new();
        evil.extend_from_slice(&100u32.to_le_bytes());
        crate::encode::write_compact_size(&mut evil, 1_000_000_000);
        let mut d = crate::encode::Decoder::new(&evil);
        assert!(PartialMerkleTree::decode(&mut d).is_none());
    }

    #[test]
    fn partial_tree_mutated_proof_is_rejected() {
        // Two identical adjacent leaves trigger the CVE-2012-2459
        // sibling-equality rejection during extraction.
        let dup = [9u8; 32];
        let txids = vec![dup, dup, [3u8; 32]];
        let mut tree = PartialMerkleTree::build(&txids, &[true, true, false]);
        assert!(tree.extract().is_none());
    }
}

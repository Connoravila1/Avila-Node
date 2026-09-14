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
}

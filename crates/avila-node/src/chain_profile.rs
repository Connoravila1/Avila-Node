//! [`ChainProfile`]: cumulative work and time along the best header
//! chain, sampled at difficulty-period boundaries — cheap history for
//! the desktop GUI's work/time charts, refreshed incrementally instead
//! of walking the full header chain every tick.

use avila_consensus::chain::{HeaderNode, HeaderTree};
use avila_consensus::hash::BlockHash;

/// One point on the best header chain.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProfilePoint {
    /// The header's height.
    pub height: u32,
    /// Cumulative chainwork through this header, as f64 (for ratios only).
    pub work: f64,
    /// The header's timestamp.
    pub time: u32,
    hash: BlockHash, // private: drives incremental refresh
}

impl ProfilePoint {
    fn from_node(node: &HeaderNode) -> Self {
        Self {
            height: node.height,
            work: node.chainwork.0.to_f64(),
            time: node.header.time,
            hash: node.hash(),
        }
    }
}

/// Cumulative work and time along the best header chain, sampled at every
/// difficulty-period boundary (heights 0, 2016, 4032, …) plus the tip.
/// Within a mainnet period every block has the same `bits`, so work between
/// samples is exactly linear.
#[derive(Clone, Debug, Default)]
pub struct ChainProfile {
    /// Boundary samples in height order: `samples[i].height == i * PERIOD`.
    pub samples: Vec<ProfilePoint>,
    /// The best header.
    pub tip: Option<ProfilePoint>,
}

impl ChainProfile {
    /// Mainnet's difficulty-adjustment interval — the sampling stride.
    pub const PERIOD: u32 = 2016;

    /// Brings the profile up to date with the tree's best header.
    ///
    /// A no-op if the tip hash hasn't changed since the last call.
    /// Otherwise walks back from the tip via `prev_block_hash`,
    /// (re)writing boundary samples until it reaches one whose cached
    /// hash already matches — nothing below that point changed, so the
    /// walk stops there — then truncates `samples` to just after that
    /// match and appends the fresh samples in height order. The first
    /// call (`samples` empty) walks the whole chain once (about 935k
    /// lookups on mainnet); steady state (tip extended, no reorg)
    /// touches at most [`Self::PERIOD`] headers; a reorg walks back
    /// only as far as the fork point.
    pub fn refresh(&mut self, tree: &HeaderTree) {
        self.refresh_with_period(tree, Self::PERIOD);
    }

    /// [`Self::refresh`], parameterized on the sampling period so tests
    /// can exercise the boundary/match/truncate logic over a small
    /// synthetic chain instead of ~935k mainnet headers.
    fn refresh_with_period(&mut self, tree: &HeaderTree, period: u32) {
        debug_assert!(period > 0, "sampling period must be positive");
        let tip_node = *tree.tip();
        let tip_point = ProfilePoint::from_node(&tip_node);
        if self.tip.is_some_and(|t| t.hash == tip_point.hash) {
            return; // tip unchanged: nothing below it could have changed either.
        }

        // Walk back one header at a time, recording a fresh candidate at
        // every boundary height, until a boundary's hash matches what's
        // already cached (nothing below it changed) or genesis is
        // reached. All mutation of `self.samples` is deferred until
        // after the walk, so every `self.samples.get(idx)` lookup below
        // sees the pre-refresh state.
        let mut fresh_rev: Vec<ProfilePoint> = Vec::new();
        let mut match_index: Option<usize> = None;
        let mut current = tip_node;
        loop {
            if current.height.is_multiple_of(period) {
                let idx = (current.height / period) as usize;
                let point = ProfilePoint::from_node(&current);
                if self.samples.get(idx).is_some_and(|s| s.hash == point.hash) {
                    match_index = Some(idx);
                    break;
                }
                fresh_rev.push(point);
            }
            if current.height == 0 {
                break;
            }
            let Some(parent) = tree.get(&current.header.prev_block_hash) else {
                break; // tree corruption guard — stop with what was found
            };
            current = *parent;
        }

        match match_index {
            Some(idx) => self.samples.truncate(idx + 1),
            None => self.samples.clear(),
        }
        fresh_rev.reverse();
        self.samples.extend(fresh_rev);
        self.tip = Some(tip_point);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use avila_consensus::arith::CompactTarget;
    use avila_consensus::header::BlockHeader;
    use avila_consensus::params::{Network, Params};
    use avila_consensus::pow;

    /// Regtest's own genesis `nBits` — with `no_retargeting` (regtest's
    /// default) every header keeps this value, and its target is wide
    /// enough that a handful of ground nonces reliably satisfies it
    /// (mirrors `avila_p2p::testchain`'s block-building recipe, which
    /// is `pub(crate)` to that crate and so not reachable here).
    const REGTEST_BITS: u32 = 0x207f_ffff;

    /// Mints and inserts a PoW-valid child of `parent`, returning the
    /// inserted node. `nonce_hint` is where nonce-grinding starts: two
    /// calls with the same `parent` (and thus the same deterministic
    /// `time`/`bits`/`merkle_root`) but different, well-separated hints
    /// land on different nonces and so produce genuinely different
    /// sibling headers — needed to build a real fork rather than
    /// deterministically rediscovering the same chain (mirrors
    /// `avila_consensus::chain`'s own private test helpers, which use
    /// this same hint trick for the same reason).
    fn extend_from(
        tree: &mut HeaderTree,
        params: &Params,
        parent: &HeaderNode,
        nonce_hint: u32,
    ) -> HeaderNode {
        let mut header = BlockHeader {
            version: 4,
            prev_block_hash: parent.hash(),
            merkle_root: parent.header.merkle_root,
            time: parent.header.time + 1,
            bits: CompactTarget(REGTEST_BITS),
            nonce: nonce_hint,
        };
        while pow::check_proof_of_work(&header.hash(), header.bits, params).is_err() {
            header.nonce += 1;
        }
        tree.insert(&header, u32::MAX)
            .expect("mined header must satisfy every header rule");
        *tree
            .get(&header.hash())
            .expect("just-inserted header must be indexed")
    }

    /// Extends the tree's current tip by `n` blocks.
    fn grow(tree: &mut HeaderTree, params: &Params, n: u32) {
        for i in 0..n {
            let tip = *tree.tip();
            extend_from(tree, params, &tip, i * 1000);
        }
    }

    #[test]
    fn boundary_samples_and_tip_are_correct() {
        let params = Network::Regtest.params();
        let mut tree = HeaderTree::new(params);
        grow(&mut tree, &params, 10); // heights 0..=10
        let chain = tree.best_chain(); // index == height

        let mut profile = ChainProfile::default();
        profile.refresh_with_period(&tree, 4);

        assert_eq!(profile.samples.len(), 3, "boundaries at heights 0, 4, 8");
        for (i, &h) in [0u32, 4, 8].iter().enumerate() {
            let node = tree
                .get(&chain[h as usize])
                .expect("boundary header must be indexed");
            assert_eq!(profile.samples[i].height, h);
            assert_eq!(profile.samples[i].hash, chain[h as usize]);
            assert_eq!(profile.samples[i].work, node.chainwork.0.to_f64());
            assert_eq!(profile.samples[i].time, node.header.time);
        }
        let tip = profile.tip.expect("tip must be set after a refresh");
        assert_eq!(tip.height, 10);
        assert_eq!(tip.hash, tree.tip_hash());
    }

    #[test]
    fn second_refresh_with_no_change_is_a_noop() {
        let params = Network::Regtest.params();
        let mut tree = HeaderTree::new(params);
        grow(&mut tree, &params, 10);

        let mut profile = ChainProfile::default();
        profile.refresh_with_period(&tree, 4);
        let before_samples = profile.samples.clone();
        let before_tip = profile.tip;

        profile.refresh_with_period(&tree, 4);
        assert_eq!(profile.samples, before_samples);
        assert_eq!(profile.tip, before_tip);
    }

    #[test]
    fn extending_the_chain_only_appends() {
        let params = Network::Regtest.params();
        let mut tree = HeaderTree::new(params);
        grow(&mut tree, &params, 10); // tip height 10, boundaries 0,4,8

        let mut profile = ChainProfile::default();
        profile.refresh_with_period(&tree, 4);
        let before = profile.samples.clone();

        grow(&mut tree, &params, 5); // tip height 15, boundaries 0,4,8,12
        profile.refresh_with_period(&tree, 4);

        assert_eq!(profile.samples.len(), 4);
        assert_eq!(profile.samples[..3], before[..]);
        assert_eq!(profile.samples[3].height, 12);
        assert_eq!(profile.tip.expect("tip set").height, 15);
    }

    #[test]
    fn reorg_rewrites_the_changed_boundaries() {
        let params = Network::Regtest.params();
        let mut tree = HeaderTree::new(params);
        grow(&mut tree, &params, 10); // main chain to height 10

        let mut profile = ChainProfile::default();
        profile.refresh_with_period(&tree, 4);
        let before = profile.samples.clone(); // heights 0, 4, 8

        // Fork below the height-4 boundary with enough extra blocks to
        // overtake the main chain's work (equal per-block work here, so
        // more blocks alone is enough).
        let fork_point = *tree
            .get_ancestor(&tree.tip_hash(), 3)
            .expect("height 3 must exist on the main chain");
        // A nonce-hint range well clear of `grow`'s (0, 1000, 2000, …)
        // so the fork's headers are genuinely different blocks, not a
        // deterministic rediscovery of the main chain's own headers.
        let mut parent = fork_point;
        for i in 0..12 {
            parent = extend_from(&mut tree, &params, &parent, 500_000 + i * 1000);
        }
        assert_eq!(
            tree.tip_hash(),
            parent.hash(),
            "the longer fork must become the best chain"
        );

        profile.refresh_with_period(&tree, 4);

        // Genesis is shared by both branches — untouched.
        assert_eq!(profile.samples[0], before[0]);
        // Heights 4 and 8 sit above the fork point (height 3) — rewritten.
        assert_ne!(profile.samples[1], before[1]);
        assert_ne!(profile.samples[2], before[2]);
        assert_eq!(profile.samples[1].height, 4);
        assert_eq!(profile.samples[2].height, 8);
        // A new boundary at height 12 appears; tip sits at the fork tip (height 15).
        assert_eq!(profile.samples.len(), 4);
        assert_eq!(profile.samples[3].height, 12);
        assert_eq!(profile.tip.expect("tip set").height, 15);
    }
}

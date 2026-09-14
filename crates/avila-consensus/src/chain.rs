//! The in-memory header tree: parent linkage, cumulative work, and best-tip selection.
//!
//! Each accepted header becomes a [`HeaderNode`] carrying the fields Bitcoin Core keeps on
//! `CBlockIndex` (`chain.h`): its parent link, `nHeight`, and `nChainWork`. Acceptance
//! (`HeaderTree::insert`) applies the header-level rules of Core's `AcceptBlockHeader` /
//! `CheckBlockHeader` / `ContextualCheckBlockHeader` (`validation.cpp`): the parent must
//! already be in the tree, `nBits` must equal [`crate::pow::required_bits`], the hash must
//! satisfy [`crate::pow::check_proof_of_work`], the timestamp must pass
//! [`crate::rules::check_block_time`] against the parent chain's median time past, and the
//! header's `nVersion` must meet the buried-deployment floors active at its height (the
//! `bad-version` check, this module's [`ChainError::BadVersion`]).
//!
//! The best tip is the node with strictly the greatest chainwork — a new tip must exceed,
//! not merely match, the current one, so among equal-work candidates the earliest inserted
//! wins. Core's full most-work logic adds sequence-number and insertion-window tie-breaks
//! (`CBlockIndexWorkComparator`, `pindexBestHeader`) that exist to tame concurrency and
//! high-rate P2P header relay; this tree is single-threaded and deterministic instead.
//!
//! Not implemented (documented gaps, not bugs): checkpoint pinning and the DoS-preservation
//! checks around it, minimum-chainwork floors, signet's block-level signature rule (BIP325
//! signs the *block*, not the header — header rules still apply), and the
//! `nMinimumChainWork`/assume-valid DoS guards. These belong to later gates alongside
//! block-level validation.

use std::collections::{HashMap, HashSet};

use thiserror::Error;

use crate::arith::{CompactTarget, Work};
use crate::hash::BlockHash;
use crate::header::BlockHeader;
use crate::params::Params;
use crate::pow::{self, Ancestry, PowError};
use crate::rules::{self, TimeError};

/// A header accepted into a [`HeaderTree`], with its position and accumulated work (Core's
/// `CBlockIndex` fields `nHeight` and `nChainWork`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HeaderNode {
    /// The accepted header.
    pub header: BlockHeader,
    /// Its height: `0` for the genesis, one more than its parent's otherwise.
    pub height: u32,
    /// The total work of the chain ending at this header: the parent's `chainwork` plus
    /// [`Work::from_compact`] of this header's `bits`.
    pub chainwork: Work,
}

impl HeaderNode {
    /// This header's block hash (Core's `CBlockIndex::GetBlockHash`).
    #[must_use]
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }
}

/// The result of a successful [`HeaderTree::insert`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InsertStatus {
    /// The header was not in the tree and has been added at the given height.
    Added {
        /// The new node's height.
        height: u32,
    },
    /// The header was already in the tree (Core's `AcceptBlockHeader` returns the existing
    /// `CBlockIndex` rather than failing). The tree is unchanged.
    AlreadyKnown {
        /// The existing node's height.
        height: u32,
    },
}

/// Reasons [`HeaderTree::insert`] can reject a header.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum ChainError {
    /// The header's `prev_block_hash` is not in the tree — an orphan (Core accepts orphans
    /// from the network layer only in that it defers them; this tree reports them instead
    /// of storing unverifiable headers).
    #[error("parent {0} is not in the tree (orphan header)")]
    UnknownParent(BlockHash),
    /// The header's `nBits` differs from what the retarget schedule requires at its height
    /// (Core's `bad-diffbits` in `ContextualCheckBlockHeader`).
    #[error("nBits {actual} does not match the required {expected}")]
    WrongBits {
        /// The `nBits` the schedule requires.
        expected: CompactTarget,
        /// The `nBits` the header actually carries.
        actual: CompactTarget,
    },
    /// The header failed [`crate::pow::check_proof_of_work`], or the retarget walk could not
    /// complete.
    #[error(transparent)]
    Pow(#[from] PowError),
    /// The header's timestamp violates a contextual time rule.
    #[error(transparent)]
    Time(#[from] TimeError),
    /// The header's `nVersion` is below a buried-deployment floor already active at its
    /// height (Core's `bad-version` in `ContextualCheckBlockHeader`): `nVersion < 2` once
    /// [`crate::params::Params::bip34_height`] is active, `nVersion < 3` once
    /// [`crate::params::Params::bip66_height`] is active, or `nVersion < 4` once
    /// [`crate::params::Params::bip65_height`] is active.
    ///
    /// The `Display` reproduces Core's exact reject reason — `strprintf("bad-version(0x%08x)",
    /// block.nVersion)` — formatting the signed `nVersion` as its 32-bit two's-complement
    /// hex (Rust's `{:x}` on a signed integer already formats the bit pattern, matching
    /// `%08x` on Core's `int32_t`).
    #[error("bad-version(0x{version:08x})")]
    BadVersion {
        /// The header's `nVersion`, as received (interpreted as signed 32-bit).
        version: i32,
    },
    /// The header descends from a block marked failed — its direct parent carries the
    /// failed flag, or the walk from the parent reached a failed ancestor (Core's
    /// `bad-prevblk` / `BLOCK_INVALID_PREV` in `AcceptBlockHeader`: the direct-parent
    /// check runs before `ContextualCheckBlockHeader`, the failed-ancestor walk after).
    #[error("prev block is invalid")]
    InvalidParent,
    /// Accumulating this header's work overflowed 256 bits — unreachable on any real chain
    /// (total attainable work is bounded by the number of headers times per-block maximum,
    /// far below `2^256`), defended anyway.
    #[error("cumulative chainwork overflowed 256 bits")]
    ChainWorkOverflow,
    /// The parent's height is `u32::MAX` — unreachable in practice (the tree would need
    /// over four billion validated headers first), defended so a height can never wrap.
    #[error("header height overflowed u32")]
    HeightOverflow,
}

impl ChainError {
    /// The reject reason Core's `submitblock`/`submitheader` reports for the equivalent
    /// `AcceptBlockHeader` failure (the `reason` field of the RPC response).
    #[must_use]
    pub fn reason(&self) -> std::borrow::Cow<'static, str> {
        match self {
            ChainError::UnknownParent(_) => "prev-blk-not-found".into(),
            ChainError::InvalidParent => "bad-prevblk".into(),
            ChainError::WrongBits { .. } => "bad-diffbits".into(),
            ChainError::Pow(
                PowError::NegativeTarget(_)
                | PowError::OverflowTarget(_)
                | PowError::ZeroTarget(_)
                | PowError::TargetAboveLimit(_)
                | PowError::InsufficientWork { .. },
            ) => "high-hash".into(),
            ChainError::Pow(
                PowError::UnknownAncestor(_) | PowError::DegenerateDifficultyParams,
            ) => "internal".into(),
            ChainError::Time(TimeError::TooOld { .. }) => "time-too-old".into(),
            ChainError::Time(TimeError::Timewarp { .. }) => "time-timewarp-attack".into(),
            ChainError::Time(TimeError::TooNew { .. }) => "time-too-new".into(),
            // `BadVersion`'s `Display` is already Core's exact reject reason.
            ChainError::BadVersion { .. } => self.to_string().into(),
            ChainError::ChainWorkOverflow | ChainError::HeightOverflow => "internal".into(),
        }
    }
}

/// A tree of accepted block headers, seeded with the network's genesis.
///
/// Memory grows linearly with the number of accepted headers (each node is small and fixed
/// size); like Core's `mapBlockIndex` it is unbounded by design — insertion of a header
/// requires full PoW and linkage validation, so growth is work-gated on public networks.
/// Bounding retention (e.g. pruning deep history) is a policy decision for the node layer,
/// not this crate.
pub struct HeaderTree {
    params: Params,
    nodes: HashMap<BlockHash, HeaderNode>,
    tip: BlockHash,
    /// Hashes of nodes carrying Core's `BLOCK_FAILED_MASK` (`BLOCK_FAILED_VALID` for the
    /// block whose own validation failed, `BLOCK_FAILED_CHILD` for descendants marked by
    /// the insertion-time ancestor walk). Children of a failed block are rejected at
    /// [`HeaderTree::insert`] — Core rejects them the same way, at `AcceptBlockHeader`.
    invalid: HashSet<BlockHash>,
}

impl HeaderTree {
    /// Creates a tree containing exactly the network's genesis header at height 0. The
    /// genesis is the anchor, not a validated child: it is inserted unconditionally, as
    /// Core hard-codes `hashGenesisBlock` into the block index at startup.
    #[must_use]
    pub fn new(params: Params) -> Self {
        let genesis = params.genesis_header;
        let hash = genesis.hash();
        let node = HeaderNode {
            header: genesis,
            height: 0,
            chainwork: Work::from_compact(genesis.bits),
        };
        let mut nodes = HashMap::new();
        nodes.insert(hash, node);
        Self {
            params,
            nodes,
            tip: hash,
            invalid: HashSet::new(),
        }
    }

    /// The network parameters this tree validates against.
    #[must_use]
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// The number of headers in the tree (always ≥ 1: the genesis is seeded at creation).
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// `true` if the tree is empty. Never true in practice — see [`HeaderTree::len`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns the node stored under `hash`, if any.
    #[must_use]
    pub fn get(&self, hash: &BlockHash) -> Option<&HeaderNode> {
        self.nodes.get(hash)
    }

    /// `true` if `hash` is a header already in the tree.
    #[must_use]
    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.nodes.contains_key(hash)
    }

    /// The header hash of the current best (most-work) tip.
    #[must_use]
    pub fn tip_hash(&self) -> BlockHash {
        self.tip
    }

    /// The current best tip: the accepted header with the greatest chainwork. Among
    /// equal-work candidates the earliest inserted wins.
    #[must_use]
    pub fn tip(&self) -> &HeaderNode {
        // `tip` is always a key in `nodes` (seeded at construction, only ever assigned a
        // just-inserted key), so this lookup cannot fail.
        let Some(node) = self.nodes.get(&self.tip) else {
            unreachable!("tip hash is always present in the tree");
        };
        node
    }

    /// The median time past at `hash` — Core's `CBlockIndex::GetMedianTimePast` applied to
    /// the node: the median of up to [`rules::MEDIAN_TIME_SPAN`] most recent header times,
    /// newest first. `None` if `hash` is not in the tree.
    #[must_use]
    pub fn median_time_past(&self, hash: &BlockHash) -> Option<u32> {
        let node = self.nodes.get(hash)?;
        let (times, count) = self.ancestor_times(node);
        Some(rules::median_time_past(&times[..count]))
    }

    /// The ancestor of `from` at exactly `height` — Core's `CBlockIndex::GetAncestor`,
    /// implemented as a linear walk (no skip list; callers needing this — BIP30's
    /// BIP34-height probe and BIP68 time-locks — walk distances bounded by coin
    /// maturity, not the whole chain). `None` when `from` is not in the tree or
    /// `height` exceeds `from`'s height.
    #[must_use]
    pub fn get_ancestor(&self, from: &BlockHash, height: u32) -> Option<&HeaderNode> {
        let mut node = self.nodes.get(from)?;
        while node.height > height {
            node = self.nodes.get(&node.header.prev_block_hash)?;
        }
        Some(node)
    }

    /// `true` if `ancestor` is `descendant`'s ancestor-or-self — Core's
    /// `pindexOther->GetAncestor(pindex->nHeight) == pindex` test (when
    /// `ancestor.height > descendant.height`, `GetAncestor` returns null,
    /// which this reports as `false`).
    #[must_use]
    pub fn is_ancestor(&self, ancestor: &HeaderNode, descendant: &HeaderNode) -> bool {
        self.get_ancestor(&descendant.hash(), ancestor.height)
            .is_some_and(|n| n == ancestor)
    }

    /// `GetBlockProofEquivalentTime` (`chain.cpp`): the wall-clock seconds the
    /// chainwork between `from` and `to` would take at `tip`'s difficulty —
    /// `|to.work - from.work| * nPowTargetSpacing / GetBlockProof(tip)`, signed
    /// negative when `to` precedes `from`, saturating at `i64::MAX`. Used by
    /// `ConnectBlock`'s assumevalid "block too recent" guard.
    #[must_use]
    pub fn block_proof_equivalent_time(
        to: &HeaderNode,
        from: &HeaderNode,
        tip: &HeaderNode,
        params: &Params,
    ) -> i64 {
        let (r, sign) = if to.chainwork > from.chainwork {
            (to.chainwork.0.wrapping_sub(from.chainwork.0), 1i64)
        } else {
            (from.chainwork.0.wrapping_sub(to.chainwork.0), -1i64)
        };
        let proof = Work::from_compact(tip.header.bits).0;
        let Some((r, _rem)) = r.wrapping_mul_u64(params.pow_target_spacing).div_rem(proof) else {
            // Zero per-block proof for the tip — unreachable for a real header
            // (zero proof means an invalid nBits, which `insert` rejected);
            // defensive saturation matching the `bits() > 63` arm.
            return sign.saturating_mul(i64::MAX);
        };
        if r.bits() > 63 {
            return sign.saturating_mul(i64::MAX);
        }
        sign.saturating_mul(i64::try_from(r.low_u64()).unwrap_or(i64::MAX))
    }

    /// Marks `hash` failed — Core's `pindex->nStatus |= BLOCK_FAILED_VALID`, set by
    /// `AcceptBlock` on `CheckBlock`/`ContextualCheckBlock` failure and by
    /// `InvalidChainFound` on `ConnectBlock` failure. Once marked, every descendant is
    /// rejected at [`HeaderTree::insert`] (`bad-prevblk`) and a resubmission reports
    /// [`InsertStatus::AlreadyKnown`] while [`HeaderTree::is_failed`] reports `true`
    /// (Core's `duplicate-invalid`).
    pub fn mark_invalid(&mut self, hash: BlockHash) {
        self.invalid.insert(hash);
    }

    /// `true` if `hash` carries the failed flag — either the block whose own validation
    /// failed, or a descendant marked by a previous insertion-time ancestor walk.
    #[must_use]
    pub fn is_failed(&self, hash: &BlockHash) -> bool {
        self.invalid.contains(hash)
    }

    /// Every indexed header sorted by height (ties unordered) — the snapshot's
    /// header set. Height-sort guarantees parents precede their children when
    /// the list is reinserted on restore.
    #[must_use]
    pub fn headers_by_height(&self) -> Vec<BlockHeader> {
        let mut nodes: Vec<&HeaderNode> = self.nodes.values().collect();
        nodes.sort_by_key(|node| node.height);
        nodes.into_iter().map(|node| node.header).collect()
    }

    /// Every hash carrying the failed flag — the snapshot's failed set.
    #[must_use]
    pub fn failed_hashes(&self) -> Vec<BlockHash> {
        self.invalid.iter().copied().collect()
    }

    /// Snapshot restore hook: moves the best tip to `hash` when it is indexed
    /// and its chainwork is at least the current tip's — i.e. it is a maximal
    /// tip. The explicit set preserves "earliest inserted wins" among
    /// equal-work candidates, which a height-sorted reinsert cannot reproduce.
    pub(crate) fn restore_tip(&mut self, hash: BlockHash) -> bool {
        let Some(node) = self.nodes.get(&hash) else {
            return false;
        };
        if node.chainwork < self.tip().chainwork {
            return false;
        }
        self.tip = hash;
        true
    }

    /// Walks the ancestor chain of `cursor` toward genesis. Returns `true` when the walk
    /// reaches a failed block — in which case every node passed on the way is marked
    /// failed, matching `AcceptBlockHeader`'s `invalid_walk` marking of the blocks
    /// between `pindexPrev` and the failed ancestor. `false` when the walk reaches the
    /// tree boundary (genesis) without hitting a failed node.
    pub(crate) fn ancestor_is_invalid(&mut self, mut cursor: BlockHash) -> bool {
        let mut path = Vec::new();
        let hit = loop {
            if self.invalid.contains(&cursor) {
                break true;
            }
            let Some(node) = self.nodes.get(&cursor) else {
                break false;
            };
            path.push(cursor);
            cursor = node.header.prev_block_hash;
        };
        if hit {
            for hash in path {
                self.invalid.insert(hash);
            }
        }
        hit
    }

    /// Validates `header` against the tree and inserts it.
    ///
    /// `now` is the caller's adjusted local time for the future-drift check — an explicit
    /// input, since this crate performs no clock I/O (see
    /// [`rules::check_block_time`]).
    ///
    /// Checks run in Core's `AcceptBlockHeader` / `ContextualCheckBlockHeader` order: the
    /// header is not already known (returns [`InsertStatus::AlreadyKnown`]); its hash
    /// satisfies [`pow::check_proof_of_work`] (`CheckBlockHeader`); its parent is in the
    /// tree; its parent does not carry the failed flag (`bad-prevblk`,
    /// [`ChainError::InvalidParent`]); its `nBits` equals [`pow::required_bits`]
    /// (`bad-diffbits`); its timestamp
    /// passes [`rules::check_block_time`] — median-time-past, then the BIP94 timewarp
    /// floor on `enforce_BIP94` networks at period-start heights, then the future-drift
    /// ceiling; and its `nVersion` meets every buried-deployment floor already active at
    /// its height (`bad-version`, [`ChainError::BadVersion`]); and no ancestor of its
    /// parent carries the failed flag (`bad-prevblk`). On success the node is
    /// stored and the best tip moves to it iff its chainwork strictly exceeds the current
    /// tip's.
    ///
    /// # Errors
    ///
    /// Returns the first failing [`ChainError`]. No header node is added on error; the
    /// failed-ancestor walk behind [`ChainError::InvalidParent`] deliberately marks the
    /// nodes it traverses failed before returning, exactly as `AcceptBlockHeader`'s
    /// `invalid_walk` sets `BLOCK_FAILED_CHILD` on the blocks between the parent and the
    /// failed ancestor.
    pub fn insert(&mut self, header: &BlockHeader, now: u32) -> Result<InsertStatus, ChainError> {
        let hash = header.hash();
        if let Some(existing) = self.nodes.get(&hash) {
            return Ok(InsertStatus::AlreadyKnown {
                height: existing.height,
            });
        }
        pow::check_proof_of_work(&hash, header.bits, &self.params)?;
        let parent = *self
            .nodes
            .get(&header.prev_block_hash)
            .ok_or(ChainError::UnknownParent(header.prev_block_hash))?;
        // `bad-prevblk` (direct parent): `AcceptBlockHeader` rejects before
        // `ContextualCheckBlockHeader` when `pindexPrev` carries `BLOCK_FAILED_MASK`.
        if self.invalid.contains(&header.prev_block_hash) {
            return Err(ChainError::InvalidParent);
        }
        let expected = pow::required_bits(
            parent.height,
            &parent.header,
            header.time,
            &self.params,
            self,
        )?;
        if header.bits != expected {
            return Err(ChainError::WrongBits {
                expected,
                actual: header.bits,
            });
        }
        let (times, count) = self.ancestor_times(&parent);
        // BIP94's timewarp floor applies only on the first block of each difficulty
        // period. `required_bits` above already rejected a zero interval, so the modulo
        // cannot panic.
        let interval = self.params.difficulty_adjustment_interval();
        let new_height = u64::from(parent.height) + 1;
        let timewarp_min = (self.params.enforce_bip94 && new_height.is_multiple_of(interval))
            .then(|| parent.header.time.saturating_sub(rules::MAX_TIMEWARP));
        rules::check_block_time(
            header.time,
            rules::median_time_past(&times[..count]),
            now,
            timewarp_min,
        )?;
        // `bad-version`: Core's ContextualCheckBlockHeader checks this last, after every
        // timestamp rule. `new_height` was already computed above (`parent.height + 1`)
        // for the BIP94 boundary test; reusing it here matches Core's
        // `pindexPrev->nHeight + 1` exactly and cannot overflow (it is a `u64`).
        if (header.version < 2 && new_height >= u64::from(self.params.bip34_height))
            || (header.version < 3 && new_height >= u64::from(self.params.bip66_height))
            || (header.version < 4 && new_height >= u64::from(self.params.bip65_height))
        {
            return Err(ChainError::BadVersion {
                version: header.version,
            });
        }
        // `bad-prevblk` (failed ancestor): `AcceptBlockHeader`'s last gate walks
        // `m_failed_blocks` for an ancestor of `pindexPrev`, marking the blocks between
        // `BLOCK_FAILED_CHILD` as it goes — the ancestor walk here is the same check
        // and leaves the same marks.
        if self.ancestor_is_invalid(header.prev_block_hash) {
            return Err(ChainError::InvalidParent);
        }
        let chainwork = parent
            .chainwork
            .checked_add(Work::from_compact(header.bits))
            .ok_or(ChainError::ChainWorkOverflow)?;
        let node = HeaderNode {
            header: *header,
            height: parent
                .height
                .checked_add(1)
                .ok_or(ChainError::HeightOverflow)?,
            chainwork,
        };
        self.nodes.insert(hash, node);
        if chainwork > self.tip().chainwork {
            self.tip = hash;
        }
        Ok(InsertStatus::Added {
            height: node.height,
        })
    }

    /// Up to `MEDIAN_TIME_SPAN` header times ending at (and including) `node`, newest first,
    /// plus how many were collected — the input [`rules::median_time_past`] expects.
    fn ancestor_times(&self, node: &HeaderNode) -> ([u32; rules::MEDIAN_TIME_SPAN], usize) {
        let mut times = [0u32; rules::MEDIAN_TIME_SPAN];
        let mut current = *node;
        let mut count = 0;
        for slot in &mut times {
            *slot = current.header.time;
            count += 1;
            let Some(parent) = self.nodes.get(&current.header.prev_block_hash) else {
                break;
            };
            current = *parent;
        }
        (times, count)
    }
}

impl Ancestry for HeaderTree {
    fn ancestor(&self, hash: &BlockHash) -> Option<BlockHeader> {
        self.nodes.get(hash).map(|node| node.header)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::params::Network;

    const MAINNET_HEADERS: &[u8] =
        include_bytes!("../../../fixtures/mainnet-headers-000000-004031.bin");
    const TESTNET4_HEADERS: &[u8] =
        include_bytes!("../../../fixtures/testnet4-headers-000000-004031.bin");
    const SIGNET_HEADERS: &[u8] =
        include_bytes!("../../../fixtures/signet-headers-000000-002047.bin");

    fn decode_headers(bytes: &[u8]) -> Vec<BlockHeader> {
        bytes
            .as_chunks::<{ BlockHeader::SIZE }>()
            .0
            .iter()
            .map(|chunk| BlockHeader::decode(chunk))
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// Inserts `headers[1..]` (index 0 is the seeded genesis) into a fresh tree and returns
    /// it. `now` for each insert is the header's own timestamp, which always satisfies both
    /// time rules on a real chain.
    fn tree_over(headers: &[BlockHeader], network: Network) -> HeaderTree {
        let mut tree = HeaderTree::new(network.params());
        for header in &headers[1..] {
            match tree.insert(header, header.time) {
                Ok(InsertStatus::Added { .. }) => {}
                other => panic!("insert of {} failed: {other:?}", header.hash()),
            }
        }
        tree
    }

    #[test]
    fn fresh_tree_contains_only_genesis() {
        let params = Network::Mainnet.params();
        let tree = HeaderTree::new(params);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.tip().height, 0);
        assert_eq!(tree.tip_hash(), params.genesis_header.hash());
        assert_eq!(
            tree.tip().chainwork,
            Work::from_compact(params.genesis_header.bits)
        );
        assert!(!tree.is_empty());
    }

    #[test]
    fn mainnet_chain_builds_to_the_fixture_tip() {
        let headers = decode_headers(MAINNET_HEADERS);
        let tree = tree_over(&headers, Network::Mainnet);
        assert_eq!(tree.len(), headers.len());
        assert_eq!(tree.tip().height, 4031);
        assert_eq!(tree.tip().header, headers[4031]);
        assert_eq!(
            tree.tip_hash().to_string(),
            "00000000f037ad09d0b05ee66b8c1da83030abaf909d2b1bf519c3c7d2cd3fdf"
        );
        // Chainwork must equal the sum of every header's per-block work.
        let expected: Work = headers.iter().fold(Work::ZERO, |acc, h| {
            acc.checked_add(Work::from_compact(h.bits)).unwrap()
        });
        assert_eq!(tree.tip().chainwork, expected);
    }

    #[test]
    fn testnet4_and_signet_chains_build_to_their_fixture_tips() {
        let testnet4 = decode_headers(TESTNET4_HEADERS);
        let tree4 = tree_over(&testnet4, Network::Testnet4);
        assert_eq!(tree4.tip().height, 4031);
        assert_eq!(
            tree4.tip_hash().to_string(),
            "000000002ad661157c553c0bbbb2490407adb1c8ac09f2b2a7174f87eeeb64bf"
        );

        let signet = decode_headers(SIGNET_HEADERS);
        let trees = tree_over(&signet, Network::Signet);
        assert_eq!(trees.tip().height, 2047);
        assert_eq!(
            trees.tip_hash().to_string(),
            "000000257b6ce53187f1adf352ef64a6b992632a1a51aa6fefc2aefd7831723e"
        );
    }

    #[test]
    fn every_height_maps_back_to_its_header() {
        let headers = decode_headers(MAINNET_HEADERS);
        let tree = tree_over(&headers, Network::Mainnet);
        for (i, header) in headers.iter().enumerate() {
            let node = tree.get(&header.hash()).unwrap();
            assert_eq!(node.height, i as u32);
            assert_eq!(node.header, *header);
        }
    }

    #[test]
    fn orphan_header_is_rejected() {
        let headers = decode_headers(MAINNET_HEADERS);
        let mut tree = HeaderTree::new(Network::Mainnet.params());
        // Height-2 header without its parent in the tree.
        assert_eq!(
            tree.insert(&headers[2], headers[2].time),
            Err(ChainError::UnknownParent(headers[1].hash()))
        );
        assert_eq!(tree.len(), 1);
    }

    /// A custom regtest-flavored params whose `powLimit` is the full 256-bit range, so any
    /// header with consistent fields can pass PoW after light nonce grinding — enough to
    /// build forks and forged rejections without mining.
    fn easy_params() -> Params {
        let mut params = Network::Regtest.params();
        params.pow_limit = crate::arith::Target(crate::arith::U256::MAX);
        params.allow_min_difficulty_blocks = false;
        params
    }

    /// Builds a child of `parent` with the given version/time/bits and grinds the nonce
    /// (starting at `nonce_hint`) until the header satisfies its own claimed target under
    /// `params`. With `easy_params`'s powLimit and the regtest genesis `nBits`
    /// (`0x207fffff`, target ≈ `2^255`), roughly every other nonce passes. The hint lets
    /// sibling headers differ even at equal times.
    fn mint_versioned(
        parent: &HeaderNode,
        params: &Params,
        version: i32,
        time: u32,
        bits: CompactTarget,
        nonce_hint: u32,
    ) -> BlockHeader {
        for nonce in nonce_hint..u32::MAX {
            let header = BlockHeader {
                version,
                prev_block_hash: parent.hash(),
                merkle_root: parent.header.merkle_root,
                time,
                bits,
                nonce,
            };
            if pow::check_proof_of_work(&header.hash(), bits, params).is_ok() {
                return header;
            }
        }
        panic!("no nonce satisfied the target — target implausibly tight for this helper");
    }

    /// [`mint_versioned`] with version 4 — the modern, always-valid version every test that
    /// is not specifically exercising the version floor should mint with.
    fn mint(
        parent: &HeaderNode,
        params: &Params,
        time: u32,
        bits: CompactTarget,
        nonce_hint: u32,
    ) -> BlockHeader {
        mint_versioned(parent, params, 4, time, bits, nonce_hint)
    }

    /// A valid child of `parent` under `easy_params`: correct bits (regtest never retargets
    /// and `easy_params` disables min-difficulty, so the required bits always equal the
    /// parent's) and a passing PoW.
    fn extend(parent: &HeaderNode, params: &Params, time: u32, nonce_hint: u32) -> BlockHeader {
        mint(parent, params, time, parent.header.bits, nonce_hint)
    }

    #[test]
    fn wrong_bits_is_rejected() {
        let params = easy_params();
        let genesis = *HeaderTree::new(params).tip();
        let mut tree = HeaderTree::new(params);
        // Forge a child whose bits differ from the required (parent's) bits but whose own
        // PoW still passes — the schedule check must be what rejects it.
        let forged = mint(
            &genesis,
            &params,
            genesis.header.time + 1,
            CompactTarget(0x207f_fffe),
            0,
        );
        assert_eq!(
            tree.insert(&forged, u32::MAX),
            Err(ChainError::WrongBits {
                expected: genesis.header.bits,
                actual: forged.bits,
            })
        );
    }

    #[test]
    fn insufficient_work_is_rejected() {
        let headers = decode_headers(MAINNET_HEADERS);
        let mut tree = HeaderTree::new(Network::Mainnet.params());
        // Keep the required bits (so a PoW pass would reach the bits check, which matches)
        // but grind the nonce until the hash provably misses the target.
        let mut forged = headers[1];
        let mut rejected = false;
        for nonce in 0..10_000u32 {
            forged.nonce = nonce;
            match tree.insert(&forged, forged.time) {
                Err(ChainError::Pow(PowError::InsufficientWork { .. })) => {
                    rejected = true;
                    break;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
                Ok(_) => {}
            }
        }
        assert!(rejected, "no tested nonce produced InsufficientWork");
    }

    #[test]
    fn too_old_timestamp_is_rejected() {
        let params = easy_params();
        let mut tree = HeaderTree::new(params);
        // Build a 12-block chain so the tip's median time past is a real median.
        for i in 1..=12u32 {
            let tip = *tree.tip();
            let next = extend(&tip, &params, tip.header.time + 600, i);
            tree.insert(&next, u32::MAX).unwrap();
        }
        let tip = *tree.tip();
        let median = tree.median_time_past(&tip.hash()).unwrap();
        // A child whose time equals the median (not strictly greater) is too old — and its
        // PoW passes, so the time check is what must fire.
        let forged = mint(&tip, &params, median, tip.header.bits, 0);
        assert_eq!(
            tree.insert(&forged, u32::MAX),
            Err(ChainError::Time(TimeError::TooOld {
                time: median,
                median_past: median,
            }))
        );
    }

    #[test]
    fn too_new_timestamp_is_rejected() {
        let params = easy_params();
        let mut tree = HeaderTree::new(params);
        let genesis = *tree.tip();
        let now = genesis.header.time;
        let forged = mint(
            &genesis,
            &params,
            now + rules::MAX_FUTURE_BLOCK_TIME + 1,
            genesis.header.bits,
            0,
        );
        assert_eq!(
            tree.insert(&forged, now),
            Err(ChainError::Time(TimeError::TooNew {
                time: forged.time,
                now,
            }))
        );
    }

    #[test]
    fn reinsertion_is_already_known() {
        let headers = decode_headers(MAINNET_HEADERS);
        let mut tree = HeaderTree::new(Network::Mainnet.params());
        tree.insert(&headers[1], headers[1].time).unwrap();
        assert_eq!(
            tree.insert(&headers[1], headers[1].time),
            Ok(InsertStatus::AlreadyKnown { height: 1 })
        );
        assert_eq!(tree.len(), 2);
        // Re-inserting the genesis is already-known too.
        let genesis = Network::Mainnet.params().genesis_header;
        assert_eq!(
            tree.insert(&genesis, genesis.time),
            Ok(InsertStatus::AlreadyKnown { height: 0 })
        );
    }

    #[test]
    fn median_time_past_walks_eleven_deep() {
        let headers = decode_headers(MAINNET_HEADERS);
        let tree = tree_over(&headers[..20], Network::Mainnet);
        let tip = tree.tip();
        // At height 19 the window covers heights 9..=19.
        let expected: Vec<u32> = headers[9..=19].iter().map(|h| h.time).collect();
        let mut sorted = expected.clone();
        sorted.sort_unstable();
        assert_eq!(tree.median_time_past(&tip.hash()), Some(sorted[5]));
        // Unknown hash → None.
        assert_eq!(tree.median_time_past(&BlockHash::ZERO), None);
    }

    #[test]
    fn fork_with_less_work_does_not_move_the_tip() {
        let params = easy_params();
        let genesis_time = params.genesis_header.time;
        let mut tree = HeaderTree::new(params);
        let genesis_node = *tree.tip();
        // Main branch: three blocks.
        let a1 = extend(&genesis_node, &params, genesis_time + 1, 1);
        tree.insert(&a1, u32::MAX).unwrap();
        let a1_node = *tree.get(&a1.hash()).unwrap();
        let a2 = extend(&a1_node, &params, a1.time + 1, 2);
        tree.insert(&a2, u32::MAX).unwrap();
        let a2_node = *tree.get(&a2.hash()).unwrap();
        let a3 = extend(&a2_node, &params, a2.time + 1, 3);
        tree.insert(&a3, u32::MAX).unwrap();
        let tip_after_main = tree.tip_hash();
        // Side branch off genesis: two blocks — fewer total work.
        let b1 = extend(&genesis_node, &params, genesis_time + 2, 100);
        tree.insert(&b1, u32::MAX).unwrap();
        let b1_node = *tree.get(&b1.hash()).unwrap();
        let b2 = extend(&b1_node, &params, b1.time + 1, 101);
        tree.insert(&b2, u32::MAX).unwrap();
        // Tip stays on the heavier branch.
        assert_eq!(tree.tip_hash(), tip_after_main);
        assert_eq!(tree.len(), 6);
    }

    #[test]
    fn fork_with_more_work_moves_the_tip() {
        let params = easy_params();
        let genesis_time = params.genesis_header.time;
        let mut tree = HeaderTree::new(params);
        let genesis_node = *tree.tip();
        let a1 = extend(&genesis_node, &params, genesis_time + 1, 1);
        tree.insert(&a1, u32::MAX).unwrap();
        // Side branch with two blocks overtakes the one-block main branch.
        let b1 = extend(&genesis_node, &params, genesis_time + 2, 100);
        tree.insert(&b1, u32::MAX).unwrap();
        let b1_node = *tree.get(&b1.hash()).unwrap();
        let b2 = extend(&b1_node, &params, b1.time + 1, 101);
        tree.insert(&b2, u32::MAX).unwrap();
        assert_eq!(tree.tip_hash(), b2.hash());
        assert_eq!(tree.tip().height, 2);
    }

    /// Regtest-flavored params with BIP94 enforced and a 4-block difficulty interval, so a
    /// period boundary — and its timewarp floor — is reachable within a few headers.
    /// `no_retargeting` (from the regtest base) keeps the required bits equal to the
    /// parent's at every height.
    fn bip94_params() -> Params {
        let mut params = easy_params();
        params.enforce_bip94 = true;
        params.pow_target_spacing = 60;
        params.pow_target_timespan = 240; // interval = 4
        params
    }

    /// Builds a 3-header extension of `tree` with times `i * 700` past genesis and returns
    /// the new tip node.
    fn grow_to_height3(tree: &mut HeaderTree, params: &Params) -> HeaderNode {
        let genesis_time = params.genesis_header.time;
        let mut node = *tree.tip();
        for i in 1..=3u32 {
            let next = extend(&node, params, genesis_time + i * 700, i);
            tree.insert(&next, u32::MAX).unwrap();
            node = *tree.get(&next.hash()).unwrap();
        }
        node
    }

    #[test]
    fn bip94_timewarp_rejects_backdated_period_start() {
        let params = bip94_params();
        let mut tree = HeaderTree::new(params);
        // Height 4 is a period boundary (interval 4); its nTime must be at least
        // parent.nTime - 600. That floor sits *above* the median here, so the timewarp
        // floor is the predicate that fires (TooOld would report otherwise).
        let parent = grow_to_height3(&mut tree, &params);
        let floor = parent.header.time - rules::MAX_TIMEWARP;
        let forged = mint(&parent, &params, floor - 1, parent.header.bits, 10_000);
        assert_eq!(
            tree.insert(&forged, u32::MAX),
            Err(ChainError::Time(TimeError::Timewarp {
                time: floor - 1,
                min_time: floor,
            }))
        );
        assert_eq!(tree.len(), 4, "rejected header must not be inserted");
        // Exactly at the floor is accepted.
        let boundary = mint(&parent, &params, floor, parent.header.bits, 20_000);
        assert_eq!(
            tree.insert(&boundary, u32::MAX),
            Ok(InsertStatus::Added { height: 4 })
        );
    }

    #[test]
    fn timewarp_backdate_is_accepted_without_bip94() {
        // The identical chain and backdated boundary header, but with `enforce_bip94`
        // off — the rule is BIP94's alone.
        let mut params = bip94_params();
        params.enforce_bip94 = false;
        let mut tree = HeaderTree::new(params);
        let parent = grow_to_height3(&mut tree, &params);
        let backdated = mint(
            &parent,
            &params,
            parent.header.time - rules::MAX_TIMEWARP - 1,
            parent.header.bits,
            30_000,
        );
        assert_eq!(
            tree.insert(&backdated, u32::MAX),
            Ok(InsertStatus::Added { height: 4 })
        );
    }

    #[test]
    fn equal_work_fork_keeps_the_first_tip() {
        let params = easy_params();
        let genesis_time = params.genesis_header.time;
        let mut tree = HeaderTree::new(params);
        let genesis_node = *tree.tip();
        let a1 = extend(&genesis_node, &params, genesis_time + 1, 1);
        tree.insert(&a1, u32::MAX).unwrap();
        let first_tip = tree.tip_hash();
        // Equal work (same bits, same height) — tip must not move.
        let b1 = extend(&genesis_node, &params, genesis_time + 2, 200);
        tree.insert(&b1, u32::MAX).unwrap();
        assert_eq!(tree.tip_hash(), first_tip);
    }

    // ---- Version floor (`bad-version`) ----

    /// Regtest's `easy_params` buries BIP34/66/65 at height 1 (the network default), so
    /// every non-genesis height already sits above every floor: versions 1–3 must each be
    /// rejected by the specific floor Core checks for them, version 4 clears every floor,
    /// and a negative version — still `< 2` — is rejected the same way version 1 is.
    #[test]
    fn version_floor_rejects_versions_below_the_buried_heights_on_regtest() {
        let params = easy_params();
        assert_eq!(params.bip34_height, 1);
        assert_eq!(params.bip66_height, 1);
        assert_eq!(params.bip65_height, 1);
        let genesis = *HeaderTree::new(params).tip();

        // Version 1: below the BIP34 floor (`nVersion < 2`), active from height 1.
        let mut tree = HeaderTree::new(params);
        let v1 = mint_versioned(
            &genesis,
            &params,
            1,
            genesis.header.time + 1,
            genesis.header.bits,
            0,
        );
        assert_eq!(
            tree.insert(&v1, u32::MAX),
            Err(ChainError::BadVersion { version: 1 })
        );
        assert_eq!(tree.len(), 1, "rejected header must not be inserted");

        // Version 2: clears BIP34 but is below the BIP66 floor (`nVersion < 3`).
        let v2 = mint_versioned(
            &genesis,
            &params,
            2,
            genesis.header.time + 1,
            genesis.header.bits,
            10,
        );
        assert_eq!(
            tree.insert(&v2, u32::MAX),
            Err(ChainError::BadVersion { version: 2 })
        );

        // Version 3: clears BIP34/66 but is below the BIP65 floor (`nVersion < 4`).
        let v3 = mint_versioned(
            &genesis,
            &params,
            3,
            genesis.header.time + 1,
            genesis.header.bits,
            20,
        );
        assert_eq!(
            tree.insert(&v3, u32::MAX),
            Err(ChainError::BadVersion { version: 3 })
        );

        // Version 4 clears every floor.
        let v4 = mint_versioned(
            &genesis,
            &params,
            4,
            genesis.header.time + 1,
            genesis.header.bits,
            30,
        );
        assert_eq!(
            tree.insert(&v4, u32::MAX),
            Ok(InsertStatus::Added { height: 1 })
        );

        // A negative version is still `< 2`: rejected exactly like version 1, with its
        // `Display` showing the 32-bit two's-complement hex Core would report.
        let neg = mint_versioned(
            &genesis,
            &params,
            -1,
            genesis.header.time + 2,
            genesis.header.bits,
            40,
        );
        assert_eq!(
            tree.insert(&neg, u32::MAX),
            Err(ChainError::BadVersion { version: -1 })
        );
        assert_eq!(
            ChainError::BadVersion { version: -1 }.to_string(),
            "bad-version(0xffffffff)"
        );
        assert_eq!(
            ChainError::BadVersion { version: 1 }.to_string(),
            "bad-version(0x00000001)"
        );
    }

    /// The genesis header is never run through `insert`'s checks — it is seeded directly
    /// by [`HeaderTree::new`] — so it is exempt from the version floor even when a floor is
    /// configured to cover height 0 itself (which no built-in network's parameters do; Core
    /// buries every floor at height ≥ 1).
    #[test]
    fn genesis_is_exempt_from_the_version_floor() {
        let mut params = easy_params();
        params.bip34_height = 0;
        // The regtest genesis carries version 1, which would fail an active BIP34 floor
        // (`nVersion < 2`) at height 0 if `new` validated it the way `insert` validates
        // every other header.
        assert_eq!(params.genesis_header.version, 1);
        let tree = HeaderTree::new(params);
        assert_eq!(tree.tip().height, 0);
        assert_eq!(tree.tip().header.version, 1);
    }

    /// Mainnet-shaped params (real buried heights) but an easy, regtest-style genesis
    /// target so a child header can be nonce-ground in a test without real mining. A
    /// version-1 header at height 1 — far below mainnet's `bip34_height` (227931) — must
    /// clear the version floor (though a real chain's version-1 blocks predate BIP34
    /// regardless, this pins the height comparison itself in isolation from real fixture
    /// data).
    fn easy_mainnet_params() -> Params {
        let mut params = Network::Mainnet.params();
        params.pow_limit = crate::arith::Target(crate::arith::U256::MAX);
        params.no_retargeting = true;
        params.allow_min_difficulty_blocks = false;
        // Keep every other mainnet field (including the real bip34/66/65 heights) but
        // swap in a trivially-easy genesis target, mirroring `easy_params`'s regtest
        // technique — `HeaderTree::new` never PoW-checks the genesis it is seeded with, so
        // an arbitrary nonce is fine here.
        params.genesis_header.bits = CompactTarget(0x207f_ffff);
        params
    }

    #[test]
    fn version_one_below_bip34_height_passes_the_version_floor_on_mainnet_params() {
        let params = easy_mainnet_params();
        assert_eq!(params.bip34_height, 227_931);
        let mut tree = HeaderTree::new(params);
        let genesis = *tree.tip();
        let header = mint_versioned(
            &genesis,
            &params,
            1,
            genesis.header.time + 1,
            genesis.header.bits,
            0,
        );
        assert_eq!(
            tree.insert(&header, u32::MAX),
            Ok(InsertStatus::Added { height: 1 })
        );
    }

    /// Core checks `bad-diffbits` before `bad-version`: a header that fails both reports
    /// the diffbits failure.
    #[test]
    fn bad_diffbits_is_reported_before_bad_version() {
        let params = easy_params();
        let genesis = *HeaderTree::new(params).tip();
        let mut tree = HeaderTree::new(params);
        // Forge a version-1 child (fails the BIP34 floor, active at height 1) whose bits
        // also differ from the required (parent's) bits — its own claimed PoW still
        // passes, so only the ordering of the two checks decides which error surfaces.
        let forged = mint_versioned(
            &genesis,
            &params,
            1,
            genesis.header.time + 1,
            CompactTarget(0x207f_fffe),
            0,
        );
        assert_eq!(
            tree.insert(&forged, u32::MAX),
            Err(ChainError::WrongBits {
                expected: genesis.header.bits,
                actual: forged.bits,
            })
        );
    }

    #[test]
    fn block_proof_equivalent_time_counts_blocks_at_tip_difficulty() {
        // Every fixture header carries the same nBits (0x1d00ffff), so the
        // work delta between two heights is exactly the height gap times the
        // per-block proof, and `r * nPowTargetSpacing / tip_proof` reduces to
        // `gap * 600`.
        let headers = decode_headers(MAINNET_HEADERS);
        let tree = tree_over(&headers, Network::Mainnet);
        let params = Network::Mainnet.params();
        let genesis = tree.get(&params.genesis_header.hash()).unwrap();
        let tip = tree.tip();
        assert_eq!(
            HeaderTree::block_proof_equivalent_time(tip, genesis, tip, &params),
            i64::from(tip.height) * i64::try_from(params.pow_target_spacing).unwrap()
        );
        // Reversed arguments negate the result.
        assert_eq!(
            HeaderTree::block_proof_equivalent_time(genesis, tip, tip, &params),
            -i64::from(tip.height) * i64::try_from(params.pow_target_spacing).unwrap()
        );
        // Same node: zero delta.
        assert_eq!(
            HeaderTree::block_proof_equivalent_time(tip, tip, tip, &params),
            0
        );
    }
}

//! Experimental, shadow-only builder for Utreexo implicit-deletion checkpoints.
//!
//! This module is not a consensus acceptance path and its result must never be
//! installed into [`crate::utreexo::UtxoAccumulator`]. The caller supplies an
//! ordered list of output commitments per block. `Some(hash)` is a live leaf;
//! `None` is an output independently established to have been spent by the
//! checkpoint. A `None` still occupies a leaf position, so the leaf count
//! includes implicit deletions.
//!
//! Before using this experiment, the caller must independently validate every
//! spentness hint, run all script and consensus checks, enumerate coins in the
//! accumulator's required order, and define same-block-spend, unspendable
//! output, and BIP30 duplicate-transaction handling. The leaf commitment is
//! Avila's existing `utreexo::leaf_for`/`leaf_hash` scheme, not a BIP
//! interoperability format. Completion returns only [`ProvisionalStump`],
//! which is explicitly unverified state even when the caller supplies an
//! external-audit receipt.

use rustreexo::node_hash::{AccumulatorHash, BitcoinNodeHash};
use rustreexo_v07::node_hash::{
    AccumulatorHash as AccumulatorHashV07, BitcoinNodeHash as BitcoinNodeHashV07,
};
use rustreexo_v07::proof::Proof as ProofV07;
use rustreexo_v07::stump::Stump as StumpV07;
use std::collections::BTreeMap;
use std::mem::size_of;

/// Resource ceilings for batches accepted by [`SwiftStumpBuilder`].
///
/// Pending byte accounting includes each batch's `Vec` backing capacity and
/// the in-memory batch value. B-tree allocator overhead is bounded indirectly
/// by `max_pending_blocks`; it is not included in `max_pending_bytes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwiftStumpLimits {
    /// Maximum number of blocks held while waiting for an earlier height.
    pub max_pending_blocks: usize,
    /// Maximum output positions held across pending blocks.
    pub max_pending_leaves: usize,
    /// Maximum accounted bytes held across pending blocks.
    pub max_pending_bytes: usize,
    /// Maximum output positions in one block batch.
    pub max_batch_leaves: usize,
    /// Maximum `Vec` backing bytes in one block batch.
    pub max_batch_bytes: usize,
}

/// Inclusive height interval and externally chosen checkpoint identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwiftCheckpoint {
    pub first_height: u32,
    pub last_height: u32,
    pub checkpoint_hash: [u8; 32],
}

/// Explicit assertion from the independent checkpoint-audit caller.
///
/// Construct this only after that audit has passed. This receipt is a caller
/// assertion, not cryptographic proof, and cannot promote the resulting stump
/// into validated consensus state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalAuditPassed {
    checkpoint: SwiftCheckpoint,
}

impl ExternalAuditPassed {
    /// Records that an external audit passed for this exact checkpoint range.
    #[must_use]
    pub const fn after_external_audit(checkpoint: SwiftCheckpoint) -> Self {
        Self { checkpoint }
    }
}

/// Completed roots that remain explicitly provisional and shadow-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionalStump {
    /// Root hashes in the standard forest order.
    pub roots: Vec<BitcoinNodeHash>,
    /// Number of output positions, including entries marked as implicitly deleted.
    pub leaves: u64,
    /// The exact height interval used to build these roots.
    pub checkpoint: SwiftCheckpoint,
}

#[derive(Clone, Debug)]
struct PendingBatch {
    outputs: Vec<Option<BitcoinNodeHash>>,
    accounted_bytes: usize,
}

/// Typed errors from range validation, resource bounds, and completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwiftStumpError {
    InvalidRange,
    InvalidLimits,
    HeightOutsideCheckpoint(u32),
    HeightAlreadyConsumed(u32),
    DuplicateHeight(u32),
    BatchTooManyLeaves { actual: usize, limit: usize },
    BatchTooManyBytes { actual: usize, limit: usize },
    InvalidEmptyLeaf { index: usize },
    InvalidPlaceholderLeaf { index: usize },
    PendingBlockLimit { limit: usize },
    PendingLeafLimit { actual: usize, limit: usize },
    PendingByteLimit { actual: usize, limit: usize },
    LeafCountOverflow,
    Incomplete { next_height: u64, last_height: u32 },
    AuditCheckpointMismatch,
    UpstreamTransition,
    InvalidSnapshot,
}

/// Ordered root-carry builder with bounded out-of-order input buffering.
///
/// Batches are accepted atomically: a rejected batch leaves roots, counters,
/// and pending heights unchanged. The caller may retry after releasing
/// backpressure by supplying the missing earlier heights. At peak, retained
/// pending batches stay within their configured budget while one incoming
/// batch may also be owned, bounded by the independent per-batch ceilings.
pub struct SwiftStumpBuilder {
    checkpoint: SwiftCheckpoint,
    limits: SwiftStumpLimits,
    next_height: u64,
    stump: StumpV07<BitcoinNodeHashV07>,
    pending: BTreeMap<u32, PendingBatch>,
    pending_leaves: usize,
    pending_bytes: usize,
}

impl SwiftStumpBuilder {
    /// Starts an empty builder for an inclusive checkpoint height range.
    pub fn new(
        checkpoint: SwiftCheckpoint,
        limits: SwiftStumpLimits,
    ) -> Result<Self, SwiftStumpError> {
        if checkpoint.first_height > checkpoint.last_height {
            return Err(SwiftStumpError::InvalidRange);
        }
        if limits.max_pending_blocks == 0 {
            return Err(SwiftStumpError::InvalidLimits);
        }
        Ok(Self {
            checkpoint,
            limits,
            next_height: u64::from(checkpoint.first_height),
            stump: StumpV07::new(),
            pending: BTreeMap::new(),
            pending_leaves: 0,
            pending_bytes: 0,
        })
    }

    /// Exact height range and checkpoint identifier configured for this builder.
    #[must_use]
    pub const fn checkpoint(&self) -> SwiftCheckpoint {
        self.checkpoint
    }

    /// Submits one block's ordered output commitments.
    ///
    /// The vector's allocated capacity is checked, not just its length, so a
    /// caller cannot evade the byte bounds with a small, over-allocated batch.
    pub fn push(
        &mut self,
        height: u32,
        outputs: Vec<Option<BitcoinNodeHash>>,
    ) -> Result<(), SwiftStumpError> {
        if height < self.checkpoint.first_height || height > self.checkpoint.last_height {
            return Err(SwiftStumpError::HeightOutsideCheckpoint(height));
        }
        if u64::from(height) < self.next_height {
            return Err(SwiftStumpError::HeightAlreadyConsumed(height));
        }
        if self.pending.contains_key(&height) {
            return Err(SwiftStumpError::DuplicateHeight(height));
        }

        let batch_leaves = outputs.len();
        if batch_leaves > self.limits.max_batch_leaves {
            return Err(SwiftStumpError::BatchTooManyLeaves {
                actual: batch_leaves,
                limit: self.limits.max_batch_leaves,
            });
        }
        let backing_bytes = outputs
            .capacity()
            .checked_mul(size_of::<Option<BitcoinNodeHash>>())
            .ok_or(SwiftStumpError::BatchTooManyBytes {
                actual: usize::MAX,
                limit: self.limits.max_batch_bytes,
            })?;
        let accounted_bytes = backing_bytes.checked_add(size_of::<PendingBatch>()).ok_or(
            SwiftStumpError::BatchTooManyBytes {
                actual: usize::MAX,
                limit: self.limits.max_batch_bytes,
            },
        )?;
        if backing_bytes > self.limits.max_batch_bytes {
            return Err(SwiftStumpError::BatchTooManyBytes {
                actual: backing_bytes,
                limit: self.limits.max_batch_bytes,
            });
        }
        for (index, output) in outputs.iter().enumerate() {
            if let Some(hash) = output {
                if hash.is_empty() {
                    return Err(SwiftStumpError::InvalidEmptyLeaf { index });
                }
                if hash.is_placeholder() {
                    return Err(SwiftStumpError::InvalidPlaceholderLeaf { index });
                }
            }
        }

        let is_frontier = u64::from(height) == self.next_height;
        let total_pending_leaves = self.pending_leaves.checked_add(batch_leaves).ok_or(
            SwiftStumpError::PendingLeafLimit {
                actual: usize::MAX,
                limit: self.limits.max_pending_leaves,
            },
        )?;
        if !is_frontier {
            let count =
                self.pending
                    .len()
                    .checked_add(1)
                    .ok_or(SwiftStumpError::PendingBlockLimit {
                        limit: self.limits.max_pending_blocks,
                    })?;
            if count > self.limits.max_pending_blocks {
                return Err(SwiftStumpError::PendingBlockLimit {
                    limit: self.limits.max_pending_blocks,
                });
            }
        }
        let pending_leaves = if is_frontier {
            self.pending_leaves
        } else {
            if total_pending_leaves > self.limits.max_pending_leaves {
                return Err(SwiftStumpError::PendingLeafLimit {
                    actual: total_pending_leaves,
                    limit: self.limits.max_pending_leaves,
                });
            }
            total_pending_leaves
        };
        let pending_bytes = if is_frontier {
            self.pending_bytes
        } else {
            let bytes = self.pending_bytes.checked_add(accounted_bytes).ok_or(
                SwiftStumpError::PendingByteLimit {
                    actual: usize::MAX,
                    limit: self.limits.max_pending_bytes,
                },
            )?;
            if bytes > self.limits.max_pending_bytes {
                return Err(SwiftStumpError::PendingByteLimit {
                    actual: bytes,
                    limit: self.limits.max_pending_bytes,
                });
            }
            bytes
        };
        self.stump
            .leaves
            .checked_add(
                u64::try_from(total_pending_leaves)
                    .map_err(|_| SwiftStumpError::LeafCountOverflow)?,
            )
            .ok_or(SwiftStumpError::LeafCountOverflow)?;

        // All fallible checks precede mutation. Removing each contiguous batch
        // below cannot overflow because the cumulative count was checked above.
        if !is_frontier {
            self.pending.insert(
                height,
                PendingBatch {
                    outputs,
                    accounted_bytes,
                },
            );
            self.pending_leaves = pending_leaves;
            self.pending_bytes = pending_bytes;
            return Ok(());
        }

        // Stage upstream changes on a clone first. If rustreexo rejects a
        // transition, neither the builder stump nor its pending queue changes.
        let mut candidate = self.stump.clone();
        apply_batch(&mut candidate, &outputs)?;
        let mut next_height = self.next_height + 1;
        let mut consumed_pending = Vec::new();
        while next_height <= u64::from(self.checkpoint.last_height) {
            let Some(batch) = self.pending.get(&(next_height as u32)) else {
                break;
            };
            apply_batch(&mut candidate, &batch.outputs)?;
            consumed_pending.push(next_height as u32);
            next_height += 1;
        }
        self.stump = candidate;
        self.next_height = next_height;
        for height in consumed_pending {
            if let Some(batch) = self.pending.remove(&height) {
                self.pending_leaves -= batch.outputs.len();
                self.pending_bytes -= batch.accounted_bytes;
            }
        }
        Ok(())
    }

    /// Returns the next height needed to advance the ordered accumulator.
    #[must_use]
    pub const fn next_height(&self) -> u64 {
        self.next_height
    }

    /// Current provisional forest leaf count.
    #[must_use]
    pub const fn leaves(&self) -> u64 {
        self.stump.leaves
    }

    /// Number of out-of-order batches still waiting for a gap to close.
    #[must_use]
    pub fn pending_blocks(&self) -> usize {
        self.pending.len()
    }

    /// Finishes only after every height and the caller's matching audit receipt.
    ///
    /// This returns an explicitly provisional value; no API in this module
    /// marks it as validated or persists it into consensus state.
    pub fn finish(&self, audit: ExternalAuditPassed) -> Result<ProvisionalStump, SwiftStumpError> {
        if self.next_height <= u64::from(self.checkpoint.last_height) {
            return Err(SwiftStumpError::Incomplete {
                next_height: self.next_height,
                last_height: self.checkpoint.last_height,
            });
        }
        if audit.checkpoint != self.checkpoint {
            return Err(SwiftStumpError::AuditCheckpointMismatch);
        }
        Ok(ProvisionalStump {
            roots: self
                .stump
                .roots
                .iter()
                .map(|root| {
                    // The two rustreexo versions represent the distinguished
                    // empty leaf differently: converting its byte view would
                    // turn `Empty` into an ordinary `Some([0; 32])` hash. Keep
                    // the sentinel when crossing this compatibility boundary.
                    if root.is_empty() {
                        BitcoinNodeHash::empty()
                    } else {
                        BitcoinNodeHash::from(**root)
                    }
                })
                .collect(),
            leaves: self.stump.leaves,
            checkpoint: self.checkpoint,
        })
    }

    /// Serializes the actual rustreexo 0.7 stump and the exact checkpoint cursor.
    /// Pending batches are intentionally excluded; this engine submits heights
    /// sequentially, and a nonempty pending queue cannot be checkpointed.
    pub(crate) fn persisted_state(&self) -> Result<Vec<u8>, SwiftStumpError> {
        if !self.pending.is_empty() {
            return Err(SwiftStumpError::InvalidSnapshot);
        }
        let mut out = Vec::with_capacity(96 + self.stump.roots.len() * 32);
        out.extend_from_slice(b"AVSTUMP1");
        out.extend_from_slice(&self.checkpoint.first_height.to_le_bytes());
        out.extend_from_slice(&self.checkpoint.last_height.to_le_bytes());
        out.extend_from_slice(&self.checkpoint.checkpoint_hash);
        out.extend_from_slice(&self.next_height.to_le_bytes());
        for limit in [
            self.limits.max_pending_blocks,
            self.limits.max_pending_leaves,
            self.limits.max_pending_bytes,
            self.limits.max_batch_leaves,
            self.limits.max_batch_bytes,
        ] {
            out.extend_from_slice(
                &u64::try_from(limit)
                    .map_err(|_| SwiftStumpError::InvalidSnapshot)?
                    .to_le_bytes(),
            );
        }
        self.stump
            .serialize(&mut out)
            .map_err(|_| SwiftStumpError::InvalidSnapshot)?;
        Ok(out)
    }

    /// Restores a persisted stump only for the same checkpoint and validated cursor.
    pub(crate) fn from_persisted_state(
        bytes: &[u8],
        checkpoint: SwiftCheckpoint,
    ) -> Result<Self, SwiftStumpError> {
        const PREFIX: usize = 8 + 4 + 4 + 32 + 8 + 5 * 8;
        if bytes.len() < PREFIX + 16 || &bytes[..8] != b"AVSTUMP1" {
            return Err(SwiftStumpError::InvalidSnapshot);
        }
        let first = u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| SwiftStumpError::InvalidSnapshot)?,
        );
        let last = u32::from_le_bytes(
            bytes[12..16]
                .try_into()
                .map_err(|_| SwiftStumpError::InvalidSnapshot)?,
        );
        let hash: [u8; 32] = bytes[16..48]
            .try_into()
            .map_err(|_| SwiftStumpError::InvalidSnapshot)?;
        let next_height = u64::from_le_bytes(
            bytes[48..56]
                .try_into()
                .map_err(|_| SwiftStumpError::InvalidSnapshot)?,
        );
        let mut limits_iter = (56..PREFIX).step_by(8).map(|offset| {
            let raw: [u8; 8] = bytes
                .get(offset..offset + 8)
                .ok_or(SwiftStumpError::InvalidSnapshot)?
                .try_into()
                .map_err(|_| SwiftStumpError::InvalidSnapshot)?;
            usize::try_from(u64::from_le_bytes(raw)).map_err(|_| SwiftStumpError::InvalidSnapshot)
        });
        let limits = SwiftStumpLimits {
            max_pending_blocks: limits_iter
                .next()
                .ok_or(SwiftStumpError::InvalidSnapshot)??,
            max_pending_leaves: limits_iter
                .next()
                .ok_or(SwiftStumpError::InvalidSnapshot)??,
            max_pending_bytes: limits_iter
                .next()
                .ok_or(SwiftStumpError::InvalidSnapshot)??,
            max_batch_leaves: limits_iter
                .next()
                .ok_or(SwiftStumpError::InvalidSnapshot)??,
            max_batch_bytes: limits_iter
                .next()
                .ok_or(SwiftStumpError::InvalidSnapshot)??,
        };
        if (first, last, hash)
            != (
                checkpoint.first_height,
                checkpoint.last_height,
                checkpoint.checkpoint_hash,
            )
            || next_height < u64::from(first)
            || next_height > u64::from(last) + 1
            || limits.max_pending_blocks == 0
        {
            return Err(SwiftStumpError::InvalidSnapshot);
        }
        let mut stump_reader = &bytes[PREFIX..];
        let stump = StumpV07::<BitcoinNodeHashV07>::deserialize(&mut stump_reader)
            .map_err(|_| SwiftStumpError::InvalidSnapshot)?;
        if !stump_reader.is_empty() || stump.roots.len() != stump.leaves.count_ones() as usize {
            return Err(SwiftStumpError::InvalidSnapshot);
        }
        Ok(Self {
            checkpoint,
            limits,
            next_height,
            stump,
            pending: BTreeMap::new(),
            pending_leaves: 0,
            pending_bytes: 0,
        })
    }
}

fn apply_batch(
    stump: &mut StumpV07<BitcoinNodeHashV07>,
    outputs: &[Option<BitcoinNodeHash>],
) -> Result<(), SwiftStumpError> {
    let additions = outputs
        .iter()
        .map(|hash| match hash {
            Some(hash) => BitcoinNodeHashV07::from(**hash),
            None => BitcoinNodeHashV07::empty(),
        })
        .collect::<Vec<_>>();
    *stump = stump
        .modify(&additions, &[], &ProofV07::default())
        .map_err(|_| SwiftStumpError::UpstreamTransition)?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        ExternalAuditPassed, PendingBatch, ProvisionalStump, SwiftCheckpoint, SwiftStumpBuilder,
        SwiftStumpError, SwiftStumpLimits,
    };
    use crate::hash::sha256d;
    use rustreexo::mem_forest::MemForest;
    use rustreexo::node_hash::{AccumulatorHash, BitcoinNodeHash};
    use rustreexo_v07::node_hash::{
        AccumulatorHash as AccumulatorHashV07, BitcoinNodeHash as BitcoinNodeHashV07,
    };
    use rustreexo_v07::proof::Proof as ProofV07;
    use rustreexo_v07::stump::Stump as StumpV07;
    use std::mem::size_of;

    fn checkpoint(last_height: u32) -> SwiftCheckpoint {
        SwiftCheckpoint {
            first_height: 1,
            last_height,
            checkpoint_hash: [0x42; 32],
        }
    }

    fn limits() -> SwiftStumpLimits {
        SwiftStumpLimits {
            max_pending_blocks: 8,
            max_pending_leaves: 256,
            max_pending_bytes: 32 * 1024,
            max_batch_leaves: 128,
            max_batch_bytes: 16 * 1024,
        }
    }

    fn leaf(index: usize) -> BitcoinNodeHash {
        BitcoinNodeHash::from(leaf_bytes(index))
    }

    fn leaf_bytes(index: usize) -> [u8; 32] {
        sha256d(&(index as u64).to_le_bytes())
    }

    fn audited(checkpoint: SwiftCheckpoint) -> ExternalAuditPassed {
        ExternalAuditPassed::after_external_audit(checkpoint)
    }

    fn expected_explicit_forest(
        outputs: &[Option<BitcoinNodeHash>],
    ) -> (u64, Vec<BitcoinNodeHash>) {
        let all_positions: Vec<_> = (0..outputs.len()).map(leaf).collect();
        let deleted: Vec<_> = outputs
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.is_none().then_some(all_positions[index]))
            .collect();

        let mut forest = MemForest::<BitcoinNodeHash>::new();
        forest.modify(&all_positions, &[]).unwrap();
        forest.modify(&[], &deleted).unwrap();
        let roots = forest
            .get_roots()
            .iter()
            .map(|root| root.get_data())
            .collect();
        (forest.leaves, roots)
    }

    fn build(outputs: &[Option<BitcoinNodeHash>], split: usize) -> ProvisionalStump {
        let split = split.max(1);
        let block_count = outputs.len().max(1).saturating_add(split - 1) / split;
        let cp = checkpoint(block_count as u32);
        let mut builder = SwiftStumpBuilder::new(cp, limits()).unwrap();
        if outputs.is_empty() {
            builder.push(1, vec![]).unwrap();
        }
        for (block, batch) in outputs.chunks(split).enumerate() {
            builder.push(block as u32 + 1, batch.to_vec()).unwrap();
        }
        builder.finish(audited(cp)).unwrap()
    }

    #[test]
    fn carries_match_memforest_for_mixed_empty_and_full_deletions() {
        for count in 0..=40 {
            let cases = [
                (0..count).map(|i| Some(leaf(i))).collect::<Vec<_>>(),
                (0..count)
                    .map(|i| (i % 3 != 1).then(|| leaf(i)))
                    .collect::<Vec<_>>(),
                (0..count).map(|_| None).collect::<Vec<_>>(),
            ];
            for outputs in cases {
                let stump = build(&outputs, 5);
                let (leaves, roots) = expected_explicit_forest(&outputs);
                assert_eq!(stump.leaves, leaves, "count={count}");
                assert_eq!(stump.roots, roots, "count={count}");
            }
        }
    }

    #[test]
    fn final_implicit_additions_match_rustreexo_v07_and_explicit_memforest() {
        // This is a final-checkpoint differential only. Upstream documents
        // intermediate stumps as provisional while these empty-hash additions
        // stand in for outputs later spent before the checkpoint.
        let batch_sizes = [1, 3, 5, 8, 13];
        for count in 0..=40 {
            let cases = [
                (0..count).map(|i| Some(leaf(i))).collect::<Vec<_>>(),
                (0..count)
                    .map(|i| (i % 3 != 1).then(|| leaf(i)))
                    .collect::<Vec<_>>(),
                (0..count).map(|_| None).collect::<Vec<_>>(),
            ];

            for outputs in cases {
                let (expected_leaves, expected_roots) = expected_explicit_forest(&outputs);
                for batch_size in batch_sizes {
                    let current = build(&outputs, batch_size);
                    let mut upstream = StumpV07::<BitcoinNodeHashV07>::new();

                    for (batch_index, batch) in outputs.chunks(batch_size).enumerate() {
                        let start = batch_size * batch_index;
                        let additions = batch
                            .iter()
                            .enumerate()
                            .map(|(offset, output)| match output {
                                Some(_) => BitcoinNodeHashV07::from(leaf_bytes(start + offset)),
                                None => BitcoinNodeHashV07::empty(),
                            })
                            .collect::<Vec<_>>();
                        upstream = upstream
                            .modify(&additions, &[], &ProofV07::default())
                            .unwrap();
                    }

                    let upstream_roots = upstream.roots;
                    let upstream_roots: Vec<_> =
                        upstream_roots.iter().map(ToString::to_string).collect();
                    let expected_root_strings: Vec<_> =
                        expected_roots.iter().map(ToString::to_string).collect();
                    let current_root_strings: Vec<_> =
                        current.roots.iter().map(ToString::to_string).collect();

                    assert_eq!(upstream.leaves, expected_leaves, "count={count}");
                    assert_eq!(upstream_roots, expected_root_strings, "count={count}");
                    assert_eq!(current.leaves, upstream.leaves, "count={count}");
                    assert_eq!(current_root_strings, upstream_roots, "count={count}");
                }
            }
        }
    }

    #[test]
    fn out_of_order_batches_are_bounded_and_retries_close_gaps() {
        let cp = checkpoint(3);
        let mut builder = SwiftStumpBuilder::new(cp, limits()).unwrap();
        builder.push(3, vec![Some(leaf(2))]).unwrap();
        builder.push(2, vec![Some(leaf(1))]).unwrap();
        assert_eq!(builder.pending_blocks(), 2);
        assert_eq!(builder.next_height(), 1);
        assert_eq!(
            builder.push(2, vec![]),
            Err(SwiftStumpError::DuplicateHeight(2))
        );
        builder.push(1, vec![Some(leaf(0))]).unwrap();
        assert_eq!(builder.pending_blocks(), 0);
        assert_eq!(builder.next_height(), 4);
        assert_eq!(builder.leaves(), 3);
    }

    #[test]
    fn rejects_overallocated_and_oversized_batches_without_mutation() {
        let cp = checkpoint(2);
        let mut bounded = limits();
        bounded.max_batch_bytes = 64;
        let mut builder = SwiftStumpBuilder::new(cp, bounded).unwrap();
        let oversized = Vec::with_capacity(100);
        assert!(matches!(
            builder.push(2, oversized),
            Err(SwiftStumpError::BatchTooManyBytes { .. })
        ));
        assert_eq!(builder.pending_blocks(), 0);
        assert_eq!(builder.next_height(), 1);
        assert_eq!(builder.leaves(), 0);
        assert!(matches!(
            builder.push(1, vec![Some(leaf(0)); 129]),
            Err(SwiftStumpError::BatchTooManyLeaves { .. })
        ));
        assert_eq!(builder.pending_blocks(), 0);
        assert_eq!(builder.leaves(), 0);
    }

    #[test]
    fn only_none_can_mark_a_leaf_as_implicitly_deleted() {
        let cp = checkpoint(3);
        let mut builder = SwiftStumpBuilder::new(cp, limits()).unwrap();
        assert_eq!(
            builder.push(2, vec![Some(BitcoinNodeHash::empty())]),
            Err(SwiftStumpError::InvalidEmptyLeaf { index: 0 })
        );
        assert_eq!(builder.pending_blocks(), 0);
        assert_eq!(builder.next_height(), 1);
        assert_eq!(builder.leaves(), 0);

        builder.push(3, vec![Some(leaf(2))]).unwrap();
        assert_eq!(
            builder.push(1, vec![Some(BitcoinNodeHash::placeholder())]),
            Err(SwiftStumpError::InvalidPlaceholderLeaf { index: 0 })
        );
        assert_eq!(builder.pending_blocks(), 1);
        assert_eq!(builder.next_height(), 1);
        assert_eq!(builder.leaves(), 0);

        // Rejected values leave the builder retryable and preserve the queued
        // future batch until valid frontier and gap batches arrive.
        builder.push(1, vec![Some(leaf(0))]).unwrap();
        assert_eq!(builder.pending_blocks(), 1);
        assert_eq!(builder.next_height(), 2);
        builder.push(2, vec![None]).unwrap();
        assert_eq!(builder.pending_blocks(), 0);
        assert_eq!(builder.next_height(), 4);
        assert_eq!(builder.leaves(), 3);
    }

    #[test]
    fn empty_blocks_gaps_old_heights_and_duplicate_consumed_heights_are_explicit() {
        let cp = checkpoint(3);
        let mut builder = SwiftStumpBuilder::new(cp, limits()).unwrap();
        assert_eq!(
            builder.push(0, vec![]),
            Err(SwiftStumpError::HeightOutsideCheckpoint(0))
        );
        assert_eq!(
            builder.push(4, vec![]),
            Err(SwiftStumpError::HeightOutsideCheckpoint(4))
        );
        builder.push(2, vec![]).unwrap();
        assert_eq!(builder.next_height(), 1);
        builder.push(1, vec![]).unwrap();
        assert_eq!(builder.next_height(), 3);
        assert_eq!(
            builder.push(1, vec![]),
            Err(SwiftStumpError::HeightAlreadyConsumed(1))
        );
        builder.push(3, vec![]).unwrap();
        assert_eq!(builder.leaves(), 0);
    }

    #[test]
    fn failures_are_atomic_and_pending_backpressure_can_be_retried() {
        let cp = checkpoint(3);
        let mut constrained = limits();
        constrained.max_pending_blocks = 1;
        constrained.max_pending_leaves = 1;
        let mut builder = SwiftStumpBuilder::new(cp, constrained).unwrap();
        builder.push(3, vec![Some(leaf(2))]).unwrap();
        assert_eq!(
            builder.push(2, vec![Some(leaf(1))]),
            Err(SwiftStumpError::PendingBlockLimit { limit: 1 })
        );
        assert_eq!(builder.pending_blocks(), 1);
        assert_eq!(builder.leaves(), 0);
        assert_eq!(builder.next_height(), 1);
        builder.push(1, vec![]).unwrap();
        builder.push(2, vec![Some(leaf(1))]).unwrap();
        assert_eq!(builder.next_height(), 4);
        assert_eq!(builder.leaves(), 2);
    }

    #[test]
    fn pending_leaf_and_byte_ceilings_reject_without_mutation() {
        let cp = checkpoint(2);
        let mut constrained = limits();
        constrained.max_pending_leaves = 0;
        constrained.max_pending_bytes = 1;
        let mut builder = SwiftStumpBuilder::new(cp, constrained).unwrap();
        assert!(matches!(
            builder.push(2, vec![Some(leaf(1))]),
            Err(SwiftStumpError::PendingLeafLimit {
                actual: 1,
                limit: 0
            })
        ));
        assert_eq!(builder.pending_blocks(), 0);
        assert_eq!(builder.next_height(), 1);
        assert_eq!(builder.leaves(), 0);

        constrained.max_pending_leaves = 1;
        let mut builder = SwiftStumpBuilder::new(cp, constrained).unwrap();
        assert!(matches!(
            builder.push(2, vec![]),
            Err(SwiftStumpError::PendingByteLimit { limit: 1, .. })
        ));
        assert_eq!(builder.pending_blocks(), 0);
        assert_eq!(builder.next_height(), 1);
        assert_eq!(builder.leaves(), 0);
    }

    #[test]
    fn full_pending_budget_does_not_block_frontier_and_oversized_frontier_is_atomic() {
        let cp = checkpoint(4);
        let queued = [
            (4, vec![Some(leaf(3))]),
            (3, vec![Some(leaf(2))]),
            (2, vec![Some(leaf(1))]),
        ];
        let queued_bytes = queued
            .iter()
            .map(|(_, batch)| {
                size_of::<PendingBatch>() + batch.capacity() * size_of::<Option<BitcoinNodeHash>>()
            })
            .sum();
        let mut constrained = limits();
        constrained.max_pending_blocks = queued.len();
        constrained.max_pending_leaves = queued.len();
        constrained.max_pending_bytes = queued_bytes;
        constrained.max_batch_leaves = 2;
        let mut builder = SwiftStumpBuilder::new(cp, constrained).unwrap();
        for (height, batch) in queued {
            builder.push(height, batch).unwrap();
        }
        assert_eq!(builder.pending_blocks(), constrained.max_pending_blocks);
        assert_eq!(builder.pending_leaves, constrained.max_pending_leaves);
        assert_eq!(builder.pending_bytes, constrained.max_pending_bytes);

        // The preflight total includes every queued leaf plus the frontier
        // batch, and rejection leaves the full pending queue untouched.
        assert_eq!(
            builder.push(1, vec![Some(leaf(0)); 3]),
            Err(SwiftStumpError::BatchTooManyLeaves {
                actual: 3,
                limit: 2
            })
        );
        assert_eq!(builder.pending_blocks(), constrained.max_pending_blocks);
        assert_eq!(builder.pending_leaves, constrained.max_pending_leaves);
        assert_eq!(builder.pending_bytes, constrained.max_pending_bytes);
        assert_eq!(builder.next_height(), 1);
        assert_eq!(builder.leaves(), 0);

        // This missing frontier height bypasses retained-pending limits, then
        // drains all queued batches in order without exceeding their budgets.
        builder.push(1, vec![Some(leaf(0))]).unwrap();
        assert_eq!(builder.pending_blocks(), 0);
        assert_eq!(builder.pending_leaves, 0);
        assert_eq!(builder.pending_bytes, 0);
        assert_eq!(builder.next_height(), 5);
        assert_eq!(builder.leaves(), 4);
    }

    #[test]
    fn finish_requires_complete_range_and_matching_external_checkpoint_audit() {
        let cp = checkpoint(2);
        let mut builder = SwiftStumpBuilder::new(cp, limits()).unwrap();
        assert_eq!(
            builder.finish(audited(cp)),
            Err(SwiftStumpError::Incomplete {
                next_height: 1,
                last_height: 2
            })
        );
        builder.push(1, vec![]).unwrap();
        builder.push(2, vec![]).unwrap();
        let wrong = SwiftCheckpoint {
            checkpoint_hash: [0x24; 32],
            ..cp
        };
        assert_eq!(
            builder.finish(audited(wrong)),
            Err(SwiftStumpError::AuditCheckpointMismatch)
        );
        let result = builder.finish(audited(cp)).unwrap();
        assert_eq!(result.checkpoint, cp);
        assert_eq!(result.leaves, 0);
    }

    #[test]
    fn persisted_stump_restores_exact_cursor_and_rejects_checkpoint_rebinding() {
        let cp = checkpoint(3);
        let mut builder = SwiftStumpBuilder::new(cp, limits()).unwrap();
        builder.push(1, vec![Some(leaf(0)), None]).unwrap();
        builder.push(2, vec![Some(leaf(2))]).unwrap();
        let snapshot = builder.persisted_state().unwrap();
        let restored = SwiftStumpBuilder::from_persisted_state(&snapshot, cp).unwrap();
        assert_eq!(restored.next_height(), 3);
        assert_eq!(restored.leaves(), 3);
        let wrong_checkpoint = SwiftCheckpoint {
            checkpoint_hash: [0x43; 32],
            ..cp
        };
        assert!(matches!(
            SwiftStumpBuilder::from_persisted_state(&snapshot, wrong_checkpoint),
            Err(SwiftStumpError::InvalidSnapshot)
        ));
    }

    #[test]
    fn rejects_upstream_forest_limit_without_mutating_builder() {
        let cp = checkpoint(2);
        let mut builder = SwiftStumpBuilder::new(cp, limits()).unwrap();
        builder.stump.leaves = 1 << 63;
        assert_eq!(
            builder.push(1, vec![Some(leaf(0))]),
            Err(SwiftStumpError::UpstreamTransition)
        );
        assert_eq!(builder.pending_blocks(), 0);
        assert_eq!(builder.next_height(), 1);
        assert_eq!(builder.leaves(), 1 << 63);
    }
}

//! BIP431 TRUC ("version 3") transaction policy — Core's
//! `policy/truc_policy.cpp`, restricted to the single-transaction path
//! (`SingleTRUCChecks`): this mempool has no package-acceptance API
//! (`accept_tx` admits one transaction at a time), so `PackageTRUCChecks`'s
//! package-only cases — a v3 tx's parent *and* child arriving together in
//! one package — don't apply here. Sibling eviction, which might look
//! package-only at a glance, is actually triggered by `SingleTRUCChecks`
//! itself and applies to ordinary single-tx submission in Core too (gated
//! there by `m_allow_sibling_eviction`, which Core sets for normal
//! relay/RPC submission) — so it is ported.
//!
//! Core also skips these checks entirely for transactions bypassing
//! package/policy limits (`bypass_limits`, e.g. reorg re-adds); `accept_tx`
//! has no such distinction today and runs them unconditionally, same as
//! its other package limits.

use std::collections::HashSet;

use avila_consensus::hash::Txid;

/// Core's `TRUC_VERSION` — a transaction opts in by setting `nVersion`
/// to exactly 3.
pub const TRUC_VERSION: u32 = 3;
/// Core's `TRUC_ANCESTOR_LIMIT` — a TRUC tx plus its in-pool ancestors.
pub const TRUC_ANCESTOR_LIMIT: usize = 2;
/// Core's `TRUC_DESCENDANT_LIMIT` — an in-pool TRUC tx plus its
/// in-pool descendants.
pub const TRUC_DESCENDANT_LIMIT: usize = 2;
/// Core's `TRUC_MAX_VSIZE`.
pub const TRUC_MAX_VSIZE: usize = 10_000;
/// Core's `TRUC_CHILD_MAX_VSIZE` — a TRUC tx with an unconfirmed parent.
pub const TRUC_CHILD_MAX_VSIZE: usize = 1_000;

/// One in-pool parent's TRUC-relevant facts, gathered by the caller
/// (this module has no mempool access — Core's `truc_policy.cpp` free
/// functions don't either; they take pre-fetched `mempool_parents`).
pub struct ParentFacts {
    /// The parent's `nVersion`.
    pub version: u32,
    /// The parent's own in-pool ancestor count, self-inclusive — Core's
    /// `CTxMemPool::GetAncestorCount` convention (1 + its own pooled
    /// ancestors).
    pub ancestor_count: usize,
    /// Each in-pool descendant of this parent (the parent itself
    /// excluded), paired with *that descendant's* own self-inclusive
    /// ancestor count — enough to tell a plain 1-parent-1-child sibling
    /// from a deeper shape (possible after a reorg) without this pure
    /// function re-querying the mempool.
    pub descendants: Vec<(Txid, usize)>,
}

/// Outcome of [`single_truc_checks`].
pub enum TrucOutcome {
    /// Every applicable rule was satisfied.
    Ok,
    /// A rule failed outright — no sibling eviction applies.
    Reject(&'static str),
    /// The only violation is the 1-child limit, and the parent's sole
    /// extra descendant sits in the simple, non-reorg 1-parent-1-child
    /// shape Core requires before offering opportunistic eviction — the
    /// caller may retry treating `sibling` as an additional RBF conflict
    /// (subject to the ordinary RBF fee rules), or reject using `reason`.
    ConsiderSiblingEviction {
        /// Fixed reject reason if the caller declines to evict.
        reason: &'static str,
        /// The sibling that could be evicted instead.
        sibling: Txid,
    },
}

/// Core's `SingleTRUCChecks`.
///
/// * `version` / `vsize` — the candidate's own version and sigop-
///   adjusted virtual size (`crate::virtual_size`).
/// * `parents` — the candidate's *direct* in-pool parents (not the full
///   ancestor set; TRUC's own limits are always ≤ 2 generations deep, so
///   direct parents suffice).
/// * `direct_conflicts` — txids the candidate directly double-spends
///   (its own RBF conflicts). An existing sole child that's itself one
///   of these doesn't count as a second child — this is a replacement
///   of it, not a new sibling.
#[must_use]
pub fn single_truc_checks(
    version: u32,
    vsize: usize,
    parents: &[ParentFacts],
    direct_conflicts: &HashSet<Txid>,
) -> TrucOutcome {
    // Rules 1/2: TRUC and non-TRUC unconfirmed ancestors never mix,
    // checked for every tx (not just TRUC ones).
    for parent in parents {
        if version != TRUC_VERSION && parent.version == TRUC_VERSION {
            return TrucOutcome::Reject("non-version=3 tx cannot spend from version=3 tx");
        }
        if version == TRUC_VERSION && parent.version != TRUC_VERSION {
            return TrucOutcome::Reject("version=3 tx cannot spend from non-version=3 tx");
        }
    }

    // The remaining rules only apply to TRUC transactions themselves.
    if version != TRUC_VERSION {
        return TrucOutcome::Ok;
    }
    if vsize > TRUC_MAX_VSIZE {
        return TrucOutcome::Reject("version=3 tx is too big");
    }
    // Rule 3: the tx's own ancestor set (including itself) is bounded.
    if parents.len() + 1 > TRUC_ANCESTOR_LIMIT {
        return TrucOutcome::Reject("tx would have too many ancestors");
    }
    let Some(parent) = parents.first() else {
        return TrucOutcome::Ok; // No unconfirmed ancestors — done.
    };
    // The parent's own ancestor count (self-inclusive) plus this tx must
    // still fit — catches a grandparent the direct-parent check above
    // can't see.
    if parent.ancestor_count + 1 > TRUC_ANCESTOR_LIMIT {
        return TrucOutcome::Reject("tx would have too many ancestors");
    }
    // Rule 5: a TRUC child (has an unconfirmed parent) is size-capped
    // tighter than a standalone TRUC tx.
    if vsize > TRUC_CHILD_MAX_VSIZE {
        return TrucOutcome::Reject("version=3 child tx is too big");
    }
    // Rule 4: the parent's descendant set (including itself, and the
    // candidate about to join it) is bounded to TRUC_DESCENDANT_LIMIT —
    // Core's `GetDescendantCount(parent) + 1 > TRUC_DESCENDANT_LIMIT`,
    // where `GetDescendantCount` is self-inclusive
    // (`descendants.len() + 1`), and the `+ 1` here is the candidate.
    let child_will_be_replaced = parent
        .descendants
        .iter()
        .any(|(id, _)| direct_conflicts.contains(id));
    if parent.descendants.len() + 2 > TRUC_DESCENDANT_LIMIT && !child_will_be_replaced {
        // Sibling eviction applies only in the exact simple shape Core
        // checks: exactly one existing child, and that child itself has
        // no further ancestors beyond this same parent (a deeper shape
        // is only reachable via a reorg, where Core also declines to
        // guess which descendant to evict).
        if let [(sibling, sibling_ancestor_count)] = parent.descendants.as_slice()
            && *sibling_ancestor_count == TRUC_ANCESTOR_LIMIT
        {
            return TrucOutcome::ConsiderSiblingEviction {
                reason: "tx would exceed descendant count limit",
                sibling: *sibling,
            };
        }
        return TrucOutcome::Reject("tx would exceed descendant count limit");
    }
    TrucOutcome::Ok
}

// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(dead_code)] // shared by multiple example targets; not all fields
// are read by every driver
//! Shared corpus-wide occurrence-record join — the Gate-4 architecture
//! used identically by the `state_join` fixture driver and the
//! `window_join` real-data driver.
//!
//!   CREATED  = {(pos=(h,txidx,vout), op, coin)}   — all window outputs
//!   SPENT    = {(pos=(h,txidx,inidx), op)}        — all window inputs
//!   BOUNDARY = authenticated pre-window coins (starting state; seeded once)
//!
//!   partition by outpoint → order events by pos → merge-walk
//!   `alive = (BOUNDARY ∪ created-before) ∖ spent-before`:
//!     creation while alive          → DupCreation @ pos   (BIP30)
//!     spend while !alive, consumed  → DupSpend @ pos      (known double spend)
//!     spend while !alive, !consumed → Missing @ pos       (unknown provenance)
//!     otherwise                     → resolves to the live coin
//!   conflicting boundary specs for the same outpoint → BoundaryConflict.

use avila_consensus::connect::Coin;
use avila_consensus::transaction::OutPoint;
use std::collections::HashMap;

/// Occurrence position: (block height, tx index in block, index in tx).
/// `idx` is the output index for creations, the input index for spends.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Occ {
    pub h: u32,
    pub tx: u32,
    pub idx: u32,
}

#[derive(Clone)]
pub struct Creation {
    pub pos: Occ,
    pub op: OutPoint,
    pub coin: Coin,
}

#[derive(Clone)]
pub struct Spend {
    pub pos: Occ,
    pub op: OutPoint,
}

/// How a spend at a given occurrence position resolved.
#[derive(Clone)]
pub enum JoinRes {
    /// The spend's outpoint was live at its position; carries the coin.
    Coin(Coin),
    /// Never alive at that position — absent from boundary and from every
    /// earlier creation. Unknown provenance (partial-coverage class).
    Missing,
    /// Was live but an EARLIER spend consumed it — a known double spend.
    /// Carries the earlier spend's position for diagnostics.
    DupSpend(Occ),
    /// Multiple distinct boundary coins were supplied for this outpoint —
    /// the supplied state is internally inconsistent.
    BoundaryConflict,
}

/// A creation-side violation (BIP30-class: created while already live).
#[derive(Clone, Debug)]
pub enum JoinViolation {
    DupCreation,
}

pub struct JoinReport {
    /// spend pos → resolution
    pub resolved: HashMap<Occ, JoinRes>,
    /// violations at creation positions, sorted
    pub violations: Vec<(Occ, JoinViolation)>,
    /// boundary coins supplied more than once with different payloads
    pub boundary_conflicts: usize,
    /// spends classified as known double spends (for diagnostics)
    pub dup_spends: usize,
    /// spends with unknown provenance (missing; coverage class, not
    /// necessarily invalidity)
    pub missing_spends: usize,
    /// earliest spend position resolving `Missing` (first missing-spend
    /// height for diagnostics; under a complete supplied boundary this
    /// is the earliest known-invalid position)
    pub first_missing: Option<Occ>,
}

/// The shared merge-join. `boundary` is the supplied starting state;
/// `created`/`spends` are the whole window's occurrence ledgers.
/// `conflicted` lists outpoints whose boundary specs disagreed — spends
/// of those resolve as `BoundaryConflict` (known invalidity, never Coin).
/// Boundary coins are seeded exactly once per outpoint; a second spend of
/// a boundary coin resolves as `DupSpend`, not `Coin` again.
pub fn join_window(
    created: &[Creation],
    spends: &[Spend],
    boundary: &HashMap<OutPoint, Coin>,
    conflicted: &std::collections::HashSet<OutPoint>,
) -> JoinReport {
    let mut created_by_op: HashMap<OutPoint, Vec<usize>> = HashMap::new();
    for (k, c) in created.iter().enumerate() {
        created_by_op.entry(c.op).or_default().push(k);
    }
    let mut spends_by_op: HashMap<OutPoint, Vec<usize>> = HashMap::new();
    for (k, s) in spends.iter().enumerate() {
        spends_by_op.entry(s.op).or_default().push(k);
    }
    let mut resolved: HashMap<Occ, JoinRes> = HashMap::new();
    let mut violations: Vec<(Occ, JoinViolation)> = Vec::new();
    let mut keys: std::collections::HashSet<OutPoint> = created_by_op.keys().copied().collect();
    keys.extend(spends_by_op.keys().copied());
    keys.extend(boundary.keys().copied());
    let mut dup_spends = 0usize;
    let mut missing_spends = 0usize;
    let mut first_missing: Option<Occ> = None;
    for op in keys {
        let mut events: Vec<(Occ, bool, usize)> = Vec::new();
        for &k in created_by_op.get(&op).map(Vec::as_slice).unwrap_or(&[]) {
            events.push((created[k].pos, true, k));
        }
        for &k in spends_by_op.get(&op).map(Vec::as_slice).unwrap_or(&[]) {
            events.push((spends[k].pos, false, k));
        }
        events.sort_by_key(|a| a.0);
        // Boundary seed: exactly once. An op that starts alive is
        // consumed by its first spend; a second spend is a DupSpend.
        let mut alive = boundary.contains_key(&op);
        let mut boundary_coin: Option<&Coin> = boundary.get(&op);
        let mut consumed = false;
        for (pos, is_creation, _k) in events {
            if is_creation {
                if alive {
                    violations.push((pos, JoinViolation::DupCreation));
                }
                alive = true;
            } else {
                if !alive {
                    if consumed {
                        resolved.insert(pos, JoinRes::DupSpend(pos));
                        dup_spends += 1;
                    } else if conflicted.contains(&op) {
                        resolved.insert(pos, JoinRes::BoundaryConflict);
                    } else {
                        resolved.insert(pos, JoinRes::Missing);
                        missing_spends += 1;
                        if first_missing.is_none_or(|f| pos < f) {
                            first_missing = Some(pos);
                        }
                    }
                } else {
                    // Latest in-window creation before pos, else the
                    // boundary coin (re-creation always out-positions the
                    // boundary seed since boundary records have no pos).
                    let coin = created_by_op
                        .get(&op)
                        .into_iter()
                        .flat_map(|v| v.iter())
                        .filter(|&&k| created[k].pos < pos)
                        .max_by_key(|&&k| created[k].pos)
                        .map(|&k| created[k].coin.clone())
                        .or_else(|| boundary_coin.take().cloned())
                        .expect("alive implies a coin exists");
                    resolved.insert(pos, JoinRes::Coin(coin));
                    consumed = true;
                }
                alive = false;
            }
        }
    }
    violations.sort_by_key(|(p, _)| *p);
    JoinReport {
        resolved,
        violations,
        boundary_conflicts: 0, // set by the boundary builder
        dup_spends,
        missing_spends,
        first_missing,
    }
}

/// Build the boundary map from per-spend resolved pre-window sources.
/// Each distinct (OutPoint → coin payload) must be unique; conflicting
/// specs for the same outpoint are recorded as conflicts and that
/// outpoint is EXCLUDED from the boundary (cannot be trusted).
pub fn build_boundary(
    specs: impl Iterator<Item = (OutPoint, Coin)>,
) -> (
    HashMap<OutPoint, Coin>,
    usize,
    std::collections::HashSet<OutPoint>,
) {
    let mut boundary: HashMap<OutPoint, Coin> = HashMap::new();
    let mut conflicts: std::collections::HashSet<OutPoint> = std::collections::HashSet::new();
    for (op, coin) in specs {
        match boundary.get(&op) {
            None => {
                boundary.insert(op, coin);
            }
            Some(existing) => {
                if existing.out != coin.out
                    || existing.height != coin.height
                    || existing.coinbase != coin.coinbase
                {
                    conflicts.insert(op);
                }
            }
        }
    }
    for op in &conflicts {
        boundary.remove(op);
    }
    (boundary, conflicts.len(), conflicts)
}

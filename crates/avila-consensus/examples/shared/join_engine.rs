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
use avila_consensus::transaction::{OutPoint, Script, TxOut};
use std::collections::HashMap;

/// Boundary lookup abstraction. At mainnet scale a complete starting
/// state holds tens of millions of coins — too many for a `HashMap`'s
/// per-entry overhead on small machines, so drivers may supply either a
/// [`HashMap`] (small corpus-derived boundaries) or a [`FlatBoundary`]
/// (complete `dumptxoutset` states) behind this interface.
pub trait BoundaryView {
    /// Whether the outpoint exists in the starting state.
    fn b_contains(&self, op: &OutPoint) -> bool;
    /// The boundary coin for `op`, if present.
    fn b_get(&self, op: &OutPoint) -> Option<Coin>;
    /// Number of records in the starting state.
    fn b_len(&self) -> usize;
}

impl BoundaryView for HashMap<OutPoint, Coin> {
    fn b_contains(&self, op: &OutPoint) -> bool {
        self.contains_key(op)
    }
    fn b_get(&self, op: &OutPoint) -> Option<Coin> {
        self.get(op).cloned()
    }
    fn b_len(&self) -> usize {
        self.len()
    }
}

/// One flat coin record — 64 bytes, stored in a single sorted vec.
/// Scripts live in one shared append-only blob (`spk_off`/`spk_len`).
struct BRec {
    txid: [u8; 32],
    vout: u32,
    value: i64,
    code: u32, // height << 1 | coinbase
    spk_off: u64,
    spk_len: u32,
}

/// Flat starting state sorted by `(txid, vout)`: ~64 bytes per coin
/// inline plus one shared script blob — versus ~150 bytes/entry in a
/// `HashMap`, and no rehash-doubling transient while building (the vec
/// is pre-sized once and sorted in place). Lookups are binary searches;
/// the sorted layout feeds the canonical export without a second sort.
pub struct FlatBoundary {
    recs: Vec<BRec>,
    spk_blob: Vec<u8>,
    alive: Vec<u64>, // bitmask, one bit per record
}

/// Streaming builder for [`FlatBoundary`] — the `for_each_coin`
/// callback feeds `push` directly, so the compact record vec is the only
/// intermediate structure (no per-coin `Coin`/map overhead).
pub struct FlatBuilder {
    recs: Vec<BRec>,
    spk_blob: Vec<u8>,
}

impl FlatBuilder {
    /// `expected` pre-sizes the table — pass the snapshot's declared coin
    /// count so the ~3 GB record vec never doubles mid-fill.
    pub fn new(expected: usize) -> Self {
        Self {
            recs: Vec::with_capacity(expected.min(1 << 26)),
            spk_blob: Vec::with_capacity(expected.saturating_mul(28).min(1 << 31)),
        }
    }

    /// Append one raw coin record (`code` is `height << 1 | coinbase`,
    /// the snapshot's native encoding — bounded far below u32).
    pub fn push(&mut self, txid: [u8; 32], vout: u32, value: i64, code: u64, spk: &[u8]) {
        let off = self.spk_blob.len() as u64;
        self.spk_blob.extend_from_slice(spk);
        self.recs.push(BRec {
            txid,
            vout,
            value,
            code: u32::try_from(code).expect("coin code fits u32"),
            spk_off: off,
            spk_len: spk.len() as u32,
        });
    }

    /// Sort in place and count outpoints supplied more than once
    /// (adjacent-equal `(txid, vout)` pairs after the sort). Duplicate
    /// records are kept — the caller treats `dups > 0` as malformed
    /// input and aborts, so they never reach the live path.
    pub fn finish(mut self) -> (FlatBoundary, usize) {
        self.recs.sort_unstable_by_key(|r| (r.txid, r.vout));
        let n = self.recs.len();
        let mut dups = 0usize;
        for w in self.recs.windows(2) {
            if w[0].txid == w[1].txid && w[0].vout == w[1].vout {
                dups += 1;
            }
        }
        let words = n.div_ceil(64);
        (
            FlatBoundary {
                recs: self.recs,
                spk_blob: self.spk_blob,
                alive: vec![u64::MAX; words],
            },
            dups,
        )
    }
}

impl FlatBoundary {
    /// Consume a HashMap boundary into the flat layout (corpus-derived
    /// boundaries are small — this is just representation unification
    /// so stage E has a single materialization path).
    pub fn from_map(map: HashMap<OutPoint, Coin>, expected: usize) -> Self {
        let mut b = FlatBuilder::new(expected);
        for (op, c) in map {
            b.push(
                *op.txid.as_bytes(),
                op.vout,
                c.out.value,
                u64::from(c.height << 1) | u64::from(c.coinbase),
                c.out.script_pubkey.as_bytes(),
            );
        }
        b.finish().0
    }

    /// Binary-search index of `op` if present.
    pub fn find(&self, txid: &[u8; 32], vout: u32) -> Option<usize> {
        let lo = self
            .recs
            .partition_point(|r| (r.txid, r.vout) < (*txid, vout));
        (lo < self.recs.len() && self.recs[lo].txid == *txid && self.recs[lo].vout == vout)
            .then_some(lo)
    }

    /// Clear the alive bit for record `i` (a spend consumed it).
    pub fn kill(&mut self, i: usize) {
        self.alive[i / 64] &= !(1u64 << (i % 64));
    }

    /// Whether record `i` is still live.
    pub fn is_alive(&self, i: usize) -> bool {
        self.alive[i / 64] & (1u64 << (i % 64)) != 0
    }

    /// Record fields by index (allocates the script).
    pub fn record(&self, i: usize) -> ([u8; 32], u32, Coin) {
        let (t, v, val, code, spk) = self.record_raw(i);
        (
            t,
            v,
            Coin {
                out: TxOut {
                    value: val,
                    script_pubkey: Script::new(spk.to_vec()),
                },
                height: code >> 1,
                coinbase: code & 1 != 0,
            },
        )
    }

    /// Iterate `i` in sorted order while record `i` is still live —
    /// the canonical export's boundary side.
    pub fn alive_indices(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.recs.len()).filter(|&i| self.is_alive(i))
    }

    /// Raw record fields by index without allocating — `(txid, vout,
    /// value, code, spk)` borrowing the script blob.
    pub fn record_raw(&self, i: usize) -> ([u8; 32], u32, i64, u32, &[u8]) {
        let r = &self.recs[i];
        let s = r.spk_off as usize;
        (
            r.txid,
            r.vout,
            r.value,
            r.code,
            &self.spk_blob[s..s + r.spk_len as usize],
        )
    }

    /// Record count.
    pub fn txids_len(&self) -> usize {
        self.recs.len()
    }
}

impl BoundaryView for FlatBoundary {
    fn b_contains(&self, op: &OutPoint) -> bool {
        self.find(op.txid.as_bytes(), op.vout).is_some()
    }
    fn b_get(&self, op: &OutPoint) -> Option<Coin> {
        self.find(op.txid.as_bytes(), op.vout)
            .map(|i| self.record(i).2)
    }
    fn b_len(&self) -> usize {
        self.recs.len()
    }
}

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
pub fn join_window<B: BoundaryView>(
    created: &[Creation],
    spends: &[Spend],
    boundary: &B,
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
    // Only ops with in-window events can produce resolutions or
    // violations — a boundary coin never touched contributes nothing, so
    // iterating every boundary key would be wasted work (and would force
    // enumeration APIs that flat tables don't need).
    let mut keys: std::collections::HashSet<OutPoint> = created_by_op.keys().copied().collect();
    keys.extend(spends_by_op.keys().copied());
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
        let mut alive = boundary.b_contains(&op);
        let mut boundary_coin: Option<Coin> = boundary.b_get(&op);
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
                        .or_else(|| boundary_coin.take())
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

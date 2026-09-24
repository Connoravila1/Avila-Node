//! BIP9 versionbits state evaluation — Core's `versionbits.cpp`
//! (`BIP9StateMachine::GetStateFor`, `GetStateSinceHeightFor`,
//! `GetStateStatisticsFor`) over our [`HeaderTree`].
//!
//! A block's deployment state is evaluated against the *previous* block:
//! `state(tree, Some(hash))` answers "which state governs the child of
//! `hash`", matching `chainman.m_versionbitscache.State(pindexPrev)`.
//! Transitions are evaluated only at window boundaries — the ancestor at
//! `h - ((h + 1) % period)` — exactly like Core.

use crate::chain::HeaderTree;
use crate::hash::BlockHash;
use crate::params::{BIP9_ALWAYS_ACTIVE, BIP9_NEVER_ACTIVE, Bip9Deployment, Params};

/// `Consensus::ThresholdState`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bip9State {
    /// `DEFINED` — not yet started (or pre-start-time).
    Defined,
    /// `STARTED` — signalling window in progress.
    Started,
    /// `LOCKED_IN` — threshold met, activation pending.
    LockedIn,
    /// `ACTIVE` — rules enforced.
    Active,
    /// `FAILED` — timed out without locking in.
    Failed,
}

impl Bip9State {
    /// The lowercase name `getdeploymentinfo` emits.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Defined => "defined",
            Self::Started => "started",
            Self::LockedIn => "locked_in",
            Self::Active => "active",
            Self::Failed => "failed",
        }
    }
}

/// The versionbit check — Core's `Condition`: top bits must equal
/// `VERSIONBITS_TOP_BITS` and the deployment's bit must be set.
fn signals(header: &crate::header::BlockHeader, bit: i32) -> bool {
    const TOP_MASK: i64 = 0xE000_0000;
    const TOP_BITS: i64 = 0x2000_0000;
    let v = i64::from(header.version) & 0xFFFF_FFFF;
    (v & TOP_MASK) == TOP_BITS && (v >> bit) & 1 == 1
}

/// `GetStateFor(pindexPrev)`: the state governing the window the child of
/// `prev` belongs to. `None` (no parent) is DEFINED, like Core's
/// `cache[nullptr] = DEFINED`.
#[must_use]
pub fn state(
    tree: &HeaderTree,
    prev: Option<&BlockHash>,
    dep: &Bip9Deployment,
    params: &Params,
) -> Bip9State {
    if dep.start_time == BIP9_ALWAYS_ACTIVE {
        return Bip9State::Active;
    }
    if dep.start_time == BIP9_NEVER_ACTIVE {
        return Bip9State::Failed;
    }
    let period = params.difficulty_adjustment_interval() as u32;
    let threshold = params.rule_change_activation_threshold;

    // Align `prev` down to the last block of its completed window.
    let mut cursor = prev.and_then(|h| tree.get(h)).and_then(|n| {
        let back = (n.height + 1) % period;
        n.height
            .checked_sub(back)
            .and_then(|h| tree.get_ancestor(&n.hash(), h))
    });

    // Walk back one window at a time until a known state — genesis or
    // pre-start-time — then replay forward.
    let mut to_compute: Vec<&crate::chain::HeaderNode> = Vec::new();
    let mut state = loop {
        let Some(n) = cursor else {
            break Bip9State::Defined;
        };
        if i64::from(tree.median_time_past(&n.hash()).unwrap_or(0)) < dep.start_time {
            break Bip9State::Defined;
        }
        to_compute.push(n);
        cursor = n
            .height
            .checked_sub(period)
            .and_then(|h| tree.get_ancestor(&n.hash(), h));
    };

    for &n in to_compute.iter().rev() {
        let mtp = i64::from(tree.median_time_past(&n.hash()).unwrap_or(0));
        state = match state {
            // Post-Speedy-Trial order (Core v31.1 versionbits.cpp):
            // DEFINED only ever checks the start time — even a window
            // that opens already past the deadline still spends one
            // period as STARTED before FAILED can be reached. There is
            // no direct DEFINED → FAILED transition.
            Bip9State::Defined if mtp >= dep.start_time => Bip9State::Started,
            Bip9State::Started => {
                // Threshold first — a window that both meets the
                // signalling threshold and is past the timeout still
                // locks in; Core's STARTED arm only falls through to
                // the timeout check when the count comes up short.
                let mut count = 0u32;
                let mut c = Some(n);
                for _ in 0..period {
                    let Some(node) = c else { break };
                    if signals(&node.header, dep.bit) {
                        count += 1;
                    }
                    c = tree.get(&node.header.prev_block_hash);
                }
                if count >= threshold {
                    Bip9State::LockedIn
                } else if mtp >= dep.timeout {
                    Bip9State::Failed
                } else {
                    state
                }
            }
            Bip9State::LockedIn if n.height + 1 >= dep.min_activation_height => Bip9State::Active,
            s => s,
        };
    }
    state
}

/// `GetStateSinceHeightFor`: the height at which the current state began.
/// Always/never-active deployments and DEFINED report 0.
#[must_use]
pub fn state_since(
    tree: &HeaderTree,
    prev: Option<&BlockHash>,
    dep: &Bip9Deployment,
    params: &Params,
) -> u32 {
    if dep.start_time == BIP9_ALWAYS_ACTIVE || dep.start_time == BIP9_NEVER_ACTIVE {
        return 0;
    }
    let initial = state(tree, prev, dep, params);
    if initial == Bip9State::Defined {
        return 0;
    }
    let period = params.difficulty_adjustment_interval() as u32;
    let Some(first) = prev.and_then(|h| tree.get(h)).and_then(|n| {
        let back = (n.height + 1) % period;
        n.height
            .checked_sub(back)
            .and_then(|h| tree.get_ancestor(&n.hash(), h))
    }) else {
        return 0;
    };
    // Walk back while the previous window reports the same state; the
    // since-height is the first block *after* the earliest matching
    // window's parent.
    let mut cursor = first;
    while let Some(pp) = cursor
        .height
        .checked_sub(period)
        .and_then(|h| tree.get_ancestor(&cursor.hash(), h))
    {
        if state(tree, Some(&pp.hash()), dep, params) != initial {
            break;
        }
        cursor = pp;
    }
    cursor.height + 1
}

/// `BIP9Stats` + the signalling string for `statistics`/`signalling` —
/// emitted only while `status` is `started` or `locked_in`.
#[derive(Clone, Debug)]
pub struct Bip9Stats {
    /// Window length in blocks.
    pub period: u32,
    /// Height of the first block of the queried window (Core 29.x emits
    /// this as `period_start`).
    pub period_start: u32,
    /// Blocks evaluated so far this window.
    pub elapsed: u32,
    /// Signalling blocks among them.
    pub count: u32,
    /// The required count.
    pub threshold: u32,
    /// Whether enough blocks remain to reach the threshold.
    pub possible: bool,
    /// Per-block signal flags, window-start first (`#`/`-` chars).
    pub signalling: Vec<bool>,
}

/// `GetStateStatisticsFor(pindex)` — counts within the window containing
/// the queried block itself.
#[must_use]
pub fn stats(
    tree: &HeaderTree,
    at: &BlockHash,
    dep: &Bip9Deployment,
    params: &Params,
) -> Bip9Stats {
    let period = params.difficulty_adjustment_interval() as u32;
    let threshold = params.rule_change_activation_threshold;
    let mut out = Bip9Stats {
        period,
        period_start: 0,
        threshold,
        elapsed: 0,
        count: 0,
        possible: false,
        signalling: Vec::new(),
    };
    let Some(mut node) = tree.get(at) else {
        return out;
    };
    out.period_start = node.height - (node.height % period);
    let blocks_in_period = 1 + (node.height % period);
    out.signalling = vec![false; blocks_in_period as usize];
    let mut remaining = blocks_in_period;
    loop {
        out.elapsed += 1;
        remaining -= 1;
        if signals(&node.header, dep.bit) {
            out.count += 1;
            out.signalling[remaining as usize] = true;
        }
        if remaining == 0 {
            break;
        }
        let Some(parent) = tree.get(&node.header.prev_block_hash) else {
            break;
        };
        node = parent;
    }
    out.possible = period - threshold >= out.elapsed - out.count;
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::arith::U256;
    use crate::chain::HeaderNode;
    use crate::header::BlockHeader;
    use crate::params::Network;
    use crate::pow;

    /// Regtest params with a trivially satisfiable PoW limit so test
    /// headers mint with a nonce scan instead of real mining. The
    /// deployment under test is slot 0 (`testdummy`, bit 28).
    fn params() -> Params {
        let mut p = Network::Regtest.params();
        p.pow_limit = crate::arith::Target(U256::MAX);
        p.allow_min_difficulty_blocks = false;
        p
    }

    /// Grinds a nonce until the header meets `bits` — identical to the
    /// `mint` helper in `chain::tests` (kept private per module).
    fn mint(
        parent: &HeaderNode,
        params: &Params,
        version: i32,
        time: u32,
        nonce_hint: u32,
    ) -> BlockHeader {
        for nonce in nonce_hint..u32::MAX {
            let h = BlockHeader {
                version,
                prev_block_hash: parent.hash(),
                merkle_root: parent.header.merkle_root,
                time,
                bits: parent.header.bits,
                nonce,
            };
            if pow::check_proof_of_work(&h.hash(), h.bits, params).is_ok() {
                return h;
            }
        }
        panic!("no nonce satisfied the target");
    }

    /// Builds `n` children on `tree` starting from its tip; `version`
    /// and `time` are per-block (`time` = genesis_time + height·spacing).
    fn grow(
        tree: &mut HeaderTree,
        params: &Params,
        n: usize,
        version: i32,
        spacing: u32,
    ) -> Vec<BlockHash> {
        let t0 = tree.tip().header.time;
        let mut hashes = Vec::with_capacity(n);
        for i in 1..=n {
            let parent = *tree.tip();
            let h = mint(&parent, params, version, t0 + i as u32 * spacing, i as u32);
            tree.insert(&h, u32::MAX).unwrap();
            hashes.push(h.hash());
        }
        hashes
    }

    const SIGNALLING: i32 = 0x2000_0000 | (1 << 28);
    const QUIET: i32 = 0x2000_0000;

    /// The full regtest lifecycle: DEFINED through the first window,
    /// STARTED once it closes, LOCKED_IN after a signalling window, and
    /// ACTIVE the window after that (min_activation_height 0).
    #[test]
    fn state_progresses_through_windows() {
        let p = params();
        let dep = p.bip9_deployments[0]; // testdummy: bit 28, start 0, no timeout
        let mut tree = HeaderTree::new(p);

        // Window 0 not yet closed → DEFINED for the child of h142…
        let hs = grow(&mut tree, &p, 144, SIGNALLING, 600);
        assert_eq!(state(&tree, Some(&hs[141]), &dep, &p), Bip9State::Defined);
        // …but at h143 the window [0,143] closed with MTP ≥ 0 → STARTED.
        assert_eq!(state(&tree, Some(&hs[142]), &dep, &p), Bip9State::Started);
        assert_eq!(state_since(&tree, Some(&hs[142]), &dep, &p), 144);

        // Mid-window queries report the open window's statistics: h144
        // is the first block of window 1, elapsed = count = 1.
        let s = stats(&tree, &hs[143], &dep, &p);
        assert_eq!(
            (s.period, s.period_start, s.elapsed, s.count),
            (144, 144, 1, 1)
        );
        assert!(s.possible);

        // Fill the rest of window 1 with signallers → LOCKED_IN at h287.
        let hs3 = grow(&mut tree, &p, 143, SIGNALLING, 600);
        assert_eq!(state(&tree, Some(&hs3[142]), &dep, &p), Bip9State::LockedIn);
        assert_eq!(state_since(&tree, Some(&hs3[142]), &dep, &p), 288);

        // One more window → ACTIVE at h431 (min_activation_height 0).
        let hs4 = grow(&mut tree, &p, 144, QUIET, 600);
        assert_eq!(state(&tree, Some(&hs4[143]), &dep, &p), Bip9State::Active);
        assert_eq!(state_since(&tree, Some(&hs4[143]), &dep, &p), 432);
    }

    /// STARTED → FAILED when the deadline passes without reaching the
    /// threshold: Core counts signalling first and only falls through
    /// to the timeout check when the count comes up short, so a
    /// window that never signals at all still fails once past the
    /// deadline.
    #[test]
    fn timeout_fails_from_started() {
        let mut p = params();
        let t0 = p.genesis_header.time;
        // Deadline falls inside window 1: MTP(h143) is below it,
        // MTP(h287) is above it.
        p.bip9_deployments[0].timeout = i64::from(t0) + 200 * 600;
        let dep = p.bip9_deployments[0];
        let mut tree = HeaderTree::new(p);
        let hs = grow(&mut tree, &p, 288, QUIET, 600);
        // Window 0 closed in STARTED…
        assert_eq!(state(&tree, Some(&hs[143]), &dep, &p), Bip9State::Started);
        // …and window 1 closed past the timeout with no signalling → FAILED at h287.
        assert_eq!(state(&tree, Some(&hs[287]), &dep, &p), Bip9State::Failed);
        assert_eq!(state_since(&tree, Some(&hs[287]), &dep, &p), 288);
    }

    /// STARTED → LOCKED_IN, not FAILED, when the final window both
    /// meets the threshold and closes past the timeout: Core's
    /// Speedy-Trial order checks the threshold before the timeout, so
    /// reaching it wins even in the deployment's last eligible window.
    #[test]
    fn threshold_wins_over_timeout_in_final_window() {
        let mut p = params();
        let t0 = p.genesis_header.time;
        // Same deadline placement as `timeout_fails_from_started` —
        // inside window 1 — but this window signals unanimously.
        p.bip9_deployments[0].timeout = i64::from(t0) + 200 * 600;
        let dep = p.bip9_deployments[0];
        let mut tree = HeaderTree::new(p);
        let hs = grow(&mut tree, &p, 144, QUIET, 600);
        assert_eq!(state(&tree, Some(&hs[143]), &dep, &p), Bip9State::Started);
        let hs2 = grow(&mut tree, &p, 144, SIGNALLING, 600);
        // Window 1 closes past the timeout, but every block signalled:
        // the threshold check wins → LOCKED_IN, not FAILED.
        assert_eq!(state(&tree, Some(&hs2[143]), &dep, &p), Bip9State::LockedIn);
    }

    /// `min_activation_height` holds ACTIVE back past LOCKED_IN until a
    /// window ends at or above the floor.
    #[test]
    fn min_activation_height_delays_active() {
        let mut p = params();
        p.bip9_deployments[0].min_activation_height = 500;
        let dep = p.bip9_deployments[0];
        let mut tree = HeaderTree::new(p);
        // Three signalling windows: STARTED@144, LOCKED_IN@288, and the
        // h431 boundary stays LOCKED_IN since 432 < 500.
        let hs = grow(&mut tree, &p, 432, SIGNALLING, 600);
        assert_eq!(state(&tree, Some(&hs[431]), &dep, &p), Bip9State::LockedIn);
        // The next window end (h575) is the first at/above 500 → ACTIVE.
        let hs2 = grow(&mut tree, &p, 144, QUIET, 600);
        assert_eq!(state(&tree, Some(&hs2[143]), &dep, &p), Bip9State::Active);
        assert_eq!(state_since(&tree, Some(&hs2[143]), &dep, &p), 576);
    }

    /// Sentinel deployments short-circuit the machine entirely.
    #[test]
    fn always_and_never_active() {
        let p = params();
        let taproot = p.bip9_deployments[1]; // ALWAYS_ACTIVE
        assert_eq!(state(&tree_new(&p), None, &taproot, &p), Bip9State::Active);
        let mut p2 = p;
        p2.bip9_deployments[0].start_time = BIP9_NEVER_ACTIVE;
        let dep = p2.bip9_deployments[0];
        assert_eq!(state(&tree_new(&p2), None, &dep, &p2), Bip9State::Failed);
        assert_eq!(state_since(&tree_new(&p2), None, &dep, &p2), 0);
    }

    fn tree_new(p: &Params) -> HeaderTree {
        HeaderTree::new(*p)
    }

    /// Only `0x2000_0000` top bits with the deployment bit set count:
    /// version 4 and top-bits-only headers are ignored by `signals`.
    #[test]
    fn signalling_requires_top_bits_and_bit() {
        let p = params();
        let dep = p.bip9_deployments[0];
        let mut tree = HeaderTree::new(p);
        // Two quiet windows → STARTED with no signallers anywhere.
        let hs = grow(&mut tree, &p, 288, QUIET, 600);
        // At window end h287 the full period was evaluated: count 0 of
        // 144 elapsed leaves no room to reach the threshold.
        let s = stats(&tree, &hs[286], &dep, &p);
        assert_eq!((s.count, s.elapsed), (0, 144));
        assert!(!s.possible);
        // And with 0 of 144 signalled, window 1 never locked in — the
        // deployment sits in STARTED (no timeout on regtest testdummy).
        assert_eq!(state(&tree, Some(&hs[287]), &dep, &p), Bip9State::Started);
    }
}

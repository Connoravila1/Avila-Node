//! Contextual header rules: the timestamp bounds a block must satisfy given its position in
//! the chain — the median-time-past floor and the future-drift ceiling.
//!
//! Mirrors `CBlockIndex::GetMedianTimePast` (`chain.h`/`chain.cpp`) and the two timestamp
//! predicates of `ContextualCheckBlockHeader` (`validation.cpp`, `time-too-old` /
//! `time-too-new`). Time is always an explicit input here: callers supply the adjusted local
//! time (what Core calls `GetAdjustedTime()`), keeping this crate free of clock I/O.

use thiserror::Error;

/// `chain.h`'s `nMedianTimeSpan`: the number of most-recent block times that feed the
/// median-time-past computation.
pub const MEDIAN_TIME_SPAN: usize = 11;

/// `chain.h`'s `MAX_FUTURE_BLOCK_TIME`: how far beyond adjusted local time a block's
/// timestamp may drift before it is rejected — two hours.
pub const MAX_FUTURE_BLOCK_TIME: u32 = 2 * 60 * 60;

/// `validation.cpp`'s `MAX_TIMEWARP`: under BIP94 (testnet4) the first block of each
/// difficulty-adjustment period must have `nTime` no earlier than its parent's `nTime`
/// minus this many seconds — 600 — so a miner cannot jump the period-ending timestamp far
/// into the past to force the difficulty down.
pub const MAX_TIMEWARP: u32 = 600;

/// Core's `CBlockIndex::GetMedianTimePast`: the median of the most recent
/// [`MEDIAN_TIME_SPAN`] block times ending at (and including) the given tip.
///
/// `times` must be newest-first — element 0 is the tip's own `nTime`, element 1 its
/// parent's, and so on; only the first `MEDIAN_TIME_SPAN` entries are considered. For an
/// even count Core's `pmedian[num/2]` picks the *upper* of the two middle values (so the
/// median of 2 values is the larger one) — replicated here. An empty `times` yields `0`;
/// Core never calls this without a real `pindex`, so the case cannot arise on a genuine
/// chain.
#[must_use]
pub fn median_time_past(times: &[u32]) -> u32 {
    let take = times.len().min(MEDIAN_TIME_SPAN);
    let mut sorted = [0u32; MEDIAN_TIME_SPAN];
    sorted[..take].copy_from_slice(&times[..take]);
    sorted[..take].sort_unstable();
    sorted[take / 2]
}

/// Ways a block's timestamp can violate the contextual time rules.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum TimeError {
    /// `block.nTime <= pindexPrev->GetMedianTimePast()` — Core's `time-too-old`.
    #[error(
        "block time {time} is not greater than the parent chain's median time past {median_past}"
    )]
    TooOld {
        /// The offending `nTime`.
        time: u32,
        /// The parent chain's median time past.
        median_past: u32,
    },
    /// `block.nTime < pindexPrev->nTime - MAX_TIMEWARP` on a difficulty-period's first
    /// block under BIP94 — Core's `time-timewarp-attack`.
    #[error("block time {time} is below the timewarp floor {min_time} (parent time - 600)")]
    Timewarp {
        /// The offending `nTime`.
        time: u32,
        /// The earliest permitted `nTime`: the parent's `nTime` minus
        /// [`MAX_TIMEWARP`].
        min_time: u32,
    },
    /// `block.nTime > nAdjustedTime + MAX_FUTURE_BLOCK_TIME` — Core's `time-too-new`.
    #[error(
        "block time {time} is more than MAX_FUTURE_BLOCK_TIME beyond adjusted local time {now}"
    )]
    TooNew {
        /// The offending `nTime`.
        time: u32,
        /// The adjusted local time the comparison used.
        now: u32,
    },
}

/// The timestamp predicates of Core's `ContextualCheckBlockHeader` (`validation.cpp`):
///
/// * `time` must be strictly greater than the parent chain's median time past
///   (`time-too-old`);
/// * if `timewarp_min` is `Some` — the BIP94 rule applying to the first block of each
///   difficulty period on `enforce_BIP94` networks — `time` must be at least that floor
///   (the parent's `nTime` minus [`MAX_TIMEWARP`]; `time-timewarp-attack`); and
/// * `time` must not exceed `now + MAX_FUTURE_BLOCK_TIME` (`time-too-new`).
///
/// The checks run in Core's order: `time-too-old`, `time-timewarp-attack`, then
/// `time-too-new`. Callers on non-BIP94 networks, or at non-boundary heights, pass `None`
/// for `timewarp_min`; [`crate::chain::HeaderTree::insert`] derives it.
///
/// `now` is the caller's adjusted local time — the equivalent of Core's `GetAdjustedTime()`,
/// which a node derives from its clock plus a network median offset. This crate performs no
/// clock or network I/O, so the value is always an explicit input.
///
/// # Errors
///
/// Returns the first failing [`TimeError`], in Core's predicate order.
pub fn check_block_time(
    time: u32,
    median_past: u32,
    now: u32,
    timewarp_min: Option<u32>,
) -> Result<(), TimeError> {
    if time <= median_past {
        return Err(TimeError::TooOld { time, median_past });
    }
    if let Some(min_time) = timewarp_min
        && time < min_time
    {
        return Err(TimeError::Timewarp { time, min_time });
    }
    if u64::from(time) > u64::from(now) + u64::from(MAX_FUTURE_BLOCK_TIME) {
        return Err(TimeError::TooNew { time, now });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn median_of_single_time_is_itself() {
        assert_eq!(median_time_past(&[123]), 123);
    }

    #[test]
    fn median_uses_only_the_newest_11() {
        // 12 entries: the oldest (index 11) must be ignored.
        let times: Vec<u32> = (100..=111).rev().collect();
        assert_eq!(times.len(), 12);
        // The newest 11 are 101..=111; sorted median index 5 → 106.
        assert_eq!(median_time_past(&times), 106);
    }

    #[test]
    fn median_of_even_count_picks_upper_middle() {
        // Core's `pmedian[num/2]`: for 10 values sorted ascending, index 5 — the larger of
        // the two middle values.
        let times: Vec<u32> = (1..=10).rev().collect();
        assert_eq!(median_time_past(&times), 6);
        // And for 2 values, the larger.
        assert_eq!(median_time_past(&[5, 9]), 9);
    }

    #[test]
    fn median_sorts_unordered_input() {
        assert_eq!(median_time_past(&[50, 10, 30, 20, 40]), 30);
    }

    #[test]
    fn median_of_empty_is_zero() {
        assert_eq!(median_time_past(&[]), 0);
    }

    #[test]
    fn time_must_strictly_exceed_median() {
        assert_eq!(
            check_block_time(1000, 1000, 2000, None),
            Err(TimeError::TooOld {
                time: 1000,
                median_past: 1000
            })
        );
        assert_eq!(
            check_block_time(999, 1000, 2000, None),
            Err(TimeError::TooOld {
                time: 999,
                median_past: 1000
            })
        );
        check_block_time(1001, 1000, 2000, None).unwrap();
    }

    #[test]
    fn time_must_not_exceed_now_plus_two_hours() {
        // Exactly at the boundary is allowed (`>` not `>=`).
        check_block_time(2000 + MAX_FUTURE_BLOCK_TIME, 0, 2000, None).unwrap();
        assert_eq!(
            check_block_time(2000 + MAX_FUTURE_BLOCK_TIME + 1, 0, 2000, None),
            Err(TimeError::TooNew {
                time: 2000 + MAX_FUTURE_BLOCK_TIME + 1,
                now: 2000
            })
        );
    }

    #[test]
    fn timewarp_floor_is_inclusive() {
        // At exactly the floor the block is allowed; one second earlier is rejected.
        check_block_time(10_000, 0, 20_000, Some(9_400)).unwrap();
        assert_eq!(
            check_block_time(9_399, 0, 20_000, Some(9_400)),
            Err(TimeError::Timewarp {
                time: 9_399,
                min_time: 9_400
            })
        );
    }

    #[test]
    fn timewarp_check_is_skipped_when_none() {
        // Non-boundary heights and non-BIP94 networks pass `None`: the same early
        // timestamp that would trip the floor is accepted.
        check_block_time(9_000, 0, 20_000, None).unwrap();
    }

    #[test]
    fn timewarp_ranks_between_too_old_and_too_new() {
        // Violating the timewarp floor but not the median reports Timewarp (Core checks
        // it second); violating the median still reports TooOld first.
        assert_eq!(
            check_block_time(9_399, 5_000, 20_000, Some(9_400)),
            Err(TimeError::Timewarp {
                time: 9_399,
                min_time: 9_400
            })
        );
        assert_eq!(
            check_block_time(4_999, 5_000, 20_000, Some(9_400)),
            Err(TimeError::TooOld {
                time: 4_999,
                median_past: 5_000
            })
        );
    }

    #[test]
    fn too_old_wins_over_too_new() {
        // A time that violates both bounds reports the first predicate Core checks.
        assert_eq!(
            check_block_time(5, 100, 0, None),
            Err(TimeError::TooOld {
                time: 5,
                median_past: 100
            })
        );
    }

    #[test]
    fn far_future_now_does_not_overflow() {
        // `now` near u32::MAX plus the 2-hour drift must not wrap.
        check_block_time(u32::MAX, 0, u32::MAX, None).unwrap();
        assert_eq!(
            check_block_time(u32::MAX, 0, u32::MAX - MAX_FUTURE_BLOCK_TIME - 1, None),
            Err(TimeError::TooNew {
                time: u32::MAX,
                now: u32::MAX - MAX_FUTURE_BLOCK_TIME - 1
            })
        );
    }
}

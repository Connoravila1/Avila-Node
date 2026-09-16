//! The node's mockable clock — Core's `util/time` `SetMockTime` /
//! `GetTime` pair. `setmocktime` (regtest only) pins the value every
//! UNIX-epoch `now` the node derives returns: block template times,
//! header/block acceptance future-drift, mempool admission, ban-list
//! and addrman timestamps. Unset (`0`) falls through to the system
//! clock.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static MOCKTIME: AtomicI64 = AtomicI64::new(0);

/// `SetMockTime` — `0` restores the system clock.
pub fn set_mock_time(t: i64) {
    MOCKTIME.store(t, Ordering::Relaxed);
}

/// `GetMockTime` — `0` when no mock time is set.
pub fn mock_time() -> i64 {
    MOCKTIME.load(Ordering::Relaxed)
}

/// Wall-clock UNIX seconds, never mocked — Core's `GetSystemTime`.
pub fn system_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `GetTime` — the pinned value when set, otherwise wall-clock seconds.
pub fn time() -> i64 {
    let mock = mock_time();
    if mock > 0 { mock } else { system_time() }
}

/// `GetTimeMillis` — `time()` at millisecond resolution (a pinned
/// value reports whole seconds, like Core).
pub fn time_millis() -> i64 {
    let mock = mock_time();
    if mock > 0 {
        mock * 1000
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

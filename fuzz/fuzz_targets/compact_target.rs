#![no_main]

use avila_consensus::arith::{CompactTarget, Target, Work};
use libfuzzer_sys::fuzz_target;

// Compact-target expansion, re-encoding and work derivation must be total:
// no u32 may panic. Sane expansions round-trip through `from_target` to a
// canonical encoding that re-expands to the same value.
fuzz_target!(|data: [u8; 4]| {
    let bits = u32::from_be_bytes(data);
    let expanded = CompactTarget(bits).expand();
    let _ = Work::from_compact(CompactTarget(bits));
    if !expanded.negative && !expanded.overflow {
        let roundtrip = CompactTarget::from_target(expanded.value, false).expand();
        assert_eq!(roundtrip.value, expanded.value);
        assert!(!roundtrip.negative && !roundtrip.overflow);
    }
    // `to_compact` of the expanded value is always defined and re-expands.
    let canonical = Target(expanded.value).to_compact();
    let _ = canonical.expand();
});

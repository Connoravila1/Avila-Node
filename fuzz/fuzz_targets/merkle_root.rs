#![no_main]

use avila_consensus::merkle;
use libfuzzer_sys::fuzz_target;

// Chunk arbitrary input into 32-byte leaves; the root computation (including
// CVE-2012-2459 mutation detection) must never panic on any leaf count.
fuzz_target!(|data: &[u8]| {
    let (leaves, _tail) = data.as_chunks::<32>();
    // Keep the tree small enough for fast iterations; odd counts exercise the
    // last-element duplication paths the mutation check watches.
    if !leaves.is_empty() && leaves.len() <= 1024 {
        let _ = merkle::merkle_root(leaves);
    }
});

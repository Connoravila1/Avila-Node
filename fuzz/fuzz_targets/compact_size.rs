#![no_main]

use avila_consensus::encode::{self, Decoder};
use libfuzzer_sys::fuzz_target;

// A successful CompactSize read must be canonical: re-encoding the value
// reproduces exactly the bytes consumed. Reads must never panic and must
// never exceed the input.
fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::new(data);
    if let Ok(value) = decoder.read_compact_size() {
        let mut reencoded = Vec::new();
        encode::write_compact_size(&mut reencoded, value);
        assert_eq!(&reencoded[..], &data[..decoder.position()]);
    }
    // A second read past the first's consumed bytes must not panic either.
    let _ = decoder.read_compact_size();
});

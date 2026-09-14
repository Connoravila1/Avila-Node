#![no_main]

use avila_consensus::header::BlockHeader;
use libfuzzer_sys::fuzz_target;

// Any 80 bytes must decode (or fail with a typed error — never panic), and a
// decoded header must re-encode to the identical bytes.
fuzz_target!(|data: &[u8]| {
    if data.len() >= BlockHeader::SIZE
        && let Ok(header) = BlockHeader::decode(&data[..BlockHeader::SIZE])
    {
        assert_eq!(header.encode(), data[..BlockHeader::SIZE]);
        let _ = header.hash();
    }
});

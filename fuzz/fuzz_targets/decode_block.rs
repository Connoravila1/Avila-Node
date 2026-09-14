#![no_main]

use avila_consensus::block::Block;
use libfuzzer_sys::fuzz_target;

// Decoding must never panic and must stay bounded by the input's size. A
// decoded block re-encodes to a stable canonical form, and merkle/witness
// root computation over the decoded transactions must also be total.
fuzz_target!(|data: &[u8]| {
    if let Ok(block) = Block::decode(data) {
        let _ = block.merkle_root();
        let _ = block.witness_merkle_root();
        let encoded = block.encode();
        assert!(encoded.len() <= data.len());
        let reparsed = Block::decode(&encoded).expect("canonical form must decode");
        assert_eq!(reparsed.encode(), encoded);
    }
});

#![no_main]

use avila_consensus::transaction::Transaction;
use libfuzzer_sys::fuzz_target;

// Decoding must never panic. A decoded transaction re-encodes to a canonical
// form no larger than the input, and that form re-decodes to the same txid.
fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = Transaction::decode(data) {
        let encoded = tx.encode();
        assert!(encoded.len() <= data.len());
        let reparsed = Transaction::decode(&encoded).expect("canonical form must decode");
        assert_eq!(reparsed.txid(), tx.txid());
        assert_eq!(reparsed.encode(), encoded);
    }
});

//! Advice sidecar files (`AVADV01`) — the file-based form of the
//! paired-node flow: a node that has already verified a block writes
//! its per-transaction advice streams to `<blockhash>.adv`; a syncing
//! peer loads them into [`ConnectContext::advice`].
//!
//! Layout (all integers little-endian):
//! ```text
//!   magic[8]   = b"AVADV01\0"
//!   block_hash[32]
//!   u32 ntx
//!   per tx:    txid[32] ‖ u32 entry_len ‖ entries[entry_len]
//! ```
//! Entry streams use the `r32 ‖ flag` pairing format defined by
//! `sigchecker` — the consumer verifies `r` before using a record, so a
//! corrupt or foreign stream degrades to ordinary verification.
//!
//! The format is deliberately flat: load is a memcpy-parse, and files
//! are content-addressed by the block hash they describe.

use crate::hash::{BlockHash, Txid};
use std::collections::HashMap;

const MAGIC: &[u8; 8] = b"AVADV01\0";

/// Serialize one block's advice map to the `AVADV01` layout.
#[must_use]
pub fn encode_advice_block(block_hash: &BlockHash, map: &HashMap<Txid, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::with_capacity(44 + map.len() * 36);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(block_hash.as_bytes());
    out.extend_from_slice(&(map.len() as u32).to_le_bytes());
    for (txid, entries) in map {
        out.extend_from_slice(txid.as_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        out.extend_from_slice(entries);
    }
    out
}

/// Parse an `AVADV01` buffer; `None` on any framing error (the caller
/// treats an unreadable sidecar exactly like a missing one — ordinary
/// verification).
#[must_use]
pub fn decode_advice_block(buf: &[u8]) -> Option<(BlockHash, HashMap<Txid, Vec<u8>>)> {
    let mut o = 0usize;
    let take = |o: &mut usize, n: usize| -> Option<&[u8]> {
        let s = buf.get(*o..*o + n)?;
        *o += n;
        Some(s)
    };
    if take(&mut o, 8)? != MAGIC {
        return None;
    }
    let hash = BlockHash::from_bytes(take(&mut o, 32)?.try_into().ok()?);
    let ntx = u32::from_le_bytes(take(&mut o, 4)?.try_into().ok()?) as usize;
    let mut map = HashMap::with_capacity(ntx);
    for _ in 0..ntx {
        let txid = Txid::from_bytes(take(&mut o, 32)?.try_into().ok()?);
        let len = u32::from_le_bytes(take(&mut o, 4)?.try_into().ok()?) as usize;
        map.insert(txid, take(&mut o, len)?.to_vec());
    }
    Some((hash, map))
}

/// Write `<dir>/<blockhash>.adv` — the sidecar a producing node shares.
pub fn write_advice_file(
    dir: &std::path::Path,
    block_hash: &BlockHash,
    map: &HashMap<Txid, Vec<u8>>,
) -> std::io::Result<()> {
    let _ = std::fs::create_dir_all(dir);
    std::fs::write(dir.join(advice_name(block_hash)), encode_advice_block(block_hash, map))
}

/// Load `<dir>/<blockhash>.adv` if present — `None` (not `Err`) on
/// absent or unreadable, matching the graceful-degradation contract.
#[must_use]
pub fn read_advice_file(
    dir: &std::path::Path,
    block_hash: &BlockHash,
) -> Option<HashMap<Txid, Vec<u8>>> {
    let buf = std::fs::read(dir.join(advice_name(block_hash))).ok()?;
    let (hash, map) = decode_advice_block(&buf)?;
    (hash == *block_hash).then_some(map)
}

/// `<blockhash>.adv` — display order (the conventional reversed hex).
#[must_use]
pub fn advice_name(block_hash: &BlockHash) -> String {
    let mut s = String::with_capacity(40);
    for b in block_hash.as_bytes().iter().rev() {
        s.push_str(&format!("{b:02x}"));
    }
    s.push_str(".adv");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advice_file_roundtrip() {
        let mut map = HashMap::new();
        map.insert(Txid::from_bytes([7u8; 32]), vec![0u8; 33]);
        map.insert(Txid::from_bytes([9u8; 32]), vec![1u8; 97]);
        let hash = BlockHash::from_bytes([3u8; 32]);
        let buf = encode_advice_block(&hash, &map);
        let (h2, m2) = decode_advice_block(&buf).unwrap();
        assert_eq!(h2, hash);
        assert_eq!(m2, map);
    }

    #[test]
    fn advice_file_rejects_garbage() {
        assert!(decode_advice_block(b"junk").is_none());
        assert!(decode_advice_block(&[]).is_none());
    }
}

//! BIP-152 compact blocks — 48-bit SipHash short-ids replace full
//! transactions on the wire; the receiver reconstructs the block from
//! its mempool and prefilled txs, then requests whatever indexes
//! didn't resolve via `getblocktxn`.
//!
//! Short-ids are keyed per block: `k0,k1 = SHA256(header || nonce)`
//! and each id is `SipHash-2-4(k0,k1,wtxid) mod 2^48` (version 2 —
//! wtxids make witness-commitment reconstruction possible; version 1's
//! txid form predates segwit and is not offered). Reconstruction never
//! skips validation — a completed block goes through the same
//! `accept_block` path as a full `block` message, so a wrong or
//! maliciously-colliding reconstruction is caught by the merkle root
//! and the full checks, exactly like any other delivery.

use avila_consensus::block::Block;
use avila_consensus::gcs::siphash24;
use avila_consensus::hash::{BlockHash, Wtxid, sha256};
use avila_consensus::header::BlockHeader;
use avila_consensus::transaction::Transaction;

use crate::message::{CmpctBlock, GetBlockTxn, PrefilledTx};

/// The per-block SipHash key pair — `SHA256(serialized_header ||
/// nonce)`'s first 16 bytes as two little-endian u64s, per BIP-152.
#[must_use]
pub fn shortid_key(header: &BlockHeader, nonce: u64) -> (u64, u64) {
    let mut buf = header.encode().to_vec();
    buf.extend_from_slice(&nonce.to_le_bytes());
    let h = sha256(&buf);
    (
        u64::from_le_bytes(h[..8].try_into().unwrap_or([0; 8])),
        u64::from_le_bytes(h[8..16].try_into().unwrap_or([0; 8])),
    )
}

/// The 48-bit little-endian short-id of `wtxid` under `key` —
/// BIP-152's `GetShortID` for version-2 (segwit) links.
#[must_use]
pub fn shortid(key: (u64, u64), wtxid: &Wtxid) -> u64 {
    siphash24(key.0, key.1, wtxid.as_bytes()) & 0x0000_ffff_ffff_ffff
}

/// The 6-byte wire form of a short-id (little-endian low 48 bits).
#[must_use]
pub fn shortid_bytes(id: u64) -> [u8; 6] {
    let b = id.to_le_bytes();
    [b[0], b[1], b[2], b[3], b[4], b[5]]
}

/// Build a `cmpctblock` for `block`: coinbase prefilled (index 0 —
/// the receiver never holds it), every other tx advertised by wtxid
/// short-id under a fresh random nonce.
#[must_use]
pub fn make_cmpctblock(block: &Block) -> CmpctBlock {
    let mut nonce_bytes = [0u8; 8];
    let _ = getrandom::fill(&mut nonce_bytes);
    let nonce = u64::from_le_bytes(nonce_bytes);
    if block.transactions.is_empty() {
        // Consensus-impossible (blocks carry ≥1 tx), but the encoder
        // shouldn't index a slice that isn't there.
        return CmpctBlock {
            header: block.header,
            nonce,
            shortids: Vec::new(),
            prefilled: Vec::new(),
        };
    }
    let key = shortid_key(&block.header, nonce);
    let shortids = block
        .transactions
        .iter()
        .skip(1)
        .map(|tx| shortid_bytes(shortid(key, &tx.wtxid())))
        .collect();
    let prefilled = vec![PrefilledTx {
        index_diff: 0,
        tx: block.transactions[0].clone(),
    }];
    CmpctBlock {
        header: block.header,
        nonce,
        shortids,
        prefilled,
    }
}

/// What reconstruction produced.
pub enum Reconstruct {
    /// Every slot filled — ready for `accept_block`.
    Complete(Box<Block>),
    /// Slots remain — send the embedded `getblocktxn`; the
    /// [`PartialBlock`] stays keyed by block hash awaiting `blocktxn`.
    Partial(Box<PartialBlock>),
}

/// A `cmpctblock` mid-reconstruction: fixed slot layout, `missing`
/// indexes awaiting a `blocktxn` reply.
pub struct PartialBlock {
    /// The block's hash — the `getblocktxn`/`blocktxn` join key.
    pub block_hash: BlockHash,
    header: BlockHeader,
    slots: Vec<Option<Transaction>>,
    missing: Vec<u32>,
}

impl PartialBlock {
    /// Lay out the slot space (`shortids + prefilled` slots), seat the
    /// prefilled txs at their absolute indexes, then resolve each
    /// remaining slot's short-id against `pool` (the mempool's
    /// transactions, scanned once into an id→tx map). Unresolvable
    /// slots become `missing`.
    ///
    /// Returns `Err` on structurally invalid encodings (prefilled
    /// indexes unsorted or out of range) — malformed, not missing.
    pub fn begin(
        cb: CmpctBlock,
        pool: &avila_mempool::Mempool,
    ) -> Result<Reconstruct, &'static str> {
        let key = shortid_key(&cb.header, cb.nonce);
        let total = cb.shortids.len() + cb.prefilled.len();

        // The pool's claimable txs by short-id. Two entries colliding
        // on an id leave a per-id queue; each claiming slot pops one —
        // under-supplied slots become `missing` and get fetched
        // (Core's collision fallback).
        let mut claimable: std::collections::HashMap<u64, Vec<Transaction>> =
            std::collections::HashMap::new();
        for tx in pool.iter_txs() {
            claimable
                .entry(shortid(key, &tx.wtxid()))
                .or_default()
                .push(tx.clone());
        }

        let mut slots: Vec<Option<Transaction>> = Vec::new();
        slots.resize_with(total, || None);
        let mut prev: i64 = -1;
        for p in cb.prefilled {
            let idx = prev + i64::from(p.index_diff) + 1;
            if idx < 0 || idx >= total as i64 {
                return Err("prefilled index out of range");
            }
            slots[idx as usize] = Some(p.tx);
            prev = idx;
        }

        let mut missing = Vec::new();
        let mut sid_iter = cb.shortids.iter();
        for (i, slot) in slots.iter_mut().enumerate() {
            if slot.is_some() {
                continue;
            }
            let Some(id) = sid_iter.next() else {
                return Err("shortid/prefilled layout mismatch");
            };
            let key48 = u64::from_le_bytes([id[0], id[1], id[2], id[3], id[4], id[5], 0, 0]);
            match claimable.get_mut(&key48).and_then(Vec::pop) {
                Some(tx) => *slot = Some(tx),
                None => missing.push(i as u32),
            }
        }

        let block = PartialBlock {
            block_hash: cb.header.hash(),
            header: cb.header,
            slots,
            missing,
        };
        Ok(if block.is_complete() {
            match block.into_block() {
                Some(b) => Reconstruct::Complete(Box::new(b)),
                None => unreachable!("is_complete held"),
            }
        } else {
            Reconstruct::Partial(Box::new(block))
        })
    }

    /// The `getblocktxn` for the outstanding slots — differential
    /// indexes per BIP-152.
    #[must_use]
    pub fn getblocktxn(&self) -> GetBlockTxn {
        let mut indexes = Vec::with_capacity(self.missing.len());
        let mut prev: i64 = -1;
        for &idx in &self.missing {
            indexes.push((i64::from(idx) - prev - 1) as u32);
            prev = i64::from(idx);
        }
        GetBlockTxn {
            block_hash: self.block_hash,
            indexes,
        }
    }

    /// Slots still unresolved (telemetry for the patch request).
    #[must_use]
    pub fn missing_len(&self) -> usize {
        self.missing.len()
    }

    /// Merge a `blocktxn` reply — fills `missing` slots in order.
    /// Extra or missing txs leave the block invalid at connect, same
    /// as any bad delivery; we only check count vs slots.
    pub fn fill(&mut self, txs: Vec<Transaction>) {
        let take = txs.len().min(self.missing.len());
        for (slot_idx, tx) in self.missing.drain(..take).zip(txs) {
            self.slots[slot_idx as usize] = Some(tx);
        }
    }

    /// Whether every slot resolved.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.slots.iter().all(Option::is_some)
    }

    /// The completed block when every slot resolved, consuming the
    /// partial.
    #[must_use]
    pub fn into_block(self) -> Option<Block> {
        if self.slots.iter().all(Option::is_some) {
            let transactions = self.slots.into_iter().flatten().collect();
            Some(Block {
                header: self.header,
                transactions,
            })
        } else {
            None
        }
    }
}

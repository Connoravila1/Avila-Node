//! UTXO-set statistics — a port of Core's `kernel/coinstats.cpp` used by
//! `gettxoutsetinfo`.
//!
//! Core iterates its LevelDB coins cursor, which yields entries sorted
//! by `(txid, vout)`. Our [`UtxoSet`] is a `HashMap` with unspecified
//! order, so the entries' references are collected and sorted once —
//! 16 bytes per coin, proportional to the set itself, never a copy of
//! the coins.

use crate::connect::{Coin, UtxoSet};
use crate::encode::{compact_size_len, write_var_bytes};
use crate::hash::{BlockHash, Hash256, Sha256d};
use crate::muhash::MuHash3072;
use crate::transaction::OutPoint;

/// Which UTXO-set hash `gettxoutsetinfo` computes (Core's
/// `CoinStatsHashType`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CoinStatsHashType {
    /// `hash_serialized_3` — SHA256d over the concatenated `TxOutSer`
    /// bytes of every coin in cursor order.
    HashSerialized,
    /// `muhash` — the MuHash-3072 multiset hash of the same bytes.
    MuHash,
    /// `none` — statistics only; no hash is computed.
    None,
}

/// Aggregate statistics over the UTXO set — the non-index fields of
/// Core's `CCoinsStats`.
pub struct CoinStats {
    /// Height of the block the statistics describe.
    pub height: i64,
    /// Hash of that block.
    pub best_block: BlockHash,
    /// Number of distinct transactions with unspent outputs
    /// (`nTransactions`).
    pub transactions: u64,
    /// Number of unspent transaction outputs (`nTransactionOutputs`).
    pub txouts: u64,
    /// Core's `nBogoSize` — a database-independent size metric.
    pub bogo_size: u64,
    /// The `hash_serialized_3`/`muhash` digest when the respective hash
    /// type was requested.
    pub hash_serialized: Option<Hash256>,
    /// Serialized-size estimate standing in for Core's LevelDB
    /// `EstimateSize` — our UTXO set never touches disk, so this reports
    /// the size the set would occupy serialized (36-byte outpoint +
    /// 4-byte height/coinbase + serialized `CTxOut` per coin).
    pub disk_size: u64,
    /// `total_amount` in satoshis — `None` only if the sum overflowed,
    /// the case Core guards with `CHECK_NONFATAL`.
    pub total_amount: Option<i64>,
}

/// Core's `GetBogoSize` — a database-independent per-coin size metric.
fn bogo_size(script_len: usize) -> u64 {
    (32 + 4 + 4 + 8 + 2 + script_len) as u64
}

/// Core's `TxOutSer` (v29): `outpoint` ‖ `uint32(height << 1 |
/// coinbase)` ‖ `CTxOut` — the bytes both hash algorithms consume.
///
/// `pub(crate)` so callers that must stream the hash instead of
/// materializing the whole set (e.g. `Chainstate::activate_snapshot`,
/// which would otherwise hold tens of GB of coins at mainnet size) can
/// feed the same bytes into their own incremental hasher.
pub(crate) fn tx_out_ser(out: &mut Vec<u8>, outpoint: &OutPoint, coin: &Coin) {
    out.extend_from_slice(outpoint.txid.as_bytes());
    out.extend_from_slice(&outpoint.vout.to_le_bytes());
    let height_coinbase = (coin.height << 1) | u32::from(coin.coinbase);
    out.extend_from_slice(&height_coinbase.to_le_bytes());
    out.extend_from_slice(&coin.out.value.to_le_bytes());
    write_var_bytes(out, coin.out.script_pubkey.as_bytes());
}

/// The serialized size of one coin entry — the `disk_size` estimate.
fn coin_ser_size(coin: &Coin) -> u64 {
    let script_len = coin.out.script_pubkey.as_bytes().len() as u64;
    36 + 4 + 8 + compact_size_len(script_len) as u64 + script_len
}

/// Computes [`CoinStats`] over `utxo` at `height`/`best_block` — Core's
/// `ComputeUTXOStats` for a single-pindex (best-block) view.
#[must_use]
pub fn compute(
    utxo: &UtxoSet,
    height: i64,
    best_block: BlockHash,
    hash_type: CoinStatsHashType,
) -> CoinStats {
    // Cursor order = (txid, vout) ascending on the raw txid bytes —
    // `Txid`'s `Ord` is exactly that lexicographic order.
    let mut entries: Vec<(OutPoint, Coin)> = utxo.iter();
    entries.sort_by_key(|(op, _)| (op.txid, op.vout));
    compute_ordered(
        entries.iter().map(|(op, c)| (*op, c.clone())),
        height,
        best_block,
        hash_type,
    )
}

/// The same statistics over coins yielded in already-sorted cursor
/// order — streaming variant: the snapshot file's on-disk order is the
/// hash order, so activation can verify the commitment without
/// materializing the set.
pub fn compute_streaming(
    entries: impl Iterator<Item = (OutPoint, Coin)>,
    height: i64,
    best_block: BlockHash,
    hash_type: CoinStatsHashType,
) -> CoinStats {
    compute_ordered(entries, height, best_block, hash_type)
}

fn compute_ordered(
    entries: impl Iterator<Item = (OutPoint, Coin)>,
    height: i64,
    best_block: BlockHash,
    hash_type: CoinStatsHashType,
) -> CoinStats {
    let mut stats = CoinStats {
        height,
        best_block,
        transactions: 0,
        txouts: 0,
        bogo_size: 0,
        hash_serialized: None,
        disk_size: 0,
        total_amount: Some(0),
    };
    let mut sha = Sha256d::new();
    let mut mu = MuHash3072::new();
    // One reused serialization buffer — bounded by one coin's encoding.
    let mut buf = Vec::new();
    let mut prev_txid = None;
    for (op, coin) in entries {
        if prev_txid != Some(op.txid) {
            stats.transactions += 1;
            prev_txid = Some(op.txid);
        }
        stats.txouts += 1;
        stats.bogo_size += bogo_size(coin.out.script_pubkey.as_bytes().len());
        stats.disk_size += coin_ser_size(&coin);
        stats.total_amount = stats
            .total_amount
            .and_then(|total| total.checked_add(coin.out.value));
        match hash_type {
            CoinStatsHashType::HashSerialized => {
                buf.clear();
                tx_out_ser(&mut buf, &op, &coin);
                sha.update(&buf);
            }
            CoinStatsHashType::MuHash => {
                buf.clear();
                tx_out_ser(&mut buf, &op, &coin);
                mu.insert(&buf);
            }
            CoinStatsHashType::None => {}
        }
    }
    stats.hash_serialized = match hash_type {
        CoinStatsHashType::HashSerialized => Some(Hash256::from(sha.finalize())),
        CoinStatsHashType::MuHash => Some(Hash256::from(mu.finalize())),
        CoinStatsHashType::None => None,
    };
    stats
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hash::Txid;
    use crate::transaction::{OutPoint, Script, TxOut};

    fn coin(value: i64, height: u32, coinbase: bool, script: &[u8]) -> Coin {
        Coin {
            out: TxOut {
                value,
                script_pubkey: Script::new(script.to_vec()),
            },
            height,
            coinbase,
        }
    }

    fn outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_bytes([byte; 32]),
            vout,
        }
    }

    /// An empty set: `hash_serialized_3` is sha256d of nothing, muhash is
    /// sha256 of the serialized field element 1.
    #[test]
    fn empty_set() {
        let set = UtxoSet::new();
        let tip = BlockHash::from_bytes([7; 32]);
        for hash_type in [
            CoinStatsHashType::HashSerialized,
            CoinStatsHashType::MuHash,
            CoinStatsHashType::None,
        ] {
            let s = compute(&set, 0, tip, hash_type);
            assert_eq!((s.txouts, s.transactions, s.bogo_size), (0, 0, 0));
            assert_eq!(s.total_amount, Some(0));
            match hash_type {
                CoinStatsHashType::HashSerialized => assert_eq!(
                    s.hash_serialized.unwrap().as_bytes(),
                    &crate::hash::sha256d(b"")
                ),
                // sha256 of Num3072(1)'s 384-byte serialization,
                // display-reversed.
                CoinStatsHashType::MuHash => assert_eq!(
                    s.hash_serialized.unwrap().to_string(),
                    "dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8"
                ),
                CoinStatsHashType::None => assert_eq!(s.hash_serialized, None),
            }
        }
    }

    /// The same set in different insertion orders produces the same
    /// hashes — the sort must make `HashMap` order irrelevant.
    #[test]
    fn order_independent() {
        let coins = [
            (outpoint(2, 1), coin(50, 3, false, b"\x51")),
            (outpoint(1, 0), coin(70, 2, true, b"\x6a")),
            (outpoint(2, 0), coin(25, 3, false, b"\x76\xa9")),
        ];
        let mut a = UtxoSet::new();
        let mut b = UtxoSet::new();
        for (op, c) in &coins {
            a.insert_synthetic(*op, c.clone());
        }
        for (op, c) in coins.iter().rev() {
            b.insert_synthetic(*op, c.clone());
        }
        let tip = BlockHash::from_bytes([9; 32]);
        for hash_type in [CoinStatsHashType::HashSerialized, CoinStatsHashType::MuHash] {
            let sa = compute(&a, 4, tip, hash_type);
            let sb = compute(&b, 4, tip, hash_type);
            assert_eq!(sa.hash_serialized, sb.hash_serialized);
        }
        let s = compute(&a, 4, tip, CoinStatsHashType::None);
        // Two distinct txids (1, 2), three outputs.
        assert_eq!((s.transactions, s.txouts), (2, 3));
        assert_eq!(s.total_amount, Some(50 + 70 + 25));
        assert_eq!(s.bogo_size, 51 + 51 + 52);
        assert_eq!(s.disk_size, (50 + 50 + 51) as u64);
    }

    /// `TxOutSer` bytes pinned: outpoint ‖ height/coinbase ‖ txout.
    #[test]
    fn tx_out_ser_layout() {
        let mut buf = Vec::new();
        let op = outpoint(0xab, 5);
        let c = coin(123_456, 9, true, b"\x51");
        tx_out_ser(&mut buf, &op, &c);
        let mut exp = Vec::new();
        exp.extend_from_slice(&[0xab; 32]);
        exp.extend_from_slice(&5u32.to_le_bytes());
        exp.extend_from_slice(&(9u32 << 1 | 1).to_le_bytes());
        exp.extend_from_slice(&123_456i64.to_le_bytes());
        exp.extend_from_slice(&[0x01, 0x51]);
        assert_eq!(buf, exp);
    }
}

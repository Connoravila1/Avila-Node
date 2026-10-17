//! Bounded read-only extraction of historical input amounts from active-chain undo.
//!
//! This API reports only values present in the connected block's undo record. It
//! does not consult the current UTXO set, fetch a body/prevout, or validate the
//! transaction. For backend records it structurally walks the stored encoding
//! without constructing `Coin` or `Script` objects; compact script payloads are
//! skipped by their encoded size and are not decompressed or pubkey-validated.
//! Persisted backend inspection is conservative: every retained undo must have
//! a current-writer admission row, and the sticky largest-record value must be
//! at most the scanner bound. Existing databases are not backfilled; incomplete
//! or oversized histories return an unavailable/too-large status. In-memory
//! tail and run records do not use this backend-wide admission gate.

use crate::check::MAX_MONEY;
use crate::hash::BlockHash;

/// Maximum encoded backend undo record admitted and scanned for a selected
/// transaction page. This is a record/parser/output admission bound, not a
/// physical redb page or RSS bound: even intact pages can exceed it through
/// power-of-two page rounding and co-resident values. Callers must keep the
/// node's process memory limit in force.
pub(crate) const MAX_UNDO_AMOUNT_RECORD_BYTES: usize = 8 * 1024 * 1024;
/// Maximum input values returned by one request.
pub const MAX_UNDO_AMOUNT_PAGE: u16 = 100;

/// A request pinned to one active-chain block and transaction identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UndoAmountsRequest {
    /// Active-chain height.
    pub height: u32,
    /// Block hash expected at `height`.
    pub block_hash: BlockHash,
    /// Transaction position in the block, including coinbase at index zero.
    pub tx_index: u32,
    /// Transaction count reported for the corresponding block body.
    pub block_tx_count: u32,
    /// Input count reported for the selected transaction.
    pub input_count: u32,
    /// First input index requested.
    pub input_offset: u32,
    /// Maximum number of input values requested (1..=100).
    pub input_limit: u16,
}

/// Amounts recovered from the matching active-chain undo record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndoAmounts {
    /// Sum of all spent prevout amounts for the selected transaction.
    pub input_total_sats: i64,
    /// Values for the requested input page only.
    pub input_values: Vec<i64>,
}

/// Outcome of a bounded historical input-amount query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UndoAmountsResult {
    /// The matching undo was present and structurally readable.
    Available(UndoAmounts),
    /// No retained undo record is available for this active block.
    Unavailable,
    /// The requested height/hash pair is not on the current connected chain.
    NotActiveChain,
    /// The stored undo's block-hash tag differs from the requested hash.
    HashMismatch,
    /// A request or encoded record exceeds a documented bound.
    TooLarge,
    /// Request metadata, counts, money values, or record structure is invalid.
    Malformed,
}

pub(crate) fn validate_request(request: &UndoAmountsRequest) -> Result<(), UndoAmountsResult> {
    if request.input_limit > MAX_UNDO_AMOUNT_PAGE {
        return Err(UndoAmountsResult::TooLarge);
    }
    if request.input_limit == 0
        || request.block_tx_count == 0
        || request.tx_index >= request.block_tx_count
        || request.input_offset > request.input_count
    {
        return Err(UndoAmountsResult::Malformed);
    }
    Ok(())
}

/// Extract values from an already-decoded, borrowed undo without cloning it.
pub(crate) fn from_borrowed_undo(
    request: &UndoAmountsRequest,
    undo: &crate::connect::BlockUndo,
) -> UndoAmountsResult {
    if let Err(result) = validate_request(request) {
        return result;
    }
    let Ok(tx_count) = u32::try_from(undo.txs.len()) else {
        return UndoAmountsResult::TooLarge;
    };
    if tx_count != request.block_tx_count {
        return UndoAmountsResult::Malformed;
    }
    let Some(tx_undo) = undo.txs.get(request.tx_index as usize) else {
        return UndoAmountsResult::Malformed;
    };
    let Ok(input_count) = u32::try_from(tx_undo.spent.len()) else {
        return UndoAmountsResult::TooLarge;
    };
    if input_count != request.input_count {
        return UndoAmountsResult::Malformed;
    }
    let Some(page_end) = request
        .input_offset
        .checked_add(u32::from(request.input_limit))
    else {
        return UndoAmountsResult::Malformed;
    };
    let mut total = 0i64;
    let page_capacity = u32::from(request.input_limit)
        .min(input_count.saturating_sub(request.input_offset)) as usize;
    let mut values = Vec::with_capacity(page_capacity);
    for (index, coin) in tx_undo.spent.iter().enumerate() {
        let value = coin.out.value;
        if !(0..=MAX_MONEY).contains(&value) {
            return UndoAmountsResult::Malformed;
        }
        let Some(next_total) = total.checked_add(value) else {
            return UndoAmountsResult::Malformed;
        };
        if next_total > MAX_MONEY {
            return UndoAmountsResult::Malformed;
        }
        total = next_total;
        let index = index as u32;
        if index >= request.input_offset && index < page_end {
            values.push(value);
        }
    }
    UndoAmountsResult::Available(UndoAmounts {
        input_total_sats: total,
        input_values: values,
    })
}

/// Scan a bounded encoded `BlockUndo`, returning only amounts for the selected
/// transaction. Legacy records use CompactSize lengths; compact records use
/// Core's nonnegative VARINT coin codec.
pub(crate) fn scan_encoded_undo(
    record: &[u8],
    format: crate::coinsdb::CoinFormat,
    request: &UndoAmountsRequest,
) -> UndoAmountsResult {
    if record.len() > MAX_UNDO_AMOUNT_RECORD_BYTES {
        return UndoAmountsResult::TooLarge;
    }
    if let Err(result) = validate_request(request) {
        return result;
    }
    let mut cursor = Cursor::new(record);
    let Some(tag) = cursor.take(32) else {
        return UndoAmountsResult::Malformed;
    };
    if tag != request.block_hash.as_bytes() {
        return UndoAmountsResult::HashMismatch;
    }
    let Some(tx_count) = cursor.compact_size() else {
        return UndoAmountsResult::Malformed;
    };
    if tx_count != u64::from(request.block_tx_count) {
        return UndoAmountsResult::Malformed;
    }

    let Some(page_end) = request
        .input_offset
        .checked_add(u32::from(request.input_limit))
    else {
        return UndoAmountsResult::Malformed;
    };
    let mut total = 0i64;
    let mut values = Vec::with_capacity(request.input_limit as usize);
    for tx_index in 0..tx_count {
        let Some(spent_count) = cursor.compact_size() else {
            return UndoAmountsResult::Malformed;
        };
        let selected = tx_index == u64::from(request.tx_index);
        if selected && spent_count != u64::from(request.input_count) {
            return UndoAmountsResult::Malformed;
        }
        for input_index in 0..spent_count {
            let Some(value) = cursor.coin_amount_and_skip(format) else {
                return UndoAmountsResult::Malformed;
            };
            if selected {
                if !(0..=i128::from(MAX_MONEY)).contains(&value) {
                    return UndoAmountsResult::Malformed;
                }
                let Ok(value) = i64::try_from(value) else {
                    return UndoAmountsResult::Malformed;
                };
                let Some(next_total) = total.checked_add(value) else {
                    return UndoAmountsResult::Malformed;
                };
                if next_total > MAX_MONEY {
                    return UndoAmountsResult::Malformed;
                }
                total = next_total;
                if input_index >= u64::from(request.input_offset)
                    && input_index < u64::from(page_end)
                {
                    values.push(value);
                }
            }
        }
        let Some(overwritten_count) = cursor.compact_size() else {
            return UndoAmountsResult::Malformed;
        };
        for _ in 0..overwritten_count {
            if cursor.take(36).is_none() || cursor.coin_amount_and_skip(format).is_none() {
                return UndoAmountsResult::Malformed;
            }
        }
    }
    if !cursor.is_finished() {
        return UndoAmountsResult::Malformed;
    }
    UndoAmountsResult::Available(UndoAmounts {
        input_total_sats: total,
        input_values: values,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(length)?;
        let bytes = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(bytes)
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn compact_size(&mut self) -> Option<u64> {
        let prefix = *self.take(1)?.first()?;
        let value = match prefix {
            0..=252 => u64::from(prefix),
            253 => u64::from(u16::from_le_bytes(self.take(2)?.try_into().ok()?)),
            254 => u64::from(u32::from_le_bytes(self.take(4)?.try_into().ok()?)),
            255 => u64::from_le_bytes(self.take(8)?.try_into().ok()?),
        };
        if (prefix == 253 && value < 253)
            || (prefix == 254 && value < 0x1_0000)
            || (prefix == 255 && value < 0x1_0000_0000)
            || value > crate::encode::MAX_SIZE
        {
            return None;
        }
        Some(value)
    }

    fn varint(&mut self, max: u64) -> Option<u64> {
        let mut remaining = self.bytes.get(self.position..)?;
        let original_len = remaining.len();
        let value = crate::utxo_snapshot::read_varint(&mut remaining, max).ok()?;
        self.position = self.position.checked_add(original_len - remaining.len())?;
        Some(value)
    }

    fn coin_amount_and_skip(&mut self, format: crate::coinsdb::CoinFormat) -> Option<i128> {
        match format {
            crate::coinsdb::CoinFormat::Legacy => {
                let value = i64::from_le_bytes(self.take(8)?.try_into().ok()?);
                let script_len = usize::try_from(self.compact_size()?).ok()?;
                self.take(script_len)?;
                self.take(4)?; // height
                self.take(1)?; // coinbase byte (same permissive interpretation as decode_coin)
                Some(i128::from(value))
            }
            crate::coinsdb::CoinFormat::Compact => {
                self.varint(u64::from(u32::MAX))?; // height/coinbase code
                let amount = self.varint(u64::MAX)?;
                let size_id = self.varint(u64::from(u32::MAX))?;
                let script_payload = match size_id {
                    0 | 1 => 20usize,
                    2..=5 => 32usize,
                    raw_size_id => usize::try_from(raw_size_id.checked_sub(6)?).ok()?,
                };
                self.take(script_payload)?;
                Some(i128::from(decompress_amount_checked(amount)?))
            }
        }
    }
}

/// Checked local equivalent of DecompressAmount for untrusted undo bytes.
/// The snapshot codec intentionally mirrors Core's wrapping u64 behavior;
/// inspection must not let an overflowing representation wrap into a valid
/// money-range amount.
fn decompress_amount_checked(mut encoded: u64) -> Option<u64> {
    if encoded == 0 {
        return Some(0);
    }
    encoded -= 1;
    let exponent = encoded % 10;
    let mut amount = encoded / 10;
    if exponent < 9 {
        let digit = amount % 9 + 1;
        amount /= 9;
        amount = amount.checked_mul(10)?.checked_add(digit)?;
    } else {
        amount = amount.checked_add(1)?;
    }
    for _ in 0..exponent {
        amount = amount.checked_mul(10)?;
    }
    Some(amount)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::connect::{BlockUndo, Coin, TxUndo};
    use crate::hash::{BlockHash, Txid};
    use crate::transaction::{OutPoint, Script, TxOut};

    fn coin(value: i64) -> Coin {
        Coin {
            out: TxOut {
                value,
                script_pubkey: Script::new(vec![0x51]),
            },
            height: 1,
            coinbase: false,
        }
    }

    fn hash() -> BlockHash {
        BlockHash::from_bytes([0x42; 32])
    }

    fn undo(values: &[i64]) -> BlockUndo {
        BlockUndo {
            txs: vec![
                TxUndo::default(),
                TxUndo {
                    spent: values.iter().copied().map(coin).collect(),
                    overwritten: vec![(
                        OutPoint {
                            txid: Txid::from_bytes([0x99; 32]),
                            vout: 7,
                        },
                        coin(500),
                    )],
                },
                TxUndo::default(),
            ],
        }
    }

    fn request(offset: u32, limit: u16, input_count: u32) -> UndoAmountsRequest {
        UndoAmountsRequest {
            height: 7,
            block_hash: hash(),
            tx_index: 1,
            block_tx_count: 3,
            input_count,
            input_offset: offset,
            input_limit: limit,
        }
    }

    fn compact_record_prefix_with_coin(amount: u64, size_id: u64, script: &[u8]) -> Vec<u8> {
        let mut record = hash().as_bytes().to_vec();
        crate::encode::write_compact_size(&mut record, 3);
        crate::encode::write_compact_size(&mut record, 0);
        crate::encode::write_compact_size(&mut record, 1);
        crate::utxo_snapshot::write_varint(&mut record, 2);
        crate::utxo_snapshot::write_varint(&mut record, amount);
        crate::utxo_snapshot::write_varint(&mut record, size_id);
        record.extend_from_slice(script);
        record
    }

    #[test]
    fn legacy_and_compact_scanners_match_borrowed_pages_and_ignore_overwrites() {
        let undo = undo(&[5, 7]);
        for format in [
            crate::coinsdb::CoinFormat::Legacy,
            crate::coinsdb::CoinFormat::Compact,
        ] {
            let record = crate::coinsdb::encode_undo(&hash(), &undo, format);
            let expected = from_borrowed_undo(&request(0, 1, 2), &undo);
            assert_eq!(
                scan_encoded_undo(&record, format, &request(0, 1, 2)),
                expected
            );
            assert_eq!(
                scan_encoded_undo(&record, format, &request(1, 1, 2)),
                UndoAmountsResult::Available(UndoAmounts {
                    input_total_sats: 12,
                    input_values: vec![7],
                })
            );
            assert_eq!(
                scan_encoded_undo(&record, format, &request(2, 1, 2)),
                UndoAmountsResult::Available(UndoAmounts {
                    input_total_sats: 12,
                    input_values: vec![],
                })
            );
        }
    }

    #[test]
    fn scanner_rejects_hash_counts_truncation_and_trailing_bytes() {
        let format = crate::coinsdb::CoinFormat::Compact;
        let record = crate::coinsdb::encode_undo(&hash(), &undo(&[5, 7]), format);
        let mut wrong_hash = request(0, 2, 2);
        wrong_hash.block_hash = BlockHash::from_bytes([0x43; 32]);
        assert_eq!(
            scan_encoded_undo(&record, format, &wrong_hash),
            UndoAmountsResult::HashMismatch
        );
        assert_eq!(
            scan_encoded_undo(&record[..record.len() - 1], format, &request(0, 2, 2)),
            UndoAmountsResult::Malformed
        );
        let mut trailing = record.clone();
        trailing.push(0);
        assert_eq!(
            scan_encoded_undo(&trailing, format, &request(0, 2, 2)),
            UndoAmountsResult::Malformed
        );
        assert_eq!(
            scan_encoded_undo(&record, format, &request(0, 2, 3)),
            UndoAmountsResult::Malformed
        );
        assert_eq!(
            scan_encoded_undo(&record, format, &request(0, 2, 1)),
            UndoAmountsResult::Malformed
        );
    }

    #[test]
    fn scanner_rejects_noncanonical_compactsize_truncated_script_and_amount_overflow() {
        let format = crate::coinsdb::CoinFormat::Compact;
        let canonical = crate::coinsdb::encode_undo(&hash(), &undo(&[5]), format);
        let mut noncanonical_count = hash().as_bytes().to_vec();
        noncanonical_count.extend_from_slice(&[253, 3, 0]);
        noncanonical_count.extend_from_slice(&canonical[33..]);
        assert_eq!(
            scan_encoded_undo(&noncanonical_count, format, &request(0, 1, 1)),
            UndoAmountsResult::Malformed
        );

        let truncated_script =
            compact_record_prefix_with_coin(crate::utxo_snapshot::compress_amount(5), 7, &[]);
        assert_eq!(
            scan_encoded_undo(&truncated_script, format, &request(0, 1, 1)),
            UndoAmountsResult::Malformed
        );

        let overflowing_raw = u64::MAX - 6;
        let mut encoded_amount = Vec::new();
        crate::utxo_snapshot::write_varint(&mut encoded_amount, overflowing_raw);
        assert_eq!(
            Cursor::new(&encoded_amount).varint(u64::MAX),
            Some(overflowing_raw)
        );
        assert_eq!(decompress_amount_checked(overflowing_raw), None);
        let overflowing_amount = compact_record_prefix_with_coin(overflowing_raw, 6, &[]);
        assert_eq!(
            scan_encoded_undo(&overflowing_amount, format, &request(0, 1, 1)),
            UndoAmountsResult::Malformed
        );
    }

    #[test]
    fn request_and_encoded_record_limits_are_enforced_before_scanning() {
        let format = crate::coinsdb::CoinFormat::Legacy;
        let record = crate::coinsdb::encode_undo(&hash(), &undo(&[1]), format);
        let oversized_page = request(0, MAX_UNDO_AMOUNT_PAGE + 1, 1);
        assert_eq!(
            scan_encoded_undo(&record, format, &oversized_page),
            UndoAmountsResult::TooLarge
        );
        assert_eq!(
            scan_encoded_undo(
                &vec![0; MAX_UNDO_AMOUNT_RECORD_BYTES + 1],
                format,
                &request(0, 1, 1)
            ),
            UndoAmountsResult::TooLarge
        );
        assert_eq!(
            scan_encoded_undo(&record, format, &request(2, 1, 1)),
            UndoAmountsResult::Malformed
        );
        assert_eq!(
            scan_encoded_undo(&record, format, &request(0, 0, 1)),
            UndoAmountsResult::Malformed
        );
    }

    #[test]
    fn scanner_enforces_money_range_and_checked_input_total() {
        for (format, values) in [
            (crate::coinsdb::CoinFormat::Legacy, vec![-1]),
            (crate::coinsdb::CoinFormat::Legacy, vec![MAX_MONEY, 1]),
            (crate::coinsdb::CoinFormat::Compact, vec![MAX_MONEY + 1]),
        ] {
            let undo = undo(&values);
            let record = crate::coinsdb::encode_undo(&hash(), &undo, format);
            assert_eq!(
                scan_encoded_undo(
                    &record,
                    format,
                    &request(0, values.len() as u16, values.len() as u32)
                ),
                UndoAmountsResult::Malformed
            );
        }
    }
}

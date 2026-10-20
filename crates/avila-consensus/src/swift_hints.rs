//! Bounded, sequential reader for draft BIP456 version-0 hintsfiles.
//!
//! A hintsfile is untrusted advice. Its height is checked here, while callers
//! must bind the file to their selected network and checkpoint hash. Every hint
//! is later checked against locally parsed block outputs and the full checkpoint
//! audit; this reader cannot make a block or UTXO set valid.

use std::io::{self, Read};

/// Conservative per-block cap for decoded survivor output indices.
pub const MAX_HINT_INDICES_PER_BLOCK: usize = 100_000;
/// Maximum encoded Elias-Fano payload for one block's hint record.
pub const MAX_HINT_RECORD_BYTES: usize = 1024 * 1024;

/// Sequential BIP456 v0 parser. It retains only one height's sorted indices.
pub struct Bip456HintsReader<R> {
    reader: R,
    target_height: u32,
    next_height: u32,
    encoded_bytes: u64,
    max_encoded_bytes: u64,
    max_indices_per_block: usize,
    finished: bool,
}

impl<R: Read> Bip456HintsReader<R> {
    /// Opens a hints stream and binds its declared height to the expected target.
    ///
    /// `max_encoded_bytes` includes the 9-byte file header and must be enforced
    /// against a file-size limit by the caller before opening an untrusted path.
    pub fn new(
        mut reader: R,
        expected_height: u32,
        max_encoded_bytes: u64,
    ) -> Result<Self, Bip456HintsError> {
        if max_encoded_bytes < 9 {
            return Err(Bip456HintsError::EncodedSizeLimit);
        }
        let mut header = [0u8; 9];
        reader.read_exact(&mut header)?;
        if &header[..4] != b"UTXO" {
            return Err(Bip456HintsError::Magic);
        }
        if header[4] != 0 {
            return Err(Bip456HintsError::Version(header[4]));
        }
        let target_height = u32::from_le_bytes(
            header[5..9]
                .try_into()
                .map_err(|_| Bip456HintsError::Encoding)?,
        );
        if target_height != expected_height {
            return Err(Bip456HintsError::Height {
                expected: expected_height,
                actual: target_height,
            });
        }
        Ok(Self {
            reader,
            target_height,
            next_height: 0,
            encoded_bytes: 9,
            max_encoded_bytes,
            max_indices_per_block: MAX_HINT_INDICES_PER_BLOCK,
            finished: false,
        })
    }

    /// Height committed by this file. It is not a checkpoint hash commitment.
    #[must_use]
    pub const fn target_height(&self) -> u32 {
        self.target_height
    }

    /// Returns sorted spendable-output ordinals for the next required height.
    /// Indices count spendable outputs only, in transaction/output order.
    pub fn next_indices(
        &mut self,
        height: u32,
        spendable_output_count: usize,
    ) -> Result<Vec<u32>, Bip456HintsError> {
        if self.finished || height != self.next_height || height > self.target_height {
            return Err(Bip456HintsError::HeightOrder);
        }

        let n = self.read_compact_u32()? as usize;
        if n > self.max_indices_per_block || n > spendable_output_count {
            return Err(Bip456HintsError::IndexCountLimit);
        }
        let indices = if n == 0 {
            Vec::new()
        } else {
            let max = self.read_compact_u32()?;
            if u64::try_from(n).map_err(|_| Bip456HintsError::Encoding)? > u64::from(max) + 1 {
                return Err(Bip456HintsError::Encoding);
            }
            if usize::try_from(max).map_err(|_| Bip456HintsError::Encoding)?
                >= spendable_output_count
            {
                return Err(Bip456HintsError::IndexOutOfRange);
            }
            decode_elias_fano(
                &mut self.reader,
                n,
                max,
                &mut self.encoded_bytes,
                self.max_encoded_bytes,
            )?
        };

        if self.next_height == self.target_height {
            self.finish()?;
        } else {
            self.next_height = self
                .next_height
                .checked_add(1)
                .ok_or(Bip456HintsError::HeightOrder)?;
        }
        Ok(indices)
    }

    fn finish(&mut self) -> Result<(), Bip456HintsError> {
        let mut extra = [0u8; 1];
        match self.reader.read(&mut extra) {
            Ok(0) => {
                self.finished = true;
                Ok(())
            }
            Ok(_) => Err(Bip456HintsError::TrailingData),
            Err(error) => Err(Bip456HintsError::Io(error)),
        }
    }

    fn read_compact_u32(&mut self) -> Result<u32, Bip456HintsError> {
        let mut prefix = [0u8; 1];
        self.read_counted(&mut prefix)?;
        match prefix[0] {
            n @ 0..=0xfc => Ok(u32::from(n)),
            0xfd => {
                let mut bytes = [0u8; 2];
                self.read_counted(&mut bytes)?;
                let value = u32::from(u16::from_le_bytes(bytes));
                if value < 0xfd {
                    return Err(Bip456HintsError::Encoding);
                }
                Ok(value)
            }
            0xfe => {
                let mut bytes = [0u8; 4];
                self.read_counted(&mut bytes)?;
                let value = u32::from_le_bytes(bytes);
                if value <= u32::from(u16::MAX) {
                    return Err(Bip456HintsError::Encoding);
                }
                Ok(value)
            }
            0xff => Err(Bip456HintsError::Encoding),
        }
    }

    fn read_counted(&mut self, bytes: &mut [u8]) -> Result<(), Bip456HintsError> {
        let next = self
            .encoded_bytes
            .checked_add(
                u64::try_from(bytes.len()).map_err(|_| Bip456HintsError::EncodedSizeLimit)?,
            )
            .ok_or(Bip456HintsError::EncodedSizeLimit)?;
        if next > self.max_encoded_bytes {
            return Err(Bip456HintsError::EncodedSizeLimit);
        }
        self.reader.read_exact(bytes)?;
        self.encoded_bytes = next;
        Ok(())
    }
}

fn decode_elias_fano<R: Read>(
    reader: &mut R,
    n: usize,
    max: u32,
    encoded_bytes: &mut u64,
    max_encoded_bytes: u64,
) -> Result<Vec<u32>, Bip456HintsError> {
    let quotient =
        (u64::from(max) + 1) / u64::try_from(n).map_err(|_| Bip456HintsError::Encoding)?;
    let low_bits = usize::try_from(quotient.ilog2()).map_err(|_| Bip456HintsError::Encoding)?;
    let low_bit_count = n
        .checked_mul(low_bits)
        .ok_or(Bip456HintsError::RecordSizeLimit)?;
    let high_bit_count = n
        .checked_add(
            usize::try_from(u64::from(max) >> low_bits)
                .map_err(|_| Bip456HintsError::RecordSizeLimit)?,
        )
        .ok_or(Bip456HintsError::RecordSizeLimit)?;
    let low_bytes = low_bit_count.div_ceil(8);
    let high_bytes = high_bit_count.div_ceil(8);
    let record_bytes = low_bytes
        .checked_add(high_bytes)
        .ok_or(Bip456HintsError::RecordSizeLimit)?;
    if record_bytes > MAX_HINT_RECORD_BYTES {
        return Err(Bip456HintsError::RecordSizeLimit);
    }
    let next_total = encoded_bytes
        .checked_add(u64::try_from(record_bytes).map_err(|_| Bip456HintsError::EncodedSizeLimit)?)
        .ok_or(Bip456HintsError::EncodedSizeLimit)?;
    if next_total > max_encoded_bytes {
        return Err(Bip456HintsError::EncodedSizeLimit);
    }
    let mut low = vec![0u8; low_bytes];
    let mut high = vec![0u8; high_bytes];
    reader.read_exact(&mut low)?;
    reader.read_exact(&mut high)?;
    *encoded_bytes = next_total;

    if !padding_is_zero(&low, low_bit_count) || !padding_is_zero(&high, high_bit_count) {
        return Err(Bip456HintsError::Encoding);
    }
    let mut indices = Vec::with_capacity(n);
    let mut high_ordinal = 0usize;
    for bit_position in 0..high_bit_count {
        if bit(&high, bit_position) {
            let high_value = bit_position
                .checked_sub(high_ordinal)
                .ok_or(Bip456HintsError::Encoding)?;
            let low_value = unpack_low(&low, high_ordinal, low_bits)?;
            let value = (u64::try_from(high_value).map_err(|_| Bip456HintsError::Encoding)?
                << low_bits)
                | u64::from(low_value);
            let value = u32::try_from(value).map_err(|_| Bip456HintsError::Encoding)?;
            if value > max || indices.last().is_some_and(|last| *last >= value) {
                return Err(Bip456HintsError::Encoding);
            }
            indices.push(value);
            high_ordinal += 1;
        }
    }
    if high_ordinal != n || indices.last().copied() != Some(max) {
        return Err(Bip456HintsError::Encoding);
    }
    Ok(indices)
}

fn bit(bytes: &[u8], index: usize) -> bool {
    (bytes[index / 8] & (1 << (index % 8))) != 0
}

fn padding_is_zero(bytes: &[u8], bit_count: usize) -> bool {
    let used = bit_count % 8;
    used == 0
        || bytes
            .last()
            .is_none_or(|byte| byte & !((1u8 << used) - 1) == 0)
}

fn unpack_low(bytes: &[u8], item: usize, width: usize) -> Result<u32, Bip456HintsError> {
    let start = item.checked_mul(width).ok_or(Bip456HintsError::Encoding)?;
    let mut value = 0u32;
    for bit_offset in 0..width {
        if bit(bytes, start + bit_offset) {
            value |= 1u32
                .checked_shl(u32::try_from(bit_offset).map_err(|_| Bip456HintsError::Encoding)?)
                .ok_or(Bip456HintsError::Encoding)?;
        }
    }
    Ok(value)
}

/// Malformed hints or local decoding/resource limits. Use ordinary validation on failure.
#[derive(Debug, thiserror::Error)]
pub enum Bip456HintsError {
    /// Underlying hints file could not be read.
    #[error("hintsfile I/O error: {0}")]
    Io(#[from] io::Error),
    /// The file does not start with the BIP456 `UTXO` magic.
    #[error("unknown BIP456 hintsfile magic")]
    Magic,
    /// Unsupported BIP456 serialization version.
    #[error("unsupported BIP456 hintsfile version {0}")]
    Version(u8),
    /// File target height differs from the caller's pinned target.
    #[error("BIP456 hintsfile height mismatch: expected {expected}, got {actual}")]
    Height { expected: u32, actual: u32 },
    /// Heights must be consumed exactly once in order from genesis to target.
    #[error("BIP456 hintsfile heights are not consumed sequentially")]
    HeightOrder,
    /// Noncanonical CompactSize or malformed Elias-Fano data.
    #[error("malformed or noncanonical BIP456 hints encoding")]
    Encoding,
    /// More indices than configured bounds or the block's spendable-output count.
    #[error("BIP456 hints index count exceeds local limits")]
    IndexCountLimit,
    /// An index does not refer to a spendable output in the local block.
    #[error("BIP456 hints index is out of range for the local block")]
    IndexOutOfRange,
    /// One Elias-Fano record exceeds its per-height byte cap.
    #[error("BIP456 hints record exceeds its byte limit")]
    RecordSizeLimit,
    /// The entire stream exceeds its configured encoded byte cap.
    #[error("BIP456 hintsfile exceeds its encoded byte limit")]
    EncodedSizeLimit,
    /// Data follows the expected final height's Elias-Fano record.
    #[error("trailing bytes after the final BIP456 hints record")]
    TrailingData,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{Bip456HintsError, Bip456HintsReader};
    use std::io::Cursor;

    fn header(height: u32) -> Vec<u8> {
        let mut bytes = b"UTXO\0".to_vec();
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes
    }

    #[test]
    fn reads_reference_ef_vector_and_empty_heights_sequentially() {
        // The BIP456 reference vector encodes [3, 7, 12] as
        // N=3, M=12, low=0x0f, high=0x25 (LSB-first).
        let mut bytes = header(1);
        bytes.extend_from_slice(&[0x03, 0x0c, 0x0f, 0x25]);
        bytes.push(0x00); // height 1: no target survivors
        let mut reader = Bip456HintsReader::new(Cursor::new(bytes), 1, 1024).unwrap();
        assert_eq!(reader.next_indices(0, 13).unwrap(), [3, 7, 12]);
        assert!(reader.next_indices(1, 0).unwrap().is_empty());
    }

    #[test]
    fn rejects_wrong_height_order_noncanonical_lengths_and_trailing_data() {
        let mut bytes = header(0);
        bytes.push(0x00);
        let mut reader = Bip456HintsReader::new(Cursor::new(bytes.clone()), 0, 1024).unwrap();
        assert!(matches!(
            reader.next_indices(1, 0),
            Err(Bip456HintsError::HeightOrder)
        ));

        bytes[9] = 0xfd; // N=0 encoded with an unnecessarily wide CompactSize.
        bytes.extend_from_slice(&[0, 0]);
        let mut reader = Bip456HintsReader::new(Cursor::new(bytes), 0, 1024).unwrap();
        assert!(matches!(
            reader.next_indices(0, 0),
            Err(Bip456HintsError::Encoding)
        ));

        let mut bytes = header(0);
        bytes.extend_from_slice(&[0, 0xff]);
        let mut reader = Bip456HintsReader::new(Cursor::new(bytes), 0, 1024).unwrap();
        assert!(matches!(
            reader.next_indices(0, 0),
            Err(Bip456HintsError::TrailingData)
        ));
    }
}

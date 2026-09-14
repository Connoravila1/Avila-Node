//! Bounded binary decoding cursor and CompactSize (varint) codec, matching Bitcoin Core's
//! `serialize.h`.
//!
//! [`Decoder`] never reads past the end of the byte slice it was created from, and every method
//! that could otherwise be tricked into a large allocation by a maliciously large declared
//! length (a `CompactSize` count, for instance) checks the claim against the bytes actually
//! remaining *before* allocating anything.

use thiserror::Error;

/// Core `serialize.h`'s `MAX_SIZE`: the largest value a canonical `CompactSize` may encode when
/// range-checked (as it always is when used as a vector length prefix).
pub const MAX_SIZE: u64 = 0x0200_0000;

/// Core `serialize.h`'s `MAX_VECTOR_ALLOCATE`: the most memory, in bytes, Core allocates in one
/// shot while deserializing a vector, regardless of the declared element count. Informational
/// here; callers bound their own reservations with [`Decoder::bounded_capacity`], which reasons
/// from the bytes actually available rather than from this fixed cap.
pub const MAX_VECTOR_ALLOCATE: usize = 5_000_000;

/// Errors that can occur while decoding a Bitcoin serialization format.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// The decoder needed more bytes than remained in the input.
    #[error("unexpected end of input: needed {needed} byte(s), {remaining} remaining")]
    UnexpectedEnd {
        /// Number of bytes the read required.
        needed: usize,
        /// Number of bytes actually left in the input.
        remaining: usize,
    },
    /// A `CompactSize` was encoded with more bytes than its value required.
    #[error("non-canonical CompactSize encoding")]
    NonCanonicalCompactSize,
    /// A canonically encoded `CompactSize` exceeded [`MAX_SIZE`].
    #[error("CompactSize {0} exceeds the maximum allowed size of {MAX_SIZE}")]
    CompactSizeTooLarge(u64),
    /// Strict top-level decoding found bytes after the value it decoded.
    #[error("{0} unexpected trailing byte(s) after decoding")]
    TrailingBytes(usize),
    /// The input itself exceeded a hard length limit before any decoding was attempted.
    #[error("input length {len} exceeds limit of {limit} byte(s)")]
    InputTooLarge {
        /// The length of the offending input, in bytes.
        len: usize,
        /// The maximum permitted length, in bytes.
        limit: usize,
    },
    /// A transaction's witness flag was set but no input actually carried a witness (Core:
    /// "Superfluous witness record").
    #[error("Superfluous witness record")]
    SuperfluousWitness,
    /// A transaction's optional-data flags byte had bits set beyond the ones this decoder
    /// understands (Core: "Unknown transaction optional data").
    #[error("Unknown transaction optional data (flags = {0:#04x})")]
    UnknownTransactionFlags(u8),
    /// A block header's serialization was not exactly 80 bytes long.
    #[error("header length {0} is not exactly 80 bytes")]
    HeaderLength(usize),
}

/// A cursor over a borrowed byte slice that decodes Bitcoin's binary serialization formats.
///
/// Every read either succeeds and advances [`Decoder::position`] by exactly the number of bytes
/// consumed, or fails with a [`DecodeError`] and leaves the cursor unchanged.
pub struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    /// Creates a decoder positioned at the start of `bytes`.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Returns the current byte offset into the original input.
    #[must_use]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Returns the number of bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        // `position` never exceeds `bytes.len()`: every read checks first.
        self.bytes.len().saturating_sub(self.position)
    }

    /// Returns `true` if every byte of the input has been consumed.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.remaining() == 0
    }

    /// Reads a single byte.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] if the input is exhausted.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_array::<1>()?[0])
    }

    /// Reads a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] if fewer than 2 bytes remain.
    pub fn read_u16_le(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    /// Reads a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] if fewer than 4 bytes remain.
    pub fn read_u32_le(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    /// Reads a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] if fewer than 8 bytes remain.
    pub fn read_u64_le(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    /// Reads a little-endian `i32`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] if fewer than 4 bytes remain.
    pub fn read_i32_le(&mut self) -> Result<i32, DecodeError> {
        Ok(i32::from_le_bytes(self.read_array::<4>()?))
    }

    /// Reads a little-endian `i64`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] if fewer than 8 bytes remain.
    pub fn read_i64_le(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.read_array::<8>()?))
    }

    /// Reads exactly `len` raw bytes, borrowed from the original input.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] if fewer than `len` bytes remain. No allocation
    /// occurs in either case: the returned slice borrows directly from the input.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let remaining = self.remaining();
        if len > remaining {
            return Err(DecodeError::UnexpectedEnd {
                needed: len,
                remaining,
            });
        }
        // `position + len <= bytes.len()` was just established via `remaining`.
        let slice = &self.bytes[self.position..self.position + len];
        self.position += len;
        Ok(slice)
    }

    /// Reads exactly `N` raw bytes into an owned array.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] if fewer than `N` bytes remain.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let slice = self.read_bytes(N)?;
        let mut array = [0u8; N];
        // `read_bytes` returns a slice of exactly `N` bytes on success.
        array.copy_from_slice(slice);
        Ok(array)
    }

    /// Reads a canonical `CompactSize`, matching Core's `ReadCompactSize(range_check = true)`.
    ///
    /// The shortest encoding for the value must have been used (`253`/`254`/`255` prefixes are
    /// rejected when the value they introduce would fit in a shorter form), and the decoded
    /// value must not exceed [`MAX_SIZE`].
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEnd`] if the input ends before the full encoding is
    /// read, [`DecodeError::NonCanonicalCompactSize`] if a shorter encoding exists for the
    /// decoded value, or [`DecodeError::CompactSizeTooLarge`] if the value exceeds [`MAX_SIZE`].
    pub fn read_compact_size(&mut self) -> Result<u64, DecodeError> {
        let start = self.position;
        self.read_compact_size_inner()
            .inspect_err(|_| self.position = start)
    }

    /// The body of [`Decoder::read_compact_size`], factored out so the public method can reset
    /// [`Decoder::position`] to its pre-call value on any error path in one place.
    fn read_compact_size_inner(&mut self) -> Result<u64, DecodeError> {
        let prefix = self.read_u8()?;
        let value = if prefix < 253 {
            u64::from(prefix)
        } else if prefix == 253 {
            let value = u64::from(self.read_u16_le()?);
            if value < 253 {
                return Err(DecodeError::NonCanonicalCompactSize);
            }
            value
        } else if prefix == 254 {
            let value = u64::from(self.read_u32_le()?);
            if value < 0x1_0000 {
                return Err(DecodeError::NonCanonicalCompactSize);
            }
            value
        } else {
            let value = self.read_u64_le()?;
            if value < 0x1_0000_0000 {
                return Err(DecodeError::NonCanonicalCompactSize);
            }
            value
        };
        if value > MAX_SIZE {
            return Err(DecodeError::CompactSizeTooLarge(value));
        }
        Ok(value)
    }

    /// Reads a `CompactSize` length prefix followed by that many bytes, returned as an owned
    /// `Vec`.
    ///
    /// The declared length is checked against [`Decoder::remaining`] *before* any allocation is
    /// made (inherited from [`Decoder::read_bytes`]), so a maliciously large prefix on a small
    /// input fails immediately instead of allocating.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`Decoder::read_compact_size`], or
    /// [`DecodeError::UnexpectedEnd`] if fewer bytes than declared remain.
    pub fn read_var_bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let start = self.position;
        self.read_var_bytes_inner()
            .inspect_err(|_| self.position = start)
    }

    /// The body of [`Decoder::read_var_bytes`], factored out so the public method can reset
    /// [`Decoder::position`] to its pre-call value on any error path in one place - including
    /// the case where the `CompactSize` prefix itself reads successfully (advancing `position`)
    /// but the subsequent [`Decoder::read_bytes`] call fails.
    fn read_var_bytes_inner(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.read_compact_size()?;
        // `len <= MAX_SIZE` (about 33.5 million) always fits in `usize`, even on 32-bit
        // targets, but convert defensively rather than assume it.
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        Ok(self.read_bytes(len)?.to_vec())
    }

    /// Consumes the decoder, succeeding only if every byte of the input was consumed.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::TrailingBytes`] with the number of leftover bytes if any remain.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.is_finished() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes(self.remaining()))
        }
    }

    /// A bounded reservation helper for `Vec::with_capacity`-style pre-allocation: the smaller
    /// of the `declared` element count and how many `min_element_size`-byte elements could
    /// possibly fit in the bytes still remaining.
    ///
    /// This lets a decoder honor a small, honest declared count while refusing to pre-allocate
    /// for a declared count vastly larger than the input could possibly contain; an oversized
    /// declared count simply fails naturally once decoding runs out of input.
    ///
    /// `min_element_size` must be the true minimum encoded size, in bytes, of one element of
    /// the type being decoded; passing `0` for a type that actually occupies one or more bytes
    /// defeats the bound. Since "how many fit" is undefined when elements are 0 bytes, that
    /// case is defined here as returning `declared.min(remaining)` — i.e. every remaining byte
    /// is treated as a possible element — rather than panicking or saturating to `0`.
    #[must_use]
    pub fn bounded_capacity(&self, declared: u64, min_element_size: usize) -> usize {
        let remaining = self.remaining();
        let by_remaining = remaining.checked_div(min_element_size).unwrap_or(remaining);
        let declared = usize::try_from(declared).unwrap_or(usize::MAX);
        declared.min(by_remaining)
    }
}

/// Returns the length in bytes (1, 3, 5, or 9) of `value`'s canonical `CompactSize` encoding.
#[must_use]
pub fn compact_size_len(value: u64) -> usize {
    if value < 253 {
        1
    } else if value <= u64::from(u16::MAX) {
        3
    } else if value <= u64::from(u32::MAX) {
        5
    } else {
        9
    }
}

/// Appends `value`'s canonical `CompactSize` encoding to `out`, matching Core's
/// `WriteCompactSize`.
pub fn write_compact_size(out: &mut Vec<u8>, value: u64) {
    if value < 253 {
        out.push(value as u8);
    } else if value <= u64::from(u16::MAX) {
        out.push(253);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= u64::from(u32::MAX) {
        out.push(254);
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        out.push(255);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Appends a `CompactSize` length prefix followed by `bytes` to `out`.
pub fn write_var_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ---- basic cursor behavior ----

    #[test]
    fn new_decoder_starts_at_zero() {
        let d = Decoder::new(&[1, 2, 3]);
        assert_eq!(d.position(), 0);
        assert_eq!(d.remaining(), 3);
        assert!(!d.is_finished());
    }

    #[test]
    fn empty_decoder_is_finished() {
        let d = Decoder::new(&[]);
        assert!(d.is_finished());
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn read_u8_advances_position() {
        let mut d = Decoder::new(&[0x42, 0x43]);
        assert_eq!(d.read_u8().unwrap(), 0x42);
        assert_eq!(d.position(), 1);
        assert_eq!(d.read_u8().unwrap(), 0x43);
        assert!(d.is_finished());
    }

    #[test]
    fn read_u8_on_empty_errors() {
        let mut d = Decoder::new(&[]);
        assert_eq!(
            d.read_u8(),
            Err(DecodeError::UnexpectedEnd {
                needed: 1,
                remaining: 0
            })
        );
        // The cursor must not have moved.
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn read_u16_le_round_trip() {
        let mut d = Decoder::new(&[0x34, 0x12]);
        assert_eq!(d.read_u16_le().unwrap(), 0x1234);
    }

    #[test]
    fn read_u16_le_truncated() {
        let mut d = Decoder::new(&[0x34]);
        assert_eq!(
            d.read_u16_le(),
            Err(DecodeError::UnexpectedEnd {
                needed: 2,
                remaining: 1
            })
        );
    }

    #[test]
    fn read_u32_le_round_trip() {
        let mut d = Decoder::new(&[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(d.read_u32_le().unwrap(), 0x1234_5678);
    }

    #[test]
    fn read_u32_le_truncated() {
        let mut d = Decoder::new(&[0x78, 0x56, 0x34]);
        assert_eq!(
            d.read_u32_le(),
            Err(DecodeError::UnexpectedEnd {
                needed: 4,
                remaining: 3
            })
        );
    }

    #[test]
    fn read_u64_le_round_trip() {
        let bytes = 0x0123_4567_89ab_cdefu64.to_le_bytes();
        let mut d = Decoder::new(&bytes);
        assert_eq!(d.read_u64_le().unwrap(), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn read_u64_le_truncated() {
        let mut d = Decoder::new(&[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            d.read_u64_le(),
            Err(DecodeError::UnexpectedEnd {
                needed: 8,
                remaining: 7
            })
        );
    }

    #[test]
    fn read_i32_le_round_trip_negative() {
        let neg_one = (-1i32).to_le_bytes();
        let mut d = Decoder::new(&neg_one);
        assert_eq!(d.read_i32_le().unwrap(), -1);
        let min = i32::MIN.to_le_bytes();
        let mut d = Decoder::new(&min);
        assert_eq!(d.read_i32_le().unwrap(), i32::MIN);
    }

    #[test]
    fn read_i32_le_truncated() {
        let mut d = Decoder::new(&[1, 2, 3]);
        assert_eq!(
            d.read_i32_le(),
            Err(DecodeError::UnexpectedEnd {
                needed: 4,
                remaining: 3
            })
        );
    }

    #[test]
    fn read_i64_le_round_trip_negative() {
        let neg_one = (-1i64).to_le_bytes();
        let mut d = Decoder::new(&neg_one);
        assert_eq!(d.read_i64_le().unwrap(), -1);
        let min = i64::MIN.to_le_bytes();
        let mut d = Decoder::new(&min);
        assert_eq!(d.read_i64_le().unwrap(), i64::MIN);
    }

    #[test]
    fn read_i64_le_truncated() {
        let mut d = Decoder::new(&[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            d.read_i64_le(),
            Err(DecodeError::UnexpectedEnd {
                needed: 8,
                remaining: 7
            })
        );
    }

    #[test]
    fn read_bytes_returns_slice_and_advances() {
        let data = [1, 2, 3, 4, 5];
        let mut d = Decoder::new(&data);
        assert_eq!(d.read_bytes(3).unwrap(), &[1, 2, 3]);
        assert_eq!(d.position(), 3);
        assert_eq!(d.read_bytes(2).unwrap(), &[4, 5]);
        assert!(d.is_finished());
    }

    #[test]
    fn read_bytes_zero_length_on_empty_ok() {
        let mut d = Decoder::new(&[]);
        assert_eq!(d.read_bytes(0).unwrap(), &[] as &[u8]);
    }

    #[test]
    fn read_bytes_truncated() {
        let data = [1, 2];
        let mut d = Decoder::new(&data);
        assert_eq!(
            d.read_bytes(3),
            Err(DecodeError::UnexpectedEnd {
                needed: 3,
                remaining: 2
            })
        );
        // Failed read must not move the cursor.
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn read_array_round_trip() {
        let data = [0xaa, 0xbb, 0xcc, 0xdd];
        let mut d = Decoder::new(&data);
        let arr: [u8; 4] = d.read_array().unwrap();
        assert_eq!(arr, data);
        assert!(d.is_finished());
    }

    #[test]
    fn read_array_truncated() {
        let data = [0xaa, 0xbb];
        let mut d = Decoder::new(&data);
        let result: Result<[u8; 4], DecodeError> = d.read_array();
        assert_eq!(
            result,
            Err(DecodeError::UnexpectedEnd {
                needed: 4,
                remaining: 2
            })
        );
    }

    #[test]
    fn read_array_zero_size() {
        let mut d = Decoder::new(&[1, 2, 3]);
        let arr: [u8; 0] = d.read_array().unwrap();
        assert_eq!(arr, []);
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn finish_ok_when_fully_consumed() {
        let mut d = Decoder::new(&[1, 2]);
        d.read_u16_le().unwrap();
        assert_eq!(d.finish(), Ok(()));
    }

    #[test]
    fn finish_errors_on_trailing_bytes() {
        let mut d = Decoder::new(&[1, 2, 3]);
        d.read_u8().unwrap();
        assert_eq!(d.finish(), Err(DecodeError::TrailingBytes(2)));
    }

    #[test]
    fn finish_ok_on_empty_input() {
        let d = Decoder::new(&[]);
        assert_eq!(d.finish(), Ok(()));
    }

    // ---- CompactSize decoding ----

    #[test]
    fn compact_size_canonical_boundaries() {
        // These all decode successfully because their values do not exceed MAX_SIZE.
        let cases: &[(&[u8], u64)] = &[
            (&[0x00], 0),
            (&[0xfc], 252),
            (&[0xfd, 0xfd, 0x00], 253),
            (&[0xfd, 0xff, 0xff], 0xffff),
            (&[0xfe, 0x00, 0x00, 0x01, 0x00], 0x1_0000),
        ];
        for (bytes, expected) in cases {
            let mut d = Decoder::new(bytes);
            assert_eq!(d.read_compact_size(), Ok(*expected), "input {bytes:02x?}");
            assert!(d.is_finished());
        }
    }

    #[test]
    fn compact_size_canonical_but_exceeds_max_size() {
        // 0xffffffff is encoded canonically with the 0xfe (u32) prefix, and 0x1_0000_0000 needs
        // the 0xff (u64) prefix; both are valid *encodings* but exceed MAX_SIZE, so both are
        // rejected by the range check rather than as non-canonical.
        let mut d = Decoder::new(&[0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::CompactSizeTooLarge(0xffff_ffff))
        );

        let mut d = Decoder::new(&[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::CompactSizeTooLarge(0x1_0000_0000))
        );
    }

    #[test]
    fn compact_size_max_size_accepted() {
        let mut bytes = vec![0xfe];
        bytes.extend_from_slice(&(MAX_SIZE as u32).to_le_bytes());
        let mut d = Decoder::new(&bytes);
        assert_eq!(d.read_compact_size(), Ok(MAX_SIZE));
    }

    #[test]
    fn compact_size_max_size_plus_one_rejected() {
        let over = MAX_SIZE + 1;
        let mut bytes = vec![0xfe];
        bytes.extend_from_slice(&(over as u32).to_le_bytes());
        let mut d = Decoder::new(&bytes);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::CompactSizeTooLarge(over))
        );
    }

    #[test]
    fn compact_size_non_canonical_253() {
        // 0xfd followed by 0x00fc (252): should have been encoded as a single byte.
        let mut d = Decoder::new(&[0xfd, 0xfc, 0x00]);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::NonCanonicalCompactSize)
        );
        // A failed read must leave the cursor exactly where it started, even though every
        // byte of the (rejected) encoding was actually read.
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn compact_size_non_canonical_254() {
        // 0xfe followed by 0x0000ffff (65535): should have used the 0xfd form.
        let mut d = Decoder::new(&[0xfe, 0xff, 0xff, 0x00, 0x00]);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::NonCanonicalCompactSize)
        );
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn compact_size_non_canonical_255() {
        // 0xff followed by 0x00000000ffffffff: should have used the 0xfe form.
        let mut d = Decoder::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::NonCanonicalCompactSize)
        );
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn compact_size_truncated_at_prefix() {
        let mut d = Decoder::new(&[]);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::UnexpectedEnd {
                needed: 1,
                remaining: 0
            })
        );
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn compact_size_truncated_after_253_prefix() {
        let mut d = Decoder::new(&[0xfd, 0x01]);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::UnexpectedEnd {
                needed: 2,
                remaining: 1
            })
        );
        // The prefix byte was consumed internally by the failed multi-byte read; the cursor
        // must still be rolled all the way back to 0, not left at 1.
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn compact_size_truncated_after_254_prefix() {
        let mut d = Decoder::new(&[0xfe, 0x01, 0x02]);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::UnexpectedEnd {
                needed: 4,
                remaining: 2
            })
        );
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn compact_size_truncated_after_255_prefix() {
        let mut d = Decoder::new(&[0xff, 1, 2, 3]);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::UnexpectedEnd {
                needed: 8,
                remaining: 3
            })
        );
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn compact_size_too_large_leaves_position_unchanged() {
        // The full multi-byte encoding is read and decoded successfully before the range
        // check rejects it; the cursor must still roll back to the start on this error path.
        let mut d = Decoder::new(&[0xfe, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::CompactSizeTooLarge(0xffff_ffff))
        );
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn compact_size_failure_never_advances_position_from_nonzero_start() {
        // The rollback must restore the position the cursor was actually at before the call,
        // not just reset it to 0 - exercise it starting from a nonzero offset.
        let mut d = Decoder::new(&[0xaa, 0xfd, 0xfc, 0x00]);
        d.read_u8().unwrap();
        assert_eq!(d.position(), 1);
        assert_eq!(
            d.read_compact_size(),
            Err(DecodeError::NonCanonicalCompactSize)
        );
        assert_eq!(d.position(), 1);
    }

    // ---- write/read round trips and compact_size_len ----

    #[test]
    fn write_read_round_trip_boundaries() {
        // Bounded by MAX_SIZE: read_compact_size range-checks the decoded value, so only
        // values it will actually accept round-trip through both write and read here.
        // compact_size_len / write_compact_size for values beyond MAX_SIZE are covered
        // separately in `compact_size_len_boundaries` and
        // `write_compact_size_produces_canonical_prefixes`.
        let values = [0u64, 1, 252, 253, 254, 255, 0xffff, 0x1_0000, MAX_SIZE];
        for value in values {
            let mut out = Vec::new();
            write_compact_size(&mut out, value);
            assert_eq!(out.len(), compact_size_len(value));
            let mut d = Decoder::new(&out);
            assert_eq!(d.read_compact_size(), Ok(value), "value {value}");
            assert!(d.is_finished());
        }
    }

    #[test]
    fn compact_size_len_boundaries() {
        assert_eq!(compact_size_len(0), 1);
        assert_eq!(compact_size_len(252), 1);
        assert_eq!(compact_size_len(253), 3);
        assert_eq!(compact_size_len(0xffff), 3);
        assert_eq!(compact_size_len(0x1_0000), 5);
        assert_eq!(compact_size_len(0xffff_ffff), 5);
        assert_eq!(compact_size_len(0x1_0000_0000), 9);
        assert_eq!(compact_size_len(u64::MAX), 9);
    }

    #[test]
    fn write_compact_size_produces_canonical_prefixes() {
        let mut out = Vec::new();
        write_compact_size(&mut out, 252);
        assert_eq!(out, vec![0xfc]);

        let mut out = Vec::new();
        write_compact_size(&mut out, 253);
        assert_eq!(out, vec![0xfd, 0xfd, 0x00]);

        let mut out = Vec::new();
        write_compact_size(&mut out, 0x1_0000);
        assert_eq!(out, vec![0xfe, 0x00, 0x00, 0x01, 0x00]);

        let mut out = Vec::new();
        write_compact_size(&mut out, 0x1_0000_0000);
        assert_eq!(
            out,
            vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
    }

    // ---- var bytes ----

    #[test]
    fn var_bytes_round_trip() {
        let mut out = Vec::new();
        write_var_bytes(&mut out, b"hello");
        let mut d = Decoder::new(&out);
        assert_eq!(d.read_var_bytes().unwrap(), b"hello".to_vec());
        assert!(d.is_finished());
    }

    #[test]
    fn var_bytes_empty_round_trip() {
        let mut out = Vec::new();
        write_var_bytes(&mut out, b"");
        assert_eq!(out, vec![0x00]);
        let mut d = Decoder::new(&out);
        assert_eq!(d.read_var_bytes().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn var_bytes_truncated_does_not_allocate_gigabytes() {
        // A declared length of MAX_SIZE (~33 million) on a two-byte buffer must fail
        // immediately with UnexpectedEnd, not attempt to allocate ~33 MB.
        let mut declared = vec![0xfe];
        declared.extend_from_slice(&(MAX_SIZE as u32).to_le_bytes());
        declared.extend_from_slice(&[0xaa, 0xbb]); // far short of MAX_SIZE bytes of payload
        let mut d = Decoder::new(&declared);
        let result = d.read_var_bytes();
        assert_eq!(
            result,
            Err(DecodeError::UnexpectedEnd {
                needed: MAX_SIZE as usize,
                remaining: 2
            })
        );
    }

    #[test]
    fn var_bytes_length_exceeding_max_size_rejected_before_allocation() {
        let mut declared = vec![0xfe];
        declared.extend_from_slice(&((MAX_SIZE + 1) as u32).to_le_bytes());
        let mut d = Decoder::new(&declared);
        assert_eq!(
            d.read_var_bytes(),
            Err(DecodeError::CompactSizeTooLarge(MAX_SIZE + 1))
        );
    }

    #[test]
    fn var_bytes_failure_after_single_byte_prefix_rolls_back_position() {
        // The CompactSize prefix (a single canonical byte, value 5) reads and advances
        // successfully; the subsequent `read_bytes(5)` then fails because only 2 bytes of
        // payload follow. The cursor must roll all the way back to 0, not stay at 1.
        let mut d = Decoder::new(&[0x05, 0xaa, 0xbb]);
        assert_eq!(
            d.read_var_bytes(),
            Err(DecodeError::UnexpectedEnd {
                needed: 5,
                remaining: 2
            })
        );
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn var_bytes_failure_after_multi_byte_prefix_rolls_back_position() {
        // The CompactSize prefix is the multi-byte 0xfd form (declaring 300), which itself
        // reads successfully and advances the cursor 3 bytes before `read_bytes(300)` fails
        // against the 2 payload bytes actually present. The cursor must roll back past the
        // entire consumed prefix, not just partially.
        let mut d = Decoder::new(&[0xfd, 0x2c, 0x01, 0xaa, 0xbb]);
        assert_eq!(
            d.read_var_bytes(),
            Err(DecodeError::UnexpectedEnd {
                needed: 300,
                remaining: 2
            })
        );
        assert_eq!(d.position(), 0);
    }

    #[test]
    fn var_bytes_failure_never_advances_position_from_nonzero_start() {
        // As with `compact_size_failure_never_advances_position_from_nonzero_start`, the
        // rollback must restore the position the cursor was actually at before the call, not
        // just reset it to 0 - exercise it starting from a nonzero offset.
        let mut d = Decoder::new(&[0xaa, 0x05, 0xbb, 0xcc]);
        d.read_u8().unwrap();
        assert_eq!(d.position(), 1);
        assert_eq!(
            d.read_var_bytes(),
            Err(DecodeError::UnexpectedEnd {
                needed: 5,
                remaining: 2
            })
        );
        assert_eq!(d.position(), 1);
    }

    // ---- bounded_capacity ----

    #[test]
    fn bounded_capacity_limited_by_remaining_bytes() {
        let data = [0u8; 10];
        let d = Decoder::new(&data);
        // Declared 1000 elements of 41 bytes each; only 10 bytes remain (0 whole elements).
        assert_eq!(d.bounded_capacity(1000, 41), 0);
    }

    #[test]
    fn bounded_capacity_limited_by_declared_count() {
        let data = [0u8; 1000];
        let d = Decoder::new(&data);
        // Only 3 elements declared even though far more could physically fit.
        assert_eq!(d.bounded_capacity(3, 9), 3);
    }

    #[test]
    fn bounded_capacity_huge_declared_count_short_buffer() {
        let data = [0u8; 4];
        let d = Decoder::new(&data);
        assert_eq!(d.bounded_capacity(MAX_SIZE, 41), 0);
    }

    #[test]
    fn bounded_capacity_zero_element_size_does_not_panic() {
        let data = [0u8; 4];
        let d = Decoder::new(&data);
        assert_eq!(d.bounded_capacity(10, 0), 4);
    }

    // ---- error Display messages ----

    #[test]
    fn error_display_messages() {
        assert_eq!(
            DecodeError::UnexpectedEnd {
                needed: 4,
                remaining: 1
            }
            .to_string(),
            "unexpected end of input: needed 4 byte(s), 1 remaining"
        );
        assert_eq!(
            DecodeError::NonCanonicalCompactSize.to_string(),
            "non-canonical CompactSize encoding"
        );
        assert_eq!(
            DecodeError::CompactSizeTooLarge(99).to_string(),
            "CompactSize 99 exceeds the maximum allowed size of 33554432"
        );
        assert_eq!(
            DecodeError::TrailingBytes(3).to_string(),
            "3 unexpected trailing byte(s) after decoding"
        );
        assert_eq!(
            DecodeError::InputTooLarge { len: 10, limit: 5 }.to_string(),
            "input length 10 exceeds limit of 5 byte(s)"
        );
        assert_eq!(
            DecodeError::SuperfluousWitness.to_string(),
            "Superfluous witness record"
        );
        assert_eq!(
            DecodeError::UnknownTransactionFlags(2).to_string(),
            "Unknown transaction optional data (flags = 0x02)"
        );
        assert_eq!(
            DecodeError::HeaderLength(79).to_string(),
            "header length 79 is not exactly 80 bytes"
        );
    }
}

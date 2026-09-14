//! 256-bit unsigned integer arithmetic and compact-target (`nBits`) encoding.
//!
//! [`U256`] mirrors the semantics of Bitcoin Core's `arith_uint256`
//! (`arith_uint256.h`/`.cpp`): a fixed-width 256-bit unsigned integer used for proof-of-work
//! targets and cumulative chain work. [`CompactTarget`] implements the "compact" (`nBits`)
//! encoding used throughout the consensus protocol, matching `arith_uint256::SetCompact` /
//! `GetCompact` bit for bit, including their negative/overflow edge cases. [`Target`] and
//! [`Work`] are thin, purpose-specific wrappers, with [`Work::from_compact`] matching Core's
//! `GetBitsProof` (declared in `chain.h`; the out-of-line definition was not present in the
//! pinned source checkout, so its arithmetic identity is taken from the specification and
//! cross-checked against the required test vectors below).
//!
//! This module is intentionally self-contained: it implements its own minimal hex
//! parsing/formatting for [`U256::from_hex`]/[`U256::to_hex`] rather than depending on
//! `crate::hex`, since that module is developed independently.
//!
//! Byte-order note: unlike the hash newtypes (`BlockHash`, `Txid`, ...), which display in
//! reversed-byte order by historical convention, `U256` is a genuine number: its hex
//! representation (`to_hex`/`from_hex`/`Display`/`Debug`) is the ordinary big-endian numeric
//! form (most significant digit first), matching Core's `arith_uint256::GetHex`.

use std::cmp::Ordering;
use std::fmt;

use thiserror::Error;

/// A 256-bit unsigned integer, stored as four 64-bit little-endian limbs (`0` is least
/// significant). Matches the numeric semantics of Bitcoin Core's `arith_uint256`.
///
/// `PartialOrd`/`Ord` are implemented manually (not derived) to compare numerically from the
/// most significant limb down; deriving on the limb array directly would compare the least
/// significant limb first, which is not numeric ordering.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct U256([u64; 4]);

impl U256 {
    /// The additive identity, `0`.
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    /// The multiplicative identity, `1`.
    pub const ONE: Self = Self([1, 0, 0, 0]);
    /// The largest representable value, `2^256 - 1`.
    pub const MAX: Self = Self([u64::MAX; 4]);

    /// Builds a value equal to `v`, zero-extended to 256 bits.
    pub const fn from_u64(v: u64) -> Self {
        Self([v, 0, 0, 0])
    }

    /// Interprets `bytes` as a 256-bit integer in little-endian byte order (byte `0` is the
    /// least significant byte).
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            *limb = u64::from_le_bytes(chunk);
        }
        Self(limbs)
    }

    /// Serializes the value as 256 bits in little-endian byte order.
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, &limb) in self.0.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    /// Interprets `bytes` as a 256-bit integer in big-endian byte order (byte `0` is the most
    /// significant byte).
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
            limbs[3 - i] = u64::from_be_bytes(chunk);
        }
        Self(limbs)
    }

    /// Serializes the value as 256 bits in big-endian byte order.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        out
    }

    /// Parses a big-endian hex number of 1 to 64 hex digits (upper or lower case), as used for
    /// literal constants in tests and chain parameters. Shorter strings are treated as having
    /// implicit leading zero digits (`"12"` and `"0012"` both parse to `18`).
    pub fn from_hex(s: &str) -> Result<Self, ParseU256Error> {
        if s.is_empty() {
            return Err(ParseU256Error::Empty);
        }
        let digit_count = s.chars().count();
        if digit_count > 64 {
            return Err(ParseU256Error::TooLong(digit_count));
        }
        let mut limbs = [0u64; 4];
        for (index, character) in s.chars().enumerate() {
            let nibble =
                hex_nibble(character).ok_or(ParseU256Error::InvalidDigit { index, character })?;
            // Shift the whole 256-bit accumulator left by 4 bits and OR in the new nibble.
            // Safe: `digit_count <= 64` guarantees at most 256 bits of shifting occur in total,
            // so no set bit is ever shifted past the top of `limbs[3]`.
            limbs[3] = (limbs[3] << 4) | (limbs[2] >> 60);
            limbs[2] = (limbs[2] << 4) | (limbs[1] >> 60);
            limbs[1] = (limbs[1] << 4) | (limbs[0] >> 60);
            limbs[0] = (limbs[0] << 4) | u64::from(nibble);
        }
        Ok(Self(limbs))
    }

    /// Renders the value as exactly 64 lowercase hex digits, most significant first (Core's
    /// `arith_uint256::GetHex`).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for &limb in self.0.iter().rev() {
            s.push_str(&format!("{limb:016x}"));
        }
        s
    }

    /// Returns `true` if the value is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Returns the low 64 bits of the value (Core's `GetLow64`).
    pub fn low_u64(&self) -> u64 {
        self.0[0]
    }

    /// Returns the position of the highest set bit plus one, or `0` if the value is zero
    /// (Core's `bits()`).
    pub fn bits(&self) -> u32 {
        for (i, &limb) in self.0.iter().enumerate().rev() {
            if limb != 0 {
                let bit_len = 64 - limb.leading_zeros();
                return (i as u32) * 64 + bit_len;
            }
        }
        0
    }

    /// Adds `rhs`, returning `None` on overflow (wrap past `2^256 - 1`).
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let (result, carry) = self.adc(rhs);
        if carry { None } else { Some(result) }
    }

    /// Subtracts `rhs`, returning `None` if the result would be negative.
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        let (result, borrow) = self.sbb(rhs);
        if borrow { None } else { Some(result) }
    }

    /// Adds `rhs`, wrapping modulo `2^256` on overflow.
    pub fn wrapping_add(self, rhs: Self) -> Self {
        self.adc(rhs).0
    }

    /// Subtracts `rhs`, wrapping modulo `2^256` on underflow.
    pub fn wrapping_sub(self, rhs: Self) -> Self {
        self.sbb(rhs).0
    }

    /// Multiplies by the 64-bit value `rhs`, returning `None` if the mathematical result does
    /// not fit in 256 bits.
    pub fn checked_mul_u64(self, rhs: u64) -> Option<Self> {
        let (result, carry) = self.mul_u64_with_carry(rhs);
        if carry == 0 { Some(result) } else { None }
    }

    /// Multiplies by the 64-bit value `rhs`, truncating to 256 bits on overflow (matches
    /// Core's `arith_uint256::operator*=`, which truncates rather than panicking or
    /// saturating).
    pub fn wrapping_mul_u64(self, rhs: u64) -> Self {
        self.mul_u64_with_carry(rhs).0
    }

    /// Divides `self` by `rhs`, returning `(quotient, remainder)`, or `None` if `rhs` is zero.
    pub fn div_rem(self, rhs: Self) -> Option<(Self, Self)> {
        if rhs.is_zero() {
            return None;
        }
        let num_bits = self.bits();
        let div_bits = rhs.bits();
        if div_bits > num_bits {
            return Some((Self::ZERO, self));
        }
        // Binary long division, mirroring `arith_uint256::operator/=`: align the divisor with
        // the dividend's highest set bit, then repeatedly compare-and-subtract while shifting
        // the divisor back down one bit at a time.
        let mut shift = num_bits - div_bits;
        let mut divisor = rhs.shl(shift);
        let mut remainder = self;
        let mut quotient = Self::ZERO;
        loop {
            if remainder >= divisor {
                remainder = remainder.wrapping_sub(divisor);
                quotient.0[(shift / 64) as usize] |= 1u64 << (shift % 64);
            }
            if shift == 0 {
                break;
            }
            divisor = divisor.shr(1);
            shift -= 1;
        }
        Some((quotient, remainder))
    }

    /// `arith_uint256::getdouble` — the value as a double, used by
    /// `networkhashps`-style reporting. Not part of consensus math.
    #[must_use]
    pub fn to_f64(self) -> f64 {
        let mut ret = 0.0f64;
        let mut factor = 1.0f64;
        for word in self.0 {
            // Match Core's 32-bit-word accumulation exactly.
            ret += factor * (word & 0xffff_ffff) as f64;
            ret += factor * 4_294_967_296.0 * (word >> 32) as f64;
            factor *= 18_446_744_073_709_551_616.0; // 2^64
        }
        ret
    }

    /// Shifts left by `shift` bits. Shifts of 256 or more return zero rather than panicking.
    ///
    /// This is an inherent method (per the crate specification) rather than an implementation
    /// of `std::ops::Shl`, since it takes a plain `u32` shift amount and never panics.
    #[allow(clippy::should_implement_trait)]
    pub fn shl(self, shift: u32) -> Self {
        if shift >= 256 {
            return Self::ZERO;
        }
        let word_shift = (shift / 64) as usize;
        let bit_shift = shift % 64;
        let mut result = [0u64; 4];
        for (i, &limb) in self.0.iter().enumerate() {
            let dest = i + word_shift;
            if dest < 4 {
                result[dest] |= limb << bit_shift;
            }
            if bit_shift != 0 {
                let dest2 = dest + 1;
                if dest2 < 4 {
                    result[dest2] |= limb >> (64 - bit_shift);
                }
            }
        }
        Self(result)
    }

    /// Shifts right by `shift` bits. Shifts of 256 or more return zero rather than panicking.
    ///
    /// This is an inherent method (per the crate specification) rather than an implementation
    /// of `std::ops::Shr`, since it takes a plain `u32` shift amount and never panics.
    #[allow(clippy::should_implement_trait)]
    pub fn shr(self, shift: u32) -> Self {
        if shift >= 256 {
            return Self::ZERO;
        }
        let word_shift = (shift / 64) as usize;
        let bit_shift = shift % 64;
        let mut result = [0u64; 4];
        for (i, &limb) in self.0.iter().enumerate() {
            if let Some(dest) = i.checked_sub(word_shift) {
                result[dest] |= limb >> bit_shift;
            }
            if bit_shift != 0
                && let Some(dest) = i.checked_sub(word_shift + 1)
            {
                result[dest] |= limb << (64 - bit_shift);
            }
        }
        Self(result)
    }

    /// Returns the bitwise complement.
    ///
    /// This is an inherent method (per the crate specification) rather than an implementation
    /// of `std::ops::Not`.
    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> Self {
        let mut limbs = [0u64; 4];
        for (out, limb) in limbs.iter_mut().zip(self.0.iter().copied()) {
            *out = !limb;
        }
        Self(limbs)
    }

    /// Add-with-carry across all four limbs; returns `(result, overflow)`.
    fn adc(self, rhs: Self) -> (Self, bool) {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for (out, (&a, &b)) in result.iter_mut().zip(self.0.iter().zip(rhs.0.iter())) {
            let (sum1, c1) = a.overflowing_add(b);
            let (sum2, c2) = sum1.overflowing_add(carry);
            *out = sum2;
            carry = u64::from(c1) + u64::from(c2);
        }
        (Self(result), carry != 0)
    }

    /// Subtract-with-borrow across all four limbs; returns `(result, underflow)`.
    fn sbb(self, rhs: Self) -> (Self, bool) {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        for (out, (&a, &b)) in result.iter_mut().zip(self.0.iter().zip(rhs.0.iter())) {
            let (diff1, b1) = a.overflowing_sub(b);
            let (diff2, b2) = diff1.overflowing_sub(borrow);
            *out = diff2;
            borrow = u64::from(b1) + u64::from(b2);
        }
        (Self(result), borrow != 0)
    }

    /// Multiplies every limb by `rhs`, propagating carry; returns `(result, overflow_limb)`
    /// where a non-zero `overflow_limb` means the true product needed a fifth 64-bit limb.
    fn mul_u64_with_carry(self, rhs: u64) -> (Self, u64) {
        let mut result = [0u64; 4];
        let mut carry: u128 = 0;
        for (out, &limb) in result.iter_mut().zip(self.0.iter()) {
            let product = u128::from(limb) * u128::from(rhs) + carry;
            *out = product as u64;
            carry = product >> 64;
        }
        (Self(result), carry as u64)
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        // Numeric comparison: most significant limb first.
        self.0.iter().rev().cmp(other.0.iter().rev())
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Maps a single hex character (either case) to its 4-bit value.
fn hex_nibble(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

/// Error returned by [`U256::from_hex`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseU256Error {
    /// The input string was empty.
    #[error("empty hex string")]
    Empty,
    /// The input had more hex digits than fit in 256 bits (more than 64).
    #[error("hex string has {0} digits, at most 64 are allowed")]
    TooLong(usize),
    /// A character was not a valid hex digit.
    #[error("invalid hex digit {character:?} at digit position {index}")]
    InvalidDigit {
        /// The 0-based digit position of the invalid character.
        index: usize,
        /// The offending character.
        character: char,
    },
}

/// The "compact" 32-bit encoding of a proof-of-work target (Bitcoin's `nBits`), matching
/// `arith_uint256::SetCompact`/`GetCompact`: the top byte is a base-256 exponent, the low 23
/// bits are the mantissa, and bit 23 (`0x0080_0000`) is a sign bit.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct CompactTarget(pub u32);

impl fmt::Display for CompactTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

/// The result of decoding a [`CompactTarget`] (Core's `arith_uint256::SetCompact` out
/// parameters plus its return value).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExpandedTarget {
    /// The decoded magnitude, ignoring the sign.
    pub value: U256,
    /// Whether the sign bit (`0x0080_0000`) was set on a non-zero mantissa.
    pub negative: bool,
    /// Whether the encoded exponent/mantissa combination cannot be represented in 256 bits.
    pub overflow: bool,
}

impl CompactTarget {
    /// Decodes the compact encoding, exactly reproducing
    /// `arith_uint256::SetCompact` including its negative/overflow detection.
    pub fn expand(self) -> ExpandedTarget {
        let compact = self.0;
        let size = compact >> 24;
        // `word` is deliberately mutated below (for `size <= 3`) before being used in the
        // negative/overflow checks, exactly mirroring Core's reuse of `nWord`.
        let mut word = compact & 0x007f_ffff;
        let value = if size <= 3 {
            let shift = 8 * (3 - size);
            word >>= shift;
            U256::from_u64(u64::from(word))
        } else {
            let shift = 8 * (size - 3);
            U256::from_u64(u64::from(word)).shl(shift)
        };
        let negative = word != 0 && (compact & 0x0080_0000) != 0;
        let overflow =
            word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
        ExpandedTarget {
            value,
            negative,
            overflow,
        }
    }

    /// Encodes `value` (with the given sign) as a compact target, exactly reproducing
    /// `arith_uint256::GetCompact`.
    pub fn from_target(value: U256, negative: bool) -> CompactTarget {
        let bits = value.bits();
        let mut size = bits.div_ceil(8);
        let mut compact: u64 = if size <= 3 {
            let shift = 8 * (3 - size);
            value.low_u64() << shift
        } else {
            let shift = 8 * (size - 3);
            value.shr(shift).low_u64()
        };
        // The sign bit denotes... the sign: if it's already set, shift the mantissa down a
        // byte and bump the exponent, so the sign bit stays free for `negative` below.
        if compact & 0x0080_0000 != 0 {
            compact >>= 8;
            size += 1;
        }
        // Provably true for any `value`/`size` derived above: `size <= 3` bounds `compact` to
        // 24 bits before the adjustment, and the size > 3 branch bounds it identically via
        // `bits() <= 8 * size`; the adjustment above only shrinks it further.
        debug_assert_eq!(
            compact & !0x007f_ffff,
            0,
            "GetCompact mantissa must fit in 23 bits"
        );
        let mut result = compact | (u64::from(size) << 24);
        if negative && (result & 0x007f_ffff) != 0 {
            result |= 0x0080_0000;
        }
        CompactTarget(result as u32)
    }
}

/// A proof-of-work target: the numeric threshold a block hash must not exceed.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Target(pub U256);

impl Target {
    /// Encodes this target in compact (`nBits`) form, with `negative = false` (Core's
    /// `GetCompact()` default).
    pub fn to_compact(self) -> CompactTarget {
        CompactTarget::from_target(self.0, false)
    }

    /// The approximate multiple of the minimum difficulty this target represents, as reported
    /// by Core's `getdifficulty` RPC (`GetDifficulty`). This is informational only, not a
    /// consensus rule.
    ///
    /// Core's `GetDifficulty` computes this directly from a block header's raw, on-disk
    /// `nBits` field (`rpc/blockchain.cpp`), not from a re-derived compact encoding of the
    /// decoded target. This method therefore takes that same raw `bits` and delegates to
    /// [`difficulty_from_compact`] rather than round-tripping through [`Target::to_compact`]:
    /// `to_compact` always produces the *canonical* encoding (Core's `GetCompact`), which is
    /// only bit-identical to `bits` when `bits` was itself canonically encoded. For a
    /// legally-decodable but non-canonical `nBits` (an exponent byte `< 3` whose low mantissa
    /// bits get shifted away during `SetCompact`), the canonical re-encoding is a different
    /// bit pattern and yields a measurably different value from Core's RPC output. Debug
    /// builds assert that `bits` actually decodes to this `Target`, to catch mismatched
    /// callers.
    pub fn difficulty(self, bits: CompactTarget) -> f64 {
        debug_assert_eq!(
            bits.expand().value,
            self.0,
            "Target::difficulty: `bits` must be the compact encoding this `Target` came from"
        );
        difficulty_from_compact(bits)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_hex())
    }
}

/// Cumulative proof-of-work ("chainwork"): the expected number of hashes represented by one or
/// more blocks, summed across a chain.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Work(pub U256);

impl Work {
    /// Zero work.
    pub const ZERO: Work = Work(U256::ZERO);

    /// The work represented by a single block with the given target bits, matching Core's
    /// `GetBitsProof`: zero if the bits are negative, overflow, or decode to a zero target;
    /// otherwise `(~target / (target + 1)) + 1`, which computes `2^256 / (target + 1)` without
    /// overflowing 256 bits.
    pub fn from_compact(bits: CompactTarget) -> Work {
        let expanded = bits.expand();
        if expanded.negative || expanded.overflow || expanded.value.is_zero() {
            return Work::ZERO;
        }
        let target = expanded.value;
        let Some(denom) = target.checked_add(U256::ONE) else {
            // Unreachable for any non-overflowing compact target: `expand()`'s non-overflow
            // branches always produce a value with its low `8 * (size - 3)` bits (or, for
            // `size <= 3`, its low `8 * (3 - size)` bits) forced to zero by the shift, so the
            // decoded value can never be `U256::MAX` (all bits set) and `+ 1` can never
            // overflow. Handled defensively rather than panicking. See
            // `work_from_compact_denominator_never_overflows` for a sweep pinning this.
            return Work::ZERO;
        };
        let Some((quotient, _remainder)) = target.not().div_rem(denom) else {
            return Work::ZERO;
        };
        Work(quotient.wrapping_add(U256::ONE))
    }

    /// Adds two work values, returning `None` on overflow.
    pub fn checked_add(self, rhs: Work) -> Option<Work> {
        self.0.checked_add(rhs.0).map(Work)
    }
}

impl fmt::Display for Work {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_hex())
    }
}

/// Approximate mining difficulty for the given compact target, exactly reproducing Core's
/// `rpc/blockchain.cpp` `GetDifficulty` (the `getdifficulty`/`getblockchaininfo` RPC field).
/// This is informational only; it is not used anywhere in consensus validation.
pub fn difficulty_from_compact(bits: CompactTarget) -> f64 {
    let n_shift = (bits.0 >> 24) & 0xff;
    let mut diff = f64::from(0x0000_ffffu32) / f64::from(bits.0 & 0x00ff_ffff);
    let mut shift = i64::from(n_shift);
    while shift < 29 {
        diff *= 256.0;
        shift += 1;
    }
    while shift > 29 {
        diff /= 256.0;
        shift -= 1;
    }
    diff
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ---- U256 basics -------------------------------------------------------------------

    #[test]
    fn constants() {
        assert!(U256::ZERO.is_zero());
        assert_eq!(U256::ONE, U256::from_u64(1));
        assert!(!U256::ONE.is_zero());
        assert_eq!(U256::MAX.to_hex(), "f".repeat(64));
        assert_eq!(U256::default(), U256::ZERO);
    }

    #[test]
    fn from_u64_and_low_u64_roundtrip() {
        for v in [0u64, 1, 42, u32::MAX as u64, u64::MAX] {
            assert_eq!(U256::from_u64(v).low_u64(), v);
        }
    }

    #[test]
    fn le_be_bytes_roundtrip() {
        let value =
            U256::from_hex("0000000000000000000000000000000000000000000000000000000000000102")
                .unwrap();
        let be = value.to_be_bytes();
        assert_eq!(be[30], 0x01);
        assert_eq!(be[31], 0x02);
        assert_eq!(U256::from_be_bytes(be), value);

        let le = value.to_le_bytes();
        assert_eq!(le[0], 0x02);
        assert_eq!(le[1], 0x01);
        assert_eq!(U256::from_le_bytes(le), value);

        // Round trip at the extremes too.
        assert_eq!(U256::from_le_bytes(U256::ZERO.to_le_bytes()), U256::ZERO);
        assert_eq!(U256::from_le_bytes(U256::MAX.to_le_bytes()), U256::MAX);
        assert_eq!(U256::from_be_bytes(U256::ZERO.to_be_bytes()), U256::ZERO);
        assert_eq!(U256::from_be_bytes(U256::MAX.to_be_bytes()), U256::MAX);
    }

    #[test]
    fn from_hex_errors() {
        assert_eq!(U256::from_hex(""), Err(ParseU256Error::Empty));
        assert_eq!(
            U256::from_hex(&"0".repeat(65)),
            Err(ParseU256Error::TooLong(65))
        );
        assert_eq!(
            U256::from_hex("12g4"),
            Err(ParseU256Error::InvalidDigit {
                index: 2,
                character: 'g'
            })
        );
        // Exactly 64 digits is allowed.
        assert!(U256::from_hex(&"1".repeat(64)).is_ok());
    }

    #[test]
    fn from_hex_case_insensitive_and_padding() {
        let lower = U256::from_hex("deadbeef").unwrap();
        let upper = U256::from_hex("DEADBEEF").unwrap();
        let mixed = U256::from_hex("DeAdBeEf").unwrap();
        assert_eq!(lower, upper);
        assert_eq!(lower, mixed);
        assert_eq!(lower, U256::from_u64(0xdead_beef));

        assert_eq!(U256::from_hex("1").unwrap(), U256::from_u64(1));
        assert_eq!(U256::from_hex("01").unwrap(), U256::from_u64(1));
        assert_eq!(
            U256::from_hex("12").unwrap(),
            U256::from_hex("0012").unwrap()
        );
    }

    #[test]
    fn to_hex_is_64_lowercase_digits() {
        for value in [
            U256::ZERO,
            U256::ONE,
            U256::MAX,
            U256::from_u64(0x1234_5678),
        ] {
            let hex = value.to_hex();
            assert_eq!(hex.len(), 64);
            assert!(
                hex.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            );
            assert_eq!(U256::from_hex(&hex).unwrap(), value);
        }
    }

    #[test]
    fn display_and_debug_match_to_hex() {
        let value = U256::from_u64(0x1234_5678);
        assert_eq!(format!("{value}"), value.to_hex());
        assert_eq!(format!("{value:?}"), value.to_hex());
    }

    #[test]
    fn bits_boundaries() {
        assert_eq!(U256::ZERO.bits(), 0);
        assert_eq!(U256::ONE.bits(), 1);
        assert_eq!(U256::from_u64(2).bits(), 2);
        assert_eq!(U256::from_u64(u64::MAX).bits(), 64);
        // 2^64 (bit 64 set, i.e. the second limb's bit 0).
        let two_pow_64 = U256::ONE.shl(64);
        assert_eq!(two_pow_64.bits(), 65);
        // 2^128 and 2^192 exercise the third and fourth limbs.
        assert_eq!(U256::ONE.shl(128).bits(), 129);
        assert_eq!(U256::ONE.shl(192).bits(), 193);
        assert_eq!(U256::MAX.bits(), 256);
    }

    #[test]
    fn ordering_across_limbs() {
        // A single high bit in the top limb outranks every bit set in the lower three limbs.
        let high = U256::ONE.shl(192);
        let low_all_ones = high.wrapping_sub(U256::ONE);
        assert!(high > low_all_ones);
        assert!(low_all_ones < high);

        assert!(U256::ZERO < U256::ONE);
        assert!(U256::ONE < U256::from_u64(2));
        assert!(U256::from_u64(2) < U256::MAX);
        assert_eq!(U256::ONE.cmp(&U256::ONE), Ordering::Equal);
    }

    #[test]
    fn add_sub_checked_and_wrapping() {
        assert_eq!(U256::MAX.checked_add(U256::ONE), None);
        assert_eq!(U256::MAX.wrapping_add(U256::ONE), U256::ZERO);
        assert_eq!(
            U256::from_u64(2).checked_add(U256::from_u64(3)),
            Some(U256::from_u64(5))
        );

        assert_eq!(U256::ZERO.checked_sub(U256::ONE), None);
        assert_eq!(U256::ZERO.wrapping_sub(U256::ONE), U256::MAX);
        assert_eq!(
            U256::from_u64(5).checked_sub(U256::from_u64(3)),
            Some(U256::from_u64(2))
        );

        // Identity: (a + b) - b == a, when it does not overflow.
        let a = U256::ONE.shl(200);
        let b = U256::ONE.shl(64);
        let sum = a.checked_add(b).unwrap();
        assert_eq!(sum.checked_sub(b).unwrap(), a);
    }

    #[test]
    fn mul_checked_and_wrapping() {
        assert_eq!(
            U256::from_u64(3).checked_mul_u64(4),
            Some(U256::from_u64(12))
        );
        assert_eq!(U256::MAX.checked_mul_u64(2), None);
        // 2 * MAX mod 2^256 == MAX - 1.
        assert_eq!(
            U256::MAX.wrapping_mul_u64(2),
            U256::MAX.wrapping_sub(U256::ONE)
        );
        assert_eq!(U256::ZERO.wrapping_mul_u64(u64::MAX), U256::ZERO);
        assert_eq!(
            U256::ONE.checked_mul_u64(u64::MAX),
            Some(U256::from_u64(u64::MAX))
        );
    }

    #[test]
    fn div_rem_basic_and_zero() {
        assert_eq!(U256::ONE.div_rem(U256::ZERO), None);

        let (q, r) = U256::from_u64(7).div_rem(U256::from_u64(2)).unwrap();
        assert_eq!(q, U256::from_u64(3));
        assert_eq!(r, U256::from_u64(1));

        // Divisor bigger than dividend: quotient 0, remainder unchanged.
        let (q, r) = U256::from_u64(5).div_rem(U256::from_u64(100)).unwrap();
        assert_eq!(q, U256::ZERO);
        assert_eq!(r, U256::from_u64(5));
    }

    #[test]
    fn div_rem_identity_across_limbs() {
        // Divisors that fit in a `u64`, so the identity can be checked with `checked_mul_u64`.
        let cases: [(U256, u64); 5] = [
            (U256::from_u64(7), 2),
            (U256::MAX, 3),
            (U256::ONE.shl(200), 1_000_003),
            (U256::ONE.shl(255), u64::MAX),
            (U256::from_hex("123456789abcdef0").unwrap(), 0xdead_beef),
        ];
        for (a, b) in cases {
            let divisor = U256::from_u64(b);
            let (q, r) = a.div_rem(divisor).unwrap();
            assert!(r < divisor, "remainder must be smaller than the divisor");
            let reconstructed = q.checked_mul_u64(b).unwrap().checked_add(r).unwrap();
            assert_eq!(reconstructed, a, "(a / b) * b + a % b == a");
        }
    }

    #[test]
    fn div_rem_multi_limb_divisor() {
        // A divisor spanning more than one limb, constructed so the expected quotient and
        // remainder are known up front: dividend = divisor * 3 + 7.
        let divisor = U256::ONE.shl(128).checked_add(U256::from_u64(5)).unwrap();
        let remainder = U256::from_u64(7);
        let dividend = divisor
            .checked_mul_u64(3)
            .unwrap()
            .checked_add(remainder)
            .unwrap();
        let (q, r) = dividend.div_rem(divisor).unwrap();
        assert_eq!(q, U256::from_u64(3));
        assert_eq!(r, remainder);
    }

    #[test]
    fn shl_boundaries() {
        assert_eq!(U256::ONE.shl(0), U256::ONE);
        assert_eq!(U256::ONE.shl(1), U256::from_u64(2));
        assert_eq!(U256::ONE.shl(63), U256::from_u64(1u64 << 63));
        assert_eq!(U256::ONE.shl(64).low_u64(), 0);
        assert_eq!(U256::ONE.shl(64).bits(), 65);
        assert_eq!(U256::ONE.shl(64), U256::ONE.shl(65).shr(1));
        assert_eq!(U256::ONE.shl(255).bits(), 256);
        assert_eq!(U256::ONE.shl(255).shr(255), U256::ONE);
        assert_eq!(U256::ONE.shl(256), U256::ZERO);
        assert_eq!(U256::ONE.shl(300), U256::ZERO);
    }

    #[test]
    fn shr_boundaries() {
        assert_eq!(U256::MAX.shr(0), U256::MAX);
        assert_eq!(U256::MAX.shr(1).bits(), 255);
        // A 256-bit shift, unlike a 64-bit one: the low limb stays all-ones since bits keep
        // flowing in from limb 1 above it.
        assert_eq!(U256::MAX.shr(63).low_u64(), u64::MAX);
        assert_eq!(U256::MAX.shr(63).bits(), 193);
        assert_eq!(U256::MAX.shr(255), U256::ONE);
        assert_eq!(U256::MAX.shr(256), U256::ZERO);
        assert_eq!(U256::MAX.shr(300), U256::ZERO);
        assert_eq!(U256::from_u64(4).shr(65), U256::ZERO);
    }

    #[test]
    fn not_is_involution() {
        assert_eq!(U256::ZERO.not(), U256::MAX);
        assert_eq!(U256::MAX.not(), U256::ZERO);
        let v = U256::from_u64(0x1234_5678_9abc_def0);
        assert_eq!(v.not().not(), v);
        assert_ne!(v.not(), v);
    }

    // ---- Compact target: required Core `bignum_SetCompact` vectors ----------------------

    #[test]
    fn set_compact_zero_group() {
        // All of these decode to value 0, compact 0, not negative, not overflow.
        let vectors = [
            0x0000_0000u32,
            0x0012_3456,
            0x0100_3456,
            0x0200_0056,
            0x0300_0000,
            0x0400_0000,
            0x0092_3456,
            0x0180_3456,
            0x0280_0056,
            0x0380_0000,
            0x0480_0000,
        ];
        for bits in vectors {
            let expanded = CompactTarget(bits).expand();
            assert_eq!(expanded.value, U256::ZERO, "bits=0x{bits:08x}");
            assert!(!expanded.negative, "bits=0x{bits:08x}");
            assert!(!expanded.overflow, "bits=0x{bits:08x}");
            assert_eq!(
                CompactTarget::from_target(expanded.value, expanded.negative).0,
                0
            );
        }
    }

    #[test]
    fn set_compact_individual_vectors() {
        let e = CompactTarget(0x0112_3456).expand();
        assert_eq!(e.value, U256::from_u64(0x12));
        assert!(!e.negative);
        assert!(!e.overflow);
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x0112_0000
        );

        let e = CompactTarget(0x01fe_dcba).expand();
        assert_eq!(e.value, U256::from_u64(0x7e));
        assert!(e.negative);
        assert!(!e.overflow);
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x01fe_0000
        );

        let e = CompactTarget(0x0212_3456).expand();
        assert_eq!(e.value, U256::from_u64(0x1234));
        assert!(!e.negative);
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x0212_3400
        );

        let e = CompactTarget(0x0312_3456).expand();
        assert_eq!(e.value, U256::from_u64(0x0012_3456));
        assert!(!e.negative);
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x0312_3456
        );

        let e = CompactTarget(0x0412_3456).expand();
        assert_eq!(e.value, U256::from_u64(0x1234_5600));
        assert!(!e.negative);
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x0412_3456
        );

        let e = CompactTarget(0x0492_3456).expand();
        assert_eq!(e.value, U256::from_u64(0x1234_5600));
        assert!(e.negative);
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x0492_3456
        );

        let e = CompactTarget(0x0500_9234).expand();
        assert_eq!(e.value, U256::from_u64(0x9234_0000));
        assert!(!e.negative);
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x0500_9234
        );

        let e = CompactTarget(0x2012_3456).expand();
        assert_eq!(
            e.value,
            U256::from_hex("1234560000000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
        assert!(!e.negative);
        // size=32 here (0x20): neither `size > 33` nor `size > 32` holds, so this vector,
        // combined with a mantissa well above 0xffff, pins the exact `> 32` boundary of the
        // third overflow clause (see `overflow_boundary_conditions` for the full sweep).
        assert!(!e.overflow);
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x2012_3456
        );

        let e = CompactTarget(0xff12_3456).expand();
        assert!(!e.negative);
        assert!(e.overflow);
    }

    #[test]
    fn set_compact_overflow_and_no_generate_sign_bit() {
        // `0x80` alone must never round-trip to a compact value with the sign bit set.
        let compact = CompactTarget::from_target(U256::from_u64(0x80), false);
        assert_eq!(compact.0, 0x0200_8000);
    }

    #[test]
    fn from_target_negative_zero_mantissa_has_no_sign_bit() {
        // Core: `nCompact |= (fNegative && (nCompact & 0x007fffff) ? 0x00800000 : 0)` -- the
        // sign bit is only ever set when the mantissa is nonzero, even if the caller asked
        // for `negative = true`. `expand()` can never itself produce `negative = true` with a
        // zero mantissa (it defines `negative = word != 0 && ...`), so every round-trip test
        // built from `expanded.negative` leaves this corner of the public
        // `from_target(value, negative)` API untested. A value of zero is the only way to
        // reach a zero mantissa here (see `overflow_boundary_conditions`'s comment: the
        // sign-bit-shift adjustment can only ever raise a zero-word compact to 0x8000 or
        // above, never back down to zero, so no nonzero value can land here).
        assert_eq!(CompactTarget::from_target(U256::ZERO, true).0, 0);
        assert_eq!(CompactTarget::from_target(U256::ZERO, false).0, 0);
    }

    #[test]
    fn overflow_boundary_conditions() {
        // Pins each of the three disjuncts in
        // `overflow = word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff
        // && size > 32))` at its exact threshold, on both sides. None of Core's required
        // `bignum_SetCompact` vectors (sizes 0-5, 0x1d, 0x20, 0xff) exercise these boundaries,
        // so a `>` accidentally weakened to `>=` in any clause survives every other test in
        // this module; each non-overflowing case below flips to `overflow == true` under
        // exactly one such mutation. Where not overflowing, also check the round trip through
        // `from_target`: since `size` here always exceeds the value's minimal byte count
        // (32, the most a 256-bit value ever needs), these compact forms are non-canonical
        // and `from_target` legitimately re-encodes them to a different (canonical, smaller
        // or equal `size`) bit pattern -- expected constants below were independently derived
        // from the `GetCompact` algorithm, not merely echoed back from `expand`.

        // Clause 1 threshold: `size > 34`. word is nonzero but small so clauses 2/3 can't fire.
        let e = CompactTarget(0x2200_0001).expand(); // size=34, word=1
        assert!(!e.overflow, "size=34 must not overflow on clause 1 alone");
        assert_eq!(e.value, U256::from_u64(1).shl(8 * (34 - 3)));
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x2001_0000
        );
        let e = CompactTarget(0x2300_0001).expand(); // size=35, word=1
        assert!(e.overflow, "size=35 (> 34) must overflow");

        // Clause 2 threshold: `word > 0xff && size > 33`.
        let e = CompactTarget(0x2200_00ff).expand(); // size=34, word=0xff (not > 0xff)
        assert!(
            !e.overflow,
            "word=0xff must not exceed the word>0xff threshold"
        );
        assert_eq!(e.value, U256::from_u64(0xff).shl(8 * (34 - 3)));
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x2100_ff00
        );
        let e = CompactTarget(0x2200_0100).expand(); // size=34, word=0x100 (> 0xff, size > 33)
        assert!(e.overflow, "size=34, word=0x100 must overflow via clause 2");
        let e = CompactTarget(0x2100_0100).expand(); // size=33 (not > 33), word=0x100 (> 0xff)
        assert!(
            !e.overflow,
            "size=33 must not satisfy clause 2's size>33 threshold"
        );
        assert_eq!(e.value, U256::from_u64(0x100).shl(8 * (33 - 3)));
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x2001_0000
        );

        // Clause 3 threshold: `word > 0xffff && size > 32`.
        let e = CompactTarget(0x2100_ffff).expand(); // size=33, word=0xffff (not > 0xffff)
        assert!(
            !e.overflow,
            "word=0xffff must not exceed the word>0xffff threshold"
        );
        assert_eq!(e.value, U256::from_u64(0xffff).shl(8 * (33 - 3)));
        assert_eq!(
            CompactTarget::from_target(e.value, e.negative).0,
            0x2100_ffff
        );
        let e = CompactTarget(0x2101_0000).expand(); // size=33, word=0x10000 (> 0xffff, size > 32)
        assert!(
            e.overflow,
            "size=33, word=0x10000 must overflow via clause 3"
        );
    }

    #[test]
    fn genesis_pow_limit_expand() {
        let expanded = CompactTarget(0x1d00_ffff).expand();
        assert_eq!(
            expanded.value,
            U256::from_hex("00000000ffff0000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
        assert!(!expanded.negative);
        assert!(!expanded.overflow);
    }

    // ---- Work / difficulty ---------------------------------------------------------------

    #[test]
    fn work_from_compact_vectors() {
        assert_eq!(
            Work::from_compact(CompactTarget(0x1d00_ffff)).0,
            U256::from_u64(0x1_0001_0001)
        );
        assert_eq!(
            Work::from_compact(CompactTarget(0x207f_ffff)).0,
            U256::from_u64(2)
        );
        assert_eq!(
            Work::from_compact(CompactTarget(0x1e03_77ae)).0,
            U256::from_u64(0x49_d414)
        );

        // Harder target (smaller mantissa/exponent) implies strictly more work.
        let base = Work::from_compact(CompactTarget(0x1d00_ffff));
        let harder = Work::from_compact(CompactTarget(0x1d00_d86a));
        assert!(harder.0 > base.0);
    }

    #[test]
    fn work_from_compact_degenerate_bits() {
        // Negative bits (sign bit set on a non-zero mantissa) -> zero work.
        assert_eq!(Work::from_compact(CompactTarget(0x0192_3456)).0, U256::ZERO);
        // Overflowing bits -> zero work.
        assert_eq!(Work::from_compact(CompactTarget(0xff12_3456)).0, U256::ZERO);
        // Zero target -> zero work.
        assert_eq!(Work::from_compact(CompactTarget(0x0000_0000)).0, U256::ZERO);
    }

    #[test]
    fn work_from_compact_denominator_never_overflows() {
        // `Work::from_compact`'s `target.checked_add(U256::ONE)` fallback is documented as
        // unreachable for any non-overflowing compact target. Sweep representative
        // (size, word, sign-bit) combinations -- including the exact overflow-boundary sizes
        // and words from `overflow_boundary_conditions` -- and confirm that whenever
        // `expand()` reports `overflow == false`, the decoded value is never `U256::MAX` and
        // adding one never overflows, backing that inline justification with real evidence
        // rather than an unverified comment.
        let words = [0u32, 1, 0xff, 0x100, 0x7fff, 0xffff, 0x1_0000, 0x7f_ffff];
        for size in 0u32..=40 {
            for &word in &words {
                for sign_bit in [0u32, 0x0080_0000] {
                    let compact = (size << 24) | sign_bit | word;
                    let expanded = CompactTarget(compact).expand();
                    if expanded.overflow {
                        continue;
                    }
                    assert_ne!(
                        expanded.value,
                        U256::MAX,
                        "compact=0x{compact:08x} decoded to U256::MAX without overflow"
                    );
                    assert!(
                        expanded.value.checked_add(U256::ONE).is_some(),
                        "compact=0x{compact:08x} value + 1 overflowed without CompactTarget overflow"
                    );
                }
            }
        }
    }

    #[test]
    fn work_checked_add() {
        let a = Work::from_compact(CompactTarget(0x1d00_ffff));
        let b = Work::from_compact(CompactTarget(0x1d00_ffff));
        let sum = a.checked_add(b).unwrap();
        assert_eq!(sum.0, U256::from_u64(2 * 0x1_0001_0001));
        assert_eq!(Work(U256::MAX).checked_add(Work(U256::ONE)), None);
        assert_eq!(Work::ZERO, Work::default());
    }

    #[test]
    fn target_to_compact_roundtrip() {
        let target = Target(CompactTarget(0x1d00_ffff).expand().value);
        assert_eq!(target.to_compact().0, 0x1d00_ffff);
    }

    #[test]
    fn difficulty_from_compact_reference_point() {
        // The minimum-difficulty target defines difficulty 1.0 exactly.
        assert_eq!(difficulty_from_compact(CompactTarget(0x1d00_ffff)), 1.0);
        // A smaller mantissa/exponent (harder target) is more than 1.0 difficulty.
        assert!(difficulty_from_compact(CompactTarget(0x1d00_d86a)) > 1.0);
        // A zero mantissa divides by zero but must not panic; it saturates to infinity.
        assert!(difficulty_from_compact(CompactTarget(0x0300_0000)).is_infinite());
    }

    #[test]
    fn target_difficulty_matches_free_function() {
        let bits = CompactTarget(0x1d00_ffff);
        let target = Target(bits.expand().value);
        assert_eq!(target.difficulty(bits), difficulty_from_compact(bits));
    }

    #[test]
    fn target_difficulty_uses_raw_bits_not_recanonicalized() {
        // Regression for a Core-conformance gap: Core's `GetDifficulty` computes directly
        // from a block's raw, possibly non-canonical `nBits`. A non-canonically-encoded
        // `nBits` (exponent byte < 3, so `SetCompact` right-shifts away some of the mantissa
        // on decode) round-trips to a *different* bit pattern through `GetCompact`
        // (`Target::to_compact`), so computing difficulty from the re-encoded canonical form
        // instead of the original bits diverges from Core.
        let bits = CompactTarget(0x0200_1234);
        let expanded = bits.expand();
        assert!(!expanded.negative && !expanded.overflow);
        assert_eq!(expanded.value, U256::from_u64(0x12));
        let target = Target(expanded.value);

        // The canonical re-encoding is a different bit pattern than the original, non-
        // canonical `bits` -- exactly the divergence this test guards against.
        let recanonicalized = target.to_compact();
        assert_eq!(recanonicalized.0, 0x0112_0000);
        assert_ne!(recanonicalized.0, bits.0);

        // `Target::difficulty` must match Core's `GetDifficulty` on the *original* bits, not
        // on the re-canonicalized `to_compact()` output.
        assert_eq!(target.difficulty(bits), difficulty_from_compact(bits));
        assert_ne!(
            target.difficulty(bits),
            difficulty_from_compact(recanonicalized)
        );
    }

    #[test]
    fn compact_target_display() {
        assert_eq!(format!("{}", CompactTarget(0x1d00_ffff)), "0x1d00ffff");
        assert_eq!(format!("{}", CompactTarget(0)), "0x00000000");
    }

    #[test]
    fn work_and_target_display_are_64_hex_digits() {
        let target = Target(CompactTarget(0x1d00_ffff).expand().value);
        let work = Work::from_compact(CompactTarget(0x1d00_ffff));
        assert_eq!(format!("{target}").len(), 64);
        assert_eq!(format!("{work}").len(), 64);
        assert_eq!(format!("{target}"), target.0.to_hex());
        assert_eq!(format!("{work}"), work.0.to_hex());
    }
}

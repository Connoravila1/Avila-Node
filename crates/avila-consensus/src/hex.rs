//! Minimal, allocation-bounded hexadecimal encoding and decoding.
//!
//! Bitcoin's human-readable formats (hashes, scripts, raw transactions) are conventionally
//! shown as lowercase hex with no `0x` prefix. [`encode`] always produces that canonical form;
//! [`decode`] accepts either case so that copy-pasted values from other tools still parse.

use thiserror::Error;

/// Errors that can occur while decoding a hexadecimal string.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HexError {
    /// The input had an odd number of bytes (UTF-8 byte length of the input string), so it
    /// cannot be grouped into whole bytes.
    #[error("odd-length hex string ({0} bytes)")]
    OddLength(usize),
    /// A character at the given byte index of the input string is not a valid hex digit.
    #[error("invalid hex character at index {index}")]
    InvalidCharacter {
        /// Byte index into the input string of the offending character.
        index: usize,
    },
}

/// Encodes `bytes` as a lowercase hexadecimal string with no `0x` prefix.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decodes a hexadecimal string into bytes.
///
/// Both uppercase and lowercase hex digits are accepted (and may be mixed). Any other
/// character, or an odd number of characters, is rejected.
///
/// # Errors
///
/// Returns [`HexError::OddLength`] if `text` does not have an even number of characters, or
/// [`HexError::InvalidCharacter`] at the byte index of the first character that is not an
/// ASCII hex digit.
pub fn decode(text: &str) -> Result<Vec<u8>, HexError> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(HexError::OddLength(bytes.len()));
    }
    let (chunks, remainder) = bytes.as_chunks::<2>();
    debug_assert!(remainder.is_empty(), "length was just checked to be even");
    let mut out = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        let hi = hex_digit(chunk[0]).ok_or(HexError::InvalidCharacter { index: i * 2 })?;
        let lo = hex_digit(chunk[1]).ok_or(HexError::InvalidCharacter { index: i * 2 + 1 })?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Returns the numeric value of a single ASCII hex digit, or `None` if `byte` is not one.
const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn decode_empty() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn round_trip() {
        let bytes: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
        let text = encode(&bytes);
        assert_eq!(text.len(), 512);
        assert_eq!(decode(&text).unwrap(), bytes);
    }

    #[test]
    fn encode_is_lowercase() {
        assert_eq!(encode(&[0xab, 0xcd, 0xef]), "abcdef");
        assert_eq!(encode(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn decode_accepts_uppercase() {
        assert_eq!(decode("ABCDEF").unwrap(), vec![0xab, 0xcd, 0xef]);
    }

    #[test]
    fn decode_accepts_mixed_case() {
        assert_eq!(decode("aBcDeF").unwrap(), vec![0xab, 0xcd, 0xef]);
        assert_eq!(decode("Ff00Aa").unwrap(), vec![0xff, 0x00, 0xaa]);
    }

    #[test]
    fn decode_odd_length() {
        assert_eq!(decode("abc"), Err(HexError::OddLength(3)));
        assert_eq!(decode("a"), Err(HexError::OddLength(1)));
    }

    #[test]
    fn decode_invalid_character_index() {
        assert_eq!(decode("zz"), Err(HexError::InvalidCharacter { index: 0 }));
        assert_eq!(decode("0z"), Err(HexError::InvalidCharacter { index: 1 }));
        assert_eq!(
            decode("aabbgg"),
            Err(HexError::InvalidCharacter { index: 4 })
        );
    }

    #[test]
    fn decode_rejects_non_ascii() {
        // "é0" is 3 UTF-8 bytes (0xc3 0xa9 0x30) but only 2 Unicode scalar values, pinning down
        // that `OddLength` counts bytes, not characters: it is caught by the odd-length check
        // before any byte is inspected as a hex digit.
        assert_eq!("é0".chars().count(), 2);
        assert_eq!(decode("é0"), Err(HexError::OddLength(3)));
    }

    #[test]
    fn decode_rejects_non_ascii_even_length() {
        // "éab" is 4 UTF-8 bytes (0xc3 0xa9 0x61 0x62): even length, so this exercises a
        // multi-byte UTF-8 character actually reaching the hex-digit check, yielding a correct
        // byte-index `InvalidCharacter` (pointing at the first byte of the 2-byte sequence),
        // not a panic or a wrong index.
        assert_eq!(decode("éab"), Err(HexError::InvalidCharacter { index: 0 }));
    }

    #[test]
    fn hex_digit_values() {
        assert_eq!(hex_digit(b'0'), Some(0));
        assert_eq!(hex_digit(b'9'), Some(9));
        assert_eq!(hex_digit(b'a'), Some(10));
        assert_eq!(hex_digit(b'f'), Some(15));
        assert_eq!(hex_digit(b'A'), Some(10));
        assert_eq!(hex_digit(b'F'), Some(15));
        assert_eq!(hex_digit(b'g'), None);
        assert_eq!(hex_digit(b' '), None);
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            HexError::OddLength(3).to_string(),
            "odd-length hex string (3 bytes)"
        );
        assert_eq!(
            HexError::InvalidCharacter { index: 5 }.to_string(),
            "invalid hex character at index 5"
        );
    }
}

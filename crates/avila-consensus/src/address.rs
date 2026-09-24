//! Address encodings for scriptPubKeys — Base58Check (legacy
//! P2PKH/P2SH) and Bech32/Bech32m (BIP173/350 segwit programs).
//!
//! These are display-layer encodings, not consensus rules: the wire
//! and chain formats never carry addresses. They exist so the RPC
//! surface can report `scriptPubKey.address`/`desc` the way Core's
//! `EncodeDestination`/`InferDescriptor` do.

use crate::hash::sha256d;
use crate::params::Params;
use crate::script::ScriptType;
use crate::transaction::Script;

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// BIP173's checksum constant for v0 witness programs.
const BECH32_CONST: u32 = 1;
/// BIP350's checksum constant for v1+ witness programs.
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// Base58Check: `version || payload || sha256d(version||payload)[..4]`
/// in the Flickr-alphabet base-58 encoding (Core's `EncodeBase58Check`).
#[must_use]
pub fn base58check(version: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(1 + payload.len() + 4);
    data.push(version);
    data.extend_from_slice(payload);
    let checksum = sha256d(&data);
    data.extend_from_slice(&checksum[..4]);
    base58_encode_raw(&data)
}

/// Raw base58 encoding of already-checksummed bytes.
fn base58_encode_raw(data: &[u8]) -> String {
    // Count leading zero bytes — each becomes a '1'.
    let zeros = data.iter().take_while(|b| **b == 0).count();

    // Repeated division by 58 over the big-endian number.
    let mut digits: Vec<u8> = Vec::new();
    let mut num = data.to_vec();
    while num.iter().any(|b| *b != 0) {
        let mut rem = 0u32;
        let mut next = Vec::with_capacity(num.len());
        for byte in &num {
            let acc = (rem << 8) | u32::from(*byte);
            next.push((acc / 58) as u8);
            rem = acc % 58;
        }
        digits.push(BASE58_ALPHABET[rem as usize]);
        num = next;
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    for d in digits.iter().rev() {
        out.push(*d as char);
    }
    out
}

/// Bech32/Bech32m polymod over `hrp` + `data` (BIP173's `polymod`).
fn polymod(hrp: &str, data: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk = 1u32;
    let mut feed = |v: u8| {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    };
    for c in hrp.bytes() {
        feed(c >> 5);
    }
    feed(0);
    for c in hrp.bytes() {
        feed(c & 0x1f);
    }
    for v in data {
        feed(*v);
    }
    chk
}

/// BIP173/BIP350 segwit address: `hrp1<version-char><program-5bit><checksum>`.
/// v0 programs use the Bech32 constant; v1+ use Bech32m (Core's
/// `Encode` — a v0 program encoded Bech32m or vice versa is invalid).
#[must_use]
pub fn witness_address(hrp: &str, version: u8, program: &[u8]) -> String {
    // 8→5 bit regrouping, high bits first, padded to a whole group.
    let mut data: Vec<u8> = vec![version];
    {
        let mut acc = 0u32;
        let mut bits = 0u32;
        for byte in program {
            acc = (acc << 8) | u32::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                data.push(((acc >> bits) & 0x1f) as u8);
            }
        }
        if bits > 0 {
            data.push(((acc << (5 - bits)) & 0x1f) as u8);
        }
    }
    let constant = if version == 0 {
        BECH32_CONST
    } else {
        BECH32M_CONST
    };
    let mut check_input = data.clone();
    check_input.extend([0u8; 6]);
    let check = polymod(hrp, &check_input) ^ constant;

    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for v in &data {
        out.push(BECH32_CHARSET[*v as usize] as char);
    }
    for shift in (0..6).rev().map(|i| i * 5) {
        out.push(BECH32_CHARSET[((check >> shift) & 0x1f) as usize] as char);
    }
    out
}

/// Base58Check decode — the inverse of [`base58check`]. `None` on a
/// non-base58 character or a checksum mismatch (Core's
/// `DecodeBase58Check` behavior: no partial results).
#[must_use]
pub fn base58check_decode(s: &str) -> Option<(u8, Vec<u8>)> {
    let mut zeros = 0usize;
    let mut num: Vec<u8> = Vec::new();
    let mut seen_nonzero = false;
    for c in s.bytes() {
        let digit = BASE58_ALPHABET.iter().position(|&b| b == c)? as u32;
        if !seen_nonzero && c == b'1' {
            zeros += 1;
            continue;
        }
        seen_nonzero = true;
        // num = num * 58 + digit (big-endian).
        let mut carry = digit;
        for byte in num.iter_mut().rev() {
            let acc = u32::from(*byte) * 58 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut data = vec![0u8; zeros];
    data.extend_from_slice(&num);
    if data.len() < 5 {
        return None;
    }
    let (body, check) = data.split_at(data.len() - 4);
    if sha256d(body)[..4] != *check {
        return None;
    }
    Some((body[0], body[1..].to_vec()))
}

/// Base58Check over a caller-supplied body — same as [`base58check`]
/// but for multi-byte version prefixes (BIP32 extended keys carry a
/// four-byte version inside the body).
#[must_use]
pub fn base58check_body(body: &[u8]) -> String {
    let mut data = body.to_vec();
    data.extend_from_slice(&sha256d(body)[..4]);
    base58_encode_raw(&data)
}

/// Base58Check decode returning the complete body — for payloads whose
/// version is wider than one byte (extended keys).
#[must_use]
pub fn base58check_decode_body(s: &str) -> Option<Vec<u8>> {
    let mut zeros = 0usize;
    let mut num: Vec<u8> = Vec::new();
    let mut seen_nonzero = false;
    for c in s.bytes() {
        let digit = BASE58_ALPHABET.iter().position(|&b| b == c)? as u32;
        if !seen_nonzero && c == b'1' {
            zeros += 1;
            continue;
        }
        seen_nonzero = true;
        let mut carry = digit;
        for byte in num.iter_mut().rev() {
            let acc = u32::from(*byte) * 58 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut data = vec![0u8; zeros];
    data.extend_from_slice(&num);
    if data.len() < 5 {
        return None;
    }
    let (body, check) = data.split_at(data.len() - 4);
    if sha256d(body)[..4] != *check {
        return None;
    }
    Some(body.to_vec())
}

/// BIP173/BIP350 decode: returns `(hrp, version, program)` — the
/// inverse of [`witness_address`]. Enforces the uniform-case rule,
/// checksum-constant-by-version (v0 → bech32, v1+ → bech32m), and the
/// BIP173 program rules (2–40 bytes; v0 must be 20 or 32).
#[must_use]
pub fn witness_decode(s: &str) -> Option<(String, u8, Vec<u8>)> {
    let lower = s.to_ascii_lowercase();
    // Mixed case is invalid (BIP173's case rule).
    if lower != s && s.to_ascii_uppercase() != s {
        return None;
    }
    let sep = lower.rfind('1')?;
    // The data part needs a version symbol plus the 6-symbol checksum;
    // exactly 6 leaves no room for a version and would underflow the
    // 5→8 regroup range below (`values[1..values.len() - 6]`).
    if sep == 0 || lower.len() - sep - 1 < 7 || lower.len() > 90 {
        return None;
    }
    let hrp = &lower[..sep];
    let mut values = Vec::with_capacity(lower.len() - sep - 1);
    for c in lower[sep + 1..].bytes() {
        values.push(BECH32_CHARSET.iter().position(|&b| b == c)? as u8);
    }
    let version = *values.first()?;
    if version > 16 {
        return None;
    }
    let expected = if version == 0 {
        BECH32_CONST
    } else {
        BECH32M_CONST
    };
    if polymod(hrp, &values) != expected {
        return None;
    }
    // 5→8 bit regrouping of the data part (checksum excluded); the
    // leftover group must be zero-padded, not data-bearing.
    let mut program = Vec::with_capacity(values.len() * 5 / 8);
    {
        let mut acc = 0u32;
        let mut bits = 0u32;
        for v in &values[1..values.len() - 6] {
            acc = (acc << 5) | u32::from(*v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                program.push((acc >> bits) as u8);
            }
        }
        if bits >= 5 || (acc << (8 - bits)) & 0xff != 0 {
            return None;
        }
    }
    if !(2..=40).contains(&program.len()) {
        return None;
    }
    if version == 0 && program.len() != 20 && program.len() != 32 {
        return None;
    }
    Some((hrp.to_owned(), version, program))
}

/// What [`validate_address`] reports for a decodable destination.
#[derive(Clone, Debug)]
pub struct AddressInfo {
    /// The scriptPubKey this address pays to.
    pub script: Script,
    /// Core's `isscript` field: `Some(true)` for P2SH and v1-32B
    /// taproot (both can carry script paths), `Some(false)` for P2PKH
    /// and v0 witness, `None` for unknown witness versions where Core
    /// omits the field entirely.
    pub is_script: Option<bool>,
    /// `(version, program)` for segwit destinations — Core's
    /// `iswitness`/`witness_version`/`witness_program` fields.
    pub witness: Option<(u8, Vec<u8>)>,
}

/// The checksum alphabet a bech32 string actually encoded with —
/// BIP173 requires `Bech32` for v0 and `Bech32m` for v1+.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Bech32Encoding {
    /// BIP173 constant.
    Bech32,
    /// BIP350 constant.
    Bech32m,
}

/// Core's `validateaddress` failure shape: the message and the
/// character positions its error locator found.
pub type DestError = (String, Vec<i32>);

/// A decoded bech32 string: HRP, the 5-bit data values (version +
/// program + checksum tail), and which checksum constant verified.
type Bech32Decoded = (String, Vec<u8>, Bech32Encoding);

/// Bech32 decode with Core's `bech32::Decode` + `LocateErrors` error
/// vocabulary. The BCH syndrome locator (which can pinpoint ≤2 wrong
/// checksum characters) is not replicated: checksum failures report
/// `"Invalid checksum"` with no locations, which is also what Core
/// emits whenever corruption exceeds its locator.
fn bech32_decode_full(s: &str) -> Result<Bech32Decoded, DestError> {
    if s.len() > 90 {
        return Err((
            "Bech32 string too long".into(),
            (90..s.len() as i32).collect(),
        ));
    }
    // Core's CheckCharacters: the first cased letter fixes the case;
    // every later char of the other case — and any non-printable —
    // is an error position.
    let mut lower = false;
    let mut upper = false;
    let mut locs = Vec::new();
    for (i, &c) in s.as_bytes().iter().enumerate() {
        match c {
            b'a'..=b'z' if upper => locs.push(i as i32),
            b'a'..=b'z' => lower = true,
            b'A'..=b'Z' if lower => locs.push(i as i32),
            b'A'..=b'Z' => upper = true,
            0..=32 | 127.. => locs.push(i as i32),
            _ => {}
        }
    }
    if !locs.is_empty() {
        return Err(("Invalid character or mixed case".into(), locs));
    }
    let lower_s = s.to_ascii_lowercase();
    let Some(pos) = lower_s.rfind('1') else {
        return Err(("Missing separator".into(), vec![]));
    };
    if pos == 0 || pos + 6 >= s.len() {
        return Err(("Invalid separator position".into(), vec![pos as i32]));
    }
    let hrp = &lower_s[..pos];
    let mut values = Vec::with_capacity(s.len() - pos - 1);
    for (i, &c) in lower_s.as_bytes()[pos + 1..].iter().enumerate() {
        let Some(v) = BECH32_CHARSET.iter().position(|&b| b == c) else {
            return Err((
                "Invalid Base 32 character".into(),
                vec![(pos + 1 + i) as i32],
            ));
        };
        values.push(v as u8);
    }
    // Values include the 6-symbol checksum tail; polymod over
    // hrp+values identifies the encoding.
    let pm = polymod(hrp, &values);
    let enc = if pm == BECH32_CONST {
        Bech32Encoding::Bech32
    } else if pm == BECH32M_CONST {
        Bech32Encoding::Bech32m
    } else {
        return Err(("Invalid checksum".into(), vec![]));
    };
    Ok((hrp.to_owned(), values, enc))
}

/// Base58 decode without the checksum — Core's `DecodeBase58`: pure
/// charset/length validity (its `max_ret_len` is 100 here).
fn base58_decode(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut num: Vec<u8> = Vec::new();
    let mut seen_nonzero = false;
    for c in s.bytes() {
        let Some(digit) = BASE58_ALPHABET.iter().position(|&b| b == c) else {
            return false;
        };
        if !seen_nonzero && c == b'1' {
            continue;
        }
        seen_nonzero = true;
        let mut carry = digit as u32;
        for byte in num.iter_mut().rev() {
            let acc = u32::from(*byte) * 58 + carry;
            *byte = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        while carry > 0 {
            if num.len() + 1 > 96 {
                return false; // beyond Core's max_ret_len
            }
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    true
}

/// Core's `DecodeDestination` for `validateaddress`: classifies a
/// string as this network's P2PKH/P2SH/witness destination or reports
/// Core's exact failure message and error positions.
///
/// The decode order matches Core: unless the string starts with this
/// network's bech32 HRP (case-insensitively), it is treated as base58;
/// an HRP-prefixed string is decoded as bech32/bech32m and reports
/// bech32's own error strings.
pub fn validate_address(s: &str, params: &Params) -> Result<AddressInfo, DestError> {
    let hrp = &params.bech32_hrp;
    // Byte-slice `s`, not `s[..hrp.len()]`: a `&str` range that lands
    // inside a multi-byte character panics, and `hrp.len()` is an
    // attacker-uncontrolled but arbitrary byte offset relative to `s`
    // (e.g. a leading "€" — 3 bytes — puts offset 2 mid-character).
    // `[u8]::get` returns `None` instead of panicking on a short
    // string, and byte comparison needs no boundary at all.
    let is_bech32 = s
        .as_bytes()
        .get(..hrp.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(hrp.as_bytes()));

    if !is_bech32 {
        if let Some((version, payload)) = base58check_decode(s) {
            if payload.len() == 20 && version == params.base58_pubkey_prefix {
                let mut script = Vec::with_capacity(25);
                script.extend_from_slice(&[0x76, 0xa9, 0x14]);
                script.extend_from_slice(&payload);
                script.extend_from_slice(&[0x88, 0xac]);
                return Ok(AddressInfo {
                    script: Script::new(script),
                    is_script: Some(false),
                    witness: None,
                });
            }
            if payload.len() == 20 && version == params.base58_script_prefix {
                let mut script = Vec::with_capacity(23);
                script.extend_from_slice(&[0xa9, 0x14]);
                script.extend_from_slice(&payload);
                script.push(0x87);
                return Ok(AddressInfo {
                    script: Script::new(script),
                    is_script: Some(true),
                    witness: None,
                });
            }
            // Prefix right but payload short → length error; a foreign
            // version byte → unsupported.
            let msg = if version == params.base58_pubkey_prefix
                || version == params.base58_script_prefix
            {
                "Invalid length for Base58 address (P2PKH or P2SH)"
            } else {
                "Invalid or unsupported Base58-encoded address."
            };
            return Err((msg.into(), vec![]));
        }
        return Err(if base58_decode(s) {
            (
                "Invalid checksum or length of Base58 address (P2PKH or P2SH)".into(),
                vec![],
            )
        } else {
            (
                "Invalid or unsupported Segwit (Bech32) or Base58 encoding.".into(),
                vec![],
            )
        });
    }

    let (got_hrp, values, enc) = bech32_decode_full(s)?;
    // `values` still carries its 6-symbol checksum tail (unlike Core's
    // post-strip `dec.data`), so "empty" here means length <= 6: no
    // version symbol survives once the checksum is accounted for. Core
    // hits the same `dec.data.empty()` check for this case; without it,
    // the 5→8 regroup range below (`values[1..values.len() - 6]`)
    // underflows to a start-after-end slice and panics.
    if values.len() <= 6 {
        return Err(("Empty Bech32 data section".into(), vec![]));
    }
    if got_hrp != *hrp {
        return Err((
            format!(
                "Invalid or unsupported prefix for Segwit (Bech32) address (expected {hrp}, got {got_hrp})."
            ),
            vec![],
        ));
    }
    let version = u32::from(values[0]);
    match (version, enc) {
        (0, Bech32Encoding::Bech32m) => {
            return Err((
                "Version 0 witness address must use Bech32 checksum".into(),
                vec![],
            ));
        }
        (v, Bech32Encoding::Bech32) if v != 0 => {
            return Err((
                "Version 1+ witness address must use Bech32m checksum".into(),
                vec![],
            ));
        }
        _ => {}
    }
    // 5→8 regroup the data part (version symbol + checksum excluded).
    let mut program = Vec::with_capacity(values.len() * 5 / 8);
    {
        let mut acc = 0u32;
        let mut bits = 0u32;
        for v in &values[1..values.len() - 6] {
            acc = (acc << 5) | u32::from(*v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                program.push((acc >> bits) as u8);
            }
        }
        if bits >= 5 || (acc << (8 - bits)) & 0xff != 0 {
            return Err(("Invalid padding in Bech32 data section".into(), vec![]));
        }
    }
    let unit = if program.len() == 1 { "byte" } else { "bytes" };
    // Core's DescribeAddress: v0 keyhash/scripthash and v1 taproot are
    // named witness types; anything else is WitnessUnknown, which gets
    // no `isscript` field.
    let is_script = if version == 0 {
        if program.len() != 20 && program.len() != 32 {
            return Err((
                format!(
                    "Invalid Bech32 v0 address program size ({} {unit}), per BIP141",
                    program.len()
                ),
                vec![],
            ));
        }
        Some(false)
    } else {
        if version > 16 {
            return Err(("Invalid Bech32 address witness version".into(), vec![]));
        }
        if !(2..=40).contains(&program.len()) {
            return Err((
                format!(
                    "Invalid Bech32 address program size ({} {unit})",
                    program.len()
                ),
                vec![],
            ));
        }
        if version == 1 && program.len() == 32 {
            Some(true)
        } else {
            None
        }
    };
    let opcode = if version == 0 {
        crate::script::OP_0
    } else {
        crate::script::OP_1 + version as u8 - 1
    };
    let mut script = vec![opcode];
    script.extend_from_slice(&crate::script::push_slice(&program));
    Ok(AddressInfo {
        script: Script::new(script),
        is_script,
        witness: Some((version as u8, program)),
    })
}

/// The scriptPubKey an address pays to — the inverse of
/// [`script_address`], Core's `GetScriptForDestination`. `None` when
/// the string is neither a valid base58check address for this
/// network's prefixes nor a bech32/bech32m address for its hrp.
#[must_use]
pub fn address_to_script(address: &str, params: &Params) -> Option<Script> {
    if let Some((version, payload)) = base58check_decode(address)
        && payload.len() == 20
    {
        let mut script = Vec::with_capacity(25);
        if version == params.base58_pubkey_prefix {
            script.extend_from_slice(&[0x76, 0xa9, 0x14]);
            script.extend_from_slice(&payload);
            script.extend_from_slice(&[0x88, 0xac]);
            return Some(Script::new(script));
        }
        if version == params.base58_script_prefix {
            script.extend_from_slice(&[0xa9, 0x14]);
            script.extend_from_slice(&payload);
            script.push(0x87);
            return Some(Script::new(script));
        }
        return None;
    }
    if let Some((hrp, version, program)) = witness_decode(address)
        && hrp == params.bech32_hrp
    {
        let opcode = if version == 0 {
            crate::script::OP_0
        } else {
            crate::script::OP_1 + version - 1
        };
        let mut script = vec![opcode];
        script.extend_from_slice(&crate::script::push_slice(&program));
        return Some(Script::new(script));
    }
    None
}

/// The address a standard scriptPubKey pays to, when one exists —
/// Core's `ExtractDestination`: base58check for P2PKH/P2SH, bech32
/// for v0 witness programs, bech32m for v1+ (including
/// `witness_unknown`). `None` for pubkey, bare-multisig, nulldata and
/// nonstandard scripts, which have no address form.
#[must_use]
pub fn script_address(script: &Script, params: &Params) -> Option<String> {
    match script.classify() {
        ScriptType::PubKeyHash(hash) => Some(base58check(params.base58_pubkey_prefix, &hash)),
        ScriptType::ScriptHash(hash) => Some(base58check(params.base58_script_prefix, &hash)),
        ScriptType::Witness { version, program } => {
            Some(witness_address(params.bech32_hrp, version, &program))
        }
        // The anchor script is a v1 program `4e73` — `ExtractDestination`
        // yields the witness destination, same as Core.
        ScriptType::Anchor => Some(witness_address(params.bech32_hrp, 1, &[0x4e, 0x73])),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::params::Network;
    use crate::transaction::Script;

    #[test]
    fn base58check_matches_known_addresses() {
        // The genesis P2PKH-style payload 0x00 + 20 zero bytes → the
        // well-known burn address.
        assert_eq!(base58check(0x00, &[0u8; 20]), "1111111111111111111114oLvT2");
        // P2SH version 5 + 20 zero bytes.
        assert_eq!(
            base58check(0x05, &[0u8; 20]),
            "31h1vYVSYuKP6AhS86fbRdMw9XHieotbST"
        );
    }

    #[test]
    fn bech32_matches_bip173_vectors() {
        // BIP173's valid-address vector (v0, 20-byte program).
        assert_eq!(
            witness_address(
                "bc",
                0,
                &[
                    0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1,
                    0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
                ]
            ),
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        );
        // BIP350's shortest vector: v16 + 2-byte program.
        assert_eq!(witness_address("bc", 16, &[0x75, 0x1e]), "bc1sw50qgdz25j");
    }

    #[test]
    fn script_address_reproduces_core_addresses() {
        // Real scriptPubKey → address pairs from a Knots 29.3 wallet
        // (regtest prefixes), covering all four standard address forms.
        let params = Network::Regtest.params();
        let cases: &[(&str, &str)] = &[
            // P2WPKH — bech32.
            (
                "00142ef0abe149d195f81afe34f9c8a5b296947bb25d",
                "bcrt1q9mc2hc2f6x2lsxh7xnuu3fdjj628hvjatzgxcr",
            ),
            // P2TR — bech32m.
            (
                "51201d4ade4c044494c4d01633a5595d9b5e1660f8ea81e60564c5377b3f8cc5a2fb",
                "bcrt1pr49dunqygj2vf5qkxwj4jhvmtctxp782s8nq2ex9xaanlrx95tasaxw9kg",
            ),
            // P2PKH — base58check, 0x6f prefix.
            (
                "76a914ba602196720c6f0c47c823e106405d9b0dc71dc088ac",
                "mxWR93hymS6qTPxA5oa9LrX6nUCEPnu9wm",
            ),
            // P2SH — base58check, 0xc4 prefix.
            (
                "a914eb2940a3d86327415123af1dc3ff8d3e349af46487",
                "2NEgeCdxfyXSUB8D2TDez9WTC5YV3LJxE9i",
            ),
        ];
        for (script_hex, expected) in cases {
            let script = Script::new(crate::hex::decode(script_hex).unwrap());
            assert_eq!(
                script_address(&script, &params).as_deref(),
                Some(*expected),
                "{script_hex}"
            );
        }
        // OP_RETURN carries no address.
        assert_eq!(script_address(&Script::new(vec![0x6a]), &params), None);
    }

    /// A bech32 data part of exactly 6 symbols is pure checksum with no
    /// version symbol; the 5→8 regroup used to slice
    /// `values[1..values.len() - 6]` as `[1..0]` and panic instead of
    /// rejecting the string.
    #[test]
    fn witness_decode_rejects_checksum_only_data_part() {
        assert_eq!(witness_decode("br1qv2gva"), None);
    }

    #[test]
    fn address_to_script_rejects_checksum_only_bech32_data() {
        let params = Network::Regtest.params();
        assert_eq!(address_to_script("br1qv2gva", &params), None);
    }

    #[test]
    fn validate_address_rejects_checksum_only_bech32_data() {
        // Same panic, reached through `validate_address`'s own copy of
        // the 5→8 regroup slice.
        let regtest = Network::Regtest.params();
        assert!(validate_address("bcrt1tyddyu", &regtest).is_err());
        let testnet4 = Network::Testnet4.params();
        assert!(validate_address("tb1dclvmr", &testnet4).is_err());
    }

    /// "€" is 3 UTF-8 bytes; byte offset 2 (mainnet's `hrp.len()`, "bc")
    /// used to land mid-character and panic on `s[..hrp.len()]`.
    #[test]
    fn validate_address_rejects_multibyte_char_at_hrp_boundary() {
        let mainnet = Network::Mainnet.params();
        assert!(validate_address("€", &mainnet).is_err());
        // A longer hrp (regtest's "bcrt", 4 bytes) needs the boundary
        // mismatch further into the string.
        let regtest = Network::Regtest.params();
        assert!(validate_address("aa€bcrt1q", &regtest).is_err());
    }
}

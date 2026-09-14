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

    // Count leading zero bytes — each becomes a '1'.
    let zeros = data.iter().take_while(|b| **b == 0).count();

    // Repeated division by 58 over the big-endian number.
    let mut digits: Vec<u8> = Vec::new();
    let mut num = data;
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
}

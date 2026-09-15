//! Output descriptors — display-layer emission plus the parse
//! direction `generateblock`'s `output` argument needs.
//!
//! `script_desc` mirrors what Core's `InferDescriptor` produces for a
//! bare `scriptPubKey` (no key material available): `addr(...)` for
//! addressable templates, `pk(...)`/`multi(...)` for bare-key scripts,
//! `rawtr(...)` for taproot programs, `raw(...)` otherwise — each
//! suffixed with the descriptor checksum from `doc/descriptors.md`.
//! `output_to_script` parses the useful subset back to a
//! `scriptPubKey`: bare addresses plus `addr`/`raw`/`pk`/`pkh`/`wpkh`/
//! `tr` (key-path only) and `rawtr` descriptor forms. Full descriptor
//! wallets (ranges, wildcards, nested trees) remain out of scope.

use crate::address::script_address;
use crate::hex;
use crate::params::Params;
use crate::script::ScriptType;
use crate::transaction::Script;

/// The descriptor input charset — every character a descriptor body
/// may contain (doc/descriptors.md).
const INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

const CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const GENERATOR: [u64; 5] = [
    0xf5dee51989,
    0xa9fdca3312,
    0x1bab10e32d,
    0x3706b1677a,
    0x644d626ffd,
];

fn polymod(chk: u64, value: u64) -> u64 {
    let top = chk >> 35;
    let mut chk = ((chk & 0x7_ffff_ffff) << 5) ^ value;
    for (i, g) in GENERATOR.iter().enumerate() {
        if (top >> i) & 1 == 1 {
            chk ^= g;
        }
    }
    chk
}

/// The 8-character checksum Core appends to a descriptor after `#`
/// (`DescriptorChecksum` in script/descriptor.cpp). Each character
/// feeds its position-within-group to the polymod, and every third
/// character also flushes the accumulated group class — that
/// group/class split is what makes transposition errors detectable.
#[must_use]
pub fn descriptor_checksum(body: &str) -> String {
    let mut chk = 1u64;
    let mut cls = 0u64;
    let mut clscount = 0u32;
    for ch in body.chars() {
        let Some(pos) = INPUT_CHARSET.find(ch) else {
            // The charset covers every byte a desc body can emit; a
            // stray character would corrupt positions silently, so
            // fail loudly rather than mint a wrong checksum.
            panic!("character {ch:?} is outside the descriptor charset");
        };
        chk = polymod(chk, (pos & 31) as u64);
        cls = cls * 3 + (pos >> 5) as u64;
        clscount += 1;
        if clscount == 3 {
            chk = polymod(chk, cls);
            cls = 0;
            clscount = 0;
        }
    }
    if clscount > 0 {
        chk = polymod(chk, cls);
    }
    for _ in 0..8 {
        chk = polymod(chk, 0);
    }
    chk ^= 1;
    (0..8)
        .map(|i| CHECKSUM_CHARSET[((chk >> (5 * (7 - i))) & 31) as usize] as char)
        .collect()
}

/// `CPubKey::IsFullyValid` — a 33-byte compressed or 65-byte
/// uncompressed key whose point is on the curve. libsecp256k1's parser
/// enforces both the length form and curve membership, matching Core's
/// `HexToPubKey` acceptance exactly.
#[must_use]
pub fn pubkey_is_valid(bytes: &[u8]) -> bool {
    secp256k1::PublicKey::from_slice(bytes).is_ok()
}

/// The BIP341 key-path tweak: `Q = P + H_taptweak(P)·G` for an
/// x-only internal key. `tr(key)` descriptors without a script tree
/// reduce to this single tweak — the output program is Q's x-only
/// encoding.
#[must_use]
fn taproot_output_key(internal: &[u8]) -> Option<[u8; 32]> {
    let internal = secp256k1::XOnlyPublicKey::from_slice(internal).ok()?;
    // TapTweak = sha256(sha256("TapTweak") || sha256("TapTweak") || key).
    let tag = crate::hash::sha256(b"TapTweak");
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(&tag);
    data.extend_from_slice(&tag);
    data.extend_from_slice(&internal.serialize());
    let tweak = secp256k1::Scalar::from_be_bytes(crate::hash::sha256(&data)).ok()?;
    let ctx = secp256k1::Secp256k1::verification_only();
    let (output, _parity) = internal.add_tweak(&ctx, &tweak).ok()?;
    Some(output.serialize())
}

/// `GetScriptForDestination`/`InferScript` — the direction
/// `generateblock`'s `output` argument needs: parse a string that is
/// either a network address or a descriptor (optionally
/// `#checksum`-suffixed, verified when present) and return the
/// scriptPubKey it pays to.
///
/// The descriptor subset is what a bare-script argument can express
/// without a wallet's key store: `addr(...)`, `raw(...)`, `pk(...)`,
/// `pkh(...)`, `wpkh(...)`, `tr(...)` (single x-only key, no tree)
/// and `rawtr(...)`. `pkh`/`wpkh` take a hex pubkey; `tr` takes a
/// 32-byte x-only internal key and applies the BIP341 key-path
/// tweak. Everything else errors.
pub fn output_to_script(output: &str, params: &Params) -> Result<Script, String> {
    let body = match output.rsplit_once('#') {
        Some((body, checksum)) => {
            if descriptor_checksum(body) != checksum {
                return Err("invalid descriptor checksum".to_string());
            }
            body
        }
        None => output,
    };
    // No parens — try the address forms.
    let Some(open) = body.find('(') else {
        return crate::address::address_to_script(body, params)
            .ok_or_else(|| "invalid address".to_string());
    };
    if !body.ends_with(')') {
        return Err("malformed descriptor".to_string());
    }
    let (name, arg) = (&body[..open], &body[open + 1..body.len() - 1]);
    let key = hex::decode(arg);
    let err = || "invalid descriptor".to_string();
    match name {
        "addr" => crate::address::address_to_script(arg, params).ok_or_else(err),
        "raw" => key.map(Script::new).map_err(|_| err()),
        "pk" => key
            .ok()
            .filter(|k| k.len() == 33 || k.len() == 65)
            .map(|k| {
                Script::new(
                    [
                        crate::script::push_slice(&k),
                        vec![crate::script::OP_CHECKSIG],
                    ]
                    .concat(),
                )
            })
            .ok_or_else(err),
        "pkh" | "wpkh" => {
            let k = key
                .ok()
                .filter(|k| k.len() == 33 || k.len() == 65)
                .ok_or_else(err)?;
            let h = crate::hash::hash160(&k);
            let script = if name == "pkh" {
                [&[0x76, 0xa9, 0x14], &h[..], &[0x88, 0xac]].concat()
            } else {
                [&[crate::script::OP_0, 0x14], &h[..]].concat()
            };
            Ok(Script::new(script))
        }
        "tr" => {
            let k = key.ok().filter(|k| k.len() == 32).ok_or_else(err)?;
            let out = taproot_output_key(&k).ok_or_else(err)?;
            Ok(Script::new(
                [&[crate::script::OP_1], &crate::script::push_slice(&out)[..]].concat(),
            ))
        }
        "rawtr" => {
            let k = key.ok().filter(|k| k.len() == 32).ok_or_else(err)?;
            Ok(Script::new(
                [&[crate::script::OP_1], &crate::script::push_slice(&k)[..]].concat(),
            ))
        }
        _ => Err("unsupported descriptor".to_string()),
    }
}

/// `InferDescriptor` for a bare scriptPubKey, including the `#`
/// checksum suffix Core's `Descriptor::ToString` emits.
#[must_use]
pub fn script_desc(script: &Script, params: &Params) -> String {
    let body = match script.classify() {
        // Taproot gets the dedicated rawtr() form, not addr().
        ScriptType::Witness {
            version: 1,
            ref program,
        } if program.len() == 32 => format!("rawtr({})", hex::encode(program)),
        ScriptType::PubKey(ref key) => format!("pk({})", hex::encode(key)),
        ScriptType::Multisig { required, ref keys } => {
            let hexes = keys
                .iter()
                .map(|k| hex::encode(k))
                .collect::<Vec<_>>()
                .join(",");
            format!("multi({required},{hexes})")
        }
        _ => match script_address(script, params) {
            Some(addr) => format!("addr({addr})"),
            None => format!("raw({})", hex::encode(script.as_bytes())),
        },
    };
    format!("{body}#{}", descriptor_checksum(&body))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::params::Network;
    use crate::transaction::Script;

    /// Every desc below was read back from Knots 29.3 `decodescript`.
    #[test]
    fn script_desc_matches_core() {
        let params = Network::Regtest.params();
        let cases: &[(&str, &str)] = &[
            (
                "76a914ba602196720c6f0c47c823e106405d9b0dc71dc088ac",
                "addr(mxWR93hymS6qTPxA5oa9LrX6nUCEPnu9wm)#3935e2kq",
            ),
            (
                "a914eb2940a3d86327415123af1dc3ff8d3e349af46487",
                "addr(2NEgeCdxfyXSUB8D2TDez9WTC5YV3LJxE9i)#957866pd",
            ),
            (
                "00142ef0abe149d195f81afe34f9c8a5b296947bb25d",
                "addr(bcrt1q9mc2hc2f6x2lsxh7xnuu3fdjj628hvjatzgxcr)#vgfdsvvs",
            ),
            (
                "0020651d283f80f9673099142e0c4d7f4367e3bf87f3b6e75f3d00e17540d1f4f96f",
                "addr(bcrt1qv5wjs0uql9nnpxg59cxy6l6rvl3mlplnkmn470gqu965p505l9hsvmeu5k)#pk44vnqt",
            ),
            (
                "51201d4ade4c044494c4d01633a5595d9b5e1660f8ea81e60564c5377b3f8cc5a2fb",
                "rawtr(1d4ade4c044494c4d01633a5595d9b5e1660f8ea81e60564c5377b3f8cc5a2fb)#wt50qs67",
            ),
            (
                "2102aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac",
                "pk(02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)#rkg34naf",
            ),
            (
                "512102aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa21\
                 03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb52ae",
                "multi(1,02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,\
                 03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)#wcrrdnej",
            ),
            ("600228e0", "addr(bcrt1s9rsqjg3vuy)#k0y40j9r"),
            (
                "6a0b68656c6c6f20776f726c64",
                "raw(6a0b68656c6c6f20776f726c64)#hcyqe6dc",
            ),
            ("", "raw()#58lrscpx"),
        ];
        for (script_hex, expected) in cases {
            let script = Script::new(hex::decode(script_hex).unwrap());
            assert_eq!(script_desc(&script, &params), *expected, "{script_hex}");
        }
    }
}

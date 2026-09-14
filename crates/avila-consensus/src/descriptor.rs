//! Output descriptors — display-layer emission only.
//!
//! `script_desc` mirrors what Core's `InferDescriptor` produces for a
//! bare `scriptPubKey` (no key material available): `addr(...)` for
//! addressable templates, `pk(...)`/`multi(...)` for bare-key scripts,
//! `rawtr(...)` for taproot programs, `raw(...)` otherwise — each
//! suffixed with the descriptor checksum from `doc/descriptors.md`.
//! Parsing/importing descriptors (watch-only wallets) is a separate,
//! larger task; this module only writes them.

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

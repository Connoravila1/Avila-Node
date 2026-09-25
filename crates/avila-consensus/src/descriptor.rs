//! Output descriptors — the parser Core's `Parse` implements in
//! `script/descriptor.cpp` plus the display-layer `InferDescriptor`
//! direction `generateblock`/`script_desc` needs.
//!
//! The parse side is a faithful port of `ParseScript`/`ParsePubkey`/
//! `ParseKeyPath`: all descriptor functions (`pk`, `pkh`, `wpkh`,
//! `combo`, `multi`, `sortedmulti`, `multi_a`, `sortedmulti_a`, `sh`,
//! `wsh`, `tr`, `addr`, `raw`, `rawtr`), key expressions (hex pubkeys,
//! WIF secrets, xpub/xprv with `[fp/path]` origins and `path/*`
//! ranges), and the single multipath `<a;b>` specifier whose values
//! expand into the returned descriptor vector. Miniscript fragments
//! inside `wsh`/`tr` are not yet parsed.

use std::collections::HashMap;

use crate::address::script_address;
use crate::extended_key::ExtKey;
use crate::hex;
use crate::params::Params;
use crate::script::{self, ScriptType};
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

// ------------------------------------------------------------------
// Descriptor parser — a faithful port of Core's `ParseScript` /
// `ParsePubkey` / `ParseKeyPath` from `script/descriptor.cpp`.
// ------------------------------------------------------------------

/// `ParseScriptContext` — where in the tree a script expression sits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ctx {
    Top,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
}

/// `DeriveType` — the wildcard form after a `/` path, if any.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Derive {
    No,
    Unhardened,
    Hardened,
}

/// A parsed key expression — Core's `PubkeyProvider` hierarchy.
#[derive(Clone, Debug)]
pub enum Provider {
    /// A literal pubkey (`ConstPubkeyProvider`); `xonly` strips the
    /// leading `02`/`03` when serialized, used in taproot contexts.
    Const { pubkey: Vec<u8>, xonly: bool },
    /// An extended key plus its derivation path (`BIP32PubkeyProvider`).
    Bip32 {
        extpub: ExtKey,
        path: Vec<u32>,
        derive: Derive,
        apostrophe: bool,
    },
    /// `[fingerprint/path]` origin metadata wrapping another provider.
    Origin {
        fingerprint: [u8; 4],
        path: Vec<u32>,
        apostrophe: bool,
        inner: Box<Provider>,
    },
}

/// `FlatSigningProvider` — the private material collected while
/// parsing, used both for `hasprivatekeys` and for hardened-range
/// derivation at `Expand` time. The remaining maps accumulate during
/// `Expand` exactly like Core's `out` provider: expanded pubkeys,
/// per-key origins, wrapped subscripts, and taproot spend data.
#[derive(Clone, Default, Debug)]
pub struct FlatProvider {
    /// `hash160(pubkey)` → secret, for WIF keys and xprv roots alike.
    pub keys: HashMap<[u8; 20], secp256k1::SecretKey>,
    /// `hash160(root pubkey)` → the decoded xprv (chain code needed
    /// for private derivation beyond the root).
    pub xprvs: HashMap<[u8; 20], ExtKey>,
    /// `hash160(pubkey)` → pubkey — written by the hash-locked
    /// `MakeScripts` (`pkh`/`wpkh`/`combo`/`tr`) so inferred
    /// descriptors can name the key.
    pub pubkeys: HashMap<[u8; 20], Vec<u8>>,
    /// `hash160(pubkey)` → `(pubkey, (fingerprint, path))` — every
    /// expanded key's origin info (`ExpandHelper`'s `out.origins`).
    pub origins: HashMap<[u8; 20], (Vec<u8>, KeyOrigin)>,
    /// `hash160(script)` → script — wrapped subscripts (`sh`, `wsh`,
    /// and combo's P2SH-P2WPKH member) for inference.
    pub scripts: HashMap<[u8; 20], Vec<u8>>,
    /// `xonly output key` → spend data (`TaprootSpendData` — merkle
    /// root, internal key, and `(script, leaf_ver)` → control blocks).
    pub tr_trees: HashMap<[u8; 32], TaprootSpendData>,
}

/// Audit SEED-3/V-S3: a dropped provider erases its secret material —
/// secrets left in freed heap survive until reallocation overwrites
/// them. `SecretKey::non_secure_erase` is a volatile write the
/// optimizer can't remove.
impl Drop for FlatProvider {
    fn drop(&mut self) {
        for sk in self.keys.values_mut() {
            sk.non_secure_erase();
        }
        for x in self.xprvs.values_mut() {
            zeroize::Zeroize::zeroize(&mut x.key);
            zeroize::Zeroize::zeroize(&mut x.chain_code);
        }
    }
}

/// Core's `TaprootSpendData` — what a `tr()` expansion records so the
/// output script can later be inferred back into `tr(...)` form.
#[derive(Clone, Debug, Default)]
pub struct TaprootSpendData {
    /// Root of the script tree — `None` for a key-path-only output.
    pub merkle_root: Option<[u8; 32]>,
    /// The untweaked internal key.
    pub internal_key: [u8; 32],
    /// `(depth, script, leaf_version)` per leaf in descriptor order.
    /// Core stores control blocks and re-inverts them in
    /// `InferTaprootTree`; since this provider is only populated by
    /// our own expansions the leaves are kept directly.
    pub leaves: Vec<(usize, Vec<u8>, u8)>,
}

/// `KeyOriginInfo` — a key's origin fingerprint and derivation path.
type KeyOrigin = ([u8; 4], Vec<u32>);

/// A parsed descriptor — Core's `DescriptorImpl` hierarchy flattened
/// into one enum.
#[derive(Clone, Debug)]
pub enum Descriptor {
    Pk {
        key: Provider,
        xonly: bool,
    },
    Pkh {
        key: Provider,
    },
    Wpkh {
        key: Provider,
    },
    Combo {
        key: Provider,
    },
    /// `multi`/`sortedmulti` (ECDSA) or `multi_a`/`sortedmulti_a`
    /// (tapscript) — distinguished by `checksig_add`.
    Multi {
        threshold: u32,
        keys: Vec<Provider>,
        sorted: bool,
        checksig_add: bool,
    },
    Sh(Box<Descriptor>),
    Wsh(Box<Descriptor>),
    Tr {
        internal: Provider,
        subs: Vec<Descriptor>,
        depths: Vec<usize>,
    },
    RawTr {
        key: Provider,
    },
    /// `sp(scan_key, spend_key)` — BIP352 silent-payments watch. The
    /// scan key's secret (WIF or xprv-derived) lives in the provider
    /// map like any key; `spend` is the x-only spend public key.
    /// `expand` yields no fixed scripts — outputs derive per-tx.
    Silent {
        scan: Provider,
        spend: Provider,
    },
    /// `addr(...)` — stores the canonical re-encoded destination.
    Addr {
        dest: String,
        script: Script,
    },
    Raw {
        script: Vec<u8>,
    },
    /// A parsed Miniscript — `wsh(...)`/`tr()` bodies that aren't a
    /// fixed-form function (`MiniscriptDescriptor`). `node.keys` index
    /// into `keys` (Core's `Key` = `KeyParser::m_keys` index).
    Miniscript {
        keys: Vec<Provider>,
        node: crate::miniscript::Node,
    },
}

const HARDENED: u32 = 0x8000_0000;
const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
const MAX_PUBKEYS_PER_MULTI_A: usize = 999;
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;
const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;

// ---- script/parsing.cpp primitives ------------------------------

/// `script::Const` — consume `s` if it prefixes `sp`.
fn parse_const(s: &str, sp: &mut &[u8]) -> bool {
    if sp.len() >= s.len() && &sp[..s.len()] == s.as_bytes() {
        *sp = &sp[s.len()..];
        true
    } else {
        false
    }
}

/// `script::Func` — `name(...)` wrapping all of `sp`; strips both
/// the `name(` prefix and the trailing `)`.
fn parse_func(name: &str, sp: &mut &[u8]) -> bool {
    if sp.len() >= name.len() + 2
        && sp[name.len()] == b'('
        && sp[sp.len() - 1] == b')'
        && &sp[..name.len()] == name.as_bytes()
    {
        *sp = &sp[name.len() + 1..sp.len() - 1];
        true
    } else {
        false
    }
}

/// `script::Expr` — consume a balanced `(`/`{` expression, stopping
/// at a level-0 `)`, `}`, or `,`.
fn parse_expr<'a>(sp: &mut &'a [u8]) -> &'a [u8] {
    let mut level = 0i32;
    let mut i = 0;
    while i < sp.len() {
        let c = sp[i];
        if c == b'(' || c == b'{' {
            level += 1;
        } else if level > 0 && (c == b')' || c == b'}') {
            level -= 1;
        } else if level == 0 && (c == b')' || c == b'}' || c == b',') {
            break;
        }
        i += 1;
    }
    let (expr, rest) = sp.split_at(i);
    *sp = rest;
    expr
}

fn to_str(sp: &[u8]) -> String {
    String::from_utf8_lossy(sp).into_owned()
}

fn split(sp: &[u8], sep: u8) -> Vec<&[u8]> {
    sp.split(|&b| b == sep).collect()
}

/// `IsHex` — nonempty, even-length hex digits.
fn is_hex(text: &str) -> bool {
    !text.is_empty() && text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---- key path parsing (ParseKeyPath / ParseKeyPathNum) ----------

fn parse_key_path_num(elem: &[u8], apostrophe: &mut bool, error: &mut String) -> Option<u32> {
    let mut elem = elem;
    let mut hardened = false;
    if let Some(&last) = elem.last()
        && (last == b'\'' || last == b'h')
    {
        elem = &elem[..elem.len() - 1];
        hardened = true;
        *apostrophe = last == b'\'';
    }
    let text = to_str(elem);
    let p: u32 = match text.parse() {
        Ok(p) if !text.starts_with('-') && !text.starts_with('+') => p,
        _ => {
            *error = format!("Key path value '{text}' is not a valid uint32");
            return None;
        }
    };
    if p > 0x7FFF_FFFF {
        *error = format!("Key path value {p} is out of range");
        return None;
    }
    Some(p | (u32::from(hardened) << 31))
}

/// `ParseKeyPath` — `split` is the `/`-split elements where element 0
/// is the key itself and is ignored. With `allow_multipath`, a single
/// `<a;b;…>` segment expands into one path per value.
fn parse_key_path(
    split_elems: &[&[u8]],
    out: &mut Vec<Vec<u32>>,
    apostrophe: &mut bool,
    error: &mut String,
    allow_multipath: bool,
) -> bool {
    let mut path = Vec::new();
    let mut multipath_index = None;
    let mut multipath_values = Vec::new();
    let mut seen_multipath = Vec::new();

    for elem in &split_elems[1..] {
        if elem.first() == Some(&b'<') && elem.last() == Some(&b'>') {
            if !allow_multipath {
                *error = format!(
                    "Key path value '{}' specifies multipath in a section where multipath is not allowed",
                    to_str(elem)
                );
                return false;
            }
            if multipath_index.is_some() {
                *error = "Multiple multipath key path specifiers found".to_string();
                return false;
            }
            let nums = split(&elem[1..elem.len() - 1], b';');
            if nums.len() < 2 {
                *error = "Multipath key path specifiers must have at least two items".to_string();
                return false;
            }
            for num in nums {
                let Some(op_num) = parse_key_path_num(num, apostrophe, error) else {
                    return false;
                };
                if seen_multipath.contains(&op_num) {
                    *error = format!("Duplicated key path value {op_num} in multipath specifier");
                    return false;
                }
                seen_multipath.push(op_num);
                multipath_values.push(op_num);
            }
            path.push(0u32);
            multipath_index = Some(path.len() - 1);
        } else {
            let Some(op_num) = parse_key_path_num(elem, apostrophe, error) else {
                return false;
            };
            path.push(op_num);
        }
    }

    match multipath_index {
        None => out.push(path),
        Some(idx) => {
            for value in multipath_values {
                let mut branch = path.clone();
                branch[idx] = value;
                out.push(branch);
            }
        }
    }
    true
}

// ---- pubkey provider parsing (ParsePubkey / ParsePubkeyInner) ---

/// `CPubKey::IsValid` structural check — 33-byte `02`/`03` or
/// 65-byte `04`/`06`/`07`.
fn pubkey_structural(bytes: &[u8]) -> bool {
    matches!(
        (bytes.len(), bytes.first()),
        (33, Some(0x02 | 0x03)) | (65, Some(0x04 | 0x06 | 0x07))
    )
}

fn key_id_of(pubkey: &[u8]) -> [u8; 20] {
    crate::hash::hash160(pubkey)
}

fn parse_pubkey_inner(
    sp: &[u8],
    ctx: Ctx,
    out: &mut FlatProvider,
    apostrophe: &mut bool,
    error: &mut String,
    params: &Params,
) -> Vec<Provider> {
    let permit_uncompressed = ctx == Ctx::Top || ctx == Ctx::P2sh;
    let elems = split(sp, b'/');
    let key_text = to_str(elems[0]);
    if key_text.is_empty() {
        *error = "No key provided".to_string();
        return Vec::new();
    }
    if elems.len() == 1 {
        if is_hex(&key_text) {
            let data = crate::hex::decode(&key_text).unwrap_or_default();
            if pubkey_structural(&data) && data.len() == 65 && data[0] != 0x04 {
                *error = "Hybrid public keys are not allowed".to_string();
                return Vec::new();
            }
            if pubkey_is_valid(&data) {
                if permit_uncompressed || data.len() == 33 {
                    return vec![Provider::Const {
                        pubkey: data,
                        xonly: false,
                    }];
                }
                *error = "Uncompressed keys are not allowed".to_string();
                return Vec::new();
            }
            if data.len() == 32 && ctx == Ctx::P2tr {
                let mut fullkey = Vec::with_capacity(33);
                fullkey.push(0x02);
                fullkey.extend_from_slice(&data);
                if pubkey_is_valid(&fullkey) {
                    return vec![Provider::Const {
                        pubkey: fullkey,
                        xonly: true,
                    }];
                }
            }
            *error = format!("Pubkey '{key_text}' is invalid");
            return Vec::new();
        }
        if let Some((secret, compressed)) =
            crate::message::decode_secret(&key_text, params.base58_secret_prefix)
        {
            if permit_uncompressed || compressed {
                let secp = secp256k1::Secp256k1::new();
                let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);
                let pubkey_bytes = if compressed {
                    pubkey.serialize().to_vec()
                } else {
                    pubkey.serialize_uncompressed().to_vec()
                };
                out.keys.insert(key_id_of(&pubkey_bytes), secret);
                return vec![Provider::Const {
                    pubkey: pubkey_bytes,
                    xonly: ctx == Ctx::P2tr,
                }];
            }
            *error = "Uncompressed keys are not allowed".to_string();
            return Vec::new();
        }
    }
    let extkey = ExtKey::decode(
        &key_text,
        params.base58_ext_pubkey_prefix,
        params.base58_ext_secret_prefix,
    );
    let Ok(extkey) = extkey else {
        *error = format!("key '{key_text}' is not valid");
        return Vec::new();
    };
    let mut elems = elems;
    let mut derive = Derive::No;
    if elems.last() == Some(&b"*".as_ref()) {
        elems.pop();
        derive = Derive::Unhardened;
    } else if elems.last() == Some(&b"*'".as_ref()) || elems.last() == Some(&b"*h".as_ref()) {
        *apostrophe = elems.last() == Some(&b"*'".as_ref());
        elems.pop();
        derive = Derive::Hardened;
    }
    let mut paths = Vec::new();
    if !parse_key_path(&elems, &mut paths, apostrophe, error, true) {
        return Vec::new();
    }
    let extpub = if extkey.is_private() {
        match extkey.neuter(params.base58_ext_pubkey_prefix) {
            Some(p) => p,
            None => {
                *error = format!("key '{key_text}' is not valid");
                return Vec::new();
            }
        }
    } else {
        extkey.clone()
    };
    if extkey.is_private()
        && let Some(secret) = secp256k1::SecretKey::from_slice(&extkey.key[1..]).ok()
    {
        let key_id = key_id_of(&extpub.key);
        out.keys.insert(key_id, secret);
        out.xprvs.insert(key_id, extkey);
    }
    paths
        .into_iter()
        .map(|path| Provider::Bip32 {
            extpub: extpub.clone(),
            path,
            derive,
            apostrophe: *apostrophe,
        })
        .collect()
}

/// `ParsePubkey` — the `[fp/path]` origin wrapper plus the inner key.
fn parse_pubkey(
    sp: &[u8],
    ctx: Ctx,
    out: &mut FlatProvider,
    error: &mut String,
    params: &Params,
) -> Vec<Provider> {
    let origin_split = split(sp, b']');
    if origin_split.len() > 2 {
        *error = "Multiple ']' characters found for a single pubkey".to_string();
        return Vec::new();
    }
    let mut apostrophe = false;
    if origin_split.len() == 1 {
        return parse_pubkey_inner(origin_split[0], ctx, out, &mut apostrophe, error, params);
    }
    if origin_split[0].is_empty() || origin_split[0][0] != b'[' {
        let got = if origin_split[0].is_empty() {
            ']'
        } else {
            origin_split[0][0] as char
        };
        *error =
            format!("Key origin start '[ character expected but not found, got '{got}' instead");
        return Vec::new();
    }
    let slash_split = split(&origin_split[0][1..], b'/');
    if slash_split[0].len() != 8 {
        *error = format!(
            "Fingerprint is not 4 bytes ({} characters instead of 8 characters)",
            slash_split[0].len()
        );
        return Vec::new();
    }
    let fpr_hex = to_str(slash_split[0]);
    if !is_hex(&fpr_hex) {
        *error = format!("Fingerprint '{fpr_hex}' is not hex");
        return Vec::new();
    }
    let fpr_bytes = crate::hex::decode(&fpr_hex).unwrap_or_default();
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&fpr_bytes);
    let mut path_out = Vec::new();
    if !parse_key_path(&slash_split, &mut path_out, &mut apostrophe, error, false) {
        return Vec::new();
    }
    let origin_path = path_out.swap_remove(0);
    let providers = parse_pubkey_inner(origin_split[1], ctx, out, &mut apostrophe, error, params);
    providers
        .into_iter()
        .map(|inner| Provider::Origin {
            fingerprint,
            path: origin_path.clone(),
            apostrophe,
            inner: Box::new(inner),
        })
        .collect()
}

// ---- ParseScript ------------------------------------------------

fn parse_script(
    sp: &mut &[u8],
    ctx: Ctx,
    out: &mut FlatProvider,
    error: &mut String,
    params: &Params,
) -> Vec<Descriptor> {
    let expr = parse_expr(sp);
    let mut e = expr;

    if parse_func("pk", &mut e) {
        let keys = parse_pubkey(e, ctx, out, error, params);
        if keys.is_empty() {
            *error = format!("pk(): {error}");
            return Vec::new();
        }
        return keys
            .into_iter()
            .map(|key| Descriptor::Pk {
                key,
                xonly: ctx == Ctx::P2tr,
            })
            .collect();
    }
    if matches!(ctx, Ctx::Top | Ctx::P2sh | Ctx::P2wsh) && parse_func("pkh", &mut e) {
        let keys = parse_pubkey(e, ctx, out, error, params);
        if keys.is_empty() {
            *error = format!("pkh(): {error}");
            return Vec::new();
        }
        return keys
            .into_iter()
            .map(|key| Descriptor::Pkh { key })
            .collect();
    }
    if ctx == Ctx::Top && parse_func("sp", &mut e) {
        // BIP352 silent payments — `sp(scan_key, spend_key)`. Each
        // parses like a normal key (WIF scan keys land their secret
        // in the provider map for the wallet to resolve).
        let args = split(e, b',');
        if args.len() != 2 {
            *error = "sp() expects exactly 2 arguments".to_string();
            return Vec::new();
        }
        // Both keys parse at the top context — the spend key keeps
        // its compressed parity for the label-subtract scan.
        let scan = parse_pubkey(args[0], ctx, out, error, params);
        let spend = parse_pubkey(args[1], ctx, out, error, params);
        if scan.len() != 1 || spend.len() != 1 {
            *error = format!("sp(): {error}");
            return Vec::new();
        }
        return vec![Descriptor::Silent {
            scan: scan.into_iter().next().unwrap_or_else(|| unreachable!()),
            spend: spend.into_iter().next().unwrap_or_else(|| unreachable!()),
        }];
    }
    if ctx == Ctx::Top && parse_func("combo", &mut e) {
        let keys = parse_pubkey(e, ctx, out, error, params);
        if keys.is_empty() {
            *error = format!("combo(): {error}");
            return Vec::new();
        }
        return keys
            .into_iter()
            .map(|key| Descriptor::Combo { key })
            .collect();
    } else if parse_func("combo", &mut e) {
        *error = "Can only have combo() at top level".to_string();
        return Vec::new();
    }
    let multi = parse_func("multi", &mut e);
    let sortedmulti = !multi && parse_func("sortedmulti", &mut e);
    let multi_a = !(multi || sortedmulti) && parse_func("multi_a", &mut e);
    let sortedmulti_a = !(multi || sortedmulti || multi_a) && parse_func("sortedmulti_a", &mut e);
    if (matches!(ctx, Ctx::Top | Ctx::P2sh | Ctx::P2wsh) && (multi || sortedmulti))
        || (ctx == Ctx::P2tr && (multi_a || sortedmulti_a))
    {
        let threshold = parse_expr(&mut e);
        let thres_text = to_str(threshold);
        let Ok(thres) = thres_text.parse::<u32>() else {
            *error = format!("Multi threshold '{thres_text}' is not valid");
            return Vec::new();
        };
        let mut script_size = 0usize;
        let mut max_len = 0usize;
        let mut providers: Vec<Vec<Provider>> = Vec::new();
        while !e.is_empty() {
            if !parse_const(",", &mut e) {
                *error = format!("Multi: expected ',', got '{}'", e[0] as char);
                return Vec::new();
            }
            let arg = parse_expr(&mut e);
            let pks = parse_pubkey(arg, ctx, out, error, params);
            if pks.is_empty() {
                *error = format!("Multi: {error}");
                return Vec::new();
            }
            script_size += provider_size(&pks[0]) + 1;
            max_len = max_len.max(pks.len());
            providers.push(pks);
        }
        let checksig_add = multi_a || sortedmulti_a;
        let (limit, name) = if checksig_add {
            (MAX_PUBKEYS_PER_MULTI_A, "multi_a")
        } else {
            (MAX_PUBKEYS_PER_MULTISIG, "multisig")
        };
        if providers.is_empty() || providers.len() > limit {
            *error = format!(
                "Cannot have {} keys in {name}; must have between 1 and {limit} keys, inclusive",
                providers.len()
            );
            return Vec::new();
        }
        if thres < 1 {
            *error = format!("Multisig threshold cannot be {thres}, must be at least 1");
            return Vec::new();
        }
        if thres as usize > providers.len() {
            *error = format!(
                "Multisig threshold cannot be larger than the number of keys; \
                 threshold is {thres} but only {} keys specified",
                providers.len()
            );
            return Vec::new();
        }
        if ctx == Ctx::Top && providers.len() > 3 {
            *error = format!(
                "Cannot have {} pubkeys in bare multisig; only at most 3 pubkeys",
                providers.len()
            );
            return Vec::new();
        }
        if ctx == Ctx::P2sh && script_size + 3 > MAX_SCRIPT_ELEMENT_SIZE {
            *error = format!(
                "P2SH script is too large, {} bytes is larger than {MAX_SCRIPT_ELEMENT_SIZE} bytes",
                script_size + 3
            );
            return Vec::new();
        }
        for vec in &mut providers {
            if vec.len() == 1 {
                let single = vec[0].clone();
                for _ in 1..max_len {
                    vec.push(single.clone());
                }
            } else if vec.len() != max_len {
                *error = "multi(): Multipath derivation paths have mismatched lengths".to_string();
                return Vec::new();
            }
        }
        return (0..max_len)
            .map(|i| Descriptor::Multi {
                threshold: thres,
                keys: providers.iter().map(|v| v[i].clone()).collect(),
                sorted: sortedmulti || sortedmulti_a,
                checksig_add,
            })
            .collect();
    } else if multi || sortedmulti {
        *error = "Can only have multi/sortedmulti at top level, in sh(), or in wsh()".to_string();
        return Vec::new();
    } else if multi_a || sortedmulti_a {
        *error = "Can only have multi_a/sortedmulti_a inside tr()".to_string();
        return Vec::new();
    }
    if matches!(ctx, Ctx::Top | Ctx::P2sh) && parse_func("wpkh", &mut e) {
        let keys = parse_pubkey(e, Ctx::P2wpkh, out, error, params);
        if keys.is_empty() {
            *error = format!("wpkh(): {error}");
            return Vec::new();
        }
        return keys
            .into_iter()
            .map(|key| Descriptor::Wpkh { key })
            .collect();
    } else if parse_func("wpkh", &mut e) {
        *error = "Can only have wpkh() at top level or inside sh()".to_string();
        return Vec::new();
    }
    if ctx == Ctx::Top && parse_func("sh", &mut e) {
        let descs = parse_script(&mut e, Ctx::P2sh, out, error, params);
        if descs.is_empty() || !e.is_empty() {
            return Vec::new();
        }
        return descs
            .into_iter()
            .map(|d| Descriptor::Sh(Box::new(d)))
            .collect();
    } else if parse_func("sh", &mut e) {
        *error = "Can only have sh() at top level".to_string();
        return Vec::new();
    }
    if matches!(ctx, Ctx::Top | Ctx::P2sh) && parse_func("wsh", &mut e) {
        let descs = parse_script(&mut e, Ctx::P2wsh, out, error, params);
        if descs.is_empty() || !e.is_empty() {
            return Vec::new();
        }
        return descs
            .into_iter()
            .map(|d| Descriptor::Wsh(Box::new(d)))
            .collect();
    } else if parse_func("wsh", &mut e) {
        *error = "Can only have wsh() at top level or inside sh()".to_string();
        return Vec::new();
    }
    if ctx == Ctx::Top && parse_func("addr", &mut e) {
        let dest_text = to_str(e);
        let Some(script) = crate::address::address_to_script(&dest_text, params) else {
            *error = "Address is not valid".to_string();
            return Vec::new();
        };
        let dest = script_address(&script, params).unwrap_or(dest_text);
        return vec![Descriptor::Addr { dest, script }];
    } else if parse_func("addr", &mut e) {
        *error = "Can only have addr() at top level".to_string();
        return Vec::new();
    }
    if ctx == Ctx::Top && parse_func("tr", &mut e) {
        let arg = parse_expr(&mut e);
        let internal = parse_pubkey(arg, Ctx::P2tr, out, error, params);
        if internal.is_empty() {
            *error = format!("tr(): {error}");
            return Vec::new();
        }
        let mut max_len = internal.len();
        let mut subscripts: Vec<Vec<Descriptor>> = Vec::new();
        let mut depths: Vec<usize> = Vec::new();
        if !e.is_empty() {
            if !parse_const(",", &mut e) {
                *error = format!("tr: expected ',', got '{}'", e[0] as char);
                return Vec::new();
            }
            let mut branches: Vec<bool> = Vec::new();
            loop {
                while parse_const("{", &mut e) {
                    branches.push(false);
                    if branches.len() > TAPROOT_CONTROL_MAX_NODE_COUNT {
                        *error = format!(
                            "tr() supports at most {TAPROOT_CONTROL_MAX_NODE_COUNT} nesting levels"
                        );
                        return Vec::new();
                    }
                }
                let sarg = parse_expr(&mut e);
                let parsed = parse_script(&mut &sarg[..], Ctx::P2tr, out, error, params);
                if parsed.is_empty() {
                    return Vec::new();
                }
                max_len = max_len.max(parsed.len());
                subscripts.push(parsed);
                depths.push(branches.len());
                while branches.last() == Some(&true) {
                    if !parse_const("}", &mut e) {
                        *error = "tr(): expected '}' after script expression".to_string();
                        return Vec::new();
                    }
                    branches.pop();
                }
                if branches.last() == Some(&false) {
                    if !parse_const(",", &mut e) {
                        *error = "tr(): expected ',' after script expression".to_string();
                        return Vec::new();
                    }
                    let last = branches.len() - 1;
                    branches[last] = true;
                }
                if branches.is_empty() {
                    break;
                }
            }
            if !e.is_empty() {
                *error = "tr(): expected ')' after script expression".to_string();
                return Vec::new();
            }
        }
        for vec in &mut subscripts {
            if vec.len() == 1 {
                let single = vec[0].clone();
                for _ in 1..max_len {
                    vec.push(single.clone());
                }
            } else if vec.len() != max_len {
                *error = "tr(): Multipath subscripts have mismatched lengths".to_string();
                return Vec::new();
            }
        }
        let mut internal = internal;
        if internal.len() > 1 && internal.len() != max_len {
            *error =
                "tr(): Multipath internal key mismatches multipath subscripts lengths".to_string();
            return Vec::new();
        }
        while internal.len() < max_len {
            internal.push(internal[0].clone());
        }
        return (0..max_len)
            .map(|i| Descriptor::Tr {
                internal: internal[i].clone(),
                subs: subscripts.iter().map(|v| v[i].clone()).collect(),
                depths: depths.clone(),
            })
            .collect();
    } else if parse_func("tr", &mut e) {
        *error = "Can only have tr at top level".to_string();
        return Vec::new();
    }
    if ctx == Ctx::Top && parse_func("rawtr", &mut e) {
        let arg = parse_expr(&mut e);
        if !e.is_empty() {
            *error = "rawtr(): only one key expected.".to_string();
            return Vec::new();
        }
        let keys = parse_pubkey(arg, Ctx::P2tr, out, error, params);
        if keys.is_empty() {
            *error = format!("rawtr(): {error}");
            return Vec::new();
        }
        return keys
            .into_iter()
            .map(|key| Descriptor::RawTr { key })
            .collect();
    } else if parse_func("rawtr", &mut e) {
        *error = "Can only have rawtr at top level".to_string();
        return Vec::new();
    }
    if ctx == Ctx::Top && parse_func("raw", &mut e) {
        let text = to_str(e);
        if !is_hex(&text) {
            *error = "Raw script is not hex".to_string();
            return Vec::new();
        }
        return vec![Descriptor::Raw {
            script: crate::hex::decode(&text).unwrap_or_default(),
        }];
    } else if parse_func("raw", &mut e) {
        *error = "Can only have raw() at top level".to_string();
        return Vec::new();
    }
    // Miniscript — Core falls through to `miniscript::FromString`
    // here; it can only appear inside wsh()/tr().
    {
        let ms_ctx = if ctx == Ctx::P2wsh {
            crate::miniscript::MsContext::P2wsh
        } else {
            crate::miniscript::MsContext::Tapscript
        };
        let parse_ctx = ctx;
        let mut parser = MiniscriptKeyParser {
            ms_ctx,
            parse_ctx,
            keys: Vec::new(),
            error: String::new(),
            out,
            params,
        };
        let node = crate::miniscript::from_string(&to_str(expr), &mut parser);
        if !parser.error.is_empty() {
            *error = std::mem::take(&mut parser.error);
            return Vec::new();
        }
        if let Some(node) = node {
            if !matches!(ctx, Ctx::P2wsh | Ctx::P2tr) {
                *error = "Miniscript expressions can only be used in wsh or tr.".to_string();
                return Vec::new();
            }
            if !node.is_sane() || node.is_not_satisfiable() {
                // Report the first insane subexpression, like Core.
                let insane = node.find_insane_sub().unwrap_or(&node);
                let mut err = insane
                    .to_string(&KeyStrings {
                        keys: &parser.keys.iter().map(|v| v[0].clone()).collect::<Vec<_>>(),
                    })
                    .unwrap_or_default();
                if !insane.is_valid() {
                    err += " is invalid";
                } else if !node.is_sane() {
                    err += " is not sane";
                    if !insane.is_non_malleable() {
                        err += ": malleable witnesses exist";
                    } else if std::ptr::eq(insane, &node) && !insane.needs_signature() {
                        err += ": witnesses without signature exist";
                    } else if !insane.check_timelocks_mix() {
                        err += ": contains mixes of timelocks expressed in blocks and seconds";
                    } else if !insane.check_duplicate_key() {
                        err += ": contains duplicate public keys";
                    } else if !insane.valid_satisfactions() {
                        err += ": needs witnesses that may exceed resource limits";
                    }
                } else {
                    err += " is not satisfiable";
                }
                *error = err;
                return Vec::new();
            }
            // Multipath expansion: all key provider vectors must be
            // length 1 (broadcast) or the shared length.
            let num_multipath = parser.keys.iter().map(Vec::len).max().unwrap_or(0);
            for vec in &mut parser.keys {
                if vec.len() == 1 {
                    let first = vec[0].clone();
                    vec.resize(num_multipath, first);
                } else if vec.len() != num_multipath {
                    *error = "Miniscript: Multipath derivation paths have mismatched lengths"
                        .to_string();
                    return Vec::new();
                }
            }
            let mut ret = Vec::with_capacity(num_multipath);
            for i in 0..num_multipath {
                let pubs = parser.keys.iter().map(|v| v[i].clone()).collect();
                ret.push(Descriptor::Miniscript {
                    keys: pubs,
                    node: node.clone(),
                });
            }
            return ret;
        }
    }
    if ctx == Ctx::P2sh {
        *error = "A function is needed within P2SH".to_string();
        return Vec::new();
    }
    if ctx == Ctx::P2wsh {
        *error = "A function is needed within P2WSH".to_string();
        return Vec::new();
    }
    *error = format!("'{}' is not a valid descriptor function", to_str(expr));
    Vec::new()
}

/// The serialized pubkey size a provider produces — `GetSize`.
fn provider_size(provider: &Provider) -> usize {
    match provider {
        Provider::Const { pubkey, .. } => pubkey.len(),
        Provider::Bip32 { .. } => 33,
        Provider::Origin { inner, .. } => provider_size(inner),
    }
}

// ---- Parse / CheckChecksum --------------------------------------

/// `CheckChecksum` — split off and verify the `#checksum` suffix.
/// Returns `(body, computed_checksum)`.
fn check_checksum<'a>(
    text: &'a str,
    require_checksum: bool,
    error: &mut String,
) -> Option<(&'a str, String)> {
    let check_split: Vec<&str> = text.splitn(3, '#').collect();
    let hash_count = text.matches('#').count();
    if hash_count > 1 {
        *error = "Multiple '#' symbols".to_string();
        return None;
    }
    if check_split.len() == 1 && require_checksum {
        *error = "Missing checksum".to_string();
        return None;
    }
    if check_split.len() == 2 && check_split[1].len() != 8 {
        *error = format!(
            "Expected 8 character checksum, not {} characters",
            check_split[1].len()
        );
        return None;
    }
    let body = check_split[0];
    // `DescriptorChecksum` rejects characters outside INPUT_CHARSET.
    if body.chars().any(|c| !INPUT_CHARSET.contains(c)) {
        *error = "Invalid characters in payload".to_string();
        return None;
    }
    let checksum = descriptor_checksum(body);
    if check_split.len() == 2 && check_split[1] != checksum {
        *error = format!(
            "Provided checksum '{}' does not match computed checksum '{checksum}'",
            check_split[1]
        );
        return None;
    }
    Some((body, checksum))
}

/// Core's `Parse` — a full descriptor string (optionally
/// `#checksummed`) into one descriptor per multipath expansion plus
/// the collected private material.
pub fn parse_descriptors(
    text: &str,
    params: &Params,
    require_checksum: bool,
) -> Result<(Vec<Descriptor>, FlatProvider, String), String> {
    let mut error = String::new();
    let Some((body, checksum)) = check_checksum(text, require_checksum, &mut error) else {
        return Err(error);
    };
    let mut out = FlatProvider::default();
    let mut sp = body.as_bytes();
    let descs = parse_script(&mut sp, Ctx::Top, &mut out, &mut error, params);
    if sp.is_empty() && !descs.is_empty() {
        Ok((descs, out, checksum))
    } else {
        Err(error)
    }
}

/// `GetDescriptorChecksum` — the checksum of the descriptor body
/// before any `#`, or `None` when the payload is malformed.
#[must_use]
pub fn get_descriptor_checksum(text: &str) -> Option<String> {
    let mut error = String::new();
    check_checksum(text, false, &mut error).map(|(_, c)| c)
}

// ---- canonical serialization (ToString / IsRange / IsSolvable) --

fn fmt_key_path(path: &[u32], apostrophe: bool) -> String {
    let mut out = String::new();
    for &entry in path {
        out.push('/');
        out.push_str(&(entry & 0x7FFF_FFFF).to_string());
        if entry & HARDENED != 0 {
            out.push(if apostrophe { '\'' } else { 'h' });
        }
    }
    out
}

fn provider_string(provider: &Provider) -> String {
    match provider {
        Provider::Const { pubkey, xonly } => {
            let h = hex::encode(pubkey);
            if *xonly { h[2..].to_string() } else { h }
        }
        Provider::Bip32 {
            extpub,
            path,
            derive,
            apostrophe,
        } => {
            let mut ret = extpub.encode() + &fmt_key_path(path, *apostrophe);
            if *derive != Derive::No {
                ret.push_str("/*");
                if *derive == Derive::Hardened {
                    ret.push(if *apostrophe { '\'' } else { 'h' });
                }
            }
            ret
        }
        Provider::Origin {
            fingerprint,
            path,
            apostrophe,
            inner,
        } => format!(
            "[{}{}]{}",
            hex::encode(fingerprint),
            fmt_key_path(path, *apostrophe),
            provider_string(inner)
        ),
    }
}

/// `KeyStrings` — a `KeyCtx`/`ScriptCtx` over an already-parsed key
/// table (canonical `ToString` and dup-compare via `provider_string`).
struct KeyStrings<'a> {
    keys: &'a [Provider],
}

impl crate::miniscript::KeyCtx for KeyStrings<'_> {
    fn ms_context(&self) -> crate::miniscript::MsContext {
        // Never invoked by to_string/duplicate_key_check.
        crate::miniscript::MsContext::P2wsh
    }
    fn key_from_str(&mut self, _text: &str) -> Option<usize> {
        None
    }
    fn key_string(&self, key: usize) -> Option<String> {
        self.keys.get(key).map(provider_string)
    }
    fn key_cmp(&self, a: usize, b: usize) -> std::cmp::Ordering {
        let (Some(a), Some(b)) = (self.keys.get(a), self.keys.get(b)) else {
            return std::cmp::Ordering::Equal;
        };
        provider_string(a).cmp(&provider_string(b))
    }
}

/// `MiniscriptKeyParser` — Core's `KeyParser`: parses key expressions
/// into a table of provider vectors (multipath expansion included),
/// collecting private material into `out` like `ParsePubkey`.
struct MiniscriptKeyParser<'a> {
    ms_ctx: crate::miniscript::MsContext,
    parse_ctx: Ctx,
    keys: Vec<Vec<Provider>>,
    error: String,
    out: &'a mut FlatProvider,
    params: &'a Params,
}

impl crate::miniscript::KeyCtx for MiniscriptKeyParser<'_> {
    fn ms_context(&self) -> crate::miniscript::MsContext {
        self.ms_ctx
    }
    fn key_from_str(&mut self, text: &str) -> Option<usize> {
        let providers = parse_pubkey(
            text.as_bytes(),
            self.parse_ctx,
            self.out,
            &mut self.error,
            self.params,
        );
        if providers.is_empty() {
            return None;
        }
        self.keys.push(providers);
        Some(self.keys.len() - 1)
    }
    fn key_string(&self, key: usize) -> Option<String> {
        self.keys
            .get(key)
            .and_then(|v| v.first())
            .map(provider_string)
    }
    fn key_cmp(&self, a: usize, b: usize) -> std::cmp::Ordering {
        // PubkeyProvider::operator< compares the canonical strings.
        let a = self
            .keys
            .get(a)
            .and_then(|v| v.first())
            .map(provider_string)
            .unwrap_or_default();
        let b = self
            .keys
            .get(b)
            .and_then(|v| v.first())
            .map(provider_string)
            .unwrap_or_default();
        a.cmp(&b)
    }
}

/// `ScriptMaker` — resolved pubkeys to script pushes for
/// `Node::to_script` (`ToPKBytes` is xonly under tapscript).
struct MiniscriptMaker<'a> {
    pubkeys: &'a [Vec<u8>],
    tapscript: bool,
}

impl crate::miniscript::ScriptCtx for MiniscriptMaker<'_> {
    fn to_pk_bytes(&self, key: usize) -> Vec<u8> {
        let pubkey = &self.pubkeys[key];
        if self.tapscript {
            pubkey[pubkey.len() - 32..].to_vec()
        } else {
            pubkey.clone()
        }
    }
    fn to_pkh_bytes(&self, key: usize) -> Vec<u8> {
        crate::hash::hash160(&self.to_pk_bytes(key)).to_vec()
    }
}

fn provider_is_range(provider: &Provider) -> bool {
    match provider {
        Provider::Const { .. } => false,
        Provider::Bip32 { derive, .. } => *derive != Derive::No,
        Provider::Origin { inner, .. } => provider_is_range(inner),
    }
}

fn join_descriptors(name: &str, extra: &str, parts: &[String]) -> String {
    let mut out = String::from(name);
    out.push('(');
    let mut pos = !extra.is_empty();
    out.push_str(extra);
    for part in parts {
        if pos {
            out.push(',');
        }
        pos = true;
        out.push_str(part);
    }
    out.push(')');
    out
}

impl Descriptor {
    /// `Descriptor::ToString` — the canonical public form including
    /// the `#checksum` suffix (never emits private key material).
    #[must_use]
    pub fn to_descriptor_string(&self) -> String {
        let body = self.canonical_body();
        format!("{body}#{}", descriptor_checksum(&body))
    }

    /// The canonical body without checksum — `ToStringHelper` with
    /// `StringType::PUBLIC`.
    #[must_use]
    pub fn canonical_body(&self) -> String {
        match self {
            Descriptor::Pk { key, .. } => join_descriptors("pk", "", &[provider_string(key)]),
            Descriptor::Pkh { key } => join_descriptors("pkh", "", &[provider_string(key)]),
            Descriptor::Wpkh { key } => join_descriptors("wpkh", "", &[provider_string(key)]),
            Descriptor::Combo { key } => join_descriptors("combo", "", &[provider_string(key)]),
            Descriptor::Multi {
                threshold,
                keys,
                sorted,
                checksig_add,
            } => {
                let name = match (*sorted, *checksig_add) {
                    (true, true) => "sortedmulti_a",
                    (false, true) => "multi_a",
                    (true, false) => "sortedmulti",
                    (false, false) => "multi",
                };
                let parts: Vec<String> = keys.iter().map(provider_string).collect();
                join_descriptors(name, &threshold.to_string(), &parts)
            }
            Descriptor::Sh(sub) => join_descriptors("sh", "", &[sub.canonical_body()]),
            Descriptor::Wsh(sub) => join_descriptors("wsh", "", &[sub.canonical_body()]),
            Descriptor::Tr {
                internal,
                subs,
                depths,
            } => {
                let mut parts = vec![provider_string(internal)];
                if !depths.is_empty() {
                    let leaf_strs: Vec<String> = subs.iter().map(|s| s.canonical_body()).collect();
                    parts.push(render_tr_tree(&leaf_strs, depths));
                }
                join_descriptors("tr", "", &parts)
            }
            Descriptor::RawTr { key } => join_descriptors("rawtr", "", &[provider_string(key)]),
            Descriptor::Silent { scan, spend } => {
                join_descriptors("sp", "", &[provider_string(scan), provider_string(spend)])
            }
            Descriptor::Addr { dest, .. } => join_descriptors("addr", dest, &[]),
            Descriptor::Raw { script } => join_descriptors("raw", &hex::encode(script), &[]),
            Descriptor::Miniscript { keys, node } => {
                node.to_string(&KeyStrings { keys }).unwrap_or_default()
            }
        }
    }

    /// `IsRange` — true when any contained key has a `/*` wildcard.
    #[must_use]
    pub fn is_range(&self) -> bool {
        match self {
            Descriptor::Pk { key, .. }
            | Descriptor::Pkh { key }
            | Descriptor::Wpkh { key }
            | Descriptor::Combo { key }
            | Descriptor::RawTr { key } => provider_is_range(key),
            Descriptor::Multi { keys, .. } => keys.iter().any(provider_is_range),
            Descriptor::Sh(sub) | Descriptor::Wsh(sub) => sub.is_range(),
            Descriptor::Tr { internal, subs, .. } => {
                provider_is_range(internal) || subs.iter().any(Self::is_range)
            }
            Descriptor::Miniscript { keys, .. } => keys.iter().any(provider_is_range),
            Descriptor::Silent { scan, spend } => {
                provider_is_range(scan) || provider_is_range(spend)
            }
            Descriptor::Addr { .. } | Descriptor::Raw { .. } => false,
        }
    }

    /// For `sp(scan, spend)` — resolves the watch pair: the scan
    /// key's private half (required for BIP352 detection, drawn from
    /// the provider's WIF/xprv map) and the spend key's full
    /// compressed public half (33 bytes — the `sp1q` encoding carries
    /// its parity).
    #[must_use]
    pub fn silent_keys(&self, signing: &FlatProvider) -> Option<([u8; 32], [u8; 33])> {
        let Descriptor::Silent { scan, spend } = self else {
            return None;
        };
        let mut cache = DeriveCache::new();
        let scan_priv = provider_privkey(scan, 0, signing, &mut cache)?;
        let (spend_full, _) = provider_pubkey(spend, 0, signing, &mut cache)?;
        let mut sp = [0u8; 32];
        sp.copy_from_slice(&scan_priv.secret_bytes());
        let mut bp = [0u8; 33];
        // The spend key must be compressed — an x-only 32-byte entry
        // lifts to even parity (the address encoding keeps parity).
        if spend_full.len() == 33 {
            bp.copy_from_slice(&spend_full);
        } else if spend_full.len() == 32 {
            bp[0] = 0x02;
            bp[1..].copy_from_slice(&spend_full);
        } else {
            return None;
        }
        Some((sp, bp))
    }

    /// `IsSolvable` — address/raw payloads carry no signing info.
    #[must_use]
    pub fn is_solvable(&self) -> bool {
        match self {
            Descriptor::Sh(sub) | Descriptor::Wsh(sub) => sub.is_solvable(),
            Descriptor::Tr { subs, .. } => subs.iter().all(Self::is_solvable),
            Descriptor::Addr { .. } | Descriptor::Raw { .. } => false,
            _ => true,
        }
    }
}

// ---- Expand (script generation) ----------------------------------

fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let t = crate::hash::sha256(tag.as_bytes());
    let mut data = Vec::with_capacity(64 + msg.len());
    data.extend_from_slice(&t);
    data.extend_from_slice(&t);
    data.extend_from_slice(msg);
    crate::hash::sha256(&data)
}

/// `DescriptorCache` — the `ExtKey` at a `Provider::Bip32`
/// derivation path is constant across range positions; memoizing it
/// turns each position's work into a single child derivation. The
/// cached node is the xprv when `signing` has it (hardened steps and
/// secrets need private material), otherwise the extpub.
pub type DeriveCache = HashMap<(Vec<u8>, Vec<u32>), ExtKey>;

fn bip32_base_key(
    extpub: &ExtKey,
    path: &[u32],
    signing: &FlatProvider,
    cache: &mut DeriveCache,
) -> Option<ExtKey> {
    let key = (extpub.key.to_vec(), path.to_vec());
    if let Some(node) = cache.get(&key) {
        return Some(node.clone());
    }
    let key_id = key_id_of(&extpub.key);
    let mut node = signing
        .xprvs
        .get(&key_id)
        .cloned()
        .unwrap_or_else(|| extpub.clone());
    for &step in path {
        node = node.derive(step)?;
    }
    cache.insert(key, node.clone());
    Some(node)
}

/// `GetPubKey` — the expanded pubkey plus its `KeyOriginInfo`
/// `(fingerprint, path)`: a const key reports its own
/// `hash160[..4]` with an empty path, a BIP32 key reports the root's
/// fingerprint with `path + [pos]` (`pos | 0x80000000` under a
/// hardened wildcard), and an origin wrapper overrides the
/// fingerprint and prepends its path — exactly Core's
/// `OriginPubkeyProvider` semantics.
fn provider_pubkey(
    provider: &Provider,
    pos: u32,
    signing: &FlatProvider,
    cache: &mut DeriveCache,
) -> Option<(Vec<u8>, KeyOrigin)> {
    match provider {
        Provider::Const { pubkey, .. } => {
            let mut fp = [0u8; 4];
            fp.copy_from_slice(&key_id_of(pubkey)[..4]);
            Some((pubkey.clone(), (fp, Vec::new())))
        }
        Provider::Origin {
            fingerprint,
            path,
            inner,
            ..
        } => {
            let (pubkey, (_, inner_path)) = provider_pubkey(inner, pos, signing, cache)?;
            let mut full = path.clone();
            full.extend_from_slice(&inner_path);
            Some((pubkey, (*fingerprint, full)))
        }
        Provider::Bip32 {
            extpub,
            path,
            derive,
            ..
        } => {
            // Hardened steps require the root secret — `bip32_base_key`
            // uses the xprv when present, and a hardened `derive` on
            // an extpub fails (Core's GetDerivedExtKey path).
            let base = bip32_base_key(extpub, path, signing, cache)?;
            let node = match derive {
                Derive::No => base,
                Derive::Unhardened => base.derive(pos)?,
                Derive::Hardened => base.derive(pos | HARDENED)?,
            };
            let mut fp = [0u8; 4];
            fp.copy_from_slice(&key_id_of(&extpub.key)[..4]);
            let mut full_path = path.clone();
            match derive {
                Derive::No => {}
                Derive::Unhardened => full_path.push(pos),
                Derive::Hardened => full_path.push(pos | HARDENED),
            }
            Some((node.public_key()?.serialize().to_vec(), (fp, full_path)))
        }
    }
}

/// `GetPrivKey` — the derived private key for `pos` when `signing`
/// holds the material: a const key reads it back from `signing.keys`
/// (WIF secrets land there at parse time), a BIP32 key derives
/// through `signing.xprvs` — needed for hardened steps anyway — and
/// an origin wrapper recurses into the inner provider.
fn provider_privkey(
    provider: &Provider,
    pos: u32,
    signing: &FlatProvider,
    cache: &mut DeriveCache,
) -> Option<secp256k1::SecretKey> {
    match provider {
        Provider::Const { pubkey, .. } => signing.keys.get(&key_id_of(pubkey)).copied(),
        Provider::Origin { inner, .. } => provider_privkey(inner, pos, signing, cache),
        Provider::Bip32 {
            extpub,
            path,
            derive,
            ..
        } => {
            let base = bip32_base_key(extpub, path, signing, cache)?;
            if !base.is_private() {
                return None;
            }
            let node = match derive {
                Derive::No => base,
                Derive::Unhardened => base.derive(pos)?,
                Derive::Hardened => base.derive(pos | HARDENED)?,
            };
            secp256k1::SecretKey::from_slice(&node.key[1..]).ok()
        }
    }
}

/// `ExpandHelper` — writes the descriptor's output scripts for
/// position `pos` into `out` and the signing data Core's
/// `MakeScripts`/`GetPubKey` record into `out_provider` (origins for
/// every key, pubkeys for hash-locked types, subscripts for the
/// wrappers, and taproot spend data for `tr`).
#[allow(clippy::too_many_arguments)]
fn expand_descriptor(
    desc: &Descriptor,
    pos: u32,
    signing: &FlatProvider,
    out: &mut Vec<Vec<u8>>,
    out_provider: &mut FlatProvider,
    expand_priv: bool,
    cache: &mut DeriveCache,
) -> Option<()> {
    let mut key = |p: &Provider, out_provider: &mut FlatProvider| {
        let (pubkey, info) = provider_pubkey(p, pos, signing, cache)?;
        out_provider
            .origins
            .insert(key_id_of(&pubkey), (pubkey.clone(), info));
        // `ExpandPrivate` — the derived secret lands in the output
        // provider keyed by the expanded pubkey's id.
        if expand_priv && let Some(secret) = provider_privkey(p, pos, signing, cache) {
            out_provider.keys.insert(key_id_of(&pubkey), secret);
        }
        Some(pubkey)
    };
    match desc {
        Descriptor::Pk { key: k, xonly } => {
            let pubkey = key(k, out_provider)?;
            let mut script = if *xonly {
                script::push_slice(&pubkey[1..])
            } else {
                script::push_slice(&pubkey)
            };
            script.push(script::OP_CHECKSIG);
            out.push(script);
        }
        Descriptor::Pkh { key: k } => {
            let pubkey = key(k, out_provider)?;
            let h = crate::hash::hash160(&pubkey);
            out_provider.pubkeys.insert(h, pubkey);
            out.push([&[0x76, 0xa9, 0x14], &h[..], &[0x88, 0xac]].concat());
        }
        Descriptor::Wpkh { key: k } => {
            let pubkey = key(k, out_provider)?;
            let h = crate::hash::hash160(&pubkey);
            out_provider.pubkeys.insert(h, pubkey);
            out.push([&[script::OP_0, 0x14], &h[..]].concat());
        }
        Descriptor::Combo { key: k } => {
            let pubkey = key(k, out_provider)?;
            let h = crate::hash::hash160(&pubkey);
            out_provider.pubkeys.insert(h, pubkey.clone());
            out.push([script::push_slice(&pubkey), vec![script::OP_CHECKSIG]].concat());
            out.push([&[0x76, 0xa9, 0x14], &h[..], &[0x88, 0xac]].concat());
            if pubkey.len() == 33 {
                let p2wpkh = [&[script::OP_0, 0x14], &h[..]].concat();
                out_provider
                    .scripts
                    .insert(crate::hash::hash160(&p2wpkh), p2wpkh.clone());
                let sh = crate::hash::hash160(&p2wpkh);
                out.push(p2wpkh);
                out.push([&[0xa9, 0x14], &sh[..], &[0x87]].concat());
            }
        }
        Descriptor::Multi {
            threshold,
            keys,
            sorted,
            checksig_add,
        } => {
            let mut pubkeys: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
            for k in keys {
                pubkeys.push(key(k, out_provider)?);
            }
            let mut script = Vec::new();
            if *checksig_add {
                // `multi_a`/`sortedmulti_a` are tapscript-only: Core's
                // `MultiADescriptor::MakeScripts` converts every key to
                // its `XOnlyPubKey` first and only then sorts (for
                // `sortedmulti_a`) — sorting the 33-byte compressed
                // keys and truncating afterward gives a different
                // order whenever a key's parity byte and its x-only
                // value disagree on ordering, which changes the
                // tapscript, leaf hash, and address.
                let mut xonly: Vec<Vec<u8>> =
                    pubkeys.iter().map(|k| k[k.len() - 32..].to_vec()).collect();
                if *sorted {
                    xonly.sort();
                }
                let first = &xonly[0];
                script.extend_from_slice(&script::push_slice(first));
                script.push(script::OP_CHECKSIG);
                for k in &xonly[1..] {
                    script.extend_from_slice(&script::push_slice(k));
                    script.push(0xba); // OP_CHECKSIGADD
                }
                push_script_num(&mut script, *threshold);
                script.push(0x9c); // OP_NUMEQUAL
            } else {
                if *sorted {
                    pubkeys.sort();
                }
                push_script_num(&mut script, *threshold);
                for k in &pubkeys {
                    script.extend_from_slice(&script::push_slice(k));
                }
                push_script_num(&mut script, pubkeys.len() as u32);
                script.push(script::OP_CHECKMULTISIG);
            }
            out.push(script);
        }
        Descriptor::Sh(sub) => {
            let mut inner = Vec::new();
            expand_descriptor(
                sub,
                pos,
                signing,
                &mut inner,
                out_provider,
                expand_priv,
                cache,
            )?;
            for s in inner {
                let h = crate::hash::hash160(&s);
                out_provider.scripts.insert(h, s);
                out.push([&[0xa9, 0x14], &h[..], &[0x87]].concat());
            }
        }
        Descriptor::Wsh(sub) => {
            let mut inner = Vec::new();
            expand_descriptor(
                sub,
                pos,
                signing,
                &mut inner,
                out_provider,
                expand_priv,
                cache,
            )?;
            for s in inner {
                let h = crate::hash::sha256(&s);
                out_provider.scripts.insert(crate::hash::hash160(&s), s);
                out.push([&[script::OP_0, 0x20], &h[..]].concat());
            }
        }
        Descriptor::Tr {
            internal,
            subs,
            depths,
        } => {
            let pubkey = key(internal, out_provider)?;
            let xonly: &[u8] = &pubkey[pubkey.len() - 32..];
            let mut internal_key = [0u8; 32];
            internal_key.copy_from_slice(xonly);
            let output = if subs.is_empty() {
                let out_key = taproot_output_key(xonly)?;
                out_provider.tr_trees.insert(
                    out_key,
                    TaprootSpendData {
                        merkle_root: None,
                        internal_key,
                        leaves: Vec::new(),
                    },
                );
                out_key
            } else {
                let mut scripts = Vec::with_capacity(subs.len());
                for sub in subs {
                    let mut s = Vec::new();
                    expand_descriptor(sub, pos, signing, &mut s, out_provider, expand_priv, cache)?;
                    if s.len() != 1 {
                        return None;
                    }
                    scripts.push(s.swap_remove(0));
                }
                let root = taproot_merkle_root(&scripts, depths)?;
                let mut msg = Vec::with_capacity(64);
                msg.extend_from_slice(xonly);
                msg.extend_from_slice(&root);
                let tweak_hash = tagged_hash("TapTweak", &msg);
                let internal = secp256k1::XOnlyPublicKey::from_slice(xonly).ok()?;
                let tweak = secp256k1::Scalar::from_be_bytes(tweak_hash).ok()?;
                let secp = secp256k1::Secp256k1::verification_only();
                let (output_key, parity) = internal.add_tweak(&secp, &tweak).ok()?;
                let output = output_key.serialize();
                let _ = parity;
                let leaves = depths
                    .iter()
                    .copied()
                    .zip(scripts.iter().cloned())
                    .map(|(d, s)| (d, s, TAPROOT_LEAF_TAPSCRIPT))
                    .collect();
                out_provider.tr_trees.insert(
                    output,
                    TaprootSpendData {
                        merkle_root: Some(root),
                        internal_key,
                        leaves,
                    },
                );
                output
            };
            out_provider.pubkeys.insert(key_id_of(&pubkey), pubkey);
            let mut script = vec![script::OP_1];
            script.extend_from_slice(&script::push_slice(&output));
            out.push(script);
        }
        Descriptor::RawTr { key: k } => {
            let pubkey = key(k, out_provider)?;
            let xonly = &pubkey[pubkey.len() - 32..];
            let mut script = vec![script::OP_1];
            script.extend_from_slice(&script::push_slice(xonly));
            out.push(script);
        }
        Descriptor::Addr { script, .. } => {
            out.push(script.as_bytes().to_vec());
        }
        Descriptor::Silent { .. } => {
            // No fixed script set — outputs derive per-tx.
        }
        Descriptor::Raw { script } => {
            out.push(script.clone());
        }
        Descriptor::Miniscript { keys, node } => {
            let mut pubkeys = Vec::with_capacity(keys.len());
            for k in keys {
                pubkeys.push(key(k, out_provider)?);
            }
            let maker = MiniscriptMaker {
                pubkeys: &pubkeys,
                tapscript: node.ms_context() == crate::miniscript::MsContext::Tapscript,
            };
            out.push(node.to_script(&maker));
        }
    }
    Some(())
}

/// CScript's `<< int64_t` — script-number encoding for small ints
/// (thresholds stay under `OP_16`; larger values use minimal-push
/// signed serialization).
fn push_script_num(script: &mut Vec<u8>, n: u32) {
    if n == 0 {
        script.push(script::OP_0);
    } else if n <= 16 {
        script.push(script::OP_1 + (n as u8) - 1);
    } else {
        let mut value = n;
        let mut bytes = Vec::new();
        while value != 0 {
            bytes.push((value & 0xff) as u8);
            value >>= 8;
        }
        if bytes.last().is_some_and(|b| b & 0x80 != 0) {
            bytes.push(0);
        }
        script.extend_from_slice(&script::push_slice(&bytes));
    }
}

/// `TaprootBuilder::GetRoot` — combine the leaf TapLeaf hashes by
/// depth into the single merkle root.
fn taproot_merkle_root(scripts: &[Vec<u8>], depths: &[usize]) -> Option<[u8; 32]> {
    let mut stack: Vec<(usize, [u8; 32])> = Vec::with_capacity(scripts.len());
    for (script, &depth) in scripts.iter().zip(depths) {
        let mut leaf = Vec::with_capacity(script.len() + 6);
        leaf.push(TAPROOT_LEAF_TAPSCRIPT);
        crate::encode::write_compact_size(&mut leaf, script.len() as u64);
        leaf.extend_from_slice(script);
        let mut node = (depth, tagged_hash("TapLeaf", &leaf));
        while let Some(&(_, other)) = stack.last().filter(|&&(d, _)| d == node.0) {
            stack.pop();
            let mut branch = Vec::with_capacity(64);
            let (a, b) = if other < node.1 {
                (other, node.1)
            } else {
                (node.1, other)
            };
            branch.extend_from_slice(&a);
            branch.extend_from_slice(&b);
            node = (node.0 - 1, tagged_hash("TapBranch", &branch));
        }
        stack.push(node);
    }
    (stack.len() == 1 && stack[0].0 == 0).then_some(stack[0].1)
}

/// `TRDescriptor`'s tree rendering — leaf expressions paired into
/// `{a,b}` braces by depth (`{` opens while descending below the
/// current path length, `}` closes completed pairs).
fn render_tr_tree(leaves: &[String], depths: &[usize]) -> String {
    let mut path: Vec<bool> = Vec::new();
    let mut tree = String::new();
    for (pos, (leaf, &depth)) in leaves.iter().zip(depths).enumerate() {
        if pos > 0 {
            tree.push(',');
        }
        while path.len() <= depth {
            if !path.is_empty() {
                tree.push('{');
            }
            path.push(false);
        }
        tree.push_str(leaf);
        while path.last() == Some(&true) {
            if path.len() > 1 {
                tree.push('}');
            }
            path.pop();
        }
        if let Some(last) = path.last_mut() {
            *last = true;
        }
    }
    tree
}

/// `FormatHDKeypath` with `apostrophe=false` — `/`-joined indices
/// with `h` for hardened steps.
fn format_keypath(path: &[u32]) -> String {
    let mut out = String::new();
    for &i in path {
        out.push('/');
        out.push_str(&(i & !0x8000_0000).to_string());
        if i & 0x8000_0000 != 0 {
            out.push('h');
        }
    }
    out
}

/// Wrap a rendered key expression in its `[fp/path]` origin prefix,
/// as `OriginPubkeyProvider::ToStringHelper` does.
fn with_origin(key_str: String, info: Option<&([u8; 4], Vec<u32>)>) -> String {
    match info {
        Some((fp, path)) => format!("[{}{}]{key_str}", hex::encode(fp), format_keypath(path)),
        None => key_str,
    }
}

/// `InferPubkey` — a `ConstPubkeyProvider` (wrapped in the stored
/// origin when the provider knows one) for a full-size script pubkey,
/// or `None` when the key can't appear in a descriptor.
fn infer_pubkey(pubkey: &[u8], ctx: Ctx, provider: &FlatProvider) -> Option<String> {
    // `IsValidNonHybrid`: 33-byte compressed or 65-byte uncompressed.
    let valid = (pubkey.len() == 33 && matches!(pubkey[0], 0x02 | 0x03))
        || (pubkey.len() == 65 && pubkey[0] == 0x04);
    if !valid || (ctx != Ctx::Top && ctx != Ctx::P2sh && pubkey.len() != 33) {
        return None;
    }
    let info = provider
        .origins
        .get(&key_id_of(pubkey))
        .map(|(_, info)| info);
    Some(with_origin(hex::encode(pubkey), info))
}

/// `InferXOnlyPubkey` — looks the key origin up under both parity
/// key IDs (`XOnlyPubKey::GetKeyIDs`) and renders the 32-byte form.
fn infer_xonly(xonly: &[u8; 32], provider: &FlatProvider) -> String {
    let info = [0x02u8, 0x03].iter().find_map(|prefix| {
        let mut full = Vec::with_capacity(33);
        full.push(*prefix);
        full.extend_from_slice(xonly);
        provider.origins.get(&key_id_of(&full)).map(|(_, i)| i)
    });
    with_origin(hex::encode(xonly), info)
}

/// `MatchMultiA` — `<32B> OP_CHECKSIG (<32B> OP_CHECKSIGADD)* OP_m
/// OP_NUMEQUAL`. Returns `(threshold, keys)` in script order.
fn match_multi_a(script: &[u8]) -> Option<(u32, Vec<[u8; 32]>)> {
    const MAX_PUBKEYS_PER_MULTI_A: usize = 999;
    if script.len() < 36 || script[0] != 32 || *script.last()? != 0x9c {
        return None;
    }
    let mut keys = Vec::new();
    let mut it = 0usize;
    while script.len() - it >= 34 {
        if script[it] != 32 {
            return None;
        }
        it += 1;
        let mut k = [0u8; 32];
        k.copy_from_slice(&script[it..it + 32]);
        keys.push(k);
        it += 32;
        if script[it]
            != if keys.len() == 1 {
                script::OP_CHECKSIG
            } else {
                0xba
            }
        {
            return None;
        }
        it += 1;
    }
    if keys.is_empty() || keys.len() > MAX_PUBKEYS_PER_MULTI_A {
        return None;
    }
    // `GetScriptNumber(opcode, data, 1, n)` — OP_1..OP_16 encode the
    // threshold directly (a push-encoded value is also legal in the
    // pattern but `push_script_num` only emits OP_n here).
    let (threshold, used) = read_script_num(script, it)?;
    it += used;
    if it >= script.len() || script[it] != 0x9c {
        return None;
    }
    it += 1;
    if it != script.len() || threshold < 1 || threshold > keys.len() as u32 {
        return None;
    }
    Some((threshold, keys))
}

/// Read a CScriptNum at `pos` — either a single `OP_n` opcode or a
/// minimal push of up to 4 bytes. Returns `(value, bytes_consumed)`.
fn read_script_num(script: &[u8], pos: usize) -> Option<(u32, usize)> {
    let op = *script.get(pos)?;
    if op == 0 {
        return Some((0, 1));
    }
    if (0x51..=0x60).contains(&op) {
        return Some(((op - 0x50) as u32, 1));
    }
    if (1..=4).contains(&op) {
        let end = pos + 1 + op as usize;
        let data = script.get(pos + 1..end)?;
        // CScriptNum deserialization (minimal form already guaranteed
        // for our own emissions; arbitrary inputs still decode).
        let mut v: i64 = 0;
        for (i, &b) in data.iter().enumerate() {
            v |= (b as i64) << (8 * i);
        }
        if let Some(&last) = data.last()
            && last & 0x80 != 0
        {
            v &= !(0x80i64 << (8 * (data.len() - 1)));
            v = -v;
        }
        return u32::try_from(v).ok().map(|v| (v, 1 + op as usize));
    }
    None
}

/// `InferScript` — the best descriptor expression for `script` in
/// context `ctx`, using `provider` for pubkey/origin/subscript/
/// taproot lookups. Returns the descriptor *body* (no checksum).
fn infer_script(
    script: &[u8],
    ctx: Ctx,
    provider: &FlatProvider,
    params: &Params,
) -> Option<String> {
    // Tapscript leaves: `pk()` for a lone x-only key, else multi_a.
    if ctx == Ctx::P2tr
        && script.len() == 34
        && script[0] == 32
        && script[33] == script::OP_CHECKSIG
    {
        let mut k = [0u8; 32];
        k.copy_from_slice(&script[1..33]);
        return Some(format!("pk({})", infer_xonly(&k, provider)));
    }
    if ctx == Ctx::P2tr
        && let Some((threshold, keys)) = match_multi_a(script)
    {
        let key_strs: Vec<String> = keys.iter().map(|k| infer_xonly(k, provider)).collect();
        return Some(format!("multi_a({threshold},{})", key_strs.join(",")));
    }

    let script_obj = Script::new(script.to_vec());
    let specialized = match script_obj.classify() {
        crate::script::ScriptType::PubKey(pk)
            if matches!(ctx, Ctx::Top | Ctx::P2sh | Ctx::P2wsh) =>
        {
            infer_pubkey(&pk, ctx, provider).map(|k| format!("pk({k})"))
        }
        crate::script::ScriptType::PubKeyHash(hash)
            if matches!(ctx, Ctx::Top | Ctx::P2sh | Ctx::P2wsh) =>
        {
            provider
                .pubkeys
                .get(&hash)
                .and_then(|pk| infer_pubkey(pk, ctx, provider))
                .map(|k| format!("pkh({k})"))
        }
        crate::script::ScriptType::Witness {
            version: 0,
            program,
        } if program.len() == 20 && matches!(ctx, Ctx::Top | Ctx::P2sh) => {
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&program);
            provider
                .pubkeys
                .get(&hash)
                .and_then(|pk| infer_pubkey(pk, Ctx::P2wpkh, provider))
                .map(|k| format!("wpkh({k})"))
        }
        crate::script::ScriptType::Multisig { required, keys }
            if matches!(ctx, Ctx::Top | Ctx::P2sh | Ctx::P2wsh) =>
        {
            let key_strs: Option<Vec<String>> = keys
                .iter()
                .map(|k| infer_pubkey(k, ctx, provider))
                .collect();
            key_strs.map(|ks| format!("multi({},{})", required, ks.join(",")))
        }
        crate::script::ScriptType::ScriptHash(hash) if ctx == Ctx::Top => provider
            .scripts
            .get(&hash)
            .and_then(|sub| infer_script(sub, Ctx::P2sh, provider, params))
            .map(|d| format!("sh({d})")),
        crate::script::ScriptType::Witness {
            version: 0,
            program,
        } if program.len() == 32 && matches!(ctx, Ctx::Top | Ctx::P2sh) => {
            // `CScriptID{RIPEMD160(program)}` — the stored key is
            // hash160 of the witness script, which equals ripemd160
            // of this sha256'd program.
            let scriptid = crate::hash::ripemd160(&program);
            provider
                .scripts
                .get(&scriptid)
                .and_then(|sub| infer_script(sub, Ctx::P2wsh, provider, params))
                .map(|d| format!("wsh({d})"))
        }
        crate::script::ScriptType::Witness {
            version: 1,
            program,
        } if program.len() == 32 && ctx == Ctx::Top => {
            let mut output = [0u8; 32];
            output.copy_from_slice(&program);
            if let Some(tap) = provider.tr_trees.get(&output) {
                // `InferTaprootTree`: verify the tweak reconstructs
                // the output key, then infer each leaf.
                let tweaked = match tap.merkle_root {
                    Some(root) => {
                        let mut msg = Vec::with_capacity(64);
                        msg.extend_from_slice(&tap.internal_key);
                        msg.extend_from_slice(&root);
                        let tweak_hash = tagged_hash("TapTweak", &msg);
                        let internal =
                            secp256k1::XOnlyPublicKey::from_slice(&tap.internal_key).ok();
                        let tweak = secp256k1::Scalar::from_be_bytes(tweak_hash).ok();
                        match (internal, tweak) {
                            (Some(i), Some(t)) => {
                                let secp = secp256k1::Secp256k1::verification_only();
                                i.add_tweak(&secp, &t).ok().map(|(k, _)| k.serialize())
                            }
                            _ => None,
                        }
                    }
                    None => taproot_output_key(&tap.internal_key),
                };
                if tweaked.as_ref() == Some(&output) {
                    let mut parts: Option<Vec<String>> = Some(Vec::new());
                    for &(_, ref leaf_script, leaf_ver) in &tap.leaves {
                        if leaf_ver != TAPROOT_LEAF_TAPSCRIPT {
                            parts = None;
                            break;
                        }
                        match infer_script(leaf_script, Ctx::P2tr, provider, params) {
                            Some(d) => {
                                if let Some(p) = parts.as_mut() {
                                    p.push(d);
                                }
                            }
                            None => {
                                parts = None;
                                break;
                            }
                        }
                    }
                    if let Some(leaf_strs) = parts {
                        let key = infer_xonly(&tap.internal_key, provider);
                        if leaf_strs.is_empty() {
                            return Some(format!("tr({key})"));
                        }
                        let depths: Vec<usize> = tap.leaves.iter().map(|(d, _, _)| *d).collect();
                        let tree = render_tr_tree(&leaf_strs, &depths);
                        return Some(format!("tr({key},{tree})"));
                    }
                }
            }
            if secp256k1::XOnlyPublicKey::from_slice(&output).is_ok() {
                let key = infer_xonly(&output, provider);
                return Some(format!("rawtr({key})"));
            }
            None
        }
        _ => None,
    };
    if specialized.is_some() {
        return specialized;
    }
    // Miniscript inside wsh/tr isn't inferable (not parsed). The
    // remaining descriptors are top-level only.
    if ctx != Ctx::Top {
        return None;
    }
    match script_address(&script_obj, params) {
        Some(addr) => Some(format!("addr({addr})")),
        None => Some(format!("raw({})", hex::encode(script))),
    }
}

/// `InferDescriptor` — Core's inferred `desc` field for
/// `scantxoutset`: the canonical descriptor (with checksum) for
/// `script` under the provider accumulated during scan expansion.
#[must_use]
pub fn infer_descriptor(script: &[u8], provider: &FlatProvider, params: &Params) -> String {
    let body = infer_script(script, Ctx::Top, provider, params)
        .unwrap_or_else(|| format!("raw({})", hex::encode(script)));
    format!("{body}#{}", descriptor_checksum(&body))
}

impl Descriptor {
    /// `Expand` — the output scripts this descriptor produces for
    /// derivation position `pos`. Fails when hardened derivation needs
    /// private material that wasn't in the descriptor.
    #[must_use]
    pub fn expand(&self, pos: u32, signing: &FlatProvider) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut provider = FlatProvider::default();
        let mut cache = DeriveCache::new();
        expand_descriptor(
            self,
            pos,
            signing,
            &mut out,
            &mut provider,
            false,
            &mut cache,
        )?;
        Some(out)
    }

    /// `Expand` with Core's `out` provider — returns the scripts plus
    /// the accumulated pubkeys/origins/subscripts/spend data that
    /// `scantxoutset` needs for `InferDescriptor`. `expand_priv`
    /// additionally records derived secrets (`ExpandPrivate`).
    /// `cache` is Core's `DescriptorCache`: the per-provider base key
    /// is memoized across range positions.
    pub fn expand_into(
        &self,
        pos: u32,
        signing: &FlatProvider,
        out_provider: &mut FlatProvider,
        expand_priv: bool,
        cache: &mut DeriveCache,
    ) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        expand_descriptor(
            self,
            pos,
            signing,
            &mut out,
            out_provider,
            expand_priv,
            cache,
        )?;
        Some(out)
    }
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

    // ---- parser tests: all vectors read back from Core 29.4's
    // getdescriptorinfo/deriveaddresses on regtest ----

    const K: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const TPUB: &str = "tpubDC7jtehYfSDGXbAgBuLKNyJBdHbyQoMX9V8oUMgfzgiL5pGrFCnv6cyoRt2dovvP3nMEaeFc2jW1aChYQpUZFdnbsaXVcc7t2WMA27AvJ4W";

    fn regtest() -> Params {
        Network::Regtest.params()
    }

    fn info(text: &str) -> Result<(String, bool, bool, bool), String> {
        let (descs, provider, _) = parse_descriptors(text, &regtest(), false)?;
        Ok((
            descs[0].to_descriptor_string(),
            descs[0].is_range(),
            descs[0].is_solvable(),
            !provider.keys.is_empty(),
        ))
    }

    #[test]
    fn canonical_forms_match_core() {
        let cases: &[(&str, &str, bool, bool, bool)] = &[
            // (input, canonical with checksum, isrange, issolvable, hasprivatekeys)
            (
                &format!("pkh({K})"),
                &format!("pkh({K})#8fhd9pwu"),
                false,
                true,
                false,
            ),
            (
                &format!("pk({K})"),
                &format!("pk({K})#3dt5nkzl"),
                false,
                true,
                false,
            ),
            (
                &format!("combo({K})"),
                &format!("combo({K})#x7yr7hv3"),
                false,
                true,
                false,
            ),
            (
                &format!("sh(wpkh({K}))"),
                &format!("sh(wpkh({K}))#la26f59y"),
                false,
                true,
                false,
            ),
            (
                "raw(deadbeef)",
                "raw(deadbeef)#89f8spxm",
                false,
                false,
                false,
            ),
            // Full 33-byte keys inside tr() keep their prefix byte;
            // only the 32-byte form serializes x-only.
            (
                &format!("tr({K})"),
                &format!("tr({K})#g74uw3rl"),
                false,
                true,
                false,
            ),
            (
                &format!("tr({K},pk({K}))"),
                &format!("tr({K},pk({K}))#ffcw0aup"),
                false,
                true,
                false,
            ),
            (
                &format!("tr({K},{{pk({K}),pk({K})}})"),
                &format!("tr({K},{{pk({K}),pk({K})}})#sm9gmmh5"),
                false,
                true,
                false,
            ),
            (
                &format!("sh(sortedmulti(1,{K},{K}))"),
                &format!("sh(sortedmulti(1,{K},{K}))#75htpr3z"),
                false,
                true,
                false,
            ),
            (
                &format!("wsh(multi(1,{K},{K}))"),
                &format!("wsh(multi(1,{K},{K}))#nmg09aec"),
                false,
                true,
                false,
            ),
            (
                &format!("wpkh({TPUB}/0/*)"),
                &format!("wpkh({TPUB}/0/*)#f2s4pvjw"),
                true,
                true,
                false,
            ),
            (
                &format!("wpkh({TPUB}/0/*')"),
                &format!("wpkh({TPUB}/0/*')#a4s4xzeg"),
                true,
                true,
                false,
            ),
        ];
        for (input, canonical, isrange, solvable, haspriv) in cases {
            let (desc, r, s, h) = info(input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(
                (desc.as_str(), r, s, h),
                (*canonical, *isrange, *solvable, *haspriv),
                "{input}"
            );
        }
    }

    #[test]
    fn parse_errors_match_core() {
        let cases: &[(&str, &str)] = &[
            (
                &format!("pkh({K})#xxxxxxxx"),
                "Provided checksum 'xxxxxxxx' does not match computed checksum '8fhd9pwu'",
            ),
            (
                &format!("wpkh({K})#"),
                "Expected 8 character checksum, not 0 characters",
            ),
            (
                &format!("bogus({K})"),
                "'bogus(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)' is not a valid descriptor function",
            ),
            (
                &format!("pkh({K})extra"),
                "'pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)extra' is not a valid descriptor function",
            ),
            (
                "addr(bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)",
                "Address is not valid",
            ),
            ("raw()", "Raw script is not hex"),
            (
                &format!("wpkh({})", &K[2..]),
                "wpkh(): Pubkey 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5' is invalid",
            ),
        ];
        for (input, expected) in cases {
            let err = parse_descriptors(input, &regtest(), false).unwrap_err();
            assert_eq!(err, *expected, "{input}");
        }
    }

    #[test]
    fn multipath_expands() {
        let (descs, provider, checksum) =
            parse_descriptors(&format!("wpkh({TPUB}/<0;1>/*)"), &regtest(), false).unwrap();
        assert_eq!(descs.len(), 2);
        assert_eq!(
            descs[0].to_descriptor_string(),
            format!("wpkh({TPUB}/0/*)#f2s4pvjw")
        );
        assert_eq!(
            descs[1].to_descriptor_string(),
            format!("wpkh({TPUB}/1/*)#c745uezk")
        );
        // The reported checksum covers the original multipath body.
        assert_eq!(checksum, "07eddr8t");
        assert!(provider.keys.is_empty());
    }

    #[test]
    fn expand_derives_core_addresses() {
        // `deriveaddresses` equivalents — script → regtest address.
        let to_addrs = |text: &str, lo: u32, hi: u32| -> Vec<String> {
            let (descs, provider, _) = parse_descriptors(text, &regtest(), true).unwrap();
            let mut out = Vec::new();
            for i in lo..=hi {
                for s in descs[0].expand(i, &provider).unwrap() {
                    if let Some(a) = script_address(&Script::new(s), &regtest()) {
                        out.push(a);
                    }
                }
            }
            out
        };
        assert_eq!(
            to_addrs(&format!("wpkh({TPUB}/0/*)#f2s4pvjw"), 0, 1),
            [
                "bcrt1qk5zs82xrm4jn7dqljm00ch559h3j78l3zszwmz".to_string(),
                "bcrt1qs3g67p7xmwv4ne28gwa35v96qq2qk487vw8y43".to_string(),
            ]
        );
        assert_eq!(
            to_addrs(&format!("tr({K})#g74uw3rl"), 0, 0),
            ["bcrt1pet7ep3czdu9k4wvdlz2fp5p8x2yp7t6ttyqg2c6cmh0lgeuu9laspse7la".to_string()]
        );
        assert_eq!(
            to_addrs(
                &format!("tr({K},{{pk({K}),pk({})}})#tvkrlmva", &K[2..]),
                0,
                0
            ),
            ["bcrt1p9545a3sudgn65tgsjd5u2qpyfl8mxvmf3lu9s47gq49s077c7rcqwenme3".to_string()]
        );
        assert_eq!(
            to_addrs(&format!("combo({K})#x7yr7hv3"), 0, 0),
            [
                "mg8Jz5776UdyiYcBb9Z873NTozEiADRW5H".to_string(),
                "bcrt1qq6hag67dl53wl99vzg42z8eyzfz2xlkvwk6f7m".to_string(),
                "2N74VLxyT79VGHiBK2zEg3a9HJG7rEc5F3o".to_string(),
            ]
        );
        assert_eq!(
            to_addrs(&format!("wsh(sortedmulti(1,{K},{K}))#6q3gsfav"), 0, 0),
            ["bcrt1qhks8dknwck5c2jwme24akwysfw0z5c902wyzdqa53750aargwcds784rlk".to_string()]
        );
    }

    /// Core's `MultiADescriptor::MakeScripts` converts every key to its
    /// `XOnlyPubKey` before sorting for `sortedmulti_a` — sorting the
    /// 33-byte compressed keys and truncating afterward gives a
    /// different order whenever a key's parity byte and its x-only
    /// value disagree, changing the tapscript, leaf hash, and address.
    ///
    /// SORT_A has odd parity (0x03) and the *smaller* x; SORT_B has
    /// even parity (0x02) and the *larger* x. Comparing full keys is
    /// decided entirely by the parity byte (0x02 < 0x03 regardless of
    /// x), so it always ranks SORT_B first — the opposite of the
    /// x-only order. `multi_a` given the keys already in x-order is
    /// the ground truth `sortedmulti_a` must reproduce however its
    /// arguments are ordered.
    #[test]
    fn sortedmulti_a_sorts_xonly_keys_not_full_keys() {
        const SORT_A: &str = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        const SORT_B: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
        let expand_addr = |text: &str| -> String {
            let (descs, provider, _) = parse_descriptors(text, &regtest(), false).unwrap();
            let scripts = descs[0].expand(0, &provider).unwrap();
            script_address(&Script::new(scripts[0].clone()), &regtest()).unwrap()
        };
        let ground_truth = expand_addr(&format!("tr({K},multi_a(2,{SORT_A},{SORT_B}))"));
        assert_eq!(
            expand_addr(&format!("tr({K},sortedmulti_a(2,{SORT_B},{SORT_A}))")),
            ground_truth
        );
        assert_eq!(
            expand_addr(&format!("tr({K},sortedmulti_a(2,{SORT_A},{SORT_B}))")),
            ground_truth
        );
    }

    #[test]
    fn hardened_xpub_expand_needs_private_key() {
        let (descs, provider, _) =
            parse_descriptors(&format!("wpkh({TPUB}/0h/0/*)"), &regtest(), false).unwrap();
        // `0h` in the path — public derivation alone can't do it.
        assert!(descs[0].expand(0, &provider).is_none());
    }

    // ---- miniscript: every vector from Core 29.4
    // getdescriptorinfo + deriveaddresses on regtest ----

    const K2: &str = "03f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    #[test]
    fn miniscript_descriptors_match_core() {
        let cases: &[(&str, &str, &str)] = &[
            (
                &format!("wsh(and_v(v:pk({K}),pk({K2})))"),
                "8k93svk3",
                "00201263632cf57ae013ca310fcb1c65799285c4fc59f839876e316d0167e34966d2",
            ),
            (
                &format!("wsh(or_b(pk({K}),s:pk({K2})))"),
                "h2zc4538",
                "00201768089be55aa6d2b0012d3da81dfc28374ba9a7ebe1df1339203b1011eff82e",
            ),
            (
                &format!("wsh(or_d(pk({K}),pk({K2})))"),
                "0xzszd0x",
                "0020c980c464541f75b2c63bc78c3d387de3fa18cbfcf78b125e092e09f088895ed5",
            ),
            (
                &format!("wsh(or_i(pk({K}),pk({K2})))"),
                "jqyfklyu",
                "0020ee9387b575dd8c325370860dbbe055df366c57ecfe3fc8f1dcaf54f86db30c1b",
            ),
            (
                &format!("wsh(andor(pk({K}),older(100),pk({K2})))"),
                "ttypvqxu",
                "002046c85a575dbdc41549ca2e043e14710623c64fb8d3308df95be4d9bea95f7178",
            ),
            (
                &format!("wsh(and_n(pk({K}),pk({K2})))"),
                "5j30f325",
                "002044c9cd1ae717f79c86566c79e7f5ee6d7c3a18a14542b9ac2c7d00e893796c57",
            ),
            (
                &format!("wsh(thresh(2,pk({K}),s:pk({K2}),snl:older(100)))"),
                "uv2h93hg",
                "0020cfbe03b4d3d7c61849e37b102715f153c88a6aeadf92afeb18149abc45491c27",
            ),
            (
                &format!("wsh(and_v(v:pk({K}),after(500000)))"),
                "gyelkc26",
                "0020e6ce11e5016d5b520a34a92bea84cabbe730642bf538f3398b7965e078497884",
            ),
            (
                &format!("wsh(and_v(v:pk({K}),older(4194304)))"),
                "2j6ngcd6",
                "0020597f2bbb2dbd5a151906e07791db0e9767fa57bc0c9934050930d256df2df03e",
            ),
            (
                &format!(
                    "wsh(and_v(v:pk({K}),sha256(6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d)))"
                ),
                "hetamraq",
                "00201fc8563b2de7b862ac0958e8a900bc78b5efb60903fcdff645a0d6dfac6ba5a2",
            ),
            (
                &format!("wsh(j:pk({K}))"),
                "tv22an3m",
                "0020ae8f3831dcacf5fa119bd378152da16b0f42797a6b5bf66e9fdb833e7dbefdb0",
            ),
            (
                &format!("wsh(n:pk({K}))"),
                "4065xu6n",
                "0020ef6bdc20e4aa93d2ae8f1ce6462be90c4cdfd30a4c4a3c35edf05af27f0f6b60",
            ),
            (
                &format!("wsh(u:pk({K}))"),
                "nhhjplsp",
                "00208f1066b2e9f75f63f6902c249999d5ea08221c7fcdd4a4ed9174f50a0a180af8",
            ),
            (
                &format!("wsh(l:pk({K}))"),
                "yez9yqql",
                "0020153bc4ef361c7e84f5ddba6e62c5bb745b7fe0b3f3d7218d7b361f24702cff56",
            ),
            (
                &format!("tr({K},{{pk({K2}),pk({K})}})"),
                "qle2cdjk",
                "5120c1efad64a7a00683536516e655b632037d74ab1f108ffd2a62255bccdd48ba8a",
            ),
            (
                &format!("tr({K},multi_a(1,{K2}))"),
                "36yqnf3n",
                "51206eaa55fcd7cc75d93115d37f05ec37cf096bb3bb12dcfe7d89546c60ed72fa79",
            ),
            (
                &format!("tr({K},thresh(1,pk({K2}),a:pk({K})))"),
                "8s5nj9rn",
                "5120960e35877d42a52ac3932628866972064766f9937ff6c89638e539e664443325",
            ),
            (
                &format!("tr({K},and_v(v:pk({K2}),pk({K})))"),
                "8zavf7p2",
                "5120b34bb7b5cc15a7e2151741efc949b1443f605c6c1dd248097ad0a49a32c92a2f",
            ),
            (
                &format!("sh(wsh(or_d(pk({K}),pk({K2}))))"),
                "3huah7u0",
                "a9146edfb8af2b8d009326bdd7d02663d2a5d4cf30f687",
            ),
        ];
        for (input, checksum, spk) in cases {
            let (descs, provider, _) = parse_descriptors(input, &regtest(), false)
                .unwrap_or_else(|e| panic!("{input}: {e}"));
            let canon = descs[0].to_descriptor_string();
            assert!(canon.ends_with(&format!("#{checksum}")), "{input}: {canon}");
            let scripts = descs[0].expand(0, &provider).unwrap();
            assert_eq!(hex::encode(&scripts[0]), *spk, "{input}");
        }
    }

    #[test]
    fn miniscript_sanity_errors_match_core() {
        let cases: &[(&str, &str)] = &[
            (
                "wsh(after(500000))",
                "after(500000) is not sane: witnesses without signature exist",
            ),
            (
                "wsh(older(4194304))",
                "older(4194304) is not sane: witnesses without signature exist",
            ),
            (
                "wsh(sha256(6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d))",
                "sha256(6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d) \
                 is not sane: witnesses without signature exist",
            ),
            (
                &format!("wsh(v:pk({K}))"),
                &format!("v:pk({K}) is not sane"),
            ),
            (&format!("wsh(d:pk({K}))"), &format!("d:pk({K}) is invalid")),
            (&format!("wsh(t:pk({K}))"), &format!("t:pk({K}) is invalid")),
            (
                &format!("wsh(multi_a(1,{K2}))"),
                "Can only have multi_a/sortedmulti_a inside tr()",
            ),
            (
                &format!("tr({K},multi(1,{K2}))"),
                "Can only have multi/sortedmulti at top level, in sh(), or in wsh()",
            ),
            (
                &format!("pk(and_v(v:pk({K}),pk({K2})))"),
                &format!("pk(): key 'and_v(v:pk({K}),pk({K2}))' is not valid"),
            ),
            (
                &format!("wsh(and_v(v:pk({K}),pk({K})))"),
                &format!("and_v(v:pk({K}),pk({K})) is not sane: contains duplicate public keys"),
            ),
            (
                // Mixed height-based and time-based locks — the
                // inner or_b is the invalid subexpression.
                &format!("wsh(and_v(v:pk({K}),or_b(after(500000),after(500000001))))"),
                "or_b(after(500000),after(500000001)) is invalid",
            ),
            (
                // and_v's left argument must be V-type.
                &format!("wsh(and_v(pk({K}),pk({K2})))"),
                &format!("and_v(pk({K}),pk({K2})) is invalid"),
            ),
            (
                // a: wraps to W-type — not a valid top-level B.
                &format!("wsh(a:pk({K}))"),
                &format!("a:pk({K}) is not sane"),
            ),
        ];
        for (input, expected) in cases {
            let err = match parse_descriptors(input, &regtest(), false) {
                Err(e) => e,
                Ok(v) => panic!("{input} should fail: {} descs", v.0.len()),
            };
            assert_eq!(&err, expected, "{input}");
        }
    }

    #[test]
    fn miniscript_canonical_sugar() {
        // Wrapper sugar canonicalizes: c:pk_k → pk, t: → and_v(..,1), etc.
        let cases: &[(&str, &str)] = &[
            (&format!("wsh(c:pk_k({K}))"), &format!("wsh(pk({K}))")),
            (
                // t: sugar unfolds to and_v(x,1) then re-folds.
                &format!("wsh(and_v(v:pk({K}),thresh(1,pk({K2}))))"),
                &format!("wsh(and_v(v:pk({K}),thresh(1,pk({K2}))))"),
            ),
        ];
        for (input, body) in cases {
            let (descs, _, _) = parse_descriptors(input, &regtest(), false)
                .unwrap_or_else(|e| panic!("{input}: {e}"));
            let canon = descs[0].to_descriptor_string();
            let checksum = descriptor_checksum(body);
            assert_eq!(canon, format!("{body}#{checksum}"), "{input}");
        }
    }
}

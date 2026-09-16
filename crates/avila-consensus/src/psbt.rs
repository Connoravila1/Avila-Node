//! BIP174 partially-signed bitcoin transactions.
//!
//! A PSBT is a magic-prefixed sequence of key-value maps: one global
//! map (carrying the unsigned transaction), one per input, and one
//! per output. Each map is ordered key→value pairs terminated by a
//! `0x00` separator; a key is `<u8 type><keydata>` so unknown and
//! proprietary entries survive a decode→encode roundtrip untouched.
//!
//! Decode errors carry Bitcoin Core's exact `DecodePSBT` message
//! text via [`PsbtError::core_message`] — the RPC layer wraps it as
//! `TX decode failed {msg}`.

use crate::encode::{self, DecodeError, Decoder};
use crate::hash::Txid;
use crate::transaction::{OutPoint, Transaction, TxOut};

/// The `psbt\xff` serialization magic.
pub const PSBT_MAGIC: &[u8] = b"psbt\xff";

/// PSBT-level structural failures. `Display`/`core_message` produce
/// the strings Core's deserializer throws (`std::ios_base::failure`
/// payloads) — RPC callers append `": iostream error"` where marked.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PsbtError {
    /// A scalar or length-prefixed read ran out of stream.
    #[error("DataStream::read(): end of data")]
    UnexpectedEnd,
    /// A CompactSize declared more than the maximum.
    #[error("ReadCompactSize(): size too large")]
    CompactSizeTooLarge,
    /// The five leading bytes weren't `psbt\xff`.
    #[error("Invalid PSBT magic bytes")]
    BadMagic,
    /// The global map hit end-of-stream before its `0x00` separator.
    #[error("Separator is missing at the end of the global map")]
    GlobalMapUnterminated,
    /// Fewer input maps than the unsigned tx has inputs.
    #[error("Inputs provided does not match the number of inputs in transaction.")]
    InputCountMismatch,
    /// Fewer output maps than the unsigned tx has outputs.
    #[error("Outputs provided does not match the number of outputs in transaction.")]
    OutputCountMismatch,
    /// The global map terminated without an unsigned-tx pair.
    #[error("No unsigned transaction was provided")]
    MissingUnsignedTx,
    /// The unsigned tx carried non-empty scriptSigs or witnesses.
    #[error("Unsigned tx does not have empty scriptSigs and scriptWitnesses.")]
    NonEmptyScriptSig,
    /// `PSBT_GLOBAL_VERSION` above `PSBT_HIGHEST_VERSION` (0 — v2
    /// PSBTs are rejected outright).
    #[error("Unsupported version number")]
    UnsupportedVersion,
    /// A Core `std::ios_base::failure` message carried verbatim —
    /// the per-type key-shape, duplicate, and value checks each
    /// carry their own string.
    #[error("{0}")]
    Core(&'static str),
    /// Bytes remained after the last map.
    #[error("extra data after PSBT")]
    TrailingBytes,
    /// A map value didn't hold what its type requires (embedded tx,
    /// TxOut, u32, …) — surfaced as the nested decode error text.
    #[error("{0}")]
    Value(String),
}

impl PsbtError {
    /// Core's full throw text — the `": iostream error"` suffix
    /// applies to every failure thrown through `std::ios_base::failure`
    /// during stream reads, which is all of them except the
    /// post-decode checks (`TrailingBytes`, count mismatches are
    /// thrown the same way — every variant gets the suffix).
    pub fn core_message(&self) -> String {
        match self {
            Self::TrailingBytes => self.to_string(),
            _ => format!("{self}: iostream error"),
        }
    }
}

/// The map a key belongs to — selects Core's per-case check tables.
#[derive(Clone, Copy)]
enum Scope {
    Global,
    Input,
    Output,
}

/// A proprietary key's keydata is `<compactsize id-len><id><compactsize
/// subtype><rest>` — Core parses `identifier` then `subtype` off the
/// key stream, so malformed keydata fails as a stream read.
fn proprietary_keydata_ok(keydata: &[u8]) -> bool {
    let mut dec = Decoder::new(keydata);
    let Ok(id_len) = dec.read_compact_size() else {
        return false;
    };
    if dec.read_bytes(id_len as usize).is_err() {
        return false;
    }
    dec.read_compact_size().is_ok()
}

/// Core's per-case key checks (`psbt.h` `Unserialize` switches): the
/// type byte selects a keydata shape and each failure carries that
/// case's exact `std::ios_base::failure` text.
fn check_key(scope: Scope, key: &[u8]) -> Result<(), PsbtError> {
    let key_type = key[0];
    let kd = &key[1..];
    match (scope, key_type) {
        (Scope::Global, Psbt::GLOBAL_TX) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Global unsigned tx key is more than one byte type",
                ));
            }
        }
        (Scope::Global, Psbt::GLOBAL_XPUB) => {
            if kd.len() != 78 {
                return Err(PsbtError::Core(
                    "Size of key was not the expected size for the type global xpub",
                ));
            }
            // `CExtPubKey::DecodeWithVersion` + `pubkey.IsFullyValid` —
            // the trailing 33 bytes are the compressed pubkey.
            if !crate::descriptor::pubkey_is_valid(&kd[45..]) {
                return Err(PsbtError::Core("Invalid pubkey"));
            }
        }
        (Scope::Global, Psbt::GLOBAL_VERSION) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Global version key is more than one byte type",
                ));
            }
        }
        (Scope::Input, Psbt::IN_NON_WITNESS_UTXO) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Non-witness utxo key is more than one byte type",
                ));
            }
        }
        (Scope::Input, Psbt::IN_WITNESS_UTXO) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Witness utxo key is more than one byte type",
                ));
            }
        }
        (Scope::Input, Psbt::IN_PARTIAL_SIG) => {
            if kd.len() != 33 && kd.len() != 65 {
                return Err(PsbtError::Core(
                    "Size of key was not the expected size for the type partial signature pubkey",
                ));
            }
            if !crate::descriptor::pubkey_is_valid(kd) {
                return Err(PsbtError::Core("Invalid pubkey"));
            }
        }
        (Scope::Input, Psbt::IN_SIGHASH_TYPE) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Sighash type key is more than one byte type",
                ));
            }
        }
        (Scope::Input, Psbt::IN_REDEEM_SCRIPT) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Input redeemScript key is more than one byte type",
                ));
            }
        }
        (Scope::Input, Psbt::IN_WITNESS_SCRIPT) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Input witnessScript key is more than one byte type",
                ));
            }
        }
        (Scope::Input, Psbt::IN_BIP32_DERIVATION) | (Scope::Output, Psbt::OUT_BIP32_DERIVATION) => {
            if kd.len() != 33 && kd.len() != 65 {
                return Err(PsbtError::Core(
                    "Size of key was not the expected size for the type BIP32 keypath",
                ));
            }
            if !crate::descriptor::pubkey_is_valid(kd) {
                return Err(PsbtError::Core("Invalid pubkey"));
            }
        }
        (Scope::Input, Psbt::IN_FINAL_SCRIPTSIG) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Final scriptSig key is more than one byte type",
                ));
            }
        }
        (Scope::Input, Psbt::IN_FINAL_SCRIPTWITNESS) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Final scriptWitness key is more than one byte type",
                ));
            }
        }
        (Scope::Input, Psbt::IN_RIPEMD160) => {
            if kd.len() != 20 {
                return Err(PsbtError::Core(
                    "Size of key was not the expected size for the type ripemd160 preimage",
                ));
            }
        }
        (Scope::Input, Psbt::IN_SHA256) => {
            if kd.len() != 32 {
                return Err(PsbtError::Core(
                    "Size of key was not the expected size for the type sha256 preimage",
                ));
            }
        }
        (Scope::Input, Psbt::IN_HASH160) => {
            if kd.len() != 20 {
                return Err(PsbtError::Core(
                    "Size of key was not the expected size for the type hash160 preimage",
                ));
            }
        }
        (Scope::Input, Psbt::IN_HASH256) => {
            if kd.len() != 32 {
                return Err(PsbtError::Core(
                    "Size of key was not the expected size for the type hash256 preimage",
                ));
            }
        }
        (Scope::Input, Psbt::IN_TAP_KEY_SIG) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Input Taproot key signature key is more than one byte type",
                ));
            }
        }
        (Scope::Input, Psbt::IN_TAP_SCRIPT_SIG) => {
            if kd.len() != 64 {
                return Err(PsbtError::Core(
                    "Input Taproot script signature key is not 65 bytes",
                ));
            }
        }
        (Scope::Input, Psbt::IN_TAP_LEAF_SCRIPT) => {
            if kd.len() < 33 {
                return Err(PsbtError::Core(
                    "Taproot leaf script key is not at least 34 bytes",
                ));
            }
            if !(kd.len() - 1).is_multiple_of(32) {
                return Err(PsbtError::Core(
                    "Input Taproot leaf script key's control block size is not valid",
                ));
            }
        }
        (Scope::Input, Psbt::IN_TAP_BIP32_DERIVATION) => {
            if kd.len() != 32 {
                return Err(PsbtError::Core(
                    "Input Taproot BIP32 keypath key is not at 33 bytes",
                ));
            }
        }
        (Scope::Input, Psbt::IN_TAP_INTERNAL_KEY) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Input Taproot internal key key is more than one byte type",
                ));
            }
        }
        (Scope::Input, Psbt::IN_TAP_MERKLE_ROOT) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Input Taproot merkle root key is more than one byte type",
                ));
            }
        }
        (Scope::Output, Psbt::OUT_REDEEM_SCRIPT) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Output redeemScript key is more than one byte type",
                ));
            }
        }
        (Scope::Output, Psbt::OUT_WITNESS_SCRIPT) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Output witnessScript key is more than one byte type",
                ));
            }
        }
        (Scope::Output, Psbt::OUT_TAP_INTERNAL_KEY) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Output Taproot internal key key is more than one byte type",
                ));
            }
        }
        (Scope::Output, Psbt::OUT_TAP_TREE) => {
            if !kd.is_empty() {
                return Err(PsbtError::Core(
                    "Output Taproot tree key is more than one byte type",
                ));
            }
        }
        (Scope::Output, Psbt::OUT_TAP_BIP32_DERIVATION) => {
            if kd.len() != 32 {
                return Err(PsbtError::Core(
                    "Output Taproot BIP32 keypath key is not at 33 bytes",
                ));
            }
        }
        (Scope::Global | Scope::Input | Scope::Output, Psbt::GLOBAL_PROPRIETARY)
            if !proprietary_keydata_ok(kd) =>
        {
            return Err(PsbtError::UnexpectedEnd);
        }
        _ => {}
    }
    Ok(())
}

/// The `Duplicate Key, …` string Core throws when a pair's key is
/// already present — each map case names its own field.
fn dup_message(scope: Scope, key_type: u8) -> &'static str {
    match (scope, key_type) {
        (Scope::Global, Psbt::GLOBAL_TX) => "Duplicate Key, unsigned tx already provided",
        (Scope::Global, Psbt::GLOBAL_XPUB) => "Duplicate key, global xpub already provided",
        (Scope::Global, Psbt::GLOBAL_VERSION) => "Duplicate Key, version already provided",
        (_, Psbt::GLOBAL_PROPRIETARY) => "Duplicate Key, proprietary key already found",
        (Scope::Input, Psbt::IN_NON_WITNESS_UTXO) => {
            "Duplicate Key, input non-witness utxo already provided"
        }
        (Scope::Input, Psbt::IN_WITNESS_UTXO) => {
            "Duplicate Key, input witness utxo already provided"
        }
        (Scope::Input, Psbt::IN_PARTIAL_SIG) => {
            "Duplicate Key, input partial signature for pubkey already provided"
        }
        (Scope::Input, Psbt::IN_SIGHASH_TYPE) => {
            "Duplicate Key, input sighash type already provided"
        }
        (Scope::Input, Psbt::IN_REDEEM_SCRIPT) => {
            "Duplicate Key, input redeemScript already provided"
        }
        (Scope::Input, Psbt::IN_WITNESS_SCRIPT) => {
            "Duplicate Key, input witnessScript already provided"
        }
        (Scope::Input, Psbt::IN_BIP32_DERIVATION) | (Scope::Output, Psbt::OUT_BIP32_DERIVATION) => {
            "Duplicate Key, pubkey derivation path already provided"
        }
        (Scope::Input, Psbt::IN_FINAL_SCRIPTSIG) => {
            "Duplicate Key, input final scriptSig already provided"
        }
        (Scope::Input, Psbt::IN_FINAL_SCRIPTWITNESS) => {
            "Duplicate Key, input final scriptWitness already provided"
        }
        (Scope::Input, Psbt::IN_RIPEMD160) => {
            "Duplicate Key, input ripemd160 preimage already provided"
        }
        (Scope::Input, Psbt::IN_SHA256) => "Duplicate Key, input sha256 preimage already provided",
        (Scope::Input, Psbt::IN_HASH160) => {
            "Duplicate Key, input hash160 preimage already provided"
        }
        (Scope::Input, Psbt::IN_HASH256) => {
            "Duplicate Key, input hash256 preimage already provided"
        }
        (Scope::Input, Psbt::IN_TAP_KEY_SIG) => {
            "Duplicate Key, input Taproot key signature already provided"
        }
        (Scope::Input, Psbt::IN_TAP_SCRIPT_SIG) => {
            "Duplicate Key, input Taproot script signature already provided"
        }
        (Scope::Input, Psbt::IN_TAP_LEAF_SCRIPT) => {
            "Duplicate Key, input Taproot leaf script already provided"
        }
        (Scope::Input, Psbt::IN_TAP_BIP32_DERIVATION) => {
            "Duplicate Key, input Taproot BIP32 keypath already provided"
        }
        (Scope::Input, Psbt::IN_TAP_INTERNAL_KEY) => {
            "Duplicate Key, input Taproot internal key already provided"
        }
        (Scope::Input, Psbt::IN_TAP_MERKLE_ROOT) => {
            "Duplicate Key, input Taproot merkle root already provided"
        }
        (Scope::Output, Psbt::OUT_REDEEM_SCRIPT) => {
            "Duplicate Key, output redeemScript already provided"
        }
        (Scope::Output, Psbt::OUT_WITNESS_SCRIPT) => {
            "Duplicate Key, output witnessScript already provided"
        }
        (Scope::Output, Psbt::OUT_TAP_INTERNAL_KEY) => {
            "Duplicate Key, output Taproot internal key already provided"
        }
        (Scope::Output, Psbt::OUT_TAP_TREE) => {
            "Duplicate Key, output Taproot tree already provided"
        }
        (Scope::Output, Psbt::OUT_TAP_BIP32_DERIVATION) => {
            "Duplicate Key, output Taproot BIP32 keypath already provided"
        }
        _ => "Duplicate Key, key for unknown value already provided",
    }
}

/// `UnserializeFromVector` — the value must decode as `needed` bytes
/// exactly; `remaining` is what the outer stream still holds so an
/// under-sized value reports end-of-data only when Core would hit EOF.
fn exact_value(value: &[u8], needed: usize, remaining: usize) -> Result<(), PsbtError> {
    if value.len() == needed {
        Ok(())
    } else if value.len() < needed && remaining < needed - value.len() {
        Err(PsbtError::UnexpectedEnd)
    } else {
        Err(PsbtError::Core("Size of value was not the stated size"))
    }
}

/// `DeserializeKeyOrigin` — the value is `fingerprint(4) || path*4`;
/// zero or non-multiple-of-four lengths are rejected.
fn check_hd_keypath(value: &[u8]) -> Result<(), PsbtError> {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return Err(PsbtError::Core("Invalid length for HD key path"));
    }
    Ok(())
}

/// The `(hashes || origin)` value of a taproot BIP32 derivation:
/// `CompactSize count` + `count` 32-byte leaf hashes, then the
/// remaining bytes must be a valid `KeyOriginInfo` length.
fn check_tap_keypath(value: &[u8], input: bool, remaining: usize) -> Result<(), PsbtError> {
    let mut dec = Decoder::new(value);
    let n = dec.read_compact_size().map_err(map_decode_err)?;
    let used = dec.position() + (n as usize).saturating_mul(32);
    if used > value.len() {
        // Core reads the leaf hashes straight off the outer stream;
        // running past the stated value errors with "end of data",
        // while a read that fits reports the invalid length.
        if used - value.len() > remaining {
            return Err(PsbtError::UnexpectedEnd);
        }
        return Err(PsbtError::Core(if input {
            "Input Taproot BIP32 keypath has an invalid length"
        } else {
            "Output Taproot BIP32 keypath has an invalid length"
        }));
    }
    check_hd_keypath(&value[used..])
}

/// `TaprootBuilder` completeness over the output `tap_tree` value:
/// `(depth, leaf_ver, CompactSize script)` triples in DFS order.
/// `branch[d]` tracks a merged node awaiting its sibling at depth `d`,
/// mirroring `TaprootBuilder::Insert` — a leaf may not sit below an
/// open branch, same-depth nodes combine and propagate up, and a
/// complete tree ends as a single root at depth 0.
fn check_tap_tree(value: &[u8]) -> Result<(), PsbtError> {
    if value.is_empty() {
        return Err(PsbtError::Core("Output Taproot tree must not be empty"));
    }
    let mut dec = Decoder::new(value);
    let mut branch: Vec<bool> = Vec::new();
    let mut valid = true;
    while !dec.is_finished() {
        let depth = dec.read_u8().map_err(map_decode_err)? as usize;
        let leaf_ver = dec.read_u8().map_err(map_decode_err)?;
        dec.read_var_bytes().map_err(map_decode_err)?;
        if depth > 128 {
            return Err(PsbtError::Core(
                "Output Taproot tree has as leaf greater than Taproot maximum depth",
            ));
        }
        if leaf_ver & !0xfe != 0 {
            return Err(PsbtError::Core(
                "Output Taproot tree has a leaf with an invalid leaf version",
            ));
        }
        if valid {
            if depth + 1 < branch.len() {
                valid = false;
            }
            let mut d = depth;
            while valid && branch.len() > d && branch[d] {
                branch.pop();
                if d == 0 {
                    valid = false;
                    break;
                }
                d -= 1;
            }
            if valid {
                if branch.len() <= d {
                    branch.resize(d + 1, false);
                }
                branch[d] = true;
            }
        }
    }
    if !valid || !(branch.is_empty() || (branch.len() == 1 && branch[0])) {
        return Err(PsbtError::Core("Output Taproot tree is malformed"));
    }
    Ok(())
}

/// Value-side checks Core runs inside each map case — embedded
/// transactions, `TxOut`s, u32s, fixed-width hashes, signature
/// lengths, and the structured taproot values.
fn check_value(scope: Scope, key: &[u8], value: &[u8], remaining: usize) -> Result<(), PsbtError> {
    match (scope, key[0]) {
        (Scope::Global, Psbt::GLOBAL_TX) => {
            let tx = Transaction::decode_no_witness(value).map_err(|e| match e {
                DecodeError::TrailingBytes(_) => {
                    PsbtError::Core("Size of value was not the stated size")
                }
                other => map_decode_err(other),
            })?;
            if tx.inputs.iter().any(|i| !i.script_sig.is_empty()) {
                return Err(PsbtError::NonEmptyScriptSig);
            }
        }
        (Scope::Global, Psbt::GLOBAL_XPUB) => check_hd_keypath(value)?,
        (Scope::Global, Psbt::GLOBAL_VERSION) => {
            exact_value(value, 4, remaining)?;
            let ver = Decoder::new(value).read_u32_le().map_err(map_decode_err)?;
            if ver > 0 {
                return Err(PsbtError::UnsupportedVersion);
            }
        }
        (Scope::Input, Psbt::IN_NON_WITNESS_UTXO) => {
            Transaction::decode(value).map_err(|e| match e {
                DecodeError::TrailingBytes(_) => {
                    PsbtError::Core("Size of value was not the stated size")
                }
                other => map_decode_err(other),
            })?;
        }
        (Scope::Input, Psbt::IN_WITNESS_UTXO) => {
            // `UnserializeFromVector(s, CTxOut)` — i64 value then a
            // var-bytes script, consuming the stated length exactly.
            let mut dec = Decoder::new(value);
            let short = |e: DecodeError| -> PsbtError {
                if remaining + value.len() < 9 {
                    PsbtError::UnexpectedEnd
                } else {
                    map_decode_err(e)
                }
            };
            dec.read_u64_le().map_err(short)?;
            dec.read_var_bytes().map_err(short)?;
            if !dec.is_finished() {
                return Err(PsbtError::Core("Size of value was not the stated size"));
            }
        }
        (Scope::Input, Psbt::IN_SIGHASH_TYPE) => exact_value(value, 4, remaining)?,
        (Scope::Input, Psbt::IN_BIP32_DERIVATION) | (Scope::Output, Psbt::OUT_BIP32_DERIVATION) => {
            check_hd_keypath(value)?
        }
        (Scope::Input, Psbt::IN_FINAL_SCRIPTWITNESS) => {
            let mut dec = Decoder::new(value);
            let count = dec.read_compact_size().map_err(map_decode_err)?;
            for _ in 0..count {
                dec.read_var_bytes().map_err(map_decode_err)?;
            }
            if !dec.is_finished() {
                return Err(PsbtError::Core("Size of value was not the stated size"));
            }
        }
        (Scope::Input, Psbt::IN_TAP_KEY_SIG) => {
            if value.len() < 64 {
                return Err(PsbtError::Core(
                    "Input Taproot key path signature is shorter than 64 bytes",
                ));
            }
            if value.len() > 65 {
                return Err(PsbtError::Core(
                    "Input Taproot key path signature is longer than 65 bytes",
                ));
            }
        }
        (Scope::Input, Psbt::IN_TAP_SCRIPT_SIG) => {
            if value.len() < 64 {
                return Err(PsbtError::Core(
                    "Input Taproot script path signature is shorter than 64 bytes",
                ));
            }
            if value.len() > 65 {
                return Err(PsbtError::Core(
                    "Input Taproot script path signature is longer than 65 bytes",
                ));
            }
        }
        (Scope::Input, Psbt::IN_TAP_LEAF_SCRIPT) => {
            if value.is_empty() {
                return Err(PsbtError::Core(
                    "Input Taproot leaf script must be at least 1 byte",
                ));
            }
        }
        (Scope::Input, Psbt::IN_TAP_BIP32_DERIVATION) => check_tap_keypath(value, true, remaining)?,
        (Scope::Input, Psbt::IN_TAP_INTERNAL_KEY)
        | (Scope::Input, Psbt::IN_TAP_MERKLE_ROOT)
        | (Scope::Output, Psbt::OUT_TAP_INTERNAL_KEY) => exact_value(value, 32, remaining)?,
        (Scope::Output, Psbt::OUT_TAP_TREE) => check_tap_tree(value)?,
        (Scope::Output, Psbt::OUT_TAP_BIP32_DERIVATION) => {
            check_tap_keypath(value, false, remaining)?
        }
        _ => {}
    }
    Ok(())
}

/// A BIP174 key-value map — pairs preserved in wire order so unknown
/// and proprietary entries survive a decode→encode roundtrip.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyMap {
    /// `(key, value)` pairs in serialization order; `key[0]` is the
    /// BIP174 type byte and `key[1..]` the type's keydata.
    pub pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl KeyMap {
    /// First value for a type byte, ignoring keydata.
    pub fn get(&self, key_type: u8) -> Option<&[u8]> {
        self.pairs
            .iter()
            .find(|(k, _)| k.first() == Some(&key_type))
            .map(|(_, v)| v.as_slice())
    }

    /// All `(keydata, value)` entries for a type byte.
    pub fn all(&self, key_type: u8) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.pairs
            .iter()
            .filter(move |(k, _)| k.first() == Some(&key_type))
            .map(|(k, v)| (&k[1..], v.as_slice()))
    }

    /// Insert or replace the pair for an exact key.
    pub fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        if let Some(slot) = self.pairs.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.pairs.push((key, value));
        }
    }

    /// `combinepsbt` merge: insert the pair only when absent — the
    /// first contributor's value wins on a key collision.
    pub fn insert_absent(&mut self, key: &[u8], value: &[u8]) {
        if !self.contains(key) {
            self.pairs.push((key.to_vec(), value.to_vec()));
        }
    }

    /// Removes every pair whose type byte is in `types`
    /// (`joinpsbts`' signature-data drop).
    pub fn remove_types(&mut self, types: &[u8]) {
        self.pairs
            .retain(|(k, _)| !types.contains(k.first().unwrap_or(&0)));
    }

    /// Sorts pairs by full key — the order Core's `std::map` emits.
    pub fn sort_keys(&mut self) {
        self.pairs.sort();
    }

    /// Whether a pair exists for the exact key.
    pub fn contains(&self, key: &[u8]) -> bool {
        self.pairs.iter().any(|(k, _)| k == key)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for (key, value) in &self.pairs {
            encode::write_compact_size(out, key.len() as u64);
            out.extend_from_slice(key);
            encode::write_var_bytes(out, value);
        }
        out.push(0x00);
    }
}

/// A decoded PSBT: the global map's unsigned transaction plus the
/// per-input and per-output maps, all retaining wire order.
#[derive(Clone, Debug)]
pub struct Psbt {
    /// The unsigned transaction from global key `0x00` — serialized
    /// without witness data per BIP174.
    pub tx: Transaction,
    /// Global map including the unsigned-tx pair itself.
    pub global: KeyMap,
    /// One map per `tx.inputs`, in order.
    pub inputs: Vec<KeyMap>,
    /// One map per `tx.outputs`, in order.
    pub outputs: Vec<KeyMap>,
}

/// Reads one `<compactsize len><bytes>` key at the stream head.
/// `None` on the `0x00` separator; EOF-before-length reports `end`.
fn read_key(dec: &mut Decoder<'_>) -> Result<Option<Vec<u8>>, PsbtError> {
    let key_len = dec.read_compact_size().map_err(map_decode_err)?;
    if key_len == 0 {
        return Ok(None);
    }
    let key = dec
        .read_bytes(key_len as usize)
        .map_err(map_decode_err)?
        .to_vec();
    Ok(Some(key))
}

fn read_value(dec: &mut Decoder<'_>) -> Result<Vec<u8>, PsbtError> {
    dec.read_var_bytes().map_err(map_decode_err)
}

/// Maps the shared `DecodeError` vocabulary onto Core's PSBT texts.
fn map_decode_err(e: DecodeError) -> PsbtError {
    match e {
        DecodeError::UnexpectedEnd { .. } => PsbtError::UnexpectedEnd,
        DecodeError::CompactSizeTooLarge(_) | DecodeError::NonCanonicalCompactSize => {
            PsbtError::CompactSizeTooLarge
        }
        _ => PsbtError::Value(e.to_string()),
    }
}

/// Reads a key-value map terminated by `0x00`, running Core's
/// per-case key and value checks for `scope` and its per-type
/// duplicate messages.
fn read_map(dec: &mut Decoder<'_>, scope: Scope) -> Result<KeyMap, PsbtError> {
    let mut map = KeyMap::default();
    let mut seen = std::collections::HashSet::new();
    loop {
        match read_key(dec)? {
            None => break,
            Some(key) => {
                check_key(scope, &key)?;
                if !seen.insert(key.clone()) {
                    return Err(PsbtError::Core(dup_message(scope, key[0])));
                }
                let value = read_value(dec)?;
                check_value(scope, &key, &value, dec.remaining())?;
                map.pairs.push((key, value));
            }
        }
    }
    Ok(map)
}

impl Psbt {
    /// `PSBT_GLOBAL_UNSIGNED_TX` — the global unsigned transaction.
    pub const GLOBAL_TX: u8 = 0x00;
    /// `PSBT_GLOBAL_XPUB` — extended pubkey + origin keydata.
    pub const GLOBAL_XPUB: u8 = 0x01;
    /// `PSBT_GLOBAL_TX_VERSION` — v2 transaction version field.
    pub const GLOBAL_TX_VERSION: u8 = 0x02;
    /// `PSBT_GLOBAL_FALLBACK_LOCKTIME` — v2 fallback nLockTime.
    pub const GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
    /// `PSBT_GLOBAL_INPUT_COUNT` — v2 explicit input count.
    pub const GLOBAL_INPUT_COUNT: u8 = 0x04;
    /// `PSBT_GLOBAL_OUTPUT_COUNT` — v2 explicit output count.
    pub const GLOBAL_OUTPUT_COUNT: u8 = 0x05;
    /// `PSBT_GLOBAL_TX_MODIFIABLE` — v2 modifiability flags.
    pub const GLOBAL_TX_MODIFIABLE: u8 = 0x06;
    /// `PSBT_GLOBAL_VERSION` — the PSBT format version (2; absent=0).
    pub const GLOBAL_VERSION: u8 = 0xfb;
    /// `PSBT_GLOBAL_PROPRIETARY` — namespaced global extensions.
    pub const GLOBAL_PROPRIETARY: u8 = 0xfc;

    /// `PSBT_IN_NON_WITNESS_UTXO` — the full prevout transaction.
    pub const IN_NON_WITNESS_UTXO: u8 = 0x00;
    /// `PSBT_IN_WITNESS_UTXO` — the prevout `TxOut`.
    pub const IN_WITNESS_UTXO: u8 = 0x01;
    /// `PSBT_IN_PARTIAL_SIG` — pubkey keydata → signature.
    pub const IN_PARTIAL_SIG: u8 = 0x02;
    /// `PSBT_IN_SIGHASH_TYPE` — u32 signature hash modifier.
    pub const IN_SIGHASH_TYPE: u8 = 0x03;
    /// `PSBT_IN_REDEEM_SCRIPT`.
    pub const IN_REDEEM_SCRIPT: u8 = 0x04;
    /// `PSBT_IN_WITNESS_SCRIPT`.
    pub const IN_WITNESS_SCRIPT: u8 = 0x05;
    /// `PSBT_IN_BIP32_DERIVATION` — pubkey → fingerprint+path.
    pub const IN_BIP32_DERIVATION: u8 = 0x06;
    /// `PSBT_IN_FINAL_SCRIPTSIG`.
    pub const IN_FINAL_SCRIPTSIG: u8 = 0x07;
    /// `PSBT_IN_FINAL_SCRIPTWITNESS` — compactsize-item stack.
    pub const IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
    /// `PSBT_IN_POR_COMMITMENT` — BIP127 proof-of-reserves message.
    pub const IN_POR_COMMITMENT: u8 = 0x09;
    /// `PSBT_IN_RIPEMD160` preimage (hash keydata).
    pub const IN_RIPEMD160: u8 = 0x0a;
    /// `PSBT_IN_SHA256` preimage (hash keydata).
    pub const IN_SHA256: u8 = 0x0b;
    /// `PSBT_IN_HASH160` preimage (hash keydata).
    pub const IN_HASH160: u8 = 0x0c;
    /// `PSBT_IN_HASH256` preimage (hash keydata).
    pub const IN_HASH256: u8 = 0x0d;
    /// `PSBT_IN_PREVIOUS_TXID` — v2 explicit input prevout txid.
    pub const IN_PREVIOUS_TXID: u8 = 0x0e;
    /// `PSBT_IN_OUTPUT_INDEX` — v2 explicit input prevout index.
    pub const IN_OUTPUT_INDEX: u8 = 0x0f;
    /// `PSBT_IN_SEQUENCE` — v2 explicit nSequence.
    pub const IN_SEQUENCE: u8 = 0x10;
    /// `PSBT_IN_REQUIRED_TIME_LOCKTIME` — v2 nLockTime requirement.
    pub const IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
    /// `PSBT_IN_REQUIRED_HEIGHT_LOCKTIME` — v2 height requirement.
    pub const IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
    /// `PSBT_IN_TAP_KEY_SIG` — key-path schnorr signature.
    pub const IN_TAP_KEY_SIG: u8 = 0x13;
    /// `PSBT_IN_TAP_SCRIPT_SIG` — xonly+leafhash → schnorr sig.
    pub const IN_TAP_SCRIPT_SIG: u8 = 0x14;
    /// `PSBT_IN_TAP_LEAF_SCRIPT` — control-block → leaf script+ver.
    pub const IN_TAP_LEAF_SCRIPT: u8 = 0x15;
    /// `PSBT_IN_TAP_BIP32_DERIVATION` — xonly → leafhashes+origin.
    pub const IN_TAP_BIP32_DERIVATION: u8 = 0x16;
    /// `PSBT_IN_TAP_INTERNAL_KEY` — xonly internal key.
    pub const IN_TAP_INTERNAL_KEY: u8 = 0x17;
    /// `PSBT_IN_TAP_MERKLE_ROOT`.
    pub const IN_TAP_MERKLE_ROOT: u8 = 0x18;
    /// `PSBT_IN_PROPRIETARY` — namespaced input extensions.
    pub const IN_PROPRIETARY: u8 = 0xfc;

    /// `PSBT_OUT_REDEEM_SCRIPT`.
    pub const OUT_REDEEM_SCRIPT: u8 = 0x00;
    /// `PSBT_OUT_WITNESS_SCRIPT`.
    pub const OUT_WITNESS_SCRIPT: u8 = 0x01;
    /// `PSBT_OUT_BIP32_DERIVATION`.
    pub const OUT_BIP32_DERIVATION: u8 = 0x02;
    /// `PSBT_OUT_AMOUNT` — v2 explicit output value.
    pub const OUT_AMOUNT: u8 = 0x03;
    /// `PSBT_OUT_SCRIPT` — v2 explicit output script.
    pub const OUT_SCRIPT: u8 = 0x04;
    /// `PSBT_OUT_TAP_INTERNAL_KEY`.
    pub const OUT_TAP_INTERNAL_KEY: u8 = 0x05;
    /// `PSBT_OUT_TAP_TREE` — serialized taproot tree.
    pub const OUT_TAP_TREE: u8 = 0x06;
    /// `PSBT_OUT_TAP_BIP32_DERIVATION`.
    pub const OUT_TAP_BIP32_DERIVATION: u8 = 0x07;
    /// `PSBT_OUT_PROPRIETARY`.
    pub const OUT_PROPRIETARY: u8 = 0xfc;

    /// Parses the full `psbt\xff…` serialization with Core's
    /// `DecodePSBT` validation: magic, separator bookkeeping,
    /// keydata rules, duplicate keys, and the input/output counts.
    pub fn decode(bytes: &[u8]) -> Result<Self, PsbtError> {
        let mut dec = Decoder::new(bytes);
        let magic = dec.read_bytes(PSBT_MAGIC.len()).map_err(map_decode_err)?;
        if magic != PSBT_MAGIC {
            return Err(PsbtError::BadMagic);
        }
        // The global map reports an unterminated stream differently
        // from the per-input/output loops: EOF at a pair boundary is
        // "Separator is missing at the end of the global map".
        let global = if dec.is_finished() {
            return Err(PsbtError::GlobalMapUnterminated);
        } else {
            let mut map = KeyMap::default();
            let mut seen = std::collections::HashSet::new();
            loop {
                if dec.is_finished() {
                    return Err(PsbtError::GlobalMapUnterminated);
                }
                match read_key(&mut dec)? {
                    None => break,
                    Some(key) => {
                        check_key(Scope::Global, &key)?;
                        if !seen.insert(key.clone()) {
                            return Err(PsbtError::Core(dup_message(Scope::Global, key[0])));
                        }
                        let value = read_value(&mut dec)?;
                        check_value(Scope::Global, &key, &value, dec.remaining())?;
                        map.pairs.push((key, value));
                    }
                }
            }
            map
        };
        let tx_bytes = global
            .get(Self::GLOBAL_TX)
            .ok_or(PsbtError::MissingUnsignedTx)?;
        let tx = Transaction::decode_no_witness(tx_bytes).map_err(map_decode_err)?;
        // Per-input maps: an exhausted stream means a missing map —
        // Core reports the count mismatch, not a separator error.
        let mut inputs = Vec::with_capacity(tx.inputs.len());
        for _ in 0..tx.inputs.len() {
            if dec.is_finished() {
                break;
            }
            let map = read_map(&mut dec, Scope::Input)?;
            // `Unserialize` checks a carried non-witness utxo against
            // the outpoint right after each input map.
            if let Some(v) = map.get(Self::IN_NON_WITNESS_UTXO) {
                let prev_tx = Transaction::decode(v).map_err(map_decode_err)?;
                let prevout = &tx.inputs[inputs.len()].previous_output;
                if prev_tx.txid() != prevout.txid {
                    return Err(PsbtError::Core(
                        "Non-witness UTXO does not match outpoint hash",
                    ));
                }
                if prevout.vout as usize >= prev_tx.outputs.len() {
                    return Err(PsbtError::Core(
                        "Input specifies output index that does not exist",
                    ));
                }
            }
            inputs.push(map);
        }
        if inputs.len() != tx.inputs.len() {
            return Err(PsbtError::InputCountMismatch);
        }
        let mut outputs = Vec::with_capacity(tx.outputs.len());
        for _ in 0..tx.outputs.len() {
            if dec.is_finished() {
                break;
            }
            outputs.push(read_map(&mut dec, Scope::Output)?);
        }
        if outputs.len() != tx.outputs.len() {
            return Err(PsbtError::OutputCountMismatch);
        }
        if !dec.is_finished() {
            return Err(PsbtError::TrailingBytes);
        }
        Ok(Self {
            tx,
            global,
            inputs,
            outputs,
        })
    }

    /// Serializes back to the exact wire form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PSBT_MAGIC);
        self.global.encode(&mut out);
        for map in &self.inputs {
            map.encode(&mut out);
        }
        for map in &self.outputs {
            map.encode(&mut out);
        }
        out
    }

    /// `PSBT_GLOBAL_VERSION` or `0` when absent (BIP174 v0).
    pub fn version(&self) -> u32 {
        self.global
            .get(Self::GLOBAL_VERSION)
            .and_then(|v| Decoder::new(v).read_u32_le().ok())
            .unwrap_or(0)
    }

    /// Witness or non-witness UTXO attached to input `i`.
    pub fn input_utxo(&self, i: usize) -> Option<TxOut> {
        let map = self.inputs.get(i)?;
        if let Some(v) = map.get(Self::IN_WITNESS_UTXO) {
            let mut dec = Decoder::new(v);
            let value = dec.read_i64_le().ok()?;
            let script = dec.read_var_bytes().ok()?;
            return Some(TxOut {
                value,
                script_pubkey: crate::transaction::Script::new(script),
            });
        }
        let prev_tx_bytes = map.get(Self::IN_NON_WITNESS_UTXO)?;
        let prev_tx = Transaction::decode(prev_tx_bytes).ok()?;
        let input = self.tx.inputs.get(i)?;
        prev_tx
            .outputs
            .get(input.previous_output.vout as usize)
            .cloned()
    }

    /// Builds a fresh v0 PSBT around `tx` — the `createpsbt`/
    /// `converttopsbt` skeleton: global unsigned tx plus empty maps.
    pub fn from_unsigned_tx(tx: Transaction) -> Self {
        let mut tx = tx;
        for input in &mut tx.inputs {
            input.script_sig = crate::transaction::Script::new(Vec::new());
            input.witness = crate::transaction::Witness::default();
        }
        let mut global = KeyMap::default();
        let mut tx_bytes = Vec::new();
        tx.write_without_witness(&mut tx_bytes);
        global.pairs.push((vec![Self::GLOBAL_TX], tx_bytes));
        Self {
            inputs: vec![KeyMap::default(); tx.inputs.len()],
            outputs: vec![KeyMap::default(); tx.outputs.len()],
            tx,
            global,
        }
    }
}

/// Decodes a BIP32-derivation value (`fingerprint || u32 path*`).
pub fn bip32_derivation_value(v: &[u8]) -> Option<(u32, Vec<u32>)> {
    if v.len() < 4 || !(v.len() - 4).is_multiple_of(4) {
        return None;
    }
    let mut dec = Decoder::new(v);
    let fingerprint = dec.read_u32_le().ok()?;
    let mut path = Vec::new();
    while !dec.is_finished() {
        path.push(dec.read_u32_le().ok()?);
    }
    Some((fingerprint, path))
}

/// Renders a derivation path in Core's `m/…/h` form.
pub fn format_derivation_path(path: &[u32]) -> String {
    let mut s = String::from("m");
    for elem in path {
        if elem & 0x8000_0000 != 0 {
            s.push_str(&format!("/{}h", elem & 0x7fff_ffff));
        } else {
            s.push_str(&format!("/{elem}"));
        }
    }
    s
}

/// The outpoint a PSBT input spends — from the unsigned tx.
pub fn input_outpoint(psbt: &Psbt, i: usize) -> Option<OutPoint> {
    psbt.tx.inputs.get(i).map(|input| input.previous_output)
}

/// Txid of the transaction a `non_witness_utxo` value carries.
pub fn non_witness_utxo_txid(v: &[u8]) -> Option<Txid> {
    Transaction::decode(v).ok().map(|t| t.txid())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::hex;

    /// A Core-wallet-funded PSBT (regtest, one P2WPKH input) —
    /// roundtrips byte-exactly through decode→encode.
    const FUNDED_PSBT_HEX: &str = include_str!("../tests/data/funded.psbt.hex");

    #[test]
    fn roundtrip_preserves_bytes() {
        let bytes = hex::decode(FUNDED_PSBT_HEX.trim()).unwrap();
        let psbt = Psbt::decode(&bytes).unwrap();
        assert_eq!(psbt.version(), 0);
        assert_eq!(psbt.inputs.len(), psbt.tx.inputs.len());
        assert_eq!(psbt.outputs.len(), psbt.tx.outputs.len());
        assert_eq!(psbt.encode(), bytes);
        // The input carries both utxo forms.
        assert!(psbt.inputs[0].get(Psbt::IN_WITNESS_UTXO).is_some());
        assert!(psbt.inputs[0].get(Psbt::IN_NON_WITNESS_UTXO).is_some());
        assert!(psbt.input_utxo(0).is_some());
    }

    #[test]
    fn rejects_bad_magic_and_missing_tx() {
        assert!(matches!(Psbt::decode(b""), Err(PsbtError::UnexpectedEnd)));
        assert_eq!(
            Psbt::decode(b"psbt\xff\x00").unwrap_err(),
            PsbtError::MissingUnsignedTx
        );
        // Unknown global key but still no unsigned tx.
        let mut bad = Vec::from(PSBT_MAGIC);
        encode::write_compact_size(&mut bad, 2);
        bad.extend_from_slice(&[0xfa, 0x00]);
        encode::write_compact_size(&mut bad, 1);
        bad.push(0xaa);
        bad.push(0x00);
        assert_eq!(
            Psbt::decode(&bad).unwrap_err(),
            PsbtError::MissingUnsignedTx
        );
    }

    #[test]
    fn keymap_lookup_and_set() {
        let mut m = KeyMap::default();
        m.set(vec![0x02, 0xaa], vec![0x01]);
        m.set(vec![0x02, 0xbb], vec![0x02]);
        assert_eq!(m.get(0x02), Some(&[0x01][..]));
        assert_eq!(m.all(0x02).count(), 2);
        m.set(vec![0x02, 0xaa], vec![0x09]);
        assert_eq!(m.get(0x02), Some(&[0x09][..]));
        assert_eq!(m.pairs.len(), 2);
    }

    #[test]
    fn derivation_value_and_format() {
        let mut v = Vec::from([0x78, 0x56, 0x34, 0x12]);
        v.extend_from_slice(&84u32.to_le_bytes());
        v.extend_from_slice(&(1u32 | 0x8000_0000).to_le_bytes());
        let (fp, path) = bip32_derivation_value(&v).unwrap();
        assert_eq!(fp, 0x1234_5678);
        assert_eq!(format_derivation_path(&path), "m/84/1h");
        assert!(bip32_derivation_value(&[1, 2]).is_none());
    }

    /// A skeleton built from an unsigned tx encodes with empty maps.
    #[test]
    fn from_unsigned_tx_shape() {
        let tx = Transaction {
            version: 2,
            inputs: vec![crate::transaction::TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_bytes([0x42; 32]),
                    vout: 0,
                },
                script_sig: crate::transaction::Script::new(vec![0x51]),
                sequence: 0xffff_fffd,
                witness: crate::transaction::Witness::default(),
            }],
            outputs: vec![
                TxOut {
                    value: 100_000,
                    script_pubkey: crate::transaction::Script::new(
                        hex::decode("00143382e2b5b2c1a5f0dbb7b1f8ea0e5d4a5c2a5b7d").unwrap(),
                    ),
                },
                TxOut {
                    value: 99_000_000,
                    script_pubkey: crate::transaction::Script::new(
                        hex::decode("00144444444444444444444444444444444444444444").unwrap(),
                    ),
                },
            ],
            lock_time: 0,
        };
        let psbt = Psbt::from_unsigned_tx(tx.clone());
        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 2);
        // The skeleton clears scriptSigs per BIP174.
        assert!(psbt.tx.inputs[0].script_sig.is_empty());
        let round = Psbt::decode(&psbt.encode()).unwrap();
        assert_eq!(round.tx.txid(), psbt.tx.txid());
    }

    /// `combinepsbt` merge: an exact-key collision keeps the first
    /// contributor's value; distinct keydatas under one type all
    /// survive; sorting is by full key bytes like Core's `std::map`.
    #[test]
    fn keymap_merge_semantics() {
        let mut m = KeyMap::default();
        m.set(vec![0x02, 0xaa], vec![0x01]);
        m.insert_absent(&[0x02, 0xaa], &[0x09]);
        assert_eq!(m.get(0x02), Some(&[0x01][..]));
        m.insert_absent(&[0x02, 0xbb], &[0x07]);
        assert_eq!(m.all(0x02).count(), 2);
        m.insert_absent(&[0x60, 0x01], &[0xcc]);
        m.sort_keys();
        let keys: Vec<&Vec<u8>> = m.pairs.iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            vec![&vec![0x02, 0xaa], &vec![0x02, 0xbb], &vec![0x60, 0x01]]
        );
    }

    /// `joinpsbts` strips only partial sigs and the two finalization
    /// fields (`AddInput` clears exactly those) — utxos, scripts,
    /// derivations, taproot sigs, and unknown keys survive.
    #[test]
    fn keymap_remove_signature_types() {
        let mut m = KeyMap::default();
        m.set(vec![Psbt::IN_PARTIAL_SIG, 0xaa], vec![0x01]);
        m.set(vec![Psbt::IN_FINAL_SCRIPTSIG], vec![0x02]);
        m.set(vec![Psbt::IN_FINAL_SCRIPTWITNESS], vec![0x03]);
        m.set(vec![Psbt::IN_TAP_KEY_SIG], vec![0x04]);
        m.set(vec![Psbt::IN_TAP_SCRIPT_SIG, 0xbb], vec![0x05]);
        m.set(vec![Psbt::IN_WITNESS_UTXO], vec![0x06]);
        m.set(vec![Psbt::IN_BIP32_DERIVATION, 0xcc], vec![0x07]);
        m.set(vec![0x60, 0xdd], vec![0x08]);
        m.remove_types(&[
            Psbt::IN_PARTIAL_SIG,
            Psbt::IN_FINAL_SCRIPTSIG,
            Psbt::IN_FINAL_SCRIPTWITNESS,
        ]);
        let types: Vec<u8> = m.pairs.iter().map(|(k, _)| k[0]).collect();
        assert_eq!(
            types,
            vec![
                Psbt::IN_TAP_KEY_SIG,
                Psbt::IN_TAP_SCRIPT_SIG,
                Psbt::IN_WITNESS_UTXO,
                Psbt::IN_BIP32_DERIVATION,
                0x60
            ]
        );
    }
}

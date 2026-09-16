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
    /// A key arrived with keydata where the type forbids it, or
    /// missing keydata where the type requires it — the `name` is
    /// Core's per-type label ("Global unsigned tx", "Input
    /// redeemScript", …).
    #[error("{0} key is more than one byte type")]
    KeyDataWrong(&'static str),
    /// A key appeared twice in the same map.
    #[error("Duplicate key not allowed in {0} map")]
    DuplicateKey(&'static str),
    /// The global map terminated without an unsigned-tx pair.
    #[error("No unsigned transaction was provided")]
    MissingUnsignedTx,
    /// More than one unsigned-tx pair in the global map.
    #[error("Multiple unsigned transactions provided")]
    DuplicateUnsignedTx,
    /// The unsigned tx carried non-empty scriptSigs or witnesses.
    #[error("Unsigned tx has non-empty scriptSigs")]
    NonEmptyScriptSig,
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

/// Whether a BIP174 key type takes mandatory keydata (`Keydata`),
/// forbids it (`NoKeydata`), or is unknown (`Any`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeydataRule {
    /// Keydata must be empty.
    NoKeydata,
    /// Keydata must be present (minimum length given).
    Keydata(usize),
    /// Type unrecognized — any keydata accepted.
    Any,
}

/// Core's `CheckKeyTypeAndKeyData` tables, one per map scope.
fn global_key_rule(key_type: u8) -> KeydataRule {
    match key_type {
        Psbt::GLOBAL_TX => KeydataRule::NoKeydata,
        Psbt::GLOBAL_XPUB => KeydataRule::Keydata(78),
        Psbt::GLOBAL_TX_VERSION
        | Psbt::GLOBAL_FALLBACK_LOCKTIME
        | Psbt::GLOBAL_INPUT_COUNT
        | Psbt::GLOBAL_OUTPUT_COUNT
        | Psbt::GLOBAL_TX_MODIFIABLE
        | Psbt::GLOBAL_VERSION => KeydataRule::NoKeydata,
        Psbt::GLOBAL_PROPRIETARY => KeydataRule::Keydata(1),
        _ => KeydataRule::Any,
    }
}

fn input_key_rule(key_type: u8) -> KeydataRule {
    match key_type {
        Psbt::IN_PARTIAL_SIG | Psbt::IN_BIP32_DERIVATION => KeydataRule::Keydata(1),
        Psbt::IN_RIPEMD160 => KeydataRule::Keydata(20),
        Psbt::IN_SHA256 | Psbt::IN_HASH256 => KeydataRule::Keydata(32),
        Psbt::IN_HASH160 => KeydataRule::Keydata(20),
        Psbt::IN_TAP_SCRIPT_SIG => KeydataRule::Keydata(64),
        Psbt::IN_TAP_LEAF_SCRIPT => KeydataRule::Keydata(32),
        Psbt::IN_TAP_BIP32_DERIVATION => KeydataRule::Keydata(32),
        Psbt::IN_PROPRIETARY => KeydataRule::Keydata(1),
        _ if key_type <= 0x18 => KeydataRule::NoKeydata,
        _ => KeydataRule::Any,
    }
}

fn output_key_rule(key_type: u8) -> KeydataRule {
    match key_type {
        Psbt::OUT_BIP32_DERIVATION => KeydataRule::Keydata(1),
        Psbt::OUT_TAP_BIP32_DERIVATION => KeydataRule::Keydata(32),
        Psbt::OUT_PROPRIETARY => KeydataRule::Keydata(1),
        _ if key_type <= 0x07 => KeydataRule::NoKeydata,
        _ => KeydataRule::Any,
    }
}

/// The scope/name labels Core embeds in key-data errors.
fn global_key_name(key_type: u8) -> &'static str {
    match key_type {
        Psbt::GLOBAL_TX => "Global unsigned tx",
        Psbt::GLOBAL_XPUB => "Global xpub",
        Psbt::GLOBAL_TX_VERSION => "Global transaction version",
        Psbt::GLOBAL_FALLBACK_LOCKTIME => "Global fallback locktime",
        Psbt::GLOBAL_INPUT_COUNT => "Global inputs count",
        Psbt::GLOBAL_OUTPUT_COUNT => "Global outputs count",
        Psbt::GLOBAL_TX_MODIFIABLE => "Global tx modifiable",
        Psbt::GLOBAL_VERSION => "Global version",
        Psbt::GLOBAL_PROPRIETARY => "Global proprietary",
        _ => "Global unknown",
    }
}

fn input_key_name(key_type: u8) -> &'static str {
    match key_type {
        Psbt::IN_NON_WITNESS_UTXO => "Input non-witness utxo",
        Psbt::IN_WITNESS_UTXO => "Input witness utxo",
        Psbt::IN_PARTIAL_SIG => "Input partial sig",
        Psbt::IN_SIGHASH_TYPE => "Input sighash type",
        Psbt::IN_REDEEM_SCRIPT => "Input redeemScript",
        Psbt::IN_WITNESS_SCRIPT => "Input witnessScript",
        Psbt::IN_BIP32_DERIVATION => "Input keypath",
        Psbt::IN_FINAL_SCRIPTSIG => "Input final scriptSig",
        Psbt::IN_FINAL_SCRIPTWITNESS => "Input final scriptWitness",
        Psbt::IN_POR_COMMITMENT => "Input por commitment",
        Psbt::IN_RIPEMD160 => "Input ripemd160 hash",
        Psbt::IN_SHA256 => "Input sha256 hash",
        Psbt::IN_HASH160 => "Input hash160",
        Psbt::IN_HASH256 => "Input hash256",
        Psbt::IN_PREVIOUS_TXID => "Input previous txid",
        Psbt::IN_OUTPUT_INDEX => "Input output index",
        Psbt::IN_SEQUENCE => "Input sequence",
        Psbt::IN_REQUIRED_TIME_LOCKTIME => "Input required time-based locktime",
        Psbt::IN_REQUIRED_HEIGHT_LOCKTIME => "Input required height-based locktime",
        Psbt::IN_TAP_KEY_SIG => "Input taproot key path signature",
        Psbt::IN_TAP_SCRIPT_SIG => "Input taproot script path signature",
        Psbt::IN_TAP_LEAF_SCRIPT => "Input taproot leaf script",
        Psbt::IN_TAP_BIP32_DERIVATION => "Input taproot BIP32 derivation",
        Psbt::IN_TAP_INTERNAL_KEY => "Input taproot internal key",
        Psbt::IN_TAP_MERKLE_ROOT => "Input taproot merkle root",
        Psbt::IN_PROPRIETARY => "Input proprietary",
        _ => "Input unknown",
    }
}

fn output_key_name(key_type: u8) -> &'static str {
    match key_type {
        Psbt::OUT_REDEEM_SCRIPT => "Output redeemScript",
        Psbt::OUT_WITNESS_SCRIPT => "Output witnessScript",
        Psbt::OUT_BIP32_DERIVATION => "Output keypath",
        Psbt::OUT_AMOUNT => "Output amount",
        Psbt::OUT_SCRIPT => "Output script",
        Psbt::OUT_TAP_INTERNAL_KEY => "Output taproot internal key",
        Psbt::OUT_TAP_TREE => "Output taproot tree",
        Psbt::OUT_TAP_BIP32_DERIVATION => "Output taproot BIP32 derivation",
        Psbt::OUT_PROPRIETARY => "Output proprietary",
        _ => "Output unknown",
    }
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

/// Reads a key-value map terminated by `0x00`, validating keydata
/// rules and duplicates against `rule`/`name` for `scope`.
fn read_map(
    dec: &mut Decoder<'_>,
    scope: &'static str,
    rule: fn(u8) -> KeydataRule,
    name: fn(u8) -> &'static str,
) -> Result<KeyMap, PsbtError> {
    let mut map = KeyMap::default();
    let mut seen = std::collections::HashSet::new();
    loop {
        match read_key(dec)? {
            None => break,
            Some(key) => {
                let key_type = key[0];
                match rule(key_type) {
                    KeydataRule::NoKeydata if key.len() != 1 => {
                        return Err(PsbtError::KeyDataWrong(name(key_type)));
                    }
                    KeydataRule::Keydata(min) if key.len() - 1 < min => {
                        return Err(PsbtError::KeyDataWrong(name(key_type)));
                    }
                    _ => {}
                }
                if !seen.insert(key.clone()) {
                    return Err(PsbtError::DuplicateKey(scope));
                }
                let value = read_value(dec)?;
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
                        let key_type = key[0];
                        match global_key_rule(key_type) {
                            KeydataRule::NoKeydata if key.len() != 1 => {
                                return Err(PsbtError::KeyDataWrong(global_key_name(key_type)));
                            }
                            KeydataRule::Keydata(min) if key.len() - 1 < min => {
                                return Err(PsbtError::KeyDataWrong(global_key_name(key_type)));
                            }
                            _ => {}
                        }
                        if !seen.insert(key.clone()) {
                            return Err(PsbtError::DuplicateKey("global"));
                        }
                        let value = read_value(&mut dec)?;
                        map.pairs.push((key, value));
                    }
                }
            }
            map
        };
        let tx_bytes = global
            .get(Self::GLOBAL_TX)
            .ok_or(PsbtError::MissingUnsignedTx)?;
        if global.all(Self::GLOBAL_TX).count() > 1 {
            return Err(PsbtError::DuplicateUnsignedTx);
        }
        let tx = Transaction::decode_no_witness(tx_bytes).map_err(map_decode_err)?;
        if tx.inputs.iter().any(|i| !i.script_sig.is_empty()) {
            return Err(PsbtError::NonEmptyScriptSig);
        }
        // Per-input maps: an exhausted stream means a missing map —
        // Core reports the count mismatch, not a separator error.
        let mut inputs = Vec::with_capacity(tx.inputs.len());
        for _ in 0..tx.inputs.len() {
            if dec.is_finished() {
                break;
            }
            inputs.push(read_map(&mut dec, "input", input_key_rule, input_key_name)?);
        }
        if inputs.len() != tx.inputs.len() {
            return Err(PsbtError::InputCountMismatch);
        }
        let mut outputs = Vec::with_capacity(tx.outputs.len());
        for _ in 0..tx.outputs.len() {
            if dec.is_finished() {
                break;
            }
            outputs.push(read_map(
                &mut dec,
                "output",
                output_key_rule,
                output_key_name,
            )?);
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

    /// `joinpsbts` strips only signature/finalization input fields —
    /// utxos, scripts, derivations, and unknown keys survive.
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
            Psbt::IN_TAP_KEY_SIG,
            Psbt::IN_TAP_SCRIPT_SIG,
        ]);
        let types: Vec<u8> = m.pairs.iter().map(|(k, _)| k[0]).collect();
        assert_eq!(
            types,
            vec![Psbt::IN_WITNESS_UTXO, Psbt::IN_BIP32_DERIVATION, 0x60]
        );
    }
}

//! Signature solving over an empty `SigningProvider` — the pieces of
//! Core's `script/sign.cpp` and `psbt.cpp` that `analyzepsbt` and
//! `finalizepsbt` run: `FillSignatureData`, `ProduceSignature`
//! (`SignStep`), `SignPSBTInput`, and `PSBTInputSignedAndVerified`.
//!
//! Both RPCs sign with `DUMMY_SIGNING_PROVIDER` — every key, script,
//! and origin lookup fails — so only signatures and scripts already
//! present in the PSBT can satisfy an input. Two creators exist:
//! [`Creator::Real`] (a `MutableTransactionSignatureCreator` against
//! the empty provider: `CreateSig` always fails, recording
//! `missing_sigs`) and [`Creator::Dummy`] (`DUMMY_SIGNATURE_CREATOR`,
//! producing placeholder 71-byte ECDSA and 64-byte Schnorr signatures
//! for size estimation and finalization).
//!
//! Scope note: `SignStep` is ported for every standard script type.
//! For a P2WSH witness script or tapscript leaf that the legacy
//! solver cannot satisfy, Core additionally attempts a
//! `miniscript::FromScript` satisfaction; we implement the leaf
//! subset `pk(<key>)` (`<key> OP_CHECKSIG`) and treat other
//! miniscript-only scripts as unsatisfiable.

use std::collections::BTreeMap;

use crate::descriptor::FlatProvider;
use crate::hash::{hash160, sha256};
use crate::interpreter::{
    SigVersion, SignatureChecker, compute_tapbranch_hash, compute_tapleaf_hash, verify_script,
};
use crate::psbt::{KeyMap, Psbt};
use crate::script::ScriptType;
use crate::sigchecker::{PrecomputedTransactionData, TransactionSignatureChecker};
use crate::transaction::{Script, Transaction, TxOut, Witness};
use sha2::{Digest, Sha256};

/// `SIGHASH_ALL`.
pub const SIGHASH_ALL: u32 = 1;
/// `WITNESS_SCALE_FACTOR`.
const WITNESS_SCALE_FACTOR: u64 = 4;
/// `nBytesPerSigOp` — standard policy's sigop-to-weight ratio.
const BYTES_PER_SIGOP: u64 = 20;
/// `MAX_MONEY` — Core's `MoneyRange` bound.
const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

/// `STANDARD_SCRIPT_VERIFY_FLAGS` — the fixed policy flag set Core's
/// PSBT paths verify against (not the height-dependent block set).
fn standard_flags() -> crate::script::ScriptFlags {
    use crate::script::ScriptFlags as F;
    F::P2SH
        .union(F::DERSIG)
        .union(F::NULLDUMMY)
        .union(F::CHECKLOCKTIMEVERIFY)
        .union(F::CHECKSEQUENCEVERIFY)
        .union(F::WITNESS)
        .union(F::TAPROOT)
        .union(F::STRICTENC)
        .union(F::MINIMALDATA)
        .union(F::DISCOURAGE_UPGRADABLE_NOPS)
        .union(F::CLEANSTACK)
        .union(F::MINIMALIF)
        .union(F::NULLFAIL)
        .union(F::LOW_S)
        .union(F::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
        .union(F::WITNESS_PUBKEYTYPE)
        .union(F::CONST_SCRIPTCODE)
        .union(F::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION)
        .union(F::DISCOURAGE_OP_SUCCESS)
        .union(F::DISCOURAGE_UPGRADABLE_PUBKEYTYPE)
}

/// Which `BaseSignatureCreator` a pass runs — the provider is always
/// empty, so the only difference is what happens when no signature is
/// already available for a key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Creator {
    /// `MutableTransactionSignatureCreator` + empty provider: creating
    /// a signature always fails and records `missing_sigs`.
    Real,
    /// `DUMMY_SIGNATURE_CREATOR`: 71-byte ECDSA / 64-byte Schnorr
    /// placeholders, no key needed.
    Dummy,
}

/// `taproot_misc_pubkeys` entry — `(leaf hashes, origin value)`.
pub type TapMiscEntry = (Vec<[u8; 32]>, Vec<u8>);

/// `SignatureData` — the subset of Core's `script/sign.h` struct the
/// empty-provider flow can populate. `missing_redeem_script` /
/// `missing_witness_script` are `Option`s standing in for
/// `IsNull()`-able `uint160`/`uint256`s.
#[derive(Default)]
pub struct SignatureData {
    /// `complete` — a final script set satisfied the output.
    pub complete: bool,
    /// `witness` — a witness program was involved (drives
    /// `require_witness_sig` in `sign_psbt_input`).
    pub witness: bool,
    /// `scriptSig`.
    pub script_sig: Vec<u8>,
    /// `scriptWitness` — `None` is `IsNull` (unset), distinct from an
    /// empty stack.
    pub script_witness: Option<Vec<Vec<u8>>>,
    /// `redeem_script`.
    pub redeem_script: Option<Vec<u8>>,
    /// `witness_script`.
    pub witness_script: Option<Vec<u8>>,
    /// `signatures` — `CKeyID → (pubkey, sig)` (PSBT partial sigs are
    /// stored by pubkey keydata; internally keyed by hash160).
    pub signatures: BTreeMap<[u8; 20], (Vec<u8>, Vec<u8>)>,
    /// `misc_pubkeys` — `CKeyID → (pubkey, origin-info value bytes)`.
    pub misc_pubkeys: BTreeMap<[u8; 20], (Vec<u8>, Vec<u8>)>,
    /// `tap_pubkeys` — `CKeyID → x-only pubkey`.
    pub tap_pubkeys: BTreeMap<[u8; 20], [u8; 32]>,
    /// `missing_pubkeys` — keyids with no derivation info.
    pub missing_pubkeys: Vec<[u8; 20]>,
    /// `missing_sigs` — keyids whose signature could not be made.
    pub missing_sigs: Vec<[u8; 20]>,
    /// `missing_redeem_script` — hash160 of the wanted P2SH script.
    pub missing_redeem_script: Option<[u8; 20]>,
    /// `missing_witness_script` — sha256 of the wanted WSH script.
    pub missing_witness_script: Option<[u8; 32]>,
    /// `taproot_key_path_sig`.
    pub taproot_key_path_sig: Vec<u8>,
    /// `taproot_script_sigs` — `(xonly, leaf_hash) → sig`.
    pub taproot_script_sigs: BTreeMap<([u8; 32], [u8; 32]), Vec<u8>>,
    /// `tr_spenddata.internal_key` — `None` for a null `XOnlyPubKey`.
    pub tr_internal_key: Option<[u8; 32]>,
    /// `tr_spenddata.merkle_root`.
    pub tr_merkle_root: Option<[u8; 32]>,
    /// `tr_spenddata.scripts` — `(script, leaf_ver) → control blocks`,
    /// each block list kept shortest-first like Core's
    /// `ShortestVectorFirstComparator`.
    pub tr_scripts: BTreeMap<(Vec<u8>, u8), Vec<Vec<u8>>>,
    /// `tr_builder` leaves as `(depth, leaf_ver, script)` tuples —
    /// set from the provider's taproot tree; written back to an
    /// output's `OUT_TAP_TREE` when scripts are present.
    pub tr_tree: Option<Vec<(u8, u8, Vec<u8>)>>,
    /// `taproot_misc_pubkeys` — `xonly → (leaf hashes, origin value)`.
    pub tap_misc: BTreeMap<[u8; 32], TapMiscEntry>,
    /// Hash-preimage maps (`ripemd160`/`sha256`/`hash160`/`hash256`).
    pub preimages: [BTreeMap<Vec<u8>, Vec<u8>>; 4],
}

impl SignatureData {
    /// `PSBTInput::FillSignatureData`.
    pub fn fill_from_input(&mut self, map: &KeyMap) {
        if let Some(v) = map.get(Psbt::IN_FINAL_SCRIPTSIG) {
            self.script_sig = v.to_vec();
            self.complete = true;
        }
        if let Some(v) = map.get(Psbt::IN_FINAL_SCRIPTWITNESS)
            && let Some(stack) = decode_witness_stack(v)
        {
            self.script_witness = Some(stack);
            self.complete = true;
        }
        if self.complete {
            return;
        }
        for (pubkey, sig) in map.all(Psbt::IN_PARTIAL_SIG) {
            self.signatures
                .insert(hash160(pubkey), (pubkey.to_vec(), sig.to_vec()));
        }
        if let Some(v) = map.get(Psbt::IN_REDEEM_SCRIPT) {
            self.redeem_script = Some(v.to_vec());
        }
        if let Some(v) = map.get(Psbt::IN_WITNESS_SCRIPT) {
            self.witness_script = Some(v.to_vec());
        }
        for (pubkey, origin) in map.all(Psbt::IN_BIP32_DERIVATION) {
            self.misc_pubkeys
                .insert(hash160(pubkey), (pubkey.to_vec(), origin.to_vec()));
        }
        if let Some(v) = map.get(Psbt::IN_TAP_KEY_SIG) {
            self.taproot_key_path_sig = v.to_vec();
        }
        for (keydata, sig) in map.all(Psbt::IN_TAP_SCRIPT_SIG) {
            if keydata.len() == 64 {
                let mut xonly = [0u8; 32];
                let mut leaf = [0u8; 32];
                xonly.copy_from_slice(&keydata[..32]);
                leaf.copy_from_slice(&keydata[32..]);
                self.taproot_script_sigs.insert((xonly, leaf), sig.to_vec());
            }
        }
        if let Some(v) = map.get(Psbt::IN_TAP_INTERNAL_KEY)
            && v.len() == 32
        {
            let mut k = [0u8; 32];
            k.copy_from_slice(v);
            self.tr_internal_key = Some(k);
        }
        if let Some(v) = map.get(Psbt::IN_TAP_MERKLE_ROOT)
            && v.len() == 32
        {
            let mut r = [0u8; 32];
            r.copy_from_slice(v);
            self.tr_merkle_root = Some(r);
        }
        for (control, v) in map.all(Psbt::IN_TAP_LEAF_SCRIPT) {
            if v.is_empty() {
                continue;
            }
            let (script, ver) = v.split_at(v.len() - 1);
            let blocks = self
                .tr_scripts
                .entry((script.to_vec(), ver[0]))
                .or_default();
            // ShortestVectorFirstComparator: length, then bytes.
            let pos = blocks
                .iter()
                .position(|b| (b.len(), b.as_slice()) > (control.len(), control));
            blocks.insert(pos.unwrap_or(blocks.len()), control.to_vec());
        }
        for (xonly, v) in map.all(Psbt::IN_TAP_BIP32_DERIVATION) {
            let Some((leaves, origin)) = parse_tap_bip32_value(v) else {
                continue;
            };
            if xonly.len() != 32 {
                continue;
            }
            let mut xk = [0u8; 32];
            xk.copy_from_slice(xonly);
            self.tap_misc.insert(xk, (leaves, origin));
            self.tap_pubkeys.insert(hash160(&xk), xk);
        }
        const PREIMAGE_TYPES: [u8; 4] = [
            Psbt::IN_RIPEMD160,
            Psbt::IN_SHA256,
            Psbt::IN_HASH160,
            Psbt::IN_HASH256,
        ];
        for (i, t) in PREIMAGE_TYPES.iter().enumerate() {
            for (hash, preimage) in map.all(*t) {
                self.preimages[i].insert(hash.to_vec(), preimage.to_vec());
            }
        }
    }

    /// `PSBTInput::FromSignatureData` — write the solved fields back
    /// into the input's key-map (final scripts on complete, otherwise
    /// merge signatures/scripts/derivations).
    pub fn store_into_input(&self, map: &mut KeyMap) {
        if self.complete {
            map.remove_types(&[
                Psbt::IN_PARTIAL_SIG,
                Psbt::IN_BIP32_DERIVATION,
                Psbt::IN_REDEEM_SCRIPT,
                Psbt::IN_WITNESS_SCRIPT,
            ]);
            if !self.script_sig.is_empty() {
                map.set(vec![Psbt::IN_FINAL_SCRIPTSIG], self.script_sig.clone());
            }
            if let Some(stack) = &self.script_witness {
                map.set(
                    vec![Psbt::IN_FINAL_SCRIPTWITNESS],
                    encode_witness_stack(stack),
                );
            }
            return;
        }
        for (pubkey, sig) in self.signatures.values() {
            let mut key = vec![Psbt::IN_PARTIAL_SIG];
            key.extend_from_slice(pubkey);
            if !map.contains(&key) {
                map.set(key, sig.clone());
            }
        }
        if let Some(script) = &self.redeem_script
            && map.get(Psbt::IN_REDEEM_SCRIPT).is_none()
        {
            map.set(vec![Psbt::IN_REDEEM_SCRIPT], script.clone());
        }
        if let Some(script) = &self.witness_script
            && map.get(Psbt::IN_WITNESS_SCRIPT).is_none()
        {
            map.set(vec![Psbt::IN_WITNESS_SCRIPT], script.clone());
        }
        for (pubkey, origin) in self.misc_pubkeys.values() {
            let mut key = vec![Psbt::IN_BIP32_DERIVATION];
            key.extend_from_slice(pubkey);
            if !map.contains(&key) {
                map.set(key, origin.clone());
            }
        }
        if !self.taproot_key_path_sig.is_empty() {
            map.set(
                vec![Psbt::IN_TAP_KEY_SIG],
                self.taproot_key_path_sig.clone(),
            );
        }
        for ((xonly, leaf), sig) in &self.taproot_script_sigs {
            let mut key = vec![Psbt::IN_TAP_SCRIPT_SIG];
            key.extend_from_slice(xonly);
            key.extend_from_slice(leaf);
            if !map.contains(&key) {
                map.set(key, sig.clone());
            }
        }
        if let Some(k) = self.tr_internal_key {
            map.set(vec![Psbt::IN_TAP_INTERNAL_KEY], k.to_vec());
        }
        if let Some(r) = self.tr_merkle_root {
            map.set(vec![Psbt::IN_TAP_MERKLE_ROOT], r.to_vec());
        }
        for ((script, ver), blocks) in &self.tr_scripts {
            let mut value = script.clone();
            value.push(*ver);
            for control in blocks {
                let mut key = vec![Psbt::IN_TAP_LEAF_SCRIPT];
                key.extend_from_slice(control);
                if !map.contains(&key) {
                    map.set(key, value.clone());
                }
            }
        }
        for (xonly, (leaves, origin)) in &self.tap_misc {
            let mut key = vec![Psbt::IN_TAP_BIP32_DERIVATION];
            key.extend_from_slice(xonly);
            let mut value = Vec::new();
            crate::encode::write_compact_size(&mut value, leaves.len() as u64);
            for h in leaves {
                value.extend_from_slice(h);
            }
            value.extend_from_slice(origin);
            if !map.contains(&key) {
                map.set(key, value);
            }
        }
    }

    /// `PSBTOutput::FillSignatureData` — output maps carry scripts,
    /// derivations, and the taproot tree (which rebuilds spend data
    /// when an internal key is present).
    pub fn fill_from_output(&mut self, map: &KeyMap) {
        if let Some(v) = map.get(Psbt::OUT_REDEEM_SCRIPT) {
            self.redeem_script = Some(v.to_vec());
        }
        if let Some(v) = map.get(Psbt::OUT_WITNESS_SCRIPT) {
            self.witness_script = Some(v.to_vec());
        }
        for (pubkey, origin) in map.all(Psbt::OUT_BIP32_DERIVATION) {
            self.misc_pubkeys
                .insert(hash160(pubkey), (pubkey.to_vec(), origin.to_vec()));
        }
        if let (Some(tree), Some(internal)) = (
            map.get(Psbt::OUT_TAP_TREE),
            map.get(Psbt::OUT_TAP_INTERNAL_KEY).and_then(|v| {
                (v.len() == 32).then(|| {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(v);
                    k
                })
            }),
        ) {
            let mut builder = TaprootTreeBuilder::new();
            let mut dec = crate::encode::Decoder::new(tree);
            while !dec.is_finished() {
                let (Ok(d), Ok(ver), Ok(script)) = (
                    dec.read_u8(),
                    dec.read_u8(),
                    dec.read_var_bytes().map(|s| s.to_vec()),
                ) else {
                    break;
                };
                builder.add(d, &script, ver);
            }
            if builder.is_complete()
                && let Some(spend) = builder.spend_data(internal)
            {
                self.tr_internal_key = Some(internal);
                self.merge_spend_scripts(spend.0);
                if self.tr_merkle_root.is_none() {
                    self.tr_merkle_root = spend.1;
                }
            }
        }
        for (xonly, v) in map.all(Psbt::OUT_TAP_BIP32_DERIVATION) {
            let Some((leaves, origin)) = parse_tap_bip32_value(v) else {
                continue;
            };
            if xonly.len() != 32 {
                continue;
            }
            let mut xk = [0u8; 32];
            xk.copy_from_slice(xonly);
            self.tap_misc.insert(xk, (leaves, origin));
            self.tap_pubkeys.insert(hash160(&xk), xk);
        }
    }

    /// `PSBTOutput::FromSignatureData` — merge-only writes: existing
    /// fields are never overwritten.
    pub fn store_into_output(&self, map: &mut KeyMap) {
        if let Some(script) = &self.redeem_script
            && map.get(Psbt::OUT_REDEEM_SCRIPT).is_none()
        {
            map.set(vec![Psbt::OUT_REDEEM_SCRIPT], script.clone());
        }
        if let Some(script) = &self.witness_script
            && map.get(Psbt::OUT_WITNESS_SCRIPT).is_none()
        {
            map.set(vec![Psbt::OUT_WITNESS_SCRIPT], script.clone());
        }
        for (pubkey, origin) in self.misc_pubkeys.values() {
            let mut key = vec![Psbt::OUT_BIP32_DERIVATION];
            key.extend_from_slice(pubkey);
            if !map.contains(&key) {
                map.set(key, origin.clone());
            }
        }
        if let Some(k) = self.tr_internal_key
            && map.get(Psbt::OUT_TAP_INTERNAL_KEY).is_none()
        {
            map.set(vec![Psbt::OUT_TAP_INTERNAL_KEY], k.to_vec());
        }
        if let Some(tree) = &self.tr_tree
            && !tree.is_empty()
            && map.get(Psbt::OUT_TAP_TREE).is_none()
        {
            let mut v = Vec::new();
            for (depth, ver, script) in tree {
                v.push(*depth);
                v.push(*ver);
                crate::encode::write_var_bytes(&mut v, script);
            }
            map.set(vec![Psbt::OUT_TAP_TREE], v);
        }
        for (xonly, (leaves, origin)) in &self.tap_misc {
            let mut key = vec![Psbt::OUT_TAP_BIP32_DERIVATION];
            key.extend_from_slice(xonly);
            let mut value = Vec::new();
            crate::encode::write_compact_size(&mut value, leaves.len() as u64);
            for h in leaves {
                value.extend_from_slice(h);
            }
            value.extend_from_slice(origin);
            if !map.contains(&key) {
                map.set(key, value);
            }
        }
    }

    /// `TaprootSpendData::Merge` — keep the existing internal key and
    /// merkle root, union the script→control-blocks map.
    fn merge_spend_scripts(&mut self, scripts: BTreeMap<(Vec<u8>, u8), Vec<Vec<u8>>>) {
        for ((script, ver), blocks) in scripts {
            let dst = self.tr_scripts.entry((script, ver)).or_default();
            for block in blocks {
                if !dst.contains(&block) {
                    let pos = dst
                        .iter()
                        .position(|b| (b.len(), b.as_slice()) > (block.len(), block.as_slice()));
                    dst.insert(pos.unwrap_or(dst.len()), block);
                }
            }
        }
    }

    /// `provider.GetTaprootSpendData`/`GetTaprootBuilder` merge —
    /// internal key and merkle root attach, leaves become control
    /// blocks, and the tree tuples are kept for `OUT_TAP_TREE`.
    fn merge_tr_spend(&mut self, spend: &crate::descriptor::TaprootSpendData) {
        // `IsNull()` — an all-zero key/root counts as unset in Core.
        if self.tr_internal_key.is_none_or(|k| k == [0; 32]) {
            self.tr_internal_key = Some(spend.internal_key);
        }
        if self.tr_merkle_root.is_none_or(|r| r == [0; 32]) {
            self.tr_merkle_root = spend.merkle_root;
        }
        let mut builder = TaprootTreeBuilder::new();
        for (depth, script, ver) in &spend.leaves {
            builder.add(*depth as u8, script, *ver);
        }
        if let Some((scripts, _)) = builder
            .is_complete()
            .then(|| builder.spend_data(spend.internal_key))
            .flatten()
        {
            self.merge_spend_scripts(scripts);
            self.tr_tree = Some(
                spend
                    .leaves
                    .iter()
                    .map(|(d, s, v)| (*d as u8, *v, s.clone()))
                    .collect(),
            );
        }
    }
}

/// The final-script-witness value: a CompactSize item count followed
/// by that many var-bytes stack items (`CScriptWitness` serialization).
pub fn decode_witness_stack(v: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut dec = crate::encode::Decoder::new(v);
    let count = dec.read_compact_size().ok()?;
    let mut stack = Vec::new();
    for _ in 0..count {
        stack.push(dec.read_var_bytes().ok()?.to_vec());
    }
    if dec.remaining() != 0 {
        return None;
    }
    Some(stack)
}

/// Serialize a witness stack into the PSBT final-scriptWitness value.
pub fn encode_witness_stack(stack: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    crate::encode::write_compact_size(&mut out, stack.len() as u64);
    for item in stack {
        crate::encode::write_var_bytes(&mut out, item);
    }
    out
}

/// `PartiallySignedTransaction::GetInputUTXO` — `non_witness_utxo`
/// takes precedence and must match the prevout; otherwise
/// `witness_utxo` when present.
pub fn get_input_utxo(psbt: &Psbt, index: usize) -> Option<TxOut> {
    let input = psbt.inputs.get(index)?;
    let prevout = &psbt.tx.inputs.get(index)?.previous_output;
    if let Some(raw) = input.get(Psbt::IN_NON_WITNESS_UTXO) {
        let tx = Transaction::decode(raw).ok()?;
        if prevout.vout as usize >= tx.outputs.len() {
            return None;
        }
        if tx.txid() != prevout.txid {
            return None;
        }
        Some(tx.outputs[prevout.vout as usize].clone())
    } else if let Some(raw) = input.get(Psbt::IN_WITNESS_UTXO) {
        // witness_utxo is a bare CTxOut: value i64le + varbytes spk.
        let mut dec = crate::encode::Decoder::new(raw);
        let value = dec.read_i64_le().ok()?;
        let spk = dec.read_var_bytes().ok()?;
        Some(TxOut {
            value,
            script_pubkey: Script::new(spk.to_vec()),
        })
    } else {
        None
    }
}

/// `PrecomputePSBTData` — midstate caches over every spendable output
/// when all are known, else with missing-data-fail semantics.
pub fn precompute_psbt_data(psbt: &Psbt) -> PrecomputedTransactionData {
    let mut utxos = Vec::with_capacity(psbt.tx.inputs.len());
    let mut all = true;
    for i in 0..psbt.tx.inputs.len() {
        match get_input_utxo(psbt, i) {
            Some(u) => utxos.push(u),
            None => {
                all = false;
                break;
            }
        }
    }
    if all {
        PrecomputedTransactionData::new(&psbt.tx, Some(utxos), true)
    } else {
        PrecomputedTransactionData::new(&psbt.tx, None, true)
    }
}

/// `PSBTInputSignedAndVerified` — the input's final scripts exist and
/// verify against its UTXO under the standard flags.
pub fn psbt_input_signed_and_verified(
    psbt: &Psbt,
    index: usize,
    txdata: &PrecomputedTransactionData,
) -> bool {
    let Some(utxo) = get_input_utxo(psbt, index) else {
        return false;
    };
    let map = &psbt.inputs[index];
    let script_sig = map
        .get(Psbt::IN_FINAL_SCRIPTSIG)
        .map_or_else(Vec::new, |v| v.to_vec());
    let witness = map
        .get(Psbt::IN_FINAL_SCRIPTWITNESS)
        .and_then(decode_witness_stack);
    let checker = TransactionSignatureChecker::new(&psbt.tx, index, utxo.value, txdata);
    verify_script(
        &Script::new(script_sig),
        &utxo.script_pubkey,
        witness.map(Witness::new).as_ref(),
        standard_flags(),
        &checker,
    )
    .is_ok()
}

/// `TaprootBuilder` — tracks each leaf's merkle branch while merging
/// DFS-ordered `(depth, script, leaf_version)` leaves up to the root,
/// then `spend_data` produces the control blocks Core's
/// `GetSpendData` emits.
#[derive(Default)]
pub struct TaprootTreeBuilder {
    /// `m_valid` — cleared when a leaf breaks DFS order or a depth-0
    /// combine would exceed the root. Core inits `true`; `Default`
    /// is overridden below.
    valid: bool,
    /// `branch[d]` = merged node awaiting its sibling at depth `d`.
    branch: Vec<Option<TapNode>>,
    parity: bool,
}

impl TaprootTreeBuilder {
    pub fn new() -> Self {
        TaprootTreeBuilder {
            valid: true,
            branch: Vec::new(),
            parity: false,
        }
    }
}

struct TapLeaf {
    script: Vec<u8>,
    leaf_ver: u8,
    /// Sibling hashes on the path from this leaf to the node.
    branch: Vec<[u8; 32]>,
}

struct TapNode {
    hash: [u8; 32],
    leaves: Vec<TapLeaf>,
}

impl TaprootTreeBuilder {
    /// `Add` — hash the leaf, `Insert` at `depth`.
    pub fn add(&mut self, depth: u8, script: &[u8], leaf_ver: u8) {
        if !self.valid {
            return;
        }
        let node = TapNode {
            hash: compute_tapleaf_hash(leaf_ver, script),
            leaves: vec![TapLeaf {
                script: script.to_vec(),
                leaf_ver,
                branch: Vec::new(),
            }],
        };
        self.insert(node, depth as usize);
    }

    /// `Insert` — see `psbt::check_tap_tree` for the depth rules.
    fn insert(&mut self, mut node: TapNode, mut depth: usize) {
        if depth + 1 < self.branch.len() {
            self.valid = false;
            return;
        }
        while self.valid && self.branch.len() > depth && self.branch[depth].is_some() {
            let other = self.branch.pop().flatten().expect("checked");
            node = combine_nodes(node, other);
            if depth == 0 {
                self.valid = false;
                break;
            }
            depth -= 1;
        }
        if self.valid {
            while self.branch.len() <= depth {
                self.branch.push(None);
            }
            self.branch[depth] = Some(node);
        }
    }

    /// `IsComplete` — single root at depth 0 (or an untouched builder).
    pub fn is_complete(&self) -> bool {
        self.valid
            && (self.branch.is_empty() || (self.branch.len() == 1 && self.branch[0].is_some()))
    }

    /// `Finalize` + `GetSpendData` — tweak the internal key against the
    /// root and emit `(script, leaf_ver) → control blocks` plus the
    /// merkle root. `None` when the tree is incomplete or the tweak
    /// fails.
    pub fn spend_data(
        &mut self,
        internal_key: [u8; 32],
    ) -> Option<(BTreeMap<(Vec<u8>, u8), Vec<Vec<u8>>>, Option<[u8; 32]>)> {
        if !self.is_complete() {
            return None;
        }
        let root = self.branch.first().and_then(|n| n.as_ref());
        // `CreateTapTweak` — `TapTweak(internal || merkle_root)`, the
        // root omitted entirely for a key-path-only builder.
        let tag = sha256(b"TapTweak");
        let mut h = Sha256::new();
        h.update(&tag);
        h.update(&tag);
        h.update(&internal_key);
        if let Some(n) = root {
            h.update(&n.hash);
        }
        let tweak: [u8; 32] = h.finalize().into();
        let internal = secp256k1::XOnlyPublicKey::from_slice(&internal_key).ok()?;
        let tweak = secp256k1::Scalar::from_be_bytes(tweak).ok()?;
        let (_out, parity) = internal
            .add_tweak(&secp256k1::Secp256k1::verification_only(), &tweak)
            .ok()?;
        self.parity = parity == secp256k1::Parity::Odd;
        let mut scripts: BTreeMap<(Vec<u8>, u8), Vec<Vec<u8>>> = BTreeMap::new();
        if let Some(n) = root {
            for leaf in &n.leaves {
                let mut control = Vec::with_capacity(33 + 32 * leaf.branch.len());
                control.push(leaf.leaf_ver | u8::from(self.parity));
                control.extend_from_slice(&internal_key);
                for node in &leaf.branch {
                    control.extend_from_slice(node);
                }
                let entry = scripts
                    .entry((leaf.script.clone(), leaf.leaf_ver))
                    .or_default();
                if !entry.contains(&control) {
                    entry.push(control);
                }
            }
        }
        Some((scripts, root.map(|n| n.hash)))
    }
}

/// `TaprootBuilder::Combine` — `a`'s leaves gain `b`'s hash and vice
/// versa; the node hash is the sorted branch hash.
fn combine_nodes(a: TapNode, b: TapNode) -> TapNode {
    let mut leaves = Vec::with_capacity(a.leaves.len() + b.leaves.len());
    for mut leaf in a.leaves {
        leaf.branch.push(b.hash);
        leaves.push(leaf);
    }
    for mut leaf in b.leaves {
        leaf.branch.push(a.hash);
        leaves.push(leaf);
    }
    TapNode {
        hash: compute_tapbranch_hash(&a.hash, &b.hash),
        leaves,
    }
}

/// `GetCScript` — the PSBT-carried redeem/witness scripts first, then
/// the provider's script map.
fn get_cscript(
    sigdata: &SignatureData,
    scriptid: &[u8; 20],
    provider: &FlatProvider,
) -> Option<Vec<u8>> {
    if let Some(script) = &sigdata.redeem_script
        && hash160(script) == *scriptid
    {
        return Some(script.clone());
    }
    if let Some(script) = &sigdata.witness_script
        && hash160(script) == *scriptid
    {
        return Some(script.clone());
    }
    provider.scripts.get(scriptid).cloned()
}

/// `GetPubKey` — partial-sig keydata, BIP32-derivation keydata,
/// taproot pubkeys (even-Y form), then the provider's pubkey map.
fn get_pubkey(
    sigdata: &SignatureData,
    keyid: &[u8; 20],
    provider: &FlatProvider,
) -> Option<Vec<u8>> {
    if let Some((pubkey, _)) = sigdata.signatures.get(keyid) {
        return Some(pubkey.clone());
    }
    if let Some((pubkey, _)) = sigdata.misc_pubkeys.get(keyid) {
        return Some(pubkey.clone());
    }
    if let Some(xonly) = sigdata.tap_pubkeys.get(keyid) {
        // XOnlyPubKey::GetEvenCorrespondingCPubKey
        let mut cpk = Vec::with_capacity(33);
        cpk.push(0x02);
        cpk.extend_from_slice(xonly);
        return Some(cpk);
    }
    provider.pubkeys.get(keyid).cloned()
}

/// The tap-bip32 value body: `CompactSize(leafcount) || leafhashes
/// || fingerprint || path elements` — Core's `SerializeToVector` with
/// a `std::set<uint256>` then `SerializeHDKeypath`.
fn parse_tap_bip32_value(v: &[u8]) -> Option<(Vec<[u8; 32]>, Vec<u8>)> {
    let mut dec = crate::encode::Decoder::new(v);
    let leaf_count = dec.read_compact_size().ok()? as usize;
    let mut leaves = Vec::with_capacity(leaf_count.min(64));
    for _ in 0..leaf_count {
        let mut h = [0u8; 32];
        h.copy_from_slice(dec.read_bytes(32).ok()?);
        leaves.push(h);
    }
    Some((leaves, v[dec.position()..].to_vec()))
}

/// `GetKeyOrigin` — the provider's `keyid → (pubkey, origin)` map;
/// the returned origin is encoded as a PSBT derivation value.
fn get_key_origin(provider: &FlatProvider, keyid: &[u8; 20]) -> Option<Vec<u8>> {
    let (_, (fp, path)) = provider.origins.get(keyid)?;
    Some(key_origin_value(fp, path))
}

/// `GetKeyOriginByXOnly` — scan origins for the key whose x-coordinate
/// matches (compressed and uncompressed keys share `key[1..33]`).
fn get_key_origin_by_xonly(provider: &FlatProvider, xonly: &[u8; 32]) -> Option<Vec<u8>> {
    provider.origins.values().find_map(|(pk, (fp, path))| {
        (pk.len() >= 33 && pk[1..33] == xonly[..]).then(|| key_origin_value(fp, path))
    })
}

/// `SerializeHDKeypath` — `fingerprint || path elements` little-endian.
fn key_origin_value(fp: &[u8; 4], path: &[u32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 4 * path.len());
    v.extend_from_slice(fp);
    for p in path {
        v.extend_from_slice(&p.to_le_bytes());
    }
    v
}

/// `DummySignatureCreator`'s ECDSA output: a DER-valid 71-byte sig —
/// `30 44 02 20 01 00… 02 20 01 00… 01` (R and S lead with 0x01 so
/// strict encoding accepts them).
fn dummy_ecdsa_sig() -> Vec<u8> {
    let mut sig = vec![0u8; 71];
    sig[0] = 0x30;
    sig[1] = 68;
    sig[2] = 0x02;
    sig[3] = 32;
    sig[4] = 0x01;
    sig[36] = 0x02;
    sig[37] = 32;
    sig[38] = 0x01;
    sig[70] = 1;
    sig
}

/// `CreateSig` — reuse an existing partial sig, else attach the
/// provider's key origin and create through the pass's creator.
/// `Real` failures record `missing_sigs`.
fn create_sig(
    sigdata: &mut SignatureData,
    pubkey: &[u8],
    mode: Creator,
    provider: &FlatProvider,
) -> Option<Vec<u8>> {
    let keyid = hash160(pubkey);
    if let Some((_, sig)) = sigdata.signatures.get(&keyid) {
        return Some(sig.clone());
    }
    if let Some(origin) = get_key_origin(provider, &keyid) {
        sigdata
            .misc_pubkeys
            .insert(keyid, (pubkey.to_vec(), origin));
    }
    match mode {
        Creator::Dummy => {
            let sig = dummy_ecdsa_sig();
            sigdata
                .signatures
                .insert(keyid, (pubkey.to_vec(), sig.clone()));
            Some(sig)
        }
        Creator::Real => {
            sigdata.missing_sigs.push(keyid);
            None
        }
    }
}

/// `CreateTaprootScriptSig` — a `(xonly, leaf_hash)`-keyed schnorr sig;
/// the provider's x-only key origin is attached to
/// `taproot_misc_pubkeys` before the sig lookup.
/// Real-mode failures are silent (taproot has no `missing_sigs` entry).
fn create_taproot_script_sig(
    sigdata: &mut SignatureData,
    xonly: &[u8; 32],
    leaf_hash: &[u8; 32],
    mode: Creator,
    provider: &FlatProvider,
) -> Option<Vec<u8>> {
    // Core emplaces the entry before the sig lookup — with no origin
    // the value serializes as `leafcount || leaves || 00000000`.
    let entry = sigdata
        .tap_misc
        .entry(*xonly)
        .or_insert_with(|| (Vec::new(), vec![0; 4]));
    if let Some(origin) = get_key_origin_by_xonly(provider, xonly) {
        entry.1 = origin;
    }
    if !entry.0.contains(leaf_hash) {
        // std::set<uint256> — ordered by the stored bytes.
        entry.0.push(*leaf_hash);
        entry.0.sort();
    }
    if let Some(sig) = sigdata.taproot_script_sigs.get(&(*xonly, *leaf_hash)) {
        return Some(sig.clone());
    }
    match mode {
        Creator::Dummy => {
            let sig = vec![0u8; 64];
            sigdata
                .taproot_script_sigs
                .insert((*xonly, *leaf_hash), sig.clone());
            Some(sig)
        }
        Creator::Real => None,
    }
}

/// `creator.CreateSchnorrSig` for the key path — a 64-byte sig, no
/// missing recording (real mode: the empty provider has no key).
fn create_schnorr_keypath(mode: Creator) -> Option<Vec<u8>> {
    match mode {
        Creator::Dummy => Some(vec![0u8; 64]),
        Creator::Real => None,
    }
}

/// `CScript::PushAll` — OP_0 for empty items, OP_1..16/OP_1NEGATE for
/// single-byte numbers, pushdata otherwise.
fn push_all(values: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in values {
        if v.is_empty() {
            out.push(0x00);
        } else if v.len() == 1 && (1..=16).contains(&v[0]) {
            out.push(0x50 + v[0]);
        } else if v.len() == 1 && v[0] == 0x81 {
            out.push(0x4f);
        } else {
            crate::encode::write_var_bytes(&mut out, v);
        }
    }
    out
}

/// The leaf subset we can satisfy without miniscript: `pk(key)` —
/// `<32B xonly> OP_CHECKSIG` (tapscript) or `<pubkey> OP_CHECKSIG`
/// (WSH). Returns the satisfaction stack.
fn satisfy_pk_leaf(
    script: &[u8],
    leaf_hash: Option<&[u8; 32]>,
    sigdata: &mut SignatureData,
    mode: Creator,
    provider: &FlatProvider,
) -> Option<Vec<Vec<u8>>> {
    if script.len() == 34 && script[0] == 0x20 && script[33] == 0xac {
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&script[1..33]);
        let sig = create_taproot_script_sig(sigdata, &xonly, leaf_hash?, mode, provider)?;
        return Some(vec![sig]);
    }
    None
}

/// `SignTaproot` — merge the provider's taproot spend data and builder
/// for this output key, sign the key path first, then the smallest
/// satisfying script-path leaf.
fn sign_taproot(
    output_key: &[u8; 32],
    sigdata: &mut SignatureData,
    mode: Creator,
    provider: &FlatProvider,
) -> Option<Vec<Vec<u8>>> {
    // GetTaprootSpendData + GetTaprootBuilder.
    if let Some(spend) = provider.tr_trees.get(output_key) {
        sigdata.merge_tr_spend(spend);
    }
    // Key path: the internal key's origin attaches, then internal key
    // first (may be null), then the output key.
    if let Some(internal) = sigdata.tr_internal_key
        && let Some(origin) = get_key_origin_by_xonly(provider, &internal)
    {
        sigdata
            .tap_misc
            .entry(internal)
            .or_insert((Vec::new(), origin));
    }
    if sigdata.taproot_key_path_sig.is_empty()
        && sigdata.tr_internal_key.is_some()
        && let Some(sig) = create_schnorr_keypath(mode)
    {
        sigdata.taproot_key_path_sig = sig;
    }
    if sigdata.taproot_key_path_sig.is_empty()
        && let Some(sig) = create_schnorr_keypath(mode)
    {
        sigdata.taproot_key_path_sig = sig;
    }
    if !sigdata.taproot_key_path_sig.is_empty() {
        return Some(vec![sigdata.taproot_key_path_sig.clone()]);
    }
    // Script path: every (script, leaf_ver) with its control blocks.
    let mut smallest: Option<Vec<Vec<u8>>> = None;
    for ((script, leaf_ver), control_blocks) in &sigdata.tr_scripts.clone() {
        if *leaf_ver != 0xc0 {
            continue;
        }
        let leaf_hash = compute_tapleaf_hash(*leaf_ver, script);
        if let Some(mut stack) = satisfy_pk_leaf(script, Some(&leaf_hash), sigdata, mode, provider)
        {
            stack.push(script.clone());
            stack.push(control_blocks[0].clone());
            let better = smallest
                .as_ref()
                .is_none_or(|s| serialized_len(&stack) < serialized_len(s));
            if better {
                smallest = Some(stack);
            }
        }
    }
    smallest
}

fn serialized_len(stack: &[Vec<u8>]) -> usize {
    stack.iter().map(|i| i.len() + 5).sum()
}

/// `SignStep` — solve one script level. Returns `(solved, result)`;
/// for SCRIPTHASH `result` carries the redeem script to recurse into.
fn sign_step(
    provider: &FlatProvider,
    script: &[u8],
    sigdata: &mut SignatureData,
    mode: Creator,
) -> (bool, Vec<Vec<u8>>, StepKind) {
    match Script::new(script.to_vec()).classify() {
        ScriptType::Nonstandard | ScriptType::NullData => (false, Vec::new(), StepKind::Other),
        ScriptType::Witness { version, program }
            if !matches!((version, program.len()), (0, 20) | (0, 32) | (1, 32)) =>
        {
            (false, Vec::new(), StepKind::Other)
        }
        ScriptType::PubKey(pubkey) => match create_sig(sigdata, &pubkey, mode, provider) {
            Some(sig) => (true, vec![sig], StepKind::Other),
            None => (false, Vec::new(), StepKind::Other),
        },
        ScriptType::PubKeyHash(h160) => {
            let Some(pubkey) = get_pubkey(sigdata, &h160, provider) else {
                sigdata.missing_pubkeys.push(h160);
                return (false, Vec::new(), StepKind::Other);
            };
            match create_sig(sigdata, &pubkey, mode, provider) {
                Some(sig) => (true, vec![sig, pubkey], StepKind::Other),
                None => (false, Vec::new(), StepKind::Other),
            }
        }
        ScriptType::ScriptHash(h160) => match get_cscript(sigdata, &h160, provider) {
            Some(script) => (true, vec![script], StepKind::ScriptHash),
            None => {
                sigdata.missing_redeem_script = Some(h160);
                (false, Vec::new(), StepKind::ScriptHash)
            }
        },
        ScriptType::Multisig { required, keys } => {
            let mut ret = vec![Vec::new()];
            for pubkey in &keys {
                if let Some(sig) = create_sig(sigdata, pubkey, mode, provider)
                    && ret.len() < required as usize + 1
                {
                    ret.push(sig);
                }
            }
            let ok = ret.len() == required as usize + 1;
            while ret.len() < required as usize + 1 {
                ret.push(Vec::new());
            }
            (ok, ret, StepKind::Other)
        }
        ScriptType::Witness {
            version: 0,
            program,
        } if program.len() == 20 => (true, vec![program], StepKind::W0KeyHash),
        ScriptType::Witness {
            version: 0,
            program,
        } if program.len() == 32 => {
            // scriptid = hash160(witscript) = ripemd160(program)
            let scriptid = {
                let mut h = [0u8; 20];
                h.copy_from_slice(&hash160_of_program(&program));
                h
            };
            match get_cscript(sigdata, &scriptid, provider) {
                Some(script) => (true, vec![script], StepKind::W0ScriptHash),
                None => {
                    let mut w = [0u8; 32];
                    w.copy_from_slice(&program);
                    sigdata.missing_witness_script = Some(w);
                    (false, Vec::new(), StepKind::W0ScriptHash)
                }
            }
        }
        ScriptType::Witness {
            version: 1,
            program,
        } if program.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(&program);
            match sign_taproot(&key, sigdata, mode, provider) {
                Some(stack) => (true, stack, StepKind::Taproot),
                None => (false, Vec::new(), StepKind::Taproot),
            }
        }
        ScriptType::Anchor => (true, Vec::new(), StepKind::Other),
        _ => (false, Vec::new(), StepKind::Other),
    }
}

/// Which outer template `sign_step` resolved — drives the wrapping
/// logic in `produce_signature`.
enum StepKind {
    /// Any non-wrapping type.
    Other,
    /// P2SH — `result[0]` is the subscript.
    ScriptHash,
    /// `OP_0 <20B>` — `result[0]` is the keyhash program.
    W0KeyHash,
    /// `OP_0 <32B>` — `result[0]` is the witness script.
    W0ScriptHash,
    /// `OP_1 <32B>` — `result` is the witness stack when solved.
    Taproot,
}

/// `RIPEMD160(program)` — for a W0SH program this equals
/// `CScriptID(witness_script)` = `hash160(witness_script)`.
fn hash160_of_program(program: &[u8]) -> [u8; 20] {
    // ripemd160(sha256(script)) == hash160(script) when
    // program == sha256(script); computing hash160(script) needs the
    // script itself, so take ripemd160 of the program directly.
    crate::hash::ripemd160(program)
}

/// `ProduceSignature` — solve `script_pubkey` into `sigdata`'s
/// scriptSig/witness. `checker` is the pass's `creator.Checker()`:
/// the real transaction checker for the missing-analysis pass,
/// `DummyChecker` for estimation.
pub fn produce_signature(
    provider: &FlatProvider,
    script_pubkey: &Script,
    sigdata: &mut SignatureData,
    mode: Creator,
    checker: &dyn SignatureChecker,
) -> bool {
    if sigdata.complete {
        return true;
    }
    let (mut solved, mut result, mut kind) =
        sign_step(provider, script_pubkey.as_bytes(), sigdata, mode);
    let mut p2sh = false;
    let mut subscript = Vec::new();

    // `whichType` is an out-param in Core — each SignStep call
    // rewrites it, and the witness arms check the *current* type.
    if solved && matches!(kind, StepKind::ScriptHash) {
        subscript = result[0].clone();
        sigdata.redeem_script = Some(subscript.clone());
        let (s2, r2, k2) = sign_step(provider, &subscript, sigdata, mode);
        solved = s2 && !matches!(k2, StepKind::ScriptHash);
        result = r2;
        kind = k2;
        p2sh = true;
    }

    if solved && matches!(kind, StepKind::W0KeyHash) {
        // OP_DUP OP_HASH160 <program> OP_EQUALVERIFY OP_CHECKSIG
        let mut wsh = Vec::with_capacity(25);
        wsh.extend_from_slice(&[0x76, 0xa9, 0x14]);
        wsh.extend_from_slice(&result[0]);
        wsh.extend_from_slice(&[0x88, 0xac]);
        let (s2, r2, _k2) = sign_step(provider, &wsh, sigdata, mode);
        solved = s2;
        sigdata.script_witness = Some(r2);
        sigdata.witness = true;
        result.clear();
    }

    if solved && matches!(kind, StepKind::W0ScriptHash) {
        let witnessscript = result[0].clone();
        sigdata.witness_script = Some(witnessscript.clone());
        let (s2, mut r2, k2) = sign_step(provider, &witnessscript, sigdata, mode);
        solved = s2
            && !matches!(k2, StepKind::ScriptHash)
            && !matches!(k2, StepKind::W0ScriptHash)
            && !matches!(k2, StepKind::W0KeyHash);
        if !solved && r2.is_empty() {
            // Miniscript fallback: only the `pk` leaf subset.
            if let Some(stack) = satisfy_wsh_miniscript(&witnessscript, sigdata, mode, provider) {
                solved = true;
                r2 = stack;
            }
        }
        r2.push(witnessscript);
        sigdata.script_witness = Some(r2);
        sigdata.witness = true;
        result.clear();
    }

    if matches!(kind, StepKind::Taproot) && !p2sh {
        sigdata.witness = true;
        if solved {
            sigdata.script_witness = Some(result.clone());
        }
        result.clear();
    }
    // Core's `solved && WITNESS_UNKNOWN` arm is unreachable (SignStep
    // never solves it) — an unknown program just leaves `witness`
    // false, failing `require_witness_sig` when the utxo came from a
    // witness_utxo field.
    if !sigdata.witness {
        sigdata.script_witness = None;
    }
    if p2sh {
        result.push(subscript);
    }
    sigdata.script_sig = push_all(&result);
    sigdata.complete = solved
        && verify_script(
            &Script::new(sigdata.script_sig.clone()),
            script_pubkey,
            sigdata.script_witness.clone().map(Witness::new).as_ref(),
            standard_flags(),
            checker,
        )
        .is_ok();
    sigdata.complete
}

/// The miniscript fallback for WSH: only the `pk`-shaped script is
/// satisfiable without a miniscript engine.
fn satisfy_wsh_miniscript(
    script: &[u8],
    sigdata: &mut SignatureData,
    mode: Creator,
    provider: &FlatProvider,
) -> Option<Vec<Vec<u8>>> {
    // `<33B compressed pubkey> OP_CHECKSIG` — `pk(key)` in P2WSH.
    if script.len() == 35 && script[0] == 0x21 && script[34] == 0xac {
        let sig = create_sig(sigdata, &script[1..34], mode, provider)?;
        return Some(vec![sig]);
    }
    None
}

/// `DUMMY_CHECKER` — every non-empty signature is valid, locktime and
/// sequence always pass. Taproot commitments still fail (the base
/// `VerifyTaprootCommitment` is not overridden, like Core's).
pub struct DummyChecker;

impl SignatureChecker for DummyChecker {
    fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        _pubkey: &[u8],
        _script_code: &[u8],
        _sigversion: SigVersion,
    ) -> bool {
        !sig.is_empty()
    }

    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        _pubkey: &[u8],
        _sigversion: SigVersion,
        _execdata: &mut crate::interpreter::ExecutionData,
    ) -> Result<(), crate::interpreter::ScriptError> {
        if sig.is_empty() {
            Err(crate::interpreter::ScriptError::SchnorrSig)
        } else {
            Ok(())
        }
    }

    fn check_locktime(&self, _locktime: i64) -> bool {
        true
    }

    fn check_sequence(&self, _sequence: i64) -> bool {
        true
    }
}

/// `SignPSBTInput` — run one pass over input `index`: `mode`
/// `Real` collects `missing_*` into `out`, `Dummy` produces final
/// scripts on the input (for `finalize`/`estimated_vsize`).
pub fn sign_psbt_input(
    provider: &FlatProvider,
    psbt: &mut Psbt,
    index: usize,
    txdata: Option<&PrecomputedTransactionData>,
    mode: Creator,
    out: Option<&mut SignatureData>,
    finalize: bool,
) -> bool {
    if psbt_input_signed_and_verified(
        psbt,
        index,
        txdata.unwrap_or(&PrecomputedTransactionData::default()),
    ) {
        return true;
    }

    let mut sigdata = SignatureData::default();
    sigdata.fill_from_input(&psbt.inputs[index]);

    // Get UTXO (same precedence/prevout checks as GetInputUTXO).
    let input = &psbt.inputs[index];
    let prevout = &psbt.tx.inputs[index].previous_output;
    let mut require_witness_sig = false;
    let utxo;
    if let Some(raw) = input.get(Psbt::IN_NON_WITNESS_UTXO) {
        let Ok(tx) = Transaction::decode(raw) else {
            return false;
        };
        if prevout.vout as usize >= tx.outputs.len() {
            return false;
        }
        if tx.txid() != prevout.txid {
            return false;
        }
        utxo = tx.outputs[prevout.vout as usize].clone();
    } else if let Some(raw) = input.get(Psbt::IN_WITNESS_UTXO) {
        let mut dec = crate::encode::Decoder::new(raw);
        let (Ok(value), Ok(spk)) = (dec.read_i64_le(), dec.read_var_bytes()) else {
            return false;
        };
        utxo = TxOut {
            value,
            script_pubkey: Script::new(spk.to_vec()),
        };
        require_witness_sig = true;
    } else {
        return false;
    }

    sigdata.witness = false;
    let sig_complete = match txdata {
        Some(td) => {
            let checker = TransactionSignatureChecker::new(&psbt.tx, index, utxo.value, td);
            produce_signature(provider, &utxo.script_pubkey, &mut sigdata, mode, &checker)
        }
        None => produce_signature(
            provider,
            &utxo.script_pubkey,
            &mut sigdata,
            mode,
            &DummyChecker,
        ),
    };
    if require_witness_sig && !sigdata.witness {
        return false;
    }
    if !finalize && sigdata.complete {
        sigdata.complete = false;
    }
    sigdata.store_into_input(&mut psbt.inputs[index]);
    if sigdata.witness {
        // sigdata.witness → witness_utxo gets the resolved CTxOut.
        let mut val = Vec::new();
        val.extend_from_slice(&utxo.value.to_le_bytes());
        crate::encode::write_var_bytes(&mut val, utxo.script_pubkey.as_bytes());
        if !psbt.inputs[index].contains(&[Psbt::IN_WITNESS_UTXO]) {
            psbt.inputs[index].set(vec![Psbt::IN_WITNESS_UTXO], val);
        }
    }
    if let Some(out) = out {
        out.missing_pubkeys = sigdata.missing_pubkeys.clone();
        out.missing_sigs = sigdata.missing_sigs.clone();
        out.missing_redeem_script = sigdata.missing_redeem_script;
        out.missing_witness_script = sigdata.missing_witness_script;
    }
    sig_complete
}

/// `PSBTInputSigned` — a final scriptSig or a non-null final witness
/// marks the input signed (Core checks presence, not validity).
pub fn psbt_input_signed(input: &KeyMap) -> bool {
    if input
        .get(Psbt::IN_FINAL_SCRIPTSIG)
        .is_some_and(|v| !v.is_empty())
    {
        return true;
    }
    input
        .get(Psbt::IN_FINAL_SCRIPTWITNESS)
        .and_then(decode_witness_stack)
        .is_some_and(|stack| !stack.is_empty())
}

/// `IsSegWitOutput` — a bare witness program, or P2SH whose provider
/// subscript is a witness program.
pub fn is_segwit_output(provider: &FlatProvider, script: &Script) -> bool {
    match script.classify() {
        ScriptType::Witness { .. } => true,
        ScriptType::ScriptHash(h160) => provider.scripts.get(&h160).is_some_and(|s| {
            matches!(
                Script::new(s.clone()).classify(),
                ScriptType::Witness { .. }
            )
        }),
        _ => false,
    }
}

/// `RemoveUnnecessaryTransactions` — when every input's witness_utxo
/// is a segwit v1+ program, the redundant non_witness_utxos can drop
/// (skipped entirely for SIGHASH_ANYONECANPAY).
pub fn remove_unnecessary_transactions(psbt: &mut Psbt, sighash_type: u32) {
    if sighash_type & 0x80 == 0x80 {
        return;
    }
    let mut to_drop = Vec::new();
    for (i, input) in psbt.inputs.iter().enumerate() {
        let segwit_v1_plus = input
            .get(Psbt::IN_WITNESS_UTXO)
            .and_then(|raw| {
                let mut dec = crate::encode::Decoder::new(raw);
                dec.read_i64_le().ok()?;
                dec.read_var_bytes().ok()
            })
            .is_some_and(|spk| {
                matches!(
                    Script::new(spk.to_vec()).classify(),
                    ScriptType::Witness { version, .. } if version != 0
                )
            });
        if !segwit_v1_plus {
            to_drop.clear();
            break;
        }
        if input.get(Psbt::IN_NON_WITNESS_UTXO).is_some() {
            to_drop.push(i);
        }
    }
    for i in to_drop {
        psbt.inputs[i].remove_types(&[Psbt::IN_NON_WITNESS_UTXO]);
    }
}

/// `UpdatePSBTOutput` — fill a `SignatureData` from the output map,
/// run `ProduceSignature` on the output's scriptPubKey as a would-be
/// spend (provider lookups fill scripts/derivations/taproot data;
/// `Real` mode with a hiding provider never produces sigs), then
/// write back merge-only.
pub fn update_psbt_output(provider: &FlatProvider, psbt: &mut Psbt, index: usize) {
    let out = psbt.tx.outputs[index].clone();
    let mut sigdata = SignatureData::default();
    sigdata.fill_from_output(&psbt.outputs[index]);
    produce_signature(
        provider,
        &out.script_pubkey,
        &mut sigdata,
        Creator::Real,
        &DummyChecker,
    );
    sigdata.store_into_output(&mut psbt.outputs[index]);
}

/// `PSBTRole` ordering — `min()` picks the earliest-needed role.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PsbtRole {
    /// `creator`
    Creator,
    /// `updater`
    Updater,
    /// `signer`
    Signer,
    /// `finalizer`
    Finalizer,
    /// `extractor`
    Extractor,
}

impl PsbtRole {
    /// `PSBTRoleName`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Creator => "creator",
            Self::Updater => "updater",
            Self::Signer => "signer",
            Self::Finalizer => "finalizer",
            Self::Extractor => "extractor",
        }
    }
}

/// Per-input analysis — `PSBTInputAnalysis`.
pub struct InputAnalysis {
    /// Whether a UTXO is provided.
    pub has_utxo: bool,
    /// Whether the input's final scripts verify.
    pub is_final: bool,
    /// The next BIP174 role needed.
    pub next: PsbtRole,
    /// `missing_pubkeys`.
    pub missing_pubkeys: Vec<[u8; 20]>,
    /// `missing_sigs`.
    pub missing_sigs: Vec<[u8; 20]>,
    /// `missing_redeem_script`.
    pub missing_redeem_script: Option<[u8; 20]>,
    /// `missing_witness_script`.
    pub missing_witness_script: Option<[u8; 32]>,
}

/// `PSBTAnalysis`.
pub struct Analysis {
    /// One entry per input.
    pub inputs: Vec<InputAnalysis>,
    /// The fee once every input's UTXO is known.
    pub fee: Option<i64>,
    /// `GetVirtualTransactionSize` of the dummy-finalized tx.
    pub estimated_vsize: Option<u64>,
    /// `fee * 1000 / vsize` (CFeeRate's GetFeePerK, sats/kvB).
    pub estimated_feerate_k: Option<i64>,
    /// The next role for the PSBT as a whole.
    pub next: PsbtRole,
    /// `SetInvalid` message — clears the computed fields.
    pub error: Option<String>,
}

impl Analysis {
    fn set_invalid(&mut self, msg: String) {
        self.estimated_vsize = None;
        self.estimated_feerate_k = None;
        self.fee = None;
        self.inputs.clear();
        self.next = PsbtRole::Creator;
        self.error = Some(msg);
    }
}

/// `GetTransactionSigOpCost` — legacy + P2SH + witness sigops in
/// weight units, over the dummy-finalized transaction's spent outputs.
fn sigop_cost(tx: &Transaction, spent: &[TxOut]) -> u64 {
    let mut cost: u64 = tx
        .inputs
        .iter()
        .map(|i| i.script_sig.sig_ops(false))
        .sum::<u64>()
        + tx.outputs
            .iter()
            .map(|o| o.script_pubkey.sig_ops(false))
            .sum::<u64>();
    cost *= WITNESS_SCALE_FACTOR;
    // P2SH sigops — only when the input's utxo is a P2SH script.
    for (i, input) in tx.inputs.iter().enumerate() {
        if let Some(utxo) = spent.get(i)
            && utxo.script_pubkey.is_p2sh()
        {
            cost += utxo.script_pubkey.p2sh_sig_ops(&input.script_sig) * WITNESS_SCALE_FACTOR;
        }
    }
    for (i, input) in tx.inputs.iter().enumerate() {
        if let Some(utxo) = spent.get(i)
            && let Some((ver, prog)) = utxo.script_pubkey.witness_program()
        {
            cost += witness_sig_ops(ver, prog, &input.witness);
        }
    }
    cost
}

/// `CountWitnessSigOps` — mirror of interpreter.rs's private helper.
fn witness_sig_ops(version: u8, program: &[u8], witness: &Witness) -> u64 {
    if version == 0 {
        if program.len() == 20 {
            return 1;
        }
        if program.len() == 32
            && let Some(last) = witness.items().last()
        {
            return Script::new(last.clone()).sig_ops(true);
        }
    }
    0
}

/// `AnalyzePSBT`.
pub fn analyze_psbt(psbt: &Psbt) -> Analysis {
    let mut result = Analysis {
        inputs: Vec::new(),
        fee: None,
        estimated_vsize: None,
        estimated_feerate_k: None,
        next: PsbtRole::Extractor,
        error: None,
    };
    let mut calc_fee = true;
    let mut in_amt: i64 = 0;
    result
        .inputs
        .resize_with(psbt.tx.inputs.len(), || InputAnalysis {
            has_utxo: false,
            is_final: false,
            next: PsbtRole::Extractor,
            missing_pubkeys: Vec::new(),
            missing_sigs: Vec::new(),
            missing_redeem_script: None,
            missing_witness_script: None,
        });
    let txdata = precompute_psbt_data(psbt);

    for i in 0..psbt.tx.inputs.len() {
        let input_analysis = &mut result.inputs[i];
        input_analysis.next = PsbtRole::Extractor;

        let utxo = get_input_utxo(psbt, i);
        if let Some(u) = &utxo {
            if !(0..=MAX_MONEY).contains(&u.value) || !(0..=MAX_MONEY).contains(&(in_amt + u.value))
            {
                result.set_invalid(format!("PSBT is not valid. Input {i} has invalid value"));
                return result;
            }
            in_amt += u.value;
            input_analysis.has_utxo = true;
        } else {
            // non_witness_utxo present but prevout out of range → invalid.
            if let Some(raw) = psbt.inputs[i].get(Psbt::IN_NON_WITNESS_UTXO)
                && let Ok(tx) = Transaction::decode(raw)
                && psbt.tx.inputs[i].previous_output.vout as usize >= tx.outputs.len()
            {
                result.set_invalid(format!(
                    "PSBT is not valid. Input {i} specifies invalid prevout"
                ));
                return result;
            }
            input_analysis.has_utxo = false;
            input_analysis.is_final = false;
            input_analysis.next = PsbtRole::Updater;
            calc_fee = false;
        }

        if let Some(u) = &utxo
            && u.script_pubkey.is_unspendable()
        {
            result.set_invalid(format!(
                "PSBT is not valid. Input {i} spends unspendable output"
            ));
            return result;
        }

        if !psbt_input_signed_and_verified(psbt, i, &txdata) {
            input_analysis.is_final = false;
            let mut outdata = SignatureData::default();
            let mut owned = psbt.clone();
            let complete = sign_psbt_input(
                &FlatProvider::default(),
                &mut owned,
                i,
                Some(&txdata),
                Creator::Real,
                Some(&mut outdata),
                false,
            );
            if !complete {
                let only_sigs = outdata.missing_pubkeys.is_empty()
                    && outdata.missing_redeem_script.is_none()
                    && outdata.missing_witness_script.is_none()
                    && !outdata.missing_sigs.is_empty();
                input_analysis.missing_pubkeys = outdata.missing_pubkeys;
                input_analysis.missing_redeem_script = outdata.missing_redeem_script;
                input_analysis.missing_witness_script = outdata.missing_witness_script;
                input_analysis.missing_sigs = outdata.missing_sigs;
                if only_sigs {
                    input_analysis.next = PsbtRole::Signer;
                } else {
                    input_analysis.next = PsbtRole::Updater;
                }
            } else {
                input_analysis.next = PsbtRole::Finalizer;
            }
        } else if utxo.is_some() {
            input_analysis.is_final = true;
        }
    }

    let mut next = PsbtRole::Extractor;
    for input_analysis in &result.inputs {
        next = next.min(input_analysis.next);
    }
    result.next = next;

    if calc_fee {
        let mut out_amt: i64 = 0;
        let mut bad = false;
        for o in &psbt.tx.outputs {
            if !(0..=MAX_MONEY).contains(&o.value)
                || !(0..=MAX_MONEY).contains(&out_amt)
                || !(0..=MAX_MONEY).contains(&(out_amt + o.value))
            {
                bad = true;
                break;
            }
            out_amt += o.value;
        }
        if bad {
            result.set_invalid("PSBT is not valid. Output amount invalid".into());
            return result;
        }
        let fee = in_amt - out_amt;
        result.fee = Some(fee);

        // Estimate the size: dummy-finalize every input.
        let mut mtx = psbt.tx.clone();
        let mut owned = psbt.clone();
        let mut spent = Vec::with_capacity(mtx.inputs.len());
        let mut success = true;
        for i in 0..mtx.inputs.len() {
            if !sign_psbt_input(
                &FlatProvider::default(),
                &mut owned,
                i,
                None,
                Creator::Dummy,
                None,
                true,
            ) {
                success = false;
                break;
            }
            let Some(u) = get_input_utxo(&owned, i) else {
                success = false;
                break;
            };
            if let Some(v) = owned.inputs[i].get(Psbt::IN_FINAL_SCRIPTSIG) {
                mtx.inputs[i].script_sig = Script::new(v.to_vec());
            }
            if let Some(v) = owned.inputs[i].get(Psbt::IN_FINAL_SCRIPTWITNESS)
                && let Some(stack) = decode_witness_stack(v)
            {
                mtx.inputs[i].witness = Witness::new(stack);
            }
            spent.push(u);
        }
        if success {
            let vsize = virtual_size(&mtx, &spent);
            result.estimated_vsize = Some(vsize);
            result.estimated_feerate_k = Some(if vsize == 0 {
                0
            } else {
                fee * 1000 / vsize as i64
            });
        }
    }
    result
}

/// `GetVirtualTransactionSize` — `max(weight/4, sigopcost/20)`, both
/// ceiling-divided.
fn virtual_size(tx: &Transaction, spent: &[TxOut]) -> u64 {
    let weight = tx.weight() as u64;
    let wu = weight.div_ceil(WITNESS_SCALE_FACTOR);
    let so = sigop_cost(tx, spent).div_ceil(BYTES_PER_SIGOP);
    wu.max(so)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hex;
    use crate::psbt::bip32_derivation_value;
    use crate::transaction::OutPoint;

    fn funded() -> Psbt {
        let bytes = hex::decode(include_str!("../tests/data/funded.psbt.hex").trim()).unwrap();
        Psbt::decode(&bytes).unwrap()
    }

    #[test]
    fn funded_input_estimates() {
        let psbt = funded();
        let analysis = analyze_psbt(&psbt);
        assert_eq!(analysis.error, None);
        assert_eq!(analysis.inputs.len(), 1);
        assert!(analysis.inputs[0].has_utxo);
        assert_eq!(analysis.fee, Some(141));
        assert_eq!(analysis.estimated_vsize, Some(141));
        assert_eq!(analysis.estimated_feerate_k, Some(1000));
    }

    /// The tap-bip32 derivation value: `CompactSize count || leaves ||
    /// fingerprint || path` — not a fixed-width count.
    #[test]
    fn tap_bip32_value_compact_size() {
        let mut v = vec![0x02];
        v.extend_from_slice(&[0xaa; 32]);
        v.extend_from_slice(&[0xbb; 32]);
        v.extend_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        v.extend_from_slice(&(84u32 | 0x8000_0000).to_le_bytes());
        let (leaves, origin) = parse_tap_bip32_value(&v).unwrap();
        assert_eq!(leaves, vec![[0xaa; 32], [0xbb; 32]]);
        assert_eq!(bip32_derivation_value(&origin).unwrap().0, 0x1234_5678);
        // A count that overruns the value is rejected.
        assert!(parse_tap_bip32_value(&[0x03, 0xaa]).is_none());
    }

    /// `ProduceSignature` on `sh(wpkh(key))`: the P2SH recursion must
    /// hand the inner witness type back to the wrapping logic so the
    /// pkh template runs — filling `redeem_script`, `witness`, and the
    /// inner key's BIP32 derivation even without private keys.
    #[test]
    fn produce_signature_sh_wpkh_metadata() {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[0x11; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret)
            .serialize()
            .to_vec();
        let keyid = hash160(&pubkey);
        // redeem = OP_0 <keyid>; spk = OP_HASH160 <h160(redeem)> OP_EQUAL.
        let mut redeem = vec![0x00, 0x14];
        redeem.extend_from_slice(&keyid);
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(&hash160(&redeem));
        spk.push(0x87);

        let mut provider = FlatProvider::default();
        provider.scripts.insert(hash160(&redeem), redeem.clone());
        provider.pubkeys.insert(keyid, pubkey.clone());
        provider.origins.insert(
            keyid,
            (
                pubkey.clone(),
                ([0xde, 0xad, 0xbe, 0xef], vec![84 | 0x8000_0000]),
            ),
        );

        let mut sigdata = SignatureData::default();
        produce_signature(
            &provider,
            &Script::new(spk),
            &mut sigdata,
            Creator::Real,
            &DummyChecker,
        );
        assert_eq!(sigdata.redeem_script.as_deref(), Some(&redeem[..]));
        assert!(sigdata.witness);
        assert_eq!(
            sigdata.misc_pubkeys.get(&keyid).map(|(p, _)| p),
            Some(&pubkey)
        );
        // No private key in the provider — the sig is missing but the
        // pubkey was found, so `missing_pubkeys` stays empty.
        assert!(sigdata.missing_pubkeys.is_empty());
        assert_eq!(sigdata.missing_sigs, vec![keyid]);
    }

    /// `UpdatePSBTOutput` on a `sh(wpkh)` output writes both the
    /// redeem script and the inner key's derivation record.
    #[test]
    fn update_psbt_output_sh_wpkh() {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[0x22; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret)
            .serialize()
            .to_vec();
        let keyid = hash160(&pubkey);
        let mut redeem = vec![0x00, 0x14];
        redeem.extend_from_slice(&keyid);
        let mut spk = vec![0xa9, 0x14];
        spk.extend_from_slice(&hash160(&redeem));
        spk.push(0x87);

        let mut provider = FlatProvider::default();
        provider.scripts.insert(hash160(&redeem), redeem.clone());
        provider.pubkeys.insert(keyid, pubkey.clone());
        provider.origins.insert(
            keyid,
            (pubkey.clone(), ([0x11, 0x22, 0x33, 0x44], Vec::new())),
        );

        let tx = Transaction {
            version: 2,
            inputs: vec![crate::transaction::TxIn {
                previous_output: OutPoint {
                    txid: crate::hash::Txid::from_bytes([0x01; 32]),
                    vout: 0,
                },
                script_sig: Script::new(Vec::new()),
                sequence: 0xffff_fffd,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 1000,
                script_pubkey: Script::new(spk),
            }],
            lock_time: 0,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx);
        update_psbt_output(&provider, &mut psbt, 0);
        assert_eq!(
            psbt.outputs[0].get(Psbt::OUT_REDEEM_SCRIPT),
            Some(&redeem[..])
        );
        let deriv = psbt.outputs[0]
            .all(Psbt::OUT_BIP32_DERIVATION)
            .collect::<Vec<_>>();
        assert_eq!(deriv.len(), 1);
        assert_eq!(deriv[0].0[..], pubkey[..]);
        assert_eq!(deriv[0].1[..4], [0x11, 0x22, 0x33, 0x44]);
    }
}

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

use std::collections::{BTreeMap, HashMap};

use crate::descriptor::FlatProvider;
use crate::hash::{hash160, sha256};
use crate::interpreter::{
    ExecutionData, ScriptError, SigVersion, SignatureChecker, compute_tapbranch_hash,
    compute_tapleaf_hash, eval_script, verify_script,
};
use crate::psbt::{KeyMap, Psbt};
use crate::script::{ScriptFlags, ScriptType};
use crate::sigchecker::{PrecomputedTransactionData, TransactionSignatureChecker};
use crate::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};
use sha2::{Digest, Sha256};

/// `SIGHASH_ALL`.
pub const SIGHASH_ALL: u32 = 1;

/// `CKeyID → (pubkey, sig)` — the `SignatureData::signatures` map type.
pub type SignatureMap = BTreeMap<[u8; 20], (Vec<u8>, Vec<u8>)>;
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

/// `MutableTransactionSignatureCreator`'s context — the transaction,
/// input position, spent amount, precomputed sighash data, and
/// `nHashType` the pass signs with.
pub struct SignerEnv<'a> {
    /// `m_txto`.
    pub tx: &'a Transaction,
    /// `nIn`.
    pub n_in: usize,
    /// `amount` — the spent output's value.
    pub amount: i64,
    /// `m_txdata`.
    pub txdata: &'a PrecomputedTransactionData,
    /// `nHashType` — `SIGHASH_DEFAULT` (0) reaches Schnorr signing
    /// as-is and normalizes to `SIGHASH_ALL` for ECDSA.
    pub sighash: i32,
}

/// Which `BaseSignatureCreator` a pass runs. `Real` signs through the
/// provider's private keys (an empty provider — `DUMMY_SIGNING_PROVIDER`
/// — always fails, recording `missing_sigs`); `Dummy` produces
/// placeholder signatures for size estimation.
#[derive(Clone, Copy)]
pub enum Creator<'a> {
    /// `MutableTransactionSignatureCreator`.
    Real(&'a SignerEnv<'a>),
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
    pub signatures: SignatureMap,
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

    /// `SignatureData::MergeSignatureData` — a complete other side
    /// wins wholesale; otherwise redeem/witness scripts fill only
    /// when unset and `signatures` unions in.
    pub fn merge_signature_data(&mut self, sigdata: SignatureData) {
        if self.complete {
            return;
        }
        if sigdata.complete {
            *self = sigdata;
            return;
        }
        if self.redeem_script.is_none() && sigdata.redeem_script.is_some() {
            self.redeem_script = sigdata.redeem_script;
        }
        if self.witness_script.is_none() && sigdata.witness_script.is_some() {
            self.witness_script = sigdata.witness_script;
        }
        self.signatures.extend(sigdata.signatures);
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

/// `spend_data`'s result — `(script, leaf_ver) → control blocks` for
/// every leaf, plus the merkle root (`GetSpendData`).
pub type TaprootSpendResult = (BTreeMap<(Vec<u8>, u8), Vec<Vec<u8>>>, Option<[u8; 32]>);

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
            let Some(other) = self.branch.pop().flatten() else {
                break;
            };
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
    pub fn spend_data(&mut self, internal_key: [u8; 32]) -> Option<TaprootSpendResult> {
        if !self.is_complete() {
            return None;
        }
        let root = self.branch.first().and_then(|n| n.as_ref());
        // `CreateTapTweak` — `TapTweak(internal || merkle_root)`, the
        // root omitted entirely for a key-path-only builder.
        let tag = sha256(b"TapTweak");
        let mut h = Sha256::new();
        h.update(tag);
        h.update(tag);
        h.update(internal_key);
        if let Some(n) = root {
            h.update(n.hash);
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
    // `GetKeyOriginByXOnly` — `GetKeyIDsByXOnly` yields the even-then-
    // odd compressed-pubkey keyids; the first origin found wins.
    for prefix in [0x02u8, 0x03] {
        let mut pk = [0u8; 33];
        pk[0] = prefix;
        pk[1..].copy_from_slice(xonly);
        if let Some((_, (fp, path))) = provider.origins.get(&hash160(&pk)) {
            return Some(key_origin_value(fp, path));
        }
    }
    None
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
/// `Real` failures record `missing_sigs` (Core's wrapper pushes the
/// keyid on any `creator.CreateSig` failure).
fn create_sig(
    sigdata: &mut SignatureData,
    pubkey: &[u8],
    mode: Creator,
    provider: &FlatProvider,
    script_code: &[u8],
    sigversion: SigVersion,
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
    let sig = match mode {
        Creator::Dummy => dummy_ecdsa_sig(),
        // `MutableTransactionSignatureCreator::CreateSig`.
        Creator::Real(env) => {
            let Some(secret) = provider.keys.get(&keyid) else {
                sigdata.missing_sigs.push(keyid);
                return None;
            };
            // Uncompressed keys cannot sign witness scripts; the
            // pubkey that produced `keyid` carries the compression.
            if sigversion == SigVersion::WitnessV0 && pubkey.len() != 33 {
                sigdata.missing_sigs.push(keyid);
                return None;
            }
            if sigversion == SigVersion::WitnessV0 && !(0..=MAX_MONEY).contains(&env.amount) {
                sigdata.missing_sigs.push(keyid);
                return None;
            }
            // BASE/WITNESS_V0 don't support explicit SIGHASH_DEFAULT.
            let hashtype = if env.sighash == 0 {
                SIGHASH_ALL as i32
            } else {
                env.sighash
            };
            let hash = crate::sigchecker::signature_hash(
                &Script::new(script_code.to_vec()),
                env.tx,
                env.n_in,
                hashtype,
                env.amount,
                sigversion,
                Some(env.txdata),
            );
            let secp = secp256k1::Secp256k1::new();
            let msg = secp256k1::Message::from_digest(hash);
            // `CKey::Sign(hash, vch, grind=true)` — RFC6979 with
            // LE32-counter extra-entropy retries until low-R.
            let sig = secp.sign_ecdsa_low_r(&msg, secret);
            let mut vch = sig.serialize_der().to_vec();
            vch.push(hashtype as u8);
            vch
        }
    };
    sigdata
        .signatures
        .insert(keyid, (pubkey.to_vec(), sig.clone()));
    Some(sig)
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
    let sig = match mode {
        Creator::Dummy => vec![0u8; 64],
        // `CreateSchnorrSig(provider, sig, xonly, &leaf_hash, nullptr,
        // TAPSCRIPT)` — untweaked script-path signature.
        Creator::Real(_) => create_schnorr_sig(
            provider,
            xonly,
            Some(leaf_hash),
            None,
            SigVersion::Tapscript,
            mode,
        )?,
    };
    sigdata
        .taproot_script_sigs
        .insert((*xonly, *leaf_hash), sig.clone());
    Some(sig)
}

/// `provider.GetKeyByXOnly` — both compressed-pubkey keyids derived
/// from the x-only key, even-then-odd like `GetKeyIDsByXOnly`.
fn get_key_by_xonly<'a>(
    provider: &'a FlatProvider,
    xonly: &[u8; 32],
) -> Option<&'a secp256k1::SecretKey> {
    for prefix in [0x02u8, 0x03] {
        let mut pk = [0u8; 33];
        pk[0] = prefix;
        pk[1..].copy_from_slice(xonly);
        if let Some(k) = provider.keys.get(&hash160(&pk)) {
            return Some(k);
        }
    }
    None
}

/// `MutableTransactionSignatureCreator::CreateSchnorrSig` —
/// `GetKeyByXOnly`, BIP341/342 precomputed-data requirements, and
/// `CKey::SignSchnorr`'s `ComputeKeyPair(merkle_root)` tweak: a
/// non-`None` `merkle_root` always tweaks (`TapTweak(internal ||
/// root)` with a null root hashing the key alone); `None` signs with
/// the raw keypair.
fn create_schnorr_sig(
    provider: &FlatProvider,
    pubkey: &[u8; 32],
    leaf_hash: Option<&[u8; 32]>,
    merkle_root: Option<&[u8; 32]>,
    sigversion: SigVersion,
    mode: Creator,
) -> Option<Vec<u8>> {
    match mode {
        Creator::Dummy => Some(vec![0u8; 64]),
        Creator::Real(env) => {
            let secret = get_key_by_xonly(provider, pubkey)?;
            if !env.txdata.bip341_taproot_ready || !env.txdata.spent_outputs_ready {
                return None;
            }
            let mut execdata = crate::interpreter::ExecutionData {
                annex_init: true,
                annex_present: false,
                ..crate::interpreter::ExecutionData::default()
            };
            if sigversion == SigVersion::Tapscript {
                execdata.codeseparator_pos_init = true;
                execdata.codeseparator_pos = 0xFFFF_FFFF;
                execdata.tapleaf_hash_init = true;
                execdata.tapleaf_hash = Some(*leaf_hash?);
            }
            let sighash = env.sighash as u8;
            let hash = crate::sigchecker::signature_hash_schnorr(
                env.tx,
                env.n_in,
                sighash,
                sigversion,
                env.txdata,
                &mut execdata,
            )?;
            let secp = secp256k1::Secp256k1::new();
            let keypair = secp256k1::Keypair::from_secret_key(&secp, secret);
            let keypair = match merkle_root {
                Some(root) => {
                    // `merkle_root->IsNull() ? nullptr : merkle_root`.
                    let root = (*root != [0; 32]).then_some(*root);
                    let mut h = Sha256::new();
                    let tag = sha256(b"TapTweak");
                    h.update(tag);
                    h.update(tag);
                    h.update(pubkey);
                    if let Some(r) = root {
                        h.update(r);
                    }
                    let tweak: [u8; 32] = h.finalize().into();
                    let scalar = secp256k1::Scalar::from_be_bytes(tweak).ok()?;
                    keypair.add_xonly_tweak(&secp, &scalar).ok()?
                }
                None => keypair,
            };
            let msg = secp256k1::Message::from_digest(hash);
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
            let mut out = sig.serialize().to_vec();
            if sighash != 0 {
                out.push(sighash);
            }
            Some(out)
        }
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
        && let Some(internal) = sigdata.tr_internal_key
    {
        // `CreateSchnorrSig(provider, sig, internal_key, nullptr,
        // &tr_spenddata.merkle_root, TAPROOT)` — the pointer is
        // non-null even when the root is null (tweak without root).
        let root = sigdata.tr_merkle_root.unwrap_or_default();
        if let Some(sig) = create_schnorr_sig(
            provider,
            &internal,
            None,
            Some(&root),
            SigVersion::Taproot,
            mode,
        ) {
            sigdata.taproot_key_path_sig = sig;
        }
    }
    if sigdata.taproot_key_path_sig.is_empty()
        && let Some(sig) =
            create_schnorr_sig(provider, output_key, None, None, SigVersion::Taproot, mode)
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
    sigversion: SigVersion,
) -> (bool, Vec<Vec<u8>>, StepKind) {
    match Script::new(script.to_vec()).classify() {
        ScriptType::Nonstandard | ScriptType::NullData => (false, Vec::new(), StepKind::Other),
        ScriptType::Witness { version, program }
            if !matches!((version, program.len()), (0, 20) | (0, 32) | (1, 32)) =>
        {
            (false, Vec::new(), StepKind::Other)
        }
        ScriptType::PubKey(pubkey) => {
            match create_sig(sigdata, &pubkey, mode, provider, script, sigversion) {
                Some(sig) => (true, vec![sig], StepKind::Other),
                None => (false, Vec::new(), StepKind::Other),
            }
        }
        ScriptType::PubKeyHash(h160) => {
            let Some(pubkey) = get_pubkey(sigdata, &h160, provider) else {
                sigdata.missing_pubkeys.push(h160);
                return (false, Vec::new(), StepKind::Other);
            };
            match create_sig(sigdata, &pubkey, mode, provider, script, sigversion) {
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
                if let Some(sig) = create_sig(sigdata, pubkey, mode, provider, script, sigversion)
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
    let (mut solved, mut result, mut kind) = sign_step(
        provider,
        script_pubkey.as_bytes(),
        sigdata,
        mode,
        SigVersion::Base,
    );
    let mut p2sh = false;
    let mut subscript = Vec::new();

    // `whichType` is an out-param in Core — each SignStep call
    // rewrites it, and the witness arms check the *current* type.
    if solved && matches!(kind, StepKind::ScriptHash) {
        subscript = result[0].clone();
        sigdata.redeem_script = Some(subscript.clone());
        let (s2, r2, k2) = sign_step(provider, &subscript, sigdata, mode, SigVersion::Base);
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
        let (s2, r2, _k2) = sign_step(provider, &wsh, sigdata, mode, SigVersion::WitnessV0);
        solved = s2;
        sigdata.script_witness = Some(r2);
        sigdata.witness = true;
        result.clear();
    }

    if solved && matches!(kind, StepKind::W0ScriptHash) {
        let witnessscript = result[0].clone();
        sigdata.witness_script = Some(witnessscript.clone());
        let (s2, mut r2, k2) = sign_step(
            provider,
            &witnessscript,
            sigdata,
            mode,
            SigVersion::WitnessV0,
        );
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
        let sig = create_sig(
            sigdata,
            &script[1..34],
            mode,
            provider,
            script,
            SigVersion::WitnessV0,
        )?;
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

/// `SignPSBTInput` — run one pass over input `index` with `sighash`.
/// `dummy_creator` picks `DUMMY_SIGNATURE_CREATOR` (size estimation);
/// otherwise a `MutableTransactionSignatureCreator` signs with the
/// provider's keys — and, per Core, a missing `txdata` still forces
/// the dummy creator. `Real` failures collect `missing_*` into `out`;
/// `finalize` keeps `sigdata.complete` so final scripts are written.
/// `walletprocesspsbt`'s verification step (queue #36's enforcement):
/// for every input, compare the PSBT's claimed `witness_utxo` against
/// the node's *verified* UTXO set — a lying host cannot understate an
/// input's value to inflate the apparent fee (the LSB-010 hardware-
/// wallet attack class); we have the chain, so prevouts are facts,
/// not claims. Missing `witness_utxo`s are filled from the set.
/// Returns `(verified, unverified)` — unverified means the prevout
/// is not in the UTXO set (spent or foreign), never silently trusted.
///
/// # Errors
/// A `String` naming the offending input when a claim mismatches.
/// Per-input result of [`verify_and_fill_prevouts`] — the signing
/// receipt's data: what the input claimed vs. what the verified UTXO
/// set holds, and whether the set could speak for it at all.
#[derive(Debug, Clone)]
pub struct PrevoutCheck {
    /// The input's outpoint.
    pub outpoint: crate::transaction::OutPoint,
    /// Authoritative value — the verified UTXO set's, never the
    /// PSBT's claim.
    pub value_sats: i64,
    /// Authoritative scriptPubKey length.
    pub script_len: usize,
    /// What the PSBT claimed, if it carried a `witness_utxo`.
    pub claimed_sats: Option<i64>,
    /// "verified" (claim matched the set) | "filled" (we supplied the
    /// prevout) | "unverified" (not in the set — never trusted).
    pub status: &'static str,
}

pub fn verify_and_fill_prevouts(
    utxo: &crate::connect::UtxoSet,
    psbt: &mut Psbt,
) -> Result<Vec<PrevoutCheck>, String> {
    let mut checks = Vec::with_capacity(psbt.tx.inputs.len());
    for i in 0..psbt.tx.inputs.len() {
        let prevout = psbt.tx.inputs[i].previous_output;
        let Some(coin) = utxo.get(&prevout) else {
            checks.push(PrevoutCheck {
                outpoint: prevout,
                value_sats: 0,
                script_len: 0,
                claimed_sats: None,
                status: "unverified",
            });
            continue;
        };
        match psbt.inputs[i].get(Psbt::IN_WITNESS_UTXO) {
            Some(claimed) => {
                let mut dec = crate::encode::Decoder::new(claimed);
                let cv = dec.read_u64_le().unwrap_or(u64::MAX) as i64;
                let cscript = dec.read_var_bytes().unwrap_or_default();
                if cv != coin.out.value || cscript != coin.out.script_pubkey.as_bytes() {
                    return Err(format!(
                        "input {i}: PSBT prevout claims {cv} sats / script len {} but the verified UTXO set says {} sats / len {} — refusing to sign",
                        cscript.len(),
                        coin.out.value,
                        coin.out.script_pubkey.as_bytes().len()
                    ));
                }
                checks.push(PrevoutCheck {
                    outpoint: prevout,
                    value_sats: coin.out.value,
                    script_len: coin.out.script_pubkey.as_bytes().len(),
                    claimed_sats: Some(cv),
                    status: "verified",
                });
            }
            None => {
                let mut v = coin.out.value.to_le_bytes().to_vec();
                crate::encode::write_var_bytes(&mut v, coin.out.script_pubkey.as_bytes());
                psbt.inputs[i].set(vec![Psbt::IN_WITNESS_UTXO], v);
                checks.push(PrevoutCheck {
                    outpoint: prevout,
                    value_sats: coin.out.value,
                    script_len: coin.out.script_pubkey.as_bytes().len(),
                    claimed_sats: None,
                    status: "filled",
                });
            }
        }
    }
    Ok(checks)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_psbt_input(
    provider: &FlatProvider,
    psbt: &mut Psbt,
    index: usize,
    txdata: Option<&PrecomputedTransactionData>,
    sighash: i32,
    dummy_creator: bool,
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
    // `MutableTransactionSignatureCreator` when the pass signs for
    // real and `txdata` exists; `txdata == nullptr` or an explicit
    // dummy request runs `DUMMY_SIGNATURE_CREATOR`.
    let env = if dummy_creator {
        None
    } else {
        txdata.map(|td| SignerEnv {
            tx: &psbt.tx,
            n_in: index,
            amount: utxo.value,
            txdata: td,
            sighash,
        })
    };
    let creator = env.as_ref().map_or(Creator::Dummy, Creator::Real);
    let sig_complete = match txdata {
        Some(td) => {
            let checker = TransactionSignatureChecker::new(&psbt.tx, index, utxo.value, td);
            produce_signature(
                provider,
                &utxo.script_pubkey,
                &mut sigdata,
                creator,
                &checker,
            )
        }
        None => produce_signature(
            provider,
            &utxo.script_pubkey,
            &mut sigdata,
            creator,
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

/// `FinalizeAndExtractPSBT` — finalize every input (empty provider,
/// real checker), then move final scriptSigs/witnesses into the
/// transaction. `None` when any input stays incomplete.
#[must_use]
pub fn finalize_and_extract_psbt(psbt: &mut Psbt) -> Option<Transaction> {
    let txdata = precompute_psbt_data(psbt);
    let provider = FlatProvider::default();
    let mut complete = true;
    for i in 0..psbt.tx.inputs.len() {
        complete &= sign_psbt_input(&provider, psbt, i, Some(&txdata), 1, false, None, true);
    }
    if !complete {
        return None;
    }
    let mut tx = psbt.tx.clone();
    for (i, input) in tx.inputs.iter_mut().enumerate() {
        input.script_sig = Script::new(
            psbt.inputs[i]
                .get(Psbt::IN_FINAL_SCRIPTSIG)
                .map_or_else(Vec::new, |v| v.to_vec()),
        );
        input.witness = psbt.inputs[i]
            .get(Psbt::IN_FINAL_SCRIPTWITNESS)
            .and_then(decode_witness_stack)
            .map(Witness::new)
            .unwrap_or_default();
    }
    Some(tx)
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
        Creator::Dummy,
        &DummyChecker,
    );
    sigdata.store_into_output(&mut psbt.outputs[index]);
}

/// `SignatureExtractorChecker` — every check delegates to the wrapped
/// checker; a passing ECDSA check also records `keyid → (pubkey, sig)`
/// (`DataFromTransaction` recovers signatures already sitting in a
/// scriptSig this way). Schnorr signatures are not extracted — Core's
/// extractor predates taproot and only wraps `CheckECDSASignature`.
struct SignatureExtractorChecker<'a> {
    inner: &'a dyn SignatureChecker,
    signatures: std::cell::RefCell<SignatureMap>,
}

impl SignatureChecker for SignatureExtractorChecker<'_> {
    fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sigversion: SigVersion,
    ) -> bool {
        if self
            .inner
            .check_ecdsa_signature(sig, pubkey, script_code, sigversion)
        {
            self.signatures
                .borrow_mut()
                .insert(hash160(pubkey), (pubkey.to_vec(), sig.to_vec()));
            return true;
        }
        false
    }
    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        sigversion: SigVersion,
        execdata: &mut ExecutionData,
    ) -> Result<(), ScriptError> {
        self.inner
            .check_schnorr_signature(sig, pubkey, sigversion, execdata)
    }
    fn check_locktime(&self, locktime: i64) -> bool {
        self.inner.check_locktime(locktime)
    }
    fn check_sequence(&self, sequence: i64) -> bool {
        self.inner.check_sequence(sequence)
    }
    fn verify_taproot_commitment(
        &self,
        control: &[u8],
        program: &[u8],
        tapleaf_hash: &[u8; 32],
    ) -> bool {
        self.inner
            .verify_taproot_commitment(control, program, tapleaf_hash)
    }
}

/// `DataFromTransaction` — pull the signatures and scripts an existing
/// (possibly partial) spend carries into a `SignatureData`: a spend
/// that already verifies is `complete`; otherwise P2SH and P2WSH
/// wrappers are recovered from the stack tails and multisig signatures
/// are matched against the script's pubkeys. Extracts signatures and
/// scripts from incomplete scriptSigs — please do not extend this
/// (Core's comment), use PSBT instead.
#[must_use]
pub fn data_from_transaction(tx: &Transaction, n_in: usize, txout: &TxOut) -> SignatureData {
    let mut data = SignatureData {
        script_sig: tx.inputs[n_in].script_sig.as_bytes().to_vec(),
        ..SignatureData::default()
    };
    if !tx.inputs[n_in].witness.is_empty() {
        data.script_witness = Some(tx.inputs[n_in].witness.items().to_vec());
    }

    // `MutableTransactionSignatureChecker(&tx, nIn, amount, FAIL)` —
    // no txdata, so segwit checks fail inside the extractor and only
    // legacy-verifiable signatures are recovered.
    let checker = TransactionSignatureChecker {
        tx,
        n_in,
        amount: txout.value,
        txdata: None,
    };
    let extractor = SignatureExtractorChecker {
        inner: &checker,
        signatures: std::cell::RefCell::new(SignatureMap::new()),
    };

    if verify_script(
        &tx.inputs[n_in].script_sig,
        &txout.script_pubkey,
        Some(&tx.inputs[n_in].witness),
        standard_flags(),
        &extractor,
    )
    .is_ok()
    {
        data.signatures = extractor.signatures.into_inner();
        data.complete = true;
        return data;
    }

    // `Stacks` — the scriptSig's pushes under STRICTENC (the eval's
    // result is ignored) plus the witness items.
    let mut script_stack: Vec<Vec<u8>> = Vec::new();
    let _ = eval_script(
        &mut script_stack,
        &tx.inputs[n_in].script_sig,
        ScriptFlags::STRICTENC,
        &DummyChecker,
        SigVersion::Base,
        &mut ExecutionData::default(),
    );
    let mut witness_stack: Vec<Vec<u8>> = tx.inputs[n_in].witness.items().to_vec();

    let mut script_type = txout.script_pubkey.classify();
    let mut next_script = txout.script_pubkey.clone();
    let mut sigversion = SigVersion::Base;

    if let ScriptType::ScriptHash(_) = script_type
        && script_stack.last().is_some_and(|s| !s.is_empty())
    {
        let redeem = script_stack.pop().unwrap_or_default();
        data.redeem_script = Some(redeem.clone());
        next_script = Script::new(redeem);
        script_type = next_script.classify();
    }
    if let ScriptType::Witness {
        version: 0,
        ref program,
    } = script_type
        && program.len() == 32
        && witness_stack.last().is_some_and(|s| !s.is_empty())
    {
        let wscript = witness_stack.pop().unwrap_or_default();
        data.witness_script = Some(wscript.clone());
        next_script = Script::new(wscript);
        script_stack = std::mem::take(&mut witness_stack);
        script_type = next_script.classify();
        sigversion = SigVersion::WitnessV0;
    }
    if let ScriptType::Multisig { keys, .. } = &script_type
        && !script_stack.is_empty()
    {
        // Match each stack signature to a script pubkey — the same
        // order CHECKMULTISIG evaluates in.
        let mut last_success_key = 0usize;
        for sig in &script_stack {
            for (i, pubkey) in keys.iter().enumerate().skip(last_success_key) {
                if extractor.signatures.borrow().contains_key(&hash160(pubkey))
                    || extractor.check_ecdsa_signature(
                        sig,
                        pubkey,
                        next_script.as_bytes(),
                        sigversion,
                    )
                {
                    last_success_key = i + 1;
                    break;
                }
            }
        }
    }
    data.signatures = extractor.signatures.into_inner();
    data
}

/// `UpdateInput` — write the produced scriptSig/witness onto the input.
pub fn update_input(input: &mut TxIn, data: &SignatureData) {
    input.script_sig = Script::new(data.script_sig.clone());
    input.witness = data
        .script_witness
        .clone()
        .map(Witness::new)
        .unwrap_or_default();
}

/// `SignTransaction` — produce signatures for every input the
/// keystore's keys can satisfy. `coins` maps each spent outpoint to
/// its `TxOut` (`None`/absent = `Coin::IsSpent`); a single missing
/// coin disables real precomputed sighash data for the whole pass
/// (`txdata.Init(tx, {}, force)`). `input_errors` collects per-input
/// failures keyed by index; the return is `input_errors.is_empty()`.
pub fn sign_transaction(
    tx: &mut Transaction,
    provider: &FlatProvider,
    coins: &HashMap<OutPoint, Option<TxOut>>,
    sighash: i32,
    input_errors: &mut BTreeMap<usize, String>,
) -> bool {
    let f_hash_single = (sighash & !0x80) == 3;
    let tx_const = tx.clone();

    let txdata = {
        let mut outs = Vec::with_capacity(tx_const.inputs.len());
        let mut all = true;
        for input in &tx_const.inputs {
            match coins.get(&input.previous_output).and_then(|c| c.as_ref()) {
                Some(o) => outs.push(o.clone()),
                None => {
                    all = false;
                    break;
                }
            }
        }
        if all {
            PrecomputedTransactionData::new(&tx_const, Some(outs), true)
        } else {
            PrecomputedTransactionData::new(&tx_const, None, true)
        }
    };

    for i in 0..tx_const.inputs.len() {
        let txin = &tx_const.inputs[i];
        let Some(coin_out) = coins.get(&txin.previous_output).and_then(|c| c.as_ref()) else {
            input_errors.insert(i, "Input not found or already spent".into());
            continue;
        };
        let prev_pubkey = coin_out.script_pubkey.clone();
        let amount = coin_out.value;

        let mut sigdata = data_from_transaction(&tx_const, i, coin_out);
        // Only sign SIGHASH_SINGLE if there's a corresponding output.
        if !f_hash_single || i < tx_const.outputs.len() {
            let env = SignerEnv {
                tx: &tx_const,
                n_in: i,
                amount,
                txdata: &txdata,
                sighash,
            };
            let checker = TransactionSignatureChecker::new(&tx_const, i, amount, &txdata);
            produce_signature(
                provider,
                &prev_pubkey,
                &mut sigdata,
                Creator::Real(&env),
                &checker,
            );
        }
        update_input(&mut tx.inputs[i], &sigdata);

        // amount must be specified for valid segwit signature.
        if amount == crate::check::MAX_MONEY && !tx.inputs[i].witness.is_empty() {
            input_errors.insert(i, "Missing amount".into());
            continue;
        }

        let verification = if sigdata.complete {
            Ok(())
        } else {
            verify_script(
                &tx.inputs[i].script_sig,
                &prev_pubkey,
                Some(&tx.inputs[i].witness),
                standard_flags(),
                &TransactionSignatureChecker::new(&tx_const, i, amount, &txdata),
            )
        };
        match verification {
            Ok(()) => {
                input_errors.remove(&i);
            }
            Err(e) => {
                let msg = match e {
                    // Unable to sign input and verification failed
                    // (possible attempt to partially sign).
                    ScriptError::InvalidStackOperation => {
                        "Unable to sign input, invalid stack size (possibly missing key)".to_string()
                    }
                    // Verification failed (possibly due to insufficient
                    // signatures).
                    ScriptError::SigNullFail => "CHECK(MULTI)SIG failing with non-zero signature (possibly need more signatures)".to_string(),
                    other => other.to_string(),
                };
                input_errors.insert(i, msg);
            }
        }
    }
    input_errors.is_empty()
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
                SIGHASH_ALL as i32,
                false,
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
                SIGHASH_ALL as i32,
                true,
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
        let tx = Transaction {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        };
        let txdata = PrecomputedTransactionData::default();
        let env = SignerEnv {
            tx: &tx,
            n_in: 0,
            amount: 0,
            txdata: &txdata,
            sighash: 1,
        };
        produce_signature(
            &provider,
            &Script::new(spk),
            &mut sigdata,
            Creator::Real(&env),
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

    /// A one-input PSBT spending `spk` via `witness_utxo` (50k sats
    /// in, half out to an OP_1 output).
    fn psbt_spending(spk: &[u8]) -> Psbt {
        let tx = Transaction {
            version: 2,
            inputs: vec![crate::transaction::TxIn {
                previous_output: OutPoint {
                    txid: crate::hash::Txid::from_bytes([0x22; 32]),
                    vout: 0,
                },
                script_sig: Script::new(Vec::new()),
                sequence: 0xffff_ffff,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 25_000,
                script_pubkey: Script::new(vec![0x51]),
            }],
            lock_time: 0,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx);
        let mut v = 50_000i64.to_le_bytes().to_vec();
        crate::encode::write_var_bytes(&mut v, spk);
        psbt.inputs[0].set(vec![Psbt::IN_WITNESS_UTXO], v);
        psbt
    }

    fn compressed_keyid(xonly: &[u8; 32], prefix: u8) -> [u8; 20] {
        let mut pk = vec![prefix];
        pk.extend_from_slice(xonly);
        hash160(&pk)
    }

    /// `TapTweak(pubkey || root?)` — descriptor.rs's tagged hash.
    fn tap_tweak(xonly: &[u8; 32], root: Option<&[u8; 32]>) -> [u8; 32] {
        let tag = sha256(b"TapTweak");
        let mut h = Sha256::new();
        h.update(tag);
        h.update(tag);
        h.update(xonly);
        if let Some(r) = root {
            h.update(r);
        }
        h.finalize().into()
    }

    /// `descriptorprocesspsbt`'s signer path — a P2WPKH input signs,
    /// finalizes, verifies, and extracts.
    #[test]
    fn sign_psbt_input_p2wpkh_signs() {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret)
            .serialize()
            .to_vec();
        let keyid = hash160(&pubkey);
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&keyid);
        let mut psbt = psbt_spending(&spk);
        let mut provider = FlatProvider::default();
        provider.keys.insert(keyid, secret);
        provider.pubkeys.insert(keyid, pubkey.clone());
        let txdata = precompute_psbt_data(&psbt);
        assert!(sign_psbt_input(
            &provider,
            &mut psbt,
            0,
            Some(&txdata),
            1,
            false,
            None,
            true,
        ));
        assert!(psbt_input_signed(&psbt.inputs[0]));
        let wit = decode_witness_stack(psbt.inputs[0].get(Psbt::IN_FINAL_SCRIPTWITNESS).unwrap())
            .unwrap();
        assert_eq!(wit.len(), 2);
        assert_eq!(wit[0].last(), Some(&1)); // SIGHASH_ALL byte
        assert_eq!(wit[1], pubkey);
        assert!(finalize_and_extract_psbt(&mut psbt).is_some());
    }

    /// A pubkey-only provider reports `missing_pubkeys`; adding the
    /// pubkey without the secret reports `missing_sigs` instead.
    #[test]
    fn sign_psbt_input_p2wpkh_missing() {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret)
            .serialize()
            .to_vec();
        let keyid = hash160(&pubkey);
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&keyid);
        let mut psbt = psbt_spending(&spk);
        let txdata = precompute_psbt_data(&psbt);
        let mut out = SignatureData::default();
        assert!(!sign_psbt_input(
            &FlatProvider::default(),
            &mut psbt,
            0,
            Some(&txdata),
            1,
            false,
            Some(&mut out),
            true,
        ));
        assert_eq!(out.missing_pubkeys, vec![keyid]);
        assert!(out.missing_sigs.is_empty());
        // Pubkey known but no secret → missing_sigs.
        let mut provider = FlatProvider::default();
        provider.pubkeys.insert(keyid, pubkey);
        let mut out = SignatureData::default();
        assert!(!sign_psbt_input(
            &provider,
            &mut psbt,
            0,
            Some(&txdata),
            1,
            false,
            Some(&mut out),
            true,
        ));
        assert!(out.missing_pubkeys.is_empty());
        assert_eq!(out.missing_sigs, vec![keyid]);
    }

    /// Taproot key-path: the internal key + merkle-root tweak signs
    /// `SIGHASH_DEFAULT` (64-byte sig, no appended sighash byte).
    #[test]
    fn sign_psbt_input_taproot_keypath() {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret);
        let (internal, _parity) = keypair.x_only_public_key();
        let scalar =
            secp256k1::Scalar::from_be_bytes(tap_tweak(&internal.serialize(), None)).unwrap();
        let tweaked = keypair.add_xonly_tweak(&secp, &scalar).unwrap();
        let (outkey, _) = tweaked.x_only_public_key();
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&outkey.serialize());
        let mut psbt = psbt_spending(&spk);
        let mut provider = FlatProvider::default();
        provider
            .keys
            .insert(compressed_keyid(&internal.serialize(), 0x02), secret);
        provider.tr_trees.insert(
            outkey.serialize(),
            crate::descriptor::TaprootSpendData {
                merkle_root: None,
                internal_key: internal.serialize(),
                leaves: Vec::new(),
            },
        );
        let txdata = precompute_psbt_data(&psbt);
        assert!(sign_psbt_input(
            &provider,
            &mut psbt,
            0,
            Some(&txdata),
            0, // SIGHASH_DEFAULT
            false,
            None,
            true,
        ));
        let wit = decode_witness_stack(psbt.inputs[0].get(Psbt::IN_FINAL_SCRIPTWITNESS).unwrap())
            .unwrap();
        assert_eq!(wit.len(), 1);
        assert_eq!(wit[0].len(), 64);
    }

    /// Taproot script path: a `pk()` leaf signs with the leaf key
    /// when the internal key is unknown.
    #[test]
    fn sign_psbt_input_taproot_script_path() {
        let secp = secp256k1::Secp256k1::new();
        let internal_secret = secp256k1::SecretKey::from_slice(&[0x21u8; 32]).unwrap();
        let internal_pair = secp256k1::Keypair::from_secret_key(&secp, &internal_secret);
        let (internal, _parity) = internal_pair.x_only_public_key();
        let leaf_secret = secp256k1::SecretKey::from_slice(&[0x33u8; 32]).unwrap();
        let leaf_pair = secp256k1::Keypair::from_secret_key(&secp, &leaf_secret);
        let (leaf_x, _lp) = leaf_pair.x_only_public_key();
        // `<32B xonly> OP_CHECKSIG` — the pk() leaf.
        let mut leaf_script = vec![0x20];
        leaf_script.extend_from_slice(&leaf_x.serialize());
        leaf_script.push(0xac);
        let root = compute_tapleaf_hash(0xc0, &leaf_script);
        let scalar =
            secp256k1::Scalar::from_be_bytes(tap_tweak(&internal.serialize(), Some(&root)))
                .unwrap();
        let out_pair = internal_pair.add_xonly_tweak(&secp, &scalar).unwrap();
        let (outkey, _) = out_pair.x_only_public_key();
        let mut spk = vec![0x51, 0x20];
        spk.extend_from_slice(&outkey.serialize());
        let mut psbt = psbt_spending(&spk);
        let mut provider = FlatProvider::default();
        provider
            .keys
            .insert(compressed_keyid(&leaf_x.serialize(), 0x02), leaf_secret);
        provider.tr_trees.insert(
            outkey.serialize(),
            crate::descriptor::TaprootSpendData {
                merkle_root: Some(root),
                internal_key: internal.serialize(),
                leaves: vec![(0, leaf_script.clone(), 0xc0)],
            },
        );
        let txdata = precompute_psbt_data(&psbt);
        assert!(sign_psbt_input(
            &provider,
            &mut psbt,
            0,
            Some(&txdata),
            0,
            false,
            None,
            true,
        ));
        let wit = decode_witness_stack(psbt.inputs[0].get(Psbt::IN_FINAL_SCRIPTWITNESS).unwrap())
            .unwrap();
        // [sig, leaf script, control block]
        assert_eq!(wit.len(), 3);
        assert_eq!(wit[0].len(), 64);
        assert_eq!(wit[1], leaf_script);
        assert_eq!(wit[2].len(), 33);
    }

    /// P2WSH 2-of-2: one key leaves a `partial_sigs` entry, the second
    /// reuses it and finalizes.
    #[test]
    fn sign_psbt_input_wsh_multisig_partial() {
        let secp = secp256k1::Secp256k1::new();
        let s1 = secp256k1::SecretKey::from_slice(&[0x41u8; 32]).unwrap();
        let s2 = secp256k1::SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let pk1 = secp256k1::PublicKey::from_secret_key(&secp, &s1)
            .serialize()
            .to_vec();
        let pk2 = secp256k1::PublicKey::from_secret_key(&secp, &s2)
            .serialize()
            .to_vec();
        let mut wscript = vec![0x52, 0x21];
        wscript.extend_from_slice(&pk1);
        wscript.push(0x21);
        wscript.extend_from_slice(&pk2);
        wscript.extend_from_slice(&[0x52, 0xae]);
        let mut spk = vec![0x00, 0x20];
        spk.extend_from_slice(&sha256(&wscript));
        let mut psbt = psbt_spending(&spk);
        let mut provider = FlatProvider::default();
        provider.keys.insert(hash160(&pk1), s1);
        provider.pubkeys.insert(hash160(&pk1), pk1.clone());
        provider.pubkeys.insert(hash160(&pk2), pk2.clone());
        provider.scripts.insert(hash160(&wscript), wscript.clone());
        let txdata = precompute_psbt_data(&psbt);
        // Only s1 → partial sig recorded, input not final.
        assert!(!sign_psbt_input(
            &provider,
            &mut psbt,
            0,
            Some(&txdata),
            1,
            false,
            None,
            true,
        ));
        assert!(!psbt_input_signed(&psbt.inputs[0]));
        let partials: Vec<_> = psbt.inputs[0].all(Psbt::IN_PARTIAL_SIG).collect();
        assert_eq!(partials.len(), 1);
        assert_eq!(partials[0].0[..], pk1[..]);
        // Adding s2 reuses the stored sig for pk1 and finalizes.
        provider.keys.insert(hash160(&pk2), s2);
        assert!(sign_psbt_input(
            &provider,
            &mut psbt,
            0,
            Some(&txdata),
            1,
            false,
            None,
            true,
        ));
        let wit = decode_witness_stack(psbt.inputs[0].get(Psbt::IN_FINAL_SCRIPTWITNESS).unwrap())
            .unwrap();
        // [CHECKMULTISIG dummy, sig1, sig2, witness script]
        assert_eq!(wit.len(), 4);
        assert!(wit[0].is_empty());
        assert_eq!(wit[3], wscript);
        assert!(psbt_input_signed(&psbt.inputs[0]));
    }

    /// `sighashtype` flows through to the appended sighash byte;
    /// `finalize=false` leaves `partial_sigs` instead.
    #[test]
    fn sign_psbt_input_sighash_and_no_finalize() {
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret)
            .serialize()
            .to_vec();
        let keyid = hash160(&pubkey);
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(&keyid);
        let mut provider = FlatProvider::default();
        provider.keys.insert(keyid, secret);
        provider.pubkeys.insert(keyid, pubkey);
        // SIGHASH_NONE|ANYONECANPAY signs and verifies as such.
        let mut psbt = psbt_spending(&spk);
        let txdata = precompute_psbt_data(&psbt);
        assert!(sign_psbt_input(
            &provider,
            &mut psbt,
            0,
            Some(&txdata),
            0x82,
            false,
            None,
            true,
        ));
        let wit = decode_witness_stack(psbt.inputs[0].get(Psbt::IN_FINAL_SCRIPTWITNESS).unwrap())
            .unwrap();
        assert_eq!(wit[0].last(), Some(&0x82));
        // finalize=false → solved (returns true) but the sig lands in
        // partial_sigs only — no final fields, not PSBTInputSigned.
        let mut psbt = psbt_spending(&spk);
        let txdata = precompute_psbt_data(&psbt);
        assert!(sign_psbt_input(
            &provider,
            &mut psbt,
            0,
            Some(&txdata),
            1,
            false,
            None,
            false,
        ));
        assert!(!psbt_input_signed(&psbt.inputs[0]));
        assert_eq!(psbt.inputs[0].all(Psbt::IN_PARTIAL_SIG).count(), 1);
    }

    /// `signrawtransactionwithkey`'s signer: a bare tx spending a
    /// `spk` outpoint. `psbt_spending`'s tx minus the PSBT wrap.
    fn raw_tx() -> Transaction {
        psbt_spending(&[0x51]).tx
    }

    fn wpkh_spk(keyid: &[u8; 20]) -> Vec<u8> {
        let mut spk = vec![0x00, 0x14];
        spk.extend_from_slice(keyid);
        spk
    }

    fn wif_provider(secret: &secp256k1::SecretKey) -> (FlatProvider, [u8; 20]) {
        let secp = secp256k1::Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, secret)
            .serialize()
            .to_vec();
        let keyid = hash160(&pubkey);
        let mut provider = FlatProvider::default();
        provider.keys.insert(keyid, *secret);
        provider.pubkeys.insert(keyid, pubkey);
        (provider, keyid)
    }

    /// A WIF provider signs a P2WPKH input to completion; the witness
    /// lands on the input and `DataFromTransaction` re-reads it as
    /// complete.
    #[test]
    fn sign_transaction_wpkh() {
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let (provider, keyid) = wif_provider(&secret);
        let mut tx = raw_tx();
        let mut coins = HashMap::new();
        coins.insert(
            tx.inputs[0].previous_output,
            Some(TxOut {
                value: 50_000,
                script_pubkey: Script::new(wpkh_spk(&keyid)),
            }),
        );
        let mut errors = BTreeMap::new();
        assert!(sign_transaction(&mut tx, &provider, &coins, 1, &mut errors));
        assert!(errors.is_empty());
        assert_eq!(tx.inputs[0].witness.len(), 2);
        assert!(tx.inputs[0].script_sig.is_empty());
        // `DataFromTransaction` — a verifying input reports complete
        // with the extracted signature.
        let coin_out = coins[&tx.inputs[0].previous_output].clone().unwrap();
        let data = data_from_transaction(&tx, 0, &coin_out);
        assert!(data.complete);
        assert_eq!(data.signatures.len(), 1);
    }

    /// A P2PKH legacy input signs into `script_sig` (no witness).
    #[test]
    fn sign_transaction_pkh() {
        let secret = secp256k1::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let (provider, keyid) = wif_provider(&secret);
        let mut spk = vec![0x76, 0xa9, 0x14];
        spk.extend_from_slice(&keyid);
        spk.extend_from_slice(&[0x88, 0xac]);
        let mut tx = raw_tx();
        let mut coins = HashMap::new();
        coins.insert(
            tx.inputs[0].previous_output,
            Some(TxOut {
                value: 50_000,
                script_pubkey: Script::new(spk),
            }),
        );
        let mut errors = BTreeMap::new();
        assert!(sign_transaction(&mut tx, &provider, &coins, 1, &mut errors));
        assert!(!tx.inputs[0].script_sig.is_empty());
        assert!(tx.inputs[0].witness.is_empty());
    }

    /// An unresolvable outpoint is `Coin::IsSpent` — the input error
    /// "Input not found or already spent" makes the tx incomplete.
    #[test]
    fn sign_transaction_input_not_found() {
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let (provider, _) = wif_provider(&secret);
        let mut tx = raw_tx();
        let mut coins = HashMap::new();
        coins.insert(tx.inputs[0].previous_output, None);
        let mut errors = BTreeMap::new();
        assert!(!sign_transaction(
            &mut tx,
            &provider,
            &coins,
            1,
            &mut errors
        ));
        assert_eq!(errors[&0], "Input not found or already spent");
    }

    /// A segwit coin at the `MAX_MONEY` sentinel — signed witness but
    /// the amount was never provided — reports `Missing amount`
    /// (surfaced as the `-3` exception by the RPC layer).
    #[test]
    fn sign_transaction_missing_amount() {
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let (provider, keyid) = wif_provider(&secret);
        let mut tx = raw_tx();
        let mut coins = HashMap::new();
        coins.insert(
            tx.inputs[0].previous_output,
            Some(TxOut {
                value: crate::check::MAX_MONEY,
                script_pubkey: Script::new(wpkh_spk(&keyid)),
            }),
        );
        let mut errors = BTreeMap::new();
        assert!(!sign_transaction(
            &mut tx,
            &provider,
            &coins,
            1,
            &mut errors
        ));
        assert_eq!(errors[&0], "Missing amount");
    }

    /// A key that doesn't own the output leaves the input unsigned and
    /// the verification failure becomes the input error.
    #[test]
    fn sign_transaction_wrong_key() {
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let (provider, _) = wif_provider(&secret);
        let mut tx = raw_tx();
        let mut coins = HashMap::new();
        coins.insert(
            tx.inputs[0].previous_output,
            Some(TxOut {
                value: 50_000,
                script_pubkey: Script::new(wpkh_spk(&[0xee; 20])),
            }),
        );
        let mut errors = BTreeMap::new();
        assert!(!sign_transaction(
            &mut tx,
            &provider,
            &coins,
            1,
            &mut errors
        ));
        assert!(errors.contains_key(&0));
    }

    /// `SIGHASH_SINGLE` without a matching output skips signing — the
    /// input error reflects the untouched, failing spend.
    #[test]
    fn sign_transaction_single_no_output() {
        let secret = secp256k1::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let (provider, keyid) = wif_provider(&secret);
        let mut tx = raw_tx();
        tx.inputs.push(crate::transaction::TxIn {
            previous_output: OutPoint {
                txid: crate::hash::Txid::from_bytes([0x33; 32]),
                vout: 7,
            },
            script_sig: Script::new(Vec::new()),
            sequence: 0xffff_ffff,
            witness: Witness::default(),
        });
        let mut coins = HashMap::new();
        for i in 0..2 {
            coins.insert(
                tx.inputs[i].previous_output,
                Some(TxOut {
                    value: 50_000,
                    script_pubkey: Script::new(wpkh_spk(&keyid)),
                }),
            );
        }
        let mut errors = BTreeMap::new();
        // Input 1 has no corresponding output — Core skips signing it.
        assert!(!sign_transaction(
            &mut tx,
            &provider,
            &coins,
            3,
            &mut errors
        ));
        assert!(tx.inputs[0].witness.len() == 2);
        assert!(errors.contains_key(&1));
    }

    /// `MergeSignatureData` — a complete other side replaces, partial
    /// data unions signatures and fills unset scripts, and a complete
    /// self is never degraded.
    #[test]
    fn merge_signature_data_core_semantics() {
        let mut dst = SignatureData::default();
        let mut src = SignatureData::default();
        src.signatures
            .insert([0x11; 20], (vec![0x02; 33], vec![0x30; 70]));
        dst.redeem_script = Some(vec![0xaa]);
        src.redeem_script = Some(vec![0xbb]);
        src.witness_script = Some(vec![0xcc]);
        dst.merge_signature_data(src);
        // redeem kept (already set), witness filled, sigs unioned.
        assert_eq!(dst.redeem_script.as_deref(), Some(&[0xaa][..]));
        assert_eq!(dst.witness_script.as_deref(), Some(&[0xcc][..]));
        assert_eq!(dst.signatures.len(), 1);

        // A complete source wins wholesale.
        let done = SignatureData {
            complete: true,
            script_sig: vec![0x51],
            ..SignatureData::default()
        };
        dst.merge_signature_data(done);
        assert!(dst.complete && dst.script_sig == vec![0x51]);
        assert!(dst.signatures.is_empty()); // wholesale replace

        // A complete self ignores the merge.
        let mut src2 = SignatureData::default();
        src2.signatures
            .insert([0x22; 20], (vec![0x03; 33], vec![0x30; 70]));
        dst.merge_signature_data(src2);
        assert!(dst.signatures.is_empty());
    }

    /// Queue #35/#36 end-to-end: a descriptor-derived provider signs a
    /// PSBT only when its prevout claims match the verified UTXO set —
    /// an understated claim (the LSB-010 fee-inflation attack) is a
    /// hard reject, not a signature.
    #[test]
    fn descriptor_signer_verifies_prevouts_then_signs() {
        use crate::descriptor::{DeriveCache, FlatProvider, parse_descriptors};
        use crate::extended_key::ExtKey;

        let params = crate::params::Network::Regtest.params();
        const H: u32 = 0x8000_0000;
        // The createdescriptorseed path: seed → master → m/84h/1h/0h.
        let master = ExtKey::from_seed(&[42u8; 32], params.base58_ext_secret_prefix).unwrap();
        let account = master
            .derive(84 | H)
            .and_then(|k| k.derive(1 | H))
            .and_then(|k| k.derive(H))
            .unwrap();
        let fp = hex::encode(&master.fingerprint());
        let body = format!("wpkh([{fp}/84h/1h/0h]{}/0/*)", account.encode());
        let desc = format!("{body}#{}", crate::descriptor::descriptor_checksum(&body));
        let (parsed, mut signing, _) = parse_descriptors(&desc, &params, true).unwrap();
        // expand_priv — the secrets for derived keys land in the provider.
        let mut expanded = FlatProvider::default();
        let mut cache = DeriveCache::new();
        let scripts = parsed[0]
            .expand_into(0, &signing, &mut expanded, true, &mut cache)
            .unwrap();
        signing.keys.extend(expanded.keys);
        signing.pubkeys.extend(expanded.pubkeys);
        signing.origins.extend(expanded.origins);
        let spk = scripts
            .iter()
            .find(|s| s.len() == 22 && s[0] == 0x00 && s[1] == 0x14)
            .unwrap()
            .clone();

        // The verified UTXO set holds a 50_000-sat coin paying to it.
        let mut utxo = crate::connect::UtxoSet::new();
        let outpoint = OutPoint {
            txid: crate::hash::Txid::from_bytes([0x22; 32]),
            vout: 0,
        };
        utxo.insert_synthetic(
            outpoint,
            crate::connect::Coin {
                out: TxOut {
                    value: 50_000,
                    script_pubkey: Script::new(spk.clone()),
                },
                height: 1,
                coinbase: false,
            },
        );

        // Honest claim → verified against the set, then a REAL signature.
        let mut psbt = psbt_spending(&spk);
        let checks = verify_and_fill_prevouts(&utxo, &mut psbt).unwrap();
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].status, "verified");
        assert_eq!(checks[0].claimed_sats, Some(50_000));
        let txdata = precompute_psbt_data(&psbt);
        assert!(sign_psbt_input(
            &signing,
            &mut psbt,
            0,
            Some(&txdata),
            1,
            false,
            None,
            true,
        ));
        assert!(finalize_and_extract_psbt(&mut psbt).is_some());

        // Lying claim — 49_999 claimed where the set says 50_000 —
        // the fee-inflation attack is refused outright.
        let mut bad = psbt_spending(&spk);
        let mut lie = 49_999i64.to_le_bytes().to_vec();
        crate::encode::write_var_bytes(&mut lie, &spk);
        bad.inputs[0].set(vec![Psbt::IN_WITNESS_UTXO], lie);
        assert!(verify_and_fill_prevouts(&utxo, &mut bad).is_err());
    }
}

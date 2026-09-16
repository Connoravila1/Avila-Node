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

use crate::hash::hash160;
use crate::interpreter::{SigVersion, SignatureChecker, compute_tapleaf_hash, verify_script};
use crate::psbt::{KeyMap, Psbt};
use crate::script::ScriptType;
use crate::sigchecker::{PrecomputedTransactionData, TransactionSignatureChecker};
use crate::transaction::{Script, Transaction, TxOut, Witness};

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
            if xonly.len() != 32 || v.len() < 4 {
                continue;
            }
            let mut xk = [0u8; 32];
            xk.copy_from_slice(xonly);
            let leaf_count = u32::from_le_bytes([v[0], v[1], v[2], v[3]]) as usize;
            let leaf_end = 4 + 32 * leaf_count;
            let mut leaves = Vec::new();
            if v.len() >= leaf_end {
                for i in 0..leaf_count {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&v[4 + 32 * i..4 + 32 * i + 32]);
                    leaves.push(h);
                }
                self.tap_misc.insert(xk, (leaves, v[leaf_end..].to_vec()));
                self.tap_pubkeys.insert(hash160(&xk), xk);
            }
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
            let mut value = (leaves.len() as u32).to_le_bytes().to_vec();
            for h in leaves {
                value.extend_from_slice(h);
            }
            value.extend_from_slice(origin);
            if !map.contains(&key) {
                map.set(key, value);
            }
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

/// `GetCScript` against an empty provider — only the PSBT-carried
/// redeem/witness scripts can satisfy the hash.
fn get_cscript(sigdata: &SignatureData, scriptid: &[u8; 20]) -> Option<Vec<u8>> {
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
    None
}

/// `GetPubKey` against an empty provider — partial-sig keydata,
/// BIP32-derivation keydata, then taproot pubkeys (even-Y form).
fn get_pubkey(sigdata: &SignatureData, keyid: &[u8; 20]) -> Option<Vec<u8>> {
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
    None
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

/// `CreateSig` — reuse an existing partial sig, else create through
/// the pass's creator. `Real` failures record `missing_sigs`.
fn create_sig(sigdata: &mut SignatureData, pubkey: &[u8], mode: Creator) -> Option<Vec<u8>> {
    let keyid = hash160(pubkey);
    if let Some((_, sig)) = sigdata.signatures.get(&keyid) {
        return Some(sig.clone());
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

/// `CreateTaprootScriptSig` — a `(xonly, leaf_hash)`-keyed schnorr sig.
/// Real-mode failures are silent (taproot has no `missing_sigs` entry).
fn create_taproot_script_sig(
    sigdata: &mut SignatureData,
    xonly: &[u8; 32],
    leaf_hash: &[u8; 32],
    mode: Creator,
) -> Option<Vec<u8>> {
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
) -> Option<Vec<Vec<u8>>> {
    if script.len() == 34 && script[0] == 0x20 && script[33] == 0xac {
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&script[1..33]);
        let sig = create_taproot_script_sig(sigdata, &xonly, leaf_hash?, mode)?;
        return Some(vec![sig]);
    }
    None
}

/// `SignTaproot` — key path first, then the smallest satisfying
/// script-path leaf (provider lookups dropped: the provider is empty).
fn sign_taproot(
    output_key: &[u8; 32],
    sigdata: &mut SignatureData,
    mode: Creator,
) -> Option<Vec<Vec<u8>>> {
    // Key path: internal key first (may be null), then the output key.
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
    let _ = output_key;
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
        if let Some(mut stack) = satisfy_pk_leaf(script, Some(&leaf_hash), sigdata, mode) {
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
        ScriptType::PubKey(pubkey) => match create_sig(sigdata, &pubkey, mode) {
            Some(sig) => (true, vec![sig], StepKind::Other),
            None => (false, Vec::new(), StepKind::Other),
        },
        ScriptType::PubKeyHash(h160) => {
            let Some(pubkey) = get_pubkey(sigdata, &h160) else {
                sigdata.missing_pubkeys.push(h160);
                return (false, Vec::new(), StepKind::Other);
            };
            match create_sig(sigdata, &pubkey, mode) {
                Some(sig) => (true, vec![sig, pubkey], StepKind::Other),
                None => (false, Vec::new(), StepKind::Other),
            }
        }
        ScriptType::ScriptHash(h160) => match get_cscript(sigdata, &h160) {
            Some(script) => (true, vec![script], StepKind::ScriptHash),
            None => {
                sigdata.missing_redeem_script = Some(h160);
                (false, Vec::new(), StepKind::ScriptHash)
            }
        },
        ScriptType::Multisig { required, keys } => {
            let mut ret = vec![Vec::new()];
            for pubkey in &keys {
                if let Some(sig) = create_sig(sigdata, pubkey, mode)
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
            match get_cscript(sigdata, &scriptid) {
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
            match sign_taproot(&key, sigdata, mode) {
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
    script_pubkey: &Script,
    sigdata: &mut SignatureData,
    mode: Creator,
    checker: &dyn SignatureChecker,
) -> bool {
    if sigdata.complete {
        return true;
    }
    let (mut solved, mut result, kind) = sign_step(script_pubkey.as_bytes(), sigdata, mode);
    let mut p2sh = false;
    let mut subscript = Vec::new();

    if solved && matches!(kind, StepKind::ScriptHash) {
        subscript = result[0].clone();
        sigdata.redeem_script = Some(subscript.clone());
        let (s2, r2, k2) = sign_step(&subscript, sigdata, mode);
        solved = s2 && !matches!(k2, StepKind::ScriptHash);
        result = r2;
        p2sh = true;
    }

    match kind {
        _ if !solved => {}
        StepKind::W0KeyHash => {
            // OP_DUP OP_HASH160 <program> OP_EQUALVERIFY OP_CHECKSIG
            let mut wsh = Vec::with_capacity(25);
            wsh.extend_from_slice(&[0x76, 0xa9, 0x14]);
            wsh.extend_from_slice(&result[0]);
            wsh.extend_from_slice(&[0x88, 0xac]);
            let (s2, r2, _k2) = sign_step(&wsh, sigdata, mode);
            solved = s2;
            sigdata.script_witness = Some(r2);
            sigdata.witness = true;
            result.clear();
        }
        StepKind::W0ScriptHash => {
            let witnessscript = result[0].clone();
            sigdata.witness_script = Some(witnessscript.clone());
            let (s2, mut r2, k2) = sign_step(&witnessscript, sigdata, mode);
            solved = s2
                && !matches!(k2, StepKind::ScriptHash)
                && !matches!(k2, StepKind::W0ScriptHash)
                && !matches!(k2, StepKind::W0KeyHash);
            if !solved && r2.is_empty() {
                // Miniscript fallback: only the `pk` leaf subset.
                if let Some(stack) = satisfy_wsh_miniscript(&witnessscript, sigdata, mode) {
                    solved = true;
                    r2 = stack;
                }
            }
            r2.push(witnessscript);
            sigdata.script_witness = Some(r2);
            sigdata.witness = true;
            result.clear();
        }
        StepKind::Taproot if !p2sh => {
            sigdata.witness = true;
            if solved {
                sigdata.script_witness = Some(result.clone());
            }
            result.clear();
        }
        _ => {}
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
) -> Option<Vec<Vec<u8>>> {
    // `<33B compressed pubkey> OP_CHECKSIG` — `pk(key)` in P2WSH.
    if script.len() == 35 && script[0] == 0x21 && script[34] == 0xac {
        let sig = create_sig(sigdata, &script[1..34], mode)?;
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
            produce_signature(&utxo.script_pubkey, &mut sigdata, mode, &checker)
        }
        None => produce_signature(&utxo.script_pubkey, &mut sigdata, mode, &DummyChecker),
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
            if !sign_psbt_input(&mut owned, i, None, Creator::Dummy, None, true) {
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
}

//! The transaction-dependent half of script verification — ports of
//! `SignatureHash` (legacy), the BIP143 segwit-v0 branch of `SignatureHash`,
//! `SignatureHashSchnorr` (BIP341/BIP342), `PrecomputedTransactionData`,
//! `GenericTransactionSignatureChecker`, and `CheckInputScripts` from Core
//! v29's `script/interpreter.cpp` and `validation.cpp`.
//!
//! [`TransactionSignatureChecker`] implements [`SignatureChecker`], the trait
//! `interpreter.rs`'s `EvalScript` port delegates to. Signature verification
//! uses the `secp256k1` crate — Rust bindings to libsecp256k1, the same C
//! library Bitcoin Core links for consensus signature verification — so DER
//! lax-parsing and verification edge cases match the reference implementation
//! bit-for-bit.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use crate::check::{LOCKTIME_THRESHOLD, SEQUENCE_FINAL};
use crate::connect::{
    SEQUENCE_LOCKS_MIN_VERSION, SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_MASK,
    SEQUENCE_LOCKTIME_TYPE_FLAG,
};
use crate::encode::{write_compact_size, write_var_bytes};
use crate::hash::{sha256, sha256d};
use crate::interpreter::{
    ExecutionData, OP_CODESEPARATOR, ScriptError, SigVersion, SignatureChecker, get_op,
    verify_script,
};
use crate::script::OP_1;
use crate::transaction::{Script, Transaction, TxOut};

// ---------------------------------------------------------------------------
// Sighash constants (script/interpreter.h)
// ---------------------------------------------------------------------------

/// `SIGHASH_DEFAULT` (BIP341): no sighash byte — equivalent to `SIGHASH_ALL`.
pub const SIGHASH_DEFAULT: u8 = 0;
/// `SIGHASH_ALL`.
pub const SIGHASH_ALL: u8 = 1;
/// `SIGHASH_NONE`.
pub const SIGHASH_NONE: u8 = 2;
/// `SIGHASH_SINGLE`.
pub const SIGHASH_SINGLE: u8 = 3;
/// `SIGHASH_ANYONECANPAY`.
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
/// `SIGHASH_OUTPUT_MASK` (BIP341).
pub const SIGHASH_OUTPUT_MASK: u8 = 3;
/// `SIGHASH_INPUT_MASK` (BIP341).
pub const SIGHASH_INPUT_MASK: u8 = 0x80;

/// `secp256k1_context_static` equivalent — a verification-only context shared
/// across checks (contexts are expensive; Core keeps one process-wide too).
fn secp() -> &'static secp256k1::Secp256k1<secp256k1::VerifyOnly> {
    static SECP: OnceLock<secp256k1::Secp256k1<secp256k1::VerifyOnly>> = OnceLock::new();
    SECP.get_or_init(secp256k1::Secp256k1::verification_only)
}

/// A `HashWriter` pre-initialized with `SHA256(tag) || SHA256(tag)` — Core's
/// `TaggedHash`/`HASHER_TAPSIGHASH`/`HASHER_TAPTWEAK` initialization.
fn tagged_hasher(tag: &str) -> Sha256 {
    let tag_hash = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h
}

// ---------------------------------------------------------------------------
// PrecomputedTransactionData
// ---------------------------------------------------------------------------

/// `PrecomputedTransactionData`: the per-transaction midstate caches shared by
/// the BIP143 and BIP341 sighash algorithms. Populated by [`Self::new`],
/// mirroring `PrecomputedTransactionData::Init` including its
/// witness-scan feature detection.
#[derive(Clone, Debug, Default)]
pub struct PrecomputedTransactionData {
    /// `m_spent_outputs` — every output this transaction spends, in input order.
    pub spent_outputs: Vec<TxOut>,
    /// `m_spent_outputs_ready`.
    pub spent_outputs_ready: bool,
    /// `m_bip143_segwit_ready` / `m_bip341_taproot_ready`.
    pub bip143_segwit_ready: bool,
    /// See [`PrecomputedTransactionData::bip143_segwit_ready`].
    pub bip341_taproot_ready: bool,
    prevouts_single_hash: [u8; 32],
    sequences_single_hash: [u8; 32],
    outputs_single_hash: [u8; 32],
    spent_amounts_single_hash: [u8; 32],
    spent_scripts_single_hash: [u8; 32],
    hash_prevouts: [u8; 32],
    hash_sequence: [u8; 32],
    hash_outputs: [u8; 32],
}

/// `GetPrevoutsSHA256` — single SHA256 over the concatenated prevouts.
fn prevouts_single_hash(tx: &Transaction) -> [u8; 32] {
    let mut h = Sha256::new();
    for input in &tx.inputs {
        h.update(input.previous_output.txid.as_bytes());
        h.update(input.previous_output.vout.to_le_bytes());
    }
    h.finalize().into()
}

/// `GetSequencesSHA256` — single SHA256 over the concatenated `nSequence`s.
fn sequences_single_hash(tx: &Transaction) -> [u8; 32] {
    let mut h = Sha256::new();
    for input in &tx.inputs {
        h.update(input.sequence.to_le_bytes());
    }
    h.finalize().into()
}

/// Serialize a `CTxOut`: `nValue` (i64 LE) then `scriptPubKey` as
/// CompactSize-prefixed bytes.
fn write_txout(out: &mut Vec<u8>, txout: &TxOut) {
    out.extend_from_slice(&txout.value.to_le_bytes());
    write_var_bytes(out, txout.script_pubkey.as_bytes());
}

/// `GetOutputsSHA256` — single SHA256 over the concatenated `CTxOut`s.
fn outputs_single_hash(tx: &Transaction) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut buf = Vec::new();
    for output in &tx.outputs {
        buf.clear();
        write_txout(&mut buf, output);
        h.update(&buf);
    }
    h.finalize().into()
}

/// `GetSpentAmountsSHA256` — single SHA256 over the spent `nValue`s.
fn spent_amounts_single_hash(spent: &[TxOut]) -> [u8; 32] {
    let mut h = Sha256::new();
    for txout in spent {
        h.update(txout.value.to_le_bytes());
    }
    h.finalize().into()
}

/// `GetSpentScriptsSHA256` — single SHA256 over the spent `scriptPubKey`s,
/// each serialized as CompactSize-prefixed bytes (`ss << scriptPubKey`).
fn spent_scripts_single_hash(spent: &[TxOut]) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut buf = Vec::new();
    for txout in spent {
        buf.clear();
        write_var_bytes(&mut buf, txout.script_pubkey.as_bytes());
        h.update(&buf);
    }
    h.finalize().into()
}

impl PrecomputedTransactionData {
    /// `Init` — build the midstate caches for `tx`. `spent_outputs` is every
    /// output spent by `tx`'s inputs, in input order; pass `None` when the
    /// UTXO view is unavailable (taproot sighashes will then report missing
    /// data, matching `HandleMissingData(FAIL)`).
    ///
    /// `force` (`Init`'s third parameter) precomputes all caches regardless of
    /// witness usage — used by tests.
    #[must_use]
    pub fn new(tx: &Transaction, spent_outputs: Option<Vec<TxOut>>, force: bool) -> Self {
        let mut this = Self::default();
        if let Some(outs) = spent_outputs {
            this.spent_outputs = outs;
            if !this.spent_outputs.is_empty() {
                debug_assert_eq!(this.spent_outputs.len(), tx.inputs.len());
                this.spent_outputs_ready = true;
            }
        }

        // Determine which precomputation-impacting features this transaction
        // uses — Core's witness-scan heuristic.
        let mut uses_bip143_segwit = force;
        let mut uses_bip341_taproot = force;
        for (inpos, input) in tx.inputs.iter().enumerate() {
            if uses_bip143_segwit && uses_bip341_taproot {
                break;
            }
            if input.witness.is_empty() {
                continue;
            }
            let is_taproot_spk = this.spent_outputs_ready
                && this.spent_outputs[inpos].script_pubkey.len() == 2 + 32
                && this.spent_outputs[inpos].script_pubkey.as_bytes()[0] == OP_1;
            if is_taproot_spk {
                // Treat every witness-bearing spend with a 34-byte
                // scriptPubKey starting with OP_1 as taproot.
                uses_bip341_taproot = true;
            } else {
                uses_bip143_segwit = true;
            }
        }

        if uses_bip143_segwit || uses_bip341_taproot {
            this.prevouts_single_hash = prevouts_single_hash(tx);
            this.sequences_single_hash = sequences_single_hash(tx);
            this.outputs_single_hash = outputs_single_hash(tx);
        }
        if uses_bip143_segwit {
            this.hash_prevouts = sha256(&this.prevouts_single_hash);
            this.hash_sequence = sha256(&this.sequences_single_hash);
            this.hash_outputs = sha256(&this.outputs_single_hash);
            this.bip143_segwit_ready = true;
        }
        if uses_bip341_taproot && this.spent_outputs_ready {
            this.spent_amounts_single_hash = spent_amounts_single_hash(&this.spent_outputs);
            this.spent_scripts_single_hash = spent_scripts_single_hash(&this.spent_outputs);
            this.bip341_taproot_ready = true;
        }
        this
    }
}

// ---------------------------------------------------------------------------
// Legacy sighash — CTransactionSignatureSerializer
// ---------------------------------------------------------------------------

/// `SerializeScriptCode` — emit `script_code` (with `OP_CODESEPARATOR`s
/// removed) as a CompactSize-prefixed byte string. The walk mirrors
/// `CScript::GetOp`: a malformed tail push contributes its opcode/length
/// bytes but is cut where `GetScriptOp` fails.
fn write_script_code(out: &mut Vec<u8>, script_code: &[u8]) {
    // First pass: count separators.
    let mut pc = 0usize;
    let mut n_separators = 0usize;
    while let Some((opcode, _)) = get_op(script_code, &mut pc) {
        if opcode == OP_CODESEPARATOR {
            n_separators += 1;
        }
    }
    write_compact_size(out, (script_code.len() - n_separators) as u64);

    // Second pass: emit the segments between separators. On GetOp failure
    // `pc` is left at the failure position — the tail write covers
    // [seg_start, failure_pos), matching Core.
    let mut pc = 0usize;
    let mut seg_start = 0usize;
    while let Some((opcode, _)) = get_op(script_code, &mut pc) {
        if opcode == OP_CODESEPARATOR {
            // `pc` has advanced past the separator byte.
            out.extend_from_slice(&script_code[seg_start..pc - 1]);
            seg_start = pc;
        }
    }
    if seg_start != script_code.len() {
        out.extend_from_slice(&script_code[seg_start..pc]);
    }
}

/// `CTransactionSignatureSerializer` — the legacy sighash preimage.
fn write_legacy_sighash_preimage(
    out: &mut Vec<u8>,
    tx: &Transaction,
    script_code: &Script,
    n_in: usize,
    hash_type: i32,
) {
    let anyone_can_pay = hash_type & i32::from(SIGHASH_ANYONECANPAY) != 0;
    let hash_single = (hash_type & 0x1f) == i32::from(SIGHASH_SINGLE);
    let hash_none = (hash_type & 0x1f) == i32::from(SIGHASH_NONE);

    out.extend_from_slice(&tx.version.to_le_bytes());

    let n_inputs = if anyone_can_pay { 1 } else { tx.inputs.len() };
    write_compact_size(out, n_inputs as u64);
    for n_input in 0..n_inputs {
        // With ANYONECANPAY only the input being signed is serialized.
        let idx = if anyone_can_pay { n_in } else { n_input };
        let input = &tx.inputs[idx];
        out.extend_from_slice(input.previous_output.txid.as_bytes());
        out.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        if idx != n_in {
            // Blank out other inputs' signatures.
            write_compact_size(out, 0);
        } else {
            write_script_code(out, script_code.as_bytes());
        }
        if idx != n_in && (hash_single || hash_none) {
            out.extend_from_slice(&0u32.to_le_bytes());
        } else {
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
    }

    let n_outputs = if hash_none {
        0
    } else if hash_single {
        n_in + 1
    } else {
        tx.outputs.len()
    };
    write_compact_size(out, n_outputs as u64);
    for n_output in 0..n_outputs {
        if hash_single && n_output != n_in {
            // CTxOut() — value -1, empty script.
            out.extend_from_slice(&(-1i64).to_le_bytes());
            write_compact_size(out, 0);
        } else {
            write_txout(out, &tx.outputs[n_output]);
        }
    }

    out.extend_from_slice(&tx.lock_time.to_le_bytes());
}

// ---------------------------------------------------------------------------
// SignatureHash — legacy + BIP143
// ---------------------------------------------------------------------------

/// `SignatureHash` — the message digest an ECDSA signature commits to. Covers
/// the legacy algorithm ([`SigVersion::Base`]) and BIP143
/// ([`SigVersion::WitnessV0`]); taproot signatures use
/// [`signature_hash_schnorr`].
///
/// Returns `0x0000…0001` (`uint256::ONE`) for the out-of-range
/// `SIGHASH_SINGLE` case — Core's famous sighash bug, consensus-preserved.
#[must_use]
pub fn signature_hash(
    script_code: &Script,
    tx: &Transaction,
    n_in: usize,
    hash_type: i32,
    amount: i64,
    sigversion: SigVersion,
    cache: Option<&PrecomputedTransactionData>,
) -> [u8; 32] {
    debug_assert!(n_in < tx.inputs.len());

    if sigversion == SigVersion::WitnessV0 {
        // `cacheready` — a provided cache whose BIP143 midstates are populated.
        let cache = cache.filter(|c| c.bip143_segwit_ready);
        let mut hash_prevouts = [0u8; 32];
        let mut hash_sequence = [0u8; 32];
        let mut hash_outputs = [0u8; 32];

        if hash_type & i32::from(SIGHASH_ANYONECANPAY) == 0 {
            hash_prevouts = match cache {
                Some(c) => c.hash_prevouts,
                None => sha256(&prevouts_single_hash(tx)),
            };
        }
        if hash_type & i32::from(SIGHASH_ANYONECANPAY) == 0
            && (hash_type & 0x1f) != i32::from(SIGHASH_SINGLE)
            && (hash_type & 0x1f) != i32::from(SIGHASH_NONE)
        {
            hash_sequence = match cache {
                Some(c) => c.hash_sequence,
                None => sha256(&sequences_single_hash(tx)),
            };
        }
        if (hash_type & 0x1f) != i32::from(SIGHASH_SINGLE)
            && (hash_type & 0x1f) != i32::from(SIGHASH_NONE)
        {
            hash_outputs = match cache {
                Some(c) => c.hash_outputs,
                None => sha256(&outputs_single_hash(tx)),
            };
        } else if (hash_type & 0x1f) == i32::from(SIGHASH_SINGLE) && n_in < tx.outputs.len() {
            // `ss.GetHash()` — double SHA256 of the single output.
            let mut buf = Vec::new();
            write_txout(&mut buf, &tx.outputs[n_in]);
            hash_outputs = sha256d(&buf);
        }

        let mut ss = Vec::new();
        ss.extend_from_slice(&tx.version.to_le_bytes());
        ss.extend_from_slice(&hash_prevouts);
        ss.extend_from_slice(&hash_sequence);
        ss.extend_from_slice(tx.inputs[n_in].previous_output.txid.as_bytes());
        ss.extend_from_slice(&tx.inputs[n_in].previous_output.vout.to_le_bytes());
        write_var_bytes(&mut ss, script_code.as_bytes());
        ss.extend_from_slice(&amount.to_le_bytes());
        ss.extend_from_slice(&tx.inputs[n_in].sequence.to_le_bytes());
        ss.extend_from_slice(&hash_outputs);
        ss.extend_from_slice(&tx.lock_time.to_le_bytes());
        ss.extend_from_slice(&hash_type.to_le_bytes());
        return sha256d(&ss);
    }

    // Legacy path: SIGHASH_SINGLE past the last output commits to
    // uint256::ONE.
    if (hash_type & 0x1f) == i32::from(SIGHASH_SINGLE) && n_in >= tx.outputs.len() {
        let mut one = [0u8; 32];
        one[0] = 1;
        return one;
    }

    let mut ss = Vec::new();
    write_legacy_sighash_preimage(&mut ss, tx, script_code, n_in, hash_type);
    ss.extend_from_slice(&hash_type.to_le_bytes());
    sha256d(&ss)
}

// ---------------------------------------------------------------------------
// SignatureHashSchnorr — BIP341/BIP342
// ---------------------------------------------------------------------------

/// `SignatureHashSchnorr` — the BIP341 tagged-hash sighash for taproot key-path
/// ([`SigVersion::Taproot`]) and tapscript ([`SigVersion::Tapscript`])
/// signatures.
///
/// Returns `None` exactly where Core's function returns `false`: unknown hash
/// type, out-of-range `SIGHASH_SINGLE`, or missing precomputed data
/// (`HandleMissingData(FAIL)` → `false`). The caller maps `None` to
/// [`ScriptError::SchnorrSigHashType`].
#[must_use]
pub fn signature_hash_schnorr(
    tx: &Transaction,
    n_in: usize,
    hash_type: u8,
    sigversion: SigVersion,
    cache: &PrecomputedTransactionData,
    execdata: &mut ExecutionData,
) -> Option<[u8; 32]> {
    let (ext_flag, key_version): (u8, u8) = match sigversion {
        SigVersion::Taproot => (0, 0),
        SigVersion::Tapscript => (1, 0),
        _ => unreachable!("schnorr sighash only for taproot sigversions"),
    };
    debug_assert!(n_in < tx.inputs.len());
    if !(cache.bip341_taproot_ready && cache.spent_outputs_ready) {
        return None;
    }

    let mut ss = tagged_hasher("TapSighash");
    // Epoch.
    ss.update([0u8]);

    let output_type = if hash_type == SIGHASH_DEFAULT {
        SIGHASH_ALL
    } else {
        hash_type & SIGHASH_OUTPUT_MASK
    };
    let input_type = hash_type & SIGHASH_INPUT_MASK;
    if !(hash_type <= 0x03 || (0x81..=0x83).contains(&hash_type)) {
        return None;
    }
    ss.update([hash_type]);

    // Transaction-level data.
    ss.update(tx.version.to_le_bytes());
    ss.update(tx.lock_time.to_le_bytes());
    if input_type != SIGHASH_ANYONECANPAY {
        ss.update(cache.prevouts_single_hash);
        ss.update(cache.spent_amounts_single_hash);
        ss.update(cache.spent_scripts_single_hash);
        ss.update(cache.sequences_single_hash);
    }
    if output_type == SIGHASH_ALL {
        ss.update(cache.outputs_single_hash);
    }

    // Data about the input/prevout being spent.
    debug_assert!(execdata.annex_init);
    let have_annex = execdata.annex_present;
    let spend_type = (ext_flag << 1) | u8::from(have_annex);
    ss.update([spend_type]);
    if input_type == SIGHASH_ANYONECANPAY {
        let input = &tx.inputs[n_in];
        ss.update(input.previous_output.txid.as_bytes());
        ss.update(input.previous_output.vout.to_le_bytes());
        let mut buf = Vec::new();
        write_txout(&mut buf, &cache.spent_outputs[n_in]);
        ss.update(&buf);
        ss.update(input.sequence.to_le_bytes());
    } else {
        ss.update((n_in as u32).to_le_bytes());
    }
    if have_annex {
        // `m_annex_init` is asserted above: present implies the hash is set.
        ss.update(execdata.annex_hash?);
    }

    // Data about the single output.
    if output_type == SIGHASH_SINGLE {
        if n_in >= tx.outputs.len() {
            return None;
        }
        let output_hash = *execdata.output_hash.get_or_insert_with(|| {
            let mut buf = Vec::new();
            write_txout(&mut buf, &tx.outputs[n_in]);
            sha256(&buf)
        });
        ss.update(output_hash);
    }

    // Additional data for BIP342 signatures.
    if sigversion == SigVersion::Tapscript {
        debug_assert!(execdata.tapleaf_hash_init);
        ss.update(execdata.tapleaf_hash?);
        ss.update([key_version]);
        debug_assert!(execdata.codeseparator_pos_init);
        ss.update(execdata.codeseparator_pos.to_le_bytes());
    }

    Some(ss.finalize().into())
}

// ---------------------------------------------------------------------------
// TransactionSignatureChecker — GenericTransactionSignatureChecker
// ---------------------------------------------------------------------------

/// `GenericTransactionSignatureChecker` — the concrete [`SignatureChecker`]
/// `EvalScript` runs against during block connection. Constructed per input;
/// `txdata` is shared across the transaction's inputs.
pub struct TransactionSignatureChecker<'a> {
    /// The spending transaction (`txTo`).
    pub tx: &'a Transaction,
    /// Index of the input being checked (`nIn`).
    pub n_in: usize,
    /// The spent output's value (`m_tx_out.nValue`), or a negative value for
    /// missing-data behavior (`HandleMissingData(FAIL)` → false).
    pub amount: i64,
    /// The shared per-transaction caches (`this->txdata`).
    pub txdata: Option<&'a PrecomputedTransactionData>,
}

impl<'a> TransactionSignatureChecker<'a> {
    /// `GenericTransactionSignatureChecker` constructor.
    #[must_use]
    pub fn new(
        tx: &'a Transaction,
        n_in: usize,
        amount: i64,
        txdata: &'a PrecomputedTransactionData,
    ) -> Self {
        Self {
            tx,
            n_in,
            amount,
            txdata: Some(txdata),
        }
    }

    /// `VerifyECDSASignature` — `CPubKey::Verify`: parse the pubkey
    /// (`secp256k1_ec_pubkey_parse`), lax-DER-parse the signature, normalize
    /// low-S, verify. libsecp256k1's verification requires lower-S
    /// signatures, which have not historically been enforced in Bitcoin —
    /// `CPubKey::Verify` normalizes first (`secp256k1_ecdsa_signature_normalize`),
    /// so we do the same (pubkey.cpp:283).
    fn verify_ecdsa_signature(sig: &[u8], pubkey: &[u8], sighash: &[u8; 32]) -> bool {
        let Ok(pk) = secp256k1::PublicKey::from_slice(pubkey) else {
            return false;
        };
        let Ok(mut sig) = secp256k1::ecdsa::Signature::from_der_lax(sig) else {
            return false;
        };
        sig.normalize_s();
        let Ok(msg) = secp256k1::Message::from_digest_slice(sighash) else {
            return false;
        };
        secp().verify_ecdsa(&msg, &sig, &pk).is_ok()
    }

    /// `VerifySchnorrSignature` — `XOnlyPubKey::VerifySchnorr`.
    fn verify_schnorr_signature(sig: &[u8], pubkey: &[u8], sighash: &[u8; 32]) -> bool {
        let Ok(pk) = secp256k1::XOnlyPublicKey::from_slice(pubkey) else {
            return false;
        };
        let Ok(sig) = secp256k1::schnorr::Signature::from_slice(sig) else {
            return false;
        };
        let Ok(msg) = secp256k1::Message::from_digest_slice(sighash) else {
            return false;
        };
        secp().verify_schnorr(&sig, &msg, &pk).is_ok()
    }
}

impl SignatureChecker for TransactionSignatureChecker<'_> {
    /// `CheckECDSASignature`.
    fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sigversion: SigVersion,
    ) -> bool {
        // CPubKey::IsValid() — non-empty (size ≤ 65 holds by construction in
        // Core; an oversized stack item is rejected as a pubkey-parse failure
        // below, which returns false either way).
        if pubkey.is_empty() {
            return false;
        }
        // The hash type is one byte tacked onto the end of the signature.
        if sig.is_empty() {
            return false;
        }
        let hash_type = i32::from(sig[sig.len() - 1]);
        let sig = &sig[..sig.len() - 1];

        // Witness sighashes need the amount.
        if sigversion == SigVersion::WitnessV0 && self.amount < 0 {
            return false;
        }

        let _t = std::time::Instant::now();
        let sighash = signature_hash(
            &Script::new(script_code.to_vec()),
            self.tx,
            self.n_in,
            hash_type,
            self.amount,
            sigversion,
            self.txdata,
        );
        SIGHASH_NS.fetch_add(
            _t.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        let _t = std::time::Instant::now();
        let r = Self::verify_ecdsa_signature(sig, pubkey, &sighash);
        VERIFY_NS.fetch_add(
            _t.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        r
    }

    /// `CheckSchnorrSignature` — every failure path maps to the ScriptError
    /// Core's `serror` would hold.
    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        sigversion: SigVersion,
        execdata: &mut ExecutionData,
    ) -> Result<(), ScriptError> {
        debug_assert!(matches!(
            sigversion,
            SigVersion::Taproot | SigVersion::Tapscript
        ));
        debug_assert_eq!(pubkey.len(), 32);
        if sig.len() != 64 && sig.len() != 65 {
            return Err(ScriptError::SchnorrSigSize);
        }
        let mut hash_type = SIGHASH_DEFAULT;
        let mut sig = sig;
        if sig.len() == 65 {
            hash_type = sig[sig.len() - 1];
            sig = &sig[..sig.len() - 1];
            if hash_type == SIGHASH_DEFAULT {
                return Err(ScriptError::SchnorrSigHashType);
            }
        }
        let Some(txdata) = self.txdata else {
            return Err(ScriptError::SchnorrSigHashType);
        };
        let Some(sighash) =
            signature_hash_schnorr(self.tx, self.n_in, hash_type, sigversion, txdata, execdata)
        else {
            return Err(ScriptError::SchnorrSigHashType);
        };
        if !Self::verify_schnorr_signature(sig, pubkey, &sighash) {
            return Err(ScriptError::SchnorrSig);
        }
        Ok(())
    }

    /// `CheckLockTime` — BIP65.
    fn check_locktime(&self, locktime: i64) -> bool {
        let tx_locktime = i64::from(self.tx.lock_time);
        // Compare like-for-like lock-time domains (height vs time).
        if !((tx_locktime < i64::from(LOCKTIME_THRESHOLD)
            && locktime < i64::from(LOCKTIME_THRESHOLD))
            || (tx_locktime >= i64::from(LOCKTIME_THRESHOLD)
                && locktime >= i64::from(LOCKTIME_THRESHOLD)))
        {
            return false;
        }
        if locktime > tx_locktime {
            return false;
        }
        // A final sequence on this input disables nLockTime — bypassing CLTV.
        if self.tx.inputs[self.n_in].sequence == SEQUENCE_FINAL {
            return false;
        }
        true
    }

    /// `CheckSequence` — BIP112.
    fn check_sequence(&self, sequence: i64) -> bool {
        let tx_sequence = i64::from(self.tx.inputs[self.n_in].sequence);
        // Version 2+ required for BIP68 semantics (unsigned compare —
        // `CTransaction::version` is `uint32_t` in v29).
        if self.tx.version < SEQUENCE_LOCKS_MIN_VERSION {
            return false;
        }
        if tx_sequence & i64::from(SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0 {
            return false;
        }
        let mask = i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK);
        let tx_sequence_masked = tx_sequence & mask;
        let sequence_masked = sequence & mask;
        // Same domain comparison as CheckLockTime.
        if !((tx_sequence_masked < i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG)
            && sequence_masked < i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG))
            || (tx_sequence_masked >= i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG)
                && sequence_masked >= i64::from(SEQUENCE_LOCKTIME_TYPE_FLAG)))
        {
            return false;
        }
        if sequence_masked > tx_sequence_masked {
            return false;
        }
        true
    }

    /// `XOnlyPubKey::CheckTapTweak` — verify `control`'s internal key tweaked
    /// by `TapTweak(internal || merkle_root)` equals `program`, including the
    /// parity bit in `control[0] & 1`.
    fn verify_taproot_commitment(
        &self,
        control: &[u8],
        program: &[u8],
        tapleaf_hash: &[u8; 32],
    ) -> bool {
        // internal key = control[1..33]; path nodes fold into the merkle root.
        let internal_bytes = &control[1..33];
        let Ok(internal) = secp256k1::XOnlyPublicKey::from_slice(internal_bytes) else {
            return false;
        };
        let merkle_root = crate::interpreter::compute_taproot_merkle_root(control, tapleaf_hash);
        let mut h = tagged_hasher("TapTweak");
        h.update(internal_bytes);
        h.update(merkle_root);
        let tweak: [u8; 32] = h.finalize().into();
        let Ok(tweak) = secp256k1::Scalar::from_be_bytes(tweak) else {
            return false;
        };
        let Ok((xonly, parity)) = internal.add_tweak(secp(), &tweak) else {
            return false;
        };
        let expected_parity = if control[0] & 1 == 1 {
            secp256k1::Parity::Odd
        } else {
            secp256k1::Parity::Even
        };
        parity == expected_parity && xonly.serialize() == program
    }
}

// ---------------------------------------------------------------------------
// CheckInputScripts
// ---------------------------------------------------------------------------

/// `CheckInputScripts` — evaluate every input's script of a non-coinbase
/// transaction against the UTXO-provided outputs it spends. `spent_outputs[i]`
/// is the [`TxOut`] `tx.inputs[i].previous_output` resolves to; Core gathers
/// them from `inputs.AccessCoin` at this same point (before `UpdateCoins`
/// spends them).
///
/// Returns the [`ScriptError`] Core's `VerifyScript` would produce — the
/// caller maps it to `mandatory-script-verify-flag-failed (...)`.
///
/// # Panics (debug builds)
///
/// `spent_outputs.len() != tx.inputs.len()` is a caller bug; Core asserts.
pub fn check_input_scripts(
    tx: &Transaction,
    spent_outputs: &[TxOut],
    flags: crate::script::ScriptFlags,
) -> Result<(), ScriptError> {
    if tx.is_coinbase() {
        return Ok(());
    }
    debug_assert_eq!(spent_outputs.len(), tx.inputs.len());
    let txdata = PrecomputedTransactionData::new(tx, Some(spent_outputs.to_vec()), false);
    for (i, input) in tx.inputs.iter().enumerate() {
        let checker = TransactionSignatureChecker::new(tx, i, spent_outputs[i].value, &txdata);
        verify_script(
            &input.script_sig,
            &spent_outputs[i].script_pubkey,
            Some(&input.witness),
            flags,
            &checker,
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

/// Cumulative ns in ECDSA sighash computation (all script checks).
pub static SIGHASH_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Cumulative ns in the libsecp verify call itself.
pub static VERIFY_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Verified-tx cache — mempool→block script-check dedup
// ---------------------------------------------------------------------------

/// Txs whose input scripts already passed `check_input_scripts` under
/// flag-set F needn't be re-verified at block connect when the block's
/// flags ⊆ F (script flags are monotone-strictening — removing a flag
/// never adds a requirement). Core's mempool does the same dedup via
/// its script-check cache.
///
/// Keyed by **wtxid**, not txid — the txid only commits to the
/// non-witness serialization, so two txs with the same txid can carry
/// different witnesses (e.g. a P2WSH spend with a swapped, invalid
/// witness). A cache keyed by txid would let a block smuggle in an
/// unverified witness under an already-verified txid. The wtxid
/// commits to the full tx including witness data (Core's
/// CheckInputScripts: "only pass in things ... clearly committed to
/// by tx' witness hash"), so a cached pass under `Wtxid` is sound.
/// FIFO eviction, bounded.
struct VerifiedCache {
    map: std::collections::HashMap<crate::hash::Wtxid, u32>,
    order: std::collections::VecDeque<crate::hash::Wtxid>,
}

static VERIFIED: std::sync::LazyLock<std::sync::Mutex<VerifiedCache>> =
    std::sync::LazyLock::new(|| {
        std::sync::Mutex::new(VerifiedCache {
            map: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        })
    });

const VERIFIED_CAP: usize = 50_000;

/// Records a tx's scripts as verified under `flags` (call after a
/// successful `check_input_scripts`, e.g. mempool acceptance).
pub fn mark_scripts_verified(wtxid: crate::hash::Wtxid, flags: crate::script::ScriptFlags) {
    let mut c = VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
    if c.map.contains_key(&wtxid) {
        return;
    }
    if c.order.len() >= VERIFIED_CAP
        && let Some(old) = c.order.pop_front()
    {
        c.map.remove(&old);
    }
    c.order.push_back(wtxid);
    c.map.insert(wtxid, flags.bits());
}

/// True when the tx's scripts were verified under a flag-set that
/// contains `flags` (block_flags ⊆ verified_flags → skip is sound).
pub fn scripts_verified(wtxid: &crate::hash::Wtxid, flags: crate::script::ScriptFlags) -> bool {
    let c = VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
    match c.map.get(wtxid) {
        Some(&verified) if flags.bits() & !verified == 0 => {
            VERIFIED_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            true
        }
        _ => {
            VERIFIED_MISSES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }
    }
}

/// Cache hits — block txs whose script checks were skipped.
pub static VERIFIED_HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Cache misses — block txs verified the hard way.
pub static VERIFIED_MISSES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

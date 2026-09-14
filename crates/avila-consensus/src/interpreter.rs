//! The Bitcoin script interpreter: a faithful port of Bitcoin Core v29's
//! `script/interpreter.cpp` — `EvalScript` (the stack machine and every opcode's
//! semantics), `VerifyScript` (the `scriptSig`/`scriptPubKey`/P2SH/witness
//! orchestration), `VerifyWitnessProgram`, and the DER/pubkey/script-number
//! encoding checks they rely on.
//!
//! Semantic reference: the pinned Core-29-lineage source at
//! `.scratch/interpreter_v29.cpp` (Bitcoin Knots v29.3), plus
//! `.scratch/script_impl_v29.cpp` (`CheckMinimalPush`, `IsOpSuccess`,
//! `IsPayToAnchor`) and `.scratch/script_error_v29.cpp` (error strings).
//! Function names below cite the Core function each mirrors.
//!
//! Signature *verification* is deliberately abstracted behind
//! [`SignatureChecker`]: this module contains no elliptic-curve code. The
//! concrete checker (sighash computation + secp256k1) lives in
//! `crate::sigchecker`; tests use a stub. This mirrors Core's
//! `BaseSignatureChecker` split exactly — `EvalScript` never calls secp256k1
//! directly either.

use std::fmt;

use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::encode::{compact_size_len, write_compact_size};
use crate::hash::sha256;
use crate::script::{
    MAX_SCRIPT_SIZE, OP_0, OP_1, OP_1NEGATE, OP_16, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY,
    OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_EQUAL, OP_HASH160, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4,
    OP_RETURN, ScriptFlags, encode_script_num, push_slice,
};
use crate::transaction::{Script, Witness};

// ---------------------------------------------------------------------------
// Limits and constants (script/script.h)
// ---------------------------------------------------------------------------

/// `MAX_SCRIPT_ELEMENT_SIZE` — the largest byte string a push or a witness stack
/// item may carry.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// `MAX_OPS_PER_SCRIPT` — counted only for opcodes `> OP_16` in non-tapscript
/// execution; `OP_RESERVED` and tapscript are exempt per Core.
pub const MAX_OPS_PER_SCRIPT: i64 = 201;

/// `MAX_STACK_SIZE` — `stack.size() + altstack.size()` must never exceed this.
pub const MAX_STACK_SIZE: usize = 1000;

/// `MAX_PUBKEYS_PER_MULTISIG` is defined in `crate::script`.
use crate::script::MAX_PUBKEYS_PER_MULTISIG;

/// `MAXIMUM_ELEMENT_SIZE` — the default `CScriptNum` operand limit (4 bytes).
pub const MAX_SCRIPTNUM_SIZE: usize = 4;

/// `ANNEX_TAG` (BIP341): a taproot witness stack whose last item starts with
/// this byte carries an annex, which is popped before execution.
pub const ANNEX_TAG: u8 = 0x50;

/// `TAPROOT_LEAF_MASK` — the leaf version is `control[0] & TAPROOT_LEAF_MASK`
/// (the low bit encodes the output key's parity instead).
pub const TAPROOT_LEAF_MASK: u8 = 0xfe;
/// `TAPROOT_LEAF_TAPSCRIPT` — the only defined taproot leaf version.
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 0xc0;
/// `TAPROOT_CONTROL_BASE_SIZE` — control byte + internal x-only key.
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;
/// `TAPROOT_CONTROL_NODE_SIZE` — each Merkle path node.
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;
/// `TAPROOT_CONTROL_MAX_SIZE` — base + 128 nodes.
pub const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * 128;
/// `WITNESS_V1_TAPROOT_SIZE` — the 32-byte v1 witness program (tweaked x-only key).
pub const WITNESS_V1_TAPROOT_SIZE: usize = 32;

/// `VALIDATION_WEIGHT_PER_SIGOP_PASSED` — each executed tapscript signature op
/// consumes this much of the validation weight budget.
pub const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;
/// `VALIDATION_WEIGHT_OFFSET` — tapscript's weight budget is the serialized
/// witness size plus this constant.
pub const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// `LOCKTIME_THRESHOLD` (`script/standard.h` via `consensus/consensus.h`):
/// `nLockTime` values below are block heights, at-or-above are unix times.
pub const LOCKTIME_THRESHOLD: i64 = 500_000_000;

/// `SIGHASH_ALL` et al. — the low-5-bit output modes and the ANYONECANPAY input
/// flag. `SIGHASH_DEFAULT` (0) exists only for Schnorr signatures.
pub const SIGHASH_ALL: u8 = 1;
pub const SIGHASH_NONE: u8 = 2;
pub const SIGHASH_SINGLE: u8 = 3;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
pub const SIGHASH_DEFAULT: u8 = 0;

// ---------------------------------------------------------------------------
// Opcode constants not already defined in crate::script
// ---------------------------------------------------------------------------

const OP_NOP: u8 = 0x61;
const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_VERIFY: u8 = 0x69;

const OP_TOALTSTACK: u8 = 0x6b;
const OP_FROMALTSTACK: u8 = 0x6c;
const OP_2DROP: u8 = 0x6d;
const OP_2DUP: u8 = 0x6e;
const OP_3DUP: u8 = 0x6f;
const OP_2OVER: u8 = 0x70;
const OP_2ROT: u8 = 0x71;
const OP_2SWAP: u8 = 0x72;
const OP_IFDUP: u8 = 0x73;
const OP_DEPTH: u8 = 0x74;
const OP_DROP: u8 = 0x75;
const OP_DUP: u8 = 0x76;
const OP_NIP: u8 = 0x77;
const OP_OVER: u8 = 0x78;
const OP_PICK: u8 = 0x79;
const OP_ROLL: u8 = 0x7a;
const OP_ROT: u8 = 0x7b;
const OP_SWAP: u8 = 0x7c;
const OP_TUCK: u8 = 0x7d;
const OP_SIZE: u8 = 0x82;

// Disabled opcodes (CVE-2010-5137) — rejected even in unexecuted branches.
const OP_CAT: u8 = 0x7e;
const OP_SUBSTR: u8 = 0x7f;
const OP_LEFT: u8 = 0x80;
const OP_RIGHT: u8 = 0x81;
const OP_INVERT: u8 = 0x83;
const OP_AND: u8 = 0x84;
const OP_OR: u8 = 0x85;
const OP_XOR: u8 = 0x86;
const OP_2MUL: u8 = 0x8d;
const OP_2DIV: u8 = 0x8e;
const OP_MUL: u8 = 0x95;
const OP_DIV: u8 = 0x96;
const OP_MOD: u8 = 0x97;
const OP_LSHIFT: u8 = 0x98;
const OP_RSHIFT: u8 = 0x99;

const OP_1ADD: u8 = 0x8b;
const OP_1SUB: u8 = 0x8c;
const OP_NEGATE: u8 = 0x8f;
const OP_ABS: u8 = 0x90;
const OP_NOT: u8 = 0x91;
const OP_0NOTEQUAL: u8 = 0x92;
const OP_ADD: u8 = 0x93;
const OP_SUB: u8 = 0x94;
const OP_BOOLAND: u8 = 0x9a;
const OP_BOOLOR: u8 = 0x9b;
const OP_NUMEQUAL: u8 = 0x9c;
const OP_NUMEQUALVERIFY: u8 = 0x9d;
const OP_NUMNOTEQUAL: u8 = 0x9e;
const OP_LESSTHAN: u8 = 0x9f;
const OP_GREATERTHAN: u8 = 0xa0;
const OP_LESSTHANOREQUAL: u8 = 0xa1;
const OP_GREATERTHANOREQUAL: u8 = 0xa2;
const OP_MIN: u8 = 0xa3;
const OP_MAX: u8 = 0xa4;
const OP_WITHIN: u8 = 0xa5;

const OP_RIPEMD160: u8 = 0xa6;
const OP_SHA1: u8 = 0xa7;
const OP_SHA256: u8 = 0xa8;
const OP_HASH256: u8 = 0xaa;
const OP_CODESEPARATOR: u8 = 0xab;
const OP_NOP1: u8 = 0xb0;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1; // NOP2
const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2; // NOP3
const OP_NOP4: u8 = 0xb3;
const OP_NOP10: u8 = 0xb9;
const OP_CHECKSIGADD: u8 = 0xba;
const OP_EQUALVERIFY: u8 = 0x88;

// ---------------------------------------------------------------------------
// ScriptError — the SCRIPT_ERR_* vocabulary (script/script_error.h)
// ---------------------------------------------------------------------------

/// One variant per `SCRIPT_ERR_*` in Core's `script_error.h`; `Display` matches
/// `ScriptErrorString` byte-for-byte (it surfaces inside Core's
/// `mandatory-script-verify-flag-failed (...)` / `non-mandatory-...` reasons).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ScriptError {
    Ok,
    EvalFalse,
    OpReturn,
    ScriptSize,
    PushSize,
    OpCount,
    StackSize,
    SigCount,
    PubkeyCount,
    Verify,
    EqualVerify,
    CheckMultisigVerify,
    CheckSigVerify,
    NumEqualVerify,
    BadOpcode,
    DisabledOpcode,
    InvalidStackOperation,
    InvalidAltstackOperation,
    UnbalancedConditional,
    NegativeLocktime,
    UnsatisfiedLocktime,
    SigHashType,
    SigDer,
    MinimalData,
    SigPushOnly,
    SigHighS,
    SigNullDummy,
    PubkeyType,
    CleanStack,
    MinimalIf,
    SigNullFail,
    DiscourageUpgradableNops,
    DiscourageUpgradableWitnessProgram,
    DiscourageUpgradableTaprootVersion,
    DiscourageOpSuccess,
    DiscourageUpgradablePubkeyType,
    WitnessProgramWrongLength,
    WitnessProgramWitnessEmpty,
    WitnessProgramMismatch,
    WitnessMalleated,
    WitnessMalleatedP2sh,
    WitnessUnexpected,
    WitnessPubkeyType,
    SchnorrSigSize,
    SchnorrSigHashType,
    SchnorrSig,
    TaprootWrongControlSize,
    TapscriptValidationWeight,
    TapscriptCheckMultisig,
    TapscriptMinimalIf,
    OpCodeSeparator,
    SigFindAndDelete,
    UnknownError,
}

impl fmt::Display for ScriptError {
    /// `ScriptErrorString` verbatim.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ok => "No error",
            Self::EvalFalse => {
                "Script evaluated without error but finished with a false/empty top stack element"
            }
            Self::Verify => "Script failed an OP_VERIFY operation",
            Self::EqualVerify => "Script failed an OP_EQUALVERIFY operation",
            Self::CheckMultisigVerify => "Script failed an OP_CHECKMULTISIGVERIFY operation",
            Self::CheckSigVerify => "Script failed an OP_CHECKSIGVERIFY operation",
            Self::NumEqualVerify => "Script failed an OP_NUMEQUALVERIFY operation",
            Self::ScriptSize => "Script is too big",
            Self::PushSize => "Push value size limit exceeded",
            Self::OpCount => "Operation limit exceeded",
            Self::StackSize => "Stack size limit exceeded",
            Self::SigCount => "Signature count negative or greater than pubkey count",
            Self::PubkeyCount => "Pubkey count negative or limit exceeded",
            Self::BadOpcode => "Opcode missing or not understood",
            Self::DisabledOpcode => "Attempted to use a disabled opcode",
            Self::InvalidStackOperation => "Operation not valid with the current stack size",
            Self::InvalidAltstackOperation => "Operation not valid with the current altstack size",
            Self::OpReturn => "OP_RETURN was encountered",
            Self::UnbalancedConditional => "Invalid OP_IF construction",
            Self::NegativeLocktime => "Negative locktime",
            Self::UnsatisfiedLocktime => "Locktime requirement not satisfied",
            Self::SigHashType => "Signature hash type missing or not understood",
            Self::SigDer => "Non-canonical DER signature",
            Self::MinimalData => "Data push larger than necessary",
            Self::SigPushOnly => "Only push operators allowed in signatures",
            Self::SigHighS => "Non-canonical signature: S value is unnecessarily high",
            Self::SigNullDummy => "Dummy CHECKMULTISIG argument must be zero",
            Self::MinimalIf => "OP_IF/NOTIF argument must be minimal",
            Self::SigNullFail => "Signature must be zero for failed CHECK(MULTI)SIG operation",
            Self::DiscourageUpgradableNops => "NOPx reserved for soft-fork upgrades",
            Self::DiscourageUpgradableWitnessProgram => {
                "Witness version reserved for soft-fork upgrades"
            }
            Self::DiscourageUpgradableTaprootVersion => {
                "Taproot version reserved for soft-fork upgrades"
            }
            Self::DiscourageOpSuccess => "OP_SUCCESSx reserved for soft-fork upgrades",
            Self::DiscourageUpgradablePubkeyType => {
                "Public key version reserved for soft-fork upgrades"
            }
            Self::PubkeyType => "Public key is neither compressed or uncompressed",
            Self::CleanStack => "Stack size must be exactly one after execution",
            Self::WitnessProgramWrongLength => "Witness program has incorrect length",
            Self::WitnessProgramWitnessEmpty => "Witness program was passed an empty witness",
            Self::WitnessProgramMismatch => "Witness program hash mismatch",
            Self::WitnessMalleated => "Witness requires empty scriptSig",
            Self::WitnessMalleatedP2sh => "Witness requires only-redeemscript scriptSig",
            Self::WitnessUnexpected => "Witness provided for non-witness script",
            Self::WitnessPubkeyType => "Using non-compressed keys in segwit",
            Self::SchnorrSigSize => "Invalid Schnorr signature size",
            Self::SchnorrSigHashType => "Invalid Schnorr signature hash type",
            Self::SchnorrSig => "Invalid Schnorr signature",
            Self::TaprootWrongControlSize => "Invalid Taproot control block size",
            Self::TapscriptValidationWeight => {
                "Too much signature validation relative to witness weight"
            }
            Self::TapscriptCheckMultisig => {
                "OP_CHECKMULTISIG(VERIFY) is not available in tapscript"
            }
            Self::TapscriptMinimalIf => "OP_IF/NOTIF argument must be minimal in tapscript",
            Self::OpCodeSeparator => "Using OP_CODESEPARATOR in non-witness script",
            Self::SigFindAndDelete => "Signature is found in scriptCode",
            Self::UnknownError => "unknown error",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ScriptError {}

// ---------------------------------------------------------------------------
// SigVersion and ScriptExecutionData
// ---------------------------------------------------------------------------

/// Core's `SigVersion`: which sighash/signature rules a script executes under.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SigVersion {
    /// Pre-segwit `scriptSig`/`scriptPubKey`/P2SH execution.
    Base,
    /// BIP143 witness v0 (P2WPKH/P2WSH).
    WitnessV0,
    /// BIP341 key-path spend — admits no script execution; used only for the
    /// direct `CheckSchnorrSignature` call.
    Taproot,
    /// BIP342 script-path spend.
    Tapscript,
}

/// Core's `ScriptExecutionData`: state shared between `EvalScript` and the
/// signature checker for taproot/tapscript evaluation.
#[derive(Clone, Debug, Default)]
pub struct ExecutionData {
    /// `m_codeseparator_pos` — instruction index of the last executed
    /// `OP_CODESEPARATOR` (tapscript sighash input); `0xFFFFFFFF` when none ran.
    pub codeseparator_pos: u32,
    /// `m_codeseparator_pos_init`.
    pub codeseparator_pos_init: bool,
    /// `m_annex_present` / `m_annex_init` / `m_annex_hash` — BIP341 annex,
    /// hashed as `SHA256(compact_size(len) || annex)` (Core's
    /// `HashWriter << annex` serialization).
    pub annex_present: bool,
    pub annex_init: bool,
    pub annex_hash: Option<[u8; 32]>,
    /// `m_tapleaf_hash` / `m_tapleaf_hash_init`.
    pub tapleaf_hash: Option<[u8; 32]>,
    pub tapleaf_hash_init: bool,
    /// `m_validation_weight_left` / `..._init` — remaining tapscript signature
    /// validation budget.
    pub validation_weight_left: i64,
    pub validation_weight_left_init: bool,
    /// `m_output_hash` — lazily computed `SHA256(txout[in_pos])` for
    /// `SIGHASH_SINGLE` taproot sighashes.
    pub output_hash: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// SignatureChecker — Core's BaseSignatureChecker
// ---------------------------------------------------------------------------

/// The transaction-dependent signature checks `EvalScript` delegates to —
/// Core's `BaseSignatureChecker`. The default implementations mirror
/// `BaseSignatureChecker`'s stubs (`false`/`false`/`false`); a real checker is
/// provided by `crate::sigchecker::TransactionSignatureChecker`.
///
/// `check_schnorr_signature` returns `Err(ScriptError)` on every failure
/// (matching Core's `CheckSchnorrSignature`, which always sets `serror`
/// before returning false); `check_ecdsa_signature` is a plain `bool` because
/// `EvalChecksig` applies NULLFAIL itself.
pub trait SignatureChecker {
    /// `CheckECDSASignature`: verify `sig` (including the trailing sighash
    /// byte) against `pubkey` over `script_code` under `sigversion` rules.
    fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sigversion: SigVersion,
    ) -> bool {
        let _ = (sig, pubkey, script_code, sigversion);
        false
    }

    /// `CheckSchnorrSignature`: verify a 64/65-byte Schnorr signature.
    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        sigversion: SigVersion,
        execdata: &mut ExecutionData,
    ) -> Result<(), ScriptError> {
        let _ = (sig, pubkey, sigversion, execdata);
        Err(ScriptError::SchnorrSig)
    }

    /// `CheckLockTime` — BIP65 `OP_CHECKLOCKTIMEVERIFY` semantics.
    fn check_locktime(&self, locktime: i64) -> bool {
        let _ = locktime;
        false
    }

    /// `CheckSequence` — BIP112 `OP_CHECKSEQUENCEVERIFY` semantics.
    fn check_sequence(&self, sequence: i64) -> bool {
        let _ = sequence;
        false
    }

    /// `VerifyTaprootCommitment` — confirm `control`'s internal key tweaked by
    /// the taproot merkle path equals the output `program` (Core's
    /// `XOnlyPubKey::CheckTapTweak`). Requires the crypto backend, so it lives
    /// on the checker; the default reports failure.
    fn verify_taproot_commitment(
        &self,
        control: &[u8],
        program: &[u8],
        tapleaf_hash: &[u8; 32],
    ) -> bool {
        let _ = (control, program, tapleaf_hash);
        false
    }
}

// ---------------------------------------------------------------------------
// Small helpers (CastToBool, GetOp, CScriptNum, CheckMinimalPush, ...)
// ---------------------------------------------------------------------------

/// `CastToBool`: false for the empty vector, zero, and *negative zero*
/// (`0x80` as the sole nonzero-looking last byte).
#[must_use]
pub fn cast_to_bool(vch: &[u8]) -> bool {
    for (i, &b) in vch.iter().enumerate() {
        if b != 0 {
            // Can be negative zero.
            if i == vch.len() - 1 && b == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/// `CScript::GetOp`/`GetScriptOp` at `*pc`, advancing `pc` past the consumed
/// bytes. Returns `(opcode, pushed_bytes)`; `pushed_bytes` is empty for
/// non-push opcodes. On failure returns `None` with `pc` left wherever
/// `GetScriptOp`'s early `return false`s leave it — past the opcode byte and
/// any length bytes that were present (find-and-delete and the sigop scans
/// depend on continuing from that position).
fn get_op<'a>(script: &'a [u8], pc: &mut usize) -> Option<(u8, &'a [u8])> {
    let opcode = *script.get(*pc)?;
    *pc += 1;
    if opcode > OP_PUSHDATA4 {
        return Some((opcode, &[]));
    }
    let size = match opcode {
        op if op < OP_PUSHDATA1 => usize::from(op),
        OP_PUSHDATA1 => {
            let b = *script.get(*pc)?;
            *pc += 1;
            usize::from(b)
        }
        OP_PUSHDATA2 => {
            let b = script.get(*pc..*pc + 2)?;
            *pc += 2;
            usize::from(u16::from_le_bytes([b[0], b[1]]))
        }
        _ => {
            let b = script.get(*pc..*pc + 4)?;
            *pc += 4;
            usize::try_from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok()?
        }
    };
    // Subtraction-safe bounds check: `*pc + size` could overflow usize on
    // 32-bit targets for a huge PUSHDATA4 operand.
    if script.len() - *pc < size {
        return None;
    }
    let data = &script[*pc..*pc + size];
    *pc += size;
    Some((opcode, data))
}

/// `CScriptNum`: decode a little-endian sign-magnitude script number.
/// `require_minimal` enforces the minimal-encoding rule; `max_size` is 4 for
/// ordinary numeric operands and 5 for CLTV/CSV. Decode failures are Core's
/// `scriptnum_error` throws, which `EvalScript`'s catch-all maps to
/// [`ScriptError::UnknownError`].
fn script_num(vch: &[u8], require_minimal: bool, max_size: usize) -> Result<i64, ScriptError> {
    if vch.len() > max_size {
        return Err(ScriptError::UnknownError);
    }
    if require_minimal && !vch.is_empty() {
        // If the most-significant-byte's data bits are all zero it could be
        // removed; if the next byte's sign bit is also clear the encoding is
        // non-minimal.
        if vch[vch.len() - 1] & 0x7f == 0 && (vch.len() <= 1 || vch[vch.len() - 2] & 0x80 == 0) {
            return Err(ScriptError::UnknownError);
        }
    }
    let mut value = 0i64;
    for (i, &b) in vch.iter().enumerate() {
        value |= i64::from(b) << (8 * i);
    }
    if !vch.is_empty() && vch[vch.len() - 1] & 0x80 != 0 {
        // Sign-magnitude: clear the sign bit, negate.
        value &= !(0x80i64 << (8 * (vch.len() - 1)));
        Ok(-value)
    } else {
        Ok(value)
    }
}

/// `CScriptNum::getint` — saturating i64→i32 used by OP_PICK/OP_ROLL and the
/// multisig counts. Saturation vs truncation is unobservable: every use is
/// immediately range-checked.
fn getint(v: i64) -> i64 {
    v.clamp(i64::from(i32::MIN), i64::from(i32::MAX))
}

/// `CheckMinimalPush` (script/script.cpp): is `opcode` the smallest encoding
/// that could push `data`?
fn check_minimal_push(data: &[u8], opcode: u8) -> bool {
    debug_assert!(opcode <= OP_PUSHDATA4);
    if data.is_empty() {
        // Should have used OP_0.
        opcode == OP_0
    } else if data.len() == 1 && (1..=16).contains(&data[0]) {
        // Should have used OP_1 .. OP_16.
        false
    } else if data.len() == 1 && data[0] == 0x81 {
        // Should have used OP_1NEGATE.
        false
    } else if data.len() <= 75 {
        // Must have used a direct push.
        opcode == data.len() as u8
    } else if data.len() <= 255 {
        opcode == OP_PUSHDATA1
    } else if data.len() <= 65535 {
        opcode == OP_PUSHDATA2
    } else {
        true
    }
}

/// `IsOpSuccess` (BIP342): opcodes that unconditionally succeed tapscript.
#[must_use]
pub fn is_op_success(opcode: u8) -> bool {
    opcode == 80
        || opcode == 98
        || (126..=129).contains(&opcode)
        || (131..=134).contains(&opcode)
        || (137..=138).contains(&opcode)
        || (141..=142).contains(&opcode)
        || (149..=153).contains(&opcode)
        || (187..=254).contains(&opcode)
}

/// `CScript::IsPayToAnchor(version, program)`: the P2A output defined by
/// BIP-... — witness v1, two-byte program `0x4e73`.
#[must_use]
pub fn is_pay_to_anchor(version: u8, program: &[u8]) -> bool {
    version == 1 && program == [0x4e, 0x73]
}

// ---------------------------------------------------------------------------
// Pubkey and signature encoding checks
// ---------------------------------------------------------------------------

/// `IsCompressedOrUncompressedPubKey`: 33-byte `0x02|0x03` or 65-byte `0x04`.
fn is_compressed_or_uncompressed_pubkey(key: &[u8]) -> bool {
    if key.len() < 33 {
        return false;
    }
    match key[0] {
        0x04 => key.len() == 65,
        0x02 | 0x03 => key.len() == 33,
        _ => false,
    }
}

/// `IsCompressedPubKey`: 33-byte `0x02|0x03` only.
fn is_compressed_pubkey(key: &[u8]) -> bool {
    key.len() == 33 && (key[0] == 0x02 || key[0] == 0x03)
}

/// `IsValidSignatureEncoding`: strict DER of `R`/`S` plus the trailing
/// sighash byte. Consensus-critical since BIP66.
pub fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }
    if sig[0] != 0x30 || sig[1] as usize != sig.len() - 3 {
        return false;
    }
    let len_r = usize::from(sig[3]);
    if 5 + len_r >= sig.len() {
        return false;
    }
    let len_s = usize::from(sig[5 + len_r]);
    if len_r + len_s + 7 != sig.len() {
        return false;
    }
    if sig[2] != 0x02 || len_r == 0 || sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }
    if sig[len_r + 4] != 0x02 || len_s == 0 || sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }
    true
}

/// secp256k1's group order `n` and `n/2` as 32-byte big-endian values, for the
/// pure-Rust `CheckLowS` port.
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// `CPubKey::CheckLowS` — is the S component of a strict-DER signature (no
/// sighash byte) at most `n/2`?
///
/// Core delegates to libsecp256k1's `signature_parse_der` +
/// `signature_normalize`. `parse_der` treats an S value `>= n` as a scalar
/// overflow and zeroes the whole signature, which then reads as already
/// normalized — so `S >= n` reports *low* here. The explicit `s >= n` branch
/// reproduces that quirk.
fn check_low_s(sig_der: &[u8]) -> bool {
    // Caller guarantees is_valid_signature_encoding held for sig_der||hashtype;
    // re-derive S's slice from the DER layout.
    if sig_der.len() < 8 || sig_der[0] != 0x30 {
        return false;
    }
    let len_r = usize::from(sig_der[3]);
    if 5 + len_r >= sig_der.len() {
        return false;
    }
    let len_s = usize::from(sig_der[5 + len_r]);
    if len_r + len_s + 6 != sig_der.len() {
        return false;
    }
    let s_bytes = &sig_der[6 + len_r..6 + len_r + len_s];
    // Big-endian compare of the DER integer against a 32-byte bound. A
    // DER-positive integer longer than 32 bytes exceeds any such bound.
    fn cmp_be256(bytes: &[u8], bound: &[u8; 32]) -> std::cmp::Ordering {
        if bytes.len() > 32 {
            return std::cmp::Ordering::Greater;
        }
        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(bytes);
        padded.as_slice().cmp(bound.as_slice())
    }
    if cmp_be256(s_bytes, &SECP256K1_ORDER) != std::cmp::Ordering::Less {
        // Scalar overflow: libsecp256k1's parse_der zeroes the signature, which
        // then reads as already-normalized (low) — reproduce that.
        return true;
    }
    cmp_be256(s_bytes, &SECP256K1_HALF_ORDER) != std::cmp::Ordering::Greater
}

/// `IsLowDERSignature` — strict DER on the whole `sig` (hashtype byte
/// included), then `CheckLowS` on the DER part.
fn check_signature_encoding_low_s(sig: &[u8]) -> Result<(), ScriptError> {
    if !is_valid_signature_encoding(sig) {
        return Err(ScriptError::SigDer);
    }
    if !check_low_s(&sig[..sig.len() - 1]) {
        return Err(ScriptError::SigHighS);
    }
    Ok(())
}

/// `IsDefinedHashtypeSignature`: the trailing byte's low 5 bits must be
/// `SIGHASH_ALL`..=`SIGHASH_SINGLE`.
fn is_defined_hashtype(sig: &[u8]) -> bool {
    match sig.last() {
        None => false,
        Some(&b) => (SIGHASH_ALL..=SIGHASH_SINGLE).contains(&(b & !SIGHASH_ANYONECANPAY)),
    }
}

/// `CheckSignatureEncoding`.
pub fn check_signature_encoding(sig: &[u8], flags: ScriptFlags) -> Result<(), ScriptError> {
    // Empty signature: not strictly DER, but the compact way to fail a
    // CHECK(MULTI)SIG.
    if sig.is_empty() {
        return Ok(());
    }
    // Core tests `(flags & (DERSIG | LOW_S | STRICTENC)) != 0` — any bit.
    let dersig_family = ScriptFlags::DERSIG
        .union(ScriptFlags::LOW_S)
        .union(ScriptFlags::STRICTENC);
    if flags.bits() & dersig_family.bits() != 0 && !is_valid_signature_encoding(sig) {
        return Err(ScriptError::SigDer);
    }
    if flags.contains(ScriptFlags::LOW_S) {
        check_signature_encoding_low_s(sig)?;
    }
    if flags.contains(ScriptFlags::STRICTENC) && !is_defined_hashtype(sig) {
        return Err(ScriptError::SigHashType);
    }
    Ok(())
}

/// `CheckPubKeyEncoding`.
fn check_pubkey_encoding(
    pubkey: &[u8],
    flags: ScriptFlags,
    sigversion: SigVersion,
) -> Result<(), ScriptError> {
    if flags.contains(ScriptFlags::STRICTENC) && !is_compressed_or_uncompressed_pubkey(pubkey) {
        return Err(ScriptError::PubkeyType);
    }
    // Only compressed keys are accepted in segwit.
    if flags.contains(ScriptFlags::WITNESS_PUBKEYTYPE)
        && sigversion == SigVersion::WitnessV0
        && !is_compressed_pubkey(pubkey)
    {
        return Err(ScriptError::WitnessPubkeyType);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// FindAndDelete — the legacy signature-removal quirk
// ---------------------------------------------------------------------------

/// `FindAndDelete`: remove occurrences of `b` found at instruction boundaries
/// (and, after each removal, wherever the cursor lands next — including inside
/// what used to be push data). Operates on raw `script_code` bytes. Returns
/// the number of matches removed.
fn find_and_delete(script: &mut Vec<u8>, b: &[u8]) -> usize {
    if b.is_empty() {
        return 0;
    }
    let mut result: Vec<u8> = Vec::with_capacity(script.len());
    let mut found = 0usize;
    let mut pc = 0usize;
    let mut pc2 = 0usize;
    loop {
        result.extend_from_slice(&script[pc2..pc]);
        while script.len() - pc >= b.len() && script[pc..pc + b.len()] == *b {
            pc += b.len();
            found += 1;
        }
        pc2 = pc;
        if get_op(script, &mut pc).is_none() {
            break;
        }
    }
    if found > 0 {
        result.extend_from_slice(&script[pc2..]);
        *script = result;
    }
    found
}

// ---------------------------------------------------------------------------
// ConditionStack — Core's optimized vfExec; semantics are a Vec<bool>.
// ---------------------------------------------------------------------------

struct ConditionStack {
    /// Depth of the implied stack.
    size: u32,
    /// Position of the first false, or `u32::MAX` (NO_FALSE) when all-true.
    first_false: u32,
}

impl Default for ConditionStack {
    fn default() -> Self {
        Self {
            size: 0,
            first_false: u32::MAX,
        }
    }
}

impl ConditionStack {
    fn is_empty(&self) -> bool {
        self.size == 0
    }
    fn all_true(&self) -> bool {
        self.first_false == u32::MAX
    }
    fn push(&mut self, f: bool) {
        if self.first_false == u32::MAX && !f {
            self.first_false = self.size;
        }
        self.size += 1;
    }
    fn pop(&mut self) {
        debug_assert!(self.size > 0);
        self.size -= 1;
        if self.first_false == self.size {
            self.first_false = u32::MAX;
        }
    }
    fn toggle_top(&mut self) {
        debug_assert!(self.size > 0);
        if self.first_false == u32::MAX {
            self.first_false = self.size - 1;
        } else if self.first_false == self.size - 1 {
            self.first_false = u32::MAX;
        }
    }
}

// ---------------------------------------------------------------------------
// EvalChecksig — signature-opcode shared core
// ---------------------------------------------------------------------------

/// `EvalChecksigPreTapscript` — BASE and WITNESS_V0 signature evaluation.
fn eval_checksig_pre_tapscript(
    sig: &[u8],
    pubkey: &[u8],
    script_code_start: usize,
    script: &[u8],
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
    sigversion: SigVersion,
) -> Result<bool, ScriptError> {
    debug_assert!(matches!(
        sigversion,
        SigVersion::Base | SigVersion::WitnessV0
    ));

    // Subset of script starting at the most recent codeseparator.
    let mut script_code: Vec<u8> = script[script_code_start..].to_vec();

    // Drop the signature in pre-segwit scripts but not segwit scripts.
    if sigversion == SigVersion::Base {
        let found = find_and_delete(&mut script_code, &push_slice(sig));
        if found > 0 && flags.contains(ScriptFlags::CONST_SCRIPTCODE) {
            return Err(ScriptError::SigFindAndDelete);
        }
    }

    check_signature_encoding(sig, flags)?;
    check_pubkey_encoding(pubkey, flags, sigversion)?;

    let success = checker.check_ecdsa_signature(sig, pubkey, &script_code, sigversion);
    if !success && flags.contains(ScriptFlags::NULLFAIL) && !sig.is_empty() {
        return Err(ScriptError::SigNullFail);
    }
    Ok(success)
}

/// `EvalChecksigTapscript` — BIP342 signature evaluation.
fn eval_checksig_tapscript(
    sig: &[u8],
    pubkey: &[u8],
    execdata: &mut ExecutionData,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<bool, ScriptError> {
    // Consensus-critical ordering: upgradable pubkey versions precede other
    // rules; an empty sig with an invalid pubkey fails; a non-empty invalid
    // sig fails.
    let success = !sig.is_empty();
    if success {
        // Sigops/witnesssize ratio test — also charged for upgradable pubkey
        // versions.
        debug_assert!(execdata.validation_weight_left_init);
        execdata.validation_weight_left -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
        if execdata.validation_weight_left < 0 {
            return Err(ScriptError::TapscriptValidationWeight);
        }
    }
    if pubkey.is_empty() {
        return Err(ScriptError::PubkeyType);
    } else if pubkey.len() == 32 {
        if success {
            checker.check_schnorr_signature(sig, pubkey, SigVersion::Tapscript, execdata)?;
        }
    } else if flags.contains(ScriptFlags::DISCOURAGE_UPGRADABLE_PUBKEYTYPE) {
        return Err(ScriptError::DiscourageUpgradablePubkeyType);
    }
    Ok(success)
}

/// `EvalChecksig` dispatcher.
#[allow(clippy::too_many_arguments)]
fn eval_checksig(
    sig: &[u8],
    pubkey: &[u8],
    script_code_start: usize,
    script: &[u8],
    execdata: &mut ExecutionData,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
    sigversion: SigVersion,
) -> Result<bool, ScriptError> {
    match sigversion {
        SigVersion::Base | SigVersion::WitnessV0 => eval_checksig_pre_tapscript(
            sig,
            pubkey,
            script_code_start,
            script,
            flags,
            checker,
            sigversion,
        ),
        SigVersion::Tapscript => eval_checksig_tapscript(sig, pubkey, execdata, flags, checker),
        // Key-path spending has no script — unreachable.
        SigVersion::Taproot => unreachable!("TAPROOT admits no script execution"),
    }
}

// ---------------------------------------------------------------------------
// EvalScript — the stack machine
// ---------------------------------------------------------------------------

/// `EvalScript` — execute `script` against `stack` under `flags`/`sigversion`.
/// On `Err`, the `ScriptError` is exactly what Core's `serror` would hold;
/// `stack` may be partially mutated (Core's behavior likewise — callers treat
/// failure as final).
///
/// `checker` supplies all transaction-dependent operations (signature
/// verification, locktime, sequence).
pub fn eval_script(
    stack: &mut Vec<Vec<u8>>,
    script: &Script,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
    sigversion: SigVersion,
    execdata: &mut ExecutionData,
) -> Result<(), ScriptError> {
    debug_assert!(!matches!(sigversion, SigVersion::Taproot));
    let bytes = script.as_bytes();
    if matches!(sigversion, SigVersion::Base | SigVersion::WitnessV0)
        && bytes.len() > MAX_SCRIPT_SIZE
    {
        return Err(ScriptError::ScriptSize);
    }

    let mut op_count: i64 = 0;
    let require_minimal = flags.contains(ScriptFlags::MINIMALDATA);
    let mut cond = ConditionStack::default();
    let mut altstack: Vec<Vec<u8>> = Vec::new();
    execdata.codeseparator_pos = 0xFFFF_FFFF;
    execdata.codeseparator_pos_init = true;

    let vch_true: Vec<u8> = vec![1];
    let vch_false: Vec<u8> = Vec::new();

    // stacktop(-n) — callers guard sizes exactly where Core checks stack.size().
    macro_rules! top {
        ($n:expr) => {
            &stack[stack.len() - $n]
        };
    }

    let mut pc = 0usize;
    let mut pbegincodehash = 0usize;
    let mut opcode_pos = 0u32;
    while pc < bytes.len() {
        let f_exec = cond.all_true();

        // Read instruction.
        let Some((opcode, push)) = get_op(bytes, &mut pc) else {
            return Err(ScriptError::BadOpcode);
        };
        if push.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }

        if matches!(sigversion, SigVersion::Base | SigVersion::WitnessV0) {
            // Note how OP_RESERVED does not count towards the opcode limit.
            if opcode > OP_16 {
                op_count += 1;
                if op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::OpCount);
                }
            }
        }

        if matches!(
            opcode,
            OP_CAT
                | OP_SUBSTR
                | OP_LEFT
                | OP_RIGHT
                | OP_INVERT
                | OP_AND
                | OP_OR
                | OP_XOR
                | OP_2MUL
                | OP_2DIV
                | OP_MUL
                | OP_DIV
                | OP_MOD
                | OP_LSHIFT
                | OP_RSHIFT
        ) {
            return Err(ScriptError::DisabledOpcode);
        }

        // With CONST_SCRIPTCODE, OP_CODESEPARATOR in non-segwit script is
        // rejected even in an unexecuted branch.
        if opcode == OP_CODESEPARATOR
            && sigversion == SigVersion::Base
            && flags.contains(ScriptFlags::CONST_SCRIPTCODE)
        {
            return Err(ScriptError::OpCodeSeparator);
        }

        if f_exec && opcode <= OP_PUSHDATA4 {
            if require_minimal && !check_minimal_push(push, opcode) {
                return Err(ScriptError::MinimalData);
            }
            stack.push(push.to_vec());
        } else if f_exec || (OP_IF..=OP_ENDIF).contains(&opcode) {
            match opcode {
                // Push value: OP_1NEGATE, OP_1..OP_16 — always minimal, so no
                // CheckMinimalPush.
                OP_1NEGATE | OP_1..=OP_16 => {
                    let n = i64::from(opcode) - i64::from(OP_1 - 1);
                    stack.push(encode_script_num(n));
                }

                OP_NOP => {}

                OP_CHECKLOCKTIMEVERIFY => {
                    if !flags.contains(ScriptFlags::CHECKLOCKTIMEVERIFY) {
                        // not enabled; treat as a NOP2
                    } else {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        // 5-byte operands: legal until 2**39-1, beyond the
                        // u32 nLockTime range (Core's year-2038 workaround).
                        let locktime = script_num(top!(1), require_minimal, 5)?;
                        if locktime < 0 {
                            return Err(ScriptError::NegativeLocktime);
                        }
                        if !checker.check_locktime(locktime) {
                            return Err(ScriptError::UnsatisfiedLocktime);
                        }
                    }
                }

                OP_CHECKSEQUENCEVERIFY => {
                    if !flags.contains(ScriptFlags::CHECKSEQUENCEVERIFY) {
                        // not enabled; treat as a NOP3
                    } else {
                        if stack.is_empty() {
                            return Err(ScriptError::InvalidStackOperation);
                        }
                        let sequence = script_num(top!(1), require_minimal, 5)?;
                        if sequence < 0 {
                            return Err(ScriptError::NegativeLocktime);
                        }
                        // If the operand has the disable flag set, CSV is a NOP.
                        if sequence & i64::from(crate::connect::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0
                        {
                            // behaves as NOP
                        } else if !checker.check_sequence(sequence) {
                            return Err(ScriptError::UnsatisfiedLocktime);
                        }
                    }
                }

                OP_NOP1 | OP_NOP4..=OP_NOP10 => {
                    if flags.contains(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                        return Err(ScriptError::DiscourageUpgradableNops);
                    }
                }

                OP_IF | OP_NOTIF => {
                    let mut f_value = false;
                    if f_exec {
                        if stack.is_empty() {
                            return Err(ScriptError::UnbalancedConditional);
                        }
                        let vch = top!(1);
                        // Tapscript requires minimal IF/NOTIF inputs as a
                        // consensus rule.
                        if sigversion == SigVersion::Tapscript
                            && (vch.len() > 1 || (vch.len() == 1 && vch[0] != 1))
                        {
                            return Err(ScriptError::TapscriptMinimalIf);
                        }
                        // Witness v0: only a policy flag (MINIMALIF).
                        if sigversion == SigVersion::WitnessV0
                            && flags.contains(ScriptFlags::MINIMALIF)
                            && (vch.len() > 1 || (vch.len() == 1 && vch[0] != 1))
                        {
                            return Err(ScriptError::MinimalIf);
                        }
                        f_value = cast_to_bool(vch);
                        if opcode == OP_NOTIF {
                            f_value = !f_value;
                        }
                        stack.pop();
                    }
                    cond.push(f_value);
                }

                OP_ELSE => {
                    if cond.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    cond.toggle_top();
                }

                OP_ENDIF => {
                    if cond.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    cond.pop();
                }

                OP_VERIFY => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    if cast_to_bool(top!(1)) {
                        stack.pop();
                    } else {
                        return Err(ScriptError::Verify);
                    }
                }

                OP_RETURN => return Err(ScriptError::OpReturn),

                // Stack ops
                OP_TOALTSTACK => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    altstack.push(stack.pop().unwrap_or_default());
                }

                OP_FROMALTSTACK => {
                    if altstack.is_empty() {
                        return Err(ScriptError::InvalidAltstackOperation);
                    }
                    stack.push(altstack.pop().unwrap_or_default());
                }

                OP_2DROP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    stack.pop();
                    stack.pop();
                }

                OP_2DUP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let (v1, v2) = (top!(2).clone(), top!(1).clone());
                    stack.push(v1);
                    stack.push(v2);
                }

                OP_3DUP => {
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let (v1, v2, v3) = (top!(3).clone(), top!(2).clone(), top!(1).clone());
                    stack.push(v1);
                    stack.push(v2);
                    stack.push(v3);
                }

                OP_2OVER => {
                    if stack.len() < 4 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let (v1, v2) = (top!(4).clone(), top!(3).clone());
                    stack.push(v1);
                    stack.push(v2);
                }

                OP_2ROT => {
                    if stack.len() < 6 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2): erase positions
                    // len-6..len-4, re-push them on top.
                    let len = stack.len();
                    let moved: Vec<Vec<u8>> = stack.drain(len - 6..len - 4).collect();
                    stack.extend(moved);
                }

                OP_2SWAP => {
                    if stack.len() < 4 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.swap(len - 4, len - 2);
                    stack.swap(len - 3, len - 1);
                }

                OP_IFDUP => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    if cast_to_bool(top!(1)) {
                        let v = top!(1).clone();
                        stack.push(v);
                    }
                }

                OP_DEPTH => {
                    stack.push(encode_script_num(stack.len() as i64));
                }

                OP_DROP => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    stack.pop();
                }

                OP_DUP => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let v = top!(1).clone();
                    stack.push(v);
                }

                OP_NIP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.remove(len - 2);
                }

                OP_OVER => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let v = top!(2).clone();
                    stack.push(v);
                }

                OP_PICK | OP_ROLL => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = getint(script_num(top!(1), require_minimal, MAX_SCRIPTNUM_SIZE)?);
                    stack.pop();
                    if n < 0 || n >= stack.len() as i64 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let n = n as usize;
                    let v = top!(n + 1).clone();
                    if opcode == OP_ROLL {
                        stack.remove(stack.len() - n - 1);
                    }
                    stack.push(v);
                }

                OP_ROT => {
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.swap(len - 3, len - 2);
                    stack.swap(len - 2, len - 1);
                }

                OP_SWAP => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let len = stack.len();
                    stack.swap(len - 2, len - 1);
                }

                OP_TUCK => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let v = top!(1).clone();
                    stack.insert(stack.len() - 2, v);
                }

                OP_SIZE => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    stack.push(encode_script_num(top!(1).len() as i64));
                }

                // Bitwise logic
                OP_EQUAL | OP_EQUALVERIFY => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let equal = stack[stack.len() - 2] == stack[stack.len() - 1];
                    stack.pop();
                    stack.pop();
                    stack.push(if equal {
                        vch_true.clone()
                    } else {
                        vch_false.clone()
                    });
                    if opcode == OP_EQUALVERIFY {
                        if equal {
                            stack.pop();
                        } else {
                            return Err(ScriptError::EqualVerify);
                        }
                    }
                }

                // Numeric: unary
                OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let bn = script_num(top!(1), require_minimal, MAX_SCRIPTNUM_SIZE)?;
                    let bn = match opcode {
                        OP_1ADD => bn.wrapping_add(1),
                        OP_1SUB => bn.wrapping_sub(1),
                        OP_NEGATE => bn.wrapping_neg(),
                        OP_ABS => {
                            if bn < 0 {
                                bn.wrapping_neg()
                            } else {
                                bn
                            }
                        }
                        OP_NOT => i64::from(bn == 0),
                        _ => i64::from(bn != 0), // OP_0NOTEQUAL
                    };
                    stack.pop();
                    stack.push(encode_script_num(bn));
                }

                // Numeric: binary
                OP_ADD
                | OP_SUB
                | OP_BOOLAND
                | OP_BOOLOR
                | OP_NUMEQUAL
                | OP_NUMEQUALVERIFY
                | OP_NUMNOTEQUAL
                | OP_LESSTHAN
                | OP_GREATERTHAN
                | OP_LESSTHANOREQUAL
                | OP_GREATERTHANOREQUAL
                | OP_MIN
                | OP_MAX => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let bn1 = script_num(top!(2), require_minimal, MAX_SCRIPTNUM_SIZE)?;
                    let bn2 = script_num(top!(1), require_minimal, MAX_SCRIPTNUM_SIZE)?;
                    let bn = match opcode {
                        OP_ADD => bn1.wrapping_add(bn2),
                        OP_SUB => bn1.wrapping_sub(bn2),
                        OP_BOOLAND => i64::from(bn1 != 0 && bn2 != 0),
                        OP_BOOLOR => i64::from(bn1 != 0 || bn2 != 0),
                        OP_NUMEQUAL | OP_NUMEQUALVERIFY => i64::from(bn1 == bn2),
                        OP_NUMNOTEQUAL => i64::from(bn1 != bn2),
                        OP_LESSTHAN => i64::from(bn1 < bn2),
                        OP_GREATERTHAN => i64::from(bn1 > bn2),
                        OP_LESSTHANOREQUAL => i64::from(bn1 <= bn2),
                        OP_GREATERTHANOREQUAL => i64::from(bn1 >= bn2),
                        OP_MIN => bn1.min(bn2),
                        _ => bn1.max(bn2), // OP_MAX
                    };
                    stack.pop();
                    stack.pop();
                    stack.push(encode_script_num(bn));
                    if opcode == OP_NUMEQUALVERIFY {
                        if cast_to_bool(top!(1)) {
                            stack.pop();
                        } else {
                            return Err(ScriptError::NumEqualVerify);
                        }
                    }
                }

                OP_WITHIN => {
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let bn1 = script_num(top!(3), require_minimal, MAX_SCRIPTNUM_SIZE)?;
                    let bn2 = script_num(top!(2), require_minimal, MAX_SCRIPTNUM_SIZE)?;
                    let bn3 = script_num(top!(1), require_minimal, MAX_SCRIPTNUM_SIZE)?;
                    let value = bn2 <= bn1 && bn1 < bn3;
                    stack.pop();
                    stack.pop();
                    stack.pop();
                    stack.push(if value {
                        vch_true.clone()
                    } else {
                        vch_false.clone()
                    });
                }

                // Crypto
                OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => {
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let vch = top!(1);
                    let hash: Vec<u8> = match opcode {
                        OP_RIPEMD160 => Ripemd160::digest(vch).to_vec(),
                        OP_SHA1 => Sha1::digest(vch).to_vec(),
                        OP_SHA256 => Sha256::digest(vch).to_vec(),
                        OP_HASH160 => Ripemd160::digest(Sha256::digest(vch)).to_vec(),
                        _ => sha256(&sha256(vch)).to_vec(), // OP_HASH256
                    };
                    stack.pop();
                    stack.push(hash);
                }

                OP_CODESEPARATOR => {
                    // Hash starts after the code separator. (CONST_SCRIPTCODE
                    // rejection in BASE happens above the match.)
                    pbegincodehash = pc;
                    execdata.codeseparator_pos = opcode_pos;
                }

                OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                    if stack.len() < 2 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let (sig, pubkey) = (top!(2).clone(), top!(1).clone());
                    let success = eval_checksig(
                        &sig,
                        &pubkey,
                        pbegincodehash,
                        bytes,
                        execdata,
                        flags,
                        checker,
                        sigversion,
                    )?;
                    stack.pop();
                    stack.pop();
                    stack.push(if success {
                        vch_true.clone()
                    } else {
                        vch_false.clone()
                    });
                    if opcode == OP_CHECKSIGVERIFY {
                        if success {
                            stack.pop();
                        } else {
                            return Err(ScriptError::CheckSigVerify);
                        }
                    }
                }

                OP_CHECKSIGADD => {
                    // Only available in tapscript.
                    if matches!(sigversion, SigVersion::Base | SigVersion::WitnessV0) {
                        return Err(ScriptError::BadOpcode);
                    }
                    if stack.len() < 3 {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let sig = top!(3).clone();
                    let num = script_num(top!(2), require_minimal, MAX_SCRIPTNUM_SIZE)?;
                    let pubkey = top!(1).clone();
                    let success = eval_checksig(
                        &sig,
                        &pubkey,
                        pbegincodehash,
                        bytes,
                        execdata,
                        flags,
                        checker,
                        sigversion,
                    )?;
                    stack.pop();
                    stack.pop();
                    stack.pop();
                    stack.push(encode_script_num(num + i64::from(success)));
                }

                OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                    if sigversion == SigVersion::Tapscript {
                        return Err(ScriptError::TapscriptCheckMultisig);
                    }

                    // ([sig ...] num_sigs [pubkey ...] num_pubkeys -- bool)
                    let mut i = 1usize;
                    if stack.len() < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let mut keys_count =
                        getint(script_num(top!(i), require_minimal, MAX_SCRIPTNUM_SIZE)?);
                    if keys_count < 0 || keys_count > i64::from(MAX_PUBKEYS_PER_MULTISIG) {
                        return Err(ScriptError::PubkeyCount);
                    }
                    op_count += keys_count;
                    if op_count > MAX_OPS_PER_SCRIPT {
                        return Err(ScriptError::OpCount);
                    }
                    i += 1;
                    let mut ikey = i; // position of the current key below the top
                    // ikey2 is the position of the last non-signature item;
                    // used for NULLFAIL cleanup when the operation fails.
                    let mut ikey2 = keys_count + 2;
                    i += keys_count as usize;
                    if stack.len() < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    let mut sigs_count =
                        getint(script_num(top!(i), require_minimal, MAX_SCRIPTNUM_SIZE)?);
                    if sigs_count < 0 || sigs_count > keys_count {
                        return Err(ScriptError::SigCount);
                    }
                    i += 1;
                    let mut isig = i;
                    i += sigs_count as usize;
                    if stack.len() < i {
                        return Err(ScriptError::InvalidStackOperation);
                    }

                    // Subset of script starting at the most recent codeseparator.
                    let mut script_code: Vec<u8> = bytes[pbegincodehash..].to_vec();
                    // Drop signatures in pre-segwit scripts only.
                    if sigversion == SigVersion::Base {
                        for k in 0..sigs_count as usize {
                            let sig = top!(isig + k);
                            let found = find_and_delete(&mut script_code, &push_slice(sig));
                            if found > 0 && flags.contains(ScriptFlags::CONST_SCRIPTCODE) {
                                return Err(ScriptError::SigFindAndDelete);
                            }
                        }
                    }

                    let mut success = true;
                    while success && sigs_count > 0 {
                        let (sig, pubkey) = (top!(isig).clone(), top!(ikey).clone());
                        // The exact pubkey/signature evaluation order is
                        // observable via STRICTENC encoding errors.
                        check_signature_encoding(&sig, flags)?;
                        check_pubkey_encoding(&pubkey, flags, sigversion)?;
                        let ok =
                            checker.check_ecdsa_signature(&sig, &pubkey, &script_code, sigversion);
                        if ok {
                            isig += 1;
                            sigs_count -= 1;
                        }
                        ikey += 1;
                        keys_count -= 1;
                        // More signatures left than keys → too many failed.
                        if sigs_count > keys_count {
                            success = false;
                        }
                    }

                    // Clean up the actual arguments.
                    while i > 1 {
                        // On failure, NULLFAIL requires all signatures empty.
                        // stack.len() >= i >= 2 here, so top!(1) is in range.
                        if !success
                            && flags.contains(ScriptFlags::NULLFAIL)
                            && ikey2 == 0
                            && !top!(1).is_empty()
                        {
                            return Err(ScriptError::SigNullFail);
                        }
                        if ikey2 > 0 {
                            ikey2 -= 1;
                        }
                        stack.pop();
                        i -= 1;
                    }

                    // CHECKMULTISIG consumes one extra unchecked argument (the
                    // "dummy"); NULLDUMMY requires it to be exactly zero.
                    if stack.is_empty() {
                        return Err(ScriptError::InvalidStackOperation);
                    }
                    if flags.contains(ScriptFlags::NULLDUMMY) && !top!(1).is_empty() {
                        return Err(ScriptError::SigNullDummy);
                    }
                    stack.pop();

                    stack.push(if success {
                        vch_true.clone()
                    } else {
                        vch_false.clone()
                    });
                    if opcode == OP_CHECKMULTISIGVERIFY {
                        if success {
                            stack.pop();
                        } else {
                            return Err(ScriptError::CheckMultisigVerify);
                        }
                    }
                }

                _ => return Err(ScriptError::BadOpcode),
            }
        }

        // Size limits.
        if stack.len() + altstack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }

        opcode_pos += 1;
    }

    if !cond.is_empty() {
        return Err(ScriptError::UnbalancedConditional);
    }
    Ok(())
}

/// `EvalScript` convenience without a pre-existing [`ExecutionData`].
pub fn eval_script_simple(
    stack: &mut Vec<Vec<u8>>,
    script: &Script,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
    sigversion: SigVersion,
) -> Result<(), ScriptError> {
    let mut execdata = ExecutionData::default();
    eval_script(stack, script, flags, checker, sigversion, &mut execdata)
}

// ---------------------------------------------------------------------------
// Taproot helpers
// ---------------------------------------------------------------------------

/// `ComputeTapleafHash` — `SHA256_TapLeaf(leaf_version || compact_size(len) || script)`.
#[must_use]
pub fn compute_tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let tag = sha256(b"TapLeaf");
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag);
    hasher.update([leaf_version]);
    let mut len_buf = Vec::new();
    write_compact_size(&mut len_buf, script.len() as u64);
    hasher.update(&len_buf);
    hasher.update(script);
    hasher.finalize().into()
}

/// `ComputeTapbranchHash` — `SHA256_TapBranch(a || b)` with the children in
/// lexicographic order.
#[must_use]
pub fn compute_tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let tag = sha256(b"TapBranch");
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag);
    if a <= b {
        hasher.update(a);
        hasher.update(b);
    } else {
        hasher.update(b);
        hasher.update(a);
    }
    hasher.finalize().into()
}

/// `ComputeTaprootMerkleRoot` — fold `control`'s path nodes into `tapleaf_hash`.
#[must_use]
pub fn compute_taproot_merkle_root(control: &[u8], tapleaf_hash: &[u8; 32]) -> [u8; 32] {
    debug_assert!(control.len() >= TAPROOT_CONTROL_BASE_SIZE);
    debug_assert!(control.len() <= TAPROOT_CONTROL_MAX_SIZE);
    debug_assert!(
        (control.len() - TAPROOT_CONTROL_BASE_SIZE).is_multiple_of(TAPROOT_CONTROL_NODE_SIZE)
    );
    let mut k = *tapleaf_hash;
    for node in control[TAPROOT_CONTROL_BASE_SIZE..]
        .as_chunks::<TAPROOT_CONTROL_NODE_SIZE>()
        .0
    {
        k = compute_tapbranch_hash(&k, node);
    }
    k
}

/// `GetSerializeSize(witness.stack)` — CompactSize count plus each item's
/// CompactSize-prefixed bytes.
fn witness_serialized_size(items: &[Vec<u8>]) -> usize {
    compact_size_len(items.len() as u64)
        + items
            .iter()
            .map(|i| compact_size_len(i.len() as u64) + i.len())
            .sum::<usize>()
}

// ---------------------------------------------------------------------------
// Witness program dispatch (VerifyWitnessProgram / ExecuteWitnessScript)
// ---------------------------------------------------------------------------

/// `ExecuteWitnessScript`.
fn execute_witness_script(
    stack_items: &[Vec<u8>],
    exec_script: &[u8],
    flags: ScriptFlags,
    sigversion: SigVersion,
    checker: &dyn SignatureChecker,
    execdata: &mut ExecutionData,
) -> Result<(), ScriptError> {
    let mut stack: Vec<Vec<u8>> = stack_items.to_vec();

    if sigversion == SigVersion::Tapscript {
        // OP_SUCCESSx processing overrides everything, including stack
        // element size limits.
        let mut pc = 0usize;
        while pc < exec_script.len() {
            match get_op(exec_script, &mut pc) {
                None => {
                    // Would not be reached if an unknown OP_SUCCESSx was found.
                    return Err(ScriptError::BadOpcode);
                }
                Some((opcode, _)) => {
                    if is_op_success(opcode) {
                        if flags.contains(ScriptFlags::DISCOURAGE_OP_SUCCESS) {
                            return Err(ScriptError::DiscourageOpSuccess);
                        }
                        return Ok(());
                    }
                }
            }
        }
        // Tapscript enforces initial stack size limits (altstack empty).
        if stack.len() > MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
    }

    // Witness stack items may not exceed MAX_SCRIPT_ELEMENT_SIZE.
    for elem in &stack {
        if elem.len() > MAX_SCRIPT_ELEMENT_SIZE {
            return Err(ScriptError::PushSize);
        }
    }

    eval_script(
        &mut stack,
        &Script::new(exec_script.to_vec()),
        flags,
        checker,
        sigversion,
        execdata,
    )?;

    // Scripts inside witness implicitly require cleanstack.
    if stack.len() != 1 {
        return Err(ScriptError::CleanStack);
    }
    if !cast_to_bool(&stack[stack.len() - 1]) {
        return Err(ScriptError::EvalFalse);
    }
    Ok(())
}

/// `VerifyWitnessProgram` — dispatch a witness program: v0 keyhash/scripthash,
/// v1 taproot (key path or script path), P2A, or an unencumbered upgradeable
/// program.
#[allow(clippy::too_many_arguments)]
pub fn verify_witness_program(
    witness: &Witness,
    witversion: u8,
    program: &[u8],
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
    is_p2sh: bool,
) -> Result<(), ScriptError> {
    let mut stack: &[Vec<u8>] = witness.items();
    let mut execdata = ExecutionData::default();

    if witversion == 0 {
        if program.len() == crate::script::WITNESS_V0_SCRIPTHASH_SIZE {
            // BIP141 P2WSH: 32-byte program = SHA256(witness script).
            let Some((script_bytes, rest)) = stack.split_last() else {
                return Err(ScriptError::WitnessProgramWitnessEmpty);
            };
            if sha256(script_bytes).as_slice() != program {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            stack = rest;
            return execute_witness_script(
                stack,
                script_bytes,
                flags,
                SigVersion::WitnessV0,
                checker,
                &mut execdata,
            );
        } else if program.len() == crate::script::WITNESS_V0_KEYHASH_SIZE {
            // BIP141 P2WPKH: 20-byte program = HASH160(pubkey); implied
            // scriptPubKey is the legacy P2PKH body.
            if stack.len() != 2 {
                return Err(ScriptError::WitnessProgramMismatch);
            }
            let mut exec_script = vec![0x76, OP_HASH160, 0x14]; // OP_DUP OP_HASH160 <20>
            exec_script.extend_from_slice(program);
            exec_script.extend_from_slice(&[0x88, OP_CHECKSIG]); // OP_EQUALVERIFY OP_CHECKSIG
            return execute_witness_script(
                stack,
                &exec_script,
                flags,
                SigVersion::WitnessV0,
                checker,
                &mut execdata,
            );
        }
        Err(ScriptError::WitnessProgramWrongLength)
    } else if witversion == 1 && program.len() == WITNESS_V1_TAPROOT_SIZE && !is_p2sh {
        // BIP341 taproot: 32-byte non-P2SH v1 program = tweaked x-only key.
        if !flags.contains(ScriptFlags::TAPROOT) {
            return Ok(());
        }
        if stack.is_empty() {
            return Err(ScriptError::WitnessProgramWitnessEmpty);
        }
        // Annex: last stack item beginning with ANNEX_TAG is removed and
        // committed to the sighash.
        if stack.len() >= 2
            && let Some(annex) = stack.last()
            && !annex.is_empty()
            && annex[0] == ANNEX_TAG
        {
            let mut annex_ser = Vec::with_capacity(annex.len() + 5);
            write_compact_size(&mut annex_ser, annex.len() as u64);
            annex_ser.extend_from_slice(annex);
            execdata.annex_hash = Some(sha256(&annex_ser));
            execdata.annex_present = true;
            stack = &stack[..stack.len() - 1];
        } else {
            execdata.annex_present = false;
        }
        execdata.annex_init = true;

        if stack.len() == 1 {
            // Key path spend.
            checker.check_schnorr_signature(
                &stack[0],
                program,
                SigVersion::Taproot,
                &mut execdata,
            )?;
            return Ok(());
        }
        // Script path spend.
        let control = &stack[stack.len() - 1];
        let script = &stack[stack.len() - 2];
        stack = &stack[..stack.len() - 2];
        if control.len() < TAPROOT_CONTROL_BASE_SIZE
            || control.len() > TAPROOT_CONTROL_MAX_SIZE
            || !(control.len() - TAPROOT_CONTROL_BASE_SIZE)
                .is_multiple_of(TAPROOT_CONTROL_NODE_SIZE)
        {
            return Err(ScriptError::TaprootWrongControlSize);
        }
        let tapleaf_hash = compute_tapleaf_hash(control[0] & TAPROOT_LEAF_MASK, script);
        execdata.tapleaf_hash = Some(tapleaf_hash);
        if !checker.verify_taproot_commitment(control, program, &tapleaf_hash) {
            return Err(ScriptError::WitnessProgramMismatch);
        }
        execdata.tapleaf_hash_init = true;
        if control[0] & TAPROOT_LEAF_MASK == TAPROOT_LEAF_TAPSCRIPT {
            execdata.validation_weight_left =
                witness_serialized_size(witness.items()) as i64 + VALIDATION_WEIGHT_OFFSET;
            execdata.validation_weight_left_init = true;
            return execute_witness_script(
                stack,
                script,
                flags,
                SigVersion::Tapscript,
                checker,
                &mut execdata,
            );
        }
        if flags.contains(ScriptFlags::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION) {
            return Err(ScriptError::DiscourageUpgradableTaprootVersion);
        }
        Ok(())
    } else if !is_p2sh && is_pay_to_anchor(witversion, program) {
        Ok(())
    } else {
        if flags.contains(ScriptFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
            return Err(ScriptError::DiscourageUpgradableWitnessProgram);
        }
        // Other version/size/p2sh combinations succeed for softfork
        // compatibility.
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VerifyScript — the scriptSig/scriptPubKey/P2SH/witness orchestration
// ---------------------------------------------------------------------------

/// `VerifyScript` — the full `CheckInputScripts` script orchestration for one
/// input: `scriptSig` → `scriptPubKey` → P2SH redeem → witness dispatch,
/// with CLEANSTACK and WITNESS_UNEXPECTED enforcement.
///
/// `witness` should be `None` when the spending input carries no witness —
/// Core's `nullptr` becomes the static empty witness.
pub fn verify_script(
    script_sig: &Script,
    script_pubkey: &Script,
    witness: Option<&Witness>,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    static EMPTY_WITNESS: Witness = Witness::EMPTY;
    let witness = witness.unwrap_or(&EMPTY_WITNESS);
    let mut had_witness = false;

    if flags.contains(ScriptFlags::SIGPUSHONLY) && !script_sig.is_push_only() {
        return Err(ScriptError::SigPushOnly);
    }

    // scriptSig and scriptPubKey evaluate sequentially on the same stack
    // (CVE-2010-5141). Each EvalScript call gets a fresh ScriptExecutionData,
    // matching Core's two-argument EvalScript overload.
    let mut stack: Vec<Vec<u8>> = Vec::new();
    eval_script(
        &mut stack,
        script_sig,
        flags,
        checker,
        SigVersion::Base,
        &mut ExecutionData::default(),
    )?;
    let stack_copy = if flags.contains(ScriptFlags::P2SH) {
        stack.clone()
    } else {
        Vec::new()
    };
    eval_script(
        &mut stack,
        script_pubkey,
        flags,
        checker,
        SigVersion::Base,
        &mut ExecutionData::default(),
    )?;
    if stack.is_empty() || !cast_to_bool(&stack[stack.len() - 1]) {
        return Err(ScriptError::EvalFalse);
    }

    // Bare witness program in the scriptPubKey.
    if flags.contains(ScriptFlags::WITNESS)
        && let Some((witversion, witprogram)) = script_pubkey.witness_program()
    {
        had_witness = true;
        if !script_sig.is_empty() {
            // The scriptSig must be exactly CScript(), else malleability.
            return Err(ScriptError::WitnessMalleated);
        }
        verify_witness_program(witness, witversion, witprogram, flags, checker, false)?;
        // Bypass the cleanstack check at the end.
        stack.truncate(1);
    }

    // Pay-to-script-hash.
    if flags.contains(ScriptFlags::P2SH) && script_pubkey.is_p2sh() {
        // scriptSig must be literals-only.
        if !script_sig.is_push_only() {
            return Err(ScriptError::SigPushOnly);
        }
        // Restore the pre-scriptPubKey stack (Core's swap(stack, stackCopy)).
        stack = stack_copy;
        // The stack cannot be empty: the P2SH scriptPubKey eval would have
        // failed above otherwise.
        debug_assert!(!stack.is_empty());
        let serialized = stack.pop().unwrap_or_default();
        let redeem = Script::new(serialized.clone());
        eval_script(
            &mut stack,
            &redeem,
            flags,
            checker,
            SigVersion::Base,
            &mut ExecutionData::default(),
        )?;
        if stack.is_empty() || !cast_to_bool(&stack[stack.len() - 1]) {
            return Err(ScriptError::EvalFalse);
        }

        // P2SH-wrapped witness program.
        if flags.contains(ScriptFlags::WITNESS)
            && let Some((witversion, witprogram)) = redeem.witness_program()
        {
            had_witness = true;
            if script_sig.as_bytes() != push_slice(&serialized).as_slice() {
                // The scriptSig must be exactly a single push of the
                // redeemScript, else malleability.
                return Err(ScriptError::WitnessMalleatedP2sh);
            }
            verify_witness_program(witness, witversion, witprogram, flags, checker, true)?;
            stack.truncate(1);
        }
    }

    // CLEANSTACK runs after P2SH evaluation: the non-P2SH stack of a P2SH
    // spend retains the pushes.
    if flags.contains(ScriptFlags::CLEANSTACK) {
        debug_assert!(flags.contains(ScriptFlags::P2SH));
        debug_assert!(flags.contains(ScriptFlags::WITNESS));
        if stack.len() != 1 {
            return Err(ScriptError::CleanStack);
        }
    }

    if flags.contains(ScriptFlags::WITNESS) {
        debug_assert!(flags.contains(ScriptFlags::P2SH));
        if !had_witness && !witness.is_empty() {
            return Err(ScriptError::WitnessUnexpected);
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

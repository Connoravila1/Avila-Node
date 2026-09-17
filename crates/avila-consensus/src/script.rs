//! Structural script model: opcode iteration, push-data decoding, well-known template
//! detection (P2SH, witness programs), signature-operation counting, and the script
//! encodings BIP34's height-in-coinbase rule needs.
//!
//! This module deliberately does **not** execute scripts — the interpreter (and its
//! consensus-critical signature checks) is a separate work item. Everything here is a
//! port of the parsing/introspection parts of Core's `script/script.cpp` and
//! `script/script.h`: [`Instructions`] mirrors `CScript::GetOp`,
//! [`Script::sig_ops`] mirrors `CScript::GetSigOpCount`, [`Script::is_push_only`]
//! mirrors `IsPushOnly`, and the witness-program helpers mirror `IsWitnessProgram`.
//!
//! Only the opcodes the structural rules actually consult are named below; the full
//! opcode table arrives with the interpreter. Every helper is total: malformed push
//! data terminates an [`Instructions`] iterator instead of panicking, matching Core's
//! `GetOp` returning `false`.

use crate::hash::BlockHash;
use crate::params::Params;
use crate::transaction::{Script, Witness};

// ---------------------------------------------------------------------------
// Opcodes (the subset the structural rules consult)
// ---------------------------------------------------------------------------

/// `OP_0` / `OP_FALSE`: pushes an empty byte string.
pub const OP_0: u8 = 0x00;
/// `OP_PUSHDATA1`: the next byte is the pushed data's length.
pub const OP_PUSHDATA1: u8 = 0x4c;
/// `OP_PUSHDATA2`: the next two bytes are the pushed data's little-endian length.
pub const OP_PUSHDATA2: u8 = 0x4d;
/// `OP_PUSHDATA4`: the next four bytes are the pushed data's little-endian length.
pub const OP_PUSHDATA4: u8 = 0x4e;
/// `OP_1NEGATE`.
pub const OP_1NEGATE: u8 = 0x4f;
/// `OP_RESERVED`.
pub const OP_RESERVED: u8 = 0x50;
/// `OP_1` / `OP_TRUE`: the smallest "small integer" opcode (`OP_1` through `OP_16`
/// occupy `0x51..=0x60`).
pub const OP_1: u8 = 0x51;
/// `OP_16`: the largest "small integer" opcode. Every opcode at or below `OP_16`
/// preserves push-only status (Core's `IsPushOnly` test is `opcode > OP_16`).
pub const OP_16: u8 = 0x60;
/// `OP_RETURN`.
pub const OP_RETURN: u8 = 0x6a;
/// `OP_IF`.
pub const OP_IF: u8 = 0x63;
/// `OP_NOTIF`.
pub const OP_NOTIF: u8 = 0x64;
/// `OP_ELSE`.
pub const OP_ELSE: u8 = 0x67;
/// `OP_ENDIF`.
pub const OP_ENDIF: u8 = 0x68;
/// `OP_VERIFY`.
pub const OP_VERIFY: u8 = 0x69;
/// `OP_TOALTSTACK`.
pub const OP_TOALTSTACK: u8 = 0x6b;
/// `OP_FROMALTSTACK`.
pub const OP_FROMALTSTACK: u8 = 0x6c;
/// `OP_IFDUP`.
pub const OP_IFDUP: u8 = 0x73;
/// `OP_DUP`.
pub const OP_DUP: u8 = 0x76;
/// `OP_SWAP`.
pub const OP_SWAP: u8 = 0x7c;
/// `OP_SIZE`.
pub const OP_SIZE: u8 = 0x82;
/// `OP_EQUAL`.
pub const OP_EQUAL: u8 = 0x87;
/// `OP_EQUALVERIFY`.
pub const OP_EQUALVERIFY: u8 = 0x88;
/// `OP_0NOTEQUAL`.
pub const OP_0NOTEQUAL: u8 = 0x92;
/// `OP_ADD`.
pub const OP_ADD: u8 = 0x93;
/// `OP_BOOLAND`.
pub const OP_BOOLAND: u8 = 0x9a;
/// `OP_BOOLOR`.
pub const OP_BOOLOR: u8 = 0x9b;
/// `OP_NUMEQUAL`.
pub const OP_NUMEQUAL: u8 = 0x9c;
/// `OP_NUMEQUALVERIFY`.
pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
/// `OP_RIPEMD160`.
pub const OP_RIPEMD160: u8 = 0xa6;
/// `OP_SHA256`.
pub const OP_SHA256: u8 = 0xa8;
/// `OP_HASH160`.
pub const OP_HASH160: u8 = 0xa9;
/// `OP_HASH256`.
pub const OP_HASH256: u8 = 0xaa;
/// `OP_CHECKSIG`.
pub const OP_CHECKSIG: u8 = 0xac;
/// `OP_CHECKSIGVERIFY`.
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
/// `OP_CHECKMULTISIG`.
pub const OP_CHECKMULTISIG: u8 = 0xae;
/// `OP_CHECKMULTISIGVERIFY`.
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
/// `OP_CHECKLOCKTIMEVERIFY` (`OP_NOP2`).
pub const OP_CLTV: u8 = 0xb1;
/// `OP_CHECKSEQUENCEVERIFY` (`OP_NOP3`).
pub const OP_CSV: u8 = 0xb2;
/// `OP_NOP10` — Core's `MAX_OPCODE`, the largest opcode `HasValidOps` accepts.
pub const OP_NOP10: u8 = 0xb9;
/// `OP_CHECKSIGADD` — the BIP342 tapscript batch-checksig opcode.
pub const OP_CHECKSIGADD: u8 = 0xba;

/// Core `script/script.h`'s `MAX_PUBKEYS_PER_MULTISIG`: the sigop cost charged for a
/// bare multisig opcode when the preceding opcode is not a small integer (or accuracy
/// isn't requested).
pub const MAX_PUBKEYS_PER_MULTISIG: u32 = 20;

/// The largest push a direct-push opcode (`0x01..=0x4b`) can encode — the boundary
/// between a bare opcode byte and a `PUSHDATA`-prefixed push.
const MAX_DIRECT_PUSH: u8 = 0x4b;

/// Decodes a small-integer opcode to its value (`OP_0` → `0`, `OP_1..=OP_16` →
/// `1..=16`), Core's `DecodeOP_N`. Returns `None` for any other opcode.
#[must_use]
pub fn decode_op_n(opcode: u8) -> Option<u8> {
    match opcode {
        OP_0 => Some(0),
        OP_1..=OP_16 => Some(opcode - (OP_1 - 1)),
        _ => None,
    }
}

/// One decoded script instruction: either a data push (the bytes pushed, which may be
/// empty for `OP_0`) or a non-push opcode byte.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Instruction<'a> {
    /// A push of `data` bytes onto the stack. `data` is empty for `OP_0` and may be
    /// empty for `OP_PUSHDATA*` encodings of a zero-length push.
    Push(&'a [u8]),
    /// A non-push opcode byte.
    Op(u8),
}

/// A push instruction whose declared length exceeds the script's remaining bytes —
/// Core's `GetScriptOp` failure. Carries the offset of the offending opcode byte.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MalformedScript {
    /// The script offset of the instruction that failed to decode.
    pub position: usize,
}

/// An iterator over a script's instructions, mirroring a `while (GetOp(pc, opcode))`
/// loop over `CScript`. On a malformed push it yields `Err`([`MalformedScript`]) once
/// and then ends, so consumers that stop at the first error behave exactly like Core's
/// loops (which `break` on `GetOp` failure).
#[derive(Clone, Debug)]
pub struct Instructions<'a> {
    bytes: &'a [u8],
    position: usize,
    finished: bool,
}

impl<'a> Iterator for Instructions<'a> {
    type Item = Result<Instruction<'a>, MalformedScript>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let bytes = self.bytes;
        let start = self.position;
        let opcode = *bytes.get(start)?;
        let mut cursor = start + 1;
        let push_len = match opcode {
            // OP_0 (0x00) pushes zero bytes — Core's GetScriptOp treats every opcode at
            // or below OP_PUSHDATA4 as a data push.
            OP_0..=MAX_DIRECT_PUSH => usize::from(opcode),
            OP_PUSHDATA1 | OP_PUSHDATA2 | OP_PUSHDATA4 => {
                let width = match opcode {
                    OP_PUSHDATA1 => 1,
                    OP_PUSHDATA2 => 2,
                    _ => 4,
                };
                let Some(len_bytes) = bytes.get(cursor..cursor + width) else {
                    self.finished = true;
                    return Some(Err(MalformedScript { position: start }));
                };
                cursor += width;
                let mut len = 0u32;
                for (shift, byte) in len_bytes.iter().enumerate() {
                    len |= u32::from(*byte) << (8 * shift);
                }
                // usize is at least 32 bits on every supported target.
                match usize::try_from(len) {
                    Ok(len) => len,
                    Err(_) => {
                        self.finished = true;
                        return Some(Err(MalformedScript { position: start }));
                    }
                }
            }
            _ => {
                self.position = cursor;
                return Some(Ok(Instruction::Op(opcode)));
            }
        };
        let Some(end) = cursor.checked_add(push_len) else {
            self.finished = true;
            return Some(Err(MalformedScript { position: start }));
        };
        match bytes.get(cursor..end) {
            Some(data) => {
                self.position = end;
                Some(Ok(Instruction::Push(data)))
            }
            None => {
                self.finished = true;
                Some(Err(MalformedScript { position: start }))
            }
        }
    }
}

/// A well-known output template — Core's `TxoutType` from `Solver`
/// (standard.cpp), with the extracted payload where the template
/// carries one. Used for RPC `scriptPubKey` classification; this is
/// display-layer naming, not a consensus rule.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ScriptType {
    /// Matches no standard template (Core's `TX_NONSTANDARD`).
    Nonstandard,
    /// `<pubkey> OP_CHECKSIG` — bare pay-to-pubkey (Core's `TX_PUBKEY`).
    PubKey(Vec<u8>),
    /// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` (`TX_PUBKEYHASH`).
    PubKeyHash([u8; 20]),
    /// `OP_HASH160 <20> OP_EQUAL` (`TX_SCRIPTHASH`).
    ScriptHash([u8; 20]),
    /// `m <pubkey>… n OP_CHECKMULTISIG` (`TX_MULTISIG`).
    Multisig {
        /// Signatures required (`m`).
        required: u8,
        /// The listed public keys, in script order.
        keys: Vec<Vec<u8>>,
    },
    /// `OP_RETURN` followed by push-only data (`TX_NULL_DATA`).
    NullData,
    /// Any witness program — `OP_n <2..40-byte program>`; the variant
    /// Core splits into `witness_v0_keyhash`/`witness_v0_scripthash`/
    /// `witness_v1_taproot`/`witness_unknown` is derived from
    /// `version`/`program` by [`ScriptType::name`].
    Witness {
        /// The witness version (0–16).
        version: u8,
        /// The witness program bytes.
        program: Vec<u8>,
    },
    /// The v28+ ephemeral-anchor script `OP_1 <0x4e73>` (`TX_ANCHOR`) —
    /// technically a v1 witness program, but `Solver` names it `anchor`.
    Anchor,
}

impl ScriptType {
    /// Core's `GetTxnOutputType` string for this template.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Nonstandard => "nonstandard",
            Self::PubKey(_) => "pubkey",
            Self::PubKeyHash(_) => "pubkeyhash",
            Self::ScriptHash(_) => "scripthash",
            Self::Multisig { .. } => "multisig",
            Self::NullData => "nulldata",
            Self::Witness { version, program } => match (version, program.len()) {
                (0, 20) => "witness_v0_keyhash",
                (0, 32) => "witness_v0_scripthash",
                (1, 32) => "witness_v1_taproot",
                _ => "witness_unknown",
            },
            Self::Anchor => "anchor",
        }
    }
}

/// A pubkey in compressed (`02`/`03` + 32 bytes) or uncompressed
/// (`04` + 64 bytes) form — Core's `CPubKey::ValidSize` +
/// `IsCompressedOrUncompressedPubKey`.
fn is_valid_pubkey(key: &[u8]) -> bool {
    match key.len() {
        33 => matches!(key[0], 0x02 | 0x03),
        65 => key[0] == 0x04,
        _ => false,
    }
}

/// `CScriptNum` decode for `asm` rendering — little-endian
/// sign-magnitude, no minimal-encoding or size enforcement (only
/// pushes of at most four bytes reach it, so the value fits `i64`).
///
/// `ScriptToAsmStr`'s sighash decode: if `data` passes strict-DER
/// signature encoding (`CheckSignatureEncoding` under
/// `SCRIPT_VERIFY_STRICTENC`) and its last byte is a *defined*
/// hashtype — base type ALL/NONE/SINGLE, no unsupported flag bits —
/// return Core's `"[HASHTYPE]"` suffix. The caller strips the byte.
fn sighash_suffix(data: &[u8]) -> Option<&'static str> {
    if !crate::interpreter::is_valid_signature_encoding(data) {
        return None;
    }
    let t = *data.last()?;
    // `IsDefinedHashtypeSignature`: the base type must be a defined
    // enum member and no bits outside ALL|NONE|SINGLE|ANYONECANPAY.
    if t & !0x83 != 0 {
        return None;
    }
    let base = match t & 0x1f {
        1 => "ALL",
        2 => "NONE",
        3 => "SINGLE",
        _ => return None,
    };
    Some(match t & 0x80 {
        0x80 if base == "ALL" => "[ALL|ANYONECANPAY]",
        0x80 if base == "NONE" => "[NONE|ANYONECANPAY]",
        0x80 if base == "SINGLE" => "[SINGLE|ANYONECANPAY]",
        0x80 => return None,
        _ if base == "ALL" => "[ALL]",
        _ if base == "NONE" => "[NONE]",
        _ => "[SINGLE]",
    })
}

fn script_num(data: &[u8]) -> i64 {
    let mut value = 0i64;
    for (i, &b) in data.iter().enumerate() {
        value |= i64::from(b) << (8 * i);
    }
    if let Some(&last) = data.last()
        && last & 0x80 != 0
    {
        value &= !(0x80i64 << (8 * (data.len() - 1)));
        return -value;
    }
    value
}

/// Core's `GetOpName` — the canonical string for a non-push opcode.
/// `OP_1..=OP_16` render as `1`–`16` and `OP_1NEGATE` as `-1`
/// (numbers, matching bitcoind's `asm` output); unassigned opcode
/// bytes render `OP_UNKNOWN`.
#[must_use]
pub fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        OP_1NEGATE => "-1",
        OP_RESERVED => "OP_RESERVED",
        OP_1..=OP_16 => {
            const NUMBERS: [&str; 16] = [
                "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15",
                "16",
            ];
            NUMBERS[usize::from(opcode - OP_1)]
        }
        0x61 => "OP_NOP",
        0x62 => "OP_VER",
        0x63 => "OP_IF",
        0x64 => "OP_NOTIF",
        0x65 => "OP_VERIF",
        0x66 => "OP_VERNOTIF",
        0x67 => "OP_ELSE",
        0x68 => "OP_ENDIF",
        0x69 => "OP_VERIFY",
        OP_RETURN => "OP_RETURN",
        0x6b => "OP_TOALTSTACK",
        0x6c => "OP_FROMALTSTACK",
        0x6d => "OP_2DROP",
        0x6e => "OP_2DUP",
        0x6f => "OP_3DUP",
        0x70 => "OP_2OVER",
        0x71 => "OP_2ROT",
        0x72 => "OP_2SWAP",
        0x73 => "OP_IFDUP",
        0x74 => "OP_DEPTH",
        0x75 => "OP_DROP",
        0x76 => "OP_DUP",
        0x77 => "OP_NIP",
        0x78 => "OP_OVER",
        0x79 => "OP_PICK",
        0x7a => "OP_ROLL",
        0x7b => "OP_ROT",
        0x7c => "OP_SWAP",
        0x7d => "OP_TUCK",
        0x7e => "OP_CAT",
        0x7f => "OP_SUBSTR",
        0x80 => "OP_LEFT",
        0x81 => "OP_RIGHT",
        0x82 => "OP_SIZE",
        0x83 => "OP_INVERT",
        0x84 => "OP_AND",
        0x85 => "OP_OR",
        0x86 => "OP_XOR",
        0x87 => "OP_EQUAL",
        0x88 => "OP_EQUALVERIFY",
        0x89 => "OP_RESERVED1",
        0x8a => "OP_RESERVED2",
        0x8b => "OP_1ADD",
        0x8c => "OP_1SUB",
        0x8d => "OP_2MUL",
        0x8e => "OP_2DIV",
        0x8f => "OP_NEGATE",
        0x90 => "OP_ABS",
        0x91 => "OP_NOT",
        0x92 => "OP_0NOTEQUAL",
        0x93 => "OP_ADD",
        0x94 => "OP_SUB",
        0x95 => "OP_MUL",
        0x96 => "OP_DIV",
        0x97 => "OP_MOD",
        0x98 => "OP_LSHIFT",
        0x99 => "OP_RSHIFT",
        0x9a => "OP_BOOLAND",
        0x9b => "OP_BOOLOR",
        0x9c => "OP_NUMEQUAL",
        0x9d => "OP_NUMEQUALVERIFY",
        0x9e => "OP_NUMNOTEQUAL",
        0x9f => "OP_LESSTHAN",
        0xa0 => "OP_GREATERTHAN",
        0xa1 => "OP_LESSTHANOREQUAL",
        0xa2 => "OP_GREATERTHANOREQUAL",
        0xa3 => "OP_MIN",
        0xa4 => "OP_MAX",
        0xa5 => "OP_WITHIN",
        0xa6 => "OP_RIPEMD160",
        0xa7 => "OP_SHA1",
        0xa8 => "OP_SHA256",
        OP_HASH160 => "OP_HASH160",
        0xaa => "OP_HASH256",
        0xab => "OP_CODESEPARATOR",
        OP_CHECKSIG => "OP_CHECKSIG",
        OP_CHECKSIGVERIFY => "OP_CHECKSIGVERIFY",
        OP_CHECKMULTISIG => "OP_CHECKMULTISIG",
        OP_CHECKMULTISIGVERIFY => "OP_CHECKMULTISIGVERIFY",
        0xb0 => "OP_NOP1",
        0xb1 => "OP_CHECKLOCKTIMEVERIFY",
        0xb2 => "OP_CHECKSEQUENCEVERIFY",
        0xb3 => "OP_NOP4",
        0xb4 => "OP_NOP5",
        0xb5 => "OP_NOP6",
        0xb6 => "OP_NOP7",
        0xb7 => "OP_NOP8",
        0xb8 => "OP_NOP9",
        0xb9 => "OP_NOP10",
        0xba => "OP_CHECKSIGADD",
        0xff => "OP_INVALIDOPCODE",
        _ => "OP_UNKNOWN",
    }
}

impl Script {
    /// Iterates this script's instructions (Core's `GetOp` loop). `OP_0`, direct pushes
    /// (`0x01..=0x4b`) and `OP_PUSHDATA1/2/4` yield [`Instruction::Push`]; every other
    /// opcode byte yields [`Instruction::Op`].
    #[must_use]
    pub fn instructions(&self) -> Instructions<'_> {
        Instructions {
            bytes: self.as_bytes(),
            position: 0,
            finished: false,
        }
    }

    /// Counts signature operations (Core's `CScript::GetSigOpCount`).
    ///
    /// `OP_CHECKSIG`/`OP_CHECKSIGVERIFY` count 1 each; `OP_CHECKMULTISIG`/
    /// `OP_CHECKMULTISIGVERIFY` count 20 unless `accurate` is set *and* the immediately
    /// preceding opcode is `OP_1..=OP_16`, in which case they count that small integer.
    /// Iteration stops at the first malformed instruction, counting what parsed.
    #[must_use]
    pub fn sig_ops(&self, accurate: bool) -> u64 {
        let mut count = 0u64;
        // The previous instruction's opcode, only when it was a non-push op — Core's
        // `lastOpcode`. Push opcodes (all below OP_1) never decode to an OP_N, so a
        // `None` here reproduces them for the accurate-multisig check.
        let mut last_opcode = None;
        for instruction in self.instructions() {
            let opcode = match instruction {
                Ok(Instruction::Push(_)) => None,
                Ok(Instruction::Op(opcode)) => Some(opcode),
                Err(_) => break,
            };
            match opcode {
                Some(OP_CHECKSIG) | Some(OP_CHECKSIGVERIFY) => count += 1,
                Some(OP_CHECKMULTISIG) | Some(OP_CHECKMULTISIGVERIFY) => {
                    count += if accurate {
                        last_opcode
                            .and_then(decode_op_n)
                            .map_or(u64::from(MAX_PUBKEYS_PER_MULTISIG), u64::from)
                    } else {
                        u64::from(MAX_PUBKEYS_PER_MULTISIG)
                    };
                }
                _ => {}
            }
            last_opcode = opcode;
        }
        count
    }

    /// Returns `true` if every instruction is a push or a small-integer opcode
    /// (`opcode <= OP_16`) — Core's `IsPushOnly`. Malformed scripts are not
    /// push-only (Core's loop returns `false` when `GetOp` fails).
    ///
    /// Note (matching Core's comment): `OP_RESERVED` *is* treated as push-type here;
    /// its execution would fail anyway, so the distinction is unobservable.
    #[must_use]
    pub fn is_push_only(&self) -> bool {
        for instruction in self.instructions() {
            match instruction {
                Ok(Instruction::Push(_)) => {}
                Ok(Instruction::Op(opcode)) if opcode <= OP_16 => {}
                _ => return false,
            }
        }
        true
    }

    /// Returns the data pushed by this script's last instruction, mirroring the
    /// "last item that `scriptSig` pushes" pattern Core uses to extract a P2SH redeem
    /// script or a nested witness program (`GetSigOpCount(scriptSig)` /
    /// `CountWitnessSigOps`).
    ///
    /// Returns `None` if the script is malformed or contains any opcode above `OP_16`.
    /// An empty script — or one whose pushes are all followed by small-integer opcodes —
    /// yields `Some(&[])`, matching Core's default-empty `vData`.
    #[must_use]
    pub fn last_pushed_data(&self) -> Option<&[u8]> {
        let mut last = &[][..];
        for instruction in self.instructions() {
            match instruction {
                Ok(Instruction::Push(data)) => last = data,
                Ok(Instruction::Op(opcode)) if opcode <= OP_16 => {}
                _ => return None,
            }
        }
        Some(last)
    }

    /// Returns `true` if this output can never be spent — Core's `IsUnspendable`:
    /// a script beginning with `OP_RETURN`, or longer than `MAX_SCRIPT_SIZE`
    /// (10,000 bytes). Unspendable outputs are never added to the UTXO set
    /// (Core's `CCoinsViewCache::AddCoin` returns early), so they cannot trigger
    /// BIP30 duplicate-output or spend checks.
    #[must_use]
    pub fn is_unspendable(&self) -> bool {
        let bytes = self.as_bytes();
        bytes.len() > MAX_SCRIPT_SIZE || bytes.first() == Some(&OP_RETURN)
    }

    /// Core's `CScript::HasValidOps` — every opcode byte must decode
    /// and be at most `MAX_OPCODE` (`OP_NOP10`, 0xb9). Display-layer
    /// gate: Core refuses to show P2SH/segwit wrap addresses for
    /// scripts containing invalid opcodes.
    #[must_use]
    pub fn has_valid_ops(&self) -> bool {
        self.instructions().all(|i| match i {
            Ok(Instruction::Op(op)) => op <= OP_NOP10,
            Ok(Instruction::Push(_)) => true,
            Err(_) => false,
        })
    }

    /// Counts signature operations the way `CScript::GetSigOpCount(const CScript&
    /// scriptSig)` does when `self` is a P2SH `scriptPubKey`: every `script_sig`
    /// instruction must decode and be `<= OP_16` (a malformed or non-push op
    /// returns `0`), then the trailing pushed data is treated as the redeem
    /// script and *its* sigops counted accurately — a trailing `OP_N` or
    /// truncated push leaves that data empty (Core's `GetScriptOp` clears
    /// `vchRet` on every call; see `trailing_push_data`).
    ///
    /// Callers must only use this when [`Script::is_p2sh`] holds — in Core the
    /// method is dispatched on the scriptPubKey and falls back to the scriptPubKey's
    /// own count otherwise; [`crate::connect`] calls it only on P2SH prevouts, so
    /// the fallback is omitted here.
    #[must_use]
    pub fn p2sh_sig_ops(&self, script_sig: &Script) -> u64 {
        if !script_sig.is_push_only() {
            return 0;
        }
        Script::new(trailing_push_data(script_sig).to_vec()).sig_ops(true)
    }

    /// Returns `true` if this is a pay-to-script-hash output: exactly
    /// `OP_HASH160 <20-byte hash> OP_EQUAL` (23 bytes), Core's `IsPayToScriptHash`.
    #[must_use]
    pub fn is_p2sh(&self) -> bool {
        let bytes = self.as_bytes();
        bytes.len() == 23 && bytes[0] == OP_HASH160 && bytes[1] == 0x14 && bytes[22] == OP_EQUAL
    }

    /// Returns `true` if this is a v0 pay-to-witness-script-hash output: exactly
    /// `OP_0 <32-byte hash>` (34 bytes), Core's `IsPayToWitnessScriptHash`.
    #[must_use]
    pub fn is_p2wsh(&self) -> bool {
        let bytes = self.as_bytes();
        bytes.len() == 34 && bytes[0] == OP_0 && bytes[1] == 0x20
    }

    /// If this script is a witness program — a 1-byte version opcode (`OP_0` or
    /// `OP_1..=OP_16`) followed by a direct push of 2 to 40 bytes, so 4 to 42 bytes
    /// total — returns `(version, program)` (Core's `IsWitnessProgram`).
    ///
    /// The push must be direct: `(*this)[1] + 2 == size` means a `PUSHDATA`-encoded
    /// program does not qualify even when its payload length would be valid.
    #[must_use]
    pub fn witness_program(&self) -> Option<(u8, &[u8])> {
        let bytes = self.as_bytes();
        if bytes.len() < 4 || bytes.len() > 42 {
            return None;
        }
        let version = match bytes[0] {
            OP_0 => 0,
            op @ OP_1..=OP_16 => op - (OP_1 - 1),
            _ => return None,
        };
        if usize::from(bytes[1]) + 2 != bytes.len() {
            return None;
        }
        Some((version, &bytes[2..]))
    }

    /// Renders this script the way Core's `ScriptToAsmStr` does for
    /// `scriptPubKey.asm`/`scriptSig.asm`: pushes of at most four
    /// bytes as their `CScriptNum` value (little-endian, sign bit in
    /// the top byte — so `OP_0` prints as `0`), longer pushes as hex,
    /// opcodes by [`opcode_name`], space-separated. A truncated push
    /// appends `[error]` and stops (Core's loop does the same on
    /// `GetOp` failure).
    #[must_use]
    pub fn asm(&self) -> String {
        self.asm_impl(false)
    }

    /// `ScriptToAsmStr` with `fAttemptSighashDecode` — the mode Core's
    /// `TxToUniv` applies to `scriptSig` (and only there): a push
    /// longer than four bytes that passes strict-DER signature
    /// encoding and ends in a defined hashtype renders as the DER hex
    /// with `[ALL]`/`[NONE]`/`[SINGLE]`/`[ALL|ANYONECANPAY]`/…
    /// appended. Skipped when the whole script is unspendable.
    #[must_use]
    pub fn asm_sighash(&self) -> String {
        self.asm_impl(true)
    }

    fn asm_impl(&self, attempt_sighash_decode: bool) -> String {
        let attempt = attempt_sighash_decode && !self.is_unspendable();
        let mut out = String::new();
        for instruction in self.instructions() {
            match instruction {
                Ok(Instruction::Push(data)) => {
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    if data.len() <= 4 {
                        out.push_str(&script_num(data).to_string());
                    } else {
                        let (body, suffix) = match sighash_suffix(data).filter(|_| attempt) {
                            Some(name) => (&data[..data.len() - 1], name),
                            None => (data, ""),
                        };
                        for byte in body {
                            out.push_str(&format!("{byte:02x}"));
                        }
                        out.push_str(suffix);
                    }
                }
                Ok(Instruction::Op(opcode)) => {
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push_str(opcode_name(opcode));
                }
                Err(_) => {
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push_str("[error]");
                    break;
                }
            }
        }
        out
    }

    /// Classifies this output script into a well-known template —
    /// Core's `Solver` (standard.cpp): witness programs first, then
    /// P2PKH/P2SH, bare pubkey, bare multisig, and `OP_RETURN`
    /// nulldata. Display-layer classification only.
    #[must_use]
    pub fn classify(&self) -> ScriptType {
        let bytes = self.as_bytes();
        if bytes.is_empty() {
            return ScriptType::Nonstandard;
        }

        // `IsPayToAnchor` precedes `IsWitnessProgram` in Solver — the
        // fixed `OP_1 <0x4e73>` template parses as a v1 program but is
        // reported as `anchor`.
        if bytes == [0x51, 0x02, 0x4e, 0x73] {
            return ScriptType::Anchor;
        }

        // Witness programs — `IsWitnessProgram` checked first in
        // Solver's modern shape (it precedes the legacy templates).
        // A v0 program is only standard at exactly 20 or 32 bytes;
        // other lengths fall through to nonstandard (BIP141).
        if let Some((version, program)) = self.witness_program()
            && (version != 0 || program.len() == 20 || program.len() == 32)
        {
            return ScriptType::Witness {
                version,
                program: program.to_vec(),
            };
        }

        // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG.
        if bytes.len() == 25
            && bytes[0] == 0x76
            && bytes[1] == OP_HASH160
            && bytes[2] == 0x14
            && bytes[23] == 0x88
            && bytes[24] == OP_CHECKSIG
            && let Ok(hash) = <[u8; 20]>::try_from(&bytes[3..23])
        {
            return ScriptType::PubKeyHash(hash);
        }

        // P2SH: OP_HASH160 <20> OP_EQUAL.
        if self.is_p2sh()
            && let Ok(hash) = <[u8; 20]>::try_from(&bytes[2..22])
        {
            return ScriptType::ScriptHash(hash);
        }

        // Bare pay-to-pubkey: <push33|push65> <pubkey> OP_CHECKSIG.
        if (bytes.len() == 35 && bytes[0] == 33) || (bytes.len() == 67 && bytes[0] == 65) {
            let key = &bytes[1..bytes.len() - 1];
            if bytes[bytes.len() - 1] == OP_CHECKSIG && is_valid_pubkey(key) {
                return ScriptType::PubKey(key.to_vec());
            }
        }

        // Bare multisig: OP_m <pubkey>… OP_n OP_CHECKMULTISIG, with the
        // pubkey count matching `n` (Solver's TX_MULTISIG).
        if bytes.len() >= 3
            && bytes[bytes.len() - 1] == OP_CHECKMULTISIG
            && let (Some(m), Some(n)) = (decode_op_n(bytes[0]), decode_op_n(bytes[bytes.len() - 2]))
        {
            let mut keys = Vec::new();
            let mut ok = true;
            for instruction in Script::new(bytes[1..bytes.len() - 2].to_vec()).instructions() {
                match instruction {
                    Ok(Instruction::Push(key)) if is_valid_pubkey(key) => {
                        keys.push(key.to_vec());
                    }
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok && keys.len() == usize::from(n) && m >= 1 && m <= n {
                return ScriptType::Multisig { required: m, keys };
            }
        }

        // Nulldata: OP_RETURN with a push-only tail (Solver does not
        // apply the 83-byte datacarrier cap — that's IsStandard).
        if bytes[0] == OP_RETURN {
            let tail_push_only = Script::new(bytes[1..].to_vec())
                .instructions()
                .all(|i| matches!(i, Ok(Instruction::Push(_))));
            if tail_push_only {
                return ScriptType::NullData;
            }
        }

        ScriptType::Nonstandard
    }
}

// ---------------------------------------------------------------------------
// Script encodings (BIP34's expected coinbase prefix)
// ---------------------------------------------------------------------------

/// Serializes an integer the way `CScriptNum::getvch` / `CScript::operator<<` do:
/// little-endian, sign-magnitude, minimally sized (zero is the empty string, and a
/// result whose top byte has bit `0x80` set gains a `0x00`/`0x80` sign byte).
#[must_use]
pub fn encode_script_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let negative = value < 0;
    // unsigned_abs avoids overflow on i64::MIN.
    let mut magnitude = value.unsigned_abs();
    let mut bytes = Vec::with_capacity(9);
    while magnitude > 0 {
        bytes.push((magnitude & 0xff) as u8);
        magnitude >>= 8;
    }
    if bytes.last().is_some_and(|top| top & 0x80 != 0) {
        bytes.push(if negative { 0x80 } else { 0 });
    } else if negative && let Some(top) = bytes.last_mut() {
        *top |= 0x80;
    }
    bytes
}

/// Encodes the canonical push of `data` (Core's `CScript::operator<<(vector)`): `OP_0`
/// for empty data, a direct length byte for up to 75 bytes, then `OP_PUSHDATA1/2/4`.
#[must_use]
pub fn push_slice(data: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(data.len() + 5);
    match data.len() {
        0 => script.push(OP_0),
        len if len <= usize::from(MAX_DIRECT_PUSH) => script.push(len as u8),
        len if len <= 0xff => {
            script.push(OP_PUSHDATA1);
            script.push(len as u8);
        }
        len if len <= 0xffff => {
            script.push(OP_PUSHDATA2);
            script.extend_from_slice(&(len as u16).to_le_bytes());
        }
        len => {
            script.push(OP_PUSHDATA4);
            script.extend_from_slice(&(len as u32).to_le_bytes());
        }
    }
    script.extend_from_slice(data);
    script
}

/// Encodes `CScript() << value` exactly — Core's `push_int64`: `OP_1NEGATE`,
/// `OP_0`, or `OP_1..=OP_16` for -1..=16, otherwise the script number pushed as
/// data. BIP34's expected coinbase prefix is `push_int(height)`, so the small
/// heights that dominate early post-activation blocks are `OP_N` bytes, not
/// raw data pushes.
#[must_use]
pub fn push_int(value: i64) -> Vec<u8> {
    match value {
        -1 => vec![OP_1NEGATE],
        0 => vec![OP_0],
        1..=16 => vec![OP_1 - 1 + value as u8],
        _ => push_slice(&encode_script_num(value)),
    }
}

/// Core `script/script.h`'s `MAX_SCRIPT_SIZE`: the longest script byte string the
/// interpreter accepts — also an [`Script::is_unspendable`] trigger.
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// Witness program sizes from `script/interpreter.h`: a version-0 program of
/// [`WITNESS_V0_KEYHASH_SIZE`] bytes is P2WPKH (1 sigop); one of
/// [`WITNESS_V0_SCRIPTHASH_SIZE`] bytes is P2WSH (sigops counted from the last
/// witness item).
pub const WITNESS_V0_KEYHASH_SIZE: usize = 20;
/// See [`WITNESS_V0_KEYHASH_SIZE`].
pub const WITNESS_V0_SCRIPTHASH_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Script verification flags (script/interpreter.h) and per-block flag selection
// ---------------------------------------------------------------------------

/// The subset of Core's `script_verification_flags` consensus validation consults.
/// Bit values are identical to `script/interpreter.h` so
/// [`Params::script_flag_exceptions`] can carry raw Core flag words.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ScriptFlags(u32);

impl ScriptFlags {
    /// `SCRIPT_VERIFY_NONE`.
    pub const NONE: Self = Self(0);
    /// `SCRIPT_VERIFY_P2SH` (1 << 0).
    pub const P2SH: Self = Self(1 << 0);
    /// `SCRIPT_VERIFY_STRICTENC` (1 << 1).
    pub const STRICTENC: Self = Self(1 << 1);
    /// `SCRIPT_VERIFY_DERSIG` (1 << 2) — BIP66 strict DER signatures.
    pub const DERSIG: Self = Self(1 << 2);
    /// `SCRIPT_VERIFY_LOW_S` (1 << 3).
    pub const LOW_S: Self = Self(1 << 3);
    /// `SCRIPT_VERIFY_NULLDUMMY` (1 << 4) — BIP147, activated with segwit.
    pub const NULLDUMMY: Self = Self(1 << 4);
    /// `SCRIPT_VERIFY_SIGPUSHONLY` (1 << 5).
    pub const SIGPUSHONLY: Self = Self(1 << 5);
    /// `SCRIPT_VERIFY_MINIMALDATA` (1 << 6) — BIP62 minimal pushes.
    pub const MINIMALDATA: Self = Self(1 << 6);
    /// `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS` (1 << 7).
    pub const DISCOURAGE_UPGRADABLE_NOPS: Self = Self(1 << 7);
    /// `SCRIPT_VERIFY_CLEANSTACK` (1 << 8) — BIP62; implies [`P2SH`](Self::P2SH)
    /// and [`WITNESS`](Self::WITNESS) per Core's asserts.
    pub const CLEANSTACK: Self = Self(1 << 8);
    /// `SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY` (1 << 9) — BIP65.
    pub const CHECKLOCKTIMEVERIFY: Self = Self(1 << 9);
    /// `SCRIPT_VERIFY_CHECKSEQUENCEVERIFY` (1 << 10) — BIP112, activated with
    /// BIP68/113 as the CSV deployment.
    pub const CHECKSEQUENCEVERIFY: Self = Self(1 << 10);
    /// `SCRIPT_VERIFY_WITNESS` (1 << 11) — BIP141.
    pub const WITNESS: Self = Self(1 << 11);
    /// `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` (1 << 12).
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: Self = Self(1 << 12);
    /// `SCRIPT_VERIFY_MINIMALIF` (1 << 13) — BIP62; consensus-enforced in tapscript.
    pub const MINIMALIF: Self = Self(1 << 13);
    /// `SCRIPT_VERIFY_NULLFAIL` (1 << 14) — BIP146.
    pub const NULLFAIL: Self = Self(1 << 14);
    /// `SCRIPT_VERIFY_WITNESS_PUBKEYTYPE` (1 << 15).
    pub const WITNESS_PUBKEYTYPE: Self = Self(1 << 15);
    /// `SCRIPT_VERIFY_CONST_SCRIPTCODE` (1 << 16).
    pub const CONST_SCRIPTCODE: Self = Self(1 << 16);
    /// `SCRIPT_VERIFY_TAPROOT` (1 << 17) — BIP341/342.
    pub const TAPROOT: Self = Self(1 << 17);
    /// `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION` (1 << 18).
    pub const DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: Self = Self(1 << 18);
    /// `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS` (1 << 19) — BIP342 OP_SUCCESSx.
    pub const DISCOURAGE_OP_SUCCESS: Self = Self(1 << 19);
    /// `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE` (1 << 20).
    pub const DISCOURAGE_UPGRADABLE_PUBKEYTYPE: Self = Self(1 << 20);

    /// Returns `true` if every bit in `other` is set in `self` (Core's
    /// `flags & SCRIPT_VERIFY_X` idiom for single-bit queries).
    #[must_use]
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union of two flag sets (`flags |= X` in Core).
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The raw `script/interpreter.h` flag word (for comparisons against Core
    /// constants and [`Params::script_flag_exceptions`]).
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Wraps a raw flag word. Unknown bits are preserved, matching Core's
    /// `uint32_t flags` (a future soft fork's flag is just another bit).
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
}

/// The script-verification flags governing `block` — Core's `GetBlockScriptFlags`.
///
/// `P2SH | WITNESS | TAPROOT` are always on (they only *restrict* what executes
/// validly, and the two historical violations are handled by
/// [`Params::script_flag_exceptions`], which replaces the base set); the buried
/// deployments then OR in `DERSIG` (BIP66), `CHECKLOCKTIMEVERIFY` (BIP65),
/// `CHECKSEQUENCEVERIFY` (CSV), and `NULLDUMMY` (segwit) at their heights.
#[must_use]
pub fn block_script_flags(params: &Params, height: u32, block_hash: &BlockHash) -> ScriptFlags {
    let mut flags = ScriptFlags::P2SH
        .union(ScriptFlags::WITNESS)
        .union(ScriptFlags::TAPROOT);
    if let Some(&(_, exception)) = params
        .script_flag_exceptions
        .iter()
        .find(|(hash, _)| hash == block_hash)
    {
        flags = ScriptFlags::from_bits(exception);
    }
    if height >= params.bip66_height {
        flags = flags.union(ScriptFlags::DERSIG);
    }
    if height >= params.bip65_height {
        flags = flags.union(ScriptFlags::CHECKLOCKTIMEVERIFY);
    }
    if height >= params.csv_height {
        flags = flags.union(ScriptFlags::CHECKSEQUENCEVERIFY);
    }
    if height >= params.segwit_height {
        flags = flags.union(ScriptFlags::NULLDUMMY);
    }
    flags
}

// ---------------------------------------------------------------------------
// UTXO-dependent sigop counting (ConnectBlock's GetTransactionSigOpCost inputs)
// ---------------------------------------------------------------------------

/// Core's `WitnessSigOps`: the witness sigop count for a witness program.
///
/// Version 0: a 20-byte program (P2WPKH) costs 1; a 32-byte program (P2WSH)
/// costs the accurate sigop count of the last witness item — `0` for an empty
/// witness (the item never deserializes to a script). Every other version and
/// size costs 0.
#[must_use]
fn witness_sig_ops(version: u8, program: &[u8], witness: &Witness) -> u64 {
    if version != 0 {
        return 0;
    }
    if program.len() == WITNESS_V0_KEYHASH_SIZE {
        return 1;
    }
    if program.len() == WITNESS_V0_SCRIPTHASH_SIZE
        && let Some(last) = witness.items().last()
    {
        return Script::new(last.clone()).sig_ops(true);
    }
    0
}

/// Core's `CountWitnessSigOps`: sigops attributable to witness data for one
/// spent input. `0` when `flags` lacks [`ScriptFlags::WITNESS`]; otherwise the
/// spent `script_pubkey`'s direct witness program counts, or — for a P2SH
/// output spent by a push-only `script_sig` — the witness program inside the
/// redeem script (nested segwit).
///
/// The caller must only reach this when `flags` also has [`ScriptFlags::P2SH`]
/// set (Core `assert`s it inside `CountWitnessSigOps`).
#[must_use]
pub fn count_witness_sig_ops(
    script_sig: &Script,
    script_pubkey: &Script,
    witness: &Witness,
    flags: ScriptFlags,
) -> u64 {
    debug_assert!(flags.contains(ScriptFlags::P2SH));
    if !flags.contains(ScriptFlags::WITNESS) {
        return 0;
    }
    if let Some((version, program)) = script_pubkey.witness_program() {
        return witness_sig_ops(version, program, witness);
    }
    if script_pubkey.is_p2sh() && script_sig.is_push_only() {
        let data = trailing_push_data(script_sig);
        if let Some((version, program)) = Script::new(data.to_vec()).witness_program() {
            return witness_sig_ops(version, program, witness);
        }
    }
    0
}

/// The value left in `vData` by Core's `while (pc < end) GetOp(pc, opcode, data)`
/// extraction loop in `CountWitnessSigOps` and `CScript::GetSigOpCount(scriptSig)`.
///
/// `GetScriptOp` clears `vchRet` at the top of every call, so the result is the
/// bytes pushed by the *final* instruction iff it decodes as a push — a trailing
/// opcode (including `OP_N`) or a failed push leaves it empty. `GetOp` failures
/// do not stop the walk: the cursor has already advanced past the opcode byte
/// (and, for `PUSHDATA*`, any length bytes that were present), so parsing resumes
/// mid-script — the tail bytes are reinterpreted as further instructions.
fn trailing_push_data(script_sig: &Script) -> &[u8] {
    let bytes = script_sig.as_bytes();
    let mut pc = 0usize;
    let mut data: &[u8] = &[];
    while let Some(&opcode) = bytes.get(pc) {
        pc += 1;
        data = &[];
        if opcode <= OP_PUSHDATA4 {
            let len = match opcode {
                op if op < OP_PUSHDATA1 => usize::from(op),
                OP_PUSHDATA1 => match bytes.get(pc) {
                    Some(&b) => {
                        pc += 1;
                        usize::from(b)
                    }
                    None => continue,
                },
                OP_PUSHDATA2 => match bytes.get(pc..pc + 2) {
                    Some(b) => {
                        pc += 2;
                        usize::from(u16::from_le_bytes([b[0], b[1]]))
                    }
                    None => continue,
                },
                _ => match bytes.get(pc..pc + 4) {
                    Some(b) => {
                        pc += 4;
                        u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
                    }
                    None => continue,
                },
            };
            if bytes.len() - pc < len {
                continue;
            }
            data = &bytes[pc..pc + len];
            pc += len;
        }
    }
    data
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn script(bytes: &[u8]) -> Script {
        Script::new(bytes.to_vec())
    }

    #[test]
    fn instructions_decode_pushes_and_ops() {
        // OP_1 <data "ab"> OP_CHECKSIG
        let s = script(&[0x51, 0x02, b'a', b'b', OP_CHECKSIG]);
        let instrs: Vec<_> = s.instructions().collect::<Result<_, _>>().unwrap();
        assert_eq!(
            instrs,
            [
                Instruction::Op(0x51),
                Instruction::Push(b"ab"),
                Instruction::Op(OP_CHECKSIG),
            ]
        );
    }

    #[test]
    fn instructions_decode_pushdata_widths() {
        let mut bytes = vec![OP_PUSHDATA1, 0x03, 1, 2, 3];
        bytes.extend_from_slice(&[OP_PUSHDATA2, 0x04, 0x00, 9, 8, 7, 6]);
        let s = script(&bytes);
        let instrs: Vec<_> = s.instructions().collect::<Result<_, _>>().unwrap();
        assert_eq!(instrs[0], Instruction::Push(&[1, 2, 3]));
        assert_eq!(instrs[1], Instruction::Push(&[9, 8, 7, 6]));
    }

    #[test]
    fn instructions_report_truncated_push_once() {
        // Declares a 5-byte push with only 2 bytes present.
        let s = script(&[0x05, 1, 2]);
        let mut it = s.instructions();
        assert_eq!(it.next(), Some(Err(MalformedScript { position: 0 })));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn instructions_report_truncated_pushdata_length() {
        // PUSHDATA2 without its length bytes.
        let s = script(&[OP_PUSHDATA2, 0x01]);
        let mut it = s.instructions();
        assert_eq!(it.next(), Some(Err(MalformedScript { position: 0 })));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn op0_pushes_empty_data() {
        let s = script(&[OP_0]);
        let instrs: Vec<_> = s.instructions().collect::<Result<_, _>>().unwrap();
        assert_eq!(instrs, [Instruction::Push(b"")]);
    }

    #[test]
    fn sig_ops_matches_core_counting() {
        // CHECKSIG + CHECKSIGVERIFY + bare MULTISIG (non-accurate → 20).
        let s = script(&[OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG]);
        assert_eq!(s.sig_ops(false), 22);
        assert_eq!(s.sig_ops(true), 22);
        // 2-of-n multisig: accurate → 2, inaccurate → 20.
        let m = script(&[OP_1 + 1, OP_CHECKMULTISIG]);
        assert_eq!(m.sig_ops(true), 2);
        assert_eq!(m.sig_ops(false), 20);
        // A push before MULTISIG is not a small-integer opcode.
        let p = script(&[0x01, 0x51, OP_CHECKMULTISIG]);
        assert_eq!(p.sig_ops(true), 20);
        // A truncated push stops iteration mid-script, like Core's break on GetOp.
        let t = script(&[OP_CHECKSIG, 0x05, 0xaa]);
        assert_eq!(t.sig_ops(true), 1);
    }

    #[test]
    fn is_push_only_boundaries() {
        assert!(script(&[0x02, 1, 2, OP_1, OP_1NEGATE, OP_RESERVED, OP_16]).is_push_only());
        assert!(!script(&[0x02, 1, 2, OP_CHECKSIG]).is_push_only());
        assert!(!script(&[0x02, 1]).is_push_only()); // truncated
        assert!(script(&[]).is_push_only());
    }

    #[test]
    fn last_pushed_data_extracts_redeem_script() {
        let s = script(&[0x01, 0xaa, 0x03, 0xbb, 0xcc, 0xdd]);
        assert_eq!(s.last_pushed_data(), Some(&[0xbb, 0xcc, 0xdd][..]));
        // Non-push opcode → not usable.
        assert_eq!(script(&[0x01, 0xaa, OP_CHECKSIG]).last_pushed_data(), None);
        // Empty / pushless-but-push-only → empty data, like Core's default vData.
        assert_eq!(script(&[]).last_pushed_data(), Some(&[][..]));
        assert_eq!(script(&[OP_1]).last_pushed_data(), Some(&[][..]));
        // Truncated → None.
        assert_eq!(script(&[0x05, 1]).last_pushed_data(), None);
    }

    #[test]
    fn p2sh_and_witness_patterns() {
        // P2SH: OP_HASH160 <20 zeros> OP_EQUAL.
        let mut p2sh = vec![OP_HASH160, 0x14];
        p2sh.extend_from_slice(&[0u8; 20]);
        p2sh.push(OP_EQUAL);
        assert!(script(&p2sh).is_p2sh());
        assert!(!script(&p2sh[..22]).is_p2sh());

        // P2WPKH and P2WSH programs.
        let mut p2wpkh = vec![OP_0, 0x14];
        p2wpkh.extend_from_slice(&[0u8; 20]);
        let mut p2wsh = vec![OP_0, 0x20];
        p2wsh.extend_from_slice(&[0u8; 32]);
        assert!(script(&p2wsh).is_p2wsh());
        assert_eq!(
            script(&p2wpkh).witness_program(),
            Some((0, &p2wpkh[2..][..]))
        );
        assert_eq!(script(&p2wsh).witness_program(), Some((0, &p2wsh[2..][..])));

        // P2TR: v1 + 32-byte program.
        let mut p2tr = vec![OP_1, 0x20];
        p2tr.extend_from_slice(&[0u8; 32]);
        assert_eq!(script(&p2tr).witness_program(), Some((1, &p2tr[2..][..])));

        // Not programs: too short/long, bad version op, PUSHDATA-encoded push.
        assert_eq!(script(&[OP_0, 0x01, 0xaa]).witness_program(), None); // 3 bytes
        let mut long = vec![OP_0, 0x28];
        long.extend_from_slice(&[0u8; 41]); // len 43 > 42
        assert_eq!(script(&long).witness_program(), None);
        assert_eq!(script(&[0x61, 0x02, 1, 2]).witness_program(), None); // OP_NOP
        let mut pd = vec![OP_0, OP_PUSHDATA1, 0x02, 1, 2];
        assert_eq!(script(&pd).witness_program(), None);
        pd.clear();
    }

    #[test]
    fn script_num_encoding_matches_core() {
        // From Core's scriptnum_tests vectors.
        assert_eq!(encode_script_num(0), Vec::<u8>::new());
        assert_eq!(encode_script_num(1), vec![0x01]);
        assert_eq!(encode_script_num(-1), vec![0x81]);
        assert_eq!(encode_script_num(127), vec![0x7f]);
        assert_eq!(encode_script_num(128), vec![0x80, 0x00]);
        assert_eq!(encode_script_num(-128), vec![0x80, 0x80]);
        assert_eq!(encode_script_num(255), vec![0xff, 0x00]);
        assert_eq!(encode_script_num(32_767), vec![0xff, 0x7f]);
        assert_eq!(encode_script_num(32_768), vec![0x00, 0x80, 0x00]);
        assert_eq!(encode_script_num(-32_768), vec![0x00, 0x80, 0x80]);
    }

    #[test]
    fn push_encodings_match_core() {
        assert_eq!(push_slice(&[]), vec![OP_0]);
        assert_eq!(push_slice(&[0xaa]), vec![0x01, 0xaa]);
        assert_eq!(push_slice(&[0u8; 75])[0], 75);
        assert_eq!(push_slice(&[0u8; 76])[..2], [OP_PUSHDATA1, 76]);
        assert_eq!(push_slice(&[0u8; 256])[..3], [OP_PUSHDATA2, 0x00, 0x01]);
        // BIP34: CScript() << height — height 227931 = 0x37A5B → scriptnum 5b 7a 03
        // → push 03 5b 7a 03.
        assert_eq!(push_int(227_931), vec![0x03, 0x5b, 0x7a, 0x03]);
        // CScript::push_int64 uses the OP_N opcodes for -1..=16, not raw pushes —
        // the differential adapter caught this against a live daemon.
        assert_eq!(push_int(-1), vec![OP_1NEGATE]);
        assert_eq!(push_int(0), vec![OP_0]);
        assert_eq!(push_int(1), vec![OP_1]);
        assert_eq!(push_int(16), vec![OP_16]);
        assert_eq!(push_int(17), vec![0x01, 0x11]);
        assert_eq!(push_int(-2), vec![0x01, 0x82]);
    }

    /// `asm_sighash` — `ScriptToAsmStr`'s `fAttemptSighashDecode`: a
    /// strict-DER push whose last byte is a defined hashtype renders
    /// without that byte plus a `[HASHTYPE]` suffix; anything else
    /// stays plain hex. The suffix never fires on `asm()`.
    #[test]
    fn asm_sighash_annotates_der_pushes() {
        // A real DER signature ending in SIGHASH_ALL (0x01).
        let mut sig = vec![
            0x30, 0x44, 0x02, 0x20, // DER: seq len 68, int len 32
        ];
        sig.extend_from_slice(&[0x11; 32]); // R
        sig.extend_from_slice(&[0x02, 0x20]);
        sig.extend_from_slice(&[0x22; 32]); // S
        sig.push(0x01); // SIGHASH_ALL
        let mut bytes = push_slice(&sig);
        bytes.extend_from_slice(&push_slice(&[0x33; 33])); // pubkey push
        let s = script(&bytes);

        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            s.asm_sighash(),
            format!("{}[ALL] {}", hex(&sig[..sig.len() - 1]), hex(&[0x33; 33]))
        );
        // Plain asm() never decodes the hashtype.
        assert_eq!(s.asm(), format!("{} {}", hex(&sig), hex(&[0x33; 33])));

        // A signature whose last byte is NOT a defined hashtype
        // (0x00) stays plain hex even in sighash mode.
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() = 0x00;
        let s = script(&push_slice(&bad));
        assert_eq!(s.asm_sighash(), hex(&bad));
        // Same for SIGHASH_SINGLE|ANYONECANPAY (0x83).
        *bad.last_mut().unwrap() = 0x83;
        let s = script(&push_slice(&bad));
        assert_eq!(
            s.asm_sighash(),
            format!("{}[SINGLE|ANYONECANPAY]", hex(&bad[..bad.len() - 1]))
        );
    }
}

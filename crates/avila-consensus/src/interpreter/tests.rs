//! `interpreter.rs` tests — behavior locked against Core's `script_tests`
//! semantics. A stub [`SignatureChecker`] stands in for the real sighash/curve
//! layer (ported separately in `crate::sigchecker`).

use super::*;

/// A [`SignatureChecker`] whose verdicts are configured per test.
#[derive(Clone, Default)]
struct StubChecker {
    ecdsa: bool,
    locktime: bool,
    sequence: bool,
    taproot_commitment: bool,
}

impl SignatureChecker for StubChecker {
    fn check_ecdsa_signature(
        &self,
        _sig: &[u8],
        _pubkey: &[u8],
        _script_code: &[u8],
        _sigversion: SigVersion,
    ) -> bool {
        self.ecdsa
    }
    fn check_locktime(&self, _n: i64) -> bool {
        self.locktime
    }
    fn check_sequence(&self, _n: i64) -> bool {
        self.sequence
    }
    fn verify_taproot_commitment(
        &self,
        _control: &[u8],
        _program: &[u8],
        _tapleaf_hash: &[u8; 32],
    ) -> bool {
        self.taproot_commitment
    }
}

fn script(bytes: &[u8]) -> Script {
    Script::new(bytes.to_vec())
}

/// Evaluates `script` with no flags and the all-false stub checker.
fn eval(script: &Script) -> Result<Vec<Vec<u8>>, ScriptError> {
    eval_with(script, ScriptFlags::NONE, &StubChecker::default())
}

fn eval_with(
    script: &Script,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<Vec<Vec<u8>>, ScriptError> {
    let mut stack = Vec::new();
    eval_script_simple(&mut stack, script, flags, checker, SigVersion::Base).map(|()| stack)
}

// ---------------------------------------------------------------------------
// Helpers: cast_to_bool, script_num, check_minimal_push, is_op_success
// ---------------------------------------------------------------------------

#[test]
fn cast_to_bool_matches_core() {
    assert!(!cast_to_bool(&[]));
    assert!(!cast_to_bool(&[0]));
    assert!(!cast_to_bool(&[0, 0, 0]));
    assert!(!cast_to_bool(&[0x80])); // negative zero
    assert!(!cast_to_bool(&[0, 0, 0x80])); // multi-byte negative zero
    assert!(cast_to_bool(&[1]));
    assert!(cast_to_bool(&[0x81])); // -1
    assert!(cast_to_bool(&[0x80, 0x00])); // 128 — last byte is 0, not neg-zero
}

#[test]
fn script_num_decoding_and_minimality() {
    assert_eq!(script_num(&[], false, 4), Ok(0));
    assert_eq!(script_num(&[0x01], false, 4), Ok(1));
    assert_eq!(script_num(&[0x81], false, 4), Ok(-1));
    assert_eq!(script_num(&[0x7f], false, 4), Ok(127));
    assert_eq!(script_num(&[0x80, 0x00], false, 4), Ok(128));
    assert_eq!(script_num(&[0x80, 0x80], false, 4), Ok(-128));
    assert_eq!(script_num(&[0x80], false, 4), Ok(0)); // negative zero decodes as 0
    // 4-byte overflow → scriptnum_error → UnknownError.
    assert_eq!(
        script_num(&[0xff, 0xff, 0xff, 0xff, 0x7f], false, 4),
        Err(ScriptError::UnknownError)
    );
    // ...but the same operand is legal with the CLTV/CSV 5-byte limit.
    assert_eq!(
        script_num(&[0xff, 0xff, 0xff, 0xff, 0x7f], false, 5),
        Ok(0x7f_ffff_ffff)
    );
    // Non-minimal encodings rejected under MINIMALDATA.
    assert_eq!(
        script_num(&[0x01, 0x00], true, 4),
        Err(ScriptError::UnknownError)
    );
    assert_eq!(script_num(&[0x01, 0x00], false, 4), Ok(1)); // allowed when not required
    assert_eq!(script_num(&[0x80], true, 4), Err(ScriptError::UnknownError));
}

#[test]
fn minimal_push_rules() {
    assert!(check_minimal_push(&[], OP_0));
    assert!(!check_minimal_push(&[], 0x01));
    assert!(!check_minimal_push(&[1], 0x01)); // 1 must be OP_1
    assert!(!check_minimal_push(&[16], 0x01)); // 16 must be OP_16
    assert!(!check_minimal_push(&[0x81], 0x01)); // -1 must be OP_1NEGATE
    assert!(check_minimal_push(&[0xaa], 0x01));
    assert!(check_minimal_push(&[0u8; 75], 75));
    // 76 bytes can't be a direct push (max 75); PUSHDATA1 is required and
    // opcode 76 IS OP_PUSHDATA1 — the over-wide encoding is PUSHDATA2.
    assert!(!check_minimal_push(&[0u8; 76], OP_PUSHDATA2));
    assert!(check_minimal_push(&[0u8; 76], OP_PUSHDATA1));
    assert!(!check_minimal_push(&[0u8; 256], OP_PUSHDATA1));
    assert!(check_minimal_push(&[0u8; 256], OP_PUSHDATA2));
}

#[test]
fn op_success_opcode_set() {
    for op in [80u8, 98, 126, 129, 131, 134, 137, 141, 149, 153, 187, 254] {
        assert!(is_op_success(op), "opcode {op}");
    }
    for op in [0u8, 97, 99, 125, 130, 135, 139, 143, 148, 154, 186, 255] {
        assert!(!is_op_success(op), "opcode {op}");
    }
}

#[test]
fn find_and_delete_semantics() {
    // Removes the pushed-signature byte string at instruction boundaries.
    let mut s = vec![0x02, 0xaa, 0xbb, OP_CHECKSIG];
    assert_eq!(find_and_delete(&mut s, &push_slice(&[0xaa, 0xbb])), 1);
    assert_eq!(s, vec![OP_CHECKSIG]);
    // Bytes inside a larger push's data are not instruction-boundary matches.
    let mut s = vec![0x04, 0x02, 0xaa, 0xbb, 0xcc, OP_CHECKSIG];
    assert_eq!(find_and_delete(&mut s, &push_slice(&[0xaa, 0xbb])), 0);
    // Empty needle → no-op.
    let mut s = vec![0x51];
    assert_eq!(find_and_delete(&mut s, &[]), 0);
}

// ---------------------------------------------------------------------------
// Signature encoding checks
// ---------------------------------------------------------------------------

/// A canonical 71-byte DER signature + sighash byte (R=S=32 bytes, low-S).
fn good_der_sig() -> Vec<u8> {
    let mut s = vec![0x30, 68, 0x02, 32];
    s.extend_from_slice(&[0x01; 32]); // R
    s.extend_from_slice(&[0x02, 32]);
    s.extend_from_slice(&[0x01; 32]); // S (small → low)
    s.push(0x01); // SIGHASH_ALL
    s
}

#[test]
fn der_encoding_checks() {
    assert!(is_valid_signature_encoding(&good_der_sig()));
    // Too short / long.
    assert!(!is_valid_signature_encoding(&[0x30; 8]));
    assert!(!is_valid_signature_encoding(&[0x30; 74]));
    // Wrong compound tag.
    let mut bad = good_der_sig();
    bad[0] = 0x31;
    assert!(!is_valid_signature_encoding(&bad));
    // Length mismatch.
    let mut bad = good_der_sig();
    bad[1] = 67;
    assert!(!is_valid_signature_encoding(&bad));
    // Negative R (high bit set).
    let mut bad = good_der_sig();
    bad[4] = 0x80;
    assert!(!is_valid_signature_encoding(&bad));
    // Excessively padded R.
    let mut padded = good_der_sig();
    padded[3] = 33;
    padded.insert(4, 0x00);
    padded[1] = 69;
    // 0x00 followed by 0x01 (no high bit) → non-minimal.
    assert!(!is_valid_signature_encoding(&padded));
}

#[test]
fn signature_encoding_flags() {
    let flags = ScriptFlags::DERSIG;
    assert_eq!(check_signature_encoding(&good_der_sig(), flags), Ok(()));
    assert_eq!(
        check_signature_encoding(&[0x30, 0x00, 0x01], flags),
        Err(ScriptError::SigDer)
    );
    // Empty sig is always fine.
    assert_eq!(check_signature_encoding(&[], flags), Ok(()));
    // Undefined hashtype under STRICTENC.
    let mut sig = good_der_sig();
    *sig.last_mut().unwrap() = 0x04;
    let strict = ScriptFlags::STRICTENC.union(ScriptFlags::DERSIG);
    assert_eq!(
        check_signature_encoding(&sig, strict),
        Err(ScriptError::SigHashType)
    );
    // ANYONECANPAY | SINGLE is defined.
    let mut sig = good_der_sig();
    *sig.last_mut().unwrap() = 0x83;
    assert_eq!(check_signature_encoding(&sig, strict), Ok(()));
    // High-S rejected under LOW_S. S = n/2 + 1 is a genuine high-S inside
    // (n/2, n): 32 bytes, top byte 0x7f — positive without padding.
    // (S = 0x00ff..ff would be ≥ n and hit the scalar-overflow quirk instead.)
    let mut high_s = SECP256K1_HALF_ORDER;
    high_s[31] += 1;
    let mut sig = vec![0x30, 68, 0x02, 32];
    sig.extend_from_slice(&[0x01; 32]);
    sig.extend_from_slice(&[0x02, 32]);
    sig.extend_from_slice(&high_s);
    sig.push(0x01);
    assert!(is_valid_signature_encoding(&sig));
    let low_s = ScriptFlags::LOW_S.union(ScriptFlags::DERSIG);
    assert_eq!(
        check_signature_encoding(&sig, low_s),
        Err(ScriptError::SigHighS)
    );
    // S >= n reads as "low" via the libsecp256k1 scalar-overflow quirk:
    // parse_der zeroes an overflowing scalar, which is already normalized.
    let mut sig = vec![0x30, 69, 0x02, 32];
    sig.extend_from_slice(&[0x01; 32]);
    sig.extend_from_slice(&[0x02, 33, 0x00]);
    sig.extend_from_slice(&SECP256K1_ORDER); // S = n exactly
    sig.push(0x01);
    assert_eq!(check_signature_encoding(&sig, low_s), Ok(()));
}

// ---------------------------------------------------------------------------
// eval_script — core semantics
// ---------------------------------------------------------------------------

#[test]
fn push_and_small_integers() {
    // OP_1 OP_2 OP_ADD → 3
    let s = script(&[OP_1, OP_1 + 1, OP_ADD]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(3)]));
    // OP_1NEGATE → -1 = 0x81
    let s = script(&[OP_1NEGATE]);
    assert_eq!(eval(&s), Ok(vec![vec![0x81]]));
    // OP_0 → empty
    let s = script(&[OP_0]);
    assert_eq!(eval(&s), Ok(vec![Vec::new()]));
    // OP_16 → 16
    let s = script(&[OP_16]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(16)]));
}

#[test]
fn numeric_ops() {
    // 7 3 OP_SUB → 4; OP_1ADD/OP_1SUB; ABS/NEGATE/NOT/0NOTEQUAL.
    let s = script(&[0x01, 7, 0x01, 3, OP_SUB]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(4)]));
    let s = script(&[OP_1, OP_1ADD]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(2)]));
    let s = script(&[OP_1, OP_1SUB]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(0)]));
    let s = script(&[OP_1NEGATE, OP_ABS]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(1)]));
    let s = script(&[OP_1, OP_NEGATE]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(-1)]));
    let s = script(&[OP_0, OP_NOT]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(1)]));
    let s = script(&[OP_1, OP_0NOTEQUAL]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(1)]));
    // Comparisons.
    let s = script(&[OP_1, OP_1, OP_NUMEQUAL]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(1)]));
    let s = script(&[OP_1, OP_1 + 1, OP_LESSTHAN]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(1)]));
    let s = script(&[OP_1, OP_1 + 1, OP_GREATERTHAN]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(0)]));
    let s = script(&[OP_1 + 1, OP_1, OP_MIN]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(1)]));
    let s = script(&[OP_1 + 1, OP_1, OP_MAX]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(2)]));
    // WITHIN: x min max.
    let s = script(&[OP_1 + 1, OP_1, OP_1 + 2, OP_WITHIN]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(1)]));
    let s = script(&[OP_1 + 2, OP_1, OP_1 + 2, OP_WITHIN]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(0)]));
    // NUMEQUALVERIFY success/failure.
    let s = script(&[OP_1, OP_1, OP_NUMEQUALVERIFY, OP_1 + 4]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(5)]));
    let s = script(&[OP_1, OP_1 + 1, OP_NUMEQUALVERIFY]);
    assert_eq!(eval(&s), Err(ScriptError::NumEqualVerify));
}

#[test]
fn stack_ops() {
    // depth: two items on the stack → OP_DEPTH pushes 2.
    let s = script(&[OP_1, OP_1 + 1, OP_DEPTH]);
    assert_eq!(
        eval(&s),
        Ok(vec![
            encode_script_num(1),
            encode_script_num(2),
            encode_script_num(2)
        ])
    );
    // dup/swap/drop/nip/over/tuck/rot/2dup/3dup/2over/2swap/2rot/2drop/ifdup/pick/roll.
    let s = script(&[OP_1, OP_1 + 1, OP_DUP, OP_ADD]); // 1 2 2 → add → 1 4
    assert_eq!(
        eval(&s),
        Ok(vec![encode_script_num(1), encode_script_num(4)])
    );
    let s = script(&[OP_1, OP_1 + 1, OP_SWAP]); // 1 2 → 2 1
    assert_eq!(
        eval(&s),
        Ok(vec![encode_script_num(2), encode_script_num(1)])
    );
    let s = script(&[OP_1, OP_1 + 1, OP_1 + 2, OP_ROT]); // 1 2 3 → 2 3 1
    assert_eq!(
        eval(&s),
        Ok(vec![
            encode_script_num(2),
            encode_script_num(3),
            encode_script_num(1)
        ])
    );
    let s = script(&[OP_1, OP_1 + 1, OP_NIP]); // 1 2 → 2
    assert_eq!(eval(&s), Ok(vec![encode_script_num(2)]));
    let s = script(&[OP_1, OP_1 + 1, OP_OVER]); // 1 2 → 1 2 1
    assert_eq!(
        eval(&s),
        Ok(vec![
            encode_script_num(1),
            encode_script_num(2),
            encode_script_num(1)
        ])
    );
    let s = script(&[OP_1, OP_1 + 1, OP_TUCK]); // 1 2 → 2 1 2
    assert_eq!(
        eval(&s),
        Ok(vec![
            encode_script_num(2),
            encode_script_num(1),
            encode_script_num(2)
        ])
    );
    let s = script(&[OP_1, OP_1 + 1, OP_2DUP, OP_ADD, OP_ADD]); // 1 2 1 2 → 1 2 3 → 1 5? no: 1 2 +1 2 → 1 2 3? let me recompute: 1 2 2DUP → 1 2 1 2; ADD → 1 2 3; ADD → 1 5
    assert_eq!(
        eval(&s),
        Ok(vec![encode_script_num(1), encode_script_num(5)])
    );
    // 1 2 3 3DUP → 1 2 3 1 2 3; 2DROP 2DROP DROP → 1.
    let s = script(&[
        OP_1,
        OP_1 + 1,
        OP_1 + 2,
        OP_3DUP,
        OP_2DROP,
        OP_2DROP,
        OP_DROP,
    ]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(1)]));
    // IFDUP duplicates only when true.
    let s = script(&[OP_1, OP_IFDUP]);
    assert_eq!(
        eval(&s),
        Ok(vec![encode_script_num(1), encode_script_num(1)])
    );
    let s = script(&[OP_0, OP_IFDUP]);
    assert_eq!(eval(&s), Ok(vec![Vec::new()]));
    // PICK/ROLL: n counts from the top (x0); n=2 selects x2 = the bottom item.
    let s = script(&[OP_1, OP_1 + 1, OP_1 + 2, OP_1 + 1, OP_PICK]); // → 1 2 3 1
    assert_eq!(
        eval(&s),
        Ok(vec![
            encode_script_num(1),
            encode_script_num(2),
            encode_script_num(3),
            encode_script_num(1)
        ])
    );
    let s = script(&[OP_1, OP_1 + 1, OP_1 + 2, OP_1 + 1, OP_ROLL]); // → 2 3 1
    assert_eq!(
        eval(&s),
        Ok(vec![
            encode_script_num(2),
            encode_script_num(3),
            encode_script_num(1)
        ])
    );
    // Altstack round-trip.
    let s = script(&[OP_1, OP_TOALTSTACK, OP_1 + 1, OP_FROMALTSTACK]);
    assert_eq!(
        eval(&s),
        Ok(vec![encode_script_num(2), encode_script_num(1)])
    );
    // Underflows.
    for op in [
        OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_2DUP, OP_2DROP, OP_SWAP, OP_ROT, OP_TUCK,
    ] {
        assert_eq!(
            eval(&script(&[op])),
            Err(ScriptError::InvalidStackOperation),
            "op {op:#x}"
        );
    }
    assert_eq!(
        eval(&script(&[OP_FROMALTSTACK])),
        Err(ScriptError::InvalidAltstackOperation)
    );
    // SIZE.
    let s = script(&[0x03, 1, 2, 3, OP_SIZE]);
    assert_eq!(eval(&s), Ok(vec![vec![1, 2, 3], encode_script_num(3)]));
}

#[test]
fn conditionals() {
    // 1 IF 2 ELSE 3 ENDIF → 2; 0 IF 2 ELSE 3 ENDIF → 3.
    let s = script(&[OP_1, OP_IF, OP_1 + 1, OP_ELSE, OP_1 + 2, OP_ENDIF]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(2)]));
    let s = script(&[OP_0, OP_IF, OP_1 + 1, OP_ELSE, OP_1 + 2, OP_ENDIF]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(3)]));
    // NOTIF inverts.
    let s = script(&[OP_0, OP_NOTIF, OP_1 + 1, OP_ENDIF]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(2)]));
    // Unbalanced.
    assert_eq!(
        eval(&script(&[OP_IF])),
        Err(ScriptError::UnbalancedConditional)
    );
    assert_eq!(
        eval(&script(&[OP_ENDIF])),
        Err(ScriptError::UnbalancedConditional)
    );
    assert_eq!(
        eval(&script(&[OP_ELSE])),
        Err(ScriptError::UnbalancedConditional)
    );
    // IF on empty stack.
    assert_eq!(
        eval(&script(&[OP_IF, OP_ENDIF])),
        Err(ScriptError::UnbalancedConditional)
    );
    // Nested.
    let s = script(&[
        OP_1,
        OP_IF,
        OP_0,
        OP_IF,
        OP_1 + 1,
        OP_ELSE,
        OP_1 + 2,
        OP_ENDIF,
        OP_ENDIF,
    ]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(3)]));
    // Disabled opcodes fail even in unexecuted branches.
    let s = script(&[OP_0, OP_IF, OP_CAT, OP_ENDIF]);
    assert_eq!(eval(&s), Err(ScriptError::DisabledOpcode));
    // ...but ordinary bad opcodes in unexecuted branches are skipped.
    let s = script(&[OP_0, OP_IF, OP_CHECKSIG, OP_ENDIF, OP_1]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(1)]));
    // OP_RETURN in an unexecuted branch is skipped.
    let s = script(&[OP_0, OP_IF, OP_RETURN, OP_ENDIF, OP_1]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(1)]));
}

#[test]
fn verify_and_return() {
    let s = script(&[OP_1, OP_VERIFY, OP_1 + 1]);
    assert_eq!(eval(&s), Ok(vec![encode_script_num(2)]));
    assert_eq!(eval(&script(&[OP_0, OP_VERIFY])), Err(ScriptError::Verify));
    assert_eq!(
        eval(&script(&[OP_VERIFY])),
        Err(ScriptError::InvalidStackOperation)
    );
    assert_eq!(eval(&script(&[OP_RETURN])), Err(ScriptError::OpReturn));
    assert_eq!(
        eval(&script(&[OP_1, OP_1, OP_EQUALVERIFY, OP_1 + 1])),
        Ok(vec![encode_script_num(2)])
    );
    assert_eq!(
        eval(&script(&[OP_1, OP_1 + 1, OP_EQUALVERIFY])),
        Err(ScriptError::EqualVerify)
    );
}

#[test]
fn hash_opcodes() {
    // OP_SHA256 of empty input.
    let s = script(&[OP_0, OP_SHA256]);
    let Ok(stack) = eval(&s) else {
        panic!("eval failed")
    };
    assert_eq!(stack[0], sha256(&[]));
    // HASH160 = RIPEMD160(SHA256(x)), HASH256 = sha256d.
    let s = script(&[OP_0, OP_HASH160]);
    let Ok(stack) = eval(&s) else {
        panic!("eval failed")
    };
    assert_eq!(stack[0].len(), 20);
    assert_eq!(stack[0], Ripemd160::digest(Sha256::digest([])).to_vec());
    let s = script(&[OP_0, OP_HASH256]);
    let Ok(stack) = eval(&s) else {
        panic!("eval failed")
    };
    assert_eq!(stack[0], sha256(&sha256(&[])));
    let s = script(&[OP_0, OP_RIPEMD160]);
    let Ok(stack) = eval(&s) else {
        panic!("eval failed")
    };
    assert_eq!(stack[0], Ripemd160::digest([]).to_vec());
    let s = script(&[OP_0, OP_SHA1]);
    let Ok(stack) = eval(&s) else {
        panic!("eval failed")
    };
    assert_eq!(stack[0], Sha1::digest([]).to_vec());
}

#[test]
fn disabled_and_reserved_opcodes() {
    for op in [
        OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR, OP_2MUL, OP_2DIV,
        OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT,
    ] {
        assert_eq!(
            eval(&script(&[op])),
            Err(ScriptError::DisabledOpcode),
            "op {op:#x}"
        );
    }
    // OP_RESERVED executes as BAD_OPCODE.
    assert_eq!(eval(&script(&[0x50])), Err(ScriptError::BadOpcode));
    // Unknown opcode.
    assert_eq!(eval(&script(&[0xff])), Err(ScriptError::BadOpcode));
    // OP_VERIF/VERNOTIF fail even in unexecuted branches (they're in the
    // IF..ENDIF range so they reach the switch).
    assert_eq!(
        eval(&script(&[OP_0, OP_IF, 0x65, OP_ENDIF])),
        Err(ScriptError::BadOpcode)
    );
}

#[test]
fn size_and_count_limits() {
    // Script > 10k in BASE → ScriptSize.
    let big = Script::new(vec![OP_NOP; MAX_SCRIPT_SIZE + 1]);
    assert_eq!(eval(&big), Err(ScriptError::ScriptSize));
    // Push > 520 → PushSize (even unexecuted).
    let mut s = vec![OP_PUSHDATA2];
    s.extend_from_slice(&521u16.to_le_bytes());
    s.extend_from_slice(&[0u8; 521]);
    assert_eq!(eval(&script(&s)), Err(ScriptError::PushSize));
    let mut s = vec![OP_0, OP_IF, OP_PUSHDATA2];
    s.extend_from_slice(&521u16.to_le_bytes());
    s.extend_from_slice(&[0u8; 521]);
    s.push(OP_ENDIF);
    assert_eq!(eval(&script(&s)), Err(ScriptError::PushSize));
    // >201 non-push opcodes → OpCount.
    let s = vec![OP_NOP; 202];
    assert_eq!(eval(&script(&s)), Err(ScriptError::OpCount));
    // Pushes and OP_1..OP_16 don't count toward the limit: 201 NOPs + extra
    // pushes execute fine.
    let mut s = vec![OP_NOP; 201];
    s.extend_from_slice(&[OP_0; 5]);
    s.extend_from_slice(&[OP_16; 5]);
    assert!(eval(&script(&s)).is_ok());
}

#[test]
fn stack_size_limit() {
    // 1001 items → StackSize.
    let mut s = vec![OP_0; 1000];
    s.push(OP_1); // the 1001st push
    assert_eq!(eval(&script(&s)), Err(ScriptError::StackSize));
    // Exactly 1000 is fine.
    let s = vec![OP_0; 1000];
    assert!(eval(&script(&s)).is_ok());
}

#[test]
fn minimaldata_flag() {
    // Non-minimal push of 1 (raw 0x01 push instead of OP_1).
    let s = script(&[0x01, 0x01]);
    assert_eq!(eval(&s), Ok(vec![vec![1]]));
    assert_eq!(
        eval_with(&s, ScriptFlags::MINIMALDATA, &StubChecker::default()),
        Err(ScriptError::MinimalData)
    );
    // PUSHDATA1 for a 3-byte value is non-minimal.
    let s = script(&[OP_PUSHDATA1, 0x03, 1, 2, 3]);
    assert_eq!(
        eval_with(&s, ScriptFlags::MINIMALDATA, &StubChecker::default()),
        Err(ScriptError::MinimalData)
    );
}

#[test]
fn locktime_and_sequence_ops() {
    let flags = ScriptFlags::CHECKLOCKTIMEVERIFY.union(ScriptFlags::CHECKSEQUENCEVERIFY);
    // CLTV: checker says satisfied.
    let s = script(&[OP_1, OP_CHECKLOCKTIMEVERIFY, OP_1 + 1]);
    let ok = StubChecker {
        locktime: true,
        ..Default::default()
    };
    assert_eq!(
        eval_with(&s, flags, &ok),
        Ok(vec![encode_script_num(1), encode_script_num(2)])
    );
    // Checker unsatisfied.
    let s = script(&[OP_1, OP_CHECKLOCKTIMEVERIFY]);
    assert_eq!(
        eval_with(&s, flags, &StubChecker::default()),
        Err(ScriptError::UnsatisfiedLocktime)
    );
    // Negative operand.
    let s = script(&[OP_1NEGATE, OP_CHECKLOCKTIMEVERIFY]);
    assert_eq!(
        eval_with(&s, flags, &StubChecker::default()),
        Err(ScriptError::NegativeLocktime)
    );
    // Without the flag, CLTV is a NOP2.
    let s = script(&[OP_1NEGATE, OP_CHECKLOCKTIMEVERIFY]);
    assert_eq!(eval(&s), Ok(vec![vec![0x81]]));
    // CSV: the SEQUENCE_LOCKTIME_DISABLE_FLAG operand (bit 31) is a NOP even
    // when the checker would fail. 0x80000001 encodes as 01 00 00 80 00.
    let operand = encode_script_num(0x8000_0001);
    assert_eq!(operand, vec![0x01, 0x00, 0x00, 0x80, 0x00]);
    let mut s = vec![0x05];
    s.extend_from_slice(&operand);
    s.push(OP_CHECKSEQUENCEVERIFY);
    assert_eq!(
        eval_with(&script(&s), flags, &StubChecker::default()),
        Ok(vec![operand.clone()])
    );
    // Negative CSV operand → NegativeLocktime.
    let s = script(&[OP_1NEGATE, OP_CHECKSEQUENCEVERIFY]);
    assert_eq!(
        eval_with(&s, flags, &StubChecker::default()),
        Err(ScriptError::NegativeLocktime)
    );
    // NOP1/4..10 under DISCOURAGE_UPGRADABLE_NOPS.
    let s = script(&[OP_NOP1]);
    let disc = ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS;
    assert_eq!(
        eval_with(&s, disc, &StubChecker::default()),
        Err(ScriptError::DiscourageUpgradableNops)
    );
    assert_eq!(eval(&s), Ok(vec![]));
}

#[test]
fn checksig_via_stub() {
    // sig pubkey CHECKSIG — stub returns ecdsa verdict.
    let s = script(&[0x01, 0xaa, 0x01, 0xbb, OP_CHECKSIG]);
    let ok = StubChecker {
        ecdsa: true,
        ..Default::default()
    };
    assert_eq!(eval_with(&s, ScriptFlags::NONE, &ok), Ok(vec![vec![1]]));
    assert_eq!(
        eval_with(&s, ScriptFlags::NONE, &StubChecker::default()),
        Ok(vec![vec![]])
    );
    // CHECKSIGVERIFY failure.
    let s = script(&[0x01, 0xaa, 0x01, 0xbb, OP_CHECKSIGVERIFY]);
    assert_eq!(
        eval_with(&s, ScriptFlags::NONE, &StubChecker::default()),
        Err(ScriptError::CheckSigVerify)
    );
    // NULLFAIL: non-empty failing sig → error.
    let nullfail = ScriptFlags::NULLFAIL;
    assert_eq!(
        eval_with(
            &script(&[0x01, 0xaa, 0x01, 0xbb, OP_CHECKSIG]),
            nullfail,
            &StubChecker::default()
        ),
        Err(ScriptError::SigNullFail)
    );
    // Empty sig is allowed to fail under NULLFAIL.
    let s = script(&[OP_0, 0x01, 0xbb, OP_CHECKSIG]);
    assert_eq!(
        eval_with(&s, nullfail, &StubChecker::default()),
        Ok(vec![vec![]])
    );
    // DER checking: malformed sig fails under DERSIG even when the checker
    // would accept it.
    let der = ScriptFlags::DERSIG;
    assert_eq!(
        eval_with(&script(&[0x01, 0xaa, 0x01, 0xbb, OP_CHECKSIG]), der, &ok),
        Err(ScriptError::SigDer)
    );
    // STRICTENC pubkey check: 0xbb is not a pubkey — but the sig must be
    // DER-valid to reach the pubkey check (STRICTENC checks DER first).
    let strict = ScriptFlags::STRICTENC;
    let mut sig_push = vec![good_der_sig().len() as u8];
    sig_push.extend_from_slice(&good_der_sig());
    sig_push.extend_from_slice(&[0x01, 0xbb, OP_CHECKSIG]);
    assert_eq!(
        eval_with(&script(&sig_push), strict, &ok),
        Err(ScriptError::PubkeyType)
    );
}

#[test]
fn checkmultisig_via_stub() {
    // 0 <sig> 1 <pk> 1 CHECKMULTISIG — 1-of-1.
    let s = script(&[OP_0, 0x01, 0xaa, OP_1, 0x01, 0xbb, OP_1, OP_CHECKMULTISIG]);
    let ok = StubChecker {
        ecdsa: true,
        ..Default::default()
    };
    assert_eq!(eval_with(&s, ScriptFlags::NONE, &ok), Ok(vec![vec![1]]));
    // NULLDUMMY: non-empty dummy → error.
    let s = script(&[
        0x01,
        0xdd,
        0x01,
        0xaa,
        OP_1,
        0x01,
        0xbb,
        OP_1,
        OP_CHECKMULTISIG,
    ]);
    assert_eq!(
        eval_with(&s, ScriptFlags::NULLDUMMY, &ok),
        Err(ScriptError::SigNullDummy)
    );
    // Sig count > key count → SigCount.
    let s = script(&[
        OP_0,
        0x01,
        0xaa,
        OP_1 + 1,
        0x01,
        0xbb,
        OP_1,
        OP_CHECKMULTISIG,
    ]);
    assert_eq!(eval(&s), Err(ScriptError::SigCount));
    // Pubkey count > 20 → PubkeyCount... that takes 21 pubkeys; use the count
    // overflow path instead: nkeys read off top of stack as OP_N > 16 isn't a
    // count — push raw 21.
    let mut s = vec![OP_0, 0x01, 0xaa, OP_1];
    s.extend_from_slice(&[0x01, 0xbb, 0x01, 0x15]); // ...1 pk, count push 21
    s.push(OP_CHECKMULTISIG);
    // stack: dummy sig nsigs=1 pk nkeys=21 → nkeys>20 → PubkeyCount
    assert_eq!(eval(&script(&s)), Err(ScriptError::PubkeyCount));
    // CHECKMULTISIGVERIFY failing → error.
    let s = script(&[
        OP_0,
        0x01,
        0xaa,
        OP_1,
        0x01,
        0xbb,
        OP_1,
        OP_CHECKMULTISIGVERIFY,
    ]);
    assert_eq!(
        eval_with(&s, ScriptFlags::NONE, &StubChecker::default()),
        Err(ScriptError::CheckMultisigVerify)
    );
    // Tapscript → TapscriptCheckMultisig.
    let s = script(&[OP_0, 0x01, 0xaa, OP_1, 0x01, 0xbb, OP_1, OP_CHECKMULTISIG]);
    let mut stack = Vec::new();
    let mut ed = ExecutionData::default();
    assert_eq!(
        eval_script(
            &mut stack,
            &s,
            ScriptFlags::NONE,
            &StubChecker::default(),
            SigVersion::Tapscript,
            &mut ed
        ),
        Err(ScriptError::TapscriptCheckMultisig)
    );
}

#[test]
fn codeseparator_and_sigfindanddelete() {
    // In BASE + CONST_SCRIPTCODE, OP_CODESEPARATOR fails even unexecuted.
    let s = script(&[OP_0, OP_IF, OP_CODESEPARATOR, OP_ENDIF]);
    let flags = ScriptFlags::CONST_SCRIPTCODE;
    assert_eq!(
        eval_with(&s, flags, &StubChecker::default()),
        Err(ScriptError::OpCodeSeparator)
    );
    // Without the flag it executes fine.
    assert_eq!(eval(&s), Ok(vec![]));
}

// ---------------------------------------------------------------------------
// verify_script — orchestration
// ---------------------------------------------------------------------------

/// The standard post-segwit mandatory flag set for a modern block.
fn standard_flags() -> ScriptFlags {
    ScriptFlags::P2SH
        .union(ScriptFlags::WITNESS)
        .union(ScriptFlags::TAPROOT)
        .union(ScriptFlags::DERSIG)
        .union(ScriptFlags::CHECKLOCKTIMEVERIFY)
        .union(ScriptFlags::CHECKSEQUENCEVERIFY)
        .union(ScriptFlags::NULLDUMMY)
        .union(ScriptFlags::STRICTENC)
        .union(ScriptFlags::LOW_S)
        .union(ScriptFlags::SIGPUSHONLY)
        .union(ScriptFlags::MINIMALDATA)
        .union(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS)
        .union(ScriptFlags::CLEANSTACK)
        .union(ScriptFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM)
        .union(ScriptFlags::MINIMALIF)
        .union(ScriptFlags::NULLFAIL)
        .union(ScriptFlags::WITNESS_PUBKEYTYPE)
        .union(ScriptFlags::CONST_SCRIPTCODE)
        .union(ScriptFlags::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION)
        .union(ScriptFlags::DISCOURAGE_OP_SUCCESS)
        .union(ScriptFlags::DISCOURAGE_UPGRADABLE_PUBKEYTYPE)
}

#[test]
fn verify_simple_scripts() {
    // OP_TRUE anyone-can-spend.
    let spk = script(&[OP_1]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            None,
            standard_flags(),
            &StubChecker::default()
        ),
        Ok(())
    );
    // scriptPubKey evals false.
    let spk = script(&[OP_0]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            None,
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::EvalFalse)
    );
    // Non-push-only scriptSig under SIGPUSHONLY.
    let sig = script(&[OP_1, OP_DUP]);
    assert_eq!(
        verify_script(&sig, &spk, None, standard_flags(), &StubChecker::default()),
        Err(ScriptError::SigPushOnly)
    );
    // Non-empty witness with a non-witness program → WITNESS_UNEXPECTED.
    let spk = script(&[OP_1]);
    let w = Witness::new(vec![vec![1]]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            Some(&w),
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::WitnessUnexpected)
    );
}

#[test]
fn verify_p2sh() {
    // P2SH of redeem = OP_1: scriptPubKey = HASH160 <h160(redeem)> EQUAL.
    let redeem = script(&[OP_1]);
    let h160 = Ripemd160::digest(Sha256::digest(redeem.as_bytes()));
    let mut spk_bytes = vec![OP_HASH160, 0x14];
    spk_bytes.extend_from_slice(&h160);
    spk_bytes.push(OP_EQUAL);
    let spk = script(&spk_bytes);
    // scriptSig pushes the redeem script.
    let mut sig = vec![redeem.len() as u8];
    sig.extend_from_slice(redeem.as_bytes());
    let sig = script(&sig);
    assert_eq!(
        verify_script(&sig, &spk, None, standard_flags(), &StubChecker::default()),
        Ok(())
    );
    // Wrong redeem hash → scriptPubKey leaves 0 → EvalFalse.
    let bad_redeem = script(&[OP_1 + 1]);
    let mut sig = vec![bad_redeem.len() as u8];
    sig.extend_from_slice(bad_redeem.as_bytes());
    assert_eq!(
        verify_script(
            &script(&sig),
            &spk,
            None,
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::EvalFalse)
    );
    // Redeem evals false.
    let redeem = script(&[OP_0]);
    let h160 = Ripemd160::digest(Sha256::digest(redeem.as_bytes()));
    let mut spk_bytes = vec![OP_HASH160, 0x14];
    spk_bytes.extend_from_slice(&h160);
    spk_bytes.push(OP_EQUAL);
    let mut sig = vec![redeem.len() as u8];
    sig.extend_from_slice(redeem.as_bytes());
    assert_eq!(
        verify_script(
            &script(&sig),
            &script(&spk_bytes),
            None,
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::EvalFalse)
    );
}

#[test]
fn verify_p2wpkh() {
    // P2WPKH spk: OP_0 <20-byte keyhash>. Witness [sig, pubkey]. The implied
    // script is DUP HASH160 <kh> EQUALVERIFY CHECKSIG — with the stub checker
    // accepting, the stack ends [1].
    let keyhash = [0x11; 20];
    let mut spk_bytes = vec![OP_0, 0x14];
    spk_bytes.extend_from_slice(&keyhash);
    let spk = script(&spk_bytes);
    // Witness: [<sig>, <pubkey whose HASH160 is keyhash>] — can't satisfy
    // HASH160 with a fake pubkey; instead craft witness to make implied
    // script pass: witness must be exactly [sig, pubkey]; the implied
    // scriptPubKey checks HASH160(pubkey)==keyhash. Find a pubkey with a
    // matching hash is infeasible → use the stub with a WITNESS_V0 eval that
    // fails at EQUALVERIFY → WitnessProgramMismatch? No — the implied script
    // evals pubkey→dup→hash160→push keyhash→equalverify→checksig. With a fake
    // pubkey, EQUALVERIFY fails → EqualVerify error inside witness eval.
    let w = Witness::new(vec![vec![0xaa], vec![0x02; 33]]);
    let ok = StubChecker {
        ecdsa: true,
        ..Default::default()
    };
    assert_eq!(
        verify_script(&script(&[]), &spk, Some(&w), standard_flags(), &ok),
        Err(ScriptError::EqualVerify)
    );
    // Non-empty scriptSig on a native witness program → WitnessMalleated.
    let sig = script(&[0x51]);
    assert_eq!(
        verify_script(&sig, &spk, Some(&w), standard_flags(), &ok),
        Err(ScriptError::WitnessMalleated)
    );
    // Witness stack != 2 → WitnessProgramMismatch.
    let w = Witness::new(vec![vec![0xaa]]);
    assert_eq!(
        verify_script(&script(&[]), &spk, Some(&w), standard_flags(), &ok),
        Err(ScriptError::WitnessProgramMismatch)
    );
    // A real P2WPKH flow: pubkey 33-byte 0x02.., hash it, set spk to that.
    // The sig must be DER-valid under standard flags (the stub decides the
    // actual verification verdict).
    let pubkey = {
        let mut p = vec![0x02];
        p.extend_from_slice(&[0x42; 32]);
        p
    };
    let kh = Ripemd160::digest(Sha256::digest(&pubkey));
    let mut spk_bytes = vec![OP_0, 0x14];
    spk_bytes.extend_from_slice(&kh);
    let spk = script(&spk_bytes);
    let w = Witness::new(vec![good_der_sig(), pubkey]);
    assert_eq!(
        verify_script(&script(&[]), &spk, Some(&w), standard_flags(), &ok),
        Ok(())
    );
    // Checker rejects the non-empty sig → NULLFAIL (standard flags include
    // it), not a mere EvalFalse.
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            Some(&w),
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::SigNullFail)
    );
    // Without NULLFAIL it's EvalFalse.
    let no_nf = ScriptFlags::from_bits(standard_flags().bits() & !ScriptFlags::NULLFAIL.bits());
    assert_eq!(
        verify_script(&script(&[]), &spk, Some(&w), no_nf, &StubChecker::default()),
        Err(ScriptError::EvalFalse)
    );
    // Uncompressed pubkey under WITNESS_PUBKEYTYPE → WitnessPubkeyType.
    let pubkey65 = {
        let mut p = vec![0x04];
        p.extend_from_slice(&[0x42; 64]);
        p
    };
    let kh = Ripemd160::digest(Sha256::digest(&pubkey65));
    let mut spk_bytes = vec![OP_0, 0x14];
    spk_bytes.extend_from_slice(&kh);
    let spk = script(&spk_bytes);
    let w = Witness::new(vec![good_der_sig(), pubkey65]);
    assert_eq!(
        verify_script(&script(&[]), &spk, Some(&w), standard_flags(), &ok),
        Err(ScriptError::WitnessPubkeyType)
    );
}

#[test]
fn verify_p2wsh() {
    // P2WSH of witness_script = OP_1: program = sha256(script).
    let ws = script(&[OP_1]);
    let prog = sha256(ws.as_bytes());
    let mut spk_bytes = vec![OP_0, 0x20];
    spk_bytes.extend_from_slice(&prog);
    let spk = script(&spk_bytes);
    let w = Witness::new(vec![ws.as_bytes().to_vec()]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            Some(&w),
            standard_flags(),
            &StubChecker::default()
        ),
        Ok(())
    );
    // Hash mismatch.
    let bad = Witness::new(vec![script(&[OP_1 + 1]).as_bytes().to_vec()]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            Some(&bad),
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::WitnessProgramMismatch)
    );
    // Empty witness stack.
    let w = Witness::new(vec![]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            Some(&w),
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::WitnessProgramWitnessEmpty)
    );
    // Witness script that evals false.
    let ws = script(&[OP_0]);
    let prog = sha256(ws.as_bytes());
    let mut spk_bytes = vec![OP_0, 0x20];
    spk_bytes.extend_from_slice(&prog);
    let w = Witness::new(vec![ws.as_bytes().to_vec()]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &script(&spk_bytes),
            Some(&w),
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::EvalFalse)
    );
    // Wrong-length v0 program (16 bytes, nonzero so the spk evals true) →
    // WitnessProgramWrongLength.
    let mut spk_bytes = vec![OP_0, 0x10];
    spk_bytes.extend_from_slice(&[0x99; 16]);
    let w = Witness::new(vec![vec![1]]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &script(&spk_bytes),
            Some(&w),
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::WitnessProgramWrongLength)
    );
}

#[test]
fn verify_p2sh_wrapped_witness() {
    // P2SH-wrapped P2WPKH: redeem = OP_0 <kh>; spk = HASH160 <h160(redeem)> EQUAL.
    let pubkey = {
        let mut p = vec![0x02];
        p.extend_from_slice(&[0x42; 32]);
        p
    };
    let kh = Ripemd160::digest(Sha256::digest(&pubkey));
    let mut redeem_bytes = vec![OP_0, 0x14];
    redeem_bytes.extend_from_slice(&kh);
    let h160 = Ripemd160::digest(Sha256::digest(&redeem_bytes));
    let mut spk_bytes = vec![OP_HASH160, 0x14];
    spk_bytes.extend_from_slice(&h160);
    spk_bytes.push(OP_EQUAL);
    let spk = script(&spk_bytes);
    // scriptSig must be exactly a single push of redeem.
    let mut sig = vec![redeem_bytes.len() as u8];
    sig.extend_from_slice(&redeem_bytes);
    let sig = script(&sig);
    let w = Witness::new(vec![good_der_sig(), pubkey]);
    let ok = StubChecker {
        ecdsa: true,
        ..Default::default()
    };
    assert_eq!(
        verify_script(&sig, &spk, Some(&w), standard_flags(), &ok),
        Ok(())
    );
    // scriptSig with an extra push → malleated P2SH witness.
    let mut sig2 = vec![0x51, redeem_bytes.len() as u8];
    sig2.extend_from_slice(&redeem_bytes);
    assert_eq!(
        verify_script(&script(&sig2), &spk, Some(&w), standard_flags(), &ok),
        Err(ScriptError::WitnessMalleatedP2sh)
    );
}

#[test]
fn verify_taproot_dispatch() {
    // v1 32-byte program.
    let mut spk_bytes = vec![OP_1, 0x20];
    spk_bytes.extend_from_slice(&[0x33; 32]);
    let spk = script(&spk_bytes);
    // Key path: single 64-byte sig item; stub's schnorr returns SchnorrSig by
    // default.
    let w = Witness::new(vec![vec![0xaa; 64]]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            Some(&w),
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::SchnorrSig)
    );
    // Empty witness stack on taproot → WitnessProgramWitnessEmpty.
    let w = Witness::new(vec![]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            Some(&w),
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::WitnessProgramWitnessEmpty)
    );
    // Script path: [script, control] with control last; a 10-byte control
    // block fails the 33-byte minimum.
    let w = Witness::new(vec![vec![0x51], vec![0xaa; 10]]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            Some(&w),
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::TaprootWrongControlSize)
    );
    // Without TAPROOT flag, taproot programs succeed vacuously.
    let flags = standard_flags();
    let no_tr = ScriptFlags::from_bits(flags.bits() & !ScriptFlags::TAPROOT.bits());
    let w = Witness::new(vec![vec![0xaa; 64]]);
    assert_eq!(
        verify_script(&script(&[]), &spk, Some(&w), no_tr, &StubChecker::default()),
        Ok(())
    );
    // P2A: OP_1 <0x4e73> — anyone-can-spend, succeeds.
    let spk = script(&[OP_1, 0x02, 0x4e, 0x73]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            Some(&Witness::new(vec![vec![]])),
            standard_flags(),
            &StubChecker::default()
        ),
        Ok(())
    );
    // Unknown v2 witness program → succeeds (upgradeable); with DISCOURAGE flag → error.
    let mut spk_bytes = vec![OP_1 + 1, 0x20];
    spk_bytes.extend_from_slice(&[0x44; 32]);
    let spk = script(&spk_bytes);
    let w = Witness::new(vec![vec![1]]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            Some(&w),
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::DiscourageUpgradableWitnessProgram)
    );
    let flags = ScriptFlags::from_bits(
        standard_flags().bits() & !ScriptFlags::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.bits(),
    );
    assert_eq!(
        verify_script(&script(&[]), &spk, Some(&w), flags, &StubChecker::default()),
        Ok(())
    );
}

#[test]
fn cleanstack_enforcement() {
    // scriptPubKey leaving two items → CleanStack under CLEANSTACK.
    let spk = script(&[OP_1, OP_1]);
    assert_eq!(
        verify_script(
            &script(&[]),
            &spk,
            None,
            standard_flags(),
            &StubChecker::default()
        ),
        Err(ScriptError::CleanStack)
    );
    // Without CLEANSTACK it's fine.
    let flags = ScriptFlags::from_bits(standard_flags().bits() & !ScriptFlags::CLEANSTACK.bits());
    assert_eq!(
        verify_script(
            &script(&[]),
            &script(&[OP_1, OP_1]),
            None,
            flags,
            &StubChecker::default()
        ),
        Ok(())
    );
}

#[test]
fn error_display_strings() {
    // Spot-check a few ScriptErrorString ports.
    assert_eq!(
        ScriptError::EvalFalse.to_string(),
        "Script evaluated without error but finished with a false/empty top stack element"
    );
    assert_eq!(
        ScriptError::SigNullDummy.to_string(),
        "Dummy CHECKMULTISIG argument must be zero"
    );
    assert_eq!(
        ScriptError::WitnessMalleatedP2sh.to_string(),
        "Witness requires only-redeemscript scriptSig"
    );
    assert_eq!(ScriptError::UnknownError.to_string(), "unknown error");
}

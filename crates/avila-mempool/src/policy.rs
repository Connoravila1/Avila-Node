//! Core v31.1's `policy/policy.cpp` standardness gate, ported: which
//! transactions this node will relay and mine even though a block
//! containing one that fails these checks would still connect fine.
//! Everything here is relay policy, gated behind [`crate::Mempool::require_standard`]
//! — never consensus.

use avila_consensus::interpreter::{ANNEX_TAG, TAPROOT_LEAF_MASK, TAPROOT_LEAF_TAPSCRIPT};
use avila_consensus::script::ScriptType;
use avila_consensus::transaction::{Script, Transaction, TxOut};

/// Core's `TX_MIN_STANDARD_VERSION`.
pub const TX_MIN_STANDARD_VERSION: u32 = 1;
/// Core's `TX_MAX_STANDARD_VERSION` — version 3 is TRUC (BIP431).
pub const TX_MAX_STANDARD_VERSION: u32 = 3;
/// Core's `MAX_STANDARD_SCRIPTSIG_SIZE`.
pub const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1650;
/// Core's `MAX_P2SH_SIGOPS`.
pub const MAX_P2SH_SIGOPS: u64 = 15;
/// Core's `MAX_TX_LEGACY_SIGOPS` (BIP54, `policy.cpp`'s `CheckSigopsBIP54`).
pub const MAX_TX_LEGACY_SIGOPS: u64 = 2_500;
/// Core's `DEFAULT_PERMIT_BAREMULTISIG`.
pub const DEFAULT_PERMIT_BAREMULTISIG: bool = true;
/// Core's `MAX_OP_RETURN_RELAY` — `MAX_STANDARD_TX_WEIGHT / 4`, the
/// default `-datacarriersize`.
pub const MAX_OP_RETURN_RELAY: usize = crate::MAX_STANDARD_TX_WEIGHT / 4;
/// Core's `DUST_RELAY_TX_FEE` default — 3000 sat/kvB.
pub const DUST_RELAY_TX_FEE: i64 = 3_000;
/// Core's `MAX_DUST_OUTPUTS_PER_TX` — the v28+ ephemeral-dust allowance
/// (a single dust output is standard; it must also be 0-fee, see
/// [`precheck_ephemeral`]).
pub const MAX_DUST_OUTPUTS_PER_TX: usize = 1;
/// Core's `MAX_STANDARD_P2WSH_STACK_ITEMS`.
pub const MAX_STANDARD_P2WSH_STACK_ITEMS: usize = 100;
/// Core's `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE`.
pub const MAX_STANDARD_P2WSH_STACK_ITEM_SIZE: usize = 80;
/// Core's `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE`.
pub const MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE: usize = 80;
/// Core's `MAX_STANDARD_P2WSH_SCRIPT_SIZE`.
pub const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3_600;
/// Core's `MIN_STANDARD_TX_NONWITNESS_SIZE` (CVE-2017-12842 mitigation).
/// Upstream this one is unconditional; here it rides under
/// `require_standard` with the rest of this module so existing test
/// fixtures under ~65 non-witness bytes keep working via the permissive
/// setting instead of needing to be padded out.
pub const MIN_STANDARD_TX_NONWITNESS_SIZE: usize = 65;

/// Core's `CFeeRate::GetFee`: `rate` sat/kvB applied to `bytes`, Core's
/// truncating integer division with its "any nonzero rate on a nonzero
/// size charges at least 1 sat" floor.
fn fee_for_size(rate_sat_per_kvb: i64, bytes: i64) -> i64 {
    let fee = rate_sat_per_kvb.saturating_mul(bytes) / 1000;
    if fee == 0 && bytes != 0 && rate_sat_per_kvb > 0 {
        1
    } else {
        fee
    }
}

/// Core's `GetDustThreshold`: the value below which spending `txout`
/// would cost more in fees than it's worth, at `dust_relay_fee` sat/kvB.
#[must_use]
pub fn dust_threshold(txout: &TxOut, dust_relay_fee: i64) -> i64 {
    if txout.script_pubkey.is_unspendable() {
        return 0;
    }
    let spk_len = txout.script_pubkey.as_bytes().len();
    let mut size = 8 + avila_consensus::encode::compact_size_len(spk_len as u64) + spk_len;
    // A spendable segwit v0 P2WPKH spend (33-byte key + ECDSA sig, 75%
    // witness-discounted); non-witness outputs use the legacy ~148-byte
    // input estimate. Taproot's cheaper key-path spend is deliberately
    // not modeled — see Core's PR #22779 discussion.
    size += if txout.script_pubkey.witness_program().is_some() {
        32 + 4 + 1 + (107 / 4) + 4
    } else {
        32 + 4 + 1 + 107 + 4
    };
    fee_for_size(dust_relay_fee, size as i64)
}

/// Core's `IsDust`.
#[must_use]
pub fn is_dust(txout: &TxOut, dust_relay_fee: i64) -> bool {
    txout.value < dust_threshold(txout, dust_relay_fee)
}

/// Core's `GetDust`: the indexes of every dust output.
#[must_use]
pub fn dust_outputs(tx: &Transaction, dust_relay_fee: i64) -> Vec<u32> {
    tx.outputs
        .iter()
        .enumerate()
        .filter(|(_, o)| is_dust(o, dust_relay_fee))
        .map(|(i, _)| i as u32)
        .collect()
}

/// Core's `IsStandard(scriptPubKey, whichType)` layered on
/// [`ScriptType::classify`] (avila's `Solver`): everything `classify`
/// returns is standard except `Nonstandard`, with bare multisig further
/// capped at 3 keys.
fn is_standard_script_type(t: &ScriptType) -> bool {
    match t {
        ScriptType::Nonstandard => false,
        ScriptType::Multisig { keys, .. } => !keys.is_empty() && keys.len() <= 3,
        _ => true,
    }
}

/// Core's `IsStandardTx`. Returns Core's short reject reason on the
/// first violation.
pub fn is_standard_tx(
    tx: &Transaction,
    max_datacarrier_bytes: Option<usize>,
    permit_bare_multisig: bool,
    dust_relay_fee: i64,
) -> Result<(), &'static str> {
    if tx.version < TX_MIN_STANDARD_VERSION || tx.version > TX_MAX_STANDARD_VERSION {
        return Err("version");
    }
    // tx.weight() > MAX_STANDARD_TX_WEIGHT is already enforced
    // unconditionally earlier in `accept_tx` (Core folds it into this
    // function; not duplicated here).
    for input in &tx.inputs {
        if input.script_sig.as_bytes().len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err("scriptsig-size");
        }
        if !input.script_sig.is_push_only() {
            return Err("scriptsig-not-pushonly");
        }
    }
    let mut datacarrier_bytes_left = max_datacarrier_bytes.unwrap_or(0) as i64;
    for output in &tx.outputs {
        let t = output.script_pubkey.classify();
        if !is_standard_script_type(&t) {
            return Err("scriptpubkey");
        }
        if matches!(t, ScriptType::NullData) {
            let size = output.script_pubkey.as_bytes().len() as i64;
            if size > datacarrier_bytes_left {
                return Err("datacarrier");
            }
            datacarrier_bytes_left -= size;
        } else if matches!(t, ScriptType::Multisig { .. }) && !permit_bare_multisig {
            return Err("bare-multisig");
        }
    }
    if dust_outputs(tx, dust_relay_fee).len() > MAX_DUST_OUTPUTS_PER_TX {
        return Err("dust");
    }
    Ok(())
}

/// Core's `AreInputsStandard`, with BIP54's `CheckSigopsBIP54` folded in
/// (as Core itself does). `spent` are the resolved previous outputs,
/// parallel to `tx.inputs`.
pub fn are_inputs_standard(tx: &Transaction, spent: &[TxOut]) -> Result<(), &'static str> {
    let mut legacy_sigops = 0u64;
    for (input, prev) in tx.inputs.iter().zip(spent) {
        legacy_sigops = legacy_sigops.saturating_add(input.script_sig.sig_ops(true));
        legacy_sigops = legacy_sigops.saturating_add(if prev.script_pubkey.is_p2sh() {
            prev.script_pubkey.p2sh_sig_ops(&input.script_sig)
        } else {
            prev.script_pubkey.sig_ops(true)
        });
        if legacy_sigops > MAX_TX_LEGACY_SIGOPS {
            return Err("bad-txns-nonstandard-inputs");
        }
    }
    for (input, prev) in tx.inputs.iter().zip(spent) {
        let t = prev.script_pubkey.classify();
        // `WITNESS_UNKNOWN` prevouts fail here even though the same
        // program is standard to *create* (Core's `IsStandardTx`
        // accepts it) — spending an unrecognized witness version is
        // exactly the soft-fork upgrade hook segwit reserves.
        if matches!(t, ScriptType::Nonstandard) || t.name() == "witness_unknown" {
            return Err("bad-txns-nonstandard-inputs");
        }
        if prev.script_pubkey.is_p2sh() {
            if input.script_sig.as_bytes().is_empty() {
                return Err("bad-txns-nonstandard-inputs");
            }
            let Some(redeem) = input.script_sig.last_pushed_data() else {
                return Err("bad-txns-nonstandard-inputs");
            };
            if Script::new(redeem.to_vec()).sig_ops(true) > MAX_P2SH_SIGOPS {
                return Err("bad-txns-nonstandard-inputs");
            }
        }
    }
    Ok(())
}

/// Core's `IsWitnessStandard`. `spent` are the resolved previous
/// outputs, parallel to `tx.inputs`.
pub fn is_witness_standard(tx: &Transaction, spent: &[TxOut]) -> Result<(), &'static str> {
    for (input, prev) in tx.inputs.iter().zip(spent) {
        // An input with no witness at all needs no witness-standardness
        // check — if the spend actually required one, consensus catches
        // it long before policy does.
        if input.witness.is_empty() {
            continue;
        }
        if prev.script_pubkey.classify() == ScriptType::Anchor {
            // "Witness stuffing": P2A is anyone-can-spend with an empty
            // witness; any witness at all on a P2A spend is nonstandard.
            return Err("bad-witness-nonstandard");
        }
        let mut spk = prev.script_pubkey.clone();
        let mut p2sh = false;
        if spk.is_p2sh() {
            if input.script_sig.as_bytes().is_empty() {
                return Err("bad-witness-nonstandard");
            }
            let Some(redeem) = input.script_sig.last_pushed_data() else {
                return Err("bad-witness-nonstandard");
            };
            spk = Script::new(redeem.to_vec());
            p2sh = true;
        }
        let Some((version, program)) = spk.witness_program() else {
            // A witness on a spend of a non-witness-program script.
            return Err("bad-witness-nonstandard");
        };
        if version == 0 && program.len() == 32 {
            let items = input.witness.items();
            let Some((script, stack)) = items.split_last() else {
                return Err("bad-witness-nonstandard");
            };
            if script.len() > MAX_STANDARD_P2WSH_SCRIPT_SIZE {
                return Err("bad-witness-nonstandard");
            }
            if stack.len() > MAX_STANDARD_P2WSH_STACK_ITEMS {
                return Err("bad-witness-nonstandard");
            }
            if stack
                .iter()
                .any(|it| it.len() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
            {
                return Err("bad-witness-nonstandard");
            }
        }
        if version == 1 && program.len() == 32 && !p2sh {
            let items = input.witness.items();
            if items.len() >= 2
                && items
                    .last()
                    .is_some_and(|last| !last.is_empty() && last[0] == ANNEX_TAG)
            {
                // Annexes carry no defined semantics yet.
                return Err("bad-witness-nonstandard");
            }
            if items.len() >= 2 {
                // Script-path spend: control block (last) + script
                // (second-to-last, ignored here); Core only bounds
                // stack-item size for the remaining witness data, and
                // only under the one defined (tapscript) leaf version.
                let control_block = &items[items.len() - 1];
                if control_block.is_empty() {
                    return Err("bad-witness-nonstandard");
                }
                if control_block[0] & TAPROOT_LEAF_MASK == TAPROOT_LEAF_TAPSCRIPT {
                    for item in &items[..items.len() - 2] {
                        if item.len() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE {
                            return Err("bad-witness-nonstandard");
                        }
                    }
                }
            } else if items.len() != 1 {
                // 0 stack elements — already invalid by consensus, kept
                // here defensively to mirror Core exactly.
                return Err("bad-witness-nonstandard");
            }
            // items.len() == 1: key-path spend, no policy rules apply.
        }
    }
    Ok(())
}

/// Core's `PreCheckEphemeralTx`: a transaction creating dust must be
/// exactly 0-fee (base and prioritised fee both zero) — there's never
/// an incentive to mine it alone, only to sweep its dust with a paying
/// child. `fee`/`modified_fee` mirror Core's `base_fee`/`mod_fee`.
///
/// Core's companion `CheckEphemeralSpends` (a *child* must sweep every
/// bit of dust its parents left behind) is a package-acceptance check;
/// this pool only ever admits one transaction at a time, so it isn't
/// ported here.
pub fn precheck_ephemeral(
    tx: &Transaction,
    dust_relay_fee: i64,
    fee: i64,
    modified_fee: i64,
) -> Result<(), &'static str> {
    if (fee != 0 || modified_fee != 0) && !dust_outputs(tx, dust_relay_fee).is_empty() {
        return Err("dust");
    }
    Ok(())
}

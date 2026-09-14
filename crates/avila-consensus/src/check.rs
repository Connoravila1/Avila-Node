//! Structural block and transaction validation: the parts of Core's `CheckTransaction`
//! (`consensus/tx_check.cpp`), `CheckBlock` and `ContextualCheckBlock`
//! (`validation.cpp`) that need only the block itself, its height, and its parent's
//! median-time-past — no UTXO set and no script execution.
//!
//! Three functions, in the order a node applies them:
//!
//! * [`check_transaction`] — context-free per-transaction rules (Core's
//!   `CheckTransaction`).
//! * [`check_block`] — context-free whole-block rules (Core's `CheckBlock` with
//!   `fCheckPOW`/`fCheckMerkleRoot` set): header proof-of-work, merkle root, size and
//!   coinbase structure, per-transaction checks, and the legacy sigop budget.
//! * [`contextual_check_block`] — the header-context-only half of Core's
//!   `ContextualCheckBlock`: transaction finality against the BIP113 locktime cutoff,
//!   the BIP34 height-in-coinbase prefix, BIP141 witness-commitment enforcement, and
//!   the block weight limit. It assumes [`check_block`] already passed, as Core does.
//!
//! Deliberately **not** here (each is recorded in `docs/RULE_INVENTORY.md`):
//!
//! * everything UTXO-dependent — `CheckTxInputs` (missing/spent inputs, coinbase
//!   maturity, input-vs-output value, fee range), P2SH and witness sigop cost
//!   (`GetTransactionSigOpCost` needs spent outputs), BIP30 duplicate-txid handling,
//!   and the BIP141 "no uncommitted witness" rule's full weighting — these belong to
//!   the connect-block layer;
//! * script *execution* — DER/CLTV/CSV/signature rules are enforcement flags inside
//!   [`crate::interpreter`];
//! * the BIP325 signet block-solution check lives in [`crate::signet`]
//!   ([`check_block`] calls it in Core's position — after the header PoW check,
//!   before the merkle check — and reports `bad-signet-blksig` on failure).
//!
//! Every error carries Core's reject-reason string via [`RuleError::reason`], so the
//! reference adapter can compare verdicts reason-for-reason once block-level
//! differential testing lands.

use std::collections::HashSet;

use thiserror::Error;

use crate::block::{Block, MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR};
use crate::params::Params;
use crate::pow;
use crate::script;
use crate::signet;
use crate::transaction::Transaction;

/// `consensus/amount.h`'s `MAX_MONEY`: 21 million BTC in satoshis.
pub const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

/// `consensus/consensus.h`'s `MAX_BLOCK_SIGOPS_COST`.
pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

/// `consensus/consensus.h`'s `LOCKTIME_THRESHOLD`: `nLockTime` values below it compare
/// against block height; at or above it, against the block-time cutoff.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// `CTxIn::SEQUENCE_FINAL` (`primitives/transaction.h`): a sequence number that makes
/// its input final regardless of `nLockTime`.
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// A reject reason a function in this module can produce. [`RuleError::reason`]
/// returns the exact string Core's `TxValidationState`/`BlockValidationState` would
/// carry, for reason-level comparison against a reference daemon.
pub trait RuleError {
    /// Core's reject reason for this failure (e.g. `"bad-txns-vin-empty"`).
    fn reason(&self) -> &'static str;
}

/// A failure of Core's `CheckTransaction` (`consensus/tx_check.cpp`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Error)]
pub enum TxRuleError {
    /// `vin` is empty.
    #[error("transaction has no inputs")]
    VinEmpty,
    /// `vout` is empty.
    #[error("transaction has no outputs")]
    VoutEmpty,
    /// `GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT`:
    /// the transaction alone cannot fit in a block, even before witness data.
    #[error("transaction's base size exceeds the block weight limit")]
    Oversize,
    /// An output carries a negative value (CVE-2010-5139).
    #[error("transaction output has a negative value")]
    VoutNegative,
    /// An output carries more than [`MAX_MONEY`] satoshis.
    #[error("transaction output value exceeds MAX_MONEY")]
    VoutTooLarge,
    /// The running sum of output values left the `0..=MAX_MONEY` range.
    #[error("transaction's total output value exceeds MAX_MONEY")]
    TxOutTotalTooLarge,
    /// Two inputs reference the same outpoint (CVE-2018-17144).
    #[error("transaction has duplicate inputs")]
    InputsDuplicate,
    /// A coinbase `scriptSig` is shorter than 2 or longer than 100 bytes.
    #[error("coinbase scriptSig length out of range")]
    BadCbLength,
    /// A non-coinbase input spends the null outpoint.
    #[error("non-coinbase transaction spends a null outpoint")]
    PrevoutNull,
}

impl RuleError for TxRuleError {
    fn reason(&self) -> &'static str {
        match self {
            TxRuleError::VinEmpty => "bad-txns-vin-empty",
            TxRuleError::VoutEmpty => "bad-txns-vout-empty",
            TxRuleError::Oversize => "bad-txns-oversize",
            TxRuleError::VoutNegative => "bad-txns-vout-negative",
            TxRuleError::VoutTooLarge => "bad-txns-vout-toolarge",
            TxRuleError::TxOutTotalTooLarge => "bad-txns-txouttotal-toolarge",
            TxRuleError::InputsDuplicate => "bad-txns-inputs-duplicate",
            TxRuleError::BadCbLength => "bad-cb-length",
            TxRuleError::PrevoutNull => "bad-txns-prevout-null",
        }
    }
}

/// A failure of Core's `CheckBlock` (`validation.cpp`), in check order.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Error)]
pub enum BlockRuleError {
    /// The header's claimed `nBits` does not satisfy [`pow::check_proof_of_work`]
    /// (Core's `CheckBlockHeader` inside `CheckBlock`).
    #[error("proof of work failed")]
    HighHash,
    /// `params.signet_blocks` is set and the block's BIP325 signet solution failed
    /// [`crate::signet::check_signet_block_solution`] — Core's
    /// `bad-signet-blksig` (`BLOCK_CONSENSUS`, `CheckBlock`).
    #[error("signet block signature validation failure")]
    BadSignetBlkSig,
    /// `hashMerkleRoot` does not match the computed txid merkle root.
    #[error("merkle root mismatch")]
    BadTxnMerkleRoot,
    /// The txid merkle computation detected a mutation pattern (CVE-2012-2459) —
    /// which includes a duplicated transaction appearing where it changes nothing
    /// about the committed root.
    #[error("duplicate transaction / merkle mutation detected")]
    BadTxnsDuplicate,
    /// The block has no transactions, claims more than `MAX_BLOCK_WEIGHT/4`
    /// transactions, or its no-witness serialized size exceeds the weight limit.
    #[error("block size limits failed")]
    BadBlkLength,
    /// The first transaction is not a coinbase.
    #[error("first transaction is not a coinbase")]
    BadCbMissing,
    /// A transaction after the first is a coinbase.
    #[error("more than one coinbase in block")]
    BadCbMultiple,
    /// A transaction inside the block failed [`check_transaction`].
    #[error("transaction check failed: {0}")]
    Tx(TxRuleError),
    /// Legacy signature operations exceed `MAX_BLOCK_SIGOPS_COST`.
    #[error("out-of-bounds sigop count")]
    BadBlkSigops,
}

impl RuleError for BlockRuleError {
    fn reason(&self) -> &'static str {
        match self {
            BlockRuleError::HighHash => "high-hash",
            BlockRuleError::BadSignetBlkSig => "bad-signet-blksig",
            BlockRuleError::BadTxnMerkleRoot => "bad-txnmrklroot",
            BlockRuleError::BadTxnsDuplicate => "bad-txns-duplicate",
            BlockRuleError::BadBlkLength => "bad-blk-length",
            BlockRuleError::BadCbMissing => "bad-cb-missing",
            BlockRuleError::BadCbMultiple => "bad-cb-multiple",
            BlockRuleError::Tx(tx) => tx.reason(),
            BlockRuleError::BadBlkSigops => "bad-blk-sigops",
        }
    }
}

/// A failure of the header-context part of Core's `ContextualCheckBlock`
/// (`validation.cpp`), in check order.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Error)]
pub enum ContextualBlockError {
    /// CSV is active at this height but the caller supplied no parent
    /// median-time-past, so the BIP113 locktime cutoff cannot be computed. This is a
    /// missing-context error, not a rule violation.
    #[error("parent median-time-past required but not supplied")]
    MissingMedianTimePast,
    /// A transaction's `nLockTime`/sequences are not satisfied by the block's height
    /// and locktime cutoff.
    #[error("non-final transaction")]
    TxNonFinal,
    /// BIP34 is active and the coinbase `scriptSig` does not begin with the block's
    /// serialized height.
    #[error("block height mismatch in coinbase")]
    BadCbHeight,
    /// A witness commitment output exists but the coinbase's first-input witness stack
    /// is not exactly one 32-byte item (the witness reserved value).
    #[error("invalid witness reserved value size")]
    BadWitnessNonceSize,
    /// The witness commitment output does not match the block's actual witness merkle
    /// root and reserved value.
    #[error("witness merkle commitment mismatch")]
    BadWitnessMerkleMatch,
    /// A transaction carries witness data but the block has no (or is not allowed a)
    /// witness commitment.
    #[error("unexpected witness data found")]
    UnexpectedWitness,
    /// [`Block::weight`] exceeds `MAX_BLOCK_WEIGHT`.
    #[error("block weight limit failed")]
    BadBlkWeight,
}

impl RuleError for ContextualBlockError {
    fn reason(&self) -> &'static str {
        match self {
            // Not a Core reason string: Core's assert means this state is unreachable
            // there; callers of this crate can supply incomplete context.
            ContextualBlockError::MissingMedianTimePast => "missing-mtp-context",
            ContextualBlockError::TxNonFinal => "bad-txns-nonfinal",
            ContextualBlockError::BadCbHeight => "bad-cb-height",
            ContextualBlockError::BadWitnessNonceSize => "bad-witness-nonce-size",
            ContextualBlockError::BadWitnessMerkleMatch => "bad-witness-merkle-match",
            ContextualBlockError::UnexpectedWitness => "unexpected-witness",
            ContextualBlockError::BadBlkWeight => "bad-blk-weight",
        }
    }
}

/// The header context [`contextual_check_block`] needs: the block's height and, when
/// CSV is active, its parent's median-time-past.
#[derive(Clone, Copy, Debug)]
pub struct BlockContext<'a> {
    /// The network's consensus parameters (carries the `*_height` deployment
    /// activation table).
    pub params: &'a Params,
    /// The candidate block's height (`pindexPrev->nHeight + 1`; `0` for genesis).
    pub height: u32,
    /// The parent block's median-time-past — the BIP113 `nLockTime` cutoff once CSV is
    /// active. `None` is only acceptable while CSV is inactive at [`Self::height`]
    /// (always true for a genesis block on the built-in networks); otherwise
    /// [`ContextualBlockError::MissingMedianTimePast`] is returned.
    pub parent_median_time_past: Option<u32>,
}

/// Core's `CheckTransaction` (`consensus/tx_check.cpp`): the context-free transaction
/// rules, in Core's order — non-empty `vin`/`vout`, base-size limit, per-output value
/// range and running total, duplicate-input rejection, and the coinbase/null-prevout
/// rules.
pub fn check_transaction(tx: &Transaction) -> Result<(), TxRuleError> {
    if tx.inputs.is_empty() {
        return Err(TxRuleError::VinEmpty);
    }
    if tx.outputs.is_empty() {
        return Err(TxRuleError::VoutEmpty);
    }
    // The no-witness size is charged, as witness data hasn't passed the malleability
    // checks yet (Core's comment in tx_check.cpp).
    if tx.size_without_witness() as u64 * u64::from(WITNESS_SCALE_FACTOR as u32)
        > MAX_BLOCK_WEIGHT as u64
    {
        return Err(TxRuleError::Oversize);
    }

    // CVE-2010-5139: negative or overflowing output values.
    let mut value_out = 0i64;
    for output in &tx.outputs {
        if output.value < 0 {
            return Err(TxRuleError::VoutNegative);
        }
        if output.value > MAX_MONEY {
            return Err(TxRuleError::VoutTooLarge);
        }
        // Every addend is non-negative here, so `checked_add` failing can only mean the
        // sum exceeded i64::MAX — far past MAX_MONEY. Core relies on MoneyRange after
        // (formally overflowing) addition; the checked form produces the same verdict.
        value_out = match value_out.checked_add(output.value) {
            Some(total) if total <= MAX_MONEY => total,
            _ => return Err(TxRuleError::TxOutTotalTooLarge),
        };
    }

    // CVE-2018-17144: duplicate inputs.
    let mut seen = HashSet::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        if !seen.insert(input.previous_output) {
            return Err(TxRuleError::InputsDuplicate);
        }
    }

    if tx.is_coinbase() {
        let len = tx.inputs[0].script_sig.len();
        if !(2..=100).contains(&len) {
            return Err(TxRuleError::BadCbLength);
        }
    } else {
        for input in &tx.inputs {
            if input.previous_output.is_null() {
                return Err(TxRuleError::PrevoutNull);
            }
        }
    }

    Ok(())
}

/// Core's `IsFinalTx` (`consensus/tx_verify.cpp`): whether `tx`'s `nLockTime` is
/// satisfied at `block_height` / `locktime_cutoff`, or all its sequences are final.
///
/// `locktime_cutoff` is the block's own timestamp before CSV activation and the
/// parent's median-time-past after (BIP113); [`contextual_check_block`] derives it.
#[must_use]
pub fn is_final_tx(tx: &Transaction, block_height: u32, locktime_cutoff: u32) -> bool {
    if tx.lock_time == 0 {
        return true;
    }
    let threshold = if tx.lock_time < LOCKTIME_THRESHOLD {
        u64::from(block_height)
    } else {
        u64::from(locktime_cutoff)
    };
    if u64::from(tx.lock_time) < threshold {
        return true;
    }
    tx.inputs
        .iter()
        .all(|input| input.sequence == SEQUENCE_FINAL)
}

/// Core's `CheckBlock` (`validation.cpp`) with `fCheckPOW` and `fCheckMerkleRoot` set —
/// the context-free whole-block rules, in Core's order:
///
/// 1. the header's proof of work;
/// 2. the txid merkle root (`hashMerkleRoot` match, then the CVE-2012-2459 mutation
///    flag — which is also where a duplicated transaction is caught);
/// 3. transaction-count and no-witness-size limits;
/// 4. exactly one coinbase, first;
/// 5. [`check_transaction`] on every transaction;
/// 6. the legacy sigop budget.
///
/// Contextual rules (finality, BIP34, witness commitments, weight) live in
/// [`contextual_check_block`]; UTXO-dependent rules are not yet implemented at all.
pub fn check_block(block: &Block, params: &Params) -> Result<(), BlockRuleError> {
    // CheckBlockHeader(block, state, consensus, fCheckPOW=true).
    pow::check_proof_of_work(&block.block_hash(), block.header.bits, params)
        .map_err(|_| BlockRuleError::HighHash)?;

    // Signet only: check the BIP325 block solution (Core's `CheckBlock` calls
    // `CheckSignetBlockSolution` at exactly this position — after CheckBlockHeader,
    // before the merkle root — gated on `signet_blocks && fCheckPOW`; our
    // `check_block` always checks PoW).
    if params.signet_blocks && !signet::check_signet_block_solution(block, params) {
        return Err(BlockRuleError::BadSignetBlkSig);
    }

    let (root, mutated) = block.merkle_root();
    if root != block.header.merkle_root {
        return Err(BlockRuleError::BadTxnMerkleRoot);
    }
    if mutated {
        return Err(BlockRuleError::BadTxnsDuplicate);
    }

    // Size limits — the transaction count and the no-witness serialized size, not the
    // full weight (that check is contextual, after witness-commitment verification).
    if block.transactions.is_empty()
        || block.transactions.len() as u64 * u64::from(WITNESS_SCALE_FACTOR as u32)
            > MAX_BLOCK_WEIGHT as u64
        || block.size_without_witness() as u64 * u64::from(WITNESS_SCALE_FACTOR as u32)
            > MAX_BLOCK_WEIGHT as u64
    {
        return Err(BlockRuleError::BadBlkLength);
    }

    // Exactly one coinbase, in first position. Emptiness was rejected above.
    if !block.transactions[0].is_coinbase() {
        return Err(BlockRuleError::BadCbMissing);
    }
    if block.transactions[1..].iter().any(Transaction::is_coinbase) {
        return Err(BlockRuleError::BadCbMultiple);
    }

    for tx in &block.transactions {
        check_transaction(tx).map_err(BlockRuleError::Tx)?;
    }

    let mut sig_ops = 0u64;
    for tx in &block.transactions {
        sig_ops = sig_ops.saturating_add(legacy_sig_op_count(tx));
    }
    if sig_ops * u64::from(WITNESS_SCALE_FACTOR as u32) > MAX_BLOCK_SIGOPS_COST {
        return Err(BlockRuleError::BadBlkSigops);
    }

    Ok(())
}

/// Core's `GetLegacySigOpCount` (`consensus/tx_verify.cpp`): the non-accurate sigop
/// count of every `scriptSig` and `scriptPubKey` in `tx`.
#[must_use]
pub fn legacy_sig_op_count(tx: &Transaction) -> u64 {
    tx.inputs
        .iter()
        .map(|input| input.script_sig.sig_ops(false))
        .sum::<u64>()
        + tx.outputs
            .iter()
            .map(|output| output.script_pubkey.sig_ops(false))
            .sum::<u64>()
}

/// The header-context half of Core's `ContextualCheckBlock` (`validation.cpp`), in
/// Core's order:
///
/// 1. every transaction must be final against the BIP113 locktime cutoff (parent MTP
///    once CSV is active, else the block's own time);
/// 2. BIP34's height-in-coinbase prefix once active;
/// 3. BIP141's witness-commitment rules once segwit is active — a present commitment
///    must verify against the witness merkle root and reserved value, and an absent
///    one (or segwit being inactive) forbids witness data entirely;
/// 4. the full block weight limit — deliberately last, after witness verification.
///
/// The caller is expected to have run [`check_block`] first (as Core runs `CheckBlock`
/// before `ContextualCheckBlock`); the function still never panics on structurally
/// degenerate input.
pub fn contextual_check_block(
    block: &Block,
    ctx: &BlockContext<'_>,
) -> Result<(), ContextualBlockError> {
    // BIP113: with CSV active the nLockTime cutoff is the parent's median-time-past;
    // before that it was the block's own timestamp. A deployment height `h` governs
    // the block *at* height `h` (Core's `DeploymentActiveAfter` tests
    // `pindexPrev->nHeight >= h - 1`).
    let locktime_cutoff = if ctx.height >= ctx.params.csv_height {
        ctx.parent_median_time_past
            .ok_or(ContextualBlockError::MissingMedianTimePast)?
    } else {
        block.header.time
    };
    for tx in &block.transactions {
        if !is_final_tx(tx, ctx.height, locktime_cutoff) {
            return Err(ContextualBlockError::TxNonFinal);
        }
    }

    // BIP34: the coinbase scriptSig must begin with the serialized block height.
    if ctx.height >= ctx.params.bip34_height {
        let expect = script::push_int(i64::from(ctx.height));
        let script_sig = block
            .transactions
            .first()
            .and_then(|coinbase| coinbase.inputs.first())
            .map_or(&[][..], |input| input.script_sig.as_bytes());
        if script_sig.len() < expect.len() || !script_sig.starts_with(&expect) {
            return Err(ContextualBlockError::BadCbHeight);
        }
    }

    // BIP141: when segwit is active, a present witness commitment must be correct;
    // an absent commitment (or segwit being inactive) forbids witness data.
    if ctx.height >= ctx.params.segwit_height
        && let Some(commitpos) = block.witness_commitment_output()
    {
        // `witness_commitment_output` only matches coinbase outputs ≥38 bytes, so the
        // [6..38] slice below is always in range.
        let expected = block
            .expected_witness_commitment()
            .ok_or(ContextualBlockError::BadWitnessNonceSize)?;
        let output_script = block.transactions[0].outputs[commitpos]
            .script_pubkey
            .as_bytes();
        if output_script[6..38] != expected[..] {
            return Err(ContextualBlockError::BadWitnessMerkleMatch);
        }
    } else if block.transactions.iter().any(Transaction::has_witness) {
        return Err(ContextualBlockError::UnexpectedWitness);
    }

    // Weight is checked last, after witness-commitment verification — the coinbase
    // witness is uncommitted until then and could otherwise inflate weight while the
    // block hash stayed constant (Core's comment in ContextualCheckBlock).
    if block.weight() > MAX_BLOCK_WEIGHT {
        return Err(ContextualBlockError::BadBlkWeight);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::hash::Txid;
    use crate::params::Network;
    use crate::transaction::{OutPoint, Script, TxIn, TxOut, Witness};

    fn input(txid_byte: u8, vout: u32, script: &[u8]) -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: Txid::from_bytes([txid_byte; 32]),
                vout,
            },
            script_sig: Script::new(script.to_vec()),
            sequence: SEQUENCE_FINAL,
            witness: Witness::default(),
        }
    }

    fn coinbase(script: &[u8]) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(script.to_vec()),
                sequence: SEQUENCE_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 50 * 100_000_000,
                script_pubkey: Script::new(vec![0x51]),
            }],
            lock_time: 0,
        }
    }

    fn spend_tx() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![input(1, 0, &[])],
            outputs: vec![TxOut {
                value: 1000,
                script_pubkey: Script::new(Vec::new()),
            }],
            lock_time: 0,
        }
    }

    fn block_with(txs: Vec<Transaction>, time: u32, bits: u32) -> Block {
        let mut header = crate::params::Network::Regtest.params().genesis_header;
        header.time = time;
        header.bits = crate::arith::CompactTarget(bits);
        Block {
            header,
            transactions: txs,
        }
    }

    /// Regtest's `0x207fffff` target is ~2^255, so a random header hash satisfies it
    /// only ~half the time — grind the nonce (deterministically, on fixed input) so
    /// `check_block` tests reach the rule under test instead of `HighHash`.
    fn grind_pow(block: &mut Block, params: &Params) {
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
            block.header.nonce += 1;
        }
    }

    // -- check_transaction -----------------------------------------------------

    #[test]
    fn check_transaction_rejects_empty_vin_and_vout() {
        let mut tx = spend_tx();
        tx.inputs.clear();
        assert_eq!(check_transaction(&tx), Err(TxRuleError::VinEmpty));
        tx.inputs.push(input(1, 0, &[]));
        tx.outputs.clear();
        assert_eq!(check_transaction(&tx), Err(TxRuleError::VoutEmpty));
    }

    #[test]
    fn check_transaction_rejects_oversize() {
        // Base size must exceed 1 MB for weight > 4_000_000.
        let mut tx = spend_tx();
        tx.inputs[0].script_sig = Script::new(vec![0u8; 1_000_100]);
        assert_eq!(check_transaction(&tx), Err(TxRuleError::Oversize));
    }

    #[test]
    fn check_transaction_value_range_rules() {
        let mut tx = spend_tx();
        tx.outputs[0].value = -1;
        assert_eq!(check_transaction(&tx), Err(TxRuleError::VoutNegative));
        tx.outputs[0].value = MAX_MONEY + 1;
        assert_eq!(check_transaction(&tx), Err(TxRuleError::VoutTooLarge));
        tx.outputs[0].value = MAX_MONEY;
        tx.outputs.push(TxOut {
            value: 1,
            script_pubkey: Script::new(Vec::new()),
        });
        assert_eq!(check_transaction(&tx), Err(TxRuleError::TxOutTotalTooLarge));
    }

    #[test]
    fn check_transaction_duplicate_inputs() {
        let mut tx = spend_tx();
        tx.inputs.push(tx.inputs[0].clone());
        assert_eq!(check_transaction(&tx), Err(TxRuleError::InputsDuplicate));
    }

    #[test]
    fn check_transaction_coinbase_script_length() {
        for len in [0usize, 1, 101] {
            let tx = coinbase(&vec![0u8; len]);
            assert_eq!(check_transaction(&tx), Err(TxRuleError::BadCbLength));
        }
        for len in [2usize, 100] {
            let tx = coinbase(&vec![0u8; len]);
            assert!(check_transaction(&tx).is_ok());
        }
    }

    #[test]
    fn check_transaction_null_prevout() {
        // A *single* null-prevout input is a coinbase, so the rule needs a multi-input
        // tx to fire: is_coinbase() requires exactly one input.
        let mut tx = spend_tx();
        tx.inputs.push(input(9, 1, &[]));
        tx.inputs[1].previous_output = OutPoint::NULL;
        assert_eq!(check_transaction(&tx), Err(TxRuleError::PrevoutNull));
        // ...but a coinbase (single null input) is fine.
        assert!(check_transaction(&coinbase(&[0x51, 0x51])).is_ok());
    }

    // -- is_final_tx -----------------------------------------------------------

    #[test]
    fn is_final_tx_locktime_and_sequences() {
        let mut tx = spend_tx();
        assert!(is_final_tx(&tx, 100, 1000)); // lock_time 0
        tx.lock_time = 100;
        assert!(is_final_tx(&tx, 101, 0));
        // lock_time unsatisfied but every sequence is final → still final.
        assert!(is_final_tx(&tx, 100, 0));
        tx.inputs[0].sequence = 0;
        // Now the unsatisfied lock_time actually binds.
        assert!(!is_final_tx(&tx, 100, 0));
        tx.lock_time = 200;
        assert!(!is_final_tx(&tx, 100, 0));
        // Time-based lock_time compares against the cutoff, not the height.
        tx.lock_time = LOCKTIME_THRESHOLD;
        assert!(is_final_tx(&tx, 0, LOCKTIME_THRESHOLD + 1));
        assert!(!is_final_tx(&tx, u32::MAX, LOCKTIME_THRESHOLD));
        assert!(is_final_tx(&tx, u32::MAX, LOCKTIME_THRESHOLD + 1));
    }

    // -- contextual_check_block: BIP34 ------------------------------------------

    fn ctx<'a>(params: &'a Params, height: u32, mtp: Option<u32>) -> BlockContext<'a> {
        BlockContext {
            params,
            height,
            parent_median_time_past: mtp,
        }
    }

    fn regtest_coinbase_at(height: u32) -> Transaction {
        let mut script = script::push_int(i64::from(height));
        script.extend_from_slice(&[0x51; 2]); // pad to ≥2 bytes after the push
        coinbase(&script)
    }

    #[test]
    fn bip34_height_prefix_enforced_when_active() {
        let params = Network::Regtest.params();
        let block = block_with(
            vec![regtest_coinbase_at(5)],
            params.genesis_header.time,
            0x207f_ffff,
        );
        // Height 4 requested but the coinbase carries 5 → reject.
        assert_eq!(
            contextual_check_block(&block, &ctx(&params, 4, Some(0))),
            Err(ContextualBlockError::BadCbHeight)
        );
        assert!(contextual_check_block(&block, &ctx(&params, 5, Some(0))).is_ok());
    }

    #[test]
    fn bip34_height_prefix_not_enforced_before_activation() {
        let mut params = Network::Regtest.params();
        params.bip34_height = 10;
        let block = block_with(
            vec![coinbase(&[0x51, 0x51])], // no height push
            params.genesis_header.time,
            0x207f_ffff,
        );
        assert!(contextual_check_block(&block, &ctx(&params, 5, Some(0))).is_ok());
    }

    // -- contextual_check_block: finality ---------------------------------------

    #[test]
    fn nonfinal_tx_rejected_with_csv_cutoff() {
        let params = Network::Regtest.params();
        // Regtest: CSV active from height 1 → parent MTP is the cutoff.
        let mut tx = spend_tx();
        tx.lock_time = LOCKTIME_THRESHOLD + 100;
        tx.inputs[0].sequence = 0; // non-final sequence so lock_time applies
        let block = block_with(
            vec![regtest_coinbase_at(3), tx],
            LOCKTIME_THRESHOLD + 200,
            0x207f_ffff,
        );
        // Parent MTP below the lock_time → non-final.
        assert_eq!(
            contextual_check_block(&block, &ctx(&params, 3, Some(LOCKTIME_THRESHOLD + 50))),
            Err(ContextualBlockError::TxNonFinal)
        );
        assert!(
            contextual_check_block(&block, &ctx(&params, 3, Some(LOCKTIME_THRESHOLD + 101)))
                .is_ok()
        );
        // With CSV active, missing MTP is a context error, not a pass.
        assert_eq!(
            contextual_check_block(&block, &ctx(&params, 3, None)),
            Err(ContextualBlockError::MissingMedianTimePast)
        );
    }

    #[test]
    fn pre_csv_cutoff_is_block_time() {
        let mut params = Network::Regtest.params();
        params.csv_height = 100; // inactive at our test heights
        let mut tx = spend_tx();
        tx.lock_time = LOCKTIME_THRESHOLD + 100;
        tx.inputs[0].sequence = 0;
        let block = block_with(
            vec![regtest_coinbase_at(3), tx],
            LOCKTIME_THRESHOLD + 101,
            0x207f_ffff,
        );
        // No parent MTP needed: cutoff is the block's own time.
        assert!(contextual_check_block(&block, &ctx(&params, 3, None)).is_ok());
    }

    // -- contextual_check_block: witness rules ----------------------------------

    fn witness_spend() -> Transaction {
        let mut tx = spend_tx();
        tx.inputs[0].witness = Witness::new(vec![vec![0xaa; 20], vec![0xbb; 33]]);
        tx
    }

    fn segwit_block(txs: Vec<Transaction>, time: u32) -> Block {
        let mut block = block_with(txs, time, 0x207f_ffff);
        // Recompute the txid merkle root for the mutated transaction set.
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        block
    }

    #[test]
    fn segwit_inactive_rejects_any_witness_data() {
        let mut params = Network::Regtest.params();
        params.segwit_height = 10; // not active at test height
        let block = segwit_block(vec![regtest_coinbase_at(5), witness_spend()], 0);
        assert_eq!(
            contextual_check_block(&block, &ctx(&params, 5, Some(0))),
            Err(ContextualBlockError::UnexpectedWitness)
        );
    }

    #[test]
    fn segwit_active_requires_commitment_for_witness_data() {
        let params = Network::Regtest.params(); // segwit active at 0
        let block = segwit_block(vec![regtest_coinbase_at(5), witness_spend()], 0);
        assert_eq!(
            contextual_check_block(&block, &ctx(&params, 5, Some(0))),
            Err(ContextualBlockError::UnexpectedWitness)
        );
    }

    #[test]
    fn segwit_commitment_verification() {
        let params = Network::Regtest.params();
        // Coinbase with the 32-byte reserved value and a witness-carrying spend.
        let mut cb = regtest_coinbase_at(5);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let mut block = segwit_block(vec![cb, witness_spend()], 0);

        // Append the correct commitment output.
        let commitment = block.expected_witness_commitment().unwrap();
        let mut commit_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commit_script.extend_from_slice(&commitment);
        block.transactions[0].outputs.push(TxOut {
            value: 0,
            script_pubkey: Script::new(commit_script),
        });
        // The coinbase changed → fix the committed merkle root.
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        assert!(contextual_check_block(&block, &ctx(&params, 5, Some(0))).is_ok());

        // Wrong commitment hash → bad-witness-merkle-match.
        let mut bad = block.clone();
        let mut mutated = bad.transactions[0].outputs[1]
            .script_pubkey
            .as_bytes()
            .to_vec();
        mutated[6] ^= 0xff;
        bad.transactions[0].outputs[1].script_pubkey = Script::new(mutated);
        assert_eq!(
            contextual_check_block(&bad, &ctx(&params, 5, Some(0))),
            Err(ContextualBlockError::BadWitnessMerkleMatch)
        );

        // Coinbase witness with two items → bad-witness-nonce-size.
        let mut bad_nonce = block.clone();
        bad_nonce.transactions[0].inputs[0].witness =
            Witness::new(vec![vec![0x42; 32], vec![0x00]]);
        assert_eq!(
            contextual_check_block(&bad_nonce, &ctx(&params, 5, Some(0))),
            Err(ContextualBlockError::BadWitnessNonceSize)
        );
    }

    #[test]
    fn segwit_active_no_witness_anywhere_passes_without_commitment() {
        let params = Network::Regtest.params();
        let block = segwit_block(vec![regtest_coinbase_at(5)], 0);
        assert!(contextual_check_block(&block, &ctx(&params, 5, Some(0))).is_ok());
    }

    #[test]
    fn overweight_block_rejected() {
        let params = Network::Regtest.params();
        // One spend tx with a ~4 MB witness → weight over the limit; witness data is
        // allowed because a valid commitment is present.
        let mut cb = regtest_coinbase_at(5);
        cb.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let mut fat = witness_spend();
        fat.inputs[0].witness = Witness::new(vec![vec![0u8; 4_000_100]]);
        let mut block = segwit_block(vec![cb, fat], 0);
        let commitment = block.expected_witness_commitment().unwrap();
        let mut commit_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commit_script.extend_from_slice(&commitment);
        block.transactions[0].outputs.push(TxOut {
            value: 0,
            script_pubkey: Script::new(commit_script),
        });
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        assert_eq!(
            contextual_check_block(&block, &ctx(&params, 5, Some(0))),
            Err(ContextualBlockError::BadBlkWeight)
        );
    }

    // -- check_block -----------------------------------------------------------

    #[test]
    fn check_block_accepts_real_fixture_blocks() {
        for (bytes, network) in [
            (
                include_bytes!("../../../fixtures/mainnet-block-000000.bin").as_slice(),
                Network::Mainnet,
            ),
            (
                include_bytes!("../../../fixtures/mainnet-block-000170.bin").as_slice(),
                Network::Mainnet,
            ),
            (
                include_bytes!("../../../fixtures/mainnet-block-100000.bin").as_slice(),
                Network::Mainnet,
            ),
            (
                include_bytes!("../../../fixtures/mainnet-block-segwit-small.bin").as_slice(),
                Network::Mainnet,
            ),
            (
                include_bytes!("../../../fixtures/mainnet-block-taproot-era-small.bin").as_slice(),
                Network::Mainnet,
            ),
            (
                include_bytes!("../../../fixtures/testnet4-block-000000.bin").as_slice(),
                Network::Testnet4,
            ),
        ] {
            let block = Block::decode(bytes).unwrap();
            assert!(
                check_block(&block, &network.params()).is_ok(),
                "{network:?} fixture rejected"
            );
        }
    }

    #[test]
    fn check_block_signet_genesis_and_signed_block_pass() {
        // The BIP325 solution check exempts the genesis block and verifies the
        // real challenge spend on later blocks — both fixtures must pass.
        for file in [
            include_bytes!("../../../fixtures/signet-block-000000.bin").as_slice(),
            include_bytes!("../../../fixtures/signet-block-000001.bin").as_slice(),
        ] {
            let block = Block::decode(file).unwrap();
            assert_eq!(check_block(&block, &Network::Signet.params()), Ok(()));
        }
    }

    #[test]
    fn check_block_rejects_wrong_pow_limit() {
        // Custom params whose pow_limit lies below the header's claimed bits →
        // check_proof_of_work fails → Core's "high-hash". (A foreign-network fixture
        // can't demonstrate this: a real genesis satisfies its own nBits, and its
        // target is under every built-in network's pow limit.)
        let mut params = Network::Regtest.params();
        params.pow_limit = crate::arith::Target(crate::arith::U256::from_u64(1));
        let block = block_with(vec![regtest_coinbase_at(0)], 0, 0x207f_ffff);
        assert_eq!(check_block(&block, &params), Err(BlockRuleError::HighHash));
    }

    #[test]
    fn check_block_rejects_merkle_mismatch() {
        let params = Network::Regtest.params();
        let mut block = block_with(vec![regtest_coinbase_at(0)], 0, 0x207f_ffff);
        // Corrupt the committed root (then re-grind: merkle_root is covered by the
        // block hash, so the mutation changes it).
        let mut bytes = block.header.merkle_root.to_bytes();
        bytes[0] ^= 0xff;
        block.header.merkle_root = crate::hash::MerkleRoot::from_bytes(bytes);
        grind_pow(&mut block, &params);
        assert_eq!(
            check_block(&block, &params),
            Err(BlockRuleError::BadTxnMerkleRoot)
        );
    }

    #[test]
    fn check_block_rejects_missing_and_multiple_coinbases() {
        let params = Network::Regtest.params();
        let mut block = block_with(vec![spend_tx()], 0, 0x207f_ffff);
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        grind_pow(&mut block, &params);
        assert_eq!(
            check_block(&block, &params),
            Err(BlockRuleError::BadCbMissing)
        );

        // Two *identical* coinbases would hit bad-txns-duplicate (merkle mutation)
        // before this check — use different scriptSigs so the txids differ.
        let mut block = block_with(
            vec![regtest_coinbase_at(0), regtest_coinbase_at(1)],
            0,
            0x207f_ffff,
        );
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        grind_pow(&mut block, &params);
        assert_eq!(
            check_block(&block, &params),
            Err(BlockRuleError::BadCbMultiple)
        );
    }

    #[test]
    fn check_block_rejects_excess_legacy_sigops() {
        let params = Network::Regtest.params();
        // 20_001 bare CHECKSIGs in a scriptPubKey → 80_004 sigop cost > 80_000.
        let mut tx = spend_tx();
        tx.outputs[0].script_pubkey = Script::new(vec![crate::script::OP_CHECKSIG; 20_001]);
        let mut block = block_with(vec![regtest_coinbase_at(0), tx], 0, 0x207f_ffff);
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        grind_pow(&mut block, &params);
        assert_eq!(
            check_block(&block, &params),
            Err(BlockRuleError::BadBlkSigops)
        );
    }

    // -- fixture-driven contextual coverage --------------------------------------

    #[test]
    fn contextual_check_block_accepts_real_blocks() {
        // Heights from fixtures/manifest.json. The segwit-era blocks are past CSV
        // activation, so a parent median-time-past must be supplied; `u32::MAX` makes
        // every nLockTime final and leaves the height/witness/weight rules fully
        // exercised.
        for (bytes, height) in [
            (
                include_bytes!("../../../fixtures/mainnet-block-000000.bin").as_slice(),
                0u32,
            ),
            (
                include_bytes!("../../../fixtures/mainnet-block-000170.bin").as_slice(),
                170,
            ),
            (
                include_bytes!("../../../fixtures/mainnet-block-100000.bin").as_slice(),
                100_000,
            ),
            (
                include_bytes!("../../../fixtures/mainnet-block-segwit-small.bin").as_slice(),
                482_229,
            ),
            (
                include_bytes!("../../../fixtures/mainnet-block-taproot-era-small.bin").as_slice(),
                709_645,
            ),
        ] {
            let params = Network::Mainnet.params();
            let block = Block::decode(bytes).unwrap();
            let context = BlockContext {
                params: &params,
                height,
                parent_median_time_past: Some(u32::MAX),
            };
            assert!(
                contextual_check_block(&block, &context).is_ok(),
                "mainnet fixture at height {height} rejected"
            );
        }
    }

    #[test]
    fn fixture_segwit_blocks_carry_valid_commitments() {
        // The segwit/taproot-era fixtures exercise the real witness-commitment path,
        // not just the "no witness data" fallback.
        for bytes in [
            include_bytes!("../../../fixtures/mainnet-block-segwit-small.bin").as_slice(),
            include_bytes!("../../../fixtures/mainnet-block-taproot-era-small.bin").as_slice(),
        ] {
            let block = Block::decode(bytes).unwrap();
            assert!(
                block.witness_commitment_output().is_some(),
                "fixture unexpectedly lacks a witness commitment"
            );
            assert!(block.transactions.iter().any(Transaction::has_witness));
        }
    }
}

//! Bounded, read-only block inspection for the in-process desktop client.
//!
//! Height queries prefer the active chain, then the best-header ancestry.
//! Returned identity and validation coverage are a snapshot, not a promise
//! that a later request will observe the same chain after a reorganization.

use avila_consensus::chainstate::Chainstate;
use avila_consensus::check::MAX_MONEY;
use avila_consensus::hash::{BlockHash, Txid};
use avila_consensus::undo_amounts::{UndoAmountsRequest, UndoAmountsResult};
use serde::{Deserialize, Serialize};

pub const MAX_TRANSACTION_PAGE: u16 = 250;
pub const MAX_TX_DETAIL_PAGE: u16 = 100;
const MAX_SCRIPT_PREFIX_BYTES: usize = 32;
const MAX_WITNESS_ITEMS_SHOWN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockLookup {
    Height(u32),
    Hash(BlockHash),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyState {
    Available,
    HeaderOnly,
    Pruned,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockSummary {
    pub hash: String,
    pub height: u32,
    pub previous_hash: String,
    pub next_hash: Option<String>,
    pub version: i32,
    pub bits: u32,
    pub time: u32,
    pub nonce: u32,
    pub merkle_root: String,
    pub active_chain: bool,
    /// Conservative: false when assumevalid is configured, or state is assumed.
    pub fully_checked: bool,
    pub snapshot_assumed: bool,
    pub body_state: BodyState,
    pub tx_count: Option<u32>,
    pub size: Option<u64>,
    pub weight: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockTxSummary {
    pub index: u32,
    pub txid: String,
    pub coinbase: bool,
    pub inputs: u32,
    pub outputs: u32,
    pub output_sats: i64,
    pub size: u64,
    pub weight: u64,
    pub has_witness: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum BlockLookupResult {
    NotFound,
    Found {
        block: BlockSummary,
        transactions: Vec<BlockTxSummary>,
        next_offset: Option<u32>,
    },
    Error(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockIdentity {
    pub hash: String,
    pub height: u32,
    pub active_chain: bool,
    pub fully_checked: bool,
    pub snapshot_assumed: bool,
    pub body_state: BodyState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmountUnknownReason {
    CoinbaseHasNoPrevoutAmount,
    PreviousOutputsNotLookedUp,
    UndoUnavailable,
    NotActiveChain,
    UndoHashMismatch,
    UndoTooLarge,
    UndoMalformed,
    InconsistentTransactionAmounts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmountSource {
    BlockUndo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxScriptSummary {
    pub byte_len: u32,
    pub hex_prefix: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInputDetail {
    pub index: u32,
    pub prev_txid: Option<String>,
    pub prev_vout: Option<u32>,
    pub sequence: u32,
    pub value_sats: Option<i64>,
    pub value_unknown_reason: Option<AmountUnknownReason>,
    pub script_sig: TxScriptSummary,
    pub witness_item_count: u32,
    pub witness_items: Vec<TxScriptSummary>,
    pub witness_items_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutputDetail {
    pub index: u32,
    pub value_sats: i64,
    pub address: Option<String>,
    pub script_pubkey: TxScriptSummary,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockTxDetail {
    pub block: BlockIdentity,
    pub tx_index: u32,
    pub txid: String,
    pub wtxid: String,
    pub version: u32,
    pub lock_time: u32,
    pub coinbase: bool,
    pub input_count: u32,
    pub output_count: u32,
    pub input_amount_sats: Option<i64>,
    pub input_amount_unknown_reason: Option<AmountUnknownReason>,
    pub fee_sats: Option<i64>,
    pub fee_unknown_reason: Option<AmountUnknownReason>,
    #[serde(default)]
    pub amount_source: Option<AmountSource>,
    pub inputs: Vec<TxInputDetail>,
    pub next_input_offset: Option<u32>,
    pub outputs: Vec<TxOutputDetail>,
    pub next_output_offset: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
pub enum BlockTxDetailResult {
    NotFound,
    BodyUnavailable { block: BlockIdentity },
    Found { detail: BlockTxDetail },
    Error(String),
}

/// Runs between sync ticks, away from the GUI's paint thread. At most one
/// bounded block is read, and only one bounded transaction page is returned.
pub(crate) fn inspect(
    cs: &Chainstate,
    lookup: BlockLookup,
    tx_offset: u32,
    tx_limit: u16,
) -> BlockLookupResult {
    let tree = cs.tree();
    let node = match lookup {
        BlockLookup::Hash(hash) => tree.get(&hash),
        BlockLookup::Height(height) => cs
            .chain()
            .get(height as usize)
            .and_then(|hash| tree.get(hash))
            .or_else(|| {
                tree.get_ancestor(&tree.tip().hash(), height)
                    .filter(|node| node.height == height)
            }),
    };
    let Some(node) = node else {
        return BlockLookupResult::NotFound;
    };
    let hash = node.hash();
    let active_chain = cs.chain().get(node.height as usize) == Some(&hash);
    let coverage = cs.validation_report();
    let snapshot_assumed = coverage.snapshot.as_ref().is_some_and(|snapshot| {
        !snapshot.verified
            && node.height <= snapshot.base_height
            && node.height > snapshot.replayed_height
    });
    let fully_checked = active_chain
        && node.height <= cs.checked_height()
        && !snapshot_assumed
        && tree.params().assume_valid.is_none();
    let mut summary = BlockSummary {
        hash: hash.to_string(),
        height: node.height,
        previous_hash: node.header.prev_block_hash.to_string(),
        next_hash: active_chain
            .then(|| cs.chain().get(node.height as usize + 1))
            .flatten()
            .map(ToString::to_string),
        version: node.header.version,
        bits: node.header.bits.0,
        time: node.header.time,
        nonce: node.header.nonce,
        merkle_root: node.header.merkle_root.to_string(),
        active_chain,
        fully_checked,
        snapshot_assumed,
        body_state: BodyState::Unavailable,
        tx_count: (node.n_tx != 0).then_some(node.n_tx),
        size: None,
        weight: None,
    };
    let Some(body) = cs.body(&hash) else {
        summary.body_state = if cs
            .store()
            .and_then(|store| store.position(&hash).map(|pos| store.is_pruned(pos)))
            == Some(true)
        {
            BodyState::Pruned
        } else if node.n_tx == 0 && node.n_chain_tx == 0 {
            // A snapshotted base can have n_tx == 0 while its persisted
            // cumulative transaction metadata is nonzero. Its missing body
            // is unexplained, not a header-only entry.
            BodyState::HeaderOnly
        } else {
            // Reopened stores cannot always prove why a historical body is
            // absent. Do not disguise unexplained missing data as pruning.
            BodyState::Unavailable
        };
        return BlockLookupResult::Found {
            block: summary,
            transactions: Vec::new(),
            next_offset: None,
        };
    };
    summary.body_state = BodyState::Available;
    summary.tx_count = Some(body.transactions.len() as u32);
    summary.size = Some(body.size_with_witness() as u64);
    summary.weight = Some(body.weight() as u64);
    let start = tx_offset as usize;
    let count = usize::from(tx_limit.clamp(1, MAX_TRANSACTION_PAGE));
    let mut transactions = Vec::with_capacity(count.min(body.transactions.len()));
    for (index, tx) in body.transactions.iter().enumerate().skip(start).take(count) {
        let Some(output_sats) = tx
            .outputs
            .iter()
            .try_fold(0i64, |sum, output| sum.checked_add(output.value))
        else {
            return BlockLookupResult::Error("Transaction output sum exceeds its range.".into());
        };
        transactions.push(BlockTxSummary {
            index: index as u32,
            txid: tx.txid().to_string(),
            coinbase: tx.is_coinbase(),
            inputs: tx.inputs.len() as u32,
            outputs: tx.outputs.len() as u32,
            output_sats,
            size: tx.size_with_witness() as u64,
            weight: tx.weight() as u64,
            has_witness: tx.has_witness(),
        });
    }
    let end = start.saturating_add(transactions.len());
    BlockLookupResult::Found {
        block: summary,
        transactions,
        next_offset: (end < body.transactions.len()).then_some(end as u32),
    }
}

/// Read bounded details for a transaction selected from an already inspected
/// block. Prevout amounts are sourced only from hash-pinned block undo; this
/// path never consults the current UTXO set, a txindex, or peers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn inspect_transaction(
    cs: &Chainstate,
    block_hash: BlockHash,
    txid: Txid,
    tx_index: u32,
    input_offset: u32,
    input_limit: u16,
    output_offset: u32,
    output_limit: u16,
) -> BlockTxDetailResult {
    let Some(node) = cs.tree().get(&block_hash) else {
        return BlockTxDetailResult::NotFound;
    };
    let active_chain = cs.chain().get(node.height as usize) == Some(&block_hash);
    let coverage = cs.validation_report();
    let snapshot_assumed = coverage.snapshot.as_ref().is_some_and(|snapshot| {
        !snapshot.verified
            && node.height <= snapshot.base_height
            && node.height > snapshot.replayed_height
    });
    let fully_checked = active_chain
        && node.height <= cs.checked_height()
        && !snapshot_assumed
        && cs.tree().params().assume_valid.is_none();
    let mut identity = BlockIdentity {
        hash: block_hash.to_string(),
        height: node.height,
        active_chain,
        fully_checked,
        snapshot_assumed,
        body_state: BodyState::Unavailable,
    };
    let Some(body) = cs.body(&block_hash) else {
        identity.body_state = if cs
            .store()
            .and_then(|store| store.position(&block_hash).map(|pos| store.is_pruned(pos)))
            == Some(true)
        {
            BodyState::Pruned
        } else if node.n_tx == 0 && node.n_chain_tx == 0 {
            BodyState::HeaderOnly
        } else {
            BodyState::Unavailable
        };
        return BlockTxDetailResult::BodyUnavailable { block: identity };
    };
    identity.body_state = BodyState::Available;
    let Some(tx) = body.transactions.get(tx_index as usize) else {
        return BlockTxDetailResult::NotFound;
    };
    if tx.txid() != txid {
        return BlockTxDetailResult::NotFound;
    }

    let coinbase = tx.is_coinbase();
    let (input_amount_sats, fee_sats, page_input_values, amount_unknown_reason) = if coinbase {
        (
            None,
            None,
            None,
            Some(AmountUnknownReason::CoinbaseHasNoPrevoutAmount),
        )
    } else {
        let input_limit = input_limit.clamp(1, MAX_TX_DETAIL_PAGE);
        let input_count = tx.inputs.len().min(u32::MAX as usize) as u32;
        let page_inputs = page_slice(&tx.inputs, input_offset, input_limit);
        let result = cs.inspect_undo_amounts(UndoAmountsRequest {
            height: node.height,
            block_hash,
            tx_index,
            block_tx_count: body.transactions.len().min(u32::MAX as usize) as u32,
            input_count,
            input_offset: input_offset.min(input_count),
            input_limit,
        });
        match result {
            UndoAmountsResult::Available(amounts) => {
                let output_total = tx.outputs.iter().try_fold(0i64, |sum, output| {
                    if !(0..=MAX_MONEY).contains(&output.value) {
                        return None;
                    }
                    sum.checked_add(output.value)
                        .filter(|total| *total <= MAX_MONEY)
                });
                let page_total = amounts.input_values.iter().try_fold(0i64, |sum, value| {
                    if !(0..=MAX_MONEY).contains(value) {
                        return None;
                    }
                    sum.checked_add(*value).filter(|total| *total <= MAX_MONEY)
                });
                let valid_values = amounts.input_values.len() == page_inputs.len()
                    && page_total.is_some_and(|page_sum| page_sum <= amounts.input_total_sats);
                let valid_input_total = (0..=MAX_MONEY).contains(&amounts.input_total_sats);
                let fee = output_total.and_then(|outputs| {
                    amounts
                        .input_total_sats
                        .checked_sub(outputs)
                        .filter(|fee| (0..=MAX_MONEY).contains(fee))
                });
                if valid_values && valid_input_total && fee.is_some() {
                    (
                        Some(amounts.input_total_sats),
                        fee,
                        Some(amounts.input_values),
                        None,
                    )
                } else {
                    (
                        None,
                        None,
                        None,
                        Some(AmountUnknownReason::InconsistentTransactionAmounts),
                    )
                }
            }
            UndoAmountsResult::Unavailable => {
                (None, None, None, Some(AmountUnknownReason::UndoUnavailable))
            }
            UndoAmountsResult::NotActiveChain => {
                (None, None, None, Some(AmountUnknownReason::NotActiveChain))
            }
            UndoAmountsResult::HashMismatch => (
                None,
                None,
                None,
                Some(AmountUnknownReason::UndoHashMismatch),
            ),
            UndoAmountsResult::TooLarge => {
                (None, None, None, Some(AmountUnknownReason::UndoTooLarge))
            }
            UndoAmountsResult::Malformed => {
                (None, None, None, Some(AmountUnknownReason::UndoMalformed))
            }
        }
    };
    let amounts_available = amount_unknown_reason.is_none();
    let inputs = page_slice(&tx.inputs, input_offset, input_limit)
        .iter()
        .enumerate()
        .map(|(page_index, input)| {
            let index = input_offset.saturating_add(page_index as u32);
            let prevout = input.previous_output;
            let value_sats = page_input_values
                .as_ref()
                .and_then(|values| values.get(page_index).copied());
            let witness_items = input
                .witness
                .items()
                .iter()
                .take(MAX_WITNESS_ITEMS_SHOWN)
                .map(|item| script_summary(item))
                .collect::<Vec<_>>();
            TxInputDetail {
                index,
                prev_txid: (!prevout.is_null()).then(|| prevout.txid.to_string()),
                prev_vout: (!prevout.is_null()).then_some(prevout.vout),
                sequence: input.sequence,
                value_sats,
                value_unknown_reason: value_sats
                    .is_none()
                    .then_some(amount_unknown_reason)
                    .flatten(),
                script_sig: script_summary(input.script_sig.as_bytes()),
                witness_item_count: input.witness.len().min(u32::MAX as usize) as u32,
                witness_items_truncated: input.witness.len() > MAX_WITNESS_ITEMS_SHOWN,
                witness_items,
            }
        })
        .collect::<Vec<_>>();
    let outputs = page_slice(&tx.outputs, output_offset, output_limit)
        .iter()
        .enumerate()
        .map(|(page_index, output)| TxOutputDetail {
            index: output_offset.saturating_add(page_index as u32),
            value_sats: output.value,
            address: avila_consensus::address::script_address(
                &output.script_pubkey,
                cs.tree().params(),
            ),
            script_pubkey: script_summary(output.script_pubkey.as_bytes()),
        })
        .collect::<Vec<_>>();
    let input_end = input_offset.saturating_add(inputs.len().min(u32::MAX as usize) as u32);
    let output_end = output_offset.saturating_add(outputs.len().min(u32::MAX as usize) as u32);
    BlockTxDetailResult::Found {
        detail: BlockTxDetail {
            block: identity,
            tx_index,
            txid: tx.txid().to_string(),
            wtxid: tx.wtxid().to_string(),
            version: tx.version,
            lock_time: tx.lock_time,
            coinbase,
            input_count: tx.inputs.len().min(u32::MAX as usize) as u32,
            output_count: tx.outputs.len().min(u32::MAX as usize) as u32,
            input_amount_sats,
            input_amount_unknown_reason: amount_unknown_reason,
            fee_sats,
            fee_unknown_reason: amount_unknown_reason,
            amount_source: amounts_available.then_some(AmountSource::BlockUndo),
            inputs,
            next_input_offset: (input_end < tx.inputs.len() as u32).then_some(input_end),
            outputs,
            next_output_offset: (output_end < tx.outputs.len() as u32).then_some(output_end),
        },
    }
}

fn page_slice<T>(items: &[T], offset: u32, limit: u16) -> &[T] {
    let start = (offset as usize).min(items.len());
    let count = usize::from(limit.clamp(1, MAX_TX_DETAIL_PAGE));
    &items[start..start.saturating_add(count).min(items.len())]
}

fn script_summary(bytes: &[u8]) -> TxScriptSummary {
    let prefix_len = bytes.len().min(MAX_SCRIPT_PREFIX_BYTES);
    TxScriptSummary {
        byte_len: bytes.len().min(u32::MAX as usize) as u32,
        hex_prefix: avila_consensus::hex::encode(&bytes[..prefix_len]),
        truncated: bytes.len() > prefix_len,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use avila_consensus::arith::CompactTarget;
    use avila_consensus::block::Block;
    use avila_consensus::check::SEQUENCE_FINAL;
    use avila_consensus::header::BlockHeader;
    use avila_consensus::params::Network;
    use avila_consensus::pow;
    use avila_consensus::script;
    use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

    #[test]
    fn lookup_result_serde_contract_round_trips_all_variants() {
        let block = BlockSummary {
            hash: "block-hash".into(),
            height: 9,
            previous_hash: "previous-hash".into(),
            next_hash: Some("next-hash".into()),
            version: 4,
            bits: 0x207f_ffff,
            time: 1_800_000_000,
            nonce: 42,
            merkle_root: "merkle-root".into(),
            active_chain: true,
            fully_checked: false,
            snapshot_assumed: true,
            body_state: BodyState::HeaderOnly,
            tx_count: Some(3),
            size: None,
            weight: Some(3_000),
        };
        let transaction = BlockTxSummary {
            index: 2,
            txid: "transaction-id".into(),
            coinbase: false,
            inputs: 1,
            outputs: 2,
            output_sats: 123,
            size: 200,
            weight: 500,
            has_witness: true,
        };
        let cases = [
            BlockLookupResult::NotFound,
            BlockLookupResult::Found {
                block,
                transactions: vec![transaction],
                next_offset: Some(3),
            },
            BlockLookupResult::Error("bounded inspection error".into()),
        ];

        for case in cases {
            let value = serde_json::to_value(&case).unwrap();
            let round_trip: BlockLookupResult = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(round_trip).unwrap(), value);
        }
        let found = serde_json::to_value(BlockLookupResult::Found {
            block: BlockSummary {
                hash: "block-hash".into(),
                height: 9,
                previous_hash: "previous-hash".into(),
                next_hash: None,
                version: 4,
                bits: 0x207f_ffff,
                time: 1_800_000_000,
                nonce: 42,
                merkle_root: "merkle-root".into(),
                active_chain: true,
                fully_checked: false,
                snapshot_assumed: false,
                body_state: BodyState::Available,
                tx_count: Some(1),
                size: Some(100),
                weight: Some(400),
            },
            transactions: Vec::new(),
            next_offset: None,
        })
        .unwrap();
        assert_eq!(found["status"], "found");
        assert_eq!(found["data"]["block"]["body_state"], "available");
        assert!(found["data"].get("next_offset").is_some());
        assert_eq!(serde_json::to_value(BodyState::Pruned).unwrap(), "pruned");
    }

    const REGTEST_BITS: u32 = 0x207f_ffff;
    const NOW: u32 = 1_800_000_000;

    fn regtest_params() -> avila_consensus::params::Params {
        Network::Regtest.params()
    }

    fn block_on(
        parent: &BlockHeader,
        transactions: Vec<Transaction>,
        params: &avila_consensus::params::Params,
    ) -> Block {
        let mut block = Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: parent.hash(),
                merkle_root: parent.merkle_root,
                time: parent.time + 1,
                bits: CompactTarget(REGTEST_BITS),
                nonce: 0,
            },
            transactions,
        };
        let (merkle_root, _) = block.merkle_root();
        block.header.merkle_root = merkle_root;
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
            block.header.nonce += 1;
        }
        block
    }

    fn coinbase(
        height: u32,
        params: &avila_consensus::params::Params,
        output_count: usize,
    ) -> Transaction {
        let mut script_sig = script::push_int(i64::from(height));
        script_sig.push(script::OP_1);
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(script_sig),
                sequence: SEQUENCE_FINAL,
                witness: Witness::default(),
            }],
            outputs: (0..output_count)
                .map(|_| TxOut {
                    value: avila_consensus::connect::block_subsidy(height, params),
                    script_pubkey: Script::new(vec![script::OP_1]),
                })
                .collect(),
            lock_time: 0,
        }
    }

    fn phantom_spend(tag: u32) -> Transaction {
        let mut txid = [0u8; 32];
        txid[..4].copy_from_slice(&tag.to_le_bytes());
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: avila_consensus::hash::Txid::from_bytes(txid),
                    vout: tag,
                },
                script_sig: Script::default(),
                sequence: SEQUENCE_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 0,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        }
    }

    fn mature_spend_blocks(params: &avila_consensus::params::Params) -> (Vec<Block>, Transaction) {
        let mut blocks = Vec::with_capacity(101);
        let mut parent = params.genesis_header;
        for height in 1..=100 {
            let block = block_on(&parent, vec![coinbase(height, params, 1)], params);
            parent = block.header;
            blocks.push(block);
        }
        let first_coinbase = &blocks[0].transactions[0];
        let spend = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: first_coinbase.txid(),
                    vout: 0,
                },
                script_sig: Script::new(vec![script::OP_1]),
                sequence: SEQUENCE_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: avila_consensus::connect::block_subsidy(1, params) - 1_000,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        let block = block_on(
            &parent,
            vec![coinbase(101, params, 1), spend.clone()],
            params,
        );
        blocks.push(block);
        (blocks, spend)
    }

    #[test]
    fn genesis_is_measured_and_unknown_height_is_absent() {
        let mut params = Network::Mainnet.params();
        params.assume_valid = None;
        let cs = Chainstate::new(&params);
        let BlockLookupResult::Found {
            block,
            transactions,
            next_offset,
        } = inspect(&cs, BlockLookup::Height(0), 0, u16::MAX)
        else {
            panic!("genesis must be inspectable")
        };
        assert_eq!(block.height, 0);
        assert!(block.active_chain && block.fully_checked);
        assert_eq!(block.body_state, BodyState::Available);
        assert_eq!(block.tx_count, Some(1));
        assert_eq!(transactions.len(), 1);
        assert!(transactions[0].coinbase);
        assert_eq!(transactions[0].output_sats, 5_000_000_000);
        assert_eq!(next_offset, None);
        assert!(matches!(
            inspect(&cs, BlockLookup::Height(1), 0, 100),
            BlockLookupResult::NotFound
        ));
        let BlockLookupResult::Found {
            transactions,
            next_offset,
            ..
        } = inspect(&cs, BlockLookup::Height(0), u32::MAX, 0)
        else {
            panic!("genesis remains inspectable")
        };
        assert!(transactions.is_empty());
        assert_eq!(next_offset, None);
    }

    #[test]
    fn configured_assumevalid_never_claims_all_scripts_checked() {
        let params = Network::Mainnet.params();
        assert!(params.assume_valid.is_some());
        let cs = Chainstate::new(&params);
        let BlockLookupResult::Found { block, .. } = inspect(&cs, BlockLookup::Height(0), 0, 1)
        else {
            panic!("genesis must be inspectable")
        };
        assert!(!block.fully_checked);
        let hash = cs.tree().tip().hash();
        let txid = cs.body(&hash).unwrap().transactions[0].txid();
        let BlockTxDetailResult::Found { detail } =
            inspect_transaction(&cs, hash, txid, 0, 0, 1, 0, 1)
        else {
            panic!("genesis transaction detail must be inspectable")
        };
        assert!(!detail.block.fully_checked);
        assert!(!detail.block.snapshot_assumed);
    }

    #[test]
    fn height_lookup_can_find_best_header_without_claiming_active_chain() {
        let params = regtest_params();
        let mut cs = Chainstate::new(&params);
        let header = block_on(
            &params.genesis_header,
            vec![coinbase(1, &params, 1)],
            &params,
        )
        .header;
        cs.accept_header(&header, NOW)
            .expect("regtest child header is valid");

        let BlockLookupResult::Found { block, .. } = inspect(&cs, BlockLookup::Height(1), 0, 100)
        else {
            panic!("best-header height should be inspectable");
        };
        assert!(!block.active_chain);
        assert!(!block.fully_checked);
        assert_eq!(block.body_state, BodyState::HeaderOnly);
        assert_eq!(block.hash, header.hash().to_string());
        assert!(matches!(
            inspect(&cs, BlockLookup::Height(2), 0, 100),
            BlockLookupResult::NotFound
        ));
        assert!(matches!(
            inspect(&cs, BlockLookup::Hash(header.hash()), 0, 100),
            BlockLookupResult::Found { .. }
        ));
        assert!(matches!(
            inspect_transaction(&cs, header.hash(), Txid::ZERO, 0, 0, 1, 0, 1),
            BlockTxDetailResult::BodyUnavailable {
                block: BlockIdentity {
                    body_state: BodyState::HeaderOnly,
                    active_chain: false,
                    fully_checked: false,
                    ..
                }
            }
        ));
    }

    #[test]
    fn transaction_pages_are_capped_at_250_and_continue_by_offset() {
        let params = regtest_params();
        let mut cs = Chainstate::new(&params);
        let mut transactions = vec![coinbase(1, &params, 1)];
        transactions.extend((1..=260).map(phantom_spend));
        let block = block_on(&params.genesis_header, transactions, &params);
        let hash = block.block_hash();
        // The body is retained before input resolution fails. Inspection remains
        // read-only and reports the body without treating the block as active.
        assert!(cs.accept_block(&block, NOW).is_err());

        let BlockLookupResult::Found {
            block,
            transactions: first,
            next_offset,
        } = inspect(&cs, BlockLookup::Hash(hash), 0, u16::MAX)
        else {
            panic!("stored body should be inspectable");
        };
        assert_eq!(block.tx_count, Some(261));
        assert_eq!(first.len(), usize::from(MAX_TRANSACTION_PAGE));
        assert_eq!(first.first().map(|tx| tx.index), Some(0));
        assert_eq!(first.last().map(|tx| tx.index), Some(249));
        assert_eq!(next_offset, Some(250));

        let BlockLookupResult::Found {
            transactions: second,
            next_offset,
            ..
        } = inspect(&cs, BlockLookup::Hash(hash), 250, u16::MAX)
        else {
            panic!("second transaction page should be inspectable");
        };
        assert_eq!(second.len(), 11);
        assert_eq!(second.first().map(|tx| tx.index), Some(250));
        assert_eq!(second.last().map(|tx| tx.index), Some(260));
        assert_eq!(next_offset, None);
    }

    #[test]
    fn transaction_details_pin_identity_bound_script_and_page_both_sides() {
        let params = regtest_params();
        let mut cs = Chainstate::new(&params);
        let tx = Transaction {
            version: 2,
            inputs: (0..3)
                .map(|index| TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_bytes([index as u8 + 1; 32]),
                        vout: index as u32,
                    },
                    script_sig: Script::new(vec![index as u8; 40]),
                    sequence: 0xffff_fffe - index as u32,
                    witness: Witness::new((0..10).map(|n| vec![n; 40]).collect()),
                })
                .collect(),
            outputs: (0..3)
                .map(|index| TxOut {
                    value: 100 + index,
                    script_pubkey: Script::new(vec![script::OP_1; 40]),
                })
                .collect(),
            // A zero locktime is final even with the nonfinal sequences below.
            lock_time: 0,
        };
        let txid = tx.txid();
        let mut coinbase = coinbase(1, &params, 1);
        coinbase.inputs[0].witness = Witness::new(vec![vec![0x42; 32]]);
        let provisional = block_on(&params.genesis_header, vec![coinbase, tx.clone()], &params);
        let commitment = provisional
            .expected_witness_commitment()
            .expect("well-formed coinbase reserved value produces a commitment");
        let mut commitment_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment_script.extend_from_slice(&commitment);
        let mut transactions = provisional.transactions;
        transactions[0].outputs.push(TxOut {
            value: 0,
            script_pubkey: Script::new(commitment_script),
        });
        // Recompute the merkle root and proof of work after changing coinbase.
        let block = block_on(&params.genesis_header, transactions, &params);
        let block_hash = block.block_hash();
        // A deliberately unresolved prevout leaves the stored body available
        // while making it unsuitable as an active-chain validation result.
        // Keep the failure precise so a fixture-rule error cannot masquerade
        // as the intended body-retention path.
        assert_eq!(
            cs.accept_block(&block, NOW),
            Err(avila_consensus::chainstate::BlockRejection::Connect(
                avila_consensus::connect::ConnectError::InputsMissingOrSpent
            ))
        );

        let BlockTxDetailResult::Found { detail } =
            inspect_transaction(&cs, block_hash, txid, 1, 1, 1, 1, 1)
        else {
            panic!("stored transaction details should be inspectable");
        };
        assert_eq!(detail.block.hash, block_hash.to_string());
        assert!(!detail.block.active_chain);
        assert_eq!(detail.tx_index, 1);
        assert_eq!(detail.txid, txid.to_string());
        assert_eq!(detail.wtxid, tx.wtxid().to_string());
        assert_eq!(detail.version, 2);
        assert_eq!(detail.lock_time, 0);
        assert_eq!(detail.input_count, 3);
        assert_eq!(detail.output_count, 3);
        assert_eq!(detail.inputs[0].index, 1);
        assert_eq!(detail.inputs[0].prev_vout, Some(1));
        assert_eq!(detail.inputs[0].sequence, 0xffff_fffd);
        assert_eq!(detail.inputs[0].value_sats, None);
        assert_eq!(
            detail.inputs[0].value_unknown_reason,
            Some(AmountUnknownReason::NotActiveChain)
        );
        assert_eq!(detail.inputs[0].script_sig.byte_len, 40);
        assert_eq!(detail.inputs[0].script_sig.hex_prefix.len(), 64);
        assert!(detail.inputs[0].script_sig.truncated);
        assert_eq!(detail.inputs[0].witness_item_count, 10);
        assert_eq!(
            detail.inputs[0].witness_items.len(),
            MAX_WITNESS_ITEMS_SHOWN
        );
        assert!(detail.inputs[0].witness_items_truncated);
        assert_eq!(detail.outputs[0].index, 1);
        assert_eq!(detail.outputs[0].value_sats, 101);
        assert_eq!(detail.outputs[0].script_pubkey.byte_len, 40);
        assert!(detail.outputs[0].script_pubkey.truncated);
        assert_eq!(detail.input_amount_sats, None);
        assert_eq!(detail.fee_sats, None);
        assert_eq!(
            detail.fee_unknown_reason,
            Some(AmountUnknownReason::NotActiveChain)
        );
        assert_eq!(detail.amount_source, None);
        assert_eq!(detail.next_input_offset, Some(2));
        assert_eq!(detail.next_output_offset, Some(2));

        // The node-side bound remains effective even for a trusted internal
        // request that bypasses RPC validation.
        let BlockTxDetailResult::Found { detail } =
            inspect_transaction(&cs, block_hash, txid, 1, 0, u16::MAX, 0, u16::MAX)
        else {
            panic!("stored transaction details should remain inspectable");
        };
        assert_eq!(detail.inputs.len(), 3);
        assert_eq!(detail.outputs.len(), 3);
        assert_eq!(detail.next_input_offset, None);
        assert_eq!(detail.next_output_offset, None);
        assert!(matches!(
            inspect_transaction(&cs, block_hash, txid, 0, 0, 1, 0, 1),
            BlockTxDetailResult::NotFound
        ));
        assert!(matches!(
            inspect_transaction(&cs, block_hash, Txid::ZERO, 1, 0, 1, 0, 1),
            BlockTxDetailResult::NotFound
        ));
    }

    #[test]
    fn undo_amounts_are_pinned_and_paginated_for_active_transactions() {
        let params = regtest_params();
        let (blocks, spend) = mature_spend_blocks(&params);
        let txid = spend.txid();
        let mut cs = Chainstate::new(&params);
        for block in &blocks {
            cs.accept_block(block, NOW)
                .expect("mature spend-chain block should connect");
        }
        let block_hash = blocks.last().expect("height 101 exists").block_hash();

        let BlockTxDetailResult::Found { detail } =
            inspect_transaction(&cs, block_hash, txid, 1, 0, 1, 0, 1)
        else {
            panic!("active transaction detail should be available");
        };
        assert!(detail.block.active_chain);
        assert_eq!(
            detail.input_amount_sats,
            Some(avila_consensus::connect::block_subsidy(1, &params))
        );
        assert_eq!(detail.fee_sats, Some(1_000));
        assert_eq!(detail.amount_source, Some(AmountSource::BlockUndo));
        assert_eq!(detail.inputs.len(), 1);
        assert_eq!(detail.inputs[0].value_sats, detail.input_amount_sats);
        assert_eq!(detail.inputs[0].value_unknown_reason, None);
        let mut legacy_json = serde_json::to_value(&detail).expect("detail serializes");
        legacy_json
            .as_object_mut()
            .expect("detail is an object")
            .remove("amount_source");
        let legacy_detail: BlockTxDetail =
            serde_json::from_value(legacy_json).expect("missing optional source is compatible");
        assert_eq!(legacy_detail.amount_source, None);

        // The result remains pinned to the exact txid/index and reports
        // per-page values without depending on a current UTXO lookup.
        let BlockTxDetailResult::Found { detail: empty_page } =
            inspect_transaction(&cs, block_hash, txid, 1, 1, u16::MAX, 0, 1)
        else {
            panic!("out-of-range input page should still return transaction detail");
        };
        assert_eq!(empty_page.inputs.len(), 0);
        assert_eq!(empty_page.input_amount_sats, detail.input_amount_sats);
        assert_eq!(empty_page.fee_sats, detail.fee_sats);
        let BlockTxDetailResult::Found {
            detail: past_end_page,
        } = inspect_transaction(&cs, block_hash, txid, 1, u32::MAX, u16::MAX, 0, 1)
        else {
            panic!("input offset past the end should return bounded detail");
        };
        assert_eq!(past_end_page.inputs.len(), 0);
        assert_eq!(past_end_page.input_amount_sats, detail.input_amount_sats);
        assert_eq!(past_end_page.fee_sats, detail.fee_sats);

        // Flush the same chain through the coins backend so inspection also
        // exercises the stored, hash-tagged undo path.
        let dir = std::env::temp_dir().join(format!(
            "avila-inspect-undo-{}-{}",
            std::process::id(),
            block_hash
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut disk = Chainstate::with_store_coinsdb(&dir, &params, NOW, 1 << 20)
            .expect("temporary block/coins stores open");
        for block in &blocks {
            disk.accept_block(block, NOW)
                .expect("same mature spend-chain block should connect on disk");
        }
        disk.flush().expect("block bodies and undo data flush");
        let BlockTxDetailResult::Found {
            detail: stored_detail,
        } = inspect_transaction(&disk, block_hash, txid, 1, 0, 1, 0, 1)
        else {
            panic!("stored active transaction details should be available");
        };
        assert_eq!(stored_detail.input_amount_sats, detail.input_amount_sats);
        assert_eq!(stored_detail.fee_sats, detail.fee_sats);
        assert_eq!(stored_detail.amount_source, Some(AmountSource::BlockUndo));
        drop(disk);
        std::fs::remove_dir_all(dir).expect("temporary inspection stores are removable");
    }
}

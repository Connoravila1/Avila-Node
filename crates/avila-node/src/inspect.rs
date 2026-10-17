//! Bounded, read-only block inspection for the in-process desktop client.
//!
//! Height queries prefer the active chain, then the best-header ancestry.
//! Returned identity and validation coverage are a snapshot, not a promise
//! that a later request will observe the same chain after a reorganization.

use avila_consensus::chainstate::Chainstate;
use avila_consensus::hash::BlockHash;
use serde::{Deserialize, Serialize};

pub const MAX_TRANSACTION_PAGE: u16 = 250;

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
}

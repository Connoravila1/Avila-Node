//! Block-template construction — the engine behind Core's
//! `getblocktemplate` RPC: greedily fill a block with the pool's
//! highest-fee-rate transactions, respecting in-pool parent order, the
//! weight cap, the subsidy, and the BIP141 witness commitment.
//!
//! Scope honesty: selection is greedy by *individual* fee rate. Core
//! mines by ancestor-feerate packages — a low-fee parent never blocks
//! its high-fee child here because inclusion is dependency-ordered,
//! but a low-fee child riding a high-fee parent is not pulled up the
//! way `UpdatePackages` would pull it. Package-feerate mining remains
//! open work.

use std::collections::HashSet;

use avila_consensus::arith::CompactTarget;
use avila_consensus::block::{Block, MAX_BLOCK_WEIGHT};
use avila_consensus::connect::block_subsidy;
use avila_consensus::hash::{BlockHash, Txid};
use avila_consensus::header::BlockHeader;
use avila_consensus::script;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

use crate::Mempool;

/// BIP141's witness-commitment script magic: `OP_RETURN aa21a9ed …`.
pub const WITNESS_COMMITMENT_MAGIC: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Space reserved for the coinbase and future commitment output.
const COINBASE_RESERVE_WEIGHT: usize = 1_000;

/// A ready-to-mine block candidate built from the pool.
#[derive(Clone, Debug)]
pub struct BlockTemplate {
    /// The block — coinbase first, pool transactions in inclusion
    /// order, merkle root and (when needed) witness commitment set.
    pub block: Block,
    /// The height this block would connect at.
    pub height: u32,
    /// Total pool fees claimed by the coinbase, in satoshis.
    pub fees: i64,
    /// Pooled transactions included.
    pub tx_count: usize,
    /// Total block weight including the coinbase.
    pub weight: usize,
}

/// Why a template could not be built.
#[derive(Clone, Debug, thiserror::Error)]
pub enum TemplateError {
    /// The chain has no tip context to build on.
    #[error("no median-time-past context for the tip")]
    NoContext,
    /// Difficulty retarget failed for the next height.
    #[error("difficulty: {0}")]
    Difficulty(String),
}

impl Mempool {
    /// Builds a candidate block paying `subsidy + fees` to
    /// `miner_script_pubkey` — Core's `BlockAssembler::CreateNewBlock`
    /// greedy pass.
    ///
    /// Selection: entries sorted by fee rate, a tx is included only
    /// when every in-pool parent is already included (dependency order)
    /// and the block stays under `MAX_BLOCK_WEIGHT`.
    ///
    /// # Errors
    ///
    /// [`TemplateError::NoContext`] when the tip lacks a median-time-past
    /// and [`TemplateError::Difficulty`] on a retarget failure.
    pub fn build_template(
        &self,
        cs: &avila_consensus::chainstate::Chainstate,
        miner_script_pubkey: Script,
        now: u32,
    ) -> Result<BlockTemplate, TemplateError> {
        let tip = cs.tip_hash();
        let tip_node = cs.tree().tip();
        let height = tip_node.height + 1;
        let mtp = cs
            .tree()
            .median_time_past(&tip)
            .ok_or(TemplateError::NoContext)?;
        let bits = avila_consensus::pow::required_bits(
            tip_node.height,
            &tip_node.header,
            now.max(mtp + 1),
            cs.tree().params(),
            cs.tree(),
        )
        .map_err(|e| TemplateError::Difficulty(e.to_string()))?;

        // Greedy fill: fee-rate order, dependency-respecting.
        let mut entries: Vec<_> = self.entries().collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.fee * 1000 / e.vsize.max(1) as i64));
        let mut chosen: Vec<&crate::MempoolEntry> = Vec::new();
        let mut chosen_ids: HashSet<Txid> = HashSet::new();
        let mut weight = 0usize;
        let mut fees = 0i64;
        // Multiple passes: a tx skipped for a not-yet-included parent may
        // become includable once the parent lands.
        loop {
            let mut progress = false;
            for entry in &entries {
                let txid = entry.tx.txid();
                if chosen_ids.contains(&txid) {
                    continue;
                }
                if weight + entry.tx.weight() > MAX_BLOCK_WEIGHT - COINBASE_RESERVE_WEIGHT {
                    continue;
                }
                // Every pooled parent must already be in the block.
                let deps_met = entry.tx.inputs.iter().all(|i| {
                    !self.has_entry(&i.previous_output.txid)
                        || chosen_ids.contains(&i.previous_output.txid)
                });
                if !deps_met {
                    continue;
                }
                chosen_ids.insert(txid);
                weight += entry.tx.weight();
                fees += entry.fee;
                chosen.push(entry);
                progress = true;
            }
            if !progress {
                break;
            }
        }

        // Coinbase: BIP34 height prefix, subsidy + fees to the miner.
        let subsidy = block_subsidy(height, cs.tree().params());
        let txs: Vec<(Transaction, i64)> = chosen.iter().map(|e| (e.tx.clone(), e.fee)).collect();
        let block = Self::assemble_block(
            cs,
            miner_script_pubkey,
            &txs,
            height,
            &tip_node.header,
            tip,
            mtp,
            bits,
            subsidy,
            now,
        )?;
        Ok(BlockTemplate {
            weight: block.weight(),
            block,
            height,
            fees,
            tx_count: chosen.len(),
        })
    }

    /// Assembles the candidate block — the tail of [`build_template`]
    /// factored out so `generateblock` can mine an explicit,
    /// caller-ordered transaction set (Core's `generateblock`
    /// semantics: exactly the listed txs, in order, plus the
    /// coinbase). Returns the block plus the count of non-coinbase
    /// transactions included.
    #[allow(clippy::too_many_arguments)]
    fn assemble_block(
        cs: &avila_consensus::chainstate::Chainstate,
        miner_script_pubkey: Script,
        txs: &[(Transaction, i64)],
        height: u32,
        tip_header: &avila_consensus::header::BlockHeader,
        tip: BlockHash,
        mtp: u32,
        bits: CompactTarget,
        subsidy: i64,
        now: u32,
    ) -> Result<Block, TemplateError> {
        // Core's CreateNewBlock adds the witness commitment to every
        // block once segwit is active — even with no witness txs the
        // coinbase carries the reserved value and the zero-root
        // commitment (`6a24aa21a9ed…`), which is what
        // getblocktemplate's `default_witness_commitment` reports.
        let segwit_active =
            avila_consensus::script::block_script_flags(cs.tree().params(), height, &tip)
                .contains(avila_consensus::script::ScriptFlags::WITNESS);
        let has_witness = segwit_active
            || txs
                .iter()
                .any(|(tx, _)| tx.inputs.iter().any(|i| !i.witness.is_empty()));
        let fees: i64 = txs.iter().map(|(_, fee)| fee).sum();
        let mut coinbase = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::ZERO,
                    vout: u32::MAX,
                },
                // Core's `CScript() << nHeight << OP_0`: the OP_N prefix
                // alone is a single byte at heights 1–16, below the
                // consensus coinbase-scriptSig minimum — the trailing
                // OP_0 keeps even the shortest height encodings valid.
                script_sig: Script::new({
                    let mut s = script::push_int(i64::from(height));
                    s.push(script::OP_0);
                    s
                }),
                sequence: u32::MAX,
                witness: if has_witness {
                    // BIP141: the coinbase carries the 32-byte nonce slot.
                    Witness::new(vec![vec![0u8; 32]])
                } else {
                    Witness::default()
                },
            }],
            outputs: vec![TxOut {
                value: subsidy + fees,
                script_pubkey: miner_script_pubkey,
            }],
            lock_time: 0,
        };

        // Core's ComputeBlockVersion: VERSIONBITS_TOP_BITS plus the bit
        // of every deployment in started/locked_in at the tip.
        let params = cs.tree().params();
        let mut version = 0x2000_0000i32;
        for dep in params.bip9_deployments.iter() {
            let st = avila_consensus::bip9::state(cs.tree(), Some(&tip), dep, params);
            use avila_consensus::bip9::Bip9State;
            if matches!(st, Bip9State::Started | Bip9State::LockedIn) {
                version |= 1 << dep.bit;
            }
        }

        let mut block = Block {
            header: BlockHeader {
                version,
                prev_block_hash: tip,
                merkle_root: tip_header.merkle_root,
                time: now.max(mtp + 1),
                bits,
                nonce: 0,
            },
            transactions: Vec::with_capacity(txs.len() + 1),
        };
        block.transactions.push(coinbase.clone());
        for (tx, _) in txs {
            block.transactions.push(tx.clone());
        }

        if has_witness {
            // BIP141: OP_RETURN aa21a9ed || sha256d(wtxid_root || nonce).
            let wroot = block.witness_merkle_root();
            let mut commitment_data = [0u8; 64];
            commitment_data[..32].copy_from_slice(wroot.as_bytes());
            // nonce = the coinbase witness item (32 zero bytes).
            let commitment = avila_consensus::hash::sha256d(&commitment_data);
            let mut spk = vec![script::OP_RETURN];
            let mut payload = WITNESS_COMMITMENT_MAGIC.to_vec();
            payload.extend_from_slice(&commitment);
            spk.extend_from_slice(&script::push_slice(&payload));
            coinbase.outputs.push(TxOut {
                value: 0,
                script_pubkey: Script::new(spk),
            });
            block.transactions[0] = coinbase;
        }

        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        Ok(block)
    }

    /// `generateblock`'s tx set: a block containing exactly `txs` in
    /// the caller's order plus the coinbase — no pool selection. `txs`
    /// pairs each transaction with its fee in sats so the coinbase
    /// carries subsidy + fees, matching `CreateNewBlock`'s payout.
    ///
    /// # Errors
    ///
    /// Same template failures as [`Self::build_template`]
    /// ([`TemplateError::NoContext`], [`TemplateError::Difficulty`]).
    pub fn build_explicit_block(
        &self,
        cs: &avila_consensus::chainstate::Chainstate,
        miner_script_pubkey: Script,
        txs: &[(Transaction, i64)],
        now: u32,
    ) -> Result<Block, TemplateError> {
        let tip = cs.tip_hash();
        let tip_node = cs.tree().tip();
        let height = tip_node.height + 1;
        let mtp = cs
            .tree()
            .median_time_past(&tip)
            .ok_or(TemplateError::NoContext)?;
        let bits = avila_consensus::pow::required_bits(
            tip_node.height,
            &tip_node.header,
            now.max(mtp + 1),
            cs.tree().params(),
            cs.tree(),
        )
        .map_err(|e| TemplateError::Difficulty(e.to_string()))?;
        let subsidy = block_subsidy(height, cs.tree().params());
        Self::assemble_block(
            cs,
            miner_script_pubkey,
            txs,
            height,
            &tip_node.header,
            tip,
            mtp,
            bits,
            subsidy,
            now,
        )
    }
}

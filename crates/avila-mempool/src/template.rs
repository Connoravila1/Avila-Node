//! Block-template construction — the engine behind Core's
//! `getblocktemplate` RPC: `BlockAssembler::addPackageTxs` — ancestor-
//! feerate package selection. Every pool entry scores by the minimum
//! of its own modified feerate and its whole in-pool ancestor
//! package's feerate; when a package is selected its descendants'
//! scores are rewritten (`UpdatePackagesForAdded`) so the next picks
//! see the not-yet-mined remainder.
//!
//! Beyond ordering, the checks mirror Core's: `TestPackage` (weight
//! in vsize terms, sigop cost), `TestPackageTransactions` (nLockTime
//! finality vs the tip's median time past), `SortForBlock` (ancestor-
//! count order with txid tie-break), and the 1000-consecutive-failure
//! early exit when the block is nearly full.

use std::collections::{HashMap, HashSet};

use avila_consensus::arith::CompactTarget;
use avila_consensus::block::{Block, MAX_BLOCK_WEIGHT};
use avila_consensus::check::MAX_BLOCK_SIGOPS_COST;
use avila_consensus::connect::block_subsidy;
use avila_consensus::hash::{BlockHash, Txid};
use avila_consensus::header::BlockHeader;
use avila_consensus::script;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

use crate::Mempool;

/// BIP141's witness-commitment script magic: `OP_RETURN aa21a9ed …`.
pub const WITNESS_COMMITMENT_MAGIC: [u8; 4] = [0xaa, 0x21, 0xa9, 0xed];

/// Core's `DEFAULT_BLOCK_RESERVED_WEIGHT` (`policy/policy.h`) — weight
/// budgeted for the coinbase transaction (and witness commitment) when
/// selecting mempool transactions for a template. Overridable via
/// [`Mempool::set_block_reserved_weight`].
pub const DEFAULT_BLOCK_RESERVED_WEIGHT: usize = 8_000;

/// Core's `MINIMUM_BLOCK_RESERVED_WEIGHT` — the floor Core clamps
/// `-blockreservedweight` to (and refuses to start below); a smaller
/// reserve risks a coinbase that doesn't fit its own budget.
pub const MINIMUM_BLOCK_RESERVED_WEIGHT: usize = 2_000;

/// Core's `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS` — sigop cost
/// budgeted for the coinbase's own outputs (payouts, witness commitment)
/// out of `MAX_BLOCK_SIGOPS_COST` when selecting mempool transactions.
/// Overridable via [`Mempool::set_coinbase_max_additional_sigops`].
pub const DEFAULT_COINBASE_MAX_ADDITIONAL_SIGOPS: u64 = 400;

/// Core's `BLOCK_FULL_ENOUGH_WEIGHT_DELTA` (`node/miner.cpp`) — once
/// 1000 candidates in a row fail to fit (`MAX_CONSECUTIVE_FAILURES`),
/// treat the block as full once fewer than this much weight remains,
/// rather than scanning the rest of the pool for a smaller fit.
const BLOCK_FULL_ENOUGH_WEIGHT_DELTA: usize = 4_000;

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
    /// The assembled block's weight exceeds `MAX_BLOCK_WEIGHT` — the
    /// real coinbase (miner script, witness commitment) outgrew the
    /// weight budgeted for it during selection. Returned instead of an
    /// invalid block; never observed with the default reserve unless the
    /// caller supplies an oversized `miner_script_pubkey`.
    #[error("block weight {actual} exceeds MAX_BLOCK_WEIGHT ({max})")]
    WeightExceeded {
        /// The assembled block's actual weight.
        actual: usize,
        /// `MAX_BLOCK_WEIGHT`.
        max: usize,
    },
    /// The assembled block's total sigop cost exceeds
    /// `MAX_BLOCK_SIGOPS_COST`. Returned instead of an invalid block.
    #[error("block sigop cost {actual} exceeds MAX_BLOCK_SIGOPS_COST ({max})")]
    SigOpsExceeded {
        /// The assembled block's actual sigop cost.
        actual: u64,
        /// `MAX_BLOCK_SIGOPS_COST`.
        max: u64,
    },
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

        // Core's `BlockAssembler::addPackageTxs`: ancestor-feerate
        // package selection. Each entry's `ancestor_score` uses
        // `GetModFeeAndSize` — the smaller of the tx's own modified
        // feerate and its in-pool ancestor package's feerate.
        let flags = avila_consensus::script::block_script_flags(cs.tree().params(), height, &tip);
        let (package, tx_sigops) = self.select_package_txs(cs, height, mtp, flags);
        let chosen: Vec<&crate::MempoolEntry> =
            package.iter().filter_map(|id| self.entry(id)).collect();
        let fees: i64 = chosen.iter().map(|e| e.fee).sum();

        // Coinbase: BIP34 height prefix, subsidy + fees to the miner.
        let subsidy = block_subsidy(height, cs.tree().params());
        let txs: Vec<(Transaction, i64)> = chosen.iter().map(|e| (e.tx.clone(), e.fee)).collect();
        let block = Self::assemble_block(
            cs,
            miner_script_pubkey,
            &txs,
            tx_sigops,
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

    /// A transaction's sigop cost — Core's `GetTransactionSigOpCost`:
    /// legacy sigops (every input's `scriptSig` plus every output's
    /// `scriptPubKey`, non-accurate count, ×4) plus, per input, P2SH
    /// redeem-script sigops and witness sigops resolved against
    /// whatever coin that input spends (confirmed UTXO or pool parent).
    /// An input that doesn't resolve contributes only its legacy share
    /// — it shouldn't happen for an already-admitted entry.
    ///
    /// `pub(crate)`: `accept_tx`/`explain_tx` (lib.rs) use it too, for
    /// the per-tx sigop cap and the sigop-adjusted vsize.
    pub(crate) fn real_sigop_cost(
        &self,
        cs: &avila_consensus::chainstate::Chainstate,
        tx: &Transaction,
        flags: avila_consensus::script::ScriptFlags,
    ) -> u64 {
        use avila_consensus::block::WITNESS_SCALE_FACTOR;
        let mut sigops = tx
            .inputs
            .iter()
            .map(|i| i.script_sig.sig_ops(false))
            .sum::<u64>()
            + tx.outputs
                .iter()
                .map(|o| o.script_pubkey.sig_ops(false))
                .sum::<u64>();
        sigops *= WITNESS_SCALE_FACTOR as u64;
        for input in &tx.inputs {
            if let Some(coin) = self.resolve(cs, &input.previous_output) {
                let spk = &coin.out.script_pubkey;
                if spk.is_p2sh() {
                    sigops += spk.p2sh_sig_ops(&input.script_sig) * WITNESS_SCALE_FACTOR as u64;
                }
                sigops += avila_consensus::script::count_witness_sig_ops(
                    &input.script_sig,
                    spk,
                    &input.witness,
                    flags,
                );
            }
        }
        sigops
    }

    /// Core's `BlockAssembler::addPackageTxs` — pick transactions by
    /// ancestor-feerate packages. Returns the included txids in block
    /// order (parents before children), plus their total real sigop
    /// cost (Core's `GetTransactionSigOpCost`, summed — not the
    /// ancestor-package score) for the caller's final block-wide check.
    ///
    /// Selection sorts every entry by the *minimum* of its own
    /// modified feerate and the feerate of itself plus all its
    /// in-pool ancestors (`GetModFeeAndSize`), so a low-fee parent is
    /// evaluated at the price its children would pay. As packages land
    /// in the block, `UpdatePackagesForAdded` subtracts the included
    /// ancestors' stats from each descendant's score — the descendant
    /// is then re-ranked on what remains unmined.
    fn select_package_txs(
        &self,
        cs: &avila_consensus::chainstate::Chainstate,
        height: u32,
        mtp: u32,
        flags: avila_consensus::script::ScriptFlags,
    ) -> (Vec<Txid>, u64) {
        use avila_consensus::block::WITNESS_SCALE_FACTOR;
        use avila_consensus::check::is_final_tx;

        /// `policy::nBytesPerSigOp` — legacy sigop cost granularity.
        const BYTES_PER_SIGOP: u64 = 20;
        /// Core's `-blockmintxfee` default (0 sat/kvB): no floor.
        const BLOCK_MIN_FEE_SAT_PER_KVB: i64 = 0;
        /// Core's `MAX_CONSECUTIVE_FAILURES` — give up once the block
        /// is nearly full and nothing fits.
        const MAX_CONSECUTIVE_FAILURES: i64 = 1000;
        // Core's BlockAssembler starts `nBlockWeight`/`nBlockSigOpsCost`
        // at the coinbase's budgeted reserve rather than zero; we instead
        // shrink the caps by the same amount and keep the running totals
        // at zero — equivalent, and reuses the existing accounting below.
        let cap = MAX_BLOCK_WEIGHT.saturating_sub(self.block_reserved_weight);
        let sigops_cap = MAX_BLOCK_SIGOPS_COST.saturating_sub(self.coinbase_max_additional_sigops);

        // Per-entry cached facts: the sigop-adjusted vsize Core calls
        // `GetTxSize`, real weight for block accounting, sigop cost,
        // modified fee, and the in-pool ancestor package totals.
        struct Facts {
            /// `GetTxSize` — `max(weight, sigops*20)` rounded up to
            /// vbytes; the feerate/TestPackage size unit.
            tx_size: u64,
            /// Real weight for `nBlockWeight`.
            weight: u64,
            /// `GetSigOpCost` — legacy×4 + p2sh + witness.
            sigops: u64,
            /// `GetModifiedFee` — fee + prioritisetransaction delta.
            mod_fee: i64,
            /// In-pool ancestors (the `CalculateMemPoolAncestors` set).
            ancestors: HashSet<Txid>,
            /// `nCountWithAncestors` — self + ancestors.
            count_wa: usize,
            /// `nSizeWithAncestors`.
            size_wa: u64,
            /// `nModFeesWithAncestors`.
            fees_wa: i64,
            /// `nSigOpCostWithAncestors`.
            sigops_wa: u64,
        }

        /// `GetModFeeAndSize`: the (fee, size) pair the ancestor_score
        /// comparator uses — the tx's own rate when it isn't dragged
        /// below its package rate, else the package rate.
        fn score_fee_size(f: &Facts) -> (i128, i128) {
            if f.mod_fee as i128 * f.size_wa as i128 > f.fees_wa as i128 * f.tx_size as i128 {
                (f.fees_wa as i128, f.size_wa as i128)
            } else {
                (f.mod_fee as i128, f.tx_size as i128)
            }
        }
        /// `CompareTxMemPoolEntryByAncestorFee`: higher score first,
        /// txid (Core's numeric uint256 order — display-order bytes)
        /// breaks exact feerate ties.
        fn better(facts: &HashMap<Txid, Facts>, a: &Txid, b: &Txid) -> bool {
            let (fa, sa) = score_fee_size(&facts[a]);
            let (fb, sb) = score_fee_size(&facts[b]);
            let f1 = fa * sb;
            let f2 = sa * fb;
            if f1 == f2 {
                // Core compares uint256 numerically — internal bytes
                // are little-endian, so compare them reversed.
                let mut x = a.to_bytes();
                x.reverse();
                let mut y = b.to_bytes();
                y.reverse();
                return x < y;
            }
            f1 > f2
        }
        /// Same comparator over a modified entry's rewritten package
        /// stats vs a still-pristine pool entry.
        fn better_mod(
            facts: &HashMap<Txid, Facts>,
            mods: &HashMap<Txid, ModEntry>,
            a: &Txid,
            b: &Txid,
        ) -> bool {
            let (fa, sa) = mod_score_fee_size(&facts[a], &mods[a]);
            let (fb, sb) = score_fee_size(&facts[b]);
            let f1 = fa * sb;
            let f2 = sa * fb;
            if f1 == f2 {
                let mut x = a.to_bytes();
                x.reverse();
                let mut y = b.to_bytes();
                y.reverse();
                return x < y;
            }
            f1 > f2
        }
        fn mod_score_fee_size(f: &Facts, m: &ModEntry) -> (i128, i128) {
            if f.mod_fee as i128 * m.size_wa as i128 > m.fees_wa as i128 * f.tx_size as i128 {
                (m.fees_wa as i128, m.size_wa as i128)
            } else {
                (f.mod_fee as i128, f.tx_size as i128)
            }
        }

        /// `CTxMemPoolModifiedEntry` — a descendant's package stats
        /// with already-mined ancestors subtracted.
        #[derive(Clone)]
        struct ModEntry {
            size_wa: u64,
            fees_wa: i64,
            sigops_wa: u64,
        }

        // Snapshot every entry's facts once — the pool is frozen for
        // the duration of selection.
        let mut facts: HashMap<Txid, Facts> = HashMap::with_capacity(self.entries().count());
        for e in self.entries() {
            let txid = e.tx.txid();
            let sigops = self.real_sigop_cost(cs, &e.tx, flags);
            let weight = e.tx.weight() as u64;
            let tx_size = weight
                .max(sigops * BYTES_PER_SIGOP)
                .div_ceil(WITNESS_SCALE_FACTOR as u64);
            facts.insert(
                txid,
                Facts {
                    tx_size,
                    weight,
                    sigops,
                    mod_fee: e.modified_fee(),
                    ancestors: HashSet::new(),
                    count_wa: 0,
                    size_wa: 0,
                    fees_wa: 0,
                    sigops_wa: 0,
                },
            );
        }
        // Ancestor package totals per entry (self + in-pool ancestors)
        // — `CalculateMemPoolAncestors` walked once at snapshot time.
        let txids: Vec<Txid> = facts.keys().copied().collect();
        for txid in &txids {
            let mut ancestors: HashSet<Txid> = HashSet::new();
            let mut pending: Vec<Txid> = self
                .entry(txid)
                .map(|e| {
                    e.tx.inputs
                        .iter()
                        .map(|i| i.previous_output.txid)
                        .filter(|p| facts.contains_key(p))
                        .collect()
                })
                .unwrap_or_default();
            while let Some(id) = pending.pop() {
                if !ancestors.insert(id) {
                    continue;
                }
                if let Some(e) = self.entry(&id) {
                    pending.extend(
                        e.tx.inputs
                            .iter()
                            .map(|i| i.previous_output.txid)
                            .filter(|p| facts.contains_key(p)),
                    );
                }
            }
            let (mut sz, mut fe, mut so) = (0u64, 0i64, 0u64);
            if let Some(f) = facts.get(txid) {
                sz += f.tx_size;
                fe += f.mod_fee;
                so += f.sigops;
            }
            for a in &ancestors {
                let af = &facts[a];
                sz += af.tx_size;
                fe += af.mod_fee;
                so += af.sigops;
            }
            if let Some(f) = facts.get_mut(txid) {
                f.count_wa = ancestors.len() + 1;
                f.size_wa = sz;
                f.fees_wa = fe;
                f.sigops_wa = so;
                f.ancestors = ancestors;
            }
        }

        // The mapTx order — entries sorted by ancestor_score once.
        let mut order: Vec<Txid> = txids;
        order.sort_by(|a, b| {
            if better(&facts, a, b) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });

        let mut in_block: HashSet<Txid> = HashSet::new();
        let mut failed_tx: HashSet<Txid> = HashSet::new();
        let mut map_modified: HashMap<Txid, ModEntry> = HashMap::new();
        let mut block_weight: u64 = 0;
        let mut block_sigops: u64 = 0;
        let mut chosen: Vec<Txid> = Vec::new();
        let mut consecutive_failed: i64 = 0;
        let mut mi = 0usize;

        while mi < order.len() || !map_modified.is_empty() {
            // Skip stale/failed/in-block mapTx entries.
            if mi < order.len() {
                let cand = order[mi];
                if map_modified.contains_key(&cand)
                    || in_block.contains(&cand)
                    || failed_tx.contains(&cand)
                {
                    mi += 1;
                    continue;
                }
            }
            // Which to evaluate: the next mapTx entry or the best
            // modified one?
            let mut using_modified = false;
            let best_mod = map_modified.keys().copied().reduce(|a, b| {
                if better_mod(&facts, &map_modified, &a, &b) {
                    a
                } else {
                    b
                }
            });
            let iter = if mi >= order.len() {
                using_modified = true;
                best_mod
            } else if let Some(m) = best_mod {
                if better_mod(&facts, &map_modified, &m, &order[mi]) {
                    using_modified = true;
                    Some(m)
                } else {
                    mi += 1;
                    Some(order[mi - 1])
                }
            } else {
                mi += 1;
                Some(order[mi - 1])
            };
            let Some(iter) = iter else { break };

            let (package_size, package_fees, package_sigops) = if using_modified {
                let m = &map_modified[&iter];
                (m.size_wa, m.fees_wa, m.sigops_wa)
            } else {
                let f = &facts[&iter];
                (f.size_wa, f.fees_wa, f.sigops_wa)
            };

            // `-blockmintxfee` floor — everything else sorts lower.
            if package_fees < BLOCK_MIN_FEE_SAT_PER_KVB * package_size as i64 / 1000 {
                return (chosen, block_sigops);
            }

            // TestPackage: weight (vsize terms) + sigops.
            if block_weight + WITNESS_SCALE_FACTOR as u64 * package_size >= cap as u64
                || block_sigops + package_sigops >= sigops_cap
            {
                if using_modified {
                    map_modified.remove(&iter);
                    failed_tx.insert(iter);
                }
                consecutive_failed += 1;
                if consecutive_failed > MAX_CONSECUTIVE_FAILURES
                    && block_weight + BLOCK_FULL_ENOUGH_WEIGHT_DELTA as u64 > cap as u64
                {
                    break;
                }
                continue;
            }

            // The actual package: in-pool ancestors not yet mined, + self.
            let mut package: HashSet<Txid> = facts[&iter]
                .ancestors
                .iter()
                .copied()
                .filter(|a| !in_block.contains(a))
                .collect();
            package.insert(iter);

            // TestPackageTransactions: nLockTime finality at height/MTP.
            if !package.iter().all(|id| {
                self.entry(id)
                    .is_some_and(|e| is_final_tx(&e.tx, height, mtp))
            }) {
                if using_modified {
                    map_modified.remove(&iter);
                    failed_tx.insert(iter);
                }
                continue;
            }
            consecutive_failed = 0;

            // SortForBlock: ancestor-count order, txid ties.
            let mut sorted: Vec<Txid> = package.into_iter().collect();
            sorted.sort_by(|a, b| {
                facts[a].count_wa.cmp(&facts[b].count_wa).then_with(|| {
                    let mut x = a.to_bytes();
                    x.reverse();
                    let mut y = b.to_bytes();
                    y.reverse();
                    x.cmp(&y)
                })
            });

            for id in &sorted {
                let f = &facts[id];
                block_weight += f.weight;
                block_sigops += f.sigops;
                in_block.insert(*id);
                map_modified.remove(id);
                chosen.push(*id);
            }

            // UpdatePackagesForAdded: subtract each included tx's stats
            // from its not-yet-mined descendants' package scores.
            for id in &sorted {
                let pf = &facts[id];
                let (p_size, p_fee, p_sig) = (pf.tx_size, pf.mod_fee, pf.sigops);
                for desc in self.descendant_txids(id) {
                    if in_block.contains(&desc) {
                        continue;
                    }
                    let m = map_modified.entry(desc).or_insert_with(|| {
                        let f = &facts[&desc];
                        ModEntry {
                            size_wa: f.size_wa,
                            fees_wa: f.fees_wa,
                            sigops_wa: f.sigops_wa,
                        }
                    });
                    m.size_wa -= p_size;
                    m.fees_wa -= p_fee;
                    m.sigops_wa -= p_sig;
                }
            }
        }
        (chosen, block_sigops)
    }

    /// Assembles the candidate block — the tail of [`build_template`]
    /// factored out so `generateblock` can mine an explicit,
    /// caller-ordered transaction set (Core's `generateblock`
    /// semantics: exactly the listed txs, in order, plus the
    /// coinbase). Returns the block plus the count of non-coinbase
    /// transactions included.
    ///
    /// `tx_sigops` is the caller's precomputed total sigop cost of
    /// `txs` (Core's `GetTransactionSigOpCost`, summed) — used only for
    /// the final `MAX_BLOCK_SIGOPS_COST` check below, since a coinbase
    /// has no prevouts of its own to derive its sigop cost from `txs`.
    ///
    /// # Errors
    ///
    /// [`TemplateError::WeightExceeded`] or [`TemplateError::SigOpsExceeded`]
    /// if the assembled block — coinbase included — doesn't fit the
    /// consensus caps. `select_package_txs` budgets a reserve for the
    /// coinbase so this should not trigger with a normally sized miner
    /// output script, but a caller-supplied `miner_script_pubkey` (or an
    /// explicit `txs` set from `build_explicit_block`) isn't bounded by
    /// that budget, so the real, assembled block is checked rather than
    /// trusting the plan.
    #[allow(clippy::too_many_arguments)]
    fn assemble_block(
        cs: &avila_consensus::chainstate::Chainstate,
        miner_script_pubkey: Script,
        txs: &[(Transaction, i64)],
        tx_sigops: u64,
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

        // Final safety net: verify the *real* assembled block rather
        // than trusting `select_package_txs`'s budgeted reserve, which
        // only bounds mempool-selected weight/sigops, not a caller's
        // `miner_script_pubkey` or an explicit `generateblock`-style
        // `txs` set. Core's own coinbase shape is bounded by its own
        // code, not a runtime check; ours accepts caller-supplied
        // scripts, so we check rather than assume.
        let weight = block.weight();
        if weight > MAX_BLOCK_WEIGHT {
            return Err(TemplateError::WeightExceeded {
                actual: weight,
                max: MAX_BLOCK_WEIGHT,
            });
        }
        // Core's `GetTransactionSigOpCost` special-cases a coinbase to
        // only its own legacy sigops (`GetLegacySigOpCount * 4`) — no
        // P2SH/witness component, since a coinbase has no real prevouts.
        let coinbase = &block.transactions[0];
        let coinbase_sigops: u64 = (coinbase
            .inputs
            .iter()
            .map(|i| i.script_sig.sig_ops(false))
            .sum::<u64>()
            + coinbase
                .outputs
                .iter()
                .map(|o| o.script_pubkey.sig_ops(false))
                .sum::<u64>())
            * avila_consensus::block::WITNESS_SCALE_FACTOR as u64;
        let total_sigops = coinbase_sigops.saturating_add(tx_sigops);
        if total_sigops > MAX_BLOCK_SIGOPS_COST {
            return Err(TemplateError::SigOpsExceeded {
                actual: total_sigops,
                max: MAX_BLOCK_SIGOPS_COST,
            });
        }
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
        // Explicit sets bypass `select_package_txs`'s budgeted reserve
        // entirely, so their real sigop cost has to be computed here for
        // `assemble_block`'s final check.
        let flags = avila_consensus::script::block_script_flags(cs.tree().params(), height, &tip);
        let tx_sigops: u64 = txs
            .iter()
            .map(|(tx, _)| self.real_sigop_cost(cs, tx, flags))
            .sum();
        Self::assemble_block(
            cs,
            miner_script_pubkey,
            txs,
            tx_sigops,
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

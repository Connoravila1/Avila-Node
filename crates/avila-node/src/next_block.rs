//! [`NextBlock`]: a preview of the block this node's mempool would
//! produce next — the desktop GUI's block-composition panel. Built
//! from [`avila_mempool::Mempool::build_template`]; a preview failure
//! (no template context, an oversized caller script, …) is reported as
//! `None`, never as a sync error — see the call site in
//! [`crate::sync::run`].

use avila_consensus::chainstate::Chainstate;
use avila_consensus::connect::block_subsidy;
use avila_consensus::script;
use avila_consensus::transaction::Script;
use avila_mempool::Mempool;

/// The block this node's mempool would produce next; `None` unless
/// [`crate::sync::SyncConfig::preview_next_block`] is set and the pool
/// has transactions (see [`crate::sync::SyncProgress::next_block`]).
#[derive(Clone, Debug, PartialEq)]
pub struct NextBlock {
    /// The height it would connect at.
    pub height: u32,
    /// Pool transactions included (the coinbase not counted).
    pub tx_count: usize,
    /// Total block weight including the coinbase, WU.
    pub weight: usize,
    /// Total fees claimed, satoshis.
    pub fees: i64,
    /// The block subsidy at `height`, satoshis.
    pub subsidy: i64,
    /// Included transactions' fee rates, highest first, as a staircase of
    /// `(cumulative vsize in vB, fee rate in sat/vB)`: at most 96 steps,
    /// downsampled so the last step always ends at the full included vsize.
    pub steps: Vec<(u32, f64)>,
}

/// At most this many `(cumulative vsize, fee rate)` points in
/// [`NextBlock::steps`] — enough resolution for a GUI chart without
/// shipping one point per transaction on a full block.
const MAX_STEPS: usize = 96;

/// A P2WPKH-shaped scriptPubKey (`OP_0 <20 zero bytes>`) so the
/// assembled coinbase carries a realistic weight. Never an address this
/// node controls or would ever mine to — the preview is display-only.
fn placeholder_miner_script() -> Script {
    let mut bytes = Vec::with_capacity(22);
    bytes.push(script::OP_0);
    bytes.push(20); // direct push of the next 20 bytes
    bytes.extend_from_slice(&[0u8; 20]);
    Script::new(bytes)
}

/// Builds today's [`NextBlock`] summary from the pool's current best
/// template. `None` when the pool is empty or [`Mempool::build_template`]
/// fails (no median-time-past context yet, or a retarget failure) —
/// both are ordinary, expected states, not errors.
pub(crate) fn build_next_block(mempool: &Mempool, cs: &Chainstate) -> Option<NextBlock> {
    if mempool.is_empty() {
        return None;
    }
    let now = u32::try_from(crate::time::time()).unwrap_or(0);
    let template = mempool
        .build_template(cs, placeholder_miner_script(), now)
        .ok()?;
    let subsidy = block_subsidy(template.height, cs.tree().params());

    // `template.block.transactions` is coinbase-first; every entry
    // after it is a pool selection with its own admission-computed
    // fee/vsize (the real fee, not the prioritised/modified one).
    let mut entries: Vec<(u32, f64)> = Vec::with_capacity(template.tx_count);
    for tx in template.block.transactions.iter().skip(1) {
        let Some(entry) = mempool.entry(&tx.txid()) else {
            continue; // defensive: every included tx must be pooled
        };
        if entry.vsize == 0 {
            continue;
        }
        let vsize = u32::try_from(entry.vsize).unwrap_or(u32::MAX);
        #[allow(clippy::cast_precision_loss)]
        let rate = entry.fee as f64 / entry.vsize as f64;
        entries.push((vsize, rate));
    }

    Some(NextBlock {
        height: template.height,
        tx_count: template.tx_count,
        weight: template.weight,
        fees: template.fees,
        subsidy,
        steps: fee_rate_staircase(entries),
    })
}

/// Reduces per-transaction `(vsize, fee rate)` pairs to a fee-rate
/// staircase: sorted highest fee rate first, then folded into
/// cumulative `(vsize, fee rate)` steps. Downsamples to at most
/// [`MAX_STEPS`] steps when there are more entries than that, always
/// keeping the last step pinned to the true total vsize. A pure
/// function so it can be unit-tested without a mempool or chainstate.
fn fee_rate_staircase(mut entries: Vec<(u32, f64)>) -> Vec<(u32, f64)> {
    // Highest fee rate first; `total_cmp` never panics on the NaN/inf
    // cases `partial_cmp` would need an `.unwrap()` for (none reachable
    // here, since zero-vsize entries are filtered before this is called).
    entries.sort_by(|a, b| b.1.total_cmp(&a.1));

    let mut cumulative: Vec<(u32, f64)> = Vec::with_capacity(entries.len());
    let mut running: u64 = 0;
    for (vsize, rate) in entries {
        running = running.saturating_add(u64::from(vsize));
        cumulative.push((u32::try_from(running).unwrap_or(u32::MAX), rate));
    }

    if cumulative.len() <= MAX_STEPS {
        return cumulative;
    }

    // More points than the budget: keep the last point of each of
    // `MAX_STEPS` equal-sized buckets over the `n > MAX_STEPS` sorted
    // entries. `bucket_end(i) = (i * n) / MAX_STEPS - 1` is strictly
    // increasing in `i` here (since `n > MAX_STEPS` makes each step's
    // real-valued increment exceed 1), which is what keeps the result's
    // cumulative vsize strictly increasing; `bucket_end(MAX_STEPS) ==
    // n - 1` pins the last step to the real total.
    let n = cumulative.len();
    let bucket_end = |i: usize| (i * n) / MAX_STEPS - 1;
    (1..=MAX_STEPS).map(|i| cumulative[bucket_end(i)]).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Checks the staircase invariants the spec requires: fee rates
    /// non-increasing, cumulative vsize strictly increasing, at most
    /// [`MAX_STEPS`] steps, and (when non-empty) the last step's vsize
    /// equal to `expected_total_vsize`.
    fn assert_valid_staircase(steps: &[(u32, f64)], expected_total_vsize: u32) {
        assert!(steps.len() <= MAX_STEPS, "at most {MAX_STEPS} steps");
        let mut prev_vsize: Option<u32> = None;
        let mut prev_rate = f64::INFINITY;
        for &(vsize, rate) in steps {
            if let Some(p) = prev_vsize {
                assert!(vsize > p, "cumulative vsize must strictly increase");
            }
            assert!(rate <= prev_rate, "fee rate must be non-increasing");
            prev_vsize = Some(vsize);
            prev_rate = rate;
        }
        if let Some(&(last_vsize, _)) = steps.last() {
            assert_eq!(
                last_vsize, expected_total_vsize,
                "the last step must end at the full included vsize"
            );
        }
    }

    #[test]
    fn empty_input_yields_no_steps() {
        assert_eq!(fee_rate_staircase(Vec::new()), Vec::new());
    }

    #[test]
    fn small_input_is_not_downsampled() {
        let entries = vec![(100u32, 5.0), (200, 10.0), (50, 1.0)];
        let total: u32 = entries.iter().map(|(v, _)| v).sum();
        let steps = fee_rate_staircase(entries);
        assert_eq!(steps.len(), 3, "fewer than MAX_STEPS entries: one per tx");
        assert_valid_staircase(&steps, total);
        // Highest fee rate (the 200-vsize, 10.0 sat/vB entry) sorts first.
        assert_eq!(steps[0], (200, 10.0));
        assert_eq!(steps[1], (300, 5.0));
        assert_eq!(steps[2], (350, 1.0));
    }

    #[test]
    fn exactly_max_steps_is_not_downsampled() {
        let entries: Vec<(u32, f64)> = (0..MAX_STEPS as u32)
            .map(|i| (1, f64::from(MAX_STEPS as u32 - i)))
            .collect();
        let total: u32 = entries.iter().map(|(v, _)| v).sum();
        let steps = fee_rate_staircase(entries);
        assert_eq!(steps.len(), MAX_STEPS);
        assert_valid_staircase(&steps, total);
    }

    #[test]
    fn large_input_downsamples_to_at_most_max_steps() {
        // 500 synthetic entries with distinct fee rates.
        let entries: Vec<(u32, f64)> = (0..500u32).map(|i| (10, f64::from(500 - i))).collect();
        let total: u32 = entries.iter().map(|(v, _)| v).sum();
        let steps = fee_rate_staircase(entries);
        assert_eq!(steps.len(), MAX_STEPS);
        assert_valid_staircase(&steps, total);
        // Each step is the *lowest* rate within its bucket (the
        // conservative edge — see `fee_rate_staircase`'s doc comment),
        // so the first step needn't equal the input's global max (500),
        // but it must not exceed it.
        assert!(steps[0].1 <= 500.0);
        assert!(steps[0].1 > steps[MAX_STEPS - 1].1);
    }

    #[test]
    fn one_more_than_max_steps_still_downsamples_cleanly() {
        let entries: Vec<(u32, f64)> = (0..=MAX_STEPS as u32)
            .map(|i| (3, f64::from(MAX_STEPS as u32 + 1 - i)))
            .collect();
        let total: u32 = entries.iter().map(|(v, _)| v).sum();
        let steps = fee_rate_staircase(entries);
        assert_eq!(steps.len(), MAX_STEPS);
        assert_valid_staircase(&steps, total);
    }

    // ---- End-to-end through a real Chainstate + Mempool -------------

    #[allow(clippy::unwrap_used, clippy::expect_used)]
    #[test]
    fn end_to_end_preview_matches_a_real_pool_and_chainstate() {
        use avila_consensus::arith::CompactTarget;
        use avila_consensus::block::Block;
        use avila_consensus::hash::Txid;
        use avila_consensus::header::BlockHeader;
        use avila_consensus::params::{Network, Params};
        use avila_consensus::pow;
        use avila_consensus::transaction::{OutPoint, Transaction, TxIn, TxOut, Witness};

        const REGTEST_BITS: u32 = 0x207f_ffff;
        const SEQ_FINAL: u32 = 0xffff_ffff;
        const NOW: u32 = 1_700_000_000;

        // Same anyone-can-spend (`OP_1`) recipe avila-mempool's own
        // test harness uses (that harness is private to that crate's
        // `#[cfg(test)]`, so it can't be reused directly — this mirrors
        // it instead of reimplementing something novel).
        fn coinbase_tx(height: u32) -> Transaction {
            let mut script_sig = script::push_int(i64::from(height));
            script_sig.push(script::OP_1);
            Transaction {
                version: 1,
                inputs: vec![TxIn {
                    previous_output: OutPoint::NULL,
                    script_sig: Script::new(script_sig),
                    sequence: SEQ_FINAL,
                    witness: Witness::default(),
                }],
                outputs: vec![TxOut {
                    value: 5_000_000_000,
                    script_pubkey: Script::new(vec![script::OP_1]),
                }],
                lock_time: 0,
            }
        }

        fn block_on(prev: &BlockHeader, height: u32, params: &Params) -> Block {
            let mut block = Block {
                header: BlockHeader {
                    version: 4,
                    prev_block_hash: prev.hash(),
                    merkle_root: prev.merkle_root,
                    time: prev.time + 1,
                    bits: CompactTarget(REGTEST_BITS),
                    nonce: 0,
                },
                transactions: vec![coinbase_tx(height)],
            };
            let (root, _) = block.merkle_root();
            block.header.merkle_root = root;
            while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err()
            {
                block.header.nonce += 1;
            }
            block
        }

        let params = Network::Regtest.params();
        let mut cs = Chainstate::new(&params);
        let mut prev = params.genesis_header;
        let mut first_coinbase_txid: Option<Txid> = None;
        // 101 blocks: block 1's coinbase matures (100 confirmations)
        // exactly when the chain reaches height 101.
        for h in 1..=101u32 {
            let b = block_on(&prev, h, &params);
            if h == 1 {
                first_coinbase_txid = Some(b.transactions[0].txid());
            }
            cs.accept_block(&b, NOW + h).expect("block must connect");
            prev = b.header;
        }

        let mut pool = Mempool::new();
        pool.set_require_standard(false); // OP_1 fixtures aren't a standard template
        let spend = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: first_coinbase_txid.expect("coinbase must exist"),
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: SEQ_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 4_999_990_000, // 10,000 sat fee
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        let spend_txid = pool
            .accept_tx(spend, &cs, NOW)
            .expect("spend of a mature coinbase must be admitted");

        assert!(build_next_block(&Mempool::new(), &cs).is_none(), "an empty pool must preview as None");

        let preview =
            build_next_block(&pool, &cs).expect("a non-empty pool must produce a preview");
        assert_eq!(preview.height, 102);
        assert_eq!(preview.tx_count, 1);
        assert_eq!(preview.fees, 10_000);
        assert_eq!(preview.subsidy, block_subsidy(102, &params));
        assert!(preview.weight > 0);

        let entry = pool.entry(&spend_txid).expect("entry must still be pooled");
        let expected_vsize = u32::try_from(entry.vsize).unwrap();
        assert_eq!(preview.steps, vec![(expected_vsize, 10_000.0 / entry.vsize as f64)]);
    }
}

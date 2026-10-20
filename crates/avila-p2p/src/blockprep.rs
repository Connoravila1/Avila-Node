//! Bounded preparation workers for checksum-verified P2P block frames.
//!
//! Workers only decode and run context-free `CheckBlock`. They never mutate
//! chainstate; the manager feeds completed tokens through its ordinary ordered
//! peer acceptance path.

use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};

use avila_consensus::block::Block;
use avila_consensus::chainstate::PreparedBlock;
use avila_consensus::params::Params;

use crate::message::{PayloadError, decode_block_payload};

pub(crate) const PREPARATION_WORKERS: usize = 2;
pub(crate) const MAX_PREPARATION_JOBS: usize = 4;
pub(crate) const MAX_SERIALIZED_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_DECODED_BYTES: usize = 256 * 1024 * 1024;
const DECODED_RESERVATION_RATIO: usize = 64;

#[derive(Debug)]
pub(crate) enum PreparationResult {
    Prepared(Box<PreparedBlock>),
    /// Keep the decoded body so the ordinary acceptance path reproduces the
    /// same `CheckBlock` rejection and peer attribution.
    CheckRejected(Block),
    DecodeRejected(PayloadError),
}

#[derive(Debug)]
pub(crate) struct Completion {
    pub peer_id: u64,
    pub session_id: u64,
    pub result: PreparationResult,
    pub _reservation: Reservation,
}

struct Task {
    peer_id: u64,
    session_id: u64,
    payload: Vec<u8>,
    params: Params,
    reservation: Reservation,
}

#[derive(Debug, Default)]
struct Budget {
    jobs: usize,
    serialized: usize,
    decoded: usize,
}

#[derive(Debug)]
pub(crate) struct Reservation {
    budget: Arc<Mutex<Budget>>,
    serialized: usize,
    decoded: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut budget = self.budget.lock().unwrap_or_else(|e| e.into_inner());
        budget.jobs -= 1;
        budget.serialized -= self.serialized;
        budget.decoded -= self.decoded;
    }
}

/// Two persistent workers, four queued/active/completed jobs maximum, and
/// explicit aggregate serialized and conservative decoded-memory budgets.
pub(crate) struct BlockPreparationPool {
    jobs: Option<mpsc::SyncSender<Task>>,
    completions: mpsc::Receiver<Completion>,
    budget: Arc<Mutex<Budget>>,
    workers: Vec<JoinHandle<()>>,
}

impl BlockPreparationPool {
    pub(crate) fn new() -> Option<Self> {
        let (job_tx, job_rx) = mpsc::sync_channel::<Task>(MAX_PREPARATION_JOBS);
        let job_rx = Arc::new(Mutex::new(job_rx));
        let (completion_tx, completions) = mpsc::channel();
        let budget = Arc::new(Mutex::new(Budget::default()));
        let mut workers = Vec::with_capacity(PREPARATION_WORKERS);
        for _ in 0..PREPARATION_WORKERS {
            let jobs = Arc::clone(&job_rx);
            let completed = completion_tx.clone();
            match thread::Builder::new()
                .name("avila-block-prep".to_string())
                .spawn(move || worker(jobs, completed))
            {
                Ok(worker) => workers.push(worker),
                Err(_) => {
                    drop(job_tx);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return None;
                }
            }
        }
        drop(completion_tx);
        Some(Self {
            jobs: Some(job_tx),
            completions,
            budget,
            workers,
        })
    }

    /// Enqueues without waiting. `false` means the caller must use the
    /// ordinary synchronous decode/accept path for this body.
    pub(crate) fn try_submit(
        &self,
        peer_id: u64,
        session_id: u64,
        payload: Vec<u8>,
        params: Params,
    ) -> Result<(), Vec<u8>> {
        if payload.is_empty() || payload.len() > MAX_SERIALIZED_BYTES {
            return Err(payload);
        }
        let serialized = payload.len();
        let decoded = serialized.saturating_mul(DECODED_RESERVATION_RATIO);
        if decoded > MAX_DECODED_BYTES {
            return Err(payload);
        }
        {
            let mut budget = self.budget.lock().unwrap_or_else(|e| e.into_inner());
            if budget.jobs >= MAX_PREPARATION_JOBS
                || budget.serialized.saturating_add(serialized) > MAX_SERIALIZED_BYTES
                || budget.decoded.saturating_add(decoded) > MAX_DECODED_BYTES
            {
                return Err(payload);
            }
            budget.jobs += 1;
            budget.serialized += serialized;
            budget.decoded += decoded;
        }
        let task = Task {
            peer_id,
            session_id,
            payload,
            params,
            reservation: Reservation {
                budget: Arc::clone(&self.budget),
                serialized,
                decoded,
            },
        };
        let Some(jobs) = &self.jobs else {
            return Err(task.payload);
        };
        match jobs.try_send(task) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(task) | mpsc::TrySendError::Disconnected(task)) => {
                let Task { payload, .. } = task;
                Err(payload)
            }
        }
    }

    pub(crate) fn drain(&self) -> Vec<Completion> {
        self.completions.try_iter().collect()
    }
}

impl Drop for BlockPreparationPool {
    fn drop(&mut self) {
        // Dropping the last sender wakes both workers; their receiver lock is
        // held only while waiting for the next task, never during validation.
        self.jobs.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn worker(jobs: Arc<Mutex<mpsc::Receiver<Task>>>, completions: mpsc::Sender<Completion>) {
    loop {
        let task = {
            let receiver = jobs.lock().unwrap_or_else(|e| e.into_inner());
            receiver.recv()
        };
        let Ok(task) = task else { return };
        let Task {
            peer_id,
            session_id,
            payload,
            params,
            reservation,
        } = task;
        let result = match decode_block_payload(&payload) {
            Err(err) => PreparationResult::DecodeRejected(err),
            Ok(block) => match PreparedBlock::check(block, params) {
                Ok(prepared) => PreparationResult::Prepared(Box::new(prepared)),
                Err((block, _error)) => {
                    // `CheckBlock` failed before header insertion. Preserve the
                    // body so the regular path emits the exact same rejection.
                    PreparationResult::CheckRejected(block)
                }
            },
        };
        let completion = Completion {
            peer_id,
            session_id,
            result,
            _reservation: reservation,
        };
        if completions.send(completion).is_err() {
            return;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use avila_consensus::arith::CompactTarget;
    use avila_consensus::hash::MerkleRoot;
    use avila_consensus::params::Network;
    use avila_consensus::transaction::{Script, Witness};

    fn take(pool: &BlockPreparationPool) -> Completion {
        pool.completions
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("worker completion")
    }

    #[test]
    fn workers_decode_check_and_preserve_failure_categories() {
        let params = Network::Regtest.params();
        let block = crate::testchain::block_on(&params.genesis_header, 1, &params);
        let expected = block.block_hash();
        let pool = BlockPreparationPool::new().expect("preparation workers spawn");
        pool.try_submit(5, 9, block.encode(), params).unwrap();
        match take(&pool).result {
            PreparationResult::Prepared(prepared) => assert_eq!(prepared.block_hash(), expected),
            other => panic!("unexpected preparation result: {other:?}"),
        }

        let mut trailing = block.encode();
        trailing.push(0);
        pool.try_submit(5, 9, trailing, params).unwrap();
        assert!(matches!(
            take(&pool).result,
            PreparationResult::DecodeRejected(_)
        ));

        let mut bad_pow = block.clone();
        bad_pow.header.bits = CompactTarget(0x0101_0000);
        pool.try_submit(5, 9, bad_pow.encode(), params).unwrap();
        assert!(matches!(
            take(&pool).result,
            PreparationResult::CheckRejected(_)
        ));

        let mut bad_merkle = block.clone();
        bad_merkle.header.merkle_root = MerkleRoot::from_bytes([0xff; 32]);
        pool.try_submit(5, 9, bad_merkle.encode(), params).unwrap();
        assert!(matches!(
            take(&pool).result,
            PreparationResult::CheckRejected(_)
        ));

        let mut oversized = crate::testchain::coinbase_tx(1);
        oversized.outputs[0].script_pubkey = Script::new(vec![0x51; 1_050_000]);
        let bad_weight =
            crate::testchain::block_on_txs(&params.genesis_header, vec![oversized], &params);
        pool.try_submit(5, 9, bad_weight.encode(), params).unwrap();
        assert!(matches!(
            take(&pool).result,
            PreparationResult::CheckRejected(_)
        ));
    }

    #[test]
    fn worker_rejects_truncated_huge_transaction_count_without_reserving_by_count() {
        let params = Network::Regtest.params();
        let block = crate::testchain::block_on(&params.genesis_header, 1, &params);
        let mut payload = Vec::new();
        block.header.write(&mut payload);
        payload.push(0xfe); // CompactSize u32 prefix
        payload.extend_from_slice(&0x0200_0000u32.to_le_bytes());
        payload.extend_from_slice(&[0xaa, 0xbb]); // cannot contain even one transaction

        let pool = BlockPreparationPool::new().expect("preparation workers spawn");
        pool.try_submit(11, 3, payload, params).unwrap();
        let completion = take(&pool);
        assert!(matches!(
            &completion.result,
            PreparationResult::DecodeRejected(_)
        ));
        assert_eq!(
            pool.budget.lock().unwrap().jobs,
            1,
            "the completed result retains its reservation until consumed"
        );
        drop(completion);
        assert_eq!(pool.budget.lock().unwrap().jobs, 0);
    }

    #[test]
    fn worker_decodes_large_empty_witness_stack_within_wire_amplification_budget() {
        const EMPTY_ITEMS: usize = 200_000;
        let params = Network::Regtest.params();
        let mut block = crate::testchain::block_on(&params.genesis_header, 1, &params);
        block.transactions[0].inputs[0].witness = Witness::new(vec![Vec::new(); EMPTY_ITEMS]);
        // Witness does not contribute to txid/merkle, so this stays the same
        // valid context-free block while exercising the high-overhead wire
        // representation: one empty Vec allocation descriptor per one-byte
        // witness item.
        let payload = block.encode();
        assert!(payload.len() <= EMPTY_ITEMS + 256);

        let pool = BlockPreparationPool::new().expect("preparation workers spawn");
        pool.try_submit(11, 3, payload, params).unwrap();
        let completion = take(&pool);
        match completion.result {
            PreparationResult::Prepared(prepared) => assert_eq!(
                prepared.block().transactions[0].inputs[0]
                    .witness
                    .items()
                    .len(),
                EMPTY_ITEMS
            ),
            other => panic!("unexpected preparation result: {other:?}"),
        }
    }

    #[test]
    fn outstanding_jobs_are_bounded_until_results_are_consumed() {
        let params = Network::Regtest.params();
        let pool = BlockPreparationPool::new().expect("preparation workers spawn");
        for _ in 0..MAX_PREPARATION_JOBS {
            pool.try_submit(1, 2, vec![0], params).unwrap();
        }
        let valid = crate::testchain::block_on(&params.genesis_header, 1, &params).encode();
        let fallback = pool
            .try_submit(1, 2, valid.clone(), params)
            .expect_err("full pool returns the body for synchronous fallback");
        assert_eq!(fallback, valid);
        let fallback_block = decode_block_payload(&fallback).unwrap();
        assert!(PreparedBlock::check(fallback_block, params).is_ok());
        let mut completions = Vec::new();
        for _ in 0..MAX_PREPARATION_JOBS {
            completions.push(take(&pool));
        }
        drop(completions); // releases all byte and job reservations
        assert!(pool.try_submit(1, 2, vec![0], params).is_ok());
    }
}

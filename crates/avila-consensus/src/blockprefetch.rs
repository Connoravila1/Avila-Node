//! Bounded, ordered lookahead for block bodies already present in `blk*.dat`.
//!
//! This pool is used by chainstate branch replay. It intentionally does not
//! intercept the normal P2P tip path: `SyncManager::on_block` already hands
//! `accept_block` a decoded body, so there is no disk read to overlap there.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::block::Block;
use crate::hash::BlockHash;
use crate::store::{BlockPos, BlockStore};

const READER_COUNT: usize = 2;
pub(crate) const WINDOW: usize = 4;
const SERIALIZED_BUDGET: usize = 16 * 1024 * 1024;
// Two readers may each decode one maximum-size block. At the conservative
// 64x decoder-amplification reservation this is 512 MiB total; larger windows
// remain available for smaller bodies, while a third maximum-size read falls
// back to the ordinary synchronous path.
const DECODED_BUDGET: usize = 512 * 1024 * 1024;

enum Command {
    Read(ReadJob),
    Shutdown,
}

struct ReadJob {
    epoch: u64,
    hash: BlockHash,
    path: PathBuf,
    magic: [u8; 4],
    pos: BlockPos,
}

struct ReadResult {
    epoch: u64,
    hash: BlockHash,
    block: io::Result<Block>,
}

#[derive(Clone, Copy)]
struct Reservation {
    epoch: u64,
    serialized: usize,
    decoded: usize,
}

/// Persistent two-reader worker pool. Each branch replay opens only a small
/// sliding window of immutable file positions; results are accepted only for
/// their originating epoch and expected block hash.
pub(crate) struct BlockPrefetcher {
    jobs: SyncSender<Command>,
    results: Receiver<ReadResult>,
    workers: Vec<JoinHandle<()>>,
    epoch: u64,
    source: Option<(PathBuf, [u8; 4])>,
    active: HashMap<BlockHash, Reservation>,
    completed: HashMap<BlockHash, io::Result<Block>>,
    serialized_reserved: usize,
    decoded_reserved: usize,
    #[cfg(test)]
    hits: usize,
}

impl BlockPrefetcher {
    pub(crate) fn new() -> Option<Self> {
        let (job_tx, job_rx) = mpsc::sync_channel::<Command>(WINDOW);
        let (result_tx, result_rx) = mpsc::channel::<ReadResult>();
        let shared_rx = Arc::new(Mutex::new(job_rx));
        let mut workers = Vec::with_capacity(READER_COUNT);
        for worker_id in 0..READER_COUNT {
            let rx = Arc::clone(&shared_rx);
            let tx = result_tx.clone();
            let worker = std::thread::Builder::new()
                .name(format!("block-prefetch-{worker_id}"))
                .spawn(move || {
                    loop {
                        let command = {
                            let guard = rx.lock().unwrap_or_else(|e| e.into_inner());
                            guard.recv()
                        };
                        let Ok(Command::Read(job)) = command else {
                            break;
                        };
                        let block =
                            crate::store::read_position(&job.path, job.magic, job.pos, job.hash);
                        if tx
                            .send(ReadResult {
                                epoch: job.epoch,
                                hash: job.hash,
                                block,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            match worker {
                Ok(worker) => workers.push(worker),
                Err(_) => {
                    for _ in 0..workers.len() {
                        let _ = job_tx.send(Command::Shutdown);
                    }
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return None;
                }
            }
        }
        Some(Self {
            jobs: job_tx,
            results: result_rx,
            workers,
            epoch: 0,
            source: None,
            active: HashMap::new(),
            completed: HashMap::new(),
            serialized_reserved: 0,
            decoded_reserved: 0,
            #[cfg(test)]
            hits: 0,
        })
    }

    /// Starts a new immutable read epoch. Any previous batch is drained and
    /// discarded before the new source becomes visible to workers.
    pub(crate) fn begin(&mut self, store: &BlockStore) {
        self.finish();
        self.epoch = self.epoch.wrapping_add(1).max(1);
        self.source = Some(store.prefetch_source());
    }

    /// Queue one job if both byte budgets and the four-job window allow it.
    /// A skipped job remains available through `BlockStore::read` fallback.
    pub(crate) fn schedule(&mut self, hash: BlockHash, pos: BlockPos) -> bool {
        let Some((path, magic)) = &self.source else {
            return false;
        };
        if self.active.contains_key(&hash) || self.active.len() >= WINDOW {
            return false;
        }
        let serialized = pos.len as usize;
        if serialized == 0 || serialized > crate::block::MAX_BLOCK_SERIALIZED_SIZE {
            return false;
        }
        // The decoder owns nested vectors (including witness-item vectors),
        // whose headers can amplify small wire elements. Reserve 64× the
        // frame plus a fixed margin before admitting a worker; frames that
        // cannot fit simply use the ordinary synchronous read path.
        let decoded = serialized.saturating_mul(64).saturating_add(4096);
        if serialized.saturating_add(self.serialized_reserved) > SERIALIZED_BUDGET
            || decoded.saturating_add(self.decoded_reserved) > DECODED_BUDGET
        {
            return false;
        }
        let job = ReadJob {
            epoch: self.epoch,
            hash,
            path: path.clone(),
            magic: *magic,
            pos,
        };
        match self.jobs.try_send(Command::Read(job)) {
            Ok(()) => {
                self.active.insert(
                    hash,
                    Reservation {
                        epoch: self.epoch,
                        serialized,
                        decoded,
                    },
                );
                self.serialized_reserved += serialized;
                self.decoded_reserved += decoded;
                true
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Waits for the expected body if it was scheduled. An I/O error, stale
    /// epoch, or hash mismatch is a cache miss; chainstate then retries through
    /// the ordinary store path and applies its normal corruption handling.
    pub(crate) fn take(&mut self, expected_hash: BlockHash) -> Option<Block> {
        let reservation = *self.active.get(&expected_hash)?;
        while !self.completed.contains_key(&expected_hash) {
            let result = self.results.recv().ok()?;
            let Some(reservation) = self.active.get(&result.hash) else {
                continue;
            };
            if result.epoch != self.epoch || reservation.epoch != result.epoch {
                continue;
            }
            self.completed.insert(result.hash, result.block);
        }
        let block = self.completed.remove(&expected_hash).and_then(Result::ok);
        self.release(expected_hash, reservation);
        let block = block.filter(|block| block.block_hash() == expected_hash);
        #[cfg(test)]
        if block.is_some() {
            self.hits += 1;
        }
        block
    }

    /// Invalidates the active batch, waits for every in-flight read, and
    /// releases its bounded result memory. The worker threads remain alive.
    pub(crate) fn finish(&mut self) {
        if self.active.is_empty() {
            self.completed.clear();
            self.source = None;
            return;
        }
        self.epoch = self.epoch.wrapping_add(1).max(1);
        let completed: Vec<_> = self.completed.keys().copied().collect();
        for hash in completed {
            if let Some(reservation) = self.active.remove(&hash) {
                self.serialized_reserved = self
                    .serialized_reserved
                    .saturating_sub(reservation.serialized);
                self.decoded_reserved = self.decoded_reserved.saturating_sub(reservation.decoded);
            }
        }
        self.completed.clear();
        while !self.active.is_empty() {
            let Ok(result) = self.results.recv() else {
                break;
            };
            if let Some(reservation) = self.active.remove(&result.hash) {
                self.serialized_reserved = self
                    .serialized_reserved
                    .saturating_sub(reservation.serialized);
                self.decoded_reserved = self.decoded_reserved.saturating_sub(reservation.decoded);
            }
        }
        self.active.clear();
        self.completed.clear();
        self.serialized_reserved = 0;
        self.decoded_reserved = 0;
        self.source = None;
    }

    fn release(&mut self, hash: BlockHash, reservation: Reservation) {
        self.active.remove(&hash);
        self.serialized_reserved = self
            .serialized_reserved
            .saturating_sub(reservation.serialized);
        self.decoded_reserved = self.decoded_reserved.saturating_sub(reservation.decoded);
    }

    #[cfg(test)]
    pub(crate) fn reserved(&self) -> (usize, usize, usize) {
        (
            self.active.len(),
            self.serialized_reserved,
            self.decoded_reserved,
        )
    }

    #[cfg(test)]
    pub(crate) fn hits(&self) -> usize {
        self.hits
    }
}

impl Drop for BlockPrefetcher {
    fn drop(&mut self) {
        self.finish();
        for _ in 0..self.workers.len() {
            let _ = self.jobs.send(Command::Shutdown);
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

pub(crate) fn enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("AVILA_BLOCK_PREFETCH").ok().as_deref() != Some("0"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::params::Network;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn test_dir() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "avila-block-prefetch-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn queue_consumes_matching_bodies_and_falls_back_on_mismatch() {
        let dir = test_dir();
        let params = Network::Regtest.params();
        let mut store = BlockStore::open(&dir, params.message_start).unwrap();
        let block = params.genesis_block().unwrap();
        let hash = block.block_hash();
        let pos = store.append(&block).unwrap();
        let mut prefetch = BlockPrefetcher::new().unwrap();
        prefetch.begin(&store);
        assert!(prefetch.schedule(hash, pos));
        assert_eq!(prefetch.take(hash), Some(block.clone()));

        let wrong_hash = BlockHash::from_bytes([0x42; 32]);
        assert!(prefetch.schedule(wrong_hash, pos));
        assert!(prefetch.take(wrong_hash).is_none());
        // The ordinary path remains usable after a stale or mismatched result.
        assert_eq!(store.read(pos).unwrap(), block);
        prefetch.finish();
        drop(prefetch);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_epoch_is_drained_and_drop_joins_readers() {
        let dir = test_dir();
        let params = Network::Regtest.params();
        let mut store = BlockStore::open(&dir, params.message_start).unwrap();
        let block = params.genesis_block().unwrap();
        let hash = block.block_hash();
        let pos = store.append(&block).unwrap();
        let mut prefetch = BlockPrefetcher::new().unwrap();
        prefetch.begin(&store);
        assert!(prefetch.schedule(hash, pos));
        prefetch.finish();
        assert_eq!(prefetch.reserved(), (0, 0, 0));

        prefetch.begin(&store);
        assert!(prefetch.schedule(hash, pos));
        assert_eq!(prefetch.take(hash), Some(block));
        drop(prefetch); // joins the persistent workers on destruction
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reservations_bound_window_and_decoded_bytes() {
        let dir = test_dir();
        let params = Network::Regtest.params();
        let store = BlockStore::open(&dir, params.message_start).unwrap();
        let mut prefetch = BlockPrefetcher::new().unwrap();
        prefetch.begin(&store);
        for i in 0..WINDOW + 1 {
            let hash = BlockHash::from_bytes([i as u8; 32]);
            let _ = prefetch.schedule(
                hash,
                BlockPos {
                    file: 0,
                    offset: 8,
                    len: 512_000,
                },
            );
        }
        let (count, serialized, decoded) = prefetch.reserved();
        assert!(count <= WINDOW);
        assert!(serialized <= SERIALIZED_BUDGET);
        assert!(decoded <= DECODED_BUDGET);
        assert_eq!(count, WINDOW, "small frames fit the bounded read window");
        prefetch.finish();
        drop(prefetch);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn maximum_size_bodies_fit_two_reader_budget() {
        let dir = test_dir();
        let params = Network::Regtest.params();
        let store = BlockStore::open(&dir, params.message_start).unwrap();
        let mut prefetch = BlockPrefetcher::new().unwrap();
        prefetch.begin(&store);
        for i in 0..2 {
            assert!(prefetch.schedule(
                BlockHash::from_bytes([0xa0 + i as u8; 32]),
                BlockPos {
                    file: 0,
                    offset: 8,
                    len: crate::block::MAX_BLOCK_SERIALIZED_SIZE as u32,
                },
            ));
        }
        let (count, serialized, decoded) = prefetch.reserved();
        assert_eq!(count, 2);
        assert_eq!(serialized, 2 * crate::block::MAX_BLOCK_SERIALIZED_SIZE);
        assert!(decoded <= DECODED_BUDGET);
        assert!(decoded >= 2 * crate::block::MAX_BLOCK_SERIALIZED_SIZE * 64);

        assert!(!prefetch.schedule(
            BlockHash::from_bytes([0xa2; 32]),
            BlockPos {
                file: 0,
                offset: 8,
                len: 400_000,
            },
        ));
        prefetch.finish();
        drop(prefetch);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
}

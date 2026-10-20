//! Revalidate an already-connected recent main-chain window on a datadir
//! clone, measuring the ordinary disconnect/reconsider/activation path.
//!
//! The source directory is only canonicalized for alias/overlap checks and is
//! never opened as a chainstate. All writes go to the separately supplied
//! work directory, which must be a stopped-node copy.
//!
//! Usage:
//! ```text
//! replay_window_probe --source-dir LIVE --work-dir COPY \
//!   --expected-tip-height H --expected-tip-hash HASH [--count 128] [--start H]
//! ```
//! Run separate baseline/candidate processes over independent copies. Baseline
//! settings: `AVILA_PREVOUT_WORKERS=0 AVILA_CLEAN_CACHE=0
//! AVILA_BLOCK_PREFETCH=0`; candidate settings: `AVILA_PREVOUT_WORKERS=2
//! AVILA_CLEAN_CACHE=1 AVILA_BLOCK_PREFETCH=1`. Keep chainstate and redb caches
//! at 256 MiB (`AVILA_COINS_CACHE_MB=256` for the redb cache), build, cache
//! warmup, and resource caps fixed. This is a
//! recent-window result, not a whole-IBD speed claim.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use avila_consensus::chainstate::Chainstate;
use avila_consensus::coinsdb::Engine;
use avila_consensus::params::Network;
use avila_consensus::store::read_state;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as u32
}

fn usage() -> ! {
    eprintln!(
        "usage: replay_window_probe --source-dir LIVE --work-dir COPY \\\n         --expected-tip-height H --expected-tip-hash HASH [--count 128] [--start H]"
    );
    std::process::exit(2);
}

fn canonical(path: &Path, name: &str) -> PathBuf {
    path.canonicalize()
        .unwrap_or_else(|e| panic!("canonicalize {name} {}: {e}", path.display()))
}

fn fmt(d: Duration) -> String {
    format!("{:.3}s", d.as_secs_f64())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut source = None;
    let mut work = None;
    let mut expected_height = None;
    let mut expected_hash = None;
    let mut count = 128u32;
    let mut requested_start = None;
    while let Some(flag) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage());
        match flag.as_str() {
            "--source-dir" => source = Some(PathBuf::from(value())),
            "--work-dir" => work = Some(PathBuf::from(value())),
            "--expected-tip-height" => expected_height = Some(value().parse::<u32>().unwrap()),
            "--expected-tip-hash" => expected_hash = Some(value().parse().unwrap()),
            "--count" => count = value().parse().unwrap(),
            "--start" => requested_start = Some(value().parse::<u32>().unwrap()),
            _ => usage(),
        }
    }
    let source = canonical(&source.unwrap_or_else(|| usage()), "immutable source");
    let work = canonical(&work.unwrap_or_else(|| usage()), "work copy");
    let expected_height = expected_height.unwrap_or_else(|| usage());
    let expected_hash = expected_hash.unwrap_or_else(|| usage());
    assert!(count > 0, "window count must be nonzero");
    let prevout_workers = std::env::var("AVILA_PREVOUT_WORKERS").unwrap_or_default();
    let clean_cache = std::env::var("AVILA_CLEAN_CACHE").unwrap_or_default();
    let block_prefetch = std::env::var("AVILA_BLOCK_PREFETCH").unwrap_or_default();
    let redb_cache_mb = std::env::var("AVILA_COINS_CACHE_MB").unwrap_or_default();
    let baseline = prevout_workers == "0"
        && clean_cache == "0"
        && block_prefetch == "0"
        && redb_cache_mb == "256";
    let candidate = prevout_workers == "2"
        && clean_cache == "1"
        && block_prefetch == "1"
        && redb_cache_mb == "256";
    assert!(
        baseline || candidate,
        "expected exact baseline or candidate env tuple: workers={prevout_workers:?} clean_cache={clean_cache:?} block_prefetch={block_prefetch:?} redb_cache_mb={redb_cache_mb:?}"
    );
    let treatment = if baseline { "baseline" } else { "candidate" };
    eprintln!(
        "treatment={treatment} prevout_workers={prevout_workers} clean_cache={clean_cache} block_prefetch={block_prefetch} dbcache_mib=256 redb_cache_mb={redb_cache_mb} assume_valid=None"
    );
    assert!(
        source != work && !source.starts_with(&work) && !work.starts_with(&source),
        "source and work paths must be disjoint; refusing to mutate an aliased or nested source"
    );

    let mut params = Network::Mainnet.params();
    params.assume_valid = None;
    let state = read_state(&work, params.message_start)
        .expect("read copied state.dat")
        .expect("copied state.dat is required");
    let open_started = Instant::now();
    let mut cs = Chainstate::with_store_coinsdb(&work, &params, now(), 256 << 20)
        .expect("open copied chainstate");
    let open_wall = open_started.elapsed();
    cs.enable_speculative_connect();

    let tip_height = cs.chain().len() as u32 - 1;
    assert_eq!(
        tip_height, expected_height,
        "copy tip height differs from source receipt"
    );
    assert_eq!(
        cs.tip_hash(),
        expected_hash,
        "copy tip hash differs from source receipt"
    );
    assert_eq!(state.height, expected_height, "state.dat height mismatch");
    assert_eq!(state.tip, expected_hash, "state.dat tip mismatch");
    let start = requested_start.unwrap_or_else(|| {
        tip_height
            .checked_add(1)
            .and_then(|n| n.checked_sub(count))
            .expect("tip is shorter than requested replay window")
    });
    let end = start
        .checked_add(count - 1)
        .expect("replay window height overflow");
    assert!(
        start > 0 && end == tip_height,
        "window must end at the recorded tip"
    );

    let backend = cs.utxo().backend().expect("coinsdb backend is required");
    assert_eq!(
        backend.engine(),
        Engine::Redb,
        "probe requires redb coins engine"
    );
    assert_eq!(
        backend.tip_height(),
        tip_height,
        "coinsdb must be durably at tip"
    );
    let (floor, floor_hash) = backend
        .undo_floor()
        .expect("read undo floor")
        .unwrap_or((0, cs.chain()[0]));
    assert!(
        start > floor,
        "requested rewind parent {} is below undo floor {floor}",
        start - 1
    );
    let preflight_started = Instant::now();
    for height in start..=end {
        let hash = cs.chain()[height as usize];
        assert!(
            cs.body_stored(&hash),
            "body is missing or pruned at height {height}: {hash}"
        );
        assert!(
            cs.body(&hash).is_some(),
            "body cannot be decoded at height {height}: {hash}"
        );
        let undo_hash = backend
            .undo_block_hash(height)
            .unwrap_or_else(|| panic!("persisted undo missing at height {height}"));
        assert_eq!(
            undo_hash, hash,
            "undo block-hash mismatch at height {height}"
        );
        assert!(
            backend.undo_at(height).is_some(),
            "undo cannot be decoded at height {height}"
        );
    }
    let preflight_wall = preflight_started.elapsed();
    let coin_count = backend.coins_len();
    assert_eq!(
        coin_count,
        cs.utxo().len() as u64,
        "coinsdb/chainstate coin count mismatch"
    );
    let initial_hash_started = Instant::now();
    let initial_utxo_hash = backend
        .hash_serialized_3()
        .expect("stream initial UTXO commitment");
    let initial_hash_wall = initial_hash_started.elapsed();
    let first_hash = cs.chain()[start as usize];
    let parent_hash = cs.chain()[start as usize - 1];
    eprintln!(
        "replay preflight: source={} work={} tip={tip_height}:{expected_hash} window={start}..={end} count={count} undo_floor={floor}:{floor_hash} coins={coin_count} utxo={initial_utxo_hash} open={} preflight={} initial_hash={} prevout_workers={} clean_cache={} block_prefetch={} redb_cache_mb={}",
        source.display(),
        work.display(),
        fmt(open_wall),
        fmt(preflight_wall),
        fmt(initial_hash_wall),
        prevout_workers,
        clean_cache,
        block_prefetch,
        redb_cache_mb,
    );

    let replay_started = Instant::now();
    let rewound = cs
        .invalidate_block(&first_hash)
        .expect("disconnect replay window");
    assert!(
        rewound.is_some(),
        "window start block disappeared from block index"
    );
    assert_eq!(
        cs.tip_hash(),
        parent_hash,
        "disconnect did not land on the requested parent"
    );
    assert!(
        cs.reconsider_block(&first_hash)
            .expect("reconsider replay window")
    );
    assert_eq!(
        cs.tip_hash(),
        expected_hash,
        "activation did not restore the expected tip"
    );
    let activation_wall = replay_started.elapsed();
    let drain_started = Instant::now();
    cs.drain_scripts()
        .expect("drain full-validation script checks");
    let script_drain_wall = drain_started.elapsed();

    let flush_started = Instant::now();
    cs.flush().expect("durable replay checkpoint");
    let flush_wall = flush_started.elapsed();
    drop(cs);
    let reopen_started = Instant::now();
    let reopened = Chainstate::with_store_coinsdb(&work, &params, now(), 256 << 20)
        .expect("reopen replayed copy");
    let reopen_wall = reopen_started.elapsed();
    assert_eq!(reopened.tip_hash(), expected_hash, "reopened tip hash");
    assert_eq!(
        reopened.chain().len() as u32 - 1,
        expected_height,
        "reopened tip height"
    );
    let reopened_backend = reopened.utxo().backend().expect("reopened coinsdb backend");
    assert_eq!(
        reopened_backend.tip_height(),
        expected_height,
        "reopened durable coins tip"
    );
    assert_eq!(
        reopened_backend.coins_len(),
        coin_count,
        "reopened full UTXO count"
    );
    let digest_started = Instant::now();
    let reopened_hash = reopened_backend
        .hash_serialized_3()
        .expect("stream reopened UTXO commitment");
    let digest_wall = digest_started.elapsed();
    assert_eq!(
        reopened_hash, initial_utxo_hash,
        "full UTXO commitment changed after replay"
    );
    eprintln!(
        "replay result: validated={count} tip={expected_height}:{expected_hash} coins={coin_count} utxo={reopened_hash} activate={} script_drain={} flush={} reopen={} final_hash={} total={}",
        fmt(activation_wall),
        fmt(script_drain_wall),
        fmt(flush_wall),
        fmt(reopen_wall),
        fmt(digest_wall),
        fmt(open_wall
            + preflight_wall
            + initial_hash_wall
            + activation_wall
            + script_drain_wall
            + flush_wall
            + reopen_wall
            + digest_wall),
    );
}

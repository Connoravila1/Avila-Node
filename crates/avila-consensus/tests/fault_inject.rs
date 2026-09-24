//! Crash fault-injection for the coinsdb engines — experiment #16.
//!
//! Simulates torn writes at each commit phase by manipulating the
//! on-disk files between `commit`s, then reopens and classifies the
//! outcome: recover-exact / fail-safe wedge / SILENT CORRUPTION.
//! The harness works through the public `CoinsBackend` +
//! `HashStore` APIs; only the file bytes are touched directly.
//!
//! Commit ordering under `Engine::Hash`:
//!   1. `commit_coins` — log bytes (in-place overwrites + tail
//!      appends), then index slots, then the header count
//!   2. `sync` — fsync dat then idx
//!   3. redb write tx — undo records + `meta` (tip, coins_len)
//!
//! A crash between 2 and 3 leaves hash coins ahead of the persisted
//! tip; a crash inside 1 leaves torn records/slots.

// Fault-injection asserts on outcomes — panics are the test mechanism.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use avila_consensus::coinsdb::{CoinsBackend, Engine};
use avila_consensus::connect::Coin;
use avila_consensus::transaction::{OutPoint, Script, TxOut};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("avila-fault-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn op(n: u8, vout: u32) -> OutPoint {
    OutPoint {
        txid: avila_consensus::hash::Txid::from_bytes([n; 32]),
        vout,
    }
}

fn coin(value: i64, height: u32) -> Coin {
    Coin {
        out: TxOut {
            value,
            script_pubkey: Script::new(vec![0x51]), // OP_1
        },
        height,
        coinbase: false,
    }
}

fn put(ops: &[(u8, u32)], value: i64, height: u32) -> HashMap<OutPoint, Option<Coin>> {
    ops.iter()
        .map(|&(n, v)| (op(n, v), Some(coin(value, height))))
        .collect()
}

/// File size + content helpers.
fn len_of(p: &Path) -> u64 {
    std::fs::metadata(p).unwrap().len()
}
fn trunc(p: &Path, len: u64) {
    std::fs::File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_len(len)
        .unwrap();
}
fn write_at(p: &Path, off: u64, bytes: &[u8]) {
    use std::os::unix::fs::FileExt;
    std::fs::File::options()
        .write(true)
        .open(p)
        .unwrap()
        .write_all_at(bytes, off)
        .unwrap();
}
fn read_at(p: &Path, off: u64, n: usize) -> Vec<u8> {
    use std::os::unix::fs::FileExt;
    let mut b = vec![0u8; n];
    std::fs::File::open(p)
        .unwrap()
        .read_exact_at(&mut b, off)
        .unwrap();
    b
}

// ---------------------------------------------------------------
// Class 1 — torn `coins.dat` tail: the index references records
// whose bytes never made it to disk (crash after index write,
// before/inside the dat flush of the *previous* tail).
// ---------------------------------------------------------------
#[test]
fn torn_dat_tail_loses_coins_detectably() {
    let d = dir("dat-tail");
    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let ops: Vec<(u8, u32)> = (0..64).map(|n| (n, 0)).collect();
    be.commit(&put(&ops, 100, 1), &[], 1).unwrap();
    drop(be);

    // Truncate the log tail — the tail block's records are gone.
    let dat = d.join("coins.dat");
    trunc(&dat, len_of(&dat) - 40);

    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let mut missing = 0;
    let mut present = 0;
    for &(n, v) in &ops {
        if be.get(&op(n, v)).is_some() {
            present += 1;
        } else {
            missing += 1;
        }
    }
    // Fail-safe: a slot whose record read fails reports absent —
    // a wedge (detectable), not a corrupt value.
    assert!(missing > 0, "truncated tail should cost coins");
    println!("torn dat tail: {present} readable, {missing} lost");
}

// ---------------------------------------------------------------
// Class 2 — torn record bytes: an in-place overwrite torn mid-way
// leaves a mix of old+new record. Does decode reject it?
// ---------------------------------------------------------------
#[test]
fn torn_record_bytes_silent_corruption_probe() {
    let d = dir("rec-tear");
    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let ops: Vec<(u8, u32)> = (0..16).map(|n| (n, 0)).collect();
    be.commit(&put(&ops, 111, 1), &[], 1).unwrap();
    drop(be);

    // Corrupt every 4th byte across the whole records region —
    // stands in for any mid-record tear.
    let dat = d.join("coins.dat");
    let len = len_of(&dat);
    for off in (64..len).step_by(3) {
        write_at(&dat, off, &[0xAB]);
    }

    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let mut ok = 0;
    let mut wrong_value = 0;
    let mut missing = 0;
    for &(n, v) in &ops {
        match be.get(&op(n, v)) {
            Some(c) if c.out.value == 111 => ok += 1,
            Some(_) => wrong_value += 1,
            None => missing += 1,
        }
    }
    println!("torn record bytes: {ok} intact, {wrong_value} corrupted, {missing} lost");
    // DOCUMENTED FINDING: compact records carry no integrity tag —
    // byte damage can decode to a wrong-but-valid coin. This test
    // only measures; the verdict is the printout + the absence of a
    // panic. If wrong_value > 0 the tear is a silent-corruption path.
}

// ---------------------------------------------------------------
// Class 3 — torn slot write: 48-byte slot written partially.
// Offset field zeroed -> slot reads as empty; probe chains break.
// ---------------------------------------------------------------
#[test]
fn torn_slot_write() {
    let d = dir("slot-tear");
    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let ops: Vec<(u8, u32)> = (0..32).map(|n| (n, 0)).collect();
    be.commit(&put(&ops, 55, 1), &[], 1).unwrap();
    drop(be);

    // Zero the offset+len bytes of the first occupied slot we can
    // find: a torn write that wrote the key but not the pointer.
    let idx = d.join("coins.idx");
    let mut hit = None;
    for i in 0.. {
        let at = 64 + i * 48;
        if at + 48 > len_of(&idx) {
            break;
        }
        let slot = read_at(&idx, at, 48);
        let off = u64::from_le_bytes(slot[36..44].try_into().unwrap());
        if off != 0 {
            write_at(&idx, at + 36, &[0u8; 12]);
            hit = Some(i);
            break;
        }
    }
    let victim = hit.expect("no occupied slot found");

    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let mut present = 0;
    let mut missing = 0;
    for &(n, v) in &ops {
        if be.get(&op(n, v)).is_some() {
            present += 1;
        } else {
            missing += 1;
        }
    }
    println!("torn slot {victim}: {present} readable, {missing} lost (probe-chain cascade)");
}

// ---------------------------------------------------------------
// Class 4 — the ordering tear: hash coins committed, redb
// bookkeeping tx lost. Simulated by committing then restoring the
// pre-commit redb file — meta tip falls behind the hash state.
// ---------------------------------------------------------------
#[test]
fn coins_ahead_of_tip_undetected() {
    let d = dir("tip-tear");
    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let ops_a: Vec<(u8, u32)> = (0..8).map(|n| (n, 0)).collect();
    be.commit(&put(&ops_a, 100, 1), &[], 1).unwrap();
    let redb = d.join("coinsdb.redb");
    let saved = d.join("coinsdb.redb.saved");
    std::fs::copy(&redb, &saved).unwrap();

    // "Block 2": spend ops_a[0], add 8 new coins.
    let mut dirty: HashMap<OutPoint, Option<Coin>> = HashMap::new();
    dirty.insert(op(0, 0), None);
    let ops_b: Vec<(u8, u32)> = (16..24).map(|n| (n, 0)).collect();
    dirty.extend(put(&ops_b, 200, 2));
    be.commit(&dirty, &[], 2).unwrap();
    assert_eq!(be.tip_height(), 2);
    drop(be);

    // Crash: the redb tx never happened — restore its pre-commit copy.
    std::fs::copy(&saved, &redb).unwrap();

    // The index-header watermark (written in phase 1, before the
    // lost meta tx) detects the tear at open — loud error instead
    // of a MissingInput wedge downstream.
    match CoinsBackend::open_with_engine(&d, Engine::Hash) {
        Err(e) => {
            println!("ordering tear DETECTED at open: {e}");
            assert!(e.to_string().contains("torn commit"));
        }
        Ok(_) => panic!("coins-ahead-of-tip went undetected"),
    }
}

// ---------------------------------------------------------------
// Class 5 — hashstore-level: tail-append torn mid-record with a
// valid varint prefix. The slot's len covers the torn record, the
// read succeeds, decode may produce a wrong coin.
// ---------------------------------------------------------------
#[test]
fn torn_record_partial_tail() {
    let d = dir("rec-partial");
    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    // Big records (long scripts) make mid-record tears meaningful.
    let mut dirty = HashMap::new();
    for n in 0..8u8 {
        dirty.insert(
            op(n, 0),
            Some(Coin {
                out: TxOut {
                    value: 123_456,
                    script_pubkey: Script::new(vec![0x42; 200]), // long script
                },
                height: 7,
                coinbase: true,
            }),
        );
    }
    be.commit(&dirty, &[], 1).unwrap();
    drop(be);

    // Cut the last record in half — its slot still points at the
    // full length; the read pulls zeros.
    let dat = d.join("coins.dat");
    trunc(&dat, len_of(&dat) - 100);

    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let mut verdicts = Vec::new();
    for n in 0..8u8 {
        match be.get(&op(n, 0)) {
            Some(c) => verdicts.push(format!(
                "{n}: value={} spk_len={}",
                c.out.value,
                c.out.script_pubkey.len()
            )),
            None => verdicts.push(format!("{n}: MISSING")),
        }
    }
    println!("torn partial record: {verdicts:?}");
}

// ---------------------------------------------------------------
// Class 6 — torn compact swaps. The generation pair must heal from
// whichever rename persisted, using the surviving .new file.
// ---------------------------------------------------------------

/// Stamps the idx header generation (`[56..64]`).
fn stamp_idx_gen(d: &Path, file: &str, g: u64) {
    write_at(&d.join(file), 56, &g.to_le_bytes());
}
/// Stamps the dat header generation (`[12..20]`).
fn stamp_dat_gen(d: &Path, file: &str, g: u64) {
    write_at(&d.join(file), 12, &g.to_le_bytes());
}

fn seeded_store(name: &str) -> PathBuf {
    let d = dir(name);
    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let ops: Vec<(u8, u32)> = (0..24).map(|n| (n, 0)).collect();
    be.commit(&put(&ops, 42, 1), &[], 1).unwrap();
    be.compact_coins().unwrap();
    drop(be);
    d
}

fn all_coins(be: &CoinsBackend, n: u8) -> (usize, usize) {
    let mut ok = 0;
    let mut miss = 0;
    for i in 0..n {
        match be.get(&op(i, 0)) {
            Some(c) if c.out.value == 42 => ok += 1,
            _ => miss += 1,
        }
    }
    (ok, miss)
}

#[test]
fn torn_compact_idx_won_heals_via_dat_new() {
    let d = seeded_store("torn-idx-won");
    // Crash: idx.new -> idx landed, dat.new -> dat did not.
    // Live: idx gen 2, dat gen 1; coins.dat.new (gen 2) survives.
    stamp_idx_gen(&d, "coins.idx", 2);
    std::fs::copy(d.join("coins.dat"), d.join("coins.dat.new")).unwrap();
    stamp_dat_gen(&d, "coins.dat.new", 2);

    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let (ok, miss) = all_coins(&be, 24);
    println!("torn compact (idx won): healed — {ok} ok, {miss} lost");
    assert_eq!(miss, 0, "healed swap must keep every coin");
    assert_eq!(ok, 24);
    assert!(!d.join("coins.dat.new").exists());
}

#[test]
fn torn_compact_dat_won_heals_via_idx_new() {
    let d = seeded_store("torn-dat-won");
    // Crash: dat.new -> dat landed, idx.new -> idx did not.
    stamp_dat_gen(&d, "coins.dat", 2);
    std::fs::copy(d.join("coins.idx"), d.join("coins.idx.new")).unwrap();
    stamp_idx_gen(&d, "coins.idx.new", 2);

    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let (ok, miss) = all_coins(&be, 24);
    println!("torn compact (dat won): healed — {ok} ok, {miss} lost");
    assert_eq!(miss, 0);
    assert_eq!(ok, 24);
    assert!(!d.join("coins.idx.new").exists());
}

#[test]
fn torn_compact_no_rename_stays_consistent() {
    let d = seeded_store("torn-none");
    // Crash before either rename: stale .new files only.
    std::fs::copy(d.join("coins.idx"), d.join("coins.idx.new")).unwrap();
    std::fs::copy(d.join("coins.dat"), d.join("coins.dat.new")).unwrap();
    stamp_idx_gen(&d, "coins.idx.new", 2);
    stamp_dat_gen(&d, "coins.dat.new", 2);

    let be = CoinsBackend::open_with_engine(&d, Engine::Hash).unwrap();
    let (ok, miss) = all_coins(&be, 24);
    assert_eq!((ok, miss), (24, 0));
    assert!(!d.join("coins.idx.new").exists());
    assert!(!d.join("coins.dat.new").exists());
}

#[test]
fn torn_compact_without_new_file_errors() {
    let d = seeded_store("torn-nolife");
    // Worst case: generations mismatch AND no .new to heal from.
    stamp_idx_gen(&d, "coins.idx", 2);

    match CoinsBackend::open_with_engine(&d, Engine::Hash) {
        Err(e) => {
            println!("unhealable torn compact DETECTED: {e}");
            assert!(e.to_string().contains("torn compact"));
        }
        Ok(_) => panic!("gen mismatch with no .new opened anyway"),
    }
}

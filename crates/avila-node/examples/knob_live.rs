// Probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Live-check of the control channel: run a real node against a
//! regtest peer, flip knobs mid-run, and print the journal's
//! `config_changed`/`config_rejected` lines as proof they landed.
//!
//! Usage: `knob_live <addr:port> <data_dir>` — the peer is a listening
//! bitcoind/Knots (or another avila) on regtest; the data dir gets the
//! `events.ndjson` journal. Cancels itself after a short soak.

use avila_consensus::params::Network;
use avila_node::sync::{ControlMsg, SyncConfig, run};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

fn main() {
    let peer: SocketAddr = std::env::args()
        .nth(1)
        .expect("usage: knob_live <peer addr:port> <data_dir>")
        .parse()
        .expect("peer addr");
    let dir = std::env::args()
        .nth(2)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp/avila-knob-live"));
    let params = Network::Regtest.params();

    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<ControlMsg>();
    let cfg = SyncConfig {
        connect: vec![peer],
        target_height: u32::MAX,
        timeout: std::time::Duration::from_secs(86_400),
        data_dir: Some(dir.clone()),
        persist: true,
        cancel: Some(cancel.clone()),
        control: Some(Arc::new(std::sync::Mutex::new(rx))),
        ..SyncConfig::default()
    };

    let worker = std::thread::spawn(move || run(&params, &cfg, |_| {}));
    std::thread::sleep(std::time::Duration::from_secs(8));

    // Live edits: one boolean, one enum, one int — then a deliberate
    // bad value and a restart-only knob, both of which must reject.
    let edits = [
        ("net.blocks_only", serde_json::json!(true)),
        ("relay.tx.announce", serde_json::json!("none")),
        ("relay.block.serve", serde_json::json!("tip")),
        ("sync.max_in_transit", serde_json::json!(64)),
        ("relay.tx.announce", serde_json::json!("bogus-value")),
        ("indexes.txindex", serde_json::json!(true)),
    ];
    for (path, value) in edits {
        tx.send(ControlMsg::Set {
            path: path.to_string(),
            value,
        })
        .unwrap();
    }
    std::thread::sleep(std::time::Duration::from_secs(4));

    cancel.store(true, Ordering::Relaxed);
    let report = worker.join().expect("sync worker panicked");
    println!("sync report: {report:?}");

    // The journal is the receipt — print every config event it holds.
    let journal = dir.join("events.ndjson");
    let text = std::fs::read_to_string(&journal).expect("events.ndjson missing");
    for line in text.lines() {
        if line.contains("config_") {
            println!("{line}");
        }
    }
}

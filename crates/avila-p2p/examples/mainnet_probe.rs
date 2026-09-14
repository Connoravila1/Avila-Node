//! Live mainnet evidence: resolve a DNS seed, handshake a real Bitcoin
//! peer, and validate a page of actual mainnet headers through
//! `Chainstate::accept_header` — the same code path that matched Core
//! verdict-for-verdict on the header fixtures.
//!
//! Bounded by design: one peer, at most `--pages` header pages, then a
//! clean disconnect. This is exactly what light clients and crawlers do.
//!
//! Usage: `mainnet_probe [--pages N]` (default 1, each ≤2000 headers).

use std::time::{Duration, Instant};

use avila_consensus::chainstate::Chainstate;
use avila_consensus::params::Network;
use avila_p2p::manager::{NetEvent, PeerManager};

fn main() -> Result<(), String> {
    let pages: u32 = std::env::args()
        .position(|a| a == "--pages")
        .and_then(|i| std::env::args().nth(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let params = Network::Mainnet.params();
    let mut mgr = PeerManager::new(4);
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    };

    let learned = mgr.seed_from_dns(&params, now());
    println!("dns seeds → {learned} candidate addresses");
    let dialed = mgr.maintain_outbounds(params.message_start, 0);
    println!("dialed {} candidates", dialed.len());

    let start = Instant::now();
    let mut cs = Chainstate::new(&params);
    let mut headers_seen = 0usize;
    let mut pages_seen = 0u32;
    loop {
        for event in mgr.tick_net(&mut cs, now(), params.message_start, 0) {
            match event {
                NetEvent::Connected { peer, info } => println!(
                    "peer {peer}: {} v{} height {}",
                    info.user_agent, info.version, info.start_height
                ),
                NetEvent::Disconnected { peer, reason } => {
                    println!("peer {peer} gone: {reason:?}")
                }
                NetEvent::Announced { .. } | NetEvent::TipAdvanced(_) => {}
            }
        }
        let indexed = cs.tree().len() - 1;
        if indexed > headers_seen {
            headers_seen = indexed;
            pages_seen += 1;
            println!(
                "validated {} mainnet headers, tip {}",
                headers_seen,
                cs.tree().tip_hash()
            );
        }
        if pages_seen >= pages {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            return Err(format!("timed out with {headers_seen} headers"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    println!(
        "done: {} real mainnet headers validated via Chainstate in {:?}",
        headers_seen,
        start.elapsed()
    );
    Ok(())
}

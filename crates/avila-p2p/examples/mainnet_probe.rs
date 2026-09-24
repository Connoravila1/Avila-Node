//! Live network evidence: resolve a DNS seed, handshake real Bitcoin
//! peers, and validate actual headers — and optionally blocks — through
//! `Chainstate`. Works on any network with DNS seeds.
//!
//! Bounded by design: at most `--pages` header pages and `--blocks`
//! connected blocks, then a clean disconnect.
//!
//! Usage: `mainnet_probe [--net mainnet|signet|testnet4|regtest]
//!        [--pages N] [--blocks N]` (defaults: mainnet, 1 page).

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
    // --blocks N: after the headers pages, download and connect bodies
    // h1..=N through the full pipeline (script checks correctly skip —
    // the blocks are far below assumevalid, as in Core's IBD).
    let blocks: u32 = std::env::args()
        .position(|a| a == "--blocks")
        .and_then(|i| std::env::args().nth(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let net = std::env::args()
        .position(|a| a == "--net")
        .and_then(|i| std::env::args().nth(i + 1))
        .unwrap_or_else(|| "mainnet".to_string());
    let network = match net.as_str() {
        "mainnet" => Network::Mainnet,
        "signet" => Network::Signet,
        "testnet4" => Network::Testnet4,
        "regtest" => Network::Regtest,
        other => return Err(format!("unknown net {other}")),
    };
    let params = network.params();
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
                NetEvent::EclipseSuspected(signals) => {
                    println!("eclipse indicators: {signals:?}")
                }
                NetEvent::ReconDivergence {
                    peer, their_misses, ..
                } => println!("peer {peer}: {their_misses} recon their-misses — filtered view?"),
                NetEvent::Announced { .. } | NetEvent::TipAdvanced(_) => {}
            }
        }
        let indexed = cs.tree().len() - 1;
        if indexed > headers_seen {
            headers_seen = indexed;
            pages_seen += 1;
            println!(
                "validated {} {net} headers, tip {}",
                headers_seen,
                cs.tree().tip_hash()
            );
        }
        let connected = cs.chain().len() as u32 - 1;
        if pages_seen >= pages && connected >= blocks {
            break;
        }
        if start.elapsed() > Duration::from_secs(120) {
            return Err(format!("timed out with {headers_seen} headers"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    println!(
        "done: {} {net} headers validated, {} blocks connected via Chainstate in {:?}",
        headers_seen,
        cs.chain().len() - 1,
        start.elapsed()
    );
    Ok(())
}

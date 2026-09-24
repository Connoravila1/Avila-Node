// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! End-to-end PeerManager evidence: connect to a Bitcoin peer over real
//! TCP and let the manager drive the whole sync — handshake, headers
//! phase, and the per-tick download scheduler — into a consensus-
//! validated `Chainstate`.
//!
//! Usage: `peer_manager <peer-ip:port> [target-height]`
//! e.g. against a local Knots/Core regtest node with 120 blocks:
//!   peer_manager 127.0.0.1:58322 120

use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

use avila_consensus::chainstate::Chainstate;
use avila_consensus::params::Network;
use avila_p2p::manager::{NetEvent, PeerManager};

fn main() -> Result<(), String> {
    // Positional args: peer addresses (any count) then a bare number = target height.
    let mut addrs = Vec::new();
    let mut target = -1i64;
    for arg in std::env::args().skip(1) {
        match arg.parse::<SocketAddr>() {
            Ok(a) => addrs.push(a),
            Err(_) if target < 0 => target = arg.parse().unwrap_or(-1),
            Err(_) => {}
        }
    }
    if addrs.is_empty() {
        return Err("usage: peer_manager <peer-ip:port>... [target-height]".to_string());
    }

    let params = Network::Regtest.params();
    let mut cs = Chainstate::new(&params);
    let mut mgr = PeerManager::new(8);
    for (i, addr) in addrs.iter().enumerate() {
        let peer = mgr
            .connect(*addr, params.message_start, 0xaaaa_bbbb + i as u64, 0, true)
            .map_err(|e| format!("connect {addr}: {e}"))?
            .ok_or("peer set full")?;
        println!("dialing {addr} as peer {peer}");
    }

    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    };
    let start = Instant::now();
    let mut last_tip = -1i64;
    loop {
        for event in mgr.tick(&mut cs, now()) {
            match event {
                NetEvent::Connected { peer, info } => println!(
                    "peer {peer} established: {} v{} height {}",
                    info.user_agent, info.version, info.start_height
                ),
                NetEvent::Disconnected { peer, reason } => {
                    println!("peer {peer} gone: {reason:?}")
                }
                NetEvent::TipAdvanced(h) => {
                    if i64::from(h) != last_tip {
                        last_tip = i64::from(h);
                        println!("tip → h{h}");
                    }
                }
                NetEvent::Announced { peer, missing } => {
                    println!("peer {peer} announced {} blocks we lack", missing.len())
                }
                NetEvent::EclipseSuspected(signals) => {
                    println!("eclipse indicators: {signals:?}")
                }
                NetEvent::ReconDivergence {
                    peer, their_misses, ..
                } => println!("peer {peer}: {their_misses} recon their-misses — filtered view?"),
                NetEvent::CpuThrottled { peer, rate_ns } => {
                    println!("peer {peer}: cpu-throttled at {rate_ns}ns/s")
                }
                NetEvent::ProxyUnreachable => println!("proxy unreachable — private route down"),
            }
        }
        let tip = cs.chain().len() as i64 - 1;
        if target > 0 && tip >= target {
            break;
        }
        if start.elapsed() > Duration::from_secs(90) {
            return Err(format!("timed out at h{tip}"));
        }
        thread::sleep(Duration::from_millis(10));
    }
    println!(
        "synced: h{} via PeerManager in {:?} ({} peers, {} in-flight)",
        cs.chain().len() - 1,
        start.elapsed(),
        mgr.len(),
        mgr.in_flight()
    );
    Ok(())
}

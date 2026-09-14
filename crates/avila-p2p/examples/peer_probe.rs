//! Interop probe: connects to a listening Bitcoin peer over real TCP, runs
//! the version handshake, then synchronizes headers-first — paging
//! `getheaders`, feeding blocks via `inv`/`getdata`, and validating every
//! arrived block through `Chainstate`. Exits when the connected tip reaches
//! the peer's announced height (or prints progress and exits nonzero on
//! timeout).
//!
//! ```sh
//! cargo run -p avila-p2p --example peer_probe -- 127.0.0.1:18444 [mainnet]
//! ```

use std::net::TcpStream;
use std::time::{Duration, Instant};

use avila_consensus::chainstate::Chainstate;
use avila_consensus::hash::BlockHash;
use avila_consensus::params::Network;
use avila_p2p::message::{Message, NetAddr};
use avila_p2p::session::{PeerSession, SessionEvent, build_version};
use avila_p2p::sync::PeerSync;

#[allow(clippy::expect_used)] // a probe binary may fail loudly
fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:18444".to_string());
    let network = match std::env::args().nth(2).as_deref() {
        Some("mainnet") => Network::Mainnet,
        Some("signet") => Network::Signet,
        Some("testnet4") => Network::Testnet4,
        _ => Network::Regtest,
    };
    let params = network.params();
    let sock: std::net::SocketAddr = addr.parse().expect("bad host:port");
    let stream = TcpStream::connect_timeout(&sock, Duration::from_secs(5)).expect("connect failed");
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("timeout");
    stream.set_nonblocking(true).expect("nonblocking");

    let version = build_version(
        0x5eed_5eed_5eed_5eed,
        0,
        NetAddr {
            services: 0,
            ip: match sock.ip() {
                std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                std::net::IpAddr::V6(v6) => v6.octets(),
            },
            port: sock.port(),
        },
    );
    let mut session =
        PeerSession::initiate(stream, params.message_start, version, 8 << 20).expect("initiate");
    let mut cs = Chainstate::new(&params);
    let mut sync = PeerSync::new();
    let mut target: i64 = -1; // peer's announced tip height
    let start = Instant::now();
    let now = || -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    };

    for round in 0..6000 {
        let events = match session.poll() {
            Ok(e) => e,
            Err(e) => {
                println!("session error after {} polls: {e}", round + 1);
                std::process::exit(1);
            }
        };
        for event in events {
            match event {
                SessionEvent::Established => {
                    target = session
                        .peer()
                        .map(|p| i64::from(p.start_height))
                        .unwrap_or(-1);
                    println!(
                        "handshake complete — peer claims height {target} ({})",
                        session
                            .peer()
                            .map(|p| p.user_agent.clone())
                            .unwrap_or_default()
                    );
                    let req = sync.request_headers(&cs);
                    session.send(&req).expect("send getheaders");
                }
                SessionEvent::Message(Message::Headers(headers)) => {
                    let n = headers.len();
                    match sync.on_headers(&mut cs, &headers, now()) {
                        Ok(outcome) => {
                            println!(
                                "headers page: {n} received, {} new, tip now h{}",
                                outcome.added,
                                cs.chain().len().saturating_sub(1)
                            );
                            if let Some(next) = outcome.continuation {
                                session.send(&next).expect("continuation");
                            } else {
                                // Headers phase done — fetch every indexed
                                // body we lack, in chain order.
                                let want: Vec<BlockHash> = cs
                                    .tree()
                                    .headers_by_height()
                                    .iter()
                                    .map(|h| h.hash())
                                    .filter(|h| !cs.have_body(h))
                                    .collect();
                                println!("headers done — fetching {} block bodies", want.len());
                                for chunk in want.chunks(16) {
                                    if let Some(req) = sync.want_blocks(&cs, chunk) {
                                        session.send(&req).expect("getdata");
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("bad headers: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                SessionEvent::Message(Message::Inv(invs)) => {
                    if let Some(req) = sync.on_inv(&cs, &invs, usize::MAX) {
                        session.send(&req).expect("getdata");
                    }
                }
                SessionEvent::Message(Message::Block(block)) => {
                    match sync.on_block(&mut cs, &block, now()) {
                        Ok(outcome) => {
                            let h = cs.chain().len().saturating_sub(1);
                            if h.is_multiple_of(100) {
                                println!("connected h{h}");
                            }
                            let _ = outcome;
                        }
                        Err(e) => {
                            println!("bad block {}: {e}", block.block_hash());
                            std::process::exit(1);
                        }
                    }
                }
                SessionEvent::Message(m) => {
                    println!("peer sent: {}", m.command_name());
                }
            }
        }
        // More getdata as in-flight slots free up.
        if !sync.awaiting_headers() && sync.in_flight() < 16 {
            let want: Vec<BlockHash> = cs
                .tree()
                .headers_by_height()
                .iter()
                .map(|h| h.hash())
                .filter(|h| !cs.have_body(h))
                .take(32)
                .collect();
            if !want.is_empty()
                && let Some(req) = sync.want_blocks(&cs, &want)
            {
                let _ = session.send(&req);
            }
        }
        let tip = cs.chain().len().saturating_sub(1) as i64;
        if target >= 0 && tip >= target {
            println!(
                "synced: h{tip} in {:?} ({} headers indexed, {} blocks)",
                start.elapsed(),
                sync.headers_applied(),
                tip
            );
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    println!(
        "timeout: tip h{} of target {target}",
        cs.chain().len().saturating_sub(1)
    );
    std::process::exit(1);
}

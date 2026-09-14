//! Interop server probe: optionally syncs a chainstate from an upstream
//! peer (`--from host:port`), then listens for one inbound peer and serves
//! `getheaders`/`getdata` from it. A fresh bitcoind pointed at the listen
//! address (`-addnode=127.0.0.1:<port>`) downloads the whole chain from us.
//!
//! ```sh
//! cargo run -p avila-p2p --example peer_serve -- --from 127.0.0.1:58322 --listen 127.0.0.1:58340
//! ```

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use avila_consensus::chainstate::Chainstate;
use avila_consensus::params::Network;
use avila_p2p::message::{Message, NetAddr};
use avila_p2p::session::{PeerSession, SessionEvent, build_version};
use avila_p2p::sync::PeerSync;

fn net_addr(sock: SocketAddr) -> NetAddr {
    NetAddr {
        services: 0,
        ip: match sock.ip() {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            std::net::IpAddr::V6(v6) => v6.octets(),
        },
        port: sock.port(),
    }
}

fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Drives a session: feeds session events through `sync`/`cs`, sends
/// whatever the sync layer asks for, and returns per-tick events.
#[allow(clippy::expect_used)]
fn pump<S: std::io::Read + std::io::Write>(
    session: &mut PeerSession<S>,
    cs: &mut Chainstate,
    sync: &mut PeerSync,
    syncing: bool,
) -> Result<(), String> {
    let events = session.poll().map_err(|e| e.to_string())?;
    for event in events {
        match event {
            SessionEvent::Established => {
                if syncing {
                    let req = sync.request_headers(cs);
                    session.send(&req).map_err(|e| e.to_string())?;
                }
            }
            SessionEvent::Message(Message::Headers(headers)) => {
                let outcome = sync
                    .on_headers(cs, &headers, now_secs())
                    .map_err(|e| e.to_string())?;
                if let Some(next) = outcome.continuation {
                    session.send(&next).map_err(|e| e.to_string())?;
                } else if !outcome.fetchable.is_empty()
                    && let Some(req) = sync.want_blocks(cs, &outcome.fetchable)
                {
                    session.send(&req).map_err(|e| e.to_string())?;
                }
            }
            SessionEvent::Message(Message::Inv(invs)) => {
                if let Some(req) = sync.on_inv(cs, &invs) {
                    session.send(&req).map_err(|e| e.to_string())?;
                }
            }
            SessionEvent::Message(Message::Block(block)) => {
                sync.on_block(cs, &block, now_secs())
                    .map_err(|e| e.to_string())?;
            }
            SessionEvent::Message(Message::GetHeaders(req)) => {
                let reply = PeerSync::serve_getheaders(cs, &req);
                session.send(&reply).map_err(|e| e.to_string())?;
            }
            SessionEvent::Message(Message::GetData(reqs)) => {
                for reply in PeerSync::serve_getdata(cs, &reqs) {
                    session.send(&reply).map_err(|e| e.to_string())?;
                }
            }
            SessionEvent::Message(_) => {}
        }
    }
    Ok(())
}

#[allow(clippy::expect_used)]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let from = args
        .iter()
        .position(|a| a == "--from")
        .and_then(|i| args.get(i + 1));
    let listen = args
        .iter()
        .position(|a| a == "--listen")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:58340".to_string());
    let params = Network::Regtest.params();
    let mut cs = Chainstate::new(&params);

    // Phase 1: fetch the chain from an upstream peer, if given.
    if let Some(upstream) = from {
        let sock: SocketAddr = upstream.parse().expect("bad --from");
        let stream =
            TcpStream::connect_timeout(&sock, Duration::from_secs(5)).expect("connect failed");
        stream.set_nonblocking(true).expect("nonblocking");
        let mut session = PeerSession::initiate(
            stream,
            params.message_start,
            build_version(0xabba_abba, 0, net_addr(sock)),
            8 << 20,
        )
        .expect("initiate");
        let mut sync = PeerSync::new();
        let start = Instant::now();
        let mut target = i64::MAX;
        loop {
            pump(&mut session, &mut cs, &mut sync, true).expect("sync pump");
            if let Some(p) = session.peer() {
                target = i64::from(p.start_height);
            }
            // Keep the fetch queue full.
            if sync.in_flight() < 16 {
                let want: Vec<_> = cs
                    .tree()
                    .headers_by_height()
                    .iter()
                    .map(|h| h.hash())
                    .filter(|h| !cs.have_body(h))
                    .take(32)
                    .collect();
                if let Some(req) = sync.want_blocks(&cs, &want) {
                    let _ = session.send(&req);
                }
            }
            if target > 0 && cs.chain().len() as i64 > target {
                break;
            }
            if start.elapsed() > Duration::from_secs(60) {
                panic!("upstream sync timed out at h{}", cs.chain().len() - 1);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        println!(
            "fetched h{} from upstream in {:?}",
            cs.chain().len() - 1,
            start.elapsed()
        );
    } else {
        println!("no --from; serving genesis-only chainstate");
    }

    // Phase 2: serve one inbound peer.
    let listen_sock: SocketAddr = listen.parse().expect("bad --listen");
    let listener = TcpListener::bind(listen_sock).expect("bind failed");
    println!("listening on {listen_sock} with h{}", cs.chain().len() - 1);
    listener.set_nonblocking(false).expect("blocking accept");
    let (stream, peer_addr) = listener.accept().expect("accept failed");
    stream.set_nonblocking(true).expect("nonblocking");
    println!("inbound peer: {peer_addr}");
    let mut session = PeerSession::accept(
        stream,
        params.message_start,
        build_version(
            0xbeef_beef,
            cs.chain().len() as i32 - 1,
            net_addr(peer_addr),
        ),
        8 << 20,
    );
    let start = Instant::now();
    let mut served_headers = 0usize;
    let mut served_blocks = 0usize;
    loop {
        // Wrap pump to count what we served.
        let events = session.poll();
        match events {
            Ok(events) => {
                for event in events {
                    match event {
                        SessionEvent::Established => println!("handshake complete"),
                        SessionEvent::Message(Message::GetHeaders(req)) => {
                            let reply = PeerSync::serve_getheaders(&cs, &req);
                            if let Message::Headers(h) = &reply {
                                served_headers += h.len();
                            }
                            session.send(&reply).expect("headers reply");
                        }
                        SessionEvent::Message(Message::GetData(reqs)) => {
                            for reply in PeerSync::serve_getdata(&cs, &reqs) {
                                if matches!(reply, Message::Block(_)) {
                                    served_blocks += 1;
                                }
                                session.send(&reply).expect("block reply");
                            }
                        }
                        SessionEvent::Message(Message::Version(v)) => {
                            println!("peer version {} height {}", v.version, v.start_height);
                        }
                        SessionEvent::Message(Message::Inv(_)) => {}
                        SessionEvent::Message(m) => println!("peer sent {}", m.command_name()),
                    }
                }
            }
            Err(e) => {
                println!(
                    "session ended: {e} (served {served_headers} headers, {served_blocks} blocks in {:?})",
                    start.elapsed()
                );
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
        if start.elapsed() > Duration::from_secs(120) {
            println!("done after 120s: served {served_headers} headers, {served_blocks} blocks");
            return;
        }
    }
}

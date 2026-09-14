//! Interop probe: opens a real TCP connection to a listening Bitcoin peer,
//! runs the version handshake, asks for headers from a locator, and prints
//! what comes back. Usage:
//!
//! ```sh
//! cargo run -p avila-p2p --example peer_probe -- 127.0.0.1:18444 [magic-fafa|mainnet]
//! ```
//!
//! Defaults to regtest magic (Core's `fabfb5da`); pass `mainnet` for the
//! mainnet message start.

use std::net::TcpStream;
use std::time::Duration;

use avila_consensus::hash::BlockHash;
use avila_p2p::message::{GetHeaders, Message, NetAddr};
use avila_p2p::session::{PeerSession, SessionEvent, build_version};

const REGTEST_MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];
const MAINNET_MAGIC: [u8; 4] = [0xf9, 0xbe, 0xb4, 0xd9];

#[allow(clippy::expect_used)] // a probe binary may fail loudly
fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:18444".to_string());
    let magic = match std::env::args().nth(2).as_deref() {
        Some("mainnet") => MAINNET_MAGIC,
        _ => REGTEST_MAGIC,
    };
    let sock: std::net::SocketAddr = addr.parse().expect("bad host:port");
    let stream = TcpStream::connect_timeout(&sock, Duration::from_secs(5)).expect("connect failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");

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
    let mut session = PeerSession::initiate(stream, magic, version, 1 << 20).expect("initiate");
    let mut got_headers = false;

    for round in 0..200 {
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
                    println!("handshake complete: peer={:?}", session.peer());
                    // Ask for headers after the regtest genesis (or a
                    // zero locator if we don't know it — genesis hash
                    // suffices; the peer answers from the first fork).
                    let genesis: BlockHash =
                        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
                            .parse()
                            .expect("genesis hash");
                    session
                        .send(&Message::GetHeaders(GetHeaders {
                            locator: vec![genesis],
                            stop: BlockHash::ZERO,
                        }))
                        .expect("send getheaders");
                }
                SessionEvent::Message(Message::Headers(headers)) => {
                    println!("headers: {} received", headers.len());
                    for h in headers.iter().take(3) {
                        println!("  {} <- {}", h.prev_block_hash, h.hash());
                    }
                    got_headers = true;
                }
                SessionEvent::Message(m) => {
                    println!("peer sent: {}", m.command_name());
                }
            }
        }
        if got_headers {
            println!("done");
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    println!("timed out waiting for headers");
    std::process::exit(1);
}

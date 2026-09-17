//! Live BIP324 interop check — ignored by default; needs a
//! v2-capable peer listening on 127.0.0.1:18457 (a regtest Core
//! works). Run: `cargo test -p avila-p2p --test v2_live -- --ignored`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use avila_p2p::message::NetAddr;
use avila_p2p::session::{PeerSession, SessionEvent, build_version, wall_epoch};
use std::net::TcpStream;

#[test]
#[ignore]
fn live_core_v2() {
    let magic: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];
    let s = TcpStream::connect("127.0.0.1:18457").unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let v = build_version(1, 0, NetAddr::unspecified(), wall_epoch());
    let mut sess = PeerSession::initiate_v2(s, magic, v, 1 << 20).unwrap();
    let mut established = false;
    for _ in 0..40 {
        match sess.poll() {
            Ok(events) => {
                for e in events {
                    if matches!(e, SessionEvent::Established) {
                        established = true;
                    }
                }
            }
            Err(e) => panic!("session error: {e}"),
        }
        if established {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(established, "v2 session never established");
    assert_eq!(sess.transport_protocol(), "v2");
    assert!(sess.v2_session_id().is_some());
}

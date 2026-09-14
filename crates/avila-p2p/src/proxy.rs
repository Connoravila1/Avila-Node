//! SOCKS5 no-auth CONNECT — Core's `-proxy`/`onion` traffic path. A peer
//! address behind a proxy (Tor's local SOCKS5, or any SOCKS5) is dialed
//! through the proxy rather than directly; the P2P session then runs
//! over the proxied stream unchanged. Only the no-auth method is
//! offered, matching Core.

use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

/// What the proxy should connect to: an IP endpoint, or a domain name
/// (`.onion` reaches its hidden service this way — the proxy resolves).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocksTarget {
    /// A resolved socket address.
    Ip(SocketAddr),
    /// A DNS name or `.onion` plus port — the proxy resolves.
    Domain(String, u16),
}

impl From<SocketAddr> for SocksTarget {
    fn from(addr: SocketAddr) -> Self {
        Self::Ip(addr)
    }
}

const SOCKS_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
/// Longest legal domain name per RFC 1035 — bounds the request buffer.
const MAX_DOMAIN_LEN: usize = 253;

fn io_err(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Opens `target` through the SOCKS5 proxy at `proxy`, returning a
/// connected stream. The handshake is fully bounded: a domain target is
/// capped at 253 bytes and the reply is parsed by type, never trusted
/// for length.
pub fn socks5_connect(
    proxy: &SocketAddr,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<std::net::TcpStream> {
    let mut stream = std::net::TcpStream::connect_timeout(proxy, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // Method negotiation: offer only no-auth.
    stream.write_all(&[SOCKS_VERSION, 0x01, AUTH_NONE])?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    if reply != [SOCKS_VERSION, AUTH_NONE] {
        return Err(io_err("SOCKS5 proxy refused no-auth method"));
    }

    // CONNECT request.
    let mut req = vec![SOCKS_VERSION, CMD_CONNECT, 0x00];
    match target {
        SocksTarget::Ip(SocketAddr::V4(a)) => {
            req.push(ATYP_IPV4);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
        SocksTarget::Ip(SocketAddr::V6(a)) => {
            req.push(ATYP_IPV6);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
        SocksTarget::Domain(name, port) => {
            if name.len() > MAX_DOMAIN_LEN || name.is_empty() {
                return Err(io_err("SOCKS5 domain target length out of range"));
            }
            req.push(ATYP_DOMAIN);
            req.push(name.len() as u8);
            req.extend_from_slice(name.as_bytes());
            req.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&req)?;

    // Reply: ver, rep, rsv, atyp, then the bound address by type.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != SOCKS_VERSION {
        return Err(io_err("SOCKS5 reply has wrong version"));
    }
    if head[1] != 0x00 {
        return Err(io_err("SOCKS5 proxy reported connect failure"));
    }
    let skip = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            usize::from(len[0])
        }
        _ => return Err(io_err("SOCKS5 reply has unknown address type")),
    };
    // Bound address + port — read and discard.
    let mut buf = vec![0u8; skip + 2];
    stream.read_exact(&mut buf)?;

    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(stream)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};

    /// A mock SOCKS5 server: accepts, negotiates no-auth, parses the
    /// CONNECT, replies success with an IPv4 bound addr. Returns the
    /// request's target bytes for assertion.
    fn mock_socks5() -> (SocketAddr, std::sync::mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            s.write_all(&[0x05, 0x00]).unwrap();
            let mut head = [0u8; 4];
            s.read_exact(&mut head).unwrap();
            assert_eq!(head[..3], [0x05, 0x01, 0x00]);
            let rest = match head[3] {
                0x01 => 4,
                0x04 => 16,
                0x03 => {
                    let mut l = [0u8; 1];
                    s.read_exact(&mut l).unwrap();
                    let mut d = vec![0u8; l[0] as usize];
                    s.read_exact(&mut d).unwrap();
                    let mut port = [0u8; 2];
                    s.read_exact(&mut port).unwrap();
                    let mut v = vec![l[0]];
                    v.extend(d);
                    v.extend(port);
                    tx.send(v).unwrap();
                    s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .unwrap();
                    return;
                }
                _ => panic!("bad atyp"),
            };
            let mut tgt = vec![0u8; rest + 2];
            s.read_exact(&mut tgt).unwrap();
            tx.send(tgt).unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });
        (addr, rx)
    }

    #[test]
    fn connect_ipv4_through_proxy() {
        let (proxy, rx) = mock_socks5();
        let target = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 8333);
        let _s = socks5_connect(&proxy, &SocksTarget::Ip(target), Duration::from_secs(5)).unwrap();
        let got = rx.recv().unwrap();
        let mut want = target
            .ip()
            .to_string()
            .parse::<Ipv4Addr>()
            .unwrap()
            .octets()
            .to_vec();
        want.extend_from_slice(&8333u16.to_be_bytes());
        assert_eq!(got, want);
    }

    #[test]
    fn connect_ipv6_through_proxy() {
        let (proxy, rx) = mock_socks5();
        let target = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 18333);
        let _s = socks5_connect(&proxy, &SocksTarget::Ip(target), Duration::from_secs(5)).unwrap();
        let got = rx.recv().unwrap();
        let mut want = Ipv6Addr::LOCALHOST.octets().to_vec();
        want.extend_from_slice(&18333u16.to_be_bytes());
        assert_eq!(got, want);
    }

    #[test]
    fn connect_domain_through_proxy() {
        let (proxy, rx) = mock_socks5();
        let t = SocksTarget::Domain("example.onion".into(), 8333);
        let _s = socks5_connect(&proxy, &t, Duration::from_secs(5)).unwrap();
        let got = rx.recv().unwrap();
        let mut want = vec![13u8];
        want.extend_from_slice(b"example.onion");
        want.extend_from_slice(&8333u16.to_be_bytes());
        assert_eq!(got, want);
    }

    #[test]
    fn proxy_refusal_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).unwrap();
            // Refuse every method.
            s.write_all(&[0x05, 0xff]).unwrap();
        });
        assert!(
            socks5_connect(
                &addr,
                &SocksTarget::Ip("1.2.3.4:8333".parse().unwrap()),
                Duration::from_secs(5),
            )
            .is_err()
        );
    }
}

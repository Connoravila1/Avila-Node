//! The address book — `CAddrMan`'s core without the new/tried bucket
//! matrix: a bounded table of gossiped [`NetAddr`]s with last-seen
//! timestamps, a tried flag set once a connection succeeds, and a
//! deterministic selection order (round-robin by recency).
//!
//! The bucket matrix exists to resist eclipse attacks; it matters once
//! we take untrusted inbound gossip on real networks. For now the table
//! is strictly bounded and recency-sorted, which keeps an attacker's
//! influence proportional to the share of *recent* addresses they feed
//! us — and nothing here is consensus-critical.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use std::net::ToSocketAddrs;

use crate::message::NetAddr;

/// Table cap — Core's `ADDRMAN_NEW_BUCKETS*TRIES` space is far larger;
/// ours only needs to outlive a discovery bootstrap.
pub const ADDR_TABLE_CAP: usize = 4096;

/// `getaddr` replies carry at most this many addresses (Core sends ~1000,
/// i.e. 23% of its table).
pub const GETADDR_REPLY_MAX: usize = 1000;

/// `peers.dat` file magic + format version.
const PEERS_MAGIC: [u8; 6] = *b"APEERS";
const PEERS_VERSION: u32 = 1;

/// One gossiped address with what we've learned about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddrInfo {
    /// The network address itself.
    pub addr: NetAddr,
    /// Last time a peer reported it (their timestamp, clamped to now).
    pub last_seen: u32,
    /// We connected successfully at least once.
    pub tried: bool,
    /// Failed or in-progress connection attempts.
    pub attempts: u8,
}

/// Table key — `CAddress::GetKey` is (ip, port): services are a
/// mutable property of the entry, not part of its identity.
type AddrKey = ([u8; 16], u16);

const fn key_of(addr: &NetAddr) -> AddrKey {
    (addr.ip, addr.port)
}

/// A bounded, recency-ordered address table.
#[derive(Default)]
pub struct AddrBook {
    /// Keyed by (ip, port) — one entry per endpoint.
    table: HashMap<AddrKey, AddrInfo>,
    /// Monotonic intake counter → deterministic "newest first" order.
    seq: HashMap<AddrKey, u64>,
    next_seq: u64,
    cap: usize,
}

impl AddrBook {
    /// An empty table with the default cap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(ADDR_TABLE_CAP)
    }

    /// An empty table with an explicit cap (tests shrink it).
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            table: HashMap::new(),
            seq: HashMap::new(),
            next_seq: 0,
            cap,
        }
    }

    /// Table size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Records `addr` as gossiped at `seen` (clamped to `now`; Core
    /// discounts future timestamps by a week). Unroutable endpoints are
    /// rejected like `AddrManImpl::AddSingle` — Core's book only ever
    /// holds publicly-routable addresses. Returns whether a new entry
    /// was inserted (`false` for duplicates and rejects).
    pub fn add(&mut self, addr: NetAddr, seen: u32, now: u32) -> bool {
        if network_of(&addr) == Network::Unroutable {
            return false;
        }
        let key = key_of(&addr);
        if let Some(e) = self.table.get_mut(&key) {
            // Refresh recency and union services (Core's AddSingle does
            // `nServices |= addr.nServices` even when nothing new is
            // inserted) — but don't reset tried/attempts.
            e.last_seen = seen.min(now).max(e.last_seen);
            e.addr.services |= addr.services;
            return false;
        }
        if self.table.len() >= self.cap {
            self.evict_oldest();
        }
        self.seq.insert(key, self.next_seq);
        self.next_seq += 1;
        self.table.insert(
            key,
            AddrInfo {
                addr,
                last_seen: seen.min(now),
                tried: false,
                attempts: 0,
            },
        );
        true
    }

    /// Bulk gossip intake (`addr`/`addrv2` messages).
    pub fn add_many(&mut self, addrs: impl Iterator<Item = (NetAddr, u32)>, now: u32) {
        for (addr, seen) in addrs {
            self.add(addr, seen, now);
        }
    }

    /// A connection attempt is starting.
    pub fn mark_attempt(&mut self, addr: &NetAddr) {
        if let Some(e) = self.table.get_mut(&key_of(addr)) {
            e.attempts = e.attempts.saturating_add(1);
        }
    }

    /// A connection succeeded — Core's `CAddrInfo::fInTried`.
    pub fn mark_tried(&mut self, addr: &NetAddr) {
        if let Some(e) = self.table.get_mut(&key_of(addr)) {
            e.tried = true;
            e.attempts = 0;
        }
    }

    /// Drops the entry (e.g. the peer proved unreachable or hostile).
    pub fn forget(&mut self, addr: &NetAddr) {
        self.table.remove(&key_of(addr));
        self.seq.remove(&key_of(addr));
    }

    /// Picks the next outbound candidate: fewest attempts first, then
    /// most recently seen. Core mixes new/tried randomly; deterministic
    /// recency order is adequate until the bucket matrix lands.
    #[must_use]
    pub fn select(&self) -> Option<NetAddr> {
        self.table
            .values()
            .min_by_key(|e| (e.attempts, std::cmp::Reverse(e.last_seen)))
            .map(|e| e.addr)
    }

    /// A bounded sample for `getaddr` replies — most recent first.
    #[must_use]
    pub fn sample(&self) -> Vec<NetAddr> {
        let mut entries: Vec<_> = self.table.values().collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.last_seen));
        entries
            .into_iter()
            .take(GETADDR_REPLY_MAX)
            .map(|e| e.addr)
            .collect()
    }

    /// Up to `count` entries for `getnodeaddresses` — Core's
    /// `GetAddresses(count, 0, network)`: `0` means all, `network`
    /// filters by [`Network`]. Newest first.
    #[must_use]
    pub fn entries(&self, count: usize, network: Option<Network>) -> Vec<AddrInfo> {
        let mut entries: Vec<_> = self
            .table
            .values()
            .filter(|e| network.is_none_or(|n| network_of(&e.addr) == n))
            .collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.last_seen));
        entries
            .into_iter()
            .take(if count == 0 { usize::MAX } else { count })
            .cloned()
            .collect()
    }

    /// Writes the table to `path` — Core's `peers.dat`: versioned,
    /// checksummed, and atomic (tmp + rename) so a crash mid-write never
    /// leaves a torn file. A corrupted file just loses gossip history —
    /// never consensus state.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        use avila_consensus::encode::write_compact_size;
        let mut body = Vec::with_capacity(self.table.len() * 32);
        body.extend_from_slice(&PEERS_VERSION.to_le_bytes());
        write_compact_size(&mut body, self.table.len() as u64);
        for e in self.table.values() {
            body.extend_from_slice(&e.last_seen.to_le_bytes());
            body.push(u8::from(e.tried));
            body.push(e.attempts);
            body.extend_from_slice(&e.addr.services.to_le_bytes());
            body.extend_from_slice(&e.addr.ip);
            body.extend_from_slice(&e.addr.port.to_le_bytes());
        }
        let mut out = PEERS_MAGIC.to_vec();
        out.extend_from_slice(&avila_consensus::hash::sha256d(&body));
        out.extend_from_slice(&body);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &out)?;
        std::fs::rename(&tmp, path)
    }

    /// Loads a saved table, replacing this book's contents. Returns the
    /// number of entries restored; a missing file yields an empty book
    /// (`Ok(0)`), a corrupt one is an error the caller may ignore.
    pub fn load(&mut self, path: &std::path::Path, now: u32) -> std::io::Result<usize> {
        use avila_consensus::encode::Decoder;
        let raw = match std::fs::read(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed peers file");
        if raw.len() < PEERS_MAGIC.len() + 32 + 4 || raw[..6] != PEERS_MAGIC[..] {
            return Err(bad());
        }
        let body = &raw[PEERS_MAGIC.len() + 32..];
        if avila_consensus::hash::sha256d(body) != raw[PEERS_MAGIC.len()..PEERS_MAGIC.len() + 32] {
            return Err(bad());
        }
        let mut d = Decoder::new(body);
        let version = d.read_u32_le().map_err(|_| bad())?;
        if version != PEERS_VERSION {
            return Err(bad());
        }
        let count = d.read_compact_size().map_err(|_| bad())?;
        if count > ADDR_TABLE_CAP as u64 {
            return Err(bad());
        }
        *self = Self::with_cap(self.cap);
        for _ in 0..count {
            let last_seen = d.read_u32_le().map_err(|_| bad())?;
            let tried = d.read_u8().map_err(|_| bad())? != 0;
            let attempts = d.read_u8().map_err(|_| bad())?;
            let services = d.read_u64_le().map_err(|_| bad())?;
            let ip = d.read_array::<16>().map_err(|_| bad())?;
            let port = d.read_u16_le().map_err(|_| bad())?;
            let addr = NetAddr { services, ip, port };
            let key = key_of(&addr);
            if network_of(&addr) != Network::Unroutable && !self.table.contains_key(&key) {
                self.seq.insert(key, self.next_seq);
                self.next_seq += 1;
                self.table.insert(
                    key,
                    AddrInfo {
                        addr,
                        last_seen: last_seen.min(now),
                        tried,
                        attempts,
                    },
                );
            }
        }
        d.finish().map_err(|_| bad())?;
        Ok(self.table.len())
    }

    /// Oldest-seen entries go first when the cap binds.
    fn evict_oldest(&mut self) {
        if let Some(victim) = self
            .table
            .iter()
            .min_by_key(|(k, e)| (e.last_seen, self.seq.get(*k).copied().unwrap_or(u64::MAX)))
            .map(|(k, _)| *k)
        {
            self.table.remove(&victim);
            self.seq.remove(&victim);
        }
    }
}

/// Resolves a network's `vSeeds` DNS names into address-book entries.
/// Each seed is queried at the network's `default_port`; failed names are
/// skipped (Core treats seed resolution the same way — partial failure is
/// normal). Blocking: call at startup or off the sync loop.
#[must_use]
pub fn resolve_seeds(seeds: &[&str], default_port: u16) -> Vec<NetAddr> {
    let mut out = Vec::new();
    for host in seeds {
        let Ok(resolved) = (*host, default_port).to_socket_addrs() else {
            continue;
        };
        for sock in resolved {
            out.push(net_addr_of(sock, 0));
        }
    }
    out
}

/// `NetAddr` → `SocketAddr` (v4-mapped addresses become real v4).
#[must_use]
pub fn socket_addr(addr: &NetAddr) -> SocketAddr {
    let ip = addr.ip;
    let v6 = Ipv6Addr::from(ip);
    if let Some(v4) = v6.to_ipv4_mapped() {
        SocketAddr::new(IpAddr::V4(v4), addr.port)
    } else {
        SocketAddr::new(IpAddr::V6(v6), addr.port)
    }
}

/// `NetAddr` → the operator-facing `"ip:port"` string (v6 bracketed) —
/// Core's `CAddress::ToStringAddrPort()`, the value `disconnectnode`
/// matches against.
#[must_use]
pub fn addr_string(addr: &NetAddr) -> String {
    socket_addr(addr).to_string()
}

/// Core's `CSubNet::Match` — whether `ip` falls under the first `plen`
/// bits of `net` (both in the 16-byte form, v4 mapped).
#[must_use]
pub fn net_match(ip: &[u8; 16], net: &[u8; 16], plen: u8) -> bool {
    let plen = plen.min(128) as usize;
    let (whole, rem) = (plen / 8, plen % 8);
    ip[..whole] == net[..whole]
        && (rem == 0 || (ip[whole] >> (8 - rem)) == (net[whole] >> (8 - rem)))
}

/// `SocketAddr` → `NetAddr` (v4 becomes v4-mapped on the wire).
#[must_use]
pub fn net_addr_of(sock: SocketAddr, services: u64) -> NetAddr {
    NetAddr {
        services,
        ip: match sock.ip() {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        },
        port: sock.port(),
    }
}

/// The loopback endpoint as a `NetAddr` — used by tests and by a node's
/// self-announcement.
#[must_use]
pub fn loopback(port: u16, services: u64) -> NetAddr {
    net_addr_of(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        services,
    )
}

/// The network class Core's `CNetAddr::GetNetClass` reports — drives
/// `getnodeaddresses`' `network` field and its filter. Onion and I2P
/// can't occur in the book: `NetAddr` only carries IP literals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// Public IPv4 (including routable v6 forms with a linked IPv4).
    Ipv4,
    /// Public IPv6.
    Ipv6,
    /// Tor hidden service — parseable as a filter, never stored.
    Onion,
    /// I2P — parseable as a filter, never stored.
    I2p,
    /// CJDNS (`fc00::/7`).
    Cjdns,
    /// Everything `!CNetAddr::IsRoutable()` — Core reports
    /// `not_publicly_routable` and never stores these.
    Unroutable,
}

/// `GetNetworkName` — the string Core emits in `getnodeaddresses` and
/// `getnetworkinfo`'s `networks` array.
#[must_use]
pub const fn network_name(net: Network) -> &'static str {
    match net {
        Network::Ipv4 => "ipv4",
        Network::Ipv6 => "ipv6",
        Network::Onion => "onion",
        Network::I2p => "i2p",
        Network::Cjdns => "cjdns",
        Network::Unroutable => "not_publicly_routable",
    }
}

/// `ParseNetwork` — the `network` filter values `getnodeaddresses`
/// accepts. Case-insensitive; `tor` is the deprecated alias of `onion`.
/// `None` means "not recognized" (`-8` on the RPC).
#[must_use]
pub fn parse_network(name: &str) -> Option<Network> {
    match name.to_ascii_lowercase().as_str() {
        "ipv4" => Some(Network::Ipv4),
        "ipv6" => Some(Network::Ipv6),
        "onion" | "tor" => Some(Network::Onion),
        "i2p" => Some(Network::I2p),
        "cjdns" => Some(Network::Cjdns),
        _ => None,
    }
}

/// `CNetAddr::GetNetClass` for our byte form: v4-mapped addresses are
/// classified by their embedded IPv4; `fc00::/7` is CJDNS; all other
/// v6 forms are IPv6. Routable 6to4/Teredo/SIIT prefixes report `ipv4`
/// like Core's `HasLinkedIPv4`.
#[must_use]
pub fn network_of(addr: &NetAddr) -> Network {
    let a = &addr.ip;
    let v4_mapped = a[..10] == [0; 10] && a[10] == 0xff && a[11] == 0xff;
    if v4_mapped {
        let v = &a[12..16];
        // IsValid: neither INADDR_ANY nor INADDR_NONE.
        if v == [0; 4] || v == [255; 4] {
            return Network::Unroutable;
        }
        let private = v[0] == 10
            || (v[0] == 172 && (16..32).contains(&v[1]))
            || (v[0] == 192 && v[1] == 168)
            || (v[0] == 198 && (v[1] == 18 || v[1] == 19)) // RFC2544
            || (v[0] == 169 && v[1] == 254) // RFC3927
            || (v[0] == 100 && (64..=127).contains(&v[1])) // RFC6598
            || (v[0] == 192 && v[1] == 0 && v[2] == 2) // RFC5737
            || (v[0] == 198 && v[1] == 51 && v[2] == 100)
            || (v[0] == 203 && v[1] == 0 && v[2] == 113)
            || v[0] == 127
            || v[0] == 0;
        return if private {
            Network::Unroutable
        } else {
            Network::Ipv4
        };
    }
    // IsValid: ::/128 and RFC3849 documentation space are invalid.
    if a == &[0; 16] || a[..4] == [0x20, 0x01, 0x0d, 0xb8] {
        return Network::Unroutable;
    }
    // fc00::/7 lands in the unroutable set like Core without
    // `-cjdnsreachable`: `MaybeFlipIPv6toCJDNS` only flips the class to
    // NET_CJDNS when cjdns is reachable; otherwise the address stays
    // NET_IPV6 and RFC4193 marks it unroutable.
    let unroutable = a[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0] // RFC4862
        || (a[0] & 0xfe) == 0xfc // RFC4193 (unreachable cjdns)
        || (a[..3] == [0x20, 0x01, 0x00] && (a[3] & 0xf0) == 0x10) // RFC4843
        || (a[..3] == [0x20, 0x01, 0x00] && (a[3] & 0xf0) == 0x20); // RFC7343
    if unroutable || (a[..15] == [0; 15] && a[15] == 1) {
        return Network::Unroutable;
    }
    // HasLinkedIPv4: 6to4, Teredo, SIIT — report ipv4 like Core.
    if a[..2] == [0x20, 0x02]
        || a[..4] == [0x20, 0x01, 0x00, 0x00]
        || a[..12] == [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]
    {
        return Network::Ipv4;
    }
    Network::Ipv6
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::message::NODE_NETWORK;

    fn addr(octet: u8, port: u16) -> NetAddr {
        NetAddr {
            services: NODE_NETWORK,
            ip: Ipv4Addr::new(93, 184, 216, octet).to_ipv6_mapped().octets(),
            port,
        }
    }

    #[test]
    fn add_and_select_prefers_recent_untried() {
        let mut book = AddrBook::new();
        book.add(addr(1, 8333), 100, 200);
        book.add(addr(2, 8333), 150, 200);
        assert_eq!(book.len(), 2);
        assert_eq!(book.select(), Some(addr(2, 8333)));
    }

    #[test]
    fn duplicate_refreshes_recency_not_state() {
        let mut book = AddrBook::new();
        book.add(addr(1, 8333), 100, 200);
        book.mark_attempt(&addr(1, 8333));
        book.add(addr(1, 8333), 190, 200);
        let e = &book.table[&key_of(&addr(1, 8333))];
        assert_eq!(e.last_seen, 190);
        assert_eq!(e.attempts, 1); // preserved across re-gossip
    }

    #[test]
    fn cap_evicts_oldest() {
        let mut book = AddrBook::with_cap(2);
        book.add(addr(1, 8333), 100, 200);
        book.add(addr(2, 8333), 150, 200);
        book.add(addr(3, 8333), 190, 200);
        assert_eq!(book.len(), 2);
        assert!(!book.table.contains_key(&key_of(&addr(1, 8333))));
        assert_eq!(book.select(), Some(addr(3, 8333)));
    }

    #[test]
    fn tried_beats_fresh_when_attempts_differ() {
        let mut book = AddrBook::new();
        book.add(addr(1, 8333), 100, 200);
        book.add(addr(2, 8333), 150, 200);
        book.mark_attempt(&addr(2, 8333));
        book.mark_attempt(&addr(2, 8333));
        // addr1: 0 attempts wins over addr2: 2 attempts despite recency.
        assert_eq!(book.select(), Some(addr(1, 8333)));
    }

    #[test]
    fn sample_bounded_and_recent_first() {
        let mut book = AddrBook::new();
        for i in 0..10u8 {
            book.add(addr(i, 8333), 100 + u32::from(i), 200);
        }
        let sample = book.sample();
        assert_eq!(sample.len(), 10);
        assert_eq!(sample[0], addr(9, 8333));
    }

    #[test]
    fn peers_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("apeers-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.dat");
        let mut book = AddrBook::new();
        book.add(addr(1, 8333), 100, 200);
        book.add(addr(2, 18333), 150, 200);
        book.mark_tried(&addr(1, 8333));
        book.mark_attempt(&addr(2, 18333));
        book.save(&path).unwrap();

        let mut fresh = AddrBook::new();
        assert_eq!(fresh.load(&path, 200).unwrap(), 2);
        assert!(
            fresh.table[&key_of(&addr(1, 8333))].tried,
            "tried flag survives"
        );
        assert_eq!(fresh.table[&key_of(&addr(2, 18333))].attempts, 1);
        assert_eq!(fresh.table[&key_of(&addr(2, 18333))].last_seen, 150);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `network_of` — `CNetAddr::GetNetClass` for the byte form. These
    /// cases were checked live against `addpeeraddress` on a Knots 29.3
    /// daemon: unroutable inputs are rejected there, so `add` must
    /// refuse them here.
    #[test]
    fn network_classification_matches_core() {
        let net = |s: &str| {
            let ip: IpAddr = s.parse().unwrap();
            let sock = SocketAddr::new(ip, 8333);
            network_of(&net_addr_of(sock, NODE_NETWORK))
        };
        assert_eq!(net("93.184.216.34"), Network::Ipv4);
        assert_eq!(net("2001:4860:4860::8888"), Network::Ipv6);
        // Routable v6 forms with a linked v4 report ipv4.
        assert_eq!(net("2002::1"), Network::Ipv4); // 6to4
        assert_eq!(net("2001::1"), Network::Ipv4); // Teredo
        assert_eq!(net("64:ff9b::1"), Network::Ipv4); // SIIT
        // Unroutable: private, loopback, link-local, doc ranges.
        assert_eq!(net("10.0.0.1"), Network::Unroutable);
        assert_eq!(net("172.16.0.1"), Network::Unroutable);
        assert_eq!(net("192.168.0.1"), Network::Unroutable);
        assert_eq!(net("169.254.0.1"), Network::Unroutable);
        assert_eq!(net("100.64.0.1"), Network::Unroutable);
        assert_eq!(net("192.0.2.1"), Network::Unroutable);
        assert_eq!(net("198.51.100.1"), Network::Unroutable);
        assert_eq!(net("203.0.113.1"), Network::Unroutable);
        assert_eq!(net("198.18.0.1"), Network::Unroutable);
        assert_eq!(net("127.0.0.1"), Network::Unroutable);
        assert_eq!(net("0.0.0.0"), Network::Unroutable);
        assert_eq!(net("255.255.255.255"), Network::Unroutable);
        assert_eq!(net("::1"), Network::Unroutable);
        assert_eq!(net("::"), Network::Unroutable);
        assert_eq!(net("fe80::1"), Network::Unroutable);
        assert_eq!(net("2001:db8::1"), Network::Unroutable);
        assert_eq!(net("2001:10::1"), Network::Unroutable); // ORCHIDv1
        assert_eq!(net("2001:20::1"), Network::Unroutable); // ORCHIDv2
        // fc00::/7 without -cjdnsreachable stays IPv6 → RFC4193.
        assert_eq!(net("fc00::1"), Network::Unroutable);
        assert_eq!(net("fd00::1"), Network::Unroutable);
        // v4-mapped notation classifies by the embedded v4.
        assert_eq!(net("::ffff:1.2.3.4"), Network::Ipv4);
        assert_eq!(net("::ffff:10.0.0.1"), Network::Unroutable);
    }

    #[test]
    fn unroutable_never_enters_the_book() {
        let mut book = AddrBook::new();
        let local = net_addr_of("10.0.0.1:8333".parse().unwrap(), NODE_NETWORK);
        assert!(!book.add(local, 100, 200));
        assert!(book.is_empty());
        // Duplicates are reported as non-inserts like Core.
        assert!(book.add(addr(1, 8333), 100, 200));
        assert!(!book.add(addr(1, 8333), 150, 200));
        // Different services, same endpoint → one entry, OR'd flags.
        let mut richer = addr(1, 8333);
        richer.services |= 1 << 10; // NODE_NETWORK_LIMITED
        assert!(!book.add(richer, 160, 200));
        let e = &book.table[&key_of(&addr(1, 8333))];
        assert_eq!(e.addr.services, NODE_NETWORK | (1 << 10));
        assert_eq!(e.last_seen, 160);
        // count/network filters drive getnodeaddresses.
        assert_eq!(book.entries(0, None).len(), 1);
        assert_eq!(book.entries(0, Some(Network::Ipv6)).len(), 0);
        assert_eq!(book.entries(0, Some(Network::Ipv4)).len(), 1);
    }

    #[test]
    fn peers_file_missing_and_corrupt() {
        let dir = std::env::temp_dir().join(format!("apeers-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("peers.dat");
        // Missing → empty book, no error.
        let mut book = AddrBook::new();
        assert_eq!(book.load(&path, 0).unwrap(), 0);
        // Corrupt checksum → error, book untouched.
        let mut good = AddrBook::new();
        good.add(addr(9, 8333), 100, 200);
        good.save(&path).unwrap();
        let mut raw = std::fs::read(&path).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();
        assert!(book.load(&path, 0).is_err());
        assert!(book.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn socket_addr_roundtrip() {
        let a = addr(7, 18333);
        assert_eq!(net_addr_of(socket_addr(&a), NODE_NETWORK), a);
        let v6 = NetAddr {
            services: 0,
            ip: Ipv6Addr::LOCALHOST.octets(),
            port: 8333,
        };
        assert_eq!(socket_addr(&v6).port(), 8333);
    }
}

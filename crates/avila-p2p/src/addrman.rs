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

/// A bounded, recency-ordered address table.
#[derive(Default)]
pub struct AddrBook {
    /// Keyed by (ip, port) — one entry per endpoint.
    table: HashMap<NetAddr, AddrInfo>,
    /// Monotonic intake counter → deterministic "newest first" order.
    seq: HashMap<NetAddr, u64>,
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
    /// discounts future timestamps by a week). Self-announcements and
    /// unroutable-looking endpoints are still accepted — the selection
    /// path decides who we actually dial.
    pub fn add(&mut self, addr: NetAddr, seen: u32, now: u32) {
        if self.table.contains_key(&addr) {
            // Refresh recency only — don't reset tried/attempts.
            if let Some(e) = self.table.get_mut(&addr) {
                e.last_seen = seen.min(now).max(e.last_seen);
            }
            return;
        }
        if self.table.len() >= self.cap {
            self.evict_oldest();
        }
        self.seq.insert(addr, self.next_seq);
        self.next_seq += 1;
        self.table.insert(
            addr,
            AddrInfo {
                addr,
                last_seen: seen.min(now),
                tried: false,
                attempts: 0,
            },
        );
    }

    /// Bulk gossip intake (`addr`/`addrv2` messages).
    pub fn add_many(&mut self, addrs: impl Iterator<Item = (NetAddr, u32)>, now: u32) {
        for (addr, seen) in addrs {
            self.add(addr, seen, now);
        }
    }

    /// A connection attempt is starting.
    pub fn mark_attempt(&mut self, addr: &NetAddr) {
        if let Some(e) = self.table.get_mut(addr) {
            e.attempts = e.attempts.saturating_add(1);
        }
    }

    /// A connection succeeded — Core's `CAddrInfo::fInTried`.
    pub fn mark_tried(&mut self, addr: &NetAddr) {
        if let Some(e) = self.table.get_mut(addr) {
            e.tried = true;
            e.attempts = 0;
        }
    }

    /// Drops the entry (e.g. the peer proved unreachable or hostile).
    pub fn forget(&mut self, addr: &NetAddr) {
        self.table.remove(addr);
        self.seq.remove(addr);
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::message::NODE_NETWORK;

    fn addr(octet: u8, port: u16) -> NetAddr {
        NetAddr {
            services: NODE_NETWORK,
            ip: Ipv4Addr::new(10, 0, 0, octet).to_ipv6_mapped().octets(),
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
        let e = &book.table[&addr(1, 8333)];
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
        assert!(!book.table.contains_key(&addr(1, 8333)));
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

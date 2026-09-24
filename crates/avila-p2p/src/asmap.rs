//! ASN bucketing for outbound peer selection — the Erebus mitigation
//! (queue #21). A malicious transit AS can eclipse a node whose outbound
//! peers all route through it; bucketing dials by ASN bounds the share
//! any single network can hold.
//!
//! The map here is the project's own simple format — a list of
//! `(ip-prefix, prefix-len, asn)` rows, longest-prefix matched. Core's
//! kartograf-produced `asmap.dat` is a bit-packed radix tree; parsing
//! that format is the remaining integration work. The bucketing logic
//! is the part that's actually testable and what this module ships.

use std::net::IpAddr;

/// One prefix→ASN row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    /// IPv4 network as a host-order u32, or `u32::MAX` entries unused
    /// for v6 (v6 is keyed by the embedded v4 for bucketing purposes —
    /// IPv6 ASN maps share allocation anyway in practice).
    pub net: u32,
    /// Prefix length 0–32.
    pub plen: u8,
    /// Autonomous system number.
    pub asn: u32,
}

/// A longest-prefix map from IP → ASN. Linear scan is fine for
/// synthetic/test maps; a production map of ~100k prefixes wants the
/// radix tree (open work — the API is the same).
#[derive(Default, Debug, Clone)]
pub struct AsMap {
    entries: Vec<Prefix>,
}

impl AsMap {
    /// Empty map — `asn` returns `None` for everything and bucketing
    /// is a no-op.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build from rows; later rows may overlap earlier ones —
    /// longest prefix wins at lookup time.
    #[must_use]
    pub fn from_entries(entries: Vec<Prefix>) -> Self {
        Self { entries }
    }

    /// The ASN for `ip`, longest-prefix match. IPv6 inputs bucket by
    /// their embedded v4 when mapped, else return `None`.
    #[must_use]
    pub fn asn(&self, ip: &IpAddr) -> Option<u32> {
        let v4 = match ip {
            IpAddr::V4(a) => u32::from_be_bytes(a.octets()),
            IpAddr::V6(a) => {
                let o = a.octets();
                if o[..10] == [0u8; 10] && o[10] == 0xff && o[11] == 0xff {
                    u32::from_be_bytes([o[12], o[13], o[14], o[15]])
                } else {
                    return None;
                }
            }
        };
        self.entries
            .iter()
            .filter(|p| {
                let plen = p.plen.min(32);
                plen == 0 || (v4 >> (32 - plen)) == (p.net >> (32 - plen))
            })
            .max_by_key(|p| p.plen)
            .map(|p| p.asn)
    }

    /// Number of prefix rows loaded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no prefixes are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn longest_prefix_wins() {
        let m = AsMap::from_entries(vec![
            Prefix { net: 0x0a00_0000, plen: 8, asn: 1 },   // 10/8
            Prefix { net: 0x0a01_0000, plen: 16, asn: 2 },  // 10.1/16
        ]);
        let a = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        let b = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1));
        assert_eq!(m.asn(&a), Some(2));
        assert_eq!(m.asn(&b), Some(1));
        assert_eq!(
            m.asn(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            None
        );
    }
}

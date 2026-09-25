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

use std::net::{IpAddr, Ipv4Addr};

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
    /// Audit low: lookups were O(entries) — one hash lookup per
    /// prefix length instead. Keyed by (plen, masked network bits).
    /// Built at load/from_entries; `entries` stays for len/is_empty.
    index: std::collections::HashMap<(u8, u32), u32>,
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
        let mut index = std::collections::HashMap::with_capacity(entries.len());
        for p in &entries {
            let plen = p.plen.min(32);
            let masked = if plen == 0 { 0 } else { p.net >> (32 - plen) };
            // `insert` (not or_insert): the old linear scan kept the
            // LAST duplicate row's ASN — same tie-break.
            index.insert((plen, masked), p.asn);
        }
        Self { entries, index }
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
        // Longest-prefix first — the index makes each probe O(1).
        for plen in (0..=32u8).rev() {
            let masked = if plen == 0 { 0 } else { v4 >> (32 - plen) };
            if let Some(asn) = self.index.get(&(plen, masked)) {
                return Some(*asn);
            }
        }
        None
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

    /// Load a text map: one `a.b.c.d/plen<ws>asn` row per line
    /// (`#` comments and blank lines skipped). Returns the map and
    /// the count of malformed lines skipped — a partial map still
    /// buckets, a wrong one misleads silently, so we report the
    /// count rather than fail or stay quiet.
    ///
    /// This is the operator-facing bridge until Core's bit-packed
    /// `asmap.dat` (kartograf output) parsing lands; a map converted
    /// to these rows drives identical bucketing.
    /// Size guard — a real kartograf-style text asmap is a few MB;
    /// 64 MiB is generous. An unbounded `read_to_string` let a corrupt
    /// or hostile file stall startup on an allocation (audit low).
    const MAX_ASMAP_BYTES: u64 = 64 * 1024 * 1024;
    /// ~1.2M prefixes cover the v4 table several times over.
    const MAX_ASMAP_ENTRIES: usize = 4_000_000;

    pub fn load_file(path: &std::path::Path) -> std::io::Result<(Self, usize)> {
        let meta = std::fs::metadata(path)?;
        if meta.len() > Self::MAX_ASMAP_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "asmap file too large ({} bytes > {})",
                    meta.len(),
                    Self::MAX_ASMAP_BYTES
                ),
            ));
        }
        let text = std::fs::read_to_string(path)?;
        let mut entries = Vec::new();
        let mut skipped = 0usize;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let row = (|| -> Option<Prefix> {
                let cidr = it.next()?;
                let asn: u32 = it.next()?.parse().ok()?;
                if it.next().is_some() {
                    return None;
                }
                let (addr, plen) = cidr.rsplit_once('/')?;
                let ip: Ipv4Addr = addr.parse().ok()?;
                let plen: u8 = plen.parse().ok()?;
                if plen > 32 {
                    return None;
                }
                Some(Prefix {
                    net: u32::from_be_bytes(ip.octets()),
                    plen,
                    asn,
                })
            })();
            match row {
                Some(p) => {
                    if entries.len() >= Self::MAX_ASMAP_ENTRIES {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "asmap entry count exceeds bound",
                        ));
                    }
                    entries.push(p);
                }
                None => skipped += 1,
            }
        }
        Ok((Self::from_entries(entries), skipped))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn longest_prefix_wins() {
        let m = AsMap::from_entries(vec![
            Prefix {
                net: 0x0a00_0000,
                plen: 8,
                asn: 1,
            }, // 10/8
            Prefix {
                net: 0x0a01_0000,
                plen: 16,
                asn: 2,
            }, // 10.1/16
        ]);
        let a = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        let b = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1));
        assert_eq!(m.asn(&a), Some(2));
        assert_eq!(m.asn(&b), Some(1));
        assert_eq!(m.asn(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))), None);
    }

    #[test]
    fn load_file_parses_rows_and_counts_bad_lines() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("asmap-test-{}", std::process::id()));
        std::fs::write(
            &path,
            "# comment\n\n10.0.0.0/8 100\n10.1.0.0/16 200\nbad row\n192.0.2.0/24\t300\n1.2.3.4/33 9\n",
        )
        .unwrap();
        let (m, skipped) = AsMap::load_file(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(m.len(), 3, "three good rows");
        assert_eq!(skipped, 2, "bad row + /33 overflow skipped");
        assert_eq!(
            m.asn(&IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            Some(200),
            "longest prefix wins through the loader"
        );
        assert_eq!(m.asn(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))), Some(300));
    }
}

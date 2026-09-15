//! Manual ban list — Core's `BanMan`: the setban/listbanned/
//! clearbanned backing store plus the `IsBanned` gate the dial and
//! accept paths consult. Entries carry creation/expiry timestamps and
//! persist to `banlist.json` in Core's exact file format so operator
//! bans survive restarts.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde_json::{Value, json};

/// Core's default `-bantime`: 24 hours.
pub const DEFAULT_BANTIME: i64 = 86_400;

/// A banned (or ban-candidate) subnet: the normalized network in
/// 16-byte form (v4 addresses v6-mapped) plus its prefix length
/// (v4 `/n` is stored as `96 + n`, like `CSubNet`'s internal form).
///
/// Ordering is `Ord` on (network, mask) — `std::map<CSubNet,…>`'s
/// comparator — so `listbanned` output is Core-sorted for free
/// (v4-mapped networks precede v6 under byte order).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SubNet {
    /// Network address with the host bits masked off.
    pub network: [u8; 16],
    /// Prefix length in the 16-byte space (`/32` v4 = 128 here).
    pub plen: u8,
}

impl SubNet {
    /// `LookupSubNet`: `"a.b.c.d[/n]"` or `"v6::[/n]"` — literal
    /// addresses only (no DNS, matching setban's `LookupHost(…,
    /// false)` behavior on regtest). A bare v4 becomes `/32` (plen
    /// 128), a bare v6 `/128`; the network is masked to the prefix.
    /// `None` on anything unparseable or a mask past the address size.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (host, plen_s) = match s.split_once('/') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        };
        if let Ok(v4) = host.parse::<Ipv4Addr>() {
            let plen = match plen_s {
                Some(p) => p.parse::<u8>().ok()?,
                None => 32,
            };
            if plen > 32 {
                return None;
            }
            let full = 96 + plen;
            let network = mask_network(&v4.to_ipv6_mapped().octets(), full);
            return Some(Self {
                network,
                plen: full,
            });
        }
        if let Ok(v6) = host.parse::<Ipv6Addr>() {
            let plen = match plen_s {
                Some(p) => p.parse::<u8>().ok()?,
                None => 128,
            };
            if plen > 128 {
                return None;
            }
            let network = mask_network(&v6.octets(), plen);
            return Some(Self {
                network,
                plen,
            });
        }
        None
    }

    /// `CSubNet::Match` — whether `ip` falls under this network.
    #[must_use]
    pub fn matches(&self, ip: &[u8; 16]) -> bool {
        crate::addrman::net_match(ip, &self.network, self.plen)
    }
}

impl fmt::Display for SubNet {
    /// `CSubNet::ToString` — v4-mapped networks print as dotted-quad
    /// with the v4 prefix (`96 + n` → `/n`); v6 prints compressed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v6 = Ipv6Addr::from(self.network);
        if let Some(v4) = v6.to_ipv4_mapped() {
            write!(f, "{}/{}", v4, self.plen.saturating_sub(96))
        } else {
            write!(f, "{}/{}", v6, self.plen)
        }
    }
}

/// `net & mask` — zero the host bits below `plen`.
fn mask_network(net: &[u8; 16], plen: u8) -> [u8; 16] {
    let plen = plen.min(128) as usize;
    let mut out = *net;
    let (whole, rem) = (plen / 8, plen % 8);
    if rem != 0 {
        out[whole] &= 0xff << (8 - rem);
    }
    out[whole + usize::from(rem != 0)..].fill(0);
    out
}

/// One banned entry — `CBanEntry`: wall-clock creation and expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BanEntry {
    /// UNIX epoch the ban was created (the setban call time).
    pub created: i64,
    /// UNIX epoch the ban expires.
    pub until: i64,
}

impl BanEntry {
    /// Whether the ban is still in force at `now` — `IsBanned`'s
    /// `nBanUntil > now` check.
    #[must_use]
    pub fn is_active(&self, now: i64) -> bool {
        self.until > now
    }
}

/// The banned-subnet map — `BanMan`'s `m_banned`. Iteration order is
/// the `CSubNet` comparator via `BTreeMap` (sorted output for
/// `listbanned` without re-sorting).
#[derive(Default)]
pub struct BanList {
    map: BTreeMap<SubNet, BanEntry>,
}

impl BanList {
    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `BanMan::Ban` — insert; `false` when the subnet is already
    /// listed *and* still active (Core's `IsBanned(subNet)` re-add
    /// rejection — an expired entry can be re-banned).
    pub fn ban(&mut self, net: SubNet, created: i64, until: i64) -> bool {
        if self.is_banned_subnet(&net, created) {
            return false;
        }
        self.map.insert(net, BanEntry { created, until });
        true
    }

    /// `BanMan::Unban` — `false` when the subnet wasn't listed.
    pub fn unban(&mut self, net: &SubNet) -> bool {
        self.map.remove(net).is_some()
    }

    /// Drops expired entries — `SweepBanned`, run lazily on reads so
    /// `listbanned` never surfaces a stale ban.
    pub fn sweep(&mut self, now: i64) {
        self.map.retain(|_, e| e.is_active(now));
    }

    /// `BanMan::IsBanned` — any active subnet covering `ip`.
    #[must_use]
    pub fn is_banned(&self, ip: &[u8; 16], now: i64) -> bool {
        self.map
            .iter()
            .any(|(net, e)| e.is_active(now) && net.matches(ip))
    }

    /// `IsBanned(CSubNet)` — the subnet is listed *and* its ban is
    /// still active. setban's already-banned check.
    #[must_use]
    pub fn is_banned_subnet(&self, net: &SubNet, now: i64) -> bool {
        self.map.get(net).is_some_and(|e| e.is_active(now))
    }

    /// Every listed (subnet, entry) pair in Core sort order.
    pub fn entries(&self) -> impl Iterator<Item = (&SubNet, &BanEntry)> {
        self.map.iter()
    }

    /// `clearbanned`.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// `DumpBanlist` — `banlist.json` in Core's exact shape.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let banned_nets: Vec<Value> = self
            .map
            .iter()
            .map(|(net, e)| {
                json!({
                    "version": 1,
                    "ban_created": e.created,
                    "banned_until": e.until,
                    "address": net.to_string(),
                })
            })
            .collect();
        let doc = json!({
            "_warning_": "This file is automatically generated and updated by Bitcoin Core. Please do not edit this file while the node is running, as any changes might be ignored or overwritten.",
            "banned_nets": banned_nets,
        });
        fs::write(path, serde_json::to_string_pretty(&doc)? + "\n")
    }

    /// `LoadBanlist` — parse `banlist.json`; unknown/malformed rows are
    /// skipped (a corrupt file costs the bans, not the boot). The read
    /// is size-capped: a banlist is thousands of small rows at most, so
    /// anything larger is treated as corrupt rather than buffered.
    #[must_use]
    pub fn load(path: &Path) -> Option<Self> {
        if fs::metadata(path).ok()?.len() > 8 * 1024 * 1024 {
            return None;
        }
        let text = fs::read_to_string(path).ok()?;
        let doc: Value = serde_json::from_str(&text).ok()?;
        let mut out = Self::new();
        for row in doc.get("banned_nets")?.as_array()? {
            let (Some(addr), Some(created), Some(until)) = (
                row.get("address").and_then(Value::as_str),
                row.get("ban_created").and_then(Value::as_i64),
                row.get("banned_until").and_then(Value::as_i64),
            ) else {
                continue;
            };
            let Some(net) = SubNet::parse(addr) else {
                continue;
            };
            out.map.insert(net, BanEntry { created, until });
        }
        Some(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        Ipv4Addr::new(a, b, c, d).to_ipv6_mapped().octets()
    }

    #[test]
    fn parse_normalizes_and_defaults_mask() {
        assert_eq!(
            SubNet::parse("10.1.2.3").unwrap().to_string(),
            "10.1.2.3/32"
        );
        assert_eq!(
            SubNet::parse("10.1.2.3/16").unwrap().to_string(),
            "10.1.0.0/16"
        );
        assert_eq!(
            SubNet::parse("2001:db8::1/48").unwrap().to_string(),
            "2001:db8::/48"
        );
        assert_eq!(SubNet::parse("::1").unwrap().to_string(), "::1/128");
        // Edge prefix lengths are fine; past the size is not.
        assert!(SubNet::parse("1.2.3.4/0").is_some());
        assert!(SubNet::parse("::/0").is_some());
        assert!(SubNet::parse("1.2.3.4/33").is_none());
        assert!(SubNet::parse("::/129").is_none());
        assert!(SubNet::parse("bogus").is_none());
        assert!(SubNet::parse("1.2.3.4/").is_none());
        assert!(SubNet::parse("1.2.3.4/x").is_none());
        assert!(SubNet::parse("1.2.3.4/1/2").is_none());
    }

    #[test]
    fn match_respects_prefix() {
        let net = SubNet::parse("192.168.5.0/24").unwrap();
        assert!(net.matches(&v4(192, 168, 5, 99)));
        assert!(!net.matches(&v4(192, 168, 6, 1)));
        // Non-byte-aligned prefix.
        let net = SubNet::parse("10.0.0.0/9").unwrap();
        assert!(net.matches(&v4(10, 127, 0, 1)));
        assert!(!net.matches(&v4(10, 128, 0, 1)));
    }

    #[test]
    fn ban_unban_and_expiry() {
        let mut bans = BanList::new();
        let net = SubNet::parse("1.2.3.4").unwrap();
        assert!(bans.ban(net, NOW, NOW + 60));
        assert!(!bans.ban(net, NOW, NOW + 600), "re-add rejected");
        assert!(bans.is_banned(&v4(1, 2, 3, 4), NOW + 30));
        assert!(!bans.is_banned(&v4(1, 2, 3, 5), NOW + 30));
        // Expired entries stop matching and sweep out on read.
        assert!(!bans.is_banned(&v4(1, 2, 3, 4), NOW + 61));
        // …and a listed-but-expired subnet can be re-banned, matching
        // Core's IsBanned(subNet) activity check.
        assert!(bans.ban(net, NOW + 61, NOW + 120));
        assert!(bans.is_banned_subnet(&net, NOW + 61));
        bans.sweep(NOW + 121);
        assert_eq!(bans.entries().count(), 0);
        assert!(bans.ban(net, NOW, NOW + 10));
        assert!(bans.unban(&net));
        assert!(!bans.unban(&net), "second unban fails");
    }

    #[test]
    fn save_load_roundtrip_core_format() {
        let dir = std::env::temp_dir().join(format!("banman-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("banlist.json");
        let mut bans = BanList::new();
        bans.ban(SubNet::parse("9.9.9.9").unwrap(), NOW, NOW + 600);
        bans.ban(SubNet::parse("2001:db8::/48").unwrap(), NOW, NOW + 60);
        bans.save(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("_warning_"));
        assert!(text.contains("9.9.9.9/32"));
        let loaded = BanList::load(&path).unwrap();
        assert_eq!(loaded.entries().count(), 2);
        assert!(loaded.is_banned(&v4(9, 9, 9, 9), NOW + 1));
        // Sorted: v4-mapped before v6 under byte order.
        let names: Vec<String> = loaded.entries().map(|(n, _)| n.to_string()).collect();
        assert_eq!(names, ["9.9.9.9/32", "2001:db8::/48"]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_tolerates_garbage() {
        let dir = std::env::temp_dir().join(format!("banman-bad-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("banlist.json");
        assert!(BanList::load(&path).is_none(), "missing file");
        fs::write(&path, "not json").unwrap();
        assert!(BanList::load(&path).is_none(), "malformed");
        fs::write(&path, r#"{"banned_nets":[{"address":"bogus","ban_created":1,"banned_until":2},{"address":"8.8.8.8/32","ban_created":1,"banned_until":9999999999}]}"#).unwrap();
        let loaded = BanList::load(&path).unwrap();
        assert_eq!(loaded.entries().count(), 1, "bad row skipped");
        fs::remove_dir_all(&dir).ok();
    }
}

//! What the screens render: a view of the node decoupled from its own
//! types, so a real run and the `--demo` preview feed the same code.

use avila_node::sync::SyncProgress;

#[derive(Clone, Debug, Default)]
pub struct NodeView {
    /// Fully validated height — every script up to here checked (or,
    /// under a snapshot, checked on top of the assumed set).
    pub connected: u32,
    /// Best header height: proof-of-work checked, bodies may be pending.
    pub headers: u32,
    /// The last few connected blocks `(height, display hash)`, newest last.
    pub recent: Vec<(u32, String)>,
    pub peers: Vec<PeerView>,
    pub mempool_txs: usize,
    pub orphans: usize,
    /// Fee rate for ~6-block confirmation, sat/kvB.
    pub fee_rate_sat_kvb: Option<i64>,
    pub uptime_secs: u64,
    pub trust: TrustView,
}

/// What the node has verified versus what it is assuming — the typed
/// validation report behind `getvalidationreport`.
#[derive(Clone, Debug, Default)]
pub struct TrustView {
    pub connected: u32,
    pub headers: u32,
    pub snapshot: Option<SnapshotView>,
    /// Share of the connected chain whose state was verified locally.
    pub verified_fraction: f64,
}

#[derive(Clone, Debug)]
pub struct SnapshotView {
    /// The assumed prefix is `1..=base`.
    pub base: u32,
    pub base_hash: String,
    /// The pinned `hash_serialized_3` the replayed set must equal.
    pub expected_utxo_hash: String,
    /// Background replay has proven `1..=replayed`.
    pub replayed: u32,
    /// The replay reached the base and matched: nothing is assumed now.
    pub proven: bool,
}

#[derive(Clone, Debug)]
pub struct PeerView {
    pub id: u64,
    pub addr: Option<String>,
    pub inbound: bool,
    pub established: bool,
    pub agent: Option<String>,
    pub their_height: Option<i32>,
    /// BIP324 encrypted transport.
    pub v2: bool,
    /// BIP330 (Erlay) reconciliation negotiated.
    pub recon: bool,
    pub ping_ms: Option<f64>,
    pub blocks_served: usize,
    pub connected_secs: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

impl From<&SyncProgress> for NodeView {
    fn from(p: &SyncProgress) -> Self {
        let v = &p.validation;
        Self {
            connected: p.connected_height,
            headers: p.header_height,
            recent: p
                .recent
                .iter()
                .map(|(h, hash)| (*h, hash.to_string()))
                .collect(),
            peers: p
                .peer_details
                .iter()
                .map(|s| PeerView {
                    id: s.id,
                    addr: s.remote.map(|a| a.to_string()),
                    inbound: s.inbound,
                    established: s.established,
                    agent: s.user_agent.clone(),
                    their_height: s.start_height,
                    v2: s.transport_protocol == "v2",
                    recon: s.recon,
                    ping_ms: s.ping_last_secs.map(|t| t * 1000.0),
                    blocks_served: s.blocks_received,
                    connected_secs: s.connected_secs,
                    bytes_sent: s.telemetry.bytes_sent,
                    bytes_recv: s.telemetry.bytes_recv,
                })
                .collect(),
            mempool_txs: p.mempool.0,
            orphans: p.mempool.1,
            fee_rate_sat_kvb: p.mempool.2,
            uptime_secs: p.elapsed_secs,
            trust: TrustView {
                connected: v.connected_height,
                headers: v.header_height,
                snapshot: v.snapshot.as_ref().map(|s| SnapshotView {
                    base: s.base_height,
                    base_hash: s.base_hash.clone(),
                    expected_utxo_hash: s.expected_utxo_hash.clone(),
                    replayed: s.replayed_height,
                    proven: s.verified,
                }),
                verified_fraction: v.verified_fraction,
            },
        }
    }
}

impl NodeView {
    #[must_use]
    pub fn tip_hash(&self) -> Option<&str> {
        self.recent.last().map(|(_, h)| h.as_str())
    }

    /// Blocks we know of (by header) but have not connected yet.
    #[must_use]
    pub fn behind(&self) -> u32 {
        self.headers.saturating_sub(self.connected)
    }

    /// The best height any handshaken peer claimed.
    #[must_use]
    pub fn best_peer_height(&self) -> Option<u32> {
        self.peers
            .iter()
            .filter(|p| p.established)
            .filter_map(|p| p.their_height)
            .filter(|h| *h > 0)
            .max()
            .map(|h| h as u32)
    }

    /// Caught up: every known header connected, and no peer claims more.
    #[must_use]
    pub fn caught_up(&self) -> bool {
        self.connected > 0
            && self.behind() == 0
            && self.best_peer_height().is_none_or(|h| h <= self.connected)
    }

    pub fn established(&self) -> impl Iterator<Item = &PeerView> {
        self.peers.iter().filter(|p| p.established)
    }

    #[must_use]
    pub fn median_ping_ms(&self) -> Option<f64> {
        let mut pings: Vec<f64> = self.established().filter_map(|p| p.ping_ms).collect();
        if pings.is_empty() {
            return None;
        }
        pings.sort_by(f64::total_cmp);
        Some(pings[pings.len() / 2])
    }
}

// ---------------------------------------------------------------------
// Formatting — one voice for numbers across every screen.
// ---------------------------------------------------------------------

/// `1234567` → `1,234,567`.
#[must_use]
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A compact elapsed time: `now`, `42 s`, `9 min`, `3 h 12 min`, `2 d 4 h`.
#[must_use]
pub fn span(secs: u64) -> String {
    match secs {
        0..=4 => "now".into(),
        5..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        3600..=86_399 => {
            let (h, m) = (secs / 3600, secs % 3600 / 60);
            if m == 0 {
                format!("{h} h")
            } else {
                format!("{h} h {m} min")
            }
        }
        _ => {
            let (d, h) = (secs / 86_400, secs % 86_400 / 3600);
            if h == 0 {
                format!("{d} d")
            } else {
                format!("{d} d {h} h")
            }
        }
    }
}

#[must_use]
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1000.0 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else if v < 10.0 {
        format!("{v:.1} {}", UNITS[unit])
    } else {
        format!("{v:.0} {}", UNITS[unit])
    }
}

/// sat/kvB → `6.2 sat/vB`.
#[must_use]
pub fn fee_rate(sat_kvb: i64) -> String {
    let per_vb = sat_kvb as f64 / 1000.0;
    if per_vb < 10.0 {
        format!("{per_vb:.1} sat/vB")
    } else {
        format!("{per_vb:.0} sat/vB")
    }
}

#[must_use]
pub fn percent(fraction: f64) -> String {
    let p = (fraction * 100.0).clamp(0.0, 100.0);
    if p >= 99.95 || p == 0.0 {
        format!("{p:.0}%")
    } else if p >= 10.0 {
        format!("{p:.1}%")
    } else {
        format!("{p:.2}%")
    }
}

/// A block hash's leading zero hex digits — the visible proof of work.
#[must_use]
pub fn work_zeros(hash: &str) -> usize {
    hash.chars().take_while(|c| *c == '0').count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_groups_digits() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(935_184), "935,184");
        assert_eq!(thousands(1_305_397_408), "1,305,397,408");
    }

    #[test]
    fn spans_read_naturally() {
        assert_eq!(span(0), "now");
        assert_eq!(span(42), "42 s");
        assert_eq!(span(540), "9 min");
        assert_eq!(span(3600), "1 h");
        assert_eq!(span(3600 * 3 + 720), "3 h 12 min");
        assert_eq!(span(86_400 * 2 + 3600 * 4), "2 d 4 h");
    }

    #[test]
    fn units_and_rates() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1_234_000), "1.2 MB");
        assert_eq!(bytes(56_000_000_000), "56 GB");
        assert_eq!(fee_rate(6_200), "6.2 sat/vB");
        assert_eq!(fee_rate(24_000), "24 sat/vB");
        assert_eq!(percent(1.0), "100%");
        assert_eq!(percent(0.6589), "65.9%");
        assert_eq!(work_zeros("0000000000000000000108970acb"), 19);
    }

    #[test]
    fn caught_up_needs_every_header_and_no_taller_peer() {
        let mut v = NodeView {
            connected: 100,
            headers: 100,
            ..NodeView::default()
        };
        assert!(v.caught_up());
        v.headers = 101;
        assert!(!v.caught_up());
        v.headers = 100;
        v.peers.push(PeerView {
            id: 1,
            addr: None,
            inbound: false,
            established: true,
            agent: None,
            their_height: Some(120),
            v2: true,
            recon: false,
            ping_ms: None,
            blocks_served: 0,
            connected_secs: 0,
            bytes_sent: 0,
            bytes_recv: 0,
        });
        assert!(!v.caught_up());
    }
}

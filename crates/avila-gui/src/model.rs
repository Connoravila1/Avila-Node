//! What the screens render: a view of the node decoupled from its own
//! types, so a real run and the `--demo` preview feed the same code.

use avila_node::sync::SyncProgress;
use avila_p2p::manager::EclipseSignal;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct NodeView {
    /// Fully validated height — every script up to here checked (or,
    /// under a snapshot, checked on top of the assumed set).
    pub connected: u32,
    /// Best header height: proof-of-work checked, bodies may be pending.
    pub headers: u32,
    /// Headers buffered in the leader's presync — progress the tree
    /// tip can't show while the anti-DoS check runs.
    pub headers_buffered: u32,
    /// The last few connected blocks `(height, display hash)`, newest last.
    pub recent: Vec<(u32, String)>,
    pub peers: Vec<PeerView>,
    pub mempool_txs: usize,
    pub orphans: usize,
    /// Fee rate for ~6-block confirmation, sat/kvB.
    pub fee_rate_sat_kvb: Option<i64>,
    pub uptime_secs: u64,
    pub trust: TrustView,
    /// Work and time along the best header chain.
    pub curve: ChainCurve,
    /// The block this node's mempool would build next.
    pub next_block: Option<NextBlockView>,
    /// Eclipse indicators the node currently raises.
    pub eclipse: Vec<Eclipse>,
}

/// An eclipse indicator — the node's advisory signs that an attacker
/// may be controlling what it sees. Signs, not proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Eclipse {
    TipStale,
    DiversityCollapse,
    AllInbound,
}

impl Eclipse {
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::TipStale => "Peers are ahead but not delivering",
            Self::DiversityCollapse => "Every peer you dialed is in one network group",
            Self::AllInbound => "Every peer dialed you",
        }
    }

    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Self::TipStale => {
                "Your newest block is over a day old while at least four peers say they have more. Peers that hold blocks back are how an eclipse attack keeps a node behind."
            }
            Self::DiversityCollapse => {
                "At least four outbound peers, all in the same /16 address range: one operator could be running all of them."
            }
            Self::AllInbound => {
                "None of the connections your node made itself is up, so everything you hear comes from peers that chose you."
            }
        }
    }
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
    pub ping_min_ms: Option<f64>,
    pub blocks_served: usize,
    pub connected_secs: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    /// The BIP324 session id in `getpeerinfo`'s byte order (Core prints
    /// it as a uint256, reversed); `None` on v1.
    pub session_id: Option<[u8; 32]>,
    /// Bytes by what they were for.
    pub traffic: Traffic,
    /// Height of the last block this peer delivered that connected.
    pub last_block: Option<u32>,
    /// Service bits from its `version` message.
    pub services: u64,
}

impl From<&SyncProgress> for NodeView {
    fn from(p: &SyncProgress) -> Self {
        let v = &p.validation;
        Self {
            connected: p.connected_height,
            headers: p.header_height,
            headers_buffered: p.headers_buffered,
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
                    agent: s.user_agent.as_deref().map(clean_agent),
                    their_height: s.start_height,
                    v2: s.transport_protocol == "v2",
                    recon: s.recon,
                    ping_ms: s.ping_last_secs.map(|t| t * 1000.0),
                    ping_min_ms: s.ping_min_secs.map(|t| t * 1000.0),
                    blocks_served: s.blocks_received,
                    connected_secs: s.connected_secs,
                    bytes_sent: s.telemetry.bytes_sent,
                    bytes_recv: s.telemetry.bytes_recv,
                    session_id: s.v2_session_id.map(|mut id| {
                        id.reverse();
                        id
                    }),
                    traffic: Traffic::from_counts(
                        &s.telemetry.recv_by_msg,
                        &s.telemetry.sent_by_msg,
                    ),
                    last_block: u32::try_from(s.synced_block_height).ok(),
                    services: s.services.unwrap_or(0),
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
            eclipse: p
                .eclipse
                .iter()
                .map(|s| match s {
                    EclipseSignal::TipStale => Eclipse::TipStale,
                    EclipseSignal::DiversityCollapse => Eclipse::DiversityCollapse,
                    EclipseSignal::AllInbound => Eclipse::AllInbound,
                })
                .collect(),
            curve: ChainCurve::new(
                p.profile
                    .samples
                    .iter()
                    .chain(p.profile.tip.iter())
                    .map(|s| CurvePoint {
                        height: s.height,
                        work: s.work,
                        time: s.time,
                    })
                    .collect(),
            ),
            next_block: p.next_block.as_deref().map(|b| NextBlockView {
                height: b.height,
                tx_count: b.tx_count,
                weight: b.weight,
                fees: b.fees,
                subsidy: b.subsidy,
                steps: b.steps.as_slice().into(),
            }),
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
// Traffic by purpose
// ---------------------------------------------------------------------

/// What a connection's bytes were for, grouped from P2P command names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    Blocks,
    Headers,
    Transactions,
    Announcements,
    Reconciliation,
    Addresses,
    Upkeep,
}

impl Purpose {
    pub const COUNT: usize = 7;
    pub const ALL: [Self; Self::COUNT] = [
        Self::Blocks,
        Self::Headers,
        Self::Transactions,
        Self::Announcements,
        Self::Reconciliation,
        Self::Addresses,
        Self::Upkeep,
    ];

    #[must_use]
    pub fn of(command: &str) -> Self {
        match command {
            "block" | "cmpctblock" | "blocktxn" | "getblocktxn" | "getblocks" | "merkleblock"
            | "cfilter" | "cfheaders" | "cfcheckpt" | "getcfilters" | "getcfheaders"
            | "getcfcheckpt" => Self::Blocks,
            "headers" | "getheaders" | "sendheaders" => Self::Headers,
            "tx" => Self::Transactions,
            "inv" | "getdata" | "notfound" | "mempool" => Self::Announcements,
            "sendtxrcncl" | "reqrecon" | "sketch" | "reqsketchext" | "reconcildiff" => {
                Self::Reconciliation
            }
            "addr" | "addrv2" | "getaddr" | "sendaddrv2" => Self::Addresses,
            _ => Self::Upkeep,
        }
    }

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Blocks => "Blocks",
            Self::Headers => "Headers",
            Self::Transactions => "Transactions",
            Self::Announcements => "Announcements",
            Self::Reconciliation => "Erlay",
            Self::Addresses => "Addresses",
            Self::Upkeep => "Upkeep",
        }
    }
}

/// A connection's bytes, received and sent, by [`Purpose`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Traffic {
    pub recv: [u64; Purpose::COUNT],
    pub sent: [u64; Purpose::COUNT],
}

impl Traffic {
    #[must_use]
    pub fn from_counts(recv: &HashMap<String, u64>, sent: &HashMap<String, u64>) -> Self {
        let mut t = Self::default();
        for (cmd, n) in recv {
            t.recv[Purpose::of(cmd) as usize] += n;
        }
        for (cmd, n) in sent {
            t.sent[Purpose::of(cmd) as usize] += n;
        }
        t
    }

    #[must_use]
    pub fn total_recv(&self) -> u64 {
        self.recv.iter().sum()
    }

    #[must_use]
    pub fn total_sent(&self) -> u64 {
        self.sent.iter().sum()
    }
}

/// A peer's user agent as it may be shown: Core's `SanitizeString`
/// (`SAFE_CHARS_DEFAULT`) over at most `MAX_SUBVERSION_LENGTH` bytes. The
/// string is whatever the peer chose to send — megabytes, control
/// characters, direction overrides — so nothing else reaches the screen.
#[must_use]
pub fn clean_agent(raw: &str) -> String {
    const SAFE: &str = " .,;-_/:?@()";
    raw.chars()
        .take(256)
        .filter(|c| c.is_ascii_alphanumeric() || SAFE.contains(*c))
        .collect()
}

/// `IPv4`, `IPv6`, or `unknown` — what can be said about a peer's address
/// without saying the address.
#[must_use]
pub fn network_kind(p: &PeerView) -> &'static str {
    match p
        .addr
        .as_deref()
        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
    {
        Some(std::net::SocketAddr::V4(_)) => "IPv4",
        Some(std::net::SocketAddr::V6(_)) => "IPv6",
        None => "unknown network",
    }
}

/// Service bits worth naming, in the order they're shown.
#[must_use]
pub fn services(bits: u64) -> Vec<&'static str> {
    [
        (1, "Full blocks"),
        (1 << 10, "Recent blocks"),
        (1 << 3, "Segwit"),
        (1 << 6, "Block filters"),
        (1 << 11, "v2 transport"),
        (1 << 2, "Bloom filters"),
    ]
    .into_iter()
    .filter(|(bit, _)| bits & bit != 0)
    .map(|(_, name)| name)
    .collect()
}

// ---------------------------------------------------------------------
// The chain's work and time
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CurvePoint {
    pub height: u32,
    /// Cumulative chainwork through this header.
    pub work: f64,
    /// Header timestamp, unix seconds.
    pub time: u32,
}

/// Work and time along the best header chain, sampled at difficulty
/// period boundaries plus the tip. Within a period every block carries
/// the same work, so interpolating between samples is exact for work
/// (and close for time).
#[derive(Clone, Debug, Default)]
pub struct ChainCurve {
    points: Arc<[CurvePoint]>,
}

impl ChainCurve {
    #[must_use]
    pub fn new(mut points: Vec<CurvePoint>) -> Self {
        points.sort_by_key(|p| p.height);
        points.dedup_by_key(|p| p.height);
        Self {
            points: points.into(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    #[must_use]
    pub fn tip(&self) -> Option<CurvePoint> {
        self.points.last().copied()
    }

    /// Cumulative work at `height`, interpolated; clamped to the samples.
    #[must_use]
    pub fn work_at(&self, height: u32) -> Option<f64> {
        self.at(height, |p| p.work)
    }

    /// Header time at `height`, interpolated; clamped to the samples.
    #[must_use]
    pub fn time_at(&self, height: u32) -> Option<f64> {
        self.at(height, |p| f64::from(p.time))
    }

    fn at(&self, height: u32, field: impl Fn(&CurvePoint) -> f64) -> Option<f64> {
        let pts = &self.points;
        let first = pts.first()?;
        let i = pts.partition_point(|p| p.height <= height);
        if i == 0 {
            return Some(field(first));
        }
        let a = &pts[i - 1];
        let Some(b) = pts.get(i) else {
            return Some(field(a));
        };
        let f = f64::from(height - a.height) / f64::from(b.height - a.height);
        Some(field(a) + (field(b) - field(a)) * f)
    }

    /// The height the chain had reached at unix time `t`, interpolated.
    #[must_use]
    pub fn height_at_time(&self, t: f64) -> Option<f64> {
        let pts = &self.points;
        let i = pts.partition_point(|p| f64::from(p.time) <= t);
        if i == 0 || i == pts.len() {
            return None;
        }
        let (a, b) = (&pts[i - 1], &pts[i]);
        let span = f64::from(b.time) - f64::from(a.time);
        if span <= 0.0 {
            return Some(f64::from(a.height));
        }
        let f = (t - f64::from(a.time)) / span;
        Some(f64::from(a.height) + f64::from(b.height - a.height) * f)
    }

    /// The height at which cumulative work reaches `work`, interpolated.
    #[must_use]
    pub fn height_at_work(&self, work: f64) -> Option<f64> {
        let pts = &self.points;
        let i = pts.partition_point(|p| p.work <= work);
        if i == 0 {
            return pts.first().map(|p| f64::from(p.height));
        }
        let a = &pts[i - 1];
        let Some(b) = pts.get(i) else {
            return Some(f64::from(a.height));
        };
        let span = b.work - a.work;
        if span <= 0.0 {
            return Some(f64::from(a.height));
        }
        Some(f64::from(a.height) + f64::from(b.height - a.height) * (work - a.work) / span)
    }

    /// The first header of the current difficulty period, if sampled.
    #[must_use]
    pub fn period_start(&self, interval: u32) -> Option<CurvePoint> {
        let tip = self.tip()?;
        let start = tip.height - tip.height % interval.max(1);
        self.points
            .iter()
            .rev()
            .find(|p| p.height == start)
            .copied()
    }
}

/// The block this node's mempool would build next.
#[derive(Clone, Debug, PartialEq)]
pub struct NextBlockView {
    pub height: u32,
    pub tx_count: usize,
    /// Weight units, coinbase included.
    pub weight: usize,
    pub fees: i64,
    pub subsidy: i64,
    /// `(cumulative vsize, sat/vB)`, highest fee rate first.
    pub steps: Arc<[(u32, f64)]>,
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

/// Satoshis as bitcoin: `3.125 BTC`, `0.0213 BTC`.
#[must_use]
pub fn btc(sats: i64) -> String {
    let v = sats as f64 / 1e8;
    // Whole-coin amounts exactly (a subsidy is 1.5625, not 1.563);
    // fractions of a coin to four places.
    let s = if v.abs() >= 1.0 {
        format!("{v:.8}")
    } else {
        format!("{v:.4}")
    };
    let s = if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_owned()
    } else {
        s
    };
    format!("{s} BTC")
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

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Unix seconds at the start of January 1 of `year`, UTC.
#[must_use]
pub fn year_start(year: i64) -> i64 {
    days_from_civil(year, 1, 1) * 86_400
}

/// `(year, month 1–12)` of a unix time, UTC.
#[must_use]
pub fn year_month(unix: i64) -> (i64, u32) {
    let z = unix.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m as u32)
}

/// `Mar 2028`.
#[must_use]
pub fn month_year(unix: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (y, m) = year_month(unix);
    format!("{} {y}", MONTHS[(m as usize).saturating_sub(1) % 12])
}

#[cfg(test)]
pub(crate) fn test_peer(id: u64) -> PeerView {
    PeerView {
        id,
        addr: None,
        inbound: false,
        established: true,
        agent: None,
        their_height: None,
        v2: true,
        recon: false,
        ping_ms: None,
        ping_min_ms: None,
        blocks_served: 0,
        connected_secs: 0,
        bytes_sent: 0,
        bytes_recv: 0,
        session_id: None,
        traffic: Traffic::default(),
        last_block: None,
        services: 0,
    }
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
        assert_eq!(btc(312_500_000), "3.125 BTC");
        assert_eq!(btc(156_250_000), "1.5625 BTC");
        assert_eq!(btc(2_130_000), "0.0213 BTC");
        assert_eq!(btc(0), "0 BTC");
    }

    #[test]
    fn calendar_math_round_trips() {
        assert_eq!(year_start(1970), 0);
        assert_eq!(year_start(2009), 1_230_768_000);
        // The genesis block's timestamp.
        assert_eq!(year_month(1_231_006_505), (2009, 1));
        assert_eq!(month_year(1_709_251_200), "Mar 2024");
        assert_eq!(year_month(year_start(2028) - 1), (2027, 12));
    }

    #[test]
    fn curves_interpolate_within_periods() {
        let c = ChainCurve::new(vec![
            CurvePoint {
                height: 2016,
                work: 20.0,
                time: 2_000,
            },
            CurvePoint {
                height: 0,
                work: 0.0,
                time: 0,
            },
            CurvePoint {
                height: 3016,
                work: 30.0,
                time: 3_000,
            },
        ]);
        assert_eq!(c.work_at(1008), Some(10.0));
        assert_eq!(c.work_at(5000), Some(30.0));
        assert_eq!(c.time_at(2516), Some(2_500.0));
        assert_eq!(c.height_at_time(1_000.0), Some(1008.0));
        assert_eq!(c.height_at_time(9_000.0), None);
        assert_eq!(c.period_start(2016).map(|p| p.height), Some(2016));
        assert_eq!(c.height_at_work(10.0), Some(1008.0));
        assert_eq!(c.height_at_work(25.0), Some(2516.0));
        assert!(ChainCurve::default().work_at(5).is_none());
    }

    #[test]
    fn traffic_groups_commands_by_purpose() {
        let recv: HashMap<String, u64> = [
            ("block".into(), 900),
            ("inv".into(), 40),
            ("sketch".into(), 5),
            ("ping".into(), 1),
        ]
        .into();
        let sent: HashMap<String, u64> = [("getdata".into(), 30), ("addrv2".into(), 7)].into();
        let t = Traffic::from_counts(&recv, &sent);
        assert_eq!(t.recv[Purpose::Blocks as usize], 900);
        assert_eq!(t.recv[Purpose::Reconciliation as usize], 5);
        assert_eq!(t.sent[Purpose::Announcements as usize], 30);
        assert_eq!(t.total_recv(), 946);
        assert_eq!(t.total_sent(), 37);
        assert_eq!(
            services(1 | 8 | 2048),
            vec!["Full blocks", "Segwit", "v2 transport"]
        );
    }

    #[test]
    fn peer_agents_are_cleaned_before_display() {
        assert_eq!(clean_agent("/Satoshi:29.0.0/"), "/Satoshi:29.0.0/");
        assert_eq!(
            clean_agent("/Satoshi:29.0.0/\n\nUpdate now at evil\u{202e}moc.example"),
            "/Satoshi:29.0.0/Update now at evilmoc.example"
        );
        assert_eq!(clean_agent(&"A".repeat(4_000_000)).len(), 256);
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
            their_height: Some(120),
            ..test_peer(1)
        });
        assert!(!v.caught_up());
    }
}

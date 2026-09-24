//! `--demo`: a simulated mainnet node, for previewing every screen
//! without touching the network. Everything it shows is invented except
//! the snapshot parameters (and the difficulty history is approximate),
//! and the interface labels it wherever it appears. The state is a pure
//! function of time since the simulated launch, so screenshots are
//! reproducible.

use crate::model::{
    ChainCurve, CurvePoint, NextBlockView, NodeView, PeerView, Purpose, SnapshotView, Traffic,
    TrustView,
};

/// Mainnet's assumeutxo snapshot at 910,000, as pinned in chainparams.
const BASE: u32 = 910_000;
const BASE_HASH: &str = "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821";
const UTXO_HASH: &str = "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568";
/// Best header at launch; the node starts `CATCHUP` blocks behind it.
const LAUNCH_HEADERS: u32 = 935_164;
const CATCHUP: u32 = 40;
const CATCHUP_PER_SEC: f64 = 2.5;
/// The background replay's height at launch, and its pace.
const REPLAY_FROM: u32 = 462_400;
const REPLAY_PER_SEC: f64 = 250.0;
/// Mean seconds between simulated blocks — far quicker than mainnet's
/// ten minutes, so a preview has something to show.
const BLOCK_MEAN: f64 = 28.0;
/// A block's body lands this long after its header.
const BODY_LAG: f64 = 1.4;
const PERIOD: u32 = 2016;
const AGENTS: [&str; 6] = [
    "/Satoshi:29.0.0/",
    "/Satoshi:28.1.0/",
    "/Satoshi:30.0.0/",
    "/Satoshi:27.1.0/",
    "/Satoshi:29.1.0/",
    "/Satoshi:26.2.0/",
];

/// Approximate mainnet difficulty at a few heights; between them the
/// simulation interpolates geometrically.
const DIFFICULTY: [(u32, f64); 20] = [
    (0, 1.0),
    (50_000, 1.0e3),
    (100_000, 1.45e4),
    (150_000, 1.47e6),
    (200_000, 2.86e6),
    (250_000, 5.0e7),
    (300_000, 8.85e9),
    (350_000, 4.94e10),
    (400_000, 1.63e11),
    (450_000, 3.37e11),
    (500_000, 1.87e12),
    (550_000, 7.18e12),
    (600_000, 1.30e13),
    (650_000, 1.93e13),
    (700_000, 1.84e13),
    (750_000, 2.84e13),
    (800_000, 5.39e13),
    (850_000, 8.37e13),
    (900_000, 1.26e14),
    (940_000, 1.44e14),
];

/// Approximate block timestamps at a few heights; linear between.
const TIMES: [(u32, u32); 10] = [
    (0, 1_231_006_505),
    (100_000, 1_293_623_863),
    (200_000, 1_348_310_759),
    (300_000, 1_399_703_554),
    (400_000, 1_456_417_484),
    (500_000, 1_513_622_125),
    (600_000, 1_571_443_461),
    (700_000, 1_631_333_672),
    (800_000, 1_690_168_629),
    (900_000, 1_747_800_000),
];

/// SplitMix64: cheap, well-mixed, deterministic.
fn mix(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A uniform draw in `[0, 1)`.
fn unit(x: u64) -> f64 {
    (mix(x) >> 11) as f64 / (1_u64 << 53) as f64
}

fn difficulty(height: u32) -> f64 {
    let i = DIFFICULTY.partition_point(|(h, _)| *h <= height);
    let (h0, d0) = DIFFICULTY[i.saturating_sub(1)];
    let Some(&(h1, d1)) = DIFFICULTY.get(i) else {
        return d0;
    };
    let f = f64::from(height - h0) / f64::from(h1 - h0);
    (d0.ln() + (d1.ln() - d0.ln()) * f).exp()
}

/// Header time: the table up to 900,000, then just under ten minutes a
/// block (hashrate still climbing), whatever the preview's own pace.
fn header_time(height: u32) -> u32 {
    let i = TIMES.partition_point(|(h, _)| *h <= height);
    let (h0, t0) = TIMES[i.saturating_sub(1)];
    match TIMES.get(i) {
        Some(&(h1, t1)) => {
            t0 + ((u64::from(t1 - t0) * u64::from(height - h0)) / u64::from(h1 - h0)) as u32
        }
        None => t0 + (height - h0) * 588,
    }
}

pub struct Demo {
    /// Session time of the simulated launch.
    start: f64,
    /// Header arrival times, seconds after launch.
    arrivals: Vec<f64>,
    /// Chainwork and time at every period boundary up to the far future.
    boundaries: Vec<CurvePoint>,
}

impl Demo {
    #[must_use]
    pub fn new(start: f64) -> Self {
        let mut t = 0.0;
        let arrivals: Vec<f64> = (0..8192_u64)
            .map(|i| {
                // Exponential gaps, clipped so no gap is absurd.
                let u = unit(i ^ 0xB10C).clamp(0.05, 0.95);
                t += -BLOCK_MEAN * (1.0 - u).ln();
                t
            })
            .collect();
        let last = LAUNCH_HEADERS + arrivals.len() as u32;
        let mut work = 0.0;
        let mut boundaries = Vec::new();
        let mut h = 0;
        while h <= last {
            boundaries.push(CurvePoint {
                height: h,
                work,
                time: header_time(h),
            });
            // Each period's blocks all carry that period's difficulty.
            work += f64::from(PERIOD) * difficulty(h) * 4_294_967_296.0;
            h += PERIOD;
        }
        Self {
            start,
            arrivals,
            boundaries,
        }
    }

    fn headers_at(&self, e: f64) -> u32 {
        LAUNCH_HEADERS + self.arrivals.partition_point(|a| *a <= e) as u32
    }

    fn arrived_at(&self, height: u32) -> Option<f64> {
        let i = height.checked_sub(LAUNCH_HEADERS + 1)?;
        self.arrivals.get(i as usize).copied()
    }

    fn last_arrival(&self, e: f64) -> f64 {
        let n = self.arrivals.partition_point(|a| *a <= e);
        n.checked_sub(1).map_or(0.0, |i| self.arrivals[i])
    }

    fn curve(&self, headers: u32) -> ChainCurve {
        let mut points: Vec<CurvePoint> = self
            .boundaries
            .iter()
            .take_while(|p| p.height <= headers)
            .copied()
            .collect();
        if let Some(last) = points.last().copied()
            && last.height < headers
        {
            points.push(CurvePoint {
                height: headers,
                work: last.work
                    + f64::from(headers - last.height) * difficulty(last.height) * 4_294_967_296.0,
                time: header_time(headers),
            });
        }
        ChainCurve::new(points)
    }

    #[must_use]
    pub fn view_at(&self, t: f64) -> NodeView {
        let e = (t - self.start).max(0.0);
        let headers = self.headers_at(e);
        let bodies = LAUNCH_HEADERS + self.arrivals.partition_point(|a| *a + BODY_LAG <= e) as u32;
        let caught = LAUNCH_HEADERS - CATCHUP + (e * CATCHUP_PER_SEC) as u32;
        let connected = caught.min(bodies);

        let peers: Vec<PeerView> = seats(e)
            .into_iter()
            .map(|seat| self.peer(seat, e, connected))
            .collect();
        let replayed = (REPLAY_FROM + (e * REPLAY_PER_SEC) as u32).min(BASE);
        let since_block = e - self.last_arrival(e);
        let mempool = 21_400.0 + 1_900.0 * (e / 170.0).sin() + 55.0 * since_block.min(240.0);

        NodeView {
            connected,
            headers,
            recent: (connected.saturating_sub(11)..=connected)
                .map(|h| (h, block_hash(h)))
                .collect(),
            peers,
            mempool_txs: mempool as usize,
            orphans: 2 + (e as usize / 37) % 5,
            fee_rate_sat_kvb: Some((6_100.0 + 1_700.0 * (e / 310.0).sin()) as i64),
            uptime_secs: e as u64,
            trust: TrustView {
                connected,
                headers,
                snapshot: Some(SnapshotView {
                    base: BASE,
                    base_hash: BASE_HASH.into(),
                    expected_utxo_hash: UTXO_HASH.into(),
                    replayed,
                    proven: replayed >= BASE,
                }),
                // The node's own formula: above the base, and whatever the
                // replay reached, is proven.
                verified_fraction: f64::from(connected - BASE + replayed) / f64::from(connected),
            },
            curve: self.curve(headers),
            next_block: Some(next_block(connected + 1, e, since_block)),
        }
    }

    /// Which long-lived outbound peer delivered block `height` first.
    fn deliverer(height: u32) -> u64 {
        1 + mix(u64::from(height) ^ 0xDE11) % 6
    }

    fn peer(&self, seat: Seat, e: f64, connected: u32) -> PeerView {
        let id = seat.id;
        let r = |k: u64| mix(id.wrapping_mul(0x1F3D) ^ k);
        // Erlay needs both sides to run it: here, other copies of this node.
        let recon = id % 5 == 2;
        let v2 = recon || !id.is_multiple_of(3);
        let port = if seat.inbound {
            40_000 + r(9) % 20_000
        } else {
            8333
        };
        // Addresses from the shared address space (100.64.0.0/10), which
        // belongs to no one on the internet: every outbound peer in its
        // own /16, and the two inbound peers sharing one.
        let group = if seat.inbound { 87 } else { 64 + (id * 7) % 64 };
        let addr = if id == 4 {
            format!("[2001:db8:{:x}::{:x}]:{port}", r(2) % 0xffff, r(3) % 0xffff)
        } else {
            format!("100.{group}.{}.{}:{port}", r(2) % 256, 1 + r(3) % 254)
        };
        let agent = if recon {
            "/Avila:0.1.0/"
        } else {
            AGENTS[(r(4) % AGENTS.len() as u64) as usize]
        };
        let age = (e - seat.joined).max(0.0);
        let base_ping = 14.0 + (r(6) % 230) as f64;
        let ping = base_ping * (1.0 + 0.12 * (e / 6.0 + id as f64).sin());
        let blocks = (age / BLOCK_MEAN) as usize + if id <= 6 { 7 } else { 0 };
        let rate_in = 1_500.0 + (r(7) % 22_000) as f64;
        let rate_out = 900.0 + (r(8) % 9_000) as f64;
        let bytes_recv = (rate_in * age) as u64 + blocks as u64 * 1_650_000;
        let bytes_sent = (rate_out * age) as u64;
        let last_block = (connected.saturating_sub(60)..=connected).rev().find(|h| {
            Self::deliverer(*h) == id && self.arrived_at(*h).is_none_or(|at| at >= seat.joined)
        });
        let session_id = v2.then(|| {
            let mut b = [0_u8; 32];
            for (i, chunk) in b.chunks_mut(8).enumerate() {
                chunk.copy_from_slice(&mix(id ^ (0x5E55 << 8) ^ i as u64).to_le_bytes());
            }
            b
        });
        PeerView {
            id,
            addr: Some(addr),
            inbound: seat.inbound,
            established: true,
            agent: Some(agent.into()),
            their_height: Some(self.headers_at(seat.joined.max(0.0)) as i32),
            v2,
            recon,
            ping_ms: Some(ping),
            ping_min_ms: Some(base_ping * 0.9),
            blocks_served: blocks,
            connected_secs: age as u64,
            bytes_sent,
            bytes_recv,
            session_id,
            traffic: traffic(bytes_recv, bytes_sent, recon, seat.inbound),
            last_block: if seat.inbound { None } else { last_block },
            services: 1 | 8 | 1024 | if v2 { 2048 } else { 0 } | if id % 4 == 1 { 64 } else { 0 },
        }
    }
}

/// Splits a connection's totals by purpose in plausible proportions. An
/// Erlay link announces far less and reconciles instead.
fn traffic(recv: u64, sent: u64, recon: bool, inbound: bool) -> Traffic {
    use Purpose as P;
    let recv_share: [(P, f64); 6] = if recon {
        [
            (P::Blocks, 0.80),
            (P::Headers, 0.01),
            (P::Transactions, 0.15),
            (P::Announcements, 0.012),
            (P::Reconciliation, 0.018),
            (P::Addresses, 0.004),
        ]
    } else {
        [
            (P::Blocks, 0.78),
            (P::Headers, 0.01),
            (P::Transactions, 0.14),
            (P::Announcements, 0.055),
            (P::Reconciliation, 0.0),
            (P::Addresses, 0.004),
        ]
    };
    let serving = if inbound { 0.40 } else { 0.04 };
    let sent_share: [(P, f64); 6] = if recon {
        [
            (P::Blocks, serving),
            (P::Headers, 0.03),
            (P::Transactions, 0.55 - serving),
            (P::Announcements, 0.12),
            (P::Reconciliation, 0.08),
            (P::Addresses, 0.01),
        ]
    } else {
        [
            (P::Blocks, serving),
            (P::Headers, 0.03),
            (P::Transactions, 0.45 - serving),
            (P::Announcements, 0.40),
            (P::Reconciliation, 0.0),
            (P::Addresses, 0.01),
        ]
    };
    let split = |total: u64, shares: &[(P, f64); 6]| {
        let mut out = [0_u64; Purpose::COUNT];
        for (p, s) in shares {
            out[*p as usize] = (total as f64 * s) as u64;
        }
        let assigned: u64 = out.iter().sum();
        out[P::Upkeep as usize] = total.saturating_sub(assigned);
        out
    };
    Traffic {
        recv: split(recv, &recv_share),
        sent: split(sent, &sent_share),
    }
}

/// The block the simulated mempool would build: a fee staircase that
/// drops fast from the eager few to the long patient tail.
fn next_block(height: u32, e: f64, since_block: f64) -> NextBlockView {
    let top = 38.0 + 10.0 * (e / 97.0).sin() + since_block.min(120.0) * 0.08;
    let floor = 1.3 + 0.3 * (e / 211.0).sin();
    let full = 997_800.0;
    let n = 96;
    let mut steps = Vec::with_capacity(n);
    let mut fees = 0.0;
    let mut prev = 0.0;
    for i in 0..n {
        let x = (i + 1) as f64 / n as f64;
        let rate = floor + (top - floor) * (1.0 - x + 0.5 / n as f64).powi(8);
        let vsize = full * x;
        fees += rate * (vsize - prev);
        prev = vsize;
        steps.push((vsize as u32, rate));
    }
    NextBlockView {
        height,
        tx_count: 3_180 + (e as usize / 13) % 240,
        weight: (full * 4.0) as usize + 1_000,
        fees: fees as i64,
        subsidy: 312_500_000,
        steps: steps.into(),
    }
}

struct Seat {
    id: u64,
    joined: f64,
    inbound: bool,
}

/// Eight long-lived peers found at launch (two of them inbound), plus a
/// rotating seat that turns over every couple of minutes.
fn seats(e: f64) -> Vec<Seat> {
    let mut out: Vec<Seat> = (1..=8_u64)
        .map(|id| Seat {
            id,
            joined: if id >= 7 {
                25.0 + 40.0 * (id - 7) as f64
            } else {
                0.6 + 1.3 * id as f64
            },
            inbound: id >= 7,
        })
        .filter(|s| s.joined <= e)
        .collect();
    let joined = rotating_joined(e);
    for j in 0..joined {
        let (start, end) = rotation(j);
        if start <= e && e < end {
            out.push(Seat {
                id: 9 + u64::from(j),
                joined: start,
                inbound: false,
            });
        }
    }
    out
}

fn rotation(j: u32) -> (f64, f64) {
    let start = 60.0 + 110.0 * f64::from(j);
    (start, start + 190.0)
}

fn rotating_joined(e: f64) -> u32 {
    if e < 60.0 {
        0
    } else {
        ((e - 60.0) / 110.0) as u32 + 1
    }
}

/// A plausible mainnet-difficulty hash for `height`: nineteen or twenty
/// leading zero digits, then noise. The snapshot base keeps its real one.
fn block_hash(height: u32) -> String {
    if height == BASE {
        return BASE_HASH.into();
    }
    let seed = u64::from(height) << 8;
    let mut hex: String = (0..4).map(|i| format!("{:016x}", mix(seed | i))).collect();
    let zeros = 19 + usize::from(mix(seed ^ 0xFF).is_multiple_of(4));
    hex.replace_range(..zeros, &"0".repeat(zeros));
    if hex.as_bytes()[zeros] == b'0' {
        hex.replace_range(zeros..=zeros, "1");
    }
    hex
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::work_zeros;

    #[test]
    fn launch_catches_up_then_follows_new_blocks() {
        let demo = Demo::new(0.0);
        let start = demo.view_at(0.0);
        assert_eq!(start.behind(), CATCHUP);
        let later = demo.view_at(600.0);
        assert!(later.connected > LAUNCH_HEADERS, "{}", later.connected);
        assert!(later.behind() <= 1);
        assert_eq!(later.recent.len(), 12);
        assert_eq!(
            later.tip_hash().map(work_zeros).map(|z| z >= 19),
            Some(true)
        );
    }

    #[test]
    fn replay_proves_the_snapshot_eventually() {
        let demo = Demo::new(0.0);
        let mid = demo.view_at(600.0);
        let snap = mid.trust.snapshot.as_ref().expect("snapshot");
        assert!(!snap.proven && snap.replayed > REPLAY_FROM);
        assert!(mid.trust.verified_fraction > 0.5 && mid.trust.verified_fraction < 1.0);
        let done = demo.view_at(3_600.0);
        assert!(done.trust.snapshot.as_ref().is_some_and(|s| s.proven));
        assert!((done.trust.verified_fraction - 1.0).abs() < 1e-12);
    }

    #[test]
    fn peers_turn_over() {
        let demo = Demo::new(0.0);
        let ids = |t: f64| {
            let mut v: Vec<u64> = demo.view_at(t).peers.iter().map(|p| p.id).collect();
            v.sort_unstable();
            v
        };
        assert!(ids(600.0).len() >= 9);
        assert_ne!(ids(600.0), ids(800.0));
        let v = demo.view_at(600.0);
        assert!(v.peers.iter().any(|p| p.recon));
        assert!(v.peers.iter().any(|p| !p.v2));
        // Someone delivered the tip, and traffic adds up.
        assert!(v.peers.iter().any(|p| p.last_block == Some(v.connected)));
        for p in &v.peers {
            assert_eq!(p.traffic.total_recv(), p.bytes_recv);
            assert_eq!(p.traffic.total_sent(), p.bytes_sent);
            assert_eq!(p.session_id.is_some(), p.v2);
        }
    }

    #[test]
    fn work_concentrates_in_recent_blocks() {
        let demo = Demo::new(0.0);
        let v = demo.view_at(600.0);
        let total = v.curve.work_at(v.headers).expect("curve");
        let before_2020 = v.curve.work_at(612_000).expect("curve");
        // Two-thirds of the blocks, a small share of the work.
        assert!(before_2020 / total < 0.1, "{}", before_2020 / total);
        let year = crate::model::year_month(v.curve.time_at(612_000).expect("time") as i64).0;
        assert_eq!(year, 2020);
    }

    #[test]
    fn next_block_is_a_descending_staircase() {
        let b = next_block(935_185, 600.0, 30.0);
        assert!(
            b.steps
                .windows(2)
                .all(|w| w[0].1 >= w[1].1 && w[0].0 < w[1].0)
        );
        assert!(b.fees > 1_000_000 && b.fees < 20_000_000, "{}", b.fees);
    }

    #[test]
    fn hashes_look_mined() {
        for h in [1_u32, 935_000, 935_184] {
            let hash = block_hash(h);
            assert_eq!(hash.len(), 64);
            assert!((19..=20).contains(&work_zeros(&hash)), "{hash}");
        }
        assert_eq!(block_hash(BASE), BASE_HASH);
    }
}

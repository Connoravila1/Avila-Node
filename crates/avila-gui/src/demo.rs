//! `--demo`: a simulated mainnet node, for previewing every screen
//! without touching the network. Everything it shows is invented except
//! the snapshot parameters, and the interface labels it wherever it
//! appears. The state is a pure function of time since the simulated
//! launch, so screenshots are reproducible.

use crate::model::{NodeView, PeerView, SnapshotView, TrustView};

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
const AGENTS: [&str; 6] = [
    "/Satoshi:29.0.0/",
    "/Satoshi:28.1.0/",
    "/Satoshi:30.0.0/",
    "/Satoshi:27.1.0/",
    "/Satoshi:29.1.0/",
    "/Satoshi:26.2.0/",
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

pub struct Demo {
    /// Session time of the simulated launch.
    start: f64,
    /// Header arrival times, seconds after launch.
    arrivals: Vec<f64>,
}

impl Demo {
    #[must_use]
    pub fn new(start: f64) -> Self {
        let mut t = 0.0;
        let arrivals = (0..8192_u64)
            .map(|i| {
                // Exponential gaps, clipped so no gap is absurd.
                let u = unit(i ^ 0xB10C).clamp(0.05, 0.95);
                t += -BLOCK_MEAN * (1.0 - u).ln();
                t
            })
            .collect();
        Self { start, arrivals }
    }

    fn headers_at(&self, e: f64) -> u32 {
        LAUNCH_HEADERS + self.arrivals.partition_point(|a| *a <= e) as u32
    }

    fn last_arrival(&self, e: f64) -> f64 {
        let n = self.arrivals.partition_point(|a| *a <= e);
        n.checked_sub(1).map_or(0.0, |i| self.arrivals[i])
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
            .map(|seat| self.peer(seat, e))
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
        }
    }

    fn peer(&self, seat: Seat, e: f64) -> PeerView {
        let id = seat.id;
        let r = |k: u64| mix(id.wrapping_mul(0x1F3D) ^ k);
        // Erlay needs both sides to run it: here, other copies of this node.
        let recon = id % 5 == 2;
        let port = if seat.inbound {
            40_000 + r(9) % 20_000
        } else {
            8333
        };
        // Distinct last octets for every seat (29 is coprime to 240).
        let octet = 10 + (id * 29) % 240;
        let addr = match r(1) % 4 {
            0 => format!("203.0.113.{octet}:{port}"),
            1 => format!("198.51.100.{octet}:{port}"),
            2 => format!("192.0.2.{octet}:{port}"),
            _ => format!("[2001:db8:{:x}::{:x}]:{port}", r(2) % 0xffff, r(3) % 0xffff),
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
        PeerView {
            id,
            addr: Some(addr),
            inbound: seat.inbound,
            established: true,
            agent: Some(agent.into()),
            their_height: Some(self.headers_at(seat.joined.max(0.0)) as i32),
            v2: recon || !id.is_multiple_of(3),
            recon,
            ping_ms: Some(ping),
            blocks_served: blocks,
            connected_secs: age as u64,
            bytes_sent: (rate_out * age) as u64,
            bytes_recv: (rate_in * age) as u64 + blocks as u64 * 1_650_000,
        }
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
        assert!(demo.view_at(600.0).peers.iter().any(|p| p.recon));
        assert!(demo.view_at(600.0).peers.iter().any(|p| !p.v2));
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

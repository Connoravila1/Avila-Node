//! Live peer-to-peer synchronization: drives [`PeerManager`] over real
//! TCP against a configured network — DNS-seeded or explicitly connected
//! peers, headers-first download, and full consensus intake through
//! [`Chainstate`]. This is the CLI-visible "real sync" path; all
//! verdicts still come from `avila-consensus`.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use avila_consensus::chainstate::Chainstate;
use avila_consensus::params::Params;
use avila_p2p::manager::{NetEvent, PeerManager};

/// How far and how long a sync run should go.
#[derive(Clone, Debug)]
pub struct SyncConfig {
    /// Explicit `addr:port` peers to dial in addition to DNS seeds.
    pub connect: Vec<SocketAddr>,
    /// Stop once the connected chain reaches this height.
    pub target_height: u32,
    /// Bound on the peer set.
    pub max_peers: usize,
    /// Wall-clock bound on the whole run.
    pub timeout: Duration,
    /// Optional SOCKS5 proxy for all outbound connections (Core's
    /// `-proxy`); DNS-seeded and explicit dials both route through it.
    pub proxy: Option<SocketAddr>,
    /// When set, the chainstate persists under this directory —
    /// re-running resumes from the stored snapshot instead of genesis.
    pub data_dir: Option<std::path::PathBuf>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            connect: Vec::new(),
            target_height: 100,
            max_peers: 8,
            timeout: Duration::from_secs(120),
            proxy: None,
            data_dir: None,
        }
    }
}

/// A snapshot of sync progress, reported after each tick.
#[derive(Clone, Debug)]
pub struct SyncProgress {
    /// Live peer count.
    pub peers: usize,
    /// Connected (fully validated) chain height.
    pub connected_height: u32,
    /// Indexed best-header height (headers ahead of bodies is normal).
    pub header_height: u32,
    /// Outstanding block requests across all peers.
    pub in_flight: usize,
    /// Cumulative peer connections established this run.
    pub established_total: u32,
    /// Cumulative disconnects this run.
    pub disconnects: u32,
}

/// The outcome of a finished (or timed-out) sync run.
#[derive(Clone, Debug)]
pub struct SyncReport {
    /// Final connected chain height.
    pub connected_height: u32,
    /// Final best-header height.
    pub header_height: u32,
    /// Connected tip hash (display hex) if any block connected.
    pub tip: Option<String>,
    /// Peers dialed successfully over the run.
    pub established_total: u32,
    /// Explicit `--connect` peers that accepted our session.
    pub explicit_dialed: usize,
    /// Whether `target_height` was reached before the timeout.
    pub target_reached: bool,
    /// Wall-clock duration of the run.
    pub elapsed: Duration,
}

/// A sync run cannot proceed.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// DNS seed resolution and explicit connects produced no peers.
    #[error("no peer candidates: DNS seeds returned {seeded}, explicit connects {explicit}")]
    NoPeers {
        /// Addresses learned from DNS seeds.
        seeded: usize,
        /// Explicit `--connect` entries attempted.
        explicit: usize,
    },
    /// A transport failure prevented any peer registration.
    #[error("peer transport error: {0}")]
    Io(#[from] io::Error),
    /// The block store could not be opened or the snapshot flushed.
    #[error("chainstate storage error: {0}")]
    Store(io::Error),
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Runs headers-first sync until `cfg.target_height` connects or
/// `cfg.timeout` elapses. `progress` is invoked after each tick with a
/// live snapshot.
pub fn run(
    params: &Params,
    cfg: &SyncConfig,
    mut progress: impl FnMut(&SyncProgress),
) -> Result<SyncReport, SyncError> {
    let mut cs = match &cfg.data_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(SyncError::Store)?;
            Chainstate::with_store(dir, params, unix_now()).map_err(SyncError::Store)?
        }
        None => Chainstate::new(params),
    };
    let resumed_height = cs.chain().len() as u32 - 1;
    let mut mgr = PeerManager::new(cfg.max_peers);
    let started = Instant::now();

    let seeded = mgr.seed_from_dns(params, unix_now());
    let mut dialed = 0usize;
    for addr in &cfg.connect {
        let attempted = match cfg.proxy {
            Some(proxy) => mgr.connect_via(
                &proxy,
                &avila_p2p::proxy::SocksTarget::Ip(*addr),
                params.message_start,
                0,
                cs.chain().len() as i32,
            ),
            None => mgr.connect(*addr, params.message_start, 0, cs.chain().len() as i32),
        };
        if let Ok(Some(_)) = attempted {
            dialed += 1;
        }
    }
    if mgr.is_empty() && seeded == 0 {
        return Err(SyncError::NoPeers {
            seeded,
            explicit: cfg.connect.len(),
        });
    }

    let mut established_total = 0u32;
    let mut disconnects = 0u32;
    let mut connected = 0u32;
    while started.elapsed() < cfg.timeout
        && connected.saturating_sub(resumed_height) < cfg.target_height
    {
        for event in mgr.tick_net(&mut cs, unix_now(), params.message_start, 0) {
            match event {
                NetEvent::Connected { .. } => established_total += 1,
                NetEvent::Disconnected { .. } => disconnects += 1,
                _ => {}
            }
        }
        connected = cs.chain().len() as u32 - 1;
        // The target counts blocks connected *this run* above whatever
        // the store resumed at — a resumed chain doesn't re-trigger
        // the stop condition at its own height.
        let run_progress = connected.saturating_sub(resumed_height);
        progress(&SyncProgress {
            peers: mgr.len(),
            connected_height: connected,
            header_height: cs.tree().tip().height,
            in_flight: mgr.in_flight(),
            established_total,
            disconnects,
        });
        if run_progress >= cfg.target_height {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    if cfg.data_dir.is_some() {
        cs.flush().map_err(SyncError::Store)?;
    }

    Ok(SyncReport {
        explicit_dialed: dialed,
        connected_height: connected,
        header_height: cs.tree().tip().height,
        tip: cs.chain().last().map(|h| h.to_string()),
        established_total,
        target_reached: connected.saturating_sub(resumed_height) >= cfg.target_height,
        elapsed: started.elapsed(),
    })
}

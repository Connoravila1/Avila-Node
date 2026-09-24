//! One run of the node as the interface sees it: the sync worker (or the
//! `--demo` simulator), the latest view, and what this session observed
//! over time — samples for the sparklines, and an activity log derived
//! from the differences between successive views.

use crate::demo::Demo;
use crate::model::{NodeView, PeerView, thousands};
use avila_node::sync::{SyncConfig, SyncProgress, SyncReport};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Fifteen minutes of one-per-second samples.
const HISTORY: usize = 900;
const ACTIVITY: usize = 500;
/// The worker reports every tick; the screens need far fewer updates.
const REPORT_EVERY: Duration = Duration::from_millis(150);
/// Simulated seconds replayed on a demo start, so the sparklines and the
/// activity log have something in them from the first frame.
const DEMO_BACKFILL: u32 = 600;

/// How the next run starts. These reset each launch; only appearance is
/// remembered.
#[derive(Clone, Debug)]
pub struct RunSettings {
    /// Comma-separated `host:port` peers to dial (empty: DNS seeds only).
    pub connect: String,
    /// SOCKS5 proxy `host:port` (empty: connect directly).
    pub proxy: String,
    /// Stop once this many blocks connect; `None` runs until stopped.
    pub stop_after: Option<u32>,
    /// Keep the chainstate on disk, so the next run resumes.
    pub store: bool,
    /// Prune block files beyond this many MiB (empty: keep everything).
    pub prune_mib: String,
}

impl RunSettings {
    #[must_use]
    pub fn new(network: avila_core::Network) -> Self {
        Self {
            // Regtest has no DNS seeds; prefill Core's default port.
            connect: if network == avila_core::Network::Regtest {
                "127.0.0.1:18444".into()
            } else {
                String::new()
            },
            proxy: String::new(),
            stop_after: None,
            store: true,
            prune_mib: String::new(),
        }
    }

    fn connect_addrs(&self) -> Vec<SocketAddr> {
        self.connect
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    }

    /// What the next start would ignore, in plain words.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        for part in self.connect.split(',').map(str::trim) {
            if !part.is_empty() && part.parse::<SocketAddr>().is_err() {
                out.push(format!(
                    "“{part}” needs to be an address with a port, like 203.0.113.5:8333."
                ));
            }
        }
        let proxy = self.proxy.trim();
        if !proxy.is_empty() && proxy.parse::<SocketAddr>().is_err() {
            out.push("The proxy needs to be an address with a port, like 127.0.0.1:9050.".into());
        }
        let prune = self.prune_mib.trim();
        if !prune.is_empty() && prune.parse::<u64>().is_err() {
            out.push("The prune target is a whole number of MiB, like 5000.".into());
        }
        out
    }
}

/// The one-glance answer to "what is my node doing?".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Idle,
    Connecting,
    Syncing,
    CaughtUp,
    Stopping,
    Stopped,
    Failed,
}

impl Phase {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "Not running",
            Self::Connecting => "Finding peers",
            Self::Syncing => "Syncing",
            Self::CaughtUp => "Up to date",
            Self::Stopping => "Stopping",
            Self::Stopped => "Stopped",
            Self::Failed => "Stopped by an error",
        }
    }

    #[must_use]
    pub fn live(self) -> bool {
        matches!(self, Self::Connecting | Self::Syncing | Self::CaughtUp)
    }
}

/// One point of the session's history, at most one per second.
#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub t: f64,
    pub connected: u32,
    /// The background replay's height (0 without a snapshot).
    pub replayed: u32,
    pub peers: usize,
    pub mempool: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityKind {
    Node,
    Blocks,
    Peers,
    Verification,
}

impl ActivityKind {
    pub const ALL: [Self; 4] = [Self::Blocks, Self::Peers, Self::Verification, Self::Node];

    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Node => "Node",
            Self::Blocks => "Blocks",
            Self::Peers => "Peers",
            Self::Verification => "Verification",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Activity {
    serial: u64,
    /// Wall-clock time, `HH:MM:SS` UTC.
    pub clock: String,
    pub kind: ActivityKind,
    pub text: String,
    /// A hash or peer detail, shown in monospace after the text.
    pub detail: Option<String>,
}

/// How the last run ended.
#[derive(Debug)]
pub enum Ended {
    /// On request, or at the block target. The simulator has no report.
    Stopped(Option<SyncReport>),
    Failed(String),
}

enum Msg {
    Progress(Box<SyncProgress>),
    Done(Result<SyncReport, String>),
}

pub struct Session {
    pub view: Option<NodeView>,
    pub history: VecDeque<Sample>,
    pub activity: VecDeque<Activity>,
    pub ended: Option<Ended>,
    /// Simulated data (`--demo`); every screen says so.
    pub demo: bool,
    /// Session time the validated tip last advanced — drives the
    /// ribbon's pulse.
    pub tip_advanced_at: Option<f64>,
    running: bool,
    stopping: bool,
    rx: Option<Receiver<Msg>>,
    cancel: Option<Arc<AtomicBool>>,
    sim: Option<Demo>,
    /// When the simulator last stepped, session seconds.
    sim_stepped: Option<f64>,
    origin: Instant,
    /// Session time each height was first seen as the tip.
    tip_seen: HashMap<u32, f64>,
    known_peers: HashMap<u64, PeerView>,
    /// The catch-up line being extended: `(first height, entry serial)`.
    catchup: Option<(u32, u64)>,
    serial: u64,
}

impl Session {
    #[must_use]
    pub fn new(demo: bool) -> Self {
        Self {
            view: None,
            history: VecDeque::new(),
            activity: VecDeque::new(),
            ended: None,
            demo,
            tip_advanced_at: None,
            running: false,
            stopping: false,
            rx: None,
            cancel: None,
            sim: None,
            sim_stepped: None,
            origin: Instant::now(),
            tip_seen: HashMap::new(),
            known_peers: HashMap::new(),
            catchup: None,
            serial: 0,
        }
    }

    /// Seconds since the session began.
    #[must_use]
    pub fn now(&self) -> f64 {
        self.origin.elapsed().as_secs_f64()
    }

    #[must_use]
    pub fn running(&self) -> bool {
        self.running
    }

    #[must_use]
    pub fn phase(&self) -> Phase {
        if self.stopping {
            return Phase::Stopping;
        }
        if self.running {
            return match &self.view {
                Some(v) if v.established().next().is_some() => {
                    if v.caught_up() {
                        Phase::CaughtUp
                    } else {
                        Phase::Syncing
                    }
                }
                _ => Phase::Connecting,
            };
        }
        match &self.ended {
            Some(Ended::Failed(_)) => Phase::Failed,
            Some(Ended::Stopped(_)) => Phase::Stopped,
            None => Phase::Idle,
        }
    }

    /// Starts a run. In demo mode the simulator stands in for the network.
    pub fn start(
        &mut self,
        network: avila_core::Network,
        data_dir: PathBuf,
        settings: &RunSettings,
    ) {
        if self.running {
            return;
        }
        self.running = true;
        self.stopping = false;
        self.ended = None;
        self.view = None;
        self.known_peers.clear();
        self.catchup = None;
        let now = self.now();
        if self.demo {
            let from = now - f64::from(DEMO_BACKFILL);
            let sim = Demo::new(from);
            self.log(
                ActivityKind::Node,
                "Started the simulated node.".into(),
                None,
                from,
            );
            for s in 0..DEMO_BACKFILL {
                let t = from + f64::from(s);
                self.apply(sim.view_at(t), t);
            }
            self.sim = Some(sim);
            return;
        }
        let params = params(network);
        let cancel = Arc::new(AtomicBool::new(false));
        let cfg = SyncConfig {
            connect: settings.connect_addrs(),
            target_height: settings.stop_after.unwrap_or(u32::MAX),
            timeout: Duration::from_secs(10 * 365 * 86_400),
            proxy: settings.proxy.trim().parse().ok(),
            data_dir: settings.store.then_some(data_dir),
            cancel: Some(cancel.clone()),
            // Without a block target this is a desktop daemon: it keeps
            // redialing with zero peers instead of giving up.
            persist: settings.stop_after.is_none(),
            prune_bytes: settings
                .prune_mib
                .trim()
                .parse::<u64>()
                .ok()
                .map(|mib| mib.saturating_mul(1024 * 1024)),
            v2transport: true,
            // The overview draws the block this mempool would build next.
            preview_next_block: true,
            ..SyncConfig::default()
        };
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let mut last: Option<Instant> = None;
            let report = avila_node::sync::run(&params, &cfg, |p| {
                if last.is_none_or(|l| l.elapsed() >= REPORT_EVERY) {
                    last = Some(Instant::now());
                    let _ = tx.send(Msg::Progress(Box::new(p.clone())));
                }
            });
            let _ = tx.send(Msg::Done(report.map_err(|e| e.to_string())));
        });
        self.cancel = Some(cancel);
        self.rx = Some(rx);
        let text = match settings.stop_after {
            Some(n) => format!(
                "Started syncing; will stop after {} blocks.",
                thousands(n.into())
            ),
            None => "Started the node.".into(),
        };
        self.log(ActivityKind::Node, text, None, now);
    }

    /// Asks the run to stop. A real run flushes its state first, so it
    /// shows as stopping until the worker reports back.
    pub fn stop(&mut self) {
        if self.sim.take().is_some() {
            self.end(Ended::Stopped(None));
            return;
        }
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Relaxed);
            self.stopping = true;
        }
    }

    /// Drains the worker, or steps the simulator. Returns whether
    /// anything changed.
    pub fn poll(&mut self) -> bool {
        let now = self.now();
        if let Some(sim) = &self.sim {
            // Ten steps a second is all the simulation needs, however
            // fast the window happens to be repainting.
            if self.sim_stepped.is_some_and(|at| now - at < 0.1) {
                return false;
            }
            self.sim_stepped = Some(now);
            let view = sim.view_at(now);
            self.apply(view, now);
            return true;
        }
        let Some(rx) = &self.rx else {
            return false;
        };
        let mut latest = None;
        let mut done = None;
        loop {
            match rx.try_recv() {
                Ok(Msg::Progress(p)) => latest = Some(p),
                Ok(Msg::Done(r)) => {
                    done = Some(r);
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    done = Some(Err("the sync worker exited without a report".into()));
                    break;
                }
            }
        }
        let changed = latest.is_some() || done.is_some();
        if let Some(p) = latest {
            self.apply(NodeView::from(p.as_ref()), now);
        }
        match done {
            Some(Ok(report)) => self.end(Ended::Stopped(Some(report))),
            Some(Err(e)) => self.end(Ended::Failed(e)),
            None => {}
        }
        changed
    }

    fn end(&mut self, ended: Ended) {
        let text = match &ended {
            Ended::Stopped(Some(r)) if r.target_reached => format!(
                "Stopped at the block target, height {}.",
                thousands(r.connected_height.into())
            ),
            Ended::Stopped(Some(r)) => {
                format!(
                    "Stopped at height {}.",
                    thousands(r.connected_height.into())
                )
            }
            Ended::Stopped(None) => "Stopped the simulated node.".into(),
            Ended::Failed(e) => format!("Stopped by an error: {e}"),
        };
        let now = self.now();
        self.log(ActivityKind::Node, text, None, now);
        self.ended = Some(ended);
        self.running = false;
        self.stopping = false;
        self.rx = None;
        self.cancel = None;
    }

    /// Folds a new view in at session time `t`.
    fn apply(&mut self, view: NodeView, t: f64) {
        match self.view.take() {
            Some(prev) => self.diff(&prev, &view, t),
            None => self.first(&view, t),
        }
        if let Some((h, _)) = view.recent.last() {
            self.tip_seen.entry(*h).or_insert(t);
            // A sync sees hundreds of thousands of tips; only the recent
            // ones are ever shown.
            if self.tip_seen.len() > 512 {
                let keep = h.saturating_sub(256);
                self.tip_seen.retain(|height, _| *height >= keep);
            }
        }
        if self.history.back().is_none_or(|s| t - s.t >= 1.0) {
            self.history.push_back(Sample {
                t,
                connected: view.connected,
                replayed: view.trust.snapshot.as_ref().map_or(0, |s| s.replayed),
                peers: view.established().count(),
                mempool: view.mempool_txs,
            });
            while self.history.len() > HISTORY {
                self.history.pop_front();
            }
        }
        self.view = Some(view);
    }

    fn first(&mut self, view: &NodeView, t: f64) {
        if view.connected > 0 {
            self.log(
                ActivityKind::Blocks,
                format!(
                    "Loaded the chain at height {}.",
                    thousands(view.connected.into())
                ),
                None,
                t,
            );
        }
        if let Some(s) = &view.trust.snapshot {
            let text = if s.proven {
                format!(
                    "The snapshot at {} is already proven by a finished replay.",
                    thousands(s.base.into())
                )
            } else {
                format!(
                    "Using a snapshot at {}. Blocks below it are assumed until the background replay checks them.",
                    thousands(s.base.into())
                )
            };
            self.log(
                ActivityKind::Verification,
                text,
                Some(s.base_hash.clone()),
                t,
            );
        }
        self.peers_changed(view, t);
    }

    fn diff(&mut self, prev: &NodeView, next: &NodeView, t: f64) {
        if next.connected > prev.connected {
            self.blocks_connected(prev, next, t);
        }
        self.peers_changed(next, t);
        let was_proven = prev.trust.snapshot.as_ref().is_some_and(|s| s.proven);
        if let Some(s) = &next.trust.snapshot
            && s.proven
            && !was_proven
        {
            self.log(
                ActivityKind::Verification,
                format!(
                    "The replay reached {} and matched the snapshot’s UTXO set hash. Every block is now proven here.",
                    thousands(s.base.into())
                ),
                Some(s.expected_utxo_hash.clone()),
                t,
            );
        }
    }

    /// One line per block once caught up; while catching up, a single
    /// line that keeps extending, so a sync doesn't bury everything else.
    fn blocks_connected(&mut self, prev: &NodeView, next: &NodeView, t: f64) {
        let extending = self
            .catchup
            .filter(|(_, serial)| self.activity.iter().rev().any(|a| a.serial == *serial));
        let near_tip = next.behind() <= 2 && next.connected - prev.connected <= 2;
        if extending.is_none() && near_tip {
            for h in prev.connected + 1..=next.connected {
                let hash = next
                    .recent
                    .iter()
                    .find(|(height, _)| *height == h)
                    .map(|(_, hash)| hash.clone());
                let from = next
                    .established()
                    .find(|p| p.last_block == Some(h))
                    .map(|p| format!(", delivered by {}", peer_name(p)))
                    .unwrap_or_default();
                self.log(
                    ActivityKind::Blocks,
                    format!("Connected block {}{from}", thousands(h.into())),
                    hash,
                    t,
                );
            }
        } else {
            let from = extending.map_or(prev.connected + 1, |(from, _)| from);
            let text = format!(
                "Connected blocks {} to {}",
                thousands(from.into()),
                thousands(next.connected.into())
            );
            match extending {
                Some((_, serial)) => {
                    if let Some(line) = self.activity.iter_mut().rev().find(|a| a.serial == serial)
                    {
                        line.text = text;
                    }
                }
                None => {
                    let serial = self.log(ActivityKind::Blocks, text, None, t);
                    self.catchup = Some((from, serial));
                }
            }
        }
        if next.behind() == 0 {
            self.catchup = None;
        }
        if near_tip {
            self.tip_advanced_at = Some(t);
        }
    }

    fn peers_changed(&mut self, next: &NodeView, t: f64) {
        let current: HashMap<u64, PeerView> =
            next.established().map(|p| (p.id, p.clone())).collect();
        let mut joined: Vec<&PeerView> = current
            .values()
            .filter(|p| !self.known_peers.contains_key(&p.id))
            .collect();
        joined.sort_by_key(|p| p.id);
        let joined: Vec<(String, Option<String>)> = joined
            .into_iter()
            .map(|p| (format!("Connected to {}", peer_name(p)), peer_detail(p)))
            .collect();
        let mut left: Vec<&PeerView> = self
            .known_peers
            .values()
            .filter(|p| !current.contains_key(&p.id))
            .collect();
        left.sort_by_key(|p| p.id);
        let left: Vec<String> = left
            .into_iter()
            .map(|p| format!("Disconnected from {}", peer_name(p)))
            .collect();
        for (text, detail) in joined {
            self.log(ActivityKind::Peers, text, detail, t);
        }
        for text in left {
            self.log(ActivityKind::Peers, text, None, t);
        }
        self.known_peers = current;
    }

    /// Adds an activity line at session time `t`; returns its serial.
    pub fn log(&mut self, kind: ActivityKind, text: String, detail: Option<String>, t: f64) -> u64 {
        self.serial += 1;
        let clock = self.clock_at(t);
        self.activity.push_back(Activity {
            serial: self.serial,
            clock,
            kind,
            text,
            detail,
        });
        while self.activity.len() > ACTIVITY {
            self.activity.pop_front();
        }
        self.serial
    }

    fn clock_at(&self, t: f64) -> String {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        let at = (wall - (self.now() - t)).max(0.0) as u64 % 86_400;
        format!("{:02}:{:02}:{:02}", at / 3600, at % 3600 / 60, at % 60)
    }

    /// Seconds since `height` first showed up as the tip this session.
    #[must_use]
    pub fn seen_ago(&self, height: u32) -> Option<f64> {
        self.tip_seen.get(&height).map(|t| self.now() - t)
    }

    /// How fast a height advanced over the last minute, per minute.
    #[must_use]
    pub fn per_min(&self, field: impl Fn(&Sample) -> u32) -> Option<f64> {
        let last = self.history.back()?;
        let first = self.history.iter().find(|s| last.t - s.t <= 60.0)?;
        let dt = last.t - first.t;
        (dt >= 5.0).then(|| f64::from(field(last).saturating_sub(field(first))) / dt * 60.0)
    }

    /// One field of every sample, oldest first.
    #[must_use]
    pub fn series(&self, field: impl Fn(&Sample) -> f64) -> Vec<f64> {
        self.history.iter().map(field).collect()
    }
}

/// Consensus parameters for `network`.
#[must_use]
pub fn params(network: avila_core::Network) -> avila_consensus::params::Params {
    use avila_consensus::params::Network as Net;
    match network {
        avila_core::Network::Mainnet => Net::Mainnet,
        avila_core::Network::Testnet4 => Net::Testnet4,
        avila_core::Network::Signet => Net::Signet,
        avila_core::Network::Regtest => Net::Regtest,
    }
    .params()
}

/// What a person would call a peer: its address, else its software.
#[must_use]
pub fn peer_name(p: &PeerView) -> String {
    p.addr
        .clone()
        .or_else(|| p.agent.as_deref().map(agent_name))
        .unwrap_or_else(|| format!("peer {}", p.id))
}

fn peer_detail(p: &PeerView) -> Option<String> {
    let agent = p.agent.as_deref().map(agent_name)?;
    let transport = if p.v2 { "encrypted" } else { "plaintext" };
    Some(format!("{agent} · {transport}"))
}

/// `/Satoshi:29.0.0/` → `Satoshi 29.0.0`.
#[must_use]
pub fn agent_name(agent: &str) -> String {
    let trimmed = agent.trim_matches('/');
    if trimmed.is_empty() {
        return "unknown software".into();
    }
    let name = trimmed.replace(':', " ").replace('/', " · ");
    match name.char_indices().nth(48) {
        Some((cut, _)) => format!("{}…", &name[..cut]),
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_report_what_the_next_start_would_ignore() {
        let mut s = RunSettings::new(avila_core::Network::Mainnet);
        assert!(s.problems().is_empty());
        s.connect = "203.0.113.5:8333, nonsense".into();
        s.proxy = "localhost".into();
        s.prune_mib = "5 GB".into();
        assert_eq!(s.problems().len(), 3);
        assert_eq!(s.connect_addrs().len(), 1);
        assert_eq!(
            RunSettings::new(avila_core::Network::Regtest).connect,
            "127.0.0.1:18444"
        );
    }

    #[test]
    fn agent_names_read_as_words() {
        assert_eq!(agent_name("/Satoshi:29.0.0/"), "Satoshi 29.0.0");
        assert_eq!(
            agent_name("/Satoshi:28.1.0/Knots:20250305/"),
            "Satoshi 28.1.0 · Knots 20250305"
        );
        assert_eq!(agent_name("//"), "unknown software");
    }

    #[test]
    fn demo_session_backfills_history_and_activity() {
        let net = avila_core::Network::Mainnet;
        let mut s = Session::new(true);
        s.start(net, PathBuf::new(), &RunSettings::new(net));
        assert!(s.running());
        assert!(s.history.len() >= 590, "{} samples", s.history.len());
        let kinds: Vec<_> = s.activity.iter().map(|a| a.kind).collect();
        for kind in ActivityKind::ALL {
            assert!(kinds.contains(&kind), "no {kind:?} activity");
        }
        // The launch catch-up is one extending line, not forty.
        let catchup = s
            .activity
            .iter()
            .filter(|a| a.text.starts_with("Connected blocks"))
            .count();
        assert_eq!(catchup, 1);
        assert_eq!(s.phase(), Phase::CaughtUp);
        s.stop();
        assert_eq!(s.phase(), Phase::Stopped);
    }
}

//! Live peer-to-peer synchronization: drives [`PeerManager`] over real
//! TCP against a configured network — DNS-seeded or explicitly connected
//! peers, headers-first download, and full consensus intake through
//! [`Chainstate`]. This is the CLI-visible "real sync" path; all
//! verdicts still come from `avila-consensus`.

use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use avila_consensus::chainstate::Chainstate;
use avila_consensus::params::Params;
use avila_p2p::manager::{EclipseSignal, NetEvent, PeerManager};

pub use crate::chain_profile::{ChainProfile, ProfilePoint};
pub use crate::next_block::NextBlock;

/// Connected-block interval between mid-sync `state.dat` checkpoints
/// — Core's `FlushStateToDisk` cadence analogue. 2048 blocks bounds a
/// crash to replaying at most that many blk-file entries.
const FLUSH_INTERVAL: u32 = 2048;

/// Blocks per pace sample — a half-retarget span balances regression
/// signal against per-sample noise.
const PACE_WINDOW_BLOCKS: u32 = 1024;
/// Windows fed to the least-squares fit (the most recent ~20k blocks —
/// old enough to span an era boundary, young enough to track drift).
const PACE_FIT_WINDOWS: usize = 20;
/// Samples retained; anything older drops — the era curve slides.
const PACE_MAX_WINDOWS: usize = 40;
/// Encoded-size ceiling for a block: weight cap is 4M units and encoded
/// bytes can't exceed ~4MB — the principled asymptote the size
/// extrapolation saturates at instead of growing linearly forever.
const BLOCK_BYTES_CAP: f64 = 4_000_000.0;

/// One pace sample: the cost of `blocks` connected blocks ending at
/// `height`, measured as wall time and summed encoded bytes.
struct PaceWindow {
    height: u32,
    wall_ms: u64,
    blocks: u64,
    bytes: u64,
}

/// Era-aware IBD pace model. A flat `blocks/minute` extrapolation is
/// systematically wrong: validation cost per block scales with block
/// size (decode, UTXO churn, script work all ride the byte count), and
/// block size is not flat across history — empty 2010 blocks run
/// thousands of times cheaper than segwit-era ones. The model regresses
/// observed per-block wall cost on per-block encoded bytes over recent
/// windows, extrapolates the byte-size curve forward — saturated at the
/// protocol weight cap, where real block growth must stop — and
/// integrates the predicted pace over the remaining heights.
struct PaceModel {
    windows: std::collections::VecDeque<PaceWindow>,
    /// Height of the last recorded sample (windows close every
    /// `PACE_WINDOW_BLOCKS` above it).
    last_height: u32,
    /// Wall clock of the last sample.
    last_at: std::time::Instant,
    /// Last fit coefficients — `debug_fit` reports them.
    last_fit: Option<(f64, f64, f64, f64, usize)>,
}

impl PaceModel {
    fn new(from_height: u32) -> Self {
        Self {
            windows: std::collections::VecDeque::new(),
            last_height: from_height,
            last_at: std::time::Instant::now(),
            last_fit: None,
        }
    }

    /// Records a sample whenever `connected` has advanced a full
    /// window; sums encoded bytes from the block store so the byte
    /// axis is real, not estimated.
    fn sample(&mut self, cs: &Chainstate, connected: u32) {
        if connected < self.last_height + PACE_WINDOW_BLOCKS {
            return;
        }
        let mut bytes = 0u64;
        let chain = cs.chain();
        if let Some(store) = cs.store() {
            for hash in &chain[(self.last_height as usize + 1)..=(connected as usize)] {
                if let Some(pos) = store.position(hash) {
                    bytes += u64::from(pos.len);
                }
            }
        }
        let now = std::time::Instant::now();
        self.windows.push_back(PaceWindow {
            height: connected,
            wall_ms: now.duration_since(self.last_at).as_millis() as u64,
            blocks: u64::from(connected - self.last_height),
            bytes,
        });
        self.last_height = connected;
        self.last_at = now;
        while self.windows.len() > PACE_MAX_WINDOWS {
            self.windows.pop_front();
        }
    }

    /// Fit coefficients of the last `eta_secs` call, for diagnostics:
    /// `(pace_intercept_ms, pace_per_byte_ms, byte_slope_per_height,
    /// byte_cap, windows_used)`.
    fn debug_fit(&self) -> Option<(f64, f64, f64, f64, usize)> {
        self.last_fit
    }

    /// Predicted seconds to connect `from + 1 ..= to` as
    /// `(lo, central, hi)` — a calibrated interval, not fake point
    /// precision. `lo` holds blocks at the measured median size (the
    /// era never densifies), `central` follows the size regression
    /// (era-bound), `hi` prices every remaining block at the dense-era
    /// ceiling. `None` while warming (<4 windows) — the flat-rate
    /// fallback stays honest instead.
    fn eta_secs(&mut self, from: u32, to: u32) -> Option<(u64, u64, u64)> {
        if self.windows.len() < 4 || to <= from {
            return None;
        }
        let fit: Vec<&PaceWindow> = self
            .windows
            .iter()
            .rev()
            .take(PACE_FIT_WINDOWS)
            .rev()
            .collect();
        // Per-window pace and size.
        let xs: Vec<f64> = fit
            .iter()
            .map(|w| w.bytes as f64 / w.blocks.max(1) as f64)
            .collect();
        let ys: Vec<f64> = fit
            .iter()
            .map(|w| w.wall_ms as f64 / w.blocks.max(1) as f64)
            .collect();
        let hs: Vec<f64> = fit.iter().map(|w| f64::from(w.height)).collect();
        // Outlier guard: a window that crossed a peer stall or a
        // checkpoint flush is wall-heavy for reasons unrelated to era.
        // Drop samples whose pace exceeds 4× the median before fitting.
        let mut sorted = ys.clone();
        sorted.sort_by(f64::total_cmp);
        let median = sorted[sorted.len() / 2].max(1.0);
        let keep: Vec<usize> = (0..ys.len())
            .filter(|&i| ys[i] <= 4.0 * median || ys.len() < 6)
            .collect();
        // Predicted pace = median observed pace scaled by the
        // predicted/observed size ratio. A linear `F + R·bytes` split
        // on 4-7 noisy windows produced unstable fits (both OLS and
        // ratio estimators): flush commits, fetch stalls, and fixed
        // per-block costs all land in the same wall sample, and any
        // two-parameter decomposition of that noise swings wildly.
        // The median is the one quantity that survives; the size
        // ratio carries the era-dependence (denser future blocks
        // cost proportionally more).
        let med_x = {
            let mut m: Vec<f64> = keep.iter().map(|&i| xs[i]).collect();
            m.sort_by(f64::total_cmp);
            m[m.len() / 2]
        };
        let med_y = sorted[sorted.len() / 2];
        // bytes/blk ≈ e + f·height — least squares on the byte axis.
        let n = keep.len() as f64;
        let (sh, sb, shh, shb) = keep.iter().fold((0.0, 0.0, 0.0, 0.0), |acc, &i| {
            (
                acc.0 + hs[i],
                acc.1 + xs[i],
                acc.2 + hs[i] * hs[i],
                acc.3 + hs[i] * xs[i],
            )
        });
        let hdenom = n * shh - sh * sh;
        let (bf, be) = if hdenom.abs() > f64::EPSILON {
            let f = (n * shb - sh * sb) / hdenom;
            (f, (sb - f * sh) / n)
        } else {
            (0.0, sb / n)
        };
        // Bounds for the extrapolation — the regression shapes relative
        // growth but is ill-conditioned on a few noisy windows, so the
        // predicted pace is clamped to a band around what has actually
        // been measured: no slower than 4× the p95 observed window pace
        // (the segwit-era plateau is a factor-of-few jump, not an
        // unbounded one), no faster than a quarter of the best observed
        // (cost doesn't teleport below what the era showed). The byte
        // mean gets the same treatment: saturation well past the
        // biggest observed era mean (era-bound below), not at the
        // protocol's per-block edge.
        let mut size_sorted = xs.clone();
        size_sorted.sort_by(f64::total_cmp);
        let p95_size = size_sorted[size_sorted.len() * 95 / 100];
        // Era-bound, not protocol-bound: the far tail can't be denser
        // than ~1.5× the worst measured window — the 4MB cap is a
        // per-block edge, never a sustained mean, and letting the
        // prediction float to it was the 9-day/4-day inflation.
        let byte_cap = (p95_size * 1.5).clamp(med_x, BLOCK_BYTES_CAP);
        // Pace bounds come from the kept (outlier-filtered) windows —
        // a stall window must not widen the cap it would sneak past.
        // ×2.5 covers a genuinely denser era without double-counting
        // the byte-size inflation already in `bytes_pred`.
        let mut kept_paces: Vec<f64> = keep.iter().map(|&i| ys[i]).collect();
        kept_paces.sort_by(f64::total_cmp);
        let p95_pace = kept_paces[kept_paces.len() * 95 / 100].max(1.0);
        let pace_cap = p95_pace * 2.5;
        let pace_floor = (kept_paces[0] * 0.25).max(0.5);
        // Debug tuple repurposed for the size-scaled model:
        // (median pace ms, size ratio at the cap, byte slope, byte
        // cap, windows used).
        self.last_fit = Some((med_y, byte_cap / med_x.max(1.0), bf, byte_cap, keep.len()));
        // The size slope only holds over the evidence — extrapolating a
        // local growth rate to the tip saturates every future block at
        // the cap (a 560k-height projection turned a +8B/blk mid-2016
        // slope into 4MB blocks forever and a 9-day ETA). The honest
        // bound: apply the trend at most twice the observed span, then
        // freeze — sizes stop growing at the edge of what we've seen.
        let (h_lo, h_hi) = keep
            .iter()
            .map(|&i| hs[i])
            .fold((f64::MAX, f64::MIN), |(lo, hi), h| (lo.min(h), hi.max(h)));
        let freeze_h = h_hi + (h_hi - h_lo).max(20_000.0);
        let mut remaining_ms = 0.0f64;
        let mut lo_ms = 0.0f64;
        let mut hi_ms = 0.0f64;
        let mut h = from as u64;
        let tip = to as u64;
        let stride = PACE_WINDOW_BLOCKS as u64;
        let pace_at = |bytes: f64| (med_y * bytes / med_x.max(1.0)).clamp(pace_floor, pace_cap);
        let lo_pace = pace_at(med_x);
        let hi_pace = pace_at(byte_cap);
        while h < tip {
            let mid = (h + stride / 2).min(freeze_h as u64);
            // Floor: the size regression can go negative on a thin
            // window (early 2015 blocks shrank after the 2014 spike),
            // but blocks never empty out — the long-run size trend is
            // growth. Hold the prediction at the recent median at
            // least, so a declining window can't predict a free future.
            let bytes_pred = (be + bf * mid as f64).clamp(med_x, byte_cap);
            let len = stride.min(tip - h) as f64;
            remaining_ms += pace_at(bytes_pred) * len;
            lo_ms += lo_pace * len;
            hi_ms += hi_pace * len;
            h += stride;
        }
        Some((
            (lo_ms / 1000.0).ceil() as u64,
            (remaining_ms / 1000.0).ceil() as u64,
            (hi_ms / 1000.0).ceil() as u64,
        ))
    }
}

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
    /// Core's `-asmap=<file>`: a prefix→ASN map for outbound-dial
    /// bucketing (the Erebus mitigation, queue #21). Text format —
    /// one `a.b.c.d/plen asn` row per line; Core's bit-packed
    /// `asmap.dat` parsing is open. Empty/absent = no bucketing.
    pub asmap_path: Option<std::path::PathBuf>,
    /// Fixed-size send cells in bytes (queue #17): pads every v2
    /// link's outgoing queue to this multiple with decoy packets so
    /// the wire write-size histogram is flat. 0 = Core's behavior
    /// (natural sizes).
    pub cell_bytes: usize,
    /// When set, the chainstate persists under this directory —
    /// re-running resumes from the stored snapshot instead of genesis.
    pub data_dir: Option<std::path::PathBuf>,
    /// Coins-view write-back cache budget in bytes — Core's `-dbcache`
    /// (in Core it also covers block/filter indexes; here it bounds
    /// only the coins cache). `None` = the 450 MiB default.
    pub dbcache: Option<usize>,
    /// Cancellation flag — checked each tick; `true` ends the run early
    /// and still returns a report (state already flushed).
    pub cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// `true` for the long-running `run` daemon: never exit on zero
    /// reachable peers — the manager redials forever and `addnode` can
    /// arrive over RPC later (Core's daemon behavior). `false` for a
    /// bounded `sync` run, where no candidates means fail fast.
    pub persist: bool,
    /// When set with `data_dir`, prune blk files after the final flush
    /// so the on-disk total stays under this many bytes.
    pub prune_bytes: Option<u64>,
    /// Core's `-txindex`: maintain a txid→block index (`txindex.dat`
    /// under `data_dir`) so `getrawtransaction` can find transactions
    /// without a named block.
    pub txindex: bool,
    /// Core's `-blockfilterindex`: maintain the BIP 158 basic filter
    /// index (`cfilters.dat` under `data_dir`) so `getblockfilter` and
    /// `scanblocks` serve real data.
    pub blockfilterindex: bool,
    /// Core's `-maxmempool` in bytes — the pool's serialized-byte cap
    /// (Core default 300 MB). `None` keeps the built-in default.
    pub maxmempool_bytes: Option<usize>,
    /// Core's `-peerblockfilters` (default off): advertise
    /// `NODE_COMPACT_FILTERS` and answer BIP157 requests. Requires the
    /// index, like Core — `-peerblockfilters` without
    /// `-blockfilterindex` is a startup error upstream.
    pub peerblockfilters: bool,
    /// Core's `-v2transport` (default true since v26): outbound peers
    /// are dialed with BIP324 first, falling back to v1 when the peer
    /// answers in cleartext.
    pub v2transport: bool,
    /// `-listen=<addr>` — accept inbound peer connections on this
    /// address. Each accepted socket runs its handshake on a bounded
    /// worker (v1 or BIP324, auto-detected from the peer's first
    /// bytes — Core's `Transport` discriminator) and joins through
    /// `PeerManager::add_inbound`'s slot/eviction rules.
    pub listen: Option<SocketAddr>,
    /// `--electrum addr`: bind the Electrum-protocol server there and
    /// maintain the scripthash index (`scindex.dat`) it serves from.
    pub electrum: Option<SocketAddr>,
    /// `--utreexo`: run the utreexo shadow consumer — ask peers for
    /// `utxproof` bundles and connect each block through
    /// `connect_block_proven` against a ~1 KiB accumulator, in
    /// parallel with the conventional UTXO path.
    pub utreexo: bool,
    /// `--utreexo-bridge`: maintain a proving forest and record a
    /// spend bundle per connected block (`proofs.dat`), served to
    /// peers who sent `sendutxproof`.
    pub utreexo_bridge: bool,
    /// Experimental fast-IBD path: mirror the committed coins into a
    /// RAM-resident flat table (~0.34 µs/input measured vs ~2.8 µs
    /// through the disk cascade — `coins_flat_bench`, experiment
    /// 09-28s). The value is the flat table's resident-byte cap; `0`
    /// means uncapped. When unset or over-budget the ordinary disk
    /// path runs — verification is identical either way.
    pub flat_utxo_bytes: Option<usize>,
    /// When set, publish each tick's progress into this snapshot so a
    /// query surface (RPC, GUI) can read it without blocking sync.
    pub status: Option<crate::rpc::SharedStatus>,
    /// When set, drain and answer chain queries each tick — the RPC
    /// surface's read path into the live chainstate (Core's `cs_main`
    /// read pattern, by message passing instead of locking). Shared so
    /// the config stays `Clone`/`Debug`.
    pub queries:
        Option<std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<crate::rpc::ChainQuery>>>>,
    /// The `waitforblock*` registry — parked predicates are re-checked
    /// against the live chainstate each tick, and `shutdown` wakes
    /// every waiter on loop exit (Core's validation-interface
    /// notifications, polled instead of callbacked).
    pub waiters: Option<std::sync::Arc<crate::rpc::BlockWaiters>>,
    /// When set, rebuild [`SyncProgress::next_block`] from the live
    /// mempool periodically. The desktop GUI sets this to draw a
    /// preview of the block this node would produce next; other
    /// callers leave it off to skip the extra template-assembly work.
    pub preview_next_block: bool,
    /// `policy.require_standard` — gate the standardness checks
    /// (negated Core `-acceptnonstdtxn`; default on).
    pub require_standard: bool,
    /// `mempool.min_relay_fee_sat_per_kvb` — admission/relay fee floor
    /// in sat/kvB (the 0.1 sat/vB post-29.x default is 100).
    pub min_relay_fee: i64,
    /// `policy.datacarrier`/`datacarrier_size` — the OP_RETURN byte
    /// budget per tx; `None` mirrors `-datacarrier=0`.
    pub datacarrier_bytes: Option<usize>,
    /// `policy.permit_bare_multisig` (Core's `-permitbaremultisig`).
    pub permit_bare_multisig: bool,
    /// `policy.dust_relay_fee_sat_per_kvb` — dust-threshold rate in
    /// sat/kvB (Core's `-dustrelayfee`, default 3000).
    pub dust_relay_fee: i64,
    /// `mempool.expiry_secs` — evict entries older than this (Core's
    /// `-mempoolexpiry`, 336h).
    pub mempool_expiry_secs: u32,
    /// `relay.tx.stem` — route locally-originated transactions through
    /// one stem hop before flooding (default on).
    pub stem_relay: bool,
    /// `sync.max_in_transit` — total blocks-in-flight budget across
    /// peers (performance policy, not correctness).
    pub max_in_transit: usize,
    /// `net.dns_seeds` (Core's `-dnsseed`): seed the address book from
    /// DNS when no `connect` peers and no proxy are configured.
    pub dns_seeds: bool,
    /// `hooks.peer_accept` — external verdict helpers consulted on
    /// inbound admission (conjunction; narrowing only). Empty = none.
    pub peer_accept_hooks: Vec<crate::hooks::HookSpec>,
    /// `tx.admit` verdict helpers — consulted on every mempool
    /// submission before the built-in checks (hot path).
    pub tx_admit_hooks: Vec<crate::hooks::HookSpec>,
    /// `policy.shadow` — counterfactual relay profiles scored on every
    /// admission. Empty disables the observatory.
    pub shadow_profiles: Vec<String>,
    /// `tx.announce` verdict helpers — consulted per (tx, link) on
    /// every announcement hop. The hottest hook path.
    pub tx_announce_hooks: Vec<crate::hooks::HookSpec>,
    /// `extrapool.admit` verdict helpers — gate observation records.
    pub extrapool_admit_hooks: Vec<crate::hooks::HookSpec>,
    /// `extrapool.promote` verdict helpers — gate re-admission.
    pub extrapool_promote_hooks: Vec<crate::hooks::HookSpec>,
    /// `relay.tx.deny_pairs` — the compartment matrix, already split
    /// into (src, dst) names by the config resolver.
    pub deny_pairs: Vec<(String, String)>,
    /// `mempool.private` — stem-only, RPC-hidden submissions.
    pub private_submissions: bool,
    /// `tx.serve` verdict helpers — consulted per tx item on inbound
    /// `getdata`; `reject` answers that item `notfound`.
    pub tx_serve_hooks: Vec<crate::hooks::HookSpec>,
    /// `mining.include_extrapool` — audition observation-pool entries
    /// for a template's leftover budget (consensus-revalidated).
    pub mine_extrapool: bool,
    /// `block.serve` verdict helpers — per block item on `getdata` and
    /// each `getblocktxn`; `reject` answers `notfound`.
    pub block_serve_hooks: Vec<crate::hooks::HookSpec>,
    /// `template.build` verdict helpers — veto assembled templates.
    pub template_build_hooks: Vec<crate::hooks::HookSpec>,
    /// `net.blocks_only` — silence tx relay in every direction.
    pub blocks_only: bool,
    /// `relay.block.*` — `(compact, compact_high_bandwidth,
    /// compact_serve, announce, serve)`.
    pub relay_block: (bool, bool, bool, String, String),
    /// `relay.tx.*` announce/reach/retry policy — `(announce_mode,
    /// to_inbound, to_blocks_only_peers, send_feefilter,
    /// rebroadcast_local, rebroadcast_interval)`.
    pub relay_tx: (String, bool, bool, u64, bool, u32),
    /// `mining.*` template budgets — `(max_weight, min_tx_fee,
    /// reserved_weight)`.
    pub mining_budgets: (Option<usize>, i64, Option<usize>),
    /// `[extrapool]` — the observation pool for policy rejects.
    pub extrapool: avila_core::ExtrapoolConfig,
    /// `peers.ban_time` — default `setban` duration (Core's `-bantime`).
    pub ban_time: i64,
    /// `config::risk_review` findings, computed at merge time so the
    /// run loop can warn once per *new* risk (acknowledged via
    /// `<datadir>/risk_ack` written by `config accept-risks`).
    pub risks: Vec<crate::config::RiskFinding>,
    /// Live knob edits — the GUI/RPC side sends `ControlMsg::Set`;
    /// the loop drains it each tick. `config::live_knob` names the
    /// accepted paths; anything else is rejected with a reason.
    /// `Arc<Mutex<..>>` keeps `SyncConfig: Clone` — `Receiver` alone is
    /// `!Clone` and `!Sync`.
    pub control: Option<std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<ControlMsg>>>>,
}

/// A live knob edit on the control channel — applies at the next sync
/// tick, journaled as `config_changed`/`config_rejected`.
#[derive(Debug)]
pub enum ControlMsg {
    /// `config describe` path + the new value as JSON.
    Set {
        path: String,
        value: serde_json::Value,
    },
}

/// Mutable copies of the tuple knobs — a live edit rewrites one member
/// and re-applies the whole setter.
struct LiveKnobs {
    relay_tx: (String, bool, bool, u64, bool, u32),
    relay_block: (bool, bool, bool, String, String),
    extrapool: avila_core::ExtrapoolConfig,
    mining: (Option<usize>, i64, Option<usize>),
    datacarrier_bytes: Option<usize>,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            connect: Vec::new(),
            target_height: 100,
            max_peers: avila_p2p::manager::DEFAULT_MAX_PEERS,
            timeout: Duration::from_secs(120),
            proxy: None,
            asmap_path: None,
            cell_bytes: 0,
            data_dir: None,
            dbcache: None,
            cancel: None,
            persist: false,
            prune_bytes: None,
            txindex: false,
            blockfilterindex: false,
            peerblockfilters: false,
            maxmempool_bytes: None,
            v2transport: true,
            listen: None,
            electrum: None,
            utreexo: false,
            utreexo_bridge: false,
            flat_utxo_bytes: None,
            status: None,
            queries: None,
            waiters: None,
            preview_next_block: false,
            require_standard: true,
            min_relay_fee: avila_mempool::DEFAULT_MIN_RELAY_FEE,
            datacarrier_bytes: Some(avila_mempool::policy::MAX_OP_RETURN_RELAY),
            permit_bare_multisig: avila_mempool::policy::DEFAULT_PERMIT_BAREMULTISIG,
            dust_relay_fee: avila_mempool::policy::DUST_RELAY_TX_FEE,
            mempool_expiry_secs: avila_mempool::DEFAULT_MEMPOOL_EXPIRY_SECS,
            stem_relay: true,
            max_in_transit: avila_p2p::manager::MAX_BLOCKS_IN_TRANSIT_TOTAL,
            dns_seeds: true,
            peer_accept_hooks: Vec::new(),
            tx_admit_hooks: Vec::new(),
            tx_announce_hooks: Vec::new(),
            extrapool_admit_hooks: Vec::new(),
            extrapool_promote_hooks: Vec::new(),
            deny_pairs: Vec::new(),
            private_submissions: false,
            tx_serve_hooks: Vec::new(),
            mine_extrapool: false,
            block_serve_hooks: Vec::new(),
            template_build_hooks: Vec::new(),
            blocks_only: false,
            relay_block: (true, true, true, String::new(), "full".to_string()),
            relay_tx: ("all".to_string(), true, false, 0, true, 60),
            mining_budgets: (None, 0, None),
            shadow_profiles: vec!["strict".to_string()],
            extrapool: avila_core::ExtrapoolConfig::default(),
            ban_time: avila_p2p::banman::DEFAULT_BANTIME,
            risks: Vec::new(),
            control: None,
        }
    }
}

/// What the node is doing right now — published from the first moment
/// of `run`, so a consumer can always answer "which phase, and how far
/// through it" instead of inferring life from a frozen tip counter.
/// The startup variants carry live counters; the network variants are
/// disambiguated by `peers`/`in_flight` on the same snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    /// Process up; opening/indexing the block store.
    #[default]
    Opening,
    /// Reinserting persisted headers into the in-memory tree.
    RestoringHeaders { done: u64, total: u64 },
    /// Re-verifying the persisted active-chain index.
    VerifyingChain { done: u64, total: u64 },
    /// Reconciling the coins backend with the snapshot tip.
    ReconcilingBackend,
    /// Reconnecting stored-but-unconnected bodies — `tip` is the live
    /// connected height so progress is visible per block.
    ReplayingBodies { done: u64, total: u64, tip: u32 },
    /// Startup complete, sync loop running, no peers yet.
    FindingPeers,
    /// Peers connected; headers/blocks flowing.
    Syncing,
}

/// A snapshot of sync progress, published on every tick and at every
/// startup-phase milestone.
#[derive(Clone, Debug)]
pub struct SyncProgress {
    /// The node's current phase — see [`Phase`]. A consumer must never
    /// infer the phase from counters; this field is the source of truth.
    pub phase: Phase,
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
    /// Utreexo shadow-accumulator height (`--utreexo`); `None` when the
    /// consumer isn't enabled.
    pub utreexo_height: Option<u32>,
    /// The last few connected blocks `(height, hash)` — newest last —
    /// for displays that render the chain itself.
    pub recent: Vec<(u32, avila_consensus::hash::BlockHash)>,
    /// Per-peer views — what each peer claims vs. what it has served.
    pub peer_details: Vec<avila_p2p::manager::PeerSnapshot>,
    /// Pooled transactions, parked orphans, and the fee estimate for
    /// ~6-block confirmation in sat/kvB (`None` = insufficient data).
    pub mempool: (usize, usize, Option<i64>),
    /// Seconds since this run started — the daemon's `uptime`.
    pub elapsed_secs: u64,
    /// What the node has actually verified — connected vs. assumed
    /// coverage per the typed report (`getvalidationreport`).
    pub validation: avila_consensus::chainstate::ValidationReport,
    /// Configured block-store prune budget — `Some` means the node
    /// runs in prune mode (`pruneblockchain` is meaningful).
    pub prune_bytes: Option<u64>,
    /// The SOCKS5 proxy, when configured — the RPC thread needs to
    /// know this WITHOUT a chain query so `addnode`-on-a-hostname can
    /// decide whether local DNS resolution is safe (audit P2P-13:
    /// under a proxy the name must resolve remotely, so the eager
    /// `to_socket_addrs` on the RPC thread would itself be the leak).
    pub proxy: Option<std::net::SocketAddr>,
    /// Work and time along the best header chain (see [`ChainProfile`]).
    pub profile: std::sync::Arc<ChainProfile>,
    /// The block the mempool would produce next; `None` unless
    /// [`SyncConfig::preview_next_block`] is set and the pool has
    /// transactions.
    pub next_block: Option<std::sync::Arc<NextBlock>>,
    /// Buffered headers in the leader's presync — the tree tip stays
    /// put while the anti-DoS check runs, so during early IBD this is
    /// the only honest progress counter (0 = none buffered).
    pub headers_buffered: u32,
    /// Eclipse indicators of the latest check (queue #12) —
    /// advisory, re-evaluated every 30 seconds; empty when nothing
    /// looks wrong, so a cleared condition clears here too.
    pub eclipse: Vec<EclipseSignal>,
    /// Estimated seconds to connect the remaining chain to the header
    /// tip — the era-aware pace model's central integration, `None`
    /// until the model has warmed up (callers fall back to a flat-rate
    /// guess).
    pub eta_secs: Option<u64>,
    /// The model's optimistic bound — every remaining block at the
    /// measured median era's cost. `Some` exactly when `eta_secs` is.
    pub eta_lo_secs: Option<u64>,
    /// The model's pessimistic bound — every remaining block priced at
    /// the dense-era ceiling.
    pub eta_hi_secs: Option<u64>,
}

impl SyncProgress {
    /// The pre-chainstate snapshot: every counter zeroed, `phase`
    /// carrying all the meaning. Published at process start and on
    /// each startup milestone so a consumer never has to infer life
    /// from a frozen tip.
    fn starting(cfg: &SyncConfig) -> Self {
        Self {
            phase: Phase::Opening,
            peers: 0,
            connected_height: 0,
            header_height: 0,
            in_flight: 0,
            established_total: 0,
            disconnects: 0,
            utreexo_height: None,
            recent: Vec::new(),
            peer_details: Vec::new(),
            mempool: (0, 0, None),
            elapsed_secs: 0,
            validation: avila_consensus::chainstate::ValidationReport {
                connected_height: 0,
                header_height: 0,
                snapshot: None,
                verified_fraction: 0.0,
            },
            prune_bytes: cfg.prune_bytes,
            proxy: cfg.proxy,
            profile: std::sync::Arc::new(ChainProfile::default()),
            next_block: None,
            headers_buffered: 0,
            eclipse: Vec::new(),
            eta_secs: None,
            eta_lo_secs: None,
            eta_hi_secs: None,
        }
    }
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
    /// Invalid option combination — Core's `InitError` text.
    #[error("{0}")]
    Config(String),
    /// A `loadtxoutset` snapshot's background validation failed —
    /// either a stored body refused to replay or the recomputed UTXO
    /// hash disagreed with the chainparams value (a dishonest
    /// snapshot; Core reports this as a fatal error).
    #[error("snapshot background validation failed: {0}")]
    SnapshotValidation(#[from] avila_consensus::connect::ConnectError),
}

fn unix_now() -> u32 {
    // `GetTime`: honors `setmocktime` so acceptance and scheduler
    // timestamps stay on the mocked clock, like Core.
    crate::time::time() as u32
}

/// Best-effort text for a `catch_unwind` payload — `panic!`'s two
/// common shapes (`&'static str`, `String`); anything else (a custom
/// payload type) falls back to a fixed message rather than failing.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// Runs headers-first sync until `cfg.target_height` connects or
/// `cfg.timeout` elapses. `progress` is invoked after each tick with a
/// live snapshot.
/// Process sandboxing — Linux `PR_SET_NO_NEW_PRIVS`: the process and
/// anything it could ever spawn are barred from privilege escalation
/// via setuid binaries or file capabilities. A wire-parser compromise
/// lands in a process that cannot escalate. Non-Linux: no-op.
fn sandbox_self() {
    #[cfg(target_os = "linux")]
    if let Err(e) = prctl::set_no_new_privileges(true) {
        eprintln!("sandbox: no_new_privs failed ({e:?}) — continuing unsandboxed");
    }
}

/// How often (in newly connected blocks) the self-audit samples the
/// stored chain — every ~2 weeks of mainnet history, or a cheap
/// interval during IBD.
const AUDIT_INTERVAL: u32 = 2016;

/// How often [`SyncProgress::eclipse`] is re-evaluated — the manager's
/// own advisory check runs about once a minute; a display can afford a
/// little more.
const ECLIPSE_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// How often [`SyncConfig::preview_next_block`] rebuilds
/// [`SyncProgress::next_block`] — `build_template`'s package selection
/// isn't free, so a busy mempool doesn't get re-summarized every tick.
/// Measured on the wall clock ([`Instant`]), not the mockable clock:
/// this throttle is a UI cadence, not a consensus- or protocol-visible
/// timestamp.
const NEXT_BLOCK_REBUILD_INTERVAL: Duration = Duration::from_secs(10);

/// Re-verify `n` random connected blocks' internal proofs; returns the
/// failure count. Heights are sampled by a seeded xorshift — the audit
/// must not be adversarially predictable or an attacker could corrupt
/// only un-sampled regions.
fn audit_sample(cs: &Chainstate, n: usize, seed: u64) -> usize {
    let tip = cs.chain().len() as u32;
    if tip == 0 {
        return 0;
    }
    let mut rng = seed ^ 0x9E3779B97F4A7C15;
    let mut bad = 0;
    for _ in 0..n {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let h = (rng % u64::from(tip)) as u32;
        if let Some(hash) = cs.chain().get(h as usize).copied()
            // A pruned body is absent by policy, not by rot — only
            // real audit failures (decode/merkle/witness) count.
            && cs.body_stored(&hash)
            && cs.audit_block(&hash).is_err()
        {
            bad += 1;
        }
    }
    bad
}

pub fn run(
    params: &Params,
    cfg: &SyncConfig,
    progress: impl FnMut(&SyncProgress) + Send + 'static,
) -> Result<SyncReport, SyncError> {
    // Process-level sandboxing (queue #11): `no_new_privs` before any
    // network work — a compromised process can never gain privileges
    // through execve of a setuid/file-capability binary. The node
    // never execve()s anything, so this is free defense-in-depth.
    // Finer-grained seccomp/Landlock filtering stays open.
    sandbox_self();
    // One shared publisher for the whole run — startup phases and the
    // tick loop report through the same path, so a consumer always sees
    // the CURRENT phase rather than a stale counter. `started_epoch`
    // hasn't been stamped yet at open; uptime starts at 0 regardless.
    let progress = std::sync::Arc::new(std::sync::Mutex::new(progress));
    let live = std::sync::Arc::new(std::sync::Mutex::new(SyncProgress::starting(cfg)));
    let publish = {
        let progress = std::sync::Arc::clone(&progress);
        let live = std::sync::Arc::clone(&live);
        let status = cfg.status.clone();
        move |phase: Phase| {
            let snap = {
                let Ok(mut s) = live.lock() else { return };
                s.phase = phase;
                s.clone()
            };
            if let Some(status) = &status
                && let Ok(mut w) = status.write()
            {
                *w = snap.clone();
            }
            if let Ok(mut p) = progress.lock() {
                p(&snap);
            }
        }
    };
    publish(Phase::Opening);
    let sink = {
        let publish = publish.clone();
        Box::new(move |ev: avila_consensus::chainstate::ProgressEvent| {
            let phase = match ev {
                avila_consensus::chainstate::ProgressEvent::StoreIndexed { .. } => Phase::Opening,
                avila_consensus::chainstate::ProgressEvent::RestoreHeaders { done, total } => {
                    Phase::RestoringHeaders {
                        done: done as u64,
                        total: total as u64,
                    }
                }
                avila_consensus::chainstate::ProgressEvent::ChainVerify { done, total } => {
                    Phase::VerifyingChain {
                        done: done as u64,
                        total: total as u64,
                    }
                }
                avila_consensus::chainstate::ProgressEvent::ReconcileBackend { .. } => {
                    Phase::ReconcilingBackend
                }
                avila_consensus::chainstate::ProgressEvent::ReplayBodies { done, total, tip } => {
                    Phase::ReplayingBodies {
                        done: done as u64,
                        total: total as u64,
                        tip,
                    }
                }
            };
            publish(phase);
        }) as Box<dyn FnMut(avila_consensus::chainstate::ProgressEvent) + Send>
    };
    let mut cs = match &cfg.data_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(SyncError::Store)?;
            let dbcache = cfg
                .dbcache
                .unwrap_or(avila_consensus::connect::DEFAULT_CACHE_BUDGET);
            Chainstate::with_store_coinsdb_progress(dir, params, unix_now(), dbcache, Some(sink))
                .map_err(SyncError::Store)?
        }
        None => Chainstate::new(params),
    };
    if let Some(cap) = cfg.flat_utxo_bytes {
        if cs.enable_flat_utxo(cap) {
            eprintln!("flat-utxo: enabled (cap {} bytes)", cap);
        } else {
            eprintln!(
                "flat-utxo: refused by cap {} bytes — staying on disk path",
                cap
            );
        }
    }
    if cfg.txindex {
        cs.enable_txindex(cfg.data_dir.as_deref())
            .map_err(SyncError::Store)?;
    }
    if cfg.blockfilterindex {
        cs.enable_blockfilterindex(cfg.data_dir.as_deref())
            .map_err(SyncError::Store)?;
    }
    // Core's InitError: "-peerblockfilters without -blockfilterindex".
    if cfg.peerblockfilters && !cfg.blockfilterindex {
        return Err(SyncError::Config(
            "Cannot set -peerblockfilters without -blockfilterindex.".into(),
        ));
    }
    if cfg.electrum.is_some() {
        cs.enable_scripthashindex(cfg.data_dir.as_deref())
            .map_err(SyncError::Store)?;
    }
    // Script checks overlap the next block's serial phase — Core's
    // `CCheckQueue` behavior. On sighash-dense eras (2016+) this is
    // worth ~2-4× on the connect critical path; receipts still only
    // publish after the check actually passes.
    cs.enable_speculative_connect();
    if let Some(dir) = &cfg.data_dir {
        if cfg.utreexo_bridge {
            cs.enable_proof_bridge(dir).map_err(SyncError::Store)?;
        }
        if cfg.utreexo {
            cs.enable_utreexo_shadow(dir).map_err(SyncError::Store)?;
        }
    } else if cfg.utreexo || cfg.utreexo_bridge {
        return Err(SyncError::Config(
            "-utreexo/-utreexo-bridge require a data directory".into(),
        ));
    }
    let resumed_height = cs.chain().len() as u32 - 1;
    // Era-aware ETA model — learns cost-vs-bytes as blocks connect.
    let mut pace = PaceModel::new(resumed_height);
    // `state.dat` checkpoint cadence — blocks between flushes during
    // sync. The value bounds post-crash replay depth, not correctness.
    let mut last_flush = resumed_height;
    let mut last_audit = resumed_height;
    // SwiftSync transient window: holds the coins cache unflushed
    // while `swift_hold` is set; released once the connected height
    // reaches the header tip (IBD complete). Tracking continues —
    // the aggregate stays live for emit/verify.
    let mut swift_released = cs.swiftsync_agg().is_none();
    let mut audit_failures = 0usize;
    let mut mgr = PeerManager::new(cfg.max_peers);
    mgr.set_proxy(cfg.proxy);
    mgr.set_cell_bytes(cfg.cell_bytes);
    if let Some(path) = &cfg.asmap_path {
        match avila_p2p::asmap::AsMap::load_file(path) {
            Ok((map, skipped)) => {
                println!(
                    "ASMap loaded: {} prefixes{}",
                    map.len(),
                    if skipped > 0 {
                        format!(" ({skipped} malformed lines skipped)")
                    } else {
                        String::new()
                    }
                );
                mgr.set_asmap(map);
            }
            Err(e) => eprintln!("asmap: cannot read {}: {e} — bucketing off", path.display()),
        }
    }
    // The whole p2p time domain — dial-path ban checks, version
    // `timestamp`s, conntime/lastsend/lastrecv and the last_* peer
    // fields — reads the node clock, so `setmocktime` shifts them too.
    mgr.set_clock(crate::time::time);
    mgr.set_v2transport(cfg.v2transport);
    mgr.set_utxproof_consumer(cfg.utreexo);
    // The index we just enabled is what makes BIP157 serving
    // legitimate — advertise NODE_COMPACT_FILTERS only then.
    mgr.set_serve_filters(cfg.blockfilterindex && cfg.peerblockfilters);
    if let Some(b) = cfg.maxmempool_bytes {
        mgr.set_max_mempool_bytes(b);
    }
    // Local relay policy — every knob is config/flag-reachable per
    // docs/DECISION_REGISTRY.md; none of it touches consensus.
    {
        let mp = mgr.mempool();
        mp.set_require_standard(cfg.require_standard);
        mp.set_min_relay_fee(cfg.min_relay_fee);
        mp.set_max_datacarrier_bytes(cfg.datacarrier_bytes);
        mp.set_permit_bare_multisig(cfg.permit_bare_multisig);
        mp.set_dust_relay_fee(cfg.dust_relay_fee);
        mp.set_mempool_expiry_secs(cfg.mempool_expiry_secs);
        // `policy.shadow` — names were validated at load; a name that
        // fails here anyway means the preset table drifted from the
        // validator, which is a bug, not config.
        let profiles: Vec<(String, avila_mempool::policy::ShadowRules)> = cfg
            .shadow_profiles
            .iter()
            .map(|n| {
                (
                    n.clone(),
                    avila_mempool::policy::shadow_preset(n)
                        .unwrap_or(avila_mempool::policy::SHADOW_STRICT),
                )
            })
            .collect();
        mp.set_shadow_profiles(profiles);
        // `[extrapool]` — observation bounds for policy rejects.
        mp.configure_extrapool(
            cfg.extrapool.observe,
            cfg.extrapool.max_entries,
            cfg.extrapool.max_bytes,
            cfg.extrapool.expiry_secs,
        );
        mp.configure_extrapool_detail(cfg.extrapool.caps.clone(), cfg.extrapool.relay != "never");
    }
    mgr.set_stem_relay(cfg.stem_relay);
    mgr.set_deny_pairs(cfg.deny_pairs.clone());
    mgr.set_private_submissions(cfg.private_submissions);
    mgr.mempool().set_mine_extrapool(cfg.mine_extrapool);
    // `relay.block.*` / `net.blocks_only` / `relay.tx.*` / `mining.*`.
    mgr.set_compact_relay(
        cfg.relay_block.0,
        cfg.relay_block.1,
        cfg.relay_block.2,
        &cfg.relay_block.3,
    );
    mgr.set_blocks_only(cfg.blocks_only);
    mgr.set_tx_relay(
        &cfg.relay_tx.0,
        cfg.relay_tx.1,
        cfg.relay_tx.2,
        cfg.relay_tx.3,
        cfg.relay_tx.4,
        cfg.relay_tx.5,
    );
    mgr.mempool().set_block_min_fee(cfg.mining_budgets.1);
    if let Some(w) = cfg.mining_budgets.0 {
        mgr.mempool().set_block_max_weight(w);
    }
    if let Some(w) = cfg.mining_budgets.2 {
        mgr.mempool().set_block_reserved_weight(w);
    }
    // `relay.block.serve` mode rides in even without a hook — the
    // verdict is layered on below when `block.serve` is configured.
    mgr.set_block_serve(&cfg.relay_block.4, None);
    mgr.set_max_in_flight_total(cfg.max_in_transit);
    mgr.set_default_ban_time(cfg.ban_time);
    // Live knob state — `cfg` is borrowed; tuple members mutate here
    // and re-apply whole through the same setters.
    let mut knobs = LiveKnobs {
        relay_tx: cfg.relay_tx.clone(),
        relay_block: cfg.relay_block.clone(),
        extrapool: cfg.extrapool.clone(),
        mining: cfg.mining_budgets,
        datacarrier_bytes: cfg.datacarrier_bytes,
    };
    // The append-only event plane (docs/DECISION_REGISTRY.md — the
    // stream law): one NDJSON line per decision/transition in the
    // network data dir; `avila-node events --follow` tails it. An
    // unwritable sink demotes events to stderr-only — diagnostics,
    // not a startup failure.
    let mut stream = cfg
        .data_dir
        .as_deref()
        .map(crate::events::EventStream::open)
        .transpose()
        .unwrap_or_else(|e| {
            eprintln!("event stream: cannot open events.ndjson ({e}) — running without it");
            None
        });
    let mut stream_warned = false;
    let mut emit =
        |stream: &mut Option<crate::events::EventStream>, kind: &str, fields: serde_json::Value| {
            if let Some(s) = stream
                && let Err(e) = s.emit(kind, fields)
                && !stream_warned
            {
                stream_warned = true;
                eprintln!("event stream write failed ({e}) — further write errors suppressed");
            }
        };
    emit(&mut stream, "run_started", serde_json::json!({}));
    // Risk review — warn once per finding set: the ack file holds the
    // literal lines acknowledged, so only *new* postures print and emit
    // `config_risk` events. Acknowledged risks stay silent; a config
    // change that introduces a new one re-warns.
    if !cfg.risks.is_empty()
        && let Some(dir) = &cfg.data_dir
    {
        let acked = crate::config::risk_ack_set(dir);
        let fresh = crate::config::unacknowledged(&cfg.risks, &acked);
        if !fresh.is_empty() {
            eprintln!(
                "config risk review — {} unacknowledged finding{}:",
                fresh.len(),
                if fresh.len() == 1 { "" } else { "s" }
            );
            for r in &fresh {
                eprintln!("  {}: {}", r.path, r.message);
            }
            eprintln!("acknowledge: avila-node config accept-risks");
            for r in &fresh {
                emit(
                    &mut stream,
                    "config_risk",
                    serde_json::json!({ "path": r.path, "message": r.message }),
                );
            }
        }
    }
    // Bounded: a flooding hot path (tx.admit per-tx verdicts) can't
    // grow memory unboundedly — drops land on a counter surfaced as a
    // `hook_events_dropped` event.
    let (hook_events_tx, hook_events_rx) = std::sync::mpsc::sync_channel::<serde_json::Value>(4096);
    let hook_events_dropped = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut hook_drop_seen = 0u64;
    if !cfg.peer_accept_hooks.is_empty() {
        use avila_core::OnDefault;
        // Spawn once, restart-supervised thereafter. A helper that
        // cannot spawn at all becomes a tombstone answering its
        // on_timeout default — the registry's narrowing rule means a
        // dead helper degrades to the point's declared posture, never
        // to a silent policy hole.
        let mut helpers: Vec<(crate::hooks::HookSpec, Option<crate::hooks::VerdictHelper>)> = cfg
            .peer_accept_hooks
            .iter()
            .map(
                |spec| match crate::hooks::VerdictHelper::spawn(spec.clone()) {
                    Ok(h) => (spec.clone(), Some(h)),
                    Err(e) => {
                        eprintln!(
                            "hooks.peer_accept {}: spawn failed ({e}) — \
                             answering {:?} for every peer",
                            spec.program.display(),
                            spec.on_timeout
                        );
                        emit(
                            &mut stream,
                            "hook_spawn_failed",
                            serde_json::json!({
                                "point": "peer.accept",
                                "program": spec.program.display().to_string(),
                                "on_timeout": format!("{:?}", spec.on_timeout),
                            }),
                        );
                        (spec.clone(), None)
                    }
                },
            )
            .collect();
        let hook_tx = hook_events_tx.clone();
        let dropped = hook_events_dropped.clone();
        mgr.set_inbound_verdict(Some(Box::new(move |facts| {
            let remote = facts.remote.to_string();
            let facts = serde_json::json!({
                "remote": remote.clone(),
                "services": facts.services,
                "protocol_version": facts.protocol_version,
                "user_agent": facts.user_agent,
                "start_height": facts.start_height,
                "relay": facts.relay,
                "wtxid_relay": facts.wtxid_relay,
                "addrv2": facts.addrv2,
                "transport": facts.transport,
            });
            // Conjunction — any helper's reject kills the connection.
            helpers.iter_mut().all(|(spec, h)| {
                let verdict = match h {
                    Some(h) => h.verdict("peer.accept", &facts),
                    None => match spec.on_timeout {
                        OnDefault::Accept => crate::hooks::Verdict::Accept,
                        OnDefault::Reject => crate::hooks::Verdict::Reject,
                    },
                };
                let admit = match verdict {
                    crate::hooks::Verdict::Accept => true,
                    crate::hooks::Verdict::Reject => false,
                    crate::hooks::Verdict::Defer => {
                        matches!(spec.on_defer, OnDefault::Accept)
                    }
                };
                if hook_tx
                    .try_send(serde_json::json!({
                        "kind": "hook_verdict",
                        "point": "peer.accept",
                        "helper": spec.program.display().to_string(),
                        "verdict": match verdict {
                            crate::hooks::Verdict::Accept => "accept",
                            crate::hooks::Verdict::Reject => "reject",
                            crate::hooks::Verdict::Defer => "defer",
                        },
                        "remote": remote.as_str(),
                        "admit": admit,
                    }))
                    .is_err()
                {
                    dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                admit
            })
        })));
    }
    if !cfg.tx_admit_hooks.is_empty() {
        use avila_core::OnDefault;
        // Same spawn/tombstone semantics as peer.accept — a dead helper
        // degrades to its on_timeout posture. This is the hot path:
        // admission throughput is bounded by helper latency.
        let mut helpers: Vec<(crate::hooks::HookSpec, Option<crate::hooks::VerdictHelper>)> = cfg
            .tx_admit_hooks
            .iter()
            .map(
                |spec| match crate::hooks::VerdictHelper::spawn(spec.clone()) {
                    Ok(h) => (spec.clone(), Some(h)),
                    Err(e) => {
                        eprintln!(
                            "hooks.tx_admit {}: spawn failed ({e}) — \
                             answering {:?} for every tx",
                            spec.program.display(),
                            spec.on_timeout
                        );
                        emit(
                            &mut stream,
                            "hook_spawn_failed",
                            serde_json::json!({
                                "point": "tx.admit",
                                "program": spec.program.display().to_string(),
                                "on_timeout": format!("{:?}", spec.on_timeout),
                            }),
                        );
                        (spec.clone(), None)
                    }
                },
            )
            .collect();
        let hook_tx = hook_events_tx.clone();
        let dropped = hook_events_dropped.clone();
        mgr.mempool().set_admit_hook(Some(Box::new(
            move |facts: &avila_mempool::TxAdmitFacts| {
                let txid = facts.txid.to_string();
                let facts = serde_json::json!({
                    "txid": txid.clone(),
                    "wtxid": facts.wtxid.to_string(),
                    "version": facts.version,
                    "lock_time": facts.lock_time,
                    "vbytes": facts.vbytes,
                    "weight": facts.weight,
                    "inputs": facts.inputs,
                    "outputs": facts.outputs,
                    "output_value": facts.output_value,
                    "fee": facts.fee,
                    "feerate": facts.feerate,
                    "rbf": facts.rbf,
                    "has_witness": facts.has_witness,
                    "spk_types": facts.spk_types,
                });
                helpers.iter_mut().all(|(spec, h)| {
                    let verdict = match h {
                        Some(h) => h.verdict("tx.admit", &facts),
                        None => match spec.on_timeout {
                            OnDefault::Accept => crate::hooks::Verdict::Accept,
                            OnDefault::Reject => crate::hooks::Verdict::Reject,
                        },
                    };
                    let admit = match verdict {
                        crate::hooks::Verdict::Accept => true,
                        crate::hooks::Verdict::Reject => false,
                        crate::hooks::Verdict::Defer => {
                            matches!(spec.on_defer, OnDefault::Accept)
                        }
                    };
                    if hook_tx
                        .try_send(serde_json::json!({
                            "kind": "hook_verdict",
                            "point": "tx.admit",
                            "helper": spec.program.display().to_string(),
                            "verdict": match verdict {
                                crate::hooks::Verdict::Accept => "accept",
                                crate::hooks::Verdict::Reject => "reject",
                                crate::hooks::Verdict::Defer => "defer",
                            },
                            "txid": txid.as_str(),
                            "admit": admit,
                        }))
                        .is_err()
                    {
                        dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    admit
                })
            },
        )));
    }
    if !cfg.tx_announce_hooks.is_empty() {
        use avila_core::OnDefault;
        // The hottest hook path: one verdict per (tx, target link) —
        // announce rate is bounded by helper latency × peer count.
        let mut helpers: Vec<(crate::hooks::HookSpec, Option<crate::hooks::VerdictHelper>)> = cfg
            .tx_announce_hooks
            .iter()
            .map(
                |spec| match crate::hooks::VerdictHelper::spawn(spec.clone()) {
                    Ok(h) => (spec.clone(), Some(h)),
                    Err(e) => {
                        eprintln!(
                            "hooks.tx_announce {}: spawn failed ({e}) — \
                             answering {:?} for every announce",
                            spec.program.display(),
                            spec.on_timeout
                        );
                        emit(
                            &mut stream,
                            "hook_spawn_failed",
                            serde_json::json!({
                                "point": "tx.announce",
                                "program": spec.program.display().to_string(),
                                "on_timeout": format!("{:?}", spec.on_timeout),
                            }),
                        );
                        (spec.clone(), None)
                    }
                },
            )
            .collect();
        let hook_tx = hook_events_tx.clone();
        let dropped = hook_events_dropped.clone();
        mgr.set_tx_announce_verdict(Some(Box::new(
            move |facts: &avila_p2p::manager::TxAnnounceFacts| {
                let txid = facts.txid.to_string();
                let peer = facts.peer;
                let facts = serde_json::json!({
                    "txid": txid.clone(),
                    "wtxid": facts.wtxid.to_string(),
                    "source": facts.source,
                    "source_peer": facts.source_peer,
                    "peer": peer,
                    "peer_addr": facts.peer_addr,
                    "peer_inbound": facts.peer_inbound,
                    "peer_user_agent": facts.peer_user_agent,
                });
                helpers.iter_mut().all(|(spec, h)| {
                    let verdict = match h {
                        Some(h) => h.verdict("tx.announce", &facts),
                        None => match spec.on_timeout {
                            OnDefault::Accept => crate::hooks::Verdict::Accept,
                            OnDefault::Reject => crate::hooks::Verdict::Reject,
                        },
                    };
                    let admit = match verdict {
                        crate::hooks::Verdict::Accept => true,
                        crate::hooks::Verdict::Reject => false,
                        crate::hooks::Verdict::Defer => {
                            matches!(spec.on_defer, OnDefault::Accept)
                        }
                    };
                    if hook_tx
                        .try_send(serde_json::json!({
                            "kind": "hook_verdict",
                            "point": "tx.announce",
                            "helper": spec.program.display().to_string(),
                            "verdict": match verdict {
                                crate::hooks::Verdict::Accept => "accept",
                                crate::hooks::Verdict::Reject => "reject",
                                crate::hooks::Verdict::Defer => "defer",
                            },
                            "txid": txid.as_str(),
                            "peer": peer,
                            "admit": admit,
                        }))
                        .is_err()
                    {
                        dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    admit
                })
            },
        )));
    }
    if !cfg.tx_serve_hooks.is_empty() {
        use avila_core::OnDefault;
        // One consult per tx item per getdata — batch frequency makes
        // this warmer than announce but still per-request bounded.
        let mut helpers: Vec<(crate::hooks::HookSpec, Option<crate::hooks::VerdictHelper>)> = cfg
            .tx_serve_hooks
            .iter()
            .map(
                |spec| match crate::hooks::VerdictHelper::spawn(spec.clone()) {
                    Ok(h) => (spec.clone(), Some(h)),
                    Err(e) => {
                        eprintln!(
                            "hooks.tx_serve {}: spawn failed ({e}) — \
                             answering {:?} for every serve",
                            spec.program.display(),
                            spec.on_timeout
                        );
                        emit(
                            &mut stream,
                            "hook_spawn_failed",
                            serde_json::json!({
                                "point": "tx.serve",
                                "program": spec.program.display().to_string(),
                                "on_timeout": format!("{:?}", spec.on_timeout),
                            }),
                        );
                        (spec.clone(), None)
                    }
                },
            )
            .collect();
        let hook_tx = hook_events_tx.clone();
        let dropped = hook_events_dropped.clone();
        mgr.set_tx_serve_verdict(Some(Box::new(
            move |facts: &avila_p2p::manager::TxServeFacts| {
                let txid = facts.txid.to_string();
                let peer = facts.peer;
                let facts = serde_json::json!({
                    "txid": txid.clone(),
                    "wtxid": facts.wtxid.to_string(),
                    "peer": peer,
                    "peer_addr": facts.peer_addr,
                    "peer_inbound": facts.peer_inbound,
                    "peer_user_agent": facts.peer_user_agent,
                });
                helpers.iter_mut().all(|(spec, h)| {
                    let verdict = match h {
                        Some(h) => h.verdict("tx.serve", &facts),
                        None => match spec.on_timeout {
                            OnDefault::Accept => crate::hooks::Verdict::Accept,
                            OnDefault::Reject => crate::hooks::Verdict::Reject,
                        },
                    };
                    let admit = match verdict {
                        crate::hooks::Verdict::Accept => true,
                        crate::hooks::Verdict::Reject => false,
                        crate::hooks::Verdict::Defer => {
                            matches!(spec.on_defer, OnDefault::Accept)
                        }
                    };
                    if hook_tx
                        .try_send(serde_json::json!({
                            "kind": "hook_verdict",
                            "point": "tx.serve",
                            "helper": spec.program.display().to_string(),
                            "verdict": match verdict {
                                crate::hooks::Verdict::Accept => "accept",
                                crate::hooks::Verdict::Reject => "reject",
                                crate::hooks::Verdict::Defer => "defer",
                            },
                            "txid": txid.as_str(),
                            "peer": peer,
                            "admit": admit,
                        }))
                        .is_err()
                    {
                        dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    admit
                })
            },
        )));
    }
    // `block.serve` — same conjunctive gate on the block side of
    // `getdata` (plus `getblocktxn`); facts carry the hash and peer.
    if !cfg.block_serve_hooks.is_empty() {
        use avila_core::OnDefault;
        let mut helpers: Vec<(crate::hooks::HookSpec, Option<crate::hooks::VerdictHelper>)> = cfg
            .block_serve_hooks
            .iter()
            .map(
                |spec| match crate::hooks::VerdictHelper::spawn(spec.clone()) {
                    Ok(h) => (spec.clone(), Some(h)),
                    Err(e) => {
                        eprintln!(
                            "hooks.block_serve {}: spawn failed ({e}) — \
                             answering {:?} for every serve",
                            spec.program.display(),
                            spec.on_timeout
                        );
                        emit(
                            &mut stream,
                            "hook_spawn_failed",
                            serde_json::json!({
                                "point": "block.serve",
                                "program": spec.program.display().to_string(),
                                "on_timeout": format!("{:?}", spec.on_timeout),
                            }),
                        );
                        (spec.clone(), None)
                    }
                },
            )
            .collect();
        let hook_tx = hook_events_tx.clone();
        let dropped = hook_events_dropped.clone();
        mgr.set_block_serve(
            &cfg.relay_block.4,
            Some(Box::new(
                move |facts: &avila_p2p::manager::BlockServeFacts| {
                    let hash = facts.block_hash.to_string();
                    let peer = facts.peer;
                    let facts = serde_json::json!({
                        "block_hash": hash.clone(),
                        "peer": peer,
                        "peer_addr": facts.peer_addr,
                        "peer_inbound": facts.peer_inbound,
                        "peer_user_agent": facts.peer_user_agent,
                    });
                    helpers.iter_mut().all(|(spec, h)| {
                        let verdict = match h {
                            Some(h) => h.verdict("block.serve", &facts),
                            None => match spec.on_timeout {
                                OnDefault::Accept => crate::hooks::Verdict::Accept,
                                OnDefault::Reject => crate::hooks::Verdict::Reject,
                            },
                        };
                        let admit = match verdict {
                            crate::hooks::Verdict::Accept => true,
                            crate::hooks::Verdict::Reject => false,
                            crate::hooks::Verdict::Defer => {
                                matches!(spec.on_defer, OnDefault::Accept)
                            }
                        };
                        if hook_tx
                            .try_send(serde_json::json!({
                                "kind": "hook_verdict",
                                "point": "block.serve",
                                "helper": spec.program.display().to_string(),
                                "verdict": match verdict {
                                    crate::hooks::Verdict::Accept => "accept",
                                    crate::hooks::Verdict::Reject => "reject",
                                    crate::hooks::Verdict::Defer => "defer",
                                },
                                "block_hash": hash.as_str(),
                                "peer": peer,
                                "admit": admit,
                            }))
                            .is_err()
                        {
                            dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        admit
                    })
                },
            )),
        );
    }
    // `template.build` — a per-template veto; the verdict sees the
    // assembled shape and can only decline it.
    if !cfg.template_build_hooks.is_empty() {
        use avila_core::OnDefault;
        let mut helpers: Vec<(crate::hooks::HookSpec, Option<crate::hooks::VerdictHelper>)> = cfg
            .template_build_hooks
            .iter()
            .map(
                |spec| match crate::hooks::VerdictHelper::spawn(spec.clone()) {
                    Ok(h) => (spec.clone(), Some(h)),
                    Err(e) => {
                        eprintln!(
                            "hooks.template_build {}: spawn failed ({e}) — \
                             answering {:?} for every build",
                            spec.program.display(),
                            spec.on_timeout
                        );
                        emit(
                            &mut stream,
                            "hook_spawn_failed",
                            serde_json::json!({
                                "point": "template.build",
                                "program": spec.program.display().to_string(),
                                "on_timeout": format!("{:?}", spec.on_timeout),
                            }),
                        );
                        (spec.clone(), None)
                    }
                },
            )
            .collect();
        let hook_tx = hook_events_tx.clone();
        let dropped = hook_events_dropped.clone();
        mgr.mempool().set_template_hook(Some(Box::new(
            move |height, tx_count, weight, sigops, fees| {
                let facts = serde_json::json!({
                    "height": height,
                    "tx_count": tx_count,
                    "weight": weight,
                    "sigops": sigops,
                    "fees": fees,
                });
                helpers.iter_mut().all(|(spec, h)| {
                    let verdict = match h {
                        Some(h) => h.verdict("template.build", &facts),
                        None => match spec.on_timeout {
                            OnDefault::Accept => crate::hooks::Verdict::Accept,
                            OnDefault::Reject => crate::hooks::Verdict::Reject,
                        },
                    };
                    let admit = match verdict {
                        crate::hooks::Verdict::Accept => true,
                        crate::hooks::Verdict::Reject => false,
                        crate::hooks::Verdict::Defer => {
                            matches!(spec.on_defer, OnDefault::Accept)
                        }
                    };
                    if hook_tx
                        .try_send(serde_json::json!({
                            "kind": "hook_verdict",
                            "point": "template.build",
                            "helper": spec.program.display().to_string(),
                            "verdict": match verdict {
                                crate::hooks::Verdict::Accept => "accept",
                                crate::hooks::Verdict::Reject => "reject",
                                crate::hooks::Verdict::Defer => "defer",
                            },
                            "height": height,
                            "tx_count": tx_count,
                            "admit": admit,
                        }))
                        .is_err()
                    {
                        dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    admit
                })
            },
        )));
    }
    // `extrapool.admit` / `extrapool.promote` — the observation pool's
    // own gates. Facts are (txid, reason); a `reject` drops the record
    // or keeps the entry respectively. Same spawn/tombstone semantics.
    for (point, specs) in [
        ("extrapool.admit", &cfg.extrapool_admit_hooks),
        ("extrapool.promote", &cfg.extrapool_promote_hooks),
    ] {
        if specs.is_empty() {
            continue;
        }
        use avila_core::OnDefault;
        let mut helpers: Vec<(crate::hooks::HookSpec, Option<crate::hooks::VerdictHelper>)> = specs
            .iter()
            .map(
                |spec| match crate::hooks::VerdictHelper::spawn(spec.clone()) {
                    Ok(h) => (spec.clone(), Some(h)),
                    Err(e) => {
                        eprintln!(
                            "hooks.{} {}: spawn failed ({e}) — \
                             answering {:?} for every call",
                            point.replace('.', "_"),
                            spec.program.display(),
                            spec.on_timeout
                        );
                        emit(
                            &mut stream,
                            "hook_spawn_failed",
                            serde_json::json!({
                                "point": point,
                                "program": spec.program.display().to_string(),
                                "on_timeout": format!("{:?}", spec.on_timeout),
                            }),
                        );
                        (spec.clone(), None)
                    }
                },
            )
            .collect();
        let hook_tx = hook_events_tx.clone();
        let dropped = hook_events_dropped.clone();
        let point_name: &'static str = point;
        let judge = move |txid: &avila_consensus::hash::Txid, reason: &str| {
            let txid_s = txid.to_string();
            let facts = serde_json::json!({
                "txid": txid_s.clone(),
                "reason": reason,
            });
            helpers.iter_mut().all(|(spec, h)| {
                let verdict = match h {
                    Some(h) => h.verdict(point_name, &facts),
                    None => match spec.on_timeout {
                        OnDefault::Accept => crate::hooks::Verdict::Accept,
                        OnDefault::Reject => crate::hooks::Verdict::Reject,
                    },
                };
                let admit = match verdict {
                    crate::hooks::Verdict::Accept => true,
                    crate::hooks::Verdict::Reject => false,
                    crate::hooks::Verdict::Defer => {
                        matches!(spec.on_defer, OnDefault::Accept)
                    }
                };
                if hook_tx
                    .try_send(serde_json::json!({
                        "kind": "hook_verdict",
                        "point": point_name,
                        "helper": spec.program.display().to_string(),
                        "verdict": match verdict {
                            crate::hooks::Verdict::Accept => "accept",
                            crate::hooks::Verdict::Reject => "reject",
                            crate::hooks::Verdict::Defer => "defer",
                        },
                        "txid": txid_s.as_str(),
                        "reason": reason,
                        "admit": admit,
                    }))
                    .is_err()
                {
                    dropped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                admit
            })
        };
        match point {
            "extrapool.admit" => {
                mgr.mempool()
                    .set_extrapool_admit_hook(Some(Box::new(judge)));
            }
            _ => {
                mgr.mempool()
                    .set_extrapool_promote_hook(Some(Box::new(judge)));
            }
        }
    }
    let started = Instant::now();
    // Core's `GetStartupTime` — wall-clock boot epoch. `uptime` reads
    // `GetTime() - GetStartupTime()`, so a pinned mock shifts it too.
    let started_epoch = crate::time::system_time();

    // peers.dat — restart keeps learned candidates; a corrupt file just
    // costs us gossip history, so load errors are ignored by design.
    if let Some(dir) = &cfg.data_dir {
        let _ = mgr.addrbook().load(&dir.join("peers.dat"), unix_now());
        // banlist.json — Core's LoadBanlist: operator bans survive
        // restarts; a corrupt file just costs the list.
        mgr.set_banlist_path(dir.join("banlist.json"), unix_now() as i64);
        // mempool.dat — Core's LoadMempool: entries re-run full
        // admission against the resumed chainstate; what fails is
        // skipped, not fatal.
        if let Ok((imported, skipped)) =
            mgr.mempool()
                .load(&dir.join("mempool.dat"), &cs, unix_now())
            && imported + skipped > 0
        {
            eprintln!("mempool.dat: imported {imported}, skipped {skipped}");
        }
        // The scheduler's first job — Core's `DumpAddrman` cadence:
        // peers.dat saves every 15 min, not just at shutdown.
        let peers_path = dir.join("peers.dat");
        mgr.schedule_every("save_peers", 15 * 60, move |m| {
            let _ = m.addrbook().save(&peers_path);
        });
    }
    // `-connect` is exclusive in Core — naming peers suppresses DNS
    // seeding entirely (and `-connect=0` yields a fully offline node).
    // Proxy mode also suppresses seeding: `resolve_seeds` is a LOCAL
    // DNS lookup, which would leak the resolver to the operator's DNS
    // even though every dial then rides the proxy — the same reason
    // Core's `-onlynet=onion` never touches DNS seeds (queue #13).
    // `net.dns_seeds` (Core's `-dnsseed=0`) is the explicit kill switch.
    let seeded = if cfg.connect.is_empty() && cfg.proxy.is_none() && cfg.dns_seeds {
        mgr.seed_from_dns(params, unix_now())
    } else {
        0
    };
    // `-listen` — the inbound side of Core's `-listen=1`: a
    // nonblocking accept each tick hands sockets to bounded handshake
    // workers; completed sessions join via `drain_inbounds`.
    let listener = match cfg.listen {
        Some(addr) => {
            let l = std::net::TcpListener::bind(addr).map_err(SyncError::Store)?;
            l.set_nonblocking(true).map_err(SyncError::Store)?;
            Some(l)
        }
        None => None,
    };
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
            None => mgr.connect(
                *addr,
                params.message_start,
                0,
                cs.chain().len() as i32,
                cfg.v2transport,
            ),
        };
        if let Ok(Some(_)) = attempted {
            dialed += 1;
        }
    }
    // `-connect` peers are persistent operator intent (Core's
    // CConnman::m_added_nodes) — not one-shot dials. Registering them
    // keeps them redialed after drops, including across
    // `setnetworkactive` off/on.
    for addr in &cfg.connect {
        mgr.add_node(addr.to_string(), false);
    }
    if !cfg.persist && mgr.is_empty() && seeded == 0 {
        return Err(SyncError::NoPeers {
            seeded,
            explicit: cfg.connect.len(),
        });
    }

    let mut established_total = 0u32;
    let mut disconnects = 0u32;
    let mut connected = 0u32;
    // (profile, reason) → last reported divergence total — the
    // `shadow_divergence` event emits only when a counter moved.
    let mut shadow_seen: std::collections::BTreeMap<(String, String), u64> =
        std::collections::BTreeMap::new();
    // Extrapool counters — same diff-the-totals emission as shadow.
    let mut extra_reason_seen: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();
    let mut extra_seen: std::collections::BTreeMap<&'static str, u64> =
        std::collections::BTreeMap::new();
    // Work/time profile of the best header chain (queue: ChainProfile) —
    // kept across ticks and refreshed incrementally; the Arc is rebuilt
    // only when the tip actually moves, so an unchanged tip costs
    // readers nothing but a refcount bump.
    let mut chain_profile = ChainProfile::default();
    let mut chain_profile_arc = std::sync::Arc::new(chain_profile.clone());
    // The next-block preview (queue: NextBlock) — GUI-only, off by
    // default; `next_block_built_at` throttles rebuilds to
    // NEXT_BLOCK_REBUILD_INTERVAL on the wall clock.
    let mut next_block: Option<std::sync::Arc<NextBlock>> = None;
    let mut next_block_built_at: Option<Instant> = None;
    // The eclipse indicators' current state for displays; the manager
    // only emits an event when something is wrong, so re-evaluate here.
    let mut eclipse: Vec<EclipseSignal> = Vec::new();
    let mut eclipse_checked_at: Option<Instant> = None;
    let cancelled = || {
        cfg.cancel
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
    };
    // Wakes every parked wait-RPC on *any* exit — clean, cancelled, or
    // the early error returns — so handlers answer the last tip rather
    // than blocking on a dead loop.
    struct WaiterShutdown<'a>(Option<&'a std::sync::Arc<crate::rpc::BlockWaiters>>);
    impl Drop for WaiterShutdown<'_> {
        fn drop(&mut self) {
            if let Some(w) = self.0 {
                w.shutdown();
            }
        }
    }
    let _waiter_shutdown = WaiterShutdown(cfg.waiters.as_ref());
    // Rescans that deferred — jobs parked until their pruned range
    // reacquires bodies.
    let mut rescans: std::collections::VecDeque<crate::rpc::DeferredQuery> =
        std::collections::VecDeque::new();

    let mut last_prune = std::time::Instant::now();
    let mut hb_at = std::time::Instant::now() - std::time::Duration::from_secs(30);
    // Interval timing: `connect_timing` is cumulative since process
    // start — the heartbeat diffs it so each line reports the actual
    // cost of the blocks connected in *this* interval, not a lifetime
    // average (audit work-order: cumulative buckets misattribute era
    // cost once the pipeline shape changes).
    let mut hb_prev_t = avila_consensus::connect::connect_timing();
    let mut hb_prev_connected = resumed_height;
    while started.elapsed() < cfg.timeout
        && connected.saturating_sub(resumed_height) < cfg.target_height
        && !cancelled()
    {
        // Nothing to talk to and nothing left to try — a bounded sync
        // fails fast rather than idling until the timeout (e.g.
        // regtest with no seeds). A persistent daemon keeps ticking:
        // Core never exits on zero peers, and `addnode` may arrive
        // over RPC at any time. While `setnetworkactive false` holds,
        // an empty peer set is the operator's intent either way.
        if !cfg.persist
            && mgr.is_empty()
            && mgr.addrbook().is_empty()
            && mgr.added_nodes().is_empty()
            && mgr.network_active()
        {
            return Err(SyncError::NoPeers {
                seeded,
                explicit: cfg.connect.len(),
            });
        }
        // Inbound accepts: hand each new socket to a handshake worker,
        // then admit whatever completed since the last tick.
        if let Some(l) = &listener {
            loop {
                match l.accept() {
                    Ok((stream, remote)) => mgr.accept_peer(
                        stream,
                        remote,
                        params.message_start,
                        0,
                        cs.chain().len() as i32,
                    ),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        mgr.drain_inbounds();
        // Live knob edits apply between ticks — never mid-dispatch —
        // and each one lands on the journal.
        if let Some(control) = &cfg.control
            && let Ok(rx) = control.lock()
        {
            while let Ok(msg) = rx.try_recv() {
                let ControlMsg::Set { path, value } = msg;
                match apply_knob(&mut mgr, &mut knobs, &path, &value) {
                    Ok(applied) => emit(
                        &mut stream,
                        "config_changed",
                        serde_json::json!({"path": path, "value": applied}),
                    ),
                    Err(reason) => emit(
                        &mut stream,
                        "config_rejected",
                        serde_json::json!({"path": path, "reason": reason}),
                    ),
                }
            }
        }
        let mut tip_moved = false;
        for event in mgr.tick_net(&mut cs, unix_now(), params.message_start, 0) {
            {
                let (kind, fields) = crate::events::net_event_json(&event);
                emit(&mut stream, kind, fields);
            }
            if matches!(event, NetEvent::TipAdvanced(_)) {
                tip_moved = true;
            }
            match event {
                NetEvent::Connected { .. } => established_total += 1,
                NetEvent::Disconnected { .. } => disconnects += 1,
                NetEvent::EclipseSuspected(signals) => {
                    eprintln!(
                        "eclipse indicators: {signals:?} — advisory only, cross-check routes"
                    );
                }
                NetEvent::ReconDivergence {
                    peer,
                    rounds,
                    their_misses,
                    our_misses,
                } => {
                    eprintln!(
                        "recon divergence: peer {peer} missed {their_misses} circulating txs \
                         over {rounds} rounds (we missed {our_misses} from them) — \
                         filtered view, advisory only"
                    );
                }
                _ => {}
            }
        }
        // Hook verdicts queue on a channel (the verdict closure runs
        // inside drain_inbounds, not the loop) — drain them into the
        // stream each tick.
        while let Ok(mut ev) = hook_events_rx.try_recv() {
            let kind = ev
                .get("kind")
                .and_then(|k| k.as_str())
                .unwrap_or("hook_verdict")
                .to_string();
            if let Some(obj) = ev.as_object_mut() {
                obj.remove("kind");
            }
            emit(&mut stream, &kind, ev);
        }
        let dropped_now = hook_events_dropped.load(std::sync::atomic::Ordering::Relaxed);
        if dropped_now > hook_drop_seen {
            hook_drop_seen = dropped_now;
            emit(
                &mut stream,
                "hook_events_dropped",
                serde_json::json!({ "total": dropped_now }),
            );
        }
        // Shadow observatory → events: diff the per-profile divergence
        // counters against what we've already reported — bounded by
        // distinct (profile, reason) pairs, so a hot divergence emits
        // once per new total rather than per tx.
        for (name, st) in &mgr.mempool().shadow_stats().profiles {
            for (reason, &n) in &st.divergent {
                let key = (name.clone(), reason.clone());
                if shadow_seen.get(&key).copied().unwrap_or(0) < n {
                    shadow_seen.insert(key, n);
                    emit(
                        &mut stream,
                        "shadow_divergence",
                        serde_json::json!({
                            "profile": name,
                            "reason": reason,
                            "total": n,
                        }),
                    );
                }
            }
        }
        // Extrapool → events: emits when a per-reason stored count or a
        // lifecycle counter moves — bounded by distinct counters, so a
        // flood of one reject kind can't spam the stream.
        {
            let extra = mgr.mempool().extrapool();
            for (reason, &n) in &extra.stats().by_reason {
                if extra_reason_seen.get(reason).copied().unwrap_or(0) < n {
                    extra_reason_seen.insert(reason.clone(), n);
                    emit(
                        &mut stream,
                        "extrapool_stored",
                        serde_json::json!({
                            "reason": reason,
                            "total": n,
                            "size": extra.len(),
                            "bytes": extra.bytes(),
                        }),
                    );
                }
            }
            for (kind, n) in [
                ("extrapool_evicted", extra.stats().evicted),
                ("extrapool_expired", extra.stats().expired),
                ("extrapool_promoted", extra.stats().promoted),
            ] {
                if extra_seen.get(kind).copied().unwrap_or(0) < n {
                    extra_seen.insert(kind, n);
                    emit(
                        &mut stream,
                        kind,
                        serde_json::json!({"total": n, "size": extra.len()}),
                    );
                }
            }
        }
        // `extrapool.relay` — newly observed entries propagate through
        // the announce gates with extrapool provenance ("outbound"
        // confines to our chosen routes, "all" fans out fully).
        for (txid, wtxid) in mgr.mempool().take_extrapool_pending() {
            mgr.announce_extrapool_tx(txid, wtxid, knobs.extrapool.relay == "outbound");
            emit(
                &mut stream,
                "extrapool_relayed",
                serde_json::json!({
                    "txid": txid.to_string(),
                    "scope": knobs.extrapool.relay.as_str(),
                }),
            );
        }
        // `extrapool.promote_on = ["tip"]` — a connected block changes
        // the fee/UTXO landscape, so re-run full admission on observed
        // entries. Bounded per tip; the promote hooks still gate.
        if tip_moved && cfg.extrapool.promote_on.iter().any(|t| t == "tip") {
            const TIP_PROMOTE_CAP: usize = 256;
            let candidates: Vec<_> = mgr
                .mempool()
                .extrapool()
                .iter()
                .map(|(id, _)| *id)
                .take(TIP_PROMOTE_CAP)
                .collect();
            if !candidates.is_empty() {
                let mut promoted = 0usize;
                for txid in &candidates {
                    if mgr.mempool().promote(txid, &cs, unix_now()).is_ok() {
                        promoted += 1;
                    }
                }
                emit(
                    &mut stream,
                    "extrapool_promotion_pass",
                    serde_json::json!({
                        "trigger": "tip",
                        "attempted": candidates.len(),
                        "promoted": promoted,
                    }),
                );
            }
        }
        // Completion boundary for the speculative tail: pending script
        // checks never linger past a quiet 50ms — a short burst's last
        // blocks must become authoritative without waiting for the
        // next arrival or a periodic flush. A drain failure rewinds
        // the failed suffix; the mempool feed then publishes only
        // fully-checked blocks.
        if cs.pending_scripts_len() > 0
            && cs.pending_idle() > Duration::from_millis(50)
            && let Err(e) = cs.drain_scripts()
        {
            eprintln!("sync: deferred script check failed: {e}");
        }
        let mut deferred_tip = None;
        for (h, hash) in cs.take_checked() {
            if let Some(body) = cs.body(&hash) {
                mgr.mempool().on_block_connected(&body, h);
            }
            deferred_tip = Some(h);
        }
        // Deferred script checks resolve after the dispatch that
        // connected them — the manager only emits TipAdvanced for the
        // set it drained in-tick, so the tail publishes here (one
        // event per drain's last height, matching its semantics).
        if let Some(h) = deferred_tip {
            emit(
                &mut stream,
                "tip_advanced",
                serde_json::json!({"height": h}),
            );
            mgr.announce_tip(&cs);
        }
        connected = cs.chain().len() as u32 - 1;
        pace.sample(&cs, connected);
        // The target counts blocks connected *this run* above whatever
        // the store resumed at — a resumed chain doesn't re-trigger
        // the stop condition at its own height.
        let run_progress = connected.saturating_sub(resumed_height);
        // Periodic chainstate checkpoint — Core's `FlushStateToDisk`
        // cadence. A crash otherwise replays every blk file since the
        // last state.dat; bounding the interval bounds the replay.
        // The SwiftSync hold no longer suppresses this: the tag
        // aggregate tracks the live set across layers, so mid-window
        // flushes preserve hint correctness (audit CA-F1 — holding
        // every coin in memory was an unbounded DoS surface).
        if cfg.data_dir.is_some() && last_flush + FLUSH_INTERVAL <= connected {
            last_flush = connected;
            cs.flush().map_err(SyncError::Store)?;
        }
        // Self-audit (queue #15): every AUDIT_INTERVAL connected
        // blocks, re-verify a random sample's internal proofs
        // (decode + merkle + witness commitment). Catches disk rot
        // and bitflips in stored blocks — a failure is loud.
        if connected.saturating_sub(last_audit) >= AUDIT_INTERVAL {
            last_audit = connected;
            let bad = audit_sample(&cs, 8, connected as u64);
            audit_failures += bad;
            if bad > 0 {
                eprintln!(
                    "self-audit: {bad} of 8 sampled blocks FAILED integrity checks                      ({audit_failures} cumulative) — storage may be corrupt"
                );
            }
            // UTXO-replay audit (queue #15): a ~2-week window ending
            // at the tip — every created coin is live-or-provably-
            // spent and every undo-claimed dead coin is dead. The
            // same rot class as the block audit, one layer deeper.
            let from = connected.saturating_sub(2015).max(1);
            if let Err(e) = cs.audit_utxo_segment(from, connected) {
                audit_failures += 1;
                eprintln!(
                    "self-audit: UTXO segment {from}..{connected} FAILED ({e:?}) —                      coins state may be corrupt ({audit_failures} cumulative)"
                );
            }
        }
        // SwiftSync checkpoint: the transient window ends when the
        // chain is fully connected — release the hold so normal
        // budget pressure + flushing resume. The aggregate keeps
        // tracking for emit/verify.
        if !swift_released && connected >= cs.tree().tip().height {
            swift_released = true;
            cs.release_swiftsync_hold();
            if let Some(agg) = cs.swiftsync_agg() {
                eprintln!(
                    "swiftsync: window closed at {connected} —                      aggregate {:x?} live, flushing resumes",
                    &agg.to_bytes()[..8]
                );
            }
        }
        // Snapshot background validation — Core's scheduler-driven ibd
        // chainstate: replay pre-base bodies into the proof UTXO set.
        // A bounded slice per tick keeps it off the sync critical path.
        // When a pre-base body is missing, fetch it — the same windowed
        // request path rescans use.
        if cs.snapshot_base().is_some()
            && !cs.snapshot_verified()
            && let avila_consensus::chainstate::BackgroundStatus::WaitingForBody { height } =
                cs.background_step(32)?
        {
            let base = cs.snapshot_base().unwrap_or(0);
            let want: Vec<avila_consensus::hash::BlockHash> = cs.chain()
                [height as usize..=base as usize]
                .iter()
                .take(16)
                .filter(|h| !cs.have_body(h))
                .copied()
                .collect();
            mgr.request_blocks(&want);
        }
        // The last *checked* blocks, for the tape display — the
        // speculative tail stays invisible to every consumer-facing
        // surface (tape, getbestblockhash, progress numbers).
        let chain = cs.chain();
        let end = (cs.checked_height() as usize + 1).min(chain.len());
        let recent: Vec<(u32, avila_consensus::hash::BlockHash)> = chain
            [end.saturating_sub(12)..end]
            .iter()
            .enumerate()
            .map(|(i, h)| (end.saturating_sub(12) as u32 + i as u32, *h))
            .collect();
        // ChainProfile::refresh is a no-op once the tip hash matches, so
        // this is cheap on every tick that didn't just connect a block;
        // only rebuild the published Arc when the tip actually moved.
        let prev_profile_tip = chain_profile.tip;
        chain_profile.refresh(cs.tree());
        if chain_profile.tip != prev_profile_tip {
            chain_profile_arc = std::sync::Arc::new(chain_profile.clone());
        }
        // Next-block preview: only while the GUI asked for it, only
        // while there's something to preview, and throttled so a busy
        // mempool isn't re-templated every tick.
        if cfg.preview_next_block {
            if mgr.mempool().is_empty() {
                next_block = None;
            } else if next_block_built_at.is_none_or(|t| t.elapsed() >= NEXT_BLOCK_REBUILD_INTERVAL)
            {
                next_block_built_at = Some(Instant::now());
                next_block = crate::next_block::build_next_block(mgr.mempool(), &cs)
                    .map(std::sync::Arc::new);
            }
        }
        if eclipse_checked_at.is_none_or(|t| t.elapsed() >= ECLIPSE_CHECK_INTERVAL) {
            eclipse_checked_at = Some(Instant::now());
            eclipse = mgr.eclipse_signals(&cs, unix_now());
        }
        if hb_at.elapsed() >= std::time::Duration::from_secs(30) {
            hb_at = std::time::Instant::now();
            let t = avila_consensus::connect::connect_timing();
            let (map_n, map_b, undos_n) = cs.mem_stats();
            let rss_kb = std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines().find(|l| l.starts_with("VmRSS")).and_then(|l| {
                        l.split_whitespace()
                            .nth(1)
                            .and_then(|v| v.parse::<u64>().ok())
                    })
                })
                .unwrap_or(0);
            let eta = pace
                .eta_secs(connected, cs.tree().tip().height)
                .map(|(lo, mid, hi)| {
                    let f = |s: u64| {
                        let h = s / 3600;
                        let m = (s % 3600) / 60;
                        if h > 0 {
                            format!("{h}h{m}m")
                        } else {
                            format!("{m}m{s}s", s = s % 60)
                        }
                    };
                    format!("{}[{lo}..{hi}]", f(mid), lo = f(lo), hi = f(hi))
                })
                .unwrap_or_else(|| "warming".to_string());
            let fit = pace
                .debug_fit()
                .map(|(med, ratio_cap, bf, cap, n)| {
                    format!(
                        "fit[med={med:.0}ms rcap={ratio_cap:.2} bf={bf:.2}B/blk cap={}KB n={n}]",
                        cap as u64 / 1000
                    )
                })
                .unwrap_or_default();
            // Interval deltas — per-block cost of THIS window, not a
            // cumulative average that flattens era changes.
            let d_blocks = connected.saturating_sub(hb_prev_connected);
            let d = |cur: u64, prev: u64| {
                let ns = cur.saturating_sub(prev);
                if d_blocks == 0 {
                    0
                } else {
                    ns / 1_000_000 / d_blocks as u64
                }
            };
            let d_ms = |cur: u64, prev: u64| cur.saturating_sub(prev) / 1_000_000;
            let pending_n = cs.pending_scripts_len();
            eprintln!(
                "sync: peers={} connected={} headers={} buffered={} in_flight={} rss={}MB map={}n/{}MB undos={} pend={} eta={} w={} | ms/blk[{} blk] total={} read={} apply={} scripts={} drain={} bip30={} other={} | accept={}ms reorg={}ms",
                mgr.len(),
                connected,
                cs.tree().tip().height,
                mgr.presync_height().unwrap_or(0),
                mgr.in_flight(),
                rss_kb / 1024,
                map_n,
                map_b / 1_048_576,
                undos_n,
                pending_n,
                format_args!("{eta} {fit}"),
                pace.windows.len(),
                d_blocks,
                d(t.total_ns, hb_prev_t.total_ns),
                d(t.read_ns, hb_prev_t.read_ns),
                d(t.apply_ns, hb_prev_t.apply_ns),
                d(t.script_ns, hb_prev_t.script_ns),
                d(t.drain_ns, hb_prev_t.drain_ns),
                d(t.bip30_ns, hb_prev_t.bip30_ns),
                d(
                    t.total_ns
                        .saturating_sub(t.read_ns + t.apply_ns + t.script_ns + t.bip30_ns),
                    hb_prev_t.total_ns.saturating_sub(
                        hb_prev_t.read_ns
                            + hb_prev_t.apply_ns
                            + hb_prev_t.script_ns
                            + hb_prev_t.bip30_ns
                    )
                ),
                d_ms(t.accept_ns, hb_prev_t.accept_ns),
                d_ms(t.reorg_ns, hb_prev_t.reorg_ns),
            );
            hb_prev_t = t;
            hb_prev_connected = connected;
        }
        let etas = pace.eta_secs(connected, cs.tree().tip().height);
        let snapshot = SyncProgress {
            phase: if mgr.is_empty() {
                Phase::FindingPeers
            } else {
                Phase::Syncing
            },
            peers: mgr.len(),
            proxy: mgr.proxy(),
            connected_height: cs.checked_height(),
            header_height: cs.tree().tip().height,
            utreexo_height: cs.utreexo_height(),
            headers_buffered: mgr.presync_height().unwrap_or(0) as u32,
            in_flight: mgr.in_flight(),
            established_total,
            disconnects,
            recent,
            peer_details: mgr.peer_snapshots(),
            mempool: (
                mgr.mempool().len(),
                mgr.mempool().orphan_count(),
                mgr.mempool().estimate_fee(6),
            ),
            elapsed_secs: (crate::time::time() - started_epoch).max(0) as u64,
            validation: cs.validation_report(),
            profile: chain_profile_arc.clone(),
            next_block: next_block.clone(),
            eclipse: eclipse.clone(),
            prune_bytes: cfg.prune_bytes,
            eta_secs: etas.map(|(_, mid, _)| mid),
            eta_lo_secs: etas.map(|(lo, _, _)| lo),
            eta_hi_secs: etas.map(|(_, _, hi)| hi),
        };
        if let Some(status) = &cfg.status
            && let Ok(mut w) = status.write()
        {
            *w = snapshot.clone();
        }
        // Answer queued chain queries against the just-ticked state —
        // bounded backlog per tick so a flood can't starve sync.
        if let Some(rx) = &cfg.queries
            && let Ok(rx) = rx.lock()
        {
            for _ in 0..64 {
                match rx.try_recv() {
                    Ok(q) => {
                        // A query closure runs arbitrary RPC-handler
                        // code (e.g. address parsing) against live
                        // state; a bug there (an out-of-bounds string
                        // slice on non-ASCII input has done it) must
                        // not take the whole sync loop down with it —
                        // every chain RPC would die along with block
                        // sync. `catch_unwind` isolates the panic to
                        // this one query: it's logged, `q`'s reply
                        // sender is dropped as part of the unwind so
                        // its caller gets RPC_INTERNAL_ERROR instead
                        // of hanging (see `chain_query_deferred`), and
                        // the loop keeps ticking. `cs`/`mgr` could in
                        // principle retain a partially-applied
                        // mutation from the aborted closure — the same
                        // residual risk any `catch_unwind` carries —
                        // but that's strictly better than the crash
                        // this replaces.
                        let method = q.method().unwrap_or("<unknown>").to_string();
                        if let Err(payload) =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                q.answer(&mut cs, &mut mgr, &mut rescans)
                            }))
                        {
                            eprintln!(
                                "chain query panicked (method={method}): {}",
                                panic_message(&payload)
                            );
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        // Drive deferred rescans: scan bodies that arrived, refetch
        // the rest, answer when the range is covered or the deadline
        // passes.
        if !rescans.is_empty() {
            let mut keep = std::collections::VecDeque::new();
            while let Some(mut job) = rescans.pop_front() {
                let arrived: Vec<u32> = job
                    .pending
                    .iter()
                    .filter(|(_, h)| cs.have_body(h))
                    .map(|(h, _)| *h)
                    .collect();
                if !arrived.is_empty()
                    && let Ok(mut w) = job.wallet.lock()
                {
                    for h in arrived {
                        if let Some(hash) = job.pending.get(&h).copied()
                            && let Some(b) = cs.body(&hash)
                        {
                            // `scan_gap_height` reports whether it
                            // actually scanned this height — `false`
                            // means the captured hash was reorged away
                            // between being queued and its body
                            // arriving, so this must not count as
                            // done. Re-target the height at the active
                            // chain's current hash there instead of
                            // marking a block scanned that never was;
                            // `rescanblockchain` would otherwise report
                            // completion having silently skipped it.
                            if w.scan_gap_height(&cs, &b, h, hash) {
                                job.pending.remove(&h);
                            } else if let Some(current) = cs.chain().get(h as usize).copied() {
                                job.pending.insert(h, current);
                            }
                        }
                    }
                    let _ = w.persist();
                }
                if job.pending.is_empty() {
                    let _ = job.reply.send(Ok(job.done));
                } else if std::time::Instant::now() >= job.deadline {
                    let _ = job.reply.send(Err((
                        -4,
                        format!(
                            "Rescan incomplete — {} blocks still missing bodies",
                            job.pending.len()
                        ),
                    )));
                } else {
                    let want: Vec<avila_consensus::hash::BlockHash> =
                        job.pending.values().take(16).copied().collect();
                    mgr.request_blocks(&want);
                    keep.push_back(job);
                }
            }
            rescans = keep;
        }
        // Fire every `waitforblock*` predicate that this tick's state
        // satisfies — the loop's half of Core's BlockConnected
        // notifications.
        if let Some(waiters) = &cfg.waiters {
            waiters.notify(&cs, mgr.mempool());
        }
        // The scheduler — periodic jobs (peers.dat dumps, …); on
        // regtest `mockscheduler` fast-forwards this same queue.
        mgr.run_due_tasks();
        // Pruned mode must hold its budget DURING sync, not only at
        // exit — IBD accumulates blk files at network speed and a
        // shutdown-only prune needs the full archival disk anyway.
        // Whole-file deletion at 128 MiB granularity: a minute
        // cadence keeps the store within keep+one file.
        if cfg.prune_bytes.is_some() && last_prune.elapsed() >= Duration::from_secs(60) {
            last_prune = std::time::Instant::now();
            if let Some(keep) = cfg.prune_bytes
                && let Err(e) = cs.prune(keep)
            {
                eprintln!("prune failed: {e}");
            }
        }
        if let Ok(mut p) = progress.lock() {
            p(&snapshot);
        }
        if run_progress >= cfg.target_height {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    // The loop is leaving — wake every parked wait-RPC so its handler
    // answers the last tip instead of blocking on a dead loop.
    if let Some(waiters) = &cfg.waiters {
        waiters.shutdown();
    }

    if let Some(dir) = &cfg.data_dir {
        cs.flush().map_err(SyncError::Store)?;
        if let Some(keep) = cfg.prune_bytes {
            cs.prune(keep).map_err(SyncError::Store)?;
        }
        mgr.addrbook().save(&dir.join("peers.dat"))?;
        // mempool.dat — Core's DumpMempool at shutdown. A failed write
        // must not fail the shutdown: the chainstate is already flushed.
        let _ = mgr.mempool_ref().save(&dir.join("mempool.dat"));
    }

    emit(
        &mut stream,
        "run_stopped",
        serde_json::json!({
            "connected_height": connected,
            "established_total": established_total,
            "disconnects": disconnects,
            "elapsed_secs": started.elapsed().as_secs(),
        }),
    );

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

/// A live `ControlMsg::Set` → the setter it resolves to. `Ok` returns
/// the value actually applied (normalized — `"auto"` lands as `""`,
/// MB lands as bytes semantics are echoed back in the knob's unit).
/// `Err` carries the rejection reason for `config_rejected`.
fn apply_knob<S: std::io::Read + std::io::Write>(
    mgr: &mut avila_p2p::PeerManager<S>,
    knobs: &mut LiveKnobs,
    path: &str,
    value: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    use serde_json::Value;
    let want_bool = |v: &Value| {
        v.as_bool()
            .ok_or_else(|| format!("expected true/false, got {v}"))
    };
    let want_u64 = |v: &Value| {
        v.as_u64()
            .ok_or_else(|| format!("expected a non-negative integer, got {v}"))
    };
    let want_i64 = |v: &Value| {
        v.as_i64()
            .ok_or_else(|| format!("expected an integer, got {v}"))
    };
    let want_str = |v: &Value| {
        v.as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("expected a string, got {v}"))
    };
    let want_enum = |v: &Value, choices: &[&str]| {
        let s = want_str(v)?;
        if choices.contains(&s.as_str()) {
            Ok(s)
        } else {
            Err(format!("expected one of {choices:?}, got {s:?}"))
        }
    };
    let applied = match path {
        "net.blocks_only" => {
            mgr.set_blocks_only(want_bool(value)?);
            value.clone()
        }
        "peers.ban_time" => {
            mgr.set_default_ban_time(want_i64(value)?);
            value.clone()
        }
        "privacy.cell_bytes" => {
            mgr.set_cell_bytes(want_u64(value)? as usize);
            value.clone()
        }
        "mempool.max_mb" => {
            let mb = want_u64(value)?;
            mgr.mempool().set_max_bytes(mb as usize * 1_000_000);
            value.clone()
        }
        "mempool.min_relay_fee_sat_per_kvb" => {
            mgr.mempool().set_min_relay_fee(want_i64(value)?);
            value.clone()
        }
        "mempool.expiry_secs" => {
            mgr.mempool()
                .set_mempool_expiry_secs(want_u64(value)? as u32);
            value.clone()
        }
        "mempool.private" => {
            mgr.set_private_submissions(want_bool(value)?);
            value.clone()
        }
        "policy.require_standard" => {
            mgr.mempool().set_require_standard(want_bool(value)?);
            value.clone()
        }
        "policy.datacarrier" => {
            let on = want_bool(value)?;
            // `false` disables datacarrier outputs (None budget); `true`
            // restores the last set size (or Core's 83-byte default).
            let size = knobs
                .datacarrier_bytes
                .unwrap_or(avila_mempool::policy::MAX_OP_RETURN_RELAY);
            knobs.datacarrier_bytes = on.then_some(size);
            mgr.mempool()
                .set_max_datacarrier_bytes(knobs.datacarrier_bytes);
            value.clone()
        }
        "policy.datacarrier_size" => {
            let n = want_u64(value)? as usize;
            knobs.datacarrier_bytes = Some(n);
            mgr.mempool().set_max_datacarrier_bytes(Some(n));
            value.clone()
        }
        "policy.permit_bare_multisig" => {
            mgr.mempool().set_permit_bare_multisig(want_bool(value)?);
            value.clone()
        }
        "policy.dust_relay_fee_sat_per_kvb" => {
            mgr.mempool().set_dust_relay_fee(want_i64(value)?);
            value.clone()
        }
        "relay.tx.stem" => {
            mgr.set_stem_relay(want_bool(value)?);
            value.clone()
        }
        "relay.tx.deny_pairs" => {
            let arr = value
                .as_array()
                .ok_or_else(|| format!("expected [\"src->dst\", …], got {value}"))?;
            let mut pairs = Vec::with_capacity(arr.len());
            for p in arr {
                let s = want_str(p)?;
                let (src, dst) = s
                    .split_once("->")
                    .ok_or_else(|| format!("{s:?} — expected \"src->dst\""))?;
                pairs.push((src.trim().to_string(), dst.trim().to_string()));
            }
            mgr.set_deny_pairs(pairs);
            value.clone()
        }
        // relay.tx tuple — mutate one member, re-apply the whole.
        "relay.tx.announce"
        | "relay.tx.to_inbound"
        | "relay.tx.to_blocks_only_peers"
        | "relay.tx.send_feefilter"
        | "relay.tx.rebroadcast_local"
        | "relay.tx.rebroadcast_interval" => {
            match path {
                "relay.tx.announce" => {
                    knobs.relay_tx.0 = want_enum(value, &["all", "private_only", "none"])?
                }
                "relay.tx.to_inbound" => knobs.relay_tx.1 = want_bool(value)?,
                "relay.tx.to_blocks_only_peers" => knobs.relay_tx.2 = want_bool(value)?,
                "relay.tx.send_feefilter" => knobs.relay_tx.3 = want_u64(value)?,
                "relay.tx.rebroadcast_local" => knobs.relay_tx.4 = want_bool(value)?,
                _ => knobs.relay_tx.5 = want_u64(value)? as u32,
            }
            mgr.set_tx_relay(
                &knobs.relay_tx.0,
                knobs.relay_tx.1,
                knobs.relay_tx.2,
                knobs.relay_tx.3,
                knobs.relay_tx.4,
                knobs.relay_tx.5,
            );
            value.clone()
        }
        "relay.block.compact"
        | "relay.block.compact_high_bandwidth"
        | "relay.block.compact_serve"
        | "relay.block.announce" => {
            match path {
                "relay.block.compact" => knobs.relay_block.0 = want_bool(value)?,
                "relay.block.compact_high_bandwidth" => knobs.relay_block.1 = want_bool(value)?,
                "relay.block.compact_serve" => knobs.relay_block.2 = want_bool(value)?,
                _ => {
                    let s = want_enum(value, &["auto", "headers", "inv", "none"])?;
                    knobs.relay_block.3 = if s == "auto" { String::new() } else { s };
                }
            }
            mgr.set_compact_relay(
                knobs.relay_block.0,
                knobs.relay_block.1,
                knobs.relay_block.2,
                &knobs.relay_block.3,
            );
            value.clone()
        }
        "relay.block.serve" => {
            knobs.relay_block.4 = want_enum(value, &["full", "tip", "none"])?;
            mgr.set_block_serve_mode(&knobs.relay_block.4);
            Value::String(knobs.relay_block.4.clone())
        }
        "extrapool.observe"
        | "extrapool.max_entries"
        | "extrapool.max_bytes"
        | "extrapool.expiry_secs" => {
            match path {
                "extrapool.observe" => knobs.extrapool.observe = want_bool(value)?,
                "extrapool.max_entries" => knobs.extrapool.max_entries = want_u64(value)? as usize,
                "extrapool.max_bytes" => knobs.extrapool.max_bytes = want_u64(value)? as usize,
                _ => knobs.extrapool.expiry_secs = want_u64(value)? as u32,
            }
            mgr.mempool().configure_extrapool(
                knobs.extrapool.observe,
                knobs.extrapool.max_entries,
                knobs.extrapool.max_bytes,
                knobs.extrapool.expiry_secs,
            );
            value.clone()
        }
        "extrapool.relay" => {
            knobs.extrapool.relay = want_enum(value, &["never", "outbound", "all"])?;
            let relay_on = knobs.extrapool.relay != "never";
            mgr.mempool()
                .configure_extrapool_detail(knobs.extrapool.caps.clone(), relay_on);
            Value::String(knobs.extrapool.relay.clone())
        }
        "mining.include_extrapool" => {
            mgr.mempool().set_mine_extrapool(want_bool(value)?);
            value.clone()
        }
        "mining.max_weight" => {
            let w = want_u64(value)? as usize;
            if w > avila_consensus::block::MAX_BLOCK_WEIGHT {
                return Err(format!(
                    "max {MAX_BLOCK_WEIGHT} — blocks beyond consensus weight are invalid",
                    MAX_BLOCK_WEIGHT = avila_consensus::block::MAX_BLOCK_WEIGHT
                ));
            }
            knobs.mining.0 = Some(w);
            mgr.mempool().set_block_max_weight(w);
            value.clone()
        }
        "mining.min_tx_fee" => {
            let f = want_i64(value)?;
            knobs.mining.1 = f;
            mgr.mempool().set_block_min_fee(f);
            value.clone()
        }
        "mining.reserved_weight" => {
            let w = want_u64(value)? as usize;
            knobs.mining.2 = Some(w);
            mgr.mempool().set_block_reserved_weight(w);
            value.clone()
        }
        "filters.serve" => {
            mgr.set_serve_filters(want_bool(value)?);
            value.clone()
        }
        "sync.max_in_transit" => {
            mgr.set_max_in_flight_total(want_u64(value)? as usize);
            value.clone()
        }
        _ if crate::config::live_knob(path) => {
            return Err(format!("{path} is listed live but has no apply mapping"));
        }
        _ => return Err(format!("{path} is restart-only (or unknown)")),
    };
    Ok(applied)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use avila_core::ExtrapoolConfig;
    use serde_json::json;
    use std::io::Cursor;

    /// `PeerManager` over an in-memory stream type — `apply_knob` only
    /// touches manager/mempool fields, never the transport.
    fn fixture() -> (PeerManager<Cursor<Vec<u8>>>, LiveKnobs) {
        (
            PeerManager::new(8),
            LiveKnobs {
                relay_tx: ("all".to_string(), true, false, 0, true, 60),
                relay_block: (true, true, true, String::new(), "full".to_string()),
                extrapool: ExtrapoolConfig::default(),
                mining: (None, 0, None),
                datacarrier_bytes: Some(avila_mempool::policy::MAX_OP_RETURN_RELAY),
            },
        )
    }

    #[test]
    fn live_knob_applies_and_normalizes() {
        let (mut mgr, mut knobs) = fixture();
        apply_knob(&mut mgr, &mut knobs, "net.blocks_only", &json!(true)).unwrap();
        apply_knob(
            &mut mgr,
            &mut knobs,
            "relay.block.announce",
            &json!("headers"),
        )
        .unwrap();
        assert_eq!(knobs.relay_block.3, "headers");
        // "auto" normalizes to the empty string = negotiated default.
        apply_knob(&mut mgr, &mut knobs, "relay.block.announce", &json!("auto")).unwrap();
        assert_eq!(knobs.relay_block.3, "");
    }

    #[test]
    fn live_knob_tuple_members_apply_whole() {
        let (mut mgr, mut knobs) = fixture();
        apply_knob(&mut mgr, &mut knobs, "relay.tx.announce", &json!("none")).unwrap();
        assert_eq!(knobs.relay_tx.0, "none");
        apply_knob(&mut mgr, &mut knobs, "relay.tx.send_feefilter", &json!(500)).unwrap();
        assert_eq!(knobs.relay_tx.3, 500);
        assert_eq!(knobs.relay_tx.0, "none");
    }

    #[test]
    fn live_knob_rejects_bad_domain_and_unknown() {
        let (mut mgr, mut knobs) = fixture();
        assert!(apply_knob(&mut mgr, &mut knobs, "relay.tx.announce", &json!("loud")).is_err());
        assert!(apply_knob(&mut mgr, &mut knobs, "relay.block.serve", &json!("some")).is_err());
        assert!(apply_knob(&mut mgr, &mut knobs, "net.connect", &json!(true)).is_err());
        // Over-consensus mining weight refuses — policy cannot make
        // an invalid block.
        assert!(
            apply_knob(
                &mut mgr,
                &mut knobs,
                "mining.max_weight",
                &json!(4_000_001u64)
            )
            .is_err()
        );
        assert!(
            apply_knob(
                &mut mgr,
                &mut knobs,
                "mining.max_weight",
                &json!(3_500_000u64)
            )
            .is_ok()
        );
        // A non-live-but-documented knob reports restart, not success.
        assert!(apply_knob(&mut mgr, &mut knobs, "indexes.txindex", &json!(true)).is_err());
    }

    #[test]
    fn live_knob_types_are_checked() {
        let (mut mgr, mut knobs) = fixture();
        assert!(apply_knob(&mut mgr, &mut knobs, "net.blocks_only", &json!("yes")).is_err());
        assert!(apply_knob(&mut mgr, &mut knobs, "mempool.max_mb", &json!(true)).is_err());
        assert!(
            apply_knob(
                &mut mgr,
                &mut knobs,
                "relay.tx.deny_pairs",
                &json!(["inbound->local", "extrapool->outbound"])
            )
            .is_ok()
        );
        assert!(
            apply_knob(
                &mut mgr,
                &mut knobs,
                "relay.tx.deny_pairs",
                &json!(["no-arrow"])
            )
            .is_err()
        );
    }
}

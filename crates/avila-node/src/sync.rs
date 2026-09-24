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
use avila_p2p::manager::{NetEvent, PeerManager};

/// Connected-block interval between mid-sync `state.dat` checkpoints
/// — Core's `FlushStateToDisk` cadence analogue. 2048 blocks bounds a
/// crash to replaying at most that many blk-file entries.
const FLUSH_INTERVAL: u32 = 2048;

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
            status: None,
            queries: None,
            waiters: None,
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
    mut progress: impl FnMut(&SyncProgress),
) -> Result<SyncReport, SyncError> {
    // Process-level sandboxing (queue #11): `no_new_privs` before any
    // network work — a compromised process can never gain privileges
    // through execve of a setuid/file-capability binary. The node
    // never execve()s anything, so this is free defense-in-depth.
    // Finer-grained seccomp/Landlock filtering stays open.
    sandbox_self();
    let mut cs = match &cfg.data_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir).map_err(SyncError::Store)?;
            let dbcache = cfg
                .dbcache
                .unwrap_or(avila_consensus::connect::DEFAULT_CACHE_BUDGET);
            Chainstate::with_store_coinsdb(dir, params, unix_now(), dbcache)
                .map_err(SyncError::Store)?
        }
        None => Chainstate::new(params),
    };
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
    let resumed_height = cs.chain().len() as u32 - 1;
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
    // The whole p2p time domain — dial-path ban checks, version
    // `timestamp`s, conntime/lastsend/lastrecv and the last_* peer
    // fields — reads the node clock, so `setmocktime` shifts them too.
    mgr.set_clock(crate::time::time);
    mgr.set_v2transport(cfg.v2transport);
    // The index we just enabled is what makes BIP157 serving
    // legitimate — advertise NODE_COMPACT_FILTERS only then.
    mgr.set_serve_filters(cfg.blockfilterindex && cfg.peerblockfilters);
    if let Some(b) = cfg.maxmempool_bytes {
        mgr.set_max_mempool_bytes(b);
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
    let seeded = if cfg.connect.is_empty() {
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
        for event in mgr.tick_net(&mut cs, unix_now(), params.message_start, 0) {
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
        connected = cs.chain().len() as u32 - 1;
        // The target counts blocks connected *this run* above whatever
        // the store resumed at — a resumed chain doesn't re-trigger
        // the stop condition at its own height.
        let run_progress = connected.saturating_sub(resumed_height);
        // Periodic chainstate checkpoint — Core's `FlushStateToDisk`
        // cadence. A crash otherwise replays every blk file since the
        // last state.dat; bounding the interval bounds the replay.
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
        // The last connected blocks, for the tape display.
        let chain = cs.chain();
        let recent: Vec<(u32, avila_consensus::hash::BlockHash)> = chain
            .iter()
            .enumerate()
            .skip(chain.len().saturating_sub(12))
            .map(|(i, h)| (i as u32, *h))
            .collect();
        let snapshot = SyncProgress {
            peers: mgr.len(),
            connected_height: connected,
            header_height: cs.tree().tip().height,
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
        progress(&snapshot);
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
